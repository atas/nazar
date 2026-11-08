package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

// logPredicate is fixed: user filters are applied by nazar after parsing,
// never spliced into the query.
//
// The unified log accepts an entry under any subsystem from any process, so
// the predicate alone would also return entries another process forged under
// dev.nazar/audit. Each entry is therefore kept only when its process image
// and its sender image are one and the same image, and that image is
// Nazar.app's main executable: either today's build (by Mach-O LC_UUID,
// fromSender) or any earlier build that ran from the same installed path
// (fromNazar). The log identifies images by UUID and reports each UUID under
// the path it first saw it at, so an image's path in the log is where that
// build first ran; it can't filter on UUIDs or image paths in a predicate,
// so the check is done here (until Milestone 5, entries written by the
// build before a rebuild went missing from `nazar log`;
// TestLogKeepsOnlyNazarsOwnEntries and TestLogKeepsEveryBuildAtTheInstalledPath
// run it against the real log store).
// Known limits: a program built to carry the LC_UUID of any build of Nazar
// that ran from the installed path still passes, and so does a program run
// from that path itself (which could replace Nazar.app outright); this stops
// forgery by any ordinary program, not by one crafted for it.
const logPredicate = `subsystem == "dev.nazar" AND category == "audit"`

// systemLog is run by absolute path, never via $PATH.
const systemLog = "/usr/bin/log"

// runSystemLog runs /usr/bin/log and calls line for each output line.
func runSystemLog(ctx context.Context, args []string, line func([]byte)) error {
	cmd := exec.CommandContext(ctx, systemLog, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line(sc.Bytes())
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}

type logEntry struct {
	Timestamp        string `json:"timestamp"`
	EventMessage     string `json:"eventMessage"`
	ProcessImageUUID string `json:"processImageUUID"`
	SenderImageUUID  string `json:"senderImageUUID"`
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
}

// trustedSender is the image `nazar log` accepts entries from: the LC_UUID
// of today's Nazar.app executable and the path it is installed at.
type trustedSender struct {
	UUID string
	Path string
}

// fromNazar reports whether e was written by Nazar.app: by today's build
// (fromSender), or by an earlier build that ran from the installed path,
// where the process image and the sender image are the same image (same
// UUID) at exactly that path (compared byte for byte: no cleaning, no case
// folding). An empty path never matches.
func fromNazar(e logEntry, s trustedSender) bool {
	if fromSender(e, s.UUID) {
		return true
	}
	return s.Path != "" && e.ProcessImageUUID != "" && strings.EqualFold(e.ProcessImageUUID, e.SenderImageUUID) &&
		e.ProcessImagePath == s.Path && e.SenderImagePath == s.Path
}

// fromSender reports whether e was written by the image with LC_UUID uuid:
// the process and the image that made the call must both be it.
func fromSender(e logEntry, uuid string) bool {
	return uuid != "" && strings.EqualFold(e.ProcessImageUUID, uuid) && strings.EqualFold(e.SenderImageUUID, uuid)
}

// logShowTime is the timestamp layout of `log show --style ndjson`.
const logShowTime = "2006-01-02 15:04:05.000000-0700"

func (a *app) log(args []string) int {
	summary := len(args) > 0 && args[0] == "summary"
	if summary {
		args = args[1:]
	}
	fs := a.flags("log")
	if summary {
		fs = a.flags("log summary")
	}
	follow := fs.Bool("follow", false, "")
	since := fs.String("since", "24h", "")
	target := fs.String("target", "", "")
	callerF := fs.String("caller", "", "")
	decision := fs.String("decision", "", "")
	if summary {
		*since = "7d"
	}
	if _, err := a.parse(fs, args, 0); err != nil {
		return a.fail(err)
	}
	d, err := config.ParseDuration(*since)
	if err != nil {
		return a.usageError("log: --since: %v", err)
	}
	if d < time.Second {
		return a.usageError("log: --since must be at least 1s")
	}
	// The identity is read before /usr/bin/log runs: without it no entry
	// could be told from a forged one, so none is shown.
	loc, err := a.locateApp()
	if err != nil {
		return a.fail(err)
	}
	uuid, err := a.imageUUID(loc.MainExe)
	if err == nil && uuid == "" {
		err = errors.New("empty LC_UUID")
	}
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "reading the identity of %s: %v", loc.MainExe, err))
	}
	sender := trustedSender{UUID: uuid, Path: loc.MainExe}
	var logArgs []string
	if *follow {
		if summary {
			return a.usageError("log summary can't --follow")
		}
		logArgs = []string{"stream", "--style", "ndjson", "--level", "default", "--predicate", logPredicate}
	} else {
		logArgs = []string{"show", "--style", "ndjson", "--predicate", logPredicate, "--last", lastWindow(d)}
	}
	ctx, stop := commandContext(*follow)
	defer stop()
	sums := map[string]*control.AuditSummary{}
	err = a.runLog(ctx, logArgs, func(b []byte) {
		var e logEntry
		if json.Unmarshal(b, &e) != nil || e.EventMessage == "" || !fromNazar(e, sender) {
			return
		}
		// ParseLine accepts exactly what the audit formatter writes: after it
		// succeeds the message is printable ASCII (plus the ellipsis). The
		// human view still prints it through term rather than trusting that.
		// The parsed fields are unquoted, though, and carry the caller's raw
		// runes again: anything printed from them goes through safe.
		fields, err := audit.ParseLine(e.EventMessage)
		if err != nil {
			return
		}
		if !matchLog(fields, *target, *callerF, *decision) {
			return
		}
		if summary {
			s := sums[fields["target"]]
			if s == nil {
				s = &control.AuditSummary{TypeMeta: control.Meta(control.KindAuditSummary), Target: fields["target"], Decisions: map[string]int{}, Callers: map[string]int{}}
				sums[fields["target"]] = s
			}
			s.Total++
			s.Decisions[fields["decision"]]++
			s.Callers[callerName(fields)]++
			return
		}
		t, terr := time.Parse(logShowTime, e.Timestamp)
		ev := control.AuditEvent{TypeMeta: control.Meta(control.KindAuditEvent), Time: t, Fields: fields}
		a.emit(ev, func() {
			stamp := printable(e.Timestamp)
			if terr == nil {
				stamp = t.Local().Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(a.stdout, "%s %s\n", stamp, term(e.EventMessage))
		})
	})
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "reading the macOS log: %v", err))
	}
	if summary {
		a.printSummary(sums)
	}
	return control.ExitOK
}

// lastWindow renders d for `log show --last`: whole minutes when exact,
// otherwise seconds, so the window is never shortened by rounding.
func lastWindow(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int64(d/time.Second))
}

func (a *app) printSummary(sums map[string]*control.AuditSummary) {
	keys := make([]string, 0, len(sums))
	for k := range sums {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	if !a.json {
		fmt.Fprintln(tw, "TARGET\tTOTAL\tBLOCKED\tCALLERS")
	}
	for _, k := range keys {
		s := sums[k]
		a.emit(s, func() {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", safe(s.Target), s.Total, s.Decisions["blocked"], joinCounts(s.Callers))
		})
	}
	tw.Flush()
}

// summaryBareRE is the only shape a summary value may have unquoted: no
// space, comma or quote, so a target or caller can never read as another
// column, as two callers, or as a forged count ("com.x x9, com.y").
var summaryBareRE = regexp.MustCompile(`^[A-Za-z0-9._:/@+~\-]+$`)

// safe renders one parsed audit value for the human summary. ParseLine
// undoes the escaping the audit formatter applied, so a target or app value
// carries the caller's raw control, bidi and look-alike runes again (spec
// 4.6; core/audit quote). It is kept bare only when it is a plain token and
// is otherwise Go-quoted ASCII-only, so the escapes reach the reader and a
// caller-chosen bundle id can never paint the terminal. JSON output needs
// nothing: encoding/json escapes control runes itself.
func safe(v string) string {
	if summaryBareRE.MatchString(v) {
		return v
	}
	return strconv.QuoteToASCII(v)
}

// printable renders untrusted text (a timestamp /usr/bin/log gave us that
// we could not parse) with every non-ASCII or control rune escaped.
func printable(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

// matchLog applies the user's filters to parsed fields. --target accepts
// the full target ("ssh:github") or the key name ("github").
func matchLog(f map[string]string, target, caller, decision string) bool {
	if target != "" && f["target"] != target && f["target"] != "ssh:"+target {
		return false
	}
	if decision != "" && f["decision"] != decision {
		return false
	}
	if caller != "" && !strings.Contains(f["app"], caller) && !strings.Contains(f["chain"], caller) {
		return false
	}
	return true
}

// callerName is the app bundle id when there is one, else the first
// process of the chain, else "unknown".
func callerName(f map[string]string) string {
	if f["app"] != "" {
		return f["app"]
	}
	if c := f["chain"]; c != "" {
		first, _, _ := strings.Cut(c, " > ")
		name, _, _ := strings.Cut(first, "(")
		return name
	}
	return "unknown"
}

func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s x%d", safe(k), m[k])
	}
	return strings.Join(parts, ", ")
}
