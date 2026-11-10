package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

// logLine is one line of the audit file, written at.
func logLine(at time.Time, msg string) string {
	return at.UTC().Format(time.RFC3339Nano) + " " + msg + "\n"
}

// writeAuditFile makes ~/.nazar/log/audit.log (or .1) with body.
func writeAuditFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, body)
}

// noMacLog fails the test if the Linux path reaches anything of the macOS
// log: /usr/bin/log or the check of the sender's image.
func noMacLog(t *testing.T, h *harness) {
	h.a.runLog = func(context.Context, []string, func([]byte)) error {
		t.Error("ran /usr/bin/log on Linux")
		return nil
	}
	h.a.imageUUID = func(string) (string, error) {
		t.Error("read an image UUID on Linux")
		return "", errors.New("no")
	}
	h.a.executable = func() (string, error) {
		t.Error("located the app on Linux")
		return "", errors.New("no")
	}
}

func TestLinuxLogReadsFile(t *testing.T) {
	h := linuxHarness(t)
	noMacLog(t, h)
	p := layout.AuditLog(h.home)
	now := time.Now().Truncate(time.Second)
	recent := now.Add(-10 * time.Minute)
	writeAuditFile(t, p+".1",
		logLine(now.Add(-48*time.Hour), "decision=allowed target=ssh:ancient app=com.old")+
			logLine(now.Add(-2*time.Hour), `decision=allowed reason="cached approval" target=ssh:github app=org.kde.konsole`))
	writeAuditFile(t, p,
		"not a line at all\n"+
			"\n"+
			logLine(recent, "garbage without fields")+
			logLine(recent, "decision=allowed target=\x1b[2Jhidden")+
			"2026-13-99T00:00:00Z decision=allowed target=ssh:badstamp\n"+
			"decision=allowed target=ssh:nostamp\n"+
			logLine(recent, `decision=blocked target=ssh:github chain="python3(9) > ssh(10)"`)+
			logLine(recent.Add(time.Minute), "decision=approved target=ssh:hydra app=org.kde.konsole"))

	if code := h.run("log"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	stamp := func(at time.Time) string { return at.Local().Format("2006-01-02 15:04:05") }
	want := stamp(now.Add(-2*time.Hour)) + ` decision=allowed reason="cached approval" target=ssh:github app=org.kde.konsole` + "\n" +
		stamp(recent) + ` decision=blocked target=ssh:github chain="python3(9) > ssh(10)"` + "\n" +
		stamp(recent.Add(time.Minute)) + " decision=approved target=ssh:hydra app=org.kde.konsole\n"
	if h.out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", h.out, want)
	}

	if code := h.run("log", "--since", "1h"); code != 0 || strings.Contains(h.out.String(), "cached approval") || strings.Count(h.out.String(), "\n") != 2 {
		t.Fatalf("--since 1h: exit %d\n%s", code, h.out)
	}
	if code := h.run("log", "--since", "7d"); code != 0 || !strings.Contains(h.out.String(), "ssh:ancient") {
		t.Fatalf("--since 7d: exit %d\n%s", code, h.out)
	}
	if code := h.run("log", "--target", "hydra"); code != 0 || !strings.Contains(h.out.String(), "ssh:hydra") || strings.Contains(h.out.String(), "ssh:github") {
		t.Fatalf("--target: exit %d\n%s", code, h.out)
	}
	if code := h.run("log", "--caller", "python3"); code != 0 || strings.Count(h.out.String(), "\n") != 1 || !strings.Contains(h.out.String(), "python3") {
		t.Fatalf("--caller: exit %d\n%s", code, h.out)
	}
	if code := h.run("log", "--decision", "blocked"); code != 0 || strings.Count(h.out.String(), "\n") != 1 || !strings.Contains(h.out.String(), "decision=blocked") {
		t.Fatalf("--decision: exit %d\n%s", code, h.out)
	}

	// --json, as on macOS.
	if code := h.run("--json", "log", "--decision", "blocked"); code != 0 {
		t.Fatalf("--json: exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindAuditEvent {
		t.Fatalf("%s", h.out)
	}
	var ev control.AuditEvent
	if err := json.Unmarshal(h.out.Bytes(), &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Time.Equal(recent) || ev.Fields["decision"] != "blocked" || ev.Fields["target"] != "ssh:github" || ev.Fields["chain"] != "python3(9) > ssh(10)" {
		t.Fatalf("%+v", ev)
	}

	// The summary, in both views.
	if code := h.run("log", "summary"); code != 0 || !strings.Contains(h.out.String(), "TARGET") || !strings.Contains(h.out.String(), "ssh:github") || !strings.Contains(h.out.String(), "org.kde.konsole x1") {
		t.Fatalf("summary: exit %d\n%s", code, h.out)
	}
	if code := h.run("--json", "log", "summary", "--since", "1h"); code != 0 || !strings.Contains(h.out.String(), `"target":"ssh:github","total":1`) || !strings.Contains(h.out.String(), `"python3":1`) {
		t.Fatalf("summary --json: exit %d\n%s", code, h.out)
	}
}

// What the file sink writes is what `nazar log` reads.
func TestLinuxLogReadsWhatTheSinkWrites(t *testing.T) {
	h := linuxHarness(t)
	noMacLog(t, h)
	s := &audit.FileSink{Path: layout.AuditLog(h.home), MaxBytes: 200}
	l := audit.NewLogger(s, audit.Formatter{}, func(err error) { t.Error(err) })
	for i := range 6 { // rotates once
		l.Log(audit.Event{Time: time.Now(), Decision: audit.Blocked, Target: fmt.Sprintf("ssh:k%d", i)})
	}
	if code := h.run("log"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	lines := strings.Split(strings.TrimSuffix(h.out.String(), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("%d lines:\n%s", len(lines), h.out)
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, fmt.Sprintf("decision=blocked target=ssh:k%d", i)) {
			t.Errorf("line %d out of order: %q", i, line)
		}
	}
}

// A line the sink is still writing has no newline yet: it is not an entry.
func TestLinuxLogSkipsAnUnfinishedLine(t *testing.T) {
	h := linuxHarness(t)
	now := time.Now()
	writeAuditFile(t, layout.AuditLog(h.home), logLine(now, "decision=blocked target=ssh:one")+strings.TrimSuffix(logLine(now, "decision=allowed target=ssh:tw"), "\n"))
	if code := h.run("log"); code != 0 || strings.Contains(h.out.String(), "ssh:tw") || !strings.Contains(h.out.String(), "ssh:one") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
}

// A rotation between the two reads loses nothing and shows nothing twice.
func TestLinuxLogRotationWhileReading(t *testing.T) {
	h := linuxHarness(t)
	p := layout.AuditLog(h.home)
	now := time.Now()
	writeAuditFile(t, p+".1", logLine(now, "decision=allowed target=ssh:oldest"))
	writeAuditFile(t, p, logLine(now, "decision=allowed target=ssh:middle"))
	rotated := false
	h.a.readAuditFile = func(path string, off int64) ([]byte, os.FileInfo, error) {
		data, fi, err := readAuditFrom(path, off)
		if !rotated {
			rotated = true
			if err := os.Rename(p, p+".1"); err != nil {
				t.Fatal(err)
			}
			writeFile(t, p, logLine(now, "decision=allowed target=ssh:newest"))
		}
		return data, fi, err
	}
	if code := h.run("log"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	if strings.Count(out, "ssh:middle") != 1 || strings.Count(out, "ssh:newest") != 1 {
		t.Fatalf("%s", out)
	}
}

func TestLinuxLogNoFile(t *testing.T) {
	h := linuxHarness(t)
	noMacLog(t, h)
	for _, args := range [][]string{{"log"}, {"log", "--since", "1h"}, {"--json", "log"}, {"--json", "log", "summary"}} {
		if code := h.run(args...); code != 0 || h.out.Len() != 0 || h.errb.Len() != 0 {
			t.Fatalf("%v: exit %d, out %q, err %q", args, code, h.out, h.errb)
		}
	}
	if code := h.run("log", "summary"); code != 0 || !strings.HasPrefix(h.out.String(), "TARGET") || strings.Count(h.out.String(), "\n") != 1 {
		t.Fatalf("summary: exit %d %q", code, h.out)
	}
	// Only .1 there, between a rotation and the next write.
	writeAuditFile(t, layout.AuditLog(h.home)+".1", logLine(time.Now(), "decision=allowed target=ssh:github"))
	if code := h.run("log"); code != 0 || !strings.Contains(h.out.String(), "ssh:github") {
		t.Fatalf("only .1: exit %d %q", code, h.out)
	}
}

// Anything but a missing file is an error, not an empty log.
func TestLinuxLogUnreadable(t *testing.T) {
	h := linuxHarness(t)
	h.a.readAuditFile = func(string, int64) ([]byte, os.FileInfo, error) {
		return nil, nil, errors.New("permission denied")
	}
	if code := h.run("log"); code != control.ExitError || !strings.Contains(h.errb.String(), "reading the audit log: permission denied") {
		t.Fatalf("exit %d, stderr %q", code, h.errb)
	}
	// A FIFO left there never hangs the command.
	h = linuxHarness(t)
	p := layout.AuditLog(h.home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() { done <- h.run("log") }()
	select {
	case code := <-done:
		if code != control.ExitError || !strings.Contains(h.errb.String(), "not a regular file") {
			t.Fatalf("exit %d, stderr %q", code, h.errb)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nazar log blocked on a FIFO")
	}
}

func TestLinuxLogSummaryCantFollow(t *testing.T) {
	h := linuxHarness(t)
	if code := h.run("log", "summary", "--follow"); code != control.ExitUsage || !strings.Contains(h.errb.String(), "log summary can't --follow") {
		t.Fatalf("exit %d, stderr %q", code, h.errb)
	}
}

// lockedBuffer is stdout for a command that runs beside its test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// following runs `nazar log --follow` until the test ends it. Each read of
// the file holds gate, so a test can make several changes between two polls.
type following struct {
	t       *testing.T
	out     lockedBuffer
	gate    sync.Mutex
	started chan struct{}
	done    chan int
	code    int
	ended   bool
}

func follow(t *testing.T, h *harness, args ...string) *following {
	t.Helper()
	f := &following{t: t, started: make(chan struct{}), done: make(chan int, 1)}
	h.a.stdout = &f.out
	var once sync.Once
	h.a.readAuditFile = func(path string, off int64) ([]byte, os.FileInfo, error) {
		f.gate.Lock()
		defer f.gate.Unlock()
		defer once.Do(func() { close(f.started) })
		return readAuditFrom(path, off)
	}
	go func() { f.done <- h.a.run(append([]string{"log", "--follow"}, args...)) }()
	select {
	case <-f.started:
	case code := <-f.done:
		t.Fatalf("ended at once: exit %d %s", code, h.errb)
	case <-time.After(10 * time.Second):
		t.Fatal("did not start")
	}
	t.Cleanup(func() { f.stop() })
	return f
}

// waitFor waits until the output holds s, and returns all of it.
func (f *following) waitFor(s string) string {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if out := f.out.String(); strings.Contains(out, s) {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatalf("no %q in:\n%s", s, f.out.String())
	return ""
}

// stop interrupts the command, as ^C does, and returns its exit code. The
// command has its signal handler from before its first read until it ends:
// a command that ended already must not get the signal, which would then
// end this test binary.
func (f *following) stop() int {
	f.t.Helper()
	if f.ended {
		return f.code
	}
	f.ended = true
	select {
	case f.code = <-f.done:
		return f.code
	default:
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		f.t.Fatal(err)
	}
	select {
	case f.code = <-f.done:
		return f.code
	case <-time.After(10 * time.Second):
		f.t.Fatal("still running after the signal")
		return -1
	}
}

func TestLinuxLogFollow(t *testing.T) {
	h := linuxHarness(t)
	noMacLog(t, h)
	p := layout.AuditLog(h.home)
	writeAuditFile(t, p, logLine(time.Now(), "decision=allowed target=ssh:before"))
	f := follow(t, h)
	s := &audit.FileSink{Path: p, MaxBytes: 600}
	write := func(target string) {
		t.Helper()
		if err := s.WriteAudit(time.Now(), "decision=allowed target="+target); err != nil {
			t.Fatal(err)
		}
	}

	// A line appended after the start is printed; what was there is not, as
	// with macOS's `log stream`. A junk line is dropped.
	write("ssh:first")
	f.waitFor("ssh:first")
	fh, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(fh, "junk\n")
	fh.Close()
	write("ssh:second")
	f.waitFor("ssh:second")

	// One rotation, with lines the poll has not seen on both sides of it.
	f.gate.Lock()
	var want []string
	for i := range 12 {
		name := fmt.Sprintf("ssh:rot%02d", i)
		write(name)
		want = append(want, name)
	}
	f.gate.Unlock()
	if fi, err := os.Stat(p + ".1"); err != nil || fi.Size() == 0 {
		t.Fatalf("no rotation: %v %v", fi, err)
	}
	out := f.waitFor(want[len(want)-1])
	at := 0
	for _, name := range want {
		i := strings.Index(out[at:], name)
		if i < 0 {
			t.Fatalf("%s missing or out of order:\n%s", name, out)
		}
		at += i
	}

	// And the file after the rotation keeps being followed.
	write("ssh:after")
	out = f.waitFor("ssh:after")
	if strings.Contains(out, "ssh:before") || strings.Contains(out, "junk") {
		t.Fatalf("%s", out)
	}
	for _, name := range []string{"ssh:first", "ssh:second", "ssh:rot00", "ssh:rot11", "ssh:after"} {
		if strings.Count(out, name) != 1 {
			t.Fatalf("%s printed %d times:\n%s", name, strings.Count(out, name), out)
		}
	}
	if code := f.stop(); code != 0 {
		t.Fatalf("exit %d after the interrupt", code)
	}
}

func TestLinuxLogFollowFilters(t *testing.T) {
	h := linuxHarness(t)
	p := layout.AuditLog(h.home)
	f := follow(t, h, "--json", "--decision", "blocked")
	s := &audit.FileSink{Path: p}
	for _, m := range []string{"decision=allowed target=ssh:no", "decision=blocked target=ssh:yes"} {
		if err := s.WriteAudit(time.Now(), m); err != nil {
			t.Fatal(err)
		}
	}
	out := f.waitFor("ssh:yes")
	objs := jsonLines(t, out)
	if len(objs) != 1 || objs[0]["kind"] != control.KindAuditEvent || strings.Contains(out, "ssh:no") {
		t.Fatalf("%s", out)
	}
}

// Started before there is any file (the agent has logged nothing yet), it
// shows the first lines from the top of the file when it appears.
func TestLinuxLogFollowNoFileYet(t *testing.T) {
	h := linuxHarness(t)
	f := follow(t, h)
	if err := (&audit.FileSink{Path: layout.AuditLog(h.home)}).WriteAudit(time.Now(), "decision=allowed target=ssh:first"); err != nil {
		t.Fatal(err)
	}
	f.waitFor("ssh:first")
	if code := f.stop(); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// The file cut short or removed by hand: following goes on from its top.
func TestLinuxLogFollowFileCutOrRemoved(t *testing.T) {
	h := linuxHarness(t)
	p := layout.AuditLog(h.home)
	now := time.Now()
	writeAuditFile(t, p, logLine(now, "decision=allowed target=ssh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	f := follow(t, h)
	// Cut shorter than where the poll was, in place.
	writeFile(t, p, logLine(now, "decision=allowed target=ssh:cut"))
	f.waitFor("ssh:cut")
	// Removed, then made again. The .1 it did not come from is not printed.
	writeAuditFile(t, p+".1", logLine(now, "decision=allowed target=ssh:stale"))
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * auditPoll)
	writeFile(t, p, logLine(now, "decision=allowed target=ssh:again"))
	out := f.waitFor("ssh:again")
	if strings.Contains(out, "ssh:stale") {
		t.Fatalf("%s", out)
	}
}

// A read that fails while following ends the command with the error.
func TestLinuxLogFollowReadError(t *testing.T) {
	h := linuxHarness(t)
	calls := 0
	h.a.readAuditFile = func(path string, off int64) ([]byte, os.FileInfo, error) {
		calls++
		if calls > 1 {
			return nil, nil, errors.New("input/output error")
		}
		return readAuditFrom(path, off)
	}
	if code := h.a.run([]string{"log", "--follow"}); code != control.ExitError || !strings.Contains(h.errb.String(), "reading the audit log: input/output error") {
		t.Fatalf("exit %d, stderr %q", code, h.errb)
	}
}

// macOS reads only its own log, and its words stay.
func TestMacLogNeverReadsTheFile(t *testing.T) {
	h := newHarness(t)
	writeAuditFile(t, layout.AuditLog(h.home), logLine(time.Now(), "decision=allowed target=ssh:file"))
	h.a.readAuditFile = func(string, int64) ([]byte, os.FileInfo, error) {
		t.Error("macOS read the audit file")
		return nil, nil, errors.New("no")
	}
	ran := false
	h.a.runLog = func(context.Context, []string, func([]byte)) error { ran = true; return nil }
	if code := h.run("log"); code != 0 || !ran || h.out.Len() != 0 {
		t.Fatalf("exit %d, ran %v, %q", code, ran, h.out)
	}
	if code := h.run("log", "--help"); code != 0 || !strings.Contains(h.out.String(), "Show nazar's entries in the macOS log") || !strings.Contains(h.out.String(), "entries written by nazar-agent itself are shown.") {
		t.Fatalf("macOS help:\n%s", h.out)
	}
}

// On Linux the help says where the entries are, and promises no check of
// who wrote them: there is none.
func TestLinuxLogHelp(t *testing.T) {
	h := linuxHarness(t)
	if code := h.run("log", "--help"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	if strings.Contains(out, "macOS") || strings.Contains(out, "written by nazar-agent itself") || !strings.Contains(out, "~/.nazar/log/audit.log") {
		t.Fatalf("%s", out)
	}
	if code := h.run("log", "summary", "--help"); code != 0 || strings.Contains(h.out.String(), "macOS") || !strings.Contains(h.out.String(), "audit log") {
		t.Fatalf("summary: exit %d\n%s", code, h.out)
	}
}
