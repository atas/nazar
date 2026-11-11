package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/secrets/envpolicy"
	"github.com/atas/nazar/core/secrets/run"
	"github.com/atas/nazar/core/unixsock"
	"github.com/atas/nazar/loaders"
)

// secret.run, the agent's half of `nazar run --secret NAME -- cmd…`
// (secrets design 6.3; D1, D2, D8–D10). The agent resolves the
// command line itself, builds the receiver's whole environment, asks, and
// replies with the RunPlan the CLI execs. The value never travels on the
// control socket: it waits on a per-run socket and goes to exactly one
// peer, after the agent saw the CLI's exec and found the exec'd process
// to be the plan: the exec'd process itself for an interpreter, a bin of
// the target package below it for npx.

const (
	// errRunUnavailable refuses late-env in an agent built without the
	// exec seam or the loaders (D8, D9).
	errRunUnavailable = "late-env is not available in this nazar-agent"
	// errMounted refuses a run during which a volume was mounted or
	// unmounted (D12): a mount over a folder hides what it holds without
	// changing a pin.
	errMounted = "receiver changed at exec: a volume was mounted or unmounted"
	// errUnexpectedPeer is the audit reason of a refused socket peer.
	errUnexpectedPeer = "unexpected socket peer"
	// runWriteTimeout bounds writing the one line to the accepted peer.
	runWriteTimeout = 5 * time.Second
	// runMaxPeerLines bounds the refused-peer audit lines of one run.
	runMaxPeerLines = 16
)

// runArgs are the only arguments secret.run takes: the request never
// chooses a directory (6.3.7), a loader or a target.
var runArgs = map[string]bool{"name": true, "argv": true, "callerEnv": true}

// defaultRunHost reads the receiver's home and user name from the user
// database, never from the caller, and the per-user temporary directory
// from the agent's own environment (launchd's). Only the agent's own user
// is served: the control socket accepts no one else.
func defaultRunHost(uid int) (envpolicy.Host, error) {
	if uid != os.Getuid() {
		return envpolicy.Host{}, fmt.Errorf("uid %d is not the agent's user", uid)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return envpolicy.Host{}, err
	}
	h := envpolicy.Host{Home: u.HomeDir, User: u.Username}
	if t := os.Getenv("TMPDIR"); filepath.IsAbs(t) {
		h.TmpDir = t
	}
	return h, nil
}

// loaderOK reports whether dir can be written into NODE_OPTIONS and
// PYTHONPATH as is: a clean absolute realpath without a quote, a
// backslash, a path-list separator or a control character, so neither
// Node's option parser nor Python's path splitting can read it as more
// than one path.
func loaderOK(dir string) bool {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.ContainsAny(dir, "\"\\:") || !utf8.ValidString(dir) {
		return false
	}
	for _, r := range dir {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	real, err := filepath.EvalSymlinks(dir)
	return err == nil && real == dir
}

// loaderSHA256 is what each loader must hash to: the copy this nazar-agent
// was built with (package loaders), part of its own code.
var loaderSHA256 = map[run.Family]string{run.FamilyNode: hexSum(loaders.Node), run.FamilyPython: hexSum(loaders.Python)}

func hexSum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// loader is what makes the receiver's runtime run nazar's loader (6.3.3):
// its variables, and the loader file, its folder and every folder above
// that the user can move, pinned. The file must be byte for byte
// the copy this nazar-agent was built with, and its folder must hold
// nothing else: CPython imports a package, an extension or cached bytecode
// beside its loader first. All are checked again at the exec and right
// before the write, so a loader changed, joined by another file, or
// swapped by moving a folder above it aside, at any moment in between is
// never served, even if put back. loaderOK leaves nothing in the path to
// escape.
func (d *Daemon) loader(fam run.Family) ([]string, []run.File, bool) {
	dir := d.o.LoaderDir
	if !loaderOK(dir) {
		return nil, nil, false
	}
	var sub, name string
	var vars []string
	switch fam {
	case run.FamilyNode:
		sub, name = "node", "env.cjs"
		// --disable-sigusr1: otherwise any process of the user can send
		// SIGUSR1, which opens Node's inspector, and read process.env over
		// it. Node older than 22.14 refuses the flag and does not start.
		vars = []string{"NODE_OPTIONS=--disable-sigusr1 --require \"" + filepath.Join(dir, sub, name) + "\""}
	case run.FamilyPython:
		sub, name = "python", "sitecustomize.py"
		// PYTHONDONTWRITEBYTECODE: otherwise Python writes __pycache__
		// beside the loader, into the signed bundle, and the folder pin
		// refuses every later run. The loader removes it again, so the
		// receiver's children write bytecode as usual.
		vars = []string{"PYTHONPATH=" + filepath.Join(dir, sub), "PYTHONDONTWRITEBYTECODE=1"}
	default:
		return nil, nil, false
	}
	folder, err := run.PinDir(filepath.Join(dir, sub), name)
	if err != nil {
		return nil, nil, false
	}
	file, err := run.Pin(filepath.Join(dir, sub, name))
	if err != nil || file.SHA256 != loaderSHA256[fam] {
		return nil, nil, false
	}
	above, err := run.PinAbove(folder.Path)
	if err != nil {
		return nil, nil, false
	}
	return vars, append([]run.File{folder, file}, above...), true
}

// runSocket is a fresh per-run socket path under the agent's own
// ~/.nazar/run (unixsock.Listen makes and checks the 0700 folder).
func (d *Daemon) runSocket() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	p := filepath.Join(layout.RunDir(d.o.Home), hex.EncodeToString(b[:])+".sock")
	if len(p) > unixsock.MaxPathLen {
		return "", fmt.Errorf("the socket path %s is longer than %d bytes", p, unixsock.MaxPathLen)
	}
	return p, nil
}

// runProblem turns a refusal before the gate into one blocked audit line
// and the CLI's Problem.
func (d *Daemon) runProblem(name string, peer *caller.Chain, code, msg string) error {
	d.broker.Refuse(broker.Request{Secret: name, Delivery: config.DeliverLateEnv, Chain: peer, Operation: "nazar run"}, msg)
	if code == control.CodeUsage {
		return control.NewProblem(code, "%s", msg)
	}
	return control.NewProblem(code, "refused: %s", msg)
}

// secretRun serves secret.run. Serve has checked the peer is the genuine
// CLI. Every refusal but the policy's comes before the gate; once the plan
// is emitted the CLI execs, so nothing more is said on this connection and
// the outcome is the audit line.
func (d *Daemon) secretRun(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	if _, ok := args["cwd"]; ok {
		return control.NewProblem(control.CodeUsage, "nazar run takes no cwd: the command always runs in /")
	}
	for k := range args {
		if !runArgs[k] {
			return control.NewProblem(control.CodeUsage, "secret.run: unknown argument %s", strconv.QuoteToASCII(k))
		}
	}
	name := args["name"]
	if !config.ValidSecretName(name) {
		return control.NewProblem(control.CodeUsage, "invalid secret name %q", name)
	}
	var argv, callerEnv []string
	if err := json.Unmarshal([]byte(args["argv"]), &argv); err != nil || len(argv) == 0 {
		return control.NewProblem(control.CodeUsage, "secret.run: argv must be a non-empty list of strings")
	}
	if a := args["callerEnv"]; a != "" {
		if err := json.Unmarshal([]byte(a), &callerEnv); err != nil {
			return control.NewProblem(control.CodeUsage, "secret.run: callerEnv must be a list of strings")
		}
	}
	if peer == nil {
		peer = &caller.Chain{Unknown: true}
	}
	cli, ok := peer.Peer()
	if !ok || cli.Ref.IsZero() {
		return d.runProblem(name, peer, control.CodeRefused, "the nazar CLI could not be identified")
	}
	if d.o.Exec == nil || d.o.Mounts == nil || d.o.LoaderDir == "" {
		return d.runProblem(name, peer, control.CodeRefused, errRunUnavailable)
	}
	info, err := d.secrets.Get(name)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		d.logOp("secret:"+name, audit.Error, "nazar run: no such secret", peer)
		return control.NewProblem(control.CodeError, "no secret named %q", name)
	case err != nil:
		return err
	case info.Broken:
		d.logOp("secret:"+name, audit.Error, "nazar run: the secret's record is unusable", peer)
		return control.NewProblem(control.CodeError, "secret %s can't be used: %s; fix: %s", name, d.vault.secretReason(info), d.vault.secretRemedy(name))
	}
	// Every mount and unmount from here to the write is seen (D12): the
	// watch is on before the first pin is taken.
	mounted, unwatch, err := d.o.Mounts.WatchMounts()
	if err != nil {
		return d.runProblem(name, peer, control.CodeRefused, "nazar run: the volumes can't be watched")
	}
	defer unwatch()
	c := d.stager.Active()
	resolver := &run.Resolver{TrustedPath: c.Defaults.TrustedPath, CodeHash: d.o.Platform.CodeHash, ShimDirs: d.o.ShimDirs}
	res, err := resolver.Resolve(argv)
	if err != nil {
		var rf *run.Refusal
		if errors.As(err, &rf) && rf.Usage {
			return d.runProblem(name, peer, control.CodeUsage, "nazar run: "+rf.Msg)
		}
		return d.runProblem(name, peer, control.CodeRefused, "nazar run: "+err.Error())
	}
	loader, pins, ok := d.loader(res.Family)
	if !ok {
		return d.runProblem(name, peer, control.CodeRefused, errRunUnavailable+": its loaders are missing or were changed")
	}
	host, err := d.o.RunHost(cli.UID)
	if err != nil || !filepath.IsAbs(host.Home) || host.User == "" {
		return d.runProblem(name, peer, control.CodeRefused, "nazar run: the home folder or user name of the receiver could not be read")
	}
	sock, err := d.runSocket()
	if err != nil {
		return d.runProblem(name, peer, control.CodeRefused, "nazar run: "+err.Error())
	}
	var allow []string
	if s, ok := c.Secrets[name]; ok {
		allow = s.EnvAllow
	}
	stable := append(loader, "NAZAR_SECRET_NAMES="+name)
	if res.Target != "" {
		stable = append(stable, "NAZAR_TARGET="+res.Target)
	}
	stableEnv, passed := envpolicy.Build(envpolicy.Input{TrustedPath: c.Defaults.TrustedPath, Host: host, CallerEnv: callerEnv, Allow: allow, Loader: stable})
	env := append(slices.Clone(stableEnv), "NAZAR_SECRET_SOCK="+sock, "NAZAR_RUN_PID="+strconv.Itoa(cli.Ref.PID))
	plan, err := runPlan(res, env)
	if err != nil {
		return d.runProblem(name, peer, control.CodeRefused, "nazar run: "+err.Error())
	}
	h := &handover{d: d, name: name, res: res, resolver: resolver, plan: plan, cli: cli.Ref, sock: sock, loader: pins, mounted: mounted}
	built := c.Hash
	var emitted bool
	r := d.broker.Handle(broker.Request{
		Secret: name, Delivery: config.DeliverLateEnv, Chain: peer,
		Receiver:  caller.Synthetic(res.Receiver(stableEnv)),
		Summary:   "nazar run " + strings.Join(audit.RedactArgs(argv), " "),
		Operation: "nazar run", EnvPassed: passed,
		Do: func(ref platform.ApprovalRef) error {
			// A change applied while the prompt was open (a tightening
			// applies at once) is not in the plan: run nothing.
			if d.stager.Active().Hash != built {
				return errors.New("config.yaml changed while the prompt was open; nothing was run")
			}
			return h.run(ref, func() error {
				emitted = true
				return out.Emit(plan)
			})
		},
	})
	if emitted {
		return nil // the CLI has exec'd: the audit line is the outcome
	}
	return resultProblem(r)
}

// runPlan is what the CLI execs: the image's realpath and the resolver's
// argv, in /, with env; and the identities of every pinned file, which the
// CLI compares with its own fstat right before execve.
func runPlan(res *run.Resolution, env []string) (control.RunPlan, error) {
	var st syscall.Stat_t
	if err := syscall.Stat("/", &st); err != nil {
		return control.RunPlan{}, err
	}
	p := control.RunPlan{TypeMeta: control.Meta(control.KindRunPlan), ExecPath: res.Image.Path, ExecArgv: res.ExecArgv, Env: env,
		Cwd: "/", CwdDev: uint64(st.Dev), CwdIno: uint64(st.Ino)}
	files := []run.File{res.Image}
	if res.Script != nil {
		files = append(files, *res.Script)
	}
	for _, f := range append(files, res.Files...) {
		p.Files = append(p.Files, control.RunFile{Path: f.Path, Dev: f.Dev, Ino: f.Ino, Size: f.Size, MtimeNs: f.MtimeNs, CtimeNs: f.CtimeNs})
	}
	return p, nil
}

// handover is one run's late-env handover (6.3 steps 5–7).
type handover struct {
	d        *Daemon
	name     string
	res      *run.Resolution
	resolver *run.Resolver
	plan     control.RunPlan
	cli      platform.ProcessRef
	sock     string
	loader   []run.File  // the loader's folder and file
	mounted  func() bool // a volume was mounted or unmounted since before the pins (D12)

	mu    sync.Mutex
	execs []platform.ProcessInfo // every exec of cli seen
	exec  chan struct{}          // a value per exec, never blocks
	gone  chan struct{}          // closed when cli exits
}

// runDenied is a refusal after the gate: decision=denied, and the approval
// the run went through is dropped (broker.DeniedError).
func runDenied(format string, args ...any) error {
	return &broker.DeniedError{Reason: fmt.Sprintf(format, args...)}
}

// errNeverConnected ends a run whose target did not connect: the deadline,
// or the process gone first.
var errNeverConnected = errors.New("target never connected")

// execCount is how many execs of the CLI were seen.
func (h *handover) execCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.execs)
}

// run is the broker's Do after the gate: it opens the value, listens,
// watches the CLI, emits the plan, checks the exec and serves one peer.
// Every refusal after the exec is a DeniedError: the approval goes.
func (h *handover) run(ref platform.ApprovalRef, emit func() error) error {
	d := h.d
	value, err := d.secrets.Open(h.name, ref)
	defer clear(value)
	if err != nil {
		return err
	}
	l, err := unixsock.Listen(h.sock)
	if err != nil {
		return err
	}
	defer l.Close() // unlinks the socket
	h.exec, h.gone = make(chan struct{}, 1), make(chan struct{})
	cancel, err := d.o.Exec.OnProcessExec(h.cli, func(p platform.ProcessInfo) {
		h.mu.Lock()
		h.execs = append(h.execs, p)
		h.mu.Unlock()
		select {
		case h.exec <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return errors.New("the nazar CLI could not be watched")
	}
	defer cancel()
	d.o.Platform.OnProcessExit(h.cli, func() { close(h.gone) })
	if err := emit(); err != nil {
		return err
	}
	if err := h.waitExec(); err != nil {
		return err
	}
	if err := h.checkExec(); err != nil {
		return err
	}
	return h.serve(l, value)
}

// waitExec waits for the CLI's first exec. An exec seen together with the
// exit still counts as an exec.
func (h *handover) waitExec() error {
	t := time.NewTimer(h.d.o.RunExecTimeout)
	defer t.Stop()
	select {
	case <-h.exec:
		return nil
	case <-h.gone:
	case <-t.C:
	case <-h.d.stopping:
		return errors.New("nazar-agent stopped")
	}
	if h.execCount() > 0 {
		return nil
	}
	return errors.New("target never exec'd")
}

// checkExec compares the process as read at its exec with the plan (6.3
// step 6, D10): the image, its code, argv, directory, environment and
// every pinned file.
func (h *handover) checkExec() error {
	h.mu.Lock()
	p, n := h.execs[0], len(h.execs)
	h.mu.Unlock()
	switch {
	case n > 1:
		return runDenied("receiver changed at exec: it exec'd again")
	case p.Ref != h.cli:
		return runDenied("receiver changed at exec: another process")
	}
	if err := h.samePlan(p); err != nil {
		return err
	}
	if err := h.checkEnv(); err != nil {
		return err
	}
	return h.recheck()
}

// samePlan compares a read of the CLI's process with the plan: the image,
// its code, argv and directory.
func (h *handover) samePlan(p platform.ProcessInfo) error {
	switch {
	case p.Path != h.plan.ExecPath:
		return runDenied("receiver changed at exec: another executable")
	case !slices.Equal(p.Code.CDHash, h.res.ImageCode):
		return runDenied("receiver changed at exec: other code")
	case !slices.Equal(p.Args, h.plan.ExecArgv):
		return runDenied("receiver changed at exec: another command line")
	case p.Cwd != h.plan.Cwd:
		return runDenied("receiver changed at exec: cwd is not %s", h.plan.Cwd)
	}
	return nil
}

// recheck finds every pinned file unchanged (run.Resolver.Recheck), and
// nazar's loader and the folders it pinned too.
func (h *handover) recheck() error {
	if err := h.resolver.Recheck(h.res); err != nil {
		return runDenied("receiver changed at exec: %s", err.Error())
	}
	for _, f := range h.loader {
		if run.Repin(f) != nil {
			return runDenied("receiver changed at exec: nazar's loader changed")
		}
	}
	// Last, so a mount while the files were read is seen too (D12).
	if h.mounted() {
		return runDenied(errMounted)
	}
	return nil
}

// sameExec reports whether the CLI's process is still the one checked at
// its exec: its environment still the plan's and no other exec seen.
// Environment hands every exec the platform has taken to the watcher before
// it answers (platform.Exec), so one still queued is counted too.
func (h *handover) sameExec() error {
	if err := h.checkEnv(); err != nil {
		return err
	}
	if h.execCount() > 1 {
		return runDenied("receiver changed at exec: it exec'd again")
	}
	return nil
}

// checkEnv compares the CLI's startup environment with the plan's as a
// set: nothing extra, nothing missing, no other value (6.3.4). Only names
// are reported.
func (h *handover) checkEnv() error {
	env, err := h.d.o.Exec.Environment(h.cli)
	if errors.Is(err, platform.ErrNoProcess) {
		return errNeverConnected
	}
	if err != nil {
		return runDenied("unexpected environment: not readable")
	}
	if names := envDiff(h.plan.Env, env); len(names) > 0 {
		return runDenied("unexpected environment: %s", strings.Join(names, ", "))
	}
	return nil
}

// maxEnvDiffNames bounds the names an environment refusal lists.
const maxEnvDiffNames = 5

// envDiff names, sorted, every variable that is not in both lists with
// the same one value; past maxEnvDiffNames, how many more.
func envDiff(want, got []string) []string {
	count := func(env []string) map[string][]string {
		m := map[string][]string{}
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = append(m[k], v)
		}
		return m
	}
	w, g := count(want), count(got)
	var out []string
	for k, gv := range g {
		if wv, ok := w[k]; !ok || !slices.Equal(wv, gv) {
			out = append(out, k)
		}
	}
	for k := range w {
		if _, ok := g[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	if len(out) > maxEnvDiffNames {
		out = append(out[:maxEnvDiffNames], fmt.Sprintf("and %d more", len(out)-maxEnvDiffNames))
	}
	return out
}

// serve accepts connections until one peer passes, the CLI exits, a second
// exec of the CLI, or the deadline. A refused peer is closed unanswered
// and does not consume the handover; it is audited once per pid, for at
// most runMaxPeerLines pids, then once with the count.
func (h *handover) serve(l *net.UnixListener, value []byte) error {
	d := h.d
	done := make(chan struct{})
	defer close(done)
	conns := make(chan *net.UnixConn)
	go func() {
		for {
			c, err := l.AcceptUnix()
			if err != nil {
				return
			}
			select {
			case conns <- c:
			case <-done:
				c.Close()
				return
			}
		}
	}()
	t := time.NewTimer(d.o.RunHandoverTimeout)
	defer t.Stop()
	refused, unlogged := map[int]bool{}, 0
	defer func() {
		if unlogged > 0 {
			h.refusePeer(nil, fmt.Sprintf("%s: %d more processes refused", errUnexpectedPeer, unlogged))
		}
	}()
	for {
		select {
		case c := <-conns:
			if err := h.sameExec(); err != nil {
				c.Close()
				return err
			}
			ok, who := h.peerOK(c)
			if !ok {
				c.Close()
				switch {
				case refused[who.PID]:
				case len(refused) >= runMaxPeerLines:
					refused[who.PID] = true
					unlogged++
				default:
					refused[who.PID] = true
					var chain *caller.Chain
					if !who.IsZero() {
						chain = d.resolver.Resolve(who)
					}
					h.refusePeer(chain, errUnexpectedPeer)
				}
				continue
			}
			// The last things before the write (6.3.3 b, D12): a file
			// swapped or a volume mounted while the interpreter started, or
			// another exec while the peer was judged, is never served.
			if err := h.recheck(); err != nil {
				c.Close()
				return err
			}
			if err := h.sameExec(); err != nil {
				c.Close()
				return err
			}
			err := h.write(c, value)
			c.Close()
			return err
		case <-h.exec:
			if h.execCount() > 1 {
				return runDenied("receiver changed at exec: it exec'd again")
			}
		case <-h.gone:
			return errNeverConnected
		case <-t.C:
			return errNeverConnected
		case <-d.stopping:
			return errors.New("nazar-agent stopped")
		}
	}
}

// refusePeer is the audit line of a refused socket peer: the run's
// secret, delivery and operation, the peer's chain.
func (h *handover) refusePeer(chain *caller.Chain, reason string) {
	h.d.broker.Refuse(broker.Request{Secret: h.name, Delivery: config.DeliverLateEnv, Chain: chain, Operation: "nazar run"}, reason)
}

// peerOK decides whether c's peer is the run's target: for an interpreter
// the exec'd process itself, read again now (a later image in its pid, an
// exec event not yet seen, must not pass) with its environment still the
// plan's; for npx a strict descendant of it running the pinned image with
// a bin of the target package as its main module (D2, run.IsBinOf).
func (h *handover) peerOK(c *net.UnixConn) (bool, platform.ProcessRef) {
	d := h.d
	var who platform.ProcessRef
	if err := unixsock.WithFD(c, func(fd int) error {
		var err error
		who, err = d.o.Platform.PeerOf(fd)
		return err
	}); err != nil || who.IsZero() {
		return false, platform.ProcessRef{}
	}
	if h.res.Kind == run.KindInterpreter {
		if who != h.cli {
			return false, who
		}
		p, err := d.o.Platform.Process(who)
		return err == nil && p.Ref == who && h.samePlan(p) == nil && h.checkEnv() == nil, who
	}
	if who == h.cli {
		return false, who // the launcher itself
	}
	chain := d.resolver.Resolve(who)
	p, ok := chain.Peer()
	if !ok || p.Ref != who || p.Path != h.res.Image.Path || len(p.Args) < 2 || !filepath.IsAbs(p.Args[1]) {
		return false, who
	}
	below := false
	for _, q := range chain.Procs[1:] {
		if q.Ref == h.cli {
			below = true
			break
		}
	}
	return below && run.IsBinOf(p.Args[1], h.res.Target), who
}

// write sends the one line, NAME\tbase64(value)\n, then EOF.
func (h *handover) write(c *net.UnixConn, value []byte) error {
	line := make([]byte, 0, len(h.name)+2+base64.StdEncoding.EncodedLen(len(value)))
	line = append(line, h.name...)
	line = append(line, '\t')
	line = base64.StdEncoding.AppendEncode(line, value)
	line = append(line, '\n')
	defer clear(line)
	_ = c.SetWriteDeadline(time.Now().Add(runWriteTimeout))
	if _, err := c.Write(line); err != nil {
		return fmt.Errorf("the handover failed: %w", err)
	}
	return nil
}

// sweepRunSockets removes the run sockets a stopped agent left in
// ~/.nazar/run (no run outlives the agent that served it). Only sockets
// with a run's name are removed.
func (d *Daemon) sweepRunSockets() {
	dir := layout.RunDir(d.o.Home)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if e.Type() != os.ModeSocket || len(n) != 37 || !strings.HasSuffix(n, ".sock") {
			continue
		}
		if _, err := hex.DecodeString(strings.TrimSuffix(n, ".sock")); err == nil {
			os.Remove(filepath.Join(dir, n))
		}
	}
}
