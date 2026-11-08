package conformance_test

// The platform conformance suite is an importable test helper
// that every Platform implementation runs (the fake here; the Swift
// platform in Milestone 3). These tests pin its API and prove it is not
// vacuous: the fake must pass, and deliberately broken platforms (each one
// violating a single clause of the contract in core/platform) must fail it.
//
// The API the tests expect from package conformance:
//
//	type Env struct {
//		P      platform.Platform
//		Answer func(allow bool)                // optional: the user's answer to the next Authenticate or Confirm
//		Spawn  func() platform.ProcessRef      // optional: start a new live process, return its ref
//		Exit   func(ref platform.ProcessRef)   // optional (with Spawn): end it; returns once it is gone
//		Peer   func() (fd int, pid int)        // optional: a connected socket fd and the PID of its peer
//	}
//	func Run(t *testing.T, newEnv func(t *testing.T) Env)
//
// newEnv is called for each subtest that needs a platform; subtests whose
// optional hook is nil are skipped, never failed.
//
// Contract clauses the suite must check (each broken variant below violates
// one of them, so a suite that skips a clause fails this file):
//   - keys: CreateKey gives a 65-byte 0x04 P-256 point and a handle; Sign is
//     DER ECDSA over SHA-256(digestInput) verifiable with that point;
//     unknown/empty/deleted handles are ErrNotFound; DeleteKey really
//     deletes; a key works only for its purpose; KeyAgreement equals local
//     ECDH and rejects malformed peer keys; out-of-range Purpose/AuthPolicy
//     is refused; an AuthNone key ignores the approval argument; a value
//     sealed with HPKE to a key-agreement key opens through KeyAgreement,
//     not through another key, and not after DeleteKey; a
//     Kubernetes CA (core/k8s) made on the platform's keys signs its own
//     certificate and one client certificate that verify with its public
//     key alone, a message of several hundred bytes, and its key no longer
//     signs after CAStore.Delete.
//   - approvals: an AuthUserPresence key needs a live ref from Authenticate:
//     zero, never-issued (including values next to a live ref), and released
//     refs are ErrAuthRequired and never panic; ReleaseApproval of zero,
//     unknown or already-released refs is a no-op; releasing one ref leaves
//     others live; ref values are never reused in-process (sequential
//     Authenticate/Release cycles and concurrent Authenticates); a denied
//     Authenticate is ErrDenied with ref 0; Confirm returns what the user
//     answered.
//   - processes: PeerOf gives the peer's PID with a non-zero Generation that
//     Process accepts (info.Ref equals it); Process is stable for a live
//     ref; a tampered generation of a live PID, an exited ref, the zero ref
//     and negative/absent PIDs are ErrNoProcess; Process({PID, 0}) (a
//     PID-only ref) answers the live occupant with its full, non-zero ref;
//     ProcessInfo.Parent is resolvable (PID-only or exact) and started no
//     later than the child; AppFor of nil, of non-app processes and of a
//     forged record (made-up ref, ".app/Contents/MacOS/" path) is false;
//     ResponsibleFor/CodeHash/InstalledApp of unknown inputs fail cleanly
//     (ok=false, ErrNotFound).
//   - events: OnProcessExit runs fn exactly once after Exit, and promptly
//     for an already-gone or never-existing ref; OnScreenLock and
//     ShowWarning return without blocking.
//   - exec (platform.Exec): every exec reported in order with the
//     same ref, the image's realpath, argv, folder and the file's code
//     hash; the environment exactly as given, only while watched,
//     ErrUnreadable when hidden or before a watched exec, never a list in
//     its place, ErrNoProcess when gone; an exec seen by every fn before
//     Environment answers for it; fn never after cancel; only the live
//     instance of a full ref is watched.
//   - mounts (platform.Mounts): a mount and unmount during a watch
//     is seen by every watch and stays seen; one before the watch, a file
//     change or a process is not; a stopped watch reports a change.
//   - pipes (platform.Pipes): StdoutReadBy is true for a child's
//     fd 1 piped to its parent, every time, and false with no error when
//     the pipe's read end is another process's (directly or through an
//     exec-hop relay), another process holds it or the write end too
//     (shared), or the parent inherited it rather than opening it (not
//     close-on-exec), and for a
//     file, a terminal, a socket, a pipe's read end and a closed fd 1; an
//     exited writer, a stale generation, a PID-only or zero ref of either
//     side is ErrNoProcess; it is not symmetric.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"github.com/atas/nazar/core/platform/fake"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

// fakeHarness drives one fresh fake through the Env hooks, and keeps the
// PID → live ref table some broken variants need.
type fakeHarness struct {
	f *fake.Fake

	mu     sync.Mutex
	queue  []bool
	live   map[int]platform.ProcessRef
	nextFD int
	piped  map[platform.ProcessRef]bool // writers whose fd 1 the stdout hook made a pipe
	shared map[platform.ProcessRef]bool // writers whose pipe's read end a third process holds too
	// writers whose pipe's write end a third process holds too
	cowritten map[platform.ProcessRef]bool
	// writers whose pipe's read end the reader inherited
	inherited map[platform.ProcessRef]bool
}

func newFakeHarness(t *testing.T) *fakeHarness {
	h := &fakeHarness{f: fake.New(t0), live: map[int]platform.ProcessRef{}, nextFD: 10, piped: map[platform.ProcessRef]bool{}, shared: map[platform.ProcessRef]bool{}, cowritten: map[platform.ProcessRef]bool{}, inherited: map[platform.ProcessRef]bool{}}
	h.live[h.f.Launchd.PID] = h.f.Launchd
	// One answer queue shared by both gates: Answer scripts "the next prompt".
	gate := func(platform.Prompt) fake.Answer {
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(h.queue) == 0 {
			return fake.Answer{} // unscripted: deny
		}
		a := h.queue[0]
		h.queue = h.queue[1:]
		return fake.Answer{Allow: a}
	}
	h.f.SetGateFuncs(gate, gate)
	return h
}

func (h *fakeHarness) answer(allow bool) {
	h.mu.Lock()
	h.queue = append(h.queue, allow)
	h.mu.Unlock()
}

func (h *fakeHarness) spawn() platform.ProcessRef {
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "60"}, Cwd: "/tmp"})
	h.mu.Lock()
	h.live[ref.PID] = ref
	h.mu.Unlock()
	return ref
}

func (h *fakeHarness) exit(ref platform.ProcessRef) {
	h.f.Exit(ref)
	h.mu.Lock()
	if h.live[ref.PID] == ref {
		delete(h.live, ref.PID)
	}
	h.mu.Unlock()
}

func (h *fakeHarness) peer() (int, int) {
	ref := h.spawn()
	h.mu.Lock()
	fd := h.nextFD
	h.nextFD++
	h.mu.Unlock()
	h.f.SetPeer(fd, ref)
	return fd, ref.PID
}

func (h *fakeHarness) occupant(pid int) (platform.ProcessRef, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.live[pid]
	return r, ok
}

func (h *fakeHarness) execer(env []string) conformance.Execer {
	ref, next := h.f.ExecScript(env)
	h.mu.Lock()
	h.live[ref.PID] = ref
	h.mu.Unlock()
	return conformance.Execer{Ref: ref, Next: func() conformance.Image { return conformance.Image(next()) }}
}

// launch starts a fake process under parent and records it as live.
func (h *fakeHarness) launch(parent platform.ProcessRef, p fake.Proc) platform.ProcessRef {
	ref := h.f.Launch(parent, p)
	h.mu.Lock()
	h.live[ref.PID] = ref
	h.mu.Unlock()
	return ref
}

// stdout is the conformance Stdout hook on the fake: each case scripted
// as the conformance host sets it up with real processes.
func (h *fakeHarness) stdout(t *testing.T, c conformance.StdoutCase) (platform.ProcessRef, platform.ProcessRef) {
	reader := h.spawn()
	sleep := fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "600"}, Cwd: "/"}
	pipe := func(w, r platform.ProcessRef) {
		h.f.SetStdout(w, r)
		h.mu.Lock()
		h.piped[w] = true
		h.mu.Unlock()
	}
	switch c {
	case conformance.StdoutPiped, conformance.StdoutGone:
		sleep.StdoutToParent = true
		w := h.launch(reader, sleep)
		h.mu.Lock()
		h.piped[w] = true
		h.mu.Unlock()
		if c == conformance.StdoutGone {
			h.exit(w)
		}
		return w, reader
	case conformance.StdoutSharedReadEnd:
		sleep.StdoutToParent = true
		w := h.launch(reader, sleep)
		h.launch(reader, fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "600"}, Cwd: "/"})
		h.f.SetStdoutForeign(w)
		h.mu.Lock()
		h.piped[w], h.shared[w] = true, true
		h.mu.Unlock()
		return w, reader
	case conformance.StdoutSharedWriteEnd:
		sleep.StdoutToParent = true
		w := h.launch(reader, sleep)
		h.launch(reader, fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "600"}, Cwd: "/"})
		h.f.SetStdoutForeign(w)
		h.mu.Lock()
		h.piped[w], h.cowritten[w] = true, true
		h.mu.Unlock()
		return w, reader
	case conformance.StdoutInheritedReadEnd:
		sleep.StdoutToParent = true
		w := h.launch(reader, sleep)
		h.f.SetStdoutForeign(w)
		h.mu.Lock()
		h.piped[w], h.inherited[w] = true, true
		h.mu.Unlock()
		return w, reader
	case conformance.StdoutPipedElsewhere:
		w := h.launch(reader, sleep)
		cat := h.launch(reader, fake.Proc{Path: "/bin/cat", StdoutToParent: true})
		pipe(w, cat)
		return w, reader
	case conformance.StdoutRelayed:
		w := h.launch(reader, fake.Proc{Path: "/bin/bash", Args: []string{"bash", "-c", "exec > >(exec /bin/cat); exec /bin/sleep 600"}, StdoutToParent: true})
		cat := h.launch(w, fake.Proc{Path: "/bin/cat"})
		pipe(cat, reader)
		pipe(w, cat)
		h.f.Exec(w, sleep, nil)
		return w, reader
	case conformance.StdoutFile, conformance.StdoutTerminal, conformance.StdoutSocket, conformance.StdoutReadEnd, conformance.StdoutClosed:
		return h.launch(reader, sleep), reader
	}
	t.Fatalf("unknown stdout case %q", c)
	return platform.ProcessRef{}, platform.ProcessRef{}
}

func (h *fakeHarness) isPiped(w platform.ProcessRef) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.piped[w]
}

func (h *fakeHarness) env(p platform.Platform) conformance.Env {
	env := conformance.Env{P: p, Answer: h.answer, Spawn: h.spawn, Exit: h.exit, Peer: h.peer}
	if x, ok := p.(platform.Exec); ok {
		env.Exec, env.Execer = x, h.execer
	}
	if m, ok := p.(platform.Mounts); ok {
		env.Mounts, env.Mount = m, func(*testing.T) { h.f.MountChange() }
	}
	if x, ok := p.(platform.Pipes); ok {
		env.Pipes, env.Stdout = x, h.stdout
	}
	return env
}

// The fake is the reference implementation in Milestones 1–2: it must pass
// the whole suite with every hook supplied.
func TestFakeConforms(t *testing.T) {
	conformance.Run(t, func(t *testing.T) conformance.Env {
		h := newFakeHarness(t)
		return h.env(h.f)
	})
}

// The optional hooks are optional: a platform that can't be driven without
// a human (no Answer) or can't spawn processes still runs the rest of the
// suite, and the skipped parts are skipped, not failed.
func TestSuiteRunsWithOnlyThePlatform(t *testing.T) {
	conformance.Run(t, func(t *testing.T) conformance.Env {
		return conformance.Env{P: newFakeHarness(t).f}
	})
}

// ---------------------------------------------------------------------------
// The suite must catch broken platforms. Each variant breaks exactly one
// clause of the contract; Run is executed in a child test process (a
// failing Run fails its *testing.T, and a panicking platform kills the
// process), and that child must fail.

const variantEnv = "NAZAR_CONFORMANCE_VARIANT"

// TestBrokenPlatformHelper is not a test on its own: it runs the suite
// against the variant named in $NAZAR_CONFORMANCE_VARIANT, in a child
// process started by TestSuiteCatchesBrokenPlatforms.
func TestBrokenPlatformHelper(t *testing.T) {
	name := os.Getenv(variantEnv)
	if name == "" {
		t.Skip("helper for TestSuiteCatchesBrokenPlatforms")
	}
	mk, ok := variants[name]
	if !ok {
		t.Fatalf("unknown variant %q", name)
	}
	conformance.Run(t, func(t *testing.T) conformance.Env {
		h := newFakeHarness(t)
		return h.env(mk(h))
	})
}

func runVariant(t *testing.T, name string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBrokenPlatformHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), variantEnv+"="+name)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("variant %s: child test process timed out:\n%s", name, out)
	}
	return string(out), err == nil
}

func TestSuiteCatchesBrokenPlatforms(t *testing.T) {
	if os.Getenv(variantEnv) != "" {
		t.Skip("running as the helper child")
	}
	// Control: the unbroken fake passes through the same harness, so a
	// failure below is the variant's fault, not the harness's.
	if out, ok := runVariant(t, "none"); !ok {
		t.Fatalf("control variant failed; the harness or the fake is broken:\n%s", out)
	}
	for name := range variants {
		if name == "none" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			out, ok := runVariant(t, name)
			if ok {
				t.Fatalf("conformance suite passed a platform that %s", describe[name])
			}
			if !strings.Contains(out, "--- FAIL") && !strings.Contains(out, "panic:") {
				t.Fatalf("child failed without a test failure or panic (wrong reason?):\n%s", out)
			}
		})
	}
}

var describe = map[string]string{
	"release-noop":             "keeps a released approval ref usable",
	"reuse-refs":               "reuses approval ref values after release",
	"unknown-ref-approves":     "treats a forged non-zero approval ref as an approval",
	"panic-unknown-ref":        "panics on an unknown approval ref",
	"denied-nonzero-ref":       "returns a non-zero approval ref with ErrDenied",
	"presence-downgraded":      "creates an AuthNone key when AuthUserPresence was asked for",
	"delete-noop":              "keeps a deleted key usable",
	"delete-keeps-agreement":   "keeps a deleted key-agreement key usable",
	"confirm-always-true":      "confirms whatever the user answered",
	"process-by-pid-only":      "answers Process for a stale generation with the PID's live occupant",
	"peer-pid-only":            "returns a PID-only (generation 0) peer ref",
	"zero-ref-resolves":        "resolves the zero ref to a process",
	"exit-fires-twice":         "runs an exit callback twice",
	"exit-never-if-gone":       "never runs an exit callback registered on a gone process",
	"appfor-trusts-record":     "attributes an app from a forged ProcessInfo record",
	"exec-after-cancel":        "calls an exec watcher after cancel returned",
	"exec-stale-env":           "answers an environment it can no longer read (a hidden image, after the last cancel)",
	"exec-hidden-empty":        "answers an empty list for an environment it cannot read",
	"exec-any-generation":      "watches whatever process holds the PID of a stale ref",
	"exec-late-event":          "answers Environment for an exec before any fn saw it",
	"mounts-never-seen":        "never reports a volume mounted during a watch",
	"mounts-forgotten":         "forgets a mount once changed reported it",
	"mounts-from-the-past":     "reports a mount from before the watch began",
	"mounts-open-on-stop":      "reports no change after the watch was stopped",
	"sign-prefix":              "signs only the first 64 bytes of a message",
	"pipes-any-reader":         "says yes for a stdout pipe whoever reads it",
	"pipes-parent-is-enough":   "says yes for any fd 1 of a child of the reader",
	"pipes-never":              "never says yes, even for a pipe the parent reads",
	"pipes-by-pid":             "answers for whatever process holds the PIDs of stale refs",
	"pipes-shared-read-end":    "says yes for a pipe the parent reads while another process holds its read end too",
	"pipes-inherited-read-end": "says yes for a pipe whose read end the parent inherited instead of opening it",
	"pipes-shared-write-end":   "says yes for a pipe the parent reads while another process holds its write end too",
}

var variants = map[string]func(h *fakeHarness) platform.Platform{
	"none":                   func(h *fakeHarness) platform.Platform { return h.f },
	"release-noop":           func(h *fakeHarness) platform.Platform { return releaseNoop{h.f} },
	"reuse-refs":             func(h *fakeHarness) platform.Platform { return newReuseRefs(h.f) },
	"unknown-ref-approves":   func(h *fakeHarness) platform.Platform { return newTracked(h.f, modeSubstitute) },
	"panic-unknown-ref":      func(h *fakeHarness) platform.Platform { return newTracked(h.f, modePanic) },
	"denied-nonzero-ref":     func(h *fakeHarness) platform.Platform { return deniedNonzero{h.f} },
	"presence-downgraded":    func(h *fakeHarness) platform.Platform { return presenceDowngraded{h.f} },
	"delete-noop":            func(h *fakeHarness) platform.Platform { return deleteNoop{h.f} },
	"delete-keeps-agreement": func(h *fakeHarness) platform.Platform { return newDeleteKeepsAgreement(h.f) },
	"confirm-always-true":    func(h *fakeHarness) platform.Platform { return confirmAlwaysTrue{h.f} },
	"process-by-pid-only":    func(h *fakeHarness) platform.Platform { return processByPID{h.f, h} },
	"peer-pid-only":          func(h *fakeHarness) platform.Platform { return peerPIDOnly{h.f} },
	"zero-ref-resolves":      func(h *fakeHarness) platform.Platform { return zeroRefResolves{h.f} },
	"exit-fires-twice":       func(h *fakeHarness) platform.Platform { return exitTwice{h.f} },
	"exit-never-if-gone":     func(h *fakeHarness) platform.Platform { return exitNeverIfGone{h.f} },
	"appfor-trusts-record":   func(h *fakeHarness) platform.Platform { return appForTrustsRecord{h.f} },
	"exec-after-cancel":      func(h *fakeHarness) platform.Platform { return execNoCancel{h.f} },
	"exec-stale-env": func(h *fakeHarness) platform.Platform {
		return &execStale{Fake: h.f, last: map[platform.ProcessRef][]string{}}
	},
	"exec-hidden-empty":        func(h *fakeHarness) platform.Platform { return execHiddenEmpty{h.f} },
	"exec-any-generation":      func(h *fakeHarness) platform.Platform { return execAnyGeneration{h.f, h} },
	"exec-late-event":          func(h *fakeHarness) platform.Platform { return execLateEvent{h.f} },
	"mounts-never-seen":        func(h *fakeHarness) platform.Platform { return mountsNeverSeen{h.f} },
	"mounts-forgotten":         func(h *fakeHarness) platform.Platform { return mountsForgotten{h.f} },
	"mounts-from-the-past":     func(h *fakeHarness) platform.Platform { return newMountsFromThePast(h.f) },
	"mounts-open-on-stop":      func(h *fakeHarness) platform.Platform { return mountsOpenOnStop{h.f} },
	"sign-prefix":              func(h *fakeHarness) platform.Platform { return signPrefix{h.f} },
	"pipes-any-reader":         func(h *fakeHarness) platform.Platform { return pipesAnyReader{h.f, h} },
	"pipes-parent-is-enough":   func(h *fakeHarness) platform.Platform { return pipesParentIsEnough{h.f} },
	"pipes-never":              func(h *fakeHarness) platform.Platform { return pipesNever{h.f} },
	"pipes-by-pid":             func(h *fakeHarness) platform.Platform { return pipesByPID{h.f, h} },
	"pipes-shared-read-end":    func(h *fakeHarness) platform.Platform { return pipesSharedReadEnd{h.f, h} },
	"pipes-inherited-read-end": func(h *fakeHarness) platform.Platform { return pipesInheritedReadEnd{h.f, h} },
	"pipes-shared-write-end":   func(h *fakeHarness) platform.Platform { return pipesSharedWriteEnd{h.f, h} },
}

// ---- broken variants ------------------------------------------------------

type releaseNoop struct{ *fake.Fake }

func (releaseNoop) ReleaseApproval(platform.ApprovalRef) {}

// reuseRefs hands out small ref values that are reused once released.
type reuseRefs struct {
	*fake.Fake
	mu sync.Mutex
	m  map[platform.ApprovalRef]platform.ApprovalRef
}

func newReuseRefs(f *fake.Fake) *reuseRefs {
	return &reuseRefs{Fake: f, m: map[platform.ApprovalRef]platform.ApprovalRef{}}
}

func (r *reuseRefs) Authenticate(p platform.AuthPolicy, pr platform.Prompt) (platform.ApprovalRef, error) {
	real, err := r.Fake.Authenticate(p, pr)
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ref := platform.ApprovalRef(len(r.m) + 1)
	r.m[ref] = real
	return ref, nil
}

func (r *reuseRefs) real(ref platform.ApprovalRef) platform.ApprovalRef {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[ref]
}

func (r *reuseRefs) ReleaseApproval(ref platform.ApprovalRef) {
	r.mu.Lock()
	real, ok := r.m[ref]
	delete(r.m, ref)
	r.mu.Unlock()
	if ok {
		r.Fake.ReleaseApproval(real)
	}
}

func (r *reuseRefs) Sign(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
	return r.Fake.Sign(h, d, r.real(ref))
}

func (r *reuseRefs) KeyAgreement(h, peer []byte, ref platform.ApprovalRef) ([]byte, error) {
	return r.Fake.KeyAgreement(h, peer, r.real(ref))
}

// tracked knows which refs are live; on an unknown non-zero ref it either
// substitutes a live one (forged refs approve) or panics.
type trackMode int

const (
	modeSubstitute trackMode = iota
	modePanic
)

type tracked struct {
	*fake.Fake
	mode trackMode
	mu   sync.Mutex
	live map[platform.ApprovalRef]bool
}

func newTracked(f *fake.Fake, m trackMode) *tracked {
	return &tracked{Fake: f, mode: m, live: map[platform.ApprovalRef]bool{}}
}

func (w *tracked) Authenticate(p platform.AuthPolicy, pr platform.Prompt) (platform.ApprovalRef, error) {
	ref, err := w.Fake.Authenticate(p, pr)
	if err == nil {
		w.mu.Lock()
		w.live[ref] = true
		w.mu.Unlock()
	}
	return ref, err
}

func (w *tracked) ReleaseApproval(ref platform.ApprovalRef) {
	w.mu.Lock()
	delete(w.live, ref)
	w.mu.Unlock()
	w.Fake.ReleaseApproval(ref)
}

func (w *tracked) fix(ref platform.ApprovalRef) platform.ApprovalRef {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ref == 0 || w.live[ref] {
		return ref
	}
	if w.mode == modePanic {
		panic("broken platform: unknown approval ref")
	}
	for l := range w.live {
		return l
	}
	return ref
}

func (w *tracked) Sign(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
	return w.Fake.Sign(h, d, w.fix(ref))
}

func (w *tracked) KeyAgreement(h, peer []byte, ref platform.ApprovalRef) ([]byte, error) {
	return w.Fake.KeyAgreement(h, peer, w.fix(ref))
}

type deniedNonzero struct{ *fake.Fake }

func (d deniedNonzero) Authenticate(p platform.AuthPolicy, pr platform.Prompt) (platform.ApprovalRef, error) {
	ref, err := d.Fake.Authenticate(p, pr)
	if err != nil {
		return 0x5eed, err
	}
	return ref, nil
}

type presenceDowngraded struct{ *fake.Fake }

func (p presenceDowngraded) CreateKey(purpose platform.Purpose, _ platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	return p.Fake.CreateKey(purpose, platform.AuthNone, access)
}

type deleteNoop struct{ *fake.Fake }

func (deleteNoop) DeleteKey([]byte) error { return nil }

// signPrefix hashes only a message's first 64 bytes, as a fixed-size copy
// at a C boundary would. Every message the suite signed before keys/k8s-ca
// was shorter; the TBS bytes of a certificate are not.
type signPrefix struct{ *fake.Fake }

func (s signPrefix) Sign(handle, msg []byte, approval platform.ApprovalRef) ([]byte, error) {
	return s.Fake.Sign(handle, msg[:min(len(msg), 64)], approval)
}

// deleteKeepsAgreement deletes signing keys but leaves key-agreement keys
// usable: a deleted secret would still open. keys/delete uses a
// signing key only, so keys/sealed-secret is what catches it.
type deleteKeepsAgreement struct {
	*fake.Fake
	mu sync.Mutex
	ka map[string]bool
}

func newDeleteKeepsAgreement(f *fake.Fake) *deleteKeepsAgreement {
	return &deleteKeepsAgreement{Fake: f, ka: map[string]bool{}}
}

func (d *deleteKeepsAgreement) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	h, pub, err := d.Fake.CreateKey(purpose, auth, access)
	if err == nil && purpose == platform.PurposeKeyAgreement {
		d.mu.Lock()
		d.ka[string(h)] = true
		d.mu.Unlock()
	}
	return h, pub, err
}

func (d *deleteKeepsAgreement) DeleteKey(h []byte) error {
	d.mu.Lock()
	keep := d.ka[string(h)]
	d.mu.Unlock()
	if keep {
		return nil
	}
	return d.Fake.DeleteKey(h)
}

type confirmAlwaysTrue struct{ *fake.Fake }

func (c confirmAlwaysTrue) Confirm(p platform.Prompt) (bool, error) {
	_, _ = c.Fake.Confirm(p) // consume the scripted answer
	return true, nil
}

// processByPID looks a non-zero-generation ref up by PID alone and returns
// the live occupant whatever generation was asked for.
type processByPID struct {
	*fake.Fake
	h *fakeHarness
}

func (p processByPID) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	if occ, ok := p.h.occupant(ref.PID); ok && ref.Generation != 0 {
		return p.Fake.Process(occ)
	}
	return p.Fake.Process(ref)
}

type peerPIDOnly struct{ *fake.Fake }

func (p peerPIDOnly) PeerOf(fd int) (platform.ProcessRef, error) {
	ref, err := p.Fake.PeerOf(fd)
	return platform.ProcessRef{PID: ref.PID}, err
}

type zeroRefResolves struct{ *fake.Fake }

func (z zeroRefResolves) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	if ref.IsZero() {
		return z.Fake.Process(z.Launchd)
	}
	return z.Fake.Process(ref)
}

type exitTwice struct{ *fake.Fake }

func (e exitTwice) OnProcessExit(ref platform.ProcessRef, fn func()) {
	e.Fake.OnProcessExit(ref, func() { fn(); fn() })
}

type exitNeverIfGone struct{ *fake.Fake }

func (e exitNeverIfGone) OnProcessExit(ref platform.ProcessRef, fn func()) {
	if _, err := e.Fake.Process(ref); err != nil {
		return
	}
	e.Fake.OnProcessExit(ref, fn)
}

// appForTrustsRecord decides "GUI app" from the record's path, so a forged
// ProcessInfo (made-up ref, app-looking path) resolves as an app.
type appForTrustsRecord struct{ *fake.Fake }

func (a appForTrustsRecord) AppFor(chain []platform.ProcessInfo) (platform.AppInfo, bool) {
	for _, p := range chain {
		if strings.Contains(p.Path, ".app/Contents/MacOS/") {
			return platform.AppInfo{Ref: p.Ref, BundleID: "forged", Name: "Forged", Code: p.Code}, true
		}
	}
	return a.Fake.AppFor(chain)
}

// execNoCancel's cancel does nothing: fn keeps being called.
type execNoCancel struct{ *fake.Fake }

func (e execNoCancel) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	_, err := e.Fake.OnProcessExec(ref, fn)
	return func() {}, err
}

// execStale keeps the last environment it read (at each answer and at
// each cancel) and answers it when the fake no longer would (a hidden
// image, after the last cancel).
type execStale struct {
	*fake.Fake
	mu   sync.Mutex
	last map[platform.ProcessRef][]string
}

func (e *execStale) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	cancel, err := e.Fake.OnProcessExec(ref, fn)
	if err != nil {
		return nil, err
	}
	return func() { e.Environment(ref); cancel() }, nil
}

func (e *execStale) Environment(ref platform.ProcessRef) ([]string, error) {
	env, err := e.Fake.Environment(ref)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.last[ref] = env
	} else if old, ok := e.last[ref]; ok && errors.Is(err, platform.ErrUnreadable) {
		return old, nil
	}
	return env, err
}

// execHiddenEmpty answers [] where the environment cannot be read.
type execHiddenEmpty struct{ *fake.Fake }

func (e execHiddenEmpty) Environment(ref platform.ProcessRef) ([]string, error) {
	env, err := e.Fake.Environment(ref)
	if errors.Is(err, platform.ErrUnreadable) {
		return []string{}, nil
	}
	return env, err
}

// execAnyGeneration watches the PID's live occupant whatever generation
// was asked for.
type execAnyGeneration struct {
	*fake.Fake
	h *fakeHarness
}

func (e execAnyGeneration) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	if occ, ok := e.h.occupant(ref.PID); ok {
		ref = occ
	}
	return e.Fake.OnProcessExec(ref, fn)
}

// execLateEvent calls fn some time after the exec, in order on one
// goroutine of its own, and never after cancel returned: only "seen
// before Environment answers" is broken.
type execLateEvent struct{ *fake.Fake }

func (e execLateEvent) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	q := make(chan platform.ProcessInfo, 64)
	stop, err := e.Fake.OnProcessExec(ref, func(p platform.ProcessInfo) { q <- p })
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	cancelled := false
	go func() {
		for p := range q {
			time.Sleep(200 * time.Millisecond)
			mu.Lock()
			if !cancelled {
				fn(p)
			}
			mu.Unlock()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			stop() // no send on q after this
			mu.Lock()
			cancelled = true
			mu.Unlock()
			close(q)
		})
	}, nil
}

// presenceCounter counts AuthUserPresence keys created.
type presenceCounter struct {
	*fake.Fake
	mu sync.Mutex
	n  int
}

func (c *presenceCounter) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	if auth == platform.AuthUserPresence {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
	}
	return c.Fake.CreateKey(purpose, auth, access)
}

// With SkipUserPresenceKeys the suite never asks for a user-presence key,
// even when every hook (Answer included) is supplied (the conformance
// host's real-enclave run).
func TestSkipUserPresenceKeysCreatesNone(t *testing.T) {
	var counters []*presenceCounter
	conformance.Run(t, func(t *testing.T) conformance.Env {
		h := newFakeHarness(t)
		c := &presenceCounter{Fake: h.f}
		counters = append(counters, c)
		env := h.env(c)
		env.SkipUserPresenceKeys = true
		return env
	})
	for _, c := range counters {
		if c.n != 0 {
			t.Fatalf("%d user-presence keys created with SkipUserPresenceKeys", c.n)
		}
	}
}

type mountsNeverSeen struct{ *fake.Fake }

func (m mountsNeverSeen) WatchMounts() (func() bool, func(), error) {
	_, stop, err := m.Fake.WatchMounts()
	return func() bool { return false }, stop, err
}

type mountsForgotten struct{ *fake.Fake }

func (m mountsForgotten) WatchMounts() (func() bool, func(), error) {
	changed, stop, err := m.Fake.WatchMounts()
	told := false
	return func() bool {
		if told {
			return false
		}
		told = changed()
		return told
	}, stop, err
}

// mountsFromThePast answers every watch from one watch made when the
// platform was, so a mount before a watch is reported by it.
type mountsFromThePast struct {
	*fake.Fake
	first func() bool
}

func newMountsFromThePast(f *fake.Fake) mountsFromThePast {
	first, _, _ := f.WatchMounts()
	return mountsFromThePast{f, first}
}

func (m mountsFromThePast) WatchMounts() (func() bool, func(), error) {
	_, stop, err := m.Fake.WatchMounts()
	return m.first, stop, err
}

type mountsOpenOnStop struct{ *fake.Fake }

func (m mountsOpenOnStop) WatchMounts() (func() bool, func(), error) {
	changed, stop, err := m.Fake.WatchMounts()
	var stopped atomic.Bool
	return func() bool { return !stopped.Load() && changed() }, func() { stopped.Store(true); stop() }, err
}

// pipesAnyReader checks only that fd 1 is a pipe, not whose read end it is.
type pipesAnyReader struct {
	*fake.Fake
	h *fakeHarness
}

func (p pipesAnyReader) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	if ok, err := p.Fake.StdoutReadBy(w, r); ok || err != nil {
		return ok, err
	}
	return p.h.isPiped(w), nil
}

// pipesParentIsEnough checks only that writer is reader's child.
type pipesParentIsEnough struct{ *fake.Fake }

func (p pipesParentIsEnough) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	if ok, err := p.Fake.StdoutReadBy(w, r); ok || err != nil {
		return ok, err
	}
	info, err := p.Process(w)
	return err == nil && info.Parent == r, nil
}

// pipesNever fails closed so hard that it refuses kubectl too.
type pipesNever struct{ *fake.Fake }

func (pipesNever) StdoutReadBy(platform.ProcessRef, platform.ProcessRef) (bool, error) {
	return false, nil
}

// pipesByPID ignores the generations: it asks about the live occupants of
// the two PIDs.
type pipesByPID struct {
	*fake.Fake
	h *fakeHarness
}

func (p pipesByPID) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	if lw, ok := p.h.occupant(w.PID); ok {
		w = lw
	}
	if lr, ok := p.h.occupant(r.PID); ok {
		r = lr
	}
	return p.Fake.StdoutReadBy(w, r)
}

// pipesSharedReadEnd checks that the parent holds the read end, not that
// it alone does.
type pipesSharedReadEnd struct {
	*fake.Fake
	h *fakeHarness
}

func (p pipesSharedReadEnd) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	if ok, err := p.Fake.StdoutReadBy(w, r); ok || err != nil {
		return ok, err
	}
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.shared[w], nil
}

// pipesInheritedReadEnd checks that the parent alone holds the read end,
// not that it opened it (close-on-exec): it takes a pipe the parent was
// handed, such as its stdin.
type pipesInheritedReadEnd struct {
	*fake.Fake
	h *fakeHarness
}

func (p pipesInheritedReadEnd) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	if ok, err := p.Fake.StdoutReadBy(w, r); ok || err != nil {
		return ok, err
	}
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.inherited[w], nil
}

// pipesSharedWriteEnd checks the read end only: it takes a pipe another
// process can write to as well, around the writer's bytes.
type pipesSharedWriteEnd struct {
	*fake.Fake
	h *fakeHarness
}

func (p pipesSharedWriteEnd) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	if ok, err := p.Fake.StdoutReadBy(w, r); ok || err != nil {
		return ok, err
	}
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.cowritten[w], nil
}
