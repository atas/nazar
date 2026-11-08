package fake

import (
	"path/filepath"
	"slices"
	"sync"

	"github.com/atas/nazar/core/platform"
)

// execWatch is one OnProcessExec registration.
type execWatch struct {
	mu        sync.Mutex // held while fn runs, and by cancel: no call after cancel returns
	fn        func(platform.ProcessInfo)
	cancelled bool
}

// OnProcessExec registers fn for every Exec of ref (platform.Exec). It
// fails for a process that is not live.
func (f *Fake) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.procs[ref]; !ok {
		return nil, platform.ErrNoProcess
	}
	if f.execWatches == nil {
		f.execWatches = map[platform.ProcessRef][]*execWatch{}
	}
	w := &execWatch{fn: fn}
	f.execWatches[ref] = append(f.execWatches[ref], w)
	return func() {
		w.mu.Lock()
		w.cancelled = true
		w.mu.Unlock()
		f.mu.Lock()
		defer f.mu.Unlock()
		ws := slices.DeleteFunc(f.execWatches[ref], func(x *execWatch) bool { return x == w })
		if len(ws) > 0 {
			f.execWatches[ref] = ws
			return
		}
		delete(f.execWatches, ref)
		delete(f.envs, ref)
	}, nil
}

// Exec makes the live process ref exec p with the startup environment env:
// its record takes p's path, argv, working directory and code (its ref,
// parent and start time stay, as across a real execve), Environment
// answers env while a watch is on, and every OnProcessExec watcher of ref is called with the
// new record before Exec returns and before Environment answers. Execs of
// ref still unseen (ExecUnseen) reach the watchers first. An unknown ref
// is a test bug and panics.
func (f *Fake) Exec(ref platform.ProcessRef, p Proc, env []string) {
	f.execMu.Lock()
	defer f.execMu.Unlock()
	f.deliverUnseen(ref)
	f.deliver(ref, f.exec(ref, p, env))
}

// ExecUnseen is an exec the platform has taken but not yet handed to the
// watchers (the Mac's kqueue event still queued): the process is
// the new image at once, and its watchers hear of it at the next
// Environment(ref), before it answers, or at the next Exec, once.
func (f *Fake) ExecUnseen(ref platform.ProcessRef, p Proc, env []string) {
	f.execMu.Lock()
	defer f.execMu.Unlock()
	info := f.exec(ref, p, env)
	f.mu.Lock()
	if f.unseen == nil {
		f.unseen = map[platform.ProcessRef][]platform.ProcessInfo{}
	}
	f.unseen[ref] = append(f.unseen[ref], info)
	f.mu.Unlock()
}

// exec updates ref's record and environment; execMu held.
func (f *Fake) exec(ref platform.ProcessRef, p Proc, env []string) platform.ProcessInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.procs[ref]
	if !ok {
		panic("fake: Exec of an unknown process")
	}
	info.Path, info.Args, info.Cwd, info.Code = p.Path, slices.Clone(p.Args), p.Cwd, p.Code
	info.Comm = filepath.Base(p.Path)
	if len(info.Comm) > 16 {
		info.Comm = info.Comm[:16]
	}
	f.procs[ref] = info
	// As on macOS, the environment is read at the exec event, so only a
	// watched exec leaves one to answer (platform.Exec).
	if len(f.execWatches[ref]) == 0 {
		delete(f.envs, ref)
	} else {
		if f.envs == nil {
			f.envs = map[platform.ProcessRef][]string{}
		}
		f.envs[ref] = slices.Clone(env)
		if env == nil {
			f.envs[ref] = []string{}
		}
	}
	return info
}

// deliver calls every watcher of ref with info; execMu held, mu not.
func (f *Fake) deliver(ref platform.ProcessRef, info platform.ProcessInfo) {
	f.mu.Lock()
	ws := slices.Clone(f.execWatches[ref])
	f.mu.Unlock()
	for _, w := range ws {
		w.mu.Lock()
		if !w.cancelled {
			w.fn(info)
		}
		w.mu.Unlock()
	}
}

// deliverUnseen hands ref's unseen execs to its watchers, in order;
// execMu held, mu not.
func (f *Fake) deliverUnseen(ref platform.ProcessRef) {
	f.mu.Lock()
	infos := f.unseen[ref]
	delete(f.unseen, ref)
	f.mu.Unlock()
	for _, info := range infos {
		f.deliver(ref, info)
	}
}

// SetEnvironmentUnreadable makes Environment(ref) answer ErrUnreadable, as
// macOS does for an Apple platform binary.
func (f *Fake) SetEnvironmentUnreadable(ref platform.ProcessRef, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.envHidden == nil {
		f.envHidden = map[platform.ProcessRef]bool{}
	}
	f.envHidden[ref] = on
}

// Environment answers the environment ref's last watched Exec gave it,
// while a watch is on, after its unseen execs reached the watchers; ErrUnreadable when there is none (no watched exec,
// the last watch cancelled) or the test hid it, ErrNoProcess when ref is
// gone.
func (f *Fake) Environment(ref platform.ProcessRef) ([]string, error) {
	f.execMu.Lock()
	defer f.execMu.Unlock()
	f.deliverUnseen(ref)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.procs[ref]; !ok {
		return nil, platform.ErrNoProcess
	}
	env, ok := f.envs[ref]
	if !ok || f.envHidden[ref] {
		return nil, platform.ErrUnreadable
	}
	return slices.Clone(env), nil
}

// ExecStep is one exec of an ExecScript process: its image and argv, and
// whether the platform hides its startup environment. Its fields are
// conformance.Image's, so the one converts to the other.
type ExecStep struct {
	Path   string
	Args   []string
	Hidden bool
}

// ExecScript launches a process in "/" that execs on cue with the startup
// environment env, the conformance suite's Execer on the fake:
// next makes it exec the next of three images, as NazarExecProbe does on
// macOS: the probe, the probe again, then /bin/sleep, whose environment
// is hidden as an Apple platform binary's is. The probe's code hash is
// scripted, so CodeHash and the exec's record agree.
func (f *Fake) ExecScript(env []string) (platform.ProcessRef, func() ExecStep) {
	const probe = "/opt/nazar-test/exec-probe"
	f.SetCodeHash(probe, []byte("exec-probe code hash"))
	ref := f.Launch(platform.ProcessRef{}, Proc{Path: probe, Args: []string{probe, probe, probe, "/bin/sleep", "600"}, Cwd: "/"})
	steps := []ExecStep{
		{Path: probe, Args: []string{probe, probe, "/bin/sleep", "600"}},
		{Path: probe, Args: []string{probe, "/bin/sleep", "600"}},
		{Path: "/bin/sleep", Args: []string{"/bin/sleep", "600"}, Hidden: true},
	}
	var mu sync.Mutex
	return ref, func() ExecStep {
		mu.Lock()
		s := steps[0]
		steps = steps[1:]
		mu.Unlock()
		code := platform.CodeIdentity{Signed: true, Apple: true, CDHash: []byte("sleep")}
		if !s.Hidden {
			h, _ := f.CodeHash(s.Path)
			code = platform.CodeIdentity{AdHoc: true, CDHash: h}
		}
		f.SetEnvironmentUnreadable(ref, s.Hidden)
		f.Exec(ref, Proc{Path: s.Path, Args: s.Args, Cwd: "/", Code: code}, env)
		return s
	}
}

var _ platform.Exec = (*Fake)(nil)
