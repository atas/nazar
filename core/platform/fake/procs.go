package fake

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/atas/nazar/core/platform"
)

// Proc describes a process to Launch. App, when set, makes it a GUI app bundle.
type Proc struct {
	Path string
	// Comm is the kernel's short name; it defaults to the first 16 bytes
	// of Path's file name, as on macOS.
	Comm string
	Args []string // defaults to []string{Path}
	Cwd  string
	Root bool // runs as uid 0; otherwise uid 501
	Code platform.CodeIdentity
	App  *App
	// StdoutToParent: fd 1 is the write end of a pipe whose read end the
	// parent holds, as client-go runs an exec plugin (platform.Pipes; see
	// SetStdout).
	StdoutToParent bool
}

// App marks a launched process as a GUI app bundle.
type App struct {
	BundleID string
	Name     string
}

// Launch starts a fake process under parent (zero parent = launchd) and
// returns its ref. Each launch gets a new PID, a unique generation and a
// start time one millisecond after the previous one. Launching under a
// parent that does not exist is a test bug and panics.
//
// Responsibility is assigned as macOS assigns it (spike S3; Milestone 7): a
// process launchd starts answers for itself, a child inherits its parent's
// responsible process, and Exit makes every process the exiting one was
// responsible for answer for itself (observed on an orphaned
// iTermServer and its tabs). SetResponsible overrides any of this.
func (f *Fake) Launch(parent platform.ProcessRef, p Proc) platform.ProcessRef {
	f.mu.Lock()
	defer f.mu.Unlock()
	if parent.IsZero() {
		parent = f.Launchd
	}
	if _, ok := f.procs[parent]; !ok {
		panic(fmt.Sprintf("fake: Launch under unknown parent %v", parent))
	}
	f.now = f.now.Add(time.Millisecond)
	pid := f.nextPID
	f.nextPID++
	ref := platform.ProcessRef{PID: pid, Generation: uint64(pid)*1000 + 1}
	args := p.Args
	if args == nil {
		args = []string{p.Path}
	}
	uid := 501
	if p.Root {
		uid = 0
	}
	comm := p.Comm
	if comm == "" && p.Path != "" {
		comm = filepath.Base(p.Path)
		if len(comm) > 16 {
			comm = comm[:16]
		}
	}
	f.procs[ref] = platform.ProcessInfo{
		Ref: ref, Parent: parent, UID: uid, StartTime: f.now, Path: p.Path,
		Args: append([]string(nil), args...), Cwd: p.Cwd, Code: p.Code, Comm: comm,
	}
	if p.App != nil {
		f.apps[ref] = platform.AppInfo{Ref: ref, BundleID: p.App.BundleID, Name: p.App.Name, Code: p.Code}
	}
	if p.StdoutToParent {
		f.stdout[ref] = parent
	}
	resp := ref
	if parent != f.Launchd {
		resp = parent
		if pr, ok := f.responsible[parent]; ok {
			resp = pr
		}
	}
	f.responsible[ref] = resp
	return ref
}

// SetProcess overwrites a process record (for tests that need odd records,
// e.g. a parent that started after its child, or a recycled PID).
func (f *Fake) SetProcess(info platform.ProcessInfo) {
	f.mu.Lock()
	info.Args = append([]string(nil), info.Args...)
	f.procs[info.Ref] = info
	f.mu.Unlock()
}

// Exit ends a process: Process() then fails, children are re-parented to
// launchd, the processes it was responsible for answer for themselves, and
// OnProcessExit callbacks run (synchronously, in order) before Exit
// returns. Exiting an unknown or already-exited ref is a no-op.
func (f *Fake) Exit(ref platform.ProcessRef) {
	f.mu.Lock()
	delete(f.procs, ref)
	delete(f.apps, ref)
	delete(f.responsible, ref)
	delete(f.stdout, ref)
	delete(f.foreign, ref)
	for r, p := range f.procs {
		if p.Parent == ref {
			p.Parent = f.Launchd
			f.procs[r] = p
		}
	}
	for r, resp := range f.responsible {
		if resp == ref {
			f.responsible[r] = r
		}
	}
	fns := f.exitFns[ref]
	delete(f.exitFns, ref)
	delete(f.execWatches, ref)
	delete(f.envs, ref)
	delete(f.envHidden, ref)
	f.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// OnProcessExit runs fn once when ref exits; if ref is already gone, fn runs
// promptly on another goroutine.
func (f *Fake) OnProcessExit(ref platform.ProcessRef, fn func()) {
	f.mu.Lock()
	if _, alive := f.procs[ref]; !alive {
		f.mu.Unlock()
		go fn()
		return
	}
	f.exitFns[ref] = append(f.exitFns[ref], fn)
	f.mu.Unlock()
}

// ExitWatchers reports how many OnProcessExit callbacks are pending for ref.
func (f *Fake) ExitWatchers(ref platform.ProcessRef) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.exitFns[ref])
}

// Process returns the record for ref, or ErrNoProcess. A full ref matches
// only its exact instance. A PID-only ref (generation 0) answers the live
// occupant of that PID with its full ref, as KERN_PROC_PID does on macOS;
// when tests scripted several records on one PID the newest (latest start
// time, then highest generation) is the occupant.
func (f *Fake) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.procs[ref]
	if !ok && ref.IsPIDOnly() {
		for r, cand := range f.procs {
			if r.PID != ref.PID {
				continue
			}
			if !ok || cand.StartTime.After(p.StartTime) || (cand.StartTime.Equal(p.StartTime) && r.Generation > p.Ref.Generation) {
				p, ok = cand, true
			}
		}
	}
	if !ok {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	p.Args = append([]string(nil), p.Args...)
	return p, nil
}

// AppFor returns the first process in chain (peer first) that was launched
// as a GUI app. A process is matched by its exact ref, so a look-alike
// process or a recycled PID never resolves as the app.
func (f *Fake) AppFor(chain []platform.ProcessInfo) (platform.AppInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range chain {
		if a, ok := f.apps[p.Ref]; ok {
			return a, true
		}
	}
	return platform.AppInfo{}, false
}

// Apps returns every live process launched as a GUI app, in PID order.
func (f *Fake) Apps() []platform.AppInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	refs := make([]platform.ProcessRef, 0, len(f.apps))
	for r := range f.apps {
		refs = append(refs, r)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].PID < refs[j].PID })
	out := make([]platform.AppInfo, 0, len(refs))
	for _, r := range refs {
		out = append(out, f.apps[r])
	}
	return out
}

// SetResponsible scripts the responsible-process lookup for ref.
func (f *Fake) SetResponsible(ref, responsible platform.ProcessRef) {
	f.mu.Lock()
	f.responsible[ref] = responsible
	f.mu.Unlock()
}

// ResponsibleFor returns the scripted responsible process for ref, if any.
func (f *Fake) ResponsibleFor(ref platform.ProcessRef) (platform.ProcessRef, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.responsible[ref]
	return r, ok
}

// SetPeer scripts PeerOf(fd). SetDefaultPeer answers every other fd.
func (f *Fake) SetPeer(fd int, ref platform.ProcessRef) {
	f.mu.Lock()
	f.peers[fd] = ref
	f.mu.Unlock()
}

// SetDefaultPeer scripts the answer for every fd without its own peer.
func (f *Fake) SetDefaultPeer(ref platform.ProcessRef) {
	f.mu.Lock()
	f.defaultPeer = ref
	f.mu.Unlock()
}

// PeerOf answers from PeerFunc when set, else the peer table, else the
// default peer; with nothing scripted it fails closed with ErrNoProcess.
func (f *Fake) PeerOf(fd int) (platform.ProcessRef, error) {
	f.mu.Lock()
	fn := f.PeerFunc
	ref, ok := f.peers[fd]
	def := f.defaultPeer
	f.mu.Unlock()
	if fn != nil {
		return fn(fd)
	}
	if ok {
		return ref, nil
	}
	if !def.IsZero() {
		return def, nil
	}
	return platform.ProcessRef{}, platform.ErrNoProcess
}

// SetCodeHash scripts CodeHash(path).
func (f *Fake) SetCodeHash(path string, hash []byte) {
	f.mu.Lock()
	f.codeHashes[path] = append([]byte(nil), hash...)
	f.mu.Unlock()
}

// CodeHash returns the scripted hash for path, else CodeHashFunc(path) if
// set, else ErrNotFound.
func (f *Fake) CodeHash(path string) ([]byte, error) {
	f.mu.Lock()
	h, ok := f.codeHashes[path]
	fn := f.CodeHashFunc
	f.mu.Unlock()
	if ok {
		return append([]byte(nil), h...), nil
	}
	if fn != nil {
		return fn(path)
	}
	return nil, platform.ErrNotFound
}
