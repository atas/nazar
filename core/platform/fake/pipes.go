package fake

import "github.com/atas/nazar/core/platform"

// SetStdout scripts fd 1 of the live process writer (platform.Pipes): the
// write end of a pipe whose read end reader holds; the zero reader makes
// it no pipe anyone reads (a file, a terminal, a socket, closed), which
// is also what an unscripted process has. Proc.StdoutToParent scripts the
// same at Launch, with the parent as reader, as client-go runs an exec
// plugin. An unknown writer is a test bug and panics.
func (f *Fake) SetStdout(writer, reader platform.ProcessRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.procs[writer]; !ok {
		panic("fake: SetStdout of an unknown process")
	}
	delete(f.foreign, writer)
	if reader.IsZero() {
		delete(f.stdout, writer)
		return
	}
	f.stdout[writer] = reader
}

// SetStdoutForeign scripts that writer's fd 1 pipe is not the writer's and
// its reader's alone: another process holds a copy of the read end (a
// launcher that kept the pipe it gave kubectl) or of the write end (a
// co-writer, such as a background job a wrapper left), or the reader
// inherited the read end (kubectl's stdin, from a launcher that closed its
// own copy).
// StdoutReadBy is then false. SetStdout clears it. An unknown writer is a
// test bug and panics.
func (f *Fake) SetStdoutForeign(writer platform.ProcessRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.procs[writer]; !ok {
		panic("fake: SetStdoutForeign of an unknown process")
	}
	f.foreign[writer] = true
}

// StdoutReadBy answers from StdoutFunc when set, else from what SetStdout
// and Launch scripted: true only when both full refs are live and writer's
// fd 1 was piped to a read end reader opened itself and holds alone;
// ErrNoProcess for a ref that is not live.
func (f *Fake) StdoutReadBy(writer, reader platform.ProcessRef) (bool, error) {
	f.mu.Lock()
	fn := f.StdoutFunc
	_, wok := f.procs[writer]
	_, rok := f.procs[reader]
	got, piped := f.stdout[writer]
	foreign := f.foreign[writer]
	f.mu.Unlock()
	if fn != nil {
		return fn(writer, reader)
	}
	if !wok || !rok || writer.IsPIDOnly() || reader.IsPIDOnly() {
		return false, platform.ErrNoProcess
	}
	return piped && got == reader && !foreign, nil
}

var _ platform.Pipes = (*Fake)(nil)
