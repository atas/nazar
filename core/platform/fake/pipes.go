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
	delete(f.through, writer)
	if reader.IsZero() {
		delete(f.stdout, writer)
		return
	}
	f.stdout[writer] = reader
}

// SetStdoutThrough scripts that writer's fd 1 is the write end of a pipe
// whose read end reader holds, and that via, between them, holds the same
// write end on its fd 1 (the shell dash stays as when it runs `sh -c`;
// platform.StdoutThrough). StdoutReadBy is then false, as a co-writer
// makes it, and StdoutReadByThrough with that via is true. An unknown
// process is a test bug and panics.
func (f *Fake) SetStdoutThrough(writer, via, reader platform.ProcessRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range []platform.ProcessRef{writer, via, reader} {
		if _, ok := f.procs[p]; !ok {
			panic("fake: SetStdoutThrough of an unknown process")
		}
	}
	delete(f.foreign, writer)
	f.stdout[writer] = reader
	f.through[writer] = via
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
// fd 1 was piped to a read end reader opened itself and holds alone, with
// no shell between them holding the write end too; ErrNoProcess for a ref
// that is not live.
func (f *Fake) StdoutReadBy(writer, reader platform.ProcessRef) (bool, error) {
	f.mu.Lock()
	fn := f.StdoutFunc
	_, wok := f.procs[writer]
	_, rok := f.procs[reader]
	got, piped := f.stdout[writer]
	foreign := f.foreign[writer]
	_, through := f.through[writer]
	f.mu.Unlock()
	if fn != nil {
		return fn(writer, reader)
	}
	if !wok || !rok || writer.IsPIDOnly() || reader.IsPIDOnly() {
		return false, platform.ErrNoProcess
	}
	return piped && got == reader && !foreign && !through, nil
}

// StdoutReadByThrough (platform.StdoutThrough) answers from StdoutFunc
// when set (called with writer and reader), else true only when all three
// full refs are live and SetStdoutThrough scripted exactly this via and
// reader for writer; ErrNoProcess for a ref that is not live.
func (f *Fake) StdoutReadByThrough(writer, via, reader platform.ProcessRef) (bool, error) {
	f.mu.Lock()
	fn := f.StdoutFunc
	_, wok := f.procs[writer]
	_, vok := f.procs[via]
	_, rok := f.procs[reader]
	got, piped := f.stdout[writer]
	foreign := f.foreign[writer]
	gotVia, through := f.through[writer]
	f.mu.Unlock()
	if fn != nil {
		return fn(writer, reader)
	}
	if !wok || !vok || !rok || writer.IsPIDOnly() || via.IsPIDOnly() || reader.IsPIDOnly() {
		return false, platform.ErrNoProcess
	}
	return piped && through && got == reader && gotVia == via && !foreign, nil
}

var (
	_ platform.Pipes         = (*Fake)(nil)
	_ platform.StdoutThrough = (*Fake)(nil)
)
