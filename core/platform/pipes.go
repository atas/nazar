package platform

// Pipes tells nazar-agent where a process's standard output goes
// (THREAT-MODEL 5.16). client-go runs an exec credential plugin with its
// stdout as the write end of a pipe whose read end kubectl holds,
// and reads the credential from it. A kubeconfig can wrap the plugin in
// exec hops (`bash -c 'exec > >(tee leak); exec nazar …'`) that keep
// kubectl as the CLI's parent but copy what the CLI writes, or leave a
// co-writer that writes around it, so nazar-agent asks, before any prompt,
// that the CLI's fd 1 is a pipe it alone writes to and whose read end its
// parent opened itself and alone holds. Optional, as Exec and Mounts:
// a daemon without it refuses k8s.credential before any prompt. On macOS it is
// proc_pidinfo(PROC_PIDLISTFDS) and proc_pidfdinfo(PROC_PIDFDPIPEINFO) of
// both processes, the pipe matched by its kernel handle (package pipes).
type Pipes interface {
	// StdoutReadBy reports whether fd 1 of the live process writer is the
	// write end of a pipe, and its only reference (no other fd, in writer
	// or any other process), whose read end the live process reader holds
	// (as one of its fds) and nothing else does: no other fd, in reader
	// or any other process; and that fd is one reader opened itself
	// (close-on-exec), never one it inherited, such as its stdin. Both
	// are full refs of live instances: a tampered generation, an exited
	// process, a PID-only ref and the zero ref are ErrNoProcess, never an
	// answer about whatever holds the PID.
	// false with a nil error when fd 1 is closed, a file, a terminal, a
	// socket, the read end of a pipe, a pipe whose read end other
	// processes hold, instead of reader or as well, one whose write end
	// another fd holds too, or one reader inherited. An error when the
	// platform can't tell; callers refuse on false and on any error.
	StdoutReadBy(writer, reader ProcessRef) (bool, error)
}
