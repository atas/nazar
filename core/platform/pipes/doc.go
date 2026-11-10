// Package pipes is platform.Pipes on macOS (THREAT-MODEL 5.16):
// proc_pidinfo(PROC_PIDLISTFDS) and proc_pidfdinfo(PROC_PIDFDPIPEINFO)
// read the writer's fd 1 and the reader's fds, and the pipe is matched by
// its kernel handles (the writer's fd 1 is the write end, with no other
// reference, whose peer is a read end among the reader's fds, held there by
// one close-on-exec fd, so one the reader opened itself and did not
// inherit, and no other reference: PROC_FP_CLEXEC, not PROC_FP_SHARED on
// either end), with both processes
// checked against their refs' generations around the reads.
//
// On Linux (pipes_linux.go) the same question is answered from /proc: the
// writer's fd 1 must link to a pipe:[inode] and be open for writing
// (fdinfo flags), and every fd of every thread of every process in /proc is
// read for a link to that inode (/proc/<pid>/task/<tid>/fd: a process whose
// main thread has exited, or a thread with an fd table of its own, shows its
// fds only there). The only references allowed are the writer's fd 1 and one
// fd of the reader, open for reading and close-on-exec; any other one is a
// co-writer or a co-reader. A thread whose fds cannot be read (another
// user's, a non-dumpable process, one part way through exit) is skipped when
// it has exited, is a kernel thread, or its process started before the
// writer (or the shell that ran it). Otherwise it is read again for a moment, and is then an error.
//
// The Linux check is a snapshot and is weaker than macOS, as the threat model
// must say. Linux has no reference count to read, so an fd in flight over a
// socket, or one in a process whose fds are hidden, is invisible. And any
// same-user process can open either end of the pipe through
// /proc/<pid>/fd/<n> after the scan, including between the mint-time check
// and the CLI's write, and the check never sees that reference. So 5.16's
// claim that once the check has seen one reference to each end only kubectl
// can copy the read end and only the CLI the write end is false on Linux. The
// check stops a relay, such as a wrapper's tee, whose copy of the pipe is
// there when it looks. It does not stop a same-user reader, such as a
// kubeconfig wrapper's background job, and no code here can close that.
// Elsewhere New returns nil and k8s.credential is refused.
package pipes
