// Package pipes is platform.Pipes on macOS (THREAT-MODEL 5.16):
// proc_pidinfo(PROC_PIDLISTFDS) and proc_pidfdinfo(PROC_PIDFDPIPEINFO)
// read the writer's fd 1 and the reader's fds, and the pipe is matched by
// its kernel handles (the writer's fd 1 is the write end, with no other
// reference, whose peer is a read end among the reader's fds, held there by
// one close-on-exec fd, so one the reader opened itself and did not
// inherit, and no other reference: PROC_FP_CLEXEC, not PROC_FP_SHARED on
// either end), with both processes
// checked against their refs' generations around the reads. Elsewhere New
// returns nil and k8s.credential is refused.
package pipes
