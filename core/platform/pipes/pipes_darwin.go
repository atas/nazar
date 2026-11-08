//go:build darwin && cgo

package pipes

/*
#include <errno.h>
#include <libproc.h>
#include <sys/proc_info.h>

// nz_pipe reads fd of pid as a pipe end: 0 with its kernel handle, its
// peer's handle, its open flags (FREAD 1, FWRITE 2), whether the open
// file is shared (PROC_FP_SHARED: more than one reference to it, from any
// fd of any process or a message in flight) and whether the fd is
// close-on-exec (PROC_FP_CLEXEC), else the errno (EBADF: no such fd;
// ENOTSUP: not a pipe; ESRCH: no such process).
static int nz_pipe(int pid, int fd, uint64_t *handle, uint64_t *peer, uint32_t *flags, int *shared, int *cloexec) {
	struct pipe_fdinfo pi;
	errno = 0;
	if (proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, &pi, sizeof pi) != (int)sizeof pi)
		return errno ? errno : EIO;
	*handle = pi.pipeinfo.pipe_handle;
	*peer = pi.pipeinfo.pipe_peerhandle;
	*flags = pi.pfi.fi_openflags;
	*shared = (pi.pfi.fi_status & PROC_FP_SHARED) != 0;
	*cloexec = (pi.pfi.fi_status & PROC_FP_CLEXEC) != 0;
	return 0;
}

// nz_fds lists pid's fds into buf (n entries at most): the number listed,
// or -errno.
static int nz_fds(int pid, struct proc_fdinfo *buf, int n) {
	errno = 0;
	int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, n * (int)sizeof *buf);
	if (got <= 0) return errno ? -errno : -EIO;
	return got / (int)sizeof *buf;
}

// nz_nfds is a size for nz_fds: the kernel's estimate of pid's fd count,
// or -errno.
static int nz_nfds(int pid) {
	errno = 0;
	int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	if (got <= 0) return errno ? -errno : -EIO;
	return got / (int)sizeof(struct proc_fdinfo);
}
*/
import "C"

import (
	"fmt"
	"syscall"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// Open flags of a file (<sys/fcntl.h>): a pipe's read end is FREAD only,
// its write end FWRITE only.
const fRead, fWrite = 1, 2

// sZomb is p_stat of a zombie (<sys/proc.h>).
const sZomb = 5

type procPipes struct{}

// New is the macOS stdout check (see doc.go).
func New() platform.Pipes { return procPipes{} }

// end is one pipe end as an fd shows it.
type end struct {
	handle, peer uint64
	flags        uint32
	shared       bool
	cloexec      bool
}

// StdoutReadBy: both refs are checked live before and after the reads, so
// the answer is about the instances they name, never a recycled PID's.
// The writer's fd 1 must be a pipe's write end and that end's only
// reference: a copy in any other fd or process (a background job a
// wrapper left, THREAT-MODEL 5.16) is a co-writer that could write around
// the reply, and makes it shared. os/exec closes its own copy as Start
// returns, before the plugin can ask. The reader must hold, as an fd open
// for reading, the end whose handle is that end's peer and whose peer is
// that end; that fd must be close-on-exec and the read end's only
// reference. A copy in any other fd or process (a launcher that gave
// kubectl the pipe and kept it) makes it shared. A pipe the reader
// inherited, such as its stdin from a launcher that then closed its copy,
// is not close-on-exec: exec closes every fd that is, and Go never sets it
// on an fd it inherited, while the pipe os/exec makes for an exec plugin is
// close-on-exec from the start. Only the reader can copy the read end, and
// only the writer the write end, after the check, so the answer stays
// true.
func (procPipes) StdoutReadBy(writer, reader platform.ProcessRef) (bool, error) {
	if err := live(writer, reader); err != nil {
		return false, err
	}
	ok, err := readBy(writer.PID, reader.PID)
	if err := live(writer, reader); err != nil {
		return false, err
	}
	return ok, err
}

func readBy(writer, reader int) (bool, error) {
	w, found, err := pipeEnd(writer, 1)
	if err != nil || !found || w.flags&(fRead|fWrite) != fWrite || w.shared || w.handle == 0 || w.peer == 0 {
		return false, err
	}
	n := C.nz_nfds(C.int(reader))
	if n < 0 {
		return false, procErr("list fds", -n)
	}
	// Room for fds opened since the estimate; a reader with more is read
	// again, never answered from a cut list.
	for size := int(n) + 32; ; size *= 2 {
		buf := make([]C.struct_proc_fdinfo, size)
		got := C.nz_fds(C.int(reader), &buf[0], C.int(size))
		if got < 0 {
			return false, procErr("list fds", -got)
		}
		if int(got) == size {
			if size > 1<<20 {
				return false, fmt.Errorf("pipes: process %d has too many fds", reader)
			}
			continue
		}
		for _, fd := range buf[:got] {
			if fd.proc_fdtype != C.PROX_FDTYPE_PIPE {
				continue
			}
			r, found, err := pipeEnd(reader, int(fd.proc_fd))
			if err != nil {
				return false, err
			}
			if found && r.handle == w.peer && r.peer == w.handle && r.flags&fRead != 0 {
				return r.cloexec && !r.shared, nil
			}
		}
		return false, nil
	}
}

// pipeEnd reads fd of pid as a pipe end; found is false when the fd is
// closed or not a pipe.
func pipeEnd(pid, fd int) (end, bool, error) {
	var handle, peer C.uint64_t
	var flags C.uint32_t
	var shared, cloexec C.int
	switch errno := C.nz_pipe(C.int(pid), C.int(fd), &handle, &peer, &flags, &shared, &cloexec); errno {
	case 0:
		return end{handle: uint64(handle), peer: uint64(peer), flags: uint32(flags), shared: shared != 0, cloexec: cloexec != 0}, true, nil
	case C.EBADF, C.ENOTSUP:
		return end{}, false, nil
	default:
		return end{}, false, procErr("read a pipe", errno)
	}
}

func procErr(what string, errno C.int) error {
	if errno == C.ESRCH {
		return platform.ErrNoProcess
	}
	return fmt.Errorf("pipes: %s: %w", what, syscall.Errno(errno))
}

// live checks that each ref names a live process: a full ref (never
// PID-only or zero) whose PID holds the instance with that start time.
func live(refs ...platform.ProcessRef) error {
	for _, r := range refs {
		if r.PID <= 0 || r.Generation == 0 {
			return platform.ErrNoProcess
		}
		k, err := unix.SysctlKinfoProc("kern.proc.pid", r.PID)
		if err != nil || int(k.Proc.P_pid) != r.PID || k.Proc.P_stat == sZomb {
			return platform.ErrNoProcess
		}
		st := k.Proc.P_starttime
		if st.Sec < 0 || uint64(st.Sec)*1_000_000+uint64(st.Usec) != r.Generation {
			return platform.ErrNoProcess
		}
	}
	return nil
}
