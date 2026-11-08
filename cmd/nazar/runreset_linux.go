package main

import (
	"os"
	"os/signal"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// resetForExec readies the process for nazar run's execve (secrets design
// 6.3 step 5): the caller's process state must not reach a program that is
// about to hold a secret. Every fd from 3 up closes at exec (no fd is
// handed over, 6.3 D1), umask is 022, no core file is ever written,
// every signal the caller ignored or blocked is back to its default, and
// the working directory is the folder dirFD names. The goroutine stays
// locked to its thread, whose signal mask execve passes on; the caller
// must exec next, from the same goroutine. A signal that arrives between
// here and execve goes to Go's handler and is dropped (microseconds).
func resetForExec(dirFD int) error {
	if err := closeOnExec(); err != nil {
		return err
	}
	unix.Umask(0o022)
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	// A Go handler on every signal Go handles: execve resets handled
	// signals to their default, where an inherited SIG_IGN would stay.
	signal.Notify(make(chan os.Signal, 1))
	if err := defaultIgnored(); err != nil {
		return err
	}
	runtime.LockOSThread()
	if err := unix.PthreadSigmask(unix.SIG_SETMASK, &unix.Sigset_t{}, nil); err != nil {
		return err
	}
	return unix.Fchdir(dirFD)
}

// defaultIgnored sets SIG_DFL on every signal still ignored after Notify:
// those Go's signal package never handles (glibc's 32 and 33, and 34).
func defaultIgnored() error {
	for sig := 1; sig <= 64; sig++ {
		if sig == int(unix.SIGKILL) || sig == int(unix.SIGSTOP) {
			continue
		}
		var old [4]uint64 // the kernel's struct sigaction; sa_handler first
		if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), 0, uintptr(unsafe.Pointer(&old)), 8, 0, 0); e != 0 || old[0] != 1 {
			continue // not SIG_IGN
		}
		var dfl [4]uint64
		if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&dfl)), 0, 8, 0, 0); e != 0 {
			return e
		}
	}
	return nil
}
