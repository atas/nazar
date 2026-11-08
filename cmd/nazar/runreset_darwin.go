//go:build darwin && cgo

package main

/*
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>

// Every exception, a crash (EXC_CRASH) and a corpse (EXC_CORPSE_NOTIFY):
// the handler of the last two is sent the task, or a copy of its memory.
#define NZ_EXC_MASK (EXC_MASK_ALL | EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY)

// nz_no_ports reports whether the task (thread == MACH_PORT_NULL) or the
// thread has no live exception port for NZ_EXC_MASK; it releases any port
// it was handed.
static int nz_no_ports(thread_act_t thread) {
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_port_t ports[EXC_TYPES_COUNT];
	exception_behavior_t behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors[EXC_TYPES_COUNT];
	mach_msg_type_number_t n = EXC_TYPES_COUNT;
	kern_return_t kr = thread == MACH_PORT_NULL
		? task_get_exception_ports(mach_task_self(), NZ_EXC_MASK, masks, &n, ports, behaviors, flavors)
		: thread_get_exception_ports(thread, NZ_EXC_MASK, masks, &n, ports, behaviors, flavors);
	if (kr != KERN_SUCCESS) return 0;
	int none = 1;
	for (mach_msg_type_number_t i = 0; i < n; i++) {
		if (MACH_PORT_VALID(ports[i])) {
			none = 0;
			mach_port_deallocate(mach_task_self(), ports[i]);
		}
	}
	return none;
}

// nz_reset_exec readies the calling thread and its task for execve: every
// ignored signal back to SIG_DFL (execve resets the handled ones), an
// empty signal mask on this thread, and no exception port on the task or
// this thread, checked after it is set. 0, or the step that failed: 1 the
// signals, 2 the mask, 3 the exception ports.
static int nz_reset_exec(void) {
	for (int sig = 1; sig < NSIG; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP) continue;
		struct sigaction old;
		if (sigaction(sig, NULL, &old) != 0) return 1;
		if (old.sa_handler != SIG_IGN) continue;
		struct sigaction dfl = {0};
		dfl.sa_handler = SIG_DFL;
		if (sigaction(sig, &dfl, NULL) != 0) return 1;
	}
	sigset_t none, now;
	sigemptyset(&none);
	if (pthread_sigmask(SIG_SETMASK, &none, NULL) != 0 || pthread_sigmask(SIG_BLOCK, NULL, &now) != 0 || now != 0) {
		return 2; // a sigset_t is a 32-bit mask on macOS
	}
	thread_act_t self = mach_thread_self();
	int ok = task_set_exception_ports(mach_task_self(), NZ_EXC_MASK, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE) == KERN_SUCCESS
		&& thread_set_exception_ports(self, NZ_EXC_MASK, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE) == KERN_SUCCESS
		&& nz_no_ports(MACH_PORT_NULL) && nz_no_ports(self);
	mach_port_deallocate(mach_task_self(), self);
	return ok ? 0 : 3;
}
*/
import "C"

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// resetSteps names nz_reset_exec's failed step.
var resetSteps = [...]string{1: "the signals", 2: "the signal mask", 3: "the exception ports"}

// resetForExec readies the process for nazar run's execve (secrets design
// 6.3 step 5, 6.3.8), as on Linux: every fd from 3 up closes at exec (no
// fd is handed over, 6.3 D1), umask 022, no core file, every signal
// at its default, an empty signal mask on the exec thread, and the folder
// dirFD names as the working directory. On macOS also no Mach exception
// port on the task or the exec thread: a port the caller set would be sent
// the receiver's task, or a copy of its memory, when it crashes. execve
// resets every signal with a handler, so only the ignored ones need
// SIG_DFL, whoever ignored them (Go keeps SIGHUP and SIGINT ignored when
// they were at start, and never takes SIGTSTP, SIGCONT, SIGTTIN or SIGTTOU
// unless asked). Any step that fails refuses the run. The goroutine stays
// locked to its thread, whose mask and exception ports execve passes on;
// the caller must exec next, from the same goroutine.
func resetForExec(dirFD int) error {
	if err := closeOnExec(); err != nil {
		return err
	}
	unix.Umask(0o022)
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	runtime.LockOSThread()
	if step := C.nz_reset_exec(); step != 0 {
		return fmt.Errorf("can't reset %s", resetSteps[step])
	}
	return unix.Fchdir(dirFD)
}
