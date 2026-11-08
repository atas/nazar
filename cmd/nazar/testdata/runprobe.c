// runprobe: both ends of cmd/nazar's macOS reset test (run_darwin_test.go).
// Test code only; never shipped.
//
//   runprobe spawn PROG ARGS...  starts PROG as a careless caller would and
//       waits for it: fds open without close-on-exec (a file three times, a
//       pipe, a socket pair, a FIFO, and fd 100), every catchable signal but
//       SIGCHLD ignored, eight signals blocked, umask 077, the core limit
//       at its maximum, and its task exception ports on a port this process
//       holds until PROG exits. Exits with PROG's status.
//   runprobe exec PROG ARGS...   puts the task's exception ports (spawn's)
//       on this thread too, then execv(PROG): a plain execve, nothing reset.
//   runprobe report              prints what it inherited, one key=value a line.
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// The exception ports the CLI clears (runreset_darwin.go).
#define MASK (EXC_MASK_ALL | EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY)

static void die(const char *what) {
	perror(what);
	exit(70);
}

// ports counts the live exception ports of the task (MACH_PORT_NULL) or of
// thread; -1 when they can't be read.
static int ports(thread_act_t thread) {
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_port_t p[EXC_TYPES_COUNT];
	exception_behavior_t b[EXC_TYPES_COUNT];
	thread_state_flavor_t f[EXC_TYPES_COUNT];
	mach_msg_type_number_t n = EXC_TYPES_COUNT;
	kern_return_t kr = thread == MACH_PORT_NULL
		? task_get_exception_ports(mach_task_self(), MASK, masks, &n, p, b, f)
		: thread_get_exception_ports(thread, MASK, masks, &n, p, b, f);
	if (kr != KERN_SUCCESS) return -1;
	int live = 0;
	for (mach_msg_type_number_t i = 0; i < n; i++) live += MACH_PORT_VALID(p[i]);
	return live;
}

// seed_thread sets this thread's exception ports to the task's, the way a
// caller would hand a thread-level port to the thread that execs.
static void seed_thread(void) {
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_port_t p[EXC_TYPES_COUNT];
	exception_behavior_t b[EXC_TYPES_COUNT];
	thread_state_flavor_t f[EXC_TYPES_COUNT];
	mach_msg_type_number_t n = EXC_TYPES_COUNT;
	if (task_get_exception_ports(mach_task_self(), MASK, masks, &n, p, b, f) != KERN_SUCCESS) die("task_get_exception_ports");
	for (mach_msg_type_number_t i = 0; i < n; i++) {
		if (MACH_PORT_VALID(p[i]) && thread_set_exception_ports(mach_thread_self(), masks[i], p[i], b[i], f[i]) != KERN_SUCCESS) {
			die("thread_set_exception_ports");
		}
	}
	if (ports(mach_thread_self()) < 1) die("seed_thread: no thread port");
}

static int report(void) {
	// The fds first, before the probe opens anything of its own.
	char fds[4096] = "";
	for (int fd = 0; fd < getdtablesize(); fd++) {
		if (fcntl(fd, F_GETFD) != -1) {
			char one[16];
			snprintf(one, sizeof one, "%s%d", fds[0] ? "," : "", fd);
			strlcat(fds, one, sizeof fds);
		}
	}
	printf("fds=%s\n", fds);
	sigset_t set;
	sigprocmask(SIG_BLOCK, NULL, &set);
	printf("blocked=%08x\n", (unsigned)set); // a 32-bit mask on macOS
	printf("ignored=");
	const char *sep = "";
	for (int sig = 1; sig < NSIG; sig++) {
		struct sigaction sa;
		if (sigaction(sig, NULL, &sa) == 0 && sa.sa_handler == SIG_IGN) {
			printf("%s%d", sep, sig);
			sep = ",";
		}
	}
	printf("\n");
	printf("umask=%03o\n", (unsigned)umask(0));
	struct rlimit rl;
	getrlimit(RLIMIT_CORE, &rl);
	printf("core=%llu/%llu\n", (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);
	printf("taskports=%d\n", ports(MACH_PORT_NULL));
	printf("threadports=%d\n", ports(mach_thread_self()));
	char cwd[PATH_MAX];
	printf("cwd=%s\n", getcwd(cwd, sizeof cwd) ? cwd : "?");
	return 0;
}

static int spawn(char **argv) {
	int fd = open("planted", O_RDWR | O_CREAT, 0600);
	int p[2], s[2];
	if (fd < 0 || dup(fd) < 0 || dup(fd) < 0) die("open");
	if (pipe(p) != 0) die("pipe");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) != 0) die("socketpair");
	unlink("fifo");
	if (mkfifo("fifo", 0600) != 0 || open("fifo", O_RDWR) < 0) die("fifo");
	if (dup2(fd, 100) != 100) die("dup2");
	for (int sig = 1; sig < NSIG; sig++) {
		if (sig != SIGKILL && sig != SIGSTOP && sig != SIGCHLD) signal(sig, SIG_IGN);
	}
	sigset_t blocked;
	sigemptyset(&blocked);
	int block[] = {SIGHUP, SIGINT, SIGPIPE, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGWINCH};
	for (size_t i = 0; i < sizeof block / sizeof *block; i++) sigaddset(&blocked, block[i]);
	umask(077);
	struct rlimit rl;
	if (getrlimit(RLIMIT_CORE, &rl) != 0) die("getrlimit");
	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_CORE, &rl) != 0) die("setrlimit");
	mach_port_t port;
	if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS ||
	    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) die("mach_port");
	posix_spawnattr_t attr;
	if (posix_spawnattr_init(&attr) != 0 || posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK) != 0 ||
	    posix_spawnattr_setsigmask(&attr, &blocked) != 0 ||
	    posix_spawnattr_setexceptionports_np(&attr, EXC_MASK_ALL | EXC_MASK_CRASH, port, EXCEPTION_DEFAULT, THREAD_STATE_NONE) != 0) die("posix_spawnattr");
	pid_t pid;
	int err = posix_spawn(&pid, argv[0], NULL, &attr, argv, environ);
	if (err != 0) {
		fprintf(stderr, "posix_spawn %s: %s\n", argv[0], strerror(err));
		return 70;
	}
	int status;
	if (waitpid(pid, &status, 0) != pid) die("waitpid");
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

int main(int argc, char **argv) {
	if (argc == 2 && strcmp(argv[1], "report") == 0) return report();
	if (argc >= 3 && strcmp(argv[1], "spawn") == 0) return spawn(argv + 2);
	if (argc >= 3 && strcmp(argv[1], "exec") == 0) {
		seed_thread();
		execv(argv[2], argv + 2);
		die("execv");
	}
	fprintf(stderr, "usage: runprobe report | spawn PROG ARGS... | exec PROG ARGS...\n");
	return 64;
}
