// NazarExecProbe: a small program the exec tests run. Linked
// (so ad-hoc signed by the linker) here, not an Apple platform binary, so
// macOS shows its startup environment. Each line on stdin makes it exec
// the rest of its own command line, argv[1..], with the environment it
// was started with; at end of input, or with nothing left to exec, it
// exits 0. With NAZAR_PROBE_SCRIBBLE=1 it zero-fills its own argument and
// environment strings 300 ms after it starts, as npm's process.title
// does about 40 ms after exec (spike S12), so a later KERN_PROCARGS2
// read of it finds nothing.
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static char **copy(char **v, int n) {
    char **c = calloc((size_t)n + 1, sizeof *c);
    for (int i = 0; i < n; i++) c[i] = strdup(v[i]);
    return c;
}

int main(int argc, char **argv) {
    int envc = 0;
    while (environ[envc]) envc++;
    char **next = copy(argv + 1, argc - 1), **env = copy(environ, envc);
    const char *s = getenv("NAZAR_PROBE_SCRIBBLE");
    if (s && strcmp(s, "1") == 0) {
        usleep(300 * 1000);
        char *end = argv[argc - 1] + strlen(argv[argc - 1]);
        if (envc > 0) end = environ[envc - 1] + strlen(environ[envc - 1]);
        memset(argv[0], 0, (size_t)(end - argv[0]));
    }
    for (char c = 0; c != '\n';)
        if (read(0, &c, 1) != 1) return 0;
    if (argc < 2) return 0;
    execve(next[0], next, env);
    return 127;
}
