package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/unixsock"
)

// controlChildEnv names a control socket; set, the test binary is a stub
// control server on it instead of running the tests (TestMain). The tests
// of the Linux verifier use it: the peer the CLI checks must be another
// process, with its own image, not the test itself. The child says "ok"
// on stdout once it listens, appends every command it is sent to the
// file controlChildRequests names, answers as the stub in the harness
// does (replyFor), and ends when its stdin does.
const controlChildEnv = "NAZAR_CLI_TEST_CONTROL_SERVER"

// controlChildRequests is the file the child records its requests in.
func controlChildRequests(sock string) string { return filepath.Join(filepath.Dir(sock), "requests") }

func serveControlChild(sock string) int {
	l, err := unixsock.Listen(sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer l.Close()
	var mu sync.Mutex
	srv := &control.Server{Resolve: func(int) *caller.Chain { return &caller.Chain{} }, Handler: handlerFunc(func(ctx context.Context, req control.Request, out control.Emitter) {
		mu.Lock()
		f, err := os.OpenFile(controlChildRequests(sock), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err == nil {
			fmt.Fprintln(f, req.Command)
			f.Close()
		}
		mu.Unlock()
		replyFor(req, out)
	})}
	go srv.Serve(l)
	fmt.Println("ok")
	io.Copy(io.Discard, os.Stdin)
	return 0
}
