// Command bridge is the Go core as a C archive for Nazar.app (spec 4.7):
//
//	go build -buildmode=c-archive -o build/libnazar-core.a ./bridge
//
// Swift calls NazarCoreStart with its NazarCallbacks table and the home
// folder; the core then runs on its own goroutines until NazarCoreStop.
// Exit, screen-lock and exec events come back through NazarProcessExited,
// NazarScreenLocked and NazarProcessExecd. The agent has no window (Milestone 6: Nazar UI.app is
// a separate app), so nothing else crosses. One Go runtime per process:
// nazar-agent links exactly this archive.
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../macos/Sources/CNazarBridge/include
#include "nazar_bridge.h"
*/
import "C"

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/platform/mounts"
	"github.com/atas/nazar/core/platform/pipes"
)

// devCLIPin is the cdhash of the one CLI build an ad-hoc nazar-agent trusts
// with secret values (codesign.CLIRequirement), set by `make agent` with
// -ldflags "-X main.devCLIPin=…" after it signed that CLI. A team-signed
// agent ignores it.
var devCLIPin string

// core is the one running daemon of this process.
var core struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// stopWait bounds how long NazarCoreStop waits for the daemon to finish.
const stopWait = 5 * time.Second

var logger = log.New(os.Stderr, "nazar core: ", log.LstdFlags)

// start runs the daemon with the platform behind cb. It returns an NZ_*
// status: NZ_INVALID for a bad table or home, NZ_ERR when a core is already
// running or the daemon can't be built.
func start(cb unsafe.Pointer, home string) int32 {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.cancel != nil {
		logger.Print("already running")
		return int32(C.NZ_ERR)
	}
	if !filepath.IsAbs(home) {
		logger.Printf("home %q is not an absolute path", home)
		return int32(C.NZ_INVALID)
	}
	b, err := cbridge.New(cb)
	if err != nil {
		logger.Print(err)
		return int32(C.NZ_INVALID)
	}
	d, err := daemon.New(coreOptions(b, home))
	if err != nil {
		logger.Print(err)
		return int32(C.NZ_ERR)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := d.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Printf("stopped: %v", err)
		}
	}()
	core.cancel, core.done = cancel, done
	return int32(C.NZ_OK)
}

// coreOptions is the daemon's configuration over b: the exec seam when
// the Swift layer offers it (secrets design 6.3, D8) and the loaders of
// the agent bundle this process runs from (D9).
func coreOptions(b *cbridge.Bridge, home string) daemon.Options {
	exe, _ := os.Executable()
	return daemon.Options{Platform: b, Vault: b.Vault(), AuditSink: b.Sink(), Home: home, Logf: logger.Printf,
		VerifyCLI: cliVerifier(b, logger.Printf), Exec: b.Exec(), Mounts: mounts.New(), Pipes: pipes.New(), LoaderDir: loaderDir(exe)}
}

// loaderDir is the folder of nazar run's loaders: <name>.app/Contents/
// Resources/loaders beside the agent's own executable, which must be
// <name>.app/Contents/MacOS/<exe> once symlinks are resolved, and only
// when that folder is a real directory (its realpath is itself). "" for
// anything else (a test host, a bare binary): late-env is then refused.
// Never from the environment or a request.
func loaderDir(exe string) string {
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil || !filepath.IsAbs(exe) {
		return ""
	}
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(filepath.Dir(contents), ".app") {
		return ""
	}
	dir := filepath.Join(contents, "Resources", "loaders")
	if real, err := filepath.EvalSymlinks(dir); err != nil || real != dir {
		return ""
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return ""
	}
	return dir
}

// stop ends the running daemon and waits for it (bounded).
func stop() {
	core.mu.Lock()
	cancel, done := core.cancel, core.done
	core.cancel, core.done = nil, nil
	core.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(stopWait):
		logger.Print("did not stop in time")
	}
}

//export NazarCoreStart
func NazarCoreStart(cb *C.NazarCallbacks, home *C.uint8_t, homeLen C.size_t) C.int32_t {
	if home == nil || homeLen == 0 || homeLen > 4096 {
		return C.NZ_INVALID
	}
	return C.int32_t(start(unsafe.Pointer(cb), string(C.GoBytes(unsafe.Pointer(home), C.int(homeLen)))))
}

//export NazarCoreStop
func NazarCoreStop() { stop() }

//export NazarProcessExited
func NazarProcessExited(token C.uint64_t) { cbridge.ProcessExited(uint64(token)) }

//export NazarScreenLocked
func NazarScreenLocked(token C.uint64_t) { cbridge.ScreenLocked(uint64(token)) }

//export NazarProcessExecd
func NazarProcessExecd(token C.uint64_t, record *C.uint8_t, n C.size_t) {
	cbridge.ExecEvent(uint64(token), unsafe.Pointer(record), uint64(n))
}

func main() {}
