//go:build darwin

package main

// The conformance host's own hooks, run by `go test` (no Swift).
// The suite itself runs from NazarConformanceHost (`make conformance`);
// these tests pin what the host feeds it:
//   - the mode decides the human-facing hooks: only seamed mode scripts a
//     gate; the real Secure Enclave run (and any mode value that is not
//     exactly seamed) never has an Answer hook and never creates a
//     user-presence key, so no prompt can ever be reached;
//   - Spawn gives the full ref of a real, live child (generation = the
//     KERN_PROC_PID start time in microseconds, which the Swift platform
//     must accept as exact);
//   - Exit kills AND reaps, so the PID is gone for the platform, not a
//     zombie that still answers;
//   - Peer is a socket really connected to the returned PID;
//   - every process and socket folder the hooks made is gone after the
//     subtest (tests kill every process they start).

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/bridge/cbridge/cfake"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"golang.org/x/sys/unix"
)

// solLocal is SOL_LOCAL from <sys/un.h> (not exported by x/sys/unix).
const solLocal = 0

func fakeBridge(t *testing.T) *cbridge.Bridge {
	t.Helper()
	b, err := cbridge.New(cfake.Install(fake.New(time.Now()), fake.NewVault(), &audit.MemorySink{}))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealModeHasNoGateAndNoUserPresenceKeys(t *testing.T) {
	b := fakeBridge(t)
	for name, mode := range map[string]int{"real": modeReal, "zero": 0, "three": 3, "negative": -1, "seamed+16": modeSeamed + 16} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t, b, hostHooks{}, mode)
			if env.Answer != nil {
				t.Fatalf("mode %d: env has an Answer hook; only seamed mode may script a gate", mode)
			}
			if !env.SkipUserPresenceKeys {
				t.Fatalf("mode %d: SkipUserPresenceKeys is false; a real-enclave run must never create a user-presence key", mode)
			}
			if env.P == nil || env.Spawn == nil || env.Exit == nil || env.Peer == nil {
				t.Fatalf("mode %d: env lacks the platform or a process hook: %+v", mode, env)
			}
		})
	}
}

func TestSeamedModeScriptsGatesAndKeepsUserPresenceKeys(t *testing.T) {
	env := newEnv(t, fakeBridge(t), hostHooks{}, modeSeamed)
	if env.Answer == nil {
		t.Fatal("seamed mode has no Answer hook: the approvals subtests would all skip")
	}
	if env.SkipUserPresenceKeys {
		t.Fatal("seamed mode skips user-presence keys: the approvals subtests would all skip")
	}
	if env.P == nil || env.Spawn == nil || env.Exit == nil || env.Peer == nil {
		t.Fatalf("seamed env lacks the platform or a process hook: %+v", env)
	}
}

func TestSpawnGivesTheFullRefOfALiveChild(t *testing.T) {
	c := &children{t: t}
	t.Cleanup(c.killAll)
	ref := c.spawn()
	if ref.PID <= 0 || ref.Generation == 0 {
		t.Fatalf("spawn = %v, want a positive PID and a non-zero generation", ref)
	}
	if !alive(ref.PID) {
		t.Fatalf("spawned PID %d is not alive", ref.PID)
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", ref.PID)
	if err != nil {
		t.Fatal(err)
	}
	st := k.Proc.P_starttime
	if want := uint64(st.Sec)*1_000_000 + uint64(st.Usec); ref.Generation != want {
		t.Fatalf("generation %d, want the KERN_PROC_PID start time %d µs", ref.Generation, want)
	}
	if got := int(k.Eproc.Ppid); got != os.Getpid() {
		t.Fatalf("spawned process's parent is %d, want this process %d", got, os.Getpid())
	}
	if comm := unix.ByteSliceToString(k.Proc.P_comm[:]); comm != "sleep" {
		t.Fatalf("spawned process is %q, want sleep", comm)
	}
	// Same PID, asked again: the same generation (it is the start time).
	if again := generation(t, ref.PID); again != ref.Generation {
		t.Fatalf("generation changed for a live process: %d then %d", ref.Generation, again)
	}
}

func TestExitKillsAndReaps(t *testing.T) {
	c := &children{t: t}
	t.Cleanup(c.killAll)
	ref := c.spawn()
	c.exit(ref)
	// Reaped, not a zombie: a zombie still answers kill(pid, 0) and
	// KERN_PROC_PID, and the platform would see it as live.
	if alive(ref.PID) {
		if k, err := unix.SysctlKinfoProc("kern.proc.pid", ref.PID); err == nil {
			st := k.Proc.P_starttime
			if uint64(st.Sec)*1_000_000+uint64(st.Usec) == ref.Generation {
				t.Fatalf("PID %d still exists with the exited instance's start time after exit", ref.PID)
			}
		}
	}
	c.mu.Lock()
	_, kept := c.cmds[ref.PID]
	c.mu.Unlock()
	if kept {
		t.Fatalf("exit left PID %d in the children table", ref.PID)
	}
}

func TestPeerIsConnectedToTheReturnedPID(t *testing.T) {
	c := &children{t: t}
	t.Cleanup(c.killAll)
	fd, pid := c.peer()
	if fd < 0 || pid <= 0 {
		t.Fatalf("peer = %d, %d", fd, pid)
	}
	got, err := unix.GetsockoptInt(fd, solLocal, unix.LOCAL_PEERPID)
	if err != nil {
		t.Fatalf("LOCAL_PEERPID on the peer fd: %v", err)
	}
	if got != pid {
		t.Fatalf("socket peer is PID %d, hook said %d", got, pid)
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		t.Fatal(err)
	}
	if comm := unix.ByteSliceToString(k.Proc.P_comm[:]); comm != "nc" {
		t.Fatalf("peer process is %q, want nc", comm)
	}
	// The peer stays connected (and alive) until cleanup.
	time.Sleep(100 * time.Millisecond)
	if !alive(pid) {
		t.Fatalf("peer nc %d exited before cleanup", pid)
	}
}

func TestEveryChildAndSocketFolderIsGoneAfterTheSubtest(t *testing.T) {
	before := socketDirs(t)
	var pids []int
	t.Run("uses-hooks", func(t *testing.T) {
		env := newEnv(t, fakeBridge(t), hostHooks{}, modeReal)
		for i := 0; i < 3; i++ {
			pids = append(pids, env.Spawn().PID)
		}
		_, p1 := env.Peer()
		_, p2 := env.Peer()
		pids = append(pids, p1, p2)
		exited := env.Spawn()
		env.Exit(exited)
		for _, pid := range pids {
			if !alive(pid) {
				t.Fatalf("PID %d died before the subtest ended", pid)
			}
		}
		if n := len(socketDirs(t)) - len(before); n < 2 {
			t.Fatalf("%d new socket folders for two peers", n)
		}
	})
	waitGone(t, pids)
	for dir := range socketDirs(t) {
		if !before[dir] {
			t.Errorf("socket folder %s left behind", dir)
		}
	}
}

func TestKillAllTwiceIsHarmless(t *testing.T) {
	c := &children{t: t}
	pid := c.spawn().PID
	_, peer := c.peer()
	c.killAll()
	c.killAll()
	waitGone(t, []int{pid, peer})
	// The table can be used again after a killAll.
	again := c.spawn()
	c.killAll()
	waitGone(t, []int{again.PID})
}

func TestConcurrentSpawnsAreAllTrackedAndKilled(t *testing.T) {
	c := &children{t: t}
	const n = 8
	refs := make([]platform.ProcessRef, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); refs[i] = c.spawn() }(i)
	}
	wg.Wait()
	seen := map[int]bool{}
	var pids []int
	for _, r := range refs {
		if seen[r.PID] || r.Generation == 0 {
			t.Fatalf("concurrent spawns gave %v", refs)
		}
		seen[r.PID] = true
		pids = append(pids, r.PID)
	}
	c.killAll()
	waitGone(t, pids)
}

// alive reports whether pid names a process (a zombie counts: it has not
// been reaped).
func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func waitGone(t *testing.T, pids []int) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for _, pid := range pids {
		for alive(pid) {
			if time.Now().After(end) {
				t.Fatalf("PID %d still exists after cleanup", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func socketDirs(t *testing.T) map[string]bool {
	t.Helper()
	m, err := filepath.Glob("/tmp/nzcf*")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, d := range m {
		out[d] = true
	}
	return out
}
