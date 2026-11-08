package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/bridge/cbridge/cfake"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
)

// The archive's entry points run the real daemon over a callbacks table:
// here cfake's, so no Swift is needed.
func TestStartRunsTheCoreAndStopEndsIt(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "nzbr") // short: sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	cb := cfake.Install(fake.New(time.Now()), fake.NewVault(), &audit.MemorySink{})
	if st := start(cb, "relative/home"); st != 7 {
		t.Fatalf("relative home: status %d, want NZ_INVALID", st)
	}
	if st := start(cb, home); st != 0 {
		t.Fatalf("start: status %d", st)
	}
	ctl := layout.ControlSocket(home)
	waitFor(t, func() bool { _, err := os.Stat(ctl); return err == nil })
	if st := start(cb, home); st != 1 {
		t.Fatalf("second start: status %d, want NZ_ERR", st)
	}
	stop()
	waitFor(t, func() bool { _, err := os.Stat(ctl); return os.IsNotExist(err) })
	stop() // stopping twice is harmless
	bad, free := cfake.BadTable(true)
	defer free()
	if st := start(bad, home); st != 7 {
		t.Fatalf("bad table: status %d, want NZ_INVALID", st)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Milestone 6: the agent has no window. Nothing about one crosses the C
// ABI any more (no NazarSetShowWindow, no NazarShowWindowFn), and the
// running core answers ui.show as an unknown command.
func TestNoWindowCrossesTheBridge(t *testing.T) {
	for _, f := range []string{"main.go", "../macos/Sources/CNazarBridge/include/nazar_bridge.h"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"ShowWindow", "ui.show"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s still mentions %s", f, bad)
			}
		}
	}
	// No other file of the archive keeps the hook either (a leftover
	// window.go would still export NazarSetShowWindow), and the Swift side
	// registers no window opener while MenuBar.swift exists (Milestone 6
	// deleted it).
	srcs, err := filepath.Glob("*.go")
	if err != nil || len(srcs) == 0 {
		t.Fatal(srcs, err)
	}
	more, _ := filepath.Glob("cbridge/*.go")
	srcs = append(srcs, more...)
	if _, err := os.Stat("../macos/Sources/NazarApp/MenuBar.swift"); err == nil {
		srcs = append(srcs, "../macos/Sources/NazarApp/MenuBar.swift")
	}
	for _, f := range srcs {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"ShowWindow", "showWindow", "NazarShowWindowFn"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s still has the window hook (%s)", f, bad)
			}
		}
	}
	home, err := os.MkdirTemp("/tmp", "nzbr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	cb := cfake.Install(fake.New(time.Now()), fake.NewVault(), &audit.MemorySink{})
	if st := start(cb, home); st != 0 {
		t.Fatalf("start: status %d", st)
	}
	defer stop()
	ctl := layout.ControlSocket(home)
	waitFor(t, func() bool { _, err := os.Stat(ctl); return err == nil })
	c := &control.Client{Socket: ctl, Verifier: control.SameUserVerifier{}}
	err = c.Call(context.Background(), control.NewRequest("ui.show", nil), control.KindUI, &struct{}{})
	if p := control.AsProblem(err); p == nil || p.ExitCode() != control.ExitUsage {
		t.Fatalf("ui.show: %+v", p)
	}
}

// D8, D9: the daemon gets the exec seam when the Swift layer has
// it, and the loader folder of the agent bundle this process runs from:
// <name>.app/Contents/MacOS/<exe> → <name>.app/Contents/Resources/loaders,
// a real directory; anything else is "" (late-env refused).
func TestCoreOptionsWireExecAndLoaders(t *testing.T) {
	b, err := cbridge.New(cfake.Install(fake.New(time.Now()), fake.NewVault(), &audit.MemorySink{}))
	if err != nil {
		t.Fatal(err)
	}
	if o := coreOptions(b, "/tmp/h"); o.Exec == nil || o.LoaderDir != "" {
		t.Fatalf("Exec %v, LoaderDir %q (the test binary is in no agent bundle)", o.Exec, o.LoaderDir)
	}
	// The mount watch is macOS only (package mounts); elsewhere it is nil and
	// late-env is refused.
	if o, mac := coreOptions(b, "/tmp/h"), runtime.GOOS == "darwin"; (o.Mounts != nil) != mac {
		t.Fatalf("Mounts %v on %s: want a mount watch exactly on macOS", o.Mounts, runtime.GOOS)
	}
	// So is the stdout check of k8s.credential (package pipes).
	if o, mac := coreOptions(b, "/tmp/h"), runtime.GOOS == "darwin"; (o.Pipes != nil) != mac {
		t.Fatalf("Pipes %v on %s: want a stdout check exactly on macOS", o.Pipes, runtime.GOOS)
	}
	p, free := cfake.NoExecTable(false)
	nb, err := cbridge.New(p)
	free()
	if err != nil {
		t.Fatal(err)
	}
	if o := coreOptions(nb, "/tmp/h"); o.Exec != nil {
		t.Fatalf("no exec callbacks: Exec = %v, want nil", o.Exec)
	}
}

func TestLoaderDir(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(p string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	app := filepath.Join(root, "nazar-agent.app")
	exe := mk(filepath.Join(app, "Contents/MacOS/nazar-agent"))
	want := filepath.Join(app, "Contents/Resources/loaders")
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "agent-link")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	noLoaders := mk(filepath.Join(root, "empty.app/Contents/MacOS/nazar-agent"))
	linked := mk(filepath.Join(root, "linked.app/Contents/MacOS/nazar-agent"))
	if err := os.MkdirAll(filepath.Join(root, "linked.app/Contents/Resources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(want, filepath.Join(root, "linked.app/Contents/Resources/loaders")); err != nil {
		t.Fatal(err)
	}
	file := mk(filepath.Join(root, "file.app/Contents/MacOS/nazar-agent"))
	mk(filepath.Join(root, "file.app/Contents/Resources/loaders"))
	notApp := mk(filepath.Join(root, "bundle/Contents/MacOS/nazar-agent"))
	if err := os.MkdirAll(filepath.Join(root, "bundle/Contents/Resources/loaders"), 0o755); err != nil {
		t.Fatal(err)
	}
	bare := mk(filepath.Join(root, "bin/nazar-agent"))
	for exe, w := range map[string]string{
		exe: want, link: want, // through a symlink: the realpath decides
		noLoaders: "", linked: "", file: "", notApp: "", bare: "",
		"relative/nazar-agent": "", "": "", filepath.Join(root, "missing"): "",
	} {
		if got := loaderDir(exe); got != w {
			t.Errorf("loaderDir(%q) = %q, want %q", exe, got, w)
		}
	}
	if self, _ := os.Executable(); loaderDir(self) != "" {
		t.Error("the test binary is in no agent bundle")
	}
}
