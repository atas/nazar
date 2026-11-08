package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/loaders"
)

// nazar-agent pins its loaders like the receiver's files. Its own
// code carries them (package loaders); nothing checks the bundle's seal
// when a receiver runs.

// pyReady approves a config whose rule serves both srv and a Python
// receiver, stores the secret, and returns the Python command line.
func (r *runEnv) pyReady(t *testing.T) []string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.bin, "python3"), []byte(elfNode+" python"), 0o755); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(r.root, "srv/app.py")
	if err := os.WriteFile(app, []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(r.config(strings.Replace(itermRule, "to: [srv, brave-mcp]", "to: [srv, py]", 1)),
		"apps:\n", "apps:\n  py: {command: [python3, "+fmt.Sprintf("%q", app)+"]}\n", 1)
	r.approved(t, cfg)
	if _, err := r.d.secrets.Add("API_KEY", []byte(testValue), platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	r.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	return []string{"python3", app}
}

func do(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// loaderTick lets the file clock move on after the fixture was written
// (Linux's is coarse), as an installed bundle's files are long written.
func loaderTick() { time.Sleep(20 * time.Millisecond) }

// A loader that is not byte for byte the agent's own, or that has anything
// beside it, is refused before any prompt.
func TestRunLoaderNotTheAgentsOwnIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		python bool
		mod    func(t *testing.T, dir string)
	}{
		{name: "the Node loader edited", mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "node", "env.cjs"), []byte(loaders.Node+"\n//"), 0o644))
		}},
		{name: "the Python loader edited", python: true, mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "python", "sitecustomize.py"), []byte(loaders.Python+"\n#"), 0o644))
		}},
		{name: "the Node loader a link to a true copy", mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "copy.cjs"), []byte(loaders.Node), 0o644))
			do(t, os.Remove(filepath.Join(d, "node", "env.cjs")))
			do(t, os.Symlink("../copy.cjs", filepath.Join(d, "node", "env.cjs")))
		}},
		{name: "the Python loader's folder a link to a true copy", python: true, mod: func(t *testing.T, d string) {
			do(t, os.Rename(filepath.Join(d, "python"), filepath.Join(d, "python-real")))
			do(t, os.Symlink("python-real", filepath.Join(d, "python")))
		}},
		{name: "a file beside the Node loader", mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "node", "extra.js"), []byte("x"), 0o644))
		}},
		{name: "a module beside the Python loader", python: true, mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "python", "socket.py"), []byte("x"), 0o644))
		}},
		{name: "an extension beside the Python loader", python: true, mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "python", "sitecustomize.cpython-314-darwin.so"), []byte("x"), 0o644))
		}},
		{name: "cached bytecode beside the Python loader", python: true, mod: func(t *testing.T, d string) {
			do(t, os.MkdirAll(filepath.Join(d, "python", "__pycache__"), 0o755))
			do(t, os.WriteFile(filepath.Join(d, "python", "__pycache__", "sitecustomize.cpython-314.pyc"), []byte("x"), 0o644))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startRun(t, nil)
			argv := []string{"node", r.srv}
			if tc.python {
				argv = r.pyReady(t)
			} else {
				r.ready(t, itermRule)
			}
			tc.mod(t, r.loaders)
			r.asCLI(cliProc("run"))
			_, p := r.run(t, argv, nil, nil)
			if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "its loaders are missing or were changed") {
				t.Fatalf("problem %+v", p)
			}
			if r.f.CountShown(fake.KindConfirm) != 0 {
				t.Fatal("asked before refusing")
			}
			if f := r.lastAudit(t, audit.Blocked); !strings.Contains(f["reason"], "its loaders are missing or were changed") {
				t.Fatalf("audit %v", f)
			}
		})
	}
}

// A loader changed during the run, even when put back, is never served:
// the file and its folder are checked again at the exec and right before
// the write, like the receiver's own files.
func TestRunLoaderChangedDuringTheRunIsNeverServed(t *testing.T) {
	node := func(d string) string { return filepath.Join(d, "node", "env.cjs") }
	for _, tc := range []struct {
		name       string
		python     bool
		beforeExec bool
		mod        func(t *testing.T, dir string)
	}{
		{name: "the Node loader rewritten and put back", mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(node(d), []byte("evil()\n"), 0o644))
			do(t, os.WriteFile(node(d), []byte(loaders.Node), 0o644))
		}},
		{name: "the Node loader rewritten before the exec and put back", beforeExec: true, mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(node(d), []byte("evil()\n"), 0o644))
			do(t, os.WriteFile(node(d), []byte(loaders.Node), 0o644))
		}},
		{name: "the Node loader swapped and put back", mod: func(t *testing.T, d string) {
			do(t, os.Rename(node(d), node(d)+".orig"))
			do(t, os.WriteFile(node(d), []byte("evil()\n"), 0o644))
			do(t, os.Rename(node(d)+".orig", node(d)))
		}},
		{name: "a file added beside the Node loader and removed", mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "node", "extra.js"), []byte("x"), 0o644))
			do(t, os.Remove(filepath.Join(d, "node", "extra.js")))
		}},
		{name: "the Node loader's folder moved aside and back", mod: func(t *testing.T, d string) {
			do(t, os.Rename(filepath.Join(d, "node"), filepath.Join(d, "node.aside")))
			do(t, os.MkdirAll(filepath.Join(d, "node"), 0o755))
			do(t, os.WriteFile(node(d), []byte("evil()\n"), 0o644))
			do(t, os.RemoveAll(filepath.Join(d, "node")))
			do(t, os.Rename(filepath.Join(d, "node.aside"), filepath.Join(d, "node")))
		}},
		// Moving a folder changes its own ctime, not that of anything in
		// it: only a pin of the folder moved sees it.
		{name: "the loaders folder moved aside and back", mod: func(t *testing.T, d string) {
			do(t, os.Rename(d, d+".aside"))
			do(t, os.MkdirAll(filepath.Join(d, "node"), 0o755))
			do(t, os.WriteFile(node(d), []byte("evil()\n"), 0o644))
			do(t, os.RemoveAll(d))
			do(t, os.Rename(d+".aside", d))
		}},
		{name: "the folder holding the loaders moved aside and back", mod: func(t *testing.T, d string) {
			up := filepath.Dir(d)
			do(t, os.Rename(up, up+".aside"))
			do(t, os.MkdirAll(filepath.Join(d, "node"), 0o755))
			do(t, os.WriteFile(node(d), []byte("evil()\n"), 0o644))
			do(t, os.RemoveAll(up))
			do(t, os.Rename(up+".aside", up))
		}},
		{name: "a module added beside the Python loader and removed", python: true, mod: func(t *testing.T, d string) {
			do(t, os.WriteFile(filepath.Join(d, "python", "socket.py"), []byte("x"), 0o644))
			do(t, os.Remove(filepath.Join(d, "python", "socket.py")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startRun(t, nil)
			argv := []string{"node", r.srv}
			if tc.python {
				argv = r.pyReady(t)
			} else {
				r.ready(t, itermRule)
			}
			cli := r.asCLI(cliProc("run"))
			plan, p := r.run(t, argv, nil, nil)
			if p != nil {
				t.Fatal(p)
			}
			loaderTick()
			if tc.beforeExec {
				tc.mod(t, r.loaders)
				r.execAs(t, cli, plan, nil)
			} else {
				r.serving(t, cli, plan)
				tc.mod(t, r.loaders)
			}
			if got := r.connect(t, plan, cli); got != "" && !strings.HasPrefix(got, "dial:") {
				t.Fatalf("served %d bytes after the loader changed", len(got))
			}
			if f := r.lastAudit(t, audit.Denied); f["reason"] != "receiver changed at exec: nazar's loader changed" {
				t.Fatalf("audit %v", f)
			}
		})
	}
}

// A Python receiver writes no bytecode beside the loader, inside the signed
// bundle; the caller can't turn that off (every PYTHON* name is denied).
func TestRunPythonPlanWritesNoBytecode(t *testing.T) {
	r := startRun(t, nil)
	argv := r.pyReady(t)
	r.asCLI(cliProc("run"))
	plan, p := r.run(t, argv, []string{"PYTHONDONTWRITEBYTECODE=0"}, nil)
	if p != nil {
		t.Fatal(p)
	}
	n := 0
	for _, kv := range plan.Env {
		if strings.HasPrefix(kv, "PYTHONDONTWRITEBYTECODE=") {
			n++
		}
	}
	if n != 1 || envVal(plan.Env, "PYTHONDONTWRITEBYTECODE") != "1" {
		t.Fatalf("env %q", plan.Env)
	}
}
