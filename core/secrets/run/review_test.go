package run

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Review findings, each a test that failed before its fix.

// headHash stands in for a code hash that does not read the whole file.
func headHash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, 4096)
	n, _ := f.Read(b)
	fi, _ := f.Stat()
	s := sha256.Sum256(append(b[:n], byte(fi.Size())))
	return s[:20], nil
}

// A real node is ~100–120 MB: the image is pinned by its code identity and
// file identity, not by a hash of its bytes, so the cap does not apply.
func TestARealSizedInterpreterResolves(t *testing.T) {
	tr := newTree(t)
	f, err := os.OpenFile(tr.node, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(120 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r := tr.resolver()
	r.CodeHash = headHash
	res := mustResolve(t, r, "npx", "-y", "@brave/brave-search-mcp-server")
	if res.Image.Path != tr.node || res.Image.SHA256 != "" || len(res.ImageCode) == 0 || res.Image.Size != 120<<20 {
		t.Fatalf("image %+v", res.Image)
	}
}

// A file element that is, or sits under, a symlink can be re-pointed after
// it was pinned: it is refused (6.3.7), and Recheck re-resolves it.
func TestSymlinkedFileElementsAreRefused(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	srv := write(t, filepath.Join(tr.root, "srv/server.js"), "1\n", 0o644)
	link(t, srv, filepath.Join(tr.root, "srv/link.js"))
	link(t, filepath.Join(tr.root, "srv"), filepath.Join(tr.root, "current"))
	wantRefused(t, r, "is a symlink or under one", "node", filepath.Join(tr.root, "srv/link.js"))
	wantRefused(t, r, "is a symlink or under one", "node", filepath.Join(tr.root, "current/server.js"))
	res := mustResolve(t, r, "node", srv)
	if err := r.Recheck(res); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	evil := write(t, filepath.Join(tr.root, "evil.js"), "1\n", 0o644)
	if err := os.Remove(srv); err != nil {
		t.Fatal(err)
	}
	link(t, evil, srv)
	if err := r.Recheck(res); err == nil || !strings.Contains(err.Error(), "server.js") {
		t.Fatalf("a symlink swapped in must be refused: %v", err)
	}
}

func TestRecheck(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	srv := write(t, filepath.Join(tr.root, "srv/server.js"), "1\n", 0o644)
	fresh := func() *Resolution {
		return mustResolve(t, r, "npx", "-y", "@brave/brave-search-mcp-server", "--config="+srv)
	}
	for name, change := range map[string]func(){
		"script bytes":       func() { write(t, tr.npxCLI, "#!/usr/bin/env node\nevil()\n", 0o755) },
		"file element bytes": func() { write(t, srv, "2\n", 0o644) },
		"file element inode": func() { os.Rename(srv, srv+".old"); write(t, srv, "1\n", 0o644) },
		"image code":         func() { write(t, tr.node, elf+" other node", 0o755) },
		"image replaced":     func() { os.Rename(tr.node, tr.node+".old"); write(t, tr.node, elf+" node", 0o755) },
		"script made a FIFO": func() { os.Remove(tr.npxCLI); mkfifo(t, tr.npxCLI) },
	} {
		// Remove before writing: a FIFO left by an earlier case would block
		// the write (the cases run in map order). The replacing cases rename
		// the old file aside instead: a removed file's inode can come back at
		// once with the same size and (coarse clock) times.
		os.Remove(tr.npxCLI)
		write(t, tr.npxCLI, "#!/usr/bin/env node\nrequire('../lib/cli.js')\n", 0o755)
		os.Remove(tr.node)
		write(t, tr.node, elf+" node", 0o755)
		os.Remove(srv)
		write(t, srv, "1\n", 0o644)
		res := fresh()
		if err := r.Recheck(res); err != nil {
			t.Fatalf("%s: unchanged must pass: %v", name, err)
		}
		change()
		var ref *Refusal
		if err := r.Recheck(res); !errors.As(err, &ref) {
			t.Errorf("%s: must be refused, got %v", name, err)
		}
	}
}

// On macOS /usr/bin/python3 (and its siblings) is Apple's xcode-select
// shim, which execs another python in the same process: refused. The
// python it would run, Xcode's, can't be a receiver either (spike S14:
// it is a framework build, which execs itself again as Python.app, and
// the agent refuses a second exec), so the refusal no longer sends the
// user to `xcrun --find python3` but to a python that works (6.3.6 step 4).
func TestXcodeSelectShimsAreRefused(t *testing.T) {
	tr := newTree(t)
	usrbin := filepath.Join(tr.root, "usr/bin")
	write(t, filepath.Join(usrbin, "python3"), elf+" shim", 0o755)
	r := &Resolver{TrustedPath: []string{usrbin, tr.bin}, CodeHash: codeHash, ShimDirs: []string{usrbin}}
	ref := wantRefused(t, r, "python3 is Apple's xcode-select shim; Apple's python3 can't take a secret by late-env: use another python3, such as mise's, and add its folder to defaults.trustedPath", "python3", "-c", "1")
	if strings.Contains(ref.Error(), "xcrun") {
		t.Fatalf("the refusal still points at Xcode's python3, which can't be a receiver: %q", ref.Error())
	}
	py := write(t, filepath.Join(tr.root, "srv/app.py"), "#!/usr/bin/env python3\nprint(1)\n", 0o755)
	wantRefused(t, r, "xcode-select shim", py)
	if res := mustResolve(t, r, "node", "-e", "1"); res.Image.Path != tr.node {
		t.Fatalf("other directories are unaffected: %+v", res.Image)
	}
}

// A framework build of Python (Homebrew's, python.org's, Xcode's) is a
// stub, <X>.framework/Versions/<v>/bin/python3.N, that execs
// Resources/Python.app/Contents/MacOS/Python in the same process (spike
// S14: the readability table saw that second exec for Homebrew's
// python3.15 and Xcode's python3.9; mise's python3.13 and python3.14 run
// as exec'd). The agent refuses a run whose receiver execs again, so such a
// python could only ever fail after the dialog: it is refused when the
// command line is resolved, before any prompt, by whatever name or link it
// is reached (6.3.6 step 7). Only Python's stub does this: a node that
// lives in a framework folder, and a non-framework python, resolve.
func TestFrameworkPythonsAreRefused(t *testing.T) {
	tr := newTree(t)
	const tail = ", which starts itself again, so it can't take a secret by late-env: use another python3, such as mise's, and add its folder to defaults.trustedPath"
	hbBin := filepath.Join(tr.root, "homebrew/bin")
	hb := write(t, filepath.Join(tr.root, "homebrew/Cellar/python@3.15/3.15.0/Frameworks/Python.framework/Versions/3.15/bin/python3.15"), elf+" python stub", 0o755)
	link(t, hb, filepath.Join(hbBin, "python3"))
	link(t, hb, filepath.Join(hbBin, "python3.15"))
	xcBin := filepath.Join(tr.root, "Xcode.app/Contents/Developer/usr/bin")
	xc := write(t, filepath.Join(tr.root, "Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9"), elf+" python stub", 0o755)
	link(t, xc, filepath.Join(xcBin, "python3"))
	r := &Resolver{TrustedPath: []string{hbBin, xcBin, tr.bin}, CodeHash: codeHash}

	wantRefused(t, r, "python3.15 is a framework build of Python"+tail, "python3", "-c", "1")
	wantRefused(t, r, "python3.15 is a framework build of Python"+tail, "python3.15", "-c", "1")
	wantRefused(t, r, "python3.15 is a framework build of Python"+tail, hb, "-c", "1")
	wantRefused(t, r, "python3.9 is a framework build of Python"+tail, filepath.Join(xcBin, "python3"), "-c", "1")
	script := write(t, filepath.Join(tr.root, "srv/app.py"), "#!"+filepath.Join(hbBin, "python3")+"\nprint(1)\n", 0o755)
	wantRefused(t, r, "python3.15 is a framework build of Python"+tail, script)
	wantRefused(t, r, "framework build of Python", filepath.Join(xcBin, "python3"), "-m", "http.server")

	// Not a framework build: mise's layout, and the tree's own python.
	mise := write(t, filepath.Join(tr.root, "mise/installs/python/3.14.0/bin/python3.14"), elf+" python", 0o755)
	if res := mustResolve(t, r, mise, "-c", "1"); res.Image.Path != mise || res.Family != FamilyPython {
		t.Fatalf("mise's python: %+v", res)
	}
	if res := mustResolve(t, tr.resolver(), "python3", "-c", "1"); res.Image.Path != tr.python {
		t.Fatalf("the tree's python: %+v", res.Image)
	}
	// Only Python's stub re-execs: a node inside a framework folder runs.
	fwNode := write(t, filepath.Join(tr.root, "Tools.framework/Versions/A/bin/node"), elf+" node", 0o755)
	if res := mustResolve(t, r, fwNode, "-e", "1"); res.Image.Path != fwNode || res.Family != FamilyNode {
		t.Fatalf("a node in a framework folder: %+v", res)
	}
}

// A launcher or a refused program run as the script (or -m module) of a
// direct interpreter is refused like its own name: otherwise the value
// would land in the launcher's process (D7).
func TestLaunchersAsAnInterpretersScript(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	pipx := write(t, filepath.Join(tr.root, "py/bin/pipx"), "#!"+tr.python+"\nimport pipx\n", 0o755)
	npm := write(t, filepath.Join(tr.root, "node/lib/node_modules/npm/bin/npm-cli.js"), "#!/usr/bin/env node\n", 0o755)
	for _, argv := range [][]string{
		{"node", tr.npxCLI, "-y", "x"},
		{"node", npm, "exec", "x"},
		{"python3", pipx, "run", "x"},
		{"python3", "-m", "pipx", "run", "x"},
	} {
		wantRefused(t, r, "by its own name", argv...)
	}
}

// Names compare without case, as APFS does.
func TestNamesIgnoreCase(t *testing.T) {
	tr := newTree(t)
	up := write(t, filepath.Join(tr.root, "up/bin/NODE"), elf+" node", 0o755)
	r := &Resolver{TrustedPath: []string{filepath.Join(tr.root, "up/bin")}, CodeHash: codeHash}
	if res := mustResolve(t, r, "NODE", "-e", "1"); res.Family != FamilyNode || res.Image.Path != up {
		t.Fatalf("%+v", res)
	}
	cli := write(t, filepath.Join(tr.root, "up/lib/NPX-CLI.JS"), "#!"+tr.node+"\n", 0o755)
	if res := mustResolve(t, r, cli, "-y", "x"); res.Kind != KindLauncher {
		t.Fatalf("NPX-CLI.JS is npx: %+v", res)
	}
	pipx := write(t, filepath.Join(tr.root, "up/bin/PIPX"), "#!"+tr.python+"\n", 0o755)
	wantRefused(t, r, "pipx", pipx, "run", "x")
}

// execArgv[0] is the absolute path of the entry that resolved (the kernel
// and env pass that): Python finds its venv and sys.executable from it,
// and a bare name would make it search PATH.
func TestExecArgv0IsTheAbsoluteEntry(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	if res := mustResolve(t, r, "npx", "-y", "x"); res.ExecArgv[0] != filepath.Join(tr.bin, "node") {
		t.Fatalf("execArgv %q", res.ExecArgv)
	}
	py3 := filepath.Join(tr.root, "py/bin/python3")
	if res := mustResolve(t, r, py3, "-c", "1"); res.ExecArgv[0] != py3 || res.Image.Path != tr.python {
		t.Fatalf("execArgv %q image %q", res.ExecArgv, res.Image.Path)
	}
	if res := mustResolve(t, r, "python3", "-c", "1"); res.ExecArgv[0] != py3 {
		t.Fatalf("execArgv %q", res.ExecArgv)
	}
	venv := filepath.Join(tr.root, "proj/.venv/bin/python")
	link(t, tr.python, venv)
	tool := write(t, filepath.Join(tr.root, "proj/.venv/bin/tool"), "#!"+venv+"\nimport x\n", 0o755)
	if res := mustResolve(t, r, tool); !slices.Equal(res.ExecArgv, []string{venv, tool}) || res.Image.Path != tr.python {
		t.Fatalf("execArgv %q image %q", res.ExecArgv, res.Image.Path)
	}
}

func TestReviewNits(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	// A shebang with no newline at all is a whole first line.
	p := write(t, filepath.Join(tr.root, "srv/nonl"), "#!"+tr.node, 0o755)
	if res := mustResolve(t, r, p); res.Image.Path != tr.node {
		t.Fatalf("%+v", res)
	}
	// NUL in the shebang's argument.
	wantRefused(t, r, "unsupported shebang", write(t, filepath.Join(tr.root, "srv/nul"), "#!"+tr.python+" -u\x00x\n", 0o755))
	// --check-hash-based-pycs takes a value; options go on after it.
	a := filepath.Join(tr.root, "a.py")
	wantRefused(t, r, "-E", "python3", "--check-hash-based-pycs", "always", "-E", a)
	// node's inspector lets any local process read the receiver's memory.
	for _, f := range []string{"--inspect", "--inspect=9229", "--inspect-brk", "--inspect-wait=0", "--inspect-port=1"} {
		wantRefused(t, r, "debugger", "node", f, filepath.Join(tr.root, "x.js"))
	}
	// npm reads a version of "." or ".." as a path.
	for _, spec := range []string{"foo@.", "foo@..", "foo@./x"} {
		if _, err := r.Resolve([]string{"npx", "-y", spec}); err == nil {
			t.Errorf("npx -y %s must be refused", spec)
		}
	}
	// No code hash seam: refuse, never panic.
	if _, err := (&Resolver{TrustedPath: r.TrustedPath}).Resolve([]string{"node", "-e", "1"}); err == nil || !strings.Contains(err.Error(), "code identity") {
		t.Fatalf("nil CodeHash: %v", err)
	}
	// An asdf shim reached through a link outside its shims directory.
	shim := write(t, filepath.Join(tr.root, ".asdf/shims/node"), "#!/usr/bin/env bash\n", 0o755)
	link(t, shim, filepath.Join(tr.root, "mybin/node"))
	wantRefused(t, &Resolver{TrustedPath: []string{filepath.Join(tr.root, "mybin")}, CodeHash: codeHash}, "is a shim", "node", "-e", "1")
	// Error texts never carry raw control bytes of a path.
	_, err := r.Resolve([]string{"node", filepath.Join(tr.root, "s\x1b[2Jx.js")})
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("raw ESC in %q", err)
	}
	// An interpreter fed from stdin, even when typed, is refused here too.
	wantRefused(t, r, "standard input", "python3", "-")
	wantRefused(t, r, "standard input", "node", "-i")
}

func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := mkfifoAt(p); err != nil {
		t.Fatal(err)
	}
}
