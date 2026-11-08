package run

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The resolver of secrets design 6.3.6, as built in M10 (6.3 D2, D4, D6,
// D7). It runs over real files in a temporary tree: a fake Node install
// (bin/node, bin/npx → lib/node_modules/npm/bin/npx-cli.js), a fake
// Python, a mise shim, and planted look-alikes.

type tree struct {
	root, bin, other, node, python, npxCLI string
}

const elf = "\x7fELF fake interpreter"

func write(t *testing.T, path, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func link(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func newTree(t *testing.T) tree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{root: root, bin: filepath.Join(root, "node/bin"), other: filepath.Join(root, "other")}
	tr.node = write(t, filepath.Join(tr.bin, "node"), elf+" node", 0o755)
	tr.npxCLI = write(t, filepath.Join(root, "node/lib/node_modules/npm/bin/npx-cli.js"), "#!/usr/bin/env node\nrequire('../lib/cli.js')\n", 0o755)
	link(t, "../lib/node_modules/npm/bin/npx-cli.js", filepath.Join(tr.bin, "npx"))
	tr.python = write(t, filepath.Join(root, "py/bin/python3.13"), elf+" python", 0o755)
	link(t, "python3.13", filepath.Join(root, "py/bin/python3"))
	write(t, filepath.Join(root, "a.py"), "print(1)\n", 0o644)
	write(t, filepath.Join(root, "x.js"), "console.log(1)\n", 0o644)
	return tr
}

// codeHash stands in for Platform.CodeHash: a hash of the file's bytes.
func codeHash(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := sha256.Sum256(append([]byte("code:"), b...))
	return s[:20], nil
}

func (tr tree) resolver(extra ...string) *Resolver {
	return &Resolver{TrustedPath: append([]string{tr.bin, filepath.Join(tr.root, "py/bin")}, extra...), CodeHash: codeHash}
}

func mustResolve(t *testing.T, r *Resolver, argv ...string) *Resolution {
	t.Helper()
	res, err := r.Resolve(argv)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", argv, err)
	}
	return res
}

func wantRefused(t *testing.T, r *Resolver, want string, argv ...string) *Refusal {
	t.Helper()
	res, err := r.Resolve(argv)
	var ref *Refusal
	if !errors.As(err, &ref) || res != nil {
		t.Fatalf("Resolve(%q) = %+v, %v; want a refusal saying %q", argv, res, err, want)
	}
	if !strings.Contains(ref.Error(), want) {
		t.Fatalf("Resolve(%q): %q does not say %q", argv, ref.Error(), want)
	}
	return ref
}

func TestNpxResolvesToALauncher(t *testing.T) {
	tr := newTree(t)
	res := mustResolve(t, tr.resolver(), "npx", "-y", "@brave/brave-search-mcp-server")
	if res.Kind != KindLauncher || res.Family != FamilyNode {
		t.Fatalf("kind %s/%s", res.Kind, res.Family)
	}
	if res.Image.Path != tr.node || res.Script == nil || res.Script.Path != tr.npxCLI {
		t.Fatalf("image %q script %+v", res.Image.Path, res.Script)
	}
	if want := []string{filepath.Join(tr.bin, "node"), tr.npxCLI, "-y", "@brave/brave-search-mcp-server"}; !slices.Equal(res.ExecArgv, want) {
		t.Fatalf("execArgv = %q, want %q", res.ExecArgv, want)
	}
	if res.Target != "@brave/brave-search-mcp-server" {
		t.Fatalf("target = %q", res.Target)
	}
	if res.Script.SHA256 == "" || len(res.ImageCode) == 0 || res.Image.Ino == 0 {
		t.Fatalf("pins missing: %+v %+v", res.Image, res.Script)
	}
	// The same file named by an absolute path, or by its realpath, is the
	// same receiver; execArgv[0] is derived, never the typed string.
	for _, a0 := range []string{filepath.Join(tr.bin, "npx"), tr.npxCLI} {
		other := mustResolve(t, tr.resolver(), a0, "-y", "@brave/brave-search-mcp-server")
		if other.Identity() != res.Identity() || other.ExecArgv[0] != res.ExecArgv[0] {
			t.Fatalf("%s: identity %q vs %q, execArgv %q", a0, other.Identity(), res.Identity(), other.ExecArgv)
		}
	}
}

// The caller's PATH plays no part: only trustedPath, first entry wins, and
// a look-alike outside it is never found.
func TestBareNamesOnlyThroughTrustedPath(t *testing.T) {
	tr := newTree(t)
	write(t, filepath.Join(tr.other, "npx"), "#!/bin/sh\necho evil\n", 0o755)
	t.Setenv("PATH", tr.other+":"+os.Getenv("PATH"))
	if res := mustResolve(t, tr.resolver(tr.other), "npx", "-y", "x"); res.Script.Path != tr.npxCLI {
		t.Fatalf("the first trustedPath entry wins: %+v", res.Script)
	}
	wantRefused(t, &Resolver{TrustedPath: []string{tr.root + "/py/bin"}, CodeHash: codeHash}, "npx not found in defaults.trustedPath", "npx", "-y", "x")
	// A directory or a non-executable file of that name is skipped.
	if err := os.MkdirAll(filepath.Join(tr.other, "node"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(tr.root, "noexec/node"), elf, 0o644)
	r := &Resolver{TrustedPath: []string{tr.other, filepath.Join(tr.root, "noexec"), tr.bin}, CodeHash: codeHash}
	if res := mustResolve(t, r, "node", filepath.Join(tr.root, "x.js")); res.Image.Path != tr.node {
		t.Fatalf("image = %q", res.Image.Path)
	}
}

func TestArgv0Shapes(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	ref := wantRefused(t, r, "pass the absolute path", "./bin/node", "/x.js")
	if !ref.Usage {
		t.Fatal("a relative argv[0] is a usage error")
	}
	wantRefused(t, r, "pass the absolute path", "bin/node", "-e", "1")
	wantRefused(t, r, "empty", "")
	wantRefused(t, r, "empty", []string{}...)
	wantRefused(t, r, "NUL", "node", "-e", "a\x00b")
	wantRefused(t, r, "not a regular file", tr.bin)
	wantRefused(t, r, "no such file", filepath.Join(tr.root, "missing"))
}

func TestShimsAreRefused(t *testing.T) {
	tr := newTree(t)
	mise := write(t, filepath.Join(tr.root, "mise/bin/mise"), elf+" mise", 0o755)
	link(t, mise, filepath.Join(tr.root, "mise/shims/npx"))
	write(t, filepath.Join(tr.root, ".asdf/shims/node"), "#!/usr/bin/env bash\nexec asdf exec node \"$@\"\n", 0o755)
	r := &Resolver{TrustedPath: []string{filepath.Join(tr.root, "mise/shims"), filepath.Join(tr.root, ".asdf/shims")}, CodeHash: codeHash}
	wantRefused(t, r, "npx resolves to a mise shim; use `mise which npx`", "npx", "-y", "x")
	wantRefused(t, r, "node is a shim", "node", filepath.Join(tr.root, "x.js"))
}

func TestShebangs(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	abs := write(t, filepath.Join(tr.root, "srv/server"), "#!"+tr.node+"\nconsole.log(1)\n", 0o755)
	res := mustResolve(t, r, abs, "--port=1")
	if res.Kind != KindInterpreter || res.Image.Path != tr.node || res.Script.Path != abs ||
		!slices.Equal(res.ExecArgv, []string{tr.node, abs, "--port=1"}) {
		t.Fatalf("%+v", res)
	}
	flagged := write(t, filepath.Join(tr.root, "srv/py"), "#!"+tr.python+" -u\nprint(1)\n", 0o755)
	if res := mustResolve(t, r, flagged); !slices.Equal(res.ExecArgv, []string{tr.python, "-u", flagged}) || res.Family != FamilyPython {
		t.Fatalf("%+v", res)
	}
	for body, want := range map[string]string{
		"#!/usr/bin/env -S node --x\n":                      "unsupported shebang",
		"#!/usr/bin/env\n":                                  "unsupported shebang",
		"#!/usr/bin/env node --flag\n":                      "unsupported shebang",
		"#!node\n":                                          "unsupported shebang",
		"#!" + tr.node + " -a -b\n":                         "unsupported shebang",
		"#!" + abs + "\n":                                   "unsupported shebang", // a script running a script
		"#!/usr/bin/env nodez\n":                            "nodez not found",
		"#!" + tr.python + " -I\n":                          "-I",
		"#!" + tr.python + " -sE\n":                         "-E",
		"#!/usr/bin/env " + strings.Repeat("x", 300) + "\n": "unsupported shebang",
	} {
		p := write(t, filepath.Join(tr.root, "srv/bad"), body+"x\n", 0o755)
		wantRefused(t, r, want, p)
	}
}

func TestKinds(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	x := filepath.Join(tr.root, "x.js")
	if res := mustResolve(t, r, "node", x); res.Kind != KindInterpreter || res.Script != nil || res.Target != "" ||
		!slices.Equal(res.ExecArgv, []string{filepath.Join(tr.bin, "node"), x}) {
		t.Fatalf("%+v", res)
	}
	if res := mustResolve(t, r, "python3", "-m", "http.server"); res.Kind != KindInterpreter || res.Image.Path != tr.python ||
		!slices.Equal(res.ExecArgv, []string{filepath.Join(tr.root, "py/bin/python3"), "-m", "http.server"}) {
		t.Fatalf("%+v", res)
	}
	write(t, filepath.Join(tr.bin, "gh"), elf+" gh", 0o755)
	wantRefused(t, r, "late-env needs node or python; gh is a program", "gh", "api")
	pipx := write(t, filepath.Join(tr.root, "py/bin/pipx"), "#!"+tr.python+"\nimport pipx\n", 0o755)
	wantRefused(t, r, "pipx removes PYTHONPATH", pipx, "run", "x")
	bun := write(t, filepath.Join(tr.root, "bun/bin/bun"), elf+" bun", 0o755)
	link(t, "bun", filepath.Join(tr.root, "bun/bin/bunx"))
	wantRefused(t, r, "Bun ignores NODE_OPTIONS", bun, x)
	wantRefused(t, r, "Bun ignores NODE_OPTIONS", filepath.Join(tr.root, "bun/bin/bunx"), "pkg")
	npm := write(t, filepath.Join(tr.root, "node/lib/node_modules/npm/bin/npm-cli.js"), "#!/usr/bin/env node\n", 0o755)
	wantRefused(t, r, "npm is not a nazar run launcher in this version; use npx", npm, "exec", "x")
	for _, name := range []string{"pnpm.cjs", "uvx", "uv"} {
		p := write(t, filepath.Join(tr.root, "l/"+name), "#!/usr/bin/env node\n", 0o755)
		wantRefused(t, r, "is not a nazar run launcher in this version", p, "x")
	}
}

func TestPythonFlagsThatSkipTheLoader(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	a := filepath.Join(tr.root, "a.py")
	for _, argv := range [][]string{
		{"python3", "-I", a}, {"python3", "-E", a}, {"python3", "-S", a},
		{"python3", "-IS", a}, {"python3", "-uE", a}, {"python3", "-bb", "-s", "-I", "-c", "x"},
	} {
		wantRefused(t, r, "the loader", argv...)
	}
	// -X and -W take a value; -c ends the options; -s alone is harmless.
	for _, argv := range [][]string{
		{"python3", "-X", "importtime", a}, {"python3", "-XI", a}, {"python3", "-Wignore", a},
		{"python3", "-c", "import sys; print(sys.argv)", "-I"}, {"python3", "-s", a}, {"python3", a, "-I"},
	} {
		mustResolve(t, r, argv...)
	}
}

func TestNpxTarget(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	for argv, want := range map[string]string{
		"-y @brave/brave-search-mcp-server":              "@brave/brave-search-mcp-server",
		"--yes @brave/brave-search-mcp-server@1.2.3 --x": "@brave/brave-search-mcp-server",
		"pkg@latest arg": "pkg",
		"pkg":            "pkg",
		"-y a.b_c-d~e":   "a.b_c-d~e",
	} {
		res := mustResolve(t, r, append([]string{"npx"}, strings.Fields(argv)...)...)
		if res.Target != want {
			t.Errorf("npx %s: target %q, want %q", argv, res.Target, want)
		}
	}
	for _, argv := range []string{"", "-y", "-p x y", "--package=x y", "-c 'x'", "-y -y x", "--call x", "-y @Brave/x",
		"-y @brave/../x", "-y ../x", "-y /abs/pkg.tgz", "-y git+https://x/y.git", "-y x/y", "-y .x", "-y @/x", "-y @brave/"} {
		res, err := r.Resolve(append([]string{"npx"}, strings.Fields(argv)...))
		var ref *Refusal
		if !errors.As(err, &ref) || res != nil {
			t.Errorf("npx %s: want a refusal, got %+v %v", argv, res, err)
		}
	}
	wantRefused(t, r, "write it as npx -y <package>", "npx", "-p", "x", "y")
}

func TestFileElementsArePinned(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	srv := write(t, filepath.Join(tr.root, "srv/server.js"), "console.log(1)\n", 0o644)
	setup := write(t, filepath.Join(tr.root, "srv/setup.cjs"), "1\n", 0o644)
	res := mustResolve(t, r, "node", "-r", setup, srv)
	if len(res.Files) != 2 || res.Files[0].Path != setup || res.Files[1].Path != srv || res.Files[1].SHA256 == "" {
		t.Fatalf("files = %+v", res.Files)
	}
	before := res.Identity()
	if err := os.WriteFile(srv, []byte("console.log(2)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mustResolve(t, r, "node", "-r", setup, srv).Identity() == before {
		t.Fatal("other bytes are another receiver")
	}
	// A symlinked element is refused (review fix; TestSymlinkedFileElementsAreRefused).
	ref := wantRefused(t, r, `"server.js" is relative: the receiver runs in /; pass the absolute path`, "node", "server.js")
	if !ref.Usage {
		t.Fatal("a relative file element is a usage error")
	}
	wantRefused(t, r, `"./x.cjs" is relative`, "node", "--require=./x.cjs", srv)
	wantRefused(t, r, "no such file", "node", filepath.Join(tr.root, "srv/missing.js"))
	wantRefused(t, r, "not a regular file", "node", filepath.Join(tr.root, "srv"))
	// A FIFO is refused without blocking.
	fifo := filepath.Join(tr.root, "srv/fifo.js")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		wantRefused(t, r, "not a regular file", "node", fifo)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a FIFO element blocked the resolver")
	}
}

func TestPinnedFilesHaveACap(t *testing.T) {
	tr := newTree(t)
	big := write(t, filepath.Join(tr.root, "srv/big.js"), "", 0o644)
	f, err := os.OpenFile(big, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxPinnedFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	wantRefused(t, tr.resolver(), "larger than", "node", big)
}

func TestIdentity(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	a := mustResolve(t, r, "npx", "-y", "@brave/brave-search-mcp-server")
	if b := mustResolve(t, r, "npx", "-y", "@brave/other"); b.Identity() == a.Identity() {
		t.Fatal("another tail is another receiver")
	}
	if err := os.WriteFile(tr.npxCLI, []byte("#!/usr/bin/env node\nevil()\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if b := mustResolve(t, r, "npx", "-y", "@brave/brave-search-mcp-server"); b.Identity() == a.Identity() {
		t.Fatal("other script bytes are another receiver")
	}
	if err := os.WriteFile(tr.node, []byte(elf+" evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if b := mustResolve(t, r, "npx", "-y", "@brave/brave-search-mcp-server"); b.Identity() == a.Identity() {
		t.Fatal("another interpreter is another receiver")
	}
	r.CodeHash = func(string) ([]byte, error) { return nil, errors.New("no signature") }
	wantRefused(t, r, "code identity", "npx", "-y", "x")
}

func mkfifoAt(p string) error { return syscallMkfifo(p, 0o600) }

var syscallMkfifo = syscall.Mkfifo
