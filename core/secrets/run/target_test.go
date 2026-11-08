package run

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The agent's own check of a launcher's socket peer, the loader's
// target rule in Go: the realpath of the peer's main module is a
// bin of the target package, installed as the first node_modules of its
// path, with no node_modules after it, and its package.json names it.
func TestIsBinOf(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	cache := filepath.Join(root, "_npx/abc")
	pkg := filepath.Join(cache, "node_modules/@brave/brave-search-mcp-server")
	bin := write(t, filepath.Join(pkg, "dist/index.js"), "x", 0o644)
	write(t, filepath.Join(pkg, "package.json"), `{"name":"@brave/brave-search-mcp-server","bin":{"brave":"dist/index.js"}}`, 0o644)
	write(t, filepath.Join(pkg, "install.js"), "x", 0o644)
	link(t, bin, filepath.Join(cache, "node_modules/.bin/brave"))
	nested := filepath.Join(cache, "node_modules/bar/node_modules/@brave/brave-search-mcp-server")
	nbin := write(t, filepath.Join(nested, "dist/index.js"), "x", 0o644)
	write(t, filepath.Join(nested, "package.json"), `{"name":"@brave/brave-search-mcp-server","bin":"dist/index.js"}`, 0o644)
	other := filepath.Join(cache, "node_modules/evil")
	ebin := write(t, filepath.Join(other, "x.js"), "x", 0o644)
	write(t, filepath.Join(other, "package.json"), `{"name":"@brave/brave-search-mcp-server","bin":"x.js"}`, 0o644)
	const target = "@brave/brave-search-mcp-server"
	for main, want := range map[string]bool{
		bin: true,
		filepath.Join(cache, "node_modules/.bin/brave"): true,
		filepath.Join(pkg, "install.js"):                false,
		nbin:                                            false,
		ebin:                                            false,
		"":                                              false,
		filepath.Join(root, "missing.js"):               false,
	} {
		if got := IsBinOf(main, target); got != want {
			t.Errorf("IsBinOf(%q) = %v, want %v", main, got, want)
		}
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"other","bin":"dist/index.js"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsBinOf(bin, target) {
		t.Fatal("a package.json naming another package is not the target")
	}
}

// Review: IsBinOf reads files a launcher's tree controls, so a
// FIFO or a symlink as package.json must never block or be followed, and
// look-alike names and odd bin maps are not the target.
func TestIsBinOfReview(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	const target = "@brave/brave-search-mcp-server"
	pkg := filepath.Join(root, "node_modules", target)
	bin := write(t, filepath.Join(pkg, "dist/index.js"), "x", 0o644)
	pj := filepath.Join(pkg, "package.json")
	set := func(body string) {
		os.Remove(pj)
		write(t, pj, body, 0o644)
	}
	set(`{"name":"@brave/brave-search-mcp-server","bin":{"n":7,"brave":"dist/index.js"}}`)
	if !IsBinOf(bin, target) {
		t.Error("a bin map with a non-string entry still lists the bin")
	}
	evil := filepath.Join(root, "node_modules", target+"-evil")
	ebin := write(t, filepath.Join(evil, "dist/index.js"), "x", 0o644)
	write(t, filepath.Join(evil, "package.json"), `{"name":"@brave/brave-search-mcp-server","bin":"dist/index.js"}`, 0o644)
	if IsBinOf(ebin, target) {
		t.Error("a look-alike package name is not the target")
	}
	up := write(t, filepath.Join(root, "node_modules", "x.js"), "x", 0o644)
	set(`{"name":"@brave/brave-search-mcp-server","bin":"../../x.js"}`)
	if IsBinOf(up, target) {
		t.Error("a bin outside the package is not the target")
	}
	// A symlinked package.json is not followed.
	real := write(t, filepath.Join(root, "real.json"), `{"name":"@brave/brave-search-mcp-server","bin":"dist/index.js"}`, 0o644)
	os.Remove(pj)
	link(t, real, pj)
	if IsBinOf(bin, target) {
		t.Error("a symlinked package.json must not be followed")
	}
	// A FIFO never blocks.
	os.Remove(pj)
	if err := syscall.Mkfifo(pj, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { done <- IsBinOf(bin, target) }()
	select {
	case got := <-done:
		if got {
			t.Error("a FIFO package.json is not a package")
		}
	case <-time.After(time.Second):
		t.Fatal("IsBinOf blocked on a FIFO package.json")
	}
}
