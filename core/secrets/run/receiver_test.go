package run

import (
	"crypto/sha256"
	"path/filepath"
	"slices"
	"testing"

	"github.com/atas/nazar/core/caller"
)

// The record a run receiver is judged and remembered by. Its path
// is what argv[0] resolved to (the script for a script), its argv the
// command line as typed, its cwd /, and its code hash the digest of the
// resolution's Identity, so the approval key changes with any pinned byte
// or argument (D5).
func TestReceiverRecord(t *testing.T) {
	tr := newTree(t)
	argv := []string{"npx", "-y", "@brave/brave-search-mcp-server"}
	res := mustResolve(t, tr.resolver(), argv...)
	p := res.Receiver(nil)
	if p.Path != tr.npxCLI || p.Cwd != "/" || len(p.Code.CDHash) != sha256.Size || p.Code.Signed || !p.Ref.IsZero() {
		t.Fatalf("receiver %+v", p)
	}
	if c := caller.Synthetic(p); !c.Synthetic || len(c.Procs) != 1 {
		t.Fatalf("chain %+v", c)
	}
	direct := mustResolve(t, tr.resolver(), "node", "-e", "1")
	if p := direct.Receiver(nil); p.Path != tr.node {
		t.Fatalf("a direct interpreter is its own path: %q", p.Path)
	}
}

// Review: the record's argv is the realpath and the resolution's own
// tail; its digest also covers the environment the receiver gets (the
// envAllow values and PATH included), and Locate is the path a command:
// matcher resolves to.
func TestReceiverRecordReview(t *testing.T) {
	tr := newTree(t)
	r := tr.resolver()
	res := mustResolve(t, r, "npx", "-y", "@brave/brave-search-mcp-server")
	env := []string{"PATH=/a", "HTTPS_PROXY=http://a"}
	p := res.Receiver(env)
	if !slices.Equal(p.Args, []string{tr.npxCLI, "-y", "@brave/brave-search-mcp-server"}) {
		t.Fatalf("args %q", p.Args)
	}
	if q := res.Receiver([]string{"PATH=/a", "HTTPS_PROXY=http://b"}); slices.Equal(q.Code.CDHash, p.Code.CDHash) {
		t.Fatal("another envAllow value is another receiver")
	}
	if q := res.Receiver([]string{"HTTPS_PROXY=http://a", "PATH=/a"}); !slices.Equal(q.Code.CDHash, p.Code.CDHash) {
		t.Fatal("the order of the environment does not matter")
	}
	for _, a0 := range []string{"npx", "node", filepath.Join(tr.bin, "npx")} {
		got, err := r.Locate(a0)
		argv := []string{a0, "-y", "x"}
		if a0 == "node" {
			argv = []string{a0, "-e", "1"}
		}
		if want := mustResolve(t, r, argv...).Receiver(nil).Path; err != nil || got != want {
			t.Fatalf("Locate(%s) = %q, %v; want %q", a0, got, err, want)
		}
	}
	if _, err := r.Locate("./x"); err == nil {
		t.Fatal("Locate refuses what Resolve refuses")
	}
}
