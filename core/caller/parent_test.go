package caller

import (
	"testing"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// For the helper and stdout methods the receiver is the parent of
// the nazar CLI that asked (secrets design 5.2).
func TestParentDropsOnlyThePeer(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{},
		fake.Proc{Path: "/usr/bin/git", Code: fake.AppleCode("com.apple.git")},
		fake.Proc{Path: "/usr/libexec/git-core/git-remote-http", Code: fake.AppleCode("com.apple.git-remote-http")},
		fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned})
	r := &Resolver{P: f}
	c := r.Resolve(tab.Peer())
	p := c.Parent()
	peer, ok := p.Peer()
	if !ok || peer.Ref != tab.Procs[1] || len(p.Procs) != len(c.Procs)-1 {
		t.Fatalf("parent peer %+v ok=%v, %d of %d procs", peer, ok, len(p.Procs), len(c.Procs))
	}
	if p.App.Ref != c.App.Ref || p.Session != c.Session || p.Unknown != c.Unknown {
		t.Fatal("the parent keeps the chain's app and session")
	}
	if got, _ := c.Peer(); got.Ref != tab.Peer() {
		t.Fatal("Parent must not change the chain it was called on")
	}
	lone := r.Resolve(f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/local/bin/x"}))
	if len(lone.Procs) != 1 {
		t.Fatalf("precondition: a launchd child is a chain of one, got %d", len(lone.Procs))
	}
	if _, ok := lone.Parent().Peer(); ok {
		t.Fatal("a chain of one has no parent peer")
	}
	if _, ok := (&Chain{Unknown: true}).Parent().Peer(); ok {
		t.Fatal("an empty chain has no parent peer")
	}
}

// k8s and aws rules are judged on whoever called the client (k8s design
// 2.3): chain[2:]. A client launchd started has no caller, so it is its
// own: chain[1:]. A chain cut off before launchd is not that case.
func TestCallersOfTheClient(t *testing.T) {
	f := fake.New(t0)
	r := &Resolver{P: f}
	cli := fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned}
	tool := fake.Proc{Path: "/opt/homebrew/Cellar/mytool/1.0/bin/mytool", Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{1}}}
	daemon := f.Launch(platform.ProcessRef{}, tool)
	c := r.Resolve(f.Launch(daemon, cli))
	if v := c.Callers(); len(v.Procs) != 1 || v.Procs[0].Ref != daemon || !v.Unknown {
		t.Fatalf("a launchd-started client is its own caller: %+v", v.Procs)
	}
	tab := f.ITermTab(platform.ProcessRef{}, tool, cli)
	c = r.Resolve(tab.Peer())
	if v := c.Callers(); len(v.Procs) != len(c.Procs)-2 || v.Procs[0].Ref != c.Procs[2].Ref {
		t.Fatalf("in a terminal the view starts above the client: %+v", v.Procs)
	}
	cut := &Chain{Procs: c.Procs[:2], Unknown: true, Truncated: true}
	if v := cut.Callers(); len(v.Procs) != 0 {
		t.Fatalf("a truncated chain: nothing above the client is known: %+v", v.Procs)
	}
}
