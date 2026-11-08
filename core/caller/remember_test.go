package caller

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// waitSaved waits for the background writes of r's helpers to land.
func (r *Resolver) waitSaved() { r.writes.Wait() }

// storedHelpers decodes the helpers item in v ("" when there is none).
func storedHelpers(t *testing.T, v platform.Vault) map[platform.ProcessRef]seenHelper {
	t.Helper()
	b, err := v.Get(HelpersVaultItem)
	if errors.Is(err, platform.ErrNotFound) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var it helpersItem
	if err := json.Unmarshal(b, &it); err != nil {
		t.Fatalf("%s: %v", HelpersVaultItem, err)
	}
	out := map[platform.ProcessRef]seenHelper{}
	for _, h := range it.Helpers {
		out[platform.ProcessRef{PID: h.PID, Generation: h.Generation}] = seenHelper{team: h.Team, bundleID: h.BundleID}
	}
	return out
}

// An earlier bug: iTerm2's tabs outlived its restart under the old
// iTermServer, and nazar-agent restarted (an install) after it had seen
// that server below iTerm2. The new agent knew nothing of it, so every
// request from those tabs was unknown and matched only any/unknown rules.
// A helper one agent witnessed is kept in the vault and stands for the app
// in the next agent exactly as it would have in the first.
func TestWitnessedHelperSurvivesARestart(t *testing.T) {
	f, v := fake.New(t0), fake.NewVault()
	before := &Resolver{P: f}
	before.Remember(v, nil)
	server, shell, peer := orphanedTab(f, before)
	before.waitSaved()
	if got := storedHelpers(t, v)[server]; got != (seenHelper{team: "H7V7XYVQ7D", bundleID: "com.googlecode.iterm2"}) {
		t.Fatalf("stored %+v for the server", got)
	}
	fresh := f.ITermTab(platform.ProcessRef{}) // iTerm2 came back

	// Without the vault (today's agent after a restart) the tab is unknown.
	if c := (&Resolver{P: f}).Resolve(peer); !c.Unknown {
		t.Fatalf("control: a resolver that saw nothing attributes the tab: %v", c.AppSource)
	}
	after := &Resolver{P: f}
	after.Remember(v, nil)
	c := after.Resolve(peer)
	if c.Unknown || c.AppSource != AppFromHelper || c.App.Ref != fresh.App || c.SessionRoot != shell {
		t.Fatalf("after the restart: unknown=%v source=%v app=%v root=%v", c.Unknown, c.AppSource, c.App.Ref, c.SessionRoot)
	}
	if c.AppIdentity() != "H7V7XYVQ7D:com.googlecode.iterm2" {
		t.Fatalf("identity %q", c.AppIdentity())
	}
}

// Every check helperApp makes still applies to a remembered helper: the
// record only says the helper was seen below its app. With no iTerm2
// running the tab stays unknown after the restart, as it did before.
func TestRememberedHelperStillNeedsItsApp(t *testing.T) {
	f, v := fake.New(t0), fake.NewVault()
	before := &Resolver{P: f}
	before.Remember(v, nil)
	_, _, peer := orphanedTab(f, before)
	before.waitSaved()
	after := &Resolver{P: f}
	after.Remember(v, nil)
	if c := after.Resolve(peer); !c.Unknown || c.AppSource == AppFromHelper {
		t.Fatalf("no iTerm2 running: source=%v", c.AppSource)
	}
}

// A record names one process instance (PID and start time). Once the
// helper exits and its PID is reused, even by a process signed by the same
// team that launchd parents and that heads a shell (a detached copy of
// iTermServer), the record is not that process: the new agent drops it at
// load and the chain stays unknown.
func TestRememberedHelperWhosePIDWasRecycledIsDropped(t *testing.T) {
	f, v := fake.New(t0), fake.NewVault()
	before := &Resolver{P: f}
	before.Remember(v, nil)
	server, _, _ := orphanedTab(f, before)
	before.waitSaved()
	f.Exit(server)

	// The PID comes back as another instance of iTerm2's own server binary.
	f.Launch(platform.ProcessRef{}, fake.SSHProc()) // time passes
	impostor := platform.ProcessRef{PID: server.PID, Generation: server.Generation + 7}
	f.SetProcess(platform.ProcessInfo{Ref: impostor, Parent: f.Launchd, UID: 501, StartTime: f.Now(),
		Path: orphanServer.Path, Code: orphanServer.Code, Comm: "iTermServer-3.7"})
	f.SetResponsible(impostor, impostor)
	sh := f.Launch(impostor, fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")})
	peer := f.Launch(sh, fake.SSHProc("h"))
	f.ITermTab(platform.ProcessRef{}) // a newer iTerm2

	after := &Resolver{P: f}
	after.Remember(v, nil)
	if c := after.Resolve(peer); !c.Unknown || c.AppSource == AppFromHelper {
		t.Fatalf("the recycled PID took the helper's place: source=%v app=%v", c.AppSource, c.App.Ref)
	}
	after.waitSaved()
	if got := storedHelpers(t, v); len(got) != 0 {
		t.Fatalf("the dead helper's record was kept: %v", got)
	}
}

// A record is kept at load only for a live process with exactly its ref
// that is still signed by the team it was seen under; the rest are dropped
// and the item is rewritten without them.
func TestRememberedHelpersAreCheckedAtLoad(t *testing.T) {
	f, v := fake.New(t0), fake.NewVault()
	before := &Resolver{P: f}
	before.Remember(v, nil)
	server, _, _ := orphanedTab(f, before)
	other := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/local/bin/x", Code: platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM1", SigningID: "x", CDHash: []byte{9}}})
	before.waitSaved()
	b, _ := json.Marshal(helpersItem{V: helpersVersion, Helpers: []helperRecord{
		{PID: server.PID, Generation: server.Generation, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"},
		{PID: server.PID, Generation: 0, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"},                     // PID only
		{PID: other.PID, Generation: other.Generation, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"},       // another team now
		{PID: 99999, Generation: 1, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"},                          // gone
		{PID: server.PID, Generation: server.Generation + 1, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"}, // another instance
		{PID: other.PID, Generation: other.Generation, Team: "OTHERTEAM1", BundleID: ""},                            // no app
		{PID: other.PID, Generation: other.Generation, Team: "apple", BundleID: "com.apple.Terminal"},               // Apple
	}})
	v.Put(HelpersVaultItem, b)
	after := &Resolver{P: f}
	after.Remember(v, nil)
	after.mu.Lock()
	n, kept := len(after.seen), after.seen[server]
	after.mu.Unlock()
	if n != 1 || kept != (seenHelper{team: "H7V7XYVQ7D", bundleID: "com.googlecode.iterm2"}) {
		t.Fatalf("kept %d records, server %+v", n, kept)
	}
	after.waitSaved()
	if got := storedHelpers(t, v); len(got) != 1 {
		t.Fatalf("the item was not rewritten without the dropped records: %v", got)
	}
}

// refusingVault is the vault refusing the helpers item as KeychainVault
// refuses an item another program planted under nazar's name (an access
// list that is not nazar's, or nazar's exact access list on an item another
// program created, which securityd's partition check refuses): Get and Put
// fail, and the item stays where it is (otherBuildVault in core/daemon is
// the same for another build of the agent).
type refusingVault struct {
	*fake.Vault
	mu      sync.Mutex
	refused bool
	puts    int
}

func (v *refusingVault) isRefused() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.refused
}

func (v *refusingVault) Get(name string) ([]byte, error) {
	if name == HelpersVaultItem && v.isRefused() {
		return nil, errors.New("platform: vault state/helpers: item trusts another application")
	}
	return v.Vault.Get(name)
}

func (v *refusingVault) Put(name string, value []byte) error {
	v.mu.Lock()
	v.puts++
	v.mu.Unlock()
	if name == HelpersVaultItem && v.isRefused() {
		return errors.New("platform: vault state/helpers: item trusts another application")
	}
	return v.Vault.Put(name, value)
}

// A helpers item planted by another program, here one that would make a
// detached copy of iTermServer (started by a LaunchAgent, never below
// iTerm2) stand for iTerm2, is refused by the vault, and the agent takes
// nothing from it: the chain stays unknown, requests are still served, the
// problem is reported, and the planted item is never overwritten.
func TestPlantedHelpersItemIsIgnored(t *testing.T) {
	f := fake.New(t0)
	v := &refusingVault{Vault: fake.NewVault()}
	detached := f.Launch(platform.ProcessRef{}, orphanServer)
	sh := f.Launch(detached, fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")})
	peer := f.Launch(sh, fake.SSHProc("h"))
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	planted, _ := json.Marshal(helpersItem{V: helpersVersion, Helpers: []helperRecord{
		{PID: detached.PID, Generation: detached.Generation, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"}}})
	v.Vault.Put(HelpersVaultItem, planted)
	v.refused = true

	var logs []string
	r := &Resolver{P: f}
	r.Remember(v, func(format string, args ...any) { logs = append(logs, format) })
	if c := r.Resolve(peer); !c.Unknown || c.AppSource == AppFromHelper {
		t.Fatalf("the planted record was used: source=%v app=%v", c.AppSource, c.App.Ref)
	}
	if c := r.Resolve(tab.Peer()); c.AppSource != AppFromChain { // still serving, and witnessing
		t.Fatalf("a plain iTerm2 tab: source=%v", c.AppSource)
	}
	r.waitSaved()
	if r.HelpersUnreadable() == "" {
		t.Fatal("the refused item is not reported")
	}
	if len(logs) != 1 {
		t.Fatalf("want the refusal logged once, got %q", logs)
	}
	if b, _ := v.Vault.Get(HelpersVaultItem); string(b) != string(planted) {
		t.Fatal("the planted item was overwritten")
	}
	v.mu.Lock()
	puts := v.puts
	v.mu.Unlock()
	if puts != 0 { // the plant went to the inner vault
		t.Fatalf("%d writes over an item the agent can't read", puts)
	}

	// The user removes the item (security delete-generic-password): the
	// next witnessed change is written and the problem clears.
	v.mu.Lock()
	v.refused = false
	v.mu.Unlock()
	v.Vault.Delete(HelpersVaultItem)
	if why := r.HelpersUnreadable(); why != "" {
		t.Fatalf("still unreadable after the item went: %s", why)
	}
	r.waitSaved()
	if got := storedHelpers(t, v); len(got) != 1 {
		t.Fatalf("after the item went, stored %v; want the witnessed server", got)
	}
}

// An item this build can't make sense of (another format, garbage) is a
// fresh start, logged once; it is overwritten by the next change.
func TestCorruptHelpersItemStartsEmpty(t *testing.T) {
	for _, content := range []string{"garbage", `{"v":2,"helpers":[]}`, `{"v":1,"helpers":"x"}`} {
		f, v := fake.New(t0), fake.NewVault()
		v.Put(HelpersVaultItem, []byte(content))
		var logs []string
		r := &Resolver{P: f}
		r.Remember(v, func(format string, args ...any) { logs = append(logs, format) })
		if len(logs) != 1 {
			t.Fatalf("%q: logs %q", content, logs)
		}
		tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
		if c := r.Resolve(tab.Peer()); c.AppSource != AppFromChain {
			t.Fatalf("%q: source=%v", content, c.AppSource)
		}
		r.waitSaved()
		if got := storedHelpers(t, v); len(got) != 1 || r.HelpersUnreadable() != "" {
			t.Fatalf("%q: stored %v, unreadable %q", content, got, r.HelpersUnreadable())
		}
	}
}

// blockingVault holds every Put until released, like a Keychain write
// stuck in securityd.
type blockingVault struct {
	*fake.Vault
	release chan struct{}
}

func (v *blockingVault) Put(name string, value []byte) error {
	<-v.release
	return v.Vault.Put(name, value)
}

// Writing the helpers never holds up a request: a witness only schedules
// the write, and a stuck vault leaves resolving (and witnessing) running.
func TestSavingHelpersNeverBlocksResolve(t *testing.T) {
	f := fake.New(t0)
	v := &blockingVault{Vault: fake.NewVault(), release: make(chan struct{})}
	r := &Resolver{P: f}
	r.Remember(v, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
			if c := r.Resolve(tab.Peer()); c.AppSource != AppFromChain {
				t.Errorf("source=%v", c.AppSource)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Resolve waited for the vault")
	}
	close(v.release)
	r.waitSaved()
	if got := storedHelpers(t, v); len(got) != 3 {
		t.Fatalf("stored %d helpers, want the 3 witnessed (writes coalesce, the last one wins)", len(got))
	}
}

// The item never holds more than maxSeen records, and a load keeps at most
// that many.
func TestRememberedHelpersAreBounded(t *testing.T) {
	f, v := fake.New(t0), fake.NewVault()
	var recs []helperRecord
	for i := 0; i < maxSeen+20; i++ {
		ref := f.Launch(platform.ProcessRef{}, orphanServer)
		recs = append(recs, helperRecord{PID: ref.PID, Generation: ref.Generation, Team: "H7V7XYVQ7D", BundleID: "com.googlecode.iterm2"})
	}
	b, _ := json.Marshal(helpersItem{V: helpersVersion, Helpers: recs})
	v.Put(HelpersVaultItem, b)
	r := &Resolver{P: f}
	r.Remember(v, nil)
	r.mu.Lock()
	n := len(r.seen)
	r.mu.Unlock()
	if n != maxSeen {
		t.Fatalf("loaded %d, want %d", n, maxSeen)
	}
	app := platform.AppInfo{BundleID: "com.googlecode.iterm2", Code: fake.ITermCode}
	for i := 0; i < 50; i++ {
		ref := f.Launch(platform.ProcessRef{}, orphanServer)
		info, _ := f.Process(ref)
		r.witness(info, app)
	}
	r.waitSaved()
	if got := storedHelpers(t, v); len(got) > maxSeen {
		t.Fatalf("stored %d records", len(got))
	}
}

// countingVault counts the writes.
type countingVault struct {
	*fake.Vault
	mu   sync.Mutex
	puts int
}

func (v *countingVault) Put(name string, value []byte) error {
	v.mu.Lock()
	v.puts++
	v.mu.Unlock()
	return v.Vault.Put(name, value)
}

// More live helpers of one team than maxSeen, each seen again and again,
// change the set on every witness (one is evicted for the next). That must
// not turn into back-to-back rewrites of the Keychain item: there is at
// most one write per minWriteInterval, of the latest set (a review
// measured 611 writes, 13.6 MB, in 2 s without it).
func TestHelperWritesAreRateLimited(t *testing.T) {
	f := fake.New(t0)
	v := &countingVault{Vault: fake.NewVault()}
	r := &Resolver{P: f}
	r.Remember(v, nil)
	app := platform.AppInfo{BundleID: "com.googlecode.iterm2", Code: fake.ITermCode}
	var helpers []platform.ProcessInfo
	for i := 0; i < maxSeen+50; i++ {
		info, _ := f.Process(f.Launch(platform.ProcessRef{}, orphanServer))
		helpers = append(helpers, info)
	}
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
		for _, h := range helpers {
			r.witness(h, app)
		}
	}
	r.waitSaved()
	v.mu.Lock()
	puts := v.puts
	v.mu.Unlock()
	if puts > 2 || puts == 0 {
		t.Fatalf("%d writes in 300 ms, want 1 or 2", puts)
	}
	if got := storedHelpers(t, v); len(got) != maxSeen {
		t.Fatalf("stored %d, want the latest full set", len(got))
	}
}
