package cbridge_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/bridge/cbridge/cfake"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"github.com/atas/nazar/core/platform/fake"
)

// harness drives one fake behind the C table, with the conformance hooks.
type harness struct {
	f      *fake.Fake
	mu     sync.Mutex
	queue  []bool
	nextFD int
}

func newHarness(t *testing.T) (*harness, *cbridge.Bridge, *fake.Vault, *audit.MemorySink) {
	t.Helper()
	h := &harness{f: fake.New(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)), nextFD: 10}
	gate := func(platform.Prompt) fake.Answer {
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(h.queue) == 0 {
			return fake.Answer{}
		}
		a := h.queue[0]
		h.queue = h.queue[1:]
		return fake.Answer{Allow: a}
	}
	h.f.SetGateFuncs(gate, gate)
	v, s := fake.NewVault(), &audit.MemorySink{}
	b, err := cbridge.New(cfake.Install(h.f, v, s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n := cfake.Live(); n != 0 {
			t.Errorf("%d Swift-side buffers never freed", n)
		}
		if n := cfake.BadFrees(); n != 0 {
			t.Errorf("%d bad frees", n)
		}
	})
	return h, b, v, s
}

func (h *harness) env(b *cbridge.Bridge) conformance.Env {
	spawn := func() platform.ProcessRef {
		return h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "60"}, Cwd: "/tmp"})
	}
	return conformance.Env{
		P:      b,
		Answer: func(allow bool) { h.mu.Lock(); h.queue = append(h.queue, allow); h.mu.Unlock() },
		Spawn:  spawn,
		Exit:   h.f.Exit,
		Peer: func() (int, int) {
			ref := spawn()
			h.mu.Lock()
			fd := h.nextFD
			h.nextFD++
			h.mu.Unlock()
			h.f.SetPeer(fd, ref)
			return fd, ref.PID
		},
		// The exec group through the C ABI.
		Exec: b.Exec(),
		Execer: func(env []string) conformance.Execer {
			ref, next := h.f.ExecScript(env)
			return conformance.Execer{Ref: ref, Next: func() conformance.Image { return conformance.Image(next()) }}
		},
	}
}

// The whole platform contract holds through the C ABI: every call crosses
// cbridge → C function pointers → cfake → the fake, and every buffer comes
// back through free_buf.
func TestConformanceThroughTheCABI(t *testing.T) {
	conformance.Run(t, func(t *testing.T) conformance.Env {
		h, b, _, _ := newHarness(t)
		return h.env(b)
	})
}

func TestVaultAndSinkThroughTheCABI(t *testing.T) {
	_, b, v, s := newHarness(t)
	vault := b.Vault()
	if _, err := vault.Get("ssh-key/x"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("Get missing = %v", err)
	}
	if err := vault.Put("ssh-key/x", []byte("h")); err != nil {
		t.Fatal(err)
	}
	if err := vault.Put("empty", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := vault.Get("empty"); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("Get(empty) = %q, %v; want a non-nil empty value", got, err)
	}
	if names, err := vault.List("ssh-key/"); err != nil || len(names) != 1 || names[0] != "ssh-key/x" {
		t.Fatalf("List = %v, %v", names, err)
	}
	if names, err := vault.List("none/"); err != nil || names == nil || len(names) != 0 {
		t.Fatalf("List(none) = %#v, %v", names, err)
	}
	if err := vault.Delete("ssh-key/x"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Delete("ssh-key/x"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("second Delete = %v", err)
	}
	if _, err := v.Get("empty"); err != nil {
		t.Fatalf("the fake never saw the Put: %v", err)
	}
	if err := b.Sink().WriteAudit(time.Now(), "decision=allowed target=ssh:x"); err != nil {
		t.Fatal(err)
	}
	if l := s.Lines(); len(l) != 1 || l[0] != "decision=allowed target=ssh:x" {
		t.Fatalf("sink saw %q", l)
	}
}

// Go never trusts what comes back: a record for another PID or instance, a
// PID-only record, unknown fields and trailing data are refused; buffers
// are freed either way.
func TestHostileAnswersAreRefused(t *testing.T) {
	h, b, _, _ := newHarness(t)
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/bin/sleep"})
	good, err := b.Process(ref)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"other pid":     `{"pid":999999,"generation":5,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":1,"path":"/x","args":[],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}}`,
		"pid-only":      `{"pid":` + itoa(ref.PID) + `,"generation":0,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":1,"path":"/x","args":[],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}}`,
		"other gen":     `{"pid":` + itoa(ref.PID) + `,"generation":` + utoa(ref.Generation+1) + `,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":1,"path":"/x","args":[],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}}`,
		"unknown field": `{"pid":` + itoa(ref.PID) + `,"generation":` + utoa(ref.Generation) + `,"isApp":true,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":1,"path":"/x","args":[],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}}`,
		"trailing":      `{"pid":` + itoa(ref.PID) + `,"generation":` + utoa(ref.Generation) + `,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":1,"path":"/x","args":[],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}} {}`,
		"not json":      `<plist/>`,
	} {
		cfake.Corrupt("process", []byte(raw))
		if info, err := b.Process(ref); err == nil {
			t.Errorf("%s: Process accepted %+v", name, info)
		}
	}
	if again, err := b.Process(ref); err != nil || again.Ref != good.Ref {
		t.Fatalf("after the hostile answers: %v %v", again.Ref, err)
	}
	cfake.Corrupt("create_key.pub", []byte{1, 2, 3})
	if _, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Error("CreateKey accepted a 3-byte public key")
	}
	cfake.Corrupt("vault_list", []byte(`null x`))
	if _, err := b.Vault().List(""); err == nil {
		t.Error("List accepted trailing data")
	}
}

func TestOutOfRangeArgumentsNeverReachC(t *testing.T) {
	_, b, _, _ := newHarness(t)
	before := cfake.Allocations()
	if _, _, err := b.CreateKey(platform.Purpose(1<<40), platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Error("CreateKey with a purpose beyond int32 succeeded")
	}
	if _, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.Access(1<<40)); err == nil {
		t.Error("CreateKey with an access beyond int32 succeeded")
	}
	if _, err := b.PeerOf(1 << 40); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("PeerOf(huge) = %v", err)
	}
	if _, err := b.PeerOf(-1); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("PeerOf(-1) = %v", err)
	}
	if cfake.Allocations() != before {
		t.Error("an out-of-range call reached the C table")
	}
}

func TestExitTokensFireOnce(t *testing.T) {
	h, b, _, _ := newHarness(t)
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/bin/sleep"})
	fired := make(chan struct{}, 4)
	b.OnProcessExit(ref, func() { fired <- struct{}{} })
	h.f.Exit(ref)
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("exit callback did not run")
	}
	// A duplicate or forged token runs nothing.
	for tok := uint64(0); tok < 1000; tok++ {
		cbridge.ProcessExited(tok)
	}
	select {
	case <-fired:
		t.Fatal("exit callback ran twice")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestNewRefusesBadTables(t *testing.T) {
	if _, err := cbridge.New(nil); err == nil {
		t.Fatal("New(nil) succeeded")
	}
	for _, wrongVersion := range []bool{true, false} {
		p, free := cfake.BadTable(wrongVersion)
		if _, err := cbridge.New(p); err == nil {
			t.Errorf("New accepted a broken table (wrong version: %v)", wrongVersion)
		}
		free()
	}
}

func itoa(i int) string    { return utoa(uint64(i)) }
func utoa(u uint64) string { return string(bytes.TrimSpace([]byte(fmtU(u)))) }

func fmtU(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b []byte
	for u > 0 {
		b = append([]byte{byte('0' + u%10)}, b...)
		u /= 10
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Further attack and edge cases (test author). Each
// pins a defence-in-depth check of cbridge; every hostile buffer must still
// come back through free_buf (the harness cleanup checks Live and BadFrees).

const zeroCode = `"code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}`

// The platform answers only the question asked: an installed app for
// another bundle id, an app record without a full ref or bundle id, a
// malformed public key, an empty handle, signature or secret, or a buffer
// beyond the output limit are all refused, and the next honest answer is
// accepted again.
func TestMalformedAnswersAreRefused(t *testing.T) {
	h, b, _, _ := newHarness(t)

	h.f.InstallApp("/System/Applications/TextEdit.app", "com.apple.TextEdit", platform.CodeIdentity{Signed: true, Apple: true})
	cfake.Corrupt("installed_app", []byte(`{"bundleId":"com.evil.Other","path":"/tmp/Evil.app",`+zeroCode+`}`))
	if got, err := b.InstalledApp("com.apple.TextEdit"); err == nil {
		t.Errorf("InstalledApp accepted an answer for another bundle id: %+v", got)
	}
	cfake.Corrupt("installed_app", []byte(`{"bundleId":"com.apple.TextEdit","path":"/x","isApple":true,`+zeroCode+`}`))
	if _, err := b.InstalledApp("com.apple.TextEdit"); err == nil {
		t.Error("InstalledApp accepted an unknown field")
	}
	if got, err := b.InstalledApp("com.apple.TextEdit"); err != nil || got.Path != "/System/Applications/TextEdit.app" || !got.Code.Apple {
		t.Fatalf("honest InstalledApp = %+v, %v", got, err)
	}

	app := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"}})
	info, err := b.Process(app)
	if err != nil {
		t.Fatal(err)
	}
	chain := []platform.ProcessInfo{info}
	for name, raw := range map[string]string{
		"pid-only":        `{"pid":` + itoa(app.PID) + `,"generation":0,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}`,
		"no pid":          `{"pid":0,"generation":` + utoa(app.Generation) + `,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}`,
		"no bundle id":    `{"pid":` + itoa(app.PID) + `,"generation":` + utoa(app.Generation) + `,"bundleId":"","name":"iTerm2",` + zeroCode + `}`,
		"unknown field":   `{"pid":` + itoa(app.PID) + `,"generation":` + utoa(app.Generation) + `,"trusted":true,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}`,
		"two documents":   `{"pid":` + itoa(app.PID) + `,"generation":` + utoa(app.Generation) + `,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}{}`,
		"wrong json type": `{"pid":"` + itoa(app.PID) + `","generation":` + utoa(app.Generation) + `,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}`,
	} {
		cfake.Corrupt("app_for", []byte(raw))
		if got, ok := b.AppFor(chain); ok {
			t.Errorf("%s: AppFor accepted %+v", name, got)
		}
	}
	if got, ok := b.AppFor(chain); !ok || got.Ref != app || got.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("honest AppFor = %+v, %v", got, ok)
	}
	if _, ok := b.AppFor(nil); ok {
		t.Error("AppFor(empty chain) resolved an app")
	}

	pk65 := func(first byte) []byte { k := make([]byte, 65); k[0] = first; return k }
	for name, pk := range map[string][]byte{
		"empty":        {},
		"compressed":   append([]byte{2}, make([]byte, 32)...),
		"wrong prefix": pk65(2),
		"too long":     append(pk65(4), 0),
	} {
		cfake.Corrupt("create_key.pub", pk)
		if _, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
			t.Errorf("CreateKey accepted public key %s", name)
		}
	}
	cfake.Corrupt("create_key", []byte{})
	if _, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Error("CreateKey accepted an empty handle")
	}

	signH, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	cfake.Corrupt("sign", []byte{})
	if _, err := b.Sign(signH, []byte("data"), 0); err == nil {
		t.Error("Sign accepted an empty signature")
	}
	if sig, err := b.Sign(signH, []byte("data"), 0); err != nil || len(sig) == 0 {
		t.Fatalf("honest Sign = %x, %v", sig, err)
	}

	kaH, kaPub, err := b.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	cfake.Corrupt("key_agreement", []byte{})
	if _, err := b.KeyAgreement(kaH, kaPub, 0); err == nil {
		t.Error("KeyAgreement accepted an empty secret")
	}
	if sec, err := b.KeyAgreement(kaH, kaPub, 0); err != nil || len(sec) == 0 {
		t.Fatalf("honest KeyAgreement = %x, %v", sec, err)
	}

	h.f.SetCodeHash("/bin/zsh", []byte{0xab, 0xcd})
	cfake.Corrupt("code_hash", make([]byte, 16<<20+1))
	if _, err := b.CodeHash("/bin/zsh"); err == nil {
		t.Error("CodeHash accepted a buffer beyond the 16 MiB output limit")
	}
	cfake.Corrupt("code_hash", []byte{})
	if _, err := b.CodeHash("/bin/zsh"); err == nil {
		t.Error("CodeHash accepted an empty hash")
	}
	if got, err := b.CodeHash("/bin/zsh"); err != nil || !bytes.Equal(got, []byte{0xab, 0xcd}) {
		t.Fatalf("honest CodeHash = %x, %v", got, err)
	}

	big := make([]byte, 5<<20) // under maxOutput, over maxDocument
	copy(big, `"`)
	cfake.Corrupt("vault_list", big)
	if _, err := b.Vault().List(""); err == nil {
		t.Error("List accepted a document beyond the 4 MiB document limit")
	}
}

// A peer is identified by a full ref or not at all (S3: audit token, never
// a PID alone); a responsible PID that is not a PID is no answer.
func TestPeerAndResponsibleNeverPIDOnlyOrOutOfRange(t *testing.T) {
	h, b, _, _ := newHarness(t)
	h.f.SetPeer(77, platform.ProcessRef{PID: 4242}) // a PID with no generation
	if ref, err := b.PeerOf(77); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("PeerOf(PID-only peer) = %v, %v; want ErrNoProcess", ref, err)
	}
	if ref, err := b.PeerOf(78); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("PeerOf(no peer) = %v, %v; want ErrNoProcess", ref, err)
	}
	live := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/ssh"})
	h.f.SetPeer(79, live)
	if ref, err := b.PeerOf(79); err != nil || ref != live {
		t.Fatalf("PeerOf(live) = %v, %v", ref, err)
	}

	h.f.SetResponsible(live, platform.ProcessRef{PID: 1 << 40})
	if r, ok := b.ResponsibleFor(live); ok {
		t.Errorf("ResponsibleFor accepted PID %d beyond int32", r.PID)
	}
	h.f.SetResponsible(live, platform.ProcessRef{PID: -3})
	if r, ok := b.ResponsibleFor(live); ok {
		t.Errorf("ResponsibleFor accepted negative PID %d", r.PID)
	}
	app := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2"})
	h.f.SetResponsible(live, app)
	if r, ok := b.ResponsibleFor(live); !ok || r != (platform.ProcessRef{PID: app.PID}) {
		t.Errorf("ResponsibleFor = %v, %v; want the PID only (display only, S3)", r, ok)
	}
	if _, ok := b.ResponsibleFor(platform.ProcessRef{}); ok {
		t.Error("ResponsibleFor(zero ref) answered")
	}
	for _, pid := range []int{0, -1} {
		if _, err := b.Process(platform.ProcessRef{PID: pid, Generation: 1}); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Process(pid %d) = %v; want ErrNoProcess", pid, err)
		}
	}
}

// Screen-lock tokens fire on every lock (a lock is not a one-off), and a
// token Go never issued runs nothing.
func TestScreenLockTokens(t *testing.T) {
	h, b, _, _ := newHarness(t)
	fired := make(chan struct{}, 8)
	b.OnScreenLock(func() { fired <- struct{}{} })
	cbridge.ScreenLocked(0)
	cbridge.ScreenLocked(^uint64(0))
	select {
	case <-fired:
		t.Fatal("a forged screen-lock token ran the callback")
	case <-time.After(100 * time.Millisecond):
	}
	for i := 0; i < 2; i++ {
		h.f.LockScreen()
		select {
		case <-fired:
		case <-time.After(5 * time.Second):
			t.Fatalf("lock %d: callback did not run", i+1)
		}
	}
}

// An exit callback must not run on Swift's thread: ProcessExited returns
// even while the callback is still blocked.
func TestExitCallbackDoesNotRunOnTheCallersThread(t *testing.T) {
	h, b, _, _ := newHarness(t)
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/bin/sleep"})
	release := make(chan struct{})
	done := make(chan struct{})
	b.OnProcessExit(ref, func() { <-release; close(done) })
	exited := make(chan struct{})
	go func() { h.f.Exit(ref); close(exited) }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("ProcessExited blocked on the Go callback (it must run on its own goroutine)")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("exit callback never ran")
	}
}

// Warnings and prompts arrive intact (lines included) on the other side.
func TestPromptsAndWarningsCrossIntact(t *testing.T) {
	h, b, _, _ := newHarness(t)
	b.ShowWarning(platform.Warning{ID: "w1", Title: "Blocked", Lines: []string{"iTerm2 › zsh › ssh", `quote " and ünïcode`}, Count: 3, SuggestedRule: "- app: x"})
	b.ShowWarning(platform.Warning{ID: "w2"})
	ws := h.f.Warnings()
	if len(ws) != 2 || ws[0].ID != "w1" || ws[0].Count != 3 || len(ws[0].Lines) != 2 || ws[0].Lines[1] != `quote " and ünïcode` || ws[0].SuggestedRule != "- app: x" || ws[1].ID != "w2" {
		t.Fatalf("warnings seen by the platform: %+v", ws)
	}

	h.mu.Lock()
	h.queue = append(h.queue, true, false) // allow the login prompt, deny the dialog
	h.mu.Unlock()
	want := platform.Prompt{Title: "Use key hydra", Lines: []string{"iTerm2", "ssh hydra"}, Unknown: true, Reason: "sign", Timeout: 60 * time.Second}
	ref, err := b.Authenticate(platform.AuthUserPresence, want)
	if err != nil || ref == 0 {
		t.Fatalf("Authenticate = %v, %v", ref, err)
	}
	b.ReleaseApproval(ref)
	if ok, err := b.Confirm(platform.Prompt{Title: "deny me"}); err == nil && ok {
		t.Fatal("Confirm allowed though the platform denied")
	}
	shown := h.f.Shown()
	if len(shown) != 2 {
		t.Fatalf("platform saw %d prompts, want 2: %+v", len(shown), shown)
	}
	got := shown[0]
	if got.Kind != fake.KindAuthenticate || got.Policy != platform.AuthUserPresence || got.Prompt.Title != want.Title ||
		len(got.Prompt.Lines) != 2 || got.Prompt.Lines[1] != "ssh hydra" || !got.Prompt.Unknown || got.Prompt.Reason != "sign" || got.Prompt.Timeout != want.Timeout {
		t.Fatalf("login prompt seen by the platform: %+v", got)
	}
	if shown[1].Kind != fake.KindConfirm || shown[1].Prompt.Title != "deny me" {
		t.Fatalf("dialog prompt seen by the platform: %+v", shown[1])
	}
	if h.f.LiveApprovals() != 0 {
		t.Fatalf("%d approvals still live after ReleaseApproval", h.f.LiveApprovals())
	}
}

// Many goroutines calling through the table at once (the daemon serves
// connections concurrently): no race, and every buffer comes back once.
func TestConcurrentCallsFreeEveryBuffer(t *testing.T) {
	h, b, _, _ := newHarness(t)
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/bin/sleep"})
	vault := b.Vault()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			name := "secret/" + itoa(g)
			for i := 0; i < 25; i++ {
				if err := vault.Put(name, []byte(itoa(i))); err != nil {
					errs <- err
					return
				}
				if v, err := vault.Get(name); err != nil || string(v) != itoa(i) {
					errs <- errors.New("Get returned another goroutine's value or failed")
					return
				}
				if _, err := vault.List("secret/"); err != nil {
					errs <- err
					return
				}
				if info, err := b.Process(ref); err != nil || info.Ref != ref {
					errs <- errors.New("Process failed under concurrency")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if names, err := vault.List("secret/"); err != nil || len(names) != 16 {
		t.Fatalf("List after concurrent puts = %v, %v", names, err)
	}
	if cfake.Live() != 0 {
		t.Fatalf("%d buffers live after all calls returned", cfake.Live())
	}
}

// Apps crosses the ABI as an array of app records and is decoded as
// strictly as AppFor's one record: a malformed answer, or an entry without
// a full ref or a bundle id, is no list.
func TestAppsAreCheckedLikeAppFor(t *testing.T) {
	h, b, _, _ := newHarness(t)
	if got := b.Apps(); len(got) != 0 {
		t.Fatalf("Apps() with nothing running = %+v", got)
	}
	app := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode, App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"}})
	h.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	got := b.Apps()
	if len(got) != 1 || got[0].Ref != app || got[0].BundleID != "com.googlecode.iterm2" || got[0].Name != "iTerm2" || got[0].Code.Team() != "H7V7XYVQ7D" {
		t.Fatalf("Apps() = %+v", got)
	}
	honest := `{"pid":` + itoa(app.PID) + `,"generation":` + utoa(app.Generation) + `,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}`
	for name, raw := range map[string]string{
		"pid-only entry":  `[{"pid":` + itoa(app.PID) + `,"generation":0,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}]`,
		"no bundle id":    `[{"pid":` + itoa(app.PID) + `,"generation":` + utoa(app.Generation) + `,"bundleId":"","name":"iTerm2",` + zeroCode + `}]`,
		"unknown field":   `[{"pid":` + itoa(app.PID) + `,"generation":` + utoa(app.Generation) + `,"trusted":true,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}]`,
		"one bad of two":  `[` + honest + `,{"pid":0,"generation":1,"bundleId":"com.evil","name":"x",` + zeroCode + `}]`,
		"not an array":    honest,
		"two documents":   `[` + honest + `][]`,
		"wrong json type": `[{"pid":"` + itoa(app.PID) + `","generation":` + utoa(app.Generation) + `,"bundleId":"com.googlecode.iterm2","name":"iTerm2",` + zeroCode + `}]`,
	} {
		cfake.Corrupt("apps", []byte(raw))
		if got := b.Apps(); len(got) != 0 {
			t.Errorf("%s: Apps() accepted %+v", name, got)
		}
	}
	if got := b.Apps(); len(got) != 1 || got[0].Ref != app {
		t.Fatalf("honest Apps() after the corrupt answers = %+v", got)
	}
	if cfake.Live() != 0 || cfake.BadFrees() != 0 {
		t.Fatalf("buffers live %d, bad frees %d", cfake.Live(), cfake.BadFrees())
	}
}

// The access crosses the bridge as made, and the platform's ErrLocked
// comes back as ErrLocked (NZ_LOCKED), not as a bare status.
func TestAccessAndLockedCrossTheBridge(t *testing.T) {
	h, b, _, _ := newHarness(t)
	unlockedOnly, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	lockedOK, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if err != nil {
		t.Fatal(err)
	}
	ka, kaPub, err := b.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.CreateKey(platform.PurposeSign, platform.AuthNone, platform.Access(2)); err == nil {
		t.Error("CreateKey with access 2 succeeded")
	}
	h.f.SetLocked(true)
	if _, err := b.Sign(unlockedOnly, []byte("d"), 0); !errors.Is(err, platform.ErrLocked) {
		t.Errorf("Sign with a when-unlocked key while locked = %v; want ErrLocked", err)
	}
	if _, err := b.KeyAgreement(ka, kaPub, 0); !errors.Is(err, platform.ErrLocked) {
		t.Errorf("KeyAgreement with a when-unlocked key while locked = %v; want ErrLocked", err)
	}
	if _, err := b.Sign(lockedOK, []byte("d"), 0); err != nil {
		t.Errorf("Sign with an after-first-unlock key while locked = %v", err)
	}
}
