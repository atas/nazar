package daemon

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// `nazar trust --app <bundle id>` (spec 4.2, 4.8, 6): pins the team of the
// INSTALLED app for an app: matcher, behind the login gate, because a pin
// is new trust (a loosening). These tests drive it end to end over the
// control socket with the fake platform.

const toolID = "com.example.tool"

var (
	toolCode  = platform.CodeIdentity{Signed: true, TeamID: "TOOLTEAM01", SigningID: toolID, CDHash: []byte{0x70}}
	toolCode2 = platform.CodeIdentity{Signed: true, TeamID: "NEWTEAM002", SigningID: toolID, CDHash: []byte{0x71}}
)

// toolRules gives key "tool" (created with gate block, so its fallback
// blocks and the key carries Secure Enclave user presence) one login rule
// for the app: matcher of toolID.
const toolRules = `apiVersion: nazar/v1
kind: Config
ssh_agent:
  keys:
    tool:
      gate: block
      rules:
        - apps: [{app: com.example.tool}]
          scope: session
          gate: login
`

// promptMentions reports whether any prompt of kind shows s in its title,
// lines or reason.
func promptMentions(f *fake.Fake, kind fake.PromptKind, s string) bool {
	for _, p := range f.Shown() {
		if p.Kind != kind {
			continue
		}
		text := p.Prompt.Title + "\n" + p.Prompt.Reason + "\n" + strings.Join(p.Prompt.Lines, "\n")
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// toolPeer launches the app toolID (signed by code) with a shell and an
// ssh below it, and returns the ssh process.
func toolPeer(f *fake.Fake, code platform.CodeIdentity) platform.ProcessRef {
	app := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Tool.app/Contents/MacOS/Tool", Code: code,
		App: &fake.App{BundleID: toolID, Name: "Tool"}})
	sh := f.Launch(app, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	return f.Launch(sh, fake.SSHProc("git@github.com"))
}

func (e *env) trustApp(t *testing.T, id string) (control.AppPin, *control.Problem) {
	t.Helper()
	var pin control.AppPin
	err := e.call(t, control.CmdTrustApp, map[string]string{"app": id}, control.KindAppPin, &pin)
	return pin, control.AsProblem(err)
}

// probes numbers the apps probeApp installs.
var probes atomic.Int32

// probeApp installs a new app, never pinned, and returns its bundle id:
// `trust --app` for it is a loosen command that opens exactly one login
// prompt (a new pin is new trust), so the prompt-machinery tests use it
// wherever any login-gated command will do. Each call is a new app, so an
// approved probe never makes the next one a no-op.
func (e *env) probeApp(t *testing.T) string {
	t.Helper()
	n := probes.Add(1)
	id := fmt.Sprintf("com.example.probe%d", n)
	e.f.InstallApp(fmt.Sprintf("/Applications/Probe%d.app", n), id,
		platform.CodeIdentity{Signed: true, TeamID: "PROBETEAM1", SigningID: id, CDHash: []byte{byte(n), byte(n >> 8)}})
	return id
}

// probeLogin runs `trust --app` for a new probeApp.
func (e *env) probeLogin(t *testing.T) *control.Problem {
	t.Helper()
	_, p := e.trustApp(t, e.probeApp(t))
	return p
}

func (e *env) status(t *testing.T) control.Status {
	t.Helper()
	var st control.Status
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func (e *env) check(t *testing.T) control.ConfigCheck {
	t.Helper()
	var chk control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil {
		t.Fatal(err)
	}
	return chk
}

func mentionsFix(ps []control.ConfigProblem, id string) bool {
	fix := configstage.FixTrustApp(id)
	for _, p := range ps {
		if strings.Contains(p.Message, fix) {
			return true
		}
	}
	return false
}

// auditFor returns the parsed audit lines whose target mentions s.
func (e *env) auditFor(t *testing.T, s string) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.sink.Lines() {
		f, err := audit.ParseLine(l)
		if err != nil {
			t.Fatalf("unparseable audit line %q: %v", l, err)
		}
		if strings.Contains(f["target"], s) {
			out = append(out, f)
		}
	}
	return out
}

// signAs dials the agent socket as peer and asks for one SSHSIG signature
// with the only key, by the blob the registry holds (the caller may not
// have been offered it, Milestone 7); it returns the error of the sign.
func (e *env) signAs(t *testing.T, peer platform.ProcessRef) error {
	t.Helper()
	e.f.SetDefaultPeer(peer)
	held, err := e.d.keys.List()
	if err != nil || len(held) != 1 {
		t.Fatalf("want exactly one key: %v %v", held, err)
	}
	pub, err := ssh.ParsePublicKey(held[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", e.d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = agent.NewClient(conn).Sign(pub, sshsig())
	return err
}

// offeredTo dials the agent socket as peer and returns how many keys
// REQUEST_IDENTITIES lists for it (Milestone 7: only the keys it may use).
func (e *env) offeredTo(t *testing.T, peer platform.ProcessRef) int {
	t.Helper()
	e.f.SetDefaultPeer(peer)
	conn, err := net.Dial("unix", e.d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ks, err := agent.NewClient(conn).List()
	if err != nil {
		t.Fatal(err)
	}
	return len(ks)
}

// The whole story the error messages tell: an app: matcher whose app was
// not installed when its config was approved matches nothing; config
// check and status say so and name `nazar trust --app <id>`; once the app
// is installed, that command (behind the login gate) pins the installed
// app's team and the rule starts matching, with no config change.
func TestTrustAppEndToEnd(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "tool"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	// ssh-key create already gave "tool" one rule (for the iTerm tab that
	// ran it), so wait for toolRules itself to be active: it is a loosening
	// the background prompt approves asynchronously. Its audit line comes
	// after the prompt's claim ends, so the trust --app below never meets
	// that prompt still open.
	approvedBefore := len(e.configAudit(t, audit.Approved))
	e.activate(t, toolRules)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Approved)) == approvedBefore+1 })
	if _, ok := e.status(t).Pins[toolID]; ok {
		t.Fatal("an app that is not installed can't be pinned by config approval")
	}
	if chk := e.check(t); !mentionsFix(chk.Problems, toolID) {
		t.Fatalf("config check must name the fix %q: %+v", configstage.FixTrustApp(toolID), chk.Problems)
	}
	if st := e.status(t); !mentionsFix(st.Problems, toolID) {
		t.Fatalf("status must name the fix %q: %+v", configstage.FixTrustApp(toolID), st.Problems)
	}

	// Unpinned: the rule matches nothing, so the key's own gate (block)
	// applies: the key is not even offered (Milestone 7), and a sign request
	// with its blob is refused.
	peer := toolPeer(e.f, toolCode)
	if n := e.offeredTo(t, peer); n != 0 {
		t.Fatalf("an unpinned app: matcher must not match: %d keys offered", n)
	}
	if err := e.signAs(t, peer); err == nil {
		t.Fatal("an unpinned app: matcher must not match")
	}

	e.f.InstallApp("/Applications/Tool.app", toolID, toolCode)
	authBefore, confirmBefore := e.f.CountShown(fake.KindAuthenticate), e.f.CountShown(fake.KindConfirm)
	pin, p := e.trustApp(t, toolID)
	if p != nil {
		t.Fatalf("trust --app: %+v", p)
	}
	if pin.APIVersion != control.APIVersion || pin.Kind != control.KindAppPin {
		t.Fatalf("reply must carry apiVersion and kind: %+v", pin)
	}
	if pin.BundleID != toolID || pin.Team != toolCode.Team() || pin.OldTeam != "" || pin.Path != "/Applications/Tool.app" || !pin.Changed {
		t.Fatalf("%+v", pin)
	}
	if n := e.f.CountShown(fake.KindAuthenticate) - authBefore; n != 1 {
		t.Fatalf("pinning is a loosening: exactly one login prompt, got %d", n)
	}
	if e.f.CountShown(fake.KindConfirm) != confirmBefore {
		t.Fatal("pinning must never use the dialog gate (spec 4.8: login, never dialog)")
	}
	for _, want := range []string{toolID, toolCode.Team(), "/Applications/Tool.app"} {
		if !promptMentions(e.f, fake.KindAuthenticate, want) {
			t.Errorf("the login prompt must show %q", want)
		}
	}
	if got := e.status(t).Pins[toolID]; got != toolCode.Team() {
		t.Fatalf("pin not recorded: %q", got)
	}
	if chk := e.check(t); mentionsFix(chk.Problems, toolID) {
		t.Fatalf("the problem must be gone once pinned: %+v", chk.Problems)
	}
	lines := e.auditFor(t, toolID)
	if len(lines) == 0 || lines[len(lines)-1]["decision"] != string(audit.Approved) {
		t.Fatalf("the pin must be audited as approved: %v", lines)
	}

	// Now the rule matches: the key is offered, its login gate runs and the
	// signature is made.
	if n := e.offeredTo(t, peer); n != 1 {
		t.Fatalf("the pinned app: matcher must match: %d keys offered", n)
	}
	if err := e.signAs(t, peer); err != nil {
		t.Fatalf("the pinned app: matcher must match: %v", err)
	}
	signed := false
	for _, f := range e.auditFor(t, "ssh:tool") {
		if f["decision"] == string(audit.Approved) && f["rule"] == "1" {
			signed = true
		}
	}
	if !signed {
		t.Fatalf("no approved rule-1 signature audited:\n%s", strings.Join(e.sink.Lines(), "\n"))
	}

	// An impostor presenting the same bundle id under another team still
	// matches nothing.
	if err := e.signAs(t, toolPeer(e.f, toolCode2)); err == nil {
		t.Fatal("another team under the pinned bundle id must not match")
	}
}

// Every message that names the fix must work exactly as written: run the
// command line FixTrustApp prints (minus the program name) as the CLI
// would send it.
func TestTrustAppFixWorksAsWritten(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.f.InstallApp("/Applications/Tool.app", toolID, toolCode)
	words := strings.Fields(configstage.FixTrustApp(toolID))
	if len(words) != 4 || words[0] != "nazar" || words[1] != "trust" || words[2] != "--app" || words[3] != toolID {
		t.Fatalf("fix %q is not `nazar trust --app <id>`", configstage.FixTrustApp(toolID))
	}
	if _, p := e.trustApp(t, words[3]); p != nil {
		t.Fatalf("%+v", p)
	}
	if e.status(t).Pins[toolID] != toolCode.Team() {
		t.Fatal("not pinned")
	}
}

// Apps that can't be pinned are refused before any prompt, with exit 1, and
// nothing is pinned: not installed, installed twice by different teams
// (ambiguous), not validly signed, ad-hoc signed.
func TestTrustAppRefusesUnpinnableApps(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.f.InstallApp("/Applications/Two.app", "com.example.two", toolCode)
	e.f.InstallApp("/Users/u/Applications/Two.app", "com.example.two", toolCode2)
	e.f.InstallApp("/Applications/Unsigned.app", "com.example.unsigned", fake.Unsigned)
	e.f.InstallApp("/Applications/AdHoc.app", "com.example.adhoc", platform.CodeIdentity{Signed: true, AdHoc: true, TeamID: "FAKETEAM01", SigningID: "com.example.adhoc"})
	shown := len(e.f.Shown())
	for _, id := range []string{"com.example.missing", "com.example.two", "com.example.unsigned", "com.example.adhoc"} {
		_, p := e.trustApp(t, id)
		if p.ExitCode() != control.ExitError {
			t.Errorf("%s: want exit %d, got %+v", id, control.ExitError, p)
			continue
		}
		if !strings.Contains(p.Message, id) {
			t.Errorf("%s: the problem must name the app: %q", id, p.Message)
		}
	}
	if len(e.f.Shown()) != shown {
		t.Fatal("an app that can't be pinned must be refused before any prompt")
	}
	if pins := e.status(t).Pins; len(pins) != 0 {
		t.Fatalf("nothing may be pinned: %v", pins)
	}
}

func TestTrustAppUsage(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	for _, args := range []map[string]string{nil, {"app": ""}} {
		var pin control.AppPin
		p := control.AsProblem(e.call(t, control.CmdTrustApp, args, control.KindAppPin, &pin))
		if p.ExitCode() != control.ExitUsage {
			t.Errorf("%v: want usage, got %+v", args, p)
		}
	}
	if len(e.f.Shown()) != 0 {
		t.Fatal("a usage error must not prompt")
	}
}

// A denied or timed-out login gate refuses with exit 3 and pins nothing.
func TestTrustAppDeniedIsRefused(t *testing.T) {
	e := start(t)
	e.f.InstallApp("/Applications/Tool.app", toolID, toolCode)
	_, p := e.trustApp(t, toolID) // default auth denies
	if p.ExitCode() != control.ExitRefused {
		t.Fatalf("%+v", p)
	}
	if _, ok := e.status(t).Pins[toolID]; ok {
		t.Fatal("a denied pin must not be recorded")
	}
	lines := e.auditFor(t, toolID)
	if len(lines) == 0 || lines[len(lines)-1]["decision"] != string(audit.Denied) {
		t.Fatalf("the denied pin must be audited: %v", lines)
	}
}

// An app already pinned to the installed team needs nothing: no prompt,
// exit 0, Changed false.
func TestTrustAppAlreadyPinnedIsANoOp(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.f.InstallApp("/Applications/Tool.app", toolID, toolCode)
	if _, p := e.trustApp(t, toolID); p != nil {
		t.Fatal(p)
	}
	shown := len(e.f.Shown())
	pin, p := e.trustApp(t, toolID)
	if p != nil || pin.Changed || pin.Team != toolCode.Team() || pin.Kind != control.KindAppPin {
		t.Fatalf("%+v %+v", pin, p)
	}
	if len(e.f.Shown()) != shown {
		t.Fatal("re-pinning the same team must not prompt")
	}
}

// An app update that changed its signing team (spec 4.8): the config never
// re-pins; only trust --app replaces the pin, after showing the old and the
// new team behind the login gate. A denial keeps the old pin.
func TestTrustAppReplacesPinAfterTeamChange(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.f.InstallApp("/Applications/Tool.app", toolID, toolCode)
	if _, p := e.trustApp(t, toolID); p != nil {
		t.Fatal(p)
	}
	e.f.InstallApp("/Applications/Tool.app", toolID, toolCode2) // the update
	if st := e.status(t); st.Pins[toolID] != toolCode.Team() {
		t.Fatal("an installed update must never change the pin by itself")
	}

	e.f.ScriptAuth(fake.Answer{Allow: false})
	shown := len(e.f.Shown())
	if _, p := e.trustApp(t, toolID); p.ExitCode() != control.ExitRefused {
		t.Fatalf("%+v", p)
	}
	last := e.f.Shown()[len(e.f.Shown())-1]
	if len(e.f.Shown()) != shown+1 || last.Kind != fake.KindAuthenticate {
		t.Fatal("replacing a pin needs exactly one login prompt")
	}
	text := last.Prompt.Title + "\n" + strings.Join(last.Prompt.Lines, "\n")
	if !strings.Contains(text, toolCode.Team()) || !strings.Contains(text, toolCode2.Team()) {
		t.Fatalf("the prompt must show the old and the new team: %q", text)
	}
	if e.status(t).Pins[toolID] != toolCode.Team() {
		t.Fatal("a denied replacement must keep the old pin")
	}

	e.f.Advance(configApplyCooldown) // a denial cools every login prompt down
	pin, p := e.trustApp(t, toolID)
	if p != nil || !pin.Changed || pin.OldTeam != toolCode.Team() || pin.Team != toolCode2.Team() {
		t.Fatalf("%+v %+v", pin, p)
	}
	if e.status(t).Pins[toolID] != toolCode2.Team() {
		t.Fatal("pin not replaced")
	}
}

// A bundle id is attacker-chosen text (any app can claim any id). Whatever
// it contains, the prompt and the audit line stay single, printable lines.
func TestTrustAppHostileBundleID(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	id := "com.evil\n\x1b[2KAllow this change to nazar's config?‮"
	e.f.InstallApp("/Applications/Evil.app", id, toolCode)
	e.trustApp(t, id)
	for _, s := range e.f.Shown() {
		for _, l := range append([]string{s.Prompt.Title, s.Prompt.Reason}, s.Prompt.Lines...) {
			if strings.IndexFunc(l, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
				t.Fatalf("prompt carries a non-printing rune: %q", l)
			}
		}
	}
	for _, l := range e.sink.Lines() {
		if strings.IndexFunc(l, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			t.Fatalf("audit line carries a non-printing rune: %q", l)
		}
	}
}
