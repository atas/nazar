package broker

import (
	"strings"
	"testing"
	"unicode"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Spec 4.6: every request is logged, including the ones a module refuses
// before they reach the pipeline (the SSH agent refuses a SIGN_REQUEST on
// a connection whose session-bind was refused, or whose userauth contradicts
// the binding). Refuse writes that line: decision=blocked with the module's
// fixed reason. It never consults the policy's gate, the approval cache or
// the user, and never runs the operation.

func TestRefuseWritesOneBlockedLine(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	req := e.req("github", tab.Peer())
	req.Destination, req.Operation = "", "sign git commit"
	r := e.b.Refuse(req, "session-bind refused on this connection")
	if r.Decision != audit.Blocked || r.Allowed() {
		t.Fatalf("%+v", r)
	}
	if e.calls.Load() != 0 || e.f.SignCalls() != 0 {
		t.Fatal("a refused request must never run its operation")
	}
	if len(e.f.Shown()) != 0 {
		t.Fatal("a refused request must never prompt")
	}
	lines := e.sink.Lines()
	if len(lines) != 1 {
		t.Fatalf("want exactly one audit line, got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	f := e.lastLine(t)
	chain := e.r.Resolve(tab.Peer())
	for k, want := range map[string]string{
		"decision":  "blocked",
		"reason":    "session-bind refused on this connection",
		"target":    "ssh:github",
		"app":       "com.googlecode.iterm2",
		"session":   chain.Session.String(),
		"operation": "sign git commit",
		"cwd":       "~/projects/foo",
	} {
		if f[k] != want {
			t.Errorf("%s = %q, want %q (line %s)", k, f[k], want, lines[0])
		}
	}
	procs, err := audit.ParseChain(f["chain"])
	if err != nil || len(procs) == 0 || procs[len(procs)-1].Name != "ssh" {
		t.Errorf("chain %q (%v): who asked must be logged", f["chain"], err)
	}
	if !strings.HasPrefix(f["receiver"], "ssh") {
		t.Errorf("receiver %q: who would have received it must be logged", f["receiver"])
	}
	if len(e.cache.List()) != 0 {
		t.Fatal("a refusal must not create an approval")
	}
}

// The refusal wins over everything the policy would allow: gate none, a
// remembered approval, or an approval being granted right now.
func TestRefuseIgnoresGateAndCache(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	plain := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	// deploy: iTerm2 has gate none.
	if r := e.b.Refuse(e.req("deploy", plain.Peer()), "userauth contradicts the session-bind"); r.Decision != audit.Blocked {
		t.Fatalf("gate none: %+v", r)
	}
	// github: remember an approval for this tab first.
	if r := e.b.Handle(e.req("github", plain.Peer())); !r.Allowed() {
		t.Fatalf("%+v", r)
	}
	calls, shown := e.calls.Load(), len(e.f.Shown())
	if r := e.b.Refuse(e.req("github", plain.Peer()), "userauth contradicts the session-bind"); r.Decision != audit.Blocked {
		t.Fatalf("cached: %+v", r)
	}
	if e.calls.Load() != calls || len(e.f.Shown()) != shown {
		t.Fatal("a refusal must neither run the operation nor prompt")
	}
	if n := len(e.cache.List()); n != 1 {
		t.Fatalf("a refusal must not touch remembered approvals; %d left", n)
	}
	lines := e.sink.Lines()
	if len(lines) != 3 {
		t.Fatalf("three requests, %d lines", len(lines))
	}
	for _, i := range []int{0, 2} {
		f, err := audit.ParseLine(lines[i])
		if err != nil || f["decision"] != "blocked" || f["reason"] != "userauth contradicts the session-bind" {
			t.Errorf("line %d: %v %v", i, f, err)
		}
	}
}

// A refusal is not a policy block: it shows no block warning (the warning
// says "this caller has no rule", which would be false).
func TestRefuseShowsNoPolicyWarning(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Refuse(e.req("github", tab.Peer()), "session-bind refused on this connection")
	for _, w := range e.f.Warnings() {
		if strings.Contains(strings.Join(w.Lines, "\n"), "no rule") {
			t.Fatalf("refusal shown as a policy block: %+v", w)
		}
	}
}

// Unknown and nil chains are logged too, and the reason, though fixed by
// the caller, can never add a line or a control sequence to the log.
func TestRefuseUnknownChainAndHostileReason(t *testing.T) {
	e := newEnv(t)
	req := e.req("github", platform.ProcessRef{})
	req.Chain = nil
	r := e.b.Refuse(req, "bad\nline\x1b[2J\u202e")
	if r.Decision != audit.Blocked {
		t.Fatalf("%+v", r)
	}
	lines := e.sink.Lines()
	if len(lines) != 1 {
		t.Fatalf("%d lines", len(lines))
	}
	if strings.IndexFunc(lines[0], func(r rune) bool { return unicode.IsControl(r) || r == '\u202e' }) >= 0 {
		t.Fatalf("audit line carries a control rune: %q", lines[0])
	}
	f := e.lastLine(t)
	if f["decision"] != "blocked" || f["target"] != "ssh:github" || f["app"] != "" {
		t.Fatalf("%v", f)
	}
}
