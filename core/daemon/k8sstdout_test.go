package daemon

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// THREAT-MODEL 5.16 (from a security review): client-go runs
// the plugin with its stdout a pipe whose read end kubectl holds. A
// kubeconfig that wraps the plugin in exec hops keeps kubectl the CLI's
// parent but copies the CLI's stdout (`exec > >(tee leak); exec nazar …`).
// nazar-agent asks the platform that the CLI's fd 1 is a pipe its parent,
// chain[1], reads, and refuses k8s.credential otherwise: before any
// prompt, whatever approval is cached, with one blocked audit line and a
// plain message.

// errStdoutNotPiped is the refusal's reason, in the Problem and the audit
// line.
const errStdoutNotPiped = "the plugin's output does not go straight to the program that ran it"

func teeProc() fake.Proc {
	return fake.Proc{Path: "/usr/bin/tee", Args: []string{"tee", "/tmp/leak"}, Code: fake.AppleCode("com.apple.tee")}
}

// relayed makes the next connection come from a plugin run by kubectl
// under shell whose stdout goes through tee, which writes to kubectl's
// pipe: the CLI's parent is kubectl, as after two exec hops.
func (e *k8sEnv) relayed(shell platform.ProcessRef, args ...string) platform.ProcessRef {
	k := e.f.Launch(shell, kubeProc(args...))
	cli := e.f.Launch(k, cliProc("k8s", "credential", "hydra"))
	tee := e.f.Launch(cli, teeProc())
	e.f.SetStdout(cli, tee)
	e.f.SetStdout(tee, k)
	e.f.SetDefaultPeer(cli)
	return cli
}

// refusedForStdout checks one refusal: the plain message, nothing minted,
// and the blocked audit line naming the client.
func (e *k8sEnv) refusedForStdout(t *testing.T, what string, c control.K8sCredential, p *control.Problem) {
	t.Helper()
	if p == nil || p.Code != control.CodeRefused || p.Message != "refused: "+errStdoutNotPiped || c.ClientKeyData != "" || c.ClientCertificateData != "" {
		t.Fatalf("%s: %+v (a credential came back: %v)", what, p, c.ClientKeyData != "") // never the credential itself
	}
	if f := e.lastAudit(t); f["decision"] != "blocked" || f["target"] != "k8s:hydra" || f["operation"] != "k8s credential" ||
		f["reason"] != errStdoutNotPiped || !strings.HasPrefix(f["receiver"], "kubectl get pods") {
		t.Fatalf("%s: audit %v", what, f)
	}
}

func TestK8sCredentialRefusesAnOutputThatDoesNotGoStraightToTheClient(t *testing.T) {
	e := startK8s(t)
	// Both gates allow: a refusal can only come from the stdout check.
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	signs := e.f.SignCalls()
	plain := cliProc("k8s", "credential", "hydra") // fd 1 no pipe anyone reads
	for name, setup := range map[string]func(){
		"not a pipe": func() { e.asCLI(kubeProc("get", "pods"), plain) },
		"a pipe the shell reads": func() {
			tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), plain)
			e.f.SetStdout(tab.Peer(), tab.Shell)
			e.f.SetDefaultPeer(tab.Peer())
		},
		"a pipe its own child reads": func() {
			tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), plain)
			e.f.SetStdout(tab.Peer(), e.f.Launch(tab.Peer(), teeProc()))
			e.f.SetDefaultPeer(tab.Peer())
		},
		"an exec-hop relay through tee": func() {
			e.relayed(e.f.ITermTab(platform.ProcessRef{}).Shell, "get", "pods")
		},
		// kubectl alone reads the pipe, but a background job the wrapper
		// left can write to it too, around the reply.
		"a pipe with a co-writer": func() {
			cli := e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
			e.f.Launch(cli, fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "1"}, Code: fake.AppleCode("com.apple.sleep")})
			e.f.SetStdoutForeign(cli)
		},
	} {
		setup()
		c, p := e.credential(t, "hydra", e.ok(t))
		e.refusedForStdout(t, name, c, p)
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 {
		t.Fatalf("nothing signed, nothing asked: %d signs, %d prompts", e.f.SignCalls()-signs, len(e.f.Shown())-e.shown0)
	}
}

// A platform that can't tell is a refusal too (fail closed), and so is a
// kubectl that is gone by the time the CLI's stdout is checked.
func TestK8sCredentialRefusesWhenTheStdoutCheckFails(t *testing.T) {
	for name, err := range map[string]error{
		"unreadable":     platform.ErrUnreadable,
		"kubectl exited": platform.ErrNoProcess,
		"anything else":  errors.New("proc_pidfdinfo: EPERM"),
	} {
		t.Run(name, func(t *testing.T) {
			e := startK8sWith(t, func(f *fake.Fake, _ *Options) {
				f.StdoutFunc = func(platform.ProcessRef, platform.ProcessRef) (bool, error) { return true, err }
			})
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
			e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
			signs := e.f.SignCalls()
			c, p := e.credential(t, "hydra", e.ok(t))
			e.refusedForStdout(t, name, c, p)
			if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 {
				t.Fatal("nothing signed, nothing asked")
			}
		})
	}
}

// The question is about the CLI on the socket and its parent, by their
// full refs: not the CLI's grandparent, the app, or a PID.
func TestK8sCredentialAsksAboutTheCLIAndItsParent(t *testing.T) {
	var mu sync.Mutex
	var asked [][2]platform.ProcessRef
	e := startK8sWith(t, func(f *fake.Fake, _ *Options) {
		f.StdoutFunc = func(w, r platform.ProcessRef) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, [2]platform.ProcessRef{w, r})
			return true, nil
		}
	})
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), credCLI("hydra"))
	e.f.SetDefaultPeer(tab.Peer())
	if _, p := e.credential(t, "hydra", e.ok(t)); p != nil {
		t.Fatal(p)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 {
		t.Fatal("the CLI's stdout was never checked")
	}
	for _, a := range asked {
		if a[0] != tab.Peer() || a[1] != tab.Procs[0] {
			t.Fatalf("asked about %v read by %v, want the CLI %v read by kubectl %v", a[0], a[1], tab.Peer(), tab.Procs[0])
		}
	}
}

// THREAT-MODEL 5.16 named it: a session approval for kubectl in a tab
// covers every kubectl there, but never one whose plugin's output is
// copied; kubectl run straight in that tab still gets its certificate.
func TestK8sCredentialSessionApprovalDoesNotCoverARelayedOutput(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), credCLI("hydra"))
	e.f.SetDefaultPeer(tab.Peer())
	if _, p := e.credential(t, "hydra", e.ok(t)); p != nil {
		t.Fatal(p)
	}
	signs, shown := e.f.SignCalls(), len(e.f.Shown())
	e.relayed(tab.Shell, "get", "pods")
	c, p := e.credential(t, "hydra", e.ok(t))
	e.refusedForStdout(t, "relayed in an approved tab", c, p)
	if e.f.SignCalls() != signs || len(e.f.Shown()) != shown {
		t.Fatal("nothing signed, nothing asked")
	}
	k := e.f.Launch(tab.Shell, kubeProc("get", "pods"))
	e.f.SetDefaultPeer(e.f.Launch(k, credCLI("hydra")))
	if c, p := e.credential(t, "hydra", e.ok(t)); p != nil || c.ClientKeyData == "" {
		t.Fatalf("kubectl run straight: %+v", p)
	}
	if f := e.lastAudit(t); f["decision"] != "allowed" || f["reason"] != "cached approval" {
		t.Fatalf("audit %v", f)
	}
}

// Without the platform's stdout check (Options.Pipes nil: not macOS)
// nazar-agent can't know where the credential goes, so it mints nothing.
func TestK8sCredentialWithoutAStdoutCheckIsRefused(t *testing.T) {
	e := startK8sWith(t, func(_ *fake.Fake, o *Options) { o.Pipes = nil })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	signs := e.f.SignCalls()
	c, p := e.credential(t, "hydra", e.ok(t))
	if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "output") || c.ClientKeyData != "" {
		t.Fatalf("%+v", p)
	}
	if f := e.lastAudit(t); f["decision"] != "blocked" || f["target"] != "k8s:hydra" {
		t.Fatalf("audit %v", f)
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 {
		t.Fatal("nothing signed, nothing asked")
	}
}

// A CLI whose parent is gone (reparented to launchd) has no program to
// read its output: check 1 refuses it with its own reason and the block
// warning (k8s design 2.1), not the stdout check.
func TestK8sCredentialWithNoParentIsCheckOnes(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	signs := e.f.SignCalls()
	k := e.f.Launch(e.f.ITermTab(platform.ProcessRef{}).Shell, kubeProc("get", "pods"))
	cli := e.f.Launch(k, credCLI("hydra"))
	e.f.Exit(k)
	e.f.SetDefaultPeer(cli)
	c, p := e.credential(t, "hydra", e.ok(t))
	if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "can't be identified") || c.ClientKeyData != "" {
		t.Fatalf("%+v", p)
	}
	if w := e.f.Warnings(); len(w) == 0 || !strings.Contains(strings.Join(w[len(w)-1].Lines, "\n"), "can't be identified") {
		t.Fatalf("the block warning: %+v", w)
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 {
		t.Fatal("nothing signed, nothing asked")
	}
}

// The output is checked again at mint time: an answer that turns to no
// while the request waits mints nothing.
func TestK8sCredentialChecksTheOutputAgainAtMint(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	e := startK8sWith(t, func(f *fake.Fake, _ *Options) {
		f.StdoutFunc = func(platform.ProcessRef, platform.ProcessRef) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			return calls == 1, nil
		}
	})
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	signs := e.f.SignCalls()
	c, p := e.credential(t, "hydra", e.ok(t))
	if p == nil || !strings.Contains(p.Message, errStdoutNotPiped) || c.ClientKeyData != "" || c.ClientCertificateData != "" {
		t.Fatalf("%+v", p)
	}
	if e.f.SignCalls() != signs {
		t.Fatal("a certificate was signed")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("%d checks, want one before the prompt and one at mint", calls)
	}
}
