package daemon

import (
	"testing"

	"github.com/atas/nazar/core/aws/awstest"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// aws design 3.4 on a /bin/sh that does not exec its command (dash, the
// sh of Debian and Ubuntu): the Go SDK and Terraform run
// credential_process by `sh -c`, so the shell stays between the program
// and the CLI, holding the write end it passed on. The platform's
// StdoutThrough check accepts exactly that shell and nothing more: a shell
// whose fd 1 is not the pipe, a wrapper that is not the system's shell, a
// shell given more arguments, and a platform without the check are all
// refused, before any prompt. Portable: runs on every OS.
func TestAWSCredentialThroughAShellThatStays(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	// Ad-hoc code with a cdhash, as Homebrew's programs are on macOS: an
	// identity check 1 accepts (on Linux every file has its hash).
	sdk := fake.Proc{Path: "/usr/local/bin/terraform", Args: []string{"terraform", "plan"}, Cwd: "/home/u/infra",
		Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x7f, 0x01}}}
	cli := cliProc("aws", "credential", "dev")
	shell := func(path string, args ...string) fake.Proc {
		return fake.Proc{Path: path, Args: args, Cwd: "/home/u/infra", Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x5a, 0x02}}}
	}
	command := "/home/u/.local/bin/nazar aws credential dev"
	// The chain: terminal shell > sdk > sh -c > cli, with the pipe from
	// the cli, through the shell's fd 1, to the sdk.
	through := func(sh fake.Proc) (c, s, a platform.ProcessRef) {
		a = e.f.Launch(e.f.ITermTab(platform.ProcessRef{}).Shell, sdk)
		s = e.f.Launch(a, sh)
		c = e.f.Launch(s, cli)
		e.f.SetDefaultPeer(c)
		return c, s, a
	}
	c, s, a := through(shell("/usr/bin/dash", "/bin/sh", "-c", command))
	e.f.SetStdoutThrough(c, s, a)
	sent := len(e.fake.Seen())
	cred, p := e.credential(t, "dev")
	if p != nil || cred.SecretAccessKey != awstest.SecretAccessKey {
		t.Fatalf("through dash: %+v %+v", p, cred)
	}
	if len(e.fake.Seen()) != sent+1 || len(e.f.Shown()) != e.shown0+1 {
		t.Fatal("one prompt, one CreateSession")
	}
	if f := e.lastAudit(t); f["decision"] != "approved" || f["target"] != "aws:dev" {
		t.Fatalf("audit %v", f)
	}
	// bash as /bin/sh (Fedora, Arch) execs a lone command, so it is not
	// in the chain; when it stays it is accepted the same way.
	c, s, a = through(shell("/bin/bash", "/bin/sh", "-c", command))
	e.f.SetStdoutThrough(c, s, a)
	if _, p := e.credential(t, "dev"); p != nil {
		t.Fatalf("through bash: %+v", p)
	}

	signs, shown, sent := e.f.SignCalls(), len(e.f.Shown()), len(e.fake.Seen())
	for name, setup := range map[string]func(){
		"a shell whose fd 1 is not the pipe": func() {
			c, _, a := through(shell("/usr/bin/dash", "/bin/sh", "-c", command))
			e.f.SetStdout(c, a) // the sdk reads it, but the shell holds no write end: not what sh -c leaves
		},
		"a shell that reads the pipe itself": func() {
			c, s, _ := through(shell("/usr/bin/dash", "/bin/sh", "-c", command))
			e.f.SetStdout(c, s)
		},
		"a wrapper that is not the system's shell": func() {
			c, s, a := through(shell("/home/u/bin/sh", "sh", "-c", command))
			e.f.SetStdoutThrough(c, s, a)
		},
		"a shell with a second argument": func() {
			c, s, a := through(shell("/usr/bin/dash", "/bin/sh", "-c", command, "x"))
			e.f.SetStdoutThrough(c, s, a)
		},
		"a shell given a script, not -c": func() {
			c, s, a := through(shell("/usr/bin/dash", "/bin/sh", "/home/u/run.sh", command))
			e.f.SetStdoutThrough(c, s, a)
		},
	} {
		setup()
		cred, p := e.credential(t, "dev")
		if p == nil || p.Code != control.CodeRefused || p.Message != "refused: "+errAWSStdout || cred.SecretAccessKey != "" {
			t.Fatalf("%s: %+v", name, p)
		}
		if f := e.lastAudit(t); f["decision"] != "blocked" || f["reason"] != errAWSStdout {
			t.Fatalf("%s: audit %v", name, f)
		}
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != shown || len(e.fake.Seen()) != sent {
		t.Fatal("nothing signed, asked or sent")
	}

	// A platform whose Pipes has no StdoutThrough (macOS) refuses the
	// chain as it always has, with the plain check.
	e2 := startAWSWith(t, nil)
	e2.d.o.Pipes = plainPipes{e2.f}
	e2.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	a2 := e2.f.Launch(e2.f.ITermTab(platform.ProcessRef{}).Shell, sdk)
	s2 := e2.f.Launch(a2, shell("/usr/bin/dash", "/bin/sh", "-c", command))
	c2 := e2.f.Launch(s2, cli)
	e2.f.SetStdoutThrough(c2, s2, a2)
	e2.f.SetDefaultPeer(c2)
	if _, p := e2.credential(t, "dev"); p == nil || p.Message != "refused: "+errAWSStdout {
		t.Fatalf("without StdoutThrough: %+v", p)
	}
	if len(e2.f.Shown()) != e2.shown0 || len(e2.fake.Seen()) != 0 {
		t.Fatal("nothing asked or sent")
	}
}

// plainPipes is a platform.Pipes without StdoutThrough.
type plainPipes struct{ f *fake.Fake }

func (p plainPipes) StdoutReadBy(w, r platform.ProcessRef) (bool, error) {
	return p.f.StdoutReadBy(w, r)
}
