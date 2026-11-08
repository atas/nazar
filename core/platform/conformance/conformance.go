// Package conformance is the behavioural contract of platform.Platform as an
// importable test suite. Every implementation runs it: the fake in
// Milestones 1–2 (core/platform/conformance tests) and the Swift platform in
// Milestone 3, from its own test binary:
//
//	conformance.Run(t, func(t *testing.T) conformance.Env {
//		return conformance.Env{P: newSwiftPlatform(t), Spawn: ..., Exit: ..., Peer: ...}
//	})
//
// The suite checks the contract written on the types in core/platform: key
// handling, approval refs (never reused, unknown or released means no
// approval and never crashes), process refs (full refs are exact, PID-only
// refs resolve to the live occupant, the zero ref and tampered refs are
// ErrNoProcess), AppFor, the exit and lock events, and, when the platform
// offers platform.Exec, the exec events and the startup environment, a
// Kubernetes CA made, used and deleted on the platform's keys, and, when
// the platform offers platform.Pipes, who reads a process's stdout.
package conformance

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/seal"
)

// Env is one platform under test plus the hooks that drive it. P is
// required. The others are optional: a subtest that needs a nil hook is
// skipped, never failed, so a platform that can't be driven without a human
// (no Answer) or can't spawn processes still runs the rest of the suite.
type Env struct {
	P platform.Platform
	// Answer scripts the user's answer to the next Authenticate or Confirm.
	Answer func(allow bool)
	// Spawn starts a new live process and returns its full ref.
	Spawn func() platform.ProcessRef
	// Exit ends a process started by Spawn; it returns once the process is
	// gone from the platform's point of view.
	Exit func(ref platform.ProcessRef)
	// Peer returns a connected socket fd and the PID of its peer process.
	Peer func() (fd int, pid int)
	// SkipUserPresenceKeys: never create an AuthUserPresence key. Set for
	// the real Secure Enclave (the conformance host): a user-presence key could raise a
	// prompt if the platform under test misbehaved, and automated runs must
	// never risk one. The subtests that need such a key are skipped.
	SkipUserPresenceKeys bool
	// Exec is the platform's exec seam (platform.Exec); nil skips
	// the exec group.
	Exec platform.Exec
	// Execer starts a live process the exec group makes exec on cue, with
	// exactly the startup environment env, in the folder "/" (see Execer).
	Execer func(env []string) Execer
	// Mounts is the platform's mount watch (platform.Mounts); nil
	// skips the mounts group.
	Mounts platform.Mounts
	// Mount mounts a volume and unmounts it again; it returns when both
	// are done.
	Mount func(t *testing.T)
	// Pipes is the platform's stdout query (platform.Pipes); nil
	// skips the pipes group.
	Pipes platform.Pipes
	// Stdout starts the processes of one case (see StdoutCase), live until
	// the subtest ends, and returns the process whose fd 1 the case set up
	// and the process the suite asks about as its reader: the process that
	// started it, as kubectl starts its exec plugin.
	Stdout func(t *testing.T, c StdoutCase) (writer, reader platform.ProcessRef)
}

// StdoutCase is one way a process's fd 1 can be set up. In each,
// writer is a child of reader; only StdoutPiped is written by writer alone
// and read by reader alone.
type StdoutCase string

const (
	// StdoutPiped: fd 1 is the write end of a pipe whose read end reader
	// holds (how client-go runs an exec plugin).
	StdoutPiped StdoutCase = "piped"
	// StdoutPipedElsewhere: fd 1 is the write end of a pipe whose read end
	// a third process holds, while reader holds the read end of another
	// pipe (the third process's stdout).
	StdoutPipedElsewhere StdoutCase = "piped-elsewhere"
	// StdoutSharedReadEnd: as StdoutPiped, but a third process (reader's
	// other child) holds a copy of the pipe's read end too, as a launcher
	// that hands kubectl a pipe and keeps it can (THREAT-MODEL 5.16).
	StdoutSharedReadEnd StdoutCase = "shared-read-end"
	// StdoutSharedWriteEnd: as StdoutPiped, but a third process (reader's
	// other child) holds a copy of the pipe's write end too, as a
	// co-writer a wrapper leaves behind can (a background job that writes
	// around the plugin's reply, THREAT-MODEL 5.16).
	StdoutSharedWriteEnd StdoutCase = "shared-write-end"
	// StdoutInheritedReadEnd: as StdoutPiped, but reader holds the read
	// end through an fd that is not close-on-exec, as a pipe a process
	// inherited is (kubectl's stdin, from a launcher that then closed its
	// own copy; THREAT-MODEL 5.16), never one it opened itself.
	StdoutInheritedReadEnd StdoutCase = "inherited-read-end"
	// StdoutRelayed: writer was started with fd 1 piped to reader, then
	// made a relay and exec'd on, as a wrapper with exec hops does:
	// /bin/bash -c 'exec > >(exec /bin/cat); exec <program>'; its fd 1 is
	// now cat's pipe, and cat writes to reader's.
	StdoutRelayed StdoutCase = "relayed"
	// StdoutFile: fd 1 is a regular file.
	StdoutFile StdoutCase = "file"
	// StdoutTerminal: fd 1 is a terminal (a pty whose controller reader
	// holds).
	StdoutTerminal StdoutCase = "terminal"
	// StdoutSocket: fd 1 is a socket whose other end reader holds.
	StdoutSocket StdoutCase = "socket"
	// StdoutReadEnd: fd 1 is the read end of a pipe whose write end
	// reader holds.
	StdoutReadEnd StdoutCase = "read-end"
	// StdoutClosed: fd 1 is closed.
	StdoutClosed StdoutCase = "closed"
	// StdoutGone: as StdoutPiped, but writer has exited (and been reaped)
	// before Stdout returns.
	StdoutGone StdoutCase = "gone"
)

// Image is what one exec of an Execer must look like: the new image's
// realpath and argv, and whether the platform hides that image's startup
// environment (an Apple platform binary on macOS).
type Image struct {
	Path   string
	Args   []string
	Hidden bool
}

// Execer is a live process with a fixed script of three execs: an image
// whose environment is readable, the same image again, then one whose
// environment is hidden. Next makes it exec once and returns what that
// exec must look like; the group calls it only after the previous exec
// was reported (two execs in one moment may be reported as one).
type Execer struct {
	Ref  platform.ProcessRef
	Next func() Image
}

// Run runs the whole suite. newEnv is called once per subtest that needs a
// platform, so every subtest starts from a fresh one.
func Run(t *testing.T, newEnv func(t *testing.T) Env) {
	t.Run("keys", func(t *testing.T) { keys(t, newEnv) })
	t.Run("approvals", func(t *testing.T) { approvals(t, newEnv) })
	t.Run("processes", func(t *testing.T) { processes(t, newEnv) })
	t.Run("events", func(t *testing.T) { events(t, newEnv) })
	t.Run("exec", func(t *testing.T) { execs(t, newEnv) })
	t.Run("mounts", func(t *testing.T) { mountsGroup(t, newEnv) })
	t.Run("pipes", func(t *testing.T) { pipesGroup(t, newEnv) })
}

// eventWait bounds how long the suite waits for a callback that must run.
const eventWait = 5 * time.Second

var prompt = platform.Prompt{
	Title:   "nazar platform conformance",
	Lines:   []string{"a test of the platform contract"},
	Reason:  "run the platform conformance suite",
	Timeout: 30 * time.Second,
}

// ---- keys ------------------------------------------------------------------

func keys(t *testing.T, newEnv func(t *testing.T) Env) {
	t.Run("create-and-sign", func(t *testing.T) {
		p := newEnv(t).P
		handle, pub := createKey(t, p, platform.PurposeSign, platform.AuthNone)
		msg := []byte("conformance: sign me")
		sig, err := p.Sign(handle, msg, 0)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		verify(t, pub, msg, sig)
		if ecdsa.VerifyASN1(pub, digest([]byte("another message")), sig) {
			t.Fatal("signature verified for a different message")
		}
		// An AuthNone key ignores the approval argument, whatever it is.
		sig, err = p.Sign(handle, msg, platform.ApprovalRef(0x5eed1234abcd))
		if err != nil {
			t.Fatalf("Sign with an arbitrary approval ref on an AuthNone key: %v", err)
		}
		verify(t, pub, msg, sig)
	})

	t.Run("unknown-handles", func(t *testing.T) {
		p := newEnv(t).P
		for name, h := range map[string][]byte{"nil": nil, "empty": {}, "random": randomBytes(t, 32), "short": {1, 2, 3}} {
			if _, err := p.Sign(h, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
				t.Errorf("Sign(%s handle) = %v, want ErrNotFound", name, err)
			}
			if _, err := p.KeyAgreement(h, p256Point(t), 0); !errors.Is(err, platform.ErrNotFound) {
				t.Errorf("KeyAgreement(%s handle) = %v, want ErrNotFound", name, err)
			}
			if err := p.DeleteKey(h); !errors.Is(err, platform.ErrNotFound) {
				t.Errorf("DeleteKey(%s handle) = %v, want ErrNotFound", name, err)
			}
		}
	})

	t.Run("delete", func(t *testing.T) {
		p := newEnv(t).P
		handle, _ := createKey(t, p, platform.PurposeSign, platform.AuthNone)
		if err := p.DeleteKey(handle); err != nil {
			t.Fatalf("DeleteKey: %v", err)
		}
		if sig, err := p.Sign(handle, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) || sig != nil {
			t.Fatalf("Sign after DeleteKey = %x, %v; want ErrNotFound", sig, err)
		}
		if err := p.DeleteKey(handle); !errors.Is(err, platform.ErrNotFound) {
			t.Fatalf("second DeleteKey = %v, want ErrNotFound", err)
		}
	})

	t.Run("purpose", func(t *testing.T) {
		p := newEnv(t).P
		signH, _ := createKey(t, p, platform.PurposeSign, platform.AuthNone)
		kaH, _ := createKey(t, p, platform.PurposeKeyAgreement, platform.AuthNone)
		if out, err := p.KeyAgreement(signH, p256Point(t), 0); err == nil || out != nil {
			t.Errorf("KeyAgreement with a signing key = %x, %v; want an error", out, err)
		}
		if out, err := p.Sign(kaH, []byte("x"), 0); err == nil || out != nil {
			t.Errorf("Sign with a key-agreement key = %x, %v; want an error", out, err)
		}
	})

	t.Run("key-agreement", func(t *testing.T) {
		p := newEnv(t).P
		handle, pub := createKey(t, p, platform.PurposeKeyAgreement, platform.AuthNone)
		local, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.KeyAgreement(handle, local.PublicKey().Bytes(), 0)
		if err != nil {
			t.Fatalf("KeyAgreement: %v", err)
		}
		remote, err := ecdh.P256().NewPublicKey(pubBytes(t, pub))
		if err != nil {
			t.Fatalf("platform public key is not a P-256 point: %v", err)
		}
		want, err := local.ECDH(remote)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("shared secret %x, want %x (local ECDH)", got, want)
		}
		notOnCurve := make([]byte, 65)
		notOnCurve[0] = 4
		for name, peer := range map[string][]byte{
			"nil": nil, "empty": {}, "prefix only": {4}, "truncated": local.PublicKey().Bytes()[:40],
			"not on curve": notOnCurve, "compressed": append([]byte{2}, local.PublicKey().Bytes()[1:33]...),
		} {
			if out, err := p.KeyAgreement(handle, peer, 0); err == nil || out != nil {
				t.Errorf("KeyAgreement(%s peer key) = %x, %v; want an error", name, out, err)
			}
		}
	})

	t.Run("sealed-secret", func(t *testing.T) {
		// Milestone 8: a secret sealed with HPKE to a key-agreement
		// key opens through KeyAgreement (the enclave's ECDH is what
		// DHKEM(P-256, HKDF-SHA256) needs), not through another key, and not
		// after DeleteKey. keys/delete deletes a signing key only.
		p := newEnv(t).P
		handle, pub := createKey(t, p, platform.PurposeKeyAgreement, platform.AuthNone)
		other, _ := createKey(t, p, platform.PurposeKeyAgreement, platform.AuthNone)
		agree := func(h []byte) seal.Agree {
			return func(peer []byte) ([]byte, error) { return p.KeyAgreement(h, peer, 0) }
		}
		value := []byte("conformance secret \x00\xff")
		enc, ct, err := seal.Seal(pubBytes(t, pub), "conformance", value)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := seal.Open(pubBytes(t, pub), agree(handle), "conformance", enc, ct)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("Open through KeyAgreement = %v; want the sealed value", err)
		}
		if out, err := seal.Open(pubBytes(t, pub), agree(other), "conformance", enc, ct); !errors.Is(err, seal.ErrOpen) || out != nil {
			t.Fatalf("Open through another key = %x, %v; want seal.ErrOpen", out, err)
		}
		if err := p.DeleteKey(handle); err != nil {
			t.Fatalf("DeleteKey: %v", err)
		}
		if out, err := seal.Open(pubBytes(t, pub), agree(handle), "conformance", enc, ct); !errors.Is(err, platform.ErrNotFound) || out != nil {
			t.Fatalf("Open after DeleteKey = %x, %v; want ErrNotFound", out, err)
		}
		if err := p.DeleteKey(other); err != nil {
			t.Fatalf("DeleteKey(other): %v", err)
		}
	})

	// A Kubernetes CA as nazar-agent makes and uses it. AuthNone,
	// so the real Secure Enclave run makes one with nothing on screen.
	t.Run("k8s-ca", func(t *testing.T) { k8sCA(t, newEnv(t).P) })

	t.Run("out-of-range", func(t *testing.T) {
		env := newEnv(t)
		p := env.P
		for _, purpose := range []platform.Purpose{0, 3, -1, math.MaxInt32} {
			if h, pub, err := p.CreateKey(purpose, platform.AuthNone, platform.AccessAfterFirstUnlock); err == nil || h != nil || pub != nil {
				t.Errorf("CreateKey(%v, none) = %x, %x, %v; want a refusal", purpose, h, pub, err)
			}
		}
		for _, auth := range []platform.AuthPolicy{2, -1, math.MaxInt32} {
			if h, pub, err := p.CreateKey(platform.PurposeSign, auth, platform.AccessAfterFirstUnlock); err == nil || h != nil || pub != nil {
				t.Errorf("CreateKey(sign, %v) = %x, %x, %v; want a refusal", auth, h, pub, err)
			}
		}
		// An unknown access never becomes "works while locked".
		for _, access := range []platform.Access{2, -1, math.MaxInt32} {
			if h, pub, err := p.CreateKey(platform.PurposeSign, platform.AuthNone, access); err == nil || h != nil || pub != nil {
				t.Errorf("CreateKey(sign, none, %v) = %x, %x, %v; want a refusal", access, h, pub, err)
			}
		}
		// A user-presence key is never made to work while locked. (Not
		// asked at all with SkipUserPresenceKeys: that run requests no
		// user-presence key, refused or not.)
		for _, purpose := range []platform.Purpose{platform.PurposeSign, platform.PurposeKeyAgreement} {
			if env.SkipUserPresenceKeys {
				break
			}
			if h, pub, err := p.CreateKey(purpose, platform.AuthUserPresence, platform.AccessAfterFirstUnlock); err == nil || h != nil || pub != nil {
				t.Errorf("CreateKey(%v, user-presence, after-first-unlock) = %x, %x, %v; want a refusal", purpose, h, pub, err)
			}
		}
	})

	// Both accesses make keys that sign and agree (the Secure Enclave run
	// makes them on the chip; nothing here locks the Mac). Run while the
	// Mac is locked, the chip makes no when-unlocked key: ErrLocked, and
	// that part is skipped.
	t.Run("access", func(t *testing.T) {
		p := newEnv(t).P
		for _, access := range []platform.Access{platform.AccessWhenUnlocked, platform.AccessAfterFirstUnlock} {
			h, pub, err := p.CreateKey(platform.PurposeSign, platform.AuthNone, access)
			if errors.Is(err, platform.ErrLocked) && access == platform.AccessWhenUnlocked {
				t.Log("the Mac is locked: no when-unlocked key can be made now")
				continue
			}
			if err != nil {
				t.Fatalf("CreateKey(sign, none, %v): %v", access, err)
			}
			der, err := p.Sign(h, []byte("x"), 0)
			if err != nil {
				t.Fatalf("Sign with a %v key: %v", access, err)
			}
			if sum := sha256.Sum256([]byte("x")); !ecdsa.VerifyASN1(pubKey(t, pub), sum[:], der) {
				t.Fatalf("a %v key's signature does not verify", access)
			}
			kh, _, err := p.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, access)
			if err != nil {
				t.Fatalf("CreateKey(key-agreement, none, %v): %v", access, err)
			}
			if out, err := p.KeyAgreement(kh, p256Point(t), 0); err != nil || len(out) != 32 {
				t.Fatalf("KeyAgreement with a %v key = %x, %v", access, out, err)
			}
			_ = p.DeleteKey(h)
			_ = p.DeleteKey(kh)
		}
	})

	t.Run("user-presence-needs-approval", func(t *testing.T) {
		env := newEnv(t)
		if env.SkipUserPresenceKeys {
			t.Skip("SkipUserPresenceKeys")
		}
		p := env.P
		signH, _ := createKey(t, p, platform.PurposeSign, platform.AuthUserPresence)
		kaH, _ := createKey(t, p, platform.PurposeKeyAgreement, platform.AuthUserPresence)
		for name, ref := range map[string]platform.ApprovalRef{"zero": 0, "forged": 0x1234567, "max": math.MaxUint64} {
			if sig, err := p.Sign(signH, []byte("x"), ref); !errors.Is(err, platform.ErrAuthRequired) || sig != nil {
				t.Errorf("Sign(user-presence key, %s ref) = %x, %v; want ErrAuthRequired", name, sig, err)
			}
			if out, err := p.KeyAgreement(kaH, p256Point(t), ref); !errors.Is(err, platform.ErrAuthRequired) || out != nil {
				t.Errorf("KeyAgreement(user-presence key, %s ref) = %x, %v; want ErrAuthRequired", name, out, err)
			}
		}
	})
}

// k8sCA makes a CA with k8s.CAStore on p, issues one client certificate,
// verifies both with the CA's public key alone (nothing of core/k8s), and
// deletes the CA. The vault is in memory: the suite never writes a real
// one. x509 hands Sign the TBS bytes, a few hundred: the longest message
// of the suite.
func k8sCA(t *testing.T, p platform.Platform) {
	const name = "nazar-conformance"
	store := k8s.NewCAStore(p, fake.NewVault(), nil)
	ca, err := store.Create(name, platform.AccessAfterFirstUnlock)
	if err != nil {
		t.Fatalf("CAStore.Create: %v", err)
	}
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			_ = store.Delete(name)
		}
	})
	caPub := pubKey(t, ca.PublicKey)
	if certPub, ok := ca.Cert.PublicKey.(*ecdsa.PublicKey); !ok || !certPub.Equal(caPub) {
		t.Fatal("the CA certificate is not for the key CreateKey made")
	}
	if !ecdsa.VerifyASN1(caPub, digest(ca.Cert.RawTBSCertificate), ca.Cert.Signature) {
		t.Fatal("the CA certificate's signature does not verify with the CA's public key")
	}

	id := config.K8sIdentity{User: "nazar-conformance", Groups: []string{"nazar:conformance"}}
	now := time.Now()
	cred, err := ca.Issue(p, id, config.MinTTLCert, now, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	defer clear(cred.KeyPEM)
	block, _ := pem.Decode(cred.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("Issue returned no PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("the issued certificate does not parse: %v", err)
	}
	if !ecdsa.VerifyASN1(caPub, digest(leaf.RawTBSCertificate), leaf.Signature) {
		t.Fatal("the issued certificate's signature does not verify with the CA's public key")
	}
	roots := x509.NewCertPool() // our own pool: never the system's trust service
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the issued certificate does not chain to the CA as a client certificate: %v", err)
	}

	if err := store.Delete(name); err != nil {
		t.Fatalf("CAStore.Delete: %v", err)
	}
	deleted = true
	if sig, err := p.Sign(ca.Handle, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) || sig != nil {
		t.Fatalf("Sign with a deleted CA's key = %x, %v; want ErrNotFound", sig, err)
	}
	if _, err := store.Get(name); !errors.Is(err, k8s.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// ---- approvals ---------------------------------------------------------------

func approvals(t *testing.T, newEnv func(t *testing.T) Env) {
	t.Run("live-ref-signs", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		handle, pub := createKey(t, env.P, platform.PurposeSign, platform.AuthUserPresence)
		ref := authenticate(t, env)
		msg := []byte("approved")
		sig, err := env.P.Sign(handle, msg, ref)
		if err != nil {
			t.Fatalf("Sign with a live ref: %v", err)
		}
		verify(t, pub, msg, sig)
		kaH, _ := createKey(t, env.P, platform.PurposeKeyAgreement, platform.AuthUserPresence)
		if _, err := env.P.KeyAgreement(kaH, p256Point(t), ref); err != nil {
			t.Fatalf("KeyAgreement with a live ref: %v", err)
		}
		env.P.ReleaseApproval(ref)
	})

	t.Run("released-ref-is-no-approval", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		handle, _ := createKey(t, env.P, platform.PurposeSign, platform.AuthUserPresence)
		kaH, _ := createKey(t, env.P, platform.PurposeKeyAgreement, platform.AuthUserPresence)
		ref := authenticate(t, env)
		if _, err := env.P.Sign(handle, []byte("x"), ref); err != nil {
			t.Fatalf("Sign with a live ref: %v", err)
		}
		env.P.ReleaseApproval(ref)
		for i := 0; i < 2; i++ { // and again after a second, no-op release
			if sig, err := env.P.Sign(handle, []byte("x"), ref); !errors.Is(err, platform.ErrAuthRequired) || sig != nil {
				t.Fatalf("Sign with a released ref = %x, %v; want ErrAuthRequired", sig, err)
			}
			if out, err := env.P.KeyAgreement(kaH, p256Point(t), ref); !errors.Is(err, platform.ErrAuthRequired) || out != nil {
				t.Fatalf("KeyAgreement with a released ref = %x, %v; want ErrAuthRequired", out, err)
			}
			env.P.ReleaseApproval(ref)
		}
	})

	t.Run("unknown-refs-are-no-approval", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		handle, _ := createKey(t, env.P, platform.PurposeSign, platform.AuthUserPresence)
		live := authenticate(t, env)
		unknown := map[string]platform.ApprovalRef{"zero": 0, "live+1": live + 1, "live-1": live - 1, "live^1": live ^ 1, "far": live + 0x100000, "max": math.MaxUint64}
		for name, ref := range unknown {
			if ref == live {
				continue
			}
			if sig, err := env.P.Sign(handle, []byte("x"), ref); !errors.Is(err, platform.ErrAuthRequired) || sig != nil {
				t.Errorf("Sign with %s ref = %x, %v; want ErrAuthRequired", name, sig, err)
			}
		}
		// Releasing zero or an unknown ref is a no-op: the live ref stays live.
		for _, ref := range unknown {
			if ref != live {
				env.P.ReleaseApproval(ref)
			}
		}
		if _, err := env.P.Sign(handle, []byte("x"), live); err != nil {
			t.Fatalf("live ref lost after releasing unknown refs: %v", err)
		}
		env.P.ReleaseApproval(live)
	})

	t.Run("release-one-leaves-others", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		handle, _ := createKey(t, env.P, platform.PurposeSign, platform.AuthUserPresence)
		a := authenticate(t, env)
		b := authenticate(t, env)
		if a == b {
			t.Fatalf("two Authenticate calls returned the same ref %d", a)
		}
		env.P.ReleaseApproval(a)
		if _, err := env.P.Sign(handle, []byte("x"), b); err != nil {
			t.Fatalf("Sign with ref b after releasing a: %v", err)
		}
		if _, err := env.P.Sign(handle, []byte("x"), a); !errors.Is(err, platform.ErrAuthRequired) {
			t.Fatalf("Sign with released ref a = %v; want ErrAuthRequired", err)
		}
		env.P.ReleaseApproval(b)
	})

	t.Run("refs-never-reused", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		seen := map[platform.ApprovalRef]int{}
		for i := 0; i < 6; i++ {
			ref := authenticate(t, env)
			if j, dup := seen[ref]; dup {
				t.Fatalf("Authenticate #%d returned ref %d, already issued by #%d and released since", i, ref, j)
			}
			seen[ref] = i
			env.P.ReleaseApproval(ref)
		}
		const n = 8
		for i := 0; i < n; i++ {
			env.Answer(true)
		}
		var wg sync.WaitGroup
		refs := make([]platform.ApprovalRef, n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				refs[i], errs[i] = env.P.Authenticate(platform.AuthUserPresence, prompt)
			}(i)
		}
		wg.Wait()
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("concurrent Authenticate #%d: %v", i, errs[i])
			}
			if refs[i] == 0 {
				t.Fatalf("concurrent Authenticate #%d returned the zero ref", i)
			}
			if _, dup := seen[refs[i]]; dup {
				t.Fatalf("concurrent Authenticate #%d returned ref %d, which was issued before", i, refs[i])
			}
			seen[refs[i]] = 100 + i
		}
		for _, ref := range refs {
			env.P.ReleaseApproval(ref)
		}
	})

	t.Run("denied", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		env.Answer(false)
		ref, err := env.P.Authenticate(platform.AuthUserPresence, prompt)
		if !errors.Is(err, platform.ErrDenied) || ref != 0 {
			t.Fatalf("denied Authenticate = %d, %v; want 0, ErrDenied", ref, err)
		}
	})

	t.Run("confirm", func(t *testing.T) {
		env := needAnswer(t, newEnv)
		for _, want := range []bool{false, true, false} {
			env.Answer(want)
			got, err := env.P.Confirm(prompt)
			// A denial may say how the dialog ended (platform.DialogDenied,
			// which wraps ErrDenied; since Milestone 5).
			if got != want || (err != nil && (want || !errors.Is(err, platform.ErrDenied))) {
				t.Fatalf("Confirm after the user answered %v = %v, %v", want, got, err)
			}
		}
	})
}

// ---- processes ---------------------------------------------------------------

func processes(t *testing.T, newEnv func(t *testing.T) Env) {
	t.Run("peer", func(t *testing.T) {
		env := newEnv(t)
		if env.Peer == nil {
			t.Skip("no Peer hook")
		}
		fd, pid := env.Peer()
		ref, err := env.P.PeerOf(fd)
		if err != nil {
			t.Fatalf("PeerOf(%d): %v", fd, err)
		}
		if ref.PID != pid || ref.Generation == 0 {
			t.Fatalf("PeerOf = %v, want PID %d with a non-zero generation", ref, pid)
		}
		info, err := env.P.Process(ref)
		if err != nil || info.Ref != ref {
			t.Fatalf("Process(peer %v) = %v, %v; want the same ref", ref, info.Ref, err)
		}
		byPID, err := env.P.Process(platform.ProcessRef{PID: pid})
		if err != nil || byPID.Ref != ref {
			t.Fatalf("Process(PID-only %d) = %v, %v; want the peer's full ref %v", pid, byPID.Ref, err, ref)
		}
		if _, err := env.P.PeerOf(-1); err == nil {
			t.Error("PeerOf(-1) succeeded")
		}
	})

	t.Run("live-ref", func(t *testing.T) {
		env := needSpawn(t, newEnv)
		ref := env.Spawn()
		if ref.IsZero() || ref.Generation == 0 {
			t.Fatalf("Spawn returned %v, want a full ref", ref)
		}
		first, err := env.P.Process(ref)
		if err != nil || first.Ref != ref {
			t.Fatalf("Process(%v) = %v, %v", ref, first.Ref, err)
		}
		// Comm (display only, since Milestone 5): the kernel's short name,
		// set for every live process, at most 16 bytes (MAXCOMLEN).
		if first.Comm == "" || len(first.Comm) > 16 {
			t.Errorf("Process(%v).Comm = %q, want the kernel's short name (1 to 16 bytes)", ref, first.Comm)
		}
		second, err := env.P.Process(ref)
		if err != nil || second.Ref != ref || !second.StartTime.Equal(first.StartTime) {
			t.Fatalf("Process(%v) again = %v %v, %v; want the same record", ref, second.Ref, second.StartTime, err)
		}
		for name, bad := range map[string]platform.ProcessRef{
			"generation+1": {PID: ref.PID, Generation: ref.Generation + 1},
			"generation-1": {PID: ref.PID, Generation: ref.Generation - 1},
			"generation^1": {PID: ref.PID, Generation: ref.Generation ^ 1},
		} {
			if bad.Generation == 0 {
				continue
			}
			if info, err := env.P.Process(bad); !errors.Is(err, platform.ErrNoProcess) {
				t.Errorf("Process(%s of a live PID) = %v, %v; want ErrNoProcess", name, info.Ref, err)
			}
		}
		byPID, err := env.P.Process(platform.ProcessRef{PID: ref.PID})
		if err != nil || byPID.Ref != ref {
			t.Fatalf("Process(PID-only %d) = %v, %v; want the live occupant's full ref %v", ref.PID, byPID.Ref, err, ref)
		}
	})

	t.Run("parent", func(t *testing.T) {
		env := needSpawn(t, newEnv)
		ref := env.Spawn()
		info, err := env.P.Process(ref)
		if err != nil {
			t.Fatal(err)
		}
		if info.Parent.IsZero() {
			t.Fatalf("Process(%v).Parent is zero; a spawned process has a parent", ref)
		}
		parent, err := env.P.Process(info.Parent)
		if err != nil {
			t.Fatalf("Process(parent %v): %v", info.Parent, err)
		}
		if parent.Ref.PID != info.Parent.PID || parent.Ref.Generation == 0 {
			t.Fatalf("Process(parent %v).Ref = %v; want that PID with a full ref", info.Parent, parent.Ref)
		}
		if info.Parent.Generation != 0 && parent.Ref != info.Parent {
			t.Fatalf("Process(exact parent %v).Ref = %v", info.Parent, parent.Ref)
		}
		if parent.StartTime.After(info.StartTime) {
			t.Fatalf("parent %v started at %v, after its child %v at %v", parent.Ref, parent.StartTime, ref, info.StartTime)
		}
	})

	t.Run("exited", func(t *testing.T) {
		env := needSpawn(t, newEnv)
		if env.Exit == nil {
			t.Skip("no Exit hook")
		}
		ref := env.Spawn()
		env.Exit(ref)
		if info, err := env.P.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Fatalf("Process(exited %v) = %v, %v; want ErrNoProcess", ref, info.Ref, err)
		}
		// The PID may have been recycled meanwhile; what must not come back
		// is the exited instance.
		if info, err := env.P.Process(platform.ProcessRef{PID: ref.PID}); err == nil && (info.Ref == ref || info.Ref.Generation == 0) {
			t.Fatalf("Process(PID-only %d) after exit = %v", ref.PID, info.Ref)
		}
	})

	t.Run("zero-and-bad-pids", func(t *testing.T) {
		p := newEnv(t).P
		for name, ref := range map[string]platform.ProcessRef{
			"zero":                {},
			"negative":            {PID: -1},
			"negative with gen":   {PID: -1, Generation: 1},
			"absent":              {PID: math.MaxInt32},
			"absent with gen":     {PID: math.MaxInt32, Generation: 1},
			"pid 0 with gen":      {PID: 0, Generation: 1},
			"very negative":       {PID: math.MinInt32},
			"max pid max gen":     {PID: math.MaxInt32, Generation: math.MaxUint64},
			"absent pid-only odd": {PID: math.MaxInt32 - 1},
		} {
			if info, err := p.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
				t.Errorf("Process(%s %v) = %v, %v; want ErrNoProcess", name, ref, info.Ref, err)
			}
		}
	})

	t.Run("appfor", func(t *testing.T) {
		env := newEnv(t)
		if app, ok := env.P.AppFor(nil); ok {
			t.Errorf("AppFor(nil) = %+v, true", app)
		}
		if app, ok := env.P.AppFor([]platform.ProcessInfo{}); ok {
			t.Errorf("AppFor(empty) = %+v, true", app)
		}
		forged := platform.ProcessInfo{
			Ref:       platform.ProcessRef{PID: 424242, Generation: 424242001},
			Parent:    platform.ProcessRef{PID: 1, Generation: 1},
			UID:       501,
			StartTime: time.Now().Add(-time.Hour),
			Path:      "/Applications/Forged.app/Contents/MacOS/Forged",
			Args:      []string{"/Applications/Forged.app/Contents/MacOS/Forged"},
			Code:      platform.CodeIdentity{Signed: true, TeamID: "FORGED0000", SigningID: "com.example.forged", CDHash: []byte{0xf0}},
		}
		if app, ok := env.P.AppFor([]platform.ProcessInfo{forged}); ok {
			t.Errorf("AppFor(forged app-looking record) = %+v, true", app)
		}
		if env.Spawn != nil {
			info, err := env.P.Process(env.Spawn())
			if err != nil {
				t.Fatal(err)
			}
			if app, ok := env.P.AppFor([]platform.ProcessInfo{info}); ok {
				t.Errorf("AppFor(non-app process %v) = %+v, true", info.Ref, app)
			}
			info.Path = forged.Path // a real process with a forged path is still not an app
			if app, ok := env.P.AppFor([]platform.ProcessInfo{info}); ok {
				t.Errorf("AppFor(live process with an app-looking path) = %+v, true", app)
			}
		}
		// Apps lists candidates AppFor agrees with: each entry is a live
		// process under its full ref, and AppFor of its own record is that
		// app. An app that quits between the two calls is simply gone.
		for _, app := range env.P.Apps() {
			if app.Ref.Generation == 0 || app.BundleID == "" {
				t.Errorf("Apps() lists %+v: not a full ref with a bundle id", app)
				continue
			}
			info, err := env.P.Process(app.Ref)
			if errors.Is(err, platform.ErrNoProcess) {
				continue
			}
			if err != nil || info.Ref != app.Ref {
				t.Errorf("Apps() lists %v (%s), but Process answers %v, %v", app.Ref, app.BundleID, info.Ref, err)
				continue
			}
			if got, ok := env.P.AppFor([]platform.ProcessInfo{info}); !ok || got.Ref != app.Ref || got.BundleID != app.BundleID {
				// A real app may have stopped being one between the two
				// calls (its activation policy changed): then it is no
				// longer listed either, and that is not a disagreement.
				for _, again := range env.P.Apps() {
					if again.Ref == app.Ref {
						t.Errorf("Apps() lists %v (%s), but AppFor(its record) = %+v, %v", app.Ref, app.BundleID, got, ok)
					}
				}
			}
		}
	})

	t.Run("unknown-inputs", func(t *testing.T) {
		p := newEnv(t).P
		for name, ref := range map[string]platform.ProcessRef{"zero": {}, "absent": {PID: math.MaxInt32, Generation: 1}, "absent pid-only": {PID: math.MaxInt32}} {
			if r, ok := p.ResponsibleFor(ref); ok {
				t.Errorf("ResponsibleFor(%s %v) = %v, true", name, ref, r)
			}
		}
		path := "/nonexistent/nazar-conformance-" + hex.EncodeToString(randomBytes(t, 8))
		if h, err := p.CodeHash(path); !errors.Is(err, platform.ErrNotFound) || h != nil {
			t.Errorf("CodeHash(missing path) = %x, %v; want ErrNotFound", h, err)
		}
		id := "dev.nazar.conformance.absent." + hex.EncodeToString(randomBytes(t, 8))
		if b, err := p.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) || b.BundleID != "" || b.Path != "" {
			t.Errorf("InstalledApp(absent bundle id) = %+v, %v; want ErrNotFound", b, err)
		}
	})
}

// ---- events ------------------------------------------------------------------

func events(t *testing.T, newEnv func(t *testing.T) Env) {
	t.Run("exit-once", func(t *testing.T) {
		env := needSpawn(t, newEnv)
		if env.Exit == nil {
			t.Skip("no Exit hook")
		}
		ref := env.Spawn()
		fired := make(chan struct{}, 16)
		env.P.OnProcessExit(ref, func() { fired <- struct{}{} })
		select {
		case <-fired:
			t.Fatalf("exit callback for live %v ran before Exit", ref)
		case <-time.After(50 * time.Millisecond):
		}
		env.Exit(ref)
		waitFired(t, fired, "exit callback after Exit")
		select {
		case <-fired:
			t.Fatal("exit callback ran twice")
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("exit-gone-promptly", func(t *testing.T) {
		env := needSpawn(t, newEnv)
		if env.Exit == nil {
			t.Skip("no Exit hook")
		}
		ref := env.Spawn()
		env.Exit(ref)
		fired := make(chan struct{}, 16)
		env.P.OnProcessExit(ref, func() { fired <- struct{}{} })
		waitFired(t, fired, "exit callback registered on an exited process")
		select {
		case <-fired:
			t.Fatal("exit callback ran twice")
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("exit-never-existed", func(t *testing.T) {
		env := newEnv(t)
		refs := []platform.ProcessRef{{PID: math.MaxInt32, Generation: 1}}
		if env.Spawn != nil {
			live := env.Spawn()
			refs = append(refs, platform.ProcessRef{PID: live.PID, Generation: live.Generation + 1})
		}
		for _, ref := range refs {
			fired := make(chan struct{}, 16)
			env.P.OnProcessExit(ref, func() { fired <- struct{}{} })
			waitFired(t, fired, "exit callback registered on a ref that names no process")
		}
	})

	t.Run("non-blocking", func(t *testing.T) {
		p := newEnv(t).P
		done := make(chan string, 2)
		go func() {
			p.OnScreenLock(func() {})
			done <- "OnScreenLock"
		}()
		go func() {
			p.ShowWarning(platform.Warning{ID: "conformance", Title: "conformance", Lines: []string{"non-modal"}, Count: 1})
			done <- "ShowWarning"
		}()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(eventWait):
				t.Fatal("OnScreenLock or ShowWarning did not return")
			}
		}
	})
}

// ---- helpers -----------------------------------------------------------------

func needAnswer(t *testing.T, newEnv func(t *testing.T) Env) Env {
	t.Helper()
	env := newEnv(t)
	if env.Answer == nil {
		t.Skip("no Answer hook")
	}
	if env.SkipUserPresenceKeys {
		t.Skip("SkipUserPresenceKeys") // every approvals subtest signs with a user-presence key
	}
	return env
}

func needSpawn(t *testing.T, newEnv func(t *testing.T) Env) Env {
	t.Helper()
	env := newEnv(t)
	if env.Spawn == nil {
		t.Skip("no Spawn hook")
	}
	return env
}

// authenticate scripts an allow and returns the live ref it produced.
func authenticate(t *testing.T, env Env) platform.ApprovalRef {
	t.Helper()
	env.Answer(true)
	ref, err := env.P.Authenticate(platform.AuthUserPresence, prompt)
	if err != nil {
		t.Fatalf("Authenticate after the user allowed: %v", err)
	}
	if ref == 0 {
		t.Fatal("Authenticate returned the zero ref for an allowed prompt")
	}
	return ref
}

func createKey(t *testing.T, p platform.Platform, purpose platform.Purpose, auth platform.AuthPolicy) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	// The access production gives auth (Access.Fits): a user-presence key
	// works only while the Mac is unlocked.
	access := platform.AccessAfterFirstUnlock
	if auth == platform.AuthUserPresence {
		access = platform.AccessWhenUnlocked
	}
	handle, pub, err := p.CreateKey(purpose, auth, access)
	if err != nil {
		t.Fatalf("CreateKey(%v, %v): %v", purpose, auth, err)
	}
	if len(handle) == 0 {
		t.Fatal("CreateKey returned an empty handle")
	}
	return handle, pubKey(t, pub)
}

// pubKey parses the X9.63 uncompressed point CreateKey returns.
func pubKey(t *testing.T, b []byte) *ecdsa.PublicKey {
	t.Helper()
	if len(b) != 65 || b[0] != 4 {
		t.Fatalf("public key is %d bytes starting 0x%02x, want a 65-byte 0x04 point", len(b), first(b))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
	if err != nil {
		t.Fatalf("public key is not a P-256 point: %v", err)
	}
	return pub
}

func pubBytes(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func first(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func digest(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}

func verify(t *testing.T, pub *ecdsa.PublicKey, msg, sig []byte) {
	t.Helper()
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	if !ecdsa.VerifyASN1(pub, digest(msg), sig) {
		t.Fatalf("signature %x does not verify as DER ECDSA over SHA-256 of the input", sig)
	}
}

// p256Point is a valid peer public key for KeyAgreement calls whose result
// does not matter.
func p256Point(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func waitFired(t *testing.T, fired <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-fired:
	case <-time.After(eventWait):
		t.Fatalf("%s did not run within %v", what, eventWait)
	}
}

// ---- exec (platform.Exec) --------------------------------------------------

// execEnv is every Execer's startup environment: a space, a non-ASCII
// letter and a second "=" must come back exactly, in order.
var execEnv = []string{"NAZAR_CONFORMANCE=exec", "B=two words", "C=ü=x"}

type execRec struct{ ch chan platform.ProcessInfo }

// watchExec watches ref and records every event; the returned cancel is
// also run at cleanup, so it must be safe to call twice.
func watchExec(t *testing.T, x platform.Exec, ref platform.ProcessRef) (*execRec, func()) {
	t.Helper()
	r := &execRec{ch: make(chan platform.ProcessInfo, 16)}
	cancel, err := x.OnProcessExec(ref, func(p platform.ProcessInfo) { r.ch <- p })
	if err != nil {
		t.Fatalf("OnProcessExec(%v): %v", ref, err)
	}
	t.Cleanup(cancel)
	return r, cancel
}

func (r *execRec) next(t *testing.T, what string) platform.ProcessInfo {
	t.Helper()
	select {
	case p := <-r.ch:
		return p
	case <-time.After(eventWait):
		t.Fatalf("no exec event: %s", what)
	}
	return platform.ProcessInfo{}
}

func (r *execRec) none(t *testing.T, what string) {
	t.Helper()
	select {
	case p := <-r.ch:
		t.Fatalf("%s: unexpected exec event %v %q", what, p.Ref, p.Path)
	case <-time.After(300 * time.Millisecond):
	}
}

func needExecer(t *testing.T, newEnv func(t *testing.T) Env) (Env, Execer) {
	t.Helper()
	env := newEnv(t)
	if env.Exec == nil || env.Execer == nil {
		t.Skip("no Exec or Execer hook")
	}
	return env, env.Execer(slices.Clone(execEnv))
}

func execs(t *testing.T, newEnv func(t *testing.T) Env) {
	// Every exec is reported, in order, as read at the exec: the same ref
	// (an exec keeps the instance), the new image's realpath and argv, the
	// folder, and the live code identity, which is the file's CodeHash
	// (the daemon compares the two, secrets design 6.3 step 6).
	t.Run("every-exec", func(t *testing.T) {
		env, e := needExecer(t, newEnv)
		w, _ := watchExec(t, env.Exec, e.Ref)
		for i := 1; i <= 3; i++ {
			img := e.Next()
			got := w.next(t, fmt.Sprintf("exec %d", i))
			if got.Ref != e.Ref || got.Path != img.Path || !slices.Equal(got.Args, img.Args) || got.Cwd != "/" {
				t.Fatalf("exec %d reported %v %q %q in %q; want %v %q %q in /", i, got.Ref, got.Path, got.Args, got.Cwd, e.Ref, img.Path, img.Args)
			}
			if img.Hidden {
				continue
			}
			if want, err := env.P.CodeHash(img.Path); err != nil || !bytes.Equal(got.Code.CDHash, want) {
				t.Fatalf("exec %d: code %x, want CodeHash(%s) = %x (%v)", i, got.Code.CDHash, img.Path, want, err)
			}
		}
		w.none(t, "after the last exec")
	})

	// The startup environment as the last watched exec gave it, exactly;
	// ErrUnreadable before any watched exec and for a hidden image, never
	// a list in its place; ErrNoProcess once the process is gone.
	t.Run("environment", func(t *testing.T) {
		env, e := needExecer(t, newEnv)
		x := env.Exec
		if got, err := x.Environment(e.Ref); !errors.Is(err, platform.ErrUnreadable) {
			t.Fatalf("Environment of a process no watch saw exec = %q, %v; want ErrUnreadable", got, err)
		}
		w, _ := watchExec(t, x, e.Ref)
		if got, err := x.Environment(e.Ref); !errors.Is(err, platform.ErrUnreadable) {
			t.Fatalf("Environment before the first watched exec = %q, %v; want ErrUnreadable", got, err)
		}
		for i := 1; i <= 2; i++ {
			e.Next()
			w.next(t, fmt.Sprintf("exec %d", i))
			if got, err := x.Environment(e.Ref); err != nil || !slices.Equal(got, execEnv) {
				t.Fatalf("Environment after exec %d = %q, %v; want exactly %q", i, got, err, execEnv)
			}
		}
		if img := e.Next(); !img.Hidden {
			t.Fatal("the Execer's third image must hide its environment")
		}
		w.next(t, "exec 3")
		if got, err := x.Environment(e.Ref); !errors.Is(err, platform.ErrUnreadable) {
			t.Fatalf("Environment of a hidden image = %q, %v; want ErrUnreadable, never a list", got, err)
		}
		if env.Exit == nil {
			return
		}
		env.Exit(e.Ref)
		w.none(t, "after exit")
		if _, err := x.Environment(e.Ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Fatalf("Environment after exit: %v, want ErrNoProcess", err)
		}
	})

	// An exec the platform saw before Environment answered has reached
	// every fn by then: once Environment answers for the first exec, its
	// event is already there (a caller never compares an image's
	// environment without having seen its exec).
	t.Run("seen-before-environment", func(t *testing.T) {
		env, e := needExecer(t, newEnv)
		w, _ := watchExec(t, env.Exec, e.Ref)
		e.Next()
		for end := time.Now().Add(eventWait); ; time.Sleep(time.Millisecond) {
			got, err := env.Exec.Environment(e.Ref)
			if err == nil {
				if !slices.Equal(got, execEnv) {
					t.Fatalf("Environment = %q, want %q", got, execEnv)
				}
				break
			}
			if !errors.Is(err, platform.ErrUnreadable) || time.Now().After(end) {
				t.Fatalf("Environment after the first exec: %v", err)
			}
		}
		select {
		case <-w.ch:
		default:
			t.Fatal("Environment answered for an exec no fn had seen")
		}
	})

	// fn is never called after cancel returns, even with an event on its
	// way; another watch of the same process keeps working; after the last
	// cancel the environment is ErrUnreadable (never a stale read).
	t.Run("cancel", func(t *testing.T) {
		env, e := needExecer(t, newEnv)
		var after, late atomic.Int32
		cancel, err := env.Exec.OnProcessExec(e.Ref, func(platform.ProcessInfo) {
			if after.Load() != 0 {
				late.Add(1)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		w, wcancel := watchExec(t, env.Exec, e.Ref)
		e.Next() // an event may be on its way while cancel runs
		cancel()
		after.Store(1)
		cancel() // twice is harmless
		w.next(t, "exec 1 on the other watch")
		e.Next()
		w.next(t, "exec 2 on the other watch")
		if n := late.Load(); n != 0 {
			t.Fatalf("fn ran %d times after cancel returned", n)
		}
		wcancel()
		if got, err := env.Exec.Environment(e.Ref); !errors.Is(err, platform.ErrUnreadable) {
			t.Fatalf("Environment after the last cancel = %q, %v; want ErrUnreadable", got, err)
		}
	})

	// Only the live instance a full ref names is watched: the zero ref, a
	// PID-only ref, another generation of the live PID, an absent PID and
	// an exited process (whose PID may be reused) are refused, and their
	// environment is ErrNoProcess.
	t.Run("refs", func(t *testing.T) {
		env, e := needExecer(t, newEnv)
		bad := map[string]platform.ProcessRef{
			"zero":         {},
			"pid-only":     {PID: e.Ref.PID},
			"generation+1": {PID: e.Ref.PID, Generation: e.Ref.Generation + 1},
			"generation-1": {PID: e.Ref.PID, Generation: e.Ref.Generation - 1},
			"absent":       {PID: math.MaxInt32, Generation: 1},
			"negative":     {PID: -1, Generation: 1},
		}
		if env.Exit != nil {
			gone := env.Execer(slices.Clone(execEnv))
			env.Exit(gone.Ref)
			bad["exited"] = gone.Ref
		}
		for name, ref := range bad {
			if cancel, err := env.Exec.OnProcessExec(ref, func(platform.ProcessInfo) {}); err == nil {
				cancel()
				t.Errorf("OnProcessExec(%s %v) succeeded", name, ref)
			}
			if _, err := env.Exec.Environment(ref); !errors.Is(err, platform.ErrNoProcess) {
				t.Errorf("Environment(%s %v): %v, want ErrNoProcess", name, ref, err)
			}
		}
		// The refusals left the live process's own watch possible.
		w, _ := watchExec(t, env.Exec, e.Ref)
		e.Next()
		w.next(t, "exec of the live process")
	})
}

// ---- mounts (platform.Mounts) ----------------------------------------------

func needMounts(t *testing.T, newEnv func(t *testing.T) Env) Env {
	t.Helper()
	env := newEnv(t)
	if env.Mounts == nil || env.Mount == nil {
		t.Skip("no Mounts or Mount hook")
	}
	return env
}

func watchMounts(t *testing.T, m platform.Mounts) (func() bool, func()) {
	t.Helper()
	changed, stop, err := m.WatchMounts()
	if err != nil {
		t.Fatalf("WatchMounts: %v", err)
	}
	t.Cleanup(stop)
	return changed, stop
}

func mountsGroup(t *testing.T, newEnv func(t *testing.T) Env) {
	// A volume mounted and unmounted during a watch is seen by every watch
	// on, and stays seen.
	t.Run("a mount is seen by every watch and stays seen", func(t *testing.T) {
		env := needMounts(t, newEnv)
		a, _ := watchMounts(t, env.Mounts)
		b, _ := watchMounts(t, env.Mounts)
		env.Mount(t)
		if !a() || !b() {
			t.Fatal("a volume mounted and unmounted during the watch was not seen")
		}
		if !a() {
			t.Fatal("changed forgot the mount on its second call")
		}
	})
	// Nothing but a mount counts: a mount before the watch began, files
	// written, renamed and removed, a process started and ended. (A volume
	// the system mounts meanwhile fails this too: run again.)
	t.Run("nothing else is a mount", func(t *testing.T) {
		env := needMounts(t, newEnv)
		env.Mount(t)
		changed, _ := watchMounts(t, env.Mounts)
		dir := t.TempDir()
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(p, p+"2"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
			t.Fatal(err)
		}
		os.RemoveAll(dir)
		if env.Spawn != nil && env.Exit != nil {
			env.Exit(env.Spawn())
		}
		if changed() {
			t.Fatal("a watch reported a mount although none happened during it")
		}
	})
	// Fail closed: a stopped watch reports a change; stop twice is harmless.
	t.Run("a stopped watch reports a change", func(t *testing.T) {
		env := needMounts(t, newEnv)
		changed, stop := watchMounts(t, env.Mounts)
		stop()
		stop()
		if !changed() {
			t.Fatal("changed after stop must be true")
		}
	})
}

// ---- pipes (platform.Pipes) ------------------------------------------------

func needPipes(t *testing.T, newEnv func(t *testing.T) Env) Env {
	t.Helper()
	env := newEnv(t)
	if env.Pipes == nil || env.Stdout == nil {
		t.Skip("no Pipes or Stdout hook")
	}
	return env
}

// stdoutCase sets up c and checks the hook's own claim that writer is
// reader's child (but for StdoutGone, whose writer is gone).
func stdoutCase(t *testing.T, env Env, c StdoutCase) (writer, reader platform.ProcessRef) {
	t.Helper()
	writer, reader = env.Stdout(t, c)
	if writer.IsPIDOnly() || reader.IsPIDOnly() || writer.IsZero() || reader.IsZero() {
		t.Fatalf("Stdout(%s) = %v, %v: want full refs", c, writer, reader)
	}
	if c != StdoutGone {
		info, err := env.P.Process(writer)
		if err != nil || info.Parent.PID != reader.PID {
			t.Fatalf("Stdout(%s): writer %v is not reader %v's child (%+v, %v)", c, writer, reader, info.Parent, err)
		}
	}
	return writer, reader
}

func pipesGroup(t *testing.T, newEnv func(t *testing.T) Env) {
	// The one yes: a pipe whose read end the parent holds, asked twice.
	t.Run("piped", func(t *testing.T) {
		env := needPipes(t, newEnv)
		w, r := stdoutCase(t, env, StdoutPiped)
		for i := range 2 {
			if ok, err := env.Pipes.StdoutReadBy(w, r); !ok || err != nil {
				t.Fatalf("StdoutReadBy of a pipe the parent reads (call %d) = %v, %v; want true", i+1, ok, err)
			}
		}
	})
	// Every other fd 1 is a plain no: the pipe is matched by identity, not
	// by "fd 1 is some pipe" or "the parent holds some pipe's read end",
	// a read end someone else holds as well is no pipe to the reader
	// alone, a write end someone else holds as well is no pipe from the
	// writer alone, one the reader inherited is no pipe it opened, and a
	// socket, a terminal or the wrong end is no pipe to it.
	for _, c := range []StdoutCase{StdoutPipedElsewhere, StdoutSharedReadEnd, StdoutSharedWriteEnd, StdoutInheritedReadEnd, StdoutRelayed, StdoutFile, StdoutTerminal, StdoutSocket, StdoutReadEnd, StdoutClosed} {
		t.Run(string(c), func(t *testing.T) {
			env := needPipes(t, newEnv)
			w, r := stdoutCase(t, env, c)
			if ok, err := env.Pipes.StdoutReadBy(w, r); ok || err != nil {
				t.Fatalf("StdoutReadBy with fd 1 %s = %v, %v; want false and no error", c, ok, err)
			}
		})
	}
	// A writer that has exited is ErrNoProcess, never an answer.
	t.Run("gone", func(t *testing.T) {
		env := needPipes(t, newEnv)
		w, r := stdoutCase(t, env, StdoutGone)
		if ok, err := env.Pipes.StdoutReadBy(w, r); ok || !errors.Is(err, platform.ErrNoProcess) {
			t.Fatalf("StdoutReadBy of an exited writer = %v, %v; want ErrNoProcess", ok, err)
		}
	})
	// Only the live instances the full refs name are asked about: a stale
	// generation, a PID-only ref or the zero ref of either side is
	// ErrNoProcess, and the question is not symmetric.
	t.Run("refs", func(t *testing.T) {
		env := needPipes(t, newEnv)
		w, r := stdoutCase(t, env, StdoutPiped)
		stale := func(ref platform.ProcessRef) platform.ProcessRef {
			return platform.ProcessRef{PID: ref.PID, Generation: ref.Generation + 1}
		}
		for name, refs := range map[string][2]platform.ProcessRef{
			"writer's generation tampered": {stale(w), r},
			"reader's generation tampered": {w, stale(r)},
			"writer PID-only":              {{PID: w.PID}, r},
			"reader PID-only":              {w, {PID: r.PID}},
			"zero writer":                  {{}, r},
			"zero reader":                  {w, {}},
		} {
			if ok, err := env.Pipes.StdoutReadBy(refs[0], refs[1]); ok || !errors.Is(err, platform.ErrNoProcess) {
				t.Errorf("StdoutReadBy(%s) = %v, %v; want ErrNoProcess", name, ok, err)
			}
		}
		if ok, err := env.Pipes.StdoutReadBy(r, w); ok || err != nil {
			t.Errorf("StdoutReadBy(reader, writer) = %v, %v; want false and no error", ok, err)
		}
		// The refusals left the true answer as it was.
		if ok, err := env.Pipes.StdoutReadBy(w, r); !ok || err != nil {
			t.Fatalf("StdoutReadBy after the refusals = %v, %v; want true", ok, err)
		}
	})
}
