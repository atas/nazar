//go:build linux && linuxplatform

// The TPM keys against a software TPM (swtpm) in the Linux test image: a
// fresh TPM per test, the in-memory fake vault, and the lock and approval
// seams as plain functions the test controls. Nothing here opens /dev/tpm0
// or /dev/tpmrm0 (container.Require refuses to run anywhere else).
package tpm

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/swtpm"
)

func TestMain(m *testing.M) { os.Exit(container.Require(m)) }

// The methods Keys gives the Linux Platform: the key part of
// platform.Platform, with the same signatures.
var _ interface {
	CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error)
	Sign(handle, digestInput []byte, approval platform.ApprovalRef) ([]byte, error)
	KeyAgreement(handle, peerPublicKey []byte, approval platform.ApprovalRef) ([]byte, error)
	DeleteKey(handle []byte) error
} = (*Keys)(nil)

// seams is what the test controls: the lock state the Keys ask about and
// the approvals they accept.
type seams struct {
	mu        sync.Mutex
	locked    bool
	lockedErr error
	approved  map[platform.ApprovalRef]bool
}

func (s *seams) isLocked() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked, s.lockedErr
}

func (s *seams) isApproved(ref platform.ApprovalRef) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.approved[ref]
}

func (s *seams) setLocked(on bool, err error) {
	s.mu.Lock()
	s.locked, s.lockedErr = on, err
	s.mu.Unlock()
}

func (s *seams) approve(ref platform.ApprovalRef) {
	s.mu.Lock()
	s.approved[ref] = true
	s.mu.Unlock()
}

type env struct {
	socket string
	vault  *fake.Vault
	seams  *seams
	keys   *Keys
}

// start runs a fresh swtpm and opens Keys on it with an empty vault.
func start(t *testing.T) *env {
	t.Helper()
	e := &env{socket: swtpm.Start(t), vault: fake.NewVault(), seams: &seams{approved: map[platform.ApprovalRef]bool{}}}
	e.keys = e.open(t)
	return e
}

// open opens Keys on the environment's TPM and vault; Close at cleanup.
func (e *env) open(t *testing.T) *Keys {
	t.Helper()
	tr, err := linuxudstpm.Open(e.socket)
	if err != nil {
		t.Fatalf("open swtpm: %v", err)
	}
	k, err := Open(tr, e.vault, e.seams.isLocked, e.seams.isApproved)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { k.Close() })
	return k
}

func create(t *testing.T, k *Keys, purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	handle, pub, err := k.CreateKey(purpose, auth, access)
	if err != nil {
		t.Fatalf("CreateKey(%v, %v, %v): %v", purpose, auth, access, err)
	}
	return handle, pubKey(t, pub)
}

func pubKey(t *testing.T, b []byte) *ecdsa.PublicKey {
	t.Helper()
	if len(b) != 65 || b[0] != 4 {
		t.Fatalf("public key is %d bytes starting %x; want 65 bytes starting 04", len(b), b[:min(1, len(b))])
	}
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		t.Fatalf("public key is not a P-256 point: %v", err)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(b[1:33]), Y: new(big.Int).SetBytes(b[33:65])}
}

func verify(t *testing.T, pub *ecdsa.PublicKey, msg, sig []byte) {
	t.Helper()
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatalf("signature %x does not verify over SHA-256(%q)", sig, msg)
	}
}

func p256Point(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv.PublicKey().Bytes()
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerifies(t *testing.T) {
	e := start(t)
	handle, pub := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	msg := []byte("tpm: sign me")
	sig, err := e.keys.Sign(handle, msg, 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verify(t, pub, msg, sig)
	if sum := sha256.Sum256([]byte("another message")); ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatal("signature verified for a different message")
	}
	// An AuthNone key ignores the approval argument, whatever it is.
	sig, err = e.keys.Sign(handle, msg, platform.ApprovalRef(0x5eed1234abcd))
	if err != nil {
		t.Fatalf("Sign with an arbitrary ref on an AuthNone key: %v", err)
	}
	verify(t, pub, msg, sig)
	// Two signatures of one message differ (a fresh nonce each time) and
	// both verify.
	again, err := e.keys.Sign(handle, msg, 0)
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}
	verify(t, pub, msg, again)
	if bytes.Equal(sig, again) {
		t.Fatal("two ECDSA signatures of one message are identical")
	}
	// A long message (x509 hands Sign a TBS of a few hundred bytes) and an
	// empty one both sign.
	for _, m := range [][]byte{randomBytes(t, 700), {}} {
		sig, err := e.keys.Sign(handle, m, 0)
		if err != nil {
			t.Fatalf("Sign(%d bytes): %v", len(m), err)
		}
		verify(t, pub, m, sig)
	}
}

func TestKeyAgreementMatchesECDH(t *testing.T) {
	e := start(t)
	handle, pub := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessAfterFirstUnlock)
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.keys.KeyAgreement(handle, local.PublicKey().Bytes(), 0)
	if err != nil {
		t.Fatalf("KeyAgreement: %v", err)
	}
	remote, err := pub.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	want, err := local.ECDH(remote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("shared secret %x, want %x (local ECDH)", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("shared secret is %d bytes, want 32", len(got))
	}
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 4
	for name, peer := range map[string][]byte{
		"nil": nil, "empty": {}, "prefix only": {4}, "truncated": local.PublicKey().Bytes()[:40],
		"not on curve": notOnCurve, "compressed": append([]byte{2}, local.PublicKey().Bytes()[1:33]...),
		"too long": append(local.PublicKey().Bytes(), 0),
	} {
		if out, err := e.keys.KeyAgreement(handle, peer, 0); err == nil || out != nil {
			t.Errorf("KeyAgreement(%s peer key) = %x, %v; want an error", name, out, err)
		}
	}
}

func TestHandleShape(t *testing.T) {
	e := start(t)
	handle, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if len(handle) != 20 {
		t.Fatalf("handle is %d bytes, want 20", len(handle))
	}
	if string(handle[:4]) != "nzt1" {
		t.Fatalf("handle starts %q, want nzt1", handle[:4])
	}
	names, err := e.vault.List(VaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	want := VaultPrefix + hex.EncodeToString(handle[4:])
	if len(names) != 1 || names[0] != want {
		t.Fatalf("vault items under %q = %q, want [%q]", VaultPrefix, names, want)
	}
	// Two keys never share a handle or an item.
	other, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if bytes.Equal(handle, other) {
		t.Fatal("two keys got the same handle")
	}
	if names, _ := e.vault.List(VaultPrefix); len(names) != 2 {
		t.Fatalf("two keys made %d vault items", len(names))
	}
	// The vault holds no private key material: the TPM-wrapped private
	// part only, which the TPM alone can open.
	item, err := e.vault.Get(want)
	if err != nil {
		t.Fatal(err)
	}
	b, err := decodeBlob(item)
	if err != nil {
		t.Fatalf("the vault item does not decode: %v", err)
	}
	if b.purpose != platform.PurposeSign || b.auth != platform.AuthNone || b.access != platform.AccessAfterFirstUnlock {
		t.Fatalf("blob records %v/%v/%v", b.purpose, b.auth, b.access)
	}
}

func TestDeleteForgets(t *testing.T) {
	e := start(t)
	handle, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if err := e.keys.DeleteKey(handle); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if sig, err := e.keys.Sign(handle, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) || sig != nil {
		t.Fatalf("Sign after DeleteKey = %x, %v; want ErrNotFound", sig, err)
	}
	if err := e.keys.DeleteKey(handle); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("second DeleteKey = %v, want ErrNotFound", err)
	}
	if names, _ := e.vault.List(VaultPrefix); len(names) != 0 {
		t.Fatalf("vault still holds %q after DeleteKey", names)
	}
	// Handles that were never issued, of every shape.
	unissued := append([]byte("nzt1"), randomBytes(t, 16)...)
	for name, h := range map[string][]byte{
		"nil": nil, "empty": {}, "random": randomBytes(t, 32), "short": {1, 2, 3},
		"right shape, never issued": unissued, "prefix only": []byte("nzt1"),
		"wrong prefix": append([]byte("nzt2"), handle[4:]...), "one byte long": append(append([]byte(nil), handle...), 0),
	} {
		if _, err := e.keys.Sign(h, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("Sign(%s handle) = %v, want ErrNotFound", name, err)
		}
		if _, err := e.keys.KeyAgreement(h, p256Point(t), 0); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("KeyAgreement(%s handle) = %v, want ErrNotFound", name, err)
		}
		if err := e.keys.DeleteKey(h); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("DeleteKey(%s handle) = %v, want ErrNotFound", name, err)
		}
	}
}

func TestPurposeEnforced(t *testing.T) {
	e := start(t)
	signH, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	kaH, _ := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if out, err := e.keys.KeyAgreement(signH, p256Point(t), 0); err == nil || out != nil {
		t.Errorf("KeyAgreement with a signing key = %x, %v; want an error", out, err)
	}
	if out, err := e.keys.Sign(kaH, []byte("x"), 0); err == nil || out != nil {
		t.Errorf("Sign with a key-agreement key = %x, %v; want an error", out, err)
	}
	// Neither mistake is "not found": the key exists, for something else.
	if _, err := e.keys.KeyAgreement(signH, p256Point(t), 0); errors.Is(err, platform.ErrNotFound) {
		t.Errorf("KeyAgreement with a signing key = %v; want a purpose error, not ErrNotFound", err)
	}
}

func TestOutOfRangeRefused(t *testing.T) {
	e := start(t)
	for _, purpose := range []platform.Purpose{0, 3, -1, math.MaxInt32} {
		if h, pub, err := e.keys.CreateKey(purpose, platform.AuthNone, platform.AccessAfterFirstUnlock); err == nil || h != nil || pub != nil {
			t.Errorf("CreateKey(%v, none) = %x, %x, %v; want a refusal", purpose, h, pub, err)
		}
	}
	for _, auth := range []platform.AuthPolicy{2, -1, math.MaxInt32} {
		if h, pub, err := e.keys.CreateKey(platform.PurposeSign, auth, platform.AccessAfterFirstUnlock); err == nil || h != nil || pub != nil {
			t.Errorf("CreateKey(sign, %v) = %x, %x, %v; want a refusal", auth, h, pub, err)
		}
	}
	for _, access := range []platform.Access{2, -1, math.MaxInt32} {
		if h, pub, err := e.keys.CreateKey(platform.PurposeSign, platform.AuthNone, access); err == nil || h != nil || pub != nil {
			t.Errorf("CreateKey(sign, none, %v) = %x, %x, %v; want a refusal", access, h, pub, err)
		}
	}
	for _, purpose := range []platform.Purpose{platform.PurposeSign, platform.PurposeKeyAgreement} {
		if h, pub, err := e.keys.CreateKey(purpose, platform.AuthUserPresence, platform.AccessAfterFirstUnlock); err == nil || h != nil || pub != nil {
			t.Errorf("CreateKey(%v, user-presence, after-first-unlock) = %x, %x, %v; want a refusal", purpose, h, pub, err)
		}
	}
	// A refusal makes nothing: no vault item.
	if names, _ := e.vault.List(VaultPrefix); len(names) != 0 {
		t.Fatalf("refused CreateKey calls left vault items %q", names)
	}
}

func TestUserPresenceNeedsApproval(t *testing.T) {
	e := start(t)
	signH, pub := create(t, e.keys, platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	kaH, _ := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	for name, ref := range map[string]platform.ApprovalRef{"zero": 0, "forged": 0x1234567, "max": math.MaxUint64} {
		if sig, err := e.keys.Sign(signH, []byte("x"), ref); !errors.Is(err, platform.ErrAuthRequired) || sig != nil {
			t.Errorf("Sign(user-presence key, %s ref) = %x, %v; want ErrAuthRequired", name, sig, err)
		}
		if out, err := e.keys.KeyAgreement(kaH, p256Point(t), ref); !errors.Is(err, platform.ErrAuthRequired) || out != nil {
			t.Errorf("KeyAgreement(user-presence key, %s ref) = %x, %v; want ErrAuthRequired", name, out, err)
		}
	}
	e.seams.approve(7)
	sig, err := e.keys.Sign(signH, []byte("x"), 7)
	if err != nil {
		t.Fatalf("Sign with an approved ref: %v", err)
	}
	verify(t, pub, []byte("x"), sig)
	if out, err := e.keys.KeyAgreement(kaH, p256Point(t), 7); err != nil || len(out) != 32 {
		t.Fatalf("KeyAgreement with an approved ref = %x, %v", out, err)
	}
	// The approval is asked about per use: the ref next to it is nothing.
	if _, err := e.keys.Sign(signH, []byte("x"), 8); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("Sign with the ref next to an approved one = %v; want ErrAuthRequired", err)
	}
}

func TestLockedRefusesWhenUnlockedKeys(t *testing.T) {
	e := start(t)
	whenUnlocked, pubWU := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	kaWhenUnlocked, _ := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessWhenUnlocked)
	afterFirst, pubAF := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)

	for _, c := range []struct {
		name   string
		locked bool
		err    error
	}{
		{"locked", true, nil},
		{"lock state unknown", false, errors.New("logind is gone")},
	} {
		e.seams.setLocked(c.locked, c.err)
		if h, pub, err := e.keys.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked); !errors.Is(err, platform.ErrLocked) || h != nil || pub != nil {
			t.Errorf("%s: CreateKey(when-unlocked) = %x, %x, %v; want ErrLocked", c.name, h, pub, err)
		} else if err.Error() == platform.ErrLocked.Error() {
			t.Errorf("%s: CreateKey(when-unlocked) is the bare Mac-worded ErrLocked %q", c.name, err)
		}
		if sig, err := e.keys.Sign(whenUnlocked, []byte("x"), 0); !errors.Is(err, platform.ErrLocked) || sig != nil {
			t.Errorf("%s: Sign(when-unlocked key) = %x, %v; want ErrLocked", c.name, sig, err)
		}
		if out, err := e.keys.KeyAgreement(kaWhenUnlocked, p256Point(t), 0); !errors.Is(err, platform.ErrLocked) || out != nil {
			t.Errorf("%s: KeyAgreement(when-unlocked key) = %x, %v; want ErrLocked", c.name, out, err)
		}
		// An after-first-unlock key is not affected, made or used.
		sig, err := e.keys.Sign(afterFirst, []byte("x"), 0)
		if err != nil {
			t.Fatalf("%s: Sign(after-first-unlock key): %v", c.name, err)
		}
		verify(t, pubAF, []byte("x"), sig)
		h, _, err := e.keys.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
		if err != nil {
			t.Fatalf("%s: CreateKey(after-first-unlock): %v", c.name, err)
		}
		if err := e.keys.DeleteKey(h); err != nil {
			t.Fatal(err)
		}
	}

	// Unlocked again: the when-unlocked key works, and the lock never
	// deleted anything.
	e.seams.setLocked(false, nil)
	sig, err := e.keys.Sign(whenUnlocked, []byte("x"), 0)
	if err != nil {
		t.Fatalf("Sign(when-unlocked key) after unlock: %v", err)
	}
	verify(t, pubWU, []byte("x"), sig)
	if names, _ := e.vault.List(VaultPrefix); len(names) != 3 {
		t.Fatalf("vault holds %d items, want the 3 keys", len(names))
	}
}

func TestKeysSurviveReopen(t *testing.T) {
	e := start(t)
	signH, pub := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	kaH, kaPub := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if err := e.keys.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := e.keys.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Closed Keys refuse to work rather than touch a closed transport.
	if _, err := e.keys.Sign(signH, []byte("x"), 0); err == nil {
		t.Fatal("Sign on closed Keys succeeded")
	}

	k := e.open(t)
	sig, err := k.Sign(signH, []byte("after reopen"), 0)
	if err != nil {
		t.Fatalf("Sign after reopen: %v", err)
	}
	verify(t, pub, []byte("after reopen"), sig)

	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.KeyAgreement(kaH, local.PublicKey().Bytes(), 0)
	if err != nil {
		t.Fatalf("KeyAgreement after reopen: %v", err)
	}
	remote, err := kaPub.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	want, err := local.ECDH(remote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("shared secret after reopen %x, want %x", got, want)
	}

	// Another vault: the blobs are what name the keys, so without them the
	// same TPM knows nothing.
	tr, err := linuxudstpm.Open(e.socket)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Open(tr, fake.NewVault(), e.seams.isLocked, e.seams.isApproved)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if _, err := empty.Sign(signH, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("Sign with an empty vault = %v, want ErrNotFound", err)
	}
}

func TestNotExportable(t *testing.T) {
	e := start(t)
	for _, purpose := range []platform.Purpose{platform.PurposeSign, platform.PurposeKeyAgreement} {
		handle, _ := create(t, e.keys, purpose, platform.AuthNone, platform.AccessAfterFirstUnlock)
		err := e.keys.withLoaded(handle, func(tr transport.TPM, obj tpm2.NamedHandle) error {
			rsp, err := tpm2.ReadPublic{ObjectHandle: obj}.Execute(tr)
			if err != nil {
				return err
			}
			pub, err := rsp.OutPublic.Contents()
			if err != nil {
				return err
			}
			a := pub.ObjectAttributes
			if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
				t.Errorf("%v key attributes: fixedTPM=%v fixedParent=%v sensitiveDataOrigin=%v; want all set", purpose, a.FixedTPM, a.FixedParent, a.SensitiveDataOrigin)
			}
			if !a.NoDA || !a.UserWithAuth {
				t.Errorf("%v key attributes: noDA=%v userWithAuth=%v; want both set", purpose, a.NoDA, a.UserWithAuth)
			}
			if a.Restricted {
				t.Errorf("%v key is restricted", purpose)
			}
			if purpose == platform.PurposeSign && (!a.SignEncrypt || a.Decrypt) {
				t.Errorf("sign key attributes: sign=%v decrypt=%v; want sign only", a.SignEncrypt, a.Decrypt)
			}
			if purpose == platform.PurposeKeyAgreement && (a.SignEncrypt || !a.Decrypt) {
				t.Errorf("key-agreement key attributes: sign=%v decrypt=%v; want decrypt only", a.SignEncrypt, a.Decrypt)
			}
			if pub.NameAlg != tpm2.TPMAlgSHA256 || pub.Type != tpm2.TPMAlgECC {
				t.Errorf("%v key: type %v, nameAlg %v", purpose, pub.Type, pub.NameAlg)
			}
			parms, err := pub.Parameters.ECCDetail()
			if err != nil {
				return err
			}
			if parms.CurveID != tpm2.TPMECCNistP256 {
				t.Errorf("%v key curve %v, want NIST P-256", purpose, parms.CurveID)
			}
			// Duplication is refused by the TPM: fixedParent keys have no
			// new parent to go to.
			dup, err := tpm2.Duplicate{
				ObjectHandle:    tpm2.AuthHandle{Handle: obj.Handle, Name: obj.Name, Auth: tpm2.PasswordAuth(nil)},
				NewParentHandle: e.keys.srk,
				Symmetric:       tpm2.TPMTSymDef{Algorithm: tpm2.TPMAlgNull},
			}.Execute(tr)
			if err == nil {
				t.Errorf("Duplicate of a %v key succeeded: %d bytes", purpose, len(dup.Duplicate.Buffer))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%v key: %v", purpose, err)
		}
	}
}

// transientHandles lists the TPM's loaded transient objects through its own
// connection to the swtpm socket, so the count is the TPM's, not ours.
func transientHandles(t *testing.T, socket string) []tpm2.TPMHandle {
	t.Helper()
	tr, err := linuxudstpm.Open(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 64,
	}.Execute(tr)
	if err != nil {
		t.Fatalf("GetCapability(handles): %v", err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatal(err)
	}
	return handles.Handle
}

func TestNoTransientLeak(t *testing.T) {
	e := start(t)
	if got := transientHandles(t, e.socket); len(got) != 1 || got[0] != e.keys.srk.Handle {
		t.Fatalf("after Open the TPM holds transient handles %v, want only the SRK %v", got, e.keys.srk.Handle)
	}
	signH, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	kaH, _ := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessAfterFirstUnlock)
	upH, _ := create(t, e.keys, platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	wuH, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	deleted, _ := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	if err := e.keys.DeleteKey(deleted); err != nil {
		t.Fatal(err)
	}
	// Mixed operations, most of them failing after the key is loaded or
	// before: each must flush what it loaded.
	ops := []func() error{
		func() error { _, err := e.keys.Sign(signH, []byte("x"), 0); return err },
		func() error { _, err := e.keys.KeyAgreement(kaH, p256Point(t), 0); return err },
		func() error { _, err := e.keys.KeyAgreement(signH, p256Point(t), 0); return err },  // wrong purpose
		func() error { _, err := e.keys.Sign(kaH, []byte("x"), 0); return err },             // wrong purpose
		func() error { _, err := e.keys.KeyAgreement(kaH, []byte{4, 1, 2}, 0); return err }, // malformed peer
		func() error { _, err := e.keys.Sign(upH, []byte("x"), 0); return err },             // no approval
		func() error { _, err := e.keys.Sign(deleted, []byte("x"), 0); return err },         // deleted
		func() error { _, err := e.keys.Sign(randomBytes(t, 20), []byte("x"), 0); return err },
		func() error {
			e.seams.setLocked(true, nil)
			defer e.seams.setLocked(false, nil)
			_, err := e.keys.Sign(wuH, []byte("x"), 0)
			return err
		},
		func() error {
			h, _, err := e.keys.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
			if err != nil {
				return err
			}
			return e.keys.DeleteKey(h)
		},
	}
	for i := 0; i < 50; i++ {
		_ = ops[i%len(ops)]()
	}
	if got := transientHandles(t, e.socket); len(got) != 1 || got[0] != e.keys.srk.Handle {
		t.Fatalf("after 50 operations the TPM holds transient handles %v, want only the SRK %v", got, e.keys.srk.Handle)
	}
	// Close flushes the SRK too.
	if err := e.keys.Close(); err != nil {
		t.Fatal(err)
	}
	if got := transientHandles(t, e.socket); len(got) != 0 {
		t.Fatalf("after Close the TPM holds transient handles %v, want none", got)
	}
}

// TestConcurrentUse: the one mutex serialises TPM commands, so parallel
// callers never overflow the TPM's few transient slots or interleave a
// load with another's flush.
func TestConcurrentUse(t *testing.T) {
	e := start(t)
	signH, pub := create(t, e.keys, platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
	kaH, _ := create(t, e.keys, platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessAfterFirstUnlock)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte{byte(i)}
			sig, err := e.keys.Sign(signH, msg, 0)
			if err != nil {
				errs <- err
				return
			}
			if sum := sha256.Sum256(msg); !ecdsa.VerifyASN1(pub, sum[:], sig) {
				errs <- errors.New("a concurrent signature does not verify")
			}
			if out, err := e.keys.KeyAgreement(kaH, p256Point(t), 0); err != nil || len(out) != 32 {
				errs <- errors.New("a concurrent key agreement failed")
			}
			h, _, err := e.keys.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessAfterFirstUnlock)
			if err != nil {
				errs <- err
				return
			}
			if err := e.keys.DeleteKey(h); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := transientHandles(t, e.socket); len(got) != 1 {
		t.Fatalf("after concurrent use the TPM holds transient handles %v, want only the SRK", got)
	}
}
