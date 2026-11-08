package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// localKey is a software recipient: what Platform.KeyAgreement does in the
// Secure Enclave, done with crypto/ecdh, counting the agreements asked for.
type localKey struct {
	priv  *ecdh.PrivateKey
	peers [][]byte
}

func newLocal(t *testing.T) *localKey {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &localKey{priv: k}
}

func (k *localKey) pub() []byte { return k.priv.PublicKey().Bytes() }

func (k *localKey) agree(peer []byte) ([]byte, error) {
	k.peers = append(k.peers, append([]byte(nil), peer...))
	p, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(p)
}

// RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
// AES-128-GCM, base mode, encryption sequence number 0. The recipient's
// ECDH goes through an Agree function, as the enclave's does: this checks
// nazar's adapter, not crypto/hpke (whose own tests run every vector).
func TestOpenRFC9180A31ThroughAgree(t *testing.T) {
	sk, err := ecdh.P256().NewPrivateKey(unhex(t, "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"))
	if err != nil {
		t.Fatal(err)
	}
	k := &localKey{priv: sk}
	pkR := unhex(t, "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
	if !bytes.Equal(k.pub(), pkR) {
		t.Fatalf("skRm does not give pkRm: %x", k.pub())
	}
	enc := unhex(t, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
	rfcInfo := unhex(t, "4f6465206f6e2061204772656369616e2055726e") // "Ode on a Grecian Urn"
	aad := unhex(t, "436f756e742d30")                               // "Count-0"
	ct := unhex(t, "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434")
	want := unhex(t, "4265617574792069732074727574682c20747275746820626561757479") // "Beauty is truth, truth beauty"

	got, err := open(pkR, k.agree, hpke.AES128GCM(), rfcInfo, aad, enc, ct)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("open(RFC 9180 A.3.1 #0) = %q, %v; want %q", got, err, want)
	}
	if len(k.peers) != 1 || !bytes.Equal(k.peers[0], enc) {
		t.Fatalf("the key agreement must be asked once, with enc as the peer: %d calls", len(k.peers))
	}
	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 1
		if out, err := open(pkR, k.agree, hpke.AES128GCM(), rfcInfo, aad, enc, bad); !errors.Is(err, ErrOpen) || out != nil {
			t.Fatalf("ciphertext with byte %d flipped = %q, %v; want ErrOpen", i, out, err)
		}
	}
	if out, err := open(pkR, k.agree, hpke.AES128GCM(), rfcInfo, []byte("Count-1"), enc, ct); !errors.Is(err, ErrOpen) || out != nil {
		t.Fatalf("another aad = %q, %v; want ErrOpen", out, err)
	}
}

// The wire format is plain RFC 9180 with nazar's suite and info string:
// any HPKE implementation given kem 0x0010, kdf 0x0001, aead 0x0002 and
// info "nazar/v1 secret\x00<name>" opens what Seal writes, and Open opens
// what it seals.
func TestSuiteAndInfoAreTheWireFormat(t *testing.T) {
	kem, err := hpke.NewKEM(0x0010)
	if err != nil {
		t.Fatal(err)
	}
	kdf, err := hpke.NewKDF(0x0001)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := hpke.NewAEAD(0x0002)
	if err != nil {
		t.Fatal(err)
	}
	k := newLocal(t)
	priv, err := kem.NewPrivateKey(k.priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("nazar/v1 secret\x00GITHUB_TOKEN")
	value := []byte("ghp_example\x00\xff\n")

	enc, ct, err := Seal(k.pub(), "GITHUB_TOKEN", value)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 65 || enc[0] != 4 || len(ct) != len(value)+16 {
		t.Fatalf("enc %d bytes (first %#x), ct %d bytes; want 65 (0x04) and %d", len(enc), enc[0], len(ct), len(value)+16)
	}
	r, err := hpke.NewRecipient(enc, priv, kdf, aead, info)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Open(nil, ct); err != nil || !bytes.Equal(got, value) {
		t.Fatalf("crypto/hpke could not open Seal's output: %v", err)
	}

	pk, err := kem.NewPublicKey(k.pub())
	if err != nil {
		t.Fatal(err)
	}
	enc2, s, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := s.Seal(nil, value)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(k.pub(), k.agree, "GITHUB_TOKEN", enc2, ct2); err != nil || !bytes.Equal(got, value) {
		t.Fatalf("Open could not open crypto/hpke's output: %v", err)
	}
}

func TestOpenRefusesOtherNamesKeysAndDamage(t *testing.T) {
	k, other := newLocal(t), newLocal(t)
	enc, ct, err := Seal(k.pub(), "A", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(k.pub(), k.agree, "A", enc, ct); err != nil || string(got) != "value" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	for name, try := range map[string]func() ([]byte, error){
		"another name":                    func() ([]byte, error) { return Open(k.pub(), k.agree, "B", enc, ct) },
		"a name differing in case":        func() ([]byte, error) { return Open(k.pub(), k.agree, "a", enc, ct) },
		"another key's agreement":         func() ([]byte, error) { return Open(k.pub(), other.agree, "A", enc, ct) },
		"another key with its own public": func() ([]byte, error) { return Open(other.pub(), other.agree, "A", enc, ct) },
		"empty ciphertext":                func() ([]byte, error) { return Open(k.pub(), k.agree, "A", enc, nil) },
		"tag only":                        func() ([]byte, error) { return Open(k.pub(), k.agree, "A", enc, ct[len(ct)-16:]) },
		"truncated ciphertext":            func() ([]byte, error) { return Open(k.pub(), k.agree, "A", enc, ct[:len(ct)-1]) },
	} {
		if got, err := try(); !errors.Is(err, ErrOpen) || got != nil {
			t.Errorf("%s: Open = %q, %v; want ErrOpen", name, got, err)
		}
	}
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 4
	asked := len(k.peers)
	for name, e := range map[string][]byte{
		"nil": nil, "truncated": enc[:40], "compressed": append([]byte{2}, enc[1:33]...), "not on curve": notOnCurve,
	} {
		if got, err := Open(k.pub(), k.agree, "A", e, ct); !errors.Is(err, ErrOpen) || got != nil {
			t.Errorf("%s enc: Open = %q, %v; want ErrOpen", name, got, err)
		}
	}
	if len(k.peers) != asked {
		t.Fatalf("a malformed enc reached the key agreement (%d calls)", len(k.peers)-asked)
	}
	enc2, ct2, err := Seal(k.pub(), "A", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, enc2) || bytes.Equal(ct, ct2) {
		t.Fatal("two seals of one value must use two ephemeral keys")
	}
}

func TestAgreeErrorsAreReturnedUnchanged(t *testing.T) {
	errAuth := errors.New("platform: key requires an authenticated approval")
	k := newLocal(t)
	enc, ct, err := Seal(k.pub(), "A", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(k.pub(), func([]byte) ([]byte, error) { return nil, errAuth }, "A", enc, ct)
	if !errors.Is(err, errAuth) || errors.Is(err, ErrOpen) || got != nil {
		t.Fatalf("Open with a refusing enclave = %q, %v; want the enclave's error itself", got, err)
	}
	for _, n := range []int{0, 31, 33, 65} {
		z := make([]byte, n)
		if got, err := Open(k.pub(), func([]byte) ([]byte, error) { return z, nil }, "A", enc, ct); err == nil || got != nil {
			t.Fatalf("an agreement of %d bytes = %q, %v; want an error", n, got, err)
		}
	}
}

func TestSealChecksValueAndKey(t *testing.T) {
	k := newLocal(t)
	for _, v := range [][]byte{nil, {}} {
		if _, _, err := Seal(k.pub(), "A", v); !errors.Is(err, ErrEmpty) {
			t.Fatalf("Seal(empty) = %v, want ErrEmpty", err)
		}
	}
	if _, _, err := Seal(k.pub(), "A", make([]byte, MaxValue+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Seal(MaxValue+1) = %v, want ErrTooLarge", err)
	}
	if Check(make([]byte, MaxValue)) != nil || Check([]byte{0}) != nil {
		t.Fatal("Check refused a value it must accept")
	}
	big := bytes.Repeat([]byte{0xff}, MaxValue)
	enc, ct, err := Seal(k.pub(), "A", big)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(k.pub(), k.agree, "A", enc, ct); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("a MaxValue secret did not round-trip: %v", err)
	}
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 4
	for name, pub := range map[string][]byte{
		"nil": nil, "compressed": append([]byte{2}, k.pub()[1:33]...), "not on curve": notOnCurve, "truncated": k.pub()[:64],
	} {
		if enc, ct, err := Seal(pub, "A", []byte("v")); err == nil || enc != nil || ct != nil {
			t.Errorf("Seal to a %s key = %x, %x, %v; want an error", name, enc, ct, err)
		}
		if got, err := Open(pub, k.agree, "A", enc, ct); err == nil || got != nil {
			t.Errorf("Open with a %s key = %q, %v; want an error", name, got, err)
		}
	}
}
