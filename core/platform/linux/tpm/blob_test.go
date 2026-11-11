//go:build linux

package tpm

import (
	"bytes"
	"testing"

	"github.com/atas/nazar/core/platform"
)

func TestBlobRoundTrip(t *testing.T) {
	in := blob{
		purpose: platform.PurposeKeyAgreement,
		auth:    platform.AuthUserPresence,
		access:  platform.AccessWhenUnlocked,
		public:  []byte("public part"),
		private: bytes.Repeat([]byte{0xab}, 300),
	}
	b := in.encode()
	out, err := decodeBlob(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.purpose != in.purpose || out.auth != in.auth || out.access != in.access ||
		!bytes.Equal(out.public, in.public) || !bytes.Equal(out.private, in.private) {
		t.Fatalf("round trip gave %+v, want %+v", out, in)
	}
	if b[0] != blobVersion {
		t.Fatalf("blob starts with %d, want version %d", b[0], blobVersion)
	}
}

// A corrupt or foreign item is an error, never a key with weaker
// protection or a key of another purpose.
func TestBlobRefusesCorrupt(t *testing.T) {
	good := blob{
		purpose: platform.PurposeSign, auth: platform.AuthNone, access: platform.AccessWhenUnlocked,
		public: []byte("pub"), private: []byte("priv"),
	}.encode()
	cases := map[string][]byte{
		"empty":           {},
		"version only":    good[:1],
		"header only":     good[:4],
		"truncated":       good[:len(good)-1],
		"trailing byte":   append(append([]byte(nil), good...), 0),
		"other version":   append([]byte{2}, good[1:]...),
		"purpose 0":       append([]byte{good[0], 0}, good[2:]...),
		"purpose 3":       append([]byte{good[0], 3}, good[2:]...),
		"auth 2":          append(append(append([]byte(nil), good[:2]...), 2), good[3:]...),
		"access 2":        append(append(append([]byte(nil), good[:3]...), 2), good[4:]...),
		"presence+after":  blob{purpose: platform.PurposeSign, auth: platform.AuthUserPresence, access: platform.AccessAfterFirstUnlock, public: []byte("p"), private: []byte("q")}.encode(),
		"public too long": append(append([]byte(nil), good[:4]...), 0xff, 0xff),
		"empty public":    blob{purpose: platform.PurposeSign, private: []byte("q")}.encode(),
		"empty private":   blob{purpose: platform.PurposeSign, public: []byte("p")}.encode(),
	}
	for name, b := range cases {
		if out, err := decodeBlob(b); err == nil {
			t.Errorf("%s: decoded to %+v, want an error", name, out)
		}
	}
	if _, err := decodeBlob(good); err != nil {
		t.Fatalf("the good blob does not decode: %v", err)
	}
}
