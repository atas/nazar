//go:build linux

package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/atas/nazar/core/platform"
)

// blobVersion is the first byte of every vault item this package writes.
const blobVersion = 1

// blob is one key as the vault holds it: nazar's record of what the key is
// for and how it is protected, and the two parts the TPM needs to load it.
// The private part is wrapped by the TPM to the SRK; no key material is in
// the clear anywhere in it.
//
// Encoding: version (1 byte), purpose, auth, access (1 byte each), then
// the TPMT_PUBLIC and the TPM2B_PRIVATE's buffer, each after a big-endian
// 2-byte length, and nothing else.
type blob struct {
	purpose platform.Purpose
	auth    platform.AuthPolicy
	access  platform.Access
	public  []byte
	private []byte
}

// errBlob is wrapped by every decode error: the item is there but not a
// key this package wrote, so it is never ErrNotFound (which would read as
// "deleted") and never a key with weaker protection.
var errBlob = errors.New("tpm: vault item is not a key record")

func (b blob) encode() []byte {
	out := make([]byte, 0, 4+2+len(b.public)+2+len(b.private))
	out = append(out, blobVersion, byte(b.purpose), byte(b.auth), byte(b.access))
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.public)))
	out = append(out, b.public...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.private)))
	out = append(out, b.private...)
	return out
}

// decodeBlob reads an item. Every field is checked: the version, the three
// enumerations against their defined values (and access against auth, as
// CreateKey checks them), both lengths against the item, and no trailing
// bytes. The slices it returns are copies.
func decodeBlob(item []byte) (blob, error) {
	if len(item) < 4 {
		return blob{}, fmt.Errorf("%w: %d bytes", errBlob, len(item))
	}
	if item[0] != blobVersion {
		return blob{}, fmt.Errorf("%w: version %d", errBlob, item[0])
	}
	b := blob{purpose: platform.Purpose(item[1]), auth: platform.AuthPolicy(item[2]), access: platform.Access(item[3])}
	if _, ok := keyTemplate(b.purpose); !ok {
		return blob{}, fmt.Errorf("%w: %v", errBlob, b.purpose)
	}
	if b.auth != platform.AuthNone && b.auth != platform.AuthUserPresence {
		return blob{}, fmt.Errorf("%w: %v", errBlob, b.auth)
	}
	if !b.access.Fits(b.auth) {
		return blob{}, fmt.Errorf("%w: %v with %v", errBlob, b.access, b.auth)
	}
	rest := item[4:]
	var err error
	if b.public, rest, err = cut(rest); err != nil {
		return blob{}, fmt.Errorf("%w: public part %v", errBlob, err)
	}
	if b.private, rest, err = cut(rest); err != nil {
		return blob{}, fmt.Errorf("%w: private part %v", errBlob, err)
	}
	if len(rest) != 0 {
		return blob{}, fmt.Errorf("%w: %d trailing bytes", errBlob, len(rest))
	}
	if len(b.public) == 0 || len(b.private) == 0 {
		return blob{}, fmt.Errorf("%w: an empty part", errBlob)
	}
	return b, nil
}

// cut takes one length-prefixed field off the front of in, copied.
func cut(in []byte) (field, rest []byte, err error) {
	if len(in) < 2 {
		return nil, nil, errors.New("has no length")
	}
	n := int(binary.BigEndian.Uint16(in))
	if len(in)-2 < n {
		return nil, nil, fmt.Errorf("says %d bytes, %d left", n, len(in)-2)
	}
	return append([]byte(nil), in[2:2+n]...), in[2+n:], nil
}
