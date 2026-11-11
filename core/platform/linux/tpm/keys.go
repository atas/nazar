//go:build linux

// Package tpm is the key part of the Linux platform: ECDSA P-256 signing
// and ECDH keys made inside a TPM 2.0 (go-tpm's direct API, no cgo), which
// never leave it. A key is a child of a deterministic storage root key, so
// the TPM-wrapped blob the vault holds loads again after a restart; the
// private part exists only inside the TPM. Each use loads the key, uses it
// and flushes it, under one mutex, because the TPM has a few transient
// slots and swtpm, like /dev/tpm0, has no resource manager.
//
// Two of the platform contract's rules are nazar's here, not the chip's
// (spec, "Weaker than macOS" 3): a user-presence key signs only with an
// approval the Platform vouches for (approved), and a when-unlocked key
// is refused while the screen is locked or its state is unknown (locked;
// it fails closed). Only cmd/nazar-agent names /dev/tpmrm0; every caller
// here, tests included, hands Open the transport.
package tpm

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/atas/nazar/core/platform"
)

// VaultPrefix starts the name of every vault item this package writes:
// VaultPrefix + the hex of the handle's 16 random bytes.
const VaultPrefix = "tpm/"

const (
	// handlePrefix starts every handle, so a handle of another platform or
	// a random value is told apart before the vault is asked.
	handlePrefix = "nzt1"
	handleRandom = 16
	handleLen    = len(handlePrefix) + handleRandom
	// coordinate is the byte length of a P-256 field element.
	coordinate = 32
)

// Keys holds the open TPM, the vault the blobs live in, and the SRK.
type Keys struct {
	mu       sync.Mutex // around every TPM command, and closed
	tpm      transport.TPMCloser
	vault    platform.Vault
	locked   func() (bool, error)
	approved func(platform.ApprovalRef) bool
	srk      tpm2.NamedHandle
	closed   bool
}

// Open creates the SRK on t (TPM2_CreatePrimary in the owner hierarchy;
// the same key every time) and returns Keys that use it until Close. v
// holds the key blobs under VaultPrefix. locked answers whether the screen
// is locked (an error counts as locked); approved says whether ref is a
// live approval of the Platform's. Keys own t and close it with Close.
func Open(t transport.TPMCloser, v platform.Vault, locked func() (bool, error), approved func(platform.ApprovalRef) bool) (*Keys, error) {
	if t == nil || v == nil || locked == nil || approved == nil {
		return nil, errors.New("tpm: Open needs a TPM, a vault, locked and approved")
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(srkTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: create the storage root key: %w", err)
	}
	return &Keys{
		tpm:      t,
		vault:    v,
		locked:   locked,
		approved: approved,
		srk:      tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name},
	}, nil
}

// Close flushes the SRK and closes the TPM. A second Close does nothing.
func (k *Keys) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	_, flushErr := tpm2.FlushContext{FlushHandle: k.srk.Handle}.Execute(k.tpm)
	closeErr := k.tpm.Close()
	if flushErr != nil {
		return fmt.Errorf("tpm: flush the storage root key: %w", flushErr)
	}
	if closeErr != nil {
		return fmt.Errorf("tpm: close: %w", closeErr)
	}
	return nil
}

// parent is the SRK as a command's authorized parent handle.
func (k *Keys) parent() tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: k.srk.Handle, Name: k.srk.Name, Auth: tpm2.PasswordAuth(nil)}
}

// checkLocked refuses a when-unlocked key while the screen is locked, or
// when nobody can say: the locked error is worded for Linux, never the
// bare Mac one, and errors.Is(err, platform.ErrLocked) holds.
func (k *Keys) checkLocked(access platform.Access) error {
	if access != platform.AccessWhenUnlocked {
		return nil
	}
	locked, err := k.locked()
	if err != nil {
		return platform.Locked(fmt.Sprintf("tpm: the screen's lock state is unknown (%v); a key that works only while it's unlocked is refused", err))
	}
	if locked {
		return platform.Locked("tpm: the screen is locked")
	}
	return nil
}

// CreateKey makes a key for purpose inside the TPM, as a child of the SRK,
// and files its blob in the vault. An out-of-range purpose, policy or
// access is refused, as is an access that does not fit the policy
// (Access.Fits); a when-unlocked key is not made while the screen is
// locked. The handle is handlePrefix plus 16 random bytes; the public key
// is the X9.63 uncompressed point.
func (k *Keys) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) (handle, publicKey []byte, err error) {
	template, ok := keyTemplate(purpose)
	if !ok {
		return nil, nil, fmt.Errorf("tpm: unknown key purpose %v", purpose)
	}
	if auth != platform.AuthNone && auth != platform.AuthUserPresence {
		return nil, nil, fmt.Errorf("tpm: unknown auth policy %v", auth)
	}
	if !access.Fits(auth) {
		return nil, nil, fmt.Errorf("tpm: access %v for auth %v", access, auth)
	}
	if err := k.checkLocked(access); err != nil {
		return nil, nil, err
	}

	random := make([]byte, handleRandom)
	if _, err := rand.Read(random); err != nil {
		return nil, nil, fmt.Errorf("tpm: %w", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, nil, errClosed
	}
	rsp, err := tpm2.Create{
		ParentHandle: k.parent(),
		InPublic:     tpm2.New2B(template),
	}.Execute(k.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: create key: %w", err)
	}
	pub, err := publicPoint(&rsp.OutPublic)
	if err != nil {
		return nil, nil, err
	}
	b := blob{
		purpose: purpose,
		auth:    auth,
		access:  access,
		public:  rsp.OutPublic.Bytes(),
		private: rsp.OutPrivate.Buffer,
	}
	handle = append([]byte(handlePrefix), random...)
	if err := k.vault.Put(itemName(handle), b.encode()); err != nil {
		return nil, nil, fmt.Errorf("tpm: file the key: %w", err)
	}
	return handle, pub, nil
}

var errClosed = errors.New("tpm: closed")

// itemName is the vault item of a handle of the right shape.
func itemName(handle []byte) string {
	return VaultPrefix + hex.EncodeToString(handle[len(handlePrefix):])
}

// wellFormed reports whether handle has the shape this package issues.
func wellFormed(handle []byte) bool {
	return len(handle) == handleLen && string(handle[:len(handlePrefix)]) == handlePrefix
}

// lookup reads the key record of handle. A handle of another shape, or one
// with no item, is ErrNotFound; an item that is not a key record is an
// error of its own (errBlob).
func (k *Keys) lookup(handle []byte) (blob, error) {
	if !wellFormed(handle) {
		return blob{}, platform.ErrNotFound
	}
	item, err := k.vault.Get(itemName(handle))
	if err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return blob{}, platform.ErrNotFound
		}
		return blob{}, fmt.Errorf("tpm: read the key record: %w", err)
	}
	return decodeBlob(item)
}

// use runs the contract's checks for using handle as a key of purpose,
// then fn with the key loaded, and flushes the key whatever fn did. The
// order is the fake's and the chip's: unknown first, then the purpose,
// the lock, the approval.
func (k *Keys) use(handle []byte, purpose platform.Purpose, approval platform.ApprovalRef, fn func(tr transport.TPM, obj tpm2.NamedHandle) error) error {
	b, err := k.lookup(handle)
	if err != nil {
		return err
	}
	if b.purpose != purpose {
		return fmt.Errorf("tpm: key was created for %v, not %v", b.purpose, purpose)
	}
	if err := k.checkLocked(b.access); err != nil {
		return err
	}
	if b.auth == platform.AuthUserPresence && !k.approved(approval) {
		return platform.ErrAuthRequired
	}
	return k.load(b, fn)
}

// withLoaded loads handle's key with no check but existence and runs fn
// with it. For the tests, which read its public area and try to duplicate
// it; Sign and KeyAgreement go through use.
func (k *Keys) withLoaded(handle []byte, fn func(tr transport.TPM, obj tpm2.NamedHandle) error) error {
	b, err := k.lookup(handle)
	if err != nil {
		return err
	}
	return k.load(b, fn)
}

// load loads b under the SRK, runs fn and flushes the object, all under
// the mutex so no other command interleaves.
func (k *Keys) load(b blob, fn func(tr transport.TPM, obj tpm2.NamedHandle) error) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return errClosed
	}
	rsp, err := tpm2.Load{
		ParentHandle: k.parent(),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: b.private},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](b.public),
	}.Execute(k.tpm)
	if err != nil {
		return fmt.Errorf("tpm: load key: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(k.tpm)
	return fn(k.tpm, tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name})
}

// authorized is a loaded key as a command's authorized handle (its auth
// value is empty).
func authorized(obj tpm2.NamedHandle) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: obj.Handle, Name: obj.Name, Auth: tpm2.PasswordAuth(nil)}
}

// ecdsaSignature is the DER form ecdsa.VerifyASN1 and ssh read.
type ecdsaSignature struct{ R, S *big.Int }

// Sign hashes digestInput with SHA-256, signs it with the key and returns
// the ASN.1 DER ECDSA signature. See use for the refusals.
func (k *Keys) Sign(handle, digestInput []byte, approval platform.ApprovalRef) ([]byte, error) {
	sum := sha256.Sum256(digestInput)
	var der []byte
	err := k.use(handle, platform.PurposeSign, approval, func(tr transport.TPM, obj tpm2.NamedHandle) error {
		rsp, err := tpm2.Sign{
			KeyHandle:  authorized(obj),
			Digest:     tpm2.TPM2BDigest{Buffer: sum[:]},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
		}.Execute(tr)
		if err != nil {
			return fmt.Errorf("tpm: sign: %w", err)
		}
		sig, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return fmt.Errorf("tpm: sign: %w", err)
		}
		der, err = asn1.Marshal(ecdsaSignature{
			R: new(big.Int).SetBytes(sig.SignatureR.Buffer),
			S: new(big.Int).SetBytes(sig.SignatureS.Buffer),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return der, nil
}

// KeyAgreement returns the ECDH shared secret (the X coordinate, 32 bytes)
// of the key and peerPublicKey, an X9.63 uncompressed P-256 point; a
// malformed or off-curve point is an error. See use for the refusals.
func (k *Keys) KeyAgreement(handle, peerPublicKey []byte, approval platform.ApprovalRef) ([]byte, error) {
	var out []byte
	err := k.use(handle, platform.PurposeKeyAgreement, approval, func(tr transport.TPM, obj tpm2.NamedHandle) error {
		// Checked after the key's own refusals, as the fake does, and
		// before the TPM sees it: only a point on the curve goes in.
		if _, err := ecdh.P256().NewPublicKey(peerPublicKey); err != nil {
			return fmt.Errorf("tpm: peer public key: %w", err)
		}
		rsp, err := tpm2.ECDHZGen{
			KeyHandle: authorized(obj),
			InPoint: tpm2.New2B(tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: peerPublicKey[1 : 1+coordinate]},
				Y: tpm2.TPM2BECCParameter{Buffer: peerPublicKey[1+coordinate : 1+2*coordinate]},
			}),
		}.Execute(tr)
		if err != nil {
			return fmt.Errorf("tpm: key agreement: %w", err)
		}
		z, err := rsp.OutPoint.Contents()
		if err != nil {
			return fmt.Errorf("tpm: key agreement: %w", err)
		}
		out, err = fieldElement(z.X.Buffer)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteKey forgets the key: its vault item goes, and with it the only
// copy of the wrapped private part. An unknown handle is ErrNotFound.
func (k *Keys) DeleteKey(handle []byte) error {
	if !wellFormed(handle) {
		return platform.ErrNotFound
	}
	if err := k.vault.Delete(itemName(handle)); err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return platform.ErrNotFound
		}
		return fmt.Errorf("tpm: delete the key record: %w", err)
	}
	return nil
}

// publicPoint is the X9.63 uncompressed point of a created key's public
// area, each coordinate left-padded to 32 bytes.
func publicPoint(pub *tpm2.TPM2BPublic) ([]byte, error) {
	contents, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: public area: %w", err)
	}
	point, err := contents.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm: public area: %w", err)
	}
	x, err := fieldElement(point.X.Buffer)
	if err != nil {
		return nil, err
	}
	y, err := fieldElement(point.Y.Buffer)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+2*coordinate)
	out = append(out, 4)
	out = append(out, x...)
	out = append(out, y...)
	if _, err := ecdh.P256().NewPublicKey(out); err != nil {
		return nil, fmt.Errorf("tpm: public area is not a P-256 point: %w", err)
	}
	return out, nil
}

// fieldElement is a P-256 field element the TPM returned as exactly 32
// bytes, big-endian, left-padded; a longer value is not one.
func fieldElement(b []byte) ([]byte, error) {
	if len(b) > coordinate {
		return nil, fmt.Errorf("tpm: a %d-byte coordinate is not a P-256 field element", len(b))
	}
	return new(big.Int).SetBytes(b).FillBytes(make([]byte, coordinate)), nil
}
