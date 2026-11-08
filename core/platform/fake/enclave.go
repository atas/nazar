package fake

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/atas/nazar/core/platform"
)

// enclaveKey is one key the software enclave holds. The private key never
// leaves the enclave.
type enclaveKey struct {
	priv    *ecdsa.PrivateKey
	purpose platform.Purpose
	auth    platform.AuthPolicy
	access  platform.Access
}

// enclave is a software stand-in for the Secure Enclave. Handles are random
// 32-byte IDs; anything but an exact issued handle is ErrNotFound.
type enclave struct {
	emu       sync.Mutex
	keys      map[string]enclaveKey
	signCalls int
	locked    bool // SetLocked
}

func (e *enclave) init() {
	e.keys = map[string]enclaveKey{}
}

// SetLocked makes the fake's Mac locked or unlocked: while locked, a key
// with AccessWhenUnlocked can't be made or used (ErrLocked), as on the chip.
func (f *Fake) SetLocked(on bool) {
	f.emu.Lock()
	f.locked = on
	f.emu.Unlock()
}

// CreateKey generates a P-256 key for purpose, protected by auth and
// access. An out-of-range purpose, policy or access is refused rather than
// silently weakened.
func (f *Fake) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	if purpose != platform.PurposeSign && purpose != platform.PurposeKeyAgreement {
		return nil, nil, fmt.Errorf("fake: unknown key purpose %v", purpose)
	}
	if auth != platform.AuthNone && auth != platform.AuthUserPresence {
		return nil, nil, fmt.Errorf("fake: unknown auth policy %v", auth)
	}
	if !access.Fits(auth) {
		return nil, nil, fmt.Errorf("fake: access %v for auth %v", access, auth)
	}
	f.emu.Lock()
	locked := f.locked
	f.emu.Unlock()
	if locked && access == platform.AccessWhenUnlocked {
		return nil, nil, platform.ErrLocked // the chip makes none while locked
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return nil, nil, err
	}
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, nil, err
	}
	f.emu.Lock()
	f.keys[hex.EncodeToString(handle)] = enclaveKey{priv: priv, purpose: purpose, auth: auth, access: access}
	f.emu.Unlock()
	return handle, pub, nil
}

// use looks up handle, checks it was created for purpose, and enforces
// access and AuthUserPresence like the Secure Enclave: a when-unlocked key
// fails while the fake is locked, and a presence key works only with a
// live approval ref this fake issued.
func (f *Fake) use(handle []byte, purpose platform.Purpose, approval platform.ApprovalRef) (*ecdsa.PrivateKey, error) {
	f.emu.Lock()
	k, ok := f.keys[hex.EncodeToString(handle)]
	locked := f.locked
	f.emu.Unlock()
	if !ok {
		return nil, platform.ErrNotFound
	}
	if k.purpose != purpose {
		return nil, fmt.Errorf("fake: key was created for %v, not %v", k.purpose, purpose)
	}
	if locked && k.access == platform.AccessWhenUnlocked {
		return nil, platform.ErrLocked
	}
	if k.auth == platform.AuthUserPresence && !f.isLive(approval) {
		return nil, platform.ErrAuthRequired
	}
	return k.priv, nil
}

// Sign returns an ASN.1 DER ECDSA signature over SHA-256(digestInput).
func (f *Fake) Sign(handle, digestInput []byte, approval platform.ApprovalRef) ([]byte, error) {
	k, err := f.use(handle, platform.PurposeSign, approval)
	if err != nil {
		return nil, err
	}
	f.emu.Lock()
	f.signCalls++
	f.emu.Unlock()
	sum := sha256.Sum256(digestInput)
	return ecdsa.SignASN1(rand.Reader, k, sum[:])
}

// SignCalls counts Sign calls that reached the key.
func (f *Fake) SignCalls() int {
	f.emu.Lock()
	defer f.emu.Unlock()
	return f.signCalls
}

// KeyAgreement returns the ECDH shared secret with peerPublicKey (an X9.63
// uncompressed P-256 point); a malformed peer key is an error.
func (f *Fake) KeyAgreement(handle, peerPublicKey []byte, approval platform.ApprovalRef) ([]byte, error) {
	k, err := f.use(handle, platform.PurposeKeyAgreement, approval)
	if err != nil {
		return nil, err
	}
	priv, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(peer)
}

// DeleteKey forgets the key; an unknown handle is ErrNotFound.
func (f *Fake) DeleteKey(handle []byte) error {
	f.emu.Lock()
	defer f.emu.Unlock()
	h := hex.EncodeToString(handle)
	if _, ok := f.keys[h]; !ok {
		return platform.ErrNotFound
	}
	delete(f.keys, h)
	return nil
}
