//go:build linux

package linux

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/atas/nazar/core/platform"
)

// approvals is the set of live approval refs the login gate issued
// (platform.ApprovalRef's contract). A ref is a counter in its high 32
// bits, from 1 and never reused in the process, and 32 random bits below
// (never all zeros or all ones), so a value next to a live ref (±1, ^1)
// falls in the same counter's range with other low bits, or in a
// neighbouring counter's range at an edge that is never issued: it is
// never live. A ref is live from Authenticate until ReleaseApproval; a
// user-presence key signs only with a live one.
type approvals struct {
	mu   sync.Mutex
	next uint32
	live map[platform.ApprovalRef]struct{}
}

// errRefsExhausted: the counter wrapped; no more refs are issued in this
// process rather than ever repeating one.
var errRefsExhausted = errors.New("linux: approval refs exhausted; restart nazar-agent")

// issue makes a new live ref.
func (a *approvals) issue() (platform.ApprovalRef, error) {
	low, err := randomLow()
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next == ^uint32(0) {
		return 0, errRefsExhausted
	}
	a.next++
	ref := platform.ApprovalRef(uint64(a.next)<<32 | uint64(low))
	if a.live == nil {
		a.live = map[platform.ApprovalRef]struct{}{}
	}
	a.live[ref] = struct{}{}
	return ref, nil
}

// randomLow is the random half of a ref: never 0 or 0xFFFFFFFF, so a
// neighbour of any issued ref never names another counter's ref.
func randomLow() (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("linux: approval ref: %w", err)
		}
		low := binary.BigEndian.Uint32(b[:])
		if low != 0 && low != ^uint32(0) {
			return low, nil
		}
	}
}

// isLive reports whether ref was issued and not released. Zero, an
// unknown and a released ref are not live.
func (a *approvals) isLive(ref platform.ApprovalRef) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.live[ref]
	return ok
}

// release ends ref; zero, unknown and released refs are a no-op.
func (a *approvals) release(ref platform.ApprovalRef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.live, ref)
}

// errNoPolkit: the Platform was made without a system bus connection, so
// the login gate has nobody to ask; it fails closed.
var errNoPolkit = errors.New("linux: no connection to the system bus; the login gate cannot ask polkit")

// Authenticate is the login gate: the user authenticates to polkit
// (their password, or a fingerprint where PAM has one), through the
// desktop's own agent. policy is AuthNone or AuthUserPresence; anything
// else is refused before polkit is asked. An authorized check issues a
// live ref; a refusal, a cancelled prompt or the timeout is
// platform.ErrDenied with the zero ref; every other outcome (no agent, no
// session, polkit down) is an error with the zero ref.
func (p *Platform) Authenticate(policy platform.AuthPolicy, prompt platform.Prompt) (platform.ApprovalRef, error) {
	if policy != platform.AuthNone && policy != platform.AuthUserPresence {
		return 0, fmt.Errorf("linux: Authenticate: unknown policy %v", policy)
	}
	if p.auth == nil {
		return 0, errNoPolkit
	}
	if err := p.auth.Check(prompt); err != nil {
		if errors.Is(err, platform.ErrDenied) {
			return 0, platform.ErrDenied
		}
		return 0, err
	}
	return p.approvals.issue()
}

// Confirm is the dialog gate: the desktop's zenity or kdialog, run by the
// agent (dialog.Dialog.Confirm). It never issues an approval ref.
func (p *Platform) Confirm(prompt platform.Prompt) (bool, error) {
	return p.dialog.Confirm(prompt)
}

// ReleaseApproval ends a live approval. Releasing zero, an unknown or an
// already released ref is a no-op, and every other ref stays live.
func (p *Platform) ReleaseApproval(ref platform.ApprovalRef) {
	p.approvals.release(ref)
}
