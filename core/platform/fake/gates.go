package fake

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/atas/nazar/core/platform"
)

// Answer scripts one gate answer. The zero Answer denies.
type Answer struct {
	Allow bool
	// How, for a denied Confirm, says how the dialog ended: Confirm then
	// returns (false, platform.DialogDenied{How}). Zero is a plain denial.
	How   platform.DialogHow
	Err   error           // returned instead of an answer; wins over Allow
	Delay time.Duration   // real-time sleep before answering
	Wait  <-chan struct{} // if set, block until closed before answering
}

// PromptKind says which gate a recorded prompt came from.
type PromptKind string

const (
	KindAuthenticate PromptKind = "authenticate"
	KindConfirm      PromptKind = "confirm"
)

// ShownPrompt is one prompt the fake was asked to show.
type ShownPrompt struct {
	Kind   PromptKind
	Policy platform.AuthPolicy
	Prompt platform.Prompt
}

// gates holds the scripted answers and the approval bookkeeping. It is
// guarded by Fake.mu.
type gates struct {
	authQueue    []Answer
	confirmQueue []Answer
	// DefaultAuth / DefaultConfirm answer when the queue is empty.
	DefaultAuth    Answer
	DefaultConfirm Answer
	// AuthFunc / ConfirmFunc, when set, answer instead of queue and default.
	// They run outside the fake's lock and may call back into the fake.
	AuthFunc    func(platform.Prompt) Answer
	ConfirmFunc func(platform.Prompt) Answer

	shown    []ShownPrompt
	live     map[platform.ApprovalRef]bool
	released []platform.ApprovalRef
	nextRef  platform.ApprovalRef
}

func (g *gates) init() {
	g.live = map[platform.ApprovalRef]bool{}
	// Refs start at a random point so a ref issued by another Fake (another
	// Mac's LAContext) or a guessed small number is not accepted by accident.
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("fake: crypto/rand: " + err.Error())
	}
	g.nextRef = platform.ApprovalRef(binary.LittleEndian.Uint64(b[:]) >> 1) // keeps room to count up
}

// ScriptAuth queues answers for Authenticate (login gate).
func (f *Fake) ScriptAuth(a ...Answer) {
	f.mu.Lock()
	f.authQueue = append(f.authQueue, a...)
	f.mu.Unlock()
}

// ScriptConfirm queues answers for Confirm (dialog gate).
func (f *Fake) ScriptConfirm(a ...Answer) {
	f.mu.Lock()
	f.confirmQueue = append(f.confirmQueue, a...)
	f.mu.Unlock()
}

// SetDefaults sets the answers used when the queues are empty.
func (f *Fake) SetDefaults(auth, confirm Answer) {
	f.mu.Lock()
	f.DefaultAuth, f.DefaultConfirm = auth, confirm
	f.mu.Unlock()
}

// SetGateFuncs installs answer functions that override queues and defaults;
// nil clears one.
func (f *Fake) SetGateFuncs(auth, confirm func(platform.Prompt) Answer) {
	f.mu.Lock()
	f.AuthFunc, f.ConfirmFunc = auth, confirm
	f.mu.Unlock()
}

// Shown returns every prompt shown so far, in order.
func (f *Fake) Shown() []ShownPrompt {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ShownPrompt, len(f.shown))
	for i, s := range f.shown {
		s.Prompt.Lines = append([]string(nil), s.Prompt.Lines...)
		out[i] = s
	}
	return out
}

// CountShown counts prompts of one kind.
func (f *Fake) CountShown(k PromptKind) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.shown {
		if s.Kind == k {
			n++
		}
	}
	return n
}

// LiveApprovals counts approval refs not yet released.
func (f *Fake) LiveApprovals() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

// Released returns released refs in order.
func (f *Fake) Released() []platform.ApprovalRef {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]platform.ApprovalRef(nil), f.released...)
}

// next records the prompt and picks its answer: the gate func if set (called
// outside the lock), else the next queued answer, else the default.
func (f *Fake) next(kind PromptKind, policy platform.AuthPolicy, p platform.Prompt) Answer {
	f.mu.Lock()
	p.Lines = append([]string(nil), p.Lines...)
	f.shown = append(f.shown, ShownPrompt{Kind: kind, Policy: policy, Prompt: p})
	fn, queue, def := f.AuthFunc, &f.authQueue, f.DefaultAuth
	if kind == KindConfirm {
		fn, queue, def = f.ConfirmFunc, &f.confirmQueue, f.DefaultConfirm
	}
	if fn != nil {
		f.mu.Unlock()
		return fn(p)
	}
	a := def
	if len(*queue) > 0 {
		a = (*queue)[0]
		*queue = (*queue)[1:]
	}
	f.mu.Unlock()
	return a
}

// wait blocks the way a real prompt would: until Wait is closed, then for
// Delay.
func wait(a Answer) {
	if a.Wait != nil {
		<-a.Wait
	}
	if a.Delay > 0 {
		time.Sleep(a.Delay)
	}
}

// Authenticate is the login gate. An allowed answer issues a fresh live
// approval ref; a denial is ErrDenied; Err is returned as is.
func (f *Fake) Authenticate(policy platform.AuthPolicy, p platform.Prompt) (platform.ApprovalRef, error) {
	a := f.next(KindAuthenticate, policy, p)
	wait(a)
	if a.Err != nil {
		return 0, a.Err
	}
	if !a.Allow {
		return 0, platform.ErrDenied
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextRef++
	if f.nextRef == 0 { // zero means "no approval"
		f.nextRef++
	}
	f.live[f.nextRef] = true
	return f.nextRef, nil
}

// Confirm is the dialog gate. It never issues an approval ref.
func (f *Fake) Confirm(p platform.Prompt) (bool, error) {
	a := f.next(KindConfirm, platform.AuthNone, p)
	wait(a)
	if a.Err != nil {
		return false, a.Err
	}
	if !a.Allow && a.How != platform.DialogNoReason {
		return false, platform.DialogDenied{How: a.How}
	}
	return a.Allow, nil
}

// ReleaseApproval ends a live approval. Releasing a released, unknown or
// zero ref is a no-op.
func (f *Fake) ReleaseApproval(ref platform.ApprovalRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live[ref] {
		delete(f.live, ref)
		f.released = append(f.released, ref)
	}
}

func (f *Fake) isLive(ref platform.ApprovalRef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live[ref]
}
