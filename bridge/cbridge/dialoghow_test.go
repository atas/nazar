package cbridge_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// How a dialog was denied crosses the C table intact, and Allow still
// crosses as Allow.
func TestDialogHowCrossesTheTable(t *testing.T) {
	h, b, _, _ := newHarness(t)
	for _, how := range []platform.DialogHow{platform.DialogDenyButton, platform.DialogEscape, platform.DialogTimedOut, platform.DialogClosed} {
		h.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{How: how} })
		ok, err := b.Confirm(platform.Prompt{Title: "t"})
		var d platform.DialogDenied
		if ok || !errors.As(err, &d) || d.How != how || !errors.Is(err, platform.ErrDenied) {
			t.Errorf("%v: Confirm = %v, %v", how, ok, err)
		}
	}
	h.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{} })
	if ok, err := b.Confirm(platform.Prompt{Title: "t"}); ok || err != nil {
		t.Errorf("plain denial: %v, %v", ok, err)
	}
	h.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{Allow: true, How: platform.DialogEscape} })
	if ok, err := b.Confirm(platform.Prompt{Title: "t"}); !ok || err != nil {
		t.Errorf("allow: %v, %v", ok, err)
	}
}

// Attack and edge cases of the same across the table. 1 is Allow and is not a
// DialogHow: a denial that claims How 1 (a platform bug) must still cross
// as a denial, never as the `allowed` value 1. Unknown or negative ways are
// a plain denial. A DialogDenied wrapped in another error keeps its way.
func TestDialogHowNeverCrossesAsAllow(t *testing.T) {
	h, b, _, _ := newHarness(t)
	for _, how := range []platform.DialogHow{1, 6, 99, -1, -7} {
		h.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{How: how} })
		ok, err := b.Confirm(platform.Prompt{Title: "t"})
		if ok {
			t.Fatalf("How %d: a denial crossed the table as Allow", int(how))
		}
		var d platform.DialogDenied
		if err != nil && (!errors.Is(err, platform.ErrDenied) || (errors.As(err, &d) && (d.How < 2 || d.How > 5))) {
			t.Errorf("How %d: Confirm = %v, %v; want a plain denial", int(how), ok, err)
		}
	}
	wrapped := fmt.Errorf("dialog: %w", platform.DialogDenied{How: platform.DialogEscape})
	h.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{Err: wrapped} })
	ok, err := b.Confirm(platform.Prompt{Title: "t"})
	var d platform.DialogDenied
	if ok || !errors.As(err, &d) || d.How != platform.DialogEscape || !errors.Is(err, platform.ErrDenied) {
		t.Errorf("wrapped Esc: Confirm = %v, %v", ok, err)
	}
	// Any other error still crosses as an error, not as a denial with a way.
	h.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{Err: errors.New("ui stuck")} })
	if ok, err := b.Confirm(platform.Prompt{Title: "t"}); ok || err == nil || errors.As(err, &d) {
		t.Errorf("plain error: Confirm = %v, %v", ok, err)
	}
}
