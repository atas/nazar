package platform_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/atas/nazar/core/platform"
)

// A NotFoundError is ErrNotFound to every caller that checks for it, and
// its reason is what it says, through any wrapping.
func TestNotFoundErrorIsNotFoundWithReason(t *testing.T) {
	err := fmt.Errorf("configstage: app %q can't be pinned: %w", "org.x.Y",
		&platform.NotFoundError{Reason: `its program "/usr/bin/flatpak" starts some other program`})
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("a NotFoundError is not ErrNotFound to errors.Is")
	}
	var nf *platform.NotFoundError
	if !errors.As(err, &nf) || nf.Reason != `its program "/usr/bin/flatpak" starts some other program` {
		t.Fatalf("errors.As = %v, %+v", errors.As(err, &nf), nf)
	}
	if want := `configstage: app "org.x.Y" can't be pinned: its program "/usr/bin/flatpak" starts some other program`; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	// The bare sentinel carries no reason.
	if errors.As(platform.ErrNotFound, &nf) {
		t.Error("the bare ErrNotFound is a NotFoundError")
	}
}
