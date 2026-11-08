package fake

import (
	"errors"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// The fake's platform.Mounts. MountChange is seen by every watch on
// and by no later one; changed stays true, and is true after stop (fail
// closed); MountWatches counts the watches not stopped; MountsErr fails
// WatchMounts.
func TestFakeMounts(t *testing.T) {
	f := New(time.Now())
	var _ platform.Mounts = f
	f.MountChange() // before any watch: seen by none
	a, stopA, err := f.WatchMounts()
	if err != nil {
		t.Fatal(err)
	}
	b, stopB, _ := f.WatchMounts()
	if a() || b() {
		t.Fatal("a mount before the watch was seen")
	}
	if n := f.MountWatches(); n != 2 {
		t.Fatalf("%d watches, want 2", n)
	}
	f.MountChange()
	if !a() || !b() || !a() {
		t.Fatal("a mount during the watch must be seen by every watch, and stay seen")
	}
	stopA()
	stopA()
	if n := f.MountWatches(); n != 1 {
		t.Fatalf("%d watches after one stop, want 1", n)
	}
	stopB()
	c, stopC, _ := f.WatchMounts()
	if c() {
		t.Fatal("a new watch saw an old mount")
	}
	stopC()
	if !c() {
		t.Fatal("after stop, changed must report a change")
	}
	f.MountsErr = errors.New("no kqueue")
	if _, _, err := f.WatchMounts(); err == nil {
		t.Fatal("MountsErr must fail WatchMounts")
	}
}
