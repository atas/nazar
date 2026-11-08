package fake

import (
	"slices"

	"github.com/atas/nazar/core/platform"
)

// mountWatch is one WatchMounts registration.
type mountWatch struct{ changed, stopped bool }

// WatchMounts starts a watch that sees every MountChange from now until
// stop (platform.Mounts); it fails with MountsErr when that is set.
func (f *Fake) WatchMounts() (func() bool, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.MountsErr != nil {
		return nil, nil, f.MountsErr
	}
	w := &mountWatch{}
	f.mountWatches = append(f.mountWatches, w)
	changed := func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return w.changed || w.stopped
	}
	stop := func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.stopped = true
		f.mountWatches = slices.DeleteFunc(f.mountWatches, func(x *mountWatch) bool { return x == w })
	}
	return changed, stop, nil
}

// MountChange is a volume mounted or unmounted: every watch on sees it.
func (f *Fake) MountChange() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.mountWatches {
		w.changed = true
	}
}

// MountWatches is how many watches are on (not stopped).
func (f *Fake) MountWatches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mountWatches)
}

var _ platform.Mounts = (*Fake)(nil)
