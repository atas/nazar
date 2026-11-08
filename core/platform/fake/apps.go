package fake

import (
	"sort"

	"github.com/atas/nazar/core/platform"
)

// InstallApp puts an app bundle at path (replacing whatever bundle was
// there, as an app update does). Installed bundles are what InstalledApp
// answers from; a running process never counts as installed.
func (f *Fake) InstallApp(path, bundleID string, code platform.CodeIdentity) {
	code.CDHash = append([]byte(nil), code.CDHash...)
	f.mu.Lock()
	f.installed[path] = platform.AppBundle{BundleID: bundleID, Path: path, Code: code}
	f.mu.Unlock()
}

// UninstallApp removes the bundle at path; a path with no bundle is a no-op.
func (f *Fake) UninstallApp(path string) {
	f.mu.Lock()
	delete(f.installed, path)
	f.mu.Unlock()
}

// InstalledApp answers from InstalledAppFunc when set, else from the
// installed bundles: ErrNotFound when none has bundleID, ErrAmbiguous when
// those that do are signed by different teams (CodeIdentity.Team), else the
// one with the lowest path, so the answer is deterministic.
func (f *Fake) InstalledApp(bundleID string) (platform.AppBundle, error) {
	f.mu.Lock()
	fn := f.InstalledAppFunc
	var found []platform.AppBundle
	for _, b := range f.installed {
		if b.BundleID == bundleID {
			found = append(found, b)
		}
	}
	f.mu.Unlock()
	if fn != nil {
		return fn(bundleID)
	}
	if len(found) == 0 {
		return platform.AppBundle{}, platform.ErrNotFound
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Path < found[j].Path })
	team := found[0].Code.Team()
	for _, b := range found[1:] {
		if b.Code.Team() != team {
			return platform.AppBundle{}, platform.ErrAmbiguous
		}
	}
	b := found[0]
	b.Code.CDHash = append([]byte(nil), b.Code.CDHash...)
	return b, nil
}
