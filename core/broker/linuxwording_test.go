package broker

import (
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// linuxFake is the fake platform describing itself as Linux.
type linuxFake struct{ *fake.Fake }

func (linuxFake) Traits() platform.Traits { return platform.LinuxTraits }

// A user-presence key that refuses its approval names who enforces it: the
// Secure Enclave on macOS, nazar on Linux. Portable: runs on every OS.
func TestAuthRequiredNamesTheEnforcer(t *testing.T) {
	for _, tc := range []struct {
		linux bool
		want  string
	}{
		{false, "key requires the login gate (it was created with Secure Enclave user presence): platform: key requires an authenticated approval"},
		{true, "key requires the login gate (it was created with user presence enforced by nazar): platform: key requires an authenticated approval"},
	} {
		e := newEnv(t)
		if tc.linux {
			o := e.b.o
			o.Platform = linuxFake{e.f}
			e.b = New(o)
		}
		tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
		req := e.req("deploy", tab.Peer())
		req.Do = func(platform.ApprovalRef) error { return platform.ErrAuthRequired }
		if r := e.b.Handle(req); r.Decision != audit.Error || r.Reason != tc.want {
			t.Errorf("linux %v: %+v, want reason %q", tc.linux, r, tc.want)
		}
	}
}
