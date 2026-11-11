//go:build linux

package linux

// Plain Linux tests of the Platform's shape: what New refuses, which
// traits it declares and that no process it describes is ever signed.
// Nothing here needs a TPM, a bus or the test image; the whole contract
// runs in the container (conformance_linuxplatform_test.go).

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

// stubTPM is a transport that must never be spoken to: New checks its
// arguments before it opens the TPM.
type stubTPM struct{ sent atomic.Int32 }

func (s *stubTPM) Send([]byte) ([]byte, error) {
	s.sent.Add(1)
	return nil, errors.New("stub TPM")
}

func (s *stubTPM) Close() error { return nil }

func TestNewNeedsTPMAndVault(t *testing.T) {
	if p, err := New(Options{Vault: fake.NewVault()}); err == nil || p != nil {
		t.Fatalf("New without a TPM = %v, %v; want an error", p, err)
	}
	stub := &stubTPM{}
	if p, err := New(Options{TPM: stub}); err == nil || p != nil {
		t.Fatalf("New without a vault = %v, %v; want an error", p, err)
	}
	if n := stub.sent.Load(); n != 0 {
		t.Fatalf("New without a vault sent %d commands to the TPM; want none", n)
	}
}

// With no connection to logind no lock is ever seen and the lock callbacks
// never run. New refuses that before it speaks to the TPM, and says why.
func TestNewNeedsLogind(t *testing.T) {
	stub := &stubTPM{}
	p, err := New(Options{TPM: stub, Vault: fake.NewVault()})
	if err == nil || p != nil {
		t.Fatalf("New without logind = %v, %v; want an error", p, err)
	}
	if !strings.Contains(err.Error(), "logind") {
		t.Fatalf("New without logind: %q does not name logind", err)
	}
	if n := stub.sent.Load(); n != 0 {
		t.Fatalf("New without logind sent %d commands to the TPM; want none", n)
	}
}

func TestTraits(t *testing.T) {
	var p platform.Platform = &Platform{}
	if got := platform.TraitsOf(p); got != platform.LinuxTraits {
		t.Fatalf("TraitsOf(linux platform) = %+v, want LinuxTraits", got)
	}
}

// No ProcessInfo of the Linux platform is ever Signed: Linux has no code
// signatures, and Code.Team() of a process must never match a signed: or
// app: pin (only AppInfo and AppBundle carry the hash pin).
func TestNoProcessIsSigned(t *testing.T) {
	p := &Platform{procs: procfs.New()}
	st, err := procfs.ReadStat(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	self := platform.ProcessRef{PID: os.Getpid(), Generation: procfs.Generation(st.StartTicks)}
	info, err := p.Process(self)
	if err != nil {
		t.Fatalf("Process(self): %v", err)
	}
	if info.Ref != self {
		t.Fatalf("Process(self).Ref = %v, want %v", info.Ref, self)
	}
	if info.Code.Signed || info.Code.Team() != "" {
		t.Fatalf("Process(self).Code = %+v; a Linux process is never signed", info.Code)
	}
	if len(info.Code.CDHash) == 0 {
		t.Fatal("Process(self).Code.CDHash is empty; want the hash of the running image")
	}
	byPID, err := p.Process(platform.ProcessRef{PID: os.Getpid()})
	if err != nil || byPID.Ref != self {
		t.Fatalf("Process(PID-only self) = %v, %v; want %v", byPID.Ref, err, self)
	}
}
