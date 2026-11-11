//go:build linux && linuxplatform

// The test image's own facts, which every linuxplatform and linuxe2e test
// relies on: swtpm starts, the system bus has polkitd with nazar's action,
// a private bus lets a test own any name, the answers queue works, and the
// tests run as the unprivileged test user with no TPM device in sight.
package linuxtest

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/internal/linuxtest/answers"
	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/dbustest"
	"github.com/atas/nazar/internal/linuxtest/swtpm"
)

func TestMain(m *testing.M) { os.Exit(container.Require(m)) }

func TestSwtpmStarts(t *testing.T) {
	socket := swtpm.Start(t)
	c, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		t.Fatalf("dial swtpm at %s: %v", socket, err)
	}
	c.Close()
}

// polkit's ImplicitAuthorization: 1 is AuthenticationRequired (auth_self).
const implicitAuthSelf = 1

type polkitAction struct {
	ActionID         string
	Description      string
	Message          string
	VendorName       string
	VendorURL        string
	IconName         string
	ImplicitAny      uint32
	ImplicitInactive uint32
	ImplicitActive   uint32
	Annotations      map[string]string
}

func TestSystemBusHasPolkit(t *testing.T) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatalf("system bus: %v", err)
	}
	defer conn.Close()

	var owner string
	if err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.PolicyKit1").Store(&owner); err != nil {
		t.Fatalf("org.freedesktop.PolicyKit1 has no owner: %v", err)
	}
	if owner == "" {
		t.Fatal("org.freedesktop.PolicyKit1: empty owner")
	}

	var actions []polkitAction
	authority := conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	if err := authority.Call("org.freedesktop.PolicyKit1.Authority.EnumerateActions", 0, "").Store(&actions); err != nil {
		t.Fatalf("EnumerateActions: %v", err)
	}
	for _, a := range actions {
		if a.ActionID != "dev.nazar.authenticate" {
			continue
		}
		if a.ImplicitAny != implicitAuthSelf || a.ImplicitInactive != implicitAuthSelf || a.ImplicitActive != implicitAuthSelf {
			t.Fatalf("dev.nazar.authenticate defaults = %d/%d/%d, want auth_self (1) for all", a.ImplicitAny, a.ImplicitInactive, a.ImplicitActive)
		}
		if a.Message != "$(nazar.prompt)" {
			t.Fatalf("dev.nazar.authenticate message = %q, want $(nazar.prompt)", a.Message)
		}
		return
	}
	t.Fatalf("polkit lists %d actions, none is dev.nazar.authenticate", len(actions))
}

func TestPrivateBus(t *testing.T) {
	address := dbustest.Start(t)
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatalf("connect %s: %v", address, err)
	}
	defer conn.Close()
	for _, name := range []string{"org.freedesktop.login1", "org.freedesktop.Notifications"} {
		reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
		if err != nil {
			t.Fatalf("RequestName %s: %v", name, err)
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			t.Fatalf("RequestName %s = %v, want primary owner", name, reply)
		}
	}
}

func TestAnswersQueue(t *testing.T) {
	q := answers.NewQueue(t)
	q.Push(true)
	q.Push(false)
	if allow, ok := answers.PopFrom(q.Socket(), time.Second); !ok || !allow {
		t.Fatalf("first PopFrom = %v, %v; want true, true", allow, ok)
	}
	if allow, ok := answers.PopFrom(q.Socket(), time.Second); !ok || allow {
		t.Fatalf("second PopFrom = %v, %v; want false, true", allow, ok)
	}
	start := time.Now()
	if allow, ok := answers.PopFrom(q.Socket(), 200*time.Millisecond); ok || allow {
		t.Fatalf("PopFrom on an empty queue = %v, %v; want false, false", allow, ok)
	}
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Fatalf("PopFrom on an empty queue returned after %v, before its timeout", d)
	}
}

func TestRunsUnprivileged(t *testing.T) {
	if uid := os.Geteuid(); uid != 1000 {
		t.Fatalf("euid = %d, want 1000 (nazartest)", uid)
	}
	for _, dev := range []string{"/dev/tpm0", "/dev/tpmrm0"} {
		if _, err := os.Lstat(dev); !os.IsNotExist(err) {
			t.Fatalf("%s: %v; the container must have no TPM device", dev, err)
		}
	}
}
