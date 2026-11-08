package daemon

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
)

// The sockets are reached through ~/.nazar as well as run/, so nazar-agent
// refuses to start on a ~/.nazar open to others, as it did when the sockets
// were directly in it, and does not fix the mode for whoever prepared it.
func TestRunRefusesLooseHome(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "nzd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	if err := os.Mkdir(layout.Root(home), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layout.Root(home), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{Platform: fake.New(time.Now()), Vault: fake.NewVault(), AuditSink: &audit.MemorySink{}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	// Bounded: a Run that accepts the folder serves until its context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := d.Run(ctx); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("Run: %v, want a mode error", err)
	}
	if fi, err := os.Lstat(layout.Root(home)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("~/.nazar: %v %v, want it left at 755", fi, err)
	}
	if _, err := os.Lstat(layout.ControlSocket(home)); !os.IsNotExist(err) {
		t.Fatalf("a control socket was made: %v", err)
	}
}
