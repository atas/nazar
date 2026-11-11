//go:build integration

package integration

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// TestSkipReason pins where the suite runs: always on macOS, on Linux only
// inside the test container, and nowhere else (it prints why and exits 0).
func TestSkipReason(t *testing.T) {
	inside := func() error { return nil }
	outside := func() error { return errors.New("not in the nazar Linux test container") }
	called := false
	never := func() error { called = true; return errors.New("checked") }

	if got := skipReason("darwin", never); got != "" || called {
		t.Fatalf("darwin: %q (container checked: %v), want it to run without asking", got, called)
	}
	if got := skipReason("linux", inside); got != "" {
		t.Fatalf("linux in the container: %q, want it to run", got)
	}
	want := "integration tests need macOS, or Linux in the test container: not in the nazar Linux test container"
	if got := skipReason("linux", outside); got != want {
		t.Fatalf("linux outside the container: %q, want %q", got, want)
	}
	for _, goos := range []string{"freebsd", "windows", "openbsd"} {
		if got := skipReason(goos, inside); got != "integration tests need macOS" {
			t.Fatalf("%s: %q, want the macOS message", goos, got)
		}
	}
}

// TestWorldPathFindsKubectl: TestK8sCommandsAsTheDocsSay runs the real kubectl
// only when the world's PATH finds it. On Linux the suite runs only in the
// test image, which has one, so a PATH that misses it would drop that run
// without a word; a run with none fails there instead. A Mac's PATH stays as
// it was, and a Mac with no kubectl still only logs it.
func TestWorldPathFindsKubectl(t *testing.T) {
	if got, want := worldPath("darwin"), "/usr/bin:/bin:/usr/sbin:/opt/homebrew/bin"; got != want {
		t.Errorf("the macOS PATH changed: %q, want %q", got, want)
	}
	if got := worldPath("linux"); !strings.Contains(":"+got+":", ":/usr/local/bin:") {
		t.Errorf("the Linux PATH %q misses /usr/local/bin, where the image keeps kubectl", got)
	}
	if noKubectlFails("darwin") {
		t.Error("a Mac with no kubectl must not fail")
	}
	if !noKubectlFails("linux") {
		t.Error("the test image has kubectl: none must fail, not pass with the run untested")
	}
	if noKubectlFails(runtime.GOOS) && findKubectl(worldPath(runtime.GOOS)) == "" {
		t.Errorf("no kubectl on the world's PATH %q", worldPath(runtime.GOOS))
	}
}
