// Package container tells a test whether it runs inside nazar's Linux test
// image (test/linux), where swtpm, a private system bus and polkitd are up
// and nothing reaches the host's TPM, polkit agent or buses. Tests built
// with the linuxplatform or linuxe2e tags call Require from TestMain, so
// they fail (exit 1), never pass, anywhere else. Test-only code; nothing in
// it ships.
package container

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

// envVar is set by the image (ENV in test/linux/Dockerfile).
const envVar = "NAZAR_LINUX_TEST_CONTAINER"

// readyPath is touched by test/linux/run.sh, as root, once swtpm's tools,
// the system bus and polkitd are up. A variable for the tests only.
var readyPath = "/run/nazar-test/ready"

// Check returns nil only inside the test container: NAZAR_LINUX_TEST_CONTAINER
// is exactly "1" and the ready file exists, is a regular file (not a link)
// and is owned by root. A variable set by hand on a real machine is not
// enough: the test user cannot make a root-owned file.
func Check() error {
	if v := os.Getenv(envVar); v != "1" {
		return fmt.Errorf("not in the nazar Linux test container (%s is %q, not \"1\"); run it with make linux-run CMD='...'", envVar, v)
	}
	fi, err := os.Lstat(readyPath)
	if err != nil {
		return fmt.Errorf("not in the nazar Linux test container: the ready file %s: %w", readyPath, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not in the nazar Linux test container: the ready file %s is not a regular file", readyPath)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("not in the nazar Linux test container: no owner for the ready file %s", readyPath)
	}
	if st.Uid != 0 {
		return fmt.Errorf("not in the nazar Linux test container: the ready file %s is owned by uid %d, not root", readyPath, st.Uid)
	}
	return nil
}

// Require runs the tests only inside the container. Outside it, it prints
// why and returns 1, so a TestMain that does os.Exit(container.Require(m))
// fails rather than passing with nothing run.
func Require(m *testing.M) int {
	if err := Check(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		return 1
	}
	return m.Run()
}
