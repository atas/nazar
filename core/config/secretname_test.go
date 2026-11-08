package config

import (
	"strings"
	"testing"
)

// Secret names (secrets design 3.3). ASCII only, "/"-separated parts
// for k8s/<context>, each part led by a letter, digit or "_", at most 64
// bytes, no "..": a name becomes a Vault item name (secret/<name>) and,
// with "/" as %2F, a FIFO path.
func TestValidSecretName(t *testing.T) {
	for _, n := range []string{
		"BRAVE_API_KEY", "GITHUB_PERSONAL_ACCESS_TOKEN", "k8s/hydra", "_x", "a.b-c",
		"A1/b_2/c.3", strings.Repeat("a", 64),
	} {
		if !ValidSecretName(n) {
			t.Errorf("ValidSecretName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{
		"", "-x", ".x", "/a", "a/", "a//b", "a/.b", "a/-b", "a/../b", "a..b", "a b", "x\n", "\nx",
		"a%2Fb", "a\\b", "ä", "a\x00", strings.Repeat("a", 65), "k8s/" + strings.Repeat("a", 61),
	} {
		if ValidSecretName(n) {
			t.Errorf("ValidSecretName(%q) = true, want false", n)
		}
	}
}
