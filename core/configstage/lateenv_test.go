package configstage

import (
	"strings"
	"testing"
)

// Secrets design 4: defaults.trustedPath is where nazar run
// resolves receivers and the receiver's PATH, so any change to it loosens;
// a name added to envAllow loosens and one removed tightens; adding
// late-env to deliver loosens like any other method.

const lateBase = `secrets:
  BRAVE_API_KEY:
    deliver: [late-env]
    envAllow: [HTTPS_PROXY]
    rules:
      - apps: [claude]
        to: [{command: [npx, -y, "@brave/brave-search-mcp-server"]}]
        scope: session
        gate: dialog
`

func TestClassifyLateEnv(t *testing.T) {
	const target = "secret:BRAVE_API_KEY"
	old := cfg(t, base+lateBase)
	for _, tc := range []struct {
		name, body string
		loosens    bool
		why        string
	}{
		{"an envAllow name added", strings.Replace(lateBase, "[HTTPS_PROXY]", "[HTTPS_PROXY, NODE_ENV]", 1), true, "the receiver gets NODE_ENV from the caller"},
		{"an envAllow name removed", strings.Replace(lateBase, "    envAllow: [HTTPS_PROXY]\n", "", 1), false, ""},
		{"stdout added", strings.Replace(lateBase, "[late-env]", "[late-env, stdout]", 1), true, "can now be delivered by stdout"},
		{"late-env swapped for helper", "secrets:\n  BRAVE_API_KEY:\n    deliver: [helper]\n    rules:\n      - apps: [claude]\n        to: [{signed: {team: apple, id: com.apple.git-remote-http}}]\n        scope: session\n        gate: dialog\n", true, "can now be delivered by helper"},
		{"another package", strings.Replace(lateBase, "@brave/brave-search-mcp-server", "@evil/server", 1), true, "(rule 1)"},
	} {
		d := Classify(old, cfg(t, base+tc.body))
		if d.Loosens() != tc.loosens || d.Empty() {
			t.Errorf("%s: loosens=%v empty=%v, want %v and a listed change:\n%s\n%q", tc.name, d.Loosens(), d.Empty(), tc.loosens, findingsText(d), d.Changes)
			continue
		}
		if tc.loosens && (!hasTarget(d, target) || !strings.Contains(findingsText(d), tc.why)) {
			t.Errorf("%s: want %s and %q:\n%s", tc.name, target, tc.why, findingsText(d))
		}
	}
	// late-env added to a secret some request can reach loosens.
	helperOnly := "secrets:\n  X:\n    deliver: [helper]\n    rules:\n      - apps: [claude]\n        to: [{signed: {team: apple, id: com.apple.git-remote-http}}]\n        gate: login\n"
	d := Classify(cfg(t, base+helperOnly), cfg(t, base+strings.Replace(helperOnly, "[helper]", "[helper, late-env]", 1)))
	if !d.Loosens() || !strings.Contains(findingsText(d), "can now be delivered by late-env") {
		t.Fatalf("adding late-env must loosen:\n%s", findingsText(d))
	}
}

func TestClassifyTrustedPath(t *testing.T) {
	with := func(list string) string { return base + "defaults:\n  trustedPath: " + list + "\n" }
	old := cfg(t, with("[/usr/bin, /bin]"))
	for _, tc := range []struct{ name, list string }{
		{"a directory added", "[/usr/bin, /bin, /tmp/x]"},
		{"reordered", "[/bin, /usr/bin]"},
		{"a directory removed", "[/usr/bin]"},
	} {
		d := Classify(old, cfg(t, with(tc.list)))
		if !d.Loosens() || !hasTarget(d, "defaults.trustedPath") || !strings.Contains(strings.Join(d.Changes, "\n"), "defaults.trustedPath") {
			t.Errorf("%s: any trustedPath change loosens and is listed:\n%s\n%q", tc.name, findingsText(d), d.Changes)
		}
	}
	if d := Classify(old, cfg(t, with("[/usr/bin, /bin]"))); !d.Empty() {
		t.Fatalf("the same list is no change: %q", d.Changes)
	}
	// Writing out the default is no change either.
	def := cfg(t, base)
	if d := Classify(def, cfg(t, with("[/usr/bin, /bin, /usr/sbin, /sbin, /opt/homebrew/bin, /usr/local/bin]"))); !d.Empty() {
		t.Fatalf("the default written out is no change: %q", d.Changes)
	}
}

// Review: an envAllow name added while every rule blocks would never
// be shown later, when a rule opens the secret; it loosens at once.
func TestEnvAllowLoosensEvenWhileBlocked(t *testing.T) {
	closed := "secrets:\n  X:\n    deliver: [late-env]\n    rules:\n      - apps: [claude]\n        to: [{command: [npx, -y, x]}]\n        gate: block\n"
	d := Classify(cfg(t, base+closed), cfg(t, base+strings.Replace(closed, "    deliver: [late-env]\n", "    deliver: [late-env]\n    envAllow: [HTTPS_PROXY]\n", 1)))
	if !d.Loosens() || !strings.Contains(findingsText(d), "HTTPS_PROXY") {
		t.Fatalf("must loosen:\n%s", findingsText(d))
	}
}
