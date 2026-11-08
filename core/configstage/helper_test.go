package configstage

import (
	"strings"
	"testing"
)

// Secrets design 4: a helper.git mapping names where git may be
// given the secret, so adding one or changing its host or username
// loosens when some request can get past the secret's rules; removing one
// tightens.
func TestClassifyHelperGit(t *testing.T) {
	const target = "secret:GH_TOKEN"
	withHelper := strings.Replace(secretBase, "    deliver: [helper]\n", "    deliver: [helper]\n    helper:\n      git: {host: github.com}\n", 1)
	old := cfg(t, base+secretBase)
	for _, tc := range []struct {
		name, from, to string
		loosens        bool
	}{
		{"helper added", secretBase, withHelper, true},
		{"host changed", withHelper, strings.Replace(withHelper, "host: github.com", "host: evil.example", 1), true},
		{"username added", withHelper, strings.Replace(withHelper, "{host: github.com}", "{host: github.com, username: atas}", 1), true},
		{"helper removed", withHelper, secretBase, false},
		{"every rule blocks", "secrets:\n  GH_TOKEN:\n    deliver: [helper]\n    gate: block\n",
			"secrets:\n  GH_TOKEN:\n    deliver: [helper]\n    gate: block\n    helper:\n      git: {host: github.com}\n", false},
	} {
		d := Classify(cfg(t, base+tc.from), cfg(t, base+tc.to))
		if d.Loosens() != tc.loosens || d.Empty() {
			t.Errorf("%s: loosens=%v empty=%v, want loosens=%v and a listed change:\n%s\n%q", tc.name, d.Loosens(), d.Empty(), tc.loosens, findingsText(d), d.Changes)
			continue
		}
		if tc.loosens && (!hasTarget(d, target) || !strings.Contains(findingsText(d), "can now answer git for https://")) {
			t.Errorf("%s: findings %s", tc.name, findingsText(d))
		}
	}
	if d := Classify(old, old); !d.Empty() {
		t.Fatalf("self-diff: %+v", d)
	}
	wh := cfg(t, base+withHelper)
	if d := Classify(wh, wh); !d.Empty() {
		t.Fatalf("self-diff with a helper: %+v", d)
	}
}
