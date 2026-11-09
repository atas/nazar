package configstage

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/platform/fake"
)

// Secrets design 4: a secrets entry is classified like an ssh key,
// by the first-match proof over its rules and its fallback (target
// secret:<NAME>), and its deliver: list on top: a method added loosens when
// some request can get past the new rules, one removed tightens. secrets:
// is no longer an unvetted section.

const gitHTTPS = "{signed: {team: apple, id: com.apple.git-remote-http}}"

// secretBase: claude is blocked first; iTerm2 may hand GH_TOKEN to git's
// HTTPS transport after a login.
const secretBase = `secrets:
  GH_TOKEN:
    deliver: [helper]
    rules:
      - apps: [claude]
        gate: block
      - apps: [iterm]
        to: [` + gitHTTPS + `]
        scope: session
        gate: login
`

func TestClassifySecrets(t *testing.T) {
	const target = "secret:GH_TOKEN"
	old := cfg(t, base+secretBase)
	if len(old.Unimplemented) != 0 || old.Secrets["GH_TOKEN"] == nil {
		t.Fatalf("precondition: secrets: is parsed, not unimplemented: %v", old.Unimplemented)
	}
	for _, tc := range []struct {
		name, body string
		loosens    bool
		why        string // in the findings when it loosens
	}{
		{"weaker gate", strings.Replace(secretBase, "gate: login", "gate: dialog", 1), true, "(rule 2)"},
		{"narrower scope", strings.Replace(secretBase, "scope: session", "scope: use", 1), false, ""},
		{"the shadowing block rule removed", strings.Replace(secretBase, "      - apps: [claude]\n        gate: block\n", "", 1), true, "requests that got gate=block (rule 1)"},
		{"stdout added", strings.Replace(secretBase, "[helper]", "[helper, stdout]", 1), true, "can now be delivered by stdout"},
		{"deliver: dropped, so the default adds stdout", strings.Replace(secretBase, "    deliver: [helper]\n", "", 1), true, "can now be delivered by stdout"},
		{"a bare new entry", secretBase + "  NEW:\n", false, ""},
		{"a new entry that only blocks", secretBase + "  NEW: {gate: block}\n", false, ""},
		{"the entry removed", "", false, ""},
		{"every rule blocks, stdout added", "secrets:\n  GH_TOKEN:\n    deliver: [helper, stdout]\n    rules:\n      - apps: [claude]\n        gate: block\n", false, ""},
	} {
		d := Classify(old, cfg(t, base+tc.body))
		if d.Loosens() != tc.loosens || d.Empty() {
			t.Errorf("%s: loosens=%v empty=%v, want loosens=%v and a listed change:\n%s\n%q", tc.name, d.Loosens(), d.Empty(), tc.loosens, findingsText(d), d.Changes)
			continue
		}
		if tc.loosens && (!hasTarget(d, target) || !strings.Contains(findingsText(d), tc.why)) {
			t.Errorf("%s: the findings must name %s and say %q:\n%s", tc.name, target, tc.why, findingsText(d))
		}
	}
	if d := Classify(old, old); !d.Empty() {
		t.Fatalf("self-diff: %+v", d)
	}
}

// Until M8 every edit to a file carrying secrets: needed the login
// gate. Now a tightening elsewhere applies at once.
func TestTighteningBesideSecretsAppliesAtOnce(t *testing.T) {
	tightBase := strings.Replace(base, "gate: dialog", "gate: login", 1)
	d := Classify(cfg(t, base+secretBase), cfg(t, tightBase+secretBase))
	if d.Loosens() || d.Empty() || strings.Contains(strings.Join(d.Changes, "\n"), "not checked by this version") {
		t.Fatalf("a tightening beside secrets: must apply at once: %+v", d)
	}
	s, _, _ := open(t)
	s.Observe(src(base + secretBase))
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if r := s.Observe(src(tightBase + secretBase)); !r.Applied || r.Staged {
		t.Fatalf("must apply at once: %+v", r)
	}
}

// The config-write attack, now judged by meaning: malware with write access to
// config.yaml plants a silent rule for itself under secrets:.
func TestPlantedSecretRuleIsStagedNotApproved(t *testing.T) {
	const planted = `secrets:
  BRAVE_API_KEY:
    deliver: [helper]
    rules:
      - apps: [{signed: {team: EVILTEAM00}}]
        gate: none
`
	s, v, _ := open(t)
	s.Observe(src(base))
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	h := s.Active().Hash
	before, _ := v.Get(ApprovedVaultItem)

	r := s.Observe(src(base + planted))
	if !r.Staged || r.Applied || r.Invalid || !hasTarget(r.Diff, "secret:BRAVE_API_KEY") || !strings.Contains(findingsText(r.Diff), "gate=none") {
		t.Fatalf("a planted silent rule must be staged and shown: %+v\n%s", r, findingsText(r.Diff))
	}
	if s.Active().Hash != h {
		t.Fatal("the approved config must stay active")
	}
	if after, err := v.Get(ApprovedVaultItem); err != nil || string(after) != string(before) {
		t.Fatalf("the vault must still hold the approved config: %v", err)
	}
	// With the default deliver (stdout included), or late-env, it is staged
	// the same way: nothing is delivered until the user approves it.
	for _, silent := range []string{
		strings.Replace(planted, "    deliver: [helper]\n", "", 1),
		strings.Replace(planted, "[helper]", "[late-env]", 1),
	} {
		r = s.Observe(src(base + silent))
		if !r.Staged || r.Applied || r.Invalid || !strings.Contains(findingsText(r.Diff), "gate=none") || s.Active().Hash != h {
			t.Fatalf("a planted silent rule must be staged and shown: %+v", r)
		}
	}
	// A method a later version builds can't be planted now, and envAllow
	// never names a variable that loads code.
	for later, why := range map[string]string{
		strings.Replace(planted, "[helper]", "[env]", 1): "not in this version",
		strings.Replace(planted, "    deliver: [helper]\n", "    deliver: [helper, late-env]\n    envAllow: [NODE_OPTIONS]\n", 1): "NODE_OPTIONS can never be passed",
	} {
		if r := s.Observe(src(base + later)); !r.Invalid || !strings.Contains(r.Problems.Error(), why) || s.Active().Hash != h {
			t.Fatalf("must be invalid (%s): %+v", why, r)
		}
	}
}

// An app: matcher in a secret's rule matches only a pinned team, so the
// approval that adds it must pin it, as for a key's rule.
func TestSecretRuleAppMatchersArePinned(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	r := pe.s.Observe(src("secrets:\n  GH_TOKEN:\n    rules:\n      - apps: [iterm]\n        to: [" + gitHTTPS + "]\n        gate: login\n"))
	if !r.Staged {
		t.Fatalf("a new login rule must be staged: %+v", r)
	}
	if p, ok := pinFor(r.Diff, itermID); !ok || p.Team != itermTm {
		t.Fatalf("the secret rule's app: matcher must be pinned: %+v", r.Diff.Pins)
	}
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if team, ok := pe.pin(itermID); !ok || team != itermTm {
		t.Fatalf("approval must record the pin: %q %v", team, ok)
	}
}
