package configstage

import (
	"strings"
	"testing"
)

// aws design 7: an aws entry is classified like a k8s context (target
// aws:<name>; an entry absent from a config is one block slot), and on top
// any change to an ARN (adding them included) or to the identity loosens,
// as does a longer duration. An entry names no program that receives the
// credential (aws design 6.1: no client list).

const (
	anchorA  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
	anchorB  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/00000000-9abb-47c2-88b2-c734e0b29539"
	profileA = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
	roleA    = "arn:aws:iam::123456789012:role/dev"
)

// awsApps continues head's apps: mapping.
const awsApps = `  aws: {path: /usr/local/bin/aws}
  terraform: {signed: {team: TFTEAM0001}}
`

const awsIdentity = "  dev:\n    identity: {user: you-nazar}\n"

const awsARNs = "    trustAnchorArn: " + anchorA + "\n    profileArn: " + profileA + "\n    roleArn: " + roleA + "\n"

const awsBase = "aws:\n" + awsIdentity + awsARNs + `    duration: 30m
    gate: block
    rules:
      - apps: [claude]
        gate: block
      - apps: [iterm]
        scope: session
        gate: login
        expire: 8h
`

func TestClassifyAWS(t *testing.T) {
	const target = "aws:dev"
	old := cfg(t, awsApps+base+awsBase)
	if old.AWS["dev"] == nil {
		t.Fatal("precondition: aws: is parsed")
	}
	unconnected := strings.Replace(awsBase, awsARNs, "", 1)
	for _, tc := range []struct {
		name, old, body string
		loosens         bool
		why             string // in the findings when it loosens
	}{
		{"weaker gate", awsBase, strings.Replace(awsBase, "gate: login", "gate: dialog", 1), true, "(rule 2)"},
		{"narrower scope", awsBase, strings.Replace(awsBase, "scope: session\n        gate: login\n        expire: 8h", "scope: use\n        gate: login", 1), false, ""},
		{"own gate weakened", awsBase, strings.Replace(awsBase, "    gate: block\n    rules", "    gate: dialog\n    rules", 1), true, "(fallback)"},
		{"trust anchor changed", awsBase, strings.Replace(awsBase, anchorA, anchorB, 1), true, "ARNs changed: the credential would be minted through " + anchorB},
		{"role changed", awsBase, strings.Replace(awsBase, "role/dev", "role/admin", 1), true, "for arn:aws:iam::123456789012:role/admin"},
		{"connected", unconnected, awsBase, true, "ARNs changed"},
		{"disconnected", awsBase, unconnected, false, ""},
		{"identity changed", awsBase, strings.Replace(awsBase, "user: you-nazar", "user: root-nazar", 1), true, "identity changed: certificates would say CN=root-nazar"},
		{"longer duration", awsBase, strings.Replace(awsBase, "duration: 30m", "duration: 1h", 1), true, "sessions live longer: duration 30m0s → 1h0m0s"},
		{"shorter duration", awsBase, strings.Replace(awsBase, "duration: 30m", "duration: 15m", 1), false, ""},
		{"entry removed", awsBase, "", false, ""},
		// An entry added sets an identity from nothing, so it
		// loosens even when every slot blocks.
		{"a new entry that only blocks", awsBase, awsBase + "  prod:\n    identity: {user: you-nazar}\n    gate: block\n", true, "aws:prod: identity changed"},
	} {
		o := cfg(t, awsApps+base+tc.old)
		nw := cfg(t, awsApps+base+tc.body)
		d := Classify(o, nw)
		if d.Loosens() != tc.loosens || d.Empty() {
			t.Errorf("%s: loosens=%v empty=%v, want loosens=%v and a listed change:\n%s\n%q", tc.name, d.Loosens(), d.Empty(), tc.loosens, findingsText(d), d.Changes)
			continue
		}
		if tc.loosens && !strings.Contains(findingsText(d), tc.why) {
			t.Errorf("%s: the findings must say %q:\n%s", tc.name, tc.why, findingsText(d))
		}
		if tc.loosens && !strings.Contains(tc.name, "new entry") && !hasTarget(d, target) {
			t.Errorf("%s: the findings must name %s:\n%s", tc.name, target, findingsText(d))
		}
	}
	if d := Classify(old, old); !d.Empty() {
		t.Fatalf("self-diff: %+v", d)
	}
	// aws entries name no program that receives the credential: editing
	// apps.aws changes nothing for them.
	moved := strings.Replace(awsApps, "/usr/local/bin/aws", "/tmp/aws", 1)
	if d := Classify(old, cfg(t, moved+base+awsBase)); hasTarget(d, target) {
		t.Fatalf("apps.aws is nothing to an entry now: %s", findingsText(d))
	}
	// Even when every slot blocks, a changed ARN loosens.
	allBlock := strings.Replace(awsBase, "        scope: session\n        gate: login\n        expire: 8h\n", "        gate: block\n", 1)
	if d := Classify(cfg(t, awsApps+base+allBlock), cfg(t, awsApps+base+strings.Replace(allBlock, anchorA, anchorB, 1))); !d.Loosens() {
		t.Fatalf("an ARN change must loosen: %+v", d)
	}
}

// Malware with write access to config.yaml plants an aws entry for itself,
// or connects one: each is staged, never blessed as approved.
func TestPlantedAWSEntryIsStaged(t *testing.T) {
	unconnected := strings.Replace(awsBase, awsARNs, "", 1)
	for _, tc := range []struct{ name, before, after, change string }{
		{"planted", "", awsBase, "aws:dev: aws entry added"},
		{"connected", unconnected, awsBase, "aws:dev: ARNs none → trust anchor " + anchorA},
	} {
		s, v, _ := open(t)
		s.Observe(src(awsApps + base + tc.before))
		s.Approve("", yes)
		h := s.Active().Hash
		before, _ := v.Get(ApprovedVaultItem)
		r := s.Observe(src(awsApps + base + tc.after))
		if !r.Staged || r.Applied || !hasTarget(r.Diff, "aws:dev") {
			t.Fatalf("%s: must be staged: %+v", tc.name, r)
		}
		if !strings.Contains(strings.Join(r.Diff.Changes, "\n"), tc.change) {
			t.Fatalf("%s: the diff must say %q: %q", tc.name, tc.change, r.Diff.Changes)
		}
		if after, _ := v.Get(ApprovedVaultItem); s.Active().Hash != h || string(after) != string(before) {
			t.Fatalf("%s: the approved config must stay", tc.name)
		}
		// Removing the approved entry only tightens.
		if r := s.Observe(src(awsApps + base)); tc.before != "" && (!r.Applied || r.Staged) {
			t.Fatalf("%s: removing the entry applies at once: %+v", tc.name, r)
		}
	}
}
