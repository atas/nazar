package configstage

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform/fake"
)

// K8s design 3, as built: a k8s context is classified like an ssh
// key, by the first-match proof over its rules and its fallback (target
// k8s:<name>; a context absent from a config is one block slot), and on top
// any change to its cluster, identity or credential loosens, as does a
// longer ttl_cert. k8s: is no longer an unvetted section.

const caA = "3f8c0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7"
const caB = "0000000000000000000000000000000000000000000000000000000000000001"

// k8sApps continues head's apps: mapping.
const k8sApps = `  kubectl: {path: /opt/homebrew/bin/kubectl}
  k9s: {signed: {team: K9STEAM001}}
`

const k8sBase = `k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      ttl_cert: 15m
      cluster:
        server: https://hydra.example:16443
        ca_sha256: ` + caA + `
      gate: block
      rules:
        - apps: [claude]
          gate: block
        - apps: [iterm]
          scope: session
          gate: login
          expire: 8h
`

func TestClassifyK8s(t *testing.T) {
	const target = "k8s:hydra"
	old := cfg(t, k8sApps+base+k8sBase)
	if len(old.Unimplemented) != 0 || old.K8s["hydra"] == nil {
		t.Fatalf("precondition: k8s: is parsed, not unimplemented: %v", old.Unimplemented)
	}
	for _, tc := range []struct {
		name, body string
		loosens    bool
		why        string // in the findings when it loosens
	}{
		{"weaker gate", strings.Replace(k8sBase, "gate: login", "gate: dialog", 1), true, "(rule 2)"},
		{"narrower scope", strings.Replace(k8sBase, "scope: session\n          gate: login\n          expire: 8h", "scope: use\n          gate: login", 1), false, ""},
		{"shorter expire", strings.Replace(k8sBase, "expire: 8h", "expire: 1h", 1), false, ""},
		{"the shadowing block rule removed", strings.Replace(k8sBase, "        - apps: [claude]\n          gate: block\n", "", 1), true, "requests that got gate=block (rule 1)"},
		{"own gate weakened", strings.Replace(k8sBase, "      gate: block\n", "      gate: dialog\n", 1), true, "(fallback)"},
		{"server re-pointed", strings.Replace(k8sBase, "https://hydra.example:16443", "https://evil.example:16443", 1), true, "cluster changed"},
		{"ca changed", strings.Replace(k8sBase, caA, caB, 1), true, "cluster changed"},
		{"tls server name added", strings.Replace(k8sBase, "        ca_sha256: "+caA+"\n", "        ca_sha256: "+caA+"\n        tls_server_name: x\n", 1), true, "cluster changed"},
		{"proxy added", strings.Replace(k8sBase, "        ca_sha256: "+caA+"\n", "        ca_sha256: "+caA+"\n        proxy_url: http://p:3128\n", 1), true, "cluster changed"},
		{"identity user changed", strings.Replace(k8sBase, "user: admin", "user: root", 1), true, "identity changed"},
		{"group added", strings.Replace(k8sBase, "[system:masters]", "[system:masters, devs]", 1), true, "identity changed"},
		{"group removed", strings.Replace(k8sBase, ", groups: [system:masters]", "", 1), true, "identity changed"},
		{"longer ttl_cert", strings.Replace(k8sBase, "ttl_cert: 15m", "ttl_cert: 30m", 1), true, "ttl_cert 15m0s → 30m0s"},
		{"shorter ttl_cert", strings.Replace(k8sBase, "ttl_cert: 15m", "ttl_cert: 5m", 1), false, ""},
		{"context removed", "", false, ""},
		// Security review: a context added sets a cluster and an identity
		// from nothing, so it loosens even when every slot blocks
		// (a later rule must not be the only thing a prompt shows).
		{"a new context that only blocks", k8sBase + "    staging:\n      credential: ca-cert\n      identity: {user: a}\n      cluster: {server: \"https://s.example\", ca_sha256: " + caA + "}\n      gate: block\n", true, "cluster changed: the credential would be minted for https://s.example"},
		{"a new context with a rule", k8sBase + "    staging:\n      credential: ca-cert\n      identity: {user: a}\n      cluster: {server: \"https://s.example\", ca_sha256: " + caA + "}\n      rules:\n        - apps: [iterm]\n          gate: login\n", true, "k8s:staging"},
	} {
		nw := cfg(t, k8sApps+base+tc.body)
		d := Classify(old, nw)
		if d.Loosens() != tc.loosens || d.Empty() {
			t.Errorf("%s: loosens=%v empty=%v, want loosens=%v and a listed change:\n%s\n%q", tc.name, d.Loosens(), d.Empty(), tc.loosens, findingsText(d), d.Changes)
			continue
		}
		if tc.loosens && !strings.Contains(findingsText(d), tc.why) {
			t.Errorf("%s: the findings must say %q:\n%s", tc.name, tc.why, findingsText(d))
		}
		if tc.loosens && !strings.Contains(tc.name, "new context") && !hasTarget(d, target) {
			t.Errorf("%s: the findings must name %s:\n%s", tc.name, target, findingsText(d))
		}
	}
	if d := Classify(old, old); !d.Empty() {
		t.Fatalf("self-diff: %+v", d)
	}
	// k8s contexts name no program that receives the credential (the
	// clients: list is gone): editing apps.kubectl changes nothing for them.
	moved := strings.Replace(k8sApps, "/opt/homebrew/bin/kubectl", "/tmp/kubectl", 1)
	if d := Classify(old, cfg(t, moved+base+k8sBase)); hasTarget(d, target) {
		t.Fatalf("apps.kubectl is nothing to a context now: %s", findingsText(d))
	}
	// Even when every slot blocks, a re-pointed cluster loosens (it is
	// never proved harmless).
	allBlock := strings.Replace(strings.Replace(k8sBase, "gate: login", "gate: block", 1), "          scope: session\n          gate: block\n          expire: 8h\n", "          gate: block\n", 1)
	blockOld := cfg(t, k8sApps+base+allBlock)
	if d := Classify(blockOld, cfg(t, k8sApps+base+strings.Replace(allBlock, caA, caB, 1))); !d.Loosens() {
		t.Fatalf("a cluster change must loosen: %+v", d)
	}
}

// Security review: removing a context tightens and applies at once;
// adding it back with every rule blocking must not then carry a new
// cluster or identity in silently, leaving a later rule edit as the
// only thing a prompt shows.
func TestReaddedK8sContextIsStaged(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(k8sApps + base + k8sBase))
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if r := s.Observe(src(k8sApps + base)); !r.Applied {
		t.Fatalf("removing the context applies at once: %+v", r)
	}
	readded := strings.NewReplacer(
		"https://hydra.example:16443", "https://evil.example:16443",
		"[system:masters]", "[system:masters, evil]",
		"          scope: session\n          gate: login\n          expire: 8h\n", "          gate: block\n",
	).Replace(k8sBase)
	r := s.Observe(src(k8sApps + base + readded))
	if !r.Staged || r.Applied {
		t.Fatalf("a context added back must be staged: %+v", r)
	}
	text := findingsText(r.Diff) + "\n" + strings.Join(r.Diff.Changes, "\n")
	for _, want := range []string{"evil.example", "O=evil", "ttl_cert"} {
		if !strings.Contains(text, want) {
			t.Errorf("the prompt must show %q:\n%s", want, text)
		}
	}
}

// The clients: list is gone (k8s design 2.1, "no client list"): any
// program the rules allow now receives the credential. A context that
// still has the line is off, never read as if the line were not there
// (that would loosen without a prompt), and the rest of the config stays
// in force: an approved config of an older version keeps its keys working.
// The file without the line is staged as the loosening it is.
func TestK8sLeftoverClientsLineTurnsTheContextOff(t *testing.T) {
	withClients := strings.Replace(k8sBase, "      gate: block\n", "      clients: [kubectl, helm, k9s]\n      gate: block\n", 1)
	// The approved config of an older version, with the line.
	v := fake.NewVault()
	if err := v.Put(ApprovedVaultItem, src(k8sApps+base+withClients)); err != nil {
		t.Fatal(err)
	}
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	approved := s.Active()
	if approved.K8s["hydra"] == nil || !approved.K8s["hydra"].LeftoverClients || len(approved.SSHAgent.Keys) == 0 {
		t.Fatalf("the approved config stays in force, its context off: %+v", approved.K8s["hydra"])
	}
	r := s.Observe(src(k8sApps + base + withClients))
	if r.Invalid || r.Staged || s.Active().Hash != approved.Hash {
		t.Fatalf("the same file changes nothing: %+v", r)
	}
	want := "k8s.contexts.hydra.clients: " + config.K8sClientsGone
	if !strings.Contains(r.Problems.Error(), want) || r.Problems.HasErrors() {
		t.Fatalf("a warning naming the fix %q: %v", want, r.Problems)
	}
	// The line removed: staged as a loosening of k8s:hydra, applied on approval.
	r = s.Observe(src(k8sApps + base + k8sBase))
	if !r.Staged || r.Applied || !r.Diff.Loosens() || !hasTarget(r.Diff, "k8s:hydra") || !strings.Contains(findingsText(r.Diff), "clients: line removed") {
		t.Fatalf("the file without clients: must be staged as loosening: %+v\n%s", r, findingsText(r.Diff))
	}
	if s.Active().Hash != approved.Hash {
		t.Fatal("staged, not applied")
	}
	if ok, err := s.Approve("", yes); !ok || err != nil || s.Active().K8s["hydra"].LeftoverClients {
		t.Fatal("approved, the context is on", ok, err)
	}
	// The line added back turns it off again at once (a tightening).
	if r := s.Observe(src(k8sApps + base + withClients)); !r.Applied || !s.Active().K8s["hydra"].LeftoverClients {
		t.Fatalf("clients: added back applies at once, the context off: %+v", r)
	}
}

// Until M12 every edit to a file carrying k8s: needed the login gate.
// Now a tightening elsewhere applies at once.
func TestTighteningBesideK8sAppliesAtOnce(t *testing.T) {
	tightBase := strings.Replace(base, "gate: dialog", "gate: login", 1)
	d := Classify(cfg(t, k8sApps+base+k8sBase), cfg(t, k8sApps+tightBase+k8sBase))
	if d.Loosens() || d.Empty() || strings.Contains(strings.Join(d.Changes, "\n"), "not checked by this version") {
		t.Fatalf("a tightening beside k8s: must apply at once: %+v", d)
	}
	s, _, _ := open(t)
	s.Observe(src(k8sApps + base + k8sBase))
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if r := s.Observe(src(k8sApps + tightBase + k8sBase)); !r.Applied || r.Staged {
		t.Fatalf("must apply at once: %+v", r)
	}
}

// The config-write attack, judged by meaning: malware with write access to
// config.yaml plants a context for itself, or re-points an approved one.
// (This replaces the k8s: case of TestClassifyUnimplementedSectionNeedsApproval,
// which tests the unvetted guard itself since k8s: is built, and goes
// further than TestUnimplementedSectionIsStagedNotApproved, which runs its
// sequence on a planted context now.)
func TestPlantedK8sContextIsStagedNotApproved(t *testing.T) {
	const planted = `    evil:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + caA + `}
      rules:
        - apps: [{signed: {team: EVILTEAM00}}]
          gate: none
`
	s, v, _ := open(t)
	s.Observe(src(k8sApps + base + k8sBase))
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	h := s.Active().Hash
	before, _ := v.Get(ApprovedVaultItem)
	for name, body := range map[string]string{
		"a planted silent context": k8sBase + planted,
		"a re-pointed cluster":     strings.Replace(k8sBase, caA, caB, 1),
		"a widened identity":       strings.Replace(k8sBase, "user: admin", "user: system:admin", 1),
	} {
		r := s.Observe(src(k8sApps + base + body))
		if !r.Staged || r.Applied || r.Invalid || !r.Diff.Loosens() {
			t.Fatalf("%s: must be staged: %+v\n%s", name, r, findingsText(r.Diff))
		}
		if s.Active().Hash != h {
			t.Fatalf("%s: the approved config must stay active", name)
		}
		if after, err := v.Get(ApprovedVaultItem); err != nil || string(after) != string(before) {
			t.Fatalf("%s: the vault must still hold the approved config: %v", name, err)
		}
		// Restarted, the planted file is still not the baseline.
		s2, err := Open(env, v, nil)
		if err != nil || s2.Active().Hash != h {
			t.Fatalf("%s: restart must start from the approved config: %v", name, err)
		}
		if r := s2.Observe(src(k8sApps + base + body)); !r.Staged || r.Applied {
			t.Fatalf("%s: found at restart, it must be staged again: %+v", name, r)
		}
	}
	if r := s.Observe(src(k8sApps + base + k8sBase + planted)); !hasTarget(r.Diff, "k8s:evil") || !strings.Contains(findingsText(r.Diff), "gate=none") {
		t.Fatalf("the planted context must be named: %s", findingsText(r.Diff))
	}
	// What this version does not build can't be planted to work later.
	for _, later := range []string{
		strings.Replace(planted, "credential: ca-cert", "credential: stored", 1),
		strings.Replace(planted, "      credential: ca-cert\n", "      credential: ca-cert\n      ttl: 1h\n", 1),
	} {
		if r := s.Observe(src(k8sApps + base + k8sBase + later)); !r.Invalid || s.Active().Hash != h {
			t.Fatalf("must be invalid: %+v", r)
		}
	}
}

// An app: matcher in a k8s rule matches only a pinned team, so the approval
// that adds it must pin it, as for a key's rule.
func TestK8sRuleAppMatchersArePinned(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	r := pe.s.Observe(src(k8sApps + "k8s:\n  contexts:\n    hydra:\n      credential: ca-cert\n      identity: {user: a}\n      cluster: {server: \"https://hydra.example\", ca_sha256: " + caA + "}\n      rules:\n        - apps: [iterm]\n          gate: login\n"))
	if !r.Staged {
		t.Fatalf("a new login rule must be staged: %+v", r)
	}
	if p, ok := pinFor(r.Diff, itermID); !ok || p.Team != itermTm {
		t.Fatalf("the k8s rule's app: matcher must be pinned: %+v", r.Diff.Pins)
	}
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if team, ok := pe.pin(itermID); !ok || team != itermTm {
		t.Fatalf("approval must record the pin: %q %v", team, ok)
	}
}

// The unvetted guard stays for a section a later version may leave
// unimplemented again: tested on a config whose Unimplemented is set by hand.
func TestUnvettedGuardStillHolds(t *testing.T) {
	old := cfg(t, base)
	nw := cfg(t, strings.Replace(base, "gate: dialog", "gate: login", 1))
	nw.Unimplemented = []string{"later"}
	d := Classify(old, nw)
	if !d.Loosens() || !hasTarget(d, "later") || !strings.Contains(strings.Join(d.Changes, "\n"), "later: section added") {
		t.Fatalf("a file carrying an unvetted section must need approval: %+v", d)
	}
}
