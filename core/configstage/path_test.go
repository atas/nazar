package configstage

import (
	"bytes"
	"testing"

	"github.com/atas/nazar/core/platform/fake"
)

// A path: matcher is a matcher like signed: (spec 4.2, 4.8): adding one,
// or a rule with one, where a request could get a weaker policy than
// before is a loosening; removing one only tightens.
func TestClassifyPathMatcher(t *testing.T) {
	const hdr = "ssh_agent:\n  keys:\n    github:\n      rules:\n"
	const tool = "{path: /opt/homebrew/opt/mytool/bin/mytool}"
	const other = "{path: /opt/homebrew/opt/other/bin/other}"
	for name, tc := range map[string]struct {
		old, nw string
		loosens bool
	}{
		"a path: rule added": {
			old:     "        - {apps: [iterm], gate: login}\n",
			nw:      "        - {apps: [" + tool + "], gate: none}\n        - {apps: [iterm], gate: login}\n",
			loosens: true,
		},
		"a path: added beside an app": {
			old:     "        - {apps: [iterm], scope: session, gate: dialog}\n",
			nw:      "        - {apps: [iterm, " + tool + "], scope: session, gate: dialog}\n",
			loosens: true,
		},
		"a path: rule's gate weakened": {
			old:     "        - {apps: [" + tool + "], gate: login}\n",
			nw:      "        - {apps: [" + tool + "], gate: none}\n",
			loosens: true,
		},
		"a path: rule pointed at another file": {
			old:     "        - {apps: [" + tool + "], gate: dialog}\n",
			nw:      "        - {apps: [" + other + "], gate: dialog}\n",
			loosens: true,
		},
		"a path: rule removed": {
			old: "        - {apps: [" + tool + "], gate: none}\n        - {apps: [iterm], gate: login}\n",
			nw:  "        - {apps: [iterm], gate: login}\n",
		},
		"a path: removed beside an app": {
			old: "        - {apps: [iterm, " + tool + "], scope: session, gate: dialog}\n",
			nw:  "        - {apps: [iterm], scope: session, gate: dialog}\n",
		},
		"a path: rule's gate strengthened": {
			old: "        - {apps: [" + tool + "], gate: none}\n",
			nw:  "        - {apps: [" + tool + "], gate: login}\n",
		},
		"a path: rule that blocks, added": {
			old: "        - {apps: [iterm], gate: login}\n",
			nw:  "        - {apps: [" + tool + "], gate: block}\n        - {apps: [iterm], gate: login}\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := Classify(cfg(t, hdr+tc.old), cfg(t, hdr+tc.nw))
			if d.Loosens() != tc.loosens {
				t.Fatalf("loosens = %v, want %v: %s %q", d.Loosens(), tc.loosens, findingsText(d), d.Changes)
			}
		})
	}
}

// pathApproved is a config with a path: rule under none, as an older
// nazar-agent approved it while path: matched nothing.
var pathApproved = src("ssh_agent:\n  keys:\n    github:\n      rules:\n" +
	"        - {apps: [{path: /opt/homebrew/opt/mytool/bin/mytool}], gate: none}\n" +
	"        - {apps: [iterm], scope: session, gate: login}\n")

// Migration: a config approved while path: matched nothing (no
// PathsApprovedVaultItem naming it) must not start matching after the
// upgrade without the owner's approval. It stays in force with its path: matchers held back
// (the rest of it works: never bricked), the file with them is staged as
// a loosening, and once approved it stays approved across restarts.
func TestApprovedBeforePathMatchersNeedsApprovalAgain(t *testing.T) {
	v := fake.NewVault()
	if err := v.Put(ApprovedVaultItem, pathApproved); err != nil {
		t.Fatal(err)
	}
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := s.Active().SSHAgent.Keys["github"].Rules
	if len(rules) != 1 || rules[0].Apps[0].Name != "iterm" {
		t.Fatalf("the approved config must stay in force without its path: rule: %+v", rules)
	}
	r := s.Observe(pathApproved)
	if !r.Staged || r.Applied || !hasTarget(r.Diff, "ssh:github") {
		t.Fatalf("the same file must be staged, its path: rule a loosening: %+v", r)
	}
	if s.Active().HasPathMatchers() {
		t.Fatal("nothing may apply before the approval")
	}
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatalf("approve: %v %v", ok, err)
	}
	if !s.Active().HasPathMatchers() {
		t.Fatal("approved: the path: rule is in force")
	}
	if item, _ := v.Get(ApprovedVaultItem); !bytes.Equal(item, pathApproved) {
		t.Fatalf("the approved item is the file, byte for byte:\n%s", item)
	}
	if mark, err := v.Get(PathsApprovedVaultItem); err != nil || string(mark) != s.Active().Hash {
		t.Fatalf("the approval of path: matchers must be recorded for this config: %q %v", mark, err)
	}
	// A restart keeps it approved: same file, nothing staged.
	s2, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Active().HasPathMatchers() || !bytes.Equal(s2.Active().Raw, pathApproved) {
		t.Fatalf("after a restart the approved path: rule stays in force: %s", s2.Active().Raw)
	}
	if r := s2.Observe(pathApproved); r.Staged || r.Applied {
		t.Fatalf("the approved file again: nothing to do: %+v", r)
	}
}

// Held back, the old config still tightens at once: removing the path:
// rule, or the whole file, applies without approval.
func TestHeldPathConfigStillTightens(t *testing.T) {
	for name, nw := range map[string][]byte{
		"path: rule removed": src("ssh_agent:\n  keys:\n    github:\n      rules:\n        - {apps: [iterm], scope: session, gate: login}\n"),
		"file removed":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			v := fake.NewVault()
			if err := v.Put(ApprovedVaultItem, pathApproved); err != nil {
				t.Fatal(err)
			}
			s, err := Open(env, v, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r := s.Observe(nw); !r.Applied || r.Staged {
				t.Fatalf("a tightening must apply at once: %+v", r)
			}
			if !bytes.Equal(s.Active().Raw, nw) {
				t.Fatalf("active: %s", s.Active().Raw)
			}
			if _, err := v.Get(PathsApprovedVaultItem); err == nil {
				t.Fatal("no path: matcher approved, no record")
			}
		})
	}
}

// The fact that path: matchers were approved is never read from the
// config: a config.yaml a process wrote, which an older build saved as
// approved without a prompt (a new path: rule matched nothing there), is
// held whatever it says, a comment that looks like a marker included. So
// is one whose record names another config (an older build approved
// something else since).
func TestPathApprovalCannotBeForged(t *testing.T) {
	forged := append([]byte("# nazar: path: matchers approved\n"), pathApproved...)
	other := config0(t, pathApproved)
	for name, tc := range map[string]struct {
		item []byte
		mark string
	}{
		"a marker comment in the file":     {forged, ""},
		"a record of another config":       {pathApproved, config0(t, forged)},
		"a record, a marker, other config": {forged, other},
	} {
		t.Run(name, func(t *testing.T) {
			v := fake.NewVault()
			if err := v.Put(ApprovedVaultItem, tc.item); err != nil {
				t.Fatal(err)
			}
			if tc.mark != "" {
				if err := v.Put(PathsApprovedVaultItem, []byte(tc.mark)); err != nil {
					t.Fatal(err)
				}
			}
			s, err := Open(env, v, nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.Active().HasPathMatchers() {
				t.Fatal("the path: rule must be held until the owner approves it")
			}
			if r := s.Observe(tc.item); !r.Staged || r.Applied {
				t.Fatalf("the file must be staged: %+v", r)
			}
		})
	}
}

// config0 is the hash Parse gives b.
func config0(t *testing.T, b []byte) string {
	t.Helper()
	return cfgFull(t, string(b)).Hash
}

// A config without path: matchers is stored as it is, with no record.
func TestPathRecordOnlyWithPathMatchers(t *testing.T) {
	v := fake.NewVault()
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := src(base)
	if r := s.Observe(plain); !r.Staged {
		t.Fatalf("setup: %+v", r)
	}
	if ok, _ := s.Approve("", yes); !ok {
		t.Fatal("approve")
	}
	if item, _ := v.Get(ApprovedVaultItem); !bytes.Equal(item, plain) {
		t.Fatalf("a config without path: is stored unchanged:\n%s", item)
	}
	if _, err := v.Get(PathsApprovedVaultItem); err == nil {
		t.Fatal("no path: matcher, no record")
	}
}
