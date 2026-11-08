package configstage

import (
	"bytes"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform/fake"
)

// openWith opens a stager on a vault whose approved item is item.
func openWith(t *testing.T, item []byte) (*Stager, *fake.Vault) {
	t.Helper()
	v := fake.NewVault()
	v.Put(ApprovedVaultItem, item)
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

// An approved config with scope or expire that did nothing, or to: [any]
// where no to: means the same, stays approved: Open drops them from the
// vault item (no prompt: the same meaning), so the file Migrate rewrites
// the same way is the approved config.
func TestApprovedConfigLosesWhatMeantNothing(t *testing.T) {
	item := src(`ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          to: [any]
          gate: none
          expire: 8h
        - apps: [iterm]
          gate: dialog
          expire: 1h
      scope: app
      gate: block
secrets:
  T:
    rules:
      - apps: [iterm]
        to: [any]
        scope: session
        gate: dialog
`)
	if _, probs := config.Parse(item, env); !probs.HasErrors() {
		t.Fatal("the fixture parses strictly: this test would prove nothing")
	}
	want := migrated(t, item)
	s, v := openWith(t, item)
	if !bytes.Equal(s.Active().Raw, want) || len(s.Active().SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatalf("active:\n%s", s.Active().Raw)
	}
	if got, _ := v.Get(ApprovedVaultItem); !bytes.Equal(got, want) {
		t.Fatalf("the vault item is not the rewrite:\n%s", got)
	}
	if r := s.Observe(want); r.Staged || r.Applied || r.Invalid {
		t.Fatalf("the rewritten file is the approved config: %+v", r)
	}
	if r := s.Observe(item); !r.Invalid {
		t.Fatalf("the old forms are config errors now: %+v", r)
	}
	// Classify agrees that the rewrite changes nothing that matters.
	old, _ := config.ParseApproved(item, env)
	if d := Classify(old, s.Active()); d.Loosens() {
		t.Fatalf("the rewrite loosens: %s", findingsText(d))
	}
}

// An approved config with a team spelled Apple (which matches nothing) or
// to: [any] on a key's rule that remembers approvals (which ties them to
// the receiver) has no rewrite of the same meaning: Open leaves the vault
// item as it is and keeps it in force, read as before, so no key falls to
// the built-in default; the same bytes in config.yaml are invalid (the
// error says what to do) and change nothing. Writing apple loosens (it
// matches Apple's programs), and so does removing to: [any] from a rule
// that remembers approvals (one approval then covers every receiver in
// the session): each waits for the gate. Blocking the rule tightens.
func TestApprovedConfigWithoutRewriteStaysInForce(t *testing.T) {
	for name, tc := range map[string]struct{ rule, why, fixed, loosened string }{
		"team Apple": {
			"        - apps: [{signed: {team: Apple, id: com.apple.openssh}}]\n          gate: dialog\n",
			`"Apple" matches nothing`,
			"        - apps: [iterm]\n          gate: block\n",
			"        - apps: [{signed: {team: apple, id: com.apple.openssh}}]\n          gate: dialog\n",
		},
		"to any, remembered": {
			"        - apps: [iterm]\n          to: [any]\n          scope: session\n          gate: dialog\n",
			"any in to: is the same as no to:",
			"        - apps: [iterm]\n          gate: block\n",
			"        - apps: [iterm]\n          scope: session\n          gate: dialog\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := "ssh_agent:\n  keys:\n    github:\n      rules:\n" + tc.rule + "      gate: block\n"
			item := src(body)
			if _, ok := config.Migrate(item, env); ok {
				t.Fatal("migrated")
			}
			s, v := openWith(t, item)
			if !bytes.Equal(s.Active().Raw, item) || len(s.Active().SSHAgent.Keys["github"].Rules) != 1 {
				t.Fatalf("the approved config is not in force:\n%s", s.Active().Raw)
			}
			if got, _ := v.Get(ApprovedVaultItem); !bytes.Equal(got, item) {
				t.Fatalf("the vault item changed:\n%s", got)
			}
			r := s.Observe(item)
			if !r.Invalid || !strings.Contains(r.Problems.Error(), tc.why) {
				t.Fatalf("the file must be invalid with %q: %+v", tc.why, r)
			}
			if !bytes.Equal(s.Active().Raw, item) {
				t.Fatal("the invalid file changed what is in force")
			}
			if r := s.Observe(src(strings.Replace(body, tc.rule, tc.loosened, 1))); !r.Staged || r.Applied {
				t.Fatalf("the change loosens: it must wait for the gate: %+v", r)
			}
			if r := s.Observe(src(strings.Replace(body, tc.rule, tc.fixed, 1))); !r.Applied {
				t.Fatalf("the fix tightens: %+v\n%s", r, findingsText(r.Diff))
			}
		})
	}
}

// Old forms that have a rewrite, next to one that has none: the vault item
// gets the rewrite, which keeps the one with none, and stays in force.
func TestApprovedConfigPartlyRewritten(t *testing.T) {
	item := src("ssh_agent:\n  keys:\n    github:\n      rules:\n        - apps: {signed: {team: Apple}}\n          gate: dialog\n      scope: app\n      gate: block\n")
	want := migrated(t, item)
	if !strings.Contains(string(want), "team: Apple") {
		t.Fatalf("rewrite:\n%s", want)
	}
	s, v := openWith(t, item)
	if !bytes.Equal(s.Active().Raw, want) {
		t.Fatalf("active:\n%s", s.Active().Raw)
	}
	if got, _ := v.Get(ApprovedVaultItem); !bytes.Equal(got, want) {
		t.Fatalf("vault item:\n%s", got)
	}
	if s2, _ := Open(env, v, nil); !bytes.Equal(s2.Active().Raw, want) {
		t.Fatal("second start")
	}
}
