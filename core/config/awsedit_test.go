package config

import (
	"strings"
	"testing"
	"time"
)

// The entry `nazar aws ca create` writes (identity, its own gate block and
// the terminal's login rule; no ARNs: the user adds them once AWS is set
// up), the removal `nazar aws forget` makes, and rule edits on an entry.

func TestAddAWSEntry(t *testing.T) {
	src := "apiVersion: nazar/v1\nkind: Config\n# mine\napps:\n  iterm: {app: com.googlecode.iterm2}  # keep\n"
	rule := RuleSpec{Apps: []string{"app:com.googlecode.iterm2"}, Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}
	out, err := AddAWSEntry([]byte(src), AWSEntrySpec{Name: "dev", Identity: AWSIdentity{User: "you-nazar"}, Rule: &rule})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# mine") || !strings.Contains(string(out), "# keep") {
		t.Fatalf("comments lost:\n%s", out)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() {
		t.Fatalf("%s\n%s", probs.Error(), out)
	}
	e := c.AWS["dev"]
	if e == nil || e.Identity.User != "you-nazar" || e.Connected() || e.Duration != DefaultAWSDuration ||
		e.Own == nil || e.Own.Gate != GateBlock || strings.Contains(string(out), "clients") {
		t.Fatalf("%+v\n%s", e, out)
	}
	if _, ok := c.Apps["aws"]; ok {
		t.Fatalf("no apps.aws is written:\n%s", out)
	}
	if len(e.Rules) != 1 || e.Rules[0].Apps[0].ID != "com.googlecode.iterm2" || e.Rules[0].Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) {
		t.Fatalf("rules %+v", e.Rules)
	}
	// Without a terminal: the block alone; beside another entry.
	two, err := AddAWSEntry(out, AWSEntrySpec{Name: "prod", Identity: AWSIdentity{User: "you-nazar"}})
	if err != nil {
		t.Fatal(err)
	}
	if c, probs := Parse(two, env); probs.HasErrors() || c.AWS["dev"] == nil || c.AWS["prod"] == nil || len(c.AWS["prod"].Rules) != 0 {
		t.Fatalf("%v\n%s", probs, two)
	}
	for name, tc := range map[string]struct {
		src  string
		spec AWSEntrySpec
	}{
		"exists":         {src + "aws:\n  DEV: {identity: {user: a}}\n", AWSEntrySpec{Name: "dev", Identity: AWSIdentity{User: "a"}}},
		"aws a list":     {src + "aws: []\n", AWSEntrySpec{Name: "dev", Identity: AWSIdentity{User: "a"}}},
		"invalid name":   {src, AWSEntrySpec{Name: "a/b", Identity: AWSIdentity{User: "a"}}},
		"no identity":    {src, AWSEntrySpec{Name: "dev"}},
		"long identity":  {src, AWSEntrySpec{Name: "dev", Identity: AWSIdentity{User: strings.Repeat("a", 62)}}},
		"not a document": {"- a\n", AWSEntrySpec{Name: "dev", Identity: AWSIdentity{User: "a"}}},
	} {
		if out, err := AddAWSEntry([]byte(tc.src), tc.spec); err == nil {
			t.Errorf("%s: want an error, got\n%s", name, out)
		}
	}
}

func TestRemoveAWSEntry(t *testing.T) {
	src := awsDev("") + "  # the other\n  prod:\n    identity: {user: you-nazar}\n"
	out, err := RemoveAWSEntry([]byte(src), "dev")
	if err != nil {
		t.Fatal(err)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() || c.AWS["dev"] != nil || c.AWS["prod"] == nil {
		t.Fatalf("%v\n%s", probs, out)
	}
	if _, err := RemoveAWSEntry([]byte(src), "nope"); err == nil {
		t.Fatal("removing an absent entry is an error")
	}
	if _, err := RemoveAWSEntry([]byte(src), "DEV"); err == nil {
		t.Fatal("names are exact")
	}
	if _, err := RemoveAWSEntry([]byte(awsApps), "dev"); err == nil {
		t.Fatal("no aws section")
	}
}

func TestAWSRuleEdits(t *testing.T) {
	e := AWSRef("dev")
	if !e.IsAWS() || e.IsK8s() || e.IsKey() || e.IsSecret() || e.String() != "aws.dev" {
		t.Fatalf("%+v %s", e, e)
	}
	src := []byte(awsDev("    gate: block\n"))
	out, err := AddRule(src, e, RuleSpec{Apps: []string{"iterm"}, Scope: ScopeSession, Gate: GateLogin}, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() || len(c.AWS["dev"].Rules) != 1 || c.AWS["dev"].RoleArn != awsRole {
		t.Fatalf("%v\n%s", probs, out)
	}
	if out, err = SetRule(out, e, 1, RulePatch{Gate: ptr(GateDialog)}); err != nil {
		t.Fatal(err)
	}
	if c, _ := Parse(out, env); c.AWS["dev"].Rules[0].Policy.Gate != GateDialog {
		t.Fatalf("%s", out)
	}
	if out, err = RemoveRule(out, e, 1); err != nil {
		t.Fatal(err)
	}
	if c, _ := Parse(out, env); len(c.AWS["dev"].Rules) != 0 || c.AWS["dev"].Own.Gate != GateBlock {
		t.Fatalf("%s", out)
	}
	// No to:, and never an entry made by a rule edit.
	if _, err := AddRule(src, e, RuleSpec{Apps: []string{"iterm"}, To: []string{"aws"}, Gate: GateLogin}, 0); err == nil || !strings.Contains(err.Error(), "aws rules take no to") {
		t.Fatalf("to: %v", err)
	}
	to := []string{"aws"}
	if _, err := SetRule(src, e, 1, RulePatch{To: &to}); err == nil {
		t.Fatal("set to:")
	}
	if _, err := AddRule([]byte(awsApps), e, RuleSpec{Apps: []string{"iterm"}, Gate: GateLogin}, 0); err == nil || !strings.Contains(err.Error(), "there is no aws.dev") {
		t.Fatalf("created: %v", err)
	}
	if _, err := AddRule(src, AWSRef("a/b"), RuleSpec{Apps: []string{"iterm"}, Gate: GateLogin}, 0); err == nil {
		t.Fatal("invalid name")
	}
}
