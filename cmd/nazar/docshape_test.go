package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// The docs show config.yaml the one way it is written: a rule's apps: and
// to: are lists, even of one (spec 4.2). A YAML block whose rule writes one
// matcher on its own, or an inline `apps: x` / `to: {…}`, would teach a
// shape config check refuses.
func TestDocsWriteAppsAndToAsLists(t *testing.T) {
	files := []string{"../../README.md", "../../docs/GUIDE.md", "../../AGENTS.md", "../../docs/CLI.md", "../../docs/THREAT-MODEL.md", "../../skills/nazar/SKILL.md"}
	design, err := filepath.Glob("../../docs/design/*.md")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, design...)
	block := regexp.MustCompile("(?s)```ya?ml\n(.*?)```")
	inline := regexp.MustCompile("`(?:[^`\\n]*?[ {,-])?(?:apps|to): +[^\\[\\s`][^`\\n]*`")
	// The checker catches what it is for (and not the refusal reason).
	for s, want := range map[string]bool{"`apps: any`": true, "`- apps: claude, gate: none`": true, "`to: {command: [x]}`": true,
		"`apps: [any]`": false, "`- apps: [claude], to: [ssh]`": false, "`to: mismatch`": false} {
		if got := inline.MatchString(s) && !strings.Contains(s, "to: mismatch"); got != want {
			t.Fatalf("inline check of %s = %v", s, got)
		}
	}
	var sample yaml.Node
	if yaml.Unmarshal([]byte("rules:\n  - apps: iterm\n    to:\n      app: x\n    gate: login\n  - apps: [iterm]\n    gate: none\n"), &sample) != nil || len(singleForms(&sample)) != 2 {
		t.Fatal("the YAML check misses single forms")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, m := range block.FindAllStringSubmatch(text, -1) {
			var doc yaml.Node
			if yaml.Unmarshal([]byte(m[1]), &doc) != nil {
				continue // a fragment that is not YAML on its own
			}
			if bad := singleForms(&doc); len(bad) > 0 {
				t.Errorf("%s: a YAML block writes %s as one matcher, not a list:\n%s", f, strings.Join(bad, ", "), m[1])
			}
		}
		for _, s := range inline.FindAllString(text, -1) {
			if strings.Contains(s, "to: mismatch") { // a refusal reason, not config
				continue
			}
			t.Errorf("%s: %s writes apps:/to: as one matcher, not a list", f, s)
		}
	}
}

// singleForms names the apps:/to: values of rules (mappings with a gate:)
// that are not sequences.
func singleForms(n *yaml.Node) []string {
	var out []string
	if n.Kind == yaml.MappingNode {
		gate := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			gate = gate || n.Content[i].Value == "gate"
		}
		for i := 0; gate && i+1 < len(n.Content); i += 2 {
			if k := n.Content[i].Value; (k == "apps" || k == "to") && n.Content[i+1].Kind != yaml.SequenceNode {
				out = append(out, k)
			}
		}
	}
	for _, c := range n.Content {
		out = append(out, singleForms(c)...)
	}
	return out
}

// Nor does a YAML block in the docs teach what config check refuses since
// 2026-11-07: any in a to:, Apple's team in other than lower case, scope or
// expire next to gate none or block, expire next to scope use.
func TestDocsWriteNoOldForms(t *testing.T) {
	files := []string{"../../README.md", "../../docs/GUIDE.md", "../../AGENTS.md", "../../docs/CLI.md", "../../docs/THREAT-MODEL.md", "../../skills/nazar/SKILL.md"}
	design, err := filepath.Glob("../../docs/design/*.md")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile("(?s)```ya?ml\n(.*?)```")
	var sample yaml.Node
	if yaml.Unmarshal([]byte("rules:\n  - apps: [iterm]\n    to: [any]\n    gate: login\n  - apps: [{signed: {team: Apple}}]\n    gate: block\n    scope: app\n  - apps: [x]\n    gate: dialog\n    expire: 1h\n  - apps: [x]\n    scope: session\n    gate: dialog\n    expire: 1h\n"), &sample) != nil || len(oldForms(&sample)) != 4 {
		t.Fatalf("the check misses old forms: %v", oldForms(&sample))
	}
	for _, f := range append(files, design...) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range block.FindAllStringSubmatch(string(b), -1) {
			var doc yaml.Node
			if yaml.Unmarshal([]byte(m[1]), &doc) != nil {
				continue
			}
			if bad := oldForms(&doc); len(bad) > 0 {
				t.Errorf("%s: a YAML block writes %s:\n%s", f, strings.Join(bad, ", "), m[1])
			}
		}
	}
}

// oldForms names the old forms in n: a team spelled apple in another case
// anywhere, and in a mapping with a gate: (a rule, an entry, the fallback)
// any in to:, scope or expire next to none or block, expire without scope
// session or app.
func oldForms(n *yaml.Node) []string {
	var out []string
	if n.Kind == yaml.MappingNode {
		f := map[string]*yaml.Node{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			f[n.Content[i].Value] = n.Content[i+1]
		}
		if tm := f["team"]; tm != nil && tm.Value != "apple" && strings.EqualFold(tm.Value, "apple") {
			out = append(out, "team: "+tm.Value)
		}
		if g := f["gate"]; g != nil {
			if to := f["to"]; to != nil {
				for _, it := range to.Content {
					if it.Value == "any" {
						out = append(out, "to: [any]")
					}
				}
			}
			scope := ""
			if s := f["scope"]; s != nil {
				scope = s.Value
			}
			switch {
			case (g.Value == "none" || g.Value == "block") && (f["scope"] != nil || f["expire"] != nil):
				out = append(out, "scope/expire with gate: "+g.Value)
			case f["expire"] != nil && scope != "session" && scope != "app":
				out = append(out, "expire with scope: use")
			}
		}
	}
	for _, c := range n.Content {
		out = append(out, oldForms(c)...)
	}
	return out
}
