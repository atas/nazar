package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
)

// The skill's config.yaml reference loads as written: every field it
// shows is one nazar accepts. Warnings are allowed; errors are not.
func TestSkillConfigReferenceLoads(t *testing.T) {
	b, err := os.ReadFile("../../skills/nazar/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n## config.yaml reference\n")
	if start < 0 {
		t.Fatal("SKILL.md has no config.yaml reference")
	}
	m := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindStringSubmatch(text[start:])
	if m == nil {
		t.Fatal("the reference has no yaml block")
	}
	_, probs := config.Parse([]byte(m[1]), config.Env{Home: t.TempDir()})
	for _, p := range probs {
		if p.Severity != config.SevWarning {
			t.Errorf("SKILL.md's config reference: %v", p)
		}
	}
}
