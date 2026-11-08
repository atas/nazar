package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
)

// The short README's example config loads as written. Warnings are allowed
// ("no to:" for the secret, kept out to keep it short); errors are not.
func TestReadmeExampleConfigLoads(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n## Config\n")
	if start < 0 {
		t.Fatal("README has no Config section")
	}
	m := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindStringSubmatch(text[start:])
	if m == nil {
		t.Fatal("the Config section has no yaml block")
	}
	c, probs := config.Parse([]byte(m[1]), config.Env{Home: t.TempDir()})
	for _, p := range probs {
		if p.Severity != config.SevWarning {
			t.Errorf("the README's config: %v", p)
		}
	}
	if c == nil {
		t.Fatalf("the README's config does not load:\n%v", probs)
	}
}
