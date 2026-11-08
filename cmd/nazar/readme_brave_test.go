package main

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

// The README's Brave Search migration (secrets design 9.1, as
// built). Its config block must load as written with no warning, give the
// secret late-env only, and hand it only to the command line the
// ~/.claude.json entry runs, as the real CLI sends it (secrets design 6.3, D3).
func TestReadmeBraveMigration(t *testing.T) {
	b, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n## Secrets: an MCP server's key (Brave Search)\n")
	if start < 0 {
		t.Fatal("README has no Brave Search section")
	}
	text = text[start+1:]
	if end := strings.Index(text, "\n## "); end >= 0 {
		text = text[:end]
	}
	yamlBlock := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindStringSubmatch(text)
	jsonBlock := regexp.MustCompile("(?s)```jsonc\n(.*?)```").FindStringSubmatch(text)
	if yamlBlock == nil || jsonBlock == nil {
		t.Fatal("the section needs its yaml and jsonc blocks")
	}
	// The block is the whole entry (no other config needed, the claude
	// matcher inline): it must load with no problem at all, warnings
	// included ("no to:" would mean any node or python3 gets the key).
	body := "apiVersion: nazar/v1\nkind: Config\n" + yamlBlock[1]
	c, probs := config.Parse([]byte(body), config.Env{Home: t.TempDir()})
	if len(probs) != 0 {
		t.Fatalf("the README's config does not load cleanly:\n%v\n%s", probs, body)
	}
	if got := c.Deliver("BRAVE_API_KEY"); !slices.Equal(got, []config.Delivery{config.DeliverLateEnv}) {
		t.Fatalf("deliver %v", got)
	}
	if !strings.Contains(text, "Replace the rule step 1") {
		t.Fatal("step 3 must say to replace the rule `nazar secret add` wrote (no to:)")
	}
	var lines []string
	for _, l := range strings.Split(jsonBlock[1], "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "//") {
			lines = append(lines, l)
		}
	}
	var entry map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal([]byte("{"+strings.Join(lines, "\n")+"}"), &entry); err != nil {
		t.Fatal(err)
	}
	e := entry["brave-search"]
	if !strings.HasSuffix(e.Command, "/nazar") {
		t.Fatalf("command %q", e.Command)
	}
	// The entry's args, through the real CLI: the request names the
	// secret and the command line after --.
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.serveRun(t, func() control.RunPlan { return f.plan }, nil)
	h.run(e.Args...)
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].Args["name"] != "BRAVE_API_KEY" {
		t.Fatalf("the entry's args sent %+v (stderr %q)", reqs, h.errb.String())
	}
	var argv []string
	json.Unmarshal([]byte(reqs[0].Args["argv"]), &argv)
	// Every rule hands the key to that command line only.
	rules := c.Secrets["BRAVE_API_KEY"].Rules
	if len(rules) == 0 {
		t.Fatal("no rule")
	}
	for _, r := range rules {
		if len(r.To) != 1 || r.To[0].Kind != config.MatchCommand || !slices.Equal(r.To[0].Command, argv) {
			t.Fatalf("rule %s: to: must be the command the entry runs, %q", r.Canonical(), argv)
		}
	}
}
