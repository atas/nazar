package trust

import (
	"encoding/json"
	"testing"

	"github.com/atas/nazar/core/platform/fake"
)

// legacyState is the item an older version wrote: app pins and the
// binaries `nazar trust <path>` recorded for path: matchers, which are
// gone (spec 4.2).
const legacyState = `{"pins":{"com.googlecode.iterm2":"H7V7XYVQ7D"},` +
	`"paths":{"/opt/homebrew/bin/kubectl":{"path":"/opt/homebrew/bin/kubectl","resolved":"/opt/homebrew/Cellar/kubernetes-cli/1.34.0/bin/kubectl","cdhash":"qq==","trustedAt":"2026-10-04T00:00:00Z"}}}`

// An item with path records opens as before (no error, no prompt, no
// write): its pins are kept and its path records are ignored. The next
// change writes the pins alone, so the records go with it.
func TestLegacyPathRecordsAreIgnoredAndDropped(t *testing.T) {
	v := fake.NewVault()
	if err := v.Put(VaultItem, []byte(legacyState)); err != nil {
		t.Fatal(err)
	}
	s, err := Open(v)
	if err != nil {
		t.Fatalf("an item with path records must open: %v", err)
	}
	if team, ok := s.PinnedTeam("com.googlecode.iterm2"); !ok || team != "H7V7XYVQ7D" {
		t.Fatal("the pins must be kept")
	}
	if b, _ := v.Get(VaultItem); string(b) != legacyState {
		t.Fatal("opening must write nothing")
	}
	if d := OpenOrDegrade(v); d.Unreadable() != "" {
		t.Fatalf("not unreadable: %s", d.Unreadable())
	}
	if _, err := s.Pin("com.mitchellh.ghostty", "24VZTF6M5V"); err != nil {
		t.Fatal(err)
	}
	b, _ := v.Get(VaultItem)
	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["paths"]; ok || len(got) != 1 {
		t.Fatalf("a save must write the pins alone: %s", b)
	}
	s2, _ := Open(v)
	if len(s2.Pins()) != 2 {
		t.Fatalf("pins after the save: %v", s2.Pins())
	}
}
