//go:build linux

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The agent refuses to run as root before it looks anything up: polkit
// approves root without asking, so no gate would mean anything, and the
// keys would be made in root's name.
func TestAgentRefusesRoot(t *testing.T) {
	defer func(u func() int, h func(int) (string, error)) { getuid, lookupHome = u, h }(getuid, lookupHome)
	getuid = func() int { return 0 }
	lookupHome = func(int) (string, error) {
		t.Error("the home was looked up for root")
		return "", errors.New("no")
	}
	var stderr bytes.Buffer
	if code := agentMain(&stderr); code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", code, stderr.String())
	}
	if got := stderr.String(); !strings.HasPrefix(got, "nazar-agent: ") || !strings.Contains(got, "root") {
		t.Fatalf("stderr %q does not say it refuses root", got)
	}
}
