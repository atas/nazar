//go:build darwin && cgo

package codesign

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Milestone 6 (spec 4): a peer is known by its signature, never by where
// it runs from. Every bundle here is ad hoc (never a real identity).

// The same build copied to another folder (a Homebrew upgrade moves the
// agent into a new Caskroom version folder) is the same program: its
// designated requirement does not change, and a peer running from the copy
// satisfies the requirement read at the original path.
func TestSameSignatureAtAnotherPathIsTheSamePeer(t *testing.T) {
	dir := t.TempDir()
	orig := bundle(t, filepath.Join(dir, "0.1.0"), "nazar-agent", "dev.nazar.test")
	req, err := DesignatedRequirement(orig)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "0.2.0", "nazar-agent.app")
	if err := os.MkdirAll(filepath.Dir(copied), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/ditto", orig, copied).CombinedOutput(); err != nil {
		t.Fatalf("ditto: %v\n%s", err, out)
	}
	if again, err := DesignatedRequirement(copied); err != nil || again != req {
		t.Fatalf("the copy's requirement %q (%v), want the original's %q", again, err, req)
	}
	c, _ := listen(t, copied)
	if err := CheckPeer(token(t, c), req); err != nil {
		t.Fatalf("the same build at another path was refused: %v", err)
	}
}

// A program at the trusted path with another signature is another program:
// the bundle signed again in place (another identifier, so another cdhash)
// no longer satisfies the requirement read before.
func TestAnotherSignatureAtTheSamePathIsRefused(t *testing.T) {
	app := bundle(t, t.TempDir(), "nazar-agent", "dev.nazar.test")
	req, err := DesignatedRequirement(app)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "dev.nazar.test.other", app).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v\n%s", err, out)
	}
	if now, err := DesignatedRequirement(app); err != nil || now == req {
		t.Fatalf("re-signed bundle's requirement %q (%v) is still %q", now, err, req)
	}
	c, _ := listen(t, app)
	if err := CheckPeer(token(t, c), req); err == nil {
		t.Fatal("another signature at the trusted path satisfied the old requirement")
	}
}

// Ad-hoc code has no team: TeamID of an ad-hoc bundle and SelfTeamID of
// this (linker-signed) test binary are "", and a team requirement is never
// met by an ad-hoc peer, whatever its identifier.
func TestAdHocCodeHasNoTeam(t *testing.T) {
	app := bundle(t, t.TempDir(), "nazar-agent", "dev.nazar.agent")
	if team, err := TeamID(app); err != nil || team != "" {
		t.Fatalf("TeamID(ad-hoc bundle) = %q, %v; want \"\"", team, err)
	}
	if team, err := SelfTeamID(); err != nil || team != "" {
		t.Fatalf("SelfTeamID() = %q, %v; want \"\" for a go test binary", team, err)
	}
	req, err := TeamRequirement("dev.nazar.agent", "ABCDE12345")
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseRequirement(req); err != nil {
		t.Fatalf("TeamRequirement wrote text Security does not parse: %v", err)
	}
	c, _ := listen(t, app)
	if err := CheckPeer(token(t, c), req); err == nil {
		t.Fatal("an ad-hoc peer satisfied a team requirement")
	}
}

func TestTeamIDAndParseRefuse(t *testing.T) {
	dir := t.TempDir()
	if _, err := TeamID(""); err == nil {
		t.Error("TeamID(\"\") passed")
	}
	if _, err := TeamID(filepath.Join(dir, "missing")); err == nil {
		t.Error("TeamID of a missing file passed")
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := TeamID(plain); err == nil {
		t.Error("TeamID of unsigned code passed")
	}
	app := bundle(t, dir, "nazar-agent", "dev.nazar.test")
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := TeamID(app); err == nil {
		t.Error("TeamID of a bundle modified after signing passed")
	}
	for _, r := range []string{"", "anchor", `identifier "x" and`, "garbage("} {
		if ParseRequirement(r) == nil {
			t.Errorf("ParseRequirement(%q) passed", r)
		}
	}
}
