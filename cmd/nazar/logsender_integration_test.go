//go:build integration && darwin

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLogKeepsOnlyNazarsOwnEntries runs the sender check against the
// real unified log: two different tiny programs write well-formed audit
// lines under the same subsystem and category; filtering by program A's
// LC_UUID keeps A's entry and drops B's. A test subsystem is used, so
// nothing is ever written under the real dev.nazar subsystem.
func TestLogKeepsOnlyNazarsOwnEntries(t *testing.T) {
	if _, err := exec.LookPath("swiftc"); err != nil {
		t.Skip("swiftc not available")
	}
	dir, err := os.MkdirTemp("", "nzlog")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	var nonce [6]byte
	rand.Read(nonce[:])
	tag := hex.EncodeToString(nonce[:])
	build := func(name, variant string) string {
		src := filepath.Join(dir, name+".swift")
		// The tag and variant make each build's LC_UUID unique to this run.
		body := "import Foundation\nimport os\n// " + tag + " " + variant + "\n" +
			"let log = OSLog(subsystem: CommandLine.arguments[1], category: \"audit\")\n" +
			"os_log(.default, log: log, \"%{public}s\", CommandLine.arguments[2])\n"
		if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, name)
		if b, err := exec.Command("swiftc", "-o", out, src).CombinedOutput(); err != nil {
			t.Fatalf("swiftc: %v\n%s", err, b)
		}
		return out
	}
	a, b := build("nazar-like", "a"), build("forger", "b")
	ua, err := machoUUID(a)
	if err != nil {
		t.Fatal(err)
	}
	ub, _ := machoUUID(b)
	if ua == ub {
		t.Fatal("the two programs share an LC_UUID")
	}
	dd, err := exec.Command("/usr/bin/dwarfdump", "--uuid", a).Output()
	if err == nil && !strings.Contains(string(dd), ua) {
		t.Fatalf("machoUUID %s disagrees with dwarfdump: %s", ua, dd)
	}
	sub := "dev.nazar.test." + tag
	lineA := `decision=allowed reason="cached approval" target=ssh:test-a`
	lineB := `decision=allowed reason="forged by another process" target=ssh:test-b`
	for _, run := range [][]string{{a, sub, lineA}, {b, sub, lineB}} {
		if out, err := exec.Command(run[0], run[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", run[0], err, out)
		}
	}
	pred := `subsystem == "` + sub + `" AND category == "audit"`
	deadline := time.Now().Add(30 * time.Second)
	for {
		var all, kept []string
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		err := runSystemLog(ctx, []string{"show", "--style", "ndjson", "--predicate", pred, "--last", "5m"}, func(l []byte) {
			var e logEntry
			if json.Unmarshal(l, &e) != nil || e.EventMessage == "" {
				return
			}
			all = append(all, e.EventMessage)
			if fromSender(e, ua) {
				kept = append(kept, e.EventMessage)
			}
		})
		cancel()
		if err != nil {
			t.Fatalf("log show: %v", err)
		}
		if len(all) == 2 {
			if len(kept) != 1 || kept[0] != lineA {
				t.Fatalf("kept %q of %q; want only A's entry", kept, all)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("entries not visible after 30s: %q", all)
		}
		time.Sleep(time.Second)
	}
}

// TestLogKeepsEveryBuildAtTheInstalledPath runs the Milestone 5
// sender check against the real unified log: two builds of the same
// program, run one after the other from the same path (an ad-hoc rebuild
// of Nazar.app reinstalled in place), are both kept with today's identity
// (the second build's LC_UUID and that path); a third program run from
// another path is dropped. A test subsystem is used, so nothing is ever
// written under the real dev.nazar subsystem.
func TestLogKeepsEveryBuildAtTheInstalledPath(t *testing.T) {
	if _, err := exec.LookPath("swiftc"); err != nil {
		t.Skip("swiftc not available")
	}
	dir, err := os.MkdirTemp("", "nzlogb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if dir, err = filepath.EvalSymlinks(dir); err != nil { // the log records real paths
		t.Fatal(err)
	}
	var nonce [6]byte
	rand.Read(nonce[:])
	tag := hex.EncodeToString(nonce[:])
	build := func(out, variant string) {
		src := filepath.Join(dir, "src-"+variant+".swift")
		// The variant is in the code (a comment alone leaves the LC_UUID
		// unchanged), so each build is a different image.
		body := "import Foundation\nimport os\n" +
			"if CommandLine.arguments.count > 9 { print(\"" + tag + " " + variant + "\") }\n" +
			"let log = OSLog(subsystem: CommandLine.arguments[1], category: \"audit\")\n" +
			"os_log(.default, log: log, \"%{public}s\", CommandLine.arguments[2])\n"
		if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Remove(out)
		if b, err := exec.Command("swiftc", "-o", out, src).CombinedOutput(); err != nil {
			t.Fatalf("swiftc: %v\n%s", err, b)
		}
	}
	installed := filepath.Join(dir, "Nazar.app", "Contents", "MacOS", "nazar-agent")
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	forger := filepath.Join(dir, "forger")
	sub := "dev.nazar.test." + tag
	lines := []string{
		`decision=allowed reason="build 1" target=ssh:test-1`,
		`decision=allowed reason="build 2" target=ssh:test-2`,
		`decision=allowed reason="forged by another process" target=ssh:test-f`,
	}
	run := func(exe, line string) {
		if out, err := exec.Command(exe, sub, line).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", exe, err, out)
		}
	}
	build(installed, "build1")
	run(installed, lines[0])
	u1, _ := machoUUID(installed)
	build(installed, "build2") // the rebuild, reinstalled at the same path
	run(installed, lines[1])
	u2, err := machoUUID(installed)
	if err != nil || u1 == u2 {
		t.Fatalf("the two builds must differ: %s %s %v", u1, u2, err)
	}
	build(forger, "forger")
	run(forger, lines[2])
	trusted := trustedSender{UUID: u2, Path: installed}
	pred := `subsystem == "` + sub + `" AND category == "audit"`
	deadline := time.Now().Add(30 * time.Second)
	for {
		var all, kept []string
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		err := runSystemLog(ctx, []string{"show", "--style", "ndjson", "--predicate", pred, "--last", "5m"}, func(l []byte) {
			var e logEntry
			if json.Unmarshal(l, &e) != nil || e.EventMessage == "" {
				return
			}
			all = append(all, e.EventMessage)
			if fromNazar(e, trusted) {
				kept = append(kept, e.EventMessage)
			}
		})
		cancel()
		if err != nil {
			t.Fatalf("log show: %v", err)
		}
		if len(all) == 3 {
			if strings.Join(kept, "|") != lines[0]+"|"+lines[1] {
				t.Fatalf("kept %q of %q; want both builds' entries and not the forger's", kept, all)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("entries not visible after 30s: %q", all)
		}
		time.Sleep(time.Second)
	}
}
