package main

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBundleOf(t *testing.T) {
	for _, c := range []struct {
		exe  string
		ok   bool
		main string
	}{
		{"/Applications/Nazar.app/Contents/MacOS/nazar", true, "/Applications/Nazar.app/Contents/MacOS/nazar-agent"},
		{"/Applications/Nazar.app/Contents/MacOS/nazar-agent", true, "/Applications/Nazar.app/Contents/MacOS/nazar-agent"},
		{"/usr/local/bin/nazar", false, ""},
		{"/x/Nazar/Contents/MacOS/nazar", false, ""},
		{"/x/Nazar.app/Contents/Resources/nazar", false, ""},
		{"nazar", false, ""},
	} {
		loc, ok := bundleOf(c.exe)
		if ok != c.ok || loc.MainExe != c.main {
			t.Errorf("bundleOf(%q) = %+v, %v; want main %q, %v", c.exe, loc, ok, c.main, c.ok)
		}
	}
}

func TestLocateAppPrefersTheCLIsOwnBundle(t *testing.T) {
	h := newHarness(t)
	loc, err := h.a.locateApp()
	if err != nil || loc != h.app {
		t.Fatalf("locateApp = %+v, %v; want %+v", loc, err, h.app)
	}
}

func TestLocateAppFallsBackToTheLaunchAgent(t *testing.T) {
	h := newHarness(t)
	h.a.executable = func() (string, error) { return "/opt/homebrew/bin/nazar", nil }
	var asked string
	h.a.plistProgram = func(p string) (string, error) { asked = p; return h.app.MainExe, nil }
	loc, err := h.a.locateApp()
	if err != nil || loc != h.app {
		t.Fatalf("locateApp = %+v, %v; want %+v", loc, err, h.app)
	}
	if want := filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist"); asked != want {
		t.Fatalf("read plist %q, want %q", asked, want)
	}
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test.x"
	h.a.locateApp()
	if !strings.HasSuffix(asked, "/dev.nazar.test.x.plist") {
		t.Fatalf("label override: read %q", asked)
	}
}

func TestLocateAppRefusesWhatIsNotANazarBundle(t *testing.T) {
	h := newHarness(t)
	h.a.executable = func() (string, error) { return "/opt/homebrew/bin/nazar", nil }
	for name, prog := range map[string]func() (string, error){
		"no plist":           func() (string, error) { return "", errors.New("no such file") },
		"not in a bundle":    func() (string, error) { return "/bin/sleep", nil },
		"bundle CLI not app": func() (string, error) { return h.app.CLI, nil },
		"missing main exe":   func() (string, error) { return filepath.Join(h.home, "Gone.app/Contents/MacOS/nazar-agent"), nil },
	} {
		h.a.plistProgram = func(string) (string, error) { return prog() }
		if loc, err := h.a.locateApp(); err == nil {
			t.Errorf("%s: locateApp = %+v, want an error", name, loc)
		}
	}
	// A bundle path that is a symlink resolves to the real bundle.
	link := filepath.Join(h.home, "Link.app")
	if err := os.Symlink(h.app.Bundle, link); err != nil {
		t.Fatal(err)
	}
	h.a.plistProgram = func(string) (string, error) { return filepath.Join(link, "Contents/MacOS/nazar-agent"), nil }
	if loc, err := h.a.locateApp(); err != nil || loc != h.app {
		t.Fatalf("symlinked bundle: %+v, %v", loc, err)
	}
}

func TestLogWithoutATrustedAppFails(t *testing.T) {
	h := newHarness(t)
	h.a.executable = func() (string, error) { return "/opt/homebrew/bin/nazar", nil }
	ran := false
	h.a.runLog = func(_ context.Context, _ []string, _ func([]byte)) error { ran = true; return nil }
	if code := h.run("log"); code != 1 || ran || !strings.Contains(h.errb.String(), "which nazar-agent to read") {
		t.Fatalf("exit %d ran=%v stderr %q", code, ran, h.errb)
	}
}

func TestLogKeepsOnlyEntriesFromNazarsOwnImage(t *testing.T) {
	h := newHarness(t)
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		for _, l := range auditLines() {
			line([]byte(l))
		}
		return nil
	}
	if code := h.run("--json", "log"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	if strings.Contains(out, "com.evil") || len(jsonLines(t, out)) != 3 {
		t.Fatalf("forged entries shown or genuine ones lost: %q", out)
	}
	if !fromSender(logEntry{ProcessImageUUID: "abc", SenderImageUUID: "ABC"}, "ABC") || fromSender(logEntry{}, "") {
		t.Fatal("fromSender: case-insensitive match, empty never matches")
	}
}

func TestLogFailsWhenTheAppIdentityCantBeRead(t *testing.T) {
	h := newHarness(t)
	h.a.imageUUID = func(string) (string, error) { return "", errors.New("not a Mach-O file") }
	ran := false
	h.a.runLog = func(_ context.Context, _ []string, _ func([]byte)) error { ran = true; return nil }
	if code := h.run("log"); code != 1 || ran {
		t.Fatalf("exit %d ran=%v", code, ran)
	}
}

func TestMachoUUIDOfThisTestBinary(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the test binary is Mach-O only on macOS")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	u, err := machoUUID(exe)
	if err != nil || len(u) != 36 || strings.ToUpper(u) != u || strings.Count(u, "-") != 4 {
		t.Fatalf("machoUUID = %q, %v", u, err)
	}
	if _, err := machoUUID("/etc/hosts"); err == nil {
		t.Fatal("machoUUID of a text file succeeded")
	}
}

// Additional edge and attack cases of the sender check (test author).

// fromSender needs both the process image and the sender image to be the
// trusted app: an entry another process wrote through a copy of Nazar's
// code (sender matches, process does not) or a library injected into
// Nazar's process (process matches, sender does not) is not Nazar's.
func TestFromSenderRequiresBothImages(t *testing.T) {
	const u = testAppUUID
	const other = "AAAAAAAA-2222-3333-4444-555555555555"
	for _, c := range []struct {
		name      string
		proc, snd string
		uuid      string
		want      bool
	}{
		{"both match", u, u, u, true},
		{"lower-case entry", strings.ToLower(u), strings.ToLower(u), u, true},
		{"lower-case trusted uuid", u, u, strings.ToLower(u), true},
		{"only the process", u, other, u, false},
		{"only the sender", other, u, u, false},
		{"neither", other, other, u, false},
		{"entry without sender fields", "", "", u, false},
		{"process field missing", "", u, u, false},
		{"sender field missing", u, "", u, false},
		{"empty trusted uuid never matches", "", "", "", false},
		{"prefix is not a match", u[:8], u[:8], u, false},
		{"surrounding space is not a match", " " + u, u + " ", u, false},
	} {
		if got := fromSender(logEntry{ProcessImageUUID: c.proc, SenderImageUUID: c.snd}, c.uuid); got != c.want {
			t.Errorf("%s: fromSender = %v, want %v", c.name, got, c.want)
		}
	}
}

// Forged entries must stay out of every view: human, --json, summary
// (human and JSON) and --follow.
func TestLogDropsForgedEntriesInEveryView(t *testing.T) {
	h := newHarness(t)
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		for _, l := range auditLines() {
			line([]byte(l))
		}
		return nil
	}
	for _, args := range [][]string{
		{"log"},
		{"--json", "log"},
		{"log", "--follow"},
		{"--json", "log", "--follow"},
		{"log", "summary"},
		{"--json", "log", "summary"},
		{"--json", "log", "--caller", "evil"},
	} {
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d %s", args, code, h.errb)
		}
		if out := h.out.String(); strings.Contains(out, "com.evil") {
			t.Errorf("%v shows a forged entry:\n%s", args, out)
		}
	}
	if code := h.run("--json", "log", "summary"); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(h.out.String(), `"target":"ssh:github","total":2`) {
		t.Fatalf("summary counts forged entries: %s", h.out)
	}
}

// The identity is the app's main executable (the sender of audit entries),
// never the CLI's own binary, and it is read before /usr/bin/log runs.
func TestLogAsksForTheAppsIdentityNotTheCLIs(t *testing.T) {
	h := newHarness(t)
	var asked []string
	h.a.imageUUID = func(p string) (string, error) { asked = append(asked, p); return testAppUUID, nil }
	ranBefore := -1
	h.a.runLog = func(context.Context, []string, func([]byte)) error { ranBefore = len(asked); return nil }
	if code := h.run("log"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if len(asked) != 1 || asked[0] != h.app.MainExe {
		t.Fatalf("imageUUID asked for %q, want only %q", asked, h.app.MainExe)
	}
	if ranBefore != 1 {
		t.Fatalf("/usr/bin/log ran before the identity was read (%d)", ranBefore)
	}
}

// An empty identity is a failure, never "match entries without sender".
func TestLogFailsOnAnEmptyAppIdentity(t *testing.T) {
	h := newHarness(t)
	h.a.imageUUID = func(string) (string, error) { return "", nil }
	shown := false
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		line([]byte(`{"timestamp":"2026-10-04 00:01:52.000000+0000","eventMessage":"decision=allowed target=ssh:github app=com.evil"}`))
		return nil
	}
	code := h.run("--json", "log")
	if strings.Contains(h.out.String(), "com.evil") {
		shown = true
	}
	if shown || (code == 0 && h.out.Len() != 0) {
		t.Fatalf("empty identity: exit %d shown=%v out %q", code, shown, h.out)
	}
}

// A bundle-shaped folder around the CLI without the app's main executable
// (or with a folder in its place) is not a Nazar.app; nor is a launch
// agent program that is not named nazar-agent.
func TestLocateAppRefusesIncompleteBundles(t *testing.T) {
	h := newHarness(t)
	h.a.plistProgram = func(string) (string, error) { return "", errors.New("no plist") }

	noMain := filepath.Join(h.home, "NoMain.app", "Contents", "MacOS")
	if err := os.MkdirAll(noMain, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(noMain, cliExeName), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.a.executable = func() (string, error) { return filepath.Join(noMain, cliExeName), nil }
	if loc, err := h.a.locateApp(); err == nil {
		t.Errorf("bundle without %s: locateApp = %+v", appExeName, loc)
	}

	dirMain := filepath.Join(h.home, "DirMain.app", "Contents", "MacOS")
	if err := os.MkdirAll(filepath.Join(dirMain, appExeName), 0o755); err != nil {
		t.Fatal(err)
	}
	h.a.executable = func() (string, error) { return filepath.Join(dirMain, cliExeName), nil }
	if loc, err := h.a.locateApp(); err == nil {
		t.Errorf("%s is a folder: locateApp = %+v", appExeName, loc)
	}

	h.a.executable = func() (string, error) { return "", errors.New("no executable") }
	if loc, err := h.a.locateApp(); err == nil {
		t.Errorf("no executable, no plist: locateApp = %+v", loc)
	}

	// The launch agent's program must be the app itself, not some other
	// file in a Nazar bundle.
	other := filepath.Join(filepath.Dir(h.app.MainExe), "Helper")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.a.plistProgram = func(string) (string, error) { return other, nil }
	if loc, err := h.a.locateApp(); err == nil {
		t.Errorf("plist program %s: locateApp = %+v", other, loc)
	}
}

func TestLaunchLabelAndPlist(t *testing.T) {
	h := newHarness(t)
	if l := h.a.launchLabel(); l != defaultLaunchLabel || defaultLaunchLabel != "dev.nazar.agent" {
		t.Fatalf("launchLabel = %q", l)
	}
	if p := h.a.launchAgentPlist(); p != filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist") {
		t.Fatalf("launchAgentPlist = %q", p)
	}
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test.y"
	if l := h.a.launchLabel(); l != "dev.nazar.test.y" {
		t.Fatalf("override: %q", l)
	}
}

func TestSelfExecutableIsResolved(t *testing.T) {
	p, err := selfExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if real, err := filepath.EvalSymlinks(p); err != nil || real != p || !filepath.IsAbs(p) {
		t.Fatalf("selfExecutable = %q (resolves to %q, %v)", p, real, err)
	}
}

// plistProgram reads ProgramArguments[0] with /usr/bin/plutil (read only;
// temporary plists, never the real LaunchAgents folder).
func TestPlistProgram(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("needs macOS /usr/bin/plutil")
	}
	dir := t.TempDir()
	write := func(name, args string) string {
		p := filepath.Join(dir, name)
		body := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>dev.nazar.test</string>` + args + `</dict></plist>
`
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.plist", `<key>ProgramArguments</key><array><string>/Applications/Nazar.app/Contents/MacOS/nazar-agent</string><string>--flag</string></array>`)
	if p, err := plistProgram(good); err != nil || p != "/Applications/Nazar.app/Contents/MacOS/nazar-agent" {
		t.Fatalf("plistProgram = %q, %v", p, err)
	}
	for name, args := range map[string]string{
		"relative.plist": `<key>ProgramArguments</key><array><string>Nazar.app/Contents/MacOS/nazar-agent</string></array>`,
		"empty.plist":    `<key>ProgramArguments</key><array></array>`,
		"none.plist":     `<key>Program</key><string>/Applications/Nazar.app/Contents/MacOS/nazar-agent</string>`,
		"notstr.plist":   `<key>ProgramArguments</key><array><integer>1</integer></array>`,
	} {
		if p, err := plistProgram(write(name, args)); err == nil {
			t.Errorf("%s: plistProgram = %q, want an error", name, p)
		}
	}
	if p, err := plistProgram(filepath.Join(dir, "missing.plist")); err == nil {
		t.Errorf("missing plist: %q", p)
	}
}

func TestIsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !isFile(f) || isFile(dir) || isFile(filepath.Join(dir, "missing")) {
		t.Fatal("isFile: a regular file only")
	}
}

// thinMachO builds a minimal 64-bit little-endian Mach-O executable header
// with the given load commands.
func thinMachO(cpu uint32, cmds ...[]byte) []byte {
	var body []byte
	for _, c := range cmds {
		body = append(body, c...)
	}
	b := make([]byte, 32, 32+len(body))
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], cpu)
	le.PutUint32(b[8:], 0)
	le.PutUint32(b[12:], 2) // MH_EXECUTE
	le.PutUint32(b[16:], uint32(len(cmds)))
	le.PutUint32(b[20:], uint32(len(body)))
	return append(b, body...)
}

func uuidCmd(u []byte, size uint32) []byte {
	c := make([]byte, size)
	binary.LittleEndian.PutUint32(c[0:], 0x1b)
	binary.LittleEndian.PutUint32(c[4:], size)
	copy(c[8:], u)
	return c
}

// segCmd is an unrelated load command (LC_SEGMENT_64 shaped, 72 bytes).
func segCmd() []byte {
	c := make([]byte, 72)
	binary.LittleEndian.PutUint32(c[0:], 0x19)
	binary.LittleEndian.PutUint32(c[4:], 72)
	return c
}

// fatMachO wraps thin slices in a universal (fat) header.
func fatMachO(slices map[uint32][]byte, order []uint32) []byte {
	be := binary.BigEndian
	hdr := make([]byte, 8+20*len(order))
	be.PutUint32(hdr[0:], 0xcafebabe)
	be.PutUint32(hdr[4:], uint32(len(order)))
	off := uint32(0x4000)
	var out []byte
	for i, cpu := range order {
		s := slices[cpu]
		e := hdr[8+20*i:]
		be.PutUint32(e[0:], cpu)
		be.PutUint32(e[4:], 0)
		be.PutUint32(e[8:], off)
		be.PutUint32(e[12:], uint32(len(s)))
		be.PutUint32(e[16:], 14)
		off += 0x4000
	}
	out = append(out, hdr...)
	for _, cpu := range order {
		for len(out)%0x4000 != 0 {
			out = append(out, 0)
		}
		out = append(out, slices[cpu]...)
	}
	return out
}

const (
	cpuArm64  = 0x0100000c
	cpuX86_64 = 0x01000007
)

func TestMachoUUIDOfCraftedFiles(t *testing.T) {
	dir := t.TempDir()
	u := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	const want = "01234567-89AB-CDEF-FEDC-BA9876543210"
	x := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee}
	files := map[string][]byte{
		"thin":         thinMachO(cpuArm64, uuidCmd(u, 24)),
		"thin-after":   thinMachO(cpuArm64, segCmd(), uuidCmd(u, 24)),
		"fat":          fatMachO(map[uint32][]byte{cpuX86_64: thinMachO(cpuX86_64, uuidCmd(x, 24)), cpuArm64: thinMachO(cpuArm64, uuidCmd(u, 24))}, []uint32{cpuX86_64, cpuArm64}),
		"fat-arm-1st":  fatMachO(map[uint32][]byte{cpuX86_64: thinMachO(cpuX86_64, uuidCmd(x, 24)), cpuArm64: thinMachO(cpuArm64, uuidCmd(u, 24))}, []uint32{cpuArm64, cpuX86_64}),
		"no-uuid":      thinMachO(cpuArm64),
		"other-cmds":   thinMachO(cpuArm64, segCmd()),
		"short-uuid":   thinMachO(cpuArm64, uuidCmd(u, 16)),
		"fat-x86-only": fatMachO(map[uint32][]byte{cpuX86_64: thinMachO(cpuX86_64, uuidCmd(x, 24))}, []uint32{cpuX86_64}),
		"empty":        {},
		"magic-only":   {0xcf, 0xfa, 0xed, 0xfe},
		"fat-magic":    {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1},
		"text":         []byte("#!/bin/sh\necho hi\n"),
	}
	ok := map[string]bool{"thin": true, "thin-after": true, "fat": true, "fat-arm-1st": true}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := machoUUID(p)
		if ok[name] {
			if err != nil || got != want {
				t.Errorf("%s: machoUUID = %q, %v; want %q", name, got, err, want)
			}
		} else if err == nil {
			t.Errorf("%s: machoUUID = %q, want an error", name, got)
		}
	}
	if _, err := machoUUID(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file: no error")
	}
}
