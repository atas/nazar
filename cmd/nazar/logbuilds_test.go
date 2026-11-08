package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// After an ad-hoc rebuild, `nazar log` must still show
// what the previous builds wrote: any build that ran from the installed
// path is Nazar, any other image is not.
func TestFromNazarAcceptsEveryBuildAtTheInstalledPath(t *testing.T) {
	const exe = "/Users/u/Applications/Nazar.app/Contents/MacOS/nazar-agent"
	const old = "AAAAAAAA-1111-2222-3333-444444444444"
	const forger = "BBBBBBBB-1111-2222-3333-444444444444"
	s := trustedSender{UUID: testAppUUID, Path: exe}
	for _, c := range []struct {
		name string
		e    logEntry
		want bool
	}{
		{"today's build", logEntry{ProcessImageUUID: testAppUUID, SenderImageUUID: testAppUUID, ProcessImagePath: exe, SenderImagePath: exe}, true},
		{"today's build first seen elsewhere (the app was moved)", logEntry{ProcessImageUUID: testAppUUID, SenderImageUUID: testAppUUID, ProcessImagePath: "/Applications/Nazar.app/Contents/MacOS/nazar-agent", SenderImagePath: "/Applications/Nazar.app/Contents/MacOS/nazar-agent"}, true},
		{"an earlier build at the installed path", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: exe, SenderImagePath: exe}, true},
		{"lower-case uuids", logEntry{ProcessImageUUID: strings.ToLower(old), SenderImageUUID: old, ProcessImagePath: exe, SenderImagePath: exe}, true},
		{"another program", logEntry{ProcessImageUUID: forger, SenderImageUUID: forger, ProcessImagePath: "/tmp/forger", SenderImagePath: "/tmp/forger"}, false},
		{"another program claiming the path as sender only", logEntry{ProcessImageUUID: forger, SenderImageUUID: forger, ProcessImagePath: "/tmp/forger", SenderImagePath: exe}, false},
		{"another program claiming the path as process only", logEntry{ProcessImageUUID: forger, SenderImageUUID: forger, ProcessImagePath: exe, SenderImagePath: "/tmp/forger"}, false},
		{"a library inside Nazar's process", logEntry{ProcessImageUUID: old, SenderImageUUID: forger, ProcessImagePath: exe, SenderImagePath: exe}, false},
		{"Nazar's code in another process", logEntry{ProcessImageUUID: forger, SenderImageUUID: old, ProcessImagePath: exe, SenderImagePath: exe}, false},
		{"today's code in another process", logEntry{ProcessImageUUID: forger, SenderImageUUID: testAppUUID, ProcessImagePath: "/tmp/forger", SenderImagePath: exe}, false},
		{"a library in today's process", logEntry{ProcessImageUUID: testAppUUID, SenderImageUUID: forger, ProcessImagePath: exe, SenderImagePath: "/tmp/lib.dylib"}, false},
		{"no sender image uuid", logEntry{ProcessImageUUID: old, ProcessImagePath: exe, SenderImagePath: exe}, false},
		{"no process image uuid", logEntry{SenderImageUUID: old, ProcessImagePath: exe, SenderImagePath: exe}, false},
		{"no sender image path", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: exe}, false},
		{"no process image path", logEntry{ProcessImageUUID: old, SenderImageUUID: old, SenderImagePath: exe}, false},
		{"a sibling path", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: exe + "2", SenderImagePath: exe + "2"}, false},
		{"a path with a dot segment", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: "/Users/u/Applications/Nazar.app/Contents/MacOS/./nazar-agent", SenderImagePath: "/Users/u/Applications/Nazar.app/Contents/MacOS/./nazar-agent"}, false},
		{"a path with a trailing slash", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: exe + "/", SenderImagePath: exe + "/"}, false},
		{"another bundle's nazar-agent", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: "/tmp/x/Nazar.app/Contents/MacOS/nazar-agent", SenderImagePath: "/tmp/x/Nazar.app/Contents/MacOS/nazar-agent"}, false},
		{"no image fields", logEntry{ProcessImagePath: exe, SenderImagePath: exe}, false},
		{"path case differs", logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: strings.ToLower(exe), SenderImagePath: strings.ToLower(exe)}, false},
		{"empty entry", logEntry{}, false},
	} {
		if got := fromNazar(c.e, s); got != c.want {
			t.Errorf("%s: fromNazar = %v, want %v", c.name, got, c.want)
		}
	}
	if fromNazar(logEntry{ProcessImageUUID: old, SenderImageUUID: old}, trustedSender{UUID: testAppUUID}) {
		t.Fatal("an empty trusted path must never match")
	}
	if fromNazar(logEntry{}, trustedSender{}) {
		t.Fatal("an empty trusted sender must never match an empty entry")
	}
	if fromNazar(logEntry{ProcessImageUUID: old, SenderImageUUID: old, ProcessImagePath: exe, SenderImagePath: exe}, trustedSender{Path: exe}) != true {
		t.Fatal("an earlier build at the installed path is kept whatever today's LC_UUID is")
	}
}

// End to end through `nazar log`: entries of an earlier build at the
// bundle's path are shown, a forger's are not.
func TestLogShowsEntriesOfEarlierBuilds(t *testing.T) {
	h := newHarness(t)
	entry := func(msg, uuid, path string) string {
		b, _ := json.Marshal(map[string]string{"timestamp": "2026-10-11 00:00:00.000000+0000", "eventMessage": msg,
			"processImageUUID": uuid, "senderImageUUID": uuid, "processImagePath": path, "senderImagePath": path})
		return string(b)
	}
	mixed := func(msg, puuid, suuid, path string) string {
		b, _ := json.Marshal(map[string]string{"timestamp": "2026-10-11 00:00:00.000000+0000", "eventMessage": msg,
			"processImageUUID": puuid, "senderImageUUID": suuid, "processImagePath": path, "senderImagePath": path})
		return string(b)
	}
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		line([]byte(entry("decision=allowed target=ssh:github app=com.old.build", "AAAAAAAA-1111-2222-3333-444444444444", h.app.MainExe)))
		line([]byte(entry("decision=allowed target=ssh:github app=com.today", testAppUUID, h.app.MainExe)))
		line([]byte(entry("decision=allowed target=ssh:github app=com.evil", "BBBBBBBB-1111-2222-3333-444444444444", "/tmp/forger")))
		line([]byte(entry("decision=allowed target=ssh:github app=com.evil.sibling", "CCCCCCCC-1111-2222-3333-444444444444", h.app.MainExe+"2")))
		line([]byte(mixed("decision=allowed target=ssh:github app=com.evil.dylib", "AAAAAAAA-1111-2222-3333-444444444444", "DDDDDDDD-1111-2222-3333-444444444444", h.app.MainExe)))
		return nil
	}
	if code := h.run("--json", "log"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	if !strings.Contains(out, "com.old.build") || !strings.Contains(out, "com.today") || strings.Contains(out, "com.evil") {
		t.Fatalf("log output:\n%s", out)
	}
}
