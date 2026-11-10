package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var _ Sink = (*FileSink)(nil)

func readLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return nil
	}
	if b[len(b)-1] != '\n' {
		t.Fatalf("%s does not end in a newline: %q", p, b)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestFileSinkFormat(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "log")
	p := filepath.Join(dir, "audit.log")
	s := &FileSink{Path: p}
	at := time.Date(2026, 11, 9, 3, 4, 5, 123456789, time.FixedZone("x", 3600))
	if err := s.WriteAudit(at, "decision=allowed target=ssh:github"); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, p); len(got) != 1 || got[0] != "2026-11-09T02:04:05.123456789Z decision=allowed target=ssh:github" {
		t.Fatalf("%q", got)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file: %v %v, want mode 600", fi, err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("folder: %v %v, want mode 700", fi, err)
	}
	// An older file that others could read is closed on the next write.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAudit(at, "decision=blocked"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file after chmod: %v %v, want mode 600", fi, err)
	}
	if DefaultFileMax != 10<<20 {
		t.Errorf("DefaultFileMax %d", DefaultFileMax)
	}
}

func TestFileSinkRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	s := &FileSink{Path: p, MaxBytes: 200}
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	line := func(i int) string { return fmt.Sprintf("decision=allowed target=ssh:k%d", i) }
	var want []string
	for i := range 6 { // 6 lines of 52 bytes pass 200 once
		if err := s.WriteAudit(at, line(i)); err != nil {
			t.Fatal(err)
		}
		want = append(want, "2026-11-09T00:00:00Z "+line(i))
	}
	older, newest := readLines(t, p+".1"), readLines(t, p)
	if len(newest) == 0 || newest[len(newest)-1] != want[len(want)-1] {
		t.Fatalf("newest line not in the file: %q", newest)
	}
	if got := append(append([]string(nil), older...), newest...); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lost across one rotation:\n%q\nwant\n%q", got, want)
	}
	for _, f := range []string{p, p + ".1"} {
		if fi, err := os.Stat(f); err != nil || fi.Size() > 200 {
			t.Errorf("%s: %v %v, want at most 200 bytes", f, fi, err)
		}
	}
	if fi, err := os.Stat(p + ".1"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf(".1: %v %v, want mode 600", fi, err)
	}
	// The next rotation replaces .1.
	first := older[0]
	for i := 100; i < 106; i++ {
		if err := s.WriteAudit(at, line(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := readLines(t, p+".1"); strings.Contains(strings.Join(got, "\n"), first) {
		t.Fatalf(".1 kept its old lines: %q", got)
	}
}

// A line longer than the limit goes into an empty file as it is: renaming
// the empty file would replace .1 with nothing.
func TestFileSinkLongLineKeepsTheOlderFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	s := &FileSink{Path: p, MaxBytes: 20}
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(p+".1", []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAudit(at, "decision=allowed"); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, p+".1"); len(got) != 1 || got[0] != "kept" {
		t.Fatalf(".1: %q", got)
	}
	if got := readLines(t, p); len(got) != 1 {
		t.Fatalf("file: %q", got)
	}
}

// A file that can't be rotated keeps growing, and the line is still written.
func TestFileSinkRotationFailureKeepsTheLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	s := &FileSink{Path: p, MaxBytes: 60}
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if err := os.MkdirAll(filepath.Join(p+".1", "sub"), 0o700); err != nil { // a rename over it fails
		t.Fatal(err)
	}
	if err := s.WriteAudit(at, "decision=allowed target=ssh:one"); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAudit(at, "decision=allowed target=ssh:two"); err == nil {
		t.Fatal("no error for the failed rotation")
	}
	if got := readLines(t, p); len(got) != 2 {
		t.Fatalf("file: %q", got)
	}
}

func TestFileSinkConcurrent(t *testing.T) {
	const workers, each = 8, 40
	for _, limit := range []int64{0, 300} {
		p := filepath.Join(t.TempDir(), "audit.log")
		s := &FileSink{Path: p, MaxBytes: limit}
		var wg sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each {
					if err := s.WriteAudit(time.Now(), fmt.Sprintf("decision=allowed target=ssh:w%d-%d", w, i)); err != nil {
						t.Error(err)
					}
				}
			}()
		}
		wg.Wait()
		lines := readLines(t, p)
		if limit == 0 && len(lines) != workers*each {
			t.Errorf("%d lines, want %d", len(lines), workers*each)
		}
		if limit != 0 {
			lines = append(lines, readLines(t, p+".1")...)
		}
		for _, l := range lines {
			if _, msg, err := ParseFileLine(l); err != nil {
				t.Errorf("torn line %q: %v", l, err)
			} else if _, err := ParseLine(msg); err != nil {
				t.Errorf("torn message %q: %v", msg, err)
			}
		}
	}
}

// Logger's promise: a failing sink never blocks the decision. A FIFO left at
// the path (no reader, so a plain open would wait for ever) is an error.
func TestFileSinkFIFONeverBlocks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- (&FileSink{Path: p}).WriteAudit(time.Now(), "decision=allowed") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error for a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteAudit blocked on a FIFO")
	}
}

func TestFileSinkNotAFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&FileSink{Path: p}).WriteAudit(time.Now(), "decision=allowed"); err == nil {
		t.Fatal("no error for a folder")
	}
}

func TestParseFileLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	s := &FileSink{Path: p}
	for _, at := range []time.Time{
		time.Date(2026, 11, 9, 3, 4, 5, 123456789, time.UTC),
		time.Date(2026, 11, 9, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 11, 9, 3, 4, 5, 500000000, time.FixedZone("x", -7200)),
	} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		const line = `decision=blocked reason="no rule" target=ssh:github`
		if err := s.WriteAudit(at, line); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range []string{string(raw), strings.TrimSuffix(string(raw), "\n")} {
			got, msg, err := ParseFileLine(in)
			if err != nil || !got.Equal(at) || msg != line {
				t.Errorf("%q: %v %q %v", in, got, msg, err)
			}
		}
	}
	for _, bad := range []string{
		"",
		"no-stamp",
		"not-a-time decision=allowed",
		"decision=allowed target=ssh:github",
		"2026-11-09 decision=allowed",
		"2026-13-09T00:00:00Z decision=allowed",
		"2026-11-09T02:00:00 decision=allowed",
		"2026-11-09T02:00:00+01:00 decision=allowed", // the sink writes UTC
		"2026-11-09T2:00:00Z decision=allowed",
		"2026-11-09T02:00:00.100Z decision=allowed", // and no trailing zeros
		"2026-11-09T02:00:00,5Z decision=allowed",
		" 2026-11-09T02:00:00Z decision=allowed",
	} {
		if at, msg, err := ParseFileLine(bad); err == nil {
			t.Errorf("%q accepted: %v %q", bad, at, msg)
		}
	}
}
