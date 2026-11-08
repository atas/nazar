package knownhosts

// Tests for naming a server from its host key via known_hosts (spec 5,
// Phase 0 S7). The name ends up in the approval dialog ("login to
// github.com"), so a key must only ever be named by a plain, positive
// known_hosts entry for that exact key, or by a candidate that a hashed
// entry for that exact key confirms. Markers, negations and patterns never
// name a host; candidates never name anything on their own.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func key(t testing.TB) ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecdsaKey(t testing.TB) ssh.PublicKey {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func write(t testing.TB, lines ...string) string {
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func entry(hosts string, k ssh.PublicKey) string {
	return hosts + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func lookup(t *testing.T, path string, k ssh.PublicKey, candidates []string) Result {
	t.Helper()
	r, err := Lookup(path, k, candidates)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// Plain entries

func TestPlainNames(t *testing.T) {
	gh, other := key(t), key(t)
	p := write(t, "# comment", entry("github.com,140.82.121.4", gh), entry("[127.0.0.1]:2222", other), entry("*.example.com", gh), entry("!bad.example", gh), "@revoked "+entry("evil.example", gh))
	r, err := Lookup(p, gh, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Names, []string{"github.com", "140.82.121.4"}) || r.Display() != "github.com (also 140.82.121.4)" {
		t.Fatalf("names %v", r.Names)
	}
	r2, _ := Lookup(p, other, nil)
	if r2.Display() != "[127.0.0.1]:2222" {
		t.Fatalf("names %v", r2.Names)
	}
}

func TestNamesInFileOrderWithoutDuplicates(t *testing.T) {
	k := key(t)
	p := write(t,
		entry("a.example", k),
		entry("b.example,a.example", k),
		entry("c.example,b.example", k),
	)
	r := lookup(t, p, k, nil)
	if !reflect.DeepEqual(r.Names, []string{"a.example", "b.example", "c.example"}) {
		t.Fatalf("names %v", r.Names)
	}
	if r.Display() != "a.example (also b.example, c.example)" {
		t.Fatalf("display %q", r.Display())
	}
}

func TestEntryWithCommentAndWhitespace(t *testing.T) {
	k := key(t)
	p := write(t,
		"",
		"   ",
		"   # indented comment "+entry("commented.example", k),
		"  "+entry("indented.example", k)+" trailing-comment",
	)
	r := lookup(t, p, k, nil)
	if !reflect.DeepEqual(r.Names, []string{"indented.example"}) {
		t.Fatalf("names %v", r.Names)
	}
}

func TestMixedHostListKeepsOnlyPlainNames(t *testing.T) {
	k := key(t)
	salt := []byte("0123456789abcdefghij")
	p := write(t, entry("box.example,!nope.example,*.wild.example,host?.example,"+HashName("hidden.example", salt)+",10.0.0.5", k))
	r := lookup(t, p, k, nil)
	if !reflect.DeepEqual(r.Names, []string{"box.example", "10.0.0.5"}) {
		t.Fatalf("names %v", r.Names)
	}
}

// ---------------------------------------------------------------------------
// Things that must never name a host

func TestMarkersNegationsPatternsNeverName(t *testing.T) {
	k := key(t)
	salt := []byte("saltsaltsaltsaltsalt")
	p := write(t,
		"@revoked "+entry("github.com", k),
		"@revoked "+entry(HashName("gitlab.com", salt), k),
		"@cert-authority "+entry("*.corp.example", k),
		"@cert-authority "+entry("ca.corp.example", k),
		entry("!negated.example", k),
		entry("*", k),
		entry("*.example.com", k),
		entry("db?.example.com", k),
		entry("[*.example.com]:2222", k),
	)
	r := lookup(t, p, k, []string{"github.com", "gitlab.com", "negated.example", "ca.corp.example", "db1.example.com"})
	if len(r.Names) != 0 {
		t.Fatalf("markers/negations/patterns named the key: %v", r.Names)
	}
	if want := "host key " + ssh.FingerprintSHA256(k); r.Display() != want {
		t.Fatalf("display %q, want %q", r.Display(), want)
	}
}

func TestUnknownKeyAndMissingFile(t *testing.T) {
	k := key(t)
	p := write(t, entry("github.com", key(t)))
	if r, _ := Lookup(p, k, []string{"github.com"}); len(r.Names) != 0 {
		t.Fatal("another key must not name this host")
	}
	if r, err := Lookup(filepath.Join(t.TempDir(), "nope"), k, nil); err != nil || len(r.Names) != 0 {
		t.Fatalf("missing file: %v %v", r, err)
	}
}

// Same key type, same host, different key bytes: no name. Different key
// types for the same host only name the matching one.
func TestOnlyExactKeyMatches(t *testing.T) {
	ed, ec, ecOther := key(t), ecdsaKey(t), ecdsaKey(t)
	p := write(t, entry("github.com", ed), entry("github.com", ec))
	if r := lookup(t, p, ec, nil); !reflect.DeepEqual(r.Names, []string{"github.com"}) {
		t.Fatalf("ecdsa key: %v", r.Names)
	}
	if r := lookup(t, p, ed, nil); !reflect.DeepEqual(r.Names, []string{"github.com"}) {
		t.Fatalf("ed25519 key: %v", r.Names)
	}
	if r := lookup(t, p, ecOther, nil); len(r.Names) != 0 {
		t.Fatalf("unrelated ecdsa key named %v", r.Names)
	}
}

// Candidates come from the caller's command line, which an attacker
// controls. They may only confirm hashed entries for this exact key; they
// never add a name on their own.
func TestCandidatesNeverNameOnTheirOwn(t *testing.T) {
	k, other := key(t), key(t)
	salt := []byte("abcdefghijklmnopqrst")
	p := write(t,
		entry("box.example", k),
		entry(HashName("github.com", salt), other),
	)
	r := lookup(t, p, k, []string{"github.com", "gitlab.com", "evil.example", "box.example"})
	if !reflect.DeepEqual(r.Names, []string{"box.example"}) {
		t.Fatalf("names %v", r.Names)
	}
	empty := write(t, "# nothing here")
	if r := lookup(t, empty, k, []string{"github.com"}); len(r.Names) != 0 {
		t.Fatalf("candidate named an absent host: %v", r.Names)
	}
}

func TestEmptyFile(t *testing.T) {
	k := key(t)
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := lookup(t, p, k, WellKnown)
	if len(r.Names) != 0 || r.Fingerprint != ssh.FingerprintSHA256(k) {
		t.Fatalf("%+v", r)
	}
}

// ---------------------------------------------------------------------------
// Hashed entries

func TestHashedNeedsCandidate(t *testing.T) {
	k := key(t)
	p := write(t, entry(HashName("[127.0.0.1]:2222", []byte("0123456789abcdefghij")), k))
	r, _ := Lookup(p, k, nil)
	if len(r.Names) != 0 || !strings.HasPrefix(r.Display(), "host key SHA256:") {
		t.Fatalf("hashed entry must not reveal a name without candidates: %+v", r)
	}
	r, _ = Lookup(p, k, CandidatesFromArgs([]string{"ssh", "-p", "2222", "git@127.0.0.1", "git-upload-pack 'x'"}))
	if !reflect.DeepEqual(r.Names, []string{"[127.0.0.1]:2222"}) {
		t.Fatalf("names %v", r.Names)
	}
}

func TestHashedConfirmsOnlyMatchingCandidate(t *testing.T) {
	k := key(t)
	p := write(t, entry(HashName("box.lan", []byte("saltysaltysaltysalty")), k))
	r := lookup(t, p, k, []string{"evil.example", "box.lan", "box.lan.", "BOX.LAN", "github.com"})
	if !reflect.DeepEqual(r.Names, []string{"box.lan"}) {
		t.Fatalf("names %v", r.Names)
	}
	if r := lookup(t, p, k, []string{"evil.example"}); len(r.Names) != 0 {
		t.Fatalf("non-matching candidate named the key: %v", r.Names)
	}
}

func TestHashedWellKnownName(t *testing.T) {
	k := key(t)
	p := write(t, entry(HashName("github.com", []byte("ghsaltghsaltghsaltgh")), k))
	// ssh to an unrelated host: github.com is still tried because it's well known.
	r := lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "git@unrelated.example"}))
	if !reflect.DeepEqual(r.Names, []string{"github.com"}) {
		t.Fatalf("names %v", r.Names)
	}
}

func TestMalformedHashedEntries(t *testing.T) {
	k := key(t)
	good := HashName("box.lan", []byte("saltysaltysaltysalty"))
	p := write(t,
		entry("|1|", k),
		entry("|1|!!!notbase64!!!|alsonot===", k),
		entry("|1|c2FsdA==", k),
		entry("|1|c2FsdA==|aGFzaA==|extra", k),
		entry("|2|c2FsdA==|aGFzaA==", k),
		entry(good, k),
	)
	r := lookup(t, p, k, []string{"box.lan", ""})
	if !reflect.DeepEqual(r.Names, []string{"box.lan"}) {
		t.Fatalf("names %v", r.Names)
	}
}

func TestHashNameFormat(t *testing.T) {
	salt := []byte("0123456789abcdefghij")
	h := HashName("github.com", salt)
	parts := strings.Split(h, "|")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
		t.Fatalf("not |1|salt|hash: %q", h)
	}
	gotSalt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || string(gotSalt) != string(salt) {
		t.Fatalf("salt %q %v", gotSalt, err)
	}
	m := hmac.New(sha1.New, salt)
	m.Write([]byte("github.com"))
	if parts[3] != base64.StdEncoding.EncodeToString(m.Sum(nil)) {
		t.Fatalf("hash is not HMAC-SHA1(salt, name): %q", parts[3])
	}
	if HashName("github.com", salt) != h {
		t.Fatal("HashName not deterministic")
	}
	if HashName("github.com", []byte("another salt 0123456")) == h || HashName("gitlab.com", salt) == h {
		t.Fatal("HashName ignores its inputs")
	}
}

// OpenSSH itself must agree with our hashing in both directions.
func TestOpenSSHHashInterop(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}
	k := key(t)

	// ssh-keygen -H hashes a plain file; Lookup confirms candidates against it.
	p := write(t, entry("plain.example", k), entry("[127.0.0.1]:2222", k))
	out, err := exec.Command(keygen, "-H", "-f", p).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -H: %v\n%s", err, out)
	}
	hashed, _ := os.ReadFile(p)
	if strings.Contains(string(hashed), "plain.example") || !strings.Contains(string(hashed), "|1|") {
		t.Fatalf("ssh-keygen did not hash the file:\n%s", hashed)
	}
	if r := lookup(t, p, k, nil); len(r.Names) != 0 {
		t.Fatalf("hashed file named without candidates: %v", r.Names)
	}
	r := lookup(t, p, k, []string{"nope.example", "plain.example", "[127.0.0.1]:2222"})
	if !reflect.DeepEqual(r.Names, []string{"plain.example", "[127.0.0.1]:2222"}) {
		t.Fatalf("names %v", r.Names)
	}

	// ssh-keygen -F finds an entry written with HashName.
	p2 := write(t, entry(HashName("[10.1.2.3]:2222", []byte("interopsaltinterop12")), k))
	out, err = exec.Command(keygen, "-F", "[10.1.2.3]:2222", "-f", p2).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "|1|") {
		t.Fatalf("ssh-keygen -F did not find our hashed entry: %v\n%s", err, out)
	}
}

// ---------------------------------------------------------------------------
// Odd files: naming keeps working and never crashes.

func TestOddFiles(t *testing.T) {
	k := key(t)
	p := filepath.Join(t.TempDir(), "known_hosts")
	content := "@cert-authority *.corp.example " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\r\n" +
		strings.Repeat("x", 200000) + "\r\n" +
		"garbage line\r\n" +
		entry("box.corp.example", k) + "\r\n"
	os.WriteFile(p, []byte(content), 0o600)
	r, err := Lookup(p, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Names) != 1 || r.Names[0] != "box.corp.example" {
		t.Fatalf("names %v", r.Names)
	}
}

func TestOddFilesBinaryGarbage(t *testing.T) {
	k := key(t)
	content := "\x00\x01\x02\xff\xfe binary junk\n" +
		"host-only-no-key\n" +
		"host ssh-ed25519\n" +
		"host ssh-ed25519 !!!notbase64!!!\n" +
		"host ssh-ed25519 AAAA\n" +
		"@\n" +
		"@revoked\n" +
		"|1|\n" +
		entry("last.example", k) // no trailing newline
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r := lookup(t, p, k, WellKnown)
	if !reflect.DeepEqual(r.Names, []string{"last.example"}) {
		t.Fatalf("names %v", r.Names)
	}
}

// A single line longer than any line buffer (here 2 MiB, well under any
// whole-file cap) must not hide the entries after it.
func TestOverlongLineDoesNotHideLaterEntries(t *testing.T) {
	k := key(t)
	content := entry("before.example", k) + "\n" +
		strings.Repeat("y", 2<<20) + "\n" +
		entry("after.example", k) + "\n"
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r := lookup(t, p, k, nil)
	if !reflect.DeepEqual(r.Names, []string{"before.example", "after.example"}) {
		t.Fatalf("names %v", r.Names)
	}
}

func TestDirectoryIsNotAName(t *testing.T) {
	k := key(t)
	r, _ := Lookup(t.TempDir(), k, WellKnown)
	if len(r.Names) != 0 {
		t.Fatalf("directory named the key: %v", r.Names)
	}
}

func TestConcurrentLookups(t *testing.T) {
	k := key(t)
	salt := []byte("concurrentsalt012345")
	p := write(t, entry("plain.example", k), entry(HashName("github.com", salt), k))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := Lookup(p, k, CandidatesFromArgs([]string{"ssh", "git@github.com"}))
			if err != nil || !reflect.DeepEqual(r.Names, []string{"github.com", "plain.example"}) {
				t.Errorf("concurrent lookup: %v %v", r.Names, err)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Result

func TestResultDisplay(t *testing.T) {
	if got := (Result{Names: []string{"a", "b"}, Fingerprint: "SHA256:x"}).Display(); got != "a (also b)" {
		t.Fatalf("%q", got)
	}
	if got := (Result{Fingerprint: "SHA256:x"}).Display(); got != "host key SHA256:x" {
		t.Fatalf("%q", got)
	}
	k := key(t)
	r := lookup(t, write(t, "# none"), k, nil)
	if r.Fingerprint != ssh.FingerprintSHA256(k) {
		t.Fatalf("fingerprint %q", r.Fingerprint)
	}
}

// Every name is shown: the first, up to three more, then a count. A user
// who reached a server through one alias must not see only an older alias
// that happens to come first in the file and think it is someone else.
func TestDisplayShowsEveryName(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"hydra.example"}, "hydra.example"},
		{[]string{"hydra.example", "192.0.2.7"}, "hydra.example (also 192.0.2.7)"},
		{[]string{"a.example", "b.example", "c.example", "d.example"}, "a.example (also b.example, c.example, d.example)"},
		{[]string{"a.example", "b.example", "c.example", "d.example", "e.example"}, "a.example (also b.example, c.example, d.example, +1 more)"},
		{[]string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"}, "a.example (also b.example, c.example, d.example, +2 more)"},
	}
	for _, c := range cases {
		if got := (Result{Names: c.names, Fingerprint: "SHA256:x"}).Display(); got != c.want {
			t.Errorf("Display(%v) = %q, want %q", c.names, got, c.want)
		}
	}
}

// The list stays short enough for the dialog's first line ("login to … as
// user"): names that would push it past maxDisplay are counted, not shown,
// and never cut in the middle. The first name is always shown.
func TestDisplayFitsTheDialog(t *testing.T) {
	long := func(c string) string { return "[" + strings.Repeat(c, 25) + ".example]:2222" } // 40 runes
	r := Result{Names: []string{long("a"), long("b"), long("c"), "192.0.2.7"}}
	want := long("a") + " (also " + long("b") + ", +2 more)"
	if got := r.Display(); got != want {
		t.Fatalf("Display = %q, want %q", got, want)
	}
	if n := len([]rune(r.Display())); n > maxDisplay {
		t.Fatalf("%d runes, over %d", n, maxDisplay)
	}
	huge := strings.Repeat("h", 150) + ".example"
	r = Result{Names: []string{huge, "b.example", "c.example"}}
	if got := r.Display(); got != huge+" (+2 more)" {
		t.Fatalf("Display = %q", got)
	}
	// The example the dialog is sized for: four [host]:port names.
	r = Result{Names: []string{"[hydra.example]:2222", "[hydra.tail0a1b2.ts.net]:2222", "[203.0.113.37]:2222", "[100.64.10.20]:2222"}}
	if got, want := r.Display(), "[hydra.example]:2222 (also [hydra.tail0a1b2.ts.net]:2222, [203.0.113.37]:2222, [100.64.10.20]:2222)"; got != want {
		t.Fatalf("Display = %q, want %q", got, want)
	}
}

// The name ssh was given comes first when it is one of the key's names
// (the most specific candidate: "[host]:port" before "host"); the rest
// keep file order.
func TestCommandLineNameFirst(t *testing.T) {
	k := key(t)
	p := write(t,
		entry("[old.example]:2222,[hydra.example]:2222", k),
		entry("hydra.tail0a1b2.ts.net,[hydra.tail0a1b2.ts.net]:2222,[192.0.2.7]:2222", k),
	)
	r := lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "-p", "2222", "u@hydra.tail0a1b2.ts.net"}))
	want := []string{"[hydra.tail0a1b2.ts.net]:2222", "[old.example]:2222", "[hydra.example]:2222", "hydra.tail0a1b2.ts.net", "[192.0.2.7]:2222"}
	if !reflect.DeepEqual(r.Names, want) {
		t.Fatalf("names %v, want %v", r.Names, want)
	}
	if got := r.Display(); got != "[hydra.tail0a1b2.ts.net]:2222 (also [old.example]:2222, [hydra.example]:2222, +2 more)" {
		t.Fatalf("display %q", got)
	}
	// Without a port the bare name is the one ssh looked up.
	r = lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "hydra.tail0a1b2.ts.net"}))
	if r.Names[0] != "hydra.tail0a1b2.ts.net" || len(r.Names) != 5 {
		t.Fatalf("names %v", r.Names)
	}
	// A command line naming none of them leaves file order.
	r = lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "elsewhere.example"}))
	if r.Names[0] != "[old.example]:2222" || len(r.Names) != 5 {
		t.Fatalf("names %v", r.Names)
	}
}

// The command line only reorders: a candidate that is not one of this
// key's names is never shown, not even when another key has it.
func TestCandidateNotInKnownHostsNeverShown(t *testing.T) {
	k, other := key(t), key(t)
	p := write(t, entry("hydra.example,192.0.2.7", k), entry("evil.example", other))
	for _, args := range [][]string{
		{"ssh", "evil.example"},
		{"ssh", "-p", "2222", "evil.example"},
		{"ssh", "attacker.example"},
	} {
		r := lookup(t, p, k, CandidatesFromArgs(args))
		if got := r.Display(); got != "hydra.example (also 192.0.2.7)" {
			t.Fatalf("%v: display %q", args, got)
		}
	}
}

// A hashed entry still names the key only through a candidate it
// confirms; without one it is neither shown nor counted.
func TestHashedNamesOnlyViaCandidates(t *testing.T) {
	k := key(t)
	salt := []byte("hydrasalthydrasalt01")
	p := write(t, entry("hydra.example", k), entry(HashName("hidden.example", salt)+","+HashName("[hidden.example]:2222", salt), k))
	if got := lookup(t, p, k, nil).Display(); got != "hydra.example" {
		t.Fatalf("display without candidates %q", got)
	}
	if got := lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "other.example"})).Display(); got != "hydra.example" {
		t.Fatalf("display with unrelated candidates %q", got)
	}
	r := lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "-p", "2222", "hidden.example"}))
	if got := r.Display(); got != "[hidden.example]:2222 (also hydra.example, hidden.example)" {
		t.Fatalf("display %q (names %v)", got, r.Names)
	}
}

// A name listed on several lines is shown once.
func TestDisplayDuplicatesOnce(t *testing.T) {
	k := key(t)
	p := write(t, entry("hydra.example,192.0.2.7", k), entry("192.0.2.7,hydra.example", k), entry("hydra.example", k))
	if got := lookup(t, p, k, CandidatesFromArgs([]string{"ssh", "192.0.2.7"})).Display(); got != "192.0.2.7 (also hydra.example)" {
		t.Fatalf("display %q", got)
	}
}

// ---------------------------------------------------------------------------
// CandidatesFromArgs

func hasWellKnownSuffix(t *testing.T, in string, got []string) []string {
	t.Helper()
	if len(got) < len(WellKnown) || !reflect.DeepEqual(got[len(got)-len(WellKnown):], WellKnown) {
		t.Fatalf("CandidatesFromArgs(%q) = %v: must end with WellKnown %v", in, got, WellKnown)
	}
	return got[:len(got)-len(WellKnown)]
}

func TestCandidatesFromArgs(t *testing.T) {
	cases := map[string][]string{
		"ssh git@github.com git-upload-pack 'atas/nazar'":  {"github.com"},
		"ssh -o SendEnv=GIT_PROTOCOL -p 2222 git@10.0.0.1": {"[10.0.0.1]:2222", "10.0.0.1"},
		"ssh -p22 host":                    {"host"},
		"ssh -i /k -l root box.lan uptime": {"box.lan"},
		"ssh ssh://git@example.com:7999/x": {"[example.com]:7999", "example.com"},
		// extra cases
		"ssh":            {},
		"ssh -p 22 host": {"host"},
		"ssh -p":         {},
		"ssh -J jump.example -F /dev/null target.example": {"target.example"},
		"ssh -4 -A -v -T git@github.com":                  {"github.com"},
		"ssh a@b@c.example":                               {"c.example"},
		"ssh ssh://git@example.com/x":                     {"example.com"},
		"ssh git@evil/../x":                               {},
		"ssh git@[::1]":                                   {},
	}
	for in, want := range cases {
		got := hasWellKnownSuffix(t, in, CandidatesFromArgs(strings.Fields(in)))
		if len(got) == 0 && len(want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("CandidatesFromArgs(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCandidatesFromNoArgs(t *testing.T) {
	for _, args := range [][]string{nil, {}} {
		got := CandidatesFromArgs(args)
		if !reflect.DeepEqual(got, WellKnown) {
			t.Fatalf("CandidatesFromArgs(%v) = %v, want WellKnown", args, got)
		}
	}
}

func TestWellKnownIncludesGitHub(t *testing.T) {
	if !slices.Contains(WellKnown, "github.com") {
		t.Fatalf("WellKnown %v lacks github.com", WellKnown)
	}
}

// Callers may modify the returned slice; that must not corrupt WellKnown.
func TestCandidatesDoNotAliasWellKnown(t *testing.T) {
	before := slices.Clone(WellKnown)
	for _, args := range [][]string{{"ssh"}, {"ssh", "host.example"}} {
		got := CandidatesFromArgs(args)
		for i := range got {
			got[i] = "tampered"
		}
		if !reflect.DeepEqual(WellKnown, before) {
			t.Fatalf("WellKnown changed to %v", WellKnown)
		}
	}
}

// ---------------------------------------------------------------------------
// Fuzzing: arbitrary file contents never crash Lookup, and without
// candidates the only names are plain, positive host names.

func FuzzLookup(f *testing.F) {
	k := key(f)
	f.Add(entry("box.example,!no,*.x,|1|c2FsdA==|aGFzaA==", k))
	f.Add("@cert-authority * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\r\n")
	f.Add("\x00\xff garbage\n\n#\n")
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, content string) {
		p := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		r, _ := Lookup(p, k, nil)
		for _, n := range r.Names {
			if n == "" || strings.HasPrefix(n, "|") || strings.HasPrefix(n, "!") || strings.ContainsAny(n, "*?") {
				t.Fatalf("Lookup named the key %q from %q", n, content)
			}
		}
	})
}

func FuzzCandidatesFromArgs(f *testing.F) {
	f.Add("ssh -p 2222 git@example.com cmd")
	f.Add("ssh ssh://u@[::1]:22/x")
	f.Fuzz(func(t *testing.T, line string) {
		got := CandidatesFromArgs(strings.Fields(line))
		if len(got) < len(WellKnown) {
			t.Fatalf("%v lacks WellKnown", got)
		}
		for _, c := range got[:len(got)-len(WellKnown)] {
			if c == "" || strings.ContainsAny(c, " \t\r\n") {
				t.Fatalf("unsafe candidate %q from %q", c, line)
			}
		}
	})
}
