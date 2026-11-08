// Package knownhosts names a server from its host key using the user's
// known_hosts file (spec 5, spike S7): plain entries are listed directly;
// hashed entries (|1|salt|hash) can only confirm a candidate name. Markers
// (@revoked, @cert-authority), negations (!host) and patterns (*, ?) never
// name a host, and only an entry for the exact key counts.
package knownhosts

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// MaxFileSize bounds how much of known_hosts is read.
const MaxFileSize = 16 << 20

// WellKnown are always tried against hashed entries.
var WellKnown = []string{"github.com", "gitlab.com", "bitbucket.org", "ssh.dev.azure.com"}

// Result is what Lookup found.
type Result struct {
	// Names are the known_hosts names for this key, no duplicates: the
	// first candidate among them, if any, then the rest in file order.
	Names       []string
	Fingerprint string // SHA256:... of the host key
}

// What Display shows: the first name and up to three more, within
// maxDisplay runes so that "login to … as user" stays on the dialog's
// first line whole; the rest are counted.
const (
	maxNamesShown = 4
	maxDisplay    = 100
)

// Display is the destination shown to the user: every name, as
// "a (also b, c, d, +2 more)", else the fingerprint. One server reached
// under several names must not look like another server.
func (r Result) Display() string {
	if len(r.Names) == 0 {
		return "host key " + r.Fingerprint
	}
	first, rest := r.Names[0], r.Names[1:]
	for k := min(len(rest), maxNamesShown-1); ; k-- {
		also := slices.Clone(rest[:k])
		if more := len(rest) - k; more > 0 {
			also = append(also, fmt.Sprintf("+%d more", more))
		}
		s := first
		switch {
		case k > 0:
			s += " (also " + strings.Join(also, ", ") + ")"
		case len(also) > 0:
			s += " (" + also[0] + ")" // "a (+3 more)"
		}
		if k == 0 || utf8.RuneCountInString(s) <= maxDisplay {
			return s
		}
	}
}

// Lookup returns the names under which key appears in the known_hosts file
// at path. A missing file is not an error. candidates are tried against
// hashed entries (see CandidatesFromArgs), and the first candidate that is
// one of the names is put first; they never add or change a name on their
// own. Unparseable lines are skipped, so an odd file never hides the
// entries around it.
func Lookup(path string, key ssh.PublicKey, candidates []string) (Result, error) {
	if key == nil {
		return Result{}, errors.New("knownhosts: nil key")
	}
	res := Result{Fingerprint: ssh.FingerprintSHA256(key)}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	defer f.Close()
	want := key.Marshal()
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			res.Names = append(res.Names, n)
		}
	}
	// The buffer may grow to the whole (capped) file, so one overlong line
	// never stops the scan and hides the entries after it.
	sc := bufio.NewScanner(io.LimitReader(f, MaxFileSize))
	sc.Buffer(make([]byte, 64*1024), MaxFileSize)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' || line[0] == '@' {
			continue // comments; markers (@revoked, @cert-authority) never name a host
		}
		_, hosts, k, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil || k == nil || !bytes.Equal(k.Marshal(), want) {
			continue
		}
		for _, h := range hosts {
			switch {
			case strings.HasPrefix(h, "|"):
				// Hashed: only "|1|salt|hash" is understood, and only a
				// candidate it confirms becomes a name.
				for _, c := range candidates {
					if c != "" && hashedMatch(h, c) {
						add(c)
					}
				}
			case strings.HasPrefix(h, "!") || strings.ContainsAny(h, "*?"):
				// Negations and patterns don't name a host.
			default:
				add(h)
			}
		}
	}
	for _, c := range candidates {
		if i := slices.Index(res.Names, c); i >= 0 {
			res.Names = slices.Insert(slices.Delete(res.Names, i, i+1), 0, c)
			break
		}
	}
	return res, sc.Err()
}

// hashedMatch tests "|1|base64(salt)|base64(hmac-sha1(salt, name))".
func hashedMatch(entry, name string) bool {
	parts := strings.Split(entry, "|")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	sum, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(sum) != sha1.Size {
		return false
	}
	m := hmac.New(sha1.New, salt)
	m.Write([]byte(name))
	return hmac.Equal(m.Sum(nil), sum)
}

// HashName returns a hashed known_hosts host field for name, as
// ssh-keygen -H writes it (for tests and for users comparing entries).
func HashName(name string, salt []byte) string {
	m := hmac.New(sha1.New, salt)
	m.Write([]byte(name))
	return "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// optionsWithValue are the ssh(1) options that take a separate argument.
const optionsWithValue = "BbcDEeFIiJLlmOoPpQRSWw"

// CandidatesFromArgs guesses host names from an ssh command line
// ("ssh -p 2222 git@example.com cmd") for testing hashed entries and for
// choosing which name comes first, most specific first: "[host]:port" when
// a non-default port is given (the name ssh looks up), the destination's
// host, then WellKnown. The returned slice never aliases WellKnown.
func CandidatesFromArgs(args []string) []string {
	dest, port := "", ""
	for i := 1; i < len(args) && dest == ""; i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				dest = args[i+1]
			}
			i++
		case a == "-p":
			if i+1 < len(args) {
				port = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "-p") && len(a) > 2:
			port = a[2:]
		case strings.HasPrefix(a, "-"):
			if len(a) == 2 && strings.ContainsRune(optionsWithValue, rune(a[1])) {
				i++ // option with a separate value
			}
		default:
			dest = a
		}
	}
	host := dest
	if strings.HasPrefix(dest, "ssh://") {
		host = ""
		if u, err := url.Parse(dest); err == nil {
			host = u.Hostname()
			if u.Port() != "" {
				port = u.Port()
			}
		}
	} else if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	out := make([]string, 0, 2+len(WellKnown))
	if safeName(host) {
		if port != "" && port != "22" && safeName(port) {
			out = append(out, "["+host+"]:"+port)
		}
		out = append(out, host)
	}
	return append(out, WellKnown...)
}

// safeName accepts a host name or port that can appear as a known_hosts
// host field: non-empty, no whitespace, no control characters and none of
// the characters that would make it a path, a quoted string or a pattern.
func safeName(s string) bool {
	if s == "" || strings.ContainsAny(s, " /'\"[]*?!|,") {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}
