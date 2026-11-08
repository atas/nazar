package audit

import "path/filepath"

// Elided replaces every command-line argument that is not a plain word.
const Elided = "…"

// MaxWord is the longest argument RedactArgs keeps, in bytes (a plain word
// is ASCII, so bytes are characters).
const MaxWord = 32

// RedactArgs returns argv as it is logged under audit.args redacted (spec
// 4.6): an allowlist, not a search for secrets. The
// program (args[0]) becomes its base name. Every other element is kept only
// if it is a plain word (see PlainWord) and otherwise becomes Elided, so
// values, URLs, --flag=value, user:pass, quoted strings, sh -c scripts and
// long tokens never reach the log. Pattern-based secret detection was
// rejected because it always misses some shape. The result has the length
// of args; the input is never modified.
func RedactArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	out[0] = Program(args[0])
	for i, a := range args[1:] {
		if PlainWord(a) {
			out[i+1] = a
		} else {
			out[i+1] = Elided
		}
	}
	return out
}

// Program is the logged name of argv[0]: its base name. It is caller
// controlled and may be anything; Format quotes it so that a crafted name
// can never read as a different command line.
func Program(argv0 string) string {
	return filepath.Base(argv0)
}

// PlainWord reports whether a is an argument the audit log may keep: 1 to
// MaxWord bytes of letters, digits, '.', '_', '-' and '/', or, when it
// starts with '-', a bare flag that cannot carry a glued value: one short
// option (-v, -n, -1), "--" alone, or one long option (--force, --dry-run:
// "--" then a letter or digit, then letters, digits, '_' and '-'). A short
// option with anything after it (-la, -j8, -p2222, -pSECRET, -F/dev/null)
// is refused, because -pSECRET is how mysql and sshpass take a password and
// the log cannot tell it from a cluster. Everything with '=', '@', ':', '?',
// '&', whitespace, quotes, control characters or a non-ASCII byte is
// refused too.
func PlainWord(a string) bool {
	if a == "" || len(a) > MaxWord {
		return false
	}
	if a[0] == '-' {
		switch {
		case len(a) == 2 && a[1] != '-':
			return alnum(a[1])
		case a == "--":
			return true
		case len(a) > 2 && a[1] == '-' && alnum(a[2]):
			return plainRun(a[3:], false)
		}
		return false
	}
	return plainRun(a, true)
}

// plainRun reports whether every byte of s is a letter, a digit, '_' or
// '-', or, when path is set, '.' or '/'.
func plainRun(s string, path bool) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case alnum(c), c == '_', c == '-':
		case path && (c == '.' || c == '/'):
		default:
			return false
		}
	}
	return true
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
