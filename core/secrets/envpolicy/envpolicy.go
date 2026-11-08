// Package envpolicy is the environment policy of nazar run (secrets design
// 6.3.4): the names nazar sets itself and the names nothing may put in a
// receiver's environment. The receiver's environment is an allowlist the
// agent builds; the deny set is not what protects it, but what keeps an
// envAllow line from ever naming a variable that loads code, changes which
// program runs, or redirects configuration or TLS trust. config check and
// the agent read the same lists from here.
package envpolicy

import (
	"regexp"
	"slices"
	"strings"
)

// denyPrefixes are matched case-insensitively against the start of a name.
// npm reads npm_config_* and NPM_CONFIG_* alike, which is why every match
// here ignores case (over-refusing is free). libuv's UV_THREADPOOL_SIZE is
// collateral of UV_, accepted.
var denyPrefixes = []string{
	"NAZAR_", "DYLD_", "LD_", "npm_config_", "PNPM_", "BUN_", "COREPACK_", "YARN_",
	"PIP_", "PIPX_", "UV_", "PYENV_", "MISE_", "ASDF_", "RTX_", "XDG_", "GIT_", "SSL_CERT_",
	// Beyond the design's list (from a review): every PYTHON* and NODE_*
	// variable (PYTHONWARNINGS imports a module, NODE_COMPILE_CACHE loads
	// compiled code; NODE_ENV is the one exception, allowedNames), and the
	// other Node version managers.
	"PYTHON", "NODE_", "VOLTA_", "NVM_", "FNM_", "NODENV_",
}

// allowedNames are exceptions to a deny prefix: they select a mode and
// load nothing.
var allowedNames = []string{"NODE_ENV"}

// denyNames are matched case-insensitively against the whole name. SHELL is
// here beyond the design's list: a program that runs commands through
// $SHELL is the class 6.3.4 closes, and 7.1 refuses it for --as already.
var denyNames = []string{
	"NODE_OPTIONS", "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE", "NODE_EXTRA_CA_CERTS",
	"NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
	"PYTHONEXECUTABLE", "PYTHONUSERBASE", "PYTHONPYCACHEPREFIX", "PYTHONPLATLIBDIR",
	"PYTHONHTTPSVERIFY", "VIRTUAL_ENV", "CONDA_PREFIX", "BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS",
	"BASHOPTS", "PERL5OPT", "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
	"_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SHELL",
	// Review: programs that run a command they read from the
	// environment (Python's webbrowser and pydoc among them), OpenSSL's
	// config and module paths (a provider is a library it loads), and the
	// file TLS session keys are written to.
	"BROWSER", "EDITOR", "VISUAL", "PAGER", "MANPAGER", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "SSLKEYLOGFILE",
}

// baseNames are the variables nazar sets itself (envpolicy's builder):
// PATH from defaults.trustedPath, HOME/USER/LOGNAME from the user
// database, TMPDIR from the system, LANG/LC_*/TERM copied only when their
// value is a plain locale or terminal name.
var baseNames = []string{"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "TERM"}

// Denied reports whether name is in the deny set, and which entry it fell
// under: the name itself, or the prefix followed by "*".
func Denied(name string) (string, bool) {
	for _, n := range denyNames {
		if strings.EqualFold(name, n) {
			return n, true
		}
	}
	for _, n := range allowedNames {
		if strings.EqualFold(name, n) {
			return "", false
		}
	}
	for _, p := range denyPrefixes {
		if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
			return p + "*", true
		}
	}
	return "", false
}

// IsBase reports whether nazar sets name itself, ignoring case.
func IsBase(name string) bool {
	for _, n := range baseNames {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return len(name) >= 3 && strings.EqualFold(name[:3], "LC_")
}

var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ValidName reports whether name is an environment variable name nazar
// accepts: ASCII letters, digits and _, not led by a digit, at most 128
// bytes. Go's $ matches only at the end of the text, so a trailing newline
// is refused.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Host is what the agent knows about the receiver's user from its own
// sources, never from the caller: the home directory and name from the
// user database, and the per-user temporary directory.
type Host struct {
	Home, User, TmpDir string
}

// Input is everything Build reads.
type Input struct {
	TrustedPath []string // defaults.trustedPath, in order: the receiver's PATH
	Host        Host
	CallerEnv   []string // NAME=VALUE as the caller sent it: input, never a base
	Allow       []string // the secret's envAllow (approved config)
	Loader      []string // NAME=VALUE the agent adds for its loaders
}

// localeRE is the shape a LANG, LC_* or TERM value must have to be copied:
// a locale or terminal name, which libc's locale tables and terminfo
// consume, and which can name no code.
var localeRE = regexp.MustCompile(`^[A-Za-z0-9_.@+-]{1,32}$`)

// lcNameRE: LC_ followed by an upper-case category name.
var lcNameRE = regexp.MustCompile(`^LC_[A-Z]+$`)

// Build returns the receiver's complete startup environment (secrets design
// 6.3.4) and the envAllow names the caller actually supplied, in envAllow
// order. The base comes from the agent (PATH from trustedPath, HOME, USER,
// LOGNAME, TMPDIR from Host), then LANG, LC_* and TERM copied from the
// caller when their values are plain names, then the allowed names with
// the caller's values, then the loader variables. A caller name sent more
// than once has no one value and is not copied. An allowed name that is in
// the deny set or the base is never copied, whatever the list says.
func Build(in Input) (env, passed []string) {
	seen := map[string]int{}
	val := map[string]string{}
	var order []string
	for _, kv := range in.CallerEnv {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if seen[k] == 0 {
			order = append(order, k)
		}
		seen[k]++
		val[k] = v
	}
	one := func(k string) (string, bool) {
		if seen[k] != 1 {
			return "", false
		}
		return val[k], true
	}
	env = append(env, "PATH="+strings.Join(in.TrustedPath, ":"))
	for _, kv := range [][2]string{{"HOME", in.Host.Home}, {"USER", in.Host.User}, {"LOGNAME", in.Host.User}, {"TMPDIR", in.Host.TmpDir}} {
		if kv[1] != "" { // never an empty base value; the agent refuses a host without home or user
			env = append(env, kv[0]+"="+kv[1])
		}
	}
	if v, ok := one("LANG"); ok && localeRE.MatchString(v) {
		env = append(env, "LANG="+v)
	}
	for _, k := range order {
		if lcNameRE.MatchString(k) {
			if v, ok := one(k); ok && localeRE.MatchString(v) {
				env = append(env, k+"="+v)
			}
		}
	}
	if v, ok := one("TERM"); ok && localeRE.MatchString(v) {
		env = append(env, "TERM="+v)
	}
	for _, k := range in.Allow {
		if _, denied := Denied(k); denied || IsBase(k) || !ValidName(k) || slices.Contains(passed, k) {
			continue
		}
		if v, ok := one(k); ok {
			env = append(env, k+"="+v)
			passed = append(passed, k)
		}
	}
	return append(env, in.Loader...), passed
}

// Names returns the names of env's NAME=VALUE entries, in order.
func Names(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		out = append(out, k)
	}
	return out
}
