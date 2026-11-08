package envpolicy

import "testing"

// Secrets design 6.3.4: the deny set is matched case-insensitively and
// names the entry a name fell under, so config check can say which.
func TestDenied(t *testing.T) {
	for name, entry := range map[string]string{
		"NODE_OPTIONS":                 "NODE_OPTIONS",
		"node_options":                 "NODE_OPTIONS",
		"npm_config_registry":          "npm_config_*",
		"Npm_Config_Registry":          "npm_config_*",
		"NPM_CONFIG_SCRIPT_SHELL":      "npm_config_*",
		"XDG_CONFIG_HOME":              "XDG_*",
		"GIT_SSH_COMMAND":              "GIT_*",
		"NODE_EXTRA_CA_CERTS":          "NODE_EXTRA_CA_CERTS",
		"NODE_TLS_REJECT_UNAUTHORIZED": "NODE_TLS_REJECT_UNAUTHORIZED",
		"DYLD_INSERT_LIBRARIES":        "DYLD_*",
		"LD_PRELOAD":                   "LD_*",
		"PYTHONPATH":                   "PYTHONPATH",
		"PYTHONSTARTUP":                "PYTHONSTARTUP",
		"PIP_INDEX_URL":                "PIP_*",
		"PIPX_HOME":                    "PIPX_*",
		"UV_INDEX_URL":                 "UV_*",
		"VIRTUAL_ENV":                  "VIRTUAL_ENV",
		"BASH_ENV":                     "BASH_ENV",
		"SSL_CERT_FILE":                "SSL_CERT_*",
		"REQUESTS_CA_BUNDLE":           "REQUESTS_CA_BUNDLE",
		"NAZAR_SECRET_SOCK":            "NAZAR_*",
		"NAZAR_TEST_PEER":              "NAZAR_*",
		"SHELL":                        "SHELL",
		"MISE_ENV":                     "MISE_*",
		"JAVA_TOOL_OPTIONS":            "JAVA_TOOL_OPTIONS",
	} {
		got, ok := Denied(name)
		if !ok || got != entry {
			t.Errorf("Denied(%q) = %q, %v; want %q", name, got, ok, entry)
		}
	}
	for _, name := range []string{"HTTPS_PROXY", "NODE_ENV", "BRAVE_MCP_LOG_LEVEL", "UVX", "NODE", "LANG"} {
		if got, ok := Denied(name); ok {
			t.Errorf("Denied(%q) = %q: not in the deny set", name, got)
		}
	}
}

func TestBase(t *testing.T) {
	for _, n := range []string{"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "path", "Home"} {
		if !IsBase(n) {
			t.Errorf("IsBase(%q) = false", n)
		}
	}
	for _, n := range []string{"HTTPS_PROXY", "TERMINFO", "LANGUAGE", "HOMEBREW_PREFIX", "PATHEXT"} {
		if IsBase(n) {
			t.Errorf("IsBase(%q) = true", n)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"A", "_x", "HTTPS_PROXY", "a1"} {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range []string{"", "1A", "A-B", "A=B", "A B", "Ä", "A\n", string(make([]byte, 129))} {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}

// Security review: variables that load code, run a command, write
// TLS keys or switch the interpreter, beyond the design's first list. All
// of PYTHON* and NODE_* is denied (NODE_ENV excepted).
func TestDeniedReviewAdditions(t *testing.T) {
	for name, entry := range map[string]string{
		"PYTHONWARNINGS":     "PYTHON*",
		"PYTHONBREAKPOINT":   "PYTHON*",
		"pythonsafepath":     "PYTHON*",
		"NODE_COMPILE_CACHE": "NODE_*",
		"NODE_ICU_DATA":      "NODE_*",
		"BROWSER":            "BROWSER",
		"EDITOR":             "EDITOR",
		"VISUAL":             "VISUAL",
		"PAGER":              "PAGER",
		"MANPAGER":           "MANPAGER",
		"OPENSSL_CONF":       "OPENSSL_CONF",
		"OPENSSL_MODULES":    "OPENSSL_MODULES",
		"OPENSSL_ENGINES":    "OPENSSL_ENGINES",
		"SSLKEYLOGFILE":      "SSLKEYLOGFILE",
		"VOLTA_HOME":         "VOLTA_*",
		"NVM_DIR":            "NVM_*",
		"FNM_DIR":            "FNM_*",
		"NODENV_VERSION":     "NODENV_*",
	} {
		if got, ok := Denied(name); !ok || got != entry {
			t.Errorf("Denied(%q) = %q, %v; want %q", name, got, ok, entry)
		}
	}
	if _, ok := Denied("NODE_ENV"); ok {
		t.Error("NODE_ENV only selects a mode and stays allowed")
	}
}
