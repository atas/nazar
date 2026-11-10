// Package layout is where nazar keeps its files: one folder in the home,
// like ~/.gnupg (spec 4.2).
//
//	~/.nazar/            0700
//	├── config/          0700: config.yaml (0600), the file the user approves
//	├── keys/            public keys (<name>.pub), k8s CA certs (k8s-ca-<context>.crt)
//	├── run/             0700: agent.sock, control.sock, the run sockets; recreated on every start
//	├── vault/           0700, Linux only: the file vault's items (0600), one file per item
//	└── log/             0700, Linux only: audit.log and audit.log.1 (0600); made by the first entry
//
// Every default path of the core, the CLI and the agent comes from here.
package layout

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/atas/nazar/core/unixsock"
)

// The same paths as ~ text, for messages, config defaults and docs; each is
// what its function gives for the home "~" (layout_test).
const (
	ConfigFileTilde  = "~/.nazar/config/config.yaml"
	KeysDirTilde     = "~/.nazar/keys"
	AgentSocketTilde = "~/.nazar/run/agent.sock"
)

// Root is ~/.nazar.
func Root(home string) string { return filepath.Join(home, ".nazar") }

// ConfigDir is ~/.nazar/config.
func ConfigDir(home string) string { return filepath.Join(Root(home), "config") }

// ConfigFile is ~/.nazar/config/config.yaml.
func ConfigFile(home string) string { return filepath.Join(ConfigDir(home), "config.yaml") }

// KeysDir is ~/.nazar/keys.
func KeysDir(home string) string { return filepath.Join(Root(home), "keys") }

// RunDir is ~/.nazar/run.
func RunDir(home string) string { return filepath.Join(Root(home), "run") }

// AgentSocket is ~/.nazar/run/agent.sock, ssh_agent.socket's default.
func AgentSocket(home string) string { return filepath.Join(RunDir(home), "agent.sock") }

// ControlSocket is ~/.nazar/run/control.sock.
func ControlSocket(home string) string { return filepath.Join(RunDir(home), "control.sock") }

// VaultDir is ~/.nazar/vault, the file vault's folder on Linux
// (core/platform/linux/vault). macOS keeps the vault in the Keychain and
// never makes it.
func VaultDir(home string) string { return filepath.Join(Root(home), "vault") }

// AuditLog is ~/.nazar/log/audit.log, nazar-agent's audit log on Linux
// (audit.FileSink makes the folder, 0700). macOS logs to the unified log and
// never makes it.
func AuditLog(home string) string { return filepath.Join(Root(home), "log", "audit.log") }

// Prepare makes the folders of the home that nazar-agent needs at start:
// ~/.nazar, config/ and run/, 0700 when it makes them. ~/.nazar and run/
// must then be real folders of this user with no group or other access
// (unixsock.CheckPrivateDir): the sockets are reached through both. An
// existing config/ is kept as it is.
func Prepare(home string) error {
	for _, dir := range []string{Root(home), ConfigDir(home), RunDir(home)} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if dir == ConfigDir(home) {
			continue
		}
		if err := unixsock.CheckPrivateDir(dir); err != nil {
			return err
		}
	}
	return nil
}
