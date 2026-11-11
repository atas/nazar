package main

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/peertrust"
	linuxfiles "github.com/atas/nazar/packaging/linux"
)

// `nazar install` on Linux: a systemd user service for the nazar-agent next
// to this CLI, the record of both programs' hashes (core/peertrust) and the
// links. What needs root is a separate step, once per user, through sudo:
// `install --system`. This file has no _linux suffix on purpose: everything
// it touches outside HOME and the system root goes through seams, so its
// tests run on every OS. The seams' production values run only on Linux
// (main sets them there).

const (
	agentService = "nazar-agent.service"
	// policyFile and udevRuleFile are where install --system puts the two
	// packaging files, under a.sysRoot.
	policyFile   = "/usr/share/polkit-1/actions/dev.nazar.authenticate.policy"
	udevRuleFile = "/etc/udev/rules.d/70-nazar-tpm.rules"
	// policyOwnerKey is the annotation that names the action's owners.
	policyOwnerKey = "org.freedesktop.policykit.owner"
	// agentAnswerWait is how long install waits for the restarted agent's
	// control socket to answer.
	agentAnswerWait = 10 * time.Second
	agentAnswerPoll = 200 * time.Millisecond
)

// unitPathRE: the agent's path goes into the unit file as it is. A space
// would split ExecStart, and % and $ are systemd's own syntax.
var unitPathRE = regexp.MustCompile(`^/[A-Za-z0-9._/+@-]+$`)

// runSystemctl runs /usr/bin/systemctl --user (absolute path, never $PATH).
func runSystemctl(args ...string) error {
	out, err := exec.Command("/usr/bin/systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runSysCommand runs one of install --system's programs by absolute path.
func runSysCommand(argv0 string, args ...string) error {
	if !filepath.IsAbs(argv0) {
		return fmt.Errorf("%s: not an absolute path", argv0)
	}
	out, err := exec.Command(argv0, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", argv0, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// openTPM opens and closes the TPM's resource manager device, sends nothing
// to it, and says whether this user may use it.
func openTPM() error {
	f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// agentUnit is the systemd user service that runs the agent.
func agentUnit(agent string) []byte {
	return []byte(`[Unit]
Description=nazar agent (SSH keys, secrets and credentials in the TPM)
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecStart=` + agent + `
Restart=on-failure
RestartSec=2

[Install]
WantedBy=graphical-session.target
`)
}

// LinuxInstallation is install's and uninstall's --json reply on Linux.
type LinuxInstallation struct {
	control.TypeMeta
	Unit        string   `json:"unit"`
	UnitFile    string   `json:"unitFile"`
	Agent       string   `json:"agent,omitempty"`
	Links       []string `json:"links"`
	Kept        []string `json:"kept,omitempty"`
	PathHint    string   `json:"pathHint,omitempty"`
	Warning     string   `json:"warning,omitempty"`
	Uninstalled bool     `json:"uninstalled"`
}

// SystemInstallation is install --system's and uninstall --system's --json
// reply.
type SystemInstallation struct {
	control.TypeMeta
	Policy      string   `json:"policy"`
	UdevRule    string   `json:"udevRule"`
	Owners      []string `json:"owners,omitempty"`
	Next        string   `json:"next,omitempty"`
	Kept        []string `json:"kept,omitempty"`
	Uninstalled bool     `json:"uninstalled"`
}

// linuxInstallFlags are install's and uninstall's arguments on Linux.
type linuxInstallFlags struct {
	binDir  string
	noLinks bool
	system  bool
}

func (a *app) parseLinuxInstall(name string, args []string) (linuxInstallFlags, error) {
	var out linuxInstallFlags
	fs := a.flags(name)
	bin := fs.String("bin-dir", a.defaultBinDir(), "")
	sys := fs.Bool("system", false, "")
	var nl *bool
	if name == "install" {
		nl = fs.Bool("no-links", false, "")
	}
	if _, err := a.parse(fs, args, 0); err != nil {
		return out, err
	}
	binSet := false
	fs.Visit(func(f *flag.Flag) { binSet = binSet || f.Name == "bin-dir" })
	out.binDir, out.system = *bin, *sys
	out.noLinks = nl != nil && *nl
	if out.system && (binSet || out.noLinks) {
		return out, control.NewProblem(control.CodeUsage, "%s: --system takes no other flag", name)
	}
	if out.noLinks && binSet {
		return out, control.NewProblem(control.CodeUsage, "%s: --no-links and --bin-dir don't go together", name)
	}
	if !out.system && !filepath.IsAbs(out.binDir) {
		return out, control.NewProblem(control.CodeUsage, "%s: --bin-dir must be an absolute path", name)
	}
	return out, nil
}

// agentUnitFile is where the user service manager looks for the unit.
func (a *app) agentUnitFile() string {
	return filepath.Join(a.home(), ".config", "systemd", "user", agentService)
}

// isLinuxCLILink: a link target that names a nazar CLI of some version:
// an absolute path whose file is called nazar. The string is judged, never
// followed, because an upgrade may have removed the old version's folder.
func isLinuxCLILink(target string) bool {
	return filepath.IsAbs(target) && filepath.Base(target) == cliExeName
}

// checkLinuxLinkSlot: path may be created or replaced only when nothing is
// there or it is a link to a nazar CLI. Anything else is the user's and is
// never touched.
func checkLinuxLinkSlot(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if t, err := os.Readlink(path); err == nil && isLinuxCLILink(t) {
			return nil
		}
	}
	return control.NewProblem(control.CodeError, "%s exists and is not a nazar link; move it away or use --bin-dir", path)
}

// installLinux sets up the systemd user service for the nazar-agent next to
// this CLI. Every check runs before the first write or systemctl call, so a
// refusal changes nothing, and running it again repairs the setup, which is
// also what an upgrade needs: the record then names the new programs.
func (a *app) installLinux(args []string) int {
	opts, err := a.parseLinuxInstall("install", args)
	if err != nil {
		return a.fail(err)
	}
	if opts.system {
		return a.installSystem()
	}
	if a.systemctl == nil || a.tpmAccess == nil || a.euid == nil || a.executable == nil {
		return a.fail(control.NewProblem(control.CodeError, "install: not available in this build"))
	}
	if a.euid() == 0 {
		return a.fail(control.NewProblem(control.CodeError, "install: run it as yourself, not as root; only install --system takes sudo"))
	}
	if !filepath.IsAbs(a.home()) {
		return a.fail(control.NewProblem(control.CodeError, "install: $HOME must be an absolute path"))
	}
	cli, err := a.executable()
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "install: can't tell where this nazar runs from: %v", err))
	}
	if filepath.Base(cli) != cliExeName {
		return a.fail(control.NewProblem(control.CodeError, "install: run it from the program named nazar, not %s", cli))
	}
	agent, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(cli), appExeName))
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "install: no nazar-agent next to %s: %v", cli, err))
	}
	if !unitPathRE.MatchString(agent) {
		return a.fail(control.NewProblem(control.CodeError, "install: the path %q can't be written into a systemd unit; move nazar to a plain path", agent))
	}
	if _, err := os.Stat(filepath.Join(a.sysRoot, policyFile)); err != nil || a.tpmAccess() != nil {
		return a.fail(control.NewProblem(control.CodeError, "install: can't use the TPM yet: run once, then log out and back in: sudo %s install --system", cli))
	}
	cliHash, err := peertrust.HashFile(cli)
	if err != nil {
		return a.fail(err)
	}
	agentHash, err := peertrust.HashFile(agent)
	if err != nil {
		return a.fail(err)
	}
	var links []string
	if !opts.noLinks {
		for _, n := range linkNames {
			l := filepath.Join(opts.binDir, n)
			if err := checkLinuxLinkSlot(l); err != nil {
				return a.fail(err)
			}
			links = append(links, l)
		}
	}
	if err := a.ensurePrivateRoot(); err != nil {
		return a.fail(err)
	}
	unit := a.agentUnitFile()
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		return a.fail(err)
	}
	if err := writeFileAtomic(unit, agentUnit(agent), 0o644); err != nil {
		return a.fail(err)
	}
	rec := peertrust.Record{CLI: peertrust.Binary{Path: cli, SHA256: cliHash}, Agent: peertrust.Binary{Path: agent, SHA256: agentHash}}
	if err := peertrust.Write(a.home(), rec); err != nil {
		return a.fail(err)
	}
	if len(links) > 0 {
		if err := os.MkdirAll(opts.binDir, 0o755); err != nil {
			return a.fail(err)
		}
	}
	for _, l := range links {
		os.Remove(l) // checkLinuxLinkSlot allowed only a missing path or a nazar link
		if err := os.Symlink(cli, l); err != nil {
			return a.fail(err)
		}
	}
	for _, call := range [][]string{{"daemon-reload"}, {"enable", agentService}, {"restart", agentService}} {
		if err := a.systemctl(call...); err != nil {
			return a.fail(control.NewProblem(control.CodeError, "install: %s written to %s but not started: %v", agentService, unit, err))
		}
	}
	if err := a.waitForAgent(); err != nil {
		return a.fail(control.NewProblem(control.CodeError, "install: %s started but nazar-agent did not answer in %v: %v; see its log: journalctl --user -u %s", agentService, agentAnswerWait, err, agentService))
	}
	out := LinuxInstallation{TypeMeta: control.Meta("Installation"), Unit: agentService, UnitFile: unit, Agent: agent, Links: links}
	if out.Links == nil {
		out.Links = []string{}
	}
	if !opts.noLinks && !onPath(a.getenv("PATH"), opts.binDir) {
		out.PathHint = fmt.Sprintf("add %s to PATH", opts.binDir)
	}
	// The unit is wanted by graphical-session.target, which the desktop
	// activates at login (GNOME and KDE do; Xfce, MATE, sway, i3 and
	// Hyprland may not without extra setup). This install started the
	// agent itself, so status looks fine either way: where the target is
	// not active in this session, nothing will start the agent at the next
	// login, and install says so.
	if a.systemctl("is-active", graphicalTarget) != nil {
		out.Warning = noGraphicalTargetWarning
	}
	return a.emit(out, func() {
		fmt.Fprintf(a.stdout, "installed %s\n  systemd user service %s (%s)\n", term(agent), term(agentService), term(unit))
		if len(links) > 0 {
			fmt.Fprintf(a.stdout, "  links %s\n", term(strings.Join(links, ", ")))
		}
		if out.PathHint != "" {
			fmt.Fprintf(a.stdout, "  %s\n", term(out.PathHint))
		}
		if out.Warning != "" {
			fmt.Fprintf(a.stdout, "  warning: %s\n", term(out.Warning))
		}
	})
}

// graphicalTarget is the systemd user target that starts the unit at
// login (agentUnit's WantedBy).
const graphicalTarget = "graphical-session.target"

// noGraphicalTargetWarning is install's warning when graphicalTarget is
// not active in the session install ran in.
const noGraphicalTargetWarning = "graphical-session.target is not active in this session, so nothing starts nazar-agent.service at your next login (GNOME and KDE activate it; Xfce, MATE, sway, i3 and Hyprland may not); start it then with: systemctl --user start nazar-agent.service"

// waitForAgent asks the restarted agent for its status until it answers,
// through the check every command makes of who listens on the socket, so an
// answer also says this CLI and the agent trust each other.
func (a *app) waitForAgent() error {
	ctx, cancel := context.WithTimeout(context.Background(), agentAnswerWait)
	defer cancel()
	for waited := time.Duration(0); ; waited += agentAnswerPoll {
		var st control.Status
		err := a.client().Call(ctx, control.NewRequest(control.CmdStatus, nil), control.KindStatus, &st)
		if err == nil {
			return nil
		}
		if waited >= agentAnswerWait || ctx.Err() != nil {
			return err
		}
		a.pause(agentAnswerPoll)
	}
}

// uninstallLinux stops and removes the service and the links in the bin
// folder that point at a nazar CLI. ~/.nazar is kept. An agent that could
// not be stopped is still running, so nothing is removed then; a unit that
// is not there has nothing to stop.
func (a *app) uninstallLinux(args []string) int {
	opts, err := a.parseLinuxInstall("uninstall", args)
	if err != nil {
		return a.fail(err)
	}
	if opts.system {
		return a.uninstallSystem()
	}
	if a.systemctl == nil || a.euid == nil {
		return a.fail(control.NewProblem(control.CodeError, "uninstall: not available in this build"))
	}
	if a.euid() == 0 {
		return a.fail(control.NewProblem(control.CodeError, "uninstall: run it as yourself, not as root; only uninstall --system takes sudo"))
	}
	if !filepath.IsAbs(a.home()) {
		return a.fail(control.NewProblem(control.CodeError, "uninstall: $HOME must be an absolute path"))
	}
	unit := a.agentUnitFile()
	_, statErr := os.Lstat(unit)
	if err := a.systemctl("disable", "--now", agentService); err != nil && statErr == nil {
		return a.fail(control.NewProblem(control.CodeError, "uninstall: can't stop %s, so nothing was removed: %v", agentService, err))
	}
	if err := os.Remove(unit); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return a.fail(err)
	}
	removed := []string{}
	for _, n := range linkNames {
		l := filepath.Join(opts.binDir, n)
		if t, err := os.Readlink(l); err == nil && isLinuxCLILink(t) {
			if os.Remove(l) == nil {
				removed = append(removed, l)
			}
		}
	}
	kept := []string{layout.Root(a.home())}
	out := LinuxInstallation{TypeMeta: control.Meta("Installation"), Unit: agentService, UnitFile: unit, Links: removed, Kept: kept, Uninstalled: true}
	return a.emit(out, func() {
		fmt.Fprintf(a.stdout, "uninstalled %s\n", term(agentService))
		fmt.Fprintf(a.stdout, "  kept %s\n", term(strings.Join(kept, ", ")))
	})
}

// readPolicyOwners reads the owners named in an installed policy: none when
// there is no file, an error when there is one nazar can't read, because
// writing over it would drop the other users.
func readPolicyOwners(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Actions []struct {
			Annotations []struct {
				Key   string `xml:"key,attr"`
				Value string `xml:",chardata"`
			} `xml:"annotate"`
		} `xml:"action"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var owners []string
	for _, act := range doc.Actions {
		for _, an := range act.Annotations {
			if an.Key == policyOwnerKey {
				for _, o := range strings.Fields(an.Value) {
					if !slices.Contains(owners, o) {
						owners = append(owners, o)
					}
				}
			}
		}
	}
	return owners, nil
}

// installSystem is what needs root, once per user: the polkit action, owned
// by the user who ran sudo as well as the owners it had, the udev rule for
// /dev/tpmrm0 and the tss group. The policy comes from PolicyFor, which is
// asked before anything is written, so it never goes in with the
// placeholder left in, and nothing of an installed file but its owners is
// kept.
func (a *app) installSystem() int {
	if a.sysCommand == nil || a.euid == nil {
		return a.fail(control.NewProblem(control.CodeError, "install: not available in this build"))
	}
	user := a.getenv("SUDO_USER")
	if a.euid() != 0 || user == "" || user == "root" {
		return a.fail(control.NewProblem(control.CodeError, "install --system: run it with sudo"))
	}
	self := "unix-user:" + user
	if _, err := linuxfiles.PolicyFor([]string{self}); err != nil {
		return a.fail(control.NewProblem(control.CodeError, "install --system: %v", err))
	}
	policyPath := filepath.Join(a.sysRoot, policyFile)
	owners, err := readPolicyOwners(policyPath)
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "install --system: can't read the owners of %s, so it was left as it is: %v", policyPath, err))
	}
	if !slices.Contains(owners, self) {
		owners = append(owners, self)
	}
	policy, err := linuxfiles.PolicyFor(owners)
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "install --system: %s, so it was left as it is: %v", policyPath, err))
	}
	rulePath := filepath.Join(a.sysRoot, udevRuleFile)
	for _, f := range []struct {
		path string
		data []byte
	}{{policyPath, policy}, {rulePath, linuxfiles.UdevRule}} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return a.fail(err)
		}
		if err := writeFileAtomic(f.path, f.data, 0o644); err != nil {
			return a.fail(err)
		}
	}
	if a.sysCommand("/usr/bin/getent", "group", "tss") != nil {
		if err := a.sysCommand("/usr/sbin/groupadd", "--system", "tss"); err != nil {
			return a.fail(control.NewProblem(control.CodeError, "install --system: %v", err))
		}
	}
	for _, c := range [][]string{
		{"/usr/sbin/usermod", "-aG", "tss", user},
		{"/usr/bin/udevadm", "control", "--reload-rules"},
		{"/usr/bin/udevadm", "trigger", "--subsystem-match=tpmrm", "--action=change"},
	} {
		if err := a.sysCommand(c[0], c[1:]...); err != nil {
			return a.fail(control.NewProblem(control.CodeError, "install --system: %v", err))
		}
	}
	const next = "done; log out and back in, then run as yourself: nazar install"
	out := SystemInstallation{TypeMeta: control.Meta("SystemInstallation"), Policy: policyPath, UdevRule: rulePath, Owners: owners, Next: next}
	return a.emit(out, func() { fmt.Fprintln(a.stdout, next) })
}

// uninstallSystem removes the two files. Group membership stays: the group
// may be in use by others, and tss is not nazar's.
func (a *app) uninstallSystem() int {
	if a.euid == nil {
		return a.fail(control.NewProblem(control.CodeError, "uninstall: not available in this build"))
	}
	if a.euid() != 0 {
		return a.fail(control.NewProblem(control.CodeError, "uninstall --system: run it with sudo"))
	}
	policyPath, rulePath := filepath.Join(a.sysRoot, policyFile), filepath.Join(a.sysRoot, udevRuleFile)
	for _, p := range []string{policyPath, rulePath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return a.fail(err)
		}
	}
	kept := []string{"the tss group and its members"}
	out := SystemInstallation{TypeMeta: control.Meta("SystemInstallation"), Policy: policyPath, UdevRule: rulePath, Kept: kept, Uninstalled: true}
	return a.emit(out, func() {
		fmt.Fprintf(a.stdout, "removed %s, %s\n  kept %s\n", term(policyPath), term(rulePath), term(strings.Join(kept, ", ")))
	})
}
