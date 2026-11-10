package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/unixsock"
)

// labelRE: a LaunchAgent label is written into XML and file names.
var labelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

// runLaunchctl runs /bin/launchctl (absolute path, never $PATH).
func runLaunchctl(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// launchAgentPlist is the user LaunchAgent that starts Nazar.app at login
// (spec 4, 12) and restarts it if it crashes.
func launchAgentPlist(label, program string) []byte {
	esc := func(s string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + esc(label) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(program) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
</dict>
</plist>
`)
}

// plistSafe reports whether s survives a round trip through an XML plist
// byte for byte: valid UTF-8 whose every rune XML 1.0 can carry, and no
// control character (xml.EscapeText would write U+FFFD for one, so launchd
// would start a different path than the one install reports; a tab or
// newline would be legal XML but ambiguous in plutil's raw output).
func plistSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 0x20 && r <= 0xD7FF, r >= 0xE000 && r <= 0xFFFD, r >= 0x10000 && r <= 0x10FFFF:
		default:
			return false
		}
	}
	return true
}

// Installation is install's and uninstall's --json reply.
type Installation struct {
	control.TypeMeta
	Label       string     `json:"label"`
	Plist       string     `json:"plist"`
	App         string     `json:"app"`
	Links       []string   `json:"links"`
	Kept        []string   `json:"kept,omitempty"`
	PathHint    string     `json:"pathHint,omitempty"`
	Migrated    *Migration `json:"migrated,omitempty"`
	Uninstalled bool       `json:"uninstalled"`
}

// Migration is what install (or uninstall) removed of the old Nazar.app
// install of Milestones 1-5 (LaunchAgent dev.nazar): its LaunchAgent and
// the links into another bundle's CLI. App is where the old LaunchAgent
// said the old app was; it is reported, never removed. Keys, config and
// Keychain items are never touched.
type Migration struct {
	Label string   `json:"label,omitempty"`
	Plist string   `json:"plist,omitempty"`
	App   string   `json:"app,omitempty"`
	Links []string `json:"links,omitempty"`
	// SignGit is the nazar-sign-git git should sign through now, when the
	// old link git's gpg.ssh.program may name was removed and not replaced
	// in place (the human hint only; --json has it in Links).
	SignGit string `json:"-"`
}

// installFlags parses install's and uninstall's arguments and checks the
// label and the seams, before anything is written or run. noLinks is
// install's --no-links (a package manager links the CLI itself: Homebrew's
// `binary` stanza).
func (a *app) installFlags(name string, args []string) (binDir string, noLinks bool, err error) {
	fs := a.flags(name)
	bin := fs.String("bin-dir", a.defaultBinDir(), "")
	var nl *bool
	if name == "install" {
		nl = fs.Bool("no-links", false, "")
	}
	if _, err := a.parse(fs, args, 0); err != nil {
		return "", false, err
	}
	if nl != nil && *nl {
		noLinks = true
		set := false
		fs.Visit(func(f *flag.Flag) { set = set || f.Name == "bin-dir" })
		if set {
			return "", false, control.NewProblem(control.CodeUsage, "%s: --no-links and --bin-dir don't go together", name)
		}
	}
	if !filepath.IsAbs(*bin) {
		return "", false, control.NewProblem(control.CodeUsage, "%s: --bin-dir must be an absolute path", name)
	}
	if !labelRE.MatchString(a.launchLabel()) {
		return "", false, control.NewProblem(control.CodeUsage, "%s: invalid LaunchAgent label %q", name, a.launchLabel())
	}
	if a.launchctl == nil || a.uid == nil {
		return "", false, control.NewProblem(control.CodeError, "%s: not available in this build", name)
	}
	return *bin, noLinks, nil
}

// linkNames are the links install makes in the bin folder; signGitName is
// git's gpg.ssh.program, gitCredentialName git's credential helper.
const signGitName = "nazar-sign-git"

var linkNames = []string{cliExeName, signGitName, gitCredentialName}

// install sets up the LaunchAgent for the agent bundle this CLI ships in,
// wherever that is (spec 4, 12: identity is the signature, so any place
// works and a move or an upgrade just runs install again), the private
// ~/.nazar folder and the nazar / nazar-sign-git links (or none, with
// --no-links), and migrates an old Nazar.app install (Migration). It must
// run from the bundled CLI, so the agent can only ever point at a real
// bundle. Running it again repairs the setup. Every check runs before the
// first write or launchctl call, so a refusal changes nothing.
func (a *app) install(args []string) int {
	if a.linux {
		return a.installLinux(args)
	}
	binDir, noLinks, err := a.installFlags("install", args)
	if err != nil {
		return a.fail(err)
	}
	var loc appLocation
	if a.executable != nil {
		if exe, err := a.executable(); err == nil {
			if l, ok := bundleOf(exe); ok && isFile(l.MainExe) && filepath.Base(exe) == cliExeName {
				loc = l
			}
		}
	}
	if loc.Bundle == "" {
		return a.fail(control.NewProblem(control.CodeError, "run install from the CLI inside nazar-agent.app: /path/to/nazar-agent.app/Contents/MacOS/nazar install"))
	}
	if !plistSafe(loc.MainExe) {
		return a.fail(control.NewProblem(control.CodeError, "the path %q cannot be written into a LaunchAgent plist; move nazar-agent.app to a plain path", loc.MainExe))
	}
	var links []string
	if !noLinks {
		for _, n := range linkNames {
			l := filepath.Join(binDir, n)
			if err := checkLinkSlot(l, loc.CLI); err != nil {
				return a.fail(err)
			}
			links = append(links, l)
		}
	}
	legacy := a.plistFor(a.legacyLabel())
	if err := checkRemovable(legacy); err != nil {
		return a.fail(err)
	}
	if err := a.ensurePrivateRoot(); err != nil {
		return a.fail(err)
	}
	domain := "gui/" + strconv.Itoa(a.uid())
	mig, err := a.migrate(domain, loc.CLI, binDir, noLinks)
	if err != nil {
		return a.fail(err)
	}
	plist := a.launchAgentPlist()
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		return a.fail(err)
	}
	if err := writeFileAtomic(plist, launchAgentPlist(a.launchLabel(), loc.MainExe), 0o644); err != nil {
		return a.fail(err)
	}
	if len(links) > 0 {
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			return a.fail(err)
		}
	}
	for _, l := range links {
		if t, err := os.Readlink(l); err == nil && t != loc.CLI && mig != nil {
			mig.Links = append(mig.Links, l) // an old install's link, replaced
		}
		os.Remove(l) // checkLinkSlot allowed only a missing path or a nazar link
		if err := os.Symlink(loc.CLI, l); err != nil {
			return a.fail(err)
		}
	}
	if err := a.restartAgent(domain, plist); err != nil {
		return a.fail(control.NewProblem(control.CodeError, "LaunchAgent written to %s but not started: %v", plist, err))
	}
	if mig != nil && mig.Label == "" && len(mig.Links) == 0 {
		mig = nil
	}
	out := Installation{TypeMeta: control.Meta("Installation"), Label: a.launchLabel(), Plist: plist, App: loc.Bundle, Links: links, Migrated: mig}
	if out.Links == nil {
		out.Links = []string{}
	}
	if !noLinks && !onPath(a.getenv("PATH"), binDir) {
		out.PathHint = fmt.Sprintf("add %s to PATH", binDir)
	}
	return a.emit(out, func() {
		fmt.Fprintf(a.stdout, "installed %s\n  LaunchAgent %s (%s)\n", term(loc.Bundle), term(plist), term(a.launchLabel()))
		if len(links) > 0 {
			fmt.Fprintf(a.stdout, "  links %s\n", term(strings.Join(links, ", ")))
		}
		if out.PathHint != "" {
			fmt.Fprintf(a.stdout, "  %s\n", term(out.PathHint))
		}
		a.printMigration(mig)
	})
}

// ensurePrivateRoot makes ~/.nazar when it is missing and says how to fix it
// when it is not a private folder of this user.
func (a *app) ensurePrivateRoot() error {
	dot := layout.Root(a.home())
	if err := os.Mkdir(dot, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := unixsock.CheckPrivateDir(dot); err != nil {
		if fi, lerr := os.Lstat(dot); lerr == nil && fi.IsDir() {
			return control.NewProblem(control.CodeError, "%v (fix it with: chmod 700 %s)", err, dot)
		}
		return control.NewProblem(control.CodeError, "%v (move it away: %s must be a private folder)", err, dot)
	}
	return nil
}

// printMigration is the human view of what install or uninstall removed of
// an old Nazar.app install.
func (a *app) printMigration(m *Migration) {
	if m == nil {
		return
	}
	if m.Label != "" {
		fmt.Fprintf(a.stdout, "  removed the old LaunchAgent %s (%s)\n", term(m.Label), term(m.Plist))
	}
	if len(m.Links) > 0 {
		fmt.Fprintf(a.stdout, "  removed old links %s\n", term(strings.Join(m.Links, ", ")))
	}
	if m.SignGit != "" {
		fmt.Fprintf(a.stdout, "  git signs through %s? point it at the new one: git config --global gpg.ssh.program %s\n", term(filepath.Join(a.defaultBinDir(), signGitName)), term(m.SignGit))
	}
	if m.App != "" {
		fmt.Fprintf(a.stdout, "  the old app is still at %s: remove it when you no longer need it\n", term(m.App))
	}
	if m.Label != "" {
		fmt.Fprintln(a.stdout, "  keys, config and Keychain items were not touched; `nazar status` lists any the new agent can't read, and how to replace them")
	}
}

// migrate removes an old Nazar.app install (Milestones 1-5): when the
// legacy LaunchAgent's plist (legacyLabel) is there, it boots that agent
// out, waits for it to be gone and removes the plist; and it removes the
// nazar / nazar-sign-git links in the default bin folder that point into
// another bundle's CLI, when install does not link there itself (install
// replaces the ones in the folder it links into). When the old
// nazar-sign-git link goes that way, git's gpg.ssh.program may still name
// it, so the Migration says where the new one is (SignGit): the folder
// install links into, or the package manager's (Homebrew's bin) with
// --no-links. Keys, config, ~/.nazar and the Keychain are never touched,
// and the old app bundle is only reported. It returns what it removed
// (nil: nothing).
func (a *app) migrate(domain, cli, binDir string, noLinks bool) (*Migration, error) {
	m := &Migration{}
	label := a.legacyLabel()
	service := domain + "/" + label
	plist := a.plistFor(label)
	if _, err := os.Lstat(plist); err == nil {
		if a.plistProgram != nil {
			if prog, err := a.plistProgram(plist); err == nil {
				if l, ok := bundleOf(prog); ok {
					m.App = l.Bundle
				}
			}
		}
		_ = a.launchctl("bootout", service) // not loaded is fine
		if !a.waitGone(service) {
			return nil, control.NewProblem(control.CodeError, "the old LaunchAgent %s did not stop; run `launchctl bootout %s` and install again", label, service)
		}
		if err := os.Remove(plist); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		m.Label, m.Plist = label, plist
	}
	if def := a.defaultBinDir(); noLinks || filepath.Clean(def) != filepath.Clean(binDir) {
		m.Links = removeOldLinks(def, cli)
		if slices.Contains(m.Links, filepath.Join(def, signGitName)) {
			m.SignGit = filepath.Join(binDir, signGitName)
			if noLinks {
				m.SignGit = "$(brew --prefix)/bin/" + signGitName
			}
		}
	}
	return m, nil
}

// removeOldLinks removes the nazar / nazar-sign-git links in dir whose
// target is the CLI of a nazar bundle other than cli's, and returns them.
// Anything else (the user's own files, foreign links, links to cli) is
// left alone.
func removeOldLinks(dir, cli string) []string {
	var removed []string
	for _, n := range linkNames {
		l := filepath.Join(dir, n)
		if t, err := os.Readlink(l); err == nil && t != cli && isNazarCLI(t) && os.Remove(l) == nil {
			removed = append(removed, l)
		}
	}
	return removed
}

// checkRemovable: the legacy plist path is missing, a file or a link
// (which install and uninstall remove); anything else is refused before
// any change.
func checkRemovable(p string) error {
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().IsRegular() || fi.Mode()&fs.ModeSymlink != 0 {
		return nil
	}
	return control.NewProblem(control.CodeError, "%s is not a LaunchAgent plist; move it away", p)
}

// The agent being replaced takes a moment to go: `launchctl bootout`
// returns before the old Nazar.app has exited, and a bootstrap issued
// meanwhile fails with "Bootstrap failed: 5: Input/output error" (seen on
// a reinstall). So install waits, at most
// bootoutWait, for `launchctl print` to stop finding the service, and
// retries a bootstrap that failed with error 5 once, after waiting again.
const (
	bootoutWait = 10 * time.Second
	bootoutPoll = 200 * time.Millisecond
)

// restartAgent boots out the agent (not loaded is fine), waits for it to
// be gone and bootstraps plist into domain.
func (a *app) restartAgent(domain, plist string) error {
	service := domain + "/" + a.launchLabel()
	_ = a.launchctl("bootout", service)
	a.waitGone(service) // still there after the wait: bootstrap says so
	err := a.launchctl("bootstrap", domain, plist)
	if err != nil && bootstrapEIO(err) {
		a.waitGone(service)
		err = a.launchctl("bootstrap", domain, plist)
	}
	return err
}

// waitGone polls `launchctl print <service>` until it fails (the service
// is not loaded any more) or bootoutWait has passed, and reports whether
// it is gone.
func (a *app) waitGone(service string) bool {
	for waited := time.Duration(0); ; waited += bootoutPoll {
		if a.launchctl("print", service) != nil {
			return true
		}
		if waited >= bootoutWait {
			return false
		}
		a.pause(bootoutPoll)
	}
}

// pause sleeps through the sleep seam (tests never sleep for real).
func (a *app) pause(d time.Duration) {
	if a.sleep != nil {
		a.sleep(d)
		return
	}
	time.Sleep(d)
}

// bootstrapEIO reports launchctl's error 5 (EIO), what bootstrap answers
// while the previous instance of the service is still being torn down.
func bootstrapEIO(err error) bool {
	s := err.Error()
	return strings.Contains(s, ": 5: ") || strings.Contains(s, "Input/output error")
}

// uninstall stops and removes the agent's LaunchAgent, the old Nazar.app's
// (dev.nazar) when it is still there, and the links in the bin folder that
// point into a nazar bundle. Keys, config and the Keychain items are kept.
func (a *app) uninstall(args []string) int {
	if a.linux {
		return a.uninstallLinux(args)
	}
	binDir, _, err := a.installFlags("uninstall", args)
	if err != nil {
		return a.fail(err)
	}
	legacy := a.plistFor(a.legacyLabel())
	if err := checkRemovable(legacy); err != nil {
		return a.fail(err)
	}
	domain := "gui/" + strconv.Itoa(a.uid())
	plist := a.launchAgentPlist()
	_ = a.launchctl("bootout", domain+"/"+a.launchLabel()) // not loaded is fine
	if err := os.Remove(plist); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return a.fail(err)
	}
	var mig *Migration
	if _, err := os.Lstat(legacy); err == nil {
		_ = a.launchctl("bootout", domain+"/"+a.legacyLabel())
		if err := os.Remove(legacy); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return a.fail(err)
		}
		mig = &Migration{Label: a.legacyLabel(), Plist: legacy}
	}
	removed := []string{}
	for _, n := range linkNames {
		l := filepath.Join(binDir, n)
		if t, err := os.Readlink(l); err == nil && isNazarCLI(t) {
			if os.Remove(l) == nil {
				removed = append(removed, l)
			}
		}
	}
	kept := []string{layout.Root(a.home()), "Keychain items of service dev.nazar"}
	out := Installation{TypeMeta: control.Meta("Installation"), Label: a.launchLabel(), Plist: plist, Links: removed, Kept: kept, Migrated: mig, Uninstalled: true}
	return a.emit(out, func() {
		fmt.Fprintf(a.stdout, "uninstalled %s\n", term(a.launchLabel()))
		if mig != nil {
			fmt.Fprintf(a.stdout, "  removed the old LaunchAgent %s (%s)\n", term(mig.Label), term(mig.Plist))
		}
		fmt.Fprintf(a.stdout, "  kept %s\n", term(strings.Join(kept, ", ")))
	})
}

// isNazarCLI: a link target that is, byte for byte, the CLI inside some
// Nazar bundle. The target string is judged, never followed.
func isNazarCLI(target string) bool {
	l, ok := bundleOf(target)
	return ok && filepath.Base(target) == cliExeName && l.CLI == target
}

// checkLinkSlot: path may be created or replaced only when nothing is
// there, it already points at cli, or it is a link to another Nazar.app's
// CLI (an older install). Anything else is the user's and is never touched.
func checkLinkSlot(path, cli string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if t, err := os.Readlink(path); err == nil && (t == cli || isNazarCLI(t)) {
			return nil
		}
	}
	return control.NewProblem(control.CodeError, "%s exists and is not a nazar link; move it away or use --bin-dir", path)
}

func onPath(path, dir string) bool {
	for _, p := range filepath.SplitList(path) {
		if p != "" && filepath.Clean(p) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

// writeFileAtomic writes via a temp file in the same folder and a rename,
// so a reader never sees a partial file and a symlink at path is replaced
// rather than written through.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".nazar-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
