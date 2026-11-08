package main

import (
	"debug/macho"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/atas/nazar/core/control"
)

// appLocation is an agent bundle: the one the CLI runs from
// (nazar-agent.app/Contents/MacOS/nazar), or else the one the installed
// LaunchAgent starts. Its MainExe is the only sender `nazar log` accepts
// (the unified log records paths and image UUIDs, no signatures).
// Which agent the control socket's peer must be is decided by signature
// alone (agentRequirement, Milestone 6), never by this location.
type appLocation struct {
	Bundle  string // …/nazar-agent.app (symlinks resolved)
	MainExe string // <Bundle>/Contents/MacOS/nazar-agent
	CLI     string // <Bundle>/Contents/MacOS/nazar
}

// The signing identifiers of nazar's programs (spec 4, 6.1): the agent,
// the CLI inside it, and Nazar UI.app.
const (
	agentBundleID = "dev.nazar.agent"
	cliBundleID   = "dev.nazar.cli"
	uiBundleID    = "dev.nazar.ui"
)

const (
	appExeName         = "nazar-agent"
	cliExeName         = "nazar"
	defaultLaunchLabel = "dev.nazar.agent"
	// legacyLaunchLabel is the LaunchAgent of the Nazar.app of Milestones
	// 1-5 (bundle id dev.nazar), which `nazar install` migrates from.
	legacyLaunchLabel = "dev.nazar"
)

// errNoApp is returned when no agent bundle can be found.
var errNoApp = control.NewProblem(control.CodeError,
	"can't tell which nazar-agent to read: run the nazar CLI inside nazar-agent.app (nazar-agent.app/Contents/MacOS/nazar), or install it with `nazar install`")

// launchLabel is the LaunchAgent label: dev.nazar.agent, or
// NAZAR_LAUNCH_LABEL (tests only, so they never touch the real agent).
func (a *app) launchLabel() string {
	if l := a.getenv("NAZAR_LAUNCH_LABEL"); l != "" {
		return l
	}
	return defaultLaunchLabel
}

// legacyLabel is the old Nazar.app's LaunchAgent label, which install and
// uninstall remove: dev.nazar, or with NAZAR_LAUNCH_LABEL=L set (tests)
// L.legacy, so a test can never reach the user's real dev.nazar.
func (a *app) legacyLabel() string {
	if l := a.getenv("NAZAR_LAUNCH_LABEL"); l != "" {
		return l + ".legacy"
	}
	return legacyLaunchLabel
}

func (a *app) launchAgentPlist() string { return a.plistFor(a.launchLabel()) }

func (a *app) plistFor(label string) string {
	return filepath.Join(a.home(), "Library", "LaunchAgents", label+".plist")
}

// defaultBinDir is where install links the CLI unless told otherwise, and
// where the old Nazar.app linked it.
func (a *app) defaultBinDir() string { return filepath.Join(a.home(), ".local", "bin") }

// bundleOf returns the location of the bundle exe lives in, when exe is
// <X>.app/Contents/MacOS/<file>.
func bundleOf(exe string) (appLocation, bool) {
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	bundle := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(bundle, ".app") {
		return appLocation{}, false
	}
	return appLocation{Bundle: bundle, MainExe: filepath.Join(macos, appExeName), CLI: filepath.Join(macos, cliExeName)}, true
}

// locateApp finds the agent bundle (`nazar log`). Paths are fully resolved, since
// the unified log records real paths (/private/tmp, not /tmp).
func (a *app) locateApp() (appLocation, error) {
	if a.executable != nil {
		if exe, err := a.executable(); err == nil {
			if loc, ok := bundleOf(exe); ok && isFile(loc.MainExe) {
				return loc, nil
			}
		}
	}
	if a.plistProgram != nil {
		if prog, err := a.plistProgram(a.launchAgentPlist()); err == nil {
			if real, err := filepath.EvalSymlinks(prog); err == nil && filepath.Base(real) == appExeName {
				if loc, ok := bundleOf(real); ok && isFile(loc.MainExe) {
					return loc, nil
				}
			}
		}
	}
	return appLocation{}, errNoApp
}

// selfExecutable is the CLI's own path with every symlink resolved (the
// ~/.local/bin/nazar link points into the bundle).
func selfExecutable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// plistProgram reads ProgramArguments[0] of a LaunchAgent plist with
// /usr/bin/plutil (absolute path, never $PATH).
func plistProgram(plist string) (string, error) {
	out, err := exec.Command("/usr/bin/plutil", "-extract", "ProgramArguments.0", "raw", "-o", "-", plist).Output()
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		return "", errors.New("ProgramArguments[0] is not an absolute path")
	}
	return p, nil
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// lcUUID is the LC_UUID load command.
const lcUUID = 0x1b

// machoUUID returns the LC_UUID of the executable at path, formatted as the
// unified log prints it (upper-case 8-4-4-4-12). For a universal binary it
// is the arm64 slice's, the one that runs.
func machoUUID(path string) (string, error) {
	var f *macho.File
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		for _, a := range fat.Arches {
			if a.Cpu == macho.CpuArm64 {
				f = a.File
			}
		}
		if f == nil {
			return "", errors.New("no arm64 slice")
		}
	} else {
		mf, err := macho.Open(path)
		if err != nil {
			return "", err
		}
		defer mf.Close()
		f = mf
	}
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) >= 24 && f.ByteOrder.Uint32(raw[0:4]) == lcUUID {
			u := raw[8:24]
			return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
		}
	}
	return "", errors.New("no LC_UUID")
}
