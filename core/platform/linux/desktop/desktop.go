//go:build linux

// Package desktop answers the app questions of platform.Platform on Linux
// (AppFor, Apps, InstalledApp) from the desktop entries installed on the
// machine. An app is a desktop file id (org.gnome.Terminal, the file name
// under <data dir>/applications/ without .desktop) whose entry is a shown
// application, and its executable is the real path of the file the entry
// runs. A process is that app when the file it was started from, as
// /proc/<pid>/exe names it, is that executable; nothing in the chain's
// own records is trusted (AppFor re-reads every process).
//
// Linux has no code signatures, so what an app: rule pins is the SHA-256
// of that executable: Code on an AppInfo or AppBundle is Signed with
// PinTeam of the hash as its team, and nothing else in the Linux platform
// is ever Signed (design: "app: on Linux"). The consequences, which the
// design accepts and the docs state:
//
//   - The program is Exec's first word, what the desktop runs. TryExec
//     only says the program is installed (the desktop hides an entry whose
//     TryExec names no file, and so does the index), so it never decides
//     which file the app is: that would pin a file the entry does not run,
//     and every process of that file would be the app.
//   - An entry whose program is a shell, an interpreter or a launcher
//     (env, python3, java, wine, firejail, flatpak, snap, gtk-launch,
//     xdg-open and the rest of entry.go's launchers) names no executable
//     of its own: the process it starts runs some other program named in
//     its arguments, and every other use of the same shell or interpreter
//     runs that file too. Such an entry is no app, so the chain is unknown
//     rather than matched to the wrong program, and InstalledApp's error
//     says so. GNOME Terminal is the one app whose running process is a
//     known other file, in serverExes; its Exec may be a script (Ubuntu's
//     is) but still has to pass the other checks (a Flatpak GNOME Terminal
//     is no app).
//   - A Flatpak or Snap app has an entry only in the folders those two
//     export to (exportDirs). Every such entry runs the app through
//     flatpak or snap, so the index reads those folders only to say why
//     the id is no app; nothing in them is ever an app.
//   - An entry whose program is a script (a #! file, common for Python and
//     GJS apps and for wrappers such as Chrome's google-chrome) is no app
//     either: the kernel starts its interpreter, which is what
//     /proc/<pid>/exe names, so no process could ever match the file.
//     InstalledApp refuses to pin it and its error says why.
//   - An entry with Terminal=true (vim, htop: a command-line program the
//     desktop opens a terminal for) is no app: the platform contract's
//     apps are GUI apps, and were the tool the app, the terminal app above
//     it in the chain would never be, unlike on macOS where a tool in a
//     Terminal tab is never a bundle. InstalledApp's error says so.
//   - A package upgrade replaces the executable: the pin is the old hash,
//     the app: rule stops matching, and the note names
//     `nazar trust --app <id>` to pin the new one (core/daemon). The index
//     follows the file as well as the entry (a replaced file, a link
//     pointed at a new version, a program installed after its entry), so
//     that command pins what is installed now. A process of the app that
//     was already running keeps the old, deleted file: /proc/<pid>/exe
//     ends in " (deleted)", procfs gives it no Path, and it is not the app
//     (never mismatched) until the app is started again; like any process
//     that is no app, it leaves the chain to the app above it, if there
//     is one (a terminal it was started from), else unknown. So is a
//     process whose executable cannot be read: procfs gives it no Path
//     either (no identity, for path: rules and app: alike). Should the
//     hash fail only after the process was read with its Path (a race
//     with such a change), the process does run an app's file, so the
//     chain stops at it: unknown, not the app above.
//   - When several ids share an executable, in one folder or across the
//     user's and the system's, the lexically first id is the app and the
//     others cannot be pinned: a user's own entry for a system program
//     under a lower id takes over that program's identity, and the system
//     id's rule stops matching. InstalledApp's error names the id that
//     won. The user's folder is the user's to write (design: "Weaker than
//     macOS" 2).
package desktop

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

// rescanEvery is how often, at most, the applications folders are looked
// at again for a change.
const rescanEvery = 2 * time.Second

// Index is the desktop entries of a set of data dirs, read once and read
// again when anything the scan looked at changes (an applications folder,
// a subfolder, a desktop file, a program an entry names or a folder a bare
// name is looked for in: its mtime, size or inode), checked at most every
// rescanEvery. The zero value is not usable: NewIndex.
type Index struct {
	dirs  []string
	procs *procfs.Procs
	// exports are the data dirs Flatpak and Snap export entries to, read
	// only to say why such an id is no app (exportDirs). Tests set it.
	exports []string
	// uid is the user whose processes Apps lists.
	uid int
	// now is the clock the rescan interval is measured by; serverExes and
	// bins are the fixed tables of entry.go. Tests set them.
	now        func() time.Time
	serverExes map[string]string
	bins       []string

	mu      sync.Mutex
	table   *table
	checked time.Time            // when the folders were last looked at
	state   map[string]fileState // everything the last scan looked at, as it was then (scan)
	// unsettled: something changed within rescanEvery of the last scan, so
	// a later change in the same coarse timestamp could hide behind an
	// unchanged mtime and size; the next look rescans whatever the state
	// says.
	unsettled bool
	scans     int // how many times the folders were read; tests read it
}

// fileState is what the look at a folder records of one directory or
// desktop file under it.
type fileState struct {
	mtime int64 // UnixNano
	size  int64
	ino   uint64
}

// table is one scan's result.
type table struct {
	byID  map[string]app    // every shown application with an executable
	byExe map[string]string // executable to the lexically first id that runs it
	noApp map[string]string // every shown application without one, and why
}

// app is one desktop entry that names an executable.
type app struct {
	id, name, exe string
}

// NewIndex returns an Index over the applications folders of dataDirs, in
// order of precedence, that reads processes through procs.
func NewIndex(dataDirs []string, procs *procfs.Procs) *Index {
	return &Index{
		dirs:       append([]string(nil), dataDirs...),
		procs:      procs,
		exports:    exportDirs(dataDirs),
		uid:        os.Geteuid(),
		now:        time.Now,
		serverExes: serverExes,
		bins:       binDirs,
	}
}

// DefaultDataDirs are the data dirs whose applications folders hold the
// user's and the system's desktop entries, the user's first. The list is
// fixed: $XDG_DATA_DIRS is the agent's own environment, which anything
// that starts the agent could set to a folder of its own entries.
func DefaultDataDirs(home string) []string {
	return []string{filepath.Join(home, ".local", "share"), "/usr/local/share", "/usr/share"}
}

// exportDirs are the data dirs Flatpak and Snap export their apps'
// desktop entries to, which the desktop reads through $XDG_DATA_DIRS: a
// Flatpak installation's exports (the user's under the user's data dir,
// the system's under /var/lib/flatpak) and snapd's. Every entry there
// runs the app through flatpak or snap, so the index reads these folders
// only to say why such an id is no app (InstalledApp), never to make one
// an app: a user's own entry in dataDirs is an app or not on its own.
func exportDirs(dataDirs []string) []string {
	dirs := make([]string, 0, len(dataDirs)+2)
	for _, dir := range dataDirs {
		dirs = append(dirs, filepath.Join(dir, "flatpak", "exports", "share"))
	}
	return append(dirs, "/var/lib/flatpak/exports/share", "/var/lib/snapd/desktop")
}

// PinTeam is the team an app: pin records for an executable whose SHA-256
// is sum: "sha256:" and the lower-case hex.
func PinTeam(sum []byte) string {
	return "sha256:" + hex.EncodeToString(sum)
}

// AppFor returns the first app in chain, peer first: the first record
// whose process, read again from /proc by its full ref, runs an app's
// executable. The record's own Path and Code are never consulted, so a
// forged record, a record with a PID-only ref or one whose process is
// gone is never an app. The app's Code is the pin of the file the process
// was started from (procfs.Procs.ExeHash); when that hash cannot be read
// the chain is unknown, not the app above (appOf).
func (x *Index) AppFor(chain []platform.ProcessInfo) (platform.AppInfo, bool) {
	tbl := x.snapshot()
	for _, rec := range chain {
		if rec.Ref.IsZero() || rec.Ref.IsPIDOnly() {
			continue
		}
		info, err := x.procs.Process(rec.Ref)
		if err != nil || info.Ref != rec.Ref {
			continue
		}
		if a, ok, isApp := x.appOf(tbl, info); isApp {
			return a, ok
		}
	}
	return platform.AppInfo{}, false
}

// appOf is what AppFor answers for one live record: isApp when the
// process runs an app's executable, and then ok when a holds the app with
// the pin of its file. A process whose executable was replaced or removed
// on disk while it ran has no Path (procfs: its exe link ends in
// " (deleted)") and is no app, like any other process that is not one.
// A process that does run an app's file but whose hash then cannot be
// read (a race: the file's mode changed or the process went between the
// two reads; procfs gives a process whose image it cannot read no Path
// in the first place) is that app without a pin to compare: isApp and
// not ok, so that AppFor stops at it rather than let the app above it in
// the chain answer for it.
func (x *Index) appOf(tbl *table, info platform.ProcessInfo) (a platform.AppInfo, ok, isApp bool) {
	if info.Path == "" {
		return platform.AppInfo{}, false, false
	}
	id, isApp := tbl.byExe[info.Path]
	if !isApp {
		return platform.AppInfo{}, false, false
	}
	sum, err := x.procs.ExeHash(info.Ref)
	if err != nil {
		return platform.AppInfo{}, false, true
	}
	return platform.AppInfo{
		Ref:      info.Ref,
		BundleID: id,
		Name:     tbl.byID[id].name,
		Code:     platform.CodeIdentity{Signed: true, TeamID: PinTeam(sum)},
	}, true, true
}

// Apps lists every live process of the agent's user that AppFor would call
// an app, each under its full ref; nil when there are none. /proc is
// walked once; only a process whose exe link names an app's executable is
// read in full.
func (x *Index) Apps() []platform.AppInfo {
	tbl := x.snapshot()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var apps []platform.AppInfo
	for _, d := range entries {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid <= 0 {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", d.Name(), "exe"))
		if err != nil {
			continue
		}
		if _, ok := tbl.byExe[exe]; !ok {
			continue
		}
		info, err := x.procs.Process(platform.ProcessRef{PID: pid})
		if err != nil || info.UID != x.uid {
			continue
		}
		if a, ok, _ := x.appOf(tbl, info); ok {
			apps = append(apps, a)
		}
	}
	return apps
}

// InstalledApp is the app installed as id: its executable and the pin of
// that file as it is on disk now (procfs.Procs.CodeHash). The error is
// platform.ErrNotFound (to errors.Is) when no shown application entry has
// that id, when the entry names no executable (a launcher or interpreter,
// a script, a bare name not in the fixed folders, a missing file, a
// TryExec that names no file, a Terminal=true entry, a Flatpak's or a
// Snap's export), or when another id, the lexically first, is the app for
// the same executable: AppFor never answers this id, so there is nothing
// to pin. For an entry that exists the error is a platform.NotFoundError
// whose text says which of these it is, with every id and path from disk
// quoted ASCII-only (q).
func (x *Index) InstalledApp(id string) (platform.AppBundle, error) {
	tbl := x.snapshot()
	a, ok := tbl.byID[id]
	if !ok {
		if why, ok := tbl.noApp[id]; ok {
			return platform.AppBundle{}, &notAppError{id: id, why: why}
		}
		return platform.AppBundle{}, platform.ErrNotFound
	}
	if first := tbl.byExe[a.exe]; first != id {
		return platform.AppBundle{}, &notAppError{id: id, why: fmt.Sprintf("another entry, %s, is the app for the same program %s", q(first), q(a.exe))}
	}
	sum, err := x.procs.CodeHash(a.exe)
	if err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return platform.AppBundle{}, &notAppError{id: id, why: fmt.Sprintf("its program %s is gone", q(a.exe))}
		}
		return platform.AppBundle{}, fmt.Errorf("desktop: %s: %w", id, err)
	}
	return platform.AppBundle{
		BundleID: id,
		Path:     a.exe,
		Code:     platform.CodeIdentity{Signed: true, TeamID: PinTeam(sum)},
	}, nil
}

// snapshot is the current table, scanned again when anything the last
// scan looked at has changed since: an applications folder, a folder
// under it, a desktop file, a program an entry names (the file itself, or
// what its link now points to) or a folder a bare name is looked for in.
func (x *Index) snapshot() *table {
	x.mu.Lock()
	defer x.mu.Unlock()
	now := x.now()
	if x.table != nil && now.Sub(x.checked) < rescanEvery {
		return x.table
	}
	x.checked = now
	if x.table != nil && !x.unsettled && maps.Equal(x.look(), x.state) {
		return x.table
	}
	x.table, x.state = x.scan()
	x.scans++
	x.unsettled = false
	for _, st := range x.state {
		// A timestamp within the interval, either side of now (clock
		// skew, a package with odd timestamps): a file further ahead of
		// the clock is settled, or it would be read again at every look.
		if d := now.Sub(time.Unix(0, st.mtime)); -rescanEvery < d && d < rescanEvery {
			x.unsettled = true
		}
	}
	return x.table
}

// look is the state, now, of everything the last scan noted: a stat each,
// no file read. An in-place edit changes a file's mtime or size; an entry
// or a program added, removed or renamed changes its folder's mtime; a
// file swapped by rename, or a link pointed at another file, changes the
// inode the path leads to; a file that has gone, or has appeared, differs
// from the zero state.
func (x *Index) look() map[string]fileState {
	state := make(map[string]fileState, len(x.state))
	for path := range x.state {
		state[path] = statState(path)
	}
	return state
}

// scanState is what a scan notes of the paths it looked at, keyed by path
// (fileState); the zero fileState is a path that was not there.
type scanState map[string]fileState

// note records the state of path now, before the scan reads or resolves
// it, so that a change between the two is seen at the next look.
func (s scanState) note(path string) { s[path] = statState(path) }

// statState is the fileState of path through links, or the zero state
// when it cannot be read.
func statState(path string) fileState {
	st, err := os.Stat(path)
	if err != nil {
		return fileState{}
	}
	fst := fileState{mtime: st.ModTime().UnixNano(), size: st.Size()}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		fst.ino = sys.Ino
	}
	return fst
}

// validID reports whether a desktop file's id can be an app: value: valid
// UTF-8 made of printable characters with no white space. A file name with
// a control character, an escape sequence or a space names no app that a
// rule could sensibly name, and an id reaches logs, prompts and messages,
// so such a file is not an entry at all rather than an id of its own.
func validID(id string) bool {
	if id == "" || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsSpace(r) || !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

// folders are the applications folders of the data dirs, in precedence order.
func (x *Index) folders() []string {
	folders := make([]string, len(x.dirs))
	for i, dir := range x.dirs {
		folders[i] = filepath.Join(dir, "applications")
	}
	return folders
}

// scan reads every desktop file under the folders and returns the table
// with the state of everything it looked at. An id found in an earlier
// folder is that folder's, whatever it says: a hidden entry in the user's
// folder removes the system's app, as the desktop does. The Flatpak and
// Snap export folders come last and only fill noApp: an id first found
// there is a Flatpak's or a Snap's, whatever its entry says.
func (x *Index) scan() (*table, map[string]fileState) {
	tbl := &table{byID: map[string]app{}, byExe: map[string]string{}, noApp: map[string]string{}}
	st := scanState{}
	for _, dir := range x.bins {
		st.note(dir)
	}
	seen := map[string]bool{}
	for _, folder := range x.folders() {
		x.walk(folder, st, seen, func(id string, e entry) {
			if e.Terminal {
				tbl.noApp[id] = "its entry runs in a terminal (Terminal=true), so it is a command-line program, not a desktop app"
				return
			}
			exe, why := x.executable(id, e, st)
			if exe == "" {
				tbl.noApp[id] = why
				return
			}
			tbl.byID[id] = app{id: id, name: e.Name, exe: exe}
			if first, ok := tbl.byExe[exe]; !ok || id < first {
				tbl.byExe[exe] = id
			}
		})
	}
	for _, dir := range x.exports {
		x.walk(filepath.Join(dir, "applications"), st, seen, func(id string, e entry) {
			tbl.noApp[id] = fmt.Sprintf("its entry is a Flatpak or Snap export, and the app runs inside flatpak or snap, so no process can match app:%s", q(id))
		})
	}
	return tbl, st
}

// walk reads every desktop file under folder, through a link (a dotfile
// manager's), noting in st everything it looks at, and hands each shown
// application entry whose id is valid and not seen yet to visit, in
// WalkDir's order. An id is marked seen whatever its entry says, so a
// later folder never fills in for a hidden or broken entry.
func (x *Index) walk(folder string, st scanState, seen map[string]bool, visit func(id string, e entry)) {
	st.note(folder)
	root, err := filepath.EvalSymlinks(folder)
	if err != nil {
		return
	}
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			st.note(path) // before WalkDir reads it
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".desktop") {
			return nil
		}
		st.note(path) // before the file is read
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		id := strings.TrimSuffix(strings.ReplaceAll(rel, string(filepath.Separator), "-"), ".desktop")
		if !validID(id) || seen[id] {
			return nil
		}
		seen[id] = true
		data, ok := readEntryFile(path)
		if !ok {
			return nil
		}
		e, ok := parseEntry(data)
		if !ok {
			return nil
		}
		visit(id, e)
		return nil
	})
}
