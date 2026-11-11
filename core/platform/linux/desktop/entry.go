//go:build linux

package desktop

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// entry is what a desktop file's [Desktop Entry] group says that matters
// here. Exec is kept as written: execWord takes its first word. Terminal
// is Terminal=true: the program runs in a terminal the desktop opens for
// it (vim, htop), so it is a command-line program, not a desktop app.
type entry struct {
	Name     string
	TryExec  string
	Exec     string
	Terminal bool
}

// maxEntry bounds a desktop file read: the largest real ones (hundreds of
// translated names) are tens of kilobytes.
const maxEntry = 1 << 20

// launchers are programs a desktop entry names in place of the app it
// starts, and whose process is shared with every other use of the same
// program: a shell or an interpreter (the entry's program is a script it
// is given as an argument, and so is any other script the user runs), a
// runtime (java, mono, wine, electron), a wrapper that starts the app
// (env, nice, firejail, bwrap, pkexec, flatpak, snap) or a desktop helper
// that asks something else to open the app (gtk-launch, xdg-open). An
// entry whose executable resolves to one of these, by the name written or
// by the file it links to (/bin/sh is dash), is no app: naming the shared
// program as the app would make every process of the user that runs it,
// `python3 -c ...` included, match the app's rule with the right hash.
//
// Names are matched by family: a trailing version is dropped first, so
// python3.11, python3.13t, perl5.36.0, wine64, node18 and electron28 are
// launchers too (isLauncher). The list is a fixed set, as the plan asks; a
// program that is not on it and runs other programs is the weaker identity
// the design states ("Weaker than macOS" 1), not a program the user
// allowed by mistake. git and ssh are on it on purpose: they are programs
// nazar gates, and both run other programs (git's subcommands and shell
// aliases, ssh's ProxyCommand and LocalCommand), so an entry such as
// `Exec=git gui` must never make every git process an app.
var launchers = map[string]bool{
	// shells
	"sh": true, "bash": true, "rbash": true, "dash": true, "ash": true, "zsh": true, "fish": true,
	"ksh": true, "mksh": true, "yash": true, "csh": true, "tcsh": true, "busybox": true, "toybox": true,
	"pwsh": true, "nu": true, "elvish": true, "xonsh": true, "ion": true, "oil": true, "osh": true,
	// interpreters and runtimes
	"python": true, "pythonw": true, "pypy": true, "perl": true, "ruby": true, "node": true, "nodejs": true,
	"deno": true, "bun": true, "php": true, "lua": true, "luajit": true, "tclsh": true, "wish": true,
	"tclkit": true, "guile": true, "racket": true, "julia": true, "R": true, "Rscript": true, "awk": true,
	"gawk": true, "mawk": true, "nawk": true, "erl": true, "escript": true, "elixir": true, "iex": true,
	"ocaml": true, "ocamlrun": true, "sbcl": true, "clisp": true, "gjs": true, "gjs-console": true,
	"cjs": true, "seed": true, "qml": true, "qmlscene": true, "java": true, "javaw": true, "jshell": true,
	"kotlin": true, "scala": true, "groovy": true, "dotnet": true, "mono": true, "wine": true,
	"wine-preloader": true, "electron": true, "nw": true, "box": true, "wine64-preloader": true,
	"ld.so": true, "ld-linux.so": true, "ld-linux-x86-64.so": true, "ld-linux-aarch64.so": true,
	"ld-musl-x86_64.so": true, "ld-musl-aarch64.so": true,
	"qemu-x86_64": true, "qemu-i386": true, "qemu-aarch64": true, "qemu-arm": true, "qemu-riscv64": true,
	// package runners that fetch and start a program
	"uv": true, "uvx": true, "pipx": true, "npx": true, "pnpx": true, "bunx": true, "poetry": true,
	// wrappers that start the program
	"env": true, "nice": true, "ionice": true, "nohup": true, "setsid": true, "timeout": true,
	"chrt": true, "taskset": true, "stdbuf": true, "unshare": true, "nsenter": true, "chroot": true,
	"setpriv": true, "setarch": true, "linux32": true, "linux64": true, "prlimit": true, "numactl": true,
	"xargs": true, "flock": true, "time": true, "watch": true, "script": true, "cgexec": true,
	"aa-exec": true, "strace": true, "ltrace": true, "gdb": true, "lldb": true, "valgrind": true,
	"sudo": true, "doas": true, "su": true, "runuser": true, "run0": true, "sg": true, "newgrp": true,
	"pkexec": true, "gksu": true, "gksudo": true, "kdesu": true, "kdesudo": true,
	"firejail": true, "bwrap": true, "systemd-run": true, "systemd-cat": true, "systemd-inhibit": true,
	"systemd-nspawn": true, "gnome-session-inhibit": true, "dbus-launch": true, "dbus-run-session": true,
	"xvfb-run": true, "torsocks": true, "proxychains": true, "gamemoderun": true, "mangohud": true,
	"pasuspender": true, "vglrun": true, "optirun": true, "primusrun": true, "prime-run": true,
	"steam-run": true, "nix-shell": true, "nix": true, "toolbox": true, "distrobox": true,
	"distrobox-enter": true, "podman": true, "docker": true, "apptainer": true, "singularity": true,
	"appimage-run": true, "git": true, "ssh": true,
	// Flatpak, Snap and desktop helpers that ask something else to open the app
	"flatpak": true, "flatpak-spawn": true, "snap": true, "gtk-launch": true, "gapplication": true,
	"gio": true, "xdg-open": true, "xdg-terminal-exec": true, "exo-open": true, "kde-open": true,
	"gnome-open": true, "mate-open": true, "kfmclient": true, "kioclient": true, "kstart": true, "dex": true,
}

// isLauncher reports whether the program name is a launcher (launchers),
// as written or with a trailing version dropped: digits and dots at the
// end, after an optional dash (python3.11, perl5.36.0, wine64, node18,
// kde-open5, guile-3.0, ld-linux-x86-64.so.2), with CPython's
// free-threaded t after the version (python3.13t) dropped first.
func isLauncher(name string) bool {
	if launchers[name] {
		return true
	}
	i := len(name)
	if i > 1 && name[i-1] == 't' && name[i-2] >= '0' && name[i-2] <= '9' {
		i--
	}
	for i > 0 && (name[i-1] >= '0' && name[i-1] <= '9' || name[i-1] == '.') {
		i--
	}
	if i == len(name) {
		return false
	}
	if i > 0 && name[i-1] == '-' {
		i--
	}
	return i > 0 && launchers[name[:i]]
}

// serverExes names the executable of an app whose running process is not
// its Exec: GNOME Terminal's `gnome-terminal` only asks the running
// `gnome-terminal-server` for a window and exits, so the server is the
// process in every chain under a GNOME Terminal tab. The table is fixed
// on purpose: an entry that could be pointed at any file would make the
// file's hash, not the app, the thing a rule names.
var serverExes = map[string]string{
	"org.gnome.Terminal": "/usr/libexec/gnome-terminal-server",
}

// binDirs are where a bare Exec name is looked for, in order. $PATH is
// never consulted: it is the agent's own environment, which the systemd
// user manager sets, and a user-writable folder on it would let any
// program take an app's name.
var binDirs = []string{"/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin", "/snap/bin"}

// notAppError is why a shown application entry is no app, or why
// InstalledApp cannot answer an id: it is platform.ErrNotFound to
// errors.Is, as the platform contract asks, and its text says what the
// entry's program is, so a caller that prints the error tells the user
// why nothing can match app:<id> rather than that nothing is installed.
type notAppError struct {
	id, why string
}

func (e *notAppError) Error() string { return "desktop: " + e.id + ": " + e.why }

// Unwrap makes a notAppError platform.ErrNotFound to errors.Is and a
// platform.NotFoundError to errors.As, so the core can show why.
func (e *notAppError) Unwrap() error { return &platform.NotFoundError{Reason: e.why} }

// q quotes a path or a name from a desktop file for a reason: every value
// the core shows is quoted ASCII-only, so a control character in an Exec
// line never reaches the user's terminal.
func q(s string) string { return strconv.QuoteToASCII(s) }

// isTrue reads a boolean value as the desktop's key file reader does:
// true, or 1 (the old spelling GLib still accepts). Anything else, false
// included, is false, so a value that is not understood hides nothing and
// opens no terminal here that the desktop would not.
func isTrue(value string) bool { return value == "true" || value == "1" }

// parseEntry reads the [Desktop Entry] group of a desktop file. ok is
// false when the file is not a shown application: no such group, Type
// other than Application, or Hidden or NoDisplay true. Keys in other
// groups ([Desktop Action ...]) are not the entry's.
func parseEntry(data []byte) (entry, bool) {
	var e entry
	var typ string
	hidden, seen, in := false, false, false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			if in {
				break // the group has ended; later groups are not the entry
			}
			in = line == "[Desktop Entry]"
			seen = seen || in
			continue
		}
		if !in {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "Type":
			typ = value
		case "Name":
			e.Name = unescape(value)
		case "TryExec":
			e.TryExec = unescape(value)
		case "Exec":
			e.Exec = value
		case "Terminal":
			e.Terminal = isTrue(value)
		case "Hidden", "NoDisplay":
			if isTrue(value) {
				hidden = true
			}
		}
	}
	if !seen || typ != "Application" || hidden {
		return entry{}, false
	}
	return e, true
}

// unescape applies the desktop entry string escapes: \s, \n, \t, \r, \\.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 's':
			b.WriteByte(' ')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// execWord is the program an Exec value names: its first argument, after
// the string escapes and then the Exec quoting rules (a double-quoted
// argument, in which \" \\ \$ and \` stand for the character). An
// unterminated quote names nothing, and so does a closing quote that is
// not the end of the argument ("/usr/bin/x"y): the spec allows no such
// argument, and a shell would run another file than the quoted one.
func execWord(value string) string {
	s := strings.TrimLeft(unescape(value), " \t")
	if s == "" {
		return ""
	}
	if s[0] != '"' {
		if i := strings.IndexAny(s, " \t"); i >= 0 {
			return s[:i]
		}
		return s
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			if i+1 < len(s) && s[i+1] != ' ' && s[i+1] != '\t' {
				return ""
			}
			return b.String()
		case '\\':
			if i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
				i++
				b.WriteByte(s[i])
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return ""
}

// executable is the file the app with id and entry e runs, as a real
// path, or "" and the reason the entry names no app executable. Exec is
// what the desktop runs, so its first word is the program (program), and
// that holds whatever TryExec says: TryExec only names a file the desktop
// checks is installed before it shows the entry, so an entry whose
// TryExec names no file is no app (the desktop hides it), but when the
// file is there the executable is still Exec's program, never TryExec's,
// or the pin would be of a file the entry does not run and every process
// of that file would be the app. For an id in serverExes the table's path
// is the executable once Exec's program has passed every check but the
// native one (runnable): the table says which file the app's process runs,
// so Exec may be a wrapper script, as Ubuntu's gnome-terminal is, but not
// that any Exec, a Flatpak's `flatpak run` included, is the app's.
//
// Every program path, as the entry names it or as it was found in
// binDirs, is noted in st before it is resolved, so that the index sees
// the file appear, go, change or be pointed elsewhere (snapshot).
func (x *Index) executable(id string, e entry, st scanState) (exe, why string) {
	word := execWord(e.Exec)
	if word == "" {
		return "", "its entry names no program"
	}
	server := x.serverExes[id]
	check := x.program
	if server != "" {
		check = x.runnable
	}
	real, why := check(word, id, st)
	if why != "" {
		return "", why
	}
	if e.TryExec != "" && e.TryExec != word {
		if _, why := x.locate(e.TryExec, st); why != "" {
			return "", fmt.Sprintf("its TryExec %s names no installed file, so the desktop does not show the entry", q(e.TryExec))
		}
	}
	if server != "" {
		return x.program(server, id, st)
	}
	return real, ""
}

// runnable is the real path of the file the program name names, or "" and
// the reason it is no app's. A bare name is looked for in binDirs only; a
// relative path with a slash, a missing file and anything but a regular
// file name nothing (locate); a launcher, by the name written or by the
// file it resolves to, is no app (launchers).
func (x *Index) runnable(name, id string, st scanState) (real, why string) {
	if isLauncher(filepath.Base(name)) {
		return "", launcherWhy(name, id)
	}
	real, why = x.locate(name, st)
	if why != "" {
		return "", why
	}
	if isLauncher(filepath.Base(real)) {
		return "", launcherWhy(real, id)
	}
	return real, ""
}

// program is the real path of the native executable the program name
// names, or "" and the reason it is no app's: it must be runnable, and a
// file that is not a native (ELF) executable is no app either: a script or
// a jar is run by its interpreter, which is what /proc/<pid>/exe then
// names, so no process could ever be matched to the file (isNative). A
// file that cannot be read is told apart from a script: nothing is known
// about it, and its hash could not be read for a pin either.
func (x *Index) program(name, id string, st scanState) (real, why string) {
	real, why = x.runnable(name, id, st)
	if why != "" {
		return "", why
	}
	native, err := isNative(real)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "", fmt.Sprintf("its program %s cannot be read (permission denied), so it cannot be checked or pinned", q(real))
	case err != nil:
		return "", fmt.Sprintf("its program %s could not be read, so it cannot be checked or pinned", q(real))
	case !native:
		return "", fmt.Sprintf("its program %s is a script, not a native executable; the process that runs it is its interpreter, so no process can match app:%s", q(real), q(id))
	}
	return real, ""
}

// locate is the real path of the regular file the program name names: a
// bare name is looked for in x.bins only, a path with a slash must be
// absolute. It is "" and the reason when name leads to no such file. A
// path under /proc, /dev or /sys, written or reached through a link,
// names no installed file (realProgram). The path, as named or as found,
// is noted in st before it is resolved, so that the index sees the file
// appear, go or be pointed elsewhere.
func (x *Index) locate(name string, st scanState) (real, why string) {
	path := name
	if !strings.Contains(name, "/") {
		path = ""
		for _, dir := range x.bins {
			if isRegular(filepath.Join(dir, name)) {
				path = filepath.Join(dir, name)
				break
			}
		}
		if path == "" {
			return "", fmt.Sprintf("its program %s is not in %s", q(name), strings.Join(x.bins, ", "))
		}
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Sprintf("its program %s is a relative path", q(name))
	}
	st.note(path)
	real, err := realProgram(path)
	switch {
	case errors.Is(err, errKernelPath):
		return "", fmt.Sprintf("its program %s is not an installed file", q(path))
	case err != nil || !isRegular(real):
		return "", fmt.Sprintf("its program %s is not a file", q(path))
	}
	return real, ""
}

// errKernelPath: the program's path, or a link on the way to it, is under
// one of the kernel's own file systems.
var errKernelPath = errors.New("not an installed file")

// realProgram is the real path of the file the absolute path leads to,
// except that a path that reaches /proc, /dev or /sys, as written or
// through any link on the way, is errKernelPath: nothing there is an
// installed program, and /proc/self/exe is whoever reads it, the agent
// included, which a link in a user's folder could name. The path is walked
// one name at a time, as the kernel does: every link is seen, and `..` is
// the parent of where the walk has really got to, never of the text.
func realProgram(path string) (string, error) {
	real, rest := "/", path
	links := 0
	for {
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			return real, nil
		}
		name, tail, more := strings.Cut(rest, "/")
		rest = tail
		switch name {
		case ".":
			continue
		case "..":
			real = filepath.Dir(real) // real has no links, so this is its parent
			continue
		}
		next := filepath.Join(real, name)
		if isKernelPath(next) {
			return "", errKernelPath
		}
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if links++; links > 40 { // the kernel's own limit on a chain of links
				return "", unix.ELOOP
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if more {
				target += "/" + rest
			}
			if filepath.IsAbs(target) {
				real = "/"
			}
			rest = target
		case more && !fi.IsDir():
			return "", unix.ENOTDIR // a file's name, then more of the path
		default:
			real = next
		}
	}
}

// isKernelPath reports whether path is one of the kernel's own file
// systems or under one, where nothing is an installed program.
func isKernelPath(path string) bool {
	for _, root := range []string{"/proc", "/dev", "/sys"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// launcherWhy words the reason an entry whose program is the launcher at
// name is no app.
func launcherWhy(name, id string) string {
	return fmt.Sprintf("its program %s is a shell, interpreter or launcher that starts some other program, so no process can match app:%s", q(name), q(id))
}

// isRegular reports whether path names a regular file.
func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// elfMagic starts every native Linux executable.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// isNative reports whether the regular file at path is a native (ELF)
// executable: the only kind the kernel runs as itself, so that a process
// started from it has /proc/<pid>/exe name it. A script (#!) is run by
// its interpreter and a jar or a Windows program by a binfmt handler;
// /proc/<pid>/exe names that program, never the file. The error is the
// open's or the read's: then nothing is known about the file.
func isNative(path string) (bool, error) {
	f, err := openRegular(path, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, len(elfMagic))
	if _, err := io.ReadFull(f, head); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil // shorter than the magic: no ELF file
		}
		return false, err
	}
	return bytes.Equal(head, elfMagic), nil
}

// readEntryFile reads a desktop file of at most maxEntry bytes; a FIFO, a
// device or anything but a regular file under a .desktop name is no entry
// (openRegular).
func readEntryFile(path string) ([]byte, bool) {
	f, err := openRegular(path, maxEntry)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxEntry))
	if err != nil {
		return nil, false
	}
	return data, true
}

// errNotRegular: openRegular's path names something other than a regular
// file, or one larger than it was asked to open.
var errNotRegular = errors.New("not a regular file of the allowed size")

// openRegular opens the regular file at path (through links) for reading,
// or returns the error: the open's (fs.ErrPermission for a file the agent
// may not read), or errNotRegular when path names anything else or, with
// maxSize > 0, a larger file. The file is not opened until it is known to
// be a regular file: a path handle (O_PATH) is taken first, which opens
// nothing and so has no effect on a FIFO or a device (opening some
// character devices does something), its fstat is checked, and the same
// inode is then opened through the handle's /proc/self/fd link, so nothing
// swapped in between is read. The read descriptor is non-blocking all the
// same.
func openRegular(path string, maxSize int64) (*os.File, error) {
	h, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(h)
	var st unix.Stat_t
	if err := unix.Fstat(h, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || (maxSize > 0 && st.Size > maxSize) {
		return nil, errNotRegular
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", h), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}
