// Package run is the agent's side of `nazar run` (secrets design 6.3): what
// a command line resolves to, pinned per request (D5), and the
// handover of a secret to the process that runs it.
package run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// MaxPinnedFileSize is the most of a file nazar reads to pin it (secrets
// design 6.3.7): a larger one, a sparse file included, is refused rather
// than hashed for minutes.
const MaxPinnedFileSize = 64 << 20

// maxShebang bounds the first line read as a shebang.
const maxShebang = 256

// Kind is what a resolved receiver is (secrets design 6.3.6 step 7).
type Kind string

const (
	KindInterpreter Kind = "interpreter" // node or python: the exec'd process is the target
	KindLauncher    Kind = "launcher"    // npx: the target is a process it starts
)

// Family says which loader reaches the receiver.
type Family string

const (
	FamilyNode   Family = "node"
	FamilyPython Family = "python"
)

// File is a regular file as nazar pinned it: its realpath, the SHA-256 of
// its bytes (empty for the image, which is pinned by its code identity),
// and its identity, which the CLI compares with its own fstat right before
// execve (6.3 step 5).
type File struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtimeNs"`
	CtimeNs int64  `json:"ctimeNs"`
	// Dir marks a folder, pinned by its identity only.
	Dir bool `json:"dir,omitempty"`
}

// Resolution is what a nazar run command line resolves to.
type Resolution struct {
	Kind   Kind
	Family Family
	// Image is the file execve runs: the interpreter for a script, else
	// argv[0] itself; ImageCode its code identity (Platform.CodeHash),
	// which the running process must have after exec.
	Image     File
	ImageCode []byte
	// Script is the script the interpreter runs when argv[0] resolved to
	// one (npx-cli.js), nil otherwise.
	Script *File
	// ExecArgv is what the CLI passes to execve, derived here: the entry's
	// base name (the interpreter's for a script), never the caller's
	// string; then the shebang's argument, the script's realpath, and
	// argv[1:] as sent.
	ExecArgv []string
	// Files are the file elements of the command line, pinned.
	Files []File
	// Target is the package whose bin a launcher's handover goes to (npx);
	// "" for an interpreter, whose target is the exec'd process.
	Target string
	// Tail is argv[1:] as sent, which a command: matcher compares.
	Tail []string
}

// Refusal is why a command line can't be a nazar run receiver. Usage marks
// a command line that is wrong as written (a relative path), rather than
// one the config or the files refuse.
type Refusal struct {
	Usage bool
	Msg   string
}

func (r *Refusal) Error() string { return r.Msg }

func refuse(format string, args ...any) error {
	return &Refusal{Msg: fmt.Sprintf(format, args...)}
}

func usage(format string, args ...any) error {
	return &Refusal{Usage: true, Msg: fmt.Sprintf(format, args...)}
}

// Resolver resolves command lines the way secrets design 6.3.6 says: a bare
// argv[0] only through TrustedPath, never the caller's PATH; symlinks to
// their realpath; a script's shebang by nazar itself, so /usr/bin/env never
// runs. The same function serves config check and every request.
type Resolver struct {
	TrustedPath []string
	// CodeHash is Platform.CodeHash: the code identity of the image, which
	// the running process must have after exec. nil refuses every run.
	CodeHash func(path string) ([]byte, error)
	// ShimDirs are directories whose interpreters are Apple's xcode-select
	// shims (/usr/bin on macOS, 6.3.6 step 4): the shim execs another
	// image in the same process, so it is refused, never resolved.
	ShimDirs []string
}

// show is s for a message: as is when plain, Go-quoted otherwise.
func show(s string) string {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+@~", r)) {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

// why words a file error for a message: the errno alone, since a PathError
// repeats the path unquoted.
func why(err error) string {
	var pe *fs.PathError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "no such file"
	case errors.As(err, &pe):
		return pe.Err.Error()
	}
	return err.Error()
}

// Resolve resolves argv (as the caller typed it) into a pinned receiver.
func (r *Resolver) Resolve(argv []string) (*Resolution, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, usage("nazar run needs a command after --; it is empty")
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return nil, usage("an argument holds NUL, which no command line can carry")
		}
	}
	if r.CodeHash == nil {
		return nil, refuse("can't read the code identity of any receiver in this build")
	}
	entry, err := r.locate(argv[0])
	if err != nil {
		return nil, err
	}
	real, err := r.real(argv[0], entry)
	if err != nil {
		return nil, err
	}
	first, head, err := pin(real, false)
	if err != nil {
		return nil, err
	}
	res := &Resolution{Tail: slices.Clone(argv[1:])}
	exec0, entryBase := entry, filepath.Base(entry)
	var shebangArg []string
	if strings.HasPrefix(string(head), "#!") {
		script, _, err := pin(real, true)
		if err != nil {
			return nil, err
		}
		ientry, interp, arg, err := r.shebang(head, first.Size)
		if err != nil {
			return nil, err
		}
		img, ihead, err := pin(interp, false)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(string(ihead), "#!") {
			return nil, refuse("unsupported shebang in %s: its interpreter %s is a script too", show(real), show(interp))
		}
		res.Image, res.Script, exec0, shebangArg = img, &script, ientry, arg
	} else {
		res.Image = first
	}
	if err := r.kind(res, entryBase, argv); err != nil {
		return nil, err
	}
	opts := slices.Clone(shebangArg)
	if res.Script == nil {
		opts = append(opts, argv[1:]...)
	}
	if res.Family == FamilyPython {
		if f := skipsSite(opts); f != "" {
			return nil, refuse("python %s ignores PYTHONPATH or skips site, so the loader can't run; nazar can't deliver by late-env to it", f)
		}
	}
	if res.Family == FamilyNode && slices.ContainsFunc(opts, func(a string) bool { return strings.HasPrefix(a, "--inspect") }) {
		return nil, refuse("node's debugger (--inspect) lets other processes read the receiver's memory; remove it")
	}
	if res.Kind == KindInterpreter {
		stdin := argv
		if res.Script != nil {
			stdin = append(append([]string{exec0}, shebangArg...), res.Script.Path)
		}
		if w := config.InterpreterStdin(stdin); w != "" {
			return nil, refuse("%s", w)
		}
	}
	code, err := r.CodeHash(res.Image.Path)
	if err != nil || len(code) == 0 {
		return nil, refuse("can't read the code identity of %s", show(res.Image.Path))
	}
	res.ImageCode = code
	res.ExecArgv = append([]string{exec0}, shebangArg...)
	if res.Script != nil {
		res.ExecArgv = append(res.ExecArgv, res.Script.Path)
	}
	res.ExecArgv = append(res.ExecArgv, argv[1:]...)
	for _, fe := range config.FileElements(argv, res.Kind == KindInterpreter && res.Script == nil) {
		f, err := element(fe.Path)
		if err != nil {
			return nil, err
		}
		res.Files = append(res.Files, f)
	}
	if res.Kind == KindLauncher {
		if res.Target, err = npxTarget(argv[1:]); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// element pins a file element of the command line (6.3.7): absolute, not a
// symlink and under none, since a link re-pointed after the pin would hand
// the interpreter another file than the one pinned.
func element(path string) (File, error) {
	if !filepath.IsAbs(path) {
		return File{}, usage("%s is relative: the receiver runs in /; pass the absolute path", strconv.Quote(path))
	}
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		return File{}, refuse("%s: %s", show(path), why(err))
	}
	if p != path {
		return File{}, refuse("%s is a symlink or under one; pass its realpath (%s)", show(path), show(p))
	}
	f, _, err := pin(p, true)
	return f, err
}

// locate finds the entry argv[0] names: an absolute path as is, a bare
// name as the first executable regular file of that name in TrustedPath.
// A relative path with a slash has nothing to be relative to: the receiver
// never runs in the caller's directory (6.3.6 step 2).
func (r *Resolver) locate(a0 string) (string, error) {
	if strings.Contains(a0, "/") {
		if !filepath.IsAbs(a0) {
			return "", usage("%s is relative: the receiver runs in /; pass the absolute path", strconv.Quote(a0))
		}
		return a0, nil
	}
	for _, dir := range r.TrustedPath {
		p := filepath.Join(dir, a0)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", refuse("%s not found in defaults.trustedPath [%s]; pass an absolute path or add its directory", show(a0), strings.Join(r.TrustedPath, ", "))
}

// shimTools are the version managers whose shims run the tool they pick
// at run time, which would make the pin meaningless (6.3.3).
var shimTools = []string{"mise", "rtx", "asdf"}

// real is entry's realpath, refusing version-manager shims (6.3.3): a
// realpath named after the manager, or an entry or realpath in a shims
// directory.
func (r *Resolver) real(typed, entry string) (string, error) {
	p, err := filepath.EvalSymlinks(entry)
	if err != nil {
		return "", refuse("%s: %s", show(entry), why(err))
	}
	if t := strings.ToLower(filepath.Base(p)); slices.Contains(shimTools, t) {
		return "", refuse("%s resolves to a %s shim; use `%s which %s` and add the directory it prints to defaults.trustedPath", show(typed), t, t, show(filepath.Base(typed)))
	}
	for _, d := range []string{entry, p} {
		if strings.EqualFold(filepath.Base(filepath.Dir(d)), "shims") {
			return "", refuse("%s is a shim (%s); add the directory of the real program to defaults.trustedPath instead", show(filepath.Base(typed)), show(d))
		}
	}
	return p, nil
}

// shebang reads a script's first line (6.3.6 step 6): `#!/usr/bin/env
// NAME` with NAME found through TrustedPath, or `#!/absolute/interpreter`
// with at most one argument. It returns the entry (what execArgv[0] gets,
// as the kernel or env would pass it), the interpreter's realpath and the
// argument. Anything else is refused.
func (r *Resolver) shebang(head []byte, size int64) (string, string, []string, error) {
	line, _, ok := strings.Cut(string(head), "\n")
	if !ok && int64(len(head)) < size || len(line) > maxShebang {
		return "", "", nil, refuse("unsupported shebang: the first line is longer than %d bytes", maxShebang)
	}
	bad := func() (string, string, []string, error) {
		return "", "", nil, refuse("unsupported shebang %s: nazar runs #!/usr/bin/env NAME or #!/absolute/interpreter with at most one argument", show(strings.TrimRight(line, "\r")))
	}
	if strings.ContainsRune(line, 0) {
		return bad()
	}
	f := strings.Fields(strings.TrimPrefix(line, "#!"))
	var entry string
	var arg []string
	switch {
	case len(f) == 2 && (f[0] == "/usr/bin/env" || f[0] == "/bin/env") && !strings.HasPrefix(f[1], "-") && !strings.Contains(f[1], "/"):
		p, err := r.locate(f[1])
		if err != nil {
			return "", "", nil, err
		}
		entry = p
	case (len(f) == 1 || len(f) == 2) && filepath.IsAbs(f[0]) && filepath.Base(f[0]) != "env":
		entry, arg = f[0], f[1:]
	default:
		return bad()
	}
	p, err := r.real(filepath.Base(entry), entry)
	if err != nil {
		return "", "", nil, err
	}
	return entry, p, arg, nil
}

// refusedNames are receivers S12 showed the loaders can't reach, or that
// this version has no target rule for (secrets design 6.3, D7), by base
// name ignoring case: the entry's, the image's, the script's, and a direct
// interpreter's script or -m module.
var refusedNames = map[string]string{
	"pipx":       "pipx removes PYTHONPATH before it runs the tool, so nazar's loader never runs there; run the tool's own command instead",
	"bun":        "Bun ignores NODE_OPTIONS, so nazar's loader never runs in it",
	"bunx":       "Bun ignores NODE_OPTIONS, so nazar's loader never runs in it",
	"npm-cli.js": "npm is not a nazar run launcher in this version; use npx",
	"npm":        "npm is not a nazar run launcher in this version; use npx",
	"pnpm.cjs":   "pnpm is not a nazar run launcher in this version",
	"pnpm":       "pnpm is not a nazar run launcher in this version",
	"pnpx":       "pnpm is not a nazar run launcher in this version",
	"uvx":        "uvx is not a nazar run launcher in this version",
	"uv":         "uv is not a nazar run launcher in this version",
	"yarn":       "yarn is not a nazar run launcher in this version",
	"yarn.js":    "yarn is not a nazar run launcher in this version",
}

// npxScript is the realpath base name of npm's bin/npx.
const npxScript = "npx-cli.js"

// usePython is where a refusal of a python that can't be a receiver sends
// the user: spike S14 saw mise's pythons run as exec'd.
const usePython = "use another python3, such as mise's, and add its folder to defaults.trustedPath"

// frameworkStub reports whether image is a framework build's python,
// <X>.framework/Versions/<v>/bin/<python>: a stub that execs
// Resources/Python.app/Contents/MacOS/Python in the same process (Homebrew's,
// python.org's, Xcode's; spike S14), which the agent refuses as a second
// exec. Refused at resolve, before any dialog.
func frameworkStub(image string) bool {
	versions := filepath.Dir(filepath.Dir(filepath.Dir(image)))
	return strings.EqualFold(filepath.Base(filepath.Dir(image)), "bin") &&
		strings.EqualFold(filepath.Base(versions), "Versions") &&
		strings.HasSuffix(strings.ToLower(filepath.Base(filepath.Dir(versions))), ".framework")
}

// kind decides Kind and Family from base names, ignoring case as APFS
// does (6.3.6 step 7), and refuses what no loader reaches.
func (r *Resolver) kind(res *Resolution, entryBase string, argv []string) error {
	names := []string{entryBase, filepath.Base(res.Image.Path)}
	if res.Script != nil {
		names = append(names, filepath.Base(res.Script.Path))
	}
	for _, n := range names {
		if why, ok := refusedNames[strings.ToLower(n)]; ok {
			return refuse("%s", why)
		}
	}
	img := filepath.Base(res.Image.Path)
	switch {
	case !config.Interpreter(img):
		return refuse("late-env needs node or python; %s is a program, which no loader can reach", show(entryBase))
	case slices.Contains(r.ShimDirs, filepath.Dir(res.Image.Path)):
		return refuse("%s is Apple's xcode-select shim; Apple's %s can't take a secret by late-env: %s", show(img), show(img), usePython)
	case strings.HasPrefix(strings.ToLower(img), "node"):
		res.Family = FamilyNode
	case frameworkStub(res.Image.Path):
		return refuse("%s is a framework build of Python, which starts itself again, so it can't take a secret by late-env: %s", show(img), usePython)
	default:
		res.Family = FamilyPython
	}
	res.Kind = KindInterpreter
	if res.Script != nil {
		if strings.EqualFold(filepath.Base(res.Script.Path), npxScript) && res.Family == FamilyNode {
			res.Kind = KindLauncher
		}
		return nil
	}
	// A launcher run as a direct interpreter's script or module would get
	// the value in its own process (D7): it runs by its own name or not.
	var scripts []string
	for _, fe := range config.FileElements(argv, true) {
		scripts = append(scripts, filepath.Base(fe.Path))
	}
	if i := slices.Index(argv, "-m"); i > 0 && i+1 < len(argv) {
		scripts = append(scripts, argv[i+1])
	}
	for _, n := range scripts {
		if _, ok := refusedNames[strings.ToLower(n)]; ok || strings.EqualFold(n, npxScript) {
			return refuse("%s must be run by its own name, not as a script of %s", show(n), show(img))
		}
	}
	return nil
}

// skipsSite returns the first python option in opts that keeps the loader
// from running (-I, -E, -S, alone or combined, 6.3.1 step 5), or "".
// Options end at the first argument that is not one, at "--", and at -c
// or -m; -W, -X and --check-hash-based-pycs take a value.
func skipsSite(opts []string) string {
	for i := 0; i < len(opts); i++ {
		a := opts[i]
		switch {
		case a == "--" || a == "-" || !strings.HasPrefix(a, "-"):
			return ""
		case a == "--check-hash-based-pycs":
			i++
			continue
		case strings.HasPrefix(a, "--"):
			continue
		}
	cluster:
		for j, c := range a[1:] {
			switch c {
			case 'I', 'E', 'S':
				return "-" + string(c)
			case 'c', 'm':
				return ""
			case 'W', 'X':
				if j == len(a)-2 {
					i++ // the value is the next argument
				}
				break cluster
			}
		}
	}
	return ""
}

// npmName is a package spec nazar run can name a target for: an npm
// package name, scoped or not, lower case, with an optional version that
// npm can't read as a path ("." and ".." would be).
var npmName = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*(@[A-Za-z0-9_~^<>=*+-][A-Za-z0-9._~^<>=*+-]*)?$`)

// npxTarget is the package `npx [-y|--yes] <package>[@version] [args…]`
// runs (secrets design 6.3, D2): its bin is the target. Any other npx
// command line is refused, because which process npx starts can't be told
// from it.
func npxTarget(tail []string) (string, error) {
	i := 0
	if i < len(tail) && (tail[i] == "-y" || tail[i] == "--yes") {
		i++
	}
	if i >= len(tail) || !npmName.MatchString(tail[i]) || len(tail[i]) > 214 {
		return "", usage("nazar run can't tell which process npx starts for this command line; write it as npx -y <package> [args]")
	}
	spec := tail[i]
	if at := strings.LastIndexByte(spec, '@'); at > 0 {
		spec = spec[:at]
	}
	return spec, nil
}

// pin opens path, a realpath, without following a final symlink and
// without blocking, and requires a regular file (6.3.7, "Reading
// attacker-writable files safely"); lstat first, so no device node is ever
// opened. With hash it reads at most MaxPinnedFileSize and records the
// SHA-256 (scripts and file elements); without, only the identity (the
// image, pinned by its code identity). It returns the file's first bytes,
// for the shebang.
func pin(path string, hash bool) (File, []byte, error) {
	if fi, err := os.Lstat(path); err != nil {
		return File{}, nil, refuse("%s: %s", show(path), why(err))
	} else if !fi.Mode().IsRegular() {
		return File{}, nil, refuse("%s is not a regular file", show(path))
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return File{}, nil, refuse("%s is not a regular file", show(path))
		}
		return File{}, nil, refuse("%s: %s", show(path), why(err))
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return File{}, nil, refuse("%s: %s", show(path), why(err))
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok {
		return File{}, nil, refuse("%s is not a regular file", show(path))
	}
	if err := onSystemVolume(f, path); err != nil {
		return File{}, nil, err
	}
	if hash && fi.Size() > MaxPinnedFileSize {
		return File{}, nil, refuse("%s is larger than %d MiB, more than nazar reads to pin a file", show(path), MaxPinnedFileSize>>20)
	}
	head := make([]byte, maxShebang+1)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	out := File{Path: path, Dev: uint64(st.Dev), Ino: st.Ino, Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), CtimeNs: ctimeNs(st)}
	if hash {
		h := sha256.New()
		h.Write(head)
		rest, err := io.Copy(h, io.LimitReader(f, MaxPinnedFileSize))
		if err != nil {
			return File{}, nil, refuse("%s: %s", show(path), why(err))
		}
		if int64(n)+rest != fi.Size() {
			return File{}, nil, refuse("%s changed while nazar read it", show(path))
		}
		out.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return out, head, nil
}

// Pin pins the regular file path, a realpath, with its SHA-256.
func Pin(path string) (File, error) {
	f, _, err := pin(path, true)
	return f, err
}

// PinDir pins the folder path, a realpath, by its identity, and requires it
// to hold exactly names (CPython imports a package, an extension
// or cached bytecode found beside its loader before the loader, and any
// module there shadows one the loader imports). An entry added, removed or
// renamed in it, even one put back, and the folder moved aside and back,
// change its mtime or ctime, which Repin then sees.
func PinDir(path string, names ...string) (File, error) { return pinDir(path, names, true) }

func pinDir(path string, names []string, list bool) (File, error) {
	d, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return File{}, refuse("%s: %s", show(path), why(err))
	}
	defer d.Close()
	if err := onSystemVolume(d, path); err != nil {
		return File{}, err
	}
	id := func() (File, error) {
		fi, err := d.Stat()
		if err != nil {
			return File{}, refuse("%s: %s", show(path), why(err))
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || !fi.IsDir() {
			return File{}, refuse("%s is not a folder", show(path))
		}
		return File{Path: path, Dir: true, Dev: uint64(st.Dev), Ino: st.Ino, Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), CtimeNs: ctimeNs(st)}, nil
	}
	before, err := id()
	if err != nil || !list {
		return before, err
	}
	got, err := d.Readdirnames(-1)
	if err != nil {
		return File{}, refuse("%s: %s", show(path), why(err))
	}
	if after, err := id(); err != nil || after != before {
		return File{}, refuse("%s changed while nazar read it", show(path))
	}
	slices.Sort(got)
	if want := slices.Sorted(slices.Values(names)); !slices.Equal(got, want) {
		return File{}, refuse("%s must hold only %s", show(path), strings.Join(want, ", "))
	}
	return before, nil
}

// onSystemVolume refuses a file or folder on a volume a process of this
// user mounted (secrets design 6.3, D12): mounted over a folder, it hides
// what the folder holds without changing it, and a share's server can give
// nazar and the interpreter different bytes. Pin, PinDir, PinAbove and
// Repin all apply
// it, so it holds at the request, at the exec and right before the write.
func onSystemVolume(f *os.File, path string) error {
	uid, err := mountedBy(f)
	switch {
	case err != nil:
		return refuse("%s: its volume can't be read", show(path))
	case uid != 0:
		return refuse("%s is on a volume you mounted", show(path))
	}
	return nil
}

// PinAbove pins, by identity, every folder above path, a realpath, that a
// process of this user can move aside and back: one whose parent it can
// write, or owns and so can make writable. Moving a folder changes its own
// ctime, not that of anything in it, so the pins of a folder and its file
// alone still match a tree put back after a swap above them.
func PinAbove(path string) ([]File, error) {
	var out []File
	for d := filepath.Dir(path); d != filepath.Dir(d); d = filepath.Dir(d) {
		if !movable(d) {
			continue
		}
		f, err := pinDir(d, nil, false)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// movable reports whether a process of this user can rename dir: its
// parent is writable, or the user's own. Unknown is movable.
func movable(dir string) bool {
	parent := filepath.Dir(dir)
	if unix.Access(parent, unix.W_OK) == nil {
		return true
	}
	var st unix.Stat_t
	return unix.Stat(parent, &st) != nil || int(st.Uid) == os.Geteuid()
}

// Repin pins f.Path again, re-resolving it (a symlink put in its place, or
// above it, is a change), and reports whether it is still the same file
// with the same bytes, or the same folder by its identity: nil, or a
// refusal naming it.
func Repin(f File) error {
	if p, err := filepath.EvalSymlinks(f.Path); err != nil || p != f.Path {
		return refuse("%s changed", show(filepath.Base(f.Path)))
	}
	var now File
	var err error
	if f.Dir {
		now, err = pinDir(f.Path, nil, false)
	} else {
		now, _, err = pin(f.Path, f.SHA256 != "")
	}
	if err != nil || now != f {
		return refuse("%s changed", show(filepath.Base(f.Path)))
	}
	return nil
}

// Recheck checks that every file res pinned is still what was pinned: the
// image by its identity and code identity, the script and the file
// elements by their bytes (6.3 steps 3 and 6). It is what the agent runs
// again right before it hands the value over.
func (r *Resolver) Recheck(res *Resolution) error {
	if err := Repin(res.Image); err != nil {
		return err
	}
	if r.CodeHash == nil {
		return refuse("can't read the code identity of %s", show(res.Image.Path))
	}
	if code, err := r.CodeHash(res.Image.Path); err != nil || !slices.Equal(code, res.ImageCode) {
		return refuse("%s changed", show(filepath.Base(res.Image.Path)))
	}
	if res.Script != nil {
		if err := Repin(*res.Script); err != nil {
			return err
		}
	}
	for _, f := range res.Files {
		if err := Repin(f); err != nil {
			return err
		}
	}
	return nil
}

// Identity is the receiver's identity for approvals (secrets design 6.3,
// D5): every realpath, the image's code identity, the hash of every other
// pinned file and the command line. Other bytes, another file or another
// argument is another receiver, so a remembered approval never serves it.
func (res *Resolution) Identity() string {
	var b strings.Builder
	fmt.Fprintf(&b, "run:%s#%x", strconv.Quote(res.Image.Path), res.ImageCode)
	if res.Script != nil {
		fmt.Fprintf(&b, " script:%s#%s", strconv.Quote(res.Script.Path), res.Script.SHA256)
	}
	for _, f := range res.Files {
		fmt.Fprintf(&b, " file:%s#%s", strconv.Quote(f.Path), f.SHA256)
	}
	b.WriteString(" argv:")
	for i, a := range res.ExecArgv {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(a))
	}
	return b.String()
}

// Receiver is the record the run is judged and remembered by (caller.
// Synthetic): the realpath argv[0] resolved to (the script, for a
// script) and its own tail as argv, the directory it runs in, and as its
// code hash a digest of Identity and of env, the environment the receiver
// gets apart from what changes every run (the agent passes it), so the
// approval key changes with any pinned byte, argument, envAllow value or
// PATH (secrets design 6.3, D5). It claims no signature.
func (res *Resolution) Receiver(env []string) platform.ProcessInfo {
	path := res.Image.Path
	if res.Script != nil {
		path = res.Script.Path
	}
	h := sha256.New()
	h.Write([]byte(res.Identity()))
	sorted := slices.Clone(env)
	slices.Sort(sorted)
	for _, kv := range sorted {
		h.Write([]byte("\x00" + kv))
	}
	return platform.ProcessInfo{Path: path, Args: append([]string{path}, res.Tail...), Cwd: "/", Code: platform.CodeIdentity{CDHash: h.Sum(nil)}}
}

// Locate is the realpath argv0 names, the way Resolve finds it (through
// TrustedPath, shims refused) without pinning anything: what a command:
// matcher's argv[0] is compared by (match.Evaluator.Command).
func (r *Resolver) Locate(argv0 string) (string, error) {
	if argv0 == "" {
		return "", usage("empty")
	}
	entry, err := r.locate(argv0)
	if err != nil {
		return "", err
	}
	return r.real(argv0, entry)
}

// maxPackageJSON bounds the package.json IsBinOf reads.
const maxPackageJSON = 1 << 20

// IsBinOf reports whether main, a launcher's descendant's main module, is a
// bin of package pkg (secrets design 6.3, D2): the same rule as the Node
// loader's. Its realpath lies under the first node_modules of the path, in
// node_modules/<pkg>/, with no node_modules after it, and that package's
// package.json names pkg and lists the file among its bins. A dependency's
// own copy, an install script and a look-alike package are not. It reads
// files a launcher wrote (its cache), so it is a selector, not a boundary:
// what a launcher runs is the launcher's choice (secrets design 10).
func IsBinOf(main, pkg string) bool {
	if main == "" || pkg == "" {
		return false
	}
	real, err := filepath.EvalSymlinks(main)
	if err != nil {
		return false
	}
	const nm = "/node_modules/"
	i := strings.Index(real, nm)
	if i < 0 || !strings.HasPrefix(real[i+len(nm):], pkg+"/") {
		return false
	}
	root := real[:i+len(nm)+len(pkg)]
	if strings.Contains(real[len(root):], nm) {
		return false
	}
	// Opened as a pinned file is (pin): never a FIFO that would block the
	// agent, never a symlink, a regular file of bounded size.
	fd, err := syscall.Open(filepath.Join(root, "package.json"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), "package.json")
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > maxPackageJSON {
		return false
	}
	var pj struct {
		Name string          `json:"name"`
		Bin  json.RawMessage `json:"bin"`
	}
	if err := json.NewDecoder(io.LimitReader(f, maxPackageJSON)).Decode(&pj); err != nil || pj.Name != pkg {
		return false
	}
	var bins []string
	var one string
	var many map[string]any
	switch {
	case json.Unmarshal(pj.Bin, &one) == nil:
		bins = []string{one}
	case json.Unmarshal(pj.Bin, &many) == nil:
		for _, b := range many {
			if s, ok := b.(string); ok { // npm skips what is not a path
				bins = append(bins, s)
			}
		}
	}
	for _, b := range bins {
		if p, err := filepath.EvalSymlinks(filepath.Join(root, b)); err == nil && p == real {
			return true
		}
	}
	return false
}
