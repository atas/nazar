package kubeconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atas/nazar/core/k8s/cluster"
)

// Pending is an edited kubeconfig waiting in its temp file (k8s design
// 8): prepared before nazar-agent's prompt, so an unwritable kubeconfig
// fails before anything is approved; committed only after it.
type Pending struct {
	named     string // the path the user named (KUBECONFIG, ~/.kube/config)
	target    string // that path, symlinks resolved
	tmp       string
	mode      os.FileMode
	tightened bool
	create    bool // a new file: linked into place, never over one
}

// PrepareChange prepares ch: Prepare for a file that exists, prepareNew for
// one that does not.
func PrepareChange(ch *Change) (*Pending, error) {
	if ch.New {
		return prepareNew(ch.Path, ch.Data)
	}
	return Prepare(ch.Path, ch.Data)
}

// prepareNew writes data to a temp file beside target, a kubeconfig that
// does not exist yet (its directory is made 0700 if missing): Commit links
// it into place, and fails if anything is at target by then.
func prepareNew(target string, data []byte) (*Pending, error) {
	if !filepath.IsAbs(target) {
		return nil, fmt.Errorf("%s is not an absolute path", cluster.Display(target))
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s appeared while nazar read the kubeconfig (or is a link to nothing); run the command again", cluster.Display(target))
	}
	dir, base := filepath.Dir(target), filepath.Base(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%s can't be created: %v", cluster.Display(target), errors.Unwrap(err))
	}
	removeStale(dir, "."+base+".nazar-tmp.", time.Now())
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := filepath.Join(dir, "."+base+".nazar-tmp."+hex.EncodeToString(rnd[:]))
	if err := writeNew(tmp, data); err != nil {
		return nil, fmt.Errorf("%s can't be created: %v", cluster.Display(target), errors.Unwrap(err))
	}
	return &Pending{named: target, target: target, tmp: tmp, mode: 0o600, create: true}, nil
}

// staleAfter is how old a temp file must be before Prepare takes it for one
// a crashed run left: a younger one may belong to a run still waiting on
// its prompt.
const staleAfter = time.Minute

// Tightened reports whether Commit made the kubeconfig 0600 because it was
// open to the group or others.
func (p *Pending) Tightened() bool { return p.tightened }

// TempPath is the temp file's path.
func (p *Pending) TempPath() string { return p.tmp }

// Prepare writes data to .<base>.nazar-tmp.<random> in the directory of
// target's real file (a symlink is followed, so the rename stays on one
// file system and the link is kept), created with O_EXCL and mode 0600:
// the file is a full kubeconfig, other users' credentials included. A
// temp file a crashed run left (older than a minute) is removed first,
// never read or followed; a link there is never nazar's and is removed
// whatever its age.
func Prepare(target string, data []byte) (*Pending, error) {
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", cluster.Display(real))
	}
	dir, base := filepath.Dir(real), filepath.Base(real)
	removeStale(dir, "."+base+".nazar-tmp.", time.Now())
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := filepath.Join(dir, "."+base+".nazar-tmp."+hex.EncodeToString(rnd[:]))
	if err := writeNew(tmp, data); err != nil {
		return nil, fmt.Errorf("%s can't be rewritten: %v", cluster.Display(real), errors.Unwrap(err))
	}
	return &Pending{named: target, target: real, tmp: tmp, mode: fi.Mode().Perm()}, nil
}

// removeStale removes dir's entries named prefix* that a crashed run left:
// links whatever their age (os.Remove never follows one), regular files
// once older than staleAfter. Nothing is read.
func removeStale(dir, prefix string, now time.Time) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		fi, err := e.Info() // lstat: a link is described, not followed
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 || (fi.Mode().IsRegular() && now.Sub(fi.ModTime()) > staleAfter) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// writeNew creates path with O_EXCL and mode 0600 (never through an
// existing file or link), writes data and syncs it.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// Commit replaces the kubeconfig with the temp file, after writing the
// original, byte for byte, to <file>.nazar-backup-<UTC time> beside the
// path the user named (O_EXCL, 0600; a name taken gets -1, -2, …): the one
// backup. A new file (PrepareChange) is linked into place instead, with no
// backup, and only while nothing is there.
// It holds client-go's lock (<named>.lock, O_EXCL) while it checks and
// replaces, and fails if another program holds it. original is what the
// rewrite was made from; a file that changed since is left alone. The new
// file gets the original's mode, or 0600 if the original was open to the
// group or others (Tightened). On any failure the temp file is removed and
// the kubeconfig is as it was.
func (p *Pending) Commit(original []byte, now time.Time) (string, error) {
	lock := p.named + ".lock"
	lf, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		p.Abort()
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%s is locked by another program (%s exists); run the command again once it is done", cluster.Display(p.named), cluster.Display(lock))
		}
		return "", fmt.Errorf("the lock of %s can't be taken: %v", cluster.Display(p.named), errors.Unwrap(err))
	}
	lf.Close()
	defer os.Remove(lock)
	if p.create {
		// link(2) never replaces: a file put there meanwhile is left alone.
		err := os.Link(p.tmp, p.target)
		p.Abort()
		if err != nil {
			return "", fmt.Errorf("%s could not be created (%v); run the command again", cluster.Display(p.target), errors.Unwrap(err))
		}
		syncDir(filepath.Dir(p.target))
		return "", nil
	}
	cur, err := readFile(p.target)
	if err != nil || !bytes.Equal(cur, original) {
		p.Abort()
		return "", fmt.Errorf("%s changed after nazar read it; run the command again", cluster.Display(p.target))
	}
	stamp := filepath.Join(filepath.Dir(p.named), filepath.Base(p.named)+".nazar-backup-"+now.UTC().Format("20060102T150405Z"))
	backup := ""
	for i := 0; i < 10 && backup == ""; i++ {
		name := stamp
		if i > 0 {
			name = fmt.Sprintf("%s-%d", stamp, i)
		}
		switch err := writeNew(name, original); {
		case err == nil:
			backup = name
		case !errors.Is(err, os.ErrExist):
			p.Abort()
			return "", fmt.Errorf("the backup of %s can't be written: %v", cluster.Display(p.target), err)
		}
	}
	if backup == "" {
		p.Abort()
		return "", fmt.Errorf("no free backup name beside %s", cluster.Display(p.target))
	}
	mode := p.mode
	if mode&0o077 != 0 {
		mode, p.tightened = 0o600, true
	}
	if err := os.Chmod(p.tmp, mode); err != nil {
		p.Abort()
		_ = os.Remove(backup)
		return "", err
	}
	if err := os.Rename(p.tmp, p.target); err != nil {
		p.Abort()
		_ = os.Remove(backup)
		return "", err
	}
	syncDir(filepath.Dir(p.target))
	return backup, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// Abort removes the temp file.
func (p *Pending) Abort() { _ = os.Remove(p.tmp) }
