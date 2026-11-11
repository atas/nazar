package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DefaultFileMax is the size a FileSink rotates at when MaxBytes is not set.
const DefaultFileMax = 10 << 20

// FileSink appends audit lines to a file: Linux has no unified log. It keeps
// two files at most, Path and Path+".1", so the log can't fill a disk. The
// file is opened for each line, so one removed by hand comes back at the next
// line. Unlike the unified log it says nothing about who wrote a line: any
// program running as this user can write to it.
type FileSink struct {
	Path     string
	MaxBytes int64 // 0 means DefaultFileMax
	mu       sync.Mutex
}

// WriteAudit implements Sink: "<RFC3339Nano UTC> <line>\n", in a file of mode
// 0600 in a folder of mode 0700. Before a write that would pass MaxBytes the
// file is renamed to Path+".1", replacing it. An empty file is never renamed:
// that would replace .1 with nothing, so one line longer than MaxBytes is
// written as it is. When the rename fails the line still goes to the file,
// which grows past MaxBytes, and the error is returned.
func (s *FileSink) WriteAudit(t time.Time, line string) error {
	record := t.UTC().Format(time.RFC3339Nano) + " " + line + "\n"
	limit := s.MaxBytes
	if limit <= 0 {
		limit = DefaultFileMax
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, size, err := s.open()
	if err != nil {
		return err
	}
	var rotateErr error
	if size > 0 && size+int64(len(record)) > limit {
		if rotateErr = os.Rename(s.Path, s.Path+".1"); rotateErr == nil {
			f.Close()
			if f, _, err = s.open(); err != nil {
				return err
			}
		}
	}
	_, err = f.WriteString(record)
	return errors.Join(err, f.Close(), rotateErr)
}

// open opens Path for appending, making it and its folder when they are
// missing, and returns its size. O_NONBLOCK keeps a FIFO left at the path from
// blocking the decision this line belongs to (Logger's promise): with no
// reader the open fails, with one the file is refused here.
func (s *FileSink) open() (*os.File, int64, error) {
	const flags = os.O_WRONLY | os.O_APPEND | os.O_CREATE | syscall.O_NONBLOCK
	f, err := os.OpenFile(s.Path, flags, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		if err = os.MkdirAll(filepath.Dir(s.Path), 0o700); err == nil {
			f, err = os.OpenFile(s.Path, flags, 0o600)
		}
	}
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("audit: %s is not a regular file", s.Path)
	}
	if err == nil && fi.Mode().Perm() != 0o600 {
		err = f.Chmod(0o600)
	}
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// ParseFileLine splits one line of the file into its time and message. Like
// ParseLine it accepts exactly what the sink writes: the stamp must be the
// time's own RFC3339Nano form in UTC, then one space. A final newline is
// allowed; the message is not looked at (ParseLine does that).
func ParseFileLine(s string) (time.Time, string, error) {
	stamp, line, ok := strings.Cut(strings.TrimSuffix(s, "\n"), " ")
	if !ok {
		return time.Time{}, "", errors.New("audit: no time on the line")
	}
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("audit: bad time on the line: %w", err)
	}
	if t.UTC().Format(time.RFC3339Nano) != stamp {
		return time.Time{}, "", fmt.Errorf("audit: time %q is not in the sink's form", stamp)
	}
	return t, line, nil
}
