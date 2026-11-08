package daemon

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/config"
)

// migrateConfig rewrites config.yaml, once at start, when it holds forms
// builds before accepted and this one refuses, where a rewrite keeps the
// meaning (config.Migrate, which checks it means exactly the same): a
// single matcher becomes a list of one; scope or expire that did nothing,
// and to: [any] where no to: is the same, are removed. The old file is
// kept as config.yaml.bak.
//
// Nothing is approved here. The file then goes through Reload like any
// other: the approved config in the vault was rewritten the same way when
// the stager opened (configstage.Open), and the rewrite of the same bytes
// is the same bytes, so the approved file stays in force with no prompt,
// while any other file (an edit left staged, a file another process wrote)
// is judged against the approved config and waits for the login gate as
// it did before. What has no rewrite of the same meaning (a team spelled
// Apple, to: [any] on a key's rule that remembers approvals) is left in
// the file, which Reload then reports invalid with the fix, the approved
// config staying in force.
func (d *Daemon) migrateConfig() {
	data, err := d.readConfig()
	if err != nil || data == nil {
		return
	}
	out, ok := config.Migrate(data, config.Env{Home: d.o.Home})
	if !ok {
		return
	}
	bak := d.o.ConfigPath + ".bak"
	if err := writeBackup(bak, data); err != nil {
		d.o.Logf("config: not rewritten in today's form: the backup %s can't be written: %v", bak, err)
		return
	}
	// The file is read again just before it is replaced: an edit made
	// meanwhile is never overwritten (it is judged as it is).
	if now, err := d.readConfig(); err != nil || !bytes.Equal(now, data) {
		return
	}
	if err := writeFileAtomic(d.o.ConfigPath, out); err != nil {
		d.o.Logf("config: not rewritten in today's form: %v", err)
		return
	}
	d.o.Logf("config: rewrote %s in today's form (the same rules); the old file is %s", d.o.ConfigPath, bak)
	d.logOp("config", audit.Allowed, "config.yaml rewritten in today's form, the same rules; the old file is config.yaml.bak", nil)
}

// writeBackup replaces path with data, mode 0600: a fresh file renamed
// over it, so a link planted at path is replaced, never written through.
func writeBackup(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-bak-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}
