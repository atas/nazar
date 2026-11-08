// Package cbridge is the Go end of the C ABI between Nazar.app (Swift) and
// the Go core (spec 4.7, spike S11; the ABI is
// macos/Sources/CNazarBridge/include/nazar_bridge.h). New wraps the
// NazarCallbacks table Swift hands to NazarCoreStart in a platform.Platform,
// a platform.Vault and an audit.Sink.
//
// Ownership: every input Go passes is C memory Go allocated for the call and
// frees when the call returns; every output is an NzBuf Swift allocated,
// which Go copies and hands back through free_buf exactly once (also on
// error statuses). No Go pointer is ever passed to C.
package cbridge

/*
#cgo CFLAGS: -I${SRCDIR}/../../macos/Sources/CNazarBridge/include
#include <stdlib.h>
#include <string.h>
#include "nazar_bridge.h"

static int nz_complete(const NazarCallbacks *c) {
	return c->create_key && c->sign && c->key_agreement && c->delete_key && c->authenticate && c->confirm &&
	       c->release_approval && c->peer_of && c->process && c->app_for && c->code_hash && c->responsible_for &&
	       c->installed_app && c->apps && c->watch_exit && c->watch_screen_lock && c->show_warning && c->vault_get &&
	       c->vault_put && c->vault_delete && c->vault_list && c->write_audit && c->free_buf;
}
static int32_t nz_create_key(const NazarCallbacks *c, int32_t p, int32_t a, int32_t x, NzBuf *h, NzBuf *pub) { return c->create_key(p, a, x, h, pub); }
static int32_t nz_sign(const NazarCallbacks *c, const uint8_t *h, size_t hn, const uint8_t *d, size_t dn, uint64_t r, NzBuf *o) { return c->sign(h, hn, d, dn, r, o); }
static int32_t nz_key_agreement(const NazarCallbacks *c, const uint8_t *h, size_t hn, const uint8_t *p, size_t pn, uint64_t r, NzBuf *o) { return c->key_agreement(h, hn, p, pn, r, o); }
static int32_t nz_delete_key(const NazarCallbacks *c, const uint8_t *h, size_t hn) { return c->delete_key(h, hn); }
static int32_t nz_authenticate(const NazarCallbacks *c, int32_t p, const uint8_t *j, size_t jn, uint64_t *r) { return c->authenticate(p, j, jn, r); }
static int32_t nz_confirm(const NazarCallbacks *c, const uint8_t *j, size_t jn, int32_t *a) { return c->confirm(j, jn, a); }
static void nz_release_approval(const NazarCallbacks *c, uint64_t r) { c->release_approval(r); }
static int32_t nz_peer_of(const NazarCallbacks *c, int32_t fd, int64_t *pid, uint64_t *gen) { return c->peer_of(fd, pid, gen); }
static int32_t nz_process(const NazarCallbacks *c, int64_t pid, uint64_t gen, NzBuf *o) { return c->process(pid, gen, o); }
static int32_t nz_app_for(const NazarCallbacks *c, const uint8_t *j, size_t jn, NzBuf *o) { return c->app_for(j, jn, o); }
static int32_t nz_code_hash(const NazarCallbacks *c, const uint8_t *p, size_t pn, NzBuf *o) { return c->code_hash(p, pn, o); }
static int32_t nz_responsible_for(const NazarCallbacks *c, int64_t pid, uint64_t gen, int64_t *r) { return c->responsible_for(pid, gen, r); }
static int32_t nz_installed_app(const NazarCallbacks *c, const uint8_t *b, size_t bn, NzBuf *o) { return c->installed_app(b, bn, o); }
static int32_t nz_apps(const NazarCallbacks *c, NzBuf *o) { return c->apps(o); }
static void nz_watch_exit(const NazarCallbacks *c, int64_t pid, uint64_t gen, uint64_t t) { c->watch_exit(pid, gen, t); }
static void nz_watch_screen_lock(const NazarCallbacks *c, uint64_t t) { c->watch_screen_lock(t); }
static void nz_show_warning(const NazarCallbacks *c, const uint8_t *j, size_t jn) { c->show_warning(j, jn); }
static int32_t nz_vault_get(const NazarCallbacks *c, const uint8_t *n, size_t nn, NzBuf *o) { return c->vault_get(n, nn, o); }
static int32_t nz_vault_put(const NazarCallbacks *c, const uint8_t *n, size_t nn, const uint8_t *v, size_t vn) { return c->vault_put(n, nn, v, vn); }
static int32_t nz_vault_delete(const NazarCallbacks *c, const uint8_t *n, size_t nn) { return c->vault_delete(n, nn); }
static int32_t nz_vault_list(const NazarCallbacks *c, const uint8_t *p, size_t pn, NzBuf *o) { return c->vault_list(p, pn, o); }
static int32_t nz_write_audit(const NazarCallbacks *c, int64_t ns, const uint8_t *l, size_t ln) { return c->write_audit(ns, l, ln); }
static void nz_free(const NazarCallbacks *c, uint8_t *p) { c->free_buf(p); }
static NazarCallbacks *nz_copy(const NazarCallbacks *c) {
	NazarCallbacks *p = malloc(sizeof *p);
	if (p) memcpy(p, c, sizeof *p);
	return p;
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unsafe"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
)

// maxOutput bounds any buffer Go accepts from Swift.
const maxOutput = 16 << 20

// Bridge implements platform.Platform over a NazarCallbacks table.
type Bridge struct {
	cb *C.NazarCallbacks // Go's own copy, in C memory, for the process lifetime
}

var (
	_ platform.Platform = (*Bridge)(nil)
	_ platform.Vault    = Vault{}
	_ audit.Sink        = Sink{}
)

// New copies the callbacks table at cb (a *NazarCallbacks) and checks its
// ABI version and that every function pointer is set.
func New(cb unsafe.Pointer) (*Bridge, error) {
	c := (*C.NazarCallbacks)(cb)
	if c == nil {
		return nil, errors.New("cbridge: no callbacks table")
	}
	if c.abi_version != C.NAZAR_ABI_VERSION {
		return nil, fmt.Errorf("cbridge: callbacks ABI version %d, want %d", c.abi_version, C.NAZAR_ABI_VERSION)
	}
	if C.nz_complete(c) == 0 {
		return nil, errors.New("cbridge: callbacks table has a NULL function")
	}
	cp := C.nz_copy(c)
	if cp == nil {
		return nil, errors.New("cbridge: out of memory")
	}
	return &Bridge{cb: cp}, nil
}

// Vault is the bridge's platform.Vault.
func (b *Bridge) Vault() Vault { return Vault{b} }

// Sink is the bridge's audit.Sink.
func (b *Bridge) Sink() Sink { return Sink{b} }

// statusErr maps an NZ_* status to the platform errors.
func statusErr(op string, st C.int32_t) error {
	switch st {
	case C.NZ_OK:
		return nil
	case C.NZ_NOT_FOUND:
		return platform.ErrNotFound
	case C.NZ_NO_PROCESS:
		return platform.ErrNoProcess
	case C.NZ_DENIED:
		return platform.ErrDenied
	case C.NZ_AUTH_REQUIRED:
		return platform.ErrAuthRequired
	case C.NZ_AMBIGUOUS:
		return platform.ErrAmbiguous
	case C.NZ_UNREADABLE:
		return platform.ErrUnreadable
	case C.NZ_LOCKED:
		return platform.ErrLocked
	case C.NZ_INVALID:
		return fmt.Errorf("platform: %s: refused input", op)
	}
	return fmt.Errorf("platform: %s failed (status %d)", op, int32(st))
}

// in is one input buffer: C memory valid until free is called. Empty input
// is (NULL, 0).
type in struct {
	p *C.uint8_t
	n C.size_t
}

func cin(b []byte) in {
	if len(b) == 0 {
		return in{}
	}
	return in{(*C.uint8_t)(C.CBytes(b)), C.size_t(len(b))}
}

func (i in) free() {
	if i.p != nil {
		C.free(unsafe.Pointer(i.p))
	}
}

// take copies an output buffer and hands it back to Swift. A buffer larger
// than maxOutput is freed and refused.
func (b *Bridge) take(buf C.NzBuf) ([]byte, error) {
	if buf.ptr == nil {
		return nil, nil
	}
	defer C.nz_free(b.cb, buf.ptr)
	if buf.len > maxOutput {
		return nil, errors.New("cbridge: output too large")
	}
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len)), nil
}

func i32(v int) (C.int32_t, bool) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, false
	}
	return C.int32_t(v), true
}

// ---- keys -----------------------------------------------------------------

func (b *Bridge) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	p, ok1 := i32(int(purpose))
	a, ok2 := i32(int(auth))
	x, ok3 := i32(int(access))
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, fmt.Errorf("platform: purpose %v / policy %v / access %v out of range", purpose, auth, access)
	}
	var h, pub C.NzBuf
	st := C.nz_create_key(b.cb, p, a, x, &h, &pub)
	handle, err1 := b.take(h)
	pk, err2 := b.take(pub)
	if err := statusErr("create key", st); err != nil {
		return nil, nil, err
	}
	if err := errors.Join(err1, err2); err != nil {
		return nil, nil, err
	}
	if len(handle) == 0 || len(pk) != 65 || pk[0] != 4 {
		return nil, nil, errors.New("platform: create key returned a malformed key")
	}
	return handle, pk, nil
}

func (b *Bridge) Sign(handle, digestInput []byte, approval platform.ApprovalRef) ([]byte, error) {
	h, d := cin(handle), cin(digestInput)
	defer h.free()
	defer d.free()
	var out C.NzBuf
	st := C.nz_sign(b.cb, h.p, h.n, d.p, d.n, C.uint64_t(approval), &out)
	sig, err := b.take(out)
	if e := statusErr("sign", st); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if len(sig) == 0 {
		return nil, errors.New("platform: sign returned no signature")
	}
	return sig, nil
}

func (b *Bridge) KeyAgreement(handle, peerPublicKey []byte, approval platform.ApprovalRef) ([]byte, error) {
	h, p := cin(handle), cin(peerPublicKey)
	defer h.free()
	defer p.free()
	var out C.NzBuf
	st := C.nz_key_agreement(b.cb, h.p, h.n, p.p, p.n, C.uint64_t(approval), &out)
	sec, err := b.take(out)
	if e := statusErr("key agreement", st); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if len(sec) == 0 {
		return nil, errors.New("platform: key agreement returned no secret")
	}
	return sec, nil
}

func (b *Bridge) DeleteKey(handle []byte) error {
	h := cin(handle)
	defer h.free()
	return statusErr("delete key", C.nz_delete_key(b.cb, h.p, h.n))
}

// ---- approvals ---------------------------------------------------------------

func (b *Bridge) Authenticate(policy platform.AuthPolicy, prompt platform.Prompt) (platform.ApprovalRef, error) {
	pol, ok := i32(int(policy))
	if !ok {
		return 0, fmt.Errorf("platform: policy %v out of range", policy)
	}
	js, err := json.Marshal(toWirePrompt(prompt))
	if err != nil {
		return 0, err
	}
	j := cin(js)
	defer j.free()
	var ref C.uint64_t
	if err := statusErr("authenticate", C.nz_authenticate(b.cb, pol, j.p, j.n, &ref)); err != nil {
		return 0, err
	}
	if ref == 0 {
		return 0, errors.New("platform: authenticate returned no approval") // fail closed
	}
	return platform.ApprovalRef(ref), nil
}

func (b *Bridge) Confirm(prompt platform.Prompt) (bool, error) {
	js, err := json.Marshal(toWirePrompt(prompt))
	if err != nil {
		return false, err
	}
	j := cin(js)
	defer j.free()
	var allowed C.int32_t
	if err := statusErr("confirm", C.nz_confirm(b.cb, j.p, j.n, &allowed)); err != nil {
		return false, err
	}
	return confirmAnswer(int32(allowed))
}

// confirmAnswer turns confirm's `allowed` output into Confirm's answer: 1
// allows; 2 to 5 say how the dialog was denied (platform.DialogHow); 0 and
// every other value are a plain denial, never an allow.
func confirmAnswer(allowed int32) (bool, error) {
	switch h := platform.DialogHow(allowed); {
	case allowed == 1:
		return true, nil
	case h == platform.DialogDenyButton, h == platform.DialogEscape, h == platform.DialogTimedOut, h == platform.DialogClosed:
		return false, platform.DialogDenied{How: h}
	}
	return false, nil
}

func (b *Bridge) ReleaseApproval(ref platform.ApprovalRef) {
	C.nz_release_approval(b.cb, C.uint64_t(ref))
}

// ---- callers ----------------------------------------------------------------

func (b *Bridge) PeerOf(fd int) (platform.ProcessRef, error) {
	f, ok := i32(fd)
	if !ok || fd < 0 {
		return platform.ProcessRef{}, platform.ErrNoProcess
	}
	var pid C.int64_t
	var gen C.uint64_t
	if err := statusErr("peer", C.nz_peer_of(b.cb, f, &pid, &gen)); err != nil {
		return platform.ProcessRef{}, err
	}
	if pid <= 0 || gen == 0 {
		return platform.ProcessRef{}, platform.ErrNoProcess // never a PID-only peer
	}
	return platform.ProcessRef{PID: int(pid), Generation: uint64(gen)}, nil
}

func (b *Bridge) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	if ref.PID <= 0 {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	var out C.NzBuf
	st := C.nz_process(b.cb, C.int64_t(ref.PID), C.uint64_t(ref.Generation), &out)
	js, err := b.take(out)
	if e := statusErr("process", st); e != nil {
		return platform.ProcessInfo{}, e
	}
	if err != nil {
		return platform.ProcessInfo{}, err
	}
	var w wireProcess
	if err := decodeStrict(js, &w); err != nil {
		return platform.ProcessInfo{}, err
	}
	info := w.info()
	// Defence in depth: the answer must be for the PID asked about, a full
	// ref, and exactly the instance asked about when the ref was full.
	if info.Ref.PID != ref.PID || info.Ref.Generation == 0 || (ref.Generation != 0 && info.Ref != ref) {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	return info, nil
}

func (b *Bridge) AppFor(chain []platform.ProcessInfo) (platform.AppInfo, bool) {
	if len(chain) == 0 {
		return platform.AppInfo{}, false
	}
	ws := make([]wireProcess, len(chain))
	for i, p := range chain {
		ws[i] = toWireProcess(p)
	}
	js, err := json.Marshal(ws)
	if err != nil {
		return platform.AppInfo{}, false
	}
	j := cin(js)
	defer j.free()
	var out C.NzBuf
	st := C.nz_app_for(b.cb, j.p, j.n, &out)
	res, err := b.take(out)
	if st != C.NZ_OK || err != nil {
		return platform.AppInfo{}, false
	}
	var w wireApp
	if decodeStrict(res, &w) != nil || w.PID <= 0 || w.Generation == 0 || w.BundleID == "" {
		return platform.AppInfo{}, false
	}
	return platform.AppInfo{Ref: platform.ProcessRef{PID: w.PID, Generation: w.Generation}, BundleID: w.BundleID, Name: w.Name, Code: w.Code.identity()}, true
}

// Apps decodes the array of app records as strictly as AppFor decodes one:
// a malformed answer, or one entry without a full ref or a bundle id, is
// no list at all (core/caller then finds no app, which is the safe side).
func (b *Bridge) Apps() []platform.AppInfo {
	var out C.NzBuf
	st := C.nz_apps(b.cb, &out)
	res, err := b.take(out)
	if st != C.NZ_OK || err != nil {
		return nil
	}
	var ws []wireApp
	if decodeStrict(res, &ws) != nil {
		return nil
	}
	apps := make([]platform.AppInfo, 0, len(ws))
	for _, w := range ws {
		if w.PID <= 0 || w.Generation == 0 || w.BundleID == "" {
			return nil
		}
		apps = append(apps, platform.AppInfo{Ref: platform.ProcessRef{PID: w.PID, Generation: w.Generation}, BundleID: w.BundleID, Name: w.Name, Code: w.Code.identity()})
	}
	return apps
}

func (b *Bridge) CodeHash(path string) ([]byte, error) {
	p := cin([]byte(path))
	defer p.free()
	var out C.NzBuf
	st := C.nz_code_hash(b.cb, p.p, p.n, &out)
	h, err := b.take(out)
	if e := statusErr("code hash", st); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if len(h) == 0 {
		return nil, errors.New("platform: code hash returned nothing")
	}
	return h, nil
}

func (b *Bridge) ResponsibleFor(ref platform.ProcessRef) (platform.ProcessRef, bool) {
	if ref.PID <= 0 {
		return platform.ProcessRef{}, false
	}
	var r C.int64_t
	if C.nz_responsible_for(b.cb, C.int64_t(ref.PID), C.uint64_t(ref.Generation), &r) != C.NZ_OK || r <= 0 || r > math.MaxInt32 {
		return platform.ProcessRef{}, false
	}
	return platform.ProcessRef{PID: int(r)}, true // PID-only: core/caller resolves and checks it
}

func (b *Bridge) InstalledApp(bundleID string) (platform.AppBundle, error) {
	id := cin([]byte(bundleID))
	defer id.free()
	var out C.NzBuf
	st := C.nz_installed_app(b.cb, id.p, id.n, &out)
	js, err := b.take(out)
	if e := statusErr("installed app", st); e != nil {
		return platform.AppBundle{}, e
	}
	if err != nil {
		return platform.AppBundle{}, err
	}
	var w wireBundle
	if err := decodeStrict(js, &w); err != nil {
		return platform.AppBundle{}, err
	}
	if w.BundleID != bundleID {
		return platform.AppBundle{}, errors.New("platform: installed app answered for another bundle id")
	}
	return platform.AppBundle{BundleID: w.BundleID, Path: w.Path, Code: w.Code.identity()}, nil
}

// ---- events -----------------------------------------------------------------

func (b *Bridge) OnProcessExit(ref platform.ProcessRef, fn func()) {
	t := addExit(fn)
	C.nz_watch_exit(b.cb, C.int64_t(ref.PID), C.uint64_t(ref.Generation), C.uint64_t(t))
}

func (b *Bridge) OnScreenLock(fn func()) {
	C.nz_watch_screen_lock(b.cb, C.uint64_t(addLock(fn)))
}

func (b *Bridge) ShowWarning(w platform.Warning) {
	js, err := json.Marshal(toWireWarning(w))
	if err != nil {
		return
	}
	j := cin(js)
	defer j.free()
	C.nz_show_warning(b.cb, j.p, j.n)
}

// ---- vault and audit ----------------------------------------------------------

// Vault is platform.Vault over the callbacks table.
type Vault struct{ b *Bridge }

func (v Vault) Get(name string) ([]byte, error) {
	n := cin([]byte(name))
	defer n.free()
	var out C.NzBuf
	st := C.nz_vault_get(v.b.cb, n.p, n.n, &out)
	val, err := v.b.take(out)
	if e := statusErr("vault get", st); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if val == nil {
		val = []byte{}
	}
	return val, nil
}

func (v Vault) Put(name string, value []byte) error {
	n, val := cin([]byte(name)), cin(value)
	defer n.free()
	defer val.free()
	return statusErr("vault put", C.nz_vault_put(v.b.cb, n.p, n.n, val.p, val.n))
}

func (v Vault) Delete(name string) error {
	n := cin([]byte(name))
	defer n.free()
	return statusErr("vault delete", C.nz_vault_delete(v.b.cb, n.p, n.n))
}

func (v Vault) List(prefix string) ([]string, error) {
	p := cin([]byte(prefix))
	defer p.free()
	var out C.NzBuf
	st := C.nz_vault_list(v.b.cb, p.p, p.n, &out)
	js, err := v.b.take(out)
	if e := statusErr("vault list", st); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	var names []string
	if err := decodeStrict(js, &names); err != nil {
		return nil, err
	}
	return names, nil
}

// Sink is audit.Sink over the callbacks table.
type Sink struct{ b *Bridge }

func (s Sink) WriteAudit(t time.Time, line string) error {
	l := cin([]byte(line))
	defer l.free()
	return statusErr("write audit", C.nz_write_audit(s.b.cb, C.int64_t(t.UnixNano()), l.p, l.n))
}
