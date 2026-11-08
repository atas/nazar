// Package cfake is a NazarCallbacks table implemented in C and Go over any
// platform.Platform, platform.Vault and audit.Sink (in tests: the fake). It
// lets the whole conformance suite, and the ownership rules of the C ABI,
// run through cbridge with `go test`, without Swift. Every buffer it hands
// out is recorded; Live and BadFrees prove each one came back exactly once.
// Test-only: no shipped binary imports it.
package cfake

/*
#cgo CFLAGS: -I${SRCDIR}/../../../macos/Sources/CNazarBridge/include
#include <stdlib.h>
#include "nazar_bridge.h"
extern NazarCallbacks *cfake_table(void);
extern NazarCallbacks *cfake_bad_table(int wrong_version);
extern NazarCallbacks *cfake_noexec_table(int partial);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
)

var state struct {
	mu     sync.Mutex
	p      platform.Platform
	v      platform.Vault
	s      audit.Sink
	live   map[uintptr]bool
	allocs int
	bad    int
	// Corrupt, when set, makes the next output buffer of op (e.g. "process")
	// the given bytes instead of the real answer (tests of Go's decoding).
	corrupt map[string][]byte
	// cancels holds the exec watches' cancels by token.
	cancels map[uint64]func()
}

// Install routes the table to p, v and s and returns the table (a
// *NazarCallbacks for cbridge.New). It resets the allocation counters.
func Install(p platform.Platform, v platform.Vault, s audit.Sink) unsafe.Pointer {
	state.mu.Lock()
	state.p, state.v, state.s = p, v, s
	state.live = map[uintptr]bool{}
	state.allocs, state.bad = 0, 0
	state.corrupt = map[string][]byte{}
	state.cancels = map[uint64]func(){}
	state.mu.Unlock()
	return unsafe.Pointer(C.cfake_table())
}

// Corrupt makes the next successful answer of op carry raw instead.
func Corrupt(op string, raw []byte) {
	state.mu.Lock()
	state.corrupt[op] = raw
	state.mu.Unlock()
}

// Live is the number of buffers handed out and not yet freed.
func Live() int { state.mu.Lock(); defer state.mu.Unlock(); return len(state.live) }

// Allocations is the number of buffers handed out since Install.
func Allocations() int { state.mu.Lock(); defer state.mu.Unlock(); return state.allocs }

// BadFrees counts free_buf calls with a pointer that was not live.
func BadFrees() int { state.mu.Lock(); defer state.mu.Unlock(); return state.bad }

func cur() (platform.Platform, platform.Vault, audit.Sink) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.p, state.v, state.s
}

// takeCorrupt returns and forgets the bytes Corrupt set for op.
func takeCorrupt(op string) ([]byte, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	raw, ok := state.corrupt[op]
	delete(state.corrupt, op)
	return raw, ok
}

func put(op string, buf *C.NzBuf, b []byte) {
	if raw, ok := takeCorrupt(op); ok {
		b = raw
	}
	state.mu.Lock()
	n := len(b)
	if n == 0 {
		n = 1
	}
	p := C.malloc(C.size_t(n))
	if len(b) > 0 {
		copy(unsafe.Slice((*byte)(p), len(b)), b)
	}
	state.live[uintptr(p)] = true
	state.allocs++
	state.mu.Unlock()
	buf.ptr = (*C.uint8_t)(p)
	buf.len = C.size_t(len(b))
}

func clear(bs ...*C.NzBuf) {
	for _, b := range bs {
		if b != nil {
			b.ptr, b.len = nil, 0
		}
	}
}

func bytesOf(p *C.uint8_t, n C.size_t) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n))
}

func status(err error) C.int32_t {
	switch {
	case err == nil:
		return C.NZ_OK
	case errors.Is(err, platform.ErrNotFound):
		return C.NZ_NOT_FOUND
	case errors.Is(err, platform.ErrNoProcess):
		return C.NZ_NO_PROCESS
	case errors.Is(err, platform.ErrDenied):
		return C.NZ_DENIED
	case errors.Is(err, platform.ErrAuthRequired):
		return C.NZ_AUTH_REQUIRED
	case errors.Is(err, platform.ErrAmbiguous):
		return C.NZ_AMBIGUOUS
	case errors.Is(err, platform.ErrUnreadable):
		return C.NZ_UNREADABLE
	case errors.Is(err, platform.ErrLocked):
		return C.NZ_LOCKED
	}
	return C.NZ_ERR
}

//export cfakeCreateKey
func cfakeCreateKey(purpose, auth, access C.int32_t, h, pub *C.NzBuf) C.int32_t {
	clear(h, pub)
	p, _, _ := cur()
	handle, pk, err := p.CreateKey(platform.Purpose(purpose), platform.AuthPolicy(auth), platform.Access(access))
	if err != nil {
		return status(err)
	}
	put("create_key", h, handle)
	put("create_key.pub", pub, pk)
	return C.NZ_OK
}

//export cfakeSign
func cfakeSign(hp *C.uint8_t, hn C.size_t, dp *C.uint8_t, dn C.size_t, ref C.uint64_t, out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	sig, err := p.Sign(bytesOf(hp, hn), bytesOf(dp, dn), platform.ApprovalRef(ref))
	if err != nil {
		return status(err)
	}
	put("sign", out, sig)
	return C.NZ_OK
}

//export cfakeKeyAgreement
func cfakeKeyAgreement(hp *C.uint8_t, hn C.size_t, pp *C.uint8_t, pn C.size_t, ref C.uint64_t, out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	sec, err := p.KeyAgreement(bytesOf(hp, hn), bytesOf(pp, pn), platform.ApprovalRef(ref))
	if err != nil {
		return status(err)
	}
	put("key_agreement", out, sec)
	return C.NZ_OK
}

//export cfakeDeleteKey
func cfakeDeleteKey(hp *C.uint8_t, hn C.size_t) C.int32_t {
	p, _, _ := cur()
	return status(p.DeleteKey(bytesOf(hp, hn)))
}

func prompt(jp *C.uint8_t, jn C.size_t) (platform.Prompt, bool) {
	var w struct {
		Title         string   `json:"title"`
		Lines         []string `json:"lines"`
		Unknown       bool     `json:"unknown"`
		Reason        string   `json:"reason"`
		TimeoutMillis int64    `json:"timeoutMillis"`
	}
	if json.Unmarshal(bytesOf(jp, jn), &w) != nil || w.Lines == nil {
		return platform.Prompt{}, false // Swift's decoder needs every field, lines included
	}
	return platform.Prompt{Title: w.Title, Lines: w.Lines, Unknown: w.Unknown, Reason: w.Reason,
		Timeout: time.Duration(w.TimeoutMillis) * time.Millisecond}, true
}

//export cfakeAuthenticate
func cfakeAuthenticate(policy C.int32_t, jp *C.uint8_t, jn C.size_t, ref *C.uint64_t) C.int32_t {
	*ref = 0
	pr, ok := prompt(jp, jn)
	if !ok {
		return C.NZ_INVALID
	}
	p, _, _ := cur()
	r, err := p.Authenticate(platform.AuthPolicy(policy), pr)
	if err != nil {
		return status(err)
	}
	*ref = C.uint64_t(r)
	return C.NZ_OK
}

//export cfakeConfirm
func cfakeConfirm(jp *C.uint8_t, jn C.size_t, allowed *C.int32_t) C.int32_t {
	*allowed = 0
	pr, ok := prompt(jp, jn)
	if !ok {
		return C.NZ_INVALID
	}
	p, _, _ := cur()
	yes, err := p.Confirm(pr)
	var how platform.DialogDenied
	switch {
	case !yes && errors.As(err, &how):
		// How it was denied (nazar_bridge.h): only 2 to 5 cross; a way
		// outside them (1 would read as Allow) is written as 0, a plain
		// denial. The value is 0 already.
		if how.How >= platform.DialogDenyButton && how.How <= platform.DialogClosed {
			*allowed = C.int32_t(how.How)
		}
		return C.NZ_OK
	case err != nil:
		return status(err)
	case yes:
		*allowed = 1
	}
	return C.NZ_OK
}

//export cfakeReleaseApproval
func cfakeReleaseApproval(ref C.uint64_t) {
	p, _, _ := cur()
	p.ReleaseApproval(platform.ApprovalRef(ref))
}

//export cfakePeerOf
func cfakePeerOf(fd C.int32_t, pid *C.int64_t, gen *C.uint64_t) C.int32_t {
	*pid, *gen = 0, 0
	p, _, _ := cur()
	r, err := p.PeerOf(int(fd))
	if err != nil {
		return status(err)
	}
	*pid, *gen = C.int64_t(r.PID), C.uint64_t(r.Generation)
	return C.NZ_OK
}

type wcode struct {
	Signed    bool   `json:"signed"`
	TeamID    string `json:"teamId"`
	SigningID string `json:"signingId"`
	Apple     bool   `json:"apple"`
	AdHoc     bool   `json:"adHoc"`
	CDHash    []byte `json:"cdhash"`
}

type wproc struct {
	PID              int      `json:"pid"`
	Generation       uint64   `json:"generation"`
	ParentPID        int      `json:"parentPid"`
	ParentGeneration uint64   `json:"parentGeneration"`
	UID              int      `json:"uid"`
	StartMicros      int64    `json:"startMicros"`
	Path             string   `json:"path"`
	Args             []string `json:"args"`
	Cwd              string   `json:"cwd"`
	Code             wcode    `json:"code"`
	Comm             string   `json:"comm"`
}

func code(c platform.CodeIdentity) wcode {
	return wcode{c.Signed, c.TeamID, c.SigningID, c.Apple, c.AdHoc, append([]byte{}, c.CDHash...)}
}

func (c wcode) identity() platform.CodeIdentity {
	return platform.CodeIdentity{Signed: c.Signed, TeamID: c.TeamID, SigningID: c.SigningID, Apple: c.Apple, AdHoc: c.AdHoc, CDHash: c.CDHash}
}

//export cfakeProcess
func cfakeProcess(pid C.int64_t, gen C.uint64_t, out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	info, err := p.Process(platform.ProcessRef{PID: int(pid), Generation: uint64(gen)})
	if err != nil {
		return status(err)
	}
	put("process", out, wireOf(info))
	return C.NZ_OK
}

// wireOf is the process record's JSON, as Swift's ProcessRecord encodes.
func wireOf(info platform.ProcessInfo) []byte {
	args := info.Args
	if args == nil {
		args = []string{}
	}
	js, _ := json.Marshal(wproc{info.Ref.PID, info.Ref.Generation, info.Parent.PID, info.Parent.Generation, info.UID,
		info.StartTime.UnixMicro(), info.Path, args, info.Cwd, code(info.Code), info.Comm})
	return js
}

//export cfakeAppFor
func cfakeAppFor(jp *C.uint8_t, jn C.size_t, out *C.NzBuf) C.int32_t {
	clear(out)
	var ws []wproc
	if json.Unmarshal(bytesOf(jp, jn), &ws) != nil {
		return C.NZ_INVALID
	}
	chain := make([]platform.ProcessInfo, len(ws))
	for i, w := range ws {
		chain[i] = platform.ProcessInfo{Ref: platform.ProcessRef{PID: w.PID, Generation: w.Generation},
			Parent: platform.ProcessRef{PID: w.ParentPID, Generation: w.ParentGeneration}, UID: w.UID,
			StartTime: time.UnixMicro(w.StartMicros), Path: w.Path, Args: w.Args, Cwd: w.Cwd, Code: w.Code.identity(), Comm: w.Comm}
	}
	p, _, _ := cur()
	app, ok := p.AppFor(chain)
	if !ok {
		return C.NZ_NOT_FOUND
	}
	js, _ := json.Marshal(wapp{app.Ref.PID, app.Ref.Generation, app.BundleID, app.Name, code(app.Code)})
	put("app_for", out, js)
	return C.NZ_OK
}

// wapp is an app record on the wire (cbridge's wireApp).
type wapp struct {
	PID        int    `json:"pid"`
	Generation uint64 `json:"generation"`
	BundleID   string `json:"bundleId"`
	Name       string `json:"name"`
	Code       wcode  `json:"code"`
}

//export cfakeApps
func cfakeApps(out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	apps := p.Apps()
	ws := make([]wapp, 0, len(apps))
	for _, a := range apps {
		ws = append(ws, wapp{a.Ref.PID, a.Ref.Generation, a.BundleID, a.Name, code(a.Code)})
	}
	js, _ := json.Marshal(ws)
	put("apps", out, js)
	return C.NZ_OK
}

//export cfakeCodeHash
func cfakeCodeHash(pp *C.uint8_t, pn C.size_t, out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	h, err := p.CodeHash(string(bytesOf(pp, pn)))
	if err != nil {
		return status(err)
	}
	put("code_hash", out, h)
	return C.NZ_OK
}

//export cfakeResponsibleFor
func cfakeResponsibleFor(pid C.int64_t, gen C.uint64_t, r *C.int64_t) C.int32_t {
	*r = 0
	p, _, _ := cur()
	ref, ok := p.ResponsibleFor(platform.ProcessRef{PID: int(pid), Generation: uint64(gen)})
	if !ok {
		return C.NZ_NOT_FOUND
	}
	*r = C.int64_t(ref.PID)
	return C.NZ_OK
}

//export cfakeInstalledApp
func cfakeInstalledApp(bp *C.uint8_t, bn C.size_t, out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	b, err := p.InstalledApp(string(bytesOf(bp, bn)))
	if err != nil {
		return status(err)
	}
	js, _ := json.Marshal(struct {
		BundleID string `json:"bundleId"`
		Path     string `json:"path"`
		Code     wcode  `json:"code"`
	}{b.BundleID, b.Path, code(b.Code)})
	put("installed_app", out, js)
	return C.NZ_OK
}

//export cfakeWatchExit
func cfakeWatchExit(pid C.int64_t, gen C.uint64_t, token C.uint64_t) {
	p, _, _ := cur()
	t := uint64(token)
	p.OnProcessExit(platform.ProcessRef{PID: int(pid), Generation: uint64(gen)}, func() { cbridge.ProcessExited(t) })
}

//export cfakeWatchScreenLock
func cfakeWatchScreenLock(token C.uint64_t) {
	p, _, _ := cur()
	t := uint64(token)
	p.OnScreenLock(func() { cbridge.ScreenLocked(t) })
}

//export cfakeShowWarning
func cfakeShowWarning(jp *C.uint8_t, jn C.size_t) {
	var w struct {
		ID            string   `json:"id"`
		Title         string   `json:"title"`
		Lines         []string `json:"lines"`
		Count         int      `json:"count"`
		SuggestedRule string   `json:"suggestedRule"`
	}
	if json.Unmarshal(bytesOf(jp, jn), &w) != nil {
		return
	}
	p, _, _ := cur()
	p.ShowWarning(platform.Warning{ID: w.ID, Title: w.Title, Lines: w.Lines, Count: w.Count, SuggestedRule: w.SuggestedRule})
}

// The exec callbacks: through the platform's platform.Exec (NZ_ERR
// when it has none). Each exec reaches Go as Swift's would: the record's
// JSON through cbridge.ProcessExecd (Corrupt("exec", …) replaces one).

//export cfakeWatchExec
func cfakeWatchExec(pid C.int64_t, gen C.uint64_t, token C.uint64_t) C.int32_t {
	p, _, _ := cur()
	x, ok := p.(platform.Exec)
	if !ok {
		return C.NZ_ERR
	}
	t := uint64(token)
	cancel, err := x.OnProcessExec(platform.ProcessRef{PID: int(pid), Generation: uint64(gen)}, func(info platform.ProcessInfo) {
		js := wireOf(info)
		if raw, ok := takeCorrupt("exec"); ok {
			js = raw
		}
		cbridge.ProcessExecd(t, js)
	})
	if err != nil {
		return status(err)
	}
	state.mu.Lock()
	state.cancels[t] = cancel
	state.mu.Unlock()
	return C.NZ_OK
}

//export cfakeCancelExec
func cfakeCancelExec(token C.uint64_t) {
	state.mu.Lock()
	cancel := state.cancels[uint64(token)]
	delete(state.cancels, uint64(token))
	state.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

//export cfakeEnvironment
func cfakeEnvironment(pid C.int64_t, gen C.uint64_t, out *C.NzBuf) C.int32_t {
	clear(out)
	p, _, _ := cur()
	x, ok := p.(platform.Exec)
	if !ok || out == nil {
		return C.NZ_ERR
	}
	env, err := x.Environment(platform.ProcessRef{PID: int(pid), Generation: uint64(gen)})
	if err != nil {
		return status(err)
	}
	js, _ := json.Marshal(env)
	put("environment", out, js)
	return C.NZ_OK
}

//export cfakeVaultGet
func cfakeVaultGet(np *C.uint8_t, nn C.size_t, out *C.NzBuf) C.int32_t {
	clear(out)
	_, v, _ := cur()
	val, err := v.Get(string(bytesOf(np, nn)))
	if err != nil {
		return status(err)
	}
	put("vault_get", out, val)
	return C.NZ_OK
}

//export cfakeVaultPut
func cfakeVaultPut(np *C.uint8_t, nn C.size_t, vp *C.uint8_t, vn C.size_t) C.int32_t {
	_, v, _ := cur()
	return status(v.Put(string(bytesOf(np, nn)), bytesOf(vp, vn)))
}

//export cfakeVaultDelete
func cfakeVaultDelete(np *C.uint8_t, nn C.size_t) C.int32_t {
	_, v, _ := cur()
	return status(v.Delete(string(bytesOf(np, nn))))
}

//export cfakeVaultList
func cfakeVaultList(pp *C.uint8_t, pn C.size_t, out *C.NzBuf) C.int32_t {
	clear(out)
	_, v, _ := cur()
	names, err := v.List(string(bytesOf(pp, pn)))
	if err != nil {
		return status(err)
	}
	if names == nil {
		names = []string{}
	}
	js, _ := json.Marshal(names)
	put("vault_list", out, js)
	return C.NZ_OK
}

//export cfakeWriteAudit
func cfakeWriteAudit(nanos C.int64_t, lp *C.uint8_t, ln C.size_t) C.int32_t {
	_, _, s := cur()
	return status(s.WriteAudit(time.Unix(0, int64(nanos)), string(bytesOf(lp, ln))))
}

//export cfakeFreeBuf
func cfakeFreeBuf(p *C.uint8_t) {
	if p == nil {
		return
	}
	state.mu.Lock()
	ok := state.live[uintptr(unsafe.Pointer(p))]
	if ok {
		delete(state.live, uintptr(unsafe.Pointer(p)))
	} else {
		state.bad++
	}
	state.mu.Unlock()
	if ok {
		C.free(unsafe.Pointer(p))
	}
}

// BadTable returns a copy of the table with the wrong ABI version
// (wrongVersion) or with one NULL function, and the function that frees it.
func BadTable(wrongVersion bool) (unsafe.Pointer, func()) {
	v := C.int(0)
	if wrongVersion {
		v = 1
	}
	p := C.cfake_bad_table(v)
	return unsafe.Pointer(p), func() { C.free(unsafe.Pointer(p)) }
}

// NoExecTable returns a copy of the table without the exec callbacks
// (partial: only environment missing), and the function that frees it.
func NoExecTable(partial bool) (unsafe.Pointer, func()) {
	v := C.int(0)
	if partial {
		v = 1
	}
	p := C.cfake_noexec_table(v)
	return unsafe.Pointer(p), func() { C.free(unsafe.Pointer(p)) }
}
