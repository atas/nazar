//go:build darwin

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../macos/Sources/CNazarBridge/include
#include "nazar_host_hooks.h"
static void nz_answer(const NazarHostHooks *h, int32_t a) { h->answer(a); }
static int64_t nz_live(const NazarHostHooks *h) { return h->live_buffers(); }
static int64_t nz_bad(const NazarHostHooks *h) { return h->bad_frees(); }
*/
import "C"

import "unsafe"

// hostHooks wraps the host's NazarHostHooks (C memory owned by Swift for
// the whole run).
type hostHooks struct{ h *C.NazarHostHooks }

func newHooks(p unsafe.Pointer) hostHooks { return hostHooks{(*C.NazarHostHooks)(p)} }

func (h hostHooks) answer(allow bool) {
	a := C.int32_t(0)
	if allow {
		a = 1
	}
	C.nz_answer(h.h, a)
}

func (h hostHooks) liveBuffers() int64 { return int64(C.nz_live(h.h)) }
func (h hostHooks) badFrees() int64    { return int64(C.nz_bad(h.h)) }
