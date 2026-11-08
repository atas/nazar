package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef int (*sign_fn)(const uint8_t* data, size_t len, uint8_t** out, size_t* out_len);
typedef void (*free_fn)(uint8_t* p);

typedef struct {
    sign_fn sign;
    free_fn free_buf;
} Callbacks;

static int call_sign(Callbacks* cb, const uint8_t* data, size_t len, uint8_t** out, size_t* out_len) {
    return cb->sign(data, len, out, out_len);
}
static void call_free(Callbacks* cb, uint8_t* p) { cb->free_buf(p); }
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"
)

var (
	cbs *C.Callbacks // C memory owned by Swift; kept for the process lifetime
	pub *ecdsa.PublicKey

	// Boundary audit: how many Swift-owned buffers Go received and how many it handed back.
	signOK    atomic.Int64
	freeCalls atomic.Int64
)

//export CoreStart
func CoreStart(cb *C.Callbacks, pubX963 *C.uint8_t, pubLen C.size_t) C.int {
	raw := C.GoBytes(unsafe.Pointer(pubX963), C.int(pubLen))
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil {
		return 1
	}
	cbs = cb
	pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return 0
}

// CoreRunSignTest starts n goroutines that each ask Swift to sign a distinct message and
// verifies every signature. It returns the number of failures. It blocks, so Swift must call
// it off the main thread.
//
// Negative control for the boundary audit: with S11_SKIP_FREE set, Go keeps the signature but
// never hands the Swift-malloc'd buffer back (the "Go forgets call_free" boundary bug).
//
//export CoreRunSignTest
func CoreRunSignTest(n C.int) C.int {
	skipFree := os.Getenv("S11_SKIP_FREE") != ""
	var wg sync.WaitGroup
	var fails atomic.Int32
	for i := 0; i < int(n); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("s11 message %d", i))
			cmsg := C.CBytes(msg)
			defer C.free(cmsg)
			var out *C.uint8_t
			var outLen C.size_t
			if rc := C.call_sign(cbs, (*C.uint8_t)(cmsg), C.size_t(len(msg)), &out, &outLen); rc != 0 {
				fails.Add(1)
				return
			}
			signOK.Add(1)
			sig := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
			if !skipFree {
				freeCalls.Add(1)
				C.call_free(cbs, out)
			}
			digest := sha256.Sum256(msg)
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				fails.Add(1)
			}
		}(i)
	}
	wg.Wait()
	return C.int(fails.Load())
}

// CoreCallCounts reports how many sign callbacks returned a buffer and how many of those
// buffers Go handed back through free_buf.
//
//export CoreCallCounts
func CoreCallCounts(signs *C.int64_t, frees *C.int64_t) {
	*signs = C.int64_t(signOK.Load())
	*frees = C.int64_t(freeCalls.Load())
}

func main() {}
