//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <stdlib.h>
#include <CoreServices/CoreServices.h>

// nz_app_for_bundle_id writes the path of the app Launch Services prefers
// for bundle id id into *out (malloc'ed; the caller frees it), or leaves
// *out NULL when it knows none. A lookup only: nothing is opened.
static int nz_app_for_bundle_id(const char *id, char **out) {
	*out = NULL;
	CFStringRef s = CFStringCreateWithCString(NULL, id, kCFStringEncodingUTF8);
	if (!s) return -1;
	CFArrayRef urls = LSCopyApplicationURLsForBundleIdentifier(s, NULL);
	CFRelease(s);
	if (!urls) return 0;
	int rc = 0;
	if (CFArrayGetCount(urls) > 0) {
		CFURLRef u = (CFURLRef)CFArrayGetValueAtIndex(urls, 0);
		char buf[4096];
		if (CFURLGetFileSystemRepresentation(u, true, (UInt8 *)buf, sizeof buf)) {
			*out = strdup(buf);
			if (!*out) rc = -1;
		} else {
			rc = -1;
		}
	}
	CFRelease(urls);
	return rc;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"
)

// appForBundleID asks Launch Services which app it would open for id. It
// opens nothing.
func appForBundleID(id string) (string, error) {
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	var out *C.char
	if C.nz_app_for_bundle_id(cid, &out) != 0 {
		return "", errors.New("Launch Services lookup failed")
	}
	if out == nil {
		return "", errUINotInstalled
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoString(out), nil
}

// openUIApp is the app's openUI seam: it looks id up in Launch Services
// and, when an app is registered, opens it by bundle id with /usr/bin/open
// (absolute path, never $PATH). It returns the app Launch Services named.
func openUIApp(id string) (string, error) {
	path, err := appForBundleID(id)
	if err != nil {
		return "", err
	}
	if out, err := exec.Command("/usr/bin/open", "-b", id).CombinedOutput(); err != nil {
		return "", fmt.Errorf("/usr/bin/open -b %s: %v: %s", id, err, strings.TrimSpace(string(out)))
	}
	return path, nil
}
