//go:build darwin && cgo

// Package codesign checks the code signature of a socket peer: the
// nazar CLI uses it as a necessary — but on its own NOT sufficient — gate
// that the process listening on the control socket is Nazar.app before
// sending anything (spec 6; core/control PeerVerifier). The peer is named
// by its audit token (LOCAL_PEERTOKEN), never by PID, so a recycled PID
// can't stand in for it (spike S3).
//
// KNOWN LIMIT (open; a Phase 1 decision where the spec is silent):
// a pass means "the process the token names is Nazar.app", not "the
// process answering me is Nazar.app". Same-user malware can own
// ~/.nazar/run/control.sock (the daemon, not launchd, binds it, and ~/.nazar
// is the user's own 0700 folder), make a genuine Nazar.app process the one
// the token names, and serve forged replies from a process of its own.
// Nothing in Phase 1 closes this, on purpose: the CLI finds
// the Nazar.app it trusts through ~/.local/bin/nazar and
// ~/Library/LaunchAgents/dev.nazar.plist, which that same attacker can
// rewrite, so neither a launchd-owned socket nor an S5 per-connection
// challenge would buy a guarantee against it. The check does refuse every
// wrong peer short of that attacker: another user, a stale or foreign
// daemon at the path, a different build of Nazar.app, a dead peer or a
// recycled PID, a non-bundle test daemon.
//
// Kernel facts the check rests on (XNU bsd/kern/uipc_usrreq.c,
// uipc_socket.c, uipc_socket2.c; pinned by
// TestTokenNamesTheLastTouchingProcessNotTheServicer on macOS 27):
//
//   - LOCAL_PEERTOKEN is the audit token of proc_find(last_pid) of the
//     PEER socket, where last_pid is the process that last did bind,
//     listen, accept, connect, send, recv, poll/select or kevent on it
//     (so_update_last_owner_locked). It is not "the process that created
//     the socket" and not fixed at listen().
//   - A new connection copies last_pid from the LISTENING socket
//     (sonewconn). So a token read right after connect(), before the
//     server has accept()ed, names whoever last touched the listening
//     socket; any process holding that descriptor becomes it by calling
//     listen() again (or by polling it). After the server accept()s and
//     writes, the token names that servicing process instead.
//   - When the named process has exited, getsockopt fails with EINVAL
//     (PeerAuditToken wraps it): a dead owner fails closed, the kernel
//     never falls back to the servicer or to a stale token. The audit
//     token carries the PID version, so a recycled PID fails too.
//
// The CLI reads the token once, before sending, i.e. against the listening
// socket's last toucher. Reading it again after the reply and requiring
// the same token would force the forging process to be a genuine
// Nazar.app image at both reads; that raises the bar but is not a closure
// (by the first fact, any write a genuine binary can be made to do on the
// connection, e.g. through a dup2 onto its stderr, moves last_pid too) and
// is not implemented.
package codesign

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <Security/Security.h>

static int nz_peer_token(int fd, audit_token_t *t) {
	socklen_t n = sizeof *t;
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, t, &n) != 0) return -1;
	return n == sizeof *t ? 0 : -1;
}

// nz_check_peer: is the live process behind token valid code that
// satisfies the requirement text?
static OSStatus nz_check_peer(const audit_token_t *t, const char *req, size_t reqLen) {
	CFStringRef rs = CFStringCreateWithBytes(NULL, (const UInt8 *)req, (CFIndex)reqLen, kCFStringEncodingUTF8, false);
	if (!rs) return errSecParam;
	SecRequirementRef r = NULL;
	OSStatus st = SecRequirementCreateWithString(rs, kSecCSDefaultFlags, &r);
	CFRelease(rs);
	if (st != errSecSuccess) return st;
	CFDataRef tok = CFDataCreate(NULL, (const UInt8 *)t, sizeof *t);
	if (!tok) { CFRelease(r); return errSecAllocate; }
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *vals[] = { tok };
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(tok);
	if (!attrs) { CFRelease(r); return errSecAllocate; }
	SecCodeRef code = NULL;
	st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	if (st == errSecSuccess) {
		st = SecCodeCheckValidity(code, kSecCSDefaultFlags, r);
		CFRelease(code);
	}
	CFRelease(r);
	return st;
}

// nz_designated writes the designated requirement of the code at path
// into a malloc'ed string (*out); the caller frees it.
static OSStatus nz_designated(const char *path, size_t pathLen, char **out) {
	*out = NULL;
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)pathLen, false);
	if (!url) return errSecParam;
	SecStaticCodeRef sc = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &sc);
	CFRelease(url);
	if (st != errSecSuccess) return st;
	SecRequirementRef r = NULL;
	st = SecCodeCopyDesignatedRequirement(sc, kSecCSDefaultFlags, &r);
	CFRelease(sc);
	if (st != errSecSuccess) return st;
	CFStringRef s = NULL;
	st = SecRequirementCopyString(r, kSecCSDefaultFlags, &s);
	CFRelease(r);
	if (st != errSecSuccess) return st;
	CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	*out = malloc((size_t)max);
	if (!*out || !CFStringGetCString(s, *out, max, kCFStringEncodingUTF8)) { free(*out); *out = NULL; st = errSecParam; }
	CFRelease(s);
	return st;
}

// nz_team_of writes the team identifier of sc into a malloc'ed string
// (*out), or leaves *out NULL when the code has none (signed ad hoc).
static OSStatus nz_team_of(SecStaticCodeRef sc, char **out) {
	*out = NULL;
	CFDictionaryRef info = NULL;
	OSStatus st = SecCodeCopySigningInformation(sc, kSecCSSigningInformation, &info);
	if (st != errSecSuccess) return st;
	CFTypeRef team = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
	if (team && CFGetTypeID(team) == CFStringGetTypeID()) {
		CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength((CFStringRef)team), kCFStringEncodingUTF8) + 1;
		*out = malloc((size_t)max);
		if (!*out || !CFStringGetCString((CFStringRef)team, *out, max, kCFStringEncodingUTF8)) { free(*out); *out = NULL; st = errSecParam; }
	}
	CFRelease(info);
	return st;
}

// nz_self_team: the team of this process's own code, after checking that
// the running code is valid.
static OSStatus nz_self_team(char **out) {
	*out = NULL;
	SecCodeRef self = NULL;
	OSStatus st = SecCodeCopySelf(kSecCSDefaultFlags, &self);
	if (st != errSecSuccess) return st;
	st = SecCodeCheckValidity(self, kSecCSDefaultFlags, NULL);
	SecStaticCodeRef sc = NULL;
	if (st == errSecSuccess) st = SecCodeCopyStaticCode(self, kSecCSDefaultFlags, &sc);
	CFRelease(self);
	if (st != errSecSuccess) return st;
	st = nz_team_of(sc, out);
	CFRelease(sc);
	return st;
}

// nz_path_team: the team of the code at path, after checking its
// signature on disk.
static OSStatus nz_path_team(const char *path, size_t pathLen, char **out) {
	*out = NULL;
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)pathLen, false);
	if (!url) return errSecParam;
	SecStaticCodeRef sc = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &sc);
	CFRelease(url);
	if (st != errSecSuccess) return st;
	st = SecStaticCodeCheckValidity(sc, kSecCSDefaultFlags, NULL);
	if (st == errSecSuccess) st = nz_team_of(sc, out);
	CFRelease(sc);
	return st;
}

// nz_parse_requirement: is req valid requirement-language text?
static OSStatus nz_parse_requirement(const char *req, size_t reqLen) {
	CFStringRef rs = CFStringCreateWithBytes(NULL, (const UInt8 *)req, (CFIndex)reqLen, kCFStringEncodingUTF8, false);
	if (!rs) return errSecParam;
	SecRequirementRef r = NULL;
	OSStatus st = SecRequirementCreateWithString(rs, kSecCSDefaultFlags, &r);
	CFRelease(rs);
	if (r) CFRelease(r);
	return st;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// AuditToken is a peer's audit_token_t.
type AuditToken [8]uint32

// PID is the token's process ID (for messages only; never an identity).
func (t AuditToken) PID() int { return int(t[5]) }

// PeerAuditToken reads the audit token the kernel recorded for the peer of
// a connected Unix socket. For the client end of a listening socket the
// peer is the socket's listen-owner (see the package doc); when that
// process has exited the kernel answers EINVAL, and the error wraps
// syscall.EINVAL so callers can tell a dead owner from a bad descriptor
// (EBADF, ENOTSOCK). It never guesses a token.
func PeerAuditToken(fd int) (AuditToken, error) {
	var t C.audit_token_t
	if rc, errno := C.nz_peer_token(C.int(fd), &t); rc != 0 {
		if errno == nil {
			return AuditToken{}, errors.New("codesign: no peer audit token: short token")
		}
		if errno == syscall.EINVAL {
			return AuditToken{}, fmt.Errorf("codesign: no peer audit token: %w (no live listen-owner: the process that listen()ed on the socket has exited, or the descriptor is not a connected stream)", errno)
		}
		return AuditToken{}, fmt.Errorf("codesign: no peer audit token: %w", errno)
	}
	var out AuditToken
	for i := range out {
		out[i] = uint32(t.val[i])
	}
	return out, nil
}

// DesignatedRequirement returns the designated requirement of the code at
// path (an app bundle or a binary), in requirement-language text. For an
// ad-hoc signed bundle it is its exact code hash (`cdhash H"…"`), so every
// rebuild is a different app; for a certificate-signed one it names the
// identifier and the signing certificate, so it survives rebuilds.
func DesignatedRequirement(path string) (string, error) {
	if path == "" {
		return "", errors.New("codesign: empty path")
	}
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var out *C.char
	if st := C.nz_designated(p, C.size_t(len(path)), &out); st != C.errSecSuccess {
		return "", fmt.Errorf("codesign: no designated requirement for %s (OSStatus %d)", path, int32(st))
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoString(out), nil
}

// CheckPeer succeeds only when the process named by tok is still alive and
// is valid code satisfying requirement.
func CheckPeer(tok AuditToken, requirement string) error {
	var t C.audit_token_t
	for i := range tok {
		t.val[i] = C.uint(tok[i])
	}
	r := C.CString(requirement)
	defer C.free(unsafe.Pointer(r))
	if st := C.nz_check_peer(&t, r, C.size_t(len(requirement))); st != C.errSecSuccess {
		return fmt.Errorf("codesign: peer (pid %d) does not satisfy %q (OSStatus %d)", tok.PID(), requirement, int32(st))
	}
	return nil
}

// SelfTeamID returns the team identifier of this process's own code
// signature (the Apple-issued certificate's team), after checking that the
// running code is valid; "" when it is signed ad hoc (no certificate, so no
// team: every development build). An error means the signature could not
// be read or is not valid, and callers trust nothing then.
func SelfTeamID() (string, error) {
	var out *C.char
	if st := C.nz_self_team(&out); st != C.errSecSuccess {
		return "", fmt.Errorf("codesign: this program's own signature (OSStatus %d)", int32(st))
	}
	if out == nil {
		return "", nil
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoString(out), nil
}

// TeamID is SelfTeamID for the code at path (an app bundle or a binary),
// after checking its signature on disk.
func TeamID(path string) (string, error) {
	if path == "" {
		return "", errors.New("codesign: empty path")
	}
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var out *C.char
	if st := C.nz_path_team(p, C.size_t(len(path)), &out); st != C.errSecSuccess {
		return "", fmt.Errorf("codesign: no valid signature for %s (OSStatus %d)", path, int32(st))
	}
	if out == nil {
		return "", nil
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoString(out), nil
}

// ParseRequirement checks that requirement is valid requirement-language
// text (SecRequirementCreateWithString).
func ParseRequirement(requirement string) error {
	r := C.CString(requirement)
	defer C.free(unsafe.Pointer(r))
	if st := C.nz_parse_requirement(r, C.size_t(len(requirement))); st != C.errSecSuccess {
		return fmt.Errorf("codesign: invalid requirement %q (OSStatus %d)", requirement, int32(st))
	}
	return nil
}
