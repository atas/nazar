/*
 * nazar_bridge.h — the C ABI between Nazar.app (Swift) and the Go core
 * (spec 4.7, spike S11). This header is the single source of truth: Go's
 * cgo preamble includes it (bridge/, -I macos/Sources/CNazarBridge/include)
 * and Swift imports it through the CNazarBridge module.
 *
 * Direction: Swift hands Go a NazarCallbacks table (NazarCoreStart). Go
 * calls a function pointer for every Platform, Vault and audit.Sink method.
 * Exit and screen-lock events come back by Swift calling the Go exports
 * NazarProcessExited(token) / NazarScreenLocked(token). Exec events come
 * back by Swift calling the Go export NazarProcessExecd(token, record_json,
 * len) (M10). Nothing else crosses: the agent has no window (Milestone 6).
 *
 * Ownership (spec 4.7 "the side that allocates memory frees it"):
 *   - Inputs (const pointers) are owned by the caller and valid only for
 *     the duration of the call. The callee copies what it keeps.
 *   - Outputs are NzBuf values the callee fills with malloc'ed memory. The
 *     caller copies the bytes and then calls free_buf(ptr) exactly once for
 *     every non-NULL ptr, whatever the status. The callee sets ptr = NULL,
 *     len = 0 on every path that returns no data.
 *   - No pointer is retained by the other side after a call returns.
 *   - Strings are UTF-8 bytes plus a length, never NUL-terminated.
 *   - Structured values (ProcessInfo, AppInfo, AppBundle, Prompt, Warning,
 *     name lists) cross as UTF-8 JSON documents whose field names are part
 *     of the ABI: macos/Sources/NazarPlatform/Wire.swift and
 *     bridge/cbridge/wire.go spell them, and the golden strings of
 *     WireTests.swift and wire_test.go hold both sides to the same bytes.
 *     Every field is always present (Swift's decoder requires them, so Go
 *     never sends null for a list); byte fields are base64. Go decodes them
 *     strictly (unknown fields and trailing data refused, at most 4 MiB).
 *
 * Threading: every callback may be called from any thread, concurrently.
 * Blocking callbacks (authenticate, confirm) block only the calling thread;
 * Swift does its UI work on the main thread.
 */
#ifndef NAZAR_BRIDGE_H
#define NAZAR_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#define NAZAR_ABI_VERSION 4u

/* Status codes. Part of the ABI; never renumber. */
enum {
    NZ_OK = 0,
    NZ_ERR = 1,           /* anything else (logged on the Swift side) */
    NZ_NOT_FOUND = 2,     /* platform.ErrNotFound */
    NZ_NO_PROCESS = 3,    /* platform.ErrNoProcess */
    NZ_DENIED = 4,        /* platform.ErrDenied */
    NZ_AUTH_REQUIRED = 5, /* platform.ErrAuthRequired */
    NZ_AMBIGUOUS = 6,     /* platform.ErrAmbiguous */
    NZ_INVALID = 7,       /* refused input: out-of-range purpose/policy, bad name */
    NZ_UNREADABLE = 8,    /* platform.ErrUnreadable */
    NZ_LOCKED = 9         /* platform.ErrLocked: a when-unlocked key, used while the Mac is locked */
};

typedef struct NzBuf {
    uint8_t *ptr;
    size_t len;
} NzBuf;

typedef struct NazarCallbacks {
    uint32_t abi_version; /* must be NAZAR_ABI_VERSION */

    /* Keys (platform.Platform). */
    /* access: platform.Access (0 when unlocked, 1 after first unlock). */
    int32_t (*create_key)(int32_t purpose, int32_t auth, int32_t access, NzBuf *handle, NzBuf *public_key);
    int32_t (*sign)(const uint8_t *handle, size_t handle_len, const uint8_t *data, size_t data_len,
                    uint64_t approval, NzBuf *signature);
    int32_t (*key_agreement)(const uint8_t *handle, size_t handle_len, const uint8_t *peer, size_t peer_len,
                             uint64_t approval, NzBuf *secret);
    int32_t (*delete_key)(const uint8_t *handle, size_t handle_len);

    /* Approvals. */
    int32_t (*authenticate)(int32_t policy, const uint8_t *prompt_json, size_t prompt_len, uint64_t *approval);
    /* *allowed: 1 = Allow; 0 = denied, no reason given; how it was denied
       (Milestone 5, platform.DialogHow): 2 = the Deny button, 3 = Esc,
       4 = the dialog's countdown ran out, 5 = closed without an answer.
       Only 1 allows; any other value is a denial. */
    int32_t (*confirm)(const uint8_t *prompt_json, size_t prompt_len, int32_t *allowed);
    void (*release_approval)(uint64_t approval);

    /* Callers. */
    int32_t (*peer_of)(int32_t fd, int64_t *pid, uint64_t *generation);
    int32_t (*process)(int64_t pid, uint64_t generation, NzBuf *info_json);
    int32_t (*app_for)(const uint8_t *chain_json, size_t chain_len, NzBuf *app_json); /* NZ_NOT_FOUND: no app */
    int32_t (*code_hash)(const uint8_t *path, size_t path_len, NzBuf *cdhash);
    int32_t (*responsible_for)(int64_t pid, uint64_t generation, int64_t *responsible_pid); /* NZ_NOT_FOUND: unknown */
    int32_t (*installed_app)(const uint8_t *bundle_id, size_t bundle_id_len, NzBuf *bundle_json);
    int32_t (*apps)(NzBuf *apps_json); /* the running GUI apps, a JSON array of app records ([] when none); Milestone 7 */

    /* Events. Swift later calls NazarProcessExited(token) exactly once, or
       NazarScreenLocked(token) on every lock. Both return at once. */
    void (*watch_exit)(int64_t pid, uint64_t generation, uint64_t token);
    void (*watch_screen_lock)(uint64_t token);
    void (*show_warning)(const uint8_t *warning_json, size_t warning_len);

    /* platform.Exec (M10; optional: a table without all three leaves
       late-env off, secrets design 6.3 D8). watch_exec arms an exec watch
       on the live instance (pid, generation): NZ_NO_PROCESS when that
       instance is not the PID's live occupant. Swift then calls Go's
       NazarProcessExecd(token, record_json, len) on every exec of it, with
       the process record read in its event handler, until
       cancel_exec(token) returns or the process exits. environment answers
       the startup environment read at the last exec a watch saw, a JSON
       array of strings: NZ_UNREADABLE when the kernel hid it, it could not
       be read, or no watched exec was seen; NZ_NO_PROCESS when the instance
       is gone. */
    int32_t (*watch_exec)(int64_t pid, uint64_t generation, uint64_t token);
    void (*cancel_exec)(uint64_t token);
    int32_t (*environment)(int64_t pid, uint64_t generation, NzBuf *env_json);

    /* platform.Vault. */
    int32_t (*vault_get)(const uint8_t *name, size_t name_len, NzBuf *value);
    int32_t (*vault_put)(const uint8_t *name, size_t name_len, const uint8_t *value, size_t value_len);
    int32_t (*vault_delete)(const uint8_t *name, size_t name_len);
    int32_t (*vault_list)(const uint8_t *prefix, size_t prefix_len, NzBuf *names_json);

    /* audit.Sink. */
    int32_t (*write_audit)(int64_t unix_nanos, const uint8_t *line, size_t line_len);

    /* Frees an NzBuf.ptr the callee allocated. */
    void (*free_buf)(uint8_t *ptr);
} NazarCallbacks;

#endif /* NAZAR_BRIDGE_H */
