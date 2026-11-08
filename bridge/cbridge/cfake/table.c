// The C half of cfake: a NazarCallbacks table whose entries forward to the
// Go functions exported by cfake.go.
#include "nazar_bridge.h"
#include <stdlib.h>
#include "_cgo_export.h"

static int32_t c_create_key(int32_t p, int32_t a, int32_t x, NzBuf *h, NzBuf *pub) { return cfakeCreateKey(p, a, x, h, pub); }
static int32_t c_sign(const uint8_t *h, size_t hn, const uint8_t *d, size_t dn, uint64_t r, NzBuf *o) { return cfakeSign((uint8_t *)h, hn, (uint8_t *)d, dn, r, o); }
static int32_t c_key_agreement(const uint8_t *h, size_t hn, const uint8_t *p, size_t pn, uint64_t r, NzBuf *o) { return cfakeKeyAgreement((uint8_t *)h, hn, (uint8_t *)p, pn, r, o); }
static int32_t c_delete_key(const uint8_t *h, size_t hn) { return cfakeDeleteKey((uint8_t *)h, hn); }
static int32_t c_authenticate(int32_t p, const uint8_t *j, size_t jn, uint64_t *r) { return cfakeAuthenticate(p, (uint8_t *)j, jn, r); }
static int32_t c_confirm(const uint8_t *j, size_t jn, int32_t *a) { return cfakeConfirm((uint8_t *)j, jn, a); }
static void c_release_approval(uint64_t r) { cfakeReleaseApproval(r); }
static int32_t c_peer_of(int32_t fd, int64_t *pid, uint64_t *gen) { return cfakePeerOf(fd, pid, gen); }
static int32_t c_process(int64_t pid, uint64_t gen, NzBuf *o) { return cfakeProcess(pid, gen, o); }
static int32_t c_app_for(const uint8_t *j, size_t jn, NzBuf *o) { return cfakeAppFor((uint8_t *)j, jn, o); }
static int32_t c_code_hash(const uint8_t *p, size_t pn, NzBuf *o) { return cfakeCodeHash((uint8_t *)p, pn, o); }
static int32_t c_responsible_for(int64_t pid, uint64_t gen, int64_t *r) { return cfakeResponsibleFor(pid, gen, r); }
static int32_t c_installed_app(const uint8_t *b, size_t bn, NzBuf *o) { return cfakeInstalledApp((uint8_t *)b, bn, o); }
static int32_t c_apps(NzBuf *o) { return cfakeApps(o); }
static void c_watch_exit(int64_t pid, uint64_t gen, uint64_t t) { cfakeWatchExit(pid, gen, t); }
static void c_watch_screen_lock(uint64_t t) { cfakeWatchScreenLock(t); }
static void c_show_warning(const uint8_t *j, size_t jn) { cfakeShowWarning((uint8_t *)j, jn); }
static int32_t c_watch_exec(int64_t pid, uint64_t gen, uint64_t t) { return cfakeWatchExec(pid, gen, t); }
static void c_cancel_exec(uint64_t t) { cfakeCancelExec(t); }
static int32_t c_environment(int64_t pid, uint64_t gen, NzBuf *o) { return cfakeEnvironment(pid, gen, o); }
static int32_t c_vault_get(const uint8_t *n, size_t nn, NzBuf *o) { return cfakeVaultGet((uint8_t *)n, nn, o); }
static int32_t c_vault_put(const uint8_t *n, size_t nn, const uint8_t *v, size_t vn) { return cfakeVaultPut((uint8_t *)n, nn, (uint8_t *)v, vn); }
static int32_t c_vault_delete(const uint8_t *n, size_t nn) { return cfakeVaultDelete((uint8_t *)n, nn); }
static int32_t c_vault_list(const uint8_t *p, size_t pn, NzBuf *o) { return cfakeVaultList((uint8_t *)p, pn, o); }
static int32_t c_write_audit(int64_t ns, const uint8_t *l, size_t ln) { return cfakeWriteAudit(ns, (uint8_t *)l, ln); }
static void c_free_buf(uint8_t *p) { cfakeFreeBuf(p); }

static NazarCallbacks table = {
    NAZAR_ABI_VERSION,
    c_create_key, c_sign, c_key_agreement, c_delete_key,
    c_authenticate, c_confirm, c_release_approval,
    c_peer_of, c_process, c_app_for, c_code_hash, c_responsible_for, c_installed_app, c_apps,
    c_watch_exit, c_watch_screen_lock, c_show_warning,
    c_watch_exec, c_cancel_exec, c_environment,
    c_vault_get, c_vault_put, c_vault_delete, c_vault_list,
    c_write_audit,
    c_free_buf,
};

NazarCallbacks *cfake_table(void) { return &table; }

// Broken tables for cbridge.New's checks: the wrong ABI version, or a
// missing function. Callers free them with free().
NazarCallbacks *cfake_bad_table(int wrong_version) {
    NazarCallbacks *p = malloc(sizeof *p);
    *p = table;
    if (wrong_version) p->abi_version = NAZAR_ABI_VERSION + 1;
    else p->sign = 0;
    return p;
}

// A table without the exec callbacks (secrets design 6.3, D8: they are
// optional), or with only some of them (partial: environment NULL, the
// others set). Callers free it with free().
NazarCallbacks *cfake_noexec_table(int partial) {
    NazarCallbacks *p = malloc(sizeof *p);
    *p = table;
    p->environment = 0;
    if (!partial) {
        p->watch_exec = 0;
        p->cancel_exec = 0;
    }
    return p;
}
