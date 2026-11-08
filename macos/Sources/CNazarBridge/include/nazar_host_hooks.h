/*
 * nazar_host_hooks.h — test-host only (never used by Nazar.app): what the
 * conformance host gives the Go suite besides the NazarCallbacks table.
 * answer scripts the next login/dialog answer (seamed mode only);
 * live_buffers and bad_frees read Swift's BufferLedger at the end of the run.
 */
#ifndef NAZAR_HOST_HOOKS_H
#define NAZAR_HOST_HOOKS_H
#include <stdint.h>

typedef struct NazarHostHooks {
    void (*answer)(int32_t allow);
    int64_t (*live_buffers)(void);
    int64_t (*bad_frees)(void);
} NazarHostHooks;

#endif
