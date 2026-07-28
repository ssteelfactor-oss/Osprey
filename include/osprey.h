/*
 * osprey.h — shared declarations for the Osprey DCOM surface auditor.
 *
 * Osprey is the DCOM twin of Kestrel: read-only, pure C, Windows SDK only,
 * no evasion, local network. This header holds the project-wide vocabulary
 * — version and the common result/target types shared by every module.
 * Module prototypes are added here as bricks land; implementation lives in
 * the matching .c under /code.
 */
#ifndef OSPREY_H
#define OSPREY_H

#include <windows.h>

#define OSPREY_NAME    "Osprey"
#define OSPREY_VERSION "0.1"

 /* Per-target reachability result, shared across the sweep and the collector
  * tiers. Extended (not replaced) as later tiers add their own verdicts. */
typedef enum {
    HOST_UNTESTED = 0,
    HOST_ALIVE,        /* RPC/DCOM surface reachable     */
    HOST_REFUSED,      /* host up, port closed           */
    HOST_TIMEOUT,      /* no response within the timeout */
    HOST_ERROR
} host_state;

/* A single sweep target: address plus its current verdict. */
typedef struct {
    ULONG      addr;   /* IPv4, network byte order */
    host_state state;
} target_t;

#endif /* OSPREY_H */