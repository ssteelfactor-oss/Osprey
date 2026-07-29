/*
 * osprey.h
 * Public API — shared types and forward declarations for all Osprey modules.
 *
 * Osprey is the network-facing twin of Kestrel. Kestrel maps the trust
 * surface of one Active Directory domain; Osprey maps the DCOM/RPC
 * activation-and-access surface across a subnet — who, from the network,
 * can reach, activate, and invoke COM servers on which hosts, under what
 * identity and at what authentication level.
 *
 * Invariants (shared with Kestrel):
 *   pure C · Windows SDK only · no evasion · on-prem / local network ·
 *   a strictly passive static core, with any activation behind an explicit
 *   opt-in probe layer over a narrowed target set.
 *
 * Module map:
 *   main.c   — v0.1  entry point / dispatch
 *   sweep.c  — v0.1  Tier-0 CIDR expansion + lock-free liveness pool
 *   epm.c    — v0.2  Tier-0 endpoint-mapper enumeration (ept_lookup)
 */

#pragma once

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

/* winsock2.h MUST precede windows.h */
#include <winsock2.h>
#include <ws2tcpip.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>
#include <strsafe.h>
#include <sal.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

#define OSPREY_VERSION L"0.2"

/* ════════════════════════════════════════════════════════════════════════════
 * Collection tier — how a fact was obtained, from most reachable to most
 * privileged. Osprey never requires the higher tiers; it degrades to what
 * access allows and records the tier alongside every finding.
 * ════════════════════════════════════════════════════════════════════════════ */
typedef enum _OSPREY_TIER {
    OSPREY_TIER_WIRE = 0,       /* EPM / OXID over the network, no registry  */
    OSPREY_TIER_REGISTRY,       /* HKLM via RemoteRegistry, usually no admin */
    OSPREY_TIER_PRIVILEGED,     /* raw hive, SACL / audit posture, admin     */
    OSPREY_TIER_INTENDED        /* GPO / SYSVOL policy, read once via Kestrel */
} OSPREY_TIER;

/* Provenance tag carried by every reported node. */
typedef enum _OSPREY_PROV {
    OSPREY_PROV_OBSERVED = 0,   /* seen on the wire                          */
    OSPREY_PROV_AUTHORITATIVE,  /* read from the registry                    */
    OSPREY_PROV_INTENDED        /* declared by policy, not host-confirmed    */
} OSPREY_PROV;

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Tier-0 sweep target model                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Per-host reachability result for the Tier-0 liveness pass. */
typedef enum _OSPREY_HOST_STATE {
    OSPREY_HOST_UNTESTED = 0,
    OSPREY_HOST_ALIVE,          /* endpoint mapper (TCP/135) reachable */
    OSPREY_HOST_REFUSED,        /* host up, port closed (RST)          */
    OSPREY_HOST_TIMEOUT,        /* no response within the timeout      */
    OSPREY_HOST_ERROR
} OSPREY_HOST_STATE;

typedef struct _OSPREY_TARGET {
    ULONG             ulAddr;   /* IPv4, network byte order */
    OSPREY_HOST_STATE State;
} OSPREY_TARGET;

typedef struct _OSPREY_TARGETS {
    OSPREY_TARGET *pTargets;
    LONG           cTargets;
} OSPREY_TARGETS;

/* ─────────────────────────────────────────────────────────────────────────── */
/*  sweep.c — target expansion + generic lock-free worker pool                 */
/* ─────────────────────────────────────────────────────────────────────────── */

/* A per-target collector. The pool hands each worker a unique index and this
 * callback; the callback owns all semantics for that target (read ulAddr,
 * write State, and stash richer per-target output through pvUser — the same
 * index it was handed). This is the seam every Tier-0 collector rides on. */
typedef VOID (*OSPREY_COLLECTOR)(
    _In_        LONG            iTarget,
    _Inout_     OSPREY_TARGETS *pSet,
    _In_        DWORD           dwTimeoutMs,
    _Inout_opt_ PVOID           pvUser);

/* Expand L"a.b.c.d/prefix" (/16..32) into a target set. The caller releases
 * the set with OspreyTargetsFree. */
_Must_inspect_result_
HRESULT
OspreyParseCidr(
    _In_z_ LPCWSTR         pwszCidr,
    _Out_  OSPREY_TARGETS *pTargets);

/* Release a target set produced by OspreyParseCidr. Safe on a zeroed struct. */
VOID
OspreyTargetsFree(
    _Inout_ OSPREY_TARGETS *pTargets);

/* Run pfnCollector across every target on a lock-free worker pool.
 * dwWorkers is clamped to [1, cTargets]; dwTimeoutMs is the per-target budget. */
VOID
OspreyRun(
    _Inout_     OSPREY_TARGETS  *pTargets,
    _In_        DWORD            dwWorkers,
    _In_        DWORD            dwTimeoutMs,
    _In_        OSPREY_COLLECTOR pfnCollector,
    _Inout_opt_ PVOID            pvUser);

/* Convenience: the Tier-0 liveness collector (TCP/135), filling each State. */
VOID
OspreySweep(
    _Inout_ OSPREY_TARGETS *pTargets,
    _In_    DWORD           dwWorkers,
    _In_    DWORD           dwTimeoutMs);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  epm.c — Tier-0 endpoint-mapper enumeration                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

/* One endpoint-mapper registration on a host: an interface bound to a
 * concrete endpoint, optionally annotated by the server. */
typedef struct _OSPREY_EPM_ELT {
    UUID   IfId;                 /* interface UUID                         */
    USHORT usVerMajor;
    USHORT usVerMinor;
    WCHAR  wszBinding[256];      /* resolved endpoint (proto:addr[endpoint]) */
    WCHAR  wszAnnotation[64];    /* server-supplied annotation, if any     */
} OSPREY_EPM_ELT;

/* Per-host EPM inventory. Status records why an inquiry yielded nothing
 * (unreachable, access denied, or simply no more entries = RPC_S_OK). */
typedef struct _OSPREY_EPM_HOST {
    OSPREY_EPM_ELT *pElts;
    DWORD           cElts;
    RPC_STATUS      Status;
} OSPREY_EPM_HOST;

/* Enumerate the endpoint mapper on every target a prior sweep marked ALIVE.
 * Allocates a per-target array parallel to pTargets (index-aligned); the
 * caller releases it with OspreyEpmFree. Dead targets get an empty host. */
_Must_inspect_result_
HRESULT
OspreyEnumEpm(
    _Inout_  OSPREY_TARGETS   *pTargets,
    _In_     DWORD             dwWorkers,
    _In_     DWORD             dwTimeoutMs,
    _Outptr_ OSPREY_EPM_HOST **ppHosts);

VOID
OspreyEpmFree(
    _Inout_ OSPREY_EPM_HOST **ppHosts,
    _In_    LONG              cHosts);

/* Format a UUID as the canonical 8-4-4-4-12 hex string. Shared utility. */
VOID
OspreyFormatUuid(
    _In_                   const UUID *pId,
    _Out_writes_z_(cchBuf) LPWSTR      pwszBuf,
    _In_                   SIZE_T       cchBuf);
