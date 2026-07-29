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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>
#include <strsafe.h>
#include <sal.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#define OSPREY_VERSION L"0.1"

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
/*  sweep.c — target expansion + lock-free liveness pool                       */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Expand L"a.b.c.d/prefix" (/16..32) into a target set. The caller releases
 * the set with OspreyTargetsFree. */
_Must_inspect_result_
HRESULT
OspreyParseCidr(
    _In_z_ LPCWSTR         pwszCidr,
    _Out_  OSPREY_TARGETS *pTargets);

/* Release a target set produced by OspreyParseCidr. Safe on a zeroed struct;
 * leaves the struct cleared. */
VOID
OspreyTargetsFree(
    _Inout_ OSPREY_TARGETS *pTargets);

/* Run the Tier-0 liveness sweep, filling each target's State in place.
 * dwWorkers is clamped to [1, cTargets]; dwTimeoutMs is the per-target budget. */
VOID
OspreySweep(
    _Inout_ OSPREY_TARGETS *pTargets,
    _In_    DWORD           dwWorkers,
    _In_    DWORD           dwTimeoutMs);
