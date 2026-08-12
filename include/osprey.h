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
 *   main.c     — v0.1  entry point / dispatch
 *   sweep.c    — v0.1  Tier-0 CIDR expansion + lock-free liveness pool
 *   epm.c      — v0.2  Tier-0 endpoint-mapper enumeration (ept_lookup)
 *   oxid.c     — v0.3  Tier-0 IObjectExporter::ServerAlive2 (binding leak)
 *   registry.c — v0.4  Tier-1 remote-registry transport (MS-RRP)
 *   posture.c  — v0.4  Tier-1 DCOM authentication / hardening posture (plan D)
 *   activation.c — v0.5 Tier-1 DCOM activation/access ACL matrix (plan A)
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
#include <sddl.h>
#include <sal.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

#define OSPREY_VERSION L"0.5"

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
 * callback; the callback owns all semantics for that target. The seam every
 * Tier-0 and Tier-1 collector rides on. */
typedef VOID (*OSPREY_COLLECTOR)(
    _In_        LONG            iTarget,
    _Inout_     OSPREY_TARGETS *pSet,
    _In_        DWORD           dwTimeoutMs,
    _Inout_opt_ PVOID           pvUser);

_Must_inspect_result_
HRESULT
OspreyParseCidr(
    _In_z_ LPCWSTR         pwszCidr,
    _Out_  OSPREY_TARGETS *pTargets);

VOID
OspreyTargetsFree(
    _Inout_ OSPREY_TARGETS *pTargets);

VOID
OspreyRun(
    _Inout_     OSPREY_TARGETS  *pTargets,
    _In_        DWORD            dwWorkers,
    _In_        DWORD            dwTimeoutMs,
    _In_        OSPREY_COLLECTOR pfnCollector,
    _Inout_opt_ PVOID            pvUser);

VOID
OspreySweep(
    _Inout_ OSPREY_TARGETS *pTargets,
    _In_    DWORD           dwWorkers,
    _In_    DWORD           dwTimeoutMs);

/* Format a target's IPv4 (network byte order) as text. Shared utility. */
VOID
OspreyFormatIp(
    _In_                   ULONG  ulAddrNbo,
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_                   SIZE_T cchBuf);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  epm.c — Tier-0 endpoint-mapper enumeration                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef struct _OSPREY_EPM_ELT {
    UUID   IfId;
    USHORT usVerMajor;
    USHORT usVerMinor;
    WCHAR  wszBinding[256];
    WCHAR  wszAnnotation[64];
} OSPREY_EPM_ELT;

typedef struct _OSPREY_EPM_HOST {
    OSPREY_EPM_ELT *pElts;
    DWORD           cElts;
    RPC_STATUS      Status;
} OSPREY_EPM_HOST;

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

VOID
OspreyFormatUuid(
    _In_                   const UUID *pId,
    _Out_writes_z_(cchBuf) LPWSTR      pwszBuf,
    _In_                   SIZE_T       cchBuf);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  oxid.c — Tier-0 IObjectExporter::ServerAlive2 (self-advertised bindings)   */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef struct _OSPREY_OXID_BINDING {
    USHORT usTowerId;
    WCHAR  wszAddr[256];
} OSPREY_OXID_BINDING;

typedef struct _OSPREY_OXID_HOST {
    OSPREY_OXID_BINDING *pBindings;
    DWORD                cBindings;
    USHORT               usComVerMajor;
    USHORT               usComVerMinor;
    HRESULT              hrResult;
} OSPREY_OXID_HOST;

_Must_inspect_result_
HRESULT
OspreyEnumOxid(
    _Inout_  OSPREY_TARGETS    *pTargets,
    _In_     DWORD              dwWorkers,
    _In_     DWORD              dwTimeoutMs,
    _Outptr_ OSPREY_OXID_HOST **ppHosts);

VOID
OspreyOxidFree(
    _Inout_ OSPREY_OXID_HOST **ppHosts,
    _In_    LONG               cHosts);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  registry.c — Tier-1 remote-registry transport (MS-RRP / RemoteRegistry)    */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Open a host's HKLM over the network under the caller's credentials. On
 * success returns S_OK and an HKEY the caller closes with RegCloseKey; on
 * failure a mapped HRESULT (RemoteRegistry off, unreachable, access denied). */
_Must_inspect_result_
HRESULT
OspreyRegConnectHklm(
    _In_z_ LPCWSTR pwszHost,        /* bare L"a.b.c.d" — no leading backslashes */
    _Out_  PHKEY   phRemote);

/* Read a REG_SZ / REG_EXPAND_SZ value at hKey\pwszSubkey (pwszSubkey may be
 * L"" for hKey itself). Result is always NUL-terminated. */
_Must_inspect_result_
HRESULT
OspreyRegReadStr(
    _In_                   HKEY    hKey,
    _In_z_                 LPCWSTR pwszSubkey,
    _In_z_                 LPCWSTR pwszValue,
    _Out_writes_z_(cchBuf) LPWSTR  pwszBuf,
    _In_                   DWORD   cchBuf);

/* Read a REG_DWORD value. */
_Must_inspect_result_
HRESULT
OspreyRegReadDword(
    _In_   HKEY    hKey,
    _In_z_ LPCWSTR pwszSubkey,
    _In_z_ LPCWSTR pwszValue,
    _Out_  DWORD  *pdwValue);

/* Read a REG_BINARY value into a HeapAlloc'd buffer (e.g. a self-relative
 * SECURITY_DESCRIPTOR). Caller frees with HeapFree(GetProcessHeap(), 0, ...). */
_Must_inspect_result_
HRESULT
OspreyRegReadBinary(
    _In_     HKEY    hKey,
    _In_z_   LPCWSTR pwszSubkey,
    _In_z_   LPCWSTR pwszValue,
    _Outptr_result_bytebuffer_(*pcbData) PBYTE *ppbData,
    _Out_    DWORD  *pcbData);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  posture.c — Tier-1 DCOM authentication / hardening posture (plan D)        */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Machine-wide DCOM posture from HKLM\SOFTWARE\Microsoft\Ole (+ AppCompat).
 * bHave* flags mark which values were actually present. */
typedef struct _OSPREY_POSTURE_HOST {
    BOOL    bEnableDcom;             /* EnableDCOM == "Y"                       */
    BOOL    bHaveEnableDcom;
    DWORD   dwLegacyAuthLevel;       /* LegacyAuthenticationLevel (RPC_C_AUTHN_LEVEL_*) */
    BOOL    bHaveLegacyAuth;
    DWORD   dwLegacyImpLevel;        /* LegacyImpersonationLevel                */
    BOOL    bHaveLegacyImp;
    DWORD   dwRequireIntegrity;      /* Ole\AppCompat\RequireIntegrityActivationAuthenticationLevel (2021-23 hardening) */
    BOOL    bHaveRequireIntegrity;
    HRESULT hrResult;                /* transport status (S_OK if Ole opened)   */
} OSPREY_POSTURE_HOST;

_Must_inspect_result_
HRESULT
OspreyEnumPosture(
    _Inout_  OSPREY_TARGETS       *pTargets,
    _In_     DWORD                 dwWorkers,
    _In_     DWORD                 dwTimeoutMs,
    _Outptr_ OSPREY_POSTURE_HOST **ppHosts);

VOID
OspreyPostureFree(
    _Inout_ OSPREY_POSTURE_HOST **ppHosts);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  activation.c — Tier-1 DCOM activation/access ACL matrix (plan A)            */
/* ─────────────────────────────────────────────────────────────────────────── */

/* The five COM launch/access rights an ACE may grant or deny. */
typedef struct _OSPREY_COM_RIGHTS {
    BOOL bExecute;          /* COM_RIGHTS_EXECUTE         0x01 */
    BOOL bExecuteLocal;     /* COM_RIGHTS_EXECUTE_LOCAL   0x02 */
    BOOL bExecuteRemote;    /* COM_RIGHTS_EXECUTE_REMOTE  0x04 */
    BOOL bActivateLocal;    /* COM_RIGHTS_ACTIVATE_LOCAL  0x08 */
    BOOL bActivateRemote;   /* COM_RIGHTS_ACTIVATE_REMOTE 0x10 */
} OSPREY_COM_RIGHTS;

/* One resolved ACE: principal, allow/deny, decoded rights. */
typedef struct _OSPREY_ACT_ACE {
    WCHAR             wszPrincipal[256];   /* DOMAIN\Name, or SID string */
    BOOL              bDeny;
    OSPREY_COM_RIGHTS Rights;
} OSPREY_ACT_ACE;

/* A parsed launch- or access-permission descriptor. */
typedef struct _OSPREY_ACT_SD {
    BOOL            bPresent;    /* value existed (else machine default applies) */
    BOOL            bNullDacl;   /* NULL DACL — everyone, everything             */
    OSPREY_ACT_ACE *pAces;
    DWORD           cAces;
} OSPREY_ACT_SD;

/* One AppID's activation posture. */
typedef struct _OSPREY_ACT_APPID {
    WCHAR         wszAppId[64];
    WCHAR         wszName[128];
    WCHAR         wszRunAs[128];
    BOOL          bHaveRunAs;
    OSPREY_ACT_SD Launch;
    OSPREY_ACT_SD Access;
} OSPREY_ACT_APPID;

/* Per-host activation inventory: machine-wide defaults/restrictions + AppIDs
 * that carry an explicit ACL or RunAs (defaulted AppIDs are omitted). */
typedef struct _OSPREY_ACT_HOST {
    OSPREY_ACT_APPID *pAppIds;
    DWORD             cAppIds;
    OSPREY_ACT_SD     DefaultLaunch;
    OSPREY_ACT_SD     DefaultAccess;
    OSPREY_ACT_SD     MachineLaunchRestriction;
    OSPREY_ACT_SD     MachineAccessRestriction;
    HRESULT           hrResult;
} OSPREY_ACT_HOST;

_Must_inspect_result_
HRESULT
OspreyEnumActivation(
    _Inout_  OSPREY_TARGETS   *pTargets,
    _In_     DWORD             dwWorkers,
    _In_     DWORD             dwTimeoutMs,
    _Outptr_ OSPREY_ACT_HOST **ppHosts);

VOID
OspreyActivationFree(
    _Inout_ OSPREY_ACT_HOST **ppHosts,
    _In_    LONG              cHosts);
