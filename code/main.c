/*
 * main.c — v0.4
 * Osprey entry point.
 *
 * Tier-0 (unprivileged, remote):
 *   1. liveness  — TCP/135 reachable?                       (sweep.c)
 *   2. epm       — which RPC/DCOM interfaces are registered? (epm.c)
 *   3. oxid      — which bindings does the host advertise?   (oxid.c)
 * Tier-1 (RemoteRegistry, usually unprivileged):
 *   4. posture   — DCOM auth / hardening posture             (posture.c)
 *
 * As modules land this becomes a dispatch over subcommands, each writing
 * provenance-tagged nodes into a shared model that report.c serialises.
 */

#include "../include/osprey.h"

#define OSPREY_DEFAULT_WORKERS      64
#define OSPREY_DEFAULT_TIMEOUT_MS   1000

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Usage                                                                      */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OspreyPrintUsage(
    _In_z_ LPCWSTR pwszArgv0)
{
    wprintf(L"\nOsprey %s — DCOM/RPC subnet auditor (Tier-0 + Tier-1)\n", OSPREY_VERSION);
    wprintf(L"usage: %s <CIDR> [workers] [timeout_ms]\n", pwszArgv0);
    wprintf(L"  e.g. %s 10.0.0.0/24 128 800\n\n", pwszArgv0);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Reporting                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OspreyPrintEpmHost(
    _In_z_ LPCWSTR                pwszIp,
    _In_   const OSPREY_EPM_HOST *pHost)
{
    DWORD e;

    if (pHost->cElts == 0) {
        wprintf(L"\n%-15s  epm: %s\n", pwszIp,
                (pHost->Status == RPC_S_OK) ? L"0 registrations" : L"inquiry failed");
        return;
    }

    wprintf(L"\n%-15s  epm: %lu registration(s)\n", pwszIp, pHost->cElts);
    for (e = 0; e < pHost->cElts; e++) {
        WCHAR wszId[40];
        OspreyFormatUuid(&pHost->pElts[e].IfId, wszId, ARRAYSIZE(wszId));
        wprintf(L"    %s v%u.%u  %-38s  %s\n",
                wszId, pHost->pElts[e].usVerMajor, pHost->pElts[e].usVerMinor,
                pHost->pElts[e].wszBinding, pHost->pElts[e].wszAnnotation);
    }
}

static VOID
OspreyPrintOxidHost(
    _In_z_ LPCWSTR                 pwszIp,
    _In_   const OSPREY_OXID_HOST *pHost)
{
    DWORD b;

    if (pHost->cBindings == 0) {
        if (FAILED(pHost->hrResult))
            wprintf(L"%-15s  oxid: ServerAlive2 failed (0x%08lX)\n",
                    pwszIp, (unsigned long)pHost->hrResult);
        return;
    }

    wprintf(L"%-15s  oxid: %lu advertised binding(s)\n", pwszIp, pHost->cBindings);
    for (b = 0; b < pHost->cBindings; b++) {
        BOOL bDiffers = (wcscmp(pHost->pBindings[b].wszAddr, pwszIp) != 0);
        wprintf(L"    [tower 0x%02X]  %s%s\n",
                pHost->pBindings[b].usTowerId, pHost->pBindings[b].wszAddr,
                bDiffers ? L"   <- differs from scanned address" : L"");
    }
}

/* Map an RPC_C_AUTHN_LEVEL_* value to a short label. */
static LPCWSTR
OspreyAuthLevelName(
    _In_ DWORD dwLevel)
{
    switch (dwLevel) {
        case 1:  return L"NONE";
        case 2:  return L"CONNECT";
        case 3:  return L"CALL";
        case 4:  return L"PKT";
        case 5:  return L"PKT_INTEGRITY";
        case 6:  return L"PKT_PRIVACY";
        default: return L"?";
    }
}

static VOID
OspreyPrintPostureHost(
    _In_z_ LPCWSTR                    pwszIp,
    _In_   const OSPREY_POSTURE_HOST *pHost)
{
    if (FAILED(pHost->hrResult)) {
        wprintf(L"%-15s  posture: unavailable (0x%08lX — RemoteRegistry off/denied?)\n",
                pwszIp, (unsigned long)pHost->hrResult);
        return;
    }

    wprintf(L"%-15s  posture:", pwszIp);

    if (pHost->bHaveEnableDcom)
        wprintf(L" EnableDCOM=%s", pHost->bEnableDcom ? L"Y" : L"N");

    if (pHost->bHaveLegacyAuth)
        wprintf(L" | LegacyAuth=%lu(%s)%s",
                pHost->dwLegacyAuthLevel,
                OspreyAuthLevelName(pHost->dwLegacyAuthLevel),
                (pHost->dwLegacyAuthLevel <= 1) ? L" [NO AUTH]" : L"");

    if (pHost->bHaveRequireIntegrity)
        wprintf(L" | ActivationHardening=%s",
                (pHost->dwRequireIntegrity != 0) ? L"enforced" : L"OFF");
    else
        wprintf(L" | ActivationHardening=not-set");

    wprintf(L"\n");
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Driver                                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

int
wmain(int argc, wchar_t *argv[])
{
    WSADATA              wsa;
    OSPREY_TARGETS       Targets = { NULL, 0 };
    OSPREY_EPM_HOST     *pEpm     = NULL;
    OSPREY_OXID_HOST    *pOxid    = NULL;
    OSPREY_POSTURE_HOST *pPosture = NULL;
    DWORD                dwWorkers, dwTimeoutMs;
    ULONGLONG            ullT0, ullDelta;
    LONG                 i, cAlive = 0;
    WCHAR                wszIp[INET_ADDRSTRLEN];

    if (argc < 2) {
        OspreyPrintUsage(argv[0]);
        return 1;
    }

    dwWorkers   = (argc > 2) ? (DWORD)_wtoi(argv[2]) : OSPREY_DEFAULT_WORKERS;
    dwTimeoutMs = (argc > 3) ? (DWORD)_wtoi(argv[3]) : OSPREY_DEFAULT_TIMEOUT_MS;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fwprintf(stderr, L"WSAStartup failed\n");
        return 1;
    }

    if (FAILED(OspreyParseCidr(argv[1], &Targets))) {
        fwprintf(stderr, L"bad CIDR (accepted prefixes: /16..32)\n");
        WSACleanup();
        return 1;
    }

    /* Stage 1 — liveness. */
    ullT0 = GetTickCount64();
    OspreySweep(&Targets, dwWorkers, dwTimeoutMs);
    ullDelta = GetTickCount64() - ullT0;

    for (i = 0; i < Targets.cTargets; i++)
        if (Targets.pTargets[i].State == OSPREY_HOST_ALIVE)
            cAlive++;

    fwprintf(stderr,
        L"[sweep] %ld targets, %lu workers, %lums timeout — %ld reachable in %llu ms\n",
        Targets.cTargets, dwWorkers, dwTimeoutMs, cAlive, ullDelta);

    if (cAlive == 0)
        goto cleanup;

    /* Stage 2 — endpoint-mapper enumeration (Tier-0). */
    if (SUCCEEDED(OspreyEnumEpm(&Targets, dwWorkers, dwTimeoutMs, &pEpm))) {
        for (i = 0; i < Targets.cTargets; i++) {
            if (Targets.pTargets[i].State == OSPREY_HOST_ALIVE) {
                OspreyFormatIp(Targets.pTargets[i].ulAddr, wszIp, ARRAYSIZE(wszIp));
                OspreyPrintEpmHost(wszIp, &pEpm[i]);
            }
        }
        OspreyEpmFree(&pEpm, Targets.cTargets);
    }

    /* Stage 3 — OXID binding leak (Tier-0). */
    if (SUCCEEDED(OspreyEnumOxid(&Targets, dwWorkers, dwTimeoutMs, &pOxid))) {
        wprintf(L"\n─── advertised bindings (ServerAlive2) ───\n");
        for (i = 0; i < Targets.cTargets; i++) {
            if (Targets.pTargets[i].State == OSPREY_HOST_ALIVE) {
                OspreyFormatIp(Targets.pTargets[i].ulAddr, wszIp, ARRAYSIZE(wszIp));
                OspreyPrintOxidHost(wszIp, &pOxid[i]);
            }
        }
        OspreyOxidFree(&pOxid, Targets.cTargets);
    }

    /* Stage 4 — DCOM posture (Tier-1, RemoteRegistry). */
    if (SUCCEEDED(OspreyEnumPosture(&Targets, dwWorkers, dwTimeoutMs, &pPosture))) {
        wprintf(L"\n─── DCOM posture (Tier-1) ───\n");
        for (i = 0; i < Targets.cTargets; i++) {
            if (Targets.pTargets[i].State == OSPREY_HOST_ALIVE) {
                OspreyFormatIp(Targets.pTargets[i].ulAddr, wszIp, ARRAYSIZE(wszIp));
                OspreyPrintPostureHost(wszIp, &pPosture[i]);
            }
        }
        OspreyPostureFree(&pPosture);
    }

cleanup:
    OspreyTargetsFree(&Targets);
    WSACleanup();
    return 0;
}
