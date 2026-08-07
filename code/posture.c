/*
 * posture.c — v0.4
 * Tier-1 DCOM authentication / hardening posture (plan D).
 *
 * The first collector to ride the registry.c transport, and the first fact
 * Osprey tags PROV_AUTHORITATIVE rather than PROV_OBSERVED. For every host a
 * prior sweep marked ALIVE, read the machine-wide DCOM settings that decide
 * whether the box is exposed to auth downgrade / activation relay:
 *
 *   HKLM\SOFTWARE\Microsoft\Ole
 *     EnableDCOM                REG_SZ   "Y"/"N"
 *     LegacyAuthenticationLevel REG_DWORD RPC_C_AUTHN_LEVEL_* (1=NONE .. 6=PKT_PRIVACY)
 *     LegacyImpersonationLevel  REG_DWORD
 *   HKLM\SOFTWARE\Microsoft\Ole\AppCompat
 *     RequireIntegrityActivationAuthenticationLevel REG_DWORD
 *       (the CVE-2021-26414 hardening toggle: 1 => activation requires
 *        packet-integrity auth; absent/0 => pre-hardening, relay-exposed)
 *
 * Read-only registry queries. No SECURITY_DESCRIPTOR parsing here — that is
 * plan A (activation.c). Posture proves the transport end-to-end first.
 */

#include "../include/osprey.h"

#define OSPREY_OLE_KEY        L"SOFTWARE\\Microsoft\\Ole"
#define OSPREY_OLE_APPCOMPAT  L"SOFTWARE\\Microsoft\\Ole\\AppCompat"

static VOID
OsPostureCollect(
    _In_        LONG            iTarget,
    _Inout_     OSPREY_TARGETS *pSet,
    _In_        DWORD           dwTimeoutMs,
    _Inout_opt_ PVOID           pvUser)
{
    OSPREY_POSTURE_HOST *pHost = &((OSPREY_POSTURE_HOST *)pvUser)[iTarget];
    WCHAR                wszIp[INET_ADDRSTRLEN];
    WCHAR                wszVal[8];
    HKEY                 hHklm = NULL;
    HRESULT              hr;

    UNREFERENCED_PARAMETER(dwTimeoutMs);

    ZeroMemory(pHost, sizeof(*pHost));
    pHost->hrResult = S_OK;

    if (pSet->pTargets[iTarget].State != OSPREY_HOST_ALIVE) {
        pHost->hrResult = HRESULT_FROM_WIN32(WSAEHOSTUNREACH);
        return;
    }

    OspreyFormatIp(pSet->pTargets[iTarget].ulAddr, wszIp, ARRAYSIZE(wszIp));

    hr = OspreyRegConnectHklm(wszIp, &hHklm);
    if (FAILED(hr)) {
        pHost->hrResult = hr;            /* RemoteRegistry off / denied / unreachable */
        return;
    }

    /* EnableDCOM ("Y"/"N") */
    if (SUCCEEDED(OspreyRegReadStr(hHklm, OSPREY_OLE_KEY, L"EnableDCOM",
                                   wszVal, ARRAYSIZE(wszVal)))) {
        pHost->bHaveEnableDcom = TRUE;
        pHost->bEnableDcom     = (wszVal[0] == L'Y' || wszVal[0] == L'y');
    }

    if (SUCCEEDED(OspreyRegReadDword(hHklm, OSPREY_OLE_KEY, L"LegacyAuthenticationLevel",
                                     &pHost->dwLegacyAuthLevel)))
        pHost->bHaveLegacyAuth = TRUE;

    if (SUCCEEDED(OspreyRegReadDword(hHklm, OSPREY_OLE_KEY, L"LegacyImpersonationLevel",
                                     &pHost->dwLegacyImpLevel)))
        pHost->bHaveLegacyImp = TRUE;

    if (SUCCEEDED(OspreyRegReadDword(hHklm, OSPREY_OLE_APPCOMPAT,
                                     L"RequireIntegrityActivationAuthenticationLevel",
                                     &pHost->dwRequireIntegrity)))
        pHost->bHaveRequireIntegrity = TRUE;

    RegCloseKey(hHklm);
}

_Must_inspect_result_
HRESULT
OspreyEnumPosture(
    _Inout_  OSPREY_TARGETS       *pTargets,
    _In_     DWORD                 dwWorkers,
    _In_     DWORD                 dwTimeoutMs,
    _Outptr_ OSPREY_POSTURE_HOST **ppHosts)
{
    OSPREY_POSTURE_HOST *pHosts;

    *ppHosts = NULL;
    if (!pTargets || pTargets->cTargets <= 0)
        return E_INVALIDARG;

    pHosts = (OSPREY_POSTURE_HOST *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                              (SIZE_T)pTargets->cTargets * sizeof(OSPREY_POSTURE_HOST));
    if (!pHosts)
        return E_OUTOFMEMORY;

    OspreyRun(pTargets, dwWorkers, dwTimeoutMs, OsPostureCollect, pHosts);

    *ppHosts = pHosts;
    return S_OK;
}

VOID
OspreyPostureFree(
    _Inout_ OSPREY_POSTURE_HOST **ppHosts)
{
    if (ppHosts && *ppHosts) {
        HeapFree(GetProcessHeap(), 0, *ppHosts);
        *ppHosts = NULL;
    }
}
