/*
 * activation.c — v0.5
 * Tier-1 DCOM activation/access ACL matrix (plan A) — "ADeleg for DCOM".
 *
 * For every host a prior sweep marked ALIVE, this reads the configuration that
 * decides who, from where, may activate and call COM servers, and under whose
 * identity those servers run:
 *
 *   HKLM\SOFTWARE\Microsoft\Ole
 *     DefaultLaunchPermission / DefaultAccessPermission   (REG_BINARY SD)
 *     MachineLaunchRestriction / MachineAccessRestriction (REG_BINARY SD)
 *   HKLM\SOFTWARE\Classes\AppID\{appid}
 *     LaunchPermission / AccessPermission                 (REG_BINARY SD)
 *     RunAs                                               (REG_SZ)
 *
 * Each REG_BINARY is a self-relative SECURITY_DESCRIPTOR. We walk its DACL,
 * resolve each ACE's SID, and decode the access mask into the five COM rights
 * — the {launch, access} x {local, remote} matrix per principal. RunAs tells
 * us what a caller inherits: a server RunAs SYSTEM, remotely activatable by a
 * broad principal, is the shape plan A exists to surface.
 *
 * This is the first fact tagged PROV_AUTHORITATIVE that carries a full ACL.
 * Read-only registry queries; SIDs resolved against local/domain context. It
 * is the heaviest per-host module — hundreds of AppIDs, two SDs each, over
 * RemoteRegistry — so it will run slower per host than the wire tiers.
 */

#include "../include/osprey.h"

#define OSPREY_OLE_KEY      L"SOFTWARE\\Microsoft\\Ole"
#define OSPREY_APPID_ROOT   L"SOFTWARE\\Classes\\AppID"

/* COM launch/access rights (from objidl.h; defined locally to avoid pulling
 * the COM headers into a pure-C, SDK-only build). */
#ifndef COM_RIGHTS_EXECUTE
#define COM_RIGHTS_EXECUTE          1
#define COM_RIGHTS_EXECUTE_LOCAL    2
#define COM_RIGHTS_EXECUTE_REMOTE   4
#define COM_RIGHTS_ACTIVATE_LOCAL   8
#define COM_RIGHTS_ACTIVATE_REMOTE  16
#endif

/* ─────────────────────────────────────────────────────────────────────────── */
/*  SID + mask helpers                                                         */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OsResolveSid(
    _In_                   PSID   pSid,
    _Out_writes_z_(cchOut) LPWSTR pwszOut,
    _In_                   DWORD  cchOut)
{
    WCHAR        wszName[256] = { 0 };
    WCHAR        wszDom[256] = { 0 };
    DWORD        cchName = ARRAYSIZE(wszName);
    DWORD        cchDom  = ARRAYSIZE(wszDom);
    SID_NAME_USE eUse;
    LPWSTR       pwszSid = 0;

    /* NULL system: resolve against local machine + its domain — fast for the
     * well-known principals that dominate DCOM ACLs (Everyone, Authenticated
     * Users, Administrators, Distributed COM Users, SYSTEM, INTERACTIVE). */
    if (LookupAccountSidW(NULL, pSid, wszName, &cchName, wszDom, &cchDom, &eUse)) {
        if (wszDom[0])
            (VOID)StringCchPrintfW(pwszOut, cchOut, L"%s\\%s", wszDom, wszName);
        else
            (VOID)StringCchCopyW(pwszOut, cchOut, wszName);
        return;
    }

    if (ConvertSidToStringSidW(pSid, &pwszSid) && pwszSid) {
        (VOID)StringCchCopyW(pwszOut, cchOut, pwszSid);
        LocalFree(pwszSid);
    } else {
        (VOID)StringCchCopyW(pwszOut, cchOut, L"<unresolved SID>");
    }
}

static VOID
OsDecodeMask(
    _In_  ACCESS_MASK        Mask,
    _Out_ OSPREY_COM_RIGHTS *pRights)
{
    pRights->bExecute       = (Mask & COM_RIGHTS_EXECUTE)         != 0;
    pRights->bExecuteLocal  = (Mask & COM_RIGHTS_EXECUTE_LOCAL)   != 0;
    pRights->bExecuteRemote = (Mask & COM_RIGHTS_EXECUTE_REMOTE)  != 0;
    pRights->bActivateLocal = (Mask & COM_RIGHTS_ACTIVATE_LOCAL)  != 0;
    pRights->bActivateRemote= (Mask & COM_RIGHTS_ACTIVATE_REMOTE) != 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  SECURITY_DESCRIPTOR → resolved DACL                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OsFreeSd(
    _Inout_ OSPREY_ACT_SD *pSd)
{
    if (pSd->pAces) {
        HeapFree(GetProcessHeap(), 0, pSd->pAces);
        pSd->pAces = 0;
    }
    pSd->cAces = 0;
}

_Must_inspect_result_
static HRESULT
OsAceAppend(
    _Inout_ OSPREY_ACT_SD        *pSd,
    _In_    const OSPREY_ACT_ACE *pAce)
{
    OSPREY_ACT_ACE *pNew = 0;
    SIZE_T          cbNew = (SIZE_T)(pSd->cAces + 1) * sizeof(OSPREY_ACT_ACE);

    if (pSd->pAces == 0)
        pNew = (OSPREY_ACT_ACE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNew);
    else
        pNew = (OSPREY_ACT_ACE *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pSd->pAces, cbNew);
    if (!pNew)
        return E_OUTOFMEMORY;

    pSd->pAces            = pNew;
    pSd->pAces[pSd->cAces] = *pAce;
    pSd->cAces++;
    return S_OK;
}

/* Parse a self-relative SD's DACL into resolved ACEs. Caller sets bPresent. */
static VOID
OsParseSd(
    _In_reads_bytes_(cbSd) PBYTE          pbSd,
    _In_                   DWORD          cbSd,
    _Inout_                OSPREY_ACT_SD *pSd)
{
    BOOL  bDaclPresent   = FALSE;
    BOOL  bDaclDefaulted = FALSE;
    PACL  pDacl          = 0;
    WORD  i = 0;

    UNREFERENCED_PARAMETER(cbSd);

    if (!pbSd || !IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR)pbSd))
        return;

    if (!GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)pbSd,
                                   &bDaclPresent, &pDacl, &bDaclDefaulted))
        return;

    /* No DACL present, or a NULL DACL, both mean "no restriction" = everyone. */
    if (!bDaclPresent || pDacl == 0) {
        pSd->bNullDacl = TRUE;
        return;
    }

    for (i = 0; i < pDacl->AceCount; i++) {
        PVOID          pAceRaw = 0;
        ACE_HEADER    *pHdr = 0;
        OSPREY_ACT_ACE ace = { 0 };
        PSID           pSid = 0;
        ACCESS_MASK    Mask = 0;

        if (!GetAce(pDacl, i, &pAceRaw))
            continue;

        pHdr = (ACE_HEADER *)pAceRaw;
        ZeroMemory(&ace, sizeof(ace));

        if (pHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *pA = (ACCESS_ALLOWED_ACE *)pAceRaw;
            Mask     = pA->Mask;
            pSid     = (PSID)&pA->SidStart;
            ace.bDeny = FALSE;
        } else if (pHdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *pD = (ACCESS_DENIED_ACE *)pAceRaw;
            Mask     = pD->Mask;
            pSid     = (PSID)&pD->SidStart;
            ace.bDeny = TRUE;
        } else {
            continue;   /* skip audit / object ACEs — not relevant to plan A */
        }

        if (!IsValidSid(pSid))
            continue;

        OsResolveSid(pSid, ace.wszPrincipal, ARRAYSIZE(ace.wszPrincipal));
        OsDecodeMask(Mask, &ace.Rights);

        if (FAILED(OsAceAppend(pSd, &ace)))
            return;     /* out of memory — stop, keep what we have */
    }
}

/* Read a REG_BINARY SD at hKey\subkey\value and parse it. */
static VOID
OsActReadSd(
    _In_    HKEY           hKey,
    _In_z_  LPCWSTR        pwszSubkey,
    _In_z_  LPCWSTR        pwszValue,
    _Inout_ OSPREY_ACT_SD *pSd)
{
    PBYTE pb = 0 ;
    DWORD cb = 0;

    ZeroMemory(pSd, sizeof(*pSd));

    if (SUCCEEDED(OspreyRegReadBinary(hKey, pwszSubkey, pwszValue, &pb, &cb))) {
        OsParseSd(pb, cb, pSd);
        pSd->bPresent = TRUE;
        HeapFree(GetProcessHeap(), 0, pb);
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  AppID enumeration                                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
OsAppIdAppend(
    _Inout_ OSPREY_ACT_HOST        *pHost,
    _In_    const OSPREY_ACT_APPID *pApp)
{
    OSPREY_ACT_APPID *pNew = 0;
    SIZE_T            cbNew = (SIZE_T)(pHost->cAppIds + 1) * sizeof(OSPREY_ACT_APPID);

    if (pHost->pAppIds == 0)
        pNew = (OSPREY_ACT_APPID *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNew);
    else
        pNew = (OSPREY_ACT_APPID *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHost->pAppIds, cbNew);
    if (!pNew)
        return E_OUTOFMEMORY;

    pHost->pAppIds              = pNew;
    pHost->pAppIds[pHost->cAppIds] = *pApp;   /* transfers ownership of pAces */
    pHost->cAppIds++;
    return S_OK;
}

/* Read one AppID key; store it only if it carries an explicit ACL or RunAs. */
static VOID
OsActReadAppId(
    _In_    HKEY             hRoot,
    _In_z_  LPCWSTR          pwszAppId,
    _Inout_ OSPREY_ACT_HOST *pHost)
{
    HKEY             hApp = 0;
    OSPREY_ACT_APPID app = { 0 };

    if (RegOpenKeyExW(hRoot, pwszAppId, 0, KEY_READ | KEY_WOW64_64KEY, &hApp) != ERROR_SUCCESS)
        return;

    ZeroMemory(&app, sizeof(app));
    (VOID)StringCchCopyW(app.wszAppId, ARRAYSIZE(app.wszAppId), pwszAppId);

    /* default value = friendly name (best-effort) */
    if (FAILED(OspreyRegReadStr(hApp, L"", L"", app.wszName, ARRAYSIZE(app.wszName))))
        app.wszName[0] = L'\0';

    if (SUCCEEDED(OspreyRegReadStr(hApp, L"", L"RunAs", app.wszRunAs, ARRAYSIZE(app.wszRunAs))))
        app.bHaveRunAs = TRUE;

    OsActReadSd(hApp, L"", L"LaunchPermission", &app.Launch);
    OsActReadSd(hApp, L"", L"AccessPermission", &app.Access);

    RegCloseKey(hApp);

    if (app.Launch.bPresent || app.Access.bPresent || app.bHaveRunAs) {
        if (FAILED(OsAppIdAppend(pHost, &app))) {
            OsFreeSd(&app.Launch);
            OsFreeSd(&app.Access);
        }
    } else {
        OsFreeSd(&app.Launch);   /* nothing interesting — release any ACEs */
        OsFreeSd(&app.Access);
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Collector                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OsActCollect(
    _In_        LONG            iTarget,
    _Inout_     OSPREY_TARGETS *pSet,
    _In_        DWORD           dwTimeoutMs,
    _Inout_opt_ PVOID           pvUser)
{
    OSPREY_ACT_HOST *pHost = &((OSPREY_ACT_HOST *)pvUser)[iTarget];
    WCHAR            wszIp[INET_ADDRSTRLEN] = { 0 };
    HKEY             hHklm      = 0;
    HKEY             hAppIdRoot = 0;
    HRESULT          hr = S_OK  ;
    DWORD            idx = 0;

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
        pHost->hrResult = hr;
        return;
    }

    /* machine-wide defaults + restrictions */
    OsActReadSd(hHklm, OSPREY_OLE_KEY, L"DefaultLaunchPermission",    &pHost->DefaultLaunch);
    OsActReadSd(hHklm, OSPREY_OLE_KEY, L"DefaultAccessPermission",    &pHost->DefaultAccess);
    OsActReadSd(hHklm, OSPREY_OLE_KEY, L"MachineLaunchRestriction",   &pHost->MachineLaunchRestriction);
    OsActReadSd(hHklm, OSPREY_OLE_KEY, L"MachineAccessRestriction",   &pHost->MachineAccessRestriction);

    /* per-AppID */
    if (RegOpenKeyExW(hHklm, OSPREY_APPID_ROOT, 0, KEY_READ | KEY_WOW64_64KEY,
                      &hAppIdRoot) == ERROR_SUCCESS) {
        WCHAR wszSub[256] = { 0 };
        DWORD cch = ARRAYSIZE(wszSub);

        for (idx = 0; ; idx++) {
            if (RegEnumKeyExW(hAppIdRoot, idx, wszSub, &cch, 0, 0, 0,0) != ERROR_SUCCESS)
                break;
            OsActReadAppId(hAppIdRoot, wszSub, pHost);
        }
        RegCloseKey(hAppIdRoot);
    }

    RegCloseKey(hHklm);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT
OspreyEnumActivation(
    _Inout_  OSPREY_TARGETS   *pTargets,
    _In_     DWORD             dwWorkers,
    _In_     DWORD             dwTimeoutMs,
    _Outptr_ OSPREY_ACT_HOST **ppHosts)
{
    OSPREY_ACT_HOST *pHosts = 0;

    if (!pTargets || pTargets->cTargets <= 0)
        return E_INVALIDARG;

    pHosts = (OSPREY_ACT_HOST *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          (SIZE_T)pTargets->cTargets * sizeof(OSPREY_ACT_HOST));
    if (!pHosts)
        return E_OUTOFMEMORY;

    OspreyRun(pTargets, dwWorkers, dwTimeoutMs, OsActCollect, pHosts);

    *ppHosts = pHosts;
    return S_OK;
}

VOID
OspreyActivationFree(
    _Inout_ OSPREY_ACT_HOST **ppHosts,
    _In_    LONG              cHosts)
{
    LONG  h = 0;
    DWORD a = 0 ;

    if (!ppHosts || !*ppHosts)
        return;

    for (h = 0; h < cHosts; h++) {
        OSPREY_ACT_HOST *pHost = &(*ppHosts)[h];

        for (a = 0; a < pHost->cAppIds; a++) {
            OsFreeSd(&pHost->pAppIds[a].Launch);
            OsFreeSd(&pHost->pAppIds[a].Access);
        }
        if (pHost->pAppIds)
            HeapFree(GetProcessHeap(), 0, pHost->pAppIds);

        OsFreeSd(&pHost->DefaultLaunch);
        OsFreeSd(&pHost->DefaultAccess);
        OsFreeSd(&pHost->MachineLaunchRestriction);
        OsFreeSd(&pHost->MachineAccessRestriction);
    }

    HeapFree(GetProcessHeap(), 0, *ppHosts);
    *ppHosts = 0;
}
