/*
 * epm.c — v0.2
 * Tier-0 endpoint-mapper enumeration for Osprey.
 *
 * For each host a prior liveness sweep marked ALIVE, bind to its endpoint
 * mapper (ncacn_ip_tcp:addr[135]) and walk every registration with
 * RpcMgmtEpEltInq{Begin,NextW,Done} — the interface UUID/version, the concrete
 * endpoint it resolves to, and any server annotation. This is the first
 * collector that distinguishes "has an RPC surface" (a reachable EPM) from
 * "registers these specific DCOM/RPC interfaces".
 *
 * Read-only and unauthenticated: an EPM lookup is a query, the loudest-but-
 * harmless recon step. It activates nothing. It rides the sweep.c pool via the
 * OSPREY_COLLECTOR seam, so concurrency/timeout/join are inherited unchanged.
 */

#include "../include/osprey.h"

#define OSPREY_EPM_ENDPOINT   L"135"
#define OSPREY_EPM_PROTSEQ    L"ncacn_ip_tcp"

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Helpers                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID
OspreyFormatUuid(
    _In_                   const UUID *pId,
    _Out_writes_z_(cchBuf) LPWSTR      pwszBuf,
    _In_                   SIZE_T       cchBuf)
{
    (VOID)StringCchPrintfW(pwszBuf, cchBuf,
        L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        pId->Data1, pId->Data2, pId->Data3,
        pId->Data4[0], pId->Data4[1], pId->Data4[2], pId->Data4[3],
        pId->Data4[4], pId->Data4[5], pId->Data4[6], pId->Data4[7]);
}

/* Append one element to a host's inventory (grow-by-one; EPM lists are small). */
_Must_inspect_result_
static HRESULT
OsEpmHostPush(
    _Inout_ OSPREY_EPM_HOST      *pHost,
    _In_    const OSPREY_EPM_ELT *pElt)
{
    OSPREY_EPM_ELT *pNew;
    SIZE_T          cbNew = (SIZE_T)(pHost->cElts + 1) * sizeof(OSPREY_EPM_ELT);

    if (pHost->pElts == NULL)
        pNew = (OSPREY_EPM_ELT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNew);
    else
        pNew = (OSPREY_EPM_ELT *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             pHost->pElts, cbNew);
    if (!pNew)
        return E_OUTOFMEMORY;

    pHost->pElts             = pNew;
    pHost->pElts[pHost->cElts] = *pElt;
    pHost->cElts++;
    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Collector — enumerate the endpoint mapper for one ALIVE target             */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OsEpmCollect(
    _In_        LONG            iTarget,
    _Inout_     OSPREY_TARGETS *pSet,
    _In_        DWORD           dwTimeoutMs,
    _Inout_opt_ PVOID           pvUser)
{
    OSPREY_EPM_HOST   *pHost = &((OSPREY_EPM_HOST *)pvUser)[iTarget];
    WCHAR              wszAddr[INET_ADDRSTRLEN];
    struct in_addr     addr;
    RPC_WSTR           pwszStringBinding = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;
    RPC_EP_INQ_HANDLE  hInq     = NULL;
    RPC_STATUS         status;

    pHost->pElts  = NULL;
    pHost->cElts  = 0;
    pHost->Status = RPC_S_OK;

    /* Only touch hosts a prior liveness pass marked reachable — dead hosts
     * would just burn the timeout. */
    if (pSet->pTargets[iTarget].State != OSPREY_HOST_ALIVE) {
        pHost->Status = RPC_S_SERVER_UNAVAILABLE;
        return;
    }

    addr.s_addr = pSet->pTargets[iTarget].ulAddr;
    InetNtopW(AF_INET, &addr, wszAddr, ARRAYSIZE(wszAddr));

    status = RpcStringBindingComposeW(NULL,
                                      (RPC_WSTR)OSPREY_EPM_PROTSEQ,
                                      (RPC_WSTR)wszAddr,
                                      (RPC_WSTR)OSPREY_EPM_ENDPOINT,
                                      NULL, &pwszStringBinding);
    if (status != RPC_S_OK) {
        pHost->Status = status;
        return;
    }

    status = RpcBindingFromStringBindingW(pwszStringBinding, &hBinding);
    RpcStringFreeW(&pwszStringBinding);
    if (status != RPC_S_OK) {
        pHost->Status = status;
        return;
    }

    /* Per-call timeout (ms) so one slow host can't stall its worker. */
    (VOID)RpcBindingSetOption(hBinding, RPC_C_OPT_CALL_TIMEOUT, (ULONG_PTR)dwTimeoutMs);

    status = RpcMgmtEpEltInqBegin(hBinding, RPC_C_EP_ALL_ELTS,
                                  NULL, 0, NULL, &hInq);
    if (status != RPC_S_OK) {
        pHost->Status = status;
        RpcBindingFree(&hBinding);
        return;
    }

    for (;;) {
        RPC_IF_ID          IfId;
        RPC_BINDING_HANDLE hElt           = NULL;
        RPC_WSTR           pwszAnnotation = NULL;
        RPC_WSTR           pwszEltBinding = NULL;
        OSPREY_EPM_ELT     Elt;

        status = RpcMgmtEpEltInqNextW(hInq, &IfId, &hElt, NULL, &pwszAnnotation);
        if (status != RPC_S_OK)          /* RPC_X_NO_MORE_ENTRIES ends the walk */
            break;

        ZeroMemory(&Elt, sizeof(Elt));
        Elt.IfId       = IfId.Uuid;
        Elt.usVerMajor = IfId.VersMajor;
        Elt.usVerMinor = IfId.VersMinor;

        if (hElt) {
            if (RpcBindingToStringBindingW(hElt, &pwszEltBinding) == RPC_S_OK
                && pwszEltBinding) {
                (VOID)StringCchCopyW(Elt.wszBinding, ARRAYSIZE(Elt.wszBinding),
                                     (LPCWSTR)pwszEltBinding);
                RpcStringFreeW(&pwszEltBinding);
            }
            RpcBindingFree(&hElt);
        }
        if (pwszAnnotation) {
            (VOID)StringCchCopyW(Elt.wszAnnotation, ARRAYSIZE(Elt.wszAnnotation),
                                 (LPCWSTR)pwszAnnotation);
            RpcStringFreeW(&pwszAnnotation);
        }

        if (FAILED(OsEpmHostPush(pHost, &Elt))) {
            pHost->Status = (RPC_STATUS)RPC_S_OUT_OF_MEMORY;
            break;
        }
    }

    RpcMgmtEpEltInqDone(&hInq);
    RpcBindingFree(&hBinding);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT
OspreyEnumEpm(
    _Inout_  OSPREY_TARGETS   *pTargets,
    _In_     DWORD             dwWorkers,
    _In_     DWORD             dwTimeoutMs,
    _Outptr_ OSPREY_EPM_HOST **ppHosts)
{
    OSPREY_EPM_HOST *pHosts;

    *ppHosts = NULL;
    if (!pTargets || pTargets->cTargets <= 0)
        return E_INVALIDARG;

    pHosts = (OSPREY_EPM_HOST *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          (SIZE_T)pTargets->cTargets * sizeof(OSPREY_EPM_HOST));
    if (!pHosts)
        return E_OUTOFMEMORY;

    OspreyRun(pTargets, dwWorkers, dwTimeoutMs, OsEpmCollect, pHosts);

    *ppHosts = pHosts;
    return S_OK;
}

VOID
OspreyEpmFree(
    _Inout_ OSPREY_EPM_HOST **ppHosts,
    _In_    LONG              cHosts)
{
    LONG i;

    if (!ppHosts || !*ppHosts)
        return;

    for (i = 0; i < cHosts; i++) {
        if ((*ppHosts)[i].pElts)
            HeapFree(GetProcessHeap(), 0, (*ppHosts)[i].pElts);
    }
    HeapFree(GetProcessHeap(), 0, *ppHosts);
    *ppHosts = NULL;
}
