/*
 * sweep.c — v0.1
 * Tier-0 liveness harness for Osprey.
 *
 * Concurrency model (the load-bearing part of any sweep):
 *   - I/O-bound work: a worker blocked in a socket wait is off the run queue
 *     and costs ~nothing, so worker count is decoupled from core count.
 *   - Lock-free distribution: a fixed target array + one InterlockedIncrement
 *     dispenser hands each worker a unique index; the survivors drain the
 *     array even if some CreateThread calls fail.
 *   - Lock-free results: each worker writes only the slot it owns.
 *   - The per-target timeout is the primary tuning knob: without it one dead
 *     host stalls a worker for the full TCP SYN timeout (~21s).
 *
 * The collector is OsProbeEpm — a bare TCP/135 reachability test, the
 * loudest-but-harmless probe: it activates nothing and invokes no RPC. When
 * epm.c lands this becomes a function-pointer seam so richer Tier-0 collectors
 * (ept_lookup, ServerAlive2) reuse this exact pool unchanged.
 */

#include "../include/osprey.h"

#define OSPREY_EPM_PORT   135

typedef struct _OS_SWEEP_CTX {
    OSPREY_TARGETS *pSet;
    volatile LONG   lNext;      /* atomic work dispenser (index) */
    DWORD           dwTimeoutMs;
} OS_SWEEP_CTX;

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Collector — non-blocking connect to TCP/135 with an explicit timeout       */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static OSPREY_HOST_STATE
OsProbeEpm(
    _In_ ULONG ulAddrNbo,
    _In_ DWORD dwTimeoutMs)
{
    SOCKET             sock;
    u_long             ulNonBlock = 1;
    struct sockaddr_in sa;
    OSPREY_HOST_STATE  State;
    int                iRc;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return OSPREY_HOST_ERROR;

    ioctlsocket(sock, FIONBIO, &ulNonBlock);

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(OSPREY_EPM_PORT);
    sa.sin_addr.s_addr = ulAddrNbo;

    iRc = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (iRc == 0) {
        State = OSPREY_HOST_ALIVE;                      /* immediate (rare) */
    } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
        State = OSPREY_HOST_ERROR;
    } else {
        fd_set         WriteSet, ExceptSet;
        struct timeval tv;
        int            iSel;

        FD_ZERO(&WriteSet);  FD_SET(sock, &WriteSet);
        FD_ZERO(&ExceptSet); FD_SET(sock, &ExceptSet);

        tv.tv_sec  = dwTimeoutMs / 1000;
        tv.tv_usec = (dwTimeoutMs % 1000) * 1000;

        iSel = select(0, NULL, &WriteSet, &ExceptSet, &tv);  /* nfds ignored on Win */
        if (iSel == 0) {
            State = OSPREY_HOST_TIMEOUT;
        } else if (iSel == SOCKET_ERROR) {
            State = OSPREY_HOST_ERROR;
        } else if (FD_ISSET(sock, &ExceptSet)) {
            State = OSPREY_HOST_REFUSED;                /* typically RST */
        } else {
            int iErr   = 0;
            int cbErr  = (int)sizeof(iErr);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&iErr, &cbErr);
            State = (iErr == 0) ? OSPREY_HOST_ALIVE : OSPREY_HOST_REFUSED;
        }
    }

    closesocket(sock);
    return State;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Worker — pull unique indices until the array is drained                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static DWORD WINAPI
OsWorker(
    _In_ LPVOID pParam)
{
    OS_SWEEP_CTX *pCtx = (OS_SWEEP_CTX *)pParam;
    LONG          iTarget;

    for (;;) {
        iTarget = InterlockedIncrement(&pCtx->lNext) - 1;
        if (iTarget >= pCtx->pSet->cTargets)
            break;
        pCtx->pSet->pTargets[iTarget].State =
            OsProbeEpm(pCtx->pSet->pTargets[iTarget].ulAddr, pCtx->dwTimeoutMs);
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT
OspreyParseCidr(
    _In_z_ LPCWSTR         pwszCidr,
    _Out_  OSPREY_TARGETS *pTargets)
{
    WCHAR          wszBuf[64];
    WCHAR         *pwszSlash;
    int            iPrefix;
    struct in_addr Base;
    ULONG          ulBaseHost, ulMask, ulNet, ulCount, k;
    OSPREY_TARGET *pArr;

    pTargets->pTargets = NULL;
    pTargets->cTargets = 0;

    if (FAILED(StringCchCopyW(wszBuf, ARRAYSIZE(wszBuf), pwszCidr)))
        return E_INVALIDARG;

    pwszSlash = wcschr(wszBuf, L'/');
    if (!pwszSlash)
        return E_INVALIDARG;
    *pwszSlash = L'\0';

    iPrefix = _wtoi(pwszSlash + 1);
    if (iPrefix < 16 || iPrefix > 32)                   /* cap skeleton allocations */
        return E_INVALIDARG;

    if (InetPtonW(AF_INET, wszBuf, &Base) != 1)
        return E_INVALIDARG;

    ulBaseHost = ntohl(Base.s_addr);
    ulMask     = (0xFFFFFFFFUL << (32 - iPrefix));
    ulNet      = ulBaseHost & ulMask;
    ulCount    = (iPrefix == 32) ? 1UL : (1UL << (32 - iPrefix));

    pArr = (OSPREY_TARGET *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                      (SIZE_T)ulCount * sizeof(OSPREY_TARGET));
    if (!pArr)
        return E_OUTOFMEMORY;

    for (k = 0; k < ulCount; k++) {
        pArr[k].ulAddr = htonl(ulNet + k);
        pArr[k].State  = OSPREY_HOST_UNTESTED;
    }

    pTargets->pTargets = pArr;
    pTargets->cTargets = (LONG)ulCount;
    return S_OK;
}

VOID
OspreyTargetsFree(
    _Inout_ OSPREY_TARGETS *pTargets)
{
    if (pTargets && pTargets->pTargets) {
        HeapFree(GetProcessHeap(), 0, pTargets->pTargets);
        pTargets->pTargets = NULL;
        pTargets->cTargets = 0;
    }
}

VOID
OspreySweep(
    _Inout_ OSPREY_TARGETS *pTargets,
    _In_    DWORD           dwWorkers,
    _In_    DWORD           dwTimeoutMs)
{
    OS_SWEEP_CTX ctx;
    HANDLE      *pThreads;
    DWORD        w;

    if (!pTargets || pTargets->cTargets <= 0)
        return;
    if (dwWorkers < 1)
        dwWorkers = 1;
    if ((LONG)dwWorkers > pTargets->cTargets)
        dwWorkers = (DWORD)pTargets->cTargets;

    ctx.pSet        = pTargets;
    ctx.lNext       = 0;
    ctx.dwTimeoutMs = dwTimeoutMs;

    pThreads = (HANDLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   (SIZE_T)dwWorkers * sizeof(HANDLE));
    if (!pThreads) {
        OsWorker(&ctx);         /* degenerate: sweep on this thread rather than not at all */
        return;
    }

    for (w = 0; w < dwWorkers; w++)
        pThreads[w] = CreateThread(NULL, 0, OsWorker, &ctx, 0, NULL);

    /* Join: wait on each handle in turn — avoids the 64-handle limit of
     * WaitForMultipleObjects; a blocked wait costs nothing. */
    for (w = 0; w < dwWorkers; w++) {
        if (pThreads[w]) {
            WaitForSingleObject(pThreads[w], INFINITE);
            CloseHandle(pThreads[w]);
        }
    }

    HeapFree(GetProcessHeap(), 0, pThreads);
}
