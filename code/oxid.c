/*
 * oxid.c — v0.3
 * Tier-0 IObjectExporter::ServerAlive2 for Osprey — the binding leak.
 *
 * Every DCOM host runs the OXID resolver (IObjectExporter, IID
 * 99fcfec4-5260-101b-bbcb-00aa0021347a) on ncacn_ip_tcp:addr[135]. Opnum 5,
 * ServerAlive2, takes no [in] parameters and returns a DUALSTRINGARRAY of the
 * string bindings the host advertises about *itself* — every address and
 * protocol it answers on. A multi-homed box leaks its other NICs, internal
 * subnets, and hostnames here, unasked. That is the fleet-relevant signal.
 *
 * This is hand-rolled raw DCE/RPC over the socket we already own: because
 * ServerAlive2 has no inputs, the bind and request PDUs are fixed byte
 * templates, and the only real work is parsing the DUALSTRINGARRAY out of the
 * response. No MIDL, no NDR stub tables, no generated code — matching the
 * "pure C, no deps" invariant. Read-only, unauthenticated: a query, nothing
 * activated. Rides the sweep.c pool via the OSPREY_COLLECTOR seam.
 *
 * Every multi-byte field on the wire is little-endian (we request drep 0x10
 * and Windows always answers in kind); we validate that and bail otherwise.
 */

#include "../include/osprey.h"

#define OSPREY_OXID_PORT     135
#define OSPREY_OXID_RECVMAX  8192   /* a ServerAlive2 response is tiny */

/* ── DCE/RPC connection-oriented PDU templates ──────────────────────────────
 * BIND (72 bytes): negotiate IObjectExporter (abstract) over NDR 2.0
 * (transfer) on presentation context 0. UUIDs are in RPC little-endian wire
 * form (Data1/2/3 byte-swapped, Data4 as-is).
 */
static const BYTE g_abBind[72] = {
    /* --- common header (16) --- */
    0x05, 0x00,             /* rpc_vers = 5, minor = 0                       */
    0x0B,                   /* PTYPE = bind (11)                             */
    0x03,                   /* pfc_flags = FIRST | LAST                      */
    0x10, 0x00, 0x00, 0x00, /* drep = little-endian, ASCII, IEEE            */
    0x48, 0x00,             /* frag_length = 72                              */
    0x00, 0x00,             /* auth_length = 0                               */
    0x01, 0x00, 0x00, 0x00, /* call_id = 1                                   */
    /* --- bind body --- */
    0xD0, 0x16,             /* max_xmit_frag = 5840                          */
    0xD0, 0x16,             /* max_recv_frag = 5840                          */
    0x00, 0x00, 0x00, 0x00, /* assoc_group_id = 0 (new)                      */
    0x01,                   /* n_context_elem = 1                            */
    0x00,                   /* reserved                                      */
    0x00, 0x00,             /* reserved2                                     */
    /* context[0] */
    0x00, 0x00,             /* p_cont_id = 0                                 */
    0x01,                   /* n_transfer_syn = 1                            */
    0x00,                   /* reserved                                      */
    /* abstract syntax: IObjectExporter 99fcfec4-5260-101b-bbcb-00aa0021347a v0.0 */
    0xC4, 0xFE, 0xFC, 0x99, 0x60, 0x52, 0x1B, 0x10,
    0xBB, 0xCB, 0x00, 0xAA, 0x00, 0x21, 0x34, 0x7A,
    0x00, 0x00, 0x00, 0x00, /* interface version 0.0                         */
    /* transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0 */
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00  /* transfer version 2.0                          */
};

/* REQUEST (24 bytes): opnum 5, presentation context 0, empty stub. */
static const BYTE g_abRequest[24] = {
    0x05, 0x00,             /* rpc_vers = 5, minor = 0                       */
    0x00,                   /* PTYPE = request (0)                           */
    0x03,                   /* pfc_flags = FIRST | LAST                      */
    0x10, 0x00, 0x00, 0x00, /* drep                                          */
    0x18, 0x00,             /* frag_length = 24                              */
    0x00, 0x00,             /* auth_length = 0                               */
    0x02, 0x00, 0x00, 0x00, /* call_id = 2                                   */
    0x00, 0x00, 0x00, 0x00, /* alloc_hint = 0                                */
    0x00, 0x00,             /* p_cont_id = 0                                 */
    0x05, 0x00              /* opnum = 5 (ServerAlive2)                       */
};

/* ── little-endian scalar reads (Windows host is LE; wire is LE) ──────────── */
static USHORT RdU16(_In_reads_(2) const BYTE *p) { USHORT v; memcpy(&v, p, 2); return v; }
static ULONG  RdU32(_In_reads_(4) const BYTE *p) { ULONG  v; memcpy(&v, p, 4); return v; }

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Transport helpers                                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Connect to addr:135 within dwTimeoutMs, then arm blocking send/recv
 * timeouts. Returns a connected blocking socket or INVALID_SOCKET. */
static SOCKET
OsOxidConnect(
    _In_ ULONG ulAddrNbo,
    _In_ DWORD dwTimeoutMs)
{
    SOCKET             sock = 0;
    u_long             ulNonBlock = 1, ulBlock = 0;
    struct sockaddr_in sa = { 0 };
    fd_set             WriteSet = { 0 }, ExceptSet = { 0 };
    struct timeval     tv = { 0 };
    int                iSel = 0;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return INVALID_SOCKET;

    ioctlsocket(sock, FIONBIO, &ulNonBlock);

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(OSPREY_OXID_PORT);
    sa.sin_addr.s_addr = ulAddrNbo;

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0
        && WSAGetLastError() == WSAEWOULDBLOCK) {
        FD_ZERO(&WriteSet);  FD_SET(sock, &WriteSet);
        FD_ZERO(&ExceptSet); FD_SET(sock, &ExceptSet);
        tv.tv_sec  = dwTimeoutMs / 1000;
        tv.tv_usec = (dwTimeoutMs % 1000) * 1000;

        iSel = select(0, NULL, &WriteSet, &ExceptSet, &tv);
        if (iSel <= 0 || FD_ISSET(sock, &ExceptSet)) {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }

    /* back to blocking, with bounded send/recv so a stall can't hang a worker */
    ioctlsocket(sock, FIONBIO, &ulBlock);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&dwTimeoutMs, sizeof(dwTimeoutMs));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&dwTimeoutMs, sizeof(dwTimeoutMs));
    return sock;
}

_Must_inspect_result_
static BOOL
OsSendAll(
    _In_               SOCKET      sock,
    _In_reads_(cbData) const BYTE *pbData,
    _In_               int         cbData)
{
    int cbSent = 0, n = 0;
    while (cbSent < cbData) {
        n = send(sock, (const char *)pbData + cbSent, cbData - cbSent, 0);
        if (n <= 0)
            return FALSE;
        cbSent += n;
    }
    return TRUE;
}

_Must_inspect_result_
static BOOL
OsRecvAll(
    _In_                     SOCKET sock,
    _Out_writes_(cbWant)     BYTE  *pbBuf,
    _In_                     int    cbWant)
{
    int cbGot = 0, n = 0;
    while (cbGot < cbWant) {
        n = recv(sock, (char *)pbBuf + cbGot, cbWant - cbGot, 0);
        if (n <= 0)
            return FALSE;
        cbGot += n;
    }
    return TRUE;
}

/* Read one CO PDU: 16-byte common header, then (frag_length - 16) body.
 * Returns body length in *pcbBody, or -1 on error. Validates version, LE
 * drep, and that the PDU is a single (LAST) fragment. */
static int
OsRecvPdu(
    _In_                       SOCKET sock,
    _Out_writes_(cbCap)        BYTE  *pbBody,
    _In_                       int    cbCap,
    _Out_                      BYTE  *pbPtype)
{
    BYTE   abHdr[16] = { 0 };
    USHORT usFrag = 0;
    int    cbBody = 0;

    *pbPtype = 0xFF;
    if (!OsRecvAll(sock, abHdr, sizeof(abHdr)))
        return -1;
    if (abHdr[0] != 0x05)                 /* rpc_vers */
        return -1;
    if (abHdr[4] != 0x10)                 /* drep: little-endian only */
        return -1;
    if ((abHdr[3] & 0x02) == 0)           /* PFC_LAST: no reassembly here */
        return -1;

    *pbPtype = abHdr[2];
    usFrag   = RdU16(&abHdr[8]);
    if (usFrag < 16)
        return -1;

    cbBody = (int)usFrag - 16;
    if (cbBody < 0 || cbBody > cbCap)
        return -1;
    if (cbBody > 0 && !OsRecvAll(sock, pbBody, cbBody))
        return -1;

    return cbBody;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  DUALSTRINGARRAY parse                                                      */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Append one binding, growing by one (leaks are small). */
_Must_inspect_result_
static HRESULT
OsOxidPush(
    _Inout_ OSPREY_OXID_HOST *pHost,
    _In_    USHORT            usTowerId,
    _In_z_  LPCWSTR           pwszAddr)
{
    OSPREY_OXID_BINDING *pNew = 0;
    SIZE_T               cbNew = (SIZE_T)(pHost->cBindings + 1) * sizeof(OSPREY_OXID_BINDING);

    if (pHost->pBindings == NULL)
        pNew = (OSPREY_OXID_BINDING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNew);
    else
        pNew = (OSPREY_OXID_BINDING *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                  pHost->pBindings, cbNew);
    if (!pNew)
        return E_OUTOFMEMORY;

    pHost->pBindings = pNew;
    pHost->pBindings[pHost->cBindings].usTowerId = usTowerId;
    (VOID)StringCchCopyW(pHost->pBindings[pHost->cBindings].wszAddr,
                         ARRAYSIZE(pHost->pBindings[pHost->cBindings].wszAddr), pwszAddr);
    pHost->cBindings++;
    return S_OK;
}

/* Parse the ServerAlive2 response stub. All offsets bounds-checked against
 * cbStub because this is attacker-influenced data off the wire. */
static VOID
OsOxidParseStub(
    _Inout_             OSPREY_OXID_HOST *pHost,
    _In_reads_(cbStub)  const BYTE       *pbStub,
    _In_                int               cbStub)
{
    ULONG  ulRefId = 0, ulMaxCount = 0, i = 0, iEnd = 0;
    USHORT usNumEntries = 0, usSecOffset = 0;
    const BYTE *pArr = 0;


    if (cbStub < 16) { pHost->hrResult = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); return; }

    pHost->usComVerMajor = RdU16(pbStub + 0);
    pHost->usComVerMinor = RdU16(pbStub + 2);

    ulRefId = RdU32(pbStub + 4);
    if (ulRefId == 0) { pHost->hrResult = S_OK; return; }   /* null DSA, no leak */

    ulMaxCount   = RdU32(pbStub + 8);
    usNumEntries = RdU16(pbStub + 12);
    usSecOffset  = RdU16(pbStub + 14);

    /* aStringArray[usNumEntries] follows at +16 */
    if (ulMaxCount != usNumEntries) { pHost->hrResult = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); return; }
    if (usSecOffset > usNumEntries) { pHost->hrResult = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); return; }
    if (16 + (int)usNumEntries * 2 > cbStub) { pHost->hrResult = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); return; }

    pArr = pbStub + 16;

    /* Walk only the string-binding region [0, usSecOffset). Each entry:
     * wTowerId (u16) + wide NUL-terminated address; region ends on a zero
     * tower id. Indices are in units of u16 into aStringArray. */
    i    = 0;
    iEnd = usSecOffset;
    while (i < iEnd) {
        USHORT usTower = RdU16(pArr + (SIZE_T)i * 2);
        i++;
        if (usTower == 0)
            break;                              /* terminator */

        {
            WCHAR  wszAddr[256] = { 0 };
            SIZE_T cch = 0;
            while (i < iEnd) {
                USHORT wc = RdU16(pArr + (SIZE_T)i * 2);
                i++;
                if (wc == 0)
                    break;
                if (cch < ARRAYSIZE(wszAddr) - 1)
                    wszAddr[cch++] = (WCHAR)wc;
            }
            wszAddr[cch] = L'\0';

            if (cch > 0 && FAILED(OsOxidPush(pHost, usTower, wszAddr))) {
                pHost->hrResult = E_OUTOFMEMORY;
                return;
            }
        }
    }

    pHost->hrResult = S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Collector                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
OsOxidCollect(
    _In_        LONG            iTarget,
    _Inout_     OSPREY_TARGETS *pSet,
    _In_        DWORD           dwTimeoutMs,
    _Inout_opt_ PVOID           pvUser)
{
    OSPREY_OXID_HOST *pHost = &((OSPREY_OXID_HOST *)pvUser)[iTarget];
    SOCKET            sock = 0;
    BYTE              abBody[OSPREY_OXID_RECVMAX] = { 0 };
    BYTE              bPtype = 0;
    int               cbBody = 0;

    pHost->pBindings = 0;
    pHost->cBindings = 0;
    pHost->hrResult  = S_OK;

    if (pSet->pTargets[iTarget].State != OSPREY_HOST_ALIVE) {
        pHost->hrResult = HRESULT_FROM_WIN32(WSAEHOSTUNREACH);
        return;
    }

    sock = OsOxidConnect(pSet->pTargets[iTarget].ulAddr, dwTimeoutMs);
    if (sock == INVALID_SOCKET) {
        pHost->hrResult = HRESULT_FROM_WIN32(WSAECONNREFUSED);
        return;
    }

    /* bind → bind_ack (ptype 12) */
    if (!OsSendAll(sock, g_abBind, sizeof(g_abBind))) {
        pHost->hrResult = HRESULT_FROM_WIN32(WSAECONNRESET); goto done;
    }
    cbBody = OsRecvPdu(sock, abBody, sizeof(abBody), &bPtype);
    if (cbBody < 0 || bPtype != 0x0C) {          /* 0x0C = bind_ack */
        pHost->hrResult = RPC_E_SERVER_DIED; goto done;
    }

    /* request opnum 5 → response (ptype 2) */
    if (!OsSendAll(sock, g_abRequest, sizeof(g_abRequest))) {
        pHost->hrResult = HRESULT_FROM_WIN32(WSAECONNRESET); goto done;
    }
    cbBody = OsRecvPdu(sock, abBody, sizeof(abBody), &bPtype);
    if (cbBody < 0 || bPtype != 0x02) {          /* 0x02 = response */
        pHost->hrResult = RPC_E_SERVER_DIED; goto done;
    }

    /* response body: alloc_hint(4) p_cont_id(2) cancel_count(1) reserved(1)
     * then the NDR stub. */
    if (cbBody < 8) { pHost->hrResult = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    OsOxidParseStub(pHost, abBody + 8, cbBody - 8);

done:
    closesocket(sock);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT
OspreyEnumOxid(
    _Inout_  OSPREY_TARGETS    *pTargets,
    _In_     DWORD              dwWorkers,
    _In_     DWORD              dwTimeoutMs,
    _Outptr_ OSPREY_OXID_HOST **ppHosts)
{
    OSPREY_OXID_HOST *pHosts = 0;

    *ppHosts = 0;
    if (!pTargets || pTargets->cTargets <= 0)
        return E_INVALIDARG;

    pHosts = (OSPREY_OXID_HOST *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                           (SIZE_T)pTargets->cTargets * sizeof(OSPREY_OXID_HOST));
    if (!pHosts)
        return E_OUTOFMEMORY;

    OspreyRun(pTargets, dwWorkers, dwTimeoutMs, OsOxidCollect, pHosts);

    *ppHosts = pHosts;
    return S_OK;
}

VOID
OspreyOxidFree(
    _Inout_ OSPREY_OXID_HOST **ppHosts,
    _In_    LONG               cHosts)
{
    LONG i = 0 ;

    if (!ppHosts || !*ppHosts)
        return;

    for (i = 0; i < cHosts; i++) {
        if ((*ppHosts)[i].pBindings)
            HeapFree(GetProcessHeap(), 0, (*ppHosts)[i].pBindings);
    }
    HeapFree(GetProcessHeap(), 0, *ppHosts);
    *ppHosts = 0;
}
