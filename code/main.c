/*
 * main.c — v0.2
 * Osprey entry point.
 *
 * Tier-0 pass: expand a CIDR, sweep for liveness (TCP/135), then enumerate the
 * endpoint mapper on every reachable host. As modules land this becomes a
 * dispatch over subcommands (sweep / epm / oxid / activation / ...), each
 * writing provenance-tagged nodes into a shared model that report.c serialises.
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
    wprintf(L"\nOsprey %s — DCOM/RPC subnet auditor (Tier-0)\n", OSPREY_VERSION);
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
        wprintf(L"\n%-15s  endpoint mapper reachable, %s\n", pwszIp,
                (pHost->Status == RPC_S_OK) ? L"0 registrations"
                                            : L"inquiry failed");
        return;
    }

    wprintf(L"\n%-15s  %lu registration(s)\n", pwszIp, pHost->cElts);
    for (e = 0; e < pHost->cElts; e++) {
        WCHAR wszId[40];

        OspreyFormatUuid(&pHost->pElts[e].IfId, wszId, ARRAYSIZE(wszId));
        wprintf(L"    %s v%u.%u  %-38s  %s\n",
                wszId,
                pHost->pElts[e].usVerMajor, pHost->pElts[e].usVerMinor,
                pHost->pElts[e].wszBinding,
                pHost->pElts[e].wszAnnotation);
    }
}

int
wmain(int argc, wchar_t *argv[])
{
    WSADATA          wsa;
    OSPREY_TARGETS   Targets = { NULL, 0 };
    OSPREY_EPM_HOST *pHosts  = NULL;
    DWORD            dwWorkers, dwTimeoutMs;
    ULONGLONG        ullT0, ullDelta;
    LONG             i, cAlive = 0;
    HRESULT          hr;

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

    hr = OspreyParseCidr(argv[1], &Targets);
    if (FAILED(hr)) {
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

    /* Stage 2 — endpoint-mapper enumeration over the reachable hosts. */
    if (cAlive > 0) {
        ullT0 = GetTickCount64();
        hr = OspreyEnumEpm(&Targets, dwWorkers, dwTimeoutMs, &pHosts);
        ullDelta = GetTickCount64() - ullT0;

        if (SUCCEEDED(hr)) {
            for (i = 0; i < Targets.cTargets; i++) {
                if (Targets.pTargets[i].State != OSPREY_HOST_ALIVE)
                    continue;
                {
                    WCHAR          wszIp[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    addr.s_addr = Targets.pTargets[i].ulAddr;
                    InetNtopW(AF_INET, &addr, wszIp, ARRAYSIZE(wszIp));
                    OspreyPrintEpmHost(wszIp, &pHosts[i]);
                }
            }
            fwprintf(stderr, L"\n[epm] enumerated %ld host(s) in %llu ms\n",
                     cAlive, ullDelta);
            OspreyEpmFree(&pHosts, Targets.cTargets);
        } else {
            fwprintf(stderr, L"[epm] enumeration failed (0x%08lX)\n", (unsigned long)hr);
        }
    }

    OspreyTargetsFree(&Targets);
    WSACleanup();
    return 0;
}
