/*
 * main.c — v0.1
 * Osprey entry point.
 *
 * For now: parse a CIDR, run the Tier-0 liveness sweep, print reachable
 * endpoint mappers. As modules land this becomes a dispatch over subcommands
 * (sweep / epm / oxid / activation / ...), each writing provenance-tagged
 * nodes into a shared model that report.c serialises.
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
    wprintf(L"\nOsprey %s — DCOM/RPC subnet auditor (Tier-0 liveness)\n",
            OSPREY_VERSION);
    wprintf(L"usage: %s <CIDR> [workers] [timeout_ms]\n", pwszArgv0);
    wprintf(L"  e.g. %s 10.0.0.0/24 128 800\n\n", pwszArgv0);
}

int
wmain(int argc, wchar_t *argv[])
{
    WSADATA        wsa;
    OSPREY_TARGETS Targets = { NULL, 0 };
    DWORD          dwWorkers, dwTimeoutMs;
    ULONGLONG      ullT0, ullDelta;
    LONG           i, cAlive = 0;
    HRESULT        hr;

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

    ullT0 = GetTickCount64();
    OspreySweep(&Targets, dwWorkers, dwTimeoutMs);
    ullDelta = GetTickCount64() - ullT0;

    for (i = 0; i < Targets.cTargets; i++) {
        if (Targets.pTargets[i].State == OSPREY_HOST_ALIVE) {
            WCHAR          wszIp[INET_ADDRSTRLEN];
            struct in_addr addr;

            addr.s_addr = Targets.pTargets[i].ulAddr;
            InetNtopW(AF_INET, &addr, wszIp, ARRAYSIZE(wszIp));
            wprintf(L"%-15s  EPM/135 reachable\n", wszIp);
            cAlive++;
        }
    }

    fwprintf(stderr,
        L"\n[%ld targets, %lu workers, %lums timeout] %ld reachable in %llu ms\n",
        Targets.cTargets, dwWorkers, dwTimeoutMs, cAlive, ullDelta);

    OspreyTargetsFree(&Targets);
    WSACleanup();
    return 0;
}
