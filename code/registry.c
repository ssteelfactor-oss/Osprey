/*
 * registry.c — v0.4
 * Tier-1 remote-registry transport for Osprey (MS-RRP via RemoteRegistry).
 *
 * Every Tier-1 collector (posture, activation, topology) reads HKLM on a
 * remote host. Rather than hand-roll MS-RRP, we use the SDK's own remote
 * registry client — RegConnectRegistryW + the ordinary Reg* calls — which
 * speaks winreg RPC under the caller's credentials. Pure C, advapi32 only,
 * no MIDL, no generated stubs. This is the transport the Tier-1 collectors
 * ride, the counterpart to the sweep.c pool for Tier-0.
 *
 * Access is gated by each key's DACL, not by SeSecurityPrivilege — that
 * privilege is only for SACL/audit (Tier-2). So an ordinary domain user
 * reads what the key ACLs permit, wherever RemoteRegistry is running.
 *
 * Note: the Reg* remote APIs expose no per-call timeout; a slow or absent
 * RemoteRegistry can stall the calling worker until the RPC runtime gives
 * up. We only ever call these on hosts a prior sweep marked ALIVE, which
 * bounds the exposure; a hard watchdog is a later refinement.
 */

#include "../include/osprey.h"

#define OSPREY_REG_SAM   (KEY_READ | KEY_WOW64_64KEY)

_Must_inspect_result_
HRESULT
OspreyRegConnectHklm(
    _In_z_ LPCWSTR pwszHost,
    _Out_  PHKEY   phRemote)
{
    WCHAR   wszMachine[80];
    LSTATUS ls;

    *phRemote = NULL;

    /* RegConnectRegistry wants \\machine */
    if (FAILED(StringCchPrintfW(wszMachine, ARRAYSIZE(wszMachine), L"\\\\%s", pwszHost)))
        return E_INVALIDARG;

    ls = RegConnectRegistryW(wszMachine, HKEY_LOCAL_MACHINE, phRemote);
    if (ls != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(ls);

    return S_OK;
}

_Must_inspect_result_
HRESULT
OspreyRegReadStr(
    _In_                   HKEY    hKey,
    _In_z_                 LPCWSTR pwszSubkey,
    _In_z_                 LPCWSTR pwszValue,
    _Out_writes_z_(cchBuf) LPWSTR  pwszBuf,
    _In_                   DWORD   cchBuf)
{
    HKEY    hSub;
    LSTATUS ls;
    DWORD   dwType = 0;
    DWORD   cbData;
    DWORD   cch;

    if (cchBuf == 0)
        return E_INVALIDARG;
    pwszBuf[0] = L'\0';

    ls = RegOpenKeyExW(hKey, pwszSubkey, 0, OSPREY_REG_SAM, &hSub);
    if (ls != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(ls);

    cbData = cchBuf * sizeof(WCHAR);
    ls = RegQueryValueExW(hSub, pwszValue, NULL, &dwType, (LPBYTE)pwszBuf, &cbData);
    RegCloseKey(hSub);

    if (ls != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(ls);
    if (dwType != REG_SZ && dwType != REG_EXPAND_SZ)
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATATYPE);

    /* force NUL-termination regardless of how the value was stored */
    cch = cbData / sizeof(WCHAR);
    if (cch >= cchBuf)
        cch = cchBuf - 1;
    pwszBuf[cch] = L'\0';
    return S_OK;
}

_Must_inspect_result_
HRESULT
OspreyRegReadDword(
    _In_   HKEY    hKey,
    _In_z_ LPCWSTR pwszSubkey,
    _In_z_ LPCWSTR pwszValue,
    _Out_  DWORD  *pdwValue)
{
    HKEY    hSub;
    LSTATUS ls;
    DWORD   dwType = 0;
    DWORD   dwData = 0;
    DWORD   cbData = sizeof(dwData);

    *pdwValue = 0;

    ls = RegOpenKeyExW(hKey, pwszSubkey, 0, OSPREY_REG_SAM, &hSub);
    if (ls != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(ls);

    ls = RegQueryValueExW(hSub, pwszValue, NULL, &dwType, (LPBYTE)&dwData, &cbData);
    RegCloseKey(hSub);

    if (ls != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(ls);
    if (dwType != REG_DWORD)
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATATYPE);

    *pdwValue = dwData;
    return S_OK;
}

_Must_inspect_result_
HRESULT
OspreyRegReadBinary(
    _In_     HKEY    hKey,
    _In_z_   LPCWSTR pwszSubkey,
    _In_z_   LPCWSTR pwszValue,
    _Outptr_result_bytebuffer_(*pcbData) PBYTE *ppbData,
    _Out_    DWORD  *pcbData)
{
    HKEY    hSub;
    LSTATUS ls;
    DWORD   dwType = 0;
    DWORD   cbData = 0;
    PBYTE   pb;

    *ppbData = NULL;
    *pcbData = 0;

    ls = RegOpenKeyExW(hKey, pwszSubkey, 0, OSPREY_REG_SAM, &hSub);
    if (ls != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(ls);

    /* size probe */
    ls = RegQueryValueExW(hSub, pwszValue, NULL, &dwType, NULL, &cbData);
    if (ls != ERROR_SUCCESS || cbData == 0) {
        RegCloseKey(hSub);
        return (ls == ERROR_SUCCESS) ? HRESULT_FROM_WIN32(ERROR_INVALID_DATA)
                                     : HRESULT_FROM_WIN32(ls);
    }

    pb = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbData);
    if (!pb) {
        RegCloseKey(hSub);
        return E_OUTOFMEMORY;
    }

    ls = RegQueryValueExW(hSub, pwszValue, NULL, &dwType, pb, &cbData);
    RegCloseKey(hSub);

    if (ls != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pb);
        return HRESULT_FROM_WIN32(ls);
    }

    *ppbData = pb;
    *pcbData = cbData;
    return S_OK;
}
