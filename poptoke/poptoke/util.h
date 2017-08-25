#pragma once

PSID GetLocalSystemSID();
DWORD GetParentProcessId();
LPVOID GetHandleAddress(ULONG, USHORT);
PVOID GetInfoFromToken(HANDLE, TOKEN_INFORMATION_CLASS);
void DumpIL(HANDLE);

void create_registry_entry(DWORD);
void run_service(DWORD);
void delete_registry_entry(DWORD);

void createRegistryKey(wchar_t *);

HANDLE get_rp_token();