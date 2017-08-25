#pragma once
#include <Windows.h>
#include <winternl.h>
#include <Windows.h>
#include <sddl.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <AclAPI.h>
//#include <Ntsecapi.h>

#include "util.h"
#include "s4u.h"
#include "MSFRottenPotato.h"

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _KERNELINFO {
	PUCHAR pKernelBase;
	PUCHAR pFunctionAddress;
} KERNELINFO, *PKERNELINFO;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION // Size=20
{
	ULONG NumberOfHandles; // Size=4 Offset=0
	SYSTEM_HANDLE Handles[1]; // Size=16 Offset=4
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SID_BUILTIN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[2];
} SID_BUILTIN, *PSID_BUILTIN;

static wchar_t *SYSTEM_SID = L"S-1-5-18";
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

typedef struct _SID_INTEGRITY
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];

} SID_INTEGRITY, *PSID_INTEGRITY;

typedef NTSYSAPI
NTSTATUS
(NTAPI *_ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
);

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)

typedef NTSYSAPI
NTSTATUS 
(NTAPI *_NtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
);

typedef NTSYSAPI
NTSTATUS 
(NTAPI *_NtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

// Spawn a shell using the SeImpersonatePrivilege, requires an elevated primary token
void se_impersonate_priv(HANDLE);

// Spawn a shell by using the SeAssignPrimaryTokenPrivilege, requires an elevated primary token
// TODO figure out how to modify/set the session ID so it could be interactive (currently on session0)
void se_assign_primary_priv(HANDLE);

// Generate a new SYSTEM level primary token and return it
// Demonstrates SeCreateTokenPrivilege
HANDLE se_create_token_privilege(HANDLE, BOOL);

void set_backup_priv_reg();
void se_restore_priv_reg();

typedef struct _PROCESS_ACCESS_TOKEN
{
	HANDLE Token;
	HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;