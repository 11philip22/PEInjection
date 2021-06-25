#pragma once

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	_PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

//
// Function types
//
typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONPROCESS)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef NTSTATUS(WINAPI* NTUNMAPVIEWOFSECTION)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);