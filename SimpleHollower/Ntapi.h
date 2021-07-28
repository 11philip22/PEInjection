#pragma once

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

typedef ULONG(WINAPI* RTLNTSTATUSTODOSERROR) (
	NTSTATUS Status
	);