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