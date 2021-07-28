#include <stdio.h>
#include <Windows.h>
#include <Winternl.h>

#include "Ntapi.h"

int main()
{
	STARTUPINFOA				startupInfo;
	PROCESS_INFORMATION			processInformation;
	PPROCESS_BASIC_INFORMATION	pProcessBasicInformation = NULL;
	HANDLE						hHostProcess;
	HANDLE						hHeap = GetProcessHeap();
	DWORD						dwReturnLength;

	NTQUERYINFORMATIONPROCESS	pNtQueryInformationProcess = NULL;

	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll) 
	{
		pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
		FreeLibrary(hNtdll);
	}
	else 
	{
		return ERROR_OPEN_FAILED;
	}

	SecureZeroMemory(&startupInfo, sizeof startupInfo);
	startupInfo.cb = sizeof startupInfo;
	SecureZeroMemory(&processInformation, sizeof processInformation);

	if (CreateProcessA(NULL,
		"\"notepad.exe\"",
		NULL,
		NULL,
		0,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startupInfo,
		&processInformation) != TRUE)
	{
		printf("[-] Unable to create the host process\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		return GetLastError();
	}

	hHostProcess = processInformation.hProcess;

	pProcessBasicInformation = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PROCESS_BASIC_INFORMATION));
	if (!pProcessBasicInformation) 
	{
		printf("[-] Unable to allocate a buffer for ProcessBasicInformation\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		return GetLastError();
	}

	pNtQueryInformationProcess(hHostProcess, 0, pProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
	// dt -t _peb
	DWORD pebImageBaseOffset = (DWORD)pProcessBasicInformation->PebBaseAddress + 10;

	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);

	HeapFree(hHeap, 0, pProcessBasicInformation);
}
