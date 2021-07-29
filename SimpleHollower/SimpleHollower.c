#include <stdio.h>
#include <Windows.h>
#include <Winternl.h>

#include "Ntapi.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int main()
{

	BOOL						bRet;
	NTSTATUS					ntStatus;
	STARTUPINFOA				startupInfo;
	PROCESS_INFORMATION			processInformation;
	PPROCESS_BASIC_INFORMATION	pProcessBasicInformation = NULL;
	HANDLE						hHostProcess;
	HANDLE						hHeap = GetProcessHeap();
	HANDLE						hSourceFile;
	DWORD						dwReturnLength;
	DWORD						dwSourceFileSize = 0;
	SIZE_T						sourceImageSize;
	LPVOID						lpSourceFileBytesBuffer;
	LPVOID						lpDestImageBase = 0;

	NTQUERYINFORMATIONPROCESS	pNtQueryInformationProcess = NULL;
	NTUNMAPVIEWOFSECTION		pNtUnmapViewOfSection = NULL;
	RTLNTSTATUSTODOSERROR		pRtlNtStatusToDosError = NULL;

	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll) 
	{
		pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
		pNtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");
		pRtlNtStatusToDosError = GetProcAddress(hNtdll, "RtlNtStatusToDosError");
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
		printf("[-] Unable to create the host process.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		return GetLastError();
	}

	hHostProcess = processInformation.hProcess;

	pProcessBasicInformation = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PROCESS_BASIC_INFORMATION));
	if (!pProcessBasicInformation) 
	{
		printf("[-] Unable to allocate a buffer for ProcessBasicInformation.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		return GetLastError();
	}

	ntStatus = pNtQueryInformationProcess(hHostProcess, 0, pProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
	if (!NT_SUCCESS(ntStatus)) 
	{
		printf("[-] Unable to query process information.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		HeapFree(hHeap, 0, pProcessBasicInformation);
		return pRtlNtStatusToDosError(ntStatus);
	}

	// dt -t _peb
	DWORD dwPebImageBaseOffset = (DWORD)pProcessBasicInformation->PebBaseAddress + 10;

	SIZE_T ccBytesRead = NULL;
	bRet = ReadProcessMemory(hHostProcess, (LPCVOID)dwPebImageBaseOffset, &lpDestImageBase, 4, &ccBytesRead);
	if (bRet == FALSE) 
	{
		printf("[-] Unable to read source file.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		HeapFree(hHeap, 0, pProcessBasicInformation);
		return GetLastError();
	}

	hSourceFile = CreateFileA(
		"C:\\Users\\Administrator\\source\\repos\\11philip22\\PEInjection\\x64\\Release\\HelloWorld.exe", 
		GENERIC_READ, 
		NULL, 
		NULL, 
		OPEN_ALWAYS, 
		NULL, 
		NULL);
	if (hSourceFile == INVALID_HANDLE_VALUE)
	{
		printf("[-]Unable to read file.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		HeapFree(hHeap, 0, pProcessBasicInformation);
		return GetLastError();
	}

	dwSourceFileSize = GetFileSize(hSourceFile, NULL);
	LPDWORD lpFileBytesRead = 0;
	
	lpSourceFileBytesBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSourceFileSize);
	if (!lpSourceFileBytesBuffer) 
	{
		printf("[-]Unable to allocate a buffer for lpSourceFileBytesBuffer.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		HeapFree(hHeap, 0, pProcessBasicInformation);
		return GetLastError();
	}
	
	bRet = ReadFile(hSourceFile, lpSourceFileBytesBuffer, dwSourceFileSize, NULL, NULL);
	if (bRet == FALSE) 
	{
		printf("[-] Unable to read source file.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		HeapFree(hHeap, 0, pProcessBasicInformation);
		HeapFree(hHeap, 0, lpSourceFileBytesBuffer);
		return GetLastError();
	}

	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)lpSourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpSourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	ntStatus = pNtUnmapViewOfSection(hHostProcess, lpDestImageBase);
	if (!NT_SUCCESS(ntStatus))
	{
		printf("[-] Unable to unmap section.\r\n");

		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		HeapFree(hHeap, 0, pProcessBasicInformation);
		HeapFree(hHeap, 0, lpSourceFileBytesBuffer);
		return pRtlNtStatusToDosError(ntStatus);
	}



	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);

	HeapFree(hHeap, 0, pProcessBasicInformation);
	HeapFree(hHeap, 0, lpSourceFileBytesBuffer);

	return ERROR_SUCCESS;
}
