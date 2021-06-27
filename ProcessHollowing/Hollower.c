#include <Windows.h>
#include <stdio.h>

#include "PEB.h"
#include "Ntapi.h"
#include "Hollower.h"
#include "resource.h"

//
// Hollower logic
//
INT main() {
	STARTUPINFOA			startupInfo;
	PROCESS_INFORMATION		processInformation;
	PLOADED_IMAGE			pImage = NULL;
	PLOADED_IMAGE			pSourceImage = NULL;
	PIMAGE_NT_HEADERS32		pSourceHeaders;
	_PPEB					pPEB = NULL;
	NTSTATUS				ntStatus;
	HANDLE					hHostProcess;
	HRSRC					hrsrcHelloWorld;
	INT						iRet = ERROR_SUCCESS;
	DWORD					dwExeSize;
	HGLOBAL					hgExe;
	PVOID					pBuffer = NULL;
	PVOID					pRemoteImage;

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

	//
	// Load Hello World EXE from resource
	//
	hrsrcHelloWorld = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_HELLOWORLD_EXE1), L"HELLOWORLD_EXE");
	if (!hrsrcHelloWorld) {
		printf("[-] Unable to load exe from resource\r\n");
		iRet = ERROR_RESOURCE_NOT_FOUND;
		goto lblCleanup;
	}

	dwExeSize = SizeofResource(NULL, hrsrcHelloWorld);
	hgExe = LoadResource(NULL, hrsrcHelloWorld);

	pBuffer = VirtualAlloc(0, dwExeSize, MEM_COMMIT, PAGE_READWRITE);
	memcpy(pBuffer, hgExe, dwExeSize);
	
	pSourceImage = GetLoadedImage((DWORD)pBuffer);
	pSourceHeaders = GetNTHeaders((DWORD)pBuffer);
	
	printf("[*] Allocating memory\r\n");
	pRemoteImage = VirtualAllocEx(hHostProcess,
		pPEB->lpImageBaseAddress,
		pSourceHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!pRemoteImage) {
		printf("VirtualAllocEx call failed\r\n");
		iRet = GetLastError();
		goto lblCleanup;
	}

	DWORD dwDelta = (DWORD)pPEB->lpImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;
	
	printf("[*] Source image base: 0x%p\r\n", pSourceHeaders->OptionalHeader.ImageBase);
	printf("[*] Destination image base: 0x%p\r\n", pPEB->lpImageBaseAddress);
	printf("[*] Relocation delta: 0x%p\r\n", dwDelta);

	if (!WriteProcessMemory(hHostProcess,
		pPEB->lpImageBaseAddress,
		pBuffer,
		pSourceHeaders->OptionalHeader.SizeOfHeaders,
		0)) 
	{
		printf("Error writing process memory\r\n");
		iRet = GetLastError();
		goto lblCleanup;
	}

	
	
lblCleanup:
	if (processInformation.hProcess)
		CloseHandle(processInformation.hProcess);

	if (processInformation.hThread)
		CloseHandle(processInformation.hThread);

	if (pPEB)
		VirtualFree(pPEB, 0, MEM_RELEASE);

	if (pImage)
		VirtualFree(pImage, 0, MEM_RELEASE);

	if (pBuffer)
		VirtualFree(pBuffer, 0, MEM_RELEASE);

	if (pSourceImage)
		VirtualFree(pSourceImage, 0, MEM_RELEASE);

	return iRet;
}

//
// Helper functions
//
PPROCESS_BASIC_INFORMATION FindRemotePeb(CONST HANDLE hProcess) {																									// NOLINT(misc-misplaced-const)
	NTSTATUS ntStatus;
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

	pBasicInfo = VirtualAlloc(NULL, sizeof(PROCESS_BASIC_INFORMATION), MEM_COMMIT, PAGE_READWRITE);
	ntStatus= pNtQueryInformationProcess(hProcess,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength);

	if (NT_SUCCESS(ntStatus)) 
		return pBasicInfo;
	
	if (pBasicInfo)
		VirtualFree(pBasicInfo, 0, MEM_RELEASE);
	return NULL;
}

_PPEB ReadRemotePEB(HANDLE hProcess) {
	PPROCESS_BASIC_INFORMATION	pBasicInfo = FindRemotePeb(hProcess);
	if (!pBasicInfo)
		return NULL;

	DWORD dwPEBAddress = pBasicInfo->PebBaseAddress;

	_PPEB pPEB = VirtualAlloc(NULL, sizeof(_PEB), MEM_COMMIT, PAGE_READWRITE);
	if (!pPEB)
		return NULL;

	BOOL bSuccess = ReadProcessMemory(hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(_PEB),
		0);
	if (!bSuccess) {
		VirtualFree(pPEB, 0, MEM_RELEASE);
		pPEB = NULL;    
	}

	if (pBasicInfo)
		VirtualFree(pBasicInfo, 0, MEM_RELEASE);

	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress) {
	PLOADED_IMAGE pImage = NULL;
	
	BYTE* lpBuffer = VirtualAlloc(0, BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
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
	pImage = VirtualAlloc(0, sizeof(LOADED_IMAGE), MEM_COMMIT, PAGE_READWRITE);
	if (!pImage)
		goto lblCleanup;

	pImage->FileHeader = (PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);
	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
	pImage->Sections = (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

lblCleanup:
	if (lpBuffer)
		VirtualFree(lpBuffer, 0, MEM_RELEASE);

	return pImage;
}