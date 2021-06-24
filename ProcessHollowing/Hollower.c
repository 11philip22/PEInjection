#include <Windows.h>

#include "PEB.h"
#include "Ntapi.h"
#include "Hollower.h"

_PPEB ReadRemotePEB(HANDLE);

//
// Hollower logic
//
INT main() {
	STARTUPINFOA			startupInfo;
	PROCESS_INFORMATION		processInformation;
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



lblCleanup:
	if (processInformation.hProcess)
		CloseHandle(processInformation.hProcess);

	if (processInformation.hThread)
		CloseHandle(processInformation.hThread);

	if (pPEB)
		free(pPEB);  // todo: replace with virtualfree
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
	_PPEB						pRetVal = NULL;

	_PPEB pPEB = malloc(sizeof(_PEB));  // todo: Replace with virtualalloc
	if (!pPEB)
		return NULL;

	BOOL bSuccess = ReadProcessMemory(hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(_PEB),
		0);
	if (bSuccess)
		pRetVal = pPEB;

	if (pBasicInfo)
		free(pBasicInfo);  // todo: replace with virtualfree

	return pRetVal;
}

#define BUFFER_SIZE 0x2000

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress) {  // todo: fix malloc
	BYTE* lpBuffer = malloc(BUFFER_SIZE);

	BOOL bSuccess = ReadProcessMemory(hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0);
	if (!bSuccess)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	PLOADED_IMAGE pImage = malloc(sizeof(LOADED_IMAGE));

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}