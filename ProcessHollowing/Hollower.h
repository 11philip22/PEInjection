#pragma once

//
// Definitions
//
#define BUFFER_SIZE 0x2000

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)

typedef struct _LOADED_IMAGE {
	PSTR                  ModuleName;
	HANDLE                hFile;
	PUCHAR                MappedAddress;
#if _WIN64
	PIMAGE_NT_HEADERS64   FileHeader;
#else
	PIMAGE_NT_HEADERS32   FileHeader;
#endif
	PIMAGE_SECTION_HEADER LastRvaSection;
	ULONG                 NumberOfSections;
	PIMAGE_SECTION_HEADER Sections;
	ULONG                 Characteristics;
	BOOLEAN               fSystemImage;
	BOOLEAN               fDOSImage;
	BOOLEAN               fReadOnly;
	UCHAR                 Version;
	LIST_ENTRY            Links;
	ULONG                 SizeOfImage;
} LOADED_IMAGE, * PLOADED_IMAGE;

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

//
// Helper functions
//
_PPEB ReadRemotePEB(HANDLE);
PLOADED_IMAGE ReadRemoteImage(HANDLE, LPCVOID);

inline PIMAGE_NT_HEADERS32 GetNTHeaders(DWORD dwImageBase)
{
	return (PIMAGE_NT_HEADERS32)(dwImageBase +
		((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
}

inline PLOADED_IMAGE GetLoadedImage(DWORD dwImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS32 pNTHeaders = GetNTHeaders(dwImageBase);

	PLOADED_IMAGE pImage = VirtualAlloc(NULL, sizeof(LOADED_IMAGE), MEM_COMMIT, PAGE_READWRITE);

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS32)(dwImageBase + pDosHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}