#pragma once

//
// Definitions
//
#define BUFFER_SIZE 0x2000

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

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

//
// Helper functions
//
_PPEB ReadRemotePEB(HANDLE);
PLOADED_IMAGE ReadRemoteImage(HANDLE, LPCVOID);