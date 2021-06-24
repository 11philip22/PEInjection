#pragma once

//
// Definitions
//
#define BUFFER_SIZE 0x2000

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	_PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

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