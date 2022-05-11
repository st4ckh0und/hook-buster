#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

#define DIRECTORY_QUERY		0x0001
#define DIRECTORY_TRAVERSE	0x0002

typedef enum _SECTION_INHERIT {
	ViewShare=1,
	ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

extern NTSTATUS NTAPI NtClose(HANDLE Handle);
extern NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
extern NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
extern NTSTATUS NTAPI RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PCWSTR SourceString);

BOOL GetKnownDllSectionHandle(LPCWSTR DllName, PHANDLE SectionHandle)
{
	BOOL Result = FALSE;

	UNICODE_STRING KnownDllName = { 0 };

#ifdef _WIN64
	RtlInitUnicodeStringEx(&KnownDllName, L"\\KnownDlls");
#else
	RtlInitUnicodeStringEx(&KnownDllName, L"\\KnownDlls32");
#endif
	
	OBJECT_ATTRIBUTES KnownDllAttributes = { 0 };
	InitializeObjectAttributes(&KnownDllAttributes, &KnownDllName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE KnownDllDirectoryHandle = NULL;

	if (NT_SUCCESS(NtOpenDirectoryObject(&KnownDllDirectoryHandle, DIRECTORY_TRAVERSE | DIRECTORY_QUERY, &KnownDllAttributes)) && KnownDllDirectoryHandle != NULL)
	{
		UNICODE_STRING SectionName = { 0 };
		
		if (NT_SUCCESS(RtlInitUnicodeStringEx(&SectionName, DllName)))
		{
			OBJECT_ATTRIBUTES SectionAttributes = { 0 };
			InitializeObjectAttributes(&SectionAttributes, &SectionName, OBJ_CASE_INSENSITIVE, KnownDllDirectoryHandle, NULL);

			if (NT_SUCCESS(NtOpenSection(SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_QUERY, &SectionAttributes)))
				Result = TRUE;
		}

		NtClose(KnownDllDirectoryHandle);
	}

	return Result;
}

int main(int argc, char* argv[])
{
	PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		UNICODE_STRING* fullname = &entry->FullDllName;
		UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)entry->DllBase;
		IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PBYTE)entry->DllBase + dos->e_lfanew);

		IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)entry->DllBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (exports->AddressOfNames != 0)
		{
			printf("Checking for hooks in %S\n", basename->Buffer);

			HANDLE section = NULL;

			if (GetKnownDllSectionHandle(basename->Buffer, &section))
			{
				PVOID base = 0;
				SIZE_T size = 0;

				if (NT_SUCCESS(NtMapViewOfSection(section, GetCurrentProcess(), &base, 0, 0, 0, &size, ViewUnmap, 0, PAGE_READONLY)))
				{
					WORD* ordinals = (WORD*)((PBYTE)entry->DllBase + exports->AddressOfNameOrdinals);
					DWORD* names = (DWORD*)((PBYTE)entry->DllBase + exports->AddressOfNames);
					DWORD* functions = (DWORD*)((PBYTE)entry->DllBase + exports->AddressOfFunctions);

					for (DWORD i = 0; i < exports->NumberOfNames; i++)
					{
						char* name = (char*)((PBYTE)entry->DllBase + names[i]);
						void* function = (void*)((PBYTE)entry->DllBase + functions[ordinals[i]]);

						if ((PBYTE)function > (PBYTE)entry->DllBase + nt->OptionalHeader.BaseOfCode &&
							(PBYTE)function < (PBYTE)entry->DllBase + nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode)
						{
							DWORD offset = (DWORD)((PBYTE)function - (PBYTE)entry->DllBase);
							void* mapped = (void*)((PBYTE)base + offset);

							if (memcmp(function, mapped, 5) != 0)
								printf("Detected hook in %S!%s\n", basename->Buffer, name);
						}
					}

					NtUnmapViewOfSection(GetCurrentProcess(), base);
				}

				NtClose(section);
			}
		}

		next = next->Flink;
	}

	return 0;
}
