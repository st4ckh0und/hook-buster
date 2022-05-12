#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define DIRECTORY_QUERY		0x0001
#define DIRECTORY_TRAVERSE	0x0002

typedef enum _SECTION_INHERIT {
	ViewShare=1,
	ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

extern NTSTATUS ZwClose_impl(HANDLE Handle);
extern NTSTATUS ZwOpenDirectoryObject_impl(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS ZwOpenSection_impl(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS ZwMapViewOfSection_impl(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
extern NTSTATUS ZwUnmapViewOfSection_impl(HANDLE ProcessHandle, PVOID BaseAddress);

NTSTATUS NTAPI RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PWSTR SourceString)
{
	DestinationString->Length = 0;
	DestinationString->MaximumLength = 0;
	DestinationString->Buffer = SourceString;

	if (SourceString == NULL)
		return 0;

	SIZE_T Length = (SIZE_T)-1;

	do
		Length++;
	while (SourceString[Length] != 0);

	if (Length >= 0x7fff)
		return 0xC0000106;
	
	USHORT ByteLength = (Length & 0xffff) * sizeof(wchar_t);

	DestinationString->Length = ByteLength;
	DestinationString->MaximumLength = ByteLength + sizeof(wchar_t);
	return 0;
}

BOOL GetKnownDllSectionHandle(LPWSTR DllName, PHANDLE SectionHandle)
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

	if (NT_SUCCESS(ZwOpenDirectoryObject_impl(&KnownDllDirectoryHandle, DIRECTORY_TRAVERSE | DIRECTORY_QUERY, &KnownDllAttributes)) && KnownDllDirectoryHandle != NULL)
	{
		UNICODE_STRING SectionName = { 0 };
		
		if (NT_SUCCESS(RtlInitUnicodeStringEx(&SectionName, DllName)))
		{
			OBJECT_ATTRIBUTES SectionAttributes = { 0 };
			InitializeObjectAttributes(&SectionAttributes, &SectionName, OBJ_CASE_INSENSITIVE, KnownDllDirectoryHandle, NULL);

			if (NT_SUCCESS(ZwOpenSection_impl(SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_QUERY, &SectionAttributes)))
				Result = TRUE;
		}

		ZwClose_impl(KnownDllDirectoryHandle);
	}

	return Result;
}

DWORD ComputeHash8(LPCSTR string)
{
	DWORD hash = 0;

	while (*string != 0)
	{
		hash = _rotr(hash, 13);
		hash += *string++;
	}

	return hash;
}

DWORD ComputeHash16(LPCWSTR string)
{
	DWORD hash = 0;

	while (*string != 0)
	{
		hash = _rotr(hash, 13);
		hash += *string++;
	}

	return hash;
}

PVOID GetModuleHandleH(DWORD hash)
{
	PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		UNICODE_STRING* fullname = &entry->FullDllName;
		UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

		if (ComputeHash16(basename->Buffer) == hash)
			return entry->DllBase;

		next = next->Flink;
	}

	return NULL;
}

typedef struct _NATIVE_FUNCTION
{
	DWORD hash;
	PBYTE function;
} NATIVE_FUNCTION;

typedef struct _NATIVE_FUNCTION_ARRAY
{
	DWORD size;
	NATIVE_FUNCTION functions[4096];
} NATIVE_FUNCTION_ARRAY;

NATIVE_FUNCTION_ARRAY g_function_array = { 0 };

void CollectNativeFunctions(PBYTE base)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (exports->AddressOfNames != 0)
	{
		PWORD ordinals = (PWORD)(base + exports->AddressOfNameOrdinals);
		PDWORD names = (PDWORD)(base + exports->AddressOfNames);
		PDWORD functions = (PDWORD)(base + exports->AddressOfFunctions);

		for (DWORD i = 0; i < exports->NumberOfNames; i++)
		{
			LPSTR name = (LPSTR)(base + names[i]);
			PBYTE function = (PBYTE)(base + functions[ordinals[i]]);

			if (function > base + nt->OptionalHeader.BaseOfCode &&
				function < base + nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode)
			{
				if (name[0] == 'Z' && name[1] == 'w')
				{
					g_function_array.functions[g_function_array.size].hash = ComputeHash8(name);
					g_function_array.functions[g_function_array.size].function = function;
					g_function_array.size++;
				}
			}
		}
	}
}

void BubbleSortFunctions()
{
	for (DWORD i = 0; i < g_function_array.size - 1; i++)
	{
		for (DWORD j = 0; j < g_function_array.size - i - 1; j++)
		{
			if (g_function_array.functions[j].function > g_function_array.functions[j + 1].function)
			{
				NATIVE_FUNCTION swap = { 0 };
				memcpy(&swap, &g_function_array.functions[j + 1], sizeof(NATIVE_FUNCTION));
				memcpy(&g_function_array.functions[j + 1], &g_function_array.functions[j], sizeof(NATIVE_FUNCTION));
				memcpy(&g_function_array.functions[j], &swap, sizeof(NATIVE_FUNCTION));
			}
		}
	}
}

DWORD GetFunctionId(DWORD hash)
{
	for (DWORD i = 0; i < g_function_array.size; i++)
	{
		if (g_function_array.functions[i].hash == hash)
			return i;
	}

	return 0xffffffff;
}

int main(int argc, char* argv[])
{
	PVOID ntdll = GetModuleHandleH(0xcef6e822);;

	if (ntdll != NULL)
	{
		CollectNativeFunctions((PBYTE)ntdll);
		BubbleSortFunctions();

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

					if (NT_SUCCESS(ZwMapViewOfSection_impl(section, (PVOID)-1, &base, 0, 0, 0, &size, ViewUnmap, 0, PAGE_READONLY)))
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

						ZwUnmapViewOfSection_impl((PVOID)-1, base);
					}

					ZwClose_impl(section);
				}
			}

			next = next->Flink;
		}
	}

	return 0;
}
