#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <detours/detours.h>
#include <iostream>
#include <chrono>

#include <TraceLoggingProvider.h>

#pragma comment(lib, "detours.lib")

// etw stuff
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Test-Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

UINT PID = 0;
const SIZE_T MSG_LEN = 1024;

UINT64 get_ns_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void emit_etw_ok(std::string msg) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "TestHookTask", // the first event name is used for all events, unless using a manifest file
        TraceLoggingString(msg.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cout << "[+] Test-Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "TestHookError",
        TraceLoggingString(error.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cerr << "[!] Test-Hook-DLL: " << error << "\n";
};

void emit_etw_msg_ns(const char msg[], UINT64 tpid, UINT64 ns) {
    TraceLoggingWrite(
        g_hProvider,
        "TestHookTask",
        TraceLoggingString(msg, "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(tpid, "targetpid")
    );
    std::cout << "[:] Test-Hook-DLL: " << ns << " - " << msg << "\n";
};

using FnNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
FnNtOpenProcess TrueNtOpenProcess = nullptr;

NTSTATUS NTAPI Hook_NtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	CLIENT_ID*         ClientId
) {
	UINT64 ns = get_ns_time();
	char msg[MSG_LEN] = { 0 };
	int tpid = (int)(ClientId ? (ULONG_PTR)ClientId->UniqueProcess : 0);
	if (tpid >= 4 && tpid <= 0xFFFFFF) { // only log events for valid process handles
		_snprintf_s(msg, sizeof(msg), _TRUNCATE,
			"NtOpenProcess with access 0x%lx",
			static_cast<LONG>(DesiredAccess));
		emit_etw_msg_ns(msg, tpid, ns);
	}
	return TrueNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// local or remote trigger, but only valid when called from a thread current process
extern "C" __declspec(dllexport) void CALLBACK ActivateHook() {
    std::cout << "[*] Test-Hook-DLL: ActivateHook called!\n";

    PID = GetCurrentProcessId();
    TraceLoggingRegister(g_hProvider);

    int retry = 0;
    while (!TraceLoggingProviderEnabled(g_hProvider, 0, 0) && retry++ < 10) {
        Sleep(10);
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    TrueNtOpenProcess = (FnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
	DetourAttach(&(PVOID&)TrueNtOpenProcess, Hook_NtOpenProcess);

    DetourTransactionCommit();

    emit_etw_ok("Hooks installed");
}

// unload hooks
extern "C" __declspec(dllexport) void CALLBACK DeactivateHook() {
	std::cout << "[*] Test-Hook-DLL: DeactivateHook called!\n";

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourDetach(&(PVOID&)TrueNtOpenProcess, Hook_NtOpenProcess);

	DetourTransactionCommit();

	emit_etw_ok("Hooks removed");
    TraceLoggingUnregister(g_hProvider);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)ActivateHook, nullptr, 0, nullptr);
        break;
	case DLL_PROCESS_DETACH:
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)DeactivateHook, nullptr, 0, nullptr);
        break;
    default:
        break;
    }
    return TRUE;
}

// ------------------ REFL INJ ------------------ //
// from https://github.com/Reijaff/offensive_c/blob/main/dll_reflective_loader_64.c
typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

///
__declspec(noinline) static DWORD64 get_current_address() {
    return (DWORD64)_ReturnAddress();
}

inline void zero_memory(DWORD64 Destination, SIZE_T Size) {
    PULONG Dest = (PULONG)Destination;
    SIZE_T Count = Size / sizeof(ULONG);

    while (Count > 0)
    {
        *Dest = 0;
        Dest++;
        Count--;
    }
}

inline SIZE_T wchar_to_char(PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed) {
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0) {
        if (!(*Destination++ = (CHAR)*Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

inline INT string_compare_a(LPCSTR String1, LPCSTR String2) {
    for (; *String1 == *String2; String1++, String2++) {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

inline DWORD64 get_module_handle_a(char* lpModuleName) {
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PLDR_MODULE Module = NULL;
    CHAR wDllName[64] = { 0 };
    PLIST_ENTRY Head = &Peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY Next = Head->Flink;
    Module = (PLDR_MODULE)((PBYTE)Next - 16);

    while (Next != Head) {
        Module = (PLDR_MODULE)((PBYTE)Next - 16);
        if (Module->BaseDllName.Buffer != NULL) {
            zero_memory((DWORD64)wDllName, sizeof(wDllName));
            wchar_to_char(wDllName, Module->BaseDllName.Buffer, 64);
            if (string_compare_a(lpModuleName, wDllName) == 0)
                return (DWORD64)Module->BaseAddress;
        }
        Next = Next->Flink;
    }

    return 0;
}

inline BOOL rtl_load_pe_headers(PIMAGE_DOS_HEADER* Dos, PIMAGE_NT_HEADERS* Nt, PIMAGE_FILE_HEADER* File, PIMAGE_OPTIONAL_HEADER* Optional, PBYTE* ImageBase) {
    *Dos = (PIMAGE_DOS_HEADER)*ImageBase;
    if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    *Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
    if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    *File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
    *Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

    return TRUE;
}

inline DWORD64 get_proc_address_a(DWORD64 ModuleBase, LPCSTR lpProcName) {
    PBYTE pFunctionName = NULL;
    PIMAGE_DOS_HEADER Dos = NULL;
    PIMAGE_NT_HEADERS Nt = NULL;
    PIMAGE_FILE_HEADER File = NULL;
    PIMAGE_OPTIONAL_HEADER Optional = NULL;

    rtl_load_pe_headers(&Dos, &Nt, &File, &Optional, (PBYTE*)&ModuleBase);

    IMAGE_EXPORT_DIRECTORY* ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + Optional->DataDirectory[0].VirtualAddress);
    PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfFunctions);
    PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNameOrdinals);

    for (DWORD dwX = 0; dwX < ExportTable->NumberOfNames; dwX++) {
        pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)ModuleBase;
        if (string_compare_a((PCHAR)pFunctionName, lpProcName) == 0)
            return ((DWORD64)ModuleBase + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]]);
    }

    return 0;
}

inline DWORD64 copy_memory(DWORD64 Destination, DWORD64 Source, SIZE_T Length) {
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* entry_DLLMAIN)(HINSTANCE, DWORD, LPVOID);

extern "C" __declspec(dllexport)
void ReflectiveLoader() {
    // 0. calculate image address
    DWORD64 dll_image_address;
    PIMAGE_NT_HEADERS nt_headers_address;

    dll_image_address = get_current_address();

    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)dll_image_address)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            nt_headers_address = (PIMAGE_NT_HEADERS)(dll_image_address + ((PIMAGE_DOS_HEADER)dll_image_address)->e_lfanew);
            if (nt_headers_address->Signature == IMAGE_NT_SIGNATURE)
                break;
        }
        dll_image_address--;
    }

    // 1. resolve system functions
    char KERNEL32_DLL_string[] = { '\x4b', '\x45', '\x52', '\x4e', '\x45', '\x4c', '\x33', '\x32', '\x2e', '\x44', '\x4c', '\x4c', 0 };                   // KERNEL32.DLL
    char VirtualAlloc_string[] = { '\x56', '\x69', '\x72', '\x74', '\x75', '\x61', '\x6c', '\x41', '\x6c', '\x6c', '\x6f', '\x63', 0 };                   // VirtualAlloc
    char GetProcAddress_string[] = { '\x47', '\x65', '\x74', '\x50', '\x72', '\x6f', '\x63', '\x41', '\x64', '\x64', '\x72', '\x65', '\x73', '\x73', 0 }; // GetProcAddress
    char LoadLibraryA_string[] = { '\x4c', '\x6f', '\x61', '\x64', '\x4c', '\x69', '\x62', '\x72', '\x61', '\x72', '\x79', '\x41', 0 };                   // LoadLibraryA

    DWORD64 kernel32 = get_module_handle_a(KERNEL32_DLL_string);
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)get_proc_address_a(kernel32, LoadLibraryA_string);
    GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)get_proc_address_a(kernel32, GetProcAddress_string);
    VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)get_proc_address_a(kernel32, VirtualAlloc_string);

    // 2. allocate memory for loading dll
    DWORD64 dll_base = (DWORD64)pVirtualAlloc(NULL, nt_headers_address->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 3. copy headers
    copy_memory(dll_base, dll_image_address, nt_headers_address->OptionalHeader.SizeOfHeaders);

    // 4. copy sections
    DWORD64 section_virtual_address;
    DWORD64 section_data_address;
    PIMAGE_SECTION_HEADER section_header_address = IMAGE_FIRST_SECTION(nt_headers_address);
    for (; section_header_address->VirtualAddress != (DWORD64)NULL; section_header_address++)
    {
        section_virtual_address = dll_base + section_header_address->VirtualAddress;
        section_data_address = dll_image_address + section_header_address->PointerToRawData;
        copy_memory(section_virtual_address, section_data_address, section_header_address->SizeOfRawData);
    }

    // 5. resolve import address table
    IMAGE_DATA_DIRECTORY imports_data_directory = nt_headers_address->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dll_base + imports_data_directory.VirtualAddress);
    LPCSTR library_name;
    HMODULE library_address;
    PIMAGE_THUNK_DATA thunk_data_address;
    PIMAGE_IMPORT_BY_NAME import_by_name_address;

    for (; import_descriptor->Name != (DWORD64)NULL; import_descriptor++)
    {
        library_name = (LPCSTR)(dll_base + import_descriptor->Name);
        library_address = pLoadLibraryA(library_name);

        if (library_address)
        {
            thunk_data_address = (PIMAGE_THUNK_DATA)(dll_base + import_descriptor->FirstThunk);

            for (; thunk_data_address->u1.AddressOfData != (DWORD64)NULL; thunk_data_address++)
            {
                import_by_name_address = (PIMAGE_IMPORT_BY_NAME)(dll_base + thunk_data_address->u1.AddressOfData);
                thunk_data_address->u1.Function = (DWORD64)pGetProcAddress(library_address, import_by_name_address->Name);
            }
        }
    }

    // 6. process all relocations
    DWORD64 base_diff = dll_base - nt_headers_address->OptionalHeader.ImageBase; // true_base - dummy_base

    IMAGE_DATA_DIRECTORY reloc_data_directory = nt_headers_address->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION base_reloc_address;
    PBASE_RELOCATION_ENTRY reloc_entry_address;
    DWORD64 reloc_block_address;
    DWORD64 reloc_block_entry_count;

    // check if any relocations present
    if (reloc_data_directory.Size) {
        base_reloc_address = (PIMAGE_BASE_RELOCATION)(dll_base + reloc_data_directory.VirtualAddress);

        while (base_reloc_address->SizeOfBlock) {
            reloc_block_address = dll_base + base_reloc_address->VirtualAddress;
            reloc_block_entry_count = (base_reloc_address->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

            reloc_entry_address = (PBASE_RELOCATION_ENTRY)((DWORD64)base_reloc_address + sizeof(IMAGE_BASE_RELOCATION));
            while (reloc_block_entry_count--) {
                if (reloc_entry_address->Type == IMAGE_REL_BASED_DIR64)
                    *(DWORD64*)(reloc_block_address + reloc_entry_address->Offset) += base_diff; // reloc_entry = dummy_va + (true_base - dummy_base)

                reloc_entry_address = (PBASE_RELOCATION_ENTRY)((DWORD64)reloc_entry_address + sizeof(BASE_RELOCATION_ENTRY));
            }
            base_reloc_address = (PIMAGE_BASE_RELOCATION)((DWORD64)base_reloc_address + base_reloc_address->SizeOfBlock);
        }
    }

    // 7. call entry point
    DWORD64 entrypoint_address = dll_base + nt_headers_address->OptionalHeader.AddressOfEntryPoint;
    ((entry_DLLMAIN)entrypoint_address)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, NULL);
}