#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stddef.h>

#pragma comment(lib, "ntdll.lib")


#define ProcessHandleInformation 51

// generic handle information
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

// generic objects
typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

// file handles
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22]; // enough padding
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


// traverses the PEB and prints all loaded DLLs and their base addrs
void printBases(HANDLE hProcess) {
    printf("[*] Traversing PEB for loaded DLLs...\n");

    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
        printf("[!] Cannot read PEB base addr\n");
        return;
    }

    PEB_LDR_DATA ldr{};
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), nullptr)) {
        printf("[-] Failed to read PEB_LDR_DATA. Error: %lu", GetLastError());
        return;
    }

    PVOID headAddr = (PBYTE)peb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

    LIST_ENTRY head{};
    ReadProcessMemory(hProcess, headAddr, &head, sizeof(head), nullptr);
    PVOID current = head.Flink;

    printf("%-19s %-100s\n", "Base Address", "DLL Name");
    printf("------------------------------------------------\n");

    while (current && current != headAddr) {
        LDR_DATA_TABLE_ENTRY entry{};
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), nullptr)) {
            printf("[-] Failed to read LDR_DATA_TABLE_ENTRY. Error: %lu", GetLastError());
            return;
        }
        if (entry.FullDllName.Buffer) {
            wchar_t dll_name[MAX_PATH];
            printf("0x%016llX ", (unsigned long long)entry.DllBase);
            if (ReadProcessMemory(hProcess, entry.FullDllName.Buffer, dll_name, entry.FullDllName.Length, nullptr)) {
                dll_name[entry.FullDllName.Length / sizeof(wchar_t)] = L'\0'; // null-terminate
                wprintf(L"%-100ls\n", dll_name);
            }
            else {
                printf("<Failed to read dll name. Error: %lu>\n", GetLastError());
            }
        }
        current = entry.InMemoryOrderLinks.Flink;
    }
}

int checkProcHandles(PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles) {
    printf("[+] Checking for process handles...\n");
    int found = 0;

    for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
        PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];

        // Check if the handle is a process handle
        DWORD targetPid = GetProcessId(entry.HandleValue);
        if (targetPid != 0) {
            printf("[+] Proc handle found: ID=0x%p, PID=%lu, Access=0x%08X\n",
                entry.HandleValue, targetPid, entry.GrantedAccess);
            found++;
            printBases(entry.HandleValue);
        }
    }
    if (found == 0) {
        printf("[-] No process handles found.\n");
    }
    return found;
}

int checkThreadHandles(PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles) {
    printf("[+] Checking for thread handles...\n");
    int found = 0;

    for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
        PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];

        // Check if the handle is a thread handle
        DWORD targetTid = GetThreadId(entry.HandleValue);
        if (targetTid != 0) {
            if (found == 0) { // print header when threads found
                printf("Handle ID  Access     Thread ID\n");
                printf("------------------------------------------------\n");
            }
            printf("0x%08X 0x%08X %lu\n", (UINT32)(ULONG_PTR)entry.HandleValue, entry.GrantedAccess, targetTid);
            found++;
        }
    }
    if (found == 0) {
        printf("[-] No thread handles found.\n");
    }
    return found;
}

int checkFileHandles(PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles) {
    printf("[+] Checking for file handles...\n");
    int found = 0;

    for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
        auto& entry = localHandles->Handles[i];

        BYTE typeBuf[1024];
        ULONG retLen = 0;

        if (!NT_SUCCESS(NtQueryObject(entry.HandleValue, (OBJECT_INFORMATION_CLASS)ObjectTypeInformation, typeBuf, sizeof(typeBuf), &retLen))) {
            printf("[!] Error querring object for type info %p\n", entry.HandleValue);
            continue;
        }

        auto typeInfo = (POBJECT_TYPE_INFORMATION)typeBuf;

        if (!typeInfo->TypeName.Buffer) {
            printf("[!] Empty type buffer for %p\n", entry.HandleValue);
            continue;
        }

        if (_wcsicmp(typeInfo->TypeName.Buffer, L"File") != 0) {
            continue; // silently ignore non files
        }

        // print header before first file entry
        if (found == 0) {
            printf("Handle ID  Access     Name\n");
            printf("------------------------------------------------\n");
        }
        found++;

        const ULONG namesBufLen = 1024;
        BYTE namesBuf[namesBufLen];

        if (!NT_SUCCESS(NtQueryObject(entry.HandleValue, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, &namesBuf, namesBufLen, &retLen))) {
            printf("[!] Error querring object for name info %p\n", entry.HandleValue);
            continue;
        }

        auto nameInfo = (POBJECT_NAME_INFORMATION)namesBuf;
        if (!nameInfo->Name.Buffer) {
            printf("[!] Empty name buffer for %p\n", entry.HandleValue);
            continue;
        }
        wprintf(L"0x%08X 0x%08X %.*s\n", (UINT32)(ULONG_PTR)entry.HandleValue, entry.GrantedAccess,
            static_cast<int>(nameInfo->Name.Length / sizeof(WCHAR)), nameInfo->Name.Buffer);
    }
    if (found == 0) {
        printf("[-] No file handles found.\n");
    }
    return found;
}

// gets all open handles in current process
bool getLocalHandles(_Out_ PPROCESS_HANDLE_SNAPSHOT_INFORMATION* localHandles) {

    ULONG bufferSize = 0x1000; // just a single local process
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG returnLength = 0;

    // Query only current process handle table
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessHandleInformation,
        buffer, bufferSize, &returnLength);

    // Resize if needed
    if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessHandleInformation, buffer, bufferSize, &returnLength);
    }

    *localHandles = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;
    return NT_SUCCESS(status);
}

int main() {
    printf("[*] Handle Inspector started\n");

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles;
    if (!getLocalHandles(&localHandles)) {
        printf("[!] Unable to query local process for handles\n");
        return 1;
    }

    if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
        printf("[*] No handles found in the current process.\n");
        if (localHandles != 0) VirtualFree(localHandles, 0, MEM_RELEASE);
        return 0;
    }
    printf("[*] Got %llu handles of all types owned by Process Handle Inspector...\n", localHandles->NumberOfHandles);

    // this traverses all localHandles 3 times and filters for the given type
    // todo optimization: prefilter once and traverse only the correct types
    int procHandles = checkProcHandles(localHandles);
    int threadHandles = checkThreadHandles(localHandles);
    int fileHandles = checkFileHandles(localHandles);

    printf("[*] Found %i process handle(s), %i thread handle(s) and %i file handle(s) in current process.\n",
        procHandles, threadHandles, fileHandles);

    if (localHandles != 0) VirtualFree(localHandles, 0, MEM_RELEASE);

    printf("[*] Print ENTER to exit...\n");
    (void)getchar();

    return 0;
}
