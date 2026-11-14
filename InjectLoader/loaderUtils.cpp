#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include "loaderUtils.h"

#pragma comment(lib, "ntdll.lib")

#define ProcessHandleInformation 0x33

// Built-in structure for local handle snapshots
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

typedef NTSTATUS(NTAPI* PFN_NtOpenEvent)(
    PHANDLE            EventHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef ULONG(WINAPI* PFN_RtlNtStatusToDosError)(
    NTSTATUS Status
    );

PFN_NtOpenEvent g_origNtOpenEvent = nullptr;
PFN_RtlNtStatusToDosError g_origRtlNtStatusToDosError = nullptr;

// get loaded DLL via snapshot
HMODULE GetRemoteModuleHandle(DWORD pid, const std::string& moduleName) {

    std::wstring wModuleName(moduleName.begin(), moduleName.end());
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, wModuleName.c_str()) == 0) {
                CloseHandle(snap);
                return me.hModule;  // remote addr 
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return NULL;
}

// find manually loaded DLL
HMODULE GetRemoteManualMappedModule(HANDLE hProcess, const std::string& targetDllName) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < maxAddr) {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {

            // PE headers can have any access when manually mapped, just ensure it's not a PAGE_GUARD or NOACCESS page
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD)) {

                IMAGE_DOS_HEADER dosHeader;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, &dosHeader, sizeof(dosHeader), NULL) &&
                    dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {

                    IMAGE_NT_HEADERS ntHeaders;
                    if (ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)mbi.BaseAddress + dosHeader.e_lfanew),
                        &ntHeaders, sizeof(ntHeaders), NULL) &&
                        ntHeaders.Signature == IMAGE_NT_SIGNATURE) {

                        DWORD exportRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                        if (exportRVA != 0) {
                            IMAGE_EXPORT_DIRECTORY exportDir;
                            if (ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)mbi.BaseAddress + exportRVA),
                                &exportDir, sizeof(exportDir), NULL)) {

                                char szInternalName[256] = { 0 };
                                if (ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)mbi.BaseAddress + exportDir.Name),
                                    szInternalName, sizeof(szInternalName) - 1, NULL)) {

                                    if (_stricmp(szInternalName, targetDllName.c_str()) == 0) {
                                        return (HMODULE)mbi.BaseAddress; // Found base address!
                                    }
                                }
                            }
                        }
                    }
                }
            }
            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
        else {
            addr += 0x1000;
        }
    }
    return 0;
}

BOOL UnloadViaThread(DWORD pid, std::string dllName) {
	HMODULE hMod = GetRemoteModuleHandle(pid, dllName);
	if (hMod == NULL) {
		printf("[!] Utils: Failed to get remote module handle.\n");
		return FALSE;
	}

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)FreeLibrary, hMod, 0, nullptr);

    if (!hThread) {
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}

// unload via a global stop signal
BOOL UnloadViaSignal(DWORD pid, std::string dllName) { // or just use a stopRequest.txt
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        printf("[!] Utils: Failed to get ntdll handle.\n");
        return FALSE;
    }

    g_origNtOpenEvent = (PFN_NtOpenEvent)GetProcAddress(ntdll, "NtOpenEvent");
    g_origRtlNtStatusToDosError = (PFN_RtlNtStatusToDosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (g_origNtOpenEvent == nullptr || g_origRtlNtStatusToDosError == nullptr) {
        printf("[!] Utils: Failed to get NtOpenEvent or RtlNtStatusToDosError address.\n");
        return FALSE;
    }

    // build NT name
    wchar_t eventName[128];
    swprintf_s(eventName, _countof(eventName), L"\\BaseNamedObjects\\Hooks_Stop_%lu", (unsigned long)pid);

    // init UNICODE_STRING
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, eventName);

    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hEvent = NULL;
    NTSTATUS st = g_origNtOpenEvent(&hEvent, EVENT_MODIFY_STATE | SYNCHRONIZE, &oa);

    if (!NT_SUCCESS(st)) {
        DWORD err = g_origRtlNtStatusToDosError(st);
        printf("[!] Utils: Failed to NtOpenEvent %ls with error %lx\n", eventName, err);
        return FALSE;
    }

    printf("[-] Utils: Received NtOpenEvent %ls -> sending stop signal\n", eventName);
    SetEvent(hEvent);
    CloseHandle(hEvent);

    Sleep(3000); // wait a bit for cleanup
    return TRUE;
}

HANDLE FindProcHandle(DWORD pid, BOOL debug) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == 0) {
        printf("[!] Utils: Failed to get handle to ntdll.dll\n");
        return 0;
    }

    ULONG bufferSize = 0x4000; // Start with 16KB (plenty for a single local process)
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG returnLength = 0;

    // Query only OUR process handle table
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)ProcessHandleInformation,
        buffer,
        bufferSize,
        &returnLength
    );

    // Resize if needed
    if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessHandleInformation, buffer, bufferSize, &returnLength);
    }

    if (status != 0) {
        printf("[!] Utils: Unable to query handle information of current process.\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;
    if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
        printf("[!] Utils: No handles found in the current process.\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    typedef DWORD(WINAPI* pfnGetProcessId)(HANDLE);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        printf("[!] Utils: Failed to get handle to kernel32.dll\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }
    pfnGetProcessId _GetProcessId = (pfnGetProcessId)GetProcAddress(hKernel32, "GetProcessId");
    if (!_GetProcessId) {
        printf("[!] Utils: Failed to get address of GetProcessId\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    PROCESS_HANDLE_TABLE_ENTRY_INFO potEntry{ 0 };
    for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
        PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];

        // Check if the handle is a process handle
        DWORD targetPid = _GetProcessId(entry.HandleValue);
        if (targetPid == pid) {
            if (debug) {
                printf("[+] Utils: Proc handle found ID=0x%p, PID=%lu, Access=0x%08X\n", entry.HandleValue, targetPid, entry.GrantedAccess);
            }
            if (entry.GrantedAccess != PROCESS_ALL_ACCESS) {
				potEntry = entry; // safe as potential candidate, but not full access
            }
            if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
            return entry.HandleValue;
        }

        // check potential candidates
        if (potEntry.GrantedAccess != 0) {
            printf("[!] Utils: Warning: Handle to pid=%i found but limited access 0x%08X\n", pid, entry.GrantedAccess);
            printf("[+] Utils: Continue searching? Y/n");
            int c = getchar();
            if (c == 'n') {
                if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
                return entry.HandleValue;
            }
            else {
                // continue searching
            }
        }
    }
    printf("[!] Utils: No process handles found in the current process.\n");
    if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

std::string GetProcAccessDetails(DWORD granted) {
    struct { DWORD mask; const char* name; } flags[] = {
        {0x0001, "PROCESS_TERMINATE"},
        {0x0002, "PROCESS_CREATE_THREAD"},
        {0x0004, "PROCESS_SET_SESSIONID"},
        {0x0008, "PROCESS_VM_OPERATION"},
        {0x0010, "PROCESS_VM_READ"},
        {0x0020, "PROCESS_VM_WRITE"},
        {0x0040, "PROCESS_DUP_HANDLE"},
        {0x0080, "PROCESS_CREATE_PROCESS"},
        {0x0100, "PROCESS_SET_QUOTA"},
        {0x0200, "PROCESS_SET_INFORMATION"},
        {0x0400, "PROCESS_QUERY_INFORMATION"},
        {0x0800, "PROCESS_SUSPEND_RESUME"},
        {0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"},
        {0x2000, "PROCESS_SET_LIMITED_INFORMATION"}
    };

    std::string access = "";
    for (auto& f : flags) {
        if (granted & f.mask) {
            access += std::string(f.name) + " | ";
        }
    }
    if (!access.empty()) {
        access = access.substr(0, access.size() - 3); // remove last " | "
    }
    else {
        return "no access";
    }
    std::string no_access = "";
    for (auto& f : flags) {
        if (!(granted & f.mask)) {
            no_access += std::string(f.name) + " | ";
        }
    }
    if (!no_access.empty()) {
        no_access = no_access.substr(0, no_access.size() - 3); // remove last " | "
    }
    else {
        return "full access";
    }
    return access + ", not including: " + no_access;
}

void PrintGrantedAccess(HANDLE h, DWORD pid) {
    PUBLIC_OBJECT_BASIC_INFORMATION obi = {};
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, ObjectBasicInformation, &obi, sizeof(obi), &ret);
    if (st < 0) {
        printf("[!] Utils: NtQueryObject failed at pid=%i with status 0x%lx", pid, st);
    }
    else {
        std::string details = GetProcAccessDetails(obi.GrantedAccess);
        printf("[+] Utils: GrantedAccess to pid=%i: 0x%lx %s\n", pid, obi.GrantedAccess, details.c_str());
    }
}

// get (first) child process id of a given parent process handle
DWORD GetChildProcessId(HANDLE hParentProcess) {

    // 1. Get the Process ID from the parent handle
    // Note: hParentProcess requires PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access
    DWORD parentPid = GetProcessId(hParentProcess);
    if (parentPid == 0) {
        printf("[!] GetProcessId failed. Error: %lu\n", GetLastError());
        return 0;
    }

    // 2. Take a snapshot of all current processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 3. Iterate through processes and collect those with matching parent PID
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ParentProcessID == parentPid) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    // 4. Clean up the snapshot handle
    CloseHandle(hSnapshot);
    return 0;
}