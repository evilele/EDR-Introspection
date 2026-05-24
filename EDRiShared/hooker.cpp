#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <cctype>

std::string get_proc_access_details(DWORD granted) {
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

void print_granted_access(HANDLE h, int pid) {
    PUBLIC_OBJECT_BASIC_INFORMATION obi = {};
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, ObjectBasicInformation, &obi, sizeof(obi), &ret);
    if (st < 0) {
        std::cerr << "[!] Hooker: NtQueryObject failed at pid " << pid << ": 0x" << std::hex << st << "\n";
    }
    else {
		std::string details = get_proc_access_details(obi.GrantedAccess);
        std::cout << "[+] Hooker: GrantedAccess to pid " << pid << ": 0x" << std::hex << obi.GrantedAccess << std::dec << " -> " << details << "\n";
    }
}

// Inject DLL into target process via CreateRemoteThread + LoadLibrary onto DLL path
bool normal_inject(HANDLE hProcess, const std::string& dllPath, bool debug)
{
    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dllPathAddr) {
        std::cerr << "[!] Hooker: VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Allocated memory in target process at " << dllPathAddr << "\n";
    }

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath.c_str(), size, nullptr)) {
        std::cerr << "[!] Hooker: WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Wrote '" << dllPath << "' to target process memory\n";
    }

    // Get LoadLibraryA address
    HMODULE lpModuleHandle = GetModuleHandleA("kernel32.dll");
    if (!lpModuleHandle) {
        std::cerr << "[!] Hooker: GetModuleHandle failed\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(lpModuleHandle, "LoadLibraryA");
    if (!loadLibAddr) {
        std::cerr << "[!] Hooker: GetProcAddress of LoadLibrary failed\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread (start the DLL)
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, dllPathAddr, 0, nullptr);
    DWORD err = GetLastError();
    if (!hThread || err != 0) {
        std::cerr << "[!] Hooker: CreateRemoteThread failed. Error: " << err << "\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Created remote thread in target process\n";
    }

    DWORD wait = WaitForSingleObject(hThread, 10000); // 5 sec timeout for hooks to init
    if (wait == WAIT_TIMEOUT) {
        std::cerr << "[!] Hooker: remote thread did not finish within timeout\n";
        return false;
    }

    // Get exit code (for LoadLibrary, exit code == hModule handle)
    DWORD hModule = 0;
    if (!GetExitCodeThread(hThread, &hModule)) {
        std::cerr << "[!] Hooker: GetExitCodeThread failed. Error: " << GetLastError() << "\n";
        CloseHandle(hThread);
        return false;
    }
    CloseHandle(hThread);
    if (hModule == 0) {
        std::cerr << "[!] Hooker: LoadLibrary() failed: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[*] Hooker: remote routine succeeded, module handle: " << std::hex << hModule << "\n";
    return true;
}

// reflective loader from https://github.com/Reijaff/offensive_c/blob/main/loadlibrary_reflective_dll.c
// reflective loader helper
DWORD64 rva_to_offset(DWORD64 rva, DWORD64 base_address)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base_address;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_address + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    if (rva < section->PointerToRawData) // pointer into PE header area
        return rva;

    for (; section->SizeOfRawData != 0; section++)
    {
        if (rva >= section->VirtualAddress && rva < (section->VirtualAddress + section->SizeOfRawData))
            return rva - section->VirtualAddress + section->PointerToRawData;
    }
    return 0;
}

// reflective loader helper
DWORD64 get_reflective_loader_offset(DWORD64 base_address, LPCSTR ReflectiveLoader_name)
{
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
    IMAGE_DATA_DIRECTORY exports_data_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports_data_directory.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)(base_address + rva_to_offset(exports_data_directory.VirtualAddress, base_address));
    DWORD* functions = (DWORD*)(base_address + rva_to_offset(export_directory->AddressOfFunctions, base_address));
    DWORD* names = (DWORD*)(base_address + rva_to_offset(export_directory->AddressOfNames, base_address));
    WORD* ords = (WORD*)(base_address + rva_to_offset(export_directory->AddressOfNameOrdinals, base_address));

    for (DWORD i = 0; i < export_directory->NumberOfNames; ++i)
    {
        char* name = (char*)(base_address + rva_to_offset(names[i], base_address));
        if (_stricmp(name, ReflectiveLoader_name) == 0) // case-insensitive
        {
            DWORD func_rva = functions[ords[i]];
            return rva_to_offset(func_rva, base_address);
        }
    }
    return 0;
}

// Inject DLL into target process via Reflective DLL Injection
bool reflective_inject(int pid, HANDLE hProcess, const std::string& dllPath, bool debug)
{
    // open dll file
    HANDLE file_handle = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) { printf("[!] Hooker: CreateFile failed: %lu\n", GetLastError()); return false; }
    if (debug)
        printf("[+] Hooker: Injecting DLL '%s' into remote process %lu\n", dllPath.c_str(), pid);

    // get file size
    LARGE_INTEGER fileSize = { 0 };
    if (!GetFileSizeEx(file_handle, &fileSize)) { printf("[!] Hooker: GetFileSizeEx failed: %lu\n", GetLastError()); CloseHandle(file_handle); return false; }
    SIZE_T sz = (SIZE_T)fileSize.QuadPart;
    if (sz == 0) { printf("[!] Hooker: Empty file\n"); CloseHandle(file_handle); return false; }
    if (debug)
        printf("[+] Hooker: DLL size: %llu bytes\n", (unsigned long long)sz);

    // allocate buffer and read
    LPBYTE file_buf = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!file_buf) { printf("[!] Hooker: HeapAlloc failed\n"); CloseHandle(file_handle); return false; }
    DWORD bytesRead = 0;
    if (!ReadFile(file_handle, file_buf, (DWORD)sz, &bytesRead, NULL) || bytesRead != (DWORD)sz) {
        printf("[!] Hooker: ReadFile failed or incomplete: %lu bytesRead=%lu\n", GetLastError(), bytesRead);
        HeapFree(GetProcessHeap(), 0, file_buf); CloseHandle(file_handle); return false;
    }
    CloseHandle(file_handle);
    if (debug)
        printf("[+] Hooker: DLL read into memory\n");

    // find reflective loader offset in raw file
    DWORD64 reflective_loader_offset = get_reflective_loader_offset((DWORD64)file_buf, "ReflectiveLoader");
    if (!reflective_loader_offset) { printf("[!] Hooker: ReflectiveLoader export not found in %s\n", dllPath.c_str()); HeapFree(GetProcessHeap(), 0, file_buf); return false; }
    if (debug)
        printf("[+] Hooker: ReflectiveLoader offset at 0x%p\n", reflective_loader_offset);

    // allocate remote memory (use the file size)
    LPVOID remote_file_buf_address = VirtualAllocEx(hProcess, NULL, sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_file_buf_address) { printf("[!] Hooker: VirtualAllocEx failed in remote proc %lu: %lu\n", pid, GetLastError()); CloseHandle(hProcess); HeapFree(GetProcessHeap(), 0, file_buf); return false; }
    if (debug)
        printf("[+] Hooker: Remote memory allocated at 0x%p\n", remote_file_buf_address);

    // write file into remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_file_buf_address, file_buf, sz, (SIZE_T*)&written) || written != sz) {
        printf("[!] Hooker: WriteProcessMemory failed: %lu written=%llu\n", GetLastError(), (unsigned long long)written);
        VirtualFreeEx(hProcess, remote_file_buf_address, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        HeapFree(GetProcessHeap(), 0, file_buf);
        return false;
    }
    if (debug)
        printf("[+] Hooker: DLL written into remote process memory\n");

    // make memory executable
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, remote_file_buf_address, sz, PAGE_EXECUTE_READ, &oldProt)) {
        // If this fails, try PAGE_EXECUTE_READWRITE (some targets)
        if (!VirtualProtectEx(hProcess, remote_file_buf_address, sz, PAGE_EXECUTE_READWRITE, &oldProt)) {
            printf("[!] Hooker: VirtualProtectEx to RWX failed: %lu\n", GetLastError());
            VirtualFreeEx(hProcess, remote_file_buf_address, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            HeapFree(GetProcessHeap(), 0, file_buf);
			return false;
        }
        if (debug)
            printf("[+] Hooker: Remote memory protection changed to RWX\n");
    }
    if (debug)
        printf("[+] Hooker: Remote memory protection changed to RX\n");

    // compute remote address of reflective loader and create remote thread
    LPTHREAD_START_ROUTINE remote_start = (LPTHREAD_START_ROUTINE)((ULONG_PTR)remote_file_buf_address + (ULONG_PTR)reflective_loader_offset);

    HANDLE thread_handle = CreateRemoteThread(hProcess, NULL, 0, remote_start, NULL, 0, NULL);
    if (!thread_handle) { printf("[!] Hooker: CreateRemoteThread failed: %lu\n", GetLastError()); VirtualFreeEx(hProcess, remote_file_buf_address, 0, MEM_RELEASE); CloseHandle(hProcess); HeapFree(GetProcessHeap(), 0, file_buf); return false; }
    if (debug)
        printf("[+] Hooker: Remote thread created\n");

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    CloseHandle(hProcess);
    HeapFree(GetProcessHeap(), 0, file_buf);

    if (debug)
        printf("[+] Hooker: DllMain successfully exited\n");
    return true;
}

// Preparation for DLL injection
bool inject_dll(int pid, const std::string& dllPath, bool debug, bool reflective) {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE, pid);

    if (!hProcess) {
        std::cerr << "[!] Hooker: Failed to open target process. Error: " << GetLastError() << "\n";
        return false;
    }
    BOOL isWow = FALSE;
    if (IsWow64Process(hProcess, &isWow)) {
        if (isWow) {
            std::cerr << "[!] Hooker: Target process is 32-bit, but this injector is 64-bit. Cannot inject.\n";
            CloseHandle(hProcess);
            return false;
        }
    }
    else {
        std::cerr << "[!] Hooker: IsWow64Process failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    print_granted_access(hProcess, pid);
    if (reflective) {
		return reflective_inject(pid, hProcess, dllPath, debug);
    }
    else {
		return normal_inject(hProcess, dllPath, debug);
    }
}
