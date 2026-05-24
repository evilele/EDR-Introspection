#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <winternl.h>

#include "hooker.h"


HMODULE GetRemoteModuleHandle(DWORD pid, const std::wstring& moduleName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName.c_str()) == 0) {
                CloseHandle(snap);
                return me.hModule;  // remote addr 
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return NULL;
}

int RemoteFreeLibrary(HANDLE hProcess, HMODULE remoteModule) {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel)
        return 1;

    LPVOID freeLibAddr = (LPVOID)GetProcAddress(hKernel, "FreeLibrary");

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)freeLibAddr,
        remoteModule, // must be remote addr of module handle
        0,
        nullptr
    );

    if (!hThread)
        return 1;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 0;
}

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

int unload(int pid, std::string dllName) { // or just use a stopRequest.txt
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 1;

    g_origNtOpenEvent = (PFN_NtOpenEvent)GetProcAddress(ntdll, "NtOpenEvent");
    g_origRtlNtStatusToDosError = (PFN_RtlNtStatusToDosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (g_origNtOpenEvent == nullptr || g_origRtlNtStatusToDosError == nullptr) {
        std::wcerr << L"[!] InjectLoader: Failed to get NtOpenEvent or RtlNtStatusToDosError address.\n";
        return 1;
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
        DWORD winerr = g_origRtlNtStatusToDosError(st);
        std::wcerr << "[!] InjectorLoader: Failt to NtOpenEvent " << eventName << ", WinErr = " << winerr << L"\n";
    }
    else {
        std::wcout << "[-] InjectorLoader: NtOpenEvent " << eventName << " ok, sending stop signal\n";
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }

    Sleep(3000); // wait a bit for cleanup

    HMODULE hMod = GetRemoteModuleHandle(pid, std::wstring(dllName.begin(), dllName.end()));
    if (hMod != NULL) {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        return RemoteFreeLibrary(hProc, hMod);
    }

    return 0;
}

enum Action {
    LOADLIBRARY_INJECTION,
    REFLECTIVE_INJECTION,
    STOP_INJECTION
};

int main(int argc, char* argv[]) {
    int pid = 0;
    std::string dllPath;

    std::string exePath = argv[0];
    std::string exeName = exePath.substr(exePath.find_last_of("\\/") + 1);

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        std::cout << "[*] InjectLoader: Usage: " << exeName << " <DLL Path> <PID> [(L)oadLibrary | (R)eflective | (S)top] [(D)ebug]\n";
        return 0;
    }

    if (argc < 4) {
        std::cout << "[*] InjectLoader: Usage: " << exeName << " <DLL Path> <PID> [(L)oadLibrary | (R)eflective | (S)top] [(D)ebug]\n";
        return 1;
    }

    dllPath = argv[1];
    try {
        pid = std::stoi(argv[2]);
    }
    catch (const std::exception&) {
        std::cerr << "[!] InjectLoader: Invalid PID: " << argv[2] << "\n";
        return 1;
    }

    Action a;
    if (_stricmp(argv[3], "S") == 0 || _stricmp(argv[3], "stop") == 0) {
        a = STOP_INJECTION;
    }
    else if (_stricmp(argv[3], "R") == 0 || _stricmp(argv[3], "reflective") == 0) {
        a = REFLECTIVE_INJECTION;
    }
    else {
        a = LOADLIBRARY_INJECTION;
    }

    if (pid <= 0) {
        std::cerr << "[!] InjectLoader: PID must be a positive integer.\n";
        return 1;
    }
    if (dllPath.empty()) {
        std::cerr << "[!] InjectLoader: DLL path cannot be empty.\n";
        return 1;
    }

    bool debug = false;
    if (argc >= 5 && (_stricmp(argv[4], "D") == 0 || _stricmp(argv[4], "debug") == 0)) {
        std::cout << "[*] InjectLoader: Debug mode enabled.\n";
        debug = true;
    }


    switch (a) {
    case LOADLIBRARY_INJECTION:
        std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using LoadLibrary injection method.\n";
        inject_dll(pid, dllPath, debug, false);
        break;
    case REFLECTIVE_INJECTION:
        std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using Reflective injection method.\n";
        inject_dll(pid, dllPath, debug, true);
        break;
    case STOP_INJECTION:
        std::cout << "[*] InjectLoader: Unloading DLL in " << pid << "\n";
        std::string dllName = dllPath.substr(dllPath.find_last_of("\\/") + 1);
        return unload(pid, dllName);
    }

    return 0;
}
