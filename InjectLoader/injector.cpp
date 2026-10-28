#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <fstream>
#include <cctype>
#include <vector>

#include "injector.h"
#include "loaderUtils.h"

// ------------------------ Paxai/DLLium ------------------------ //
typedef HMODULE(WINAPI* f_LoadLibraryA)(const char* lpLibFileName);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, const char* lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);
typedef BOOLEAN(WINAPI* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

// uint32t bc shared memory standard ABI something somthing
enum ShellcodeResult : uint32_t { 
    scPending,
    scInvalidDllBase,
    scRtlFailed,
    scLoadLibraryError, // unable to LoadLibrary a dependent DLL
    scGetProcAddrOrdinalError, // unable to GetProcessAddress of an ordinal IAT entry
    scGetProcAddrNameError, // unable to GetProcessAddress of an named IAT entry
    scExecuting, // this means the shellcode loader is executing, not the DLL yet
    scNoEntrypointFound,
    scDllMainFailed,
    scDllMainSuccessful
};

struct ShellcodeData {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    f_RtlAddFunctionTable pRtlAddFunctionTable;

    uintptr_t pDllBase;
    uintptr_t EntryPoint;

    uintptr_t RelocDir;
    uintptr_t ImportDir;
    uintptr_t ExceptionDir;
    uintptr_t ExceptionSize;
    uintptr_t TLSDir;

    uint32_t Result;
    uintptr_t DllFailed;
    uintptr_t IATNameFailed;
    uint32_t IATOrdinalFailed;
    uint32_t RtlFailed;

    BOOL YoloMode;
    uint64_t YoloWait;
};

// this should result in a wait that's a bit longer than msSleepBetweenPolls
uint64_t yoloBusyWait = 300'000'000; // for _ in wait; this is placed in PIC

// Define a custom section set to calc shellcodeSize
#pragma section(".sc$a", read, execute)
#pragma section(".sc$b", read, execute)
#pragma section(".sc$c", read, execute)

// Place start marker in .sc$a
__declspec(allocate(".sc$a")) const unsigned char g_ShellcodeStartMarker = 'A';

// Place the function in .sc$b
__declspec(code_seg(".sc$b"))
// DLLium's remote dll loading shellcode (executed in remote proc)
__declspec(noinline) void __stdcall UniversalDllLoadingShellcode(ShellcodeData* pData) { // should be ABI compatible with PAPCFUNC (QueueAPC)
    if (!pData) { 
        return; // well I tried
    }

    if (!pData->pDllBase) {
        pData->Result = ShellcodeResult::scInvalidDllBase;
        return; // only now we can set an actual error
    }

    pData->Result = ShellcodeResult::scExecuting;
    uintptr_t pBase = pData->pDllBase;

    if (pData->ImportDir) {
        auto* pImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pData->ImportDir);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HMODULE hMod = pData->pLoadLibraryA(szMod);
            if (!hMod) { // failed to load a module, report error
                if (szMod) {
                    pData->DllFailed = (uintptr_t)szMod;
                }
                else if ((uintptr_t)pImportDescr->Name) {
                    pData->DllFailed = (uintptr_t)pImportDescr->Name;
                }
                else {
                    pData->DllFailed = (uintptr_t)"<invalid dll import dir - fix your dll>";
                }
                if (!pData->YoloMode) {
                    pData->Result = ShellcodeResult::scLoadLibraryError;
                    return; // no risk
                }
                else { // ignore error but busy wait for at least one read
                    pImportDescr++;
                    volatile uint64_t x = 0; for (uint64_t i = 0; i < pData->YoloWait; i++) { x += i; }
                    continue; // and try loading the next dll, skip this one
                }
            }

            auto* pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDescr->FirstThunk);

            PIMAGE_THUNK_DATA pThunk = pIAT;
            if (pImportDescr->OriginalFirstThunk) {
                pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDescr->OriginalFirstThunk);
            }

            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pIAT->u1.Function = (uintptr_t)pData->pGetProcAddress(hMod, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
                    if (!pIAT->u1.Function) {
                        pData->DllFailed = reinterpret_cast<uintptr_t>(szMod);
                        pData->IATOrdinalFailed = (uint32_t)(pThunk->u1.Ordinal & 0xFFFF);
                        if (!pData->YoloMode) {
                            pData->Result = ShellcodeResult::scGetProcAddrOrdinalError;
                            return; // no risk
                        }
                        else { // ignore error but busy wait for at least one read
                            volatile uint64_t x = 0; for (uint64_t i = 0; i < pData->YoloWait; i++) { x += i; }
                        }
                    }
                }
                else {
                    auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pThunk->u1.AddressOfData);
                    pIAT->u1.Function = (uintptr_t)pData->pGetProcAddress(hMod, pImportByName->Name);
                    if (!pIAT->u1.Function) {
                        pData->DllFailed = reinterpret_cast<uintptr_t>(szMod);
                        pData->IATNameFailed = (uintptr_t)pImportByName->Name;
                        if (!pData->YoloMode) {
                            pData->Result = ShellcodeResult::scGetProcAddrNameError;
                            return; // no risk
                        }
                        else { // ignore error but busy wait for at least one read
                            volatile uint64_t x = 0; for (uint64_t i = 0; i < pData->YoloWait; i++) { x += i; }
                        }
                    }
                }
                pThunk++;
                pIAT++;
            }
            pImportDescr++;
        }
    }

    if (pData->TLSDir) {
        auto* pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBase + pData->TLSDir);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        if (pCallback) {
            while (*pCallback) {
                (*pCallback)(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr);
                pCallback++;
            }
        }
    }

    if (pData->pRtlAddFunctionTable && pData->ExceptionDir && pData->ExceptionSize) {
        auto* pFuncTable = reinterpret_cast<PRUNTIME_FUNCTION>(pBase + pData->ExceptionDir);
        DWORD count = (DWORD)(pData->ExceptionSize / sizeof(RUNTIME_FUNCTION));
        if (!pData->pRtlAddFunctionTable(pFuncTable, count, (DWORD64)pBase)) {
            pData->RtlFailed = 1;
            if (!pData->YoloMode) {
                pData->Result = ShellcodeResult::scRtlFailed;
                return; // no risk
            }
            else { // ignore error but busy wait for at least one read
                volatile uint64_t x = 0; for (uint64_t i = 0; i < pData->YoloWait; i++) { x += i; }
            }
        }
    }

    if (pData->EntryPoint) {
        auto fEntrypoint = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pData->EntryPoint);
        if (fEntrypoint(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr)) {
            // success, pData->pDllBase points to the loaded DLL
            pData->Result = ShellcodeResult::scDllMainSuccessful;
            return;
        }
        // entrypoint returned false
        pData->Result = ShellcodeResult::scDllMainFailed;
        return;
    }

    // no Entrypoint found and called, just mapped and ready
    pData->Result = ShellcodeResult::scNoEntrypointFound;
    return;
}

// Place end marker in .sc$c
__declspec(allocate(".sc$c")) const unsigned char g_ShellcodeEndMarker = 'C';

size_t GetUniversalShellcodeSize() {
    return (uintptr_t)&g_ShellcodeEndMarker - (uintptr_t)&g_ShellcodeStartMarker;
}

static void* ResolveFunction(void* ptr) {
    if (!ptr) return nullptr;

    unsigned char* b = static_cast<unsigned char*>(ptr);

    // Loop up to 10 times to resolve chained/nested thunks
    for (int i = 0; i < 10; ++i) {
        // 1. Standard 5-byte Relative JMP: E9 xx xx xx xx
        if (b[0] == 0xE9) {
            int32_t rel = *reinterpret_cast<int32_t*>(b + 1);
            b = b + 5 + rel;
            continue;
        }

        // 2. Short Relative JMP: EB xx
        if (b[0] == 0xEB) {
            int8_t rel = *reinterpret_cast<int8_t*>(b + 1);
            b = b + 2 + rel;
            continue;
        }

        // 3. RIP-Relative Indirect JMP without REX prefix: FF 25 xx xx xx xx (6 bytes)
        if (b[0] == 0xFF && b[1] == 0x25) {
            int32_t disp = *reinterpret_cast<int32_t*>(b + 2);
            void** target = reinterpret_cast<void**>(b + 6 + disp);
            if (!target || !*target) break;
            b = static_cast<unsigned char*>(*target);
            continue;
        }

        // 4. RIP-Relative Indirect JMP with REX.W prefix: 48 FF 25 xx xx xx xx (7 bytes)
        if (b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25) {
            int32_t disp = *reinterpret_cast<int32_t*>(b + 3);
            void** target = reinterpret_cast<void**>(b + 7 + disp);
            if (!target || !*target) break;
            b = static_cast<unsigned char*>(*target);
            continue;
        }

        // No more thunks/jumps detected -> 'b' is the true function entry point!
        break;
    }

    return static_cast<void*>(b);
}

// ------------------------ GuidedHacking ------------------------ //
#ifndef QUEUE_USER_APC_SPECIAL_USER_APC
#define QUEUE_USER_APC_SPECIAL_USER_APC 0x00000001
#endif

enum class BOOTSTRAP_STATE : ULONG_PTR {
    BS_PENDING = 0,
    BS_EXECUTING = 1,
    BS_FINISHED = 2
};

using f_Routine = DWORD(__fastcall*)(void* pArg);

#define ALIGN __declspec(align(8))

ALIGN struct BootstrapData {
    ALIGN BOOTSTRAP_STATE    State = BOOTSTRAP_STATE::BS_PENDING;
    ALIGN DWORD              Ret = 0;
    ALIGN DWORD              LastWin32Error = 0;
    ALIGN void*              pArg = nullptr;
    ALIGN f_Routine          pRoutine = nullptr;
    ALIGN UINT_PTR           Buffer = 0;
};

// Space reserved for SR_REMOTE_DATA (sizeof X void pointers, see above)
#define VOID_PTR_BUFFER 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#define SR_REMOTE_DATA_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER

#define ProcessHandleInformation 51 // handles in current proc
#define SystemProcessInformation 5  // handles in all procs

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

#define ThreadBasicInformation 0

typedef struct _CLIENT_ID_NATIVE {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_NATIVE, * PCLIENT_ID_NATIVE;

typedef struct _THREAD_BASIC_INFORMATION_NATIVE {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID_NATIVE ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION_NATIVE, * PTHREAD_BASIC_INFORMATION_NATIVE;

// ------------------------ Reijaff/reflective_dll.c ------------------------ //
DWORD64 RvaToOffset(DWORD64 rva, DWORD64 base_address) {
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

DWORD64 GetReflectiveLoaderOffset(DWORD64 base_address, LPCSTR ReflectiveLoader_name) {
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
    IMAGE_DATA_DIRECTORY exports_data_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports_data_directory.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)(base_address + RvaToOffset(exports_data_directory.VirtualAddress, base_address));
    DWORD* functions = (DWORD*)(base_address + RvaToOffset(export_directory->AddressOfFunctions, base_address));
    DWORD* names = (DWORD*)(base_address + RvaToOffset(export_directory->AddressOfNames, base_address));
    WORD* ords = (WORD*)(base_address + RvaToOffset(export_directory->AddressOfNameOrdinals, base_address));

    for (DWORD i = 0; i < export_directory->NumberOfNames; ++i)
    {
        char* name = (char*)(base_address + RvaToOffset(names[i], base_address));
        if (_stricmp(name, ReflectiveLoader_name) == 0) // case-insensitive
        {
            DWORD func_rva = functions[ords[i]];
            return RvaToOffset(func_rva, base_address);
        }
    }
    return 0;
}

// ------------------------ my helpers ------------------------ //
int msMaxWaitForExecutor = 60000; // 1min
int msSleepBetweenPolls = 50;
int msBetweenStatusUpdates = 5000; // 5sec
int loopsBetweenStatusUpdates = msBetweenStatusUpdates / msSleepBetweenPolls;

std::string GetInjectTypeStr(Injection injectType) {
    switch (injectType) {
    case LOADLIBRARY_INJECTION: return "LoadLibrary injection";
    case HOSTMAPPED_INJECTION: return "HostMapped+Shellcode injection";
    case REFLECTIVE_INJECTION: return "ReflectiveSelfLoader injection";
    default: return "Unknown inject type";
    }
}

std::string GetExecutorTypeStr(Executor execType) {
    switch (execType) {
    case CREATE_REMOTE_THREAD: return "CreateRemoteThread";
    case HIJACK_THREAD: return "HijackThread";
    case QUEUE_USER_APC2: return "QueueUserAPC2";
    case THREADLESS_INJECTION: return "Threadless";
    default: return "unknown execute type";
    }
}

enum LOADER_RET {
    failed,
    successful,
    timeout
};

// ----------------------- thread hijacking ----------------------- //
#define ThreadSystemThreadInformation 40

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

// Standard KWAIT_REASON enumeration from Ntddk.h
typedef enum _KWAIT_REASON {
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,      // Sleep() / ExecutionDelay
    Suspended = 5,
    UserRequest = 6,         // WaitForSingleObject
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,      // Win32 Message Pump (win32k)
    WrQueue = 19             // ThreadPool / IOCP Queue
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION_LITE {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID_NATIVE ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState; // 5 = Waiting
    KWAIT_REASON WaitReason;  // 8 = UserRequest
} SYSTEM_THREAD_INFORMATION_LITE, * PSYSTEM_THREAD_INFORMATION_LITE;

typedef int (*ThreadScoreEvaluator)(ULONG threadState, KWAIT_REASON waitReason);

// Scoring logic specifically for Thread Hijacking (SuspendThread + SetThreadContext)
int EvaluateThreadScoreForHijacking(ULONG threadState, KWAIT_REASON waitReason) {
    // State 5 = Waiting (Safe to suspend and modify register context)
    if (threadState == 5) {
        switch (waitReason) {
        case DelayExecution:
        case WrDelayExecution:
            return 100; // Safest (Timer guaranteed to expire)

        case WrUserRequest:
            return 80;  // GUI Message loop

        case WrQueue:
            return 60;  // ThreadPool worker

        case UserRequest:
        case Executive:
        case WrExecutive:
            return 40;  // Risky (May wait on INFINITE handle)

        default:
            return 20;
        }
    }
    // State 2 = Running, State 1 = Ready
    else if (threadState == 2 || threadState == 1) {
        return 10; // Reckless for hijacking (Risk of corrupting active execution state)
    }

    return 0;
}

// Scoring logic specifically for QueueUserAPC / Special User APCs
int EvaluateThreadScoreForQueueAPC2(ULONG threadState, KWAIT_REASON waitReason) {
    // State 2 = Running, State 1 = Ready -> active threads frequently make user/kernel transitions, triggering APCs quickly
    if (threadState == 2 || threadState == 1) {
        return 100;
    }

    // State 5 = Waiting
    if (threadState == 5) {
        switch (waitReason) {
        case WrUserRequest:
            return 80; // GUI message loops process APCs quickly

        case WrQueue:
            return 70; // ThreadPool workers wake frequently for work items

        case DelayExecution:
        case WrDelayExecution:
            return 30; // Risky: May sit in a long non-alertable Sleep()

        case UserRequest:
        case Executive:
        case WrExecutive:
            return 10; // High Risk: May be blocked on a non-alertable INFINITE kernel handle

        default:
            return 20;
        }
    }

    return 0;
}


OPTIMAL_THREAD nullOptThread = { NULL, 0, NULL_EXECUTOR };

// Unified thread selection function
OPTIMAL_THREAD FindOptimalThread(const std::vector<HANDLE>& hThreads, Executor execType, bool yoloMode, bool debug) {

    // make sure this exec type makes sense
    ThreadScoreEvaluator EvaluateScore = nullptr;
    switch (execType) {
    case Executor::HIJACK_THREAD:
        EvaluateScore = EvaluateThreadScoreForHijacking;
        break;
    case Executor::QUEUE_USER_APC2:
        EvaluateScore = EvaluateThreadScoreForQueueAPC2;
        break;
    default:
        printf("[!] Injector-Thread: FindOptimalThread not implemented for %s\n", GetExecutorTypeStr(execType).c_str());
        return nullOptThread;
    }

    HANDLE hBestThread = NULL;
    int bestThreadScore = -1;

    HANDLE hThreadMaxCpuTime = NULL;
    ULONGLONG maxCpuTime = 0;

    for (HANDLE hThread : hThreads) {
        SYSTEM_THREAD_INFORMATION_LITE threadInfo = { 0 };
        ULONG returnLength = 0;

        NTSTATUS status = NtQueryInformationThread(
            hThread,
            (THREADINFOCLASS)ThreadSystemThreadInformation,
            &threadInfo,
            sizeof(threadInfo),
            &returnLength
        );

        if (status == 0) { // STATUS_SUCCESS
            ULONGLONG cpuTime = threadInfo.KernelTime.QuadPart + threadInfo.UserTime.QuadPart;
            int score = EvaluateScore(threadInfo.ThreadState, threadInfo.WaitReason);

            if (score > bestThreadScore || (score == bestThreadScore && cpuTime > maxCpuTime)) {
                hBestThread = hThread;
                bestThreadScore = score;
            }

            if (cpuTime > maxCpuTime) {
                hThreadMaxCpuTime = hThread;
                maxCpuTime = cpuTime;
            }
        }
    }

    if (debug && hBestThread != NULL) {
        printf("[+] Injector-Thread: Best thread for %s is tid=%i with score %d\n", GetExecutorTypeStr(execType).c_str(), GetThreadId(hBestThread), bestThreadScore);
    }
    if (hBestThread != NULL && bestThreadScore < 50) {
        printf("[-] Injector-Thread: Warning, no perfectly suitable thread found.");
        if (yoloMode) {
            printf(" Still continuing with the risk of a crash!\n");
            return { hBestThread, bestThreadScore, execType };
        }
        else {
            printf(" Not continuing the injection, use RiskInstability to override!\n");
            return nullOptThread;
        }
    }

    return { hBestThread, bestThreadScore, execType };
}

BOOL CheckThreadHandleAccess(HANDLE hThread) {
    if (!hThread || hThread == INVALID_HANDLE_VALUE) return FALSE;

    PUBLIC_OBJECT_BASIC_INFORMATION basicInfo = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryObject(
        hThread,
        ObjectBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength
    );

    if (status == 0) { // STATUS_SUCCESS
        return (basicInfo.GrantedAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS;
    }

    return FALSE;
}

// get McFullAccess mit Hendle
OPTIMAL_THREAD GetThreadForExecutor(DWORD targetProcessId, Executor exec, bool yoloMode, bool debug) {

    if (debug)
        printf("[+] Injector-Thread: Trying to get optimal thread handle to the remote process pid=%i for %s\n", targetProcessId, GetExecutorTypeStr(exec).c_str());

    ULONG bufferSize = 0x4000;
    ULONG returnLength = 0;
    NTSTATUS status = NULL;

    PVOID sysInfoBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (sysInfoBuffer == 0) {
        printf("[!] Injector-Thread: Cannot allocate mem for query information buffer\n");
        return nullOptThread;
    }

    PVOID procBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (procBuffer == 0) {
        printf("[!] Injector-Thread: Cannot allocate mem for query information buffers\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        return nullOptThread;
    }

    // 1. Get the System Process/Thread info buffer first to verify states
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, sysInfoBuffer, bufferSize, &returnLength);
    if (status == 0xC0000004) { // Length mismatch
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        sysInfoBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, sysInfoBuffer, bufferSize, &returnLength);
    }
    if (status != 0) {
        printf("[!] Injector-Thread: Cannot read SystemProcessInformation to find threads\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        return nullOptThread;
    }

    // 2. Query our internal process handle table
    status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessHandleInformation, procBuffer, bufferSize, &returnLength);
    if (status == 0xC0000004) { // Length mismatch
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        procBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessHandleInformation, procBuffer, bufferSize, &returnLength);
    }
    if (status != 0) {
        printf("[!] Injector-Thread: Cannot read ProcessHandleInformation to find threads\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        return nullOptThread;
    }

    auto* localHandles = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(procBuffer);
    if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
        printf("[!] Injector-Thread: No handles found in current process\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        return nullOptThread;
    }

    std::vector<HANDLE> hThreads; // contains open thread handles to remote threads with full access

    // 3. check if any thread handle from the remote proc is in the current process
    PSYSTEM_PROCESS_INFORMATION iterProc = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(sysInfoBuffer);
    while (iterProc != nullptr) {

        if (reinterpret_cast<uintptr_t>(iterProc->UniqueProcessId) == targetProcessId) {

            if (debug)
                printf("[+] Injector-Thread: Got remote process information, traversing the remote processes threads...\n");

            PSYSTEM_THREAD_INFORMATION threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(
                reinterpret_cast<uintptr_t>(iterProc) + sizeof(SYSTEM_PROCESS_INFORMATION)
                );

            // traverse remote threads
            for (ULONG t = 0; t < iterProc->NumberOfThreads; ++t) {
                DWORD remoteTID = static_cast<DWORD>(reinterpret_cast<uintptr_t>(threads[t].ClientId.UniqueThread));

                // check if the local proc has handles to the remote threads -> traverse all local handles
                for (ULONG_PTR l = 0; l < localHandles->NumberOfHandles; l++) {
                    PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[l];
                    HANDLE hThreadLocal = reinterpret_cast<HANDLE>(entry.HandleValue);

                    DWORD localTID = GetThreadId(hThreadLocal); // check if this is a thread handle
                    if (localTID == 0 || entry.GrantedAccess != THREAD_ALL_ACCESS) continue;

                    if (remoteTID == localTID) {
                        hThreads.push_back(hThreadLocal);
                        if (debug)
                            printf("[+] Injector-Thread: Found a handle of thread tid=%i of remote process pid=%i in current process with full access\n", localTID, targetProcessId);
                    }
                }

                if (debug && hThreads.empty())
                    printf("[-] Injector-Thread: Found no existing thread handles of remote process pid=%i in current process, now trying with OpenThread...\n", targetProcessId);

                // fallback: check if the local proc can open any remote thread with full access
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, remoteTID);
                if (hThread && 
                    (std::find(hThreads.begin(), hThreads.end(), hThread) == hThreads.end()) && // do not re-add existing handles
                    CheckThreadHandleAccess(hThread) // and make sure handle has sufficient access
                ) {
                    hThreads.push_back(hThread);
                    if (debug)
                        printf("[+] Injector-Thread: Remote thread tid=%i can be opened from the current proc with full access\n", remoteTID);
                }
            }
            break; // found target pid, but no thread handles
        }

        // advance to the next process
        iterProc = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<uintptr_t>(iterProc) + iterProc->NextEntryOffset);
    }

    if (sysInfoBuffer) VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
    if (procBuffer) VirtualFree(procBuffer, 0, MEM_RELEASE);

    if (hThreads.empty()) {
        if (debug)
            printf("[!] Injector-Thread: No thread handles of remote process pid=%i could be found or opened with full access\n", targetProcessId);
        return nullOptThread;
    }

    // return the optimal for the given exec
    return FindOptimalThread(hThreads, exec, yoloMode, debug);
}

/*
* cleanly hijack a thread (hopefully)
* 1. get a thread, suspend it and store the old RIP
* 2. define setup shellcode for clean prologue and epilogue
* 3. patch the setup shellcode with the old RIP (to continue at old context) and the remote routine (to be executed) with its args
* 4. write the patched shellcode to the remote process
* 5. set the RIP to the new setup shellcode and resume the thread
* 6. read back the memory to check if the execution was successful
*/
// https://github.com/guidedhacking/GuidedHacking-Injector/blob/e3c6eab04943b10881a7039dc27ff964c79fcb64/GH%20Injector%20Library/Thread%20Hijacking.cpp#L10
LOADER_RET HijackThread(HANDLE hProcess, HANDLE hThread, LPVOID pRemoteRoutine, LPVOID pRemoteArgs, bool debug) {

    // Suspend the target thread to safely modify its state
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] Injector-Hijack: SuspendThread failed for thread tid=%i: %lu\n", GetThreadId(hThread), GetLastError());
        CloseHandle(hThread);
        return failed;
    }
    if (debug)
        printf("[+] Injector-Hijack: Suspended thread tid=%i\n", GetThreadId(hThread));

    // Capture the current register state (specifically RIP) of the thread
    CONTEXT threadContext{ 0 };
    threadContext.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &threadContext)) {
        printf("[!] Injector-Hijack: GetThreadContext failed for thread tid=%i: %lu\n", GetThreadId(hThread), GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return failed;
    }

    // x64 remote Shellcode bootstrap stub
    BYTE BootstrapShellcode[] =
    {
        SR_REMOTE_DATA_BUFFER

        // =========================================================================
        // PHASE 1: Original Thread Context Staging
        // push rax and patch old rip into rax,  and at the end pop and jump to it.
        // =========================================================================
        0x50,                                                                   // [0x00] push rax (save RAX before saving OldRIP to stack)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // [0x01] mov rax, OldRIP (Patched dynamically)

        // =========================================================================
        // PHASE 2: Register & CPU State Preservation
        // Saves volatile registers, flags, and non-volatile RBX to preserve the thread's
        // exact state prior to hijacking.
        // =========================================================================
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       // [0x0B] push volatile regs (RAX with OldRIP, RCX, RDX, R8-R11)
        0x9C,                                                                   // [0x16] pushfq (Push CPU flags)
        0x53,                                                                   // [0x17] push rbx

        // =========================================================================
        // PHASE 3: Data Structure Resolution & Execution Status Update
        // Calculates RIP-relative pointer to BootstrapData and updates state to "EXECUTING".
        // =========================================================================
        0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,                               // [0x18] lea rbx, [BootstrapData] (Patched dynamically)
        0xC6, 0x03, 0x01,                                                       // [0x1F] mov byte ptr [rbx], 1 (BOOTSTRAP_STATE = EXECUTING)

        // =========================================================================
        // PHASE 4: Win64 ABI Stack Alignment & Argument Setup
        // Establishes a frame pointer, enforces 16-byte stack alignment required by 
        // x64 calling convention, loads RCX (1st argument), and allocates 32-byte shadow space.
        // =========================================================================
        0x55,                                                                   // [0x22] push rbp
        0x48, 0x8B, 0xEC,                                                       // [0x23] mov rbp, rsp
        0x48, 0x83, 0xE4, 0xF0,                                                 // [0x26] and rsp, -0x10 (16-byte align RSP)
        0x48, 0x8B, 0x4B, 0x18,                                                 // [0x2A] mov rcx, [rbx + 0x18] (Load BootstrapData::pArg into RCX)
        0x48, 0x83, 0xEC, 0x28,                                                 // [0x2E] sub rsp, 0x28 (Reserve shadow space)

        // =========================================================================
        // PHASE 5: Call pRoutine
        // movs BootstrapData::pRoutine function and calls it (WHAT THIS EVEN DO?)
        // =========================================================================
        0x48, 0x8D, 0x05, 0x0D, 0x00, 0x00, 0x00,                               // [0x32] lea rax, [rip + 0x0D] (Point to 'add rsp, 0x20')
        0x50,                                                                   // [0x39] push rax (Push real return address)
        0x48, 0x8B, 0x43, 0x20,                                                 // [0x3A] mov rax, [rbx + 0x20] (get BootstrapData::pRoutine)
        0xFF, 0xD0,                                                             // [0x3E] call rax (call BootstrapData::pRoutine and return to 0x40)


        // =========================================================================
        // PHASE 6: Post-Execution Cleanup & Return Value Capture
        // Cleans up shadow space and saves BootstrapData::pRoutine's return value (RAX).
        // =========================================================================
        0x48, 0x83, 0xC4, 0x20,                                                 // [0x40] add rsp, 0x20 (Clean shadow space)
        0x48, 0x89, 0x43, 0x08,                                                 // [0x44] mov [rbx + 0x08], rax (Store ReturnValue in BootstrapData::Ret)
        0x48, 0x8B, 0xE5,                                                       // [0x48] mov rsp, rbp (Restore RSP)
        0x5D,                                                                   // [0x4B] pop rbp

        // =========================================================================
        // PHASE 7: Thread Environment Capture & Completion Signaling
        // Fetches GetLastError via TEB (GS:[0x30] -> offset 0x68) and marks state as "Finished".
        // =========================================================================
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,                   // [0x4C] mov rax, gs:[0x30] (TEB pointer)
        0x8B, 0x40, 0x68,                                                       // [0x55] mov eax, [rax + 0x68] (TEB.LastErrorValue)
        0x89, 0x43, 0x10,                                                       // [0x58] mov [rbx + 0x10], eax (Store LastWin32Error)
        0xC6, 0x03, 0x02,                                                       // [0x5A] mov byte ptr [rbx], 2 (BOOTSTRAP_STATE = Finished)

        // =========================================================================
        // PHASE 8: Register Restoration & Thread Execution Resume
        // Restores original thread registers in reverse order. The final RET pops
        // OldRIP (pushed in Phase 1) back into RIP to seamlessly resume original execution.
        // =========================================================================
        0x5B,                                                                   // [0x5E] pop rbx
        0x9D,                                                                   // [0x5F] popfq (Restore flags)
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,       // [0x60] pop volatile regs (R11-R8, RDX, RCX, RAX)
        0x48, 0x83, 0xC4, 0x08,                                                 // [0x6B] add rsp, 0x08 (restore old RSP, ret would do the same to RSP)
        0xFF, 0x64, 0x24, 0x08                                                  // [0x70] jmp [rsp+8] (same as ret would, or is it -8)
    };

    size_t ripOffsetInBootstrap = sizeof(BootstrapData) + 0x03; // mov(2) XX XX XX XX XX XX XX XX

    // Patch the old RIP into the shellcode return sequence (right after SR_REMOTE_DATA)
    DWORD64 OldRIP = threadContext.Rip;
    *reinterpret_cast<DWORD64*>(BootstrapShellcode + ripOffsetInBootstrap) = OldRIP;

    // Patch the LEA instruction, loading the BootstrapData into rbx
    size_t leaOpcodeOffset = sizeof(BootstrapData) + 0x18; // Start of LEA in shellcode
    size_t leaOpcodePrefixSize = 0x03;                     // lea(3) XX XX XX XX
    size_t leaOpcodeSize = 0x07;
    size_t leaEndOffset = leaOpcodeOffset + leaOpcodeSize;
    int32_t relativeOffset = (int32_t)(0 - leaEndOffset);  // Target address relative to LEA end (BootstrapData sits at offset 0)
    // Patch the actual displacement (where the 4-byte offset lives)
    *reinterpret_cast<int32_t*>(BootstrapShellcode + leaOpcodeOffset + leaOpcodePrefixSize) = relativeOffset;

    // Initialize arguments inside BootstrapShellcode to point to (future) remote shellcode
    auto* sr_data = reinterpret_cast<BootstrapData*>(BootstrapShellcode); // get the head (start) of the shellcode as SR_REMOTE_DATA struct
    sr_data->pRoutine = (f_Routine)pRemoteRoutine;                        // the DLLium (dll loading) shellcode
    sr_data->pArg = pRemoteArgs;                                          // the required data by DLLium to load the dll

    // Allocate space for bootstrap shellcode and data structure into remote proc
    void* pRemoteBootstrapShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(BootstrapShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // needs Execute
    if (!pRemoteBootstrapShellcode) {
        printf("[!] Injector-Hijack: VirtualAllocEx failed for BootstrapShellcode: %lu\n", GetLastError());
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        return failed;
    }
    if (debug)
        printf("[+] Injector-Hijack: Allocated memory for BootstrapShellcode at 0x%p in remote process\n", pRemoteBootstrapShellcode);

    // now write the finished BootstrapShellcode to the remote proc
    if (!WriteProcessMemory(hProcess, pRemoteBootstrapShellcode, BootstrapShellcode, sizeof(BootstrapShellcode), nullptr)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        printf("[!] Injector-Hijack: WriteProcessMemory failed for BootstrapShellcode: %lu\n", GetLastError());
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        return failed;
    }
    if (debug)
        printf("[+] Injector-Hijack: Updated pointers in BootstrapShellcode and written it to remote process\n");

    // Redirect the thread's instruction pointer to point to our newly allocated shellcode
    void* pRemoteStartOfBootstrapShellcodeFunc = reinterpret_cast<BYTE*>(pRemoteBootstrapShellcode) + sizeof(BootstrapData);
    threadContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteStartOfBootstrapShellcodeFunc);

    if (!SetThreadContext(hThread, &threadContext)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        printf("[!] Injector-Hijack: SetThreadContext failed for thread %p: %lu\n", hThread, GetLastError());
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        return failed;
    }
    if (debug)
        printf("[+] Injector-Hijack: SetThreadContext to RemoteStartOfBootstrapShellcodeFunc at 0x%p\n", pRemoteStartOfBootstrapShellcodeFunc);

    // Resume the thread to execute the payload
    ResumeThread(hThread);
    if (debug)
        printf("[+] Injector-Hijack: Resumed thread tid=%i\n", GetThreadId(hThread));

    // Check the execution state with memread into local bootstrapVerify
    BootstrapData bootstrapVerify{ };
    bootstrapVerify.State = BOOTSTRAP_STATE::BS_PENDING;
    bootstrapVerify.Ret = ERROR_SUCCESS;
    bootstrapVerify.LastWin32Error = ERROR_SUCCESS;

    if (debug)
        printf("[+] Injector-Hijack: Checking for execution status of BootstrapShellcode...\n");

    std::string waitingFor = "execution"; // Still waiting for x of BootstrapShellcode
    bool alreadyExecuting = false;
    uintptr_t timer = GetTickCount64();
    int loopCount = 0;
    while (GetTickCount64() - timer < msMaxWaitForExecutor) {
        loopCount++;
        Sleep(msSleepBetweenPolls);

        if (!ReadProcessMemory(hProcess, pRemoteBootstrapShellcode, &bootstrapVerify, sizeof(bootstrapVerify), nullptr)) {
            // check if terminated
            if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
                printf("[!] Injector-Hijack: Target process was terminated -> no more injection :(\n");
                return failed; // at least I don't have to clean-up
            }
            if (debug)
                printf("[-] Injector-Hijack: Cannot read back BootstapShellcode state in injected proc, wait for next read\n");
            continue;
        }

        if (debug && loopCount % loopsBetweenStatusUpdates == 0) {
            const char* waitingFor = bootstrapVerify.State == BOOTSTRAP_STATE::BS_PENDING ? "execution" : "completion";
            int secondsPassed = (msSleepBetweenPolls * loopCount) / 1000;
            printf("[:] Injector-Hijack: Still waiting for %s of BootstrapShellcode after %i seconds\n", waitingFor, secondsPassed);
        }

        if (bootstrapVerify.State == BOOTSTRAP_STATE::BS_PENDING || bootstrapVerify.State == BOOTSTRAP_STATE::BS_EXECUTING) {
            continue; // just wait
        }

        if (bootstrapVerify.State == BOOTSTRAP_STATE::BS_FINISHED) {
            if (bootstrapVerify.Ret == 0) {
                printf("[*] Injector-Hijack: BootstrapShellcode and supplied routine successfully executed and returned to old state\n");
            }
            else {
                printf("[!] Injector-Hijack: BootstrapShellcode and supplied routine successfully executed but returned %lu with LastError %lu\n", bootstrapVerify.Ret, bootstrapVerify.LastWin32Error);
            }
            // when finished, do cleanup
            if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
            if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
            return successful;
        }
        // else loop until timeout
    }

    // reaching here means pending or executing
    if (bootstrapVerify.State == BOOTSTRAP_STATE::BS_PENDING) {
        printf("[!] Injector-Hijack: BootstrapShellcode still not called (thread has not yet been executed with the injected shellcode) -> abort and cleanup!\n");
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        threadContext.Rip = OldRIP;
        if (SetThreadContext(hThread, &threadContext)) {
            ResumeThread(hThread);
        }
        else {
            printf("[!] Injector-Hijack: SetThreadContext failed to restore original RIP: %lu\n", GetLastError());
        }
        return failed;
    }

    if (bootstrapVerify.State == BOOTSTRAP_STATE::BS_EXECUTING) {
        printf("[*] Injector-Hijack: BootstrapShellcode still executing... assuming it will eventually work\n"); // no cleanup
        return timeout;
    }

    return failed; // unknown state
}

bool HandleCleanup(HANDLE hProcess, std::vector<LPVOID> remoteAddrs, LPVOID localAddr) {
    if (!remoteAddrs.empty()) {
        for (LPVOID addr : remoteAddrs) {
            if (addr) {
                VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
            }
        }
    }
    if (localAddr) {
        VirtualFree(localAddr, 0, MEM_RELEASE);
    }
    return false;
}

// see github.com/CCob/ThreadlessInject
LOADER_RET ThreadlessInject(HANDLE hProc, LPVOID lpStart, LPVOID lpParameters, bool debug) {

    HMODULE hModHook = GetModuleHandleA(g_libThreadlessHook.c_str());
    if (hModHook == NULL) {
        printf("[!] Injector-Threadless: Failed to find %s\n", g_libThreadlessHook.c_str());
        return failed;
    }

    DWORD64 hookedFuncAddr = (DWORD64)GetProcAddress(hModHook, g_funcThreadlessHook.c_str());
    if (hookedFuncAddr == NULL) {
        printf("[!] Injector-Threadless: Did not find the function to hook for threadless injection\n");
        return failed;
    }

    if (debug)
        printf("[+] Injector-Threadless: Found %s!%s at 0x%llx\n", g_libThreadlessHook.c_str(), g_funcThreadlessHook.c_str(), hookedFuncAddr);

    SIZE_T readBytes = 0;
    DWORD64 originalInstructions_0_8 = 0;
    UINT originalInstructions_8_B = 0;
    if (!ReadProcessMemory(hProc, (LPVOID)hookedFuncAddr, &originalInstructions_0_8, 8, &readBytes) || readBytes != 8 ||
        !ReadProcessMemory(hProc, (LPVOID)(hookedFuncAddr+8), &originalInstructions_8_B, 4, &readBytes) || readBytes != 4) {
        printf("[!] Injector-Threadless: Failed to read original instructions of hooked function %s at %llu\n", g_funcThreadlessHook.c_str(), hookedFuncAddr);
        return failed;
    }

    if (debug) {
        printf("[+] Injector-Threadless: Got original instructions before hooking: ");
        const byte* p1 = reinterpret_cast<const byte*>(&originalInstructions_0_8);
        for (size_t i = 0; i < sizeof(originalInstructions_0_8); ++i) {
            printf("%02X ", p1[i]);
        }
        const byte* p2 = reinterpret_cast<const byte*>(&originalInstructions_8_B);
        for (size_t i = 0; i < sizeof(originalInstructions_8_B); ++i) {
            printf("%02X ", p2[i]);
        }
        printf("\n");
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("[!] Injector-Threadless: Failed to find kernel32.dll\n");
        return failed;
    }
    DWORD64 virtProtAddr = (DWORD64)GetProcAddress(hKernel32, "VirtualProtect");
    if (virtProtAddr == NULL) {
        printf("[!] Injector-Threadless: Did not find address of VirtualProtect for threadless injection\n");
        return failed;
    }

    std::vector<byte> shellcodeLoader = {
        // --- 1. Preserve Registers & store Addrs ---
        /* 0000 */ 0x51, 0x52, 0x41, 0x50, 0x41, 0x51,                         // push rcx rdx r8 r9               ; in this order
        /* 0006 */ 0x56,                                                       // push rsi                         ; used for virtProtAddr over multiple calls
        /* 0007 */ 0x53,                                                       // push rbx                         ; used for hookedFuncAddr over multiple calls
        /* 0008 */ 0x48, 0xBB, 0x44, 0x44, 0x33, 0x33, 0x33, 0x33, 0x22, 0x22, // movabs rbx, 0x4444333322221111   ; define hookedFuncAddr (patched)
        /* 0012 */ 0x48, 0xBE, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66, 0x55, 0x55, // movabs rsi, 0x8888777766665555   ; define virtProtAddr   (patched)

        // --- 2. VirtualProtect to restore original function ---
        /* 001c */ 0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h                     ; allocate space
        /* 0020 */ 0x48, 0x8B, 0xCB,                                           // mov rcx, rbx                     ; lpAddress, unprotect hookedFuncAddr
        /* 0023 */ 0x48, 0xC7, 0xC2, 0x0C, 0x00, 0x00, 0x00,                   // mov rdx, 0xC                     ; dwSize, unprotect 12 bytes
        /* 002a */ 0x49, 0xC7, 0xC0, 0x40, 0x00, 0x00, 0x00,                   // mov r8, 0x40                     ; flNewProtect, PAGE_EXECUTE_READWRITE
        /* 0031 */ 0x4C, 0x8D, 0x0C, 0x24,                                     // lea r9, [rsp]                    ; lpflOldProtect, pointer for old value
        /* 0035 */ 0xFF, 0xD6,                                                 // call rsi                         ; VirtualProtect(hookedFuncAddr, 12, RWX, old)

        // --- 3. Write Back Original Instructions ---
        /* 0037 */ 0x48, 0xB8, 0xDD, 0xDD, 0xCC, 0xCC, 0xAA, 0xAA, 0x99, 0x99, // movabs rax, 0xddddccccaaaa9999   ; define originalInstructions_0_8 (patched)
        /* 0041 */ 0x48, 0x89, 0x03,                                           // mov qword ptr [rbx], rax         ; write to rbx (hookedFuncAddr)
        /* 0044 */ 0xB8, 0x09, 0x09, 0x09, 0x09,                               // mov eax, 0x09090909              ; define originalInstructions_8_B (patched)
        /* 0049 */ 0x89, 0x43, 0x08,                                           // mov dword ptr [rbx+8], eax       ; write to rbx+8 (hookedFuncAddr+8)

        // --- 4. Re-VirtualProtect ---
        /* 004c */ 0x48, 0x8B, 0xCB,                                           // mov rcx, rbx                     ; lpAddress, unprotect hookedFuncAddr
        /* 004f */ 0x48, 0xC7, 0xC2, 0x0C, 0x00, 0x00, 0x00,                   // mov rdx, 0xC                     ; dwSize, unprotect 12 bytes
        /* 0056 */ 0x49, 0xC7, 0xC0, 0x20, 0x00, 0x00, 0x00,                   // mov r8, 0x20                     ; flNewProtect, PAGE_EXECUTE_READ
        /* 005d */ 0x4C, 0x8D, 0x0C, 0x24,                                     // lea r9, [rsp]                    ; lpflOldProtect, pointer for old value
        /* 0061 */ 0xFF, 0xD6,                                                 // call rsi                         ; VirtualProtect(hookedFuncAddr, 12, RX, old)

        // --- 5. Call lpStart(lpParameters) ---
        /* 0063 */ 0x48, 0xB9, 0x2f, 0x6d, 0x6e, 0x74, 0x2f, 0x61, 0x69, 0x6e, // movabs rcx, lpParameters         ; e.g. DLL path (patched)
        /* 006d */ 0x48, 0xB8, 0x77, 0x61, 0x73, 0x20, 0x68, 0x65, 0x72, 0x65, // movabs rax, lpStart              ; e.g. LoadLibraryA patched)
        /* 0077 */ 0xFF, 0xD0,                                                 // call rax                         ; e.g. LoadLibraryA(DllPath)
        /* 0079 */ 0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 28h                     ; un-allocate space

        // --- 6. Epiloge & Jump Back ---
        /* 007d */ 0x48, 0x89, 0xD8,                                           // mov rax, rbx                     ; rbx still holds final return dest, but rbx must be restored now
        /* 0080 */ 0x5B, 0x5E,                                                 // pop rbx rsi                      ; restore original rbx and rsi
        /* 0082 */ 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59,                         // pop r9 r8 rdx rcs                ; in this order
        /* 0082 */ 0xFF, 0xE0                                                  // jmp rax                          ; jump back to hookedFuncAddr
    };

    // 1. Patch the hooked function address into the shellcode loader stub
    *reinterpret_cast<DWORD64*>(shellcodeLoader.data() + 0x0A) = hookedFuncAddr;

    // 2. Patch the VirtualProtect address into the shellcode loader stub
    *reinterpret_cast<DWORD64*>(shellcodeLoader.data() + 0x14) = virtProtAddr;

    // 3. Patch the 12 bytes that were in the original export prior to hooking
    *reinterpret_cast<DWORD64*>(shellcodeLoader.data() + 0x39) = originalInstructions_0_8;
    *reinterpret_cast<UINT*>(shellcodeLoader.data() + 0x45) = originalInstructions_8_B;

    // 4. Patch lpParameters into RCX
    *reinterpret_cast<DWORD64*>(shellcodeLoader.data() + 0x65) = (DWORD64)lpParameters;

    // 5. Patch lpStart into RAX
    *reinterpret_cast<DWORD64*>(shellcodeLoader.data() + 0x6F) = (DWORD64)lpStart;

    if (debug)
        printf("[+] Injector-Threadless: Patched and prepared the threadless loader locally\n");

    // handle the location of the loader stub
    LPVOID loaderAddr = NULL;
    bool foundCodeCave = false;
    struct CodeCave {
        LPVOID address;
        DWORD flProtect;
        std::vector<byte> originalBytes;
    };
    auto revertCodeCave = [&](CodeCave cc) {
        DWORD oldProt = 0;
        // if this fails the process will crash if the code cave will ever be used
        if (!VirtualProtectEx(hProc, cc.address, cc.originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProt)) {
            printf("[!] Injector-Threadless: Failed to unprotect code cave to RWX at %p\n", cc.address);
            return false;
        }
        if (!WriteProcessMemory(hProc, cc.address, cc.originalBytes.data(), cc.originalBytes.size(), NULL)) {
            printf("[!] Injector-Threadless: Failed to write back original bytes to code cave at %p\n", cc.address);
            return false;
        }
        if (!VirtualProtectEx(hProc, cc.address, cc.originalBytes.size(), oldProt, &oldProt)) {
            printf("[!] Injector-Threadless: Failed to protect code cave to RX at %p\n", cc.address);
            return false;
        }
        return true;
    };
    CodeCave cc = {};

    if (false) {
        // TODO find cc
        // TODO unprotect
    }
    else {
        loaderAddr = VirtualAllocEx(hProc, NULL, shellcodeLoader.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (loaderAddr == NULL) {
            printf("[!] Injector-Threadless: Failed to allocate memory in target process for threadless loader\n");
            return failed;
        }
    }

    // write the actual loader to the cave / allocation and RX protect again
    if (!WriteProcessMemory(hProc, loaderAddr, shellcodeLoader.data(), shellcodeLoader.size(), NULL)) {
        printf("[!] Injector-Threadless: Failed to write the loader to remote process at %p, error %i\n", loaderAddr, GetLastError());
        if (!foundCodeCave) { HandleCleanup(hProc, { loaderAddr }, {}); }
        return failed;
    }
    DWORD oldLoaderProtect = NULL;
    if (!VirtualProtectEx(hProc, loaderAddr, shellcodeLoader.size(), PAGE_EXECUTE_READ, &oldLoaderProtect)) {
        printf("[!] Injector-Threadless: Failed to RX protect the loader at %p in remote process, error %i\n", loaderAddr, GetLastError());
        if (foundCodeCave) { revertCodeCave(cc); } else { HandleCleanup(hProc, { loaderAddr }, {}); }
        return failed;
    }
    if (debug)
        printf("[+] Injector-Threadless: Written the threadless shellcode loader to the remote process at 0x%p\n", loaderAddr);

    // define the hook
    std::vector<byte> hook {
        0x48, 0xB8,              // [Index 0-1]   movabs rax, XXXX
        0, 0, 0, 0, 0, 0, 0, 0,  // [Index 2-9]   full 8-bytes addressing (where the loader may be)
        0xFF, 0xE0               // [Index 10-11] jmp rax
    };
    // Write the address of the shellcode loader stub to the new hook
    *reinterpret_cast<DWORD64*>(hook.data() + 0x02) = (DWORD64)loaderAddr;
    if (debug) {
        printf("[*] Injector-Threadless: Calculated hook: ");
        for (size_t i = 0; i < hook.size(); ++i) {
            printf("%02X ", hook[i]);
        }
        printf("\n");
    }

    // write the actual hook to execute the loader on next hooked function invokation
    DWORD oldHookProtect = NULL;
    if (!VirtualProtectEx(hProc, (LPVOID)hookedFuncAddr, hook.size(), PAGE_EXECUTE_READWRITE, &oldHookProtect)) {
        printf("[!] Injector-Threadless: Failed to RWX protect the hook at 0x%llx in remote process, error %i\n", hookedFuncAddr, GetLastError());
        if (foundCodeCave) { revertCodeCave(cc); } else { HandleCleanup(hProc, { loaderAddr }, {}); }
        return failed;
    }
    if (!WriteProcessMemory(hProc, (LPVOID)hookedFuncAddr, hook.data(), hook.size(), NULL)) {
        printf("[!] Injector-Threadless: Failed to write the hook to remote process at 0x%llx, error %i\n", hookedFuncAddr, GetLastError());
        if (foundCodeCave) { revertCodeCave(cc); } else { HandleCleanup(hProc, { loaderAddr }, {}); }
        return failed;
    }
    if (!VirtualProtectEx(hProc, (LPVOID)hookedFuncAddr, hook.size(), PAGE_EXECUTE_READ, &oldHookProtect)) {
        printf("[!] Injector-Threadless: Failed to RX protect the hook at 0x%llx in remote process (proc will crash on next access, gl hf), error %i\n", hookedFuncAddr, GetLastError());
        // I would not touch anything here, hopes and prayers that the remote process does not crash now
        if (foundCodeCave) { revertCodeCave(cc); } else { HandleCleanup(hProc, { loaderAddr }, {}); }
        return failed;
    }

    // verify
    std::vector<byte> hookVerify(hook.size());
    if (!ReadProcessMemory(hProc, (LPVOID)hookedFuncAddr, hookVerify.data(), hook.size(), NULL)) {
        printf("[!] Injector-Threadless: Failed to verify the written hook at 0x%llx\n", hookedFuncAddr); // ignore and hope it works
    }
    if (hookVerify != hook) {
        printf("[!] Injector-Threadless: Failed to verify the written hook at 0x%llx : got ", hookedFuncAddr);
        for (size_t i = 0; i < hookVerify.size(); ++i) {
            printf("%02X ", hookVerify[i]);
        }
        printf("\n");
        if (foundCodeCave) { revertCodeCave(cc); } else { HandleCleanup(hProc, { loaderAddr }, {}); }
        return failed;
    }
    if (debug)
        printf("[*] Injector-Threadless: Successfully written hook to %s at 0x%llx\n", g_funcThreadlessHook.c_str(), hookedFuncAddr);

    // check execution of threadless hooker
    uintptr_t timer = GetTickCount64();
    int loopCount = 0;
    while (GetTickCount64() - timer < msMaxWaitForExecutor) {
        loopCount++;
        Sleep(msSleepBetweenPolls);

        if (debug && loopCount % loopsBetweenStatusUpdates == 0) {
            int secondsPassed = (msSleepBetweenPolls * loopCount) / 1000;
            printf("[:] Injector-Threadless: Still waiting for execution of Threadless loader after %i seconds\n", secondsPassed);
        }


        // read back the hooked function to check for execution start
        std::vector<byte> originalVerify(hook.size());
        if (!ReadProcessMemory(hProc, (LPVOID)hookedFuncAddr, originalVerify.data(), hook.size(), NULL)) {
            if (debug && loopCount % loopsBetweenStatusUpdates == 0)
                printf("[!] Injector-Threadless: Failed to read back original hooked function, likely something wrong with the remote process\n");
        }

        // check if loader started executing (loader restores the hook, check if it is restored)
        DWORD64 readPart1 = *reinterpret_cast<const DWORD64*>(originalVerify.data());
        UINT readPart2 = *reinterpret_cast<const UINT*>(originalVerify.data() + 8);
        if (readPart1 == originalInstructions_0_8 && readPart2 == originalInstructions_8_B) {
            if (debug) {
                printf("[+] Injector-Threadless: Got original instructions again: ");
                for (size_t i = 0; i < originalVerify.size(); ++i) {
                    printf("%02X ", originalVerify[i]);
                }
                printf("\n");
            }
            printf("[+] Injector-Threadless: Threadless loader started its execution, big success! (probably)\n");
            if (foundCodeCave) {
                revertCodeCave(cc);
            }
            else {
                HandleCleanup(hProc, { loaderAddr }, NULL);
            }
            return successful;
        }
    }

    printf("[-] Injector-Threadless: No sign of threadless loader execution, leave hook in place but exit here\n");
    return timeout;
}

// execute lpStartAddress(lpParameter) with the given executor type in remote hProcess
LOADER_RET ExecuteDllLoader(HANDLE hProcess, Executor exec, LPVOID lpStartAddress, LPVOID lpParameter, bool yoloMode, bool debug) {

    if (debug) {
        printf("[*] Injector-Executor: Will do %s on 0x%p", GetExecutorTypeStr(exec).c_str(), lpStartAddress);
        if (lpParameter != NULL) {
            printf(" with args at 0x%p", lpParameter);
        }
        printf("\n");
    }
    
    if (exec == CREATE_REMOTE_THREAD) {
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, nullptr);
        if (hThread == NULL) {
            printf("[!] Injector-Executor: %s on 0x%p failed\n", GetExecutorTypeStr(exec).c_str(), lpStartAddress);
            return failed;
        }

        printf("[*] Injector-Executor: Remote thread created on 0x%p now waiting for return...\n", lpStartAddress);
        DWORD wait = WaitForSingleObject(hThread, msMaxWaitForExecutor);
        if (wait == WAIT_TIMEOUT) {
            printf("[!] Injector-Executor: Remote thread did not finish within timeout\n");
            return timeout;
        }

        CloseHandle(hThread);
        return successful;
    }

    else if (exec == THREADLESS_INJECTION) {
        return ThreadlessInject(hProcess, lpStartAddress, lpParameter, debug);
    }

    // other executors need an existing thread -> get the optimal one for the execType
    OPTIMAL_THREAD optThread = GetThreadForExecutor(GetProcessId(hProcess), exec, yoloMode, debug);
	HANDLE hThread = optThread.hThread;
    Executor execUpdated = optThread.execType;

    if (optThread.hThread == NULL) {
        printf("[!] Injector-Executor: Failed to get any thread for %s\n", GetExecutorTypeStr(exec).c_str());
        return failed;
    }
    LOADER_RET ret = failed;
    
    if (execUpdated == HIJACK_THREAD) {
        ret = HijackThread(hProcess, hThread, lpStartAddress, lpParameter, debug);
    }
    
    else if (execUpdated == QUEUE_USER_APC2) {
        QUEUE_USER_APC_FLAGS flags = (QUEUE_USER_APC_FLAGS)QUEUE_USER_APC_SPECIAL_USER_APC;
        if (debug)
            printf("[+] Injector-Executor: About to queue 0x%p with QUEUE_USER_APC_SPECIAL_USER_APC\n", lpStartAddress);
        if (QueueUserAPC2((PAPCFUNC)lpStartAddress, hThread, (ULONG_PTR)lpParameter, flags)) {
            ret = LOADER_RET::successful;
        }
        else {
            ret = LOADER_RET::failed;
        }
    }

    CloseHandle(hThread);
    if (ret == LOADER_RET::failed) {
        printf("[!] Injector-Executor: %s on 0x%p failed\n", GetExecutorTypeStr(exec).c_str(), lpStartAddress);
    }
    else if (ret == LOADER_RET::timeout) {
        printf("[=] Injector-Executor: %s on 0x%p timeout, leaving everything in place and hope for the best\n", GetExecutorTypeStr(exec).c_str(), lpStartAddress);
    }
    return ret;
}

// ------------------------ actual injectors ------------------------ //
// Inject DLL into target process via CreateRemoteThread + LoadLibrary onto DLL path
bool LoadLibraryInject(HANDLE hProcess, const std::string& dllPath, Executor exec, bool yoloMode, bool debug) {
    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID pDllPath = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        printf("[!] Injector-LoadLibrary: VirtualAllocEx failed. Error: %lx", GetLastError());
        CloseHandle(hProcess);
        return false;
    }
    if (debug)
        printf("[+] Injector-LoadLibrary: Allocated memory in target process at 0x%p\n", pDllPath);

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), size, nullptr)) {
        printf("[!] Injector-LoadLibrary: WriteProcessMemory failed. Error: %lx", GetLastError());
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug)
        printf("[+] Injector-LoadLibrary: Wrote string '%s' to target\n", dllPath.c_str());

    // finally execute the dll loader with the given executor
    LOADER_RET ret = ExecuteDllLoader(hProcess, exec, (LPVOID)LoadLibraryA, pDllPath, yoloMode, debug);
    if (ret == LOADER_RET::failed) {
        printf("[!] Injector-LoadLibrary: %s failed to load '%s' into remote process %i\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess));
        return HandleCleanup(hProcess, { pDllPath }, NULL);
    }
    if (ret == LOADER_RET::timeout) {
        printf("[=] Injector-LoadLibrary: %s did not load '%s' into remote process %i (yet)\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess));
        HandleCleanup(hProcess, { }, NULL); // must leave DLL path in proc
        return true;
    }
    printf("[+] Injector-LoadLibrary: %s loaded '%s' into remote process %i\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess));
    HandleCleanup(hProcess, { pDllPath }, NULL);
    return true;
}

// write dll to remote proc and handle patching from external -> minimal remote shellcode to setup
// https://github.com/Paxai/DLLium/blob/de79b82bbeb011778b03022b21c0a9d623f3d813/DLLium/injection.cpp#L161
bool HostMappedAndShellcodeLoaderInject(HANDLE hProcess, const std::string& dllPath, Executor exec, bool yoloMode, bool debug) {

    std::ifstream File(dllPath, std::ios::binary | std::ios::ate);
    if (File.fail()) { printf("[!] Injector-HostShell: Open file %s failed: %lu\n", dllPath.c_str(), GetLastError()); return false; }
    if (debug)
        printf("[+] Injector-HostShell: Opened %s\n", dllPath.c_str());

    std::streampos fileSize = File.tellg();
    if (fileSize < 0x1000) { File.close(); return false; }
    if (debug)
        printf("[+] Injector-HostShell: DLL size: %llu bytes\n", (unsigned long long)fileSize);

    std::vector<BYTE> pSrcDllData((size_t)fileSize);
    File.seekg(0, std::ios::beg);
    File.read((char*)pSrcDllData.data(), fileSize);
    File.close();
    if (debug)
        printf("[+] Injector-HostShell: DLL read into memory\n");

    auto* pLocalDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcDllData.data());
    if (pLocalDos->e_magic != IMAGE_DOS_SIGNATURE) { printf("[!] Unable to find magic bytes in DLL '%s'\n", dllPath.c_str()); return false; }

    auto* pNtLocal = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcDllData.data() + pLocalDos->e_lfanew);
    if (pNtLocal->Signature != IMAGE_NT_SIGNATURE) { printf("[!] Unable to find NT header signature in DLL '%s'\n", dllPath.c_str()); return false; }
    auto* pOpt = &pNtLocal->OptionalHeader;

    LPVOID pRemoteTargetBase = VirtualAllocEx(hProcess, nullptr, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteTargetBase) {
        printf("[!] Injector-HostShell: VirtualAllocEx failed at remote process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, {}, NULL);
    }

    BYTE* pLocalImage = (BYTE*)VirtualAlloc(nullptr, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalImage) {
        printf("[!] Injector-HostShell: VirtualAlloc failed at local process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, {pRemoteTargetBase}, NULL);
    }
    if (debug)
        printf("[+] Injector-HostShell: Allocated DLL into local 0x%p and remote memory 0x%p\n", pLocalImage, pRemoteTargetBase);

    memcpy(pLocalImage, pSrcDllData.data(), pOpt->SizeOfHeaders);

    auto* pSection = IMAGE_FIRST_SECTION(pNtLocal);
    for (UINT i = 0; i < pNtLocal->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (pSection->SizeOfRawData > 0) {
            memcpy(pLocalImage + pSection->VirtualAddress,
                pSrcDllData.data() + pSection->PointerToRawData,
                pSection->SizeOfRawData);
            if (debug)
                printf("[+] Injector-HostShell: Copied section %.8s to local image\n", pSection->Name);
        }
    }

    // get local offsets for relocation 
    auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(pLocalImage);
    auto* rpNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pLocalImage + pDosHdr->e_lfanew);
    auto* rpOpt = &rpNt->OptionalHeader;

    uintptr_t delta = (uintptr_t)pRemoteTargetBase - (uintptr_t)rpOpt->ImageBase;
    if (delta == 0) { printf("[!] Injector-HostShell: Delta of 0 between local DLL base and remote process base, no reloc needed\n"); }

    auto relocDir = rpOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) { printf("[-] Injector-HostShell: Empty relocation dir found, no reloc needed\n"); }

    if (delta != 0 && relocDir.Size > 0) {
        auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pLocalImage + relocDir.VirtualAddress);
        uintptr_t relocEnd = (uintptr_t)pReloc + relocDir.Size;

        // relocate images (known dlls use the same offset over all processes, calculate via local process)
        while (pReloc && (uintptr_t)pReloc < relocEnd && pReloc->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            UINT  count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* info = reinterpret_cast<WORD*>(pReloc + 1);

            for (UINT i = 0; i < count; ++i) {
                WORD type = info[i] >> 12;
                WORD offset = info[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    uintptr_t* patch = reinterpret_cast<uintptr_t*>(pLocalImage + pReloc->VirtualAddress + offset);
                    *patch += delta;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* patch = reinterpret_cast<uint32_t*>(pLocalImage + pReloc->VirtualAddress + offset);
                    *patch += (uint32_t)delta;
                }
                else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue; // skip padding
                }
                else {
                    printf("[!] Injector-HostShell: Unknown relocation type %d\n", type);
                }
            }

            if (debug)
                printf("[+] Injector-HostShell: Processed relocation block at 0x%p\n", pReloc);
            pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
        }
    }

    // write the image to the remote process, same address
    if (!WriteProcessMemory(hProcess, pRemoteTargetBase, pLocalImage, pOpt->SizeOfImage, nullptr)) {
        printf("[!] Injector-HostShell: WriteProcessMemory failed: %lu at remote process\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    VirtualFree(pLocalImage, 0, MEM_RELEASE);
    pLocalImage = nullptr;
    if (debug)
        printf("[+] Injector-HostShell: Wrote DLL to remote process memory at 0x%p\n", pRemoteTargetBase);

    HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
    if (!hK32Local) {
        printf("[!] Injector-HostShell: GetModuleHandleA failed for kernel32.dll at local process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }

    // get address of setup functions
    auto pRtlAddFuncTableLocal = (f_RtlAddFunctionTable)GetProcAddress(hK32Local, "RtlAddFunctionTable");
    auto pLoadLibraryALocal = (f_LoadLibraryA)GetProcAddress(hK32Local, "LoadLibraryA");
    auto pGetProcAddressLocal = (f_GetProcAddress)GetProcAddress(hK32Local, "GetProcAddress");

    if (!pLoadLibraryALocal || !pGetProcAddressLocal) {
        printf("[!] Injector-HostShell: GetProcAddress failed for LoadLibraryA or GetProcAddress at local process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    if (debug)
        printf("[+] Injector-HostShell: Resolved LoadLibraryA, GetProcAddress, and RtlAddFunctionTable at local process\n");

    ShellcodeData dllLoadingData = {};
    dllLoadingData.pDllBase = (uintptr_t)pRemoteTargetBase;
    dllLoadingData.EntryPoint = pOpt->AddressOfEntryPoint;
    dllLoadingData.ImportDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    dllLoadingData.RelocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    dllLoadingData.ExceptionDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    dllLoadingData.ExceptionSize = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    dllLoadingData.TLSDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    dllLoadingData.pLoadLibraryA = pLoadLibraryALocal;
    dllLoadingData.pGetProcAddress = pGetProcAddressLocal;
    dllLoadingData.pRtlAddFunctionTable = pRtlAddFuncTableLocal;
    dllLoadingData.Result = ShellcodeResult::scPending;
    dllLoadingData.DllFailed = (uintptr_t)nullptr;
    dllLoadingData.IATOrdinalFailed = (uintptr_t)nullptr;
    dllLoadingData.IATNameFailed = (uintptr_t)nullptr;
    dllLoadingData.RtlFailed = 0;
    dllLoadingData.YoloMode = yoloMode;
    dllLoadingData.YoloWait = yoloBusyWait;

    // allocate memory for shellcode data in remote process
    LPVOID pRemoteDllLoadingData = VirtualAllocEx(hProcess, nullptr, sizeof(ShellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllLoadingData) {
        printf("[!] Injector-HostShell: VirtualAllocEx failed for dllLoadingData: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    if (!WriteProcessMemory(hProcess, pRemoteDllLoadingData, &dllLoadingData, sizeof(ShellcodeData), nullptr)) {
        printf("[!] Injector-HostShell: WriteProcessMemory failed for remote dllLoadingData: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, NULL);
    }
    if (debug)
        printf("[+] Injector-HostShell: Wrote required dllLoadingData to remote process memory at 0x%p\n", pRemoteDllLoadingData);

    size_t dllLoadingShellcodeSize = GetUniversalShellcodeSize(); // now with fancy code sections
    const void* pLocalDllLoadingShellcodeStart = ResolveFunction((void*)UniversalDllLoadingShellcode);

    // sanity check on the shellcodeSize, just set to 4kB if non-sensical and hope
    if (dllLoadingShellcodeSize == 0 || dllLoadingShellcodeSize > 0x8000) {
        printf("[-] Injector-HostShell: Warning, dllLoadingShellcodeSize has strange size %llu\n", dllLoadingShellcodeSize);
        dllLoadingShellcodeSize = 0x1000;
    }

    // alloc space for the DLLium (DLL loading shellcode) in remote proc
    LPVOID pRemoteDllLoadingShellcode = VirtualAllocEx(hProcess, nullptr, dllLoadingShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // needs Execute
    if (!pRemoteDllLoadingShellcode) {
        printf("[!] Injector-HostShell: VirtualAllocEx failed for remote dll loading shellcode: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, NULL);
    }

    // write the DLLium (DLL loading shellcode) to remote proc
    if (!WriteProcessMemory(hProcess, pRemoteDllLoadingShellcode, pLocalDllLoadingShellcodeStart, dllLoadingShellcodeSize, nullptr)) {
        printf("[!] Injector-HostShell: WriteProcessMemory failed for remote dll loading shellcode: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, NULL);
    }
    if (debug)
        printf("[+] Injector-HostShell: Wrote all %zu bytes of dll loading shellcode to remote process at 0x%p\n", dllLoadingShellcodeSize, pRemoteDllLoadingShellcode);

    // finally execute the dll loader with the given executor
    LOADER_RET ret = ExecuteDllLoader(hProcess, exec, pRemoteDllLoadingShellcode, pRemoteDllLoadingData, yoloMode, debug);
    if (ret == LOADER_RET::failed) {
        printf("[!] Injector-HostShell: Executor %s failed to execute in remote process %i\n", GetExecutorTypeStr(exec).c_str(), GetProcessId(hProcess));
        return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, NULL);
    }
    if (ret == LOADER_RET::timeout) {
        printf("[=] Injector-HostShell: Executor %s did not execute in remote process %i (yet)\n", GetExecutorTypeStr(exec).c_str(), GetProcessId(hProcess));
        if (debug)
            printf("[-] Injector-HostShell: Cannot check for execution status of DllLoadingShellcode, returning here and hope for the best\n");
        HandleCleanup(hProcess, { }, NULL); // must leave DLL path in proc
        return true;
    }

    if (debug)
        printf("[+] Injector-HostShell: Also checking for execution status of DllLoadingShellcode...\n");
    
    // get result of shellcode loader
    uintptr_t timer = GetTickCount64();
    int loopCount = 0;
    while (GetTickCount64() - timer < msMaxWaitForExecutor) {
        loopCount++;
        Sleep(msSleepBetweenPolls);

        if (!ReadProcessMemory(hProcess, pRemoteDllLoadingData, &dllLoadingData, sizeof(ShellcodeData), NULL)) {
            // check if terminated
            if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
                printf("[!] Injector-HostShell: Target process was terminated -> no more injection :(\n");
                return false; // at least I don't have to clean-up
            }
            if (debug && loopCount % loopsBetweenStatusUpdates == 0)
                printf("[-] Injector-HostShell: Cannot read back DllLoadingShellcode state with executor %s. Error: %i\n", GetExecutorTypeStr(exec).c_str(), GetLastError());
            continue;
        }

        if (debug && loopCount % loopsBetweenStatusUpdates == 0) {
            const char* waitingFor = dllLoadingData.Result == ShellcodeResult::scPending ? "execution" : "completion";
            int secondsPassed = (msSleepBetweenPolls * loopCount) / 1000;
            printf("[:] Injector-HostShell: Still waiting for %s of DllLoadingShellcode after %i seconds\n", waitingFor, secondsPassed);
        }

        // wait for result (except when in yolo, then print pending/about to crash states too)
        if (dllLoadingData.Result == ShellcodeResult::scPending || (dllLoadingData.Result == ShellcodeResult::scExecuting && !yoloMode)) {
            continue;
        }

        if (dllLoadingData.Result == ShellcodeResult::scInvalidDllBase) {
            printf("[!] Injector-HostShell: Invalid DllBase. '%s' not loaded!\n", dllPath.c_str());
            return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, NULL); // return fail
        }

        // if in yoloMode: there might've been some ignored errors, try to print them
        if (yoloMode) {

            // offsets to relevant information
            LPVOID pRemoteDllFailed = (LPBYTE)pRemoteDllLoadingData + offsetof(ShellcodeData, DllFailed);
            LPVOID pRemoteIATNameFailed = (LPBYTE)pRemoteDllLoadingData + offsetof(ShellcodeData, IATNameFailed);
            LPVOID pRemoteIATOrdinalFailed = (LPBYTE)pRemoteDllLoadingData + offsetof(ShellcodeData, IATOrdinalFailed);
            uintptr_t nullPtr = 0;
            uint32_t zeroOrdinal = 0;

            if (dllLoadingData.IATOrdinalFailed != 0 || dllLoadingData.IATNameFailed != nullPtr) {
                char failingDll[MAX_PATH]{};
                if (dllLoadingData.DllFailed != nullPtr) {
                    if (!ReadProcessMemory(hProcess, (LPCVOID)dllLoadingData.DllFailed, failingDll, sizeof(failingDll) - 1, nullptr)) {
                        strncpy_s(failingDll, "<error reading dll name>", _TRUNCATE);
                    }

                    // Clear DllFailed in the struct offset
                    WriteProcessMemory(hProcess, pRemoteDllFailed, &nullPtr, sizeof(nullPtr), NULL);
                }

                if (dllLoadingData.IATNameFailed != nullPtr) {
                    char failingIATName[MAX_PATH]{};
                    if (!ReadProcessMemory(hProcess, (LPCVOID)dllLoadingData.IATNameFailed, failingIATName, sizeof(failingIATName) - 1, nullptr)) {
                        strncpy_s(failingIATName, "<error reading func name>", _TRUNCATE);
                    }
                    printf("[$] Injector-HostShell: GetProcAddress failed for IAT '%s' in '%s', but yolo!\n", failingIATName, failingDll);

                    // Clear IATNameFailed in the struct offset
                    WriteProcessMemory(hProcess, pRemoteIATNameFailed, &nullPtr, sizeof(nullPtr), NULL);
                }
                else {
                    printf("[$] Injector-HostShell: GetProcAddress failed for IAT ordinal=%i in '%s', but yolo!\n", dllLoadingData.IATOrdinalFailed, failingDll);

                    // Clear IATOrdinalFailed in the struct offset
                    WriteProcessMemory(hProcess, pRemoteIATOrdinalFailed, &zeroOrdinal, sizeof(zeroOrdinal), NULL);
                }
            }

            // Check remaining LoadLibrary errors
            if (dllLoadingData.DllFailed != nullPtr) {
                char failingDll[MAX_PATH]{};
                if (!ReadProcessMemory(hProcess, (LPCVOID)dllLoadingData.DllFailed, failingDll, sizeof(failingDll) - 1, nullptr)) {
                    strncpy_s(failingDll, "<error reading dll name>", _TRUNCATE);
                }
                printf("[$] Injector-HostShell: LoadLibrary failed when importing the dependent library '%s', but yolo!\n", failingDll);

                // Clear DllFailed in the struct offset
                WriteProcessMemory(hProcess, pRemoteDllFailed, &nullPtr, sizeof(nullPtr), NULL);
            }

        }
        else { // else check if there were some errors and early exits

            if (dllLoadingData.Result == ShellcodeResult::scLoadLibraryError) {
                char failingDll[MAX_PATH]{};
                if (dllLoadingData.DllFailed == (uintptr_t)nullptr || !ReadProcessMemory(hProcess, (LPCVOID)dllLoadingData.DllFailed, failingDll, sizeof(failingDll) - 1, nullptr)) {
                    strncpy_s(failingDll, "<error reading dll name>", _TRUNCATE);
                }
                printf("[!] Injector-HostShell: LoadLibrary failed when importing the dependent library '%s'. '%s' not loaded!\n", failingDll, dllPath.c_str());
                return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, NULL); // return fail
            }

            if (dllLoadingData.Result == ShellcodeResult::scGetProcAddrOrdinalError || dllLoadingData.Result == ShellcodeResult::scGetProcAddrNameError) {
                char failingDll[MAX_PATH]{};

                if (dllLoadingData.DllFailed == (uintptr_t)nullptr || !ReadProcessMemory(hProcess, (LPCVOID)dllLoadingData.DllFailed, failingDll, sizeof(failingDll) - 1, nullptr)) {
                    strncpy_s(failingDll, "<error reading dll name>", _TRUNCATE);
                }
                char failingIATEntry[MAX_PATH]{};
                if (dllLoadingData.IATNameFailed != (uintptr_t)nullptr && dllLoadingData.Result == ShellcodeResult::scGetProcAddrNameError) {
                    if (!ReadProcessMemory(hProcess, (LPCVOID)dllLoadingData.IATNameFailed, failingIATEntry, sizeof(failingIATEntry) - 1, nullptr)) {
                        strncpy_s(failingIATEntry, "<error reading func name>", _TRUNCATE);
                    }
                }
                else {
                    snprintf(failingIATEntry, sizeof(failingDll) - 1, "ordinal=%i", dllLoadingData.IATOrdinalFailed);
                }
                printf("[!] Injector-HostShell: GetProcAddress failed for IAT entry '%s' in '%s'. '%s' not loaded!\n", failingIATEntry, failingDll, dllPath.c_str());
                return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, NULL); // return fail
            }
        
            if (dllLoadingData.RtlFailed != (uintptr_t)nullptr && dllLoadingData.Result == ShellcodeResult::scRtlFailed) {
                printf("[!] Injector-HostShell: Failed to add items to Rtl. '%s' not loaded!\n", dllPath.c_str());
                return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, NULL); // return fail
            }
        }

        if (dllLoadingData.Result == ShellcodeResult::scNoEntrypointFound) {
            printf("[-] Injector-HostShell: %s mapped '%s' in remote process %i at 0x%p but no entrypoint found and called!\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess), (LPVOID)dllLoadingData.pDllBase);
            HandleCleanup(hProcess, { pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage); // do not free the dll mem if successful
            return true;
        }

        if (dllLoadingData.Result == ShellcodeResult::scDllMainFailed) {
            printf("[!] Injector-HostShell: Executor %s failed with DllLoadingShellcode in remote process %i\n", GetExecutorTypeStr(exec).c_str(), GetProcessId(hProcess));
            return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage); // return fail
        }

        if (dllLoadingData.Result == ShellcodeResult::scDllMainSuccessful) {
            printf("[*] Injector-HostShell: %s loaded '%s' in remote process %i at 0x%p\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess), (LPVOID)dllLoadingData.pDllBase);
            HandleCleanup(hProcess, { pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage); // do not free the dll mem if successful
            return true;
        }
    }

    // reaching here means pending or executing
    if (dllLoadingData.Result == ShellcodeResult::scPending) {
        printf("[-] Injector-HostShell: Shellcode to load DLL still not called, thread has not yet been executed with the injected shellcode, abort and cleanup\n"); // cleanup
        return HandleCleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage); // return fail
    }

    if (dllLoadingData.Result == ShellcodeResult::scExecuting) {
        printf("[+] Injector-HostShell: Shellcode to load DLL still executing... Let him cook, but I'm out of here.\n"); // no cleanup
        HandleCleanup(hProcess, { pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage); // do not free the dll mem if potentioally successful
        return true;
    }

    return false; // should never be reached
}

// write dll to remote proc and call self-reflective loader (handles image address, system function resol., mem alloc, header copy, section copy, IAT resolution, relocations, and call DllMain)
bool ReflectiveSelfLoaderInject(HANDLE hProcess, const std::string& dllPath, Executor exec, bool yoloMode, bool debug) {
    // open dll file
    HANDLE fileHandle = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) { printf("[!] Injector-Reflective: CreateFile failed: %lu\n", GetLastError()); return false; }
    if (debug)
        printf("[+] Injector-Reflective: Opened '%s'\n", dllPath.c_str());

    // get file size
    LARGE_INTEGER liFileSize = { 0 };
    if (!GetFileSizeEx(fileHandle, &liFileSize)) { printf("[!] Injector-Reflective: GetFileSizeEx failed: %lu\n", GetLastError()); CloseHandle(fileHandle); return false; }
    SIZE_T fileSize = (SIZE_T)liFileSize.QuadPart;
    if (fileSize == 0) { printf("[!] Injector-Reflective: Empty file\n"); CloseHandle(fileHandle); return false; }
    if (debug)
        printf("[+] Injector-Reflective: DLL size: %llu bytes\n", (unsigned long long)fileSize);

    // allocate buffer and read
    LPBYTE fileBuffer = (LPBYTE)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuffer) { printf("[!] Injector-Reflective: HeapAlloc failed\n"); CloseHandle(fileHandle); return false; }
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, fileBuffer, (DWORD)fileSize, &bytesRead, NULL) || bytesRead != (DWORD)fileSize) {
        printf("[!] Injector-Reflective: ReadFile failed or incomplete: %lu bytesRead=%lu\n", GetLastError(), bytesRead);
        CloseHandle(fileHandle);
        return HandleCleanup(hProcess, {  }, fileBuffer);
    }
    CloseHandle(fileHandle);
    if (debug)
        printf("[+] Injector-Reflective: DLL read into memory\n");

    // find reflective loader offset in raw file
    DWORD64 loaderOffset = GetReflectiveLoaderOffset((DWORD64)fileBuffer, "ReflectiveLoader");
    if (!loaderOffset) { printf("[!] Injector-Reflective: ReflectiveLoader export not found in %s\n", dllPath.c_str()); HeapFree(GetProcessHeap(), 0, fileBuffer); return false; }
    if (debug)
        printf("[+] Injector-Reflective: ReflectiveLoader offset at 0x%llu\n", loaderOffset);

    // allocate remote memory (use the file size)
    LPVOID pRemoteTargetBase = VirtualAllocEx(hProcess, NULL, fileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteTargetBase) { printf("[!] Injector-Reflective: VirtualAllocEx failed in remote proc: %lu\n", GetLastError()); CloseHandle(hProcess); HeapFree(GetProcessHeap(), 0, fileBuffer); return false; }
    if (debug)
        printf("[+] Injector-Reflective: Remote memory allocated at 0x%p\n", pRemoteTargetBase);

    // write file into remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemoteTargetBase, fileBuffer, fileSize, (SIZE_T*)&written) || written != fileSize) {
        printf("[!] Injector-Reflective: WriteProcessMemory failed: %lu written=%llu\n", GetLastError(), (unsigned long long)written);
        VirtualFreeEx(hProcess, pRemoteTargetBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        return false;
    }
    if (debug)
        printf("[+] Injector-Reflective: DLL written into remote process memory\n");

    // make memory executable
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, pRemoteTargetBase, fileSize, PAGE_EXECUTE_READ, &oldProt)) {
        // If this fails, try PAGE_EXECUTE_READWRITE (some targets)
        if (!VirtualProtectEx(hProcess, pRemoteTargetBase, fileSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
            printf("[!] Injector-Reflective: VirtualProtectEx to RWX failed: %lu\n", GetLastError());
            return HandleCleanup(hProcess, { pRemoteTargetBase }, fileBuffer);
        }
        if (debug)
            printf("[+] Injector-Reflective: Remote memory protection changed to RWX\n");
    }
    if (debug)
        printf("[+] Injector-Reflective: Remote memory protection changed to RX\n");

    // compute remote address of reflective loader and create remote thread
    LPTHREAD_START_ROUTINE lpRemoteLoaderEntry = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pRemoteTargetBase + (ULONG_PTR)loaderOffset);

    // finally execute the dll loader with the given executor
    LOADER_RET ret = ExecuteDllLoader(hProcess, exec, lpRemoteLoaderEntry, NULL, yoloMode, debug);
    if (ret == LOADER_RET::failed) {
        printf("[!] Injector-Reflective: %s failed to load '%s' into remote process %i\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess));
        return HandleCleanup(hProcess, { pRemoteTargetBase }, fileBuffer);
    }
    if (ret == LOADER_RET::timeout) {
        printf("[=] Injector-Reflective: %s did not load '%s' into remote process %i (yet)\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess));
        HandleCleanup(hProcess, { }, fileBuffer); // must leave dll in remote proc
        return true;
    }
    printf("[*] Injector-Reflective: %s loaded '%s' into remote process %i\n", GetExecutorTypeStr(exec).c_str(), dllPath.c_str(), GetProcessId(hProcess));
    HandleCleanup(hProcess, { }, fileBuffer); // do not free the dll mem if successful
    return true;
}

// Preparation for DLL injection
bool InjectDll(DWORD pid, const std::string& dllPath, HANDLE hProcess, Injection injectType, Executor execType, bool yoloMode, bool debug) {
    if (hProcess == NULL) {
        if (debug) {
            printf("[+] Injector: Opening pid=%i\n", pid);
        }
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
    else {
        if (debug) {
            printf("[+] Injector: Using existing handle=0x%p\n", hProcess);
        }
    }

    if (!hProcess) {
        printf("[!] Injector: Failed to open target process. Error: %lx\n", GetLastError());
        return false;
    }
    BOOL isWow = FALSE;
    if (IsWow64Process(hProcess, &isWow)) {
        if (isWow) {
            printf("[!] Injector: Target process is 32-bit but this injector is 64-bit. Abort.\n");
            CloseHandle(hProcess);
            return false;
        }
    }
    else {
        printf("[!] Injector: IsWow64Process failed. Error: %lx\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }
    PrintGrantedAccess(hProcess, pid);

    switch (injectType) {
    case LOADLIBRARY_INJECTION:
        return LoadLibraryInject(hProcess, dllPath, execType, yoloMode, debug);
    case HOSTMAPPED_INJECTION:
        return HostMappedAndShellcodeLoaderInject(hProcess, dllPath, execType, yoloMode, debug);
    case REFLECTIVE_INJECTION:
        return ReflectiveSelfLoaderInject(hProcess, dllPath, execType, yoloMode, debug);
    default:
        printf("[!] Injector: Unknown action\n");
        CloseHandle(hProcess);
        return false;
    }
}
