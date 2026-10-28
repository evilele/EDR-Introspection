#include <krabs.hpp>
#include "catch.hpp"

#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>

#include "../InjectLoader/loaderUtils.h"
#include "../InjectLoader/injector.h"
#include "testUtils.h"


const std::string testDll = "TestDLL.dll";
const std::string testDllPath = GetCurrentExePath() + "TestDLL.dll"; // relative path to the DLL to inject
const std::string testExe = "TestEXE.exe";

BOOL debug = TRUE;

// used by the threadless injection technique
std::string g_libThreadlessHook = "ntdll";
std::string g_funcThreadlessHook = "NtDelayExecution";

class TestProcess {
private:
    DWORD explorerPid = GetProcessIdByName(L"explorer.exe");
	std::string szExplorerPid = std::to_string(explorerPid);
    HANDLE hTriggerEvent = CreateEventA(
        NULL, FALSE, FALSE, ("Local\\TestEXE_OpenProc_" + szExplorerPid).c_str()
    );

public:
    PROCESS_INFORMATION pi{ 0 };
    DWORD pid = 0;
    HANDLE hProcess = NULL;

    TestProcess() = default;

	// starts the TestEXE process and returns true if exe is running, false if failed
    bool Start(bool withSignal, bool withWorkers) {
        if (!hTriggerEvent) {
            std::cerr << "[!] TestProcess: Failed to create event signals. Error: " << GetLastError() << "\n";
            return false;
        }

        STARTUPINFOA si = { 0 };
        si.cb = sizeof(si);
        std::string szCmdLine = testExe;
        if (withSignal) szCmdLine += " " + szExplorerPid; else szCmdLine += " 0";
        if (withWorkers) szCmdLine += " 1";
        char* cmdLine = const_cast<char*>(szCmdLine.c_str());

        BOOL result = CreateProcessA(
            NULL,            // Application name
            cmdLine,         // Command line (use standard application search order, Tests.exe and TestEXE.exe in same dir)
            NULL,            // Process security attributes
            NULL,            // Thread security attributes
            FALSE,           // Inherit handles
            0,               // Creation flags
            NULL,            // Environment
            NULL,            // Current directory
            &si,             // Startup info
            &pi              // Process information (out)
        );
        if (result == FALSE) {
            std::cerr << "[!] TestProcess: Failed to start test process. Error: " << GetLastError() << "\n";
            return FALSE;
        }

        pid = pi.dwProcessId;
        hProcess = pi.hProcess;
        Sleep(500); // let the new process cook for a while

        return TRUE;
    }

    // Signals TestEXE to run OpenProcess and waits for the _done event
    bool TriggerAction(DWORD timeoutMs = 5000) {
        if (!hTriggerEvent) return false;
        SetEvent(hTriggerEvent);
        return true;
    }

    DWORD GetExplorerPid() {
        return explorerPid;
    }

    // RAII Destructor: Automatically terminates process on scope exit or REQUIRE failure
    ~TestProcess() {
        if (hProcess) {
            if (!TerminateProcess(hProcess, 0)) {
                std::cerr << "[!] TestProcess: Failed to stop test process. Error: " << GetLastError() << "\n";
            }
            CloseHandle(hProcess);
        }
        if (pi.hThread) {
            CloseHandle(pi.hThread);
        }
    }

    // Prevent accidental copying
    TestProcess(const TestProcess&) = delete;
    TestProcess& operator=(const TestProcess&) = delete;
};

TEST_CASE("FindProcHandle: Query Process Handle Table", "[utils][handles]") {

    SECTION("Returns NULL when no matching handle exists in local process") {
		SUCCEED("Starting FindProcHandle negative test..."); // forces the section header to print)

        // Querying for an invalid/non-existent PID returns NULL
        HANDLE hFound = FindProcHandle(3, FALSE);
        REQUIRE(hFound == NULL);
    }

    SECTION("Finds a valid handle to explorer.exe in the local handle table") {
        // 1. Locate explorer.exe (running on almost all Windows desktop sessions)
        DWORD explorerPid = GetProcessIdByName(L"explorer.exe");
        REQUIRE(explorerPid != 0);

        // 2. Open a handle to explorer.exe to populate it in OUR handle table
        HANDLE hExplorer = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, explorerPid);
        REQUIRE(hExplorer != NULL);

        // 3. Verify FindProcHandle locates the handle pointing to explorer.exe
        HANDLE hFound = FindProcHandle(static_cast<int>(explorerPid), FALSE);
		REQUIRE(hFound == hExplorer);

        // Clean up
        CloseHandle(hExplorer);
    }
}

TEST_CASE("GetThreadForExecutor: Get best thread for Hijacking", "[hooker][getthread]") {
    SUCCEED("Starting TestEXE..."); // force print of test headers

    // start test process
    TestProcess p;
    REQUIRE(p.Start(false, true));

    OPTIMAL_THREAD optThread = GetThreadForExecutor(p.pid, HIJACK_THREAD, false, debug);
    REQUIRE(optThread.hThread != NULL);
    REQUIRE(optThread.score == 100);
}

TEST_CASE("GetThreadForExecutor: Get best thread for QueueAPC2", "[hooker][getthread]") {
    SUCCEED("Starting TestEXE..."); // force print of test headers

    // start test process
    TestProcess p;
    REQUIRE(p.Start(false, true));

    OPTIMAL_THREAD optThread = GetThreadForExecutor(p.pid, QUEUE_USER_APC2, false, debug);
    REQUIRE(optThread.hThread != NULL);
    REQUIRE(optThread.score == 100); // this can vary, higher CPU frequency -> less time in busy work and thus smaller chance to be actually running
}

enum DllLoadedVerification {
    TOOLHELP_MODULE_SNAPSHOT,
	MEMORY_PARSING
 };

void ResetEtwEvent() {
    g_lastEvent = { "", 0, 0 };
    if (g_hEtwEvent) {
        ResetEvent(g_hEtwEvent);
    }
}

void TestDllInjection(Injection injectionType, Executor execType) {
    SUCCEED("Starting TestEXE..."); // force print of test headers

    DllLoadedVerification verificationType;
    BOOL testUnloading;
    switch (injectionType) {
    case Injection::LOADLIBRARY_INJECTION:
        verificationType = TOOLHELP_MODULE_SNAPSHOT;
        testUnloading = true;
        break;
    case Injection::HOSTMAPPED_INJECTION:
    case Injection::REFLECTIVE_INJECTION:
        verificationType = MEMORY_PARSING;
        testUnloading = false;
        break;
    default:
        FAIL("Unknown injection type.\n");
    }

	// start test process and reset event
	TestProcess p;
	REQUIRE(p.Start(true, true));
    ResetEtwEvent();

	// inject the test DLL into the current process
	bool injected = InjectDll(p.pid, testDllPath, NULL, injectionType, execType, false, debug);
	Sleep(100); // wait for prints
	REQUIRE(injected == true);

	// verify that the startup event is caught
	REQUIRE(WaitForEtwEvent(3000, p.pid, "Hooks installed"));

	// also verify also that the DLL it is loaded
    switch (verificationType) {
    case TOOLHELP_MODULE_SNAPSHOT:
        REQUIRE(GetRemoteModuleHandle(p.pid, testDll) != NULL);
        break;
    case MEMORY_PARSING:
        REQUIRE(GetRemoteManualMappedModule(p.hProcess, testDll) != NULL);
        break;
    default:
        FAIL("Unknown verification type.\n");
        break;
    }

    Sleep(100); // wait a bit for reset
    ResetEtwEvent();
    Sleep(100); // wait a bit for reset

	// send the OpenProcess signal and verify that the NtOpenProcess hook was triggered and captured
	p.TriggerAction();
    REQUIRE(WaitForEtwEvent(3000, p.GetExplorerPid(), "NtOpenProcess with access 0x1fffff"));

    if (testUnloading) {
        if (injectionType != LOADLIBRARY_INJECTION) {
            FAIL("Cannot unload a manually mapped DLL\n");
        }
        // else check if unloading works
        REQUIRE(UnloadViaThread(p.pid, testDll));
        // and if module is now unloaded
        REQUIRE(GetRemoteModuleHandle(p.pid, testDll) == NULL);
    }
}

TEST_CASE("DLL Injection: LoadLibrary + CreateRemoteThread", "[hooker][loadlibrary][createremotethread]") {
    TestDllInjection(LOADLIBRARY_INJECTION, CREATE_REMOTE_THREAD);
}
TEST_CASE("DLL Injection: LoadLibrary + HijackThread", "[hooker][loadlibrary][hijackthread]") {
    TestDllInjection(LOADLIBRARY_INJECTION, HIJACK_THREAD);
}
TEST_CASE("DLL Injection: LoadLibrary + QueueUserAPC2", "[hooker][loadlibrary][queueuserapc2]") {
    TestDllInjection(LOADLIBRARY_INJECTION, QUEUE_USER_APC2);
}
TEST_CASE("DLL Injection: LoadLibrary + Threadless", "[hooker][loadlibrary][threadless]") {
    TestDllInjection(LOADLIBRARY_INJECTION, THREADLESS_INJECTION);
}

TEST_CASE("DLL Injection: HostMappedAndShellcode + CreateRemoteThread", "[hooker][hostmapped][createremotethread]") {
    TestDllInjection(HOSTMAPPED_INJECTION, CREATE_REMOTE_THREAD);
}
TEST_CASE("DLL Injection: HostMappedAndShellcode + HijackThread", "[hooker][hostmapped][hijackthread]") {
    TestDllInjection(HOSTMAPPED_INJECTION, HIJACK_THREAD);
}
TEST_CASE("DLL Injection: HostMappedAndShellcode + QueueUserAPC2", "[hooker][hostmapped][queueuserapc2]") {
    TestDllInjection(HOSTMAPPED_INJECTION, QUEUE_USER_APC2);
}
TEST_CASE("DLL Injection: HostMappedAndShellcode + Threadless", "[hooker][hostmapped][threadless]") {
    TestDllInjection(HOSTMAPPED_INJECTION, THREADLESS_INJECTION);
}

TEST_CASE("DLL Injection: Reflective + CreateRemoteThread", "[hooker][reflective][createremotethread]") {
    TestDllInjection(REFLECTIVE_INJECTION, CREATE_REMOTE_THREAD);
}
TEST_CASE("DLL Injection: Reflective + HijackThread", "[hooker][inject][reflective][hijackthread]") {
    TestDllInjection(REFLECTIVE_INJECTION, HIJACK_THREAD);
}
TEST_CASE("DLL Injection: Reflective + QueueUserAPC2", "[hooker][reflective][queueuserapc2]") {
    TestDllInjection(REFLECTIVE_INJECTION, QUEUE_USER_APC2);
}
TEST_CASE("DLL Injection: Reflective + Threadless", "[hooker][reflective][threadless]") {
    TestDllInjection(REFLECTIVE_INJECTION, THREADLESS_INJECTION);
}