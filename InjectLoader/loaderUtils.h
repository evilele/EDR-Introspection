#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>

HMODULE GetRemoteManualMappedModule(HANDLE hProcess, const std::string& targetDllName);
HMODULE GetRemoteModuleHandle(DWORD pid, const std::string& moduleName);
BOOL UnloadViaThread(DWORD pid, const std::string dllName);
BOOL UnloadViaSignal(DWORD pid, const std::string dllName);
HANDLE FindProcHandle(DWORD pid, BOOL debug);
void PrintGrantedAccess(HANDLE h, DWORD pid);
DWORD GetChildProcessId(HANDLE hParentProcess);