#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <sstream>
#include <fstream>

#pragma comment(lib, "ntdll.lib")

typedef struct my_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union
	{
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} my_LDR_DATA_TABLE_ENTRY, * my_PLDR_DATA_TABLE_ENTRY;

typedef struct my_PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} my_PEB_LDR_DATA, * my_PPEB_LDR_DATA;

typedef struct my_PEB {
	BYTE Reserved1[16];
	PVOID ImageBaseAddress;
	my_PPEB_LDR_DATA Ldr;
} my_PEB, * my_PPEB;


typedef struct _PROCESS_PROTECTION_LEVEL_INFORMATION {
	UCHAR ProtectionLevel;
} my_PROCESS_PROTECTION_LEVEL_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

// search for MsMpEng.exe and return pid
int get_defender_proc() {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return 0;
	}
	do {
		if (lstrcmpiW(pe32.szExeFile, L"MsMpEng.exe") == 0) {
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return 0;
}

// open MsMpEng.exe with limited permissions and return base address
std::wstring print_defender_base(int pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {
		std::wcout << L"[-] Failed to open process. Error: " << GetLastError() << L"\n";
		return L"";
	}

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == 0) {
		std::wcout << L"[-] Failed to get NtQueryInformationProcess address.\n";
		CloseHandle(hProcess);
		return L"";
	}

	PROCESS_BASIC_INFORMATION pbi;
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

	my_PEB peb;
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
		std::wcout << L"[-] Failed to read PEB. Error: " << GetLastError() << L"\n";
		CloseHandle(hProcess);
		return L"";
	}

	my_PEB_LDR_DATA ldr{};
	if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), nullptr)) {
		std::wcout << L"[-] Failed to read PEB_LDR_DATA. Error: " << GetLastError() << L"\n";
		CloseHandle(hProcess);
		return L"";
	}

	PVOID headAddr = (PBYTE)peb.Ldr + offsetof(my_PEB_LDR_DATA, InMemoryOrderModuleList);

	LIST_ENTRY head{};
	ReadProcessMemory(hProcess, headAddr, &head, sizeof(head), nullptr);
	PVOID current = head.Flink;

	std::wstring bases = L"BaseAddr,ModuleName\n";

	while (current && current != headAddr) {
		my_LDR_DATA_TABLE_ENTRY entry{};
		if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, my_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), nullptr)) {
			std::wcout << L"[-] Failed to read LDR_DATA_TABLE_ENTRY. Error: " << GetLastError() << L"\n";
			CloseHandle(hProcess);
			return bases;
		}
		if (entry.FullDllName.Buffer) {
			wchar_t dll_name[MAX_PATH];
			if (ReadProcessMemory(hProcess, entry.FullDllName.Buffer, dll_name, entry.FullDllName.Length, nullptr)) {
				dll_name[entry.FullDllName.Length / sizeof(wchar_t)] = L'\0'; // null-terminate
				std::wcout << L"[+] Found module: 0x" << entry.DllBase << L":" << dll_name << L"\n";
				std::wstringstream wss;
				wss << L"0x" << std::hex << (uintptr_t)entry.DllBase;
				bases += wss.str() + L",\"" + dll_name + L"\"\n";
			}
			else {
				std::wcout << L"[-] Failed to read module name. Error: " << GetLastError() << L"\n";
			}
		}
		current = entry.InMemoryOrderLinks.Flink;
	}

	CloseHandle(hProcess);
	return bases;
}

int wmain(int argc, wchar_t* argv[]) {
	int pid = get_defender_proc();
	if (pid == 0) {
		std::wcout << L"[-] MsMpEng.exe not found.\n";
		return 1;
	}

	std::wstring bases = print_defender_base(pid);
	std::wstring output_file = L"defender_bases.csv";

	if (argc > 1) {
		output_file = argv[1];
		std::wcout << L"[+] Output file specified: " << output_file << L"\n";
	}
	else {
		std::wcout << L"[+] No output file specified, using default: defender_bases.csv\n";
	}

	// write bases to file
	std::wofstream outfile(output_file);
	if (outfile.is_open()) {
		outfile << bases;
		outfile.close();
	}
	else {
		std::wcout << L"[-] Failed to write to file.\n";
		return 1;
	}

	std::wcout << L"[+] Done.\n";
}