#include <windows.h>
#include <stdio.h>
#include <string>

enum SignOptions {
	SIGNOPT_NONE,
	SIGNOPT_MICROSOFT_SIGNED_ONLY,
	SIGNOPT_STORE_SIGNED_ONLY
};

enum MitigationOptions {
	MITOPT_NONE,
	MITOPT_ACG
};

// https://blog.xpnsec.com/protecting-your-malware/
BOOL start_protected_proc(const char* cmd, SignOptions options) {
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size = 0;
	BOOL ret;
	DWORD dwCreationFlags = NULL;
	std::string prot = "";

	ZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (options != SIGNOPT_NONE) {
		prot = "protected ";

		// Required for a STARTUPINFOEXA
		si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
		dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT;

		// Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
		InitializeProcThreadAttributeList(NULL, 1, 0, &size);

		// Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
		si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

		// Initialise our list 
		InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

		// Enable blocking of non-Microsoft signed DLLs
		DWORD64 policy = NULL;
		if (options == SIGNOPT_STORE_SIGNED_ONLY) {
			policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE;
		}
		else if (options == SIGNOPT_MICROSOFT_SIGNED_ONLY) {
			policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
		}

		// Assign our attribute
		UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
	}

	// Finally, create the process
	ret = CreateProcessA(
		NULL,
		(LPSTR)cmd,
		NULL,
		NULL,
		true,
		dwCreationFlags,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi
	);
	
	if (!ret) {
		printf("[!] MitigationsTest: Failed to create %schild process. Error: %lu\n", prot.c_str(), GetLastError());
		return FALSE;
	}

	// Wait indefinitely for the child process to exit (else stdio is broken)
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return TRUE;
}

void continually_check_signing_level() {
	printf("[+] MitigationsTest: Press enter to check signing level of this process...\n");
	while (true) {
		char c = getchar();
		if (c != '\n') {
			printf("\n[*] MitigationsTest: kthxby\n");
			break;
		}

		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };
		if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy))) {
			printf("[!] MitigationsTest: Failed to get signing level. Error: %lu\n", GetLastError());
			continue;
		}

		printf("[+] --- Process Binary Signature Policy Status ---\n");
		printf("    [01] MicrosoftSignedOnly      : %u\n", signaturePolicy.MicrosoftSignedOnly);
		printf("    [02] StoreSignedOnly          : %u\n", signaturePolicy.StoreSignedOnly);
		printf("    [03] MitigationOptIn          : %u\n", signaturePolicy.MitigationOptIn);
		printf("    [04] AuditMicrosoftSignedOnly : %u\n", signaturePolicy.AuditMicrosoftSignedOnly);
		printf("    [05] AuditStoreSignedOnly     : %u\n", signaturePolicy.AuditStoreSignedOnly);
		printf("    --------------------------------------------\n");
		printf("    [Raw Flags Bitmask]           : 0x%08X", signaturePolicy.Flags);
	}
	return;
}

// the return is the exit code of the test process
int do_self_test(MitigationOptions opts) {

	Sleep(500); // give a test process time to capture the pid and handle of this protected child proc

	// check that the mitigations are active
	if (opts == MITOPT_ACG) {
		printf("[*] MitigationsTest: Running internal ACG self-test...\r\n");

		// try to allocate memory locally as RW
		LPVOID localAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (localAddr == NULL) {
			DWORD  err = GetLastError();
			printf("[!] MitigationsTest: Local VirtualAlloc failed. Error: %lu\r\n", err);
			return err;
		}

		// try to change local RW memory to RX (Should be BLOCKED by ACG)
		DWORD oldProtect = 0;
		BOOL protResult = VirtualProtect(localAddr, 0x1000, PAGE_EXECUTE_READ, &oldProtect);

		// with ACG VirtualProtect turning RW -> RX must FAIL
		DWORD err = GetLastError();
		if (protResult == FALSE) {
			printf("[+] MitigationsTest: SUCCESS, ACG successfully blocked local VirtualProtect (RW -> RX), result: %d, error: %lu\r\n", protResult, err);
		}
		else {
			printf("[!] MitigationsTest: FAILURE, ACG did NOT block VirtualProtect, result: %d, error: %lu\r\n", protResult, err);
		}
		return err;
	}

	printf("[*] MitigationsTest: Running self-test without mitigations -> return 0\r\n");
	return 0;
}

// ---------------------------------------
// HIJACKABLE FUNCTIONS
// ---------------------------------------

// dedicated worker thread to be hijacked
DWORD WINAPI HijackableWorkerThread(LPVOID lpParam) {
	printf("[+] TestEXE: Hijackable worker thread tid=%i started...\n", GetCurrentThreadId());
	while (true) { Sleep(1000); } // results in KWAIT_REASON::DelayExecution -> safe to hijack
	return 0;
}

// a busy wait, this is intentionally shitty
int GetLargestPrimeBelow(int m) {
	int maxP = 0;
	bool isPrime;
	for (int candidate = 0; candidate < m; candidate++) {
		isPrime = true; // reset for each candidate at start
		for (int possibleFactor = 2; possibleFactor * possibleFactor < m; possibleFactor++) {
			if ((candidate % possibleFactor) == 0) {
				isPrime = false;
				break;
			}
		}
		if (isPrime) {
			maxP = candidate;
		}
	}
	return maxP;
}

// dedicated and mostly busy thread to get high score and cross usermode kernelmode often 
DWORD WINAPI BusyWorkerThread(LPVOID lpParam) {
	printf("[+] TestEXE: APC-queueable worker thread tid=%i started...\n", GetCurrentThreadId());
	volatile int p = 0;
	while (true) { Sleep(50); p = GetLargestPrimeBelow(1000000); }
	return 0;
}

int main(int argc, char* argv[]) {

	if (argc < 4) {
		printf("[!] Usage: %s <Signing Options> <Mitigation Options> <Self Test> <reserved_for_child_proc>\n", argv[0]);
		printf("[!]   Signing Options: <s> for StoreSignedOnly, <m> for MicrosoftSignedOnly, <n> for No Signing\n");
		printf("[!]   Mitigation Options: <a> for ACG, <n> for No Mitigation\n");
		printf("[!]   Self Test: <t> to run self-test, <n> to skip\n");
		return 1;
	}

	// check if already in child proc
	if (argc > 4 && strcmp(argv[4], "c") == 0) {
		printf("[+] MitigationsTest: Started child proc with pid=%i\n", GetCurrentProcessId());
		MitigationOptions mitOpts = MITOPT_NONE;

		if (strcmp(argv[2], "a") == 0) { // and check if in child proc and child proc should also be ACG
			mitOpts = MITOPT_ACG;
			PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy;
			ZeroMemory(&policy, sizeof(policy));
			policy.ProhibitDynamicCode = 1;
			if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)) == false) {
				printf("[!] MitigationsTest: SetProcessMitigationPolicy ACG failed\n");
				return 1;
			}
			printf("[+] MitigationsTest: SetProcessMitigationPolicy ACG succeeded\n");
		}

		if (strcmp(argv[3], "t") == 0) { // and check if in child proc and child proc should also be self-test
			return do_self_test(mitOpts);
		}

		// start the hijackable and busy worker threads
		HANDLE hHijackableWorker = CreateThread(NULL, 0, HijackableWorkerThread, NULL, 0, NULL);
		HANDLE hQueueableWorker = CreateThread(NULL, 0, BusyWorkerThread, NULL, 0, NULL);

		continually_check_signing_level();

		if (hHijackableWorker) CloseHandle(hHijackableWorker);
		if (hQueueableWorker) CloseHandle(hQueueableWorker);
		return 0;
	}
	
	// else parse options in parent proc
	SignOptions signOpts = SIGNOPT_NONE;
	if (strcmp(argv[1], "s") == 0) {
		signOpts = SIGNOPT_STORE_SIGNED_ONLY;
		printf("[+] MitigationsTest: Will start child proc with StoreSignedOnly\n");
	}
	else if (strcmp(argv[1], "m") == 0) {
		signOpts = SIGNOPT_MICROSOFT_SIGNED_ONLY;
		printf("[+] MitigationsTest: Will start child proc with MicrosoftSignedOnly\n");
	}
	else {
		signOpts = SIGNOPT_NONE;
		printf("[+] MitigationsTest: Will start child proc with No Signing\n");
	}

	// in parent proc, start child proc
	std::string cmd = std::string(argv[0]) + " " + std::string(argv[1]) + " " + std::string(argv[2]) + " " + std::string(argv[3]) + " c";
	printf("[+] MitigationsTest: Started initial parent proc with pid=%i\n", GetCurrentProcessId());
	printf("[+] MitigationsTest: Starting child proc with command: %s\n", cmd.c_str());
	
	if (!start_protected_proc(cmd.c_str(), signOpts)) {
		return 1;
	}
	return 0;
}