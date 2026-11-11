#include <windows.h>
#include <stdio.h>
#include <string>

enum SignOptions {
	OPT_MICROSOFT_SIGNED_ONLY,
	OPT_STORE_SIGNED_ONLY,
	OPT_NONE
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

	if (options != OPT_NONE) {
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
		if (options == OPT_STORE_SIGNED_ONLY) {
			policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE;
		}
		else if (options == OPT_MICROSOFT_SIGNED_ONLY) {
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
	printf("[+] MitigationsTest: Press enter to check signing level of this process...");
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

int main(int argc, char* argv[]) {

	if (argc < 3) {
		printf("[!] Usage: %s <Signing Options> <Mitigation Options> <reserved_for_child_proc>\n", argv[0]);
		printf("[!]   Signing Options: <s> for StoreSignedOnly, <m> for MicrosoftSignedOnly, <n> for No Signing\n");
		printf("[!]   Mitigation Options: <a> for ACG, <n> for No Mitigation\n");
		return 1;
	}

	// check if already in child proc
	if (argc > 3 && strcmp(argv[3], "c") == 0) {
		printf("[+] MitigationsTest: Started child proc with pid=%i\n", GetCurrentProcessId());

		if (strcmp(argv[2], "a") == 0) { // and check if in child proc and child proc should also be ACG
			PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy;
			ZeroMemory(&policy, sizeof(policy));
			policy.ProhibitDynamicCode = 1;
			if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)) == false) {
				printf("[!] MitigationsTest: SetProcessMitigationPolicy ACG failed\n");
				return 1;
			}
			printf("[+] MitigationsTest: SetProcessMitigationPolicy ACG succeeded\n");
		}

		continually_check_signing_level();
		return 0;
	}
	
	// else parse options in parent proc
	SignOptions options = OPT_NONE;
	if (strcmp(argv[1], "s") == 0) {
		options = OPT_STORE_SIGNED_ONLY;
		printf("[+] MitigationsTest: Will start child proc with StoreSignedOnly\n");
	}
	else if (strcmp(argv[1], "m") == 0) {
		options = OPT_MICROSOFT_SIGNED_ONLY;
		printf("[+] MitigationsTest: Will start child proc with MicrosoftSignedOnly\n");
	}
	else {
		options = OPT_NONE;
		printf("[+] MitigationsTest: Will start child proc with No Signing\n");
	}

	// in parent proc, start child proc
	std::string cmd = std::string(argv[0]) + " " + std::string(argv[1]) + " " + std::string(argv[2]) + " c";
	printf("[+] MitigationsTest: Started initial parent proc with pid=%i\n", GetCurrentProcessId());
	printf("[+] MitigationsTest: Starting child proc with command: %s\n", cmd.c_str());
	
	if (!start_protected_proc(cmd.c_str(), options)) {
		return 1;
	}
	return 0;
}