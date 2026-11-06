#include <windows.h>
#include <stdio.h>
#include <string>

// https://blog.xpnsec.com/protecting-your-malware/
BOOL start_protected_proc(const char* cmd) {
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size = 0;
	BOOL ret;

	// Required for a STARTUPINFOEXA
	ZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

	// Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);

	// Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);

	// Initialise our list 
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

	// Enable blocking of non-Microsoft signed DLLs
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	// Assign our attribute
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

	// Finally, create the process
	ret = CreateProcessA(
		NULL,
		(LPSTR)cmd,
		NULL,
		NULL,
		true,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi
	);
	
	if (!ret) {
		printf("[!] TestSectionSigning: Failed to create protected process. Error: %lu\n", GetLastError());
		return FALSE;
	}

	// Wait indefinitely for the child process to exit (else stdio is broken)
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return TRUE;
}

void check_signing_level() {
	printf("[+] TestSectionSigning: Press enter to check signing level of this process...");
	while (true) {
		char c = getchar();
		if (c != '\n') {
			printf("\n[*] TestSectionSigning: kthxby\n");
			break;
		}

		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };
		if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy))) {
			printf("[!] TestSectionSigning: Failed to get signing level. Error: %lu\n", GetLastError());
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

	if (argc >= 2) {
		printf("[+] TestSectionSigning: Started protected child proc with pid=%i\n", GetCurrentProcessId());
		check_signing_level();
		return 0;
	}

	std::string cmd = std::string(argv[0]) + " c";
	printf("[+] TestSectionSigning: Started initial parent proc with pid=%i\n", GetCurrentProcessId());
	
	if (!start_protected_proc(cmd.c_str())) {
		return 1;
	}
	return 0;
}