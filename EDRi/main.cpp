#include <chrono>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "hooker.h"
#include "globals.h"
#include "sandblast.h"
#include "utils.h"
#include "filter.h"
#include "profile.h"
#include "etwreader.h"
#include "output.h"
#include "main.h"

#include "helpers/cxxopts.hpp"
#include "helpers/json.hpp"
#include <TraceLoggingProvider.h>

/*
- creates krabs ETW traces for Antimalware, Kernel, etc. and the attack provider
- invokes the attack
- then transforms all captured events into a "filtered" csv, ready for Timeline Explorer
*/


// my provider
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "EDRi-Provider", // name in the ETW, cannot be a variable
    (0x72248477, 0x7177, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

// globals
std::vector<int> g_newly_hooked_procs = std::vector<int>{};
std::vector<ProcInfo> g_running_procs = std::vector<ProcInfo>{};
std::vector<std::string> g_exes_to_track = {
    "smartscreen.exe", "System"
};

// attack exe paths
std::string g_attack_exe_name = "attack-" + get_random_3digit_num() + ".exe"; // random every run
std::string g_attack_exe_path = "C:\\Users\\Public\\Downloads\\" + g_attack_exe_name;

// more debug info
bool g_debug = false;
bool g_super_debug = false;

// misc settings
bool reflective_inject = true;

// wait times
static const int add_wait_for_other_traces = 10000; // ensure all other traces are also started (additional wait)
static const int wait_own_traces_ms = 5000; // own traces also need some time to register
static const int wait_between_events_ms = 1000;
static const int wait_after_termination_ms = 5000;
static const int wait_attack_not_found_threshold_ms = 20000;
static const int wait_time_between_start_markers_ms = 1000;
static const int wait_callbacks_reenable_ms = 21000;
static const int timeout_for_hooker_init = 30;

// etw print prefixes
std::string ok = "[+] ";
std::string fail = "[!] ";
std::string bef = "[<]  ";
std::string aft = "[>]  ";

void emit_etw_event(std::string msg, std::string pre, bool print_when_debug) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "EDRiTask",
        TraceLoggingValue(msg.c_str(), "message"), // cannot be a variable
        TraceLoggingUInt64(ns, "ns_since_epoch")
    );
    if (g_debug && print_when_debug) {
        std::cout << pre << msg << "\n";
    }
}

void process_results(std::string output_events, std::string output_signatures, bool dump_sig, bool colored) {
    std::cout << "\n------------------------------------- Result parsing -------------------------------------\n";
    std::cout << "[+] EDRi: Processing the results...\n";

    int n = get_null_events_count();
    if (n != 0 && g_debug) {
        std::cout << "[-] EDRi: Discarded " << n << " null events due to parsing errors or invalidated by ETW traces before parsed\n";
    }

    if (g_super_debug) {
        dump_proc_map();
    }
    std::vector<json> all_etw_events = concat_all_etw_events();
    filter_all_events(all_etw_events); // etw_events just point to all_etw_events
    write_events_to_file(all_etw_events, output_events, colored);

    if (g_debug) {
        print_etw_counts(all_etw_events);
        print_time_differences();
    }

    if (dump_sig) {
        dump_signatures(all_etw_events, output_signatures); // can only dump from antimalware provider
    }
    std::cout << "[*] EDRi: Done\n";
}

void cleanup(std::string output_events, std::string output_signatures, bool dump_sig, bool colored) {
    remove_file(g_attack_exe_path); // remove again if it still exists
    stop_all_etw_traces();
    process_results(output_events, output_signatures, dump_sig, colored);
}

bool is_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

int main(int argc, char* argv[]) {
    std::cout << BANNER;

    cxxopts::Options options("EDRi");
    options.set_width(120);

    // PARSER OPTIONS
    options.add_options()
        ("h,help", "Print usage")
        ("e,encrypt", "The path of the attack executable to encrypt", cxxopts::value<std::string>())
        ("update-defender2yara", "Update the defender2yara signatures")
        ("p,edr-profile", "The EDR to track, supporting: " + get_available_edrs(), cxxopts::value<std::string>())
        ("just-hook", "Only inject hooks on the relevant EDR processes, then exit again")
        ("a,attack-exe", "The attack to execute, supporting: " + get_available_attacks(), cxxopts::value<std::string>())
        ("own-attack-exe", "An own supplied C:\\path\\to\\attack.exe", cxxopts::value<std::string>())
        ("r,run-as-child", "Execute the attack automatically as a child-proc or manually")
        ("o,output-path-custom", "Writing to " + get_output_path("[name]", true), cxxopts::value<std::string>())
        ("m,trace-etw-misc", "Trace misc ETW")
        ("i,trace-etw-ti", "Trace ETW-TI (needs PPL)")
        ("n,hook-ntdll", "Hook ntdll.dll (needs PPL)")
        ("t,track-all", "Trace misc ETW, ETW-TI and hooks ntdll.dll")
        ("k,no-disable-krnl-callb", "Do not disable kernel callbacks (only applicable if hook-ntdll)")
        ("d,debug", "Print debug info")
        ("v,verbose-debug", "Print very verbose debug info")
        ("c,colored", "Add color formatting information");

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    }
    catch (const cxxopts::exceptions::parsing& e) {
        std::cerr << "Error parsing options: " << e.what() << "\n";
        std::cout << options.help() << "\n";
        return 1;
    }

    // PARSING
    if (result.count("help")) {
        std::cout << options.help() << "\n";
        return 0;
    }

    // update defender2yara
    if (result.count("update-defender2yara") > 0) {
        update_defender2yara_sigs();
        std::cout << "[*] EDRi: Updated defender2yara signatures\n";
        return 0;
    }

    // encrypt an exe
    bool just_copy = false;
    if (result.count("e") > 0) {
        std::string in_path = result["encrypt"].as<std::string>();
        std::string out_path = in_path + ".enc";
        if (xor_file(in_path, out_path, just_copy)) {
            std::cout << "[*] EDRi: XOR encrypted " << in_path << " to " << out_path << "\n";
            return 0;
        }
        else {
            std::cerr << "[!] EDRi: Failed to encrypt " << in_path << "\n";
            return 1;
        }
    }

    // normal run
    std::cout << "\n------------------------------------- EDRi init -------------------------------------\n";
    if (!is_admin()) {
        std::cerr << "[!] EDRi: Please run as administrator\n";
        return 1;
    }
    build_device_map();

    // main variables
    std::string attack_name, attack_exe_enc_path, output_name, output_events, output_signatures;
    bool trace_etw_misc, trace_etw_ti, hook_ntdll, disable_kernel_callbacks_needed, dump_sig, run_as_child, colored;
    std::vector<HANDLE> threads;
    int waited_for_traces_ms;

    // check edr profile
    if (result.count("edr-profile") == 0) {
        std::cerr << "[!] EDRi: No EDR specified, use -p and one of: " << get_available_edrs() << "\n";
        return 1;
    }
    std::string edr_name = result["edr-profile"].as<std::string>();
    if (edr_profiles.find(edr_name) == edr_profiles.end()) {
        std::cerr << "[!] EDRi: Unsupported EDR specified, use one of: " << get_available_edrs() << "\n";
        return 1;
    }
    EDR_Profile edr_profile = edr_profiles.at(edr_name);
    bool just_hook = false;
    if (result.count("just-hook") > 0) {
        just_hook = true;
    }

    // check supplied attack exe (pre-defined or custom)
    if (!just_hook) {
        if (result.count("attack-exe") > 0) {
            attack_name = result["attack-exe"].as<std::string>();
            if (!is_attack_available(attack_name)) {
                std::cerr << "[!] EDRi: Unsupported attack specified, use one of: " << get_available_attacks() << "\n";
                return 1;
            }
            attack_exe_enc_path = get_attack_enc_path(attack_name);
        }
        else if (result.count("own-attack-exe") > 0) {
            just_copy = true;
            std::string own_attack_path = result["own-attack-exe"].as<std::string>(); // do not use own_attack_path after here
            attack_name = check_custum_attack_path(own_attack_path);
            if (attack_name == "") {
                std::cerr << "[!] EDRi: Cannot find own attack exe, please supply a valid path\n";
                return 1;
            }
            attack_exe_enc_path = own_attack_path;
        }
        else {
            std::cerr << "[!] EDRi: No attack specified, set an own attack or use -a and one of: " << get_available_attacks() << "\n";
            return 1;
        }
    }

    // check tracking options
    trace_etw_misc = false, trace_etw_ti = false, hook_ntdll = false;
    if (just_hook) {
        hook_ntdll = true;
    }
    else {
        if (result.count("track-all") > 0) {
            trace_etw_misc = true, trace_etw_ti = true, hook_ntdll = true;
        }
        else {
            if (result.count("trace-etw-misc") > 0) {
                trace_etw_misc = true;
            }
            if (result.count("trace-etw-ti") > 0) {
                trace_etw_ti = true;
            }
            if (result.count("hook-ntdll") > 0) {
                hook_ntdll = true;
            }
        }
    }
    std::cout << "[*] EDRi: Tracking options: ETW-Misc: " << (trace_etw_misc ? "Yes" : "No")
        << ", ETW-TI: " << (trace_etw_ti ? "Yes" : "No")
        << ", Hook-ntdll: " << (hook_ntdll ? "Yes" : "No") << "\n";
    dump_sig = trace_etw_misc; // can only dump signatures if antimalware provider is traced

    disable_kernel_callbacks_needed = hook_ntdll && edr_profile.needs_kernel_callbacks_disabling; // normally needed when hooking ntdll
    if (result.count("no-disable-krnl-callb") > 0) {
        disable_kernel_callbacks_needed = false; // may be not needed when manually disabled / EDR not protecting
    }

    // check output path
    if (!just_hook) {
        if (result.count("output-path-custom") == 0) {
            output_name = edr_name + "-vs-" + attack_name;
        }
        else {
            output_name = result["output-path-custom"].as<std::string>();
        }
        output_events = get_output_path(output_name, true);
        output_signatures = get_output_path(output_name, false);
        std::cout << "[*] EDRi: Writing to " << output_events;
        if (dump_sig) {
            std::cout << " and " << output_signatures;
        }
        std::cout << "\n";

        run_as_child = false;
        if (result.count("run-as-child") > 0) {
            run_as_child = true;
        }
    }

    // debug
    if (result.count("debug") > 0) {
        g_debug = true;
    }
    if (result.count("verbose-debug") > 0) {
        g_debug = true;
        g_super_debug = true;
    }
    colored = false;
    if (result.count("color") > 0) {
        colored = true;
    }

    // TRACKING PREPARATION + INIT ETW TRACES
    TraceLoggingRegister(g_hProvider);
    std::cout << "[+] EDRi: Own provider registered\n";

    if (trace_etw_misc) {
        g_misc_trace_started = false; // needs to be checked, so set to false
        if (!start_etw_misc_traces(threads)) {
            std::cerr << "[!] EDRi: Failed to start misc ETW traces(s)\n";
            return 1;
        }
    }
    if (trace_etw_ti) {
        g_etw_ti_trace_started = false; // needs to be checked, so set to false
        if (!start_etw_ti_trace(threads)) {
            std::cerr << "[!] EDRi: Failed to start ETW-TI traces\n";
            return 1;
        }
    }
    if (hook_ntdll) {
        g_hook_trace_started = false; // needs to be checked, so set to false
        if (!start_etw_hook_trace(threads)) {
            std::cerr << "[!] EDRi: Failed to start ETW-Hook traces\n";
            return 1;
        }
    }
    if (!start_etw_default_traces(threads)) { // start last (start marker is detected here)
        std::cerr << "[!] EDRi: Failed to start default ETW traces(s)\n";
        return 1;
    }

    // WAIT UNTIL TRACES ARE READY
    waited_for_traces_ms = 0;
    std::cout << "[*] EDRi: Waiting until all traces are live and start markers is detected...\n";
    while (!g_start_marked_detected) {
        emit_etw_event(EDRi_TRACE_START_MARKER, "", false);
        Sleep(wait_time_between_start_markers_ms);
        waited_for_traces_ms += wait_time_between_start_markers_ms;
        if (g_debug && ((waited_for_traces_ms / wait_time_between_start_markers_ms) % 5 == 0)) {
            std::cout << "[~] EDRi: Still waiting for own trace...\n"; // print all 10 iterations of waiting
        }
    }
    while (!g_misc_trace_started || !g_etw_ti_trace_started || !g_hook_trace_started) {
        Sleep(wait_time_between_start_markers_ms);
        waited_for_traces_ms += wait_time_between_start_markers_ms;
        if (g_debug && ((waited_for_traces_ms / wait_time_between_start_markers_ms) % 5 == 0)) {
            std::string t = "";
            if (!g_misc_trace_started) { t += "misc "; }
            if (!g_etw_ti_trace_started) { t += "etw-ti "; }
            if (!g_hook_trace_started) { t += "hook "; }
            std::cout << "[~] EDRi: Still waiting for " << t << "traces...\n"; // print all 10 iterations of waiting
        }
    }
    std::cout << "[*] EDRi: All traces started\n";

    // GET PROCS TO TRACK
    // add all EDR specific procs
    for (auto& e : get_all_edr_exes(edr_profile)) {
        g_exes_to_track.push_back(e); // must happen before snapshot!
    }
    // snapshot_procs must be after traces started!
    // -> taking a snapshot of procs first and then starting etw would miss procs started in between
    // -> therefore snapshot_procs() after traces started
    snapshot_procs();
    std::cout << "[*] EDRi: Get running procs\n";
    UINT64 proc_snapshot_timestamp = get_ns_time();
    std::string ut = unnecessary_tools_running();
    if (!ut.empty()) {
        std::cout << "[!] EDRi: Unnecessary tools running: " << ut << "\n";
        std::cout << "[!] EDRi: It is recommended to close them and start again, continuing in 10 sec...\n";
        Sleep(10000);
    }

    // HOOK NTDLL
    // hooking emits etw events, so hooking must be done after the traces are started
    if (hook_ntdll) {
        // get main edr processes and inject the hooker
        std::vector<std::string> main_edr_exes = edr_profile.main_exes;
        std::vector<int> already_hooked_procs = get_hooked_procs();
        std::vector<std::pair<int, std::string>> procs_to_be_hooked;

        for (auto& exe : main_edr_exes) {
            std::vector<int> pids = get_PID_by_name(exe, proc_snapshot_timestamp);
            if (pids.empty()) {
                std::cerr << "[!] EDRi: Could not find the EDR process " << exe << ", is it running?\n";
                continue;
            }
            for (auto& pid : pids) {
                if (std::find(already_hooked_procs.begin(), already_hooked_procs.end(), pid) != already_hooked_procs.end()) {
                    if (g_debug) {
                        std::cout << "[~] EDRi: Found the EDR process " << exe << ":" << pid << ", but already hooked\n";
                    }
                    g_newly_hooked_procs.push_back(pid); // add for next run, only when PID stayed the same
                    continue; // already hooked
                }
                if (g_debug) {
                    std::cout << "[+] EDRi: EDR process " << exe << ":" << pid << " not hooked yet\n";
                }
                procs_to_be_hooked.push_back({ pid, exe });
            }
        }

        // only disable callbacks if not overridden and there are new procs to hook
        bool disable = disable_kernel_callbacks_needed && !procs_to_be_hooked.empty();
        if (disable) {
            if (!disable_kernel_callbacks_ok()) {
                std::cerr << "[!] EDRi: Failed to disable kernel callbacks!\n";
                stop_all_etw_traces();
                return 1;
            }
        }

        // now hook into all found processes
        for (auto& proc : procs_to_be_hooked) {
            int pid = proc.first;
            std::string exe = proc.second;
            if (g_debug) {
                std::cout << "[+] EDRi: Injecting into " << exe << ":" << pid << " ...\n";
            }
            if (!inject_dll(pid, get_hook_dll_path(edr_profile.needs_minimal_hooks), g_debug, reflective_inject)) {
                std::cerr << "[!] EDRi: Failed to inject the hooker dll into " << exe << "\n";
				Sleep(1000); // small wait to ensure the hooker dll released the hooks.txt file
                save_hooked_procs(g_newly_hooked_procs); // save newly hooked procs for next round
                stop_all_etw_traces();
                return 1;
            }
            g_newly_hooked_procs.push_back(pid); // add for next run
        }
        Sleep(1000); // small wait to ensure the hooker dll released the hooks.txt file
        save_hooked_procs(g_newly_hooked_procs); // and save for next round

        // no new procs hooked -> no checks
        if (procs_to_be_hooked.empty()) {
            if (g_debug) {
                std::cout << "[~] EDRi: No new process hooked, no need to check for initialization of the hooker\n";
            }
        }
        // else check if ALL NEWLY hooked procs emitted the hook start msg
        else {
            if (g_debug) {
                std::cout << "[+] EDRi: Hooked " << procs_to_be_hooked.size() << " new process(es), waiting for initialization marker of the hooker...\n";
            }
            int wait = 0;
            while (!g_hooker_started) {
                Sleep(1000);
                if (++wait > timeout_for_hooker_init) {
                    std::cerr << "[!] EDRi: Could not detect a successful initialization(s) of the hooker!\n";
                    stop_all_etw_traces();
                    return 1;
                }
            }
            std::cout << "[*] EDRi: Hooker initialization detected on all relevant processes, wait for re-enabling of kernel callbacks by EDRSandblast...\n";
        }

        if (disable) { // only wait when EDRSandblast was invoked in the first place
            Sleep(wait_callbacks_reenable_ms); // wait until callbacks are reenabled, at least as long as EDRSandblast waits
        }
    }
    if (just_hook) {
        std::cout << "[*] EDRi: Successfully hooked, all done\n";
        return 0;
    }

    std::cout << "\n------------------------------------- Conducting test ------------------------------------\n";

    // ATTACK
    // decrypt the attack exe
    emit_etw_event("Before decrypting the attack exe from " + attack_exe_enc_path, bef, true);
    if (xor_file(attack_exe_enc_path, g_attack_exe_path, just_copy)) {
        std::string action = just_copy ? "Copied" : "Decrypted";
        std::cout << "[*] EDRi: " << action << " the attack exe to: " << g_attack_exe_path << "\n";
    }
    else {
        std::string action = just_copy ? "copy" : "decrypt";
        std::cerr << "[!] EDRi: Failed to " << action << " the attack exe: " << attack_exe_enc_path << "\n";
        stop_all_etw_traces();
        return 1;
    }
    std::string action = just_copy ? "copying" : "decrypting";
    emit_etw_event("After " + action + " the attack exe", aft, true);
    Sleep(wait_between_events_ms);

    // start the attack
    emit_etw_event("Before starting the attack exe", bef, true);
    if (g_debug) {
        std::cout << "[~] EDRi: The EDR might block the attack and a pop up is displayed. In this case, just close it or click OK\n";
    }
    Sleep(wait_between_events_ms);
    if (run_as_child) {
        try {
            if (!launch_as_child(g_attack_exe_path)) {
                std::cerr << "[!] EDRi: Failed to launch the attack exe: " << g_attack_exe_path << ". Was it marked as a virus?\n";
                cleanup(output_events, output_signatures, dump_sig, colored);
                return 0;
            }
        }
        catch (...) {
            std::cerr << "[!] EDRi: Launching attack as child failed: " << GetLastError() << "\n";
            Sleep(wait_after_termination_ms);
            cleanup(output_events, output_signatures, dump_sig, colored);
        }
    }
    else {
        std::cout << "[*] EDRi: Execute " << g_attack_exe_path << " now manually\n";
    }
    int cnt_waited = 0;
    while (g_attack_proc.PID == 0) { // always wait for the attack_PID, lauch_as_child() might succeed even when attack is not started
        Sleep(100);
        cnt_waited += 100;
        if (cnt_waited > wait_attack_not_found_threshold_ms) {
            std::cerr << "[!] EDRi: Timeout waiting for attack PID, did you start " << g_attack_exe_path << ", or was it marked as a virus?\n";
            cleanup(output_events, output_signatures, dump_sig, colored);
            return 0;
        }
    }
    emit_etw_event("After starting the attack exe", aft, true);

    // wait until the attack.exe terminates again
    std::cout << "[+] EDRi: Waiting for the attack exe to finish...\n";
    while (!g_attack_terminated) {
        Sleep(100);
    }
    std::cout << "[+] EDRi: Waiting for any final events...\n";
    Sleep(wait_after_termination_ms);

    // threading stop and cleanup
    std::cout << "[*] EDRi: Stopping traces\n";
    stop_all_etw_traces();
    DWORD res = WaitForMultipleObjects(
        static_cast<DWORD>(threads.size()),
        threads.data(),
        TRUE,
        INFINITE
    ); // wait for all ETW threads to exit
    if (res == WAIT_FAILED) {
        std::cout << "[!] EDRi: Wait failed";
    }
    std::cout << "[*] EDRi: All " << threads.size() << " threads finished\n";
    for (auto h : threads) {
        try {
            CloseHandle(h);
        }
        catch (...) {
            std::cerr << "[!] EDRi: Closing thread handle failed, ignoring...\n";
        }
    }
    threads.clear();

    remove_file(g_attack_exe_path); // remove again

    process_results(output_events, output_signatures, dump_sig, colored);
    return 0;
}