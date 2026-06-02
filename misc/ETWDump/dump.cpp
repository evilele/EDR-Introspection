#include <krabs.hpp> // must be before windows.h???

#include <windows.h>
#include <sddl.h>
#include <chrono>
#include <iostream>
#include <string>


static const std::wstring edri_provider = L"{72248477-7177-4feb-a386-34d8f35bb637}"; // EDRi
static const std::wstring attacks_provider = L"{72248466-7166-4feb-a386-34d8f35bb637}"; // attack
static const std::wstring hooks_provider = L"{72248411-7166-4feb-a386-34d8f35bb637}"; // Hooks


bool minimal = false;


bool is_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;

    // Create a SID for the Administrators group.
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group))
    {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    return is_admin == TRUE;
}


std::string unix_epoch_ns_to_iso8601(uint64_t ns_since_epoch)
{
    using namespace std::chrono;
    system_clock::duration duration = duration_cast<system_clock::duration>(nanoseconds(ns_since_epoch));
    system_clock::time_point time_point(duration);
    auto in_time_t = system_clock::to_time_t(time_point);
    auto fractional = duration_cast<nanoseconds>(time_point.time_since_epoch()) % 1'000'000'000;

    // Convert to UTC
    std::tm tm_buf;
    gmtime_s(&tm_buf, &in_time_t);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(9) << std::setfill('0') << fractional.count()
        << "Z"; // UTC

    return oss.str();
}

std::wstring char2wstring(const char* str) {
    if (!str) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (size_needed <= 0) return L"(conversion error)";
    std::wstring wstr(size_needed - 1, 0); // exclude null terminator
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &wstr[0], size_needed);
    return wstr;
}

int wmain(int argc, wchar_t* argv[]) {
    if (!is_admin()) {
        std::wcerr << L"[!] " << argv[0] << " must be run as Administrator.\n";
        return 1;
    }
    std::wstring provider_guid_str;
    if (argc < 2 || argc > 3) {
        std::wcerr << L"[!] Usage: " << argv[0] << L" [EDRi | Attack | Hooks] (minimal)\n";
        return 1;
    }
    if (argc == 3) {
        minimal = true;
    }
    // argc == 2
    wchar_t *p = argv[1];
    if (lstrcmpW(p, L"EDRi") == 0) {
        provider_guid_str = edri_provider;
    }
    else if (lstrcmpW(p, L"Attack") == 0) {
        provider_guid_str = attacks_provider;
    }
    else if (lstrcmpW(p, L"Hooks") == 0) {
        provider_guid_str = hooks_provider;
    }
    else {
        std::wcerr << L"[!] Usage: " << argv[0] << L" [EDRi | Attack | Hooks]\n";
        return 1;
    }

    try {
        // Create provider
        krabs::guid provider_guid(provider_guid_str);
        krabs::provider<> provider(provider_guid);

        // Callback to dump all event fields
        provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
            krabs::schema schema(record, ctx.schema_locator);

			// custom parsing when not using manifest based ETW --> cannot use property parsing
            const BYTE* data = (const BYTE*)record.UserData;
            ULONG size = record.UserDataLength;

            // PARSE MESSAGE
            const char* msg = reinterpret_cast<const char*>(data); // read until first null byte
            size_t msg_len = strnlen(msg, size);
            const BYTE* ptr_field = data + msg_len + 1;

            // PARSE NS_SINCE_EPOCH
            UINT64 ns_since_epoch = 0;
            if (ptr_field + sizeof(UINT64) <= data + size) {
                memcpy(&ns_since_epoch, ptr_field, sizeof(UINT64));
                ptr_field += sizeof(UINT64);
            }
            std::string iso_time = unix_epoch_ns_to_iso8601(ns_since_epoch);

            // PARSE TARGETPID
            uint64_t targetpid = static_cast<uint64_t>(-1);
            if (ptr_field + sizeof(uint64_t) <= data + size) {
                uint64_t tmp;
                memcpy(&tmp, ptr_field, sizeof(tmp));
                targetpid = tmp;
                ptr_field += sizeof(uint64_t);
            }
            
            std::wstring wtask = schema.task_name();
            std::wstring wmsg = char2wstring(msg);
            std::wstring wtime = char2wstring(iso_time.c_str());

            if (minimal) {
                std::wcout << wtime << L": ";
                if (targetpid != static_cast<uint64_t>(-1)) {
                    std::wcout << L"TargetPID=" << std::left << std::setw(5) << std::setfill(L' ') << targetpid << L" - ";
                }
                std::wcout << wmsg.substr(0, 94) << L"\n";
            }
            else {
                std::wcout << L"PID: " << record.EventHeader.ProcessId
                    << L" : " << wtask << L"\n";
                std::wcout << L"  message: " << wmsg << L"\n";
                std::wcout << L"  timestamp: " << wtime << L"\n";
                if (targetpid != static_cast<uint64_t>(-1)) {
                    std::wcout << L"  targetpid: " << targetpid << L"\n";
                }
                std::wcout << L"--------------------------\n";
            }
        });

        // Trace session
        krabs::user_trace trace(L"SimpleKrabsTrace");
        trace.enable(provider);

        std::wcout << L"[*] Listening to " << provider_guid_str << L"..." << L"\n";
        trace.start(); // blocks
    }
    catch (const std::exception& e) {
        std::wcerr << L"Error: " << char2wstring(e.what()) << L"\n";
        return 1;
    }

    return 0;
}