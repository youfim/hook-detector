#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cwctype>

#include "hook_detector/core/types.h"
#include "hook_detector/core/privileges.h"
#include "hook_detector/core/process_target.h"
#include "hook_detector/core/pe_image.h"
#include "hook_detector/scanners/pattern_scanner.h"
#include "hook_detector/scanners/inline_hook_scanner.h"
#include "hook_detector/scanners/iat_scanner.h"
#include "hook_detector/scanners/eat_scanner.h"
#include "hook_detector/scanners/vtable_scanner.h"
#include "hook_detector/scanners/hw_breakpoint_scanner.h"
#include "hook_detector/report/hook_report.h"
#include "hook_detector/report/json_exporter.h"

namespace {

void print_banner() {
    std::cout << "======================================================================\n";
    std::cout << "               HOOK DETECTOR (C++20 / Windows x64)                    \n";
    std::cout << "======================================================================\n\n";
}

void print_usage(const char* exe_name) {
    std::cout << "Usage:\n";
    std::cout << "  " << exe_name << " --pid <ProcessID> [options]\n";
    std::cout << "  " << exe_name << " --name <ProcessName.exe> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --module, -m <name>      Target module(s) for deep scanning (comma-separated or multiple)\n";
    std::cout << "  --all-game-modules       Target all non-system game/application modules (default)\n";
    std::cout << "  --all-modules            Target all loaded modules without exception\n";
    std::cout << "  --no-system              Exclude Windows system modules (ntdll, kernel32, user32, etc.)\n";
    std::cout << "  --json <file_path>       Export scan results to JSON file\n";
    std::cout << "  --help, -h               Display this help message\n\n";
}

std::string wide_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) {
        return "";
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return "";
    }
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring utf8_to_wide(const std::string& str) {
    if (str.empty()) {
        return L"";
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    if (size <= 0) {
        return L"";
    }
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), result.data(), size);
    return result;
}

bool string_starts_with(const std::string& str, const std::string& prefix) {
    return str.rfind(prefix, 0) == 0;
}

std::string to_lower_string(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

std::string to_hex_string(uint64_t val) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(val));
    return std::string(buf);
}

std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string current;
    for (char ch : str) {
        if (ch == delimiter) {
            size_t first = current.find_first_not_of(" \t\r\n");
            size_t last = current.find_last_not_of(" \t\r\n");
            if (first != std::string::npos && last != std::string::npos) {
                tokens.push_back(current.substr(first, last - first + 1));
            } else if (!current.empty()) {
                tokens.push_back(current);
            }
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    size_t first = current.find_first_not_of(" \t\r\n");
    size_t last = current.find_last_not_of(" \t\r\n");
    if (first != std::string::npos && last != std::string::npos) {
        tokens.push_back(current.substr(first, last - first + 1));
    } else if (!current.empty()) {
        tokens.push_back(current);
    }
    return tokens;
}

bool is_windows_system_module(const std::wstring& full_path) {
    if (full_path.empty()) {
        return false;
    }
    std::wstring lower_path = full_path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::towlower);

    wchar_t win_dir[MAX_PATH] = {0};
    UINT len = GetWindowsDirectoryW(win_dir, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        std::wstring lower_windir = win_dir;
        std::transform(lower_windir.begin(), lower_windir.end(), lower_windir.begin(), ::towlower);
        if (lower_path.rfind(lower_windir, 0) == 0) {
            return true;
        }
    }

    if (lower_path.find(L"\\windows\\") != std::wstring::npos) {
        return true;
    }

    return false;
}

bool is_targeted_module(const hook_detector::core::ModuleInfo& mod,
                        const std::vector<const hook_detector::core::ModuleInfo*>& targets) {
    for (const auto* tmod : targets) {
        if (tmod == &mod) {
            return true;
        }
    }
    return false;
}

}

int main(int argc, char* argv[]) {
    print_banner();

    DWORD target_pid = 0;
    std::wstring target_name;
    std::string json_output_path;
    std::vector<std::string> module_filters;
    bool scan_all_game_modules = false;
    bool scan_all_modules = false;
    bool exclude_system = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" && i + 1 < argc) {
            target_pid = static_cast<DWORD>(std::stoul(argv[++i]));
        } else if (arg == "--name" && i + 1 < argc) {
            target_name = utf8_to_wide(argv[++i]);
        } else if ((arg == "--module" || arg == "-m") && i + 1 < argc) {
            auto parts = split_string(argv[++i], ',');
            for (const auto& p : parts) {
                if (!p.empty()) {
                    module_filters.push_back(p);
                }
            }
        } else if (arg == "--all-game-modules" || arg == "--game") {
            scan_all_game_modules = true;
        } else if (arg == "--all-modules" || arg == "--all") {
            scan_all_modules = true;
        } else if (arg == "--no-system" || arg == "--exclude-system") {
            exclude_system = true;
        } else if (arg == "--json" && i + 1 < argc) {
            json_output_path = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "[-] Unknown argument: " << arg << "\n\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (target_pid == 0 && target_name.empty()) {
        std::cerr << "[-] Error: Target process must be specified via --pid or --name\n\n";
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "[*] Enabling SeDebugPrivilege..." << std::endl;
    if (hook_detector::core::enable_debug_privilege()) {
        std::cout << "[+] SeDebugPrivilege enabled successfully." << std::endl;
    } else {
        std::cout << "[-] Warning: Failed to enable SeDebugPrivilege. Proceeding with current token rights." << std::endl;
    }

    hook_detector::core::ProcessTarget process;
    bool attached = false;

    if (target_pid != 0) {
        std::cout << "[*] Attaching to process PID " << target_pid << "..." << std::endl;
        attached = process.attach_by_pid(target_pid);
    } else {
        std::wcout << L"[*] Searching for process '" << target_name << L"'..." << std::endl;
        attached = process.attach_by_name(target_name);
    }

    if (!attached) {
        std::cerr << "[-] Fatal: Failed to attach to target process." << std::endl;
        return 1;
    }

    std::wcout << L"[+] Attached to process: " << process.get_name()
               << L" (PID: " << process.get_pid() << L")" << std::endl;

    if (process.is_wow64()) {
        std::cout << "[-] Warning: Target process is running under WoW64 (32-bit). Scanner is optimized for native x64." << std::endl;
    }

    std::cout << "[*] Enumerating loaded modules..." << std::endl;
    auto modules = process.enumerate_modules();
    std::cout << "[+] Found " << modules.size() << " loaded modules." << std::endl;

    hook_detector::core::DiskImageProvider disk_provider;
    std::vector<const hook_detector::core::ModuleInfo*> target_modules;

    if (scan_all_modules) {
        for (const auto& mod : modules) {
            target_modules.push_back(&mod);
        }
    } else if (!module_filters.empty()) {
        for (const auto& filter : module_filters) {
            std::string filter_lower = to_lower_string(filter);
            bool found = false;

            for (const auto& mod : modules) {
                std::string mod_lower = to_lower_string(wide_to_utf8(mod.name));
                if (mod_lower == filter_lower) {
                    if (std::find(target_modules.begin(), target_modules.end(), &mod) == target_modules.end()) {
                        target_modules.push_back(&mod);
                    }
                    found = true;
                    break;
                }
            }

            if (!found) {
                for (const auto& mod : modules) {
                    std::string mod_lower = to_lower_string(wide_to_utf8(mod.name));
                    if (mod_lower.find(filter_lower) != std::string::npos) {
                        if (std::find(target_modules.begin(), target_modules.end(), &mod) == target_modules.end()) {
                            target_modules.push_back(&mod);
                        }
                        found = true;
                    }
                }
            }

            if (!found) {
                std::cerr << "[-] Warning: Specified module '" << filter << "' was not found." << std::endl;
            }
        }
    } else {
        for (const auto& mod : modules) {
            if (!is_windows_system_module(mod.full_path)) {
                target_modules.push_back(&mod);
            }
        }
    }

    std::cout << "[*] Selected " << target_modules.size() << " module(s) for deep inspection:" << std::endl;
    if (target_modules.size() <= 8) {
        for (const auto* mod : target_modules) {
            std::wcout << L"    - " << mod->name << L" (Base: 0x" << std::hex << mod->base_address
                       << L" Size: 0x" << mod->size << std::dec << L")" << std::endl;
        }
    } else {
        for (size_t idx = 0; idx < 6; ++idx) {
            std::wcout << L"    - " << target_modules[idx]->name << L" (Base: 0x" << std::hex
                       << target_modules[idx]->base_address << std::dec << L")" << std::endl;
        }
        std::wcout << L"    ... and " << (target_modules.size() - 6) << L" more modules." << std::endl;
    }

    size_t mapped_count = 0;
    for (const auto* target_mod : target_modules) {
        auto img = disk_provider.get_image(target_mod->full_path);
        if (img && img->is_valid()) {
            ++mapped_count;
            if (target_modules.size() <= 3) {
                std::wcout << L"[+] Mapped on-disk image: " << target_mod->name << std::endl;
            }
        }
    }
    if (target_modules.size() > 3) {
        std::cout << "[+] Mapped " << mapped_count << " on-disk images for original byte comparison." << std::endl;
    }

    hook_detector::report::HookReport report;

    std::cout << "\n[*] [Stage 1/5] Scanning hardware debug registers..." << std::endl;
    auto hw_breakpoints = hook_detector::scanners::HwBreakpointScanner::scan_process(process);
    for (const auto& bp : hw_breakpoints) {
        if (bp.is_active) {
            hook_detector::report::Finding f;
            f.type = hook_detector::report::FindingType::hw_breakpoint;
            f.severity = hook_detector::report::FindingSeverity::critical;
            f.module_name = wide_to_utf8(process.get_name());
            f.function_name = "Thread_" + std::to_string(bp.thread_id);
            f.resolved_via = hook_detector::core::ResolutionMethod::manual_offset;
            f.address = bp.dr0 != 0 ? bp.dr0 : (bp.dr1 != 0 ? bp.dr1 : (bp.dr2 != 0 ? bp.dr2 : bp.dr3));
            f.redirect_target = 0;
            f.details = bp.details;
            f.captured_bytes = bp.captured_bytes;
            report.add_finding(std::move(f));
        }
    }

    std::cout << "[*] [Stage 2/5] Scanning Import Address Tables (IAT)..." << std::endl;
    size_t iat_scanned_count = 0;
    for (const auto& mod : modules) {
        if (exclude_system && is_windows_system_module(mod.full_path)) {
            continue;
        }
        std::string mod_utf8 = wide_to_utf8(mod.name);
        auto iat_entries = hook_detector::scanners::IatScanner::scan_module(process, mod, modules);
        iat_scanned_count += iat_entries.size();

        for (const auto& entry : iat_entries) {
            if (entry.is_hooked) {
                hook_detector::report::Finding f;
                f.type = hook_detector::report::FindingType::iat_hook;
                f.severity = hook_detector::report::FindingSeverity::high;
                f.module_name = mod_utf8;
                f.function_name = entry.function_name.empty() ? entry.module_name : (entry.module_name + "!" + entry.function_name);
                f.resolved_via = hook_detector::core::ResolutionMethod::export_table;
                f.address = entry.iat_slot_address;
                f.redirect_target = entry.target_function_address;
                f.details = entry.details;
                f.captured_bytes = entry.slot_raw_bytes;
                f.expected_bytes = disk_provider.get_original_bytes(mod, entry.iat_slot_address, sizeof(uint64_t));
                report.add_finding(std::move(f));
            }
        }
    }
    std::cout << "[+] Processed " << iat_scanned_count << " IAT slots across loaded modules." << std::endl;

    std::cout << "[*] [Stage 3/5] Scanning Export Address Tables (EAT)..." << std::endl;
    size_t eat_scanned_count = 0;
    for (const auto& mod : modules) {
        std::string mod_utf8 = wide_to_utf8(mod.name);
        std::string mod_lower = to_lower_string(mod_utf8);

        bool is_system_lib = !exclude_system && (mod_lower.find("ntdll.dll") != std::string::npos ||
                              mod_lower.find("kernel32.dll") != std::string::npos ||
                              mod_lower.find("kernelbase.dll") != std::string::npos ||
                              mod_lower.find("user32.dll") != std::string::npos);

        bool is_targeted = is_targeted_module(mod, target_modules);

        if (!is_system_lib && !is_targeted) {
            continue;
        }

        auto exports = hook_detector::scanners::EatScanner::scan_module(process, mod);
        eat_scanned_count += exports.size();

        for (const auto& exp : exports) {
            if (exp.is_forwarded || exp.eat_slot_address == 0) {
                continue;
            }

            std::vector<uint8_t> orig_slot = disk_provider.get_original_bytes(mod, exp.eat_slot_address, sizeof(uint32_t));
            bool is_eat_hooked = false;
            std::string hook_detail;

            if (orig_slot.size() == sizeof(uint32_t)) {
                uint32_t orig_rva = 0;
                std::memcpy(&orig_rva, orig_slot.data(), sizeof(uint32_t));
                if (orig_rva != exp.func_rva) {
                    is_eat_hooked = true;
                    hook_detail = "EAT slot RVA rewritten in memory (Memory RVA: 0x" +
                                  to_hex_string(exp.func_rva) +
                                  ", Disk RVA: 0x" +
                                  to_hex_string(orig_rva) + ")";
                }
            } else if (exp.is_anomalous) {
                is_eat_hooked = true;
                hook_detail = exp.details;
            }

            if (is_eat_hooked) {
                hook_detector::report::Finding f;
                f.type = hook_detector::report::FindingType::eat_hook;
                f.severity = hook_detector::report::FindingSeverity::high;
                f.module_name = mod_utf8;
                f.function_name = exp.function_name;
                f.resolved_via = hook_detector::core::ResolutionMethod::export_table;
                f.address = exp.function_address;
                f.redirect_target = 0;
                f.details = hook_detail;
                f.captured_bytes = exp.captured_bytes;
                f.expected_bytes = disk_provider.get_original_bytes(mod, exp.function_address, 16);
                report.add_finding(std::move(f));
            }
        }
    }
    std::cout << "[+] Verified " << eat_scanned_count << " exports across monitored libraries." << std::endl;

    std::cout << "[*] [Stage 4/5] Scanning exported functions for inline hooks..." << std::endl;
    for (const auto& mod : modules) {
        std::string mod_utf8 = wide_to_utf8(mod.name);
        std::string mod_lower = to_lower_string(mod_utf8);

        bool is_ntdll = !exclude_system && (mod_lower.find("ntdll.dll") != std::string::npos);
        bool is_kernel32 = !exclude_system && (mod_lower.find("kernel32.dll") != std::string::npos);
        bool is_kernelbase = !exclude_system && (mod_lower.find("kernelbase.dll") != std::string::npos);
        bool is_user32 = !exclude_system && (mod_lower.find("user32.dll") != std::string::npos);
        bool is_targeted = is_targeted_module(mod, target_modules);

        if (!is_ntdll && !is_kernel32 && !is_kernelbase && !is_user32 && !is_targeted) {
            continue;
        }

        hook_detector::core::PeImage mod_pe(process, mod.base_address);
        if (!mod_pe.parse()) {
            continue;
        }

        auto exports = hook_detector::scanners::EatScanner::scan_module(process, mod);
        for (const auto& exp : exports) {
            if (exp.is_forwarded || exp.function_address == 0) {
                continue;
            }

            if (!mod_pe.is_address_executable(exp.function_address)) {
                continue;
            }

            bool should_check = is_targeted;
            if (is_ntdll && string_starts_with(exp.function_name, "Nt")) {
                should_check = true;
            } else if (is_kernel32 || is_kernelbase) {
                if (exp.function_name == "VirtualAlloc" ||
                    exp.function_name == "VirtualProtect" ||
                    exp.function_name == "WriteProcessMemory" ||
                    exp.function_name == "CreateRemoteThread" ||
                    exp.function_name == "LoadLibraryW" ||
                    exp.function_name == "LoadLibraryA" ||
                    exp.function_name == "GetProcAddress") {
                    should_check = true;
                }
            } else if (is_user32) {
                if (exp.function_name.find("Cursor") != std::string::npos ||
                    exp.function_name.find("Message") != std::string::npos ||
                    exp.function_name.find("Input") != std::string::npos ||
                    exp.function_name.find("Key") != std::string::npos ||
                    exp.function_name.find("Capture") != std::string::npos) {
                    should_check = true;
                }
            }

            if (!should_check) {
                continue;
            }

            std::vector<uint8_t> expected_prologue = disk_provider.get_original_bytes(mod, exp.function_address, 16);
            if (expected_prologue.empty() && is_ntdll && string_starts_with(exp.function_name, "Nt")) {
                expected_prologue = {0x4C, 0x8B, 0xD1, 0xB8};
            }

            auto inline_result = hook_detector::scanners::InlineHookScanner::check_function(
                process,
                exp.function_address,
                expected_prologue,
                16
            );

            if (inline_result.is_hooked) {
                hook_detector::report::Finding f;
                f.type = hook_detector::report::FindingType::inline_hook;
                f.severity = hook_detector::report::FindingSeverity::critical;
                f.module_name = mod_utf8;
                f.function_name = exp.function_name;
                f.resolved_via = hook_detector::core::ResolutionMethod::export_table;
                f.address = exp.function_address;
                f.redirect_target = inline_result.target_address;
                f.details = inline_result.details;
                f.captured_bytes = inline_result.captured_bytes;
                f.expected_bytes = !expected_prologue.empty() ? expected_prologue : inline_result.expected_bytes;
                report.add_finding(std::move(f));
            }
        }
    }

    if (!target_modules.empty()) {
        std::cout << "[*] [Stage 5/5] Deep scanning code sections (.text) across "
                  << target_modules.size() << " target module(s)..." << std::endl;
        size_t total_deep_findings = 0;

        for (const auto* target_mod : target_modules) {
            hook_detector::core::PeImage target_pe(process, target_mod->base_address);
            if (!target_pe.parse()) {
                continue;
            }

            uintptr_t text_start = 0;
            size_t text_size = 0;
            if (!target_pe.get_section_bounds(".text", text_start, text_size) || text_size == 0) {
                continue;
            }

            const size_t chunk_size = 4 * 1024 * 1024;
            std::vector<uint8_t> buffer(chunk_size);
            size_t mod_findings = 0;

            for (size_t offset = 0; offset < text_size; offset += (chunk_size - 64)) {
                size_t to_read = std::min(chunk_size, text_size - offset);
                size_t bytes_read = 0;

                if (!process.read_memory(text_start + offset, buffer.data(), to_read, &bytes_read) || bytes_read < 16) {
                    continue;
                }

                for (size_t i = 0; i + 14 < bytes_read; ++i) {
                    bool is_function_boundary = (i == 0 ||
                                                 buffer[i - 1] == 0xCC ||
                                                 buffer[i - 1] == 0x90 ||
                                                 buffer[i - 1] == 0xC3);

                    if (!is_function_boundary) {
                        continue;
                    }

                    uintptr_t current_va = text_start + offset + i;
                    uintptr_t target_va = 0;
                    bool found_trampoline = false;
                    std::string hook_descr;

                    if (buffer[i] == 0xE9) {
                        int32_t rel32 = 0;
                        std::memcpy(&rel32, &buffer[i + 1], sizeof(int32_t));
                        target_va = current_va + 5 + static_cast<intptr_t>(rel32);

                        if (!target_mod->contains_address(target_va)) {
                            MEMORY_BASIC_INFORMATION mbi{};
                            if (VirtualQueryEx(process.get_handle(), reinterpret_cast<LPCVOID>(target_va), &mbi, sizeof(mbi)) != 0) {
                                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                                    if (mbi.Type == MEM_PRIVATE) {
                                        found_trampoline = true;
                                        hook_descr = "External jmp rel32 (E9) targeting private executable memory (MEM_PRIVATE)";
                                    } else if (mbi.Type == MEM_IMAGE) {
                                        bool is_known_module = false;
                                        for (const auto& km : modules) {
                                            if (km.contains_address(target_va)) {
                                                is_known_module = true;
                                                break;
                                            }
                                        }
                                        if (!is_known_module) {
                                            found_trampoline = true;
                                            hook_descr = "External jmp rel32 (E9) targeting unlisted foreign image memory";
                                        }
                                    }
                                }
                            }
                        }
                    } else if (buffer[i] == 0xFF && buffer[i + 1] == 0x25) {
                        int32_t disp32 = 0;
                        std::memcpy(&disp32, &buffer[i + 2], sizeof(int32_t));
                        uintptr_t ptr_location = current_va + 6 + static_cast<intptr_t>(disp32);
                        uint64_t imm_target = 0;
                        if (disp32 == 0) {
                            std::memcpy(&imm_target, &buffer[i + 6], sizeof(uint64_t));
                        } else {
                            process.read_memory(ptr_location, &imm_target, sizeof(uint64_t));
                        }
                        if (imm_target != 0) {
                            target_va = static_cast<uintptr_t>(imm_target);
                            if (!target_mod->contains_address(target_va)) {
                                MEMORY_BASIC_INFORMATION mbi{};
                                if (VirtualQueryEx(process.get_handle(), reinterpret_cast<LPCVOID>(target_va), &mbi, sizeof(mbi)) != 0) {
                                    if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                                        if (mbi.Type == MEM_PRIVATE) {
                                            found_trampoline = true;
                                            hook_descr = "External jmp [rip+disp32] (FF 25) targeting private executable memory";
                                        }
                                    }
                                }
                            }
                        }
                    } else if (buffer[i] == 0x48 && buffer[i + 1] == 0xB8 && buffer[i + 10] == 0xFF && buffer[i + 11] == 0xE0) {
                        uint64_t imm_target = 0;
                        std::memcpy(&imm_target, &buffer[i + 2], sizeof(uint64_t));
                        target_va = static_cast<uintptr_t>(imm_target);

                        if (!target_mod->contains_address(target_va)) {
                            MEMORY_BASIC_INFORMATION mbi{};
                            if (VirtualQueryEx(process.get_handle(), reinterpret_cast<LPCVOID>(target_va), &mbi, sizeof(mbi)) != 0) {
                                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                                    if (mbi.Type == MEM_PRIVATE) {
                                        found_trampoline = true;
                                        hook_descr = "External mov rax, imm64 / jmp rax targeting private executable memory";
                                    }
                                }
                            }
                        }
                    }

                    if (found_trampoline) {
                        std::vector<uint8_t> captured(16, 0);
                        std::memcpy(captured.data(), &buffer[i], std::min<size_t>(16, bytes_read - i));

                        hook_detector::report::Finding f;
                        f.type = hook_detector::report::FindingType::inline_hook;
                        f.severity = hook_detector::report::FindingSeverity::critical;
                        f.module_name = wide_to_utf8(target_mod->name);
                        f.function_name = "func_prologue_0x" + std::to_string(offset + i);
                        f.resolved_via = hook_detector::core::ResolutionMethod::pattern_scan;
                        f.address = current_va;
                        f.redirect_target = target_va;
                        f.details = hook_descr;
                        f.captured_bytes = captured;
                        f.expected_bytes = disk_provider.get_original_bytes(*target_mod, current_va, 16);

                        report.add_finding(std::move(f));
                        ++mod_findings;
                        ++total_deep_findings;

                        i += 4;
                    }
                }
            }

            if (mod_findings > 0) {
                std::wcout << L"[+] Module " << target_mod->name << L": detected "
                           << mod_findings << L" inline trampolines." << std::endl;
            }
        }

        std::cout << "[+] Deep scan complete across target modules. Total trampolines found: "
                  << total_deep_findings << std::endl;
    }

    report.print_to_console();

    if (!json_output_path.empty()) {
        std::cout << "[*] Exporting results to JSON: " << json_output_path << "..." << std::endl;
        hook_detector::report::ScanInfo scan_info;
        scan_info.pid = process.get_pid();
        scan_info.process_name = wide_to_utf8(process.get_name());
        scan_info.scan_time_utc = hook_detector::report::JsonExporter::get_current_utc_iso8601();
        scan_info.scanner_version = "1.0.0";

        if (hook_detector::report::JsonExporter::export_to_file(report, scan_info, json_output_path)) {
            std::cout << "[+] JSON report saved successfully." << std::endl;
        } else {
            std::cerr << "[-] Error: Failed to write JSON report to: " << json_output_path << std::endl;
        }
    }

    return 0;
}
