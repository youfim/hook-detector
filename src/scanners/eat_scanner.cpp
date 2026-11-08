#include <unordered_map>
#include <cstring>

#include "hook_detector/core/pe_image.h"
#include "hook_detector/scanners/eat_scanner.h"

namespace hook_detector::scanners {

namespace {

std::string read_remote_ascii_string(const core::ProcessTarget& process, uintptr_t address, size_t max_len = 260) {
    std::string result;
    if (address == 0) {
        return result;
    }

    std::vector<char> buffer(max_len, 0);
    size_t bytes_read = 0;
    if (process.read_memory(address, buffer.data(), max_len, &bytes_read)) {
        for (size_t i = 0; i < bytes_read; ++i) {
            if (buffer[i] == '\0') {
                result.assign(buffer.data(), i);
                return result;
            }
        }
        result.assign(buffer.data(), bytes_read);
    }
    return result;
}

}

std::vector<ExportEntry> EatScanner::scan_module(
    const core::ProcessTarget& process,
    const core::ModuleInfo& mod
) {
    std::vector<ExportEntry> entries;
    if (!process.is_attached() || mod.base_address == 0) {
        return entries;
    }

    core::PeImage pe(process, mod.base_address);
    if (!pe.parse()) {
        return entries;
    }

    uintptr_t export_va = 0;
    size_t export_size = 0;
    if (!pe.get_export_directory(export_va, export_size) || export_size == 0) {
        return entries;
    }

    IMAGE_EXPORT_DIRECTORY export_dir{};
    size_t bytes_read = 0;
    if (!process.read_memory(export_va, &export_dir, sizeof(export_dir), &bytes_read) ||
        bytes_read != sizeof(export_dir)) {
        return entries;
    }

    uintptr_t export_start_rva = pe.get_nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uintptr_t export_end_rva = export_start_rva + export_size;

    std::unordered_map<uint16_t, std::string> ordinal_to_name;
    for (DWORD i = 0; i < export_dir.NumberOfNames; ++i) {
        uintptr_t name_rva_addr = pe.rva_to_va(export_dir.AddressOfNames + i * sizeof(uint32_t));
        uintptr_t ordinal_addr = pe.rva_to_va(export_dir.AddressOfNameOrdinals + i * sizeof(uint16_t));

        uint32_t name_rva = 0;
        uint16_t ordinal_index = 0;

        if (process.read_memory(name_rva_addr, &name_rva, sizeof(name_rva), &bytes_read) &&
            process.read_memory(ordinal_addr, &ordinal_index, sizeof(ordinal_index), &bytes_read)) {
            std::string name = read_remote_ascii_string(process, pe.rva_to_va(name_rva));
            ordinal_to_name[ordinal_index] = name;
        }
    }

    for (DWORD f = 0; f < export_dir.NumberOfFunctions; ++f) {
        uintptr_t func_rva_addr = pe.rva_to_va(export_dir.AddressOfFunctions + f * sizeof(uint32_t));
        uint32_t func_rva = 0;

        if (!process.read_memory(func_rva_addr, &func_rva, sizeof(func_rva), &bytes_read) || func_rva == 0) {
            continue;
        }

        ExportEntry entry;
        entry.ordinal = static_cast<uint16_t>(export_dir.Base + f);
        entry.eat_slot_address = func_rva_addr;
        entry.func_rva = func_rva;

        auto it = ordinal_to_name.find(static_cast<uint16_t>(f));
        if (it != ordinal_to_name.end()) {
            entry.function_name = it->second;
        } else {
            entry.function_name = "Ordinal_" + std::to_string(entry.ordinal);
        }

        entry.captured_bytes.assign(16, 0);

        if (func_rva >= export_start_rva && func_rva < export_end_rva) {
            entry.is_forwarded = true;
            entry.forwarder_str = read_remote_ascii_string(process, pe.rva_to_va(func_rva));
            entry.function_address = 0;
            entry.is_anomalous = false;
            entry.details = "Forwarded to: " + entry.forwarder_str;
        } else {
            entry.is_forwarded = false;
            entry.function_address = pe.rva_to_va(func_rva);

            size_t func_read = 0;
            process.read_memory(entry.function_address, entry.captured_bytes.data(), 16, &func_read);

            bool is_valid_va = mod.contains_address(entry.function_address);
            bool is_executable = pe.is_address_executable(entry.function_address);

            if (!is_valid_va) {
                entry.is_anomalous = true;
                entry.details = "Export address points outside module virtual memory";
            } else {
                entry.is_anomalous = false;
                entry.details = is_executable ? "Executable export" : "Data export";
            }
        }

        entries.push_back(std::move(entry));
    }

    return entries;
}

}
