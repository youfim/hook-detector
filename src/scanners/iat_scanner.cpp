#include <cstring>
#include <algorithm>

#include "hook_detector/core/pe_image.h"
#include "hook_detector/scanners/iat_scanner.h"

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

std::vector<IatEntry> IatScanner::scan_module(
    const core::ProcessTarget& process,
    const core::ModuleInfo& mod,
    const std::vector<core::ModuleInfo>& all_modules
) {
    std::vector<IatEntry> entries;
    if (!process.is_attached() || mod.base_address == 0) {
        return entries;
    }

    core::PeImage pe(process, mod.base_address);
    if (!pe.parse()) {
        return entries;
    }

    uintptr_t import_va = 0;
    size_t import_size = 0;
    if (!pe.get_import_directory(import_va, import_size) || import_size == 0) {
        return entries;
    }

    uintptr_t current_desc_va = import_va;
    while (true) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        size_t bytes_read = 0;
        if (!process.read_memory(current_desc_va, &desc, sizeof(desc), &bytes_read) || bytes_read != sizeof(desc)) {
            break;
        }

        if (desc.Characteristics == 0 && desc.FirstThunk == 0) {
            break;
        }

        std::string imported_dll_name = read_remote_ascii_string(process, pe.rva_to_va(desc.Name));
        uintptr_t thunk_rva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
        uintptr_t iat_rva = desc.FirstThunk;

        size_t index = 0;
        while (true) {
            uintptr_t current_thunk_va = pe.rva_to_va(static_cast<uint32_t>(thunk_rva + index * sizeof(uint64_t)));
            uintptr_t current_iat_slot_va = pe.rva_to_va(static_cast<uint32_t>(iat_rva + index * sizeof(uint64_t)));

            IMAGE_THUNK_DATA64 thunk_data{};
            if (!process.read_memory(current_thunk_va, &thunk_data, sizeof(thunk_data), &bytes_read) ||
                bytes_read != sizeof(thunk_data)) {
                break;
            }

            if (thunk_data.u1.AddressOfData == 0) {
                break;
            }

            IatEntry entry;
            entry.module_name = imported_dll_name;
            entry.iat_slot_address = current_iat_slot_va;
            entry.slot_raw_bytes.assign(sizeof(uint64_t), 0);
            entry.target_function_bytes.assign(16, 0);

            if (IMAGE_SNAP_BY_ORDINAL64(thunk_data.u1.Ordinal)) {
                entry.ordinal = static_cast<uint16_t>(IMAGE_ORDINAL64(thunk_data.u1.Ordinal));
                entry.function_name = "Ordinal_" + std::to_string(entry.ordinal);
            } else {
                uintptr_t name_data_va = pe.rva_to_va(static_cast<uint32_t>(thunk_data.u1.AddressOfData));
                WORD hint = 0;
                process.read_memory(name_data_va, &hint, sizeof(hint), &bytes_read);
                entry.ordinal = hint;
                entry.function_name = read_remote_ascii_string(process, name_data_va + sizeof(WORD));
            }

            size_t slot_read = 0;
            if (process.read_memory(current_iat_slot_va, entry.slot_raw_bytes.data(), sizeof(uint64_t), &slot_read) &&
                slot_read == sizeof(uint64_t)) {
                std::memcpy(&entry.target_function_address, entry.slot_raw_bytes.data(), sizeof(uint64_t));
            }

            if (entry.target_function_address != 0) {
                size_t func_read = 0;
                process.read_memory(entry.target_function_address, entry.target_function_bytes.data(), 16, &func_read);
            }

            if (entry.target_function_address == 0) {
                entry.is_hooked = false;
                entry.details = "IAT slot contains null pointer";
            } else {
                bool in_known_module = false;
                for (const auto& known_mod : all_modules) {
                    if (known_mod.contains_address(entry.target_function_address)) {
                        in_known_module = true;
                        break;
                    }
                }

                if (!in_known_module) {
                    entry.is_hooked = true;
                    entry.details = "IAT slot points outside all loaded modules (private or unmapped memory)";
                } else {
                    entry.is_hooked = false;
                    entry.details = "Legitimate module pointer";
                }
            }

            entries.push_back(std::move(entry));
            ++index;
        }

        current_desc_va += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return entries;
}

}
