#include <cstring>

#include "hook_detector/core/pe_image.h"
#include "hook_detector/scanners/vtable_scanner.h"

namespace hook_detector::scanners {

VTableCheckResult VTableScanner::check_instance(
    const core::ProcessTarget& process,
    uintptr_t instance_address,
    const core::ModuleInfo& owner_mod,
    size_t methods_to_check
) {
    VTableCheckResult result;
    result.instance_address = instance_address;
    result.slot_raw_bytes.assign(sizeof(uintptr_t), 0);
    result.target_function_bytes.assign(16, 0);

    if (!process.is_attached() || instance_address == 0) {
        result.details = "Invalid process or instance address";
        return result;
    }

    uintptr_t vtable_ptr = 0;
    size_t bytes_read = 0;
    if (!process.read_memory(instance_address, &vtable_ptr, sizeof(vtable_ptr), &bytes_read) ||
        bytes_read != sizeof(vtable_ptr) || vtable_ptr == 0) {
        result.details = "Failed to read vtable pointer from instance";
        return result;
    }

    result.vtable_address = vtable_ptr;
    std::memcpy(result.slot_raw_bytes.data(), &vtable_ptr, sizeof(uintptr_t));

    core::PeImage pe(process, owner_mod.base_address);
    bool pe_valid = pe.parse();

    if (pe_valid) {
        if (!pe.is_address_in_section(vtable_ptr, ".rdata")) {
            result.is_hooked = true;
            result.details = "VTable pointer resides outside .rdata section";
        }
    }

    if (methods_to_check == 0) {
        methods_to_check = 10;
    }

    std::vector<uintptr_t> methods(methods_to_check, 0);
    size_t requested_size = methods_to_check * sizeof(uintptr_t);
    if (!process.read_memory(vtable_ptr, methods.data(), requested_size, &bytes_read) || bytes_read == 0) {
        if (!result.is_hooked) {
            result.is_hooked = true;
            result.details = "Failed to read vtable methods";
        }
        return result;
    }

    size_t actual_methods = bytes_read / sizeof(uintptr_t);
    methods.resize(actual_methods);
    result.method_addresses = methods;

    if (!methods.empty()) {
        std::memcpy(result.slot_raw_bytes.data(), &methods[0], sizeof(uintptr_t));
        process.read_memory(methods[0], result.target_function_bytes.data(), 16, &bytes_read);
    }

    for (size_t i = 0; i < methods.size(); ++i) {
        uintptr_t method_addr = methods[i];
        if (method_addr == 0) {
            continue;
        }

        std::vector<uint8_t> m_bytes(16, 0);
        process.read_memory(method_addr, m_bytes.data(), 16, &bytes_read);

        bool is_exec = pe_valid ? pe.is_address_executable(method_addr) : true;
        bool has_jump = (m_bytes[0] == 0xE9) || (m_bytes[0] == 0xFF && m_bytes[1] == 0x25);

        if (!is_exec || has_jump) {
            result.is_hooked = true;
            std::memcpy(result.slot_raw_bytes.data(), &method_addr, sizeof(uintptr_t));
            result.target_function_bytes = m_bytes;

            if (!is_exec) {
                result.details = "VTable method " + std::to_string(i) + " points outside executable memory";
            } else {
                result.details = "VTable method " + std::to_string(i) + " contains hook trampoline";
            }
            return result;
        }
    }

    if (!result.is_hooked) {
        result.details = "Clean vtable";
    }

    return result;
}

}
