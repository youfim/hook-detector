#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hook_detector::core {

struct ModuleInfo {
    std::wstring name;
    uintptr_t base_address = 0;
    size_t size = 0;
    std::wstring full_path;

    bool contains_address(uintptr_t addr) const {
        return addr >= base_address && addr < (base_address + size);
    }
};

using module_info = ModuleInfo;

enum class ResolutionMethod {
    export_table,
    pattern_scan,
    vtable_slot,
    manual_offset
};

using resolution_method = ResolutionMethod;

struct ResolvedFunction {
    std::string name;
    uintptr_t remote_address = 0;
    ResolutionMethod method = ResolutionMethod::export_table;
    bool is_valid = false;
};

using resolved_function = ResolvedFunction;

}
