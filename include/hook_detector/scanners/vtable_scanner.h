#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/types.h"
#include "hook_detector/core/process_target.h"

namespace hook_detector::scanners {

struct VTableCheckResult {
    uintptr_t instance_address = 0;
    uintptr_t vtable_address = 0;
    std::vector<uintptr_t> method_addresses;
    std::vector<uint8_t> slot_raw_bytes;
    std::vector<uint8_t> target_function_bytes;
    bool is_hooked = false;
    std::string details;
};

using vtable_check_result = VTableCheckResult;

class VTableScanner {
public:
    static VTableCheckResult check_instance(
        const core::ProcessTarget& process,
        uintptr_t instance_address,
        const core::ModuleInfo& owner_mod,
        size_t methods_to_check = 10
    );
};

using vtable_scanner = VTableScanner;

}
