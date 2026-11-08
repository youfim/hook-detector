#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/types.h"
#include "hook_detector/core/process_target.h"

namespace hook_detector::scanners {

struct IatEntry {
    std::string module_name;
    std::string function_name;
    uint16_t ordinal = 0;
    uintptr_t iat_slot_address = 0;
    uintptr_t target_function_address = 0;
    std::vector<uint8_t> slot_raw_bytes;
    std::vector<uint8_t> target_function_bytes;
    bool is_hooked = false;
    std::string details;
};

using iat_entry = IatEntry;

class IatScanner {
public:
    static std::vector<IatEntry> scan_module(
        const core::ProcessTarget& process,
        const core::ModuleInfo& mod,
        const std::vector<core::ModuleInfo>& all_modules
    );
};

using iat_scanner = IatScanner;

}
