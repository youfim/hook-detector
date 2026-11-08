#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/types.h"
#include "hook_detector/core/process_target.h"

namespace hook_detector::scanners {

struct ExportEntry {
    std::string function_name;
    uint16_t ordinal = 0;
    uintptr_t eat_slot_address = 0;
    uint32_t func_rva = 0;
    uintptr_t function_address = 0;
    bool is_forwarded = false;
    std::string forwarder_str;
    std::vector<uint8_t> captured_bytes;
    bool is_anomalous = false;
    std::string details;
};

using export_entry = ExportEntry;

class EatScanner {
public:
    static std::vector<ExportEntry> scan_module(
        const core::ProcessTarget& process,
        const core::ModuleInfo& mod
    );
};

using eat_scanner = EatScanner;

}
