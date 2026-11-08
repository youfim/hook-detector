#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/types.h"
#include "hook_detector/core/process_target.h"

namespace hook_detector::scanners {

struct BytePattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;

    static BytePattern parse(const std::string& ida_style_pattern);
};

using byte_pattern = BytePattern;

class PatternScanner {
public:
    static std::vector<uintptr_t> scan_buffer(
        const uint8_t* data,
        size_t size,
        const BytePattern& pattern,
        uintptr_t base_va = 0
    );

    static std::vector<uintptr_t> scan_module(
        const core::ProcessTarget& process,
        const core::ModuleInfo& mod,
        const BytePattern& pattern
    );
};

using pattern_scanner = PatternScanner;

}
