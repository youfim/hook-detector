#include <sstream>
#include <iomanip>

#include "hook_detector/core/pe_image.h"
#include "hook_detector/scanners/pattern_scanner.h"

namespace hook_detector::scanners {

BytePattern BytePattern::parse(const std::string& ida_style_pattern) {
    BytePattern pattern;
    std::istringstream stream(ida_style_pattern);
    std::string token;

    while (stream >> token) {
        if (token == "?" || token == "??") {
            pattern.bytes.push_back(0);
            pattern.mask.push_back(false);
        } else {
            uint8_t byte_val = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
            pattern.bytes.push_back(byte_val);
            pattern.mask.push_back(true);
        }
    }

    return pattern;
}

std::vector<uintptr_t> PatternScanner::scan_buffer(
    const uint8_t* data,
    size_t size,
    const BytePattern& pattern,
    uintptr_t base_va
) {
    std::vector<uintptr_t> results;

    if (data == nullptr || pattern.bytes.empty() || size < pattern.bytes.size()) {
        return results;
    }

    size_t pattern_len = pattern.bytes.size();
    size_t max_offset = size - pattern_len;

    for (size_t i = 0; i <= max_offset; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; ++j) {
            if (pattern.mask[j] && data[i + j] != pattern.bytes[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            results.push_back(base_va + i);
        }
    }

    return results;
}

std::vector<uintptr_t> PatternScanner::scan_module(
    const core::ProcessTarget& process,
    const core::ModuleInfo& mod,
    const BytePattern& pattern
) {
    std::vector<uintptr_t> results;
    if (!process.is_attached() || pattern.bytes.empty() || mod.base_address == 0) {
        return results;
    }

    core::PeImage pe(process, mod.base_address);
    if (!pe.parse()) {
        return results;
    }

    uintptr_t text_start = 0;
    size_t text_size = 0;
    if (!pe.get_section_bounds(".text", text_start, text_size) || text_size == 0) {
        return results;
    }

    std::vector<uint8_t> buffer(text_size);
    size_t bytes_read = 0;
    if (!process.read_memory(text_start, buffer.data(), text_size, &bytes_read) || bytes_read == 0) {
        return results;
    }

    return scan_buffer(buffer.data(), bytes_read, pattern, text_start);
}

}
