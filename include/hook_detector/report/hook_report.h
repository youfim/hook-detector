#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/types.h"

namespace hook_detector::report {

enum class FindingType {
    inline_hook,
    iat_hook,
    eat_hook,
    vtable_hook,
    hw_breakpoint
};

using finding_type = FindingType;

enum class FindingSeverity {
    low,
    medium,
    high,
    critical
};

using finding_severity = FindingSeverity;

struct Finding {
    size_t id = 0;
    FindingType type = FindingType::inline_hook;
    FindingSeverity severity = FindingSeverity::medium;
    std::string module_name;
    std::string function_name;
    core::ResolutionMethod resolved_via = core::ResolutionMethod::export_table;
    uintptr_t address = 0;
    uintptr_t redirect_target = 0;
    std::string details;
    std::vector<uint8_t> captured_bytes;
    std::vector<uint8_t> expected_bytes;
};

using finding = Finding;

std::string bytes_to_hex_string(const std::vector<uint8_t>& bytes);
std::string finding_type_to_string(FindingType type);
std::string finding_severity_to_string(FindingSeverity severity);
std::string resolution_method_to_string(core::ResolutionMethod method);

class HookReport {
public:
    void add_finding(Finding finding_entry);
    const std::vector<Finding>& get_findings() const;
    size_t get_total_findings() const;
    void print_to_console() const;

private:
    std::vector<Finding> m_findings;
};

using hook_report = HookReport;

}
