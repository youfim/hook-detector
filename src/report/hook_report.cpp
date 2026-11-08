#include <iostream>
#include <iomanip>
#include <sstream>

#include "hook_detector/report/hook_report.h"

namespace hook_detector::report {

std::string bytes_to_hex_string(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return "";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
            ss << " ";
        }
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string finding_type_to_string(FindingType type) {
    switch (type) {
        case FindingType::inline_hook: return "inline_hook";
        case FindingType::iat_hook: return "iat_hook";
        case FindingType::eat_hook: return "eat_hook";
        case FindingType::vtable_hook: return "vtable_hook";
        case FindingType::hw_breakpoint: return "hw_breakpoint";
        default: return "unknown";
    }
}

std::string finding_severity_to_string(FindingSeverity severity) {
    switch (severity) {
        case FindingSeverity::low: return "low";
        case FindingSeverity::medium: return "medium";
        case FindingSeverity::high: return "high";
        case FindingSeverity::critical: return "critical";
        default: return "unknown";
    }
}

std::string resolution_method_to_string(core::ResolutionMethod method) {
    switch (method) {
        case core::ResolutionMethod::export_table: return "export_table";
        case core::ResolutionMethod::pattern_scan: return "pattern_scan";
        case core::ResolutionMethod::vtable_slot: return "vtable_slot";
        case core::ResolutionMethod::manual_offset: return "manual_offset";
        default: return "unknown";
    }
}

void HookReport::add_finding(Finding finding_entry) {
    finding_entry.id = m_findings.size() + 1;
    m_findings.push_back(std::move(finding_entry));
}

const std::vector<Finding>& HookReport::get_findings() const {
    return m_findings;
}

size_t HookReport::get_total_findings() const {
    return m_findings.size();
}

void HookReport::print_to_console() const {
    std::cout << "\n======================================================================\n";
    std::cout << "                        HOOK DETECTOR REPORT                          \n";
    std::cout << "======================================================================\n";
    std::cout << "Total Anomalies Detected: " << m_findings.size() << "\n\n";

    if (m_findings.empty()) {
        std::cout << "[+] Target process appears clean. No hooks or anomalies found.\n";
        std::cout << "======================================================================\n\n";
        return;
    }

    for (const auto& item : m_findings) {
        std::cout << "----------------------------------------------------------------------\n";
        std::cout << " Finding #" << item.id << " [" << finding_severity_to_string(item.severity) << "]\n";
        std::cout << " Type:            " << finding_type_to_string(item.type) << "\n";
        std::cout << " Target Module:   " << (item.module_name.empty() ? "<unknown>" : item.module_name) << "\n";
        std::cout << " Target Function: " << (item.function_name.empty() ? "<unknown>" : item.function_name) << "\n";
        std::cout << " Resolved Via:    " << resolution_method_to_string(item.resolved_via) << "\n";
        std::cout << " Address:         0x" << std::hex << item.address << std::dec << "\n";

        if (item.redirect_target != 0) {
            std::cout << " Redirect To:     0x" << std::hex << item.redirect_target << std::dec << "\n";
        }

        std::cout << " Captured Bytes:  " << bytes_to_hex_string(item.captured_bytes) << "\n";
        if (!item.expected_bytes.empty()) {
            std::cout << " Expected Bytes:  " << bytes_to_hex_string(item.expected_bytes) << "\n";
        }

        std::cout << " Details:         " << item.details << "\n";
    }

    std::cout << "======================================================================\n\n";
}

}
