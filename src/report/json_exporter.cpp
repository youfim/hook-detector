#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "nlohmann/json.hpp"
#include "hook_detector/report/json_exporter.h"

namespace hook_detector::report {

std::string JsonExporter::get_current_utc_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t time_t_val = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    gmtime_s(&tm_buf, &time_t_val);

    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string JsonExporter::to_json_string(
    const HookReport& report,
    const ScanInfo& info
) {
    nlohmann::ordered_json root;

    root["scan_info"] = {
        {"pid", info.pid},
        {"process_name", info.process_name},
        {"scan_time_utc", info.scan_time_utc},
        {"scanner_version", info.scanner_version}
    };

    root["total_findings"] = report.get_total_findings();

    auto findings_arr = nlohmann::json::array();
    for (const auto& item : report.get_findings()) {
        nlohmann::ordered_json f_json;
        f_json["id"] = item.id;
        f_json["type"] = finding_type_to_string(item.type);
        f_json["severity"] = finding_severity_to_string(item.severity);
        f_json["module_name"] = item.module_name;
        f_json["function_name"] = item.function_name;
        f_json["resolved_via"] = resolution_method_to_string(item.resolved_via);

        std::ostringstream addr_stream;
        addr_stream << "0x" << std::hex << item.address;
        f_json["address"] = addr_stream.str();

        std::ostringstream redirect_stream;
        redirect_stream << "0x" << std::hex << item.redirect_target;
        f_json["redirect_target"] = redirect_stream.str();

        f_json["details"] = item.details;
        f_json["captured_bytes_hex"] = bytes_to_hex_string(item.captured_bytes);
        f_json["expected_bytes_hex"] = bytes_to_hex_string(item.expected_bytes);

        findings_arr.push_back(std::move(f_json));
    }

    root["findings"] = std::move(findings_arr);

    return root.dump(4);
}

bool JsonExporter::export_to_file(
    const HookReport& report,
    const ScanInfo& info,
    const std::string& filepath
) {
    std::string json_str = to_json_string(report, info);
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    file << json_str;
    return file.good();
}

}
