#pragma once

#include <cstdint>
#include <string>

#include "hook_detector/report/hook_report.h"

namespace hook_detector::report {

struct ScanInfo {
    uint32_t pid = 0;
    std::string process_name;
    std::string scan_time_utc;
    std::string scanner_version = "1.0.0";
};

using scan_info = ScanInfo;

class JsonExporter {
public:
    static std::string get_current_utc_iso8601();

    static std::string to_json_string(
        const HookReport& report,
        const ScanInfo& info
    );

    static bool export_to_file(
        const HookReport& report,
        const ScanInfo& info,
        const std::string& filepath
    );
};

using json_exporter = JsonExporter;

}
