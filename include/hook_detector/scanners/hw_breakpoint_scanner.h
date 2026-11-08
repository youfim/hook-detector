#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/process_target.h"

namespace hook_detector::scanners {

class ThreadSuspendGuard {
public:
    explicit ThreadSuspendGuard(HANDLE thread_handle);
    ~ThreadSuspendGuard();

    ThreadSuspendGuard(const ThreadSuspendGuard&) = delete;
    ThreadSuspendGuard& operator=(const ThreadSuspendGuard&) = delete;

    bool is_suspended() const;

private:
    HANDLE m_thread_handle;
    bool m_is_suspended;
};

using thread_suspend_guard = ThreadSuspendGuard;

struct HwBreakpointEntry {
    DWORD thread_id = 0;
    uintptr_t dr0 = 0;
    uintptr_t dr1 = 0;
    uintptr_t dr2 = 0;
    uintptr_t dr3 = 0;
    uint64_t dr6 = 0;
    uint64_t dr7 = 0;
    bool is_active = false;
    std::string details;
    std::vector<uint8_t> captured_bytes;
};

using hw_breakpoint_entry = HwBreakpointEntry;

class HwBreakpointScanner {
public:
    static std::vector<HwBreakpointEntry> scan_process(const core::ProcessTarget& process);
};

using hw_breakpoint_scanner = HwBreakpointScanner;

}
