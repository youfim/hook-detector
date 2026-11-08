#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

#include "hook_detector/core/types.h"

namespace hook_detector::core {

class ProcessTarget {
public:
    ProcessTarget();
    ~ProcessTarget();

    ProcessTarget(const ProcessTarget&) = delete;
    ProcessTarget& operator=(const ProcessTarget&) = delete;

    ProcessTarget(ProcessTarget&& other) noexcept;
    ProcessTarget& operator=(ProcessTarget&& other) noexcept;

    bool attach_by_pid(DWORD pid);
    bool attach_by_name(const std::wstring& process_name);
    void detach();

    std::vector<ModuleInfo> enumerate_modules() const;
    bool read_memory(uintptr_t address, void* buffer, size_t size, size_t* bytes_read = nullptr) const;
    bool is_wow64() const;

    HANDLE get_handle() const;
    DWORD get_pid() const;
    const std::wstring& get_name() const;
    bool is_attached() const;

private:
    HANDLE m_handle;
    DWORD m_pid;
    std::wstring m_process_name;
};

using process_target = ProcessTarget;

}
