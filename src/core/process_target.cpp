#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <utility>

#include "hook_detector/core/process_target.h"

namespace hook_detector::core {

ProcessTarget::ProcessTarget()
    : m_handle(nullptr), m_pid(0) {}

ProcessTarget::~ProcessTarget() {
    detach();
}

ProcessTarget::ProcessTarget(ProcessTarget&& other) noexcept
    : m_handle(other.m_handle), m_pid(other.m_pid), m_process_name(std::move(other.m_process_name)) {
    other.m_handle = nullptr;
    other.m_pid = 0;
}

ProcessTarget& ProcessTarget::operator=(ProcessTarget&& other) noexcept {
    if (this != &other) {
        detach();
        m_handle = other.m_handle;
        m_pid = other.m_pid;
        m_process_name = std::move(other.m_process_name);
        other.m_handle = nullptr;
        other.m_pid = 0;
    }
    return *this;
}

bool ProcessTarget::attach_by_pid(DWORD pid) {
    detach();

    HANDLE handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] OpenProcess failed for PID " << pid << " with error: " << GetLastError() << std::endl;
        return false;
    }

    m_handle = handle;
    m_pid = pid;

    wchar_t name_buffer[MAX_PATH] = {0};
    DWORD buffer_size = MAX_PATH;
    if (QueryFullProcessImageNameW(m_handle, 0, name_buffer, &buffer_size)) {
        std::wstring full_path(name_buffer);
        size_t last_slash = full_path.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos) {
            m_process_name = full_path.substr(last_slash + 1);
        } else {
            m_process_name = full_path;
        }
    } else {
        m_process_name = L"PID_" + std::to_wstring(pid);
    }

    return true;
}

bool ProcessTarget::attach_by_name(const std::wstring& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE || snapshot == nullptr) {
        std::cerr << "[-] CreateToolhelp32Snapshot failed with error: " << GetLastError() << std::endl;
        return false;
    }

    struct SnapshotGuard {
        HANDLE handle;
        ~SnapshotGuard() {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    } guard{snapshot};

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &pe)) {
        std::cerr << "[-] Process32FirstW failed with error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD target_pid = 0;
    do {
        if (_wcsicmp(pe.szExeFile, process_name.c_str()) == 0) {
            target_pid = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(snapshot, &pe));

    if (target_pid == 0) {
        std::wcerr << L"[-] Process not found: " << process_name << std::endl;
        return false;
    }

    return attach_by_pid(target_pid);
}

void ProcessTarget::detach() {
    if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
        m_handle = nullptr;
    }
    m_pid = 0;
    m_process_name.clear();
}

std::vector<ModuleInfo> ProcessTarget::enumerate_modules() const {
    std::vector<ModuleInfo> result;
    if (!is_attached()) {
        return result;
    }

    DWORD bytes_needed = 0;
    if (!EnumProcessModulesEx(m_handle, nullptr, 0, &bytes_needed, LIST_MODULES_ALL)) {
        std::cerr << "[-] EnumProcessModulesEx query failed with error: " << GetLastError() << std::endl;
        return result;
    }

    size_t count = bytes_needed / sizeof(HMODULE);
    std::vector<HMODULE> modules(count);

    if (!EnumProcessModulesEx(m_handle, modules.data(), bytes_needed, &bytes_needed, LIST_MODULES_ALL)) {
        std::cerr << "[-] EnumProcessModulesEx enumeration failed with error: " << GetLastError() << std::endl;
        return result;
    }

    result.reserve(count);
    for (HMODULE h_mod : modules) {
        MODULEINFO mi{};
        if (!GetModuleInformation(m_handle, h_mod, &mi, sizeof(mi))) {
            continue;
        }

        wchar_t path_buffer[MAX_PATH] = {0};
        if (!GetModuleFileNameExW(m_handle, h_mod, path_buffer, MAX_PATH)) {
            continue;
        }

        std::wstring full_path(path_buffer);
        std::wstring name = full_path;
        size_t last_slash = full_path.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos) {
            name = full_path.substr(last_slash + 1);
        }

        ModuleInfo info{};
        info.name = name;
        info.base_address = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        info.size = static_cast<size_t>(mi.SizeOfImage);
        info.full_path = full_path;

        result.push_back(std::move(info));
    }

    return result;
}

bool ProcessTarget::read_memory(uintptr_t address, void* buffer, size_t size, size_t* bytes_read) const {
    if (bytes_read != nullptr) {
        *bytes_read = 0;
    }

    if (!is_attached() || address == 0 || buffer == nullptr || size == 0) {
        return false;
    }

    SIZE_T read_count = 0;
    BOOL ok = ReadProcessMemory(m_handle, reinterpret_cast<LPCVOID>(address), buffer, size, &read_count);
    if (bytes_read != nullptr) {
        *bytes_read = static_cast<size_t>(read_count);
    }

    return (ok != FALSE && read_count == size) || (read_count > 0);
}

bool ProcessTarget::is_wow64() const {
    if (!is_attached()) {
        return false;
    }

    BOOL wow64 = FALSE;
    if (IsWow64Process(m_handle, &wow64)) {
        return wow64 == TRUE;
    }

    return false;
}

HANDLE ProcessTarget::get_handle() const {
    return m_handle;
}

DWORD ProcessTarget::get_pid() const {
    return m_pid;
}

const std::wstring& ProcessTarget::get_name() const {
    return m_process_name;
}

bool ProcessTarget::is_attached() const {
    return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
}

}
