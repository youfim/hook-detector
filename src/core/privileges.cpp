#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>

#include "hook_detector/core/privileges.h"

namespace hook_detector::core {

bool enable_debug_privilege() {
    HANDLE token_handle = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) {
        std::cerr << "[-] OpenProcessToken failed with error: " << GetLastError() << std::endl;
        return false;
    }

    struct TokenGuard {
        HANDLE handle;
        ~TokenGuard() {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    } guard{token_handle};

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        std::cerr << "[-] LookupPrivilegeValueW failed with error: " << GetLastError() << std::endl;
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        std::cerr << "[-] AdjustTokenPrivileges failed with error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD error = GetLastError();
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "[-] SeDebugPrivilege is not assigned to current token." << std::endl;
        return false;
    }

    return true;
}

}
