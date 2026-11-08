#include "hook_detector/scanners/hw_breakpoint_scanner.h"

#include <tlhelp32.h>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace hook_detector::scanners {

ThreadSuspendGuard::ThreadSuspendGuard(HANDLE thread_handle)
    : m_thread_handle(thread_handle), m_is_suspended(false) {
    if (m_thread_handle != nullptr && m_thread_handle != INVALID_HANDLE_VALUE) {
        DWORD count = SuspendThread(m_thread_handle);
        if (count != static_cast<DWORD>(-1)) {
            m_is_suspended = true;
        }
    }
}

ThreadSuspendGuard::~ThreadSuspendGuard() {
    if (m_is_suspended && m_thread_handle != nullptr && m_thread_handle != INVALID_HANDLE_VALUE) {
        ResumeThread(m_thread_handle);
    }
}

bool ThreadSuspendGuard::is_suspended() const {
    return m_is_suspended;
}

std::vector<HwBreakpointEntry> HwBreakpointScanner::scan_process(const core::ProcessTarget& process) {
    std::vector<HwBreakpointEntry> results;
    if (!process.is_attached()) {
        return results;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE || snapshot == nullptr) {
        return results;
    }

    struct SnapshotGuard {
        HANDLE handle;
        ~SnapshotGuard() {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    } snap_guard{snapshot};

    THREADENTRY32 te{};
    te.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot, &te)) {
        return results;
    }

    DWORD target_pid = process.get_pid();
    DWORD self_tid = GetCurrentThreadId();
    DWORD self_pid = GetCurrentProcessId();

    do {
        if (te.th32OwnerProcessID != target_pid) {
            continue;
        }

        if (target_pid == self_pid && te.th32ThreadID == self_tid) {
            continue;
        }

        HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
        if (thread_handle == nullptr || thread_handle == INVALID_HANDLE_VALUE) {
            continue;
        }

        struct ThreadHandleGuard {
            HANDLE handle;
            ~ThreadHandleGuard() {
                if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(handle);
                }
            }
        } th_guard{thread_handle};

        ThreadSuspendGuard suspend_guard(thread_handle);

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(thread_handle, &ctx)) {
            continue;
        }

        HwBreakpointEntry entry;
        entry.thread_id = te.th32ThreadID;
        entry.dr0 = static_cast<uintptr_t>(ctx.Dr0);
        entry.dr1 = static_cast<uintptr_t>(ctx.Dr1);
        entry.dr2 = static_cast<uintptr_t>(ctx.Dr2);
        entry.dr3 = static_cast<uintptr_t>(ctx.Dr3);
        entry.dr6 = ctx.Dr6;
        entry.dr7 = ctx.Dr7;

        entry.captured_bytes.resize(sizeof(uint64_t));
        std::memcpy(entry.captured_bytes.data(), &ctx.Dr7, sizeof(uint64_t));

        uint64_t enable_bits = ctx.Dr7 & 0xFF;
        if (enable_bits != 0) {
            entry.is_active = true;
            std::ostringstream ss;
            ss << "Active hardware breakpoint detected. Dr7=0x" << std::hex << ctx.Dr7;
            if ((ctx.Dr7 & 0x03) != 0) ss << " [Dr0=0x" << ctx.Dr0 << "]";
            if ((ctx.Dr7 & 0x0C) != 0) ss << " [Dr1=0x" << ctx.Dr1 << "]";
            if ((ctx.Dr7 & 0x30) != 0) ss << " [Dr2=0x" << ctx.Dr2 << "]";
            if ((ctx.Dr7 & 0xC0) != 0) ss << " [Dr3=0x" << ctx.Dr3 << "]";
            entry.details = ss.str();
        } else {
            entry.is_active = false;
            entry.details = "No hardware breakpoints active";
        }

        results.push_back(std::move(entry));
    } while (Thread32Next(snapshot, &te));

    return results;
}

}
