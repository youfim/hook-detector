#include <cstring>
#include <algorithm>

#include "hook_detector/scanners/inline_hook_scanner.h"

namespace hook_detector::scanners {

InlineHookResult InlineHookScanner::check_function(
    const core::ProcessTarget& process,
    uintptr_t func_addr,
    const std::vector<uint8_t>& expected_prologue,
    size_t compare_len
) {
    InlineHookResult result;
    result.expected_bytes = expected_prologue;
    result.captured_bytes.resize(compare_len, 0);

    size_t bytes_read = 0;
    if (!process.read_memory(func_addr, result.captured_bytes.data(), compare_len, &bytes_read) || bytes_read == 0) {
        result.captured_bytes.clear();
        result.details = "Failed to read function memory";
        return result;
    }

    result.captured_bytes.resize(bytes_read);
    const auto& b = result.captured_bytes;

    if (!expected_prologue.empty()) {
        size_t check_len = std::min(expected_prologue.size(), b.size());
        if (check_len >= 5 && std::equal(b.begin(), b.begin() + check_len, expected_prologue.begin())) {
            result.is_hooked = false;
            result.hook_type = InlineHookType::none;
            result.details = "Clean function (matches on-disk original binary)";
            return result;
        }
    }

    if (b[0] == 0xE9 && bytes_read >= 5) {
        int32_t rel32 = 0;
        std::memcpy(&rel32, &b[1], sizeof(int32_t));
        result.hook_type = InlineHookType::jmp_rel32;
        result.target_address = func_addr + 5 + static_cast<intptr_t>(rel32);
        result.is_hooked = true;
        result.details = "Detected jmp rel32 (E9)";
        return result;
    }

    if (b[0] == 0xFF && b[1] == 0x25 && bytes_read >= 6) {
        int32_t disp32 = 0;
        std::memcpy(&disp32, &b[2], sizeof(int32_t));

        if (disp32 == 0) {
            result.hook_type = InlineHookType::jmp_absolute_rip_zero;
            if (bytes_read >= 14) {
                uint64_t target = 0;
                std::memcpy(&target, &b[6], sizeof(uint64_t));
                result.target_address = static_cast<uintptr_t>(target);
            } else {
                uint64_t target = 0;
                size_t read_target = 0;
                process.read_memory(func_addr + 6, &target, sizeof(target), &read_target);
                result.target_address = static_cast<uintptr_t>(target);
            }
            result.is_hooked = true;
            result.details = "Detected jmp qword ptr [rip+0] (FF 25 00 00 00 00)";
            return result;
        } else {
            result.hook_type = InlineHookType::jmp_indirect_rip;
            uintptr_t ptr_addr = func_addr + 6 + static_cast<intptr_t>(disp32);
            uint64_t target = 0;
            size_t read_target = 0;
            if (process.read_memory(ptr_addr, &target, sizeof(target), &read_target) && read_target == sizeof(target)) {
                result.target_address = static_cast<uintptr_t>(target);
            } else {
                result.target_address = ptr_addr;
            }
            result.is_hooked = true;
            result.details = "Detected jmp qword ptr [rip+disp32] (FF 25)";
            return result;
        }
    }

    if (b[0] == 0x68 && bytes_read >= 6 && b[5] == 0xC3) {
        uint32_t target32 = 0;
        std::memcpy(&target32, &b[1], sizeof(uint32_t));
        result.hook_type = InlineHookType::push_ret;
        result.target_address = static_cast<uintptr_t>(target32);
        result.is_hooked = true;
        result.details = "Detected push imm32 / ret (68 xx xx xx xx C3)";
        return result;
    }

    if (bytes_read >= 12 && b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0x50 && b[11] == 0xC3) {
        uint64_t target64 = 0;
        std::memcpy(&target64, &b[2], sizeof(uint64_t));
        result.hook_type = InlineHookType::push_ret;
        result.target_address = static_cast<uintptr_t>(target64);
        result.is_hooked = true;
        result.details = "Detected mov rax, imm64 / push rax / ret";
        return result;
    }

    if (bytes_read >= 12 && b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) {
        uint64_t target64 = 0;
        std::memcpy(&target64, &b[2], sizeof(uint64_t));
        result.hook_type = InlineHookType::mov_rax_jmp;
        result.target_address = static_cast<uintptr_t>(target64);
        result.is_hooked = true;
        result.details = "Detected mov rax, imm64 / jmp rax (48 B8 ... FF E0)";
        return result;
    }

    if (bytes_read >= 13 && b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF && b[12] == 0xE3) {
        uint64_t target64 = 0;
        std::memcpy(&target64, &b[2], sizeof(uint64_t));
        result.hook_type = InlineHookType::mov_r11_jmp;
        result.target_address = static_cast<uintptr_t>(target64);
        result.is_hooked = true;
        result.details = "Detected mov r11, imm64 / jmp r11 (49 BB ... 41 FF E3)";
        return result;
    }

    if (!expected_prologue.empty()) {
        size_t check_len = std::min(expected_prologue.size(), b.size());
        bool mismatch = false;
        for (size_t i = 0; i < check_len; ++i) {
            if (b[i] != expected_prologue[i]) {
                mismatch = true;
                break;
            }
        }

        if (mismatch) {
            result.hook_type = InlineHookType::prologue_mismatch;
            result.is_hooked = true;
            result.details = "Prologue mismatch against reference bytes";
            return result;
        }
    }

    result.is_hooked = false;
    result.details = "Clean prologue";
    return result;
}

}
