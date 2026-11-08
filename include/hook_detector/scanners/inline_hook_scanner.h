#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hook_detector/core/process_target.h"

namespace hook_detector::scanners {

enum class InlineHookType {
    none,
    jmp_rel32,
    jmp_indirect_rip,
    jmp_absolute_rip_zero,
    push_ret,
    mov_rax_jmp,
    mov_r11_jmp,
    prologue_mismatch
};

using inline_hook_type = InlineHookType;

struct InlineHookResult {
    InlineHookType hook_type = InlineHookType::none;
    uintptr_t target_address = 0;
    std::vector<uint8_t> captured_bytes;
    std::vector<uint8_t> expected_bytes;
    bool is_hooked = false;
    std::string details;
};

using inline_hook_result = InlineHookResult;

class InlineHookScanner {
public:
    static InlineHookResult check_function(
        const core::ProcessTarget& process,
        uintptr_t func_addr,
        const std::vector<uint8_t>& expected_prologue = {},
        size_t compare_len = 16
    );
};

using inline_hook_scanner = InlineHookScanner;

}
