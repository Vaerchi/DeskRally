#pragma once
#include <cstdint>

namespace drhello {
enum class Setting { Disabled, Enabled, Invalid };
inline Setting read_setting(bool missing, bool valid_dword, uint32_t value) {
    if (missing) return Setting::Disabled;
    if (!valid_dword || value > 1) return Setting::Invalid;
    return value ? Setting::Enabled : Setting::Disabled;
}
inline bool may_open_profile(Setting setting, bool verified, bool closing) {
    return !closing && (setting == Setting::Disabled ||
                       (setting == Setting::Enabled && verified));
}
inline bool may_complete(uint64_t expected, uint64_t received, bool pending, bool closing) {
    return pending && !closing && expected == received;
}
}
