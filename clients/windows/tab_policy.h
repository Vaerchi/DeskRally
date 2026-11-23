#pragma once
// Pure tab policy for the desktop client's tabs (docs-tabs-design.md): keyboard command decoding with
// EXACT modifier matching, the per-window tab cap, and index arithmetic for switching and for choosing
// the tab to show after one closes. No Win32 types beyond plain integers, so client_policy_test covers it.

#include <cstddef>
#include <cstdint>

namespace drtabs {

// Tabs per window: a WebView/resource limit, counting tabs still being created.
inline constexpr std::size_t kMaxTabs = 12;

enum class Cmd { None, New, Close, Next, Prev, Select, Last };

struct KeyInput {
    bool key_down = false;   // a KEY_DOWN event (WebView2) / WM_KEYDOWN
    bool system_key = false; // SYSTEM_KEY_DOWN / WM_SYSKEYDOWN: what Alt and AltGr combinations produce
    bool repeat = false;     // auto-repeat (the key was already down)
    unsigned vk = 0;         // virtual-key code
    bool ctrl = false, shift = false, alt = false, win = false;
};

struct Decoded {
    Cmd cmd = Cmd::None;
    int index = -1; // Select: 0-based tab index
};

// A command matches only on a fresh (non-repeat) KEY_DOWN with Ctrl down and Alt (either side, which
// also rules out AltGr = Ctrl+Alt) and both Win keys up, with Shift exactly as listed. Everything else
// is None, so the caller leaves the key to the page untouched.
inline Decoded decode(const KeyInput& k) {
    Decoded none;
    if (!k.key_down || k.system_key || k.repeat || !k.ctrl || k.alt || k.win) return none;
    const unsigned kVkTab = 0x09;
    if (k.vk == kVkTab) return {k.shift ? Cmd::Prev : Cmd::Next, -1};
    if (k.shift) return none;
    if (k.vk == 'T') return {Cmd::New, -1};
    if (k.vk == 'W') return {Cmd::Close, -1};
    if (k.vk >= '1' && k.vk <= '8') return {Cmd::Select, static_cast<int>(k.vk - '1')};
    if (k.vk == '9') return {Cmd::Last, -1};
    return none;
}

// May another tab be created, given the tabs that are live or still being created?
inline bool can_create(std::size_t creating_plus_live) { return creating_plus_live < kMaxTabs; }

// The tab to show after Next/Prev from `current` among `count` tabs, wrapping around.
inline std::size_t step(std::size_t current, std::size_t count, bool forward) {
    if (count == 0) return 0;
    if (current >= count) current = count - 1;
    return forward ? (current + 1) % count : (current + count - 1) % count;
}

// Ctrl+1..8 picks that tab when it exists; Ctrl+9 the last. -1 = nothing to do.
inline long long select_index(const Decoded& d, std::size_t count) {
    if (count == 0) return -1;
    if (d.cmd == Cmd::Last) return static_cast<long long>(count - 1);
    if (d.cmd == Cmd::Select && d.index >= 0 && static_cast<std::size_t>(d.index) < count) return d.index;
    return -1;
}

// After removing the tab at `closed` from a list that had `count_before` tabs, which index of the
// remaining list to show: the tab that was to its right (now at the same index), else the one to its
// left. -1 when none remain.
inline long long replacement_after_close(std::size_t closed, std::size_t count_before) {
    if (count_before <= 1) return -1;
    const std::size_t remaining = count_before - 1;
    if (closed < remaining) return static_cast<long long>(closed);
    return static_cast<long long>(remaining - 1);
}

} // namespace drtabs
