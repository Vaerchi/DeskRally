#pragma once
#include <cstddef>
#include <cstdint>

// The process must not outlive its main window (client.cpp: WM_NCDESTROY latches, the main loop drains).
//
// A 0.8.1 client did: its main window was destroyed, but WM_DESTROY's WM_QUIT never reached the main
// loop, which then sat in GetMessageW for a day while its lifetime-lock handle blocked every client
// update (observed on a lab machine, 2026-10-20). Which pump kept the quit was not identified, so the
// loop no longer depends on receiving it: once the main window is gone, the loop stops BLOCKING. It
// drains what is already queued (the teardown's posted work, then WM_QUIT if one is still there)
// and exits. The latch is read when control returns to the outer loop, which always happens after
// the dispatch that destroyed the window returns, so no timer or wake-up is needed.
namespace drlifetime {

struct DrainResult {
    bool quit = false;         // a WM_QUIT was found: exit with its code, exactly as before
    uintptr_t quit_code = 0;
    size_t dispatched = 0;     // posted messages dispatched before exiting
    bool bounded = false;      // stopped at max_messages (something kept re-posting)
};

// `peek(is_quit, code)` removes one message without blocking and returns false when the queue is
// empty; `dispatch()` dispatches the message just removed.
template <class Peek, class Dispatch>
DrainResult drain_after_main_window(Peek&& peek, Dispatch&& dispatch, size_t max_messages) {
    DrainResult r;
    for (;;) {
        if (r.dispatched >= max_messages) { r.bounded = true; return r; }
        bool is_quit = false;
        uintptr_t code = 0;
        if (!peek(is_quit, code)) return r;  // drained, and no quit was waiting: it was lost
        if (is_quit) { r.quit = true; r.quit_code = code; return r; }
        dispatch();
        ++r.dispatched;
    }
}

}  // namespace drlifetime
