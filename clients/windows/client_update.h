#pragma once
// DeskRally desktop auto-updater public API.
// Implementation: client_update.cpp  (Win32 + WinHTTP + WinVerifyTrust).
//
// Design:
//   - Only updates when the running exe is at the fixed installed path.
//   - ClientLock: each app process holds a shared file lock while alive;
//     the updater worker acquires exclusive access only after all windows close.
//   - Updater::CheckForUpdate(): async, fires background thread, posts
//     WM_UPDATE_STATUS to the notify HWND when state changes.
//   - Apply(): spawns an independent copy of the installed exe in
//     "--update-worker" mode; returns immediately. Worker waits for all
//     client instances to exit, then atomically replaces the installed exe,
//     verifies the result, and rolls back on failure.
//   - Multiple updater instances are serialized via a named mutex.
//   - Daily check timestamp persisted in registry.

#ifndef UNICODE
#  define UNICODE
#endif
#ifndef _UNICODE
#  define _UNICODE
#endif
#include <windows.h>
#include <string>
#include <memory>

namespace drupdate {

// ── WM message posted to notify_hwnd on any state change ──────────────────
// wParam = 0, lParam = 0.  Caller calls Updater::GetState() to read status.
static constexpr UINT WM_UPDATE_STATUS = WM_APP + 20;

// ── Status ────────────────────────────────────────────────────────────────
enum class UpdateStatus {
    Idle,        // no check in flight
    Checking,    // fetching manifest
    Downloading, // downloading binary
    Ready,       // downloaded+verified; call Apply() or schedule it
    NoUpdate,    // manifest fetched; installed version is current
    Failed,      // last attempt failed; see error_message
};

struct UpdateState {
    UpdateStatus status          = UpdateStatus::Idle;
    std::wstring pending_version; // populated when Ready
    std::wstring error_message;   // populated when Failed
};

// ── ClientLock ────────────────────────────────────────────────────────────
// Create one instance at app startup; destroy at exit.
// Holds a shared (FILE_SHARE_READ) open on the install-dir lock file while
// the app process is alive.  The update worker tries to acquire exclusive
// access to that same file before swapping the binary.
class ClientLock {
public:
    ClientLock();   // opens/creates lock file shared; silently no-ops if not at installed path
    ~ClientLock();
    ClientLock(const ClientLock&) = delete;
    ClientLock& operator=(const ClientLock&) = delete;
    bool IsReady() const { return ready_; }
private:
    HANDLE lock_file_ = INVALID_HANDLE_VALUE;
    bool ready_ = false;
};

// ── About ─────────────────────────────────────────────────────────────────
// What the Help > About dialog shows about the RUNNING executable (Ed, 2026-10-16).
struct AboutInfo {
    std::wstring version;      // FileVersion of this exe, e.g. "0.7.0.0"
    bool publisher_pinned = false;
    std::wstring publisher_name; // CN from the configured subject
    bool publisher_verified = false; // Authenticode valid AND the expected publisher (no revocation fetch)
    std::wstring last_result;  // updater's last recorded result, e.g. "Installed 0.6.1"
    std::wstring last_check;   // local time of the last update check, or empty
};
AboutInfo GetAboutInfo();

// ── Updater ───────────────────────────────────────────────────────────────
class Updater {
public:
    // notify_hwnd receives WM_UPDATE_STATUS on every state transition.
    // Pass nullptr to suppress notifications.
    explicit Updater(HWND notify_hwnd);
    ~Updater();
    Updater(const Updater&) = delete;
    Updater& operator=(const Updater&) = delete;

    // Trigger async check + download.  Safe to call from the UI thread.
    // Returns false if updates are unconfigured (with an explanatory state) or
    // the current exe is not at the installed path (dev build).
    // No-op (returns true) if a check is already running.
    bool CheckForUpdate();

    // Read current state.  Thread-safe.
    UpdateState GetState() const;

    // Spawn the update worker process and return.  Call only when
    // status == Ready.  The worker exits after applying the update or
    // on failure; it never kills running app windows.
    // Returns false if spawning fails.
    bool Apply();

    // True if 24 hours have elapsed since the last successful check (or
    // if no check has ever been recorded).
    static bool IsDailyCheckDue();

    // Record that a check was performed now.  Call after CheckForUpdate
    // initiates (regardless of outcome).
    static void RecordCheckTime();

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

// ── Update worker entry point ─────────────────────────────────────────────
// Only "--update-worker" is accepted; no caller-supplied paths or URLs.
// A generated copy of the installed app reads the pending release from HKCU,
// waits up to seven days for all app windows to close, re-fetches the current
// manifest, re-verifies the candidate, and replaces only the fixed installed exe.
// Verification or the no-profile startup self-test failing restores the backup.
// Exit codes 8/9/10 distinguish replacement failure, rollback, and failed recovery.
int RunUpdateWorker(int argc, wchar_t** argv);

} // namespace drupdate
