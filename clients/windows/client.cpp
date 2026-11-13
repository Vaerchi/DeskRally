// DeskRally native Windows client – Win32 + WebView2.
// Tenant-aware without a built-in tenant list: each process is pinned to one
// organization, https://<slug>.deskrally.com, chosen by the launch link, the last
// organization this Windows user signed in to here, or the user. The Organization
// menu lists only the organizations this Windows user has signed in to on this PC.
// Per-user WebView2 profile per tenant; no browser chrome; popup window.open supported.

#ifndef UNICODE
#  define UNICODE
#endif
#ifndef _UNICODE
#  define _UNICODE
#endif
#ifndef WINVER
#  define WINVER       0x0A00
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NTDDI_VERSION
#  define NTDDI_VERSION 0x0A000004
#endif
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wrl.h>
#include <deque>
#include <map>
#include <WebView2.h>
#include <roapi.h>
#include <wrl/wrappers/corewrappers.h>
#include <windows.security.credentials.ui.h>
#include <userconsentverifierinterop.h>

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <algorithm>

#include "client_policy.h"
#include "hello_policy.h"
#include "sso_policy.h"
#include "tab_policy.h"
#include "lifetime_policy.h"
#include "client_update.h"

using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Callback;

// ── Constants ──────────────────────────────────────────────────────────────
// The source commit, injected by build-client.ps1 (/DDESKRALLY_COMMIT=L"..."); "dev" otherwise.
#ifndef DESKRALLY_COMMIT
#  define DESKRALLY_COMMIT L"dev"
#endif
static constexpr wchar_t kWindowTitle[]       = L"DeskRally";
static constexpr wchar_t kWindowClass[]       = L"DeskRallyClientWnd";
// The main tenant keeps the original folder; every other tenant uses Profile.<slug>
// (so Loam's existing Profile.loam is unchanged).
static constexpr wchar_t kProfileSubdir[]     = L"DeskRally Client\\Profile";
static constexpr wchar_t kClientRegKey[]      = L"Software\\DeskRally\\Client";

// WM_APP+1: deferred clipboard consent dialog (avoid WebView2 reentrancy).
static constexpr UINT WM_CLIPBOARD_CONSENT = WM_APP + 1;
// WM_APP+2: deferred spawn of child process for deskrally-client:// URI (avoid WebView2 reentrancy).
static constexpr UINT WM_SPAWN_CLIENT     = WM_APP + 2;
static constexpr UINT WM_HELLO_RESULT     = WM_APP + 3;
// WM_APP+4: a tab command (wParam = TabCommand, lParam = tab id or index), always executed from the
// message loop, never inside a WebView2 callback (docs-tabs-design.md).
static constexpr UINT WM_APP_TAB_COMMAND   = WM_APP + 4;
// WM_APP+5: a tab's renderer failed (wParam = tab id, lParam = 1 exited / 2 unresponsive).
static constexpr UINT WM_APP_TAB_FAILED    = WM_APP + 5;
// WM_APP+6: the WebView2 browser process exited: every tab of this window is gone.
static constexpr UINT WM_APP_BROWSER_DIED  = WM_APP + 6;
// WM_APP+7: a tab's creation failed (wParam = tab id, lParam = TabFailure). Handled in the window
// procedure, never inside the controller-creation callback.
static constexpr UINT WM_APP_TAB_CREATE_FAILED = WM_APP + 7;
enum TabFailure : LPARAM { kFailController = 1, kFailInterface, kFailSecurity, kFailDisplay };
enum TabCommand : WPARAM { kTabNew = 1, kTabCloseActive, kTabCloseId, kTabNext, kTabPrev, kTabSelect, kTabLast };
// Timer that looks for this organization's sign-in cookie until it is recorded.
static constexpr UINT_PTR kSignInTimerId = 21;
static constexpr UINT_PTR kSsoTimerId = 31;
static constexpr UINT     kSignInPollMs  = 3000;  // a local cookie query; short so a quick sign-in-and-close is still seen

// Organization menu command IDs. Known organizations occupy a contiguous range.
static constexpr UINT IDM_ORG_OTHER = 1001;
static constexpr UINT IDM_ORG_FIRST = 1100;
static constexpr size_t kMaxKnownOrgs = 20;
static std::vector<drpolicy::Tenant> g_orgMenuTenants;
// Organization prompt dialog (client.rc).
static constexpr int IDD_ORGANIZATION = 200;
static constexpr int IDC_ORG_EDIT     = 201;
static constexpr int IDC_ORG_ERROR    = 202;
static constexpr int IDC_ORG_HINT     = 203;
static constexpr UINT IDM_HELLO_ENABLE = 1010;
static constexpr UINT IDM_HELLO_DISABLE = 1011;
static constexpr UINT IDM_UPDATE_CHECK = 1020;
static constexpr UINT IDM_ABOUT     = 1040;
static constexpr UINT IDM_TAB_NEW   = 1030;
static constexpr UINT IDM_TAB_CLOSE = 1031;
static constexpr UINT IDM_TAB_NEXT  = 1032;
static constexpr UINT IDM_TAB_PREV  = 1033;
static constexpr int  kTabControlId = 3000;
static std::unique_ptr<drupdate::Updater> g_updater;
static int g_exitCode = 0;  // the process exit code posted by WM_DESTROY
// Set in the main window's WM_NCDESTROY; the main loop then drains and exits (lifetime_policy.h).
static bool g_mainWindowGone = false;
static constexpr size_t kMaxExitDrainMessages = 10000;
static bool g_manualUpdateCheck = false;
static bool g_updateApplyRequested = false;

// Smoke test constants (compile-time isolation)
#ifdef SMOKE_TEST
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
static bool g_ssoSmoke = false;
static int64_t g_ssoSmokeWindowMs = 3000;
static bool g_ssoSmokeDelayIdp = false;
// --sso-smoke-probe: after the five scenarios, measure whether a navigation the policy CANCELS
// still sends its request to the network (a real local listener on 127.0.0.1:8765 records hits).
static bool g_ssoSmokeProbe = false;
static constexpr UINT_PTR kSsoSmokeTimerId = 33; // 31 is kSsoTimerId
static constexpr UINT_PTR kSsoSmokeResponseTimerId = 32;
// DNS suffixes are ASCII; retain these wide values for all WebView2 calls.
static const std::string kSsoSmokeHost = drpolicy::tenant_host(drpolicy::Tenant::main());
static const std::string kSsoSmokeOriginNarrow = drpolicy::tenant_origin(drpolicy::Tenant::main());
static const std::wstring kSsoSmokeOrigin(kSsoSmokeOriginNarrow.begin(), kSsoSmokeOriginNarrow.end());
static const std::wstring kSsoSmokeConsole = kSsoSmokeOrigin + L"/console";
static constexpr wchar_t kSsoSmokeAuthz[] = L"https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/oauth2/v2.0/authorize?x=1";
static ComPtr<ICoreWebView2WebResourceRequestedEventArgs> g_ssoSmokePendingArgs;
static ComPtr<ICoreWebView2WebResourceResponse> g_ssoSmokePendingResponse;
static ComPtr<ICoreWebView2Deferral> g_ssoSmokeDeferral;
static unsigned g_ssoSmokeUnsupported = 0;
static unsigned g_ssoSmokeTimedOut = 0;
static unsigned g_ssoSmokeEvilRequests = 0;
static constexpr bool    kSmokeTest      = true;
static constexpr DWORD   kSmokeTimeoutMs = 30000;
// Isolated profile and fixture paths; all on F: drive.
static std::wstring g_smokeDirectory;
static constexpr wchar_t kSmokeVirtualHost[] = L"deskrally-smoke.test";
static constexpr wchar_t kSmokeTestUrl[]     = L"https://deskrally-smoke.test/index.html";
// 7 fixture tests + 4 tab tests + 10 lifetime/failure tests + 2 remembered-consent tests
// + 5 full-screen tests (SmokeTabTick).
static constexpr int     kSmokeExpectedTests = 28;
static int               g_smokeLateControllersClosed = 0;
static constexpr int     kSmokeFixtureTests = 7;
static constexpr UINT_PTR kSmokeTabTimerId = 30;
static int               g_smokeTabStep = 0;
static uint64_t          g_smokeTabMark = 0;   // a tab id the current step is about
static int               g_smokeLateBefore = 0;
static bool              g_smokeClosePending = false;
static int               g_smokePassCount    = 0;
static int               g_smokeFailCount    = 0;
static int               g_smokeResult       = 1; // pessimistic; 0 on full pass
#else
static constexpr bool kSmokeTest = false;
#endif

// ── Globals ────────────────────────────────────────────────────────────────
static HINSTANCE g_hInstance = nullptr;

LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK PopupWndProc(HWND, UINT, WPARAM, LPARAM);

// ── Per-window state ───────────────────────────────────────────────────────
struct WindowState {
    HWND                                      hwnd       = nullptr;
    ComPtr<ICoreWebView2Controller>           controller;
    ComPtr<ICoreWebView2>                     webview;
    std::vector<std::shared_ptr<WindowState>> children;  // popup children (main window only)
    std::weak_ptr<WindowState>                parent;    // set for popup windows
    bool                                      is_popup   = false;
    bool                                      closing    = false;
    uint64_t                                  navigation_generation = 0;
    // Pinned at process start; all nav/permission/popup checks use this tenant's host.
    drpolicy::Tenant                          selectedTenant = drpolicy::Tenant::main();
    bool                                      org_recorded = false;
    std::unique_ptr<drpolicy::SsoFlow>          sso;
    bool                                      sso_dialog_open = false;

    // Event handler registration tokens; must be real pointers per API contract.
    EventRegistrationToken tok_nav_starting{};
    EventRegistrationToken tok_new_window{};
    EventRegistrationToken tok_window_close{};
    EventRegistrationToken tok_permission{};
    EventRegistrationToken tok_title{};
    EventRegistrationToken tok_source_changed{};
    EventRegistrationToken tok_sso_nav_completed{};
    EventRegistrationToken tok_denied_request{};
    // Main-frame navigations the policy just CANCELLED. WebView2 still issues the request for a
    // navigation cancelled in NavigationStarting (measured: the request reaches the network), so the
    // matching document request is answered locally instead. Short-lived and bounded.
    std::vector<std::pair<std::wstring, ULONGLONG>> denied_navs;
    EventRegistrationToken tok_accel{};
    EventRegistrationToken tok_process_failed{};
    EventRegistrationToken tok_fullscreen{};
    // ── Full screen (main window and popups; SyncFullscreen) ──
    bool                                      fullscreen = false;
    WINDOWPLACEMENT                           restore_placement{sizeof(WINDOWPLACEMENT)};
    LONG_PTR                                  restore_style = 0;
    HMENU                                     restore_menu = nullptr;  // detached while full screen

    // ── Tabs (docs-tabs-design.md) ──
    // A TAB is a WindowState with is_tab set: its controller is parented to the main window (hwnd is
    // the main window's), it is addressed only by its stable tab_id, and every callback re-validates
    // (window, tab_id, phase) on entry. The MAIN window state holds the tab list and the tab strip.
    enum class Phase { Creating, Live, Closing };
    bool                                      is_tab     = false;
    uint64_t                                  tab_id     = 0;
    Phase                                     phase      = Phase::Creating;
    std::wstring                              title;
    std::weak_ptr<WindowState>                window;       // a tab's main window
    std::vector<std::shared_ptr<WindowState>> tabs;         // main window only, in strip order
    uint64_t                                  active_tab = 0;
    uint64_t                                  next_tab_id = 1;
    HWND                                      tab_ctrl   = nullptr;
    // ── Popups ──
    uint64_t                                  opener_tab_id = 0;     // the tab whose window.open made this popup
    bool                                      popup_pending = false; // NewWindowRequested deferral not yet completed
    std::function<void()>                     deny_pending_popup;    // completes that deferral as denied (idempotent)
    bool                                      first_tab  = false;    // the window's initial tab (its failure is fatal)
    bool                                      recovery_pending = false; // a renderer-failure prompt is open for this tab
    bool                                      failure_pending = false;  // a creation-failure error is open for this tab
    bool                                      env_failed = false;    // main window: the browser process exited (latched)
#ifdef SMOKE_TEST
    bool smoke_close_pending = false;
    bool smoke_pending_rejected = false;
    bool smoke_pending_reported = false;
    EventRegistrationToken tok_nav_completed{};
    EventRegistrationToken tok_web_msg{};
#endif

    bool ShowClipboardConsentDialog(const std::wstring& origin) const {
        const std::wstring text = L"The DeskRally web app at " + origin +
            L" is requesting clipboard read access.\n\nAllow this clipboard read?";
        int r = MessageBoxW(hwnd, text.c_str(),
            L"DeskRally \x2013 Clipboard Access",
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
        return r == IDYES;
    }
};

// Heap-allocated context for deferred clipboard consent.
struct ClipboardConsentCtx {
    std::shared_ptr<WindowState>                         state;   // the tab or popup that asked
    ComPtr<ICoreWebView2PermissionRequestedEventArgs>    args;
    ComPtr<ICoreWebView2Deferral>                        deferral;
    uint64_t                                            generation;
    std::wstring                                        origin;  // validated requesting origin, shown in the dialog
    bool                                                settled = false; // the deferral has been completed
};
// The process's ONE consent manager (docs-tabs-design.md v2 + Codex impl review): every clipboard
// request of every tab and popup is queued here; at most one dialog is ever on screen (a dialog's
// own modal loop cannot open another); teardown settles a request whether it is queued or on
// screen, BEFORE the WebView is released; each deferral completes exactly once (`settled`).
static std::deque<std::shared_ptr<ClipboardConsentCtx>> g_consentQueue;
static std::shared_ptr<ClipboardConsentCtx>             g_consentActive;
static bool                                             g_consentShowing = false;
// The operator's answer per requesting origin, for THIS RUN only (never the WebView2 profile, never
// the registry). WebView2 raises PermissionRequested on every read because SavesInProfile is FALSE,
// so without this the console's automatic clipboard send (a read on each press into the remote
// screen) put this dialog up on every click. One question per tenant per app start; a restart asks
// again. Only an answer to a request that was still valid is kept: a request whose window closed
// mid-dialog proves nothing about the next one.
static std::map<std::wstring, bool>                     g_consentAnswers;
#ifdef SMOKE_TEST
static int g_smokeConsentCompletions = 0;
static std::function<bool(const std::shared_ptr<ClipboardConsentCtx>&)> g_smokeConsentAnswer;
static std::function<int(const std::wstring&)> g_smokeRecoveryAnswer;
static int g_smokeRecoveryPrompts = 0;
static int g_smokeErrorsShown = 0;
static std::function<void()> g_smokeErrorHook;  // set by a test: ShowError counts, runs it, and returns
#endif

static std::shared_ptr<WindowState> g_mainState;
static std::shared_ptr<WindowState> ActiveTab(const std::shared_ptr<WindowState>& win);
static RECT TabContentRect(const std::shared_ptr<WindowState>& win);
static ComPtr<ICoreWebView2Environment> g_env;

// Hello is an app-opening lock, not server attestation. No password or PIN is stored.
using HelloResult = ABI::Windows::Security::Credentials::UI::UserConsentVerificationResult;
using HelloOperation = ABI::Windows::Foundation::IAsyncOperation<HelloResult>;
using HelloCompletion = ABI::Windows::Foundation::IAsyncOperationCompletedHandler<HelloResult>;
enum class HelloPurpose { Startup, Enable, Disable };
static ComPtr<HelloOperation> g_helloOperation;
static drhello::Setting g_helloSetting = drhello::Setting::Disabled;
static bool g_helloPending = false;
static bool g_helloVerifiedAtStartup = false;
static uint64_t g_helloGeneration = 0;
static HelloPurpose g_helloPurpose = HelloPurpose::Startup;
static std::wstring g_initialUrl;
static void StartProfile(const std::shared_ptr<WindowState>& state);
static void UpdateHelloMenu(HWND hwnd);
static void StartHello(const std::shared_ptr<WindowState>& state, HelloPurpose purpose);
static void CompleteHello(const std::shared_ptr<WindowState>& state, uint64_t generation, bool verified);

static std::wstring Utf8ToWide(const std::string& s);
static std::string WideToUtf8(const std::wstring& w);

// Per-organization key: HelloEnabled and LastUsed live here. Slugs are validated
// DNS labels, so the path cannot escape the client key. Main and Loam keep the
// key names the 0.4/0.5 Hello settings already use.
static std::wstring OrgRegistryPath(const drpolicy::Tenant& tenant) {
    return std::wstring(kClientRegKey) + L"\\" + Utf8ToWide(tenant.slug());
}
static std::wstring HelloRegistryPath(const drpolicy::Tenant& tenant) {
    return OrgRegistryPath(tenant);
}

static drhello::Setting ReadHelloSetting(const drpolicy::Tenant& tenant) {
#ifdef SMOKE_TEST
    (void)tenant;
    return drhello::Setting::Disabled; // Compile-time fixture isolation; never read real settings.
#else
    DWORD value = 0, size = sizeof(value);
    const auto path = HelloRegistryPath(tenant);
    LSTATUS result = RegGetValueW(HKEY_CURRENT_USER, path.c_str(), L"HelloEnabled",
        RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, nullptr, &value, &size);
    return drhello::read_setting(result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND,
        result == ERROR_SUCCESS && size == sizeof(value), value);
#endif
}

static bool WriteHelloSetting(const drpolicy::Tenant& tenant, bool enabled) {
#ifdef SMOKE_TEST
    (void)tenant; (void)enabled;
    return false; // A smoke binary cannot change real security preferences.
#else
    HKEY key = nullptr;
    const auto path = HelloRegistryPath(tenant);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE,
        nullptr, &key, nullptr) != ERROR_SUCCESS) return false;
    DWORD value = enabled ? 1 : 0;
    LSTATUS result = RegSetValueExW(key, L"HelloEnabled", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
#endif
}

// ── Helpers ────────────────────────────────────────────────────────────────
static std::wstring GetProfilePath(const drpolicy::Tenant& tenant) {
    wchar_t local[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local)))
        return L"";
    std::wstring subdir = kProfileSubdir;
    if (tenant != drpolicy::Tenant::main()) subdir += L"." + Utf8ToWide(tenant.slug());
    return std::wstring(local) + L"\\" + subdir;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n)) return {};
    w.resize(static_cast<size_t>(n - 1));
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr)) return {};
    s.resize(static_cast<size_t>(n - 1));
    return s;
}

static std::wstring TenantLabel(const drpolicy::Tenant& t) {
    return Utf8ToWide(drpolicy::tenant_label(t));
}

// ── Organizations signed in to on this PC ─────────────────────────────────
// An organization is remembered only once its own origin holds the control plane's
// session cookie, i.e. after a successful sign-in there (RecordOrgSignedIn). A page
// that merely loaded (an error page, a mistyped or unknown organization) never
// joins the menu or becomes the Start-menu default.
struct KnownOrg { drpolicy::Tenant tenant; ULONGLONG last_used; };

static std::vector<KnownOrg> ReadKnownOrgs() {
    std::vector<KnownOrg> orgs;
#ifndef SMOKE_TEST
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kClientRegKey, 0, KEY_READ, &root) != ERROR_SUCCESS)
        return orgs;
    for (DWORD i = 0; i < 1024; ++i) {
        wchar_t name[256]; DWORD len = 256;
        LSTATUS st = RegEnumKeyExW(root, i, name, &len, nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) continue;
        drpolicy::Tenant t = drpolicy::Tenant::main();
        // Exact match only: a key whose name is not already a canonical slug is ignored.
        if (!drpolicy::make_tenant(WideToUtf8(std::wstring(name, len)), t)) continue;
        ULONGLONG used = 0; DWORD size = sizeof(used);
        if (RegGetValueW(root, name, L"LastUsed", RRF_RT_REG_QWORD, nullptr, &used, &size)
            != ERROR_SUCCESS || used == 0) continue;
        orgs.push_back({t, used});
    }
    RegCloseKey(root);
    std::sort(orgs.begin(), orgs.end(),
        [](const KnownOrg& a, const KnownOrg& b) { return a.last_used > b.last_used; });
    if (orgs.size() > kMaxKnownOrgs) orgs.erase(orgs.begin() + kMaxKnownOrgs, orgs.end());
#endif
    return orgs;
}

static bool ReadLastOrganization(drpolicy::Tenant& out) {
#ifdef SMOKE_TEST
    (void)out;
    return false;
#else
    wchar_t value[128] = {}; DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER, kClientRegKey, L"LastOrganization",
        RRF_RT_REG_SZ, nullptr, value, &size) != ERROR_SUCCESS) return false;
    return drpolicy::make_tenant(WideToUtf8(value), out);
#endif
}

static void RecordOrgSignedIn(const drpolicy::Tenant& tenant) {
#ifdef SMOKE_TEST
    (void)tenant;
#else
    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
    const ULONGLONG now = (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    HKEY key = nullptr;
    const auto path = OrgRegistryPath(tenant);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE,
        nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"LastUsed", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&now), sizeof(now));
        RegCloseKey(key);
    }
    const std::wstring slug = Utf8ToWide(tenant.slug());
    RegSetKeyValueW(HKEY_CURRENT_USER, kClientRegKey, L"LastOrganization", REG_SZ,
        slug.c_str(), static_cast<DWORD>((slug.size() + 1) * sizeof(wchar_t)));
#endif
}

static std::wstring OrganizationHint() {
    return L"If you sign in at acme" + Utf8ToWide(std::string(drpolicy::kTenantZone)) + L", enter acme.";
}

// ── Organization prompt ────────────────────────────────────────────────────
static INT_PTR CALLBACK OrgDialogProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG:
        SetWindowLongPtrW(dlg, DWLP_USER, lp);
        SetDlgItemTextW(dlg, IDC_ORG_HINT, (L"Enter your organization's DeskRally name. " + OrganizationHint()).c_str());
        SendDlgItemMessageW(dlg, IDC_ORG_EDIT, EM_LIMITTEXT, 253, 0);
        SetFocus(GetDlgItem(dlg, IDC_ORG_EDIT));
        return FALSE; // focus was set explicitly
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t text[256] = {};
            GetDlgItemTextW(dlg, IDC_ORG_EDIT, text, 256);
            auto* out = reinterpret_cast<drpolicy::Tenant*>(GetWindowLongPtrW(dlg, DWLP_USER));
            if (out && drpolicy::parse_org_input(WideToUtf8(text), *out)) {
                EndDialog(dlg, IDOK);
            } else {
                SetDlgItemTextW(dlg, IDC_ORG_ERROR,
                    (L"That is not a DeskRally organization name. " + OrganizationHint()).c_str());
                SetFocus(GetDlgItem(dlg, IDC_ORG_EDIT));
                SendDlgItemMessageW(dlg, IDC_ORG_EDIT, EM_SETSEL, 0, -1); // retype replaces it
            }
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

// Returns false when the user cancels or the dialog cannot be shown.
static bool PromptForOrganization(HWND owner, drpolicy::Tenant& out) {
    return DialogBoxParamW(g_hInstance, MAKEINTRESOURCEW(IDD_ORGANIZATION), owner,
        OrgDialogProc, reinterpret_cast<LPARAM>(&out)) == IDOK;
}

static std::wstring ConsoleUriFor(const drpolicy::Tenant& tenant) {
    return L"deskrally-client://tenant/" + Utf8ToWide(tenant.slug()) + L"/console";
}

#ifdef SMOKE_TEST
static void SmokeLog(const char* fmt, ...);
#endif

// Spawn a new instance of this executable with the given validated URI.
// The URI characters are restricted by parse_client_uri, so quoting is safe.
static bool SpawnWithUri(const std::wstring& uri) {
    if (!drpolicy::parse_client_uri(WideToUtf8(uri)).valid) return false;
    wchar_t exePath[32768]{};
    DWORD len = GetModuleFileNameW(nullptr, exePath, 32768);
    if (!len || len == 32768) return false;
    std::wstring cmdLine = L"\"" + std::wstring(exePath, len) + L"\" \"" + uri + L"\"";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(exePath, cmdLine.data(), nullptr, nullptr, FALSE, 0,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    return false;
}

static void ShowError(HWND parent, const wchar_t* msg) {
#ifdef SMOKE_TEST
    (void)parent;
    SmokeLog("[smoke] ERROR: %ls\n", msg);
    if (g_smokeErrorHook) { ++g_smokeErrorsShown; g_smokeErrorHook(); return; }
    PostQuitMessage(1);
#else
    MessageBoxW(parent, msg, L"DeskRally \x2013 Error", MB_OK | MB_ICONERROR);
#endif
}

static void UpdateHelloMenu(HWND hwnd) {
    HMENU menu = GetMenu(hwnd);
    if (!menu) return;
    const UINT blocked = g_helloPending ? MF_GRAYED : MF_ENABLED;
    EnableMenuItem(menu, IDM_HELLO_ENABLE, MF_BYCOMMAND | blocked);
    EnableMenuItem(menu, IDM_HELLO_DISABLE, MF_BYCOMMAND | blocked);
    CheckMenuItem(menu, IDM_HELLO_ENABLE, MF_BYCOMMAND |
        (g_helloSetting == drhello::Setting::Enabled ? MF_CHECKED : MF_UNCHECKED));
    DrawMenuBar(hwnd);
}

static void CompleteHello(const std::shared_ptr<WindowState>& state, uint64_t generation, bool verified) {
    if (!state || !drhello::may_complete(g_helloGeneration, generation, g_helloPending,
        state->closing || !IsWindow(state->hwnd))) return;
    g_helloPending = false;
    g_helloOperation.Reset();
    UpdateHelloMenu(state->hwnd);
    if (!verified) {
        if (g_helloPurpose == HelloPurpose::Startup) {
            // Offer another attempt in place: a missed face or finger is common, and failing used to
            // close the app, so the only way to retry was to reopen it.
            const int choice = MessageBoxW(state->hwnd,
                L"Windows Hello did not unlock DeskRally. Your saved profile was not opened.\n\n"
                L"Try again, or Cancel to close the app (you can also sign in through your organization's website).",
                L"DeskRally - Windows Hello", MB_RETRYCANCEL | MB_ICONWARNING);
            if (choice == IDRETRY) {
                SetForegroundWindow(state->hwnd);
                StartHello(state, HelloPurpose::Startup);
                return;
            }
            SendMessageW(state->hwnd, WM_CLOSE, 0, 0);
        } else {
            ShowError(state->hwnd, L"Windows Hello verification was canceled, unavailable, or unsuccessful.\n\n"
                L"Your setting was not changed. Configure Windows Hello in Windows Settings if needed.");
        }
        return;
    }
    if (g_helloPurpose == HelloPurpose::Startup) {
        g_helloVerifiedAtStartup = true;
        StartProfile(state);
        return;
    }
    const bool enable = g_helloPurpose == HelloPurpose::Enable;
    if (!WriteHelloSetting(state->selectedTenant, enable)) {
        ShowError(state->hwnd, L"Could not save the Windows Hello setting. Please try again.");
        return;
    }
    g_helloSetting = enable ? drhello::Setting::Enabled : drhello::Setting::Disabled;
    UpdateHelloMenu(state->hwnd);
    MessageBoxW(state->hwnd, enable
        ? L"Windows Hello is enabled for this organization.\n\nClose and reopen this app window to unlock with Hello. "
          L"Then sign out and sign in with Remember this app selected for a 30-day sign-in. Existing windows are unchanged."
        : L"Windows Hello is disabled for new app launches in this organization.\n\n"
          L"This does not sign you out of DeskRally. Use Sign out to end your remembered server sign-in. "
          L"Close and reopen existing windows to apply the setting.",
        L"DeskRally - Windows Hello", MB_OK | MB_ICONINFORMATION);
}

static void StartHello(const std::shared_ptr<WindowState>& state, HelloPurpose purpose) {
    if (!state || state->closing || g_helloPending) return;
#ifdef SMOKE_TEST
    (void)purpose;
    return; // Synthetic tests never request user verification or touch real settings.
#else
    g_helloPurpose = purpose;
    g_helloPending = true;
    const uint64_t generation = ++g_helloGeneration;
    const HWND hwnd = state->hwnd;
    UpdateHelloMenu(hwnd);
    ComPtr<IUserConsentVerifierInterop> verifier;
    HRESULT hr = RoGetActivationFactory(Microsoft::WRL::Wrappers::HStringReference(
        L"Windows.Security.Credentials.UI.UserConsentVerifier").Get(), IID_PPV_ARGS(&verifier));
    if (SUCCEEDED(hr)) {
        std::wstring message = L"DeskRally - " + TenantLabel(state->selectedTenant) +
            (purpose == HelloPurpose::Startup ? L": unlock your saved sign-in" : L": change Windows Hello setting");
        hr = verifier->RequestVerificationForWindowAsync(hwnd,
            Microsoft::WRL::Wrappers::HStringReference(message.c_str()).Get(),
            __uuidof(HelloOperation), reinterpret_cast<void**>(g_helloOperation.GetAddressOf()));
    }
    if (SUCCEEDED(hr) && g_helloOperation) {
        // The completion can arrive on another thread. Only post scalar result data;
        // the UI thread owns settings, WebView creation, and window lifetime checks.
        hr = g_helloOperation->put_Completed(Callback<HelloCompletion>(
            [hwnd, generation](HelloOperation* op, AsyncStatus status) -> HRESULT {
                HelloResult result{};
                const bool verified = status == AsyncStatus::Completed && op &&
                    SUCCEEDED(op->GetResults(&result)) && result ==
                    ABI::Windows::Security::Credentials::UI::UserConsentVerificationResult_Verified;
                PostMessageW(hwnd, WM_HELLO_RESULT, static_cast<WPARAM>(generation), verified ? 1 : 0);
                return S_OK;
            }).Get());
    } else if (SUCCEEDED(hr)) {
        hr = E_FAIL;
    }
    if (FAILED(hr)) CompleteHello(state, generation, false);
#endif
}

// ── Smoke-test log ─────────────────────────────────────────────────────────
#ifdef SMOKE_TEST
static FILE* g_smokeLog = nullptr;
static void SmokeLog(const char* fmt, ...) {
    if (!g_smokeLog) return;
    va_list va; va_start(va, fmt);
    vfprintf(g_smokeLog, fmt, va);
    va_end(va);
    fflush(g_smokeLog);
}

static void SsoSmokeCompleteResponse(HWND hwnd) {
    KillTimer(hwnd, kSsoSmokeResponseTimerId);
    if (g_ssoSmokePendingArgs && g_ssoSmokePendingResponse)
        g_ssoSmokePendingArgs->put_Response(g_ssoSmokePendingResponse.Get());
    if (g_ssoSmokeDeferral) g_ssoSmokeDeferral->Complete();
    g_ssoSmokePendingArgs.Reset();
    g_ssoSmokePendingResponse.Reset();
    g_ssoSmokeDeferral.Reset();
}

static bool SsoSmokeInstall(const std::shared_ptr<WindowState>& tab, HWND hwnd) {
    auto* wv = tab->webview.Get();
    // Catch all resources as well as the explicit test origins: unexpected requests
    // receive a local response too, rather than escaping to the network.
    const std::wstring tenantFilter = kSsoSmokeOrigin + L"/*";
    for (const wchar_t* filter : {tenantFilter.c_str(),
             L"https://login.microsoftonline.com/*", L"https://evil.example/*", L"*"}) {
        if (FAILED(wv->AddWebResourceRequestedFilter(filter, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)))
            return false;
    }
    EventRegistrationToken token{};
    return SUCCEEDED(wv->add_WebResourceRequested(
        Callback<ICoreWebView2WebResourceRequestedEventHandler>(
            [hwnd](ICoreWebView2*, ICoreWebView2WebResourceRequestedEventArgs* args) -> HRESULT {
                ComPtr<ICoreWebView2WebResourceRequest> request;
                HRESULT hr = args->get_Request(&request);
                if (FAILED(hr) || !request) return E_FAIL;
                LPWSTR raw = nullptr;
                hr = request->get_Uri(&raw);
                const std::wstring uri(raw ? raw : L"");
                CoTaskMemFree(raw);
                if (FAILED(hr)) return hr;
                const auto end = uri.find_first_of(L"?#");
                const auto path = uri.substr(0, end);
                const bool redirect = path == kSsoSmokeOrigin + L"/cp/auth/oidc/start" ||
                    path == kSsoSmokeOrigin + L"/cp/machines";
                // The product's request-layer backstop may already have answered (a local 403 for a
                // cancelled navigation). Never overwrite it, or the harness would mask the backstop.
                {
                    ComPtr<ICoreWebView2WebResourceResponse> existing;
                    if (SUCCEEDED(args->get_Response(&existing)) && existing) {
                        int status = 0;
                        existing->get_StatusCode(&status);
                        if (status == 403) {
                            SmokeLog("[sso-smoke] harness: leaving the backstop's 403 for %ls\n", uri.c_str());
                            return S_OK;
                        }
                    }
                }
                if (g_ssoSmokeProbe && uri.rfind(L"http://127.0.0.1:8765/", 0) == 0) {
                    SmokeLog("[sso-smoke] probe: WebResourceRequested saw %ls (passing it to the network)\n", uri.c_str());
                    return S_OK;
                }
                const bool idp = uri == kSsoSmokeAuthz;
                if (path == L"https://evil.example/") {
                    ++g_ssoSmokeEvilRequests;
                    SmokeLog("[sso-smoke] t=%llu WebResourceRequested evil.example\n", (unsigned long long)GetTickCount64());
                }
                const char* body = "<!doctype html><title>console</title>";
                if (idp) body = "<!doctype html><title>idp</title>idp";
                else if (path == kSsoSmokeOrigin + L"/cp/auth/oidc/callback")
                    body = "<!doctype html><title>tenant back</title>tenant back";
                else if (path == L"https://evil.example/")
                    body = "<!doctype html><title>evil</title>evil";
                UINT length = 0;
                while (body[length]) ++length;
                ComPtr<IStream> stream;
                stream.Attach(SHCreateMemStream(reinterpret_cast<const BYTE*>(body), length));
                if (!stream) return E_OUTOFMEMORY;
                std::wstring headers = L"Content-Type: text/html\r\n";
                if (redirect) headers += std::wstring(L"Location: ") + kSsoSmokeAuthz + L"\r\n";
                ComPtr<ICoreWebView2WebResourceResponse> response;
                hr = g_env->CreateWebResourceResponse(stream.Get(), redirect ? 302 : 200,
                    redirect ? L"Found" : L"OK", headers.c_str(), &response);
                if (FAILED(hr)) return hr;
                if (idp && g_ssoSmokeDelayIdp) {
                    g_ssoSmokeDelayIdp = false;
                    if (g_ssoSmokeDeferral) return E_UNEXPECTED;
                    hr = args->GetDeferral(&g_ssoSmokeDeferral);
                    if (FAILED(hr)) return hr;
                    g_ssoSmokePendingArgs = args;
                    g_ssoSmokePendingResponse = response;
                    if (!SetTimer(hwnd, kSsoSmokeResponseTimerId, 5000, nullptr)) {
                        SsoSmokeCompleteResponse(hwnd);
                        return E_FAIL;
                    }
                    return S_OK;
                }
                return args->put_Response(response.Get());
            }).Get(), &token));
}

static bool StateUsable(const std::shared_ptr<WindowState>& st);
static void SsoSmokeTick(HWND hwnd) {
    static int step = 0;
    static ULONGLONG began = 0;
    static unsigned unsupportedBefore = 0, timeoutBefore = 0;
    static int passed = 0, failed = 0;
    static std::wstring committed;
    static unsigned completions = 0, mark = 0;
    static bool observing = false;
    static bool unsupportedSeen = false;
    static bool evilSeen = false;
    const ULONGLONG now = GetTickCount64();
    auto tab = ActiveTab(g_mainState);
    if (!tab || !StateUsable(tab) || !tab->webview) return;
    auto* wv = tab->webview.Get();
    const auto finish = [&]() {
        KillTimer(hwnd, kSsoSmokeTimerId);
        SsoSmokeCompleteResponse(hwnd);
        SmokeLog("[sso-smoke] DONE pass=%d fail=%d\n", passed, failed);
        g_smokeResult = failed == 0 ? 0 : 1;
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    };
    const char* name = step <= 3 ? "entry-A" : step <= 6 ? "entry-B" :
        step <= 9 ? "deny-other-redirect" : step <= 14 ? "unsupported-host" : step <= 17 ? "deadline-delay" : step <= 19 ? "retry-after-timeout" : "probe";
    const auto fail = [&](const char* detail) {
        ++failed;
        SmokeLog("[sso-smoke] FAIL %s %s (step=%d)\n", name, detail, step);
        finish();
    };
    const auto next = [&](int value) { step = value; began = now; mark = completions; };
    const auto pass = [&]() { ++passed; SmokeLog("[sso-smoke] PASS %s\n", name); };
    if (!observing) {
        EventRegistrationToken token{};
        const HRESULT hr = wv->add_NavigationCompleted(
            Callback<ICoreWebView2NavigationCompletedEventHandler>(
                [](ICoreWebView2* sender, ICoreWebView2NavigationCompletedEventArgs* args) -> HRESULT {
                    BOOL success = FALSE;
                    if (SUCCEEDED(args->get_IsSuccess(&success)) && success) {
                        LPWSTR raw = nullptr;
                        if (SUCCEEDED(sender->get_Source(&raw)) && raw) {
                            committed = raw;
                            ++completions;
                        }
                        CoTaskMemFree(raw);
                    }
                    return S_OK;
                }).Get(), &token);
        if (FAILED(hr)) { fail("cannot observe completion"); return; }
        observing = true;
        began = now;
    }
    LPWSTR raw = nullptr;
    wv->get_Source(&raw);
    const std::wstring source(raw ? raw : L"");
    CoTaskMemFree(raw);
    wchar_t title[1024]{};
    GetWindowTextW(hwnd, title, 1024);
    const bool signIn = std::wstring(title).find(L"Microsoft sign-in") == 0;
    const auto host = drpolicy::parse_url(WideToUtf8(source)).host;
    const bool tenant = host == kSsoSmokeHost;
    const bool complete = completions > mark && committed == source;
    const bool console = complete && source == kSsoSmokeConsole && tenant && !signIn;
    const bool idp = complete && host == "login.microsoftonline.com" && signIn;
    if (step == 13) {
        unsupportedSeen = unsupportedSeen || g_ssoSmokeUnsupported > unsupportedBefore;
        // The design's guarantee is that a non-allowed page never LOADS (commits). WebView2 still raises
        // WebResourceRequested for a navigation cancelled in NavigationStarting (measured: same tick),
        // so the request count is logged as information, not as a failure.
        evilSeen = evilSeen || host == "evil.example";
    }
    if (now - began >= 8000) { fail("8 s observable timeout"); return; }
    HRESULT hr = S_OK;
    const auto script = [&](const std::wstring& code) {
        return wv->ExecuteScript(code.c_str(),
            Callback<ICoreWebView2ExecuteScriptCompletedHandler>(
                [](HRESULT result, LPCWSTR) -> HRESULT {
                    if (FAILED(result)) SmokeLog("[sso-smoke] ExecuteScript failed 0x%08x\n", (unsigned)result);
                    return S_OK;
                }).Get());
    };
    switch (step) {
    case 0: case 4: case 7: case 10: case 15:
        hr = wv->Navigate(kSsoSmokeConsole.c_str()); next(step + 1); break;
    case 1:
        if (console) { hr = script(std::wstring(L"location.assign('") + kSsoSmokeAuthz + L"')"); next(2); }
        break;
    case 2:
        if (idp) { hr = script(L"location.assign('" + kSsoSmokeOrigin + L"/cp/auth/oidc/callback?code=x')"); next(3); }
        break;
    case 3:
        if (complete && tenant && !signIn && source.find(L"/cp/auth/oidc/callback?code=x") != std::wstring::npos) {
            pass(); next(4);
        }
        break;
    case 5: case 11:
        if (console) { hr = wv->Navigate((kSsoSmokeOrigin + L"/cp/auth/oidc/start").c_str()); next(step + 1); }
        break;
    case 6:
        if (idp) { pass(); next(7); }
        break;
    case 8:
        if (console) { hr = wv->Navigate((kSsoSmokeOrigin + L"/cp/machines").c_str()); next(9); }
        break;
    case 9:
        if (now - began >= 2000) {
            if (!tenant || signIn) { fail("redirect escaped tenant"); return; }
            pass(); next(10);
        }
        break;
    case 12:
        if (idp) {
            unsupportedBefore = g_ssoSmokeUnsupported;
            unsupportedSeen = false; evilSeen = false;
            hr = script(L"location.assign('https://evil.example/')"); next(13);
        }
        break;
    case 13:
        if (evilSeen) {
            SmokeLog("[sso-smoke] evil diag: committed host=%s evil_requests=%u source=%ls\n",
                     host.c_str(), g_ssoSmokeEvilRequests, source.c_str());
            fail("evil origin reached"); return;
        }
        if (unsupportedSeen && host != "evil.example") {
            if (source == kSsoSmokeConsole && tenant && !signIn) { pass(); next(15); }
            else { step = 14; }
        } else if (now - began >= 3000) { fail("Unsupported notification missing within 3 s"); return; }
        break;
    case 14:
        if (source == kSsoSmokeConsole && tenant && !signIn) { pass(); next(15); }
        break;
    case 16:
        if (console) {
            timeoutBefore = g_ssoSmokeTimedOut;
            g_ssoSmokeDelayIdp = true;
            hr = script(std::wstring(L"location.assign('") + kSsoSmokeAuthz + L"')"); next(17);
        }
        break;
    case 18:
        if (console) { hr = wv->Navigate((kSsoSmokeOrigin + L"/cp/auth/oidc/start").c_str()); next(19); }
        break;
    case 19:
        // S6 retry-after-timeout: after S5's timed-out flow, a fresh sign-in must be possible again
        // (the expired flow closes on the tenant reload, which SourceChanged alone never reported).
        if (idp) {
            pass();
            if (!g_ssoSmokeProbe) { finish(); return; }
            hr = script(L"location.assign('http://127.0.0.1:8765/probe')"); next(20);
        }
        break;
    case 20:
        if (now - began >= 3000) {
            SmokeLog("[sso-smoke] PROBE finished: committed host=%s (see the listener log for a hit)\n", host.c_str());
            if (host == "127.0.0.1") { fail("probe page COMMITTED"); return; }
            finish(); return;
        }
        break;
    case 17:
        // Wait beyond the deferred response, even if Stop already left the tenant document visible.
        if (now - began >= 5500 && !g_ssoSmokeDeferral && tenant && !signIn &&
            g_ssoSmokeTimedOut > timeoutBefore) { pass(); next(18); hr = wv->Navigate(kSsoSmokeConsole.c_str()); break; }
        break;
    }
    if (FAILED(hr)) fail("navigation/script dispatch failed");
}

// Called from WebMessageReceived – count results, close main when all done.
static void SmokeHandleMessage(const std::wstring& msg, HWND mainHwnd) {
    auto u8 = WideToUtf8(msg);
    SmokeLog("[smoke] webmessage: %s\n", u8.c_str());
    if (msg.find(L"REQUEST_CLIPBOARD_TEST") != std::wstring::npos && !g_mainState->children.empty()) {
        auto child = g_mainState->children.back();
        auto webview = child->webview;
        webview->CallDevToolsProtocolMethod(L"Emulation.setFocusEmulationEnabled", L"{\"enabled\":true}",
            Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
                [webview](HRESULT, LPCWSTR) -> HRESULT {
                    webview->CallDevToolsProtocolMethod(L"Runtime.evaluate",
                        LR"json({"expression":"navigator.clipboard.readText().then(()=>0,()=>0)","userGesture":true})json",
                        Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
                            [](HRESULT result, LPCWSTR response) -> HRESULT {
                                SmokeLog("[smoke] clipboard dispatch 0x%08x %ls\n", (unsigned)result, response ? response : L"");
                                return S_OK;
                            }).Get());
                    return S_OK;
                }).Get());
        return;
    }
    if (msg.find(L"ARM_CLOSE_PENDING") != std::wstring::npos) {
        g_smokeClosePending = true;
        auto tab = ActiveTab(g_mainState);
        if (!tab || !tab->webview) return;
        tab->webview->CallDevToolsProtocolMethod(L"Runtime.evaluate",
            LR"json({"expression":"document.getElementById('b2').click()","userGesture":true})json",
            Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
                [](HRESULT, LPCWSTR) -> HRESULT { return S_OK; }).Get());
        return;
    }
    if (msg.find(L"\"PASS\"") != std::wstring::npos) {
        ++g_smokePassCount;
        SmokeLog("[smoke] PASS count=%d\n", g_smokePassCount);
    } else if (msg.find(L"\"FAIL\"") != std::wstring::npos) {
        ++g_smokeFailCount;
        SmokeLog("[smoke] FAIL count=%d\n", g_smokeFailCount);
    }
    if (g_smokePassCount + g_smokeFailCount == kSmokeFixtureTests && g_smokeTabStep == 0) {
        g_smokeTabStep = 1;
        SmokeLog("[smoke] fixture tests done; starting the tab sequence\n");
        SetTimer(mainHwnd, kSmokeTabTimerId, 200, nullptr);
    }
    if (g_smokePassCount + g_smokeFailCount >= kSmokeExpectedTests) {
        if (g_smokeFailCount == 0) g_smokeResult = 0;
        SmokeLog("[smoke] all %d tests done: %d passed %d failed – posting close\n",
                 kSmokeExpectedTests, g_smokePassCount, g_smokeFailCount);
        PostMessageW(mainHwnd, WM_CLOSE, 0, 0);
    }
}
// Test the actual native controller: hidden WebViews still execute JavaScript,
// so the DOM/popup tests alone cannot detect a blank native window.
static void SmokeCheckSurface(const std::shared_ptr<WindowState>& state) {
    BOOL visible = FALSE;
    RECT bounds{}, client{};
    if (state->is_tab) { if (auto w = state->window.lock()) client = TabContentRect(w); }
    else GetClientRect(state->hwnd, &client);
    const bool ok = SUCCEEDED(state->controller->get_IsVisible(&visible)) && visible &&
        SUCCEEDED(state->controller->get_Bounds(&bounds)) &&
        EqualRect(&bounds, &client) && bounds.right > bounds.left && bounds.bottom > bounds.top &&
        // A tab's page must sit BELOW a real tab strip (a strip measured with no items is ~6 px).
        (!state->is_tab || bounds.top >= 16);
    SmokeLog("[smoke] %s surface visible=%d bounds=%ld,%ld,%ld,%ld\n",
        state->is_popup ? "popup" : "main", (int)visible,
        bounds.left, bounds.top, bounds.right, bounds.bottom);
    SmokeHandleMessage(ok
        ? L"{\"test\":\"native_surface\",\"result\":\"PASS\"}"
        : L"{\"test\":\"native_surface\",\"result\":\"FAIL\"}", g_mainState->hwnd);
}
#endif

// ── Forward declarations ───────────────────────────────────────────────────
static bool RegisterHandlers(std::shared_ptr<WindowState> state);
static void CreateChildPopupWindow(std::shared_ptr<WindowState> parent,
                                   ComPtr<ICoreWebView2NewWindowRequestedEventArgs> args,
                                   uint64_t openerTabId);

// ── Clipboard consent – deferred dispatch to avoid WebView2 reentrancy ─────
// Takes the request BY VALUE: Complete() can re-enter (WebView2 runs callbacks that queue, pump or
// tear down), so nothing here may refer into g_consentQueue or g_consentActive across the COM calls.
static void SettleConsent(std::shared_ptr<ClipboardConsentCtx> req, bool allow) {
    if (!req || req->settled) return;
    req->settled = true;
    req->args->put_State(allow ? COREWEBVIEW2_PERMISSION_STATE_ALLOW : COREWEBVIEW2_PERMISSION_STATE_DENY);
    req->deferral->Complete();
#ifdef SMOKE_TEST
    ++g_smokeConsentCompletions;
#endif
}

// Deny + complete every request of `who`, queued or on screen. Matching requests are DETACHED into a
// local owning list first, then settled, so a re-entrant Complete() never invalidates an iteration.
// The dialog of an on-screen request returns later into a settled request and changes nothing.
static void SettleConsentsFor(std::shared_ptr<WindowState> who) {
    std::vector<std::shared_ptr<ClipboardConsentCtx>> mine;
    for (auto it = g_consentQueue.begin(); it != g_consentQueue.end();) {
        if (*it && (*it)->state == who) { mine.push_back(std::move(*it)); it = g_consentQueue.erase(it); }
        else ++it;
    }
    if (g_consentActive && g_consentActive->state == who) mine.push_back(g_consentActive);
    for (auto& req : mine) SettleConsent(req, false);
}
static void SettleAllConsents() {
    std::deque<std::shared_ptr<ClipboardConsentCtx>> all;
    all.swap(g_consentQueue);
    if (g_consentActive) all.push_back(g_consentActive);
    for (auto& req : all) SettleConsent(req, false);
}

static bool StateUsable(const std::shared_ptr<WindowState>& st);

static bool ConsentStillValid(const std::shared_ptr<ClipboardConsentCtx>& req) {
    return req && !req->settled && StateUsable(req->state) && req->state->hwnd && IsWindow(req->state->hwnd) &&
        req->generation == req->state->navigation_generation;
}

// Runs from WM_CLIPBOARD_CONSENT on the main window. The WHOLE pump - validation, dialog and
// settlement - is guarded: re-entry (from a dialog's modal loop, or from a Complete() callback) returns
// at once, and whatever it queued is drained by the outer loop. There is never a second dialog.
static void PumpConsents() {
    if (g_consentShowing) return;
    g_consentShowing = true;
    while (!g_consentQueue.empty()) {
        auto req = g_consentQueue.front();
        g_consentQueue.pop_front();
        if (!req || req->settled) continue;
        if (!ConsentStillValid(req)) { SettleConsent(req, false); continue; }
        if (const auto known = g_consentAnswers.find(req->origin); known != g_consentAnswers.end()) {
            SettleConsent(req, known->second);
            continue;
        }
        g_consentActive = req;
        bool granted;
#ifdef SMOKE_TEST
        granted = g_smokeConsentAnswer ? g_smokeConsentAnswer(req) : false;
#else
        granted = req->state->ShowClipboardConsentDialog(req->origin);
#endif
        // Still the active request while it settles (a teardown re-entering from Complete() finds it
        // settled); `req` owns it whatever the callbacks do to the globals.
        const bool stillValid = ConsentStillValid(req);
        if (stillValid) g_consentAnswers[req->origin] = granted;
        SettleConsent(req, granted && stillValid);
        g_consentActive.reset();
    }
    g_consentShowing = false;
}

// ── Window creation ────────────────────────────────────────────────────────
static void CancelQueuedConsent(HWND hwnd) {
    MSG message{};
    while (PeekMessageW(&message, hwnd, WM_CLIPBOARD_CONSENT, WM_CLIPBOARD_CONSENT, PM_REMOVE)) {
        auto* ctx = reinterpret_cast<ClipboardConsentCtx*>(message.lParam);
        if (!ctx) continue;
        ctx->args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
        ctx->deferral->Complete();
        delete ctx;
    }
}

static void CancelQueuedSpawn(HWND hwnd) {
    MSG message{};
    while (PeekMessageW(&message, hwnd, WM_SPAWN_CLIENT, WM_SPAWN_CLIENT, PM_REMOVE))
        delete reinterpret_cast<std::wstring*>(message.lParam);
}

static HWND CreateMainWindow() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = g_hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClass;
    wc.hIcon         = LoadIconW(g_hInstance, MAKEINTRESOURCEW(101));
    wc.hIconSm       = LoadIconW(g_hInstance, MAKEINTRESOURCEW(101));
    RegisterClassExW(&wc);
    return CreateWindowExW(
        0, kWindowClass, kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800,
        nullptr, nullptr, g_hInstance, nullptr);
}

static HWND CreatePopupWindow() {
    static bool registered = false;
    static constexpr wchar_t kPopupClass[] = L"DeskRallyPopupWnd";
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = PopupWndProc;
        wc.hInstance     = g_hInstance;
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = kPopupClass;
        wc.hIcon         = LoadIconW(g_hInstance, MAKEINTRESOURCEW(101));
        wc.hIconSm       = LoadIconW(g_hInstance, MAKEINTRESOURCEW(101));
        RegisterClassExW(&wc);
        registered = true;
    }
    return CreateWindowExW(
        0, kPopupClass, kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1024, 700,
        nullptr, nullptr, g_hInstance, nullptr);
}

// Returns a menu bar whose Organization submenu lists the current organization and
// the others this Windows user has opened on this PC, then "Open another organization...".
// Returns nullptr on allocation failure; caller must DestroyMenu on success.
static HMENU CreateOrgMenu(const drpolicy::Tenant& current) {
    g_orgMenuTenants.clear();
    g_orgMenuTenants.push_back(current);
    for (const auto& known : ReadKnownOrgs()) {
        if (g_orgMenuTenants.size() >= kMaxKnownOrgs) break;
        if (known.tenant != current) g_orgMenuTenants.push_back(known.tenant);
    }
    HMENU bar = CreateMenu();
    if (!bar) return nullptr;
    HMENU org = CreatePopupMenu();
    if (!org) { DestroyMenu(bar); return nullptr; }
    bool ok = true;
    for (size_t i = 0; ok && i < g_orgMenuTenants.size(); ++i) {
        const auto& t = g_orgMenuTenants[i];
        const std::wstring label = TenantLabel(t) + L"\t" + Utf8ToWide(drpolicy::tenant_host(t));
        ok = AppendMenuW(org, MF_STRING | (i == 0 ? MF_CHECKED : 0),
            IDM_ORG_FIRST + static_cast<UINT>(i), label.c_str()) != FALSE;
    }
    if (!ok ||
        !AppendMenuW(org, MF_SEPARATOR, 0, nullptr) ||
        !AppendMenuW(org, MF_STRING, IDM_ORG_OTHER, L"Open another organization...") ||
        !AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(org), L"Organization")) {
        DestroyMenu(org);
        DestroyMenu(bar);
        return nullptr;
    }
    HMENU security = CreatePopupMenu();
    if (!security) { DestroyMenu(bar); return nullptr; }
    if (!AppendMenuW(security, MF_STRING, IDM_HELLO_ENABLE, L"Enable Windows Hello") ||
        !AppendMenuW(security, MF_STRING, IDM_HELLO_DISABLE, L"Disable Windows Hello") ||
        !AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(security), L"Security")) {
        DestroyMenu(security);
        DestroyMenu(bar);
        return nullptr;
    }
    HMENU tabsMenu = CreatePopupMenu();
    if (!tabsMenu) { DestroyMenu(bar); return nullptr; }
    if (!AppendMenuW(tabsMenu, MF_STRING, IDM_TAB_NEW, L"New tab\tCtrl+T") ||
        !AppendMenuW(tabsMenu, MF_STRING, IDM_TAB_CLOSE, L"Close tab\tCtrl+W") ||
        !AppendMenuW(tabsMenu, MF_SEPARATOR, 0, nullptr) ||
        !AppendMenuW(tabsMenu, MF_STRING, IDM_TAB_NEXT, L"Next tab\tCtrl+Tab") ||
        !AppendMenuW(tabsMenu, MF_STRING, IDM_TAB_PREV, L"Previous tab\tCtrl+Shift+Tab") ||
        !AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(tabsMenu), L"Tabs")) {
        DestroyMenu(tabsMenu);
        DestroyMenu(bar);
        return nullptr;
    }
    HMENU updates = CreatePopupMenu();
    if (!updates) { DestroyMenu(bar); return nullptr; }
    if (!AppendMenuW(updates, MF_STRING, IDM_UPDATE_CHECK, L"Check for updates") ||
        !AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(updates), L"Updates")) {
        DestroyMenu(updates);
        DestroyMenu(bar);
        return nullptr;
    }
    HMENU help = CreatePopupMenu();
    if (!help) { DestroyMenu(bar); return nullptr; }
    if (!AppendMenuW(help, MF_STRING, IDM_ABOUT, L"About DeskRally") ||
        !AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"Help")) {
        DestroyMenu(help);
        DestroyMenu(bar);
        return nullptr;
    }
    return bar;
}

// ── Tear down children (snapshot to avoid iterator invalidation) ───────────
static void CloseAllChildren(std::shared_ptr<WindowState>& st) {
    // Move children out before iterating; DestroyWindow triggers WM_DESTROY which
    // would otherwise erase from the same vector mid-iteration (UB).
    auto snapshot = std::move(st->children);
    for (auto& child : snapshot) {
        if (!child) continue;
        child->closing = true;
        SettleConsentsFor(child);
        if (child->controller) {
            child->controller->Close();
            child->controller.Reset();
            child->webview.Reset();
        }
        if (child->hwnd && IsWindow(child->hwnd))
            DestroyWindow(child->hwnd);
    }
}


// ── Tabs (docs-tabs-design.md) ─────────────────────────────────────────────
// All tab state lives on the UI thread. Tabs are addressed by stable tab_id only; nothing holds an
// index across an asynchronous boundary.
static std::shared_ptr<WindowState> FindTab(const std::shared_ptr<WindowState>& win, uint64_t id) {
    if (!win || id == 0) return nullptr;
    for (auto& t : win->tabs) if (t && t->tab_id == id) return t;
    return nullptr;
}
static long long TabIndex(const std::shared_ptr<WindowState>& win, uint64_t id) {
    if (!win) return -1;
    for (size_t i = 0; i < win->tabs.size(); ++i) if (win->tabs[i] && win->tabs[i]->tab_id == id) return (long long)i;
    return -1;
}
static std::shared_ptr<WindowState> ActiveTab(const std::shared_ptr<WindowState>& win) {
    auto t = FindTab(win, win ? win->active_tab : 0);
    return (t && t->phase != WindowState::Phase::Closing) ? t : nullptr;
}
// Any live tab's WebView: every tab shares the organization's profile and cookie manager.
static ComPtr<ICoreWebView2> AnyLiveWebView(const std::shared_ptr<WindowState>& win) {
    if (auto t = ActiveTab(win); t && t->phase == WindowState::Phase::Live && t->webview) return t->webview;
    if (win) for (auto& t : win->tabs) if (t && t->phase == WindowState::Phase::Live && t->webview) return t->webview;
    return nullptr;
}
// Is this WebView's owner still one the app acts for? A TAB must still be in its window's list (by
// id), Live, and its window not closing; a POPUP must not be closing and its main window must not be.
// Every WebView2 event handler checks this first (Codex impl review: uniform validation).
static bool StateUsable(const std::shared_ptr<WindowState>& st) {
    if (!st || st->closing) return false;
    if (st->is_tab) {
        auto win = st->window.lock();
        return win && !win->closing && FindTab(win, st->tab_id) == st && st->phase == WindowState::Phase::Live;
    }
    if (st->is_popup) {
        auto parent = st->parent.lock();
        return parent && !parent->closing;
    }
    return true;
}

static size_t CountOpenTabs(const std::shared_ptr<WindowState>& win) {
    size_t n = 0;
    if (win) for (auto& t : win->tabs) if (t && t->phase != WindowState::Phase::Closing) ++n;
    return n;
}

// The WebView area: the client area below the tab strip (all of it in full screen, the strip hidden).
static RECT TabContentRect(const std::shared_ptr<WindowState>& win) {
    RECT rc{}; GetClientRect(win->hwnd, &rc);
    if (win->tab_ctrl && !win->fullscreen) {
        RECT strip{}; GetWindowRect(win->tab_ctrl, &strip);
        MapWindowPoints(nullptr, win->hwnd, reinterpret_cast<POINT*>(&strip), 2);
        rc.top = (std::min)(rc.bottom, strip.bottom);
    }
    return rc;
}

static void LayoutTabs(const std::shared_ptr<WindowState>& win) {
    if (!win || !win->hwnd) return;
    RECT rc{}; GetClientRect(win->hwnd, &rc);
    if (win->tab_ctrl) {
        // Height of the strip = the tab control's header height for its current font and DPI.
        RECT probe{0, 0, rc.right, 400};
        TabCtrl_AdjustRect(win->tab_ctrl, FALSE, &probe);
        const int stripHeight = (std::max)(0L, probe.top) + 2;
        MoveWindow(win->tab_ctrl, 0, 0, rc.right, stripHeight, TRUE);
    }
    const RECT content = TabContentRect(win);
    for (auto& t : win->tabs)
        if (t && t->controller && t->phase == WindowState::Phase::Live) t->controller->put_Bounds(content);
}

// ── Full screen ──
// A page's requestFullscreen() only fills the WebView; the title bar, frame and tab strip stay unless
// the HOST takes the window full screen. One rule, re-evaluated whenever an input to it changes
// (the WebView's ContainsFullScreenElementChanged, switching or closing tabs): a window (the main
// window or a popup) is borderless and covers its monitor exactly while the WebView it SHOWS
// contains a full-screen element. A tab switched away from keeps its element full screen inside its
// own page, so switching back resumes full screen, as a browser does.
static void FitFullscreen(const std::shared_ptr<WindowState>& frame) {
    MONITORINFO mi{sizeof(mi)};
    if (!GetMonitorInfoW(MonitorFromWindow(frame->hwnd, MONITOR_DEFAULTTONEAREST), &mi)) return;
    SetWindowPos(frame->hwnd, HWND_TOP, mi.rcMonitor.left, mi.rcMonitor.top,
        mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top,
        SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
}

// A window destroyed while full screen still owns the menu SyncFullscreen detached: DestroyWindow
// frees only an ATTACHED menu, so free it here (both window procedures' WM_NCDESTROY).
static void ReleaseDetachedMenu(WindowState& frame) {
    if (frame.restore_menu) DestroyMenu(frame.restore_menu);
    frame.restore_menu = nullptr;
}

static void SyncFullscreen(const std::shared_ptr<WindowState>& frame) {
    if (!frame || frame->closing || !frame->hwnd || frame->is_tab) return;
    auto shown = frame->is_popup ? frame : ActiveTab(frame);
    BOOL contains = FALSE;
    if (shown && !shown->closing && shown->webview &&
        (frame->is_popup || shown->phase == WindowState::Phase::Live))
        shown->webview->get_ContainsFullScreenElement(&contains);
    const bool want = contains != FALSE;
    if (want == frame->fullscreen) return;
    if (want) {
        frame->restore_placement.length = sizeof(WINDOWPLACEMENT);
        if (!GetWindowPlacement(frame->hwnd, &frame->restore_placement)) return;
        // A maximized window is restored first (its placement remembers it), so the borderless
        // window is an ordinary one sized to the monitor rather than a maximized one without a frame.
        if (IsZoomed(frame->hwnd)) ShowWindow(frame->hwnd, SW_RESTORE);
        frame->restore_style = GetWindowLongPtrW(frame->hwnd, GWL_STYLE);
        frame->fullscreen = true;  // before resizing: the layout it triggers must drop the strip
        if (frame->tab_ctrl) ShowWindow(frame->tab_ctrl, SW_HIDE);
        // The menu bar is non-client area that survives losing the frame (measured: it kept 20 px of a
        // full-screen window). SetMenu(nullptr) detaches without destroying; exit reattaches it.
        frame->restore_menu = GetMenu(frame->hwnd);
        if (frame->restore_menu) SetMenu(frame->hwnd, nullptr);
        SetWindowLongPtrW(frame->hwnd, GWL_STYLE, frame->restore_style & ~WS_OVERLAPPEDWINDOW);
        FitFullscreen(frame);
    } else {
        frame->fullscreen = false;
        if (frame->restore_menu) SetMenu(frame->hwnd, frame->restore_menu);
        frame->restore_menu = nullptr;
        SetWindowLongPtrW(frame->hwnd, GWL_STYLE, frame->restore_style);
        SetWindowPlacement(frame->hwnd, &frame->restore_placement);
        SetWindowPos(frame->hwnd, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        if (frame->tab_ctrl) ShowWindow(frame->tab_ctrl, SW_SHOW);
    }
    if (frame->is_popup) {
        RECT rc{}; GetClientRect(frame->hwnd, &rc);
        if (frame->controller) frame->controller->put_Bounds(rc);
    } else {
        LayoutTabs(frame);
    }
}

static std::wstring TabStripLabel(const std::shared_ptr<WindowState>& t) {
    std::wstring label = t->phase == WindowState::Phase::Creating ? L"Loading..." : t->title;
    if (label.empty()) label = TenantLabel(t->selectedTenant);
    if (label.size() > 32) { label.resize(31); label += L"\x2026"; }
    return label;
}

// Rebuild the strip from win->tabs (+ the "+" pseudo-tab) and select the active tab.
static void RefreshTabStrip(const std::shared_ptr<WindowState>& win) {
    if (!win || !win->tab_ctrl) return;
    TabCtrl_DeleteAllItems(win->tab_ctrl);
    int i = 0, activeIndex = -1;
    for (auto& t : win->tabs) {
        if (!t || t->phase == WindowState::Phase::Closing) continue;
        std::wstring label = TabStripLabel(t);
        TCITEMW item{}; item.mask = TCIF_TEXT | TCIF_PARAM;
        item.pszText = label.data(); item.lParam = static_cast<LPARAM>(t->tab_id);
        TabCtrl_InsertItem(win->tab_ctrl, i, &item);
        if (t->tab_id == win->active_tab) activeIndex = i;
        ++i;
    }
    wchar_t plus[] = L"  +  ";
    TCITEMW item{}; item.mask = TCIF_TEXT | TCIF_PARAM; item.pszText = plus; item.lParam = 0;
    TabCtrl_InsertItem(win->tab_ctrl, i, &item);
    if (activeIndex >= 0) TabCtrl_SetCurSel(win->tab_ctrl, activeIndex);
    // The strip's height depends on its items (it is ~0 with none), so re-lay out the strip and the
    // WebViews below it whenever the items change.
    LayoutTabs(win);
}

static void UpdateWindowTitleFromTab(const std::shared_ptr<WindowState>& win) {
    auto t = ActiveTab(win);
    if (t && t->sso && t->sso->external_committed()) {
        const auto host = t->sso->committed_host();
        const std::wstring title = L"Microsoft sign-in \x2013 " +
            std::wstring(host.begin(), host.end()) + L" \x2013 DeskRally";
        SetWindowTextW(win->hwnd, title.c_str());
        return;
    }
    std::wstring title = (t && !t->title.empty()) ? t->title : std::wstring(kWindowTitle);
    title.resize((std::min)(title.size(), size_t(160)));
    title += L" \x2013 " + TenantLabel(win->selectedTenant);
    SetWindowTextW(win->hwnd, title.c_str());
}

static void ApplyDocumentTitle(const std::shared_ptr<WindowState>& state, std::wstring title) {
    if (state->is_tab) {
        state->title = title;
        if (auto win = state->window.lock(); win && !win->closing) {
            RefreshTabStrip(win);
            if (win->active_tab == state->tab_id) UpdateWindowTitleFromTab(win);
        }
    } else if (!title.empty()) {
        title.resize((std::min)(title.size(), size_t(160)));
        title += L" \x2013 " + TenantLabel(state->selectedTenant);
        SetWindowTextW(state->hwnd, title.c_str());
    }
}

static void ActivateTab(const std::shared_ptr<WindowState>& win, uint64_t id) {
    auto target = FindTab(win, id);
    if (!target || target->phase == WindowState::Phase::Closing || win->closing) return;
    win->active_tab = id;
    const RECT content = TabContentRect(win);
    for (auto& t : win->tabs) {
        if (!t || !t->controller || t->phase != WindowState::Phase::Live) continue;
        const bool show = t->tab_id == id;
        if (show) t->controller->put_Bounds(content);
        t->controller->put_IsVisible(show ? TRUE : FALSE);
        if (show) t->controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
    }
    SyncFullscreen(win);
    RefreshTabStrip(win);
    UpdateWindowTitleFromTab(win);
}

static void RemoveTabHandlers(const std::shared_ptr<WindowState>& t) {
    if (t->webview) {
        t->webview->remove_NavigationStarting(t->tok_nav_starting);
        t->webview->remove_NewWindowRequested(t->tok_new_window);
        t->webview->remove_WindowCloseRequested(t->tok_window_close);
        t->webview->remove_PermissionRequested(t->tok_permission);
        t->webview->remove_DocumentTitleChanged(t->tok_title);
        if (!t->is_popup) {
            t->webview->remove_SourceChanged(t->tok_source_changed);
            t->webview->remove_NavigationCompleted(t->tok_sso_nav_completed);
        }
        {
            t->webview->remove_WebResourceRequested(t->tok_denied_request);
        }
        t->webview->remove_ProcessFailed(t->tok_process_failed);
        t->webview->remove_ContainsFullScreenElementChanged(t->tok_fullscreen);
    }
    if (t->controller) t->controller->remove_AcceleratorKeyPressed(t->tok_accel);
}

// Teardown in the designed order: (1) mark closing, (2) settle its outstanding permission and popup
// deferrals, (3) remove handlers, (4) close and release the controller. The caller removes it from the
// list. A tab still Creating has no controller yet: its creation callback sees Closing and closes the
// late controller itself.
static void TeardownTab(const std::shared_ptr<WindowState>& win, const std::shared_ptr<WindowState>& t) {
    if (!t || t->phase == WindowState::Phase::Closing) return;
    t->phase = WindowState::Phase::Closing;
    t->closing = true;
    SettleConsentsFor(t);
    if (win) {
        // Snapshot: denying a pending popup removes it from win->children. Call a COPY of the stored
        // closure, so clearing the member cannot destroy the closure while it runs.
        auto snapshot = win->children;
        for (auto& child : snapshot) {
            if (child && child->opener_tab_id == t->tab_id && child->popup_pending && child->deny_pending_popup) {
                auto deny = child->deny_pending_popup;
                child->deny_pending_popup = nullptr;
                deny();
            }
        }
    }
    RemoveTabHandlers(t);
    if (t->controller) {
        t->controller->Close();
        t->controller.Reset();
    }
    t->webview.Reset();
}

static void CloseTab(const std::shared_ptr<WindowState>& win, uint64_t id) {
    auto t = FindTab(win, id);
    if (!t || t->phase == WindowState::Phase::Closing) return;
    const bool wasActive = win->active_tab == id;
    TeardownTab(win, t);
    // Re-find after teardown (never trust an index across code that could re-enter).
    const long long closedIndex = TabIndex(win, id);
    if (closedIndex < 0) return;
    const size_t before = win->tabs.size();
    win->tabs.erase(win->tabs.begin() + closedIndex);
    if (win->tabs.empty()) {
        // Closing the last tab closes the window, as closing the window does today.
        PostMessageW(win->hwnd, WM_CLOSE, 0, 0);
        return;
    }
    if (wasActive) {
        const long long next = drtabs::replacement_after_close(static_cast<size_t>(closedIndex), before);
        if (next >= 0) { ActivateTab(win, win->tabs[static_cast<size_t>(next)]->tab_id); return; }
    }
    RefreshTabStrip(win);
}

static void CloseAllTabs(const std::shared_ptr<WindowState>& win) {
    auto snapshot = win->tabs;  // TeardownTab never touches the list
    for (auto& t : snapshot) TeardownTab(win, t);
    win->tabs.clear();
}

static void CreateTab(const std::shared_ptr<WindowState>& win, const std::wstring& url, bool first);

// Executed from the message loop (WM_APP_TAB_COMMAND, menu, strip), never inside a WebView2 callback.
static void ExecuteTabCommand(const std::shared_ptr<WindowState>& win, WPARAM cmd, LPARAM arg) {
    if (!win || win->closing || win->env_failed || g_helloPending) return;
    std::vector<uint64_t> ids;
    for (auto& t : win->tabs) if (t && t->phase != WindowState::Phase::Closing) ids.push_back(t->tab_id);
    long long cur = -1;
    for (size_t i = 0; i < ids.size(); ++i) if (ids[i] == win->active_tab) cur = (long long)i;
    switch (cmd) {
    case kTabNew:
        if (!drtabs::can_create(CountOpenTabs(win))) { MessageBeep(MB_ICONWARNING); return; }
        // The https console page; ConsoleUriFor is the deskrally-client:// LAUNCH uri (a new process).
        CreateTab(win, Utf8ToWide(drpolicy::console_url(win->selectedTenant)), false);
        return;
    case kTabCloseActive:
        CloseTab(win, win->active_tab);
        return;
    case kTabCloseId:
        CloseTab(win, static_cast<uint64_t>(arg));  // a removed id is a no-op
        return;
    case kTabNext:
    case kTabPrev:
        if (ids.empty() || cur < 0) return;
        ActivateTab(win, ids[drtabs::step(static_cast<size_t>(cur), ids.size(), cmd == kTabNext)]);
        return;
    case kTabSelect:
    case kTabLast: {
        drtabs::Decoded d; d.cmd = cmd == kTabLast ? drtabs::Cmd::Last : drtabs::Cmd::Select; d.index = static_cast<int>(arg);
        const long long idx = drtabs::select_index(d, ids.size());
        if (idx >= 0) ActivateTab(win, ids[static_cast<size_t>(idx)]);
        return;
    }
    default:
        return;
    }
}

// Map a decoded shortcut to a posted tab command. Returns true when the key was a tab command.
static bool PostTabShortcut(HWND hwnd, const drtabs::Decoded& d) {
    WPARAM cmd = 0; LPARAM arg = 0;
    switch (d.cmd) {
    case drtabs::Cmd::New:    cmd = kTabNew; break;
    case drtabs::Cmd::Close:  cmd = kTabCloseActive; break;
    case drtabs::Cmd::Next:   cmd = kTabNext; break;
    case drtabs::Cmd::Prev:   cmd = kTabPrev; break;
    case drtabs::Cmd::Select: cmd = kTabSelect; arg = d.index; break;
    case drtabs::Cmd::Last:   cmd = kTabLast; break;
    default: return false;
    }
    PostMessageW(hwnd, WM_APP_TAB_COMMAND, cmd, arg);
    return true;
}

static drtabs::KeyInput KeyModifiersNow(drtabs::KeyInput k) {
    k.ctrl  = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
    k.shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
    k.alt   = (GetKeyState(VK_MENU) & 0x8000) != 0;
    k.win   = (GetKeyState(VK_LWIN) & 0x8000) != 0 || (GetKeyState(VK_RWIN) & 0x8000) != 0;
    return k;
}

// Middle-click on a tab closes it (posted, by id).
static LRESULT CALLBACK TabStripSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR ref) {
    if (msg == WM_MBUTTONUP) {
        TCHITTESTINFO hit{}; hit.pt.x = GET_X_LPARAM(lp); hit.pt.y = GET_Y_LPARAM(lp);
        const int idx = TabCtrl_HitTest(h, &hit);
        if (idx >= 0) {
            TCITEMW item{}; item.mask = TCIF_PARAM;
            if (TabCtrl_GetItem(h, idx, &item) && item.lParam != 0)
                PostMessageW(reinterpret_cast<HWND>(ref), WM_APP_TAB_COMMAND, kTabCloseId, item.lParam);
        }
        return 0;
    }
    return DefSubclassProc(h, msg, wp, lp);
}

// ── Handler registration ───────────────────────────────────────────────────
static bool RegisterHandlers(std::shared_ptr<WindowState> state) {
    auto* wv = state->webview.Get();
    if (!wv) return false;
    ComPtr<ICoreWebView2Settings> settings;
    if (FAILED(wv->get_Settings(&settings)) || !settings) return false;
    if (FAILED(settings->put_AreDefaultContextMenusEnabled(FALSE)) ||
        FAILED(settings->put_AreDevToolsEnabled(FALSE)) ||
        FAILED(settings->put_IsStatusBarEnabled(FALSE)) ||
        FAILED(settings->put_AreHostObjectsAllowed(FALSE))) return false;
#ifndef SMOKE_TEST
    if (FAILED(settings->put_IsWebMessageEnabled(FALSE))) return false;
#endif

    // Marker controls launch UX only. Every window still uses normal server authentication.
    ComPtr<ICoreWebView2Settings2> settings2;
    if (FAILED(settings.As(&settings2)) || !settings2) return false;
    LPWSTR uaW = nullptr;
    if (FAILED(settings2->get_UserAgent(&uaW)) || !uaW) return false;
    std::wstring ua(uaW);
    CoTaskMemFree(uaW);
    if (ua.find(L"DeskRallyDesktop/") == std::wstring::npos)
        ua += L" DeskRallyDesktop/0.8.4";
    if (g_helloVerifiedAtStartup) ua += L" DeskRallyHello/1";
    ua += L" DeskRallySSO/1";
    // The clipboard answer is remembered for the run (g_consentAnswers), so the console may read the
    // clipboard on each press into the remote screen without a dialog per click.
    ua += L" DeskRallyClipAuto/1";
    if (FAILED(settings2->put_UserAgent(ua.c_str()))) return false;

    // DocumentTitleChanged – update title and append tenant label.
    HRESULT titleRegistration = wv->add_DocumentTitleChanged(
        Callback<ICoreWebView2DocumentTitleChangedEventHandler>(
            [state](ICoreWebView2* sender, IUnknown*) -> HRESULT {
                if (!StateUsable(state)) return S_OK;
                if (state->sso && state->sso->ignore_document_title()) return S_OK;
                LPWSTR text = nullptr;
                if (SUCCEEDED(sender->get_DocumentTitle(&text)) && text)
                    ApplyDocumentTitle(state, text);
                CoTaskMemFree(text);
                return S_OK;
            }).Get(), &state->tok_title);
    if (FAILED(titleRegistration)) return false;


    // NavigationStarting – enforce URL allow-list for the selected process tenant.
    HRESULT registration = wv->add_NavigationStarting(
        Callback<ICoreWebView2NavigationStartingEventHandler>(
            [state](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                if (!StateUsable(state)) { args->put_Cancel(TRUE); return S_OK; }
                ++state->navigation_generation;
                if (!state->is_popup && !state->sso) {
#ifdef SMOKE_TEST
                    state->sso = std::make_unique<drpolicy::SsoFlow>(state->selectedTenant,
                        g_ssoSmoke ? g_ssoSmokeWindowMs : 10 * 60 * 1000);
#else
                    state->sso = std::make_unique<drpolicy::SsoFlow>(state->selectedTenant);
#endif
                }
                LPWSTR uriW = nullptr;
                args->get_Uri(&uriW);
                std::wstring uriWstr(uriW ? uriW : L"");
                CoTaskMemFree(uriW);

                auto uriStr = WideToUtf8(uriWstr);

                if (uriStr == "about:blank") {
                    // Popup windows' initial about:blank navigation is expected and allowed;
                    // the main frame must never navigate to about:blank.
                    if (!state->is_popup) args->put_Cancel(TRUE);
                    return S_OK;
                }

                // deskrally-client:// navigation from a trusted main frame: cancel and spawn
                // a new process. Never navigate the WebView to this scheme.
                static constexpr std::string_view kClientScheme = "deskrally-client://";
                if (uriStr.size() >= kClientScheme.size() &&
                    std::string_view(uriStr).substr(0, kClientScheme.size()) == kClientScheme) {
                    args->put_Cancel(TRUE);
                    if (!state->is_popup && !state->closing) {
                        BOOL userInitiated = FALSE;
                        ComPtr<ICoreWebView2NavigationStartingEventArgs2> args2;
                        if (SUCCEEDED(args->QueryInterface(IID_PPV_ARGS(&args2))) && args2)
                            args2->get_IsUserInitiated(&userInitiated);
                        if (userInitiated) {
                            LPWSTR srcW = nullptr;
                            state->webview->get_Source(&srcW);
                            std::string src = WideToUtf8(srcW ? std::wstring(srcW) : std::wstring{});
                            CoTaskMemFree(srcW);
                            // Source must be trusted for this process's tenant.
                            if (drpolicy::check_navigation(src, state->selectedTenant) == drpolicy::NavResult::Allow) {
                                auto parsed = drpolicy::parse_client_uri(uriStr);
                                // URI tenant must match selected process tenant (legacy URI = Main).
                                if (parsed.valid && parsed.tenant == state->selectedTenant) {
                                    auto* uriCopy = new std::wstring(uriWstr);
                                    if (!PostMessageW(state->hwnd, WM_SPAWN_CLIENT, 0,
                                                      reinterpret_cast<LPARAM>(uriCopy)))
                                        delete uriCopy;
                                }
                            }
                        }
                    }
                    return S_OK;
                }

                // SSO changes main-frame navigation only. Permission and protocol-spawn
                // decisions must continue to use the tenant-only check_navigation.
                drpolicy::NavResult result = drpolicy::NavResult::Deny;
                if (state->is_popup) {
                    result = drpolicy::check_navigation(uriStr, state->selectedTenant);
                } else {
                    UINT64 id = 0;
                    BOOL redirected = FALSE;
                    if (SUCCEEDED(args->get_NavigationId(&id)) &&
                        SUCCEEDED(args->get_IsRedirected(&redirected))) {
                        result = state->sso->on_navigation_starting(
                            id, uriStr, redirected == TRUE, (int64_t)GetTickCount64());
                    }
                }
                {
                    const ULONGLONG nowTick = GetTickCount64();
                    auto& denied = state->denied_navs;
                    // Expired entries go; and ANY decision about this URI replaces an older one, so a
                    // later ALLOWED navigation to a previously denied URI is never answered with the
                    // backstop's 403 (Codex 0.8.1 review v1).
                    denied.erase(std::remove_if(denied.begin(), denied.end(),
                        [nowTick, &uriWstr](const std::pair<std::wstring, ULONGLONG>& d) {
                            return nowTick - d.second > 5000 || d.first == uriWstr; }),
                        denied.end());
                    if (result == drpolicy::NavResult::Deny) {
                        args->put_Cancel(TRUE);
                        if (denied.size() >= 16) denied.erase(denied.begin());
                        denied.emplace_back(uriWstr, nowTick);
                    }
                }
#ifdef SMOKE_TEST
                if (g_ssoSmoke)
                    SmokeLog("[sso-smoke] t=%llu NavigationStarting %s %s\n", (unsigned long long)GetTickCount64(),
                             result == drpolicy::NavResult::Deny ? "DENY" : "allow", uriStr.c_str());
#endif
                return S_OK;
            }).Get(), &state->tok_nav_starting);
    if (FAILED(registration)) return false;

    // Request-layer backstop for cancelled navigations (see WindowState::denied_navs). Only the EXACT
    // document request of a navigation this policy cancelled in the last 5 s is answered with a local
    // 403; every other request (iframes on Microsoft pages included) proceeds untouched.
    if (FAILED(wv->AddWebResourceRequestedFilter(L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT)))
        return false;
    {
        registration = wv->add_WebResourceRequested(
            Callback<ICoreWebView2WebResourceRequestedEventHandler>(
                [state](ICoreWebView2*, ICoreWebView2WebResourceRequestedEventArgs* args) -> HRESULT {
                    if (!StateUsable(state) || state->denied_navs.empty() || !g_env) return S_OK;
                    ComPtr<ICoreWebView2WebResourceRequest> request;
                    if (FAILED(args->get_Request(&request)) || !request) return S_OK;
                    LPWSTR raw = nullptr;
                    if (FAILED(request->get_Uri(&raw)) || !raw) { CoTaskMemFree(raw); return S_OK; }
                    const std::wstring uri(raw);
                    CoTaskMemFree(raw);
                    const ULONGLONG nowTick = GetTickCount64();
                    auto& denied = state->denied_navs;
                    // Not consumed on match: for its 5 s lifetime EVERY document request in this tab to
                    // the exact URI the policy just refused as a page is answered locally, so a
                    // same-URI iframe cannot use the entry up and let the cancelled request escape.
                    for (auto it = denied.begin(); it != denied.end(); ++it) {
                        if (it->first != uri || nowTick - it->second > 5000) continue;
                        ComPtr<ICoreWebView2WebResourceResponse> response;
                        if (SUCCEEDED(g_env->CreateWebResourceResponse(nullptr, 403, L"Forbidden",
                                L"Cache-Control: no-store\r\n", &response)) && response)
                            args->put_Response(response.Get());
#ifdef SMOKE_TEST
                        SmokeLog("[sso-smoke] blocked the request of a cancelled navigation: %ls\n", uri.c_str());
#endif
                        break;
                    }
                    return S_OK;
                }).Get(), &state->tok_denied_request);
        if (FAILED(registration)) return false;
    }

    if (!state->is_popup) {
        // A committed document reaches the SSO policy from TWO events. SourceChanged alone is not
        // enough: it does not fire when a navigation commits the SAME address again (reloading
        // /console after a timed-out flow), so the expired flow never closed and every retry was
        // refused until the app restarted (found by the --sso-smoke probe run, 10-18).
        const auto ssoCommitted = [](const std::shared_ptr<WindowState>& state, ICoreWebView2* sender) {
                    LPWSTR source = nullptr;
                    const HRESULT hr = sender->get_Source(&source);
                    if (FAILED(hr) || !source) {
                        CoTaskMemFree(source);
                        return;
                    }
                    const std::string uri = WideToUtf8(std::wstring(source));
                    CoTaskMemFree(source);
                    state->sso->on_commit(uri, (int64_t)GetTickCount64());
                    // A late external commit after expiry is recovered NOW (design v2.1), not on the
                    // next timer tick, which a modal message could postpone.
                    {
                        const auto actions = state->sso->on_tick((int64_t)GetTickCount64());
                        if (actions.stop_pending_external && state->webview) state->webview->Stop();
                        if (actions.navigate_to_tenant_console && state->webview) {
                            const auto url = state->sso->tenant_console_url();
                            const std::wstring wide(url.begin(), url.end());
                            state->webview->Navigate(wide.c_str());
                        }
                    }
                    if (state->sso->external_committed()) {
                        if (state->is_tab) {
                            ApplyDocumentTitle(state, L"Microsoft sign-in");
                        } else {
                            const auto host = state->sso->committed_host();
                            const std::wstring title = L"Microsoft sign-in \x2013 " +
                                std::wstring(host.begin(), host.end()) + L" \x2013 DeskRally";
                            SetWindowTextW(state->hwnd, title.c_str());
                        }
                    } else {
                        LPWSTR text = nullptr;
                        if (SUCCEEDED(sender->get_DocumentTitle(&text)) && text)
                            ApplyDocumentTitle(state, text);
                        CoTaskMemFree(text);
                    }
        };
        registration = wv->add_SourceChanged(
            Callback<ICoreWebView2SourceChangedEventHandler>(
                [state, ssoCommitted](ICoreWebView2* sender, ICoreWebView2SourceChangedEventArgs*) -> HRESULT {
                    if (!StateUsable(state) || !state->sso) return S_OK;
                    ssoCommitted(state, sender);
                    return S_OK;
                }).Get(), &state->tok_source_changed);
        if (FAILED(registration)) return false;

        registration = wv->add_NavigationCompleted(
            Callback<ICoreWebView2NavigationCompletedEventHandler>(
                [state, ssoCommitted](ICoreWebView2* sender, ICoreWebView2NavigationCompletedEventArgs* args) -> HRESULT {
                    if (!StateUsable(state) || !state->sso) return S_OK;
                    UINT64 id = 0;
                    BOOL success = FALSE;
                    if (SUCCEEDED(args->get_NavigationId(&id)) &&
                        SUCCEEDED(args->get_IsSuccess(&success))) {
                        state->sso->on_navigation_completed(id, success == TRUE);
                        // A successful navigation committed a document, even one at the same address.
                        if (success == TRUE && StateUsable(state) && state->sso) ssoCommitted(state, sender);
                    }
                    return S_OK;
                }).Get(), &state->tok_sso_nav_completed);
        if (FAILED(registration)) return false;
    }

    // NewWindowRequested – handle popup window.open
    registration = wv->add_NewWindowRequested(
        Callback<ICoreWebView2NewWindowRequestedEventHandler>(
            [state](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
                // Nested popups are disallowed; closing parent also blocks.
                if (!StateUsable(state) || state->is_popup) {
                    args->put_Handled(TRUE);
                    return S_OK;
                }

                // Verify the source frame is trusted for this process's tenant.
                ComPtr<ICoreWebView2NewWindowRequestedEventArgs3> args3;
                bool frameTrusted = false;
                if (SUCCEEDED(args->QueryInterface(IID_PPV_ARGS(&args3))) && args3) {
                    ComPtr<ICoreWebView2FrameInfo> fi;
                    if (SUCCEEDED(args3->get_OriginalSourceFrameInfo(&fi)) && fi) {
                        LPWSTR srcW = nullptr;
                        fi->get_Source(&srcW);
                        std::string frameSrc = WideToUtf8(srcW ? std::wstring(srcW) : std::wstring{});
                        CoTaskMemFree(srcW);
                        frameTrusted = drpolicy::check_navigation(frameSrc, state->selectedTenant) == drpolicy::NavResult::Allow;
                    }
                }
                if (!frameTrusted) {
                    args->put_Handled(TRUE);
                    return S_OK;
                }

                LPWSTR uriW = nullptr;
                args->get_Uri(&uriW);
                std::wstring uri(uriW ? uriW : L"");
                CoTaskMemFree(uriW);

                BOOL hasGesture = FALSE;
                args->get_IsUserInitiated(&hasGesture);

                if (drpolicy::check_popup(WideToUtf8(uri), hasGesture == TRUE)
                        == drpolicy::PopupResult::Deny) {
                    args->put_Handled(TRUE);
                    return S_OK;
                }

                // Popups are owned by the MAIN window, not the opener tab (they outlive it); the opener
                // is recorded so a still-pending request can be denied if that tab closes first.
                if (state->is_tab) {
                    auto win = state->window.lock();
                    if (!win || win->closing) { args->put_Handled(TRUE); return S_OK; }
                    CreateChildPopupWindow(win, args, state->tab_id);
                } else {
                    CreateChildPopupWindow(state, args, 0);
                }
                return S_OK;
            }).Get(), &state->tok_new_window);
    if (FAILED(registration)) return false;

    // WindowCloseRequested – script called window.close() on a popup
    registration = wv->add_WindowCloseRequested(
        Callback<ICoreWebView2WindowCloseRequestedEventHandler>(
            [state](ICoreWebView2*, IUnknown*) -> HRESULT {
                if (!StateUsable(state)) return S_OK;
                if (state->is_tab)  // window.close() in a tab closes that tab, posted out of the callback
                    PostMessageW(state->hwnd, WM_APP_TAB_COMMAND, kTabCloseId, static_cast<LPARAM>(state->tab_id));
                else
                    PostMessageW(state->hwnd, WM_CLOSE, 0, 0);
                return S_OK;
            }).Get(), &state->tok_window_close);
    if (FAILED(registration)) return false;

    // PermissionRequested – deny all except clipboard-read, which requires
    // verified user gesture, trusted URI for the selected tenant, and explicit user consent.
    // Never persist permission to profile.
    registration = wv->add_PermissionRequested(
        Callback<ICoreWebView2PermissionRequestedEventHandler>(
            [state](ICoreWebView2*, ICoreWebView2PermissionRequestedEventArgs* rawArgs) -> HRESULT {
                if (!StateUsable(state)) {
                    rawArgs->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
                    return S_OK;
                }

                COREWEBVIEW2_PERMISSION_KIND kind{};
                rawArgs->get_PermissionKind(&kind);

                if (kind != COREWEBVIEW2_PERMISSION_KIND_CLIPBOARD_READ) {
                    rawArgs->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
                    return S_OK;
                }

                // Verify URI is the trusted origin for this process's tenant.
                LPWSTR uriW = nullptr;
                rawArgs->get_Uri(&uriW);
                std::wstring uriWstr(uriW ? uriW : L"");
                CoTaskMemFree(uriW);
                bool uriOk = (drpolicy::check_navigation(WideToUtf8(uriWstr), state->selectedTenant)
                              == drpolicy::NavResult::Allow);

                // Verify actual user gesture and disable profile persistence.
                bool isUserInitiated = false;
                ComPtr<ICoreWebView2PermissionRequestedEventArgs3> args3;
                if (SUCCEEDED(rawArgs->QueryInterface(IID_PPV_ARGS(&args3))) && args3) {
                    BOOL uig = FALSE;
                    rawArgs->get_IsUserInitiated(&uig);
                    isUserInitiated = (uig == TRUE);
                    // Prevent saving the decision to the WebView2 profile.
                    if (FAILED(args3->put_SavesInProfile(FALSE))) isUserInitiated = false;
                }

#ifdef SMOKE_TEST
                // Exercise the real permission event but NEVER read the operator's clipboard.
                rawArgs->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
                SmokeLog("[smoke] clipboard origin=%ls gesture=%d\n", uriWstr.c_str(), (int)isUserInitiated);
                SmokeHandleMessage(uriOk && isUserInitiated
                    ? L"{\"test\":\"native_clipboard\",\"result\":\"PASS\"}"
                    : L"{\"test\":\"native_clipboard\",\"result\":\"FAIL\"}", g_mainState->hwnd);
                if (auto opener = ActiveTab(g_mainState); opener && opener->webview)
                    opener->webview->ExecuteScript(L"window.__clipTestDone=true", nullptr);
                return S_OK;
#else
                if (!uriOk || !isUserInitiated) {
                    rawArgs->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
                    return S_OK;
                }

                // Take a deferral so the handler can return before the modal dialog runs.
                // This avoids reentering WebView2 message processing during MessageBoxW.
                ComPtr<ICoreWebView2Deferral> deferral;
                if (FAILED(rawArgs->GetDeferral(&deferral)) || !deferral) {
                    rawArgs->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
                    return S_OK;
                }

                auto req = std::make_shared<ClipboardConsentCtx>();
                req->state = state;
                req->args = rawArgs;
                req->deferral = deferral;
                req->generation = state->navigation_generation;
                req->origin = Utf8ToWide("https://" + drpolicy::tenant_host(state->selectedTenant));
                g_consentQueue.push_back(req);
                // The dialog runs from the main window's message loop, never inside this callback.
                if (!g_mainState || !PostMessageW(g_mainState->hwnd, WM_CLIPBOARD_CONSENT, 0, 0))
                    SettleConsent(req, false);
                return S_OK;
#endif
            }).Get(), &state->tok_permission);
    if (FAILED(registration)) return false;

    // ContainsFullScreenElementChanged: the page entered or left full screen (the viewer's button, Esc,
    // the page exiting). The window follows the WebView it shows (SyncFullscreen).
    registration = wv->add_ContainsFullScreenElementChanged(
        Callback<ICoreWebView2ContainsFullScreenElementChangedEventHandler>(
            [state](ICoreWebView2*, IUnknown*) -> HRESULT {
                if (!StateUsable(state)) return S_OK;
                SyncFullscreen(state->is_tab ? state->window.lock() : state);
                return S_OK;
            }).Get(), &state->tok_fullscreen);
    if (FAILED(registration)) return false;

    // ProcessFailed (tabs): a renderer that exited or hung affects only the WebViews it served; the
    // browser process exiting takes every tab with it. Handled from the message loop.
    if (state->is_tab) {
        registration = wv->add_ProcessFailed(
            Callback<ICoreWebView2ProcessFailedEventHandler>(
                [state](ICoreWebView2*, ICoreWebView2ProcessFailedEventArgs* args) -> HRESULT {
                    // Not StateUsable: a browser-process exit must be reported even mid-teardown races.
                    if (state->closing) return S_OK;
                    COREWEBVIEW2_PROCESS_FAILED_KIND kind{};
                    args->get_ProcessFailedKind(&kind);
                    if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED)
                        PostMessageW(state->hwnd, WM_APP_BROWSER_DIED, 0, 0);
                    else if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED ||
                             kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE)
                        PostMessageW(state->hwnd, WM_APP_TAB_FAILED, static_cast<WPARAM>(state->tab_id),
                            kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED ? 1 : 2);
                    return S_OK;
                }).Get(), &state->tok_process_failed);
    }
    return SUCCEEDED(registration);
}

// ── Child popup window creation ────────────────────────────────────────────
static void CreateChildPopupWindow(
        std::shared_ptr<WindowState> parent,
        ComPtr<ICoreWebView2NewWindowRequestedEventArgs> args,
        uint64_t openerTabId) {

    auto childState = std::make_shared<WindowState>();
    childState->is_popup       = true;
    childState->parent         = parent;
    childState->opener_tab_id  = openerTabId;
    childState->selectedTenant = parent->selectedTenant; // inherit process tenant
#ifdef SMOKE_TEST
    childState->smoke_close_pending = g_smokeClosePending;
    g_smokeClosePending = false;
#endif

    HWND hwnd = CreatePopupWindow();
    if (!hwnd) { args->put_Handled(TRUE); return; }
    childState->hwnd = hwnd;

    // Set initial title with tenant label; DocumentTitleChanged will update it later.
    SetWindowTextW(hwnd, (std::wstring(kWindowTitle) + L" \x2013 " +
                          TenantLabel(childState->selectedTenant)).c_str());

    ComPtr<ICoreWebView2Deferral> deferral;
    if (FAILED(args->GetDeferral(&deferral)) || !deferral) {
        DestroyWindow(hwnd);
        args->put_Handled(TRUE);
        return;
    }

    // Register child in parent's list and set GWLP_USERDATA BEFORE starting async
    // controller creation, so closing parent during init can find and mark this child.
    parent->children.push_back(childState);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA,
        reinterpret_cast<LONG_PTR>(new std::shared_ptr<WindowState>(childState)));

    // Helper to remove child from parent's list and complete the deferral as denied. Idempotent: the
    // deferral completes at most once (popup_pending), whether the opener tab's teardown or the
    // controller-creation callback gets here first.
    childState->popup_pending = true;
    // Captures are WEAK for the two window states: this closure is also stored on the child
    // (deny_pending_popup), and a strong capture would form a child -> closure -> child/parent cycle.
    // `settled` is shared by every copy of this closure and by the success path below, so the
    // deferral completes EXACTLY once whichever path gets there first.
    auto settled = std::make_shared<bool>(false);
    auto completeAndDeny = [weakChild = std::weak_ptr<WindowState>(childState),
                            weakParent = std::weak_ptr<WindowState>(parent), args, deferral, settled]() mutable {
        auto childState = weakChild.lock();
        auto parent = weakParent.lock();
        const bool settle = !*settled;
        *settled = true;
        if (!childState) {
            if (settle) { args->put_Handled(TRUE); deferral->Complete(); }
            return;
        }
        childState->popup_pending = false;
        childState->closing = true;
        if (childState->controller) childState->controller->Close();
        childState->controller.Reset();
        childState->webview.Reset();
        if (IsWindow(childState->hwnd)) DestroyWindow(childState->hwnd);
        if (parent && !parent->closing) {
            auto& ch = parent->children;
            ch.erase(std::remove(ch.begin(), ch.end(), childState), ch.end());
        }
        if (settle) {
            args->put_Handled(TRUE);
            deferral->Complete();
        }
    };
    childState->deny_pending_popup = completeAndDeny;

#ifdef SMOKE_TEST
    auto finishPendingTest = [childState, parent]() {
        if (childState->smoke_close_pending && childState->smoke_pending_rejected &&
            !IsWindow(childState->hwnd) && !childState->smoke_pending_reported) {
            childState->smoke_pending_reported = true;
            SmokeHandleMessage(L"{\"test\":\"pending_close\",\"result\":\"PASS\"}", parent->hwnd);
        }
    };
#endif

    HRESULT hr = g_env->CreateCoreWebView2Controller(hwnd,
        Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
            [childState, parent, completeAndDeny, deferral, args, settled
#ifdef SMOKE_TEST
             , finishPendingTest
#endif
            ]
            (HRESULT hr2, ICoreWebView2Controller* ctrl) mutable -> HRESULT {
                if (FAILED(hr2) || !ctrl) {
#ifdef SMOKE_TEST
                    // DestroyWindow may synchronously invoke this callback before
                    // WM_NCDESTROY. Assert cancellation now and destruction later.
                    childState->smoke_pending_rejected = childState->closing;
#endif
                    completeAndDeny();
#ifdef SMOKE_TEST
                    finishPendingTest();
#endif
                    return S_OK;
                }
                // Parent or child may have closed during async controller creation.
                if (childState->closing || parent->closing || !IsWindow(childState->hwnd)) {
                    ctrl->Close();
                    completeAndDeny();
#ifdef SMOKE_TEST
                    childState->smoke_pending_rejected = true;
                    finishPendingTest();
#endif
                    return S_OK;
                }

                childState->controller = ctrl;
                HRESULT hrGCV = ctrl->get_CoreWebView2(
                    childState->webview.ReleaseAndGetAddressOf());
                if (FAILED(hrGCV) || !childState->webview) {
                    ctrl->Close();
                    childState->controller.Reset();
                    completeAndDeny();
                    return S_OK;
                }

                // Register event handlers BEFORE completing the deferral so the
                // new window is fully guarded before the browser assigns it.
                if (!RegisterHandlers(childState)) { completeAndDeny(); return S_OK; }

                // Controller visibility is independent of the native parent window.
                // A loaded DOM alone does not mean WebView2 is painting its surface.
                RECT rc; GetClientRect(childState->hwnd, &rc);
                if (FAILED(ctrl->put_Bounds(rc)) || FAILED(ctrl->put_IsVisible(TRUE))) {
                    completeAndDeny();
                    return S_OK;
                }
#ifdef SMOKE_TEST
                SmokeCheckSurface(childState);
#endif

                if (FAILED(args->put_NewWindow(childState->webview.Get())) || FAILED(args->put_Handled(TRUE))) {
                    completeAndDeny();
                    return S_OK;
                }
                if (*settled) return S_OK;  // already denied (opener tab closed meanwhile)
                *settled = true;
                childState->popup_pending = false;
                childState->deny_pending_popup = nullptr;  // settled; drop the captured args/deferral
                deferral->Complete();

#ifndef SMOKE_TEST
                ShowWindow(childState->hwnd, SW_SHOWMAXIMIZED);
                UpdateWindow(childState->hwnd);
#endif
                return S_OK;
            }).Get());

    if (FAILED(hr)) {
        completeAndDeny();
    }
#ifdef SMOKE_TEST
    else if (childState->smoke_close_pending) { CloseAllChildren(parent); finishPendingTest(); }
#endif
}

// ── Tab creation (replaces the single main-window WebView) ─────────────────
// Creates a tab: registers it as Creating (counted by the cap), asks for a controller parented to the
// main window, and on completion re-validates (window live, tab still Creating) before using it. A
// controller that arrives for a tab closed meanwhile, or a closing window, is closed at once.
// `first` = the window's initial tab: failure there is fatal (as the single WebView's was); a later
// tab's failure only removes that tab.
static void CreateTab(const std::shared_ptr<WindowState>& win, const std::wstring& url, bool first) {
    if (!win || win->closing || !g_env) return;
    if (!drtabs::can_create(CountOpenTabs(win))) { MessageBeep(MB_ICONWARNING); return; }
    auto tab = std::make_shared<WindowState>();
    tab->is_tab = true;
    tab->tab_id = win->next_tab_id++;
    tab->phase = WindowState::Phase::Creating;
    tab->hwnd = win->hwnd;
    tab->window = win;
    tab->selectedTenant = win->selectedTenant;
    tab->first_tab = first;
    win->tabs.push_back(tab);
    const uint64_t id = tab->tab_id;
    // Activate now: the previous tab's page is hidden at once, so the strip and the window never show
    // one tab while displaying another. The new page appears when its controller is ready.
    ActivateTab(win, id);
    std::weak_ptr<WindowState> weakWin = win;

    // Failures are POSTED to the window procedure (by tab id) and handled there, never inside the
    // controller-creation callback.
    auto fail = [weakWin, id](TabFailure why) {
        if (auto w = weakWin.lock(); w && w->hwnd && IsWindow(w->hwnd))
            PostMessageW(w->hwnd, WM_APP_TAB_CREATE_FAILED, static_cast<WPARAM>(id), why);
    };

    HRESULT hr = g_env->CreateCoreWebView2Controller(win->hwnd,
        Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
            [weakWin, id, url, first, fail](HRESULT hr, ICoreWebView2Controller* ctrl) -> HRESULT {
                auto w = weakWin.lock();
                auto t = FindTab(w, id);
                // Closed while the controller was being created: close the late controller.
                if (!w || w->closing || !t || t->phase != WindowState::Phase::Creating ||
                    !w->hwnd || !IsWindow(w->hwnd)) {
                    // Only close the late controller: the tab's removal already decided what happens
                    // next (a removed first tab is no reason to quit while other tabs remain).
                    if (ctrl) ctrl->Close();
#ifdef SMOKE_TEST
                    ++g_smokeLateControllersClosed;
#endif
                    return S_OK;
                }
                if (FAILED(hr) || !ctrl) { fail(kFailController); return S_OK; }
                t->controller = ctrl;
                if (FAILED(ctrl->get_CoreWebView2(t->webview.ReleaseAndGetAddressOf())) || !t->webview) {
                    ctrl->Close();
                    t->controller.Reset();
                    fail(kFailInterface);
                    return S_OK;
                }
                {
                    ComPtr<ICoreWebView2Settings> settings;
                    if (SUCCEEDED(t->webview->get_Settings(&settings)) && settings)
                        settings->put_IsZoomControlEnabled(FALSE);
                }
                if (!RegisterHandlers(t)) {
                    RemoveTabHandlers(t);  // whatever registered before the failure
                    ctrl->Close();
                    t->controller.Reset();
                    t->webview.Reset();
                    fail(kFailSecurity);
                    return S_OK;
                }
                // Tab shortcuts while the page has focus: exact matching (drtabs::decode), Handled
                // only for a recognised command, and the command itself posted to the message loop.
                const HRESULT accelHr = ctrl->add_AcceleratorKeyPressed(
                    Callback<ICoreWebView2AcceleratorKeyPressedEventHandler>(
                        [weakWin, id](ICoreWebView2Controller*, ICoreWebView2AcceleratorKeyPressedEventArgs* a) -> HRESULT {
                            auto w2 = weakWin.lock();
                            auto t2 = FindTab(w2, id);
                            if (!w2 || w2->closing || !t2 || t2->phase != WindowState::Phase::Live) return S_OK;
                            COREWEBVIEW2_KEY_EVENT_KIND kind{};
                            UINT vk = 0;
                            COREWEBVIEW2_PHYSICAL_KEY_STATUS status{};
                            if (FAILED(a->get_KeyEventKind(&kind)) || FAILED(a->get_VirtualKey(&vk)) ||
                                FAILED(a->get_PhysicalKeyStatus(&status))) return S_OK;
                            drtabs::KeyInput k;
                            k.key_down = kind == COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN;
                            k.system_key = kind == COREWEBVIEW2_KEY_EVENT_KIND_SYSTEM_KEY_DOWN;
                            k.repeat = status.WasKeyDown == TRUE;
                            k.vk = vk;
                            k = KeyModifiersNow(k);
                            if (PostTabShortcut(w2->hwnd, drtabs::decode(k))) a->put_Handled(TRUE);
                            return S_OK;
                        }).Get(), &t->tok_accel);
                if (FAILED(accelHr)) {
                    RemoveTabHandlers(t);
                    ctrl->Close();
                    t->controller.Reset();
                    t->webview.Reset();
                    fail(kFailSecurity);
                    return S_OK;
                }

                t->phase = WindowState::Phase::Live;
                const RECT content = TabContentRect(w);
                const bool active = w->active_tab == id;
                if (FAILED(ctrl->put_Bounds(content)) || FAILED(ctrl->put_IsVisible(active ? TRUE : FALSE))) {
                    fail(kFailDisplay);
                    return S_OK;
                }
                if (active) ActivateTab(w, id); else RefreshTabStrip(w);

#ifdef SMOKE_TEST
                if (first) {
                    SmokeLog("[smoke] WebView2 controller created OK\n");
                    SmokeCheckSurface(t);
                }
                if (g_ssoSmoke) {
                    if (!SsoSmokeInstall(t, w->hwnd)) {
                        SmokeLog("[sso-smoke] FAIL setup resource interception\n");
                        SmokeLog("[sso-smoke] DONE pass=0 fail=1\n");
                        g_smokeResult = 1;
                        PostMessageW(w->hwnd, WM_CLOSE, 0, 0);
                        return S_OK;
                    }
                    if (first && !SetTimer(w->hwnd, kSsoSmokeTimerId, 50, nullptr)) {
                        SmokeLog("[sso-smoke] FAIL setup runner timer\n");
                        SmokeLog("[sso-smoke] DONE pass=0 fail=1\n");
                        PostMessageW(w->hwnd, WM_CLOSE, 0, 0);
                    }
                    return S_OK;
                }
                ComPtr<ICoreWebView2_3> wv3;
                if (SUCCEEDED(t->webview->QueryInterface(IID_PPV_ARGS(&wv3))) && wv3) {
                    HRESULT hrV = wv3->SetVirtualHostNameToFolderMapping(
                        kSmokeVirtualHost, (g_smokeDirectory + L"\\test-fixtures").c_str(),
                        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_ALLOW);
                    SmokeLog("[smoke] VirtualHostMapping hr=0x%08x\n", (unsigned)hrV);
                }
                if (first) {
                    t->webview->add_WebMessageReceived(
                        Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                            [weakWin](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* wma) -> HRESULT {
                                LPWSTR msgW = nullptr;
                                wma->TryGetWebMessageAsString(&msgW);
                                std::wstring msg(msgW ? msgW : L"");
                                CoTaskMemFree(msgW);
                                if (auto w3 = weakWin.lock()) SmokeHandleMessage(msg, w3->hwnd);
                                return S_OK;
                            }).Get(), &t->tok_web_msg);
                    t->webview->add_NavigationCompleted(
                        Callback<ICoreWebView2NavigationCompletedEventHandler>(
                            [weakWin](ICoreWebView2* wv, ICoreWebView2NavigationCompletedEventArgs* nca) -> HRESULT {
                                auto w3 = weakWin.lock();
                                if (!w3 || w3->closing) return S_OK;
                                BOOL success = FALSE;
                                nca->get_IsSuccess(&success);
                                SmokeLog("[smoke] NavigationCompleted success=%d\n", (int)success);
                                if (!success) {
                                    SmokeLog("[smoke] FAIL navigation to fixture failed\n");
                                    PostMessageW(w3->hwnd, WM_CLOSE, 0, 0);
                                    return S_OK;
                                }
                                wv->CallDevToolsProtocolMethod(
                                    L"Runtime.evaluate",
                                    LR"json({"expression":"document.getElementById('b').click()","userGesture":true})json",
                                    Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
                                        [](HRESULT result, LPCWSTR response) -> HRESULT {
                                            SmokeLog("[smoke] gesture dispatch hr=0x%08x response=%ls\n",
                                                     (unsigned)result, response ? response : L"");
                                            return S_OK;
                                        }).Get());
                                return S_OK;
                            }).Get(), &t->tok_nav_completed);
                    t->webview->Navigate(kSmokeTestUrl);
                    SetTimer(w->hwnd, 2, kSmokeTimeoutMs, nullptr);
                } else {
                    t->webview->Navigate(url.c_str());
                }
#else
                t->webview->Navigate(url.c_str());
                if (first) {
                    SetTimer(w->hwnd, kSignInTimerId, kSignInPollMs, nullptr);
                    ShowWindow(w->hwnd, SW_SHOWMAXIMIZED);
                    UpdateWindow(w->hwnd);
                }
#endif
                return S_OK;
            }).Get());

    if (FAILED(hr)) fail(kFailController);
}


#ifdef SMOKE_TEST
// ── Fake WebView2 event args for the lifetime tests: they COUNT completions and record the decided
// state, so "exactly once" and "denied" are asserted, not assumed.
#include <wrl/implements.h>
struct SmokeCounters {
    int completed = 0;
    COREWEBVIEW2_PERMISSION_STATE state = COREWEBVIEW2_PERMISSION_STATE_DEFAULT;
    BOOL handled = FALSE;
    bool newWindowSet = false;
    std::function<void()> onComplete;  // runs INSIDE Complete(), like a re-entrant WebView2 callback
};
class FakeDeferral : public Microsoft::WRL::RuntimeClass<
        Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, ICoreWebView2Deferral> {
public:
    explicit FakeDeferral(std::shared_ptr<SmokeCounters> c) : c_(std::move(c)) {}
    HRESULT STDMETHODCALLTYPE Complete() override {
        ++c_->completed;
        if (auto f = std::move(c_->onComplete)) f();
        return S_OK;
    }
private:
    std::shared_ptr<SmokeCounters> c_;
};
class FakePermissionArgs : public Microsoft::WRL::RuntimeClass<
        Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, ICoreWebView2PermissionRequestedEventArgs> {
public:
    explicit FakePermissionArgs(std::shared_ptr<SmokeCounters> c) : c_(std::move(c)) {}
    HRESULT STDMETHODCALLTYPE get_Uri(LPWSTR* u) override { *u = nullptr; return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_PermissionKind(COREWEBVIEW2_PERMISSION_KIND* k) override { *k = COREWEBVIEW2_PERMISSION_KIND_CLIPBOARD_READ; return S_OK; }
    HRESULT STDMETHODCALLTYPE get_IsUserInitiated(BOOL* b) override { *b = TRUE; return S_OK; }
    HRESULT STDMETHODCALLTYPE get_State(COREWEBVIEW2_PERMISSION_STATE* st) override { *st = c_->state; return S_OK; }
    HRESULT STDMETHODCALLTYPE put_State(COREWEBVIEW2_PERMISSION_STATE st) override { c_->state = st; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetDeferral(ICoreWebView2Deferral** d) override { *d = nullptr; return E_NOTIMPL; }
private:
    std::shared_ptr<SmokeCounters> c_;
};
class FakeNewWindowArgs : public Microsoft::WRL::RuntimeClass<
        Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, ICoreWebView2NewWindowRequestedEventArgs> {
public:
    explicit FakeNewWindowArgs(std::shared_ptr<SmokeCounters> c) : c_(std::move(c)) {}
    HRESULT STDMETHODCALLTYPE get_Uri(LPWSTR* u) override { *u = nullptr; return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_NewWindow(ICoreWebView2*) override { c_->newWindowSet = true; return S_OK; }
    HRESULT STDMETHODCALLTYPE get_NewWindow(ICoreWebView2** w) override { *w = nullptr; return S_OK; }
    HRESULT STDMETHODCALLTYPE put_Handled(BOOL h) override { c_->handled = h; return S_OK; }
    HRESULT STDMETHODCALLTYPE get_Handled(BOOL* h) override { *h = c_->handled; return S_OK; }
    HRESULT STDMETHODCALLTYPE get_IsUserInitiated(BOOL* b) override { *b = TRUE; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetDeferral(ICoreWebView2Deferral** d) override {
        auto f = Microsoft::WRL::Make<FakeDeferral>(c_);
        return f ? f.CopyTo(d) : E_OUTOFMEMORY;
    }
    HRESULT STDMETHODCALLTYPE get_WindowFeatures(ICoreWebView2WindowFeatures** v) override { *v = nullptr; return E_NOTIMPL; }
private:
    std::shared_ptr<SmokeCounters> c_;
};
static std::shared_ptr<ClipboardConsentCtx> SmokeMakeConsent(const std::shared_ptr<WindowState>& owner,
                                                           const std::shared_ptr<SmokeCounters>& c) {
    auto req = std::make_shared<ClipboardConsentCtx>();
    req->state = owner;
    req->args = Microsoft::WRL::Make<FakePermissionArgs>(c);
    req->deferral = Microsoft::WRL::Make<FakeDeferral>(c);
    req->generation = owner->navigation_generation;
    req->origin = L"https://smoke";
    return req;
}
#endif

#ifdef SMOKE_TEST
// Tab smoke sequence (docs-tabs-design.md, "Lifetime races"), one step per 200 ms tick:
//  1 create two tabs                        -> tabs_create: 3 live, the newest active
//  2 close the middle tab (posted command)  -> tabs_close_middle: 2 left, the closed id gone
//  3 create a tab and close it while its controller is still being created
//                                           -> tabs_close_during_creation: the late controller is closed
//  4 post a close for that removed id       -> tabs_removed_id_noop: nothing else changes
static void SmokeReport(const char* test, bool ok) {
    std::wstring m = L"{\"test\":\"" + Utf8ToWide(test) + L"\",\"result\":\"" + (ok ? L"PASS" : L"FAIL") + L"\"}";
    SmokeHandleMessage(m, g_mainState->hwnd);
}
static size_t SmokeLiveTabs() {
    size_t n = 0;
    for (auto& t : g_mainState->tabs) if (t && t->phase == WindowState::Phase::Live) ++n;
    return n;
}
static int g_smokeTicks = 0;
static RECT g_smokeFsBeforeRect{};
static LONG_PTR g_smokeFsBeforeStyle = 0;
static bool g_smokeFsBeforeZoomed = false;
static HMENU g_smokeFsBeforeMenu = nullptr;
// Runs `expr` in the tab's page as a user gesture (requestFullscreen needs transient activation).
static void SmokeEval(const std::shared_ptr<WindowState>& t, const std::wstring& expr) {
    if (!t || !t->webview) return;
    const std::wstring params = L"{\"expression\":\"" + expr + L"\",\"userGesture\":true}";
    t->webview->CallDevToolsProtocolMethod(L"Runtime.evaluate", params.c_str(),
        Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
            [](HRESULT, LPCWSTR) -> HRESULT { return S_OK; }).Get());
}
// Full screen as the USER sees it: no frame, the window exactly on its monitor, the strip hidden,
// and the shown WebView filling the whole window.
static bool SmokeFsCoversMonitor(const std::shared_ptr<WindowState>& win) {
    MONITORINFO mi{sizeof(mi)};
    if (!GetMonitorInfoW(MonitorFromWindow(win->hwnd, MONITOR_DEFAULTTONEAREST), &mi)) return false;
    RECT wr{}, cr{}, bounds{};
    GetWindowRect(win->hwnd, &wr);
    GetClientRect(win->hwnd, &cr);
    auto t = ActiveTab(win);
    if (!t || !t->controller || FAILED(t->controller->get_Bounds(&bounds))) return false;
    const LONG_PTR style = GetWindowLongPtrW(win->hwnd, GWL_STYLE);
    SmokeLog("[smoke] fs window=(%ld,%ld,%ld,%ld) monitor=(%ld,%ld,%ld,%ld) webview=(%ld,%ld,%ld,%ld) style=0x%llx\n",
        wr.left, wr.top, wr.right, wr.bottom, mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right,
        mi.rcMonitor.bottom, bounds.left, bounds.top, bounds.right, bounds.bottom, (unsigned long long)style);
    return (style & (WS_CAPTION | WS_THICKFRAME)) == 0 && EqualRect(&wr, &mi.rcMonitor) &&
        !IsWindowVisible(win->tab_ctrl) && EqualRect(&bounds, &cr) &&
        cr.right == mi.rcMonitor.right - mi.rcMonitor.left && cr.bottom == mi.rcMonitor.bottom - mi.rcMonitor.top;
}
// Back to the window it was before full screen: same style, maximized state and rect; the strip
// shown and the WebView below it.
static bool SmokeFsRestored(const std::shared_ptr<WindowState>& win) {
    RECT wr{}, bounds{};
    GetWindowRect(win->hwnd, &wr);
    auto t = ActiveTab(win);
    if (!t || !t->controller || FAILED(t->controller->get_Bounds(&bounds))) return false;
    const RECT content = TabContentRect(win);
    const LONG_PTR style = GetWindowLongPtrW(win->hwnd, GWL_STYLE);
    SmokeLog("[smoke] restored window=(%ld,%ld,%ld,%ld) before=(%ld,%ld,%ld,%ld) zoomed=%d/%d style=0x%llx/0x%llx\n",
        wr.left, wr.top, wr.right, wr.bottom, g_smokeFsBeforeRect.left, g_smokeFsBeforeRect.top,
        g_smokeFsBeforeRect.right, g_smokeFsBeforeRect.bottom, (int)(IsZoomed(win->hwnd) != FALSE),
        (int)g_smokeFsBeforeZoomed, (unsigned long long)style, (unsigned long long)g_smokeFsBeforeStyle);
    SmokeLog("[smoke] restored menu=%d before=%d\n", (int)(GetMenu(win->hwnd) != nullptr), (int)(g_smokeFsBeforeMenu != nullptr));
    return style == g_smokeFsBeforeStyle && (IsZoomed(win->hwnd) != FALSE) == g_smokeFsBeforeZoomed &&
        GetMenu(win->hwnd) == g_smokeFsBeforeMenu &&
        EqualRect(&wr, &g_smokeFsBeforeRect) && IsWindowVisible(win->tab_ctrl) &&
        content.top > 0 && EqualRect(&bounds, &content);
}
static void SmokeTabTick() {
    auto win = g_mainState;
    if (!win || win->closing) return;
    ++g_smokeTicks;
    switch (g_smokeTabStep) {
    case 1:
        CreateTab(win, kSmokeTestUrl, false);
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTabMark = win->next_tab_id - 1;  // the newest
        g_smokeTicks = 0;
        g_smokeTabStep = 2;
        return;
    case 2:
        if (SmokeLiveTabs() < 3 && g_smokeTicks < 40) return;
        SmokeReport("tabs_create", SmokeLiveTabs() == 3 && win->tabs.size() == 3 && win->active_tab == g_smokeTabMark);
        g_smokeTabMark = win->tabs.size() >= 2 ? win->tabs[1]->tab_id : 0;
        PostMessageW(win->hwnd, WM_APP_TAB_COMMAND, kTabCloseId, static_cast<LPARAM>(g_smokeTabMark));
        g_smokeTicks = 0;
        g_smokeTabStep = 3;
        return;
    case 3: {
        const bool gone = !FindTab(win, g_smokeTabMark);
        SmokeReport("tabs_close_middle", gone && win->tabs.size() == 2 && FindTab(win, win->active_tab) != nullptr);
        g_smokeLateBefore = g_smokeLateControllersClosed;
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTabMark = win->next_tab_id - 1;
        CloseTab(win, g_smokeTabMark);  // still Creating: its controller arrives later and must be closed
        g_smokeTicks = 0;
        g_smokeTabStep = 4;
        return;
    }
    case 4:
        if (g_smokeLateControllersClosed == g_smokeLateBefore && g_smokeTicks < 40) return;
        SmokeReport("tabs_close_during_creation",
            g_smokeLateControllersClosed == g_smokeLateBefore + 1 && win->tabs.size() == 2 && !FindTab(win, g_smokeTabMark));
        PostMessageW(win->hwnd, WM_APP_TAB_COMMAND, kTabCloseId, static_cast<LPARAM>(g_smokeTabMark));
        g_smokeTicks = 0;
        g_smokeTabStep = 5;
        return;
    case 5:
        SmokeReport("tabs_removed_id_noop", win->tabs.size() == 2 && SmokeLiveTabs() == 2);
        g_smokeTabStep = 6;
        return;
    // ── Lifetime/failure tests (Codex impl review) ──
    case 6: {
        // A QUEUED consent is settled (denied, exactly once) when its tab closes, before release.
        auto owner = win->tabs.back();
        auto c = std::make_shared<SmokeCounters>();
        auto req = SmokeMakeConsent(owner, c);
        g_consentQueue.push_back(req);
        CloseTab(win, owner->tab_id);
        SettleConsent(req, true);  // a late second settle (e.g. a dialog returning) changes nothing
        SmokeReport("consent_queued_settled_on_close",
            c->completed == 1 && c->state == COREWEBVIEW2_PERMISSION_STATE_DENY);
        PumpConsents();  // drops the settled request without completing it again
        SmokeReport("consent_queued_not_completed_twice", c->completed == 1);
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 7;
        return;
    }
    case 7: {
        if (SmokeLiveTabs() < 2 && g_smokeTicks < 40) return;
        // An ON-SCREEN consent whose tab closes during the dialog is settled exactly once (denied);
        // a request arriving while the dialog is open never opens a second dialog.
        auto owner = win->tabs.back();
        auto first = win->tabs.front();
        auto c1 = std::make_shared<SmokeCounters>();
        auto c2 = std::make_shared<SmokeCounters>();
        static int depth = 0, maxDepth = 0, calls = 0;
        static bool settledDuringDialog = false;
        g_consentAnswers.clear(); // earlier steps answered (No) for this origin; this case needs dialogs
        depth = maxDepth = calls = 0;
        settledDuringDialog = false;
        g_smokeConsentAnswer = [win, owner, first, c1, c2](const std::shared_ptr<ClipboardConsentCtx>&) {
            ++calls; ++depth; maxDepth = (std::max)(maxDepth, depth);
            bool answer = false;
            if (calls == 1) {
                CloseTab(win, owner->tab_id);                         // the owner goes away mid-dialog
                settledDuringDialog = c1->completed == 1 &&           // ...and is settled BEFORE the
                    c1->state == COREWEBVIEW2_PERMISSION_STATE_DENY;  //    dialog returns

                g_consentQueue.push_back(SmokeMakeConsent(first, c2)); // a new request arrives...
                PumpConsents();                                       // ...and must NOT open a nested dialog
                answer = true;                                        // the user clicked Yes anyway
            }
            --depth;
            return answer;
        };
        auto c1req = SmokeMakeConsent(owner, c1);
        g_consentQueue.push_back(c1req);
        PumpConsents();
        g_smokeConsentAnswer = nullptr;
        SmokeReport("consent_on_screen_settled_once",
            c1->completed == 1 && c1->state == COREWEBVIEW2_PERMISSION_STATE_DENY &&
            c2->completed == 1 && maxDepth == 1 && calls == 2 && settledDuringDialog);
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 8;
        return;
    }
    case 8: {
        if (SmokeLiveTabs() < 2 && g_smokeTicks < 40) return;
        // A popup request still pending when its OPENER tab closes is denied exactly once, before the
        // opener is released, and never gets a window.
        auto opener = win->tabs.back();
        auto c = std::make_shared<SmokeCounters>();
        ComPtr<ICoreWebView2NewWindowRequestedEventArgs> args = Microsoft::WRL::Make<FakeNewWindowArgs>(c);
        CreateChildPopupWindow(win, args, opener->tab_id);
        CloseTab(win, opener->tab_id);
        SmokeReport("popup_pending_denied_on_opener_close",
            c->completed == 1 && c->handled == TRUE && !c->newWindowSet);
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 9;
        return;
    }
    case 9: {
        if (SmokeLiveTabs() < 2 && g_smokeTicks < 40) return;
        // A renderer failure reported twice for one tab prompts once (naming it); "No" closes it.
        auto victim = win->tabs.back();
        g_smokeRecoveryPrompts = 0;
        // Like a real modal dialog, pump the window's messages while "open", so the second failure
        // report is dispatched while the first prompt is still showing.
        g_smokeRecoveryAnswer = [win](const std::wstring&) {
            MSG m{};
            while (PeekMessageW(&m, win->hwnd, WM_APP_TAB_FAILED, WM_APP_TAB_FAILED, PM_REMOVE)) DispatchMessageW(&m);
            return IDNO;
        };
        const uint64_t vid = victim->tab_id;
        PostMessageW(win->hwnd, WM_APP_TAB_FAILED, static_cast<WPARAM>(vid), 1);
        PostMessageW(win->hwnd, WM_APP_TAB_FAILED, static_cast<WPARAM>(vid), 1);
        g_smokeTabMark = vid;
        g_smokeTabStep = 10;
        return;
    }
    case 10:
        SmokeReport("renderer_failure_one_prompt", g_smokeRecoveryPrompts == 1 && !FindTab(win, g_smokeTabMark));
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 11;
        return;
    case 11: {
        if (SmokeLiveTabs() < 2 && g_smokeTicks < 40) return;
        // Re-entrant Complete(): settling a closing tab's requests runs a callback that queues a new
        // request, pumps, and tears down again. Every request completes exactly once, denied.
        auto owner = win->tabs.back();
        auto first = win->tabs.front();
        auto c1 = std::make_shared<SmokeCounters>(), c2 = std::make_shared<SmokeCounters>();
        auto c3 = std::make_shared<SmokeCounters>(), c4 = std::make_shared<SmokeCounters>();
        g_consentAnswers.clear();
        c1->onComplete = [owner, first, c4] {
            g_consentQueue.push_back(SmokeMakeConsent(first, c4));
            PumpConsents();
            SettleConsentsFor(owner);
            SettleAllConsents();
        };
        g_consentQueue.push_back(SmokeMakeConsent(owner, c1));
        g_consentQueue.push_back(SmokeMakeConsent(owner, c2));
        g_consentQueue.push_back(SmokeMakeConsent(owner, c3));
        CloseTab(win, owner->tab_id);
        PumpConsents();
        auto deniedOnce = [](const std::shared_ptr<SmokeCounters>& c) {
            return c->completed == 1 && c->state == COREWEBVIEW2_PERMISSION_STATE_DENY;
        };
        // Window teardown (settle ALL) with a non-empty queue, whose first Complete() queues another
        // request and settles all again: everything completes once and the queue ends empty.
        auto c7 = std::make_shared<SmokeCounters>(), c8 = std::make_shared<SmokeCounters>();
        auto c9 = std::make_shared<SmokeCounters>();
        c7->onComplete = [first, c9] {
            g_consentQueue.push_back(SmokeMakeConsent(first, c9));
            SettleAllConsents();
        };
        g_consentQueue.push_back(SmokeMakeConsent(first, c7));
        g_consentQueue.push_back(SmokeMakeConsent(first, c8));
        SettleAllConsents();
        SmokeReport("consent_reentrant_complete_settles_once",
            deniedOnce(c1) && deniedOnce(c2) && deniedOnce(c3) && deniedOnce(c4) &&
            deniedOnce(c7) && deniedOnce(c8) && deniedOnce(c9) && g_consentQueue.empty());

        // Settlement inside the pump is guarded too: a Complete() that queues and pumps does NOT
        // recurse into the pump; the outer loop handles the new request after Complete() returns.
        auto c5 = std::make_shared<SmokeCounters>(), c6 = std::make_shared<SmokeCounters>();
        static bool c6HandledInside = false;
        c6HandledInside = false;
        c5->onComplete = [first, c6] {
            g_consentQueue.push_back(SmokeMakeConsent(first, c6));
            PumpConsents();
            c6HandledInside = c6->completed != 0;
        };
        g_smokeConsentAnswer = [](const std::shared_ptr<ClipboardConsentCtx>&) { return false; };
        g_consentQueue.push_back(SmokeMakeConsent(first, c5));
        PumpConsents();
        g_smokeConsentAnswer = nullptr;
        SmokeReport("consent_pump_not_reentered_from_complete",
            c5->completed == 1 && c6->completed == 1 && !c6HandledInside && !g_consentShowing);

        // The answer to a VALID request is remembered for the run: one dialog, then the same answer
        // for every later read from that origin (automatic clipboard send reads on each press). Both
        // a Yes and a No are kept, so a No does not turn into a dialog per click.
        for (const bool answer : { true, false }) {
            g_consentAnswers.clear();
            static int asked = 0;
            asked = 0;
            g_smokeConsentAnswer = [answer](const std::shared_ptr<ClipboardConsentCtx>&) { ++asked; return answer; };
            auto r1 = std::make_shared<SmokeCounters>(), r2 = std::make_shared<SmokeCounters>();
            auto r3 = std::make_shared<SmokeCounters>();
            g_consentQueue.push_back(SmokeMakeConsent(first, r1));
            PumpConsents();
            g_consentQueue.push_back(SmokeMakeConsent(first, r2));
            g_consentQueue.push_back(SmokeMakeConsent(first, r3));
            PumpConsents();
            g_smokeConsentAnswer = nullptr;
            const auto expected = answer ? COREWEBVIEW2_PERMISSION_STATE_ALLOW : COREWEBVIEW2_PERMISSION_STATE_DENY;
            auto once = [expected](const std::shared_ptr<SmokeCounters>& c) {
                return c->completed == 1 && c->state == expected;
            };
            SmokeReport(answer ? "consent_yes_remembered_for_run" : "consent_no_remembered_for_run",
                asked == 1 && once(r1) && once(r2) && once(r3));
        }
        g_consentAnswers.clear();
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 12;
        return;
    }
    case 12: {
        if (SmokeLiveTabs() < 2 && g_smokeTicks < 40) return;
        // An INITIAL tab whose creation fails while another tab is open closes only itself: the
        // window and the other tab survive, exit code unchanged, one error.
        auto failed = win->tabs.back();
        const size_t before = win->tabs.size();
        failed->first_tab = true;
        g_smokeErrorsShown = 0;
        // Like a modal loop, the error dispatches a second failure report for the same tab.
        static int nested = 0;
        nested = 0;
        g_smokeErrorHook = [win, fid = failed->tab_id] {
            if (nested++ == 0)
                SendMessageW(win->hwnd, WM_APP_TAB_CREATE_FAILED, static_cast<WPARAM>(fid), kFailController);
        };
        SendMessageW(win->hwnd, WM_APP_TAB_CREATE_FAILED, static_cast<WPARAM>(failed->tab_id), kFailController);
        SmokeReport("first_tab_failure_keeps_survivors",
            g_smokeErrorsShown == 1 && !win->closing && g_exitCode == 0 &&
            !FindTab(win, failed->tab_id) && win->tabs.size() == before - 1 && SmokeLiveTabs() == before - 1);
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 13;
        return;
    }
    case 13: {
        if (SmokeLiveTabs() < 2 && g_smokeTicks < 40) return;
        // The failed tab is closed WHILE its error is showing (the modal loop dispatched a close): the
        // handler revalidates afterwards, closes nothing else, and the window stays open.
        auto failed = win->tabs.back();
        const uint64_t fid = failed->tab_id;
        const size_t before = win->tabs.size();
        failed->first_tab = true;
        g_smokeErrorsShown = 0;
        g_smokeErrorHook = [win, fid] { CloseTab(win, fid); };
        SendMessageW(win->hwnd, WM_APP_TAB_CREATE_FAILED, static_cast<WPARAM>(fid), kFailController);
        g_smokeErrorHook = nullptr;
        SmokeReport("first_tab_failure_removed_during_error",
            g_smokeErrorsShown == 1 && !win->closing && g_exitCode == 0 &&
            win->tabs.size() == before - 1 && SmokeLiveTabs() == before - 1);
        g_smokeTabStep = 20;
        return;
    }
    // ── Full screen (SyncFullscreen): the page's requestFullscreen() takes the WINDOW full screen ──
    case 20:
        // The smoke window is never shown; the app shows its window maximized, the case that matters
        // (restoring must return it MAXIMIZED, framed, with its menu).
        ShowWindow(win->hwnd, SW_SHOWMAXIMIZED);
        g_smokeTabStep = 28;
        return;
    case 28: {
        auto t = ActiveTab(win);
        if (!t) { SmokeReport("fullscreen_enter", false); g_smokeTabStep = 14; return; }
        GetWindowRect(win->hwnd, &g_smokeFsBeforeRect);
        g_smokeFsBeforeStyle = GetWindowLongPtrW(win->hwnd, GWL_STYLE);
        g_smokeFsBeforeZoomed = IsZoomed(win->hwnd) != FALSE;
        g_smokeFsBeforeMenu = GetMenu(win->hwnd);
        SmokeEval(t, L"document.documentElement.requestFullscreen()");
        g_smokeTicks = 0;
        g_smokeTabStep = 21;
        return;
    }
    case 21: {
        if (!win->fullscreen && g_smokeTicks < 40) return;
        const bool ok = SmokeFsCoversMonitor(win);
        SmokeLog("[smoke] fullscreen enter: flag=%d covers=%d\n", (int)win->fullscreen, (int)ok);
        SmokeReport("fullscreen_enter", win->fullscreen && ok);
        if (auto t = ActiveTab(win)) SmokeEval(t, L"document.exitFullscreen()");
        g_smokeTicks = 0;
        g_smokeTabStep = 22;
        return;
    }
    case 22: {
        if (win->fullscreen && g_smokeTicks < 40) return;
        SmokeReport("fullscreen_exit_restores_window", !win->fullscreen && SmokeFsRestored(win));
        if (auto t = ActiveTab(win)) SmokeEval(t, L"document.documentElement.requestFullscreen()");
        g_smokeTicks = 0;
        g_smokeTabStep = 23;
        return;
    }
    case 23:
        if (!win->fullscreen && g_smokeTicks < 40) return;
        g_smokeTabMark = win->active_tab;  // the full-screen tab
        CreateTab(win, kSmokeTestUrl, false);
        g_smokeTicks = 0;
        g_smokeTabStep = 24;
        return;
    case 24: {
        auto t = ActiveTab(win);
        const bool switched = t && t->tab_id != g_smokeTabMark && t->phase == WindowState::Phase::Live;
        if (!switched && g_smokeTicks < 40) return;
        // Another tab shown: the window leaves full screen (that tab has no full-screen element).
        SmokeReport("fullscreen_left_on_tab_switch", switched && !win->fullscreen && SmokeFsRestored(win));
        ActivateTab(win, g_smokeTabMark);
        g_smokeTicks = 0;
        g_smokeTabStep = 25;
        return;
    }
    case 25: {
        if (!win->fullscreen && g_smokeTicks < 10) return;
        // Back on the tab whose page is still full screen: the window resumes full screen.
        SmokeReport("fullscreen_resumes_on_return",
            win->active_tab == g_smokeTabMark && win->fullscreen && SmokeFsCoversMonitor(win));
        // Esc, delivered as a key to the page, leaves full screen (WebView2 does this itself; the host
        // relies on it, so a runtime that stopped would fail here).
        if (auto t = ActiveTab(win); t && t->webview)
            t->webview->CallDevToolsProtocolMethod(L"Input.dispatchKeyEvent",
                LR"json({"type":"rawKeyDown","key":"Escape","code":"Escape","windowsVirtualKeyCode":27,"nativeVirtualKeyCode":27})json",
                Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
                    [](HRESULT, LPCWSTR) -> HRESULT { return S_OK; }).Get());
        g_smokeTicks = 0;
        g_smokeTabStep = 26;
        return;
    }
    case 26:
        if (win->fullscreen && g_smokeTicks < 15) return;
        SmokeReport("fullscreen_esc_exits", !win->fullscreen && SmokeFsRestored(win));
        if (win->fullscreen) if (auto t = ActiveTab(win)) SmokeEval(t, L"document.exitFullscreen()");
        g_smokeTicks = 0;
        g_smokeTabStep = 27;
        return;
    case 27:
        if (win->fullscreen && g_smokeTicks < 40) return;
        g_smokeTabStep = 14;
        return;
    case 14:
        // A browser-process exit reported by several tabs shows ONE message and latches.
        KillTimer(win->hwnd, kSmokeTabTimerId);
        g_smokeErrorsShown = 0;
        SendMessageW(win->hwnd, WM_APP_BROWSER_DIED, 0, 0);
        SendMessageW(win->hwnd, WM_APP_BROWSER_DIED, 0, 0);
        g_smokeTabStep = 15;
        SmokeReport("browser_exit_latched", g_smokeErrorsShown == 1 && win->env_failed);
        return;
    default:
        return;
    }
}
#endif

// ── Sign-in detection ──────────────────────────────────────────────────────
// Records this process's organization once ITS OWN origin holds a server-issued control-plane
// session cookie, then stops. This is evidence that a sign-in completed through this origin,
// not that the session is still valid or that the user belongs to this tenant. The
// cookie must match what control-plane/auth.go sessionCookie sets: host-only (Domain equal
// to the host, so a sibling or parent-domain cookie cannot match), Path "/", Secure and
// HttpOnly. HttpOnly matters: page script cannot create an HttpOnly cookie, so a
// document.cookie counterfeit is refused. Runs on the UI thread.
static void CheckSignedIn(const std::shared_ptr<WindowState>& state) {
#ifdef SMOKE_TEST
    (void)state;
#else
    if (!state || state->closing || state->org_recorded) return;
    // Every tab shares the organization's profile, so any live tab's cookie manager sees the same jar.
    ComPtr<ICoreWebView2> anyTab = AnyLiveWebView(state);
    if (!anyTab) return;
    ComPtr<ICoreWebView2_2> wv2;
    ComPtr<ICoreWebView2CookieManager> cookies;
    if (FAILED(anyTab.As(&wv2)) || !wv2 || FAILED(wv2->get_CookieManager(&cookies)) || !cookies)
        return;
    const std::string host = drpolicy::tenant_host(state->selectedTenant);
    const std::wstring origin = L"https://" + Utf8ToWide(host) + L"/";
    cookies->GetCookies(origin.c_str(),
        Callback<ICoreWebView2GetCookiesCompletedHandler>(
            [state, host](HRESULT hr, ICoreWebView2CookieList* list) -> HRESULT {
                if (FAILED(hr) || !list || !state || state->closing || state->org_recorded) return S_OK;
                UINT count = 0;
                if (FAILED(list->get_Count(&count))) return S_OK;
                for (UINT i = 0; i < count; ++i) {
                    ComPtr<ICoreWebView2Cookie> cookie;
                    if (FAILED(list->GetValueAtIndex(i, &cookie)) || !cookie) continue;
                    LPWSTR name = nullptr, value = nullptr, domain = nullptr, path = nullptr;
                    BOOL httpOnly = FALSE, secure = FALSE;
                    const bool read = SUCCEEDED(cookie->get_Name(&name)) &&
                        SUCCEEDED(cookie->get_Value(&value)) &&
                        SUCCEEDED(cookie->get_Domain(&domain)) &&
                        SUCCEEDED(cookie->get_Path(&path)) &&
                        SUCCEEDED(cookie->get_IsHttpOnly(&httpOnly)) &&
                        SUCCEEDED(cookie->get_IsSecure(&secure));
                    const bool match = read && name && value && domain && path &&
                        drpolicy::is_session_cookie(WideToUtf8(name), WideToUtf8(value), WideToUtf8(domain),
                                                    host, WideToUtf8(path), httpOnly == TRUE, secure == TRUE);
                    CoTaskMemFree(name); CoTaskMemFree(value); CoTaskMemFree(domain); CoTaskMemFree(path);
                    if (match) {
                        state->org_recorded = true;
                        if (state->hwnd && IsWindow(state->hwnd)) KillTimer(state->hwnd, kSignInTimerId);
                        RecordOrgSignedIn(state->selectedTenant);
                        break;
                    }
                }
                return S_OK;
            }).Get());
#endif
}

// ── WndProcs ───────────────────────────────────────────────────────────────
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* sp = reinterpret_cast<std::shared_ptr<WindowState>*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    auto state = sp ? *sp : g_mainState;

    switch (msg) {
    case WM_SIZE:
    case WM_DPICHANGED:
        if (state) LayoutTabs(state);
        if (msg == WM_DPICHANGED) {
            // Full screen stays covering the monitor; the suggested rect is for a framed window.
            if (state && state->fullscreen) { FitFullscreen(state); return 0; }
            const RECT* suggested = reinterpret_cast<const RECT*>(lp);
            SetWindowPos(hwnd, nullptr, suggested->left, suggested->top, suggested->right - suggested->left,
                suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        break;

    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lp);
        if (!state || state->closing || !hdr || hdr->hwndFrom != state->tab_ctrl) break;
        if (hdr->code == TCN_SELCHANGING) {
            // Picking "+" opens a new tab instead of selecting the pseudo-tab.
            const int sel = TabCtrl_GetCurSel(state->tab_ctrl);
            (void)sel;
            return FALSE;
        }
        if (hdr->code == TCN_SELCHANGE) {
            const int sel = TabCtrl_GetCurSel(state->tab_ctrl);
            TCITEMW item{}; item.mask = TCIF_PARAM;
            if (sel >= 0 && TabCtrl_GetItem(state->tab_ctrl, sel, &item)) {
                if (item.lParam == 0) {
                    RefreshTabStrip(state);  // restore the real selection, then open the tab
                    PostMessageW(hwnd, WM_APP_TAB_COMMAND, kTabNew, 0);
                } else {
                    ActivateTab(state, static_cast<uint64_t>(item.lParam));
                }
            }
            return 0;
        }
        break;
    }

    case WM_APP_TAB_COMMAND:
        ExecuteTabCommand(state, wp, lp);
        return 0;

    case WM_APP_TAB_CREATE_FAILED: {
        auto t = FindTab(state, static_cast<uint64_t>(wp));
        if (!state || state->closing || !t || t->failure_pending) return 0;  // already removed or handled
        t->failure_pending = true;  // latched before the error, whose modal loop pumps messages
        const uint64_t id = t->tab_id;
        const wchar_t* text =
            lp == kFailController ? L"A new tab could not be created.\nEnsure the WebView2 Runtime is installed." :
            lp == kFailInterface  ? L"A new tab could not be created (WebView2 interface unavailable)." :
            lp == kFailSecurity   ? L"A new tab could not establish the client security settings." :
                                    L"A new tab could not be displayed.";
        ShowError(hwnd, text);
        if (state->closing) return 0;
        // Revalidate after the dialog: the tab may have been closed meanwhile. Only the failed tab is
        // closed; closing the last tab closes the window (CloseTab), so a failed INITIAL tab with
        // nothing else open ends the process with exit code 1, and never takes other tabs with it.
        const bool stillThere = FindTab(state, id) == t;
        if (t->first_tab && CountOpenTabs(state) == (stillThere ? 1u : 0u)) g_exitCode = 1;
        if (stillThere) CloseTab(state, id);
        return 0;
    }

    case WM_APP_TAB_FAILED: {
        // Native recovery surface: a hung renderer cannot be trusted to paint an error page. One prompt
        // per tab at a time (more failure events for it are ignored while it is open), naming the tab.
        auto t = FindTab(state, static_cast<uint64_t>(wp));
        if (!state || state->closing || state->env_failed || !t || t->phase != WindowState::Phase::Live ||
            t->recovery_pending) return 0;
        t->recovery_pending = true;
        ActivateTab(state, t->tab_id);
        const std::wstring name = TabStripLabel(t);
        const std::wstring text = L"The tab \u201C" + name + (lp == 2
            ? L"\u201D stopped responding.\n\nReload it? (No closes the tab.)"
            : L"\u201D stopped unexpectedly.\n\nReload it? (No closes the tab.)");
        int r;
#ifdef SMOKE_TEST
        ++g_smokeRecoveryPrompts;
        r = g_smokeRecoveryAnswer ? g_smokeRecoveryAnswer(text) : IDNO;
#else
        r = MessageBoxW(hwnd, text.c_str(), L"DeskRally", MB_YESNO | MB_ICONWARNING);
#endif
        // The dialog pumped messages: revalidate the window and the tab by id.
        auto again = FindTab(state, static_cast<uint64_t>(wp));
        if (again) again->recovery_pending = false;
        if (state->closing || state->env_failed || !again || again->phase != WindowState::Phase::Live) return 0;
        if (r == IDYES && again->webview && SUCCEEDED(again->webview->Reload())) return 0;
        if (r == IDYES) ShowError(hwnd, L"The tab could not be reloaded and will be closed.");
        CloseTab(state, again->tab_id);
        return 0;
    }

    case WM_APP_BROWSER_DIED:
        // Environment-wide: every tab and popup of this window is gone. Latched: one message, every
        // later report and every tab command is ignored, and the window closes normally.
        if (!state || state->closing || state->env_failed) return 0;
        state->env_failed = true;
#ifdef SMOKE_TEST
        ++g_smokeErrorsShown;
#else
        ShowError(hwnd, L"DeskRally's browser component stopped. Please restart DeskRally.");
#endif
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
        return 0;

    case WM_CLOSE:
        g_helloPending = false;
        ++g_helloGeneration;
        if (g_helloOperation) {
            ComPtr<IAsyncInfo> info;
            if (SUCCEEDED(g_helloOperation.As(&info))) info->Cancel();
            g_helloOperation.Reset();
        }
        if (state) {
            if (!state->closing) {
                // Mark the window closing FIRST (rejects new tabs and popups), then tear down every
                // tab in the designed order, then the popups.
                state->closing = true;
                CloseAllTabs(state);
                CloseAllChildren(state);
                SettleAllConsents();
            }
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (state && state->tab_ctrl) {
            RemoveWindowSubclass(state->tab_ctrl, TabStripSubclass, 1);
            state->tab_ctrl = nullptr;
        }
        PostQuitMessage(g_exitCode);
        return 0;

    case WM_NCDESTROY: {
        // The process must not outlive this window, even if WM_DESTROY's quit is lost (a 0.8.1
        // client sat in GetMessageW for a day and blocked every update): see lifetime_policy.h.
        g_mainWindowGone = true;
        SettleAllConsents();
        CancelQueuedSpawn(hwnd);
        // Free the heap-allocated shared_ptr after the window is fully destroyed.
        auto* sp2 = reinterpret_cast<std::shared_ptr<WindowState>*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (sp2) ReleaseDetachedMenu(**sp2);
        if (sp2) { (*sp2)->hwnd = nullptr; delete sp2; SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0); }
        return 0;
    }

    case WM_CLIPBOARD_CONSENT:
        PumpConsents();
        return 0;

    case WM_SPAWN_CLIENT: {
        auto* uri = reinterpret_cast<std::wstring*>(lp);
        if (uri) {
            if (state && !state->closing && !SpawnWithUri(*uri))
                ShowError(hwnd, L"Could not open a new DeskRally window. Please try again.");
            delete uri;
        }
        return 0;
    }

    case WM_COMMAND:
        if (!state || state->closing || g_helloPending) return 0;
        switch (LOWORD(wp)) {
        case IDM_ABOUT: {
            // Ed, 2026-10-16: show what is actually running. Read live, not from build-time constants
            // (except the commit, which only the build knows).
            const auto about = drupdate::GetAboutInfo();
            std::wstring text = L"DeskRally Desktop Client\n\nVersion " +
                (about.version.empty() ? std::wstring(L"unknown") : about.version) +
                L"  (source " DESKRALLY_COMMIT L")\n" +
                (!about.publisher_pinned
                    ? std::wstring(L"Publisher: not pinned in this build\n")
                    : about.publisher_verified
                        ? L"Publisher: " + about.publisher_name + L" (signature verified; revocation not checked)\n"
                        : std::wstring(L"Publisher: signature verification unavailable or failed\n")) +
                L"Organization: " + TenantLabel(state->selectedTenant) + L"  (https://" +
                Utf8ToWide(drpolicy::tenant_host(state->selectedTenant)) + L")\n\n" +
                L"Updates: " + (about.last_result.empty() ? std::wstring(L"no update recorded") : about.last_result) +
                (about.last_check.empty() ? std::wstring() : L"\nLast checked: " + about.last_check);
            MessageBoxW(hwnd, text.c_str(), L"About DeskRally", MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDM_TAB_NEW:   ExecuteTabCommand(state, kTabNew, 0); break;
        case IDM_TAB_CLOSE: ExecuteTabCommand(state, kTabCloseActive, 0); break;
        case IDM_TAB_NEXT:  ExecuteTabCommand(state, kTabNext, 0); break;
        case IDM_TAB_PREV:  ExecuteTabCommand(state, kTabPrev, 0); break;
        case IDM_UPDATE_CHECK:
            if (g_updater) {
                g_manualUpdateCheck = true;
                if (!g_updater->CheckForUpdate()) {
                    g_manualUpdateCheck = false;
                    ShowError(hwnd, L"Automatic updates are available in the installed DeskRally app. "
                        L"Install the signed package, then check again from the Start menu.");
                }
            }
            break;
        case IDM_HELLO_ENABLE:
        case IDM_HELLO_DISABLE: {
            const bool enable = LOWORD(wp) == IDM_HELLO_ENABLE;
            if (MessageBoxW(hwnd, enable
                ? L"Require Windows Hello when opening this organization's app profile?\n\n"
                  L"Windows will verify your PIN, face, or fingerprint. No password or PIN is saved by DeskRally. "
                  L"This takes effect on your next app launch; already-open windows stay open."
                : L"Disable Windows Hello for future app launches?\n\nWindows Hello verification is required "
                  L"to change this setting. This will not sign you out of the server. Sign out first if you "
                  L"want to end remembered access.",
                L"DeskRally - Windows Hello", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES)
                StartHello(state, enable ? HelloPurpose::Enable : HelloPurpose::Disable);
            break;
        }
        case IDM_ORG_OTHER: {
            // Each organization opens in an independent new process pinned to it.
            drpolicy::Tenant chosen = drpolicy::Tenant::main();
            if (PromptForOrganization(hwnd, chosen) && !SpawnWithUri(ConsoleUriFor(chosen)))
                ShowError(hwnd, L"Could not open that organization's console. Please try again.");
            break;
        }
        default: {
            const UINT id = LOWORD(wp);
            if (id >= IDM_ORG_FIRST && id - IDM_ORG_FIRST < g_orgMenuTenants.size()) {
                if (!SpawnWithUri(ConsoleUriFor(g_orgMenuTenants[id - IDM_ORG_FIRST])))
                    ShowError(hwnd, L"Could not open that organization's console. Please try again.");
            }
            break;
        }
        }
        return 0;

    case drupdate::WM_UPDATE_STATUS: {
        if (!state || state->closing || !g_updater) return 0;
        const auto update = g_updater->GetState();
        std::wstring label = L"Check for updates";
        std::wstring notice;
        switch (update.status) {
        case drupdate::UpdateStatus::Checking:
            g_updateApplyRequested = false; label = L"Checking for updates..."; break;
        case drupdate::UpdateStatus::Downloading: label = L"Downloading update..."; break;
        case drupdate::UpdateStatus::Ready:
            if (!g_updateApplyRequested) g_updateApplyRequested = g_updater->Apply();
            if (g_updateApplyRequested) {
                label = L"Update ready - close all DeskRally windows to install";
                notice = L"DeskRally " + update.pending_version + L" is ready. It will install after "
                    L"all DeskRally windows are closed. Your remote sessions will not be interrupted.";
            } else {
                notice = L"The update downloaded, but could not be scheduled. Please check again later.";
            }
            break;
        case drupdate::UpdateStatus::NoUpdate: notice = L"DeskRally is up to date."; break;
        case drupdate::UpdateStatus::Failed:
            notice = L"Could not update DeskRally. Your installed app is unchanged.\n\n" + update.error_message;
            break;
        default: break;
        }
        if (HMENU menu = GetMenu(hwnd)) {
            ModifyMenuW(menu, IDM_UPDATE_CHECK, MF_BYCOMMAND | MF_STRING, IDM_UPDATE_CHECK, label.c_str());
            DrawMenuBar(hwnd);
        }
        if (g_manualUpdateCheck && !notice.empty()) {
            g_manualUpdateCheck = false;
            MessageBoxW(hwnd, notice.c_str(), L"DeskRally updates", MB_OK | MB_ICONINFORMATION);
        }
        return 0;
    }

    case WM_HELLO_RESULT:
        CompleteHello(state, static_cast<uint64_t>(wp), lp == 1);
        return 0;

    case WM_TIMER:
        if (wp == kSsoTimerId) {
            if (!state || state->closing || state->is_popup || state->is_tab) return 0;
            // Snapshot shared ownership: a modal dialog can dispatch tab/window teardown.
            const auto tabs = state->tabs;
            // Enforcement (expiry, Stop, recovery) runs on EVERY tick for every tab, whatever any dialog
            // is doing: MessageBox pumps messages, so navigation continues underneath it (impl review
            // v1). Only the notification is guarded, and at WINDOW scope, so tabs cannot nest dialogs.
            const auto tick = [hwnd, state](const std::shared_ptr<WindowState>& current) {
                if (!current || !StateUsable(current) || current->is_popup ||
                    !current->webview || !current->sso) return;
                const auto actions = current->sso->on_tick((int64_t)GetTickCount64());
                if (actions.stop_pending_external) current->webview->Stop();
                if (!StateUsable(current) || !current->webview) return;
                if (actions.navigate_to_tenant_console) {
                    const auto url = current->sso->tenant_console_url();
                    const std::wstring wide(url.begin(), url.end());
                    current->webview->Navigate(wide.c_str());
                }
                if (!StateUsable(current) || !current->webview) return;
                if (state->sso_dialog_open) return;
                const auto banner = current->sso->banner();
                if (banner == drpolicy::SsoFlow::Banner::None) return;
                const auto generation = current->sso->generation();
                state->sso_dialog_open = true;
#ifdef SMOKE_TEST
                if (banner == drpolicy::SsoFlow::Banner::TimedOut) {
                    ++g_ssoSmokeTimedOut;
                    SmokeLog("[sso-smoke] NOTIFY TimedOut\n");
                } else {
                    ++g_ssoSmokeUnsupported;
                    SmokeLog("[sso-smoke] NOTIFY Unsupported\n");
                }
#else
                const wchar_t* text = banner == drpolicy::SsoFlow::Banner::TimedOut
                    ? L"Microsoft sign-in ended or timed out. DeskRally will return to the console; start the sign-in again if you still need it."
                    : L"This sign-in step isn't supported in the DeskRally app yet. Use the console in a web browser for this sign-in.";
                MessageBoxW(hwnd, text, L"DeskRally", MB_OK | MB_ICONINFORMATION);
#endif
                state->sso_dialog_open = false;
                // Re-validate: while the box was up, a tenant page may have committed or a new flow
                // started. Act only on the flow the message was about, and leave a tenant page alone.
                if (!StateUsable(current) || !current->webview || !current->sso) return;
                if (current->sso->generation() != generation || current->sso->banner() != banner) return;
                current->sso->dismiss_banner();
                if (current->sso->external_committed() || banner == drpolicy::SsoFlow::Banner::TimedOut) {
                    const auto url = current->sso->tenant_console_url();
                    const std::wstring wide(url.begin(), url.end());
                    current->webview->Navigate(wide.c_str());
                }
            };
            tick(state);
            for (const auto& tab : tabs) tick(tab);
            return 0;
        }
#ifdef SMOKE_TEST
        if (g_ssoSmoke && wp == kSsoSmokeTimerId) { SsoSmokeTick(hwnd); return 0; }
        if (g_ssoSmoke && wp == kSsoSmokeResponseTimerId) { SsoSmokeCompleteResponse(hwnd); return 0; }
        if (wp == kSmokeTabTimerId) { SmokeTabTick(); return 0; }
        KillTimer(hwnd, wp);
        SmokeLog("[smoke] timer %llu fired – tearing down\n", (unsigned long long)wp);
        if (state) {
            state->closing = true;
            CloseAllTabs(state);
            CloseAllChildren(state);
        }
        DestroyWindow(hwnd);
        return 0;
#else
        if (wp == kSignInTimerId) {
            CheckSignedIn(state);
            return 0;
        }
        if (wp == 20 && state && !state->closing && g_updater && drupdate::Updater::IsDailyCheckDue()) {
            if (g_updater->CheckForUpdate()) {
                drupdate::Updater::RecordCheckTime();
            }
        }
        return 0;
#endif
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT CALLBACK PopupWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* sp = reinterpret_cast<std::shared_ptr<WindowState>*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_SIZE:
        if (sp && (*sp)->controller) {
            RECT rc; GetClientRect(hwnd, &rc);
            (*sp)->controller->put_Bounds(rc);
        }
        break;

    case WM_CLOSE:
        if (sp) {
            (*sp)->closing = true;
            SettleConsentsFor(*sp);
            // Always call Close() even if closing was already set.
            if ((*sp)->controller) {
                (*sp)->controller->Close();
                (*sp)->controller.Reset();
                (*sp)->webview.Reset();
            }
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY: {
        // Remove from the actual parent's children list (not always g_mainState).
        if (sp && *sp) {
            auto parentState = (*sp)->parent.lock();
            if (parentState) {
                auto& ch = parentState->children;
                ch.erase(std::remove_if(ch.begin(), ch.end(),
                    [hwnd](const std::shared_ptr<WindowState>& c){
                        return c && c->hwnd == hwnd;
                    }), ch.end());
            }
        }
        return 0;
    }

    case WM_NCDESTROY: {
        auto* sp2 = reinterpret_cast<std::shared_ptr<WindowState>*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (sp2) ReleaseDetachedMenu(**sp2);
        if (sp2) { (*sp2)->hwnd = nullptr; delete sp2; SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0); }
        return 0;
    }

    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void StartProfile(const std::shared_ptr<WindowState>& state) {
    if (!state || !drhello::may_open_profile(g_helloSetting, g_helloVerifiedAtStartup,
        state->closing || !IsWindow(state->hwnd))) return;
    const HWND hwnd = state->hwnd;
    const std::wstring initialUrl = g_initialUrl;
#ifdef SMOKE_TEST
    std::wstring profilePath = g_smokeDirectory + L"\\smoke-profile";
#else
    std::wstring profilePath = GetProfilePath(state->selectedTenant);
    if (profilePath.empty()) {
        ShowError(hwnd, L"Could not find your local profile folder. DeskRally cannot start safely.");
        SendMessageW(hwnd, WM_CLOSE, 0, 0);
        return;
    }
#endif

    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        nullptr, profilePath.c_str(), nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hwnd, initialUrl](HRESULT envHr, ICoreWebView2Environment* env) -> HRESULT {
                if (!g_mainState || g_mainState->closing || !IsWindow(hwnd)) return S_OK;
                if (FAILED(envHr) || !env) {
#ifdef SMOKE_TEST
                    SmokeLog("[smoke] FAIL environment hr=0x%08x\n", (unsigned)envHr);
#endif
                    ShowError(hwnd,
                        L"WebView2 Runtime is not installed or could not be initialized.\n"
                        L"Please install the Microsoft Edge WebView2 Runtime.");
                    PostQuitMessage(1);
                    return S_OK;
                }
                g_env = env;
#ifdef SMOKE_TEST
                SmokeLog("[smoke] environment created OK\n");
#endif
                CreateTab(g_mainState, initialUrl, true);
                return S_OK;
            }).Get());

    if (FAILED(hr)) {
#ifdef SMOKE_TEST
        SmokeLog("[smoke] FAIL CreateCoreWebView2EnvironmentWithOptions hr=0x%08x\n", (unsigned)hr);
#endif
        ShowError(hwnd, L"Failed to start WebView2 environment.");
        SendMessageW(hwnd, WM_CLOSE, 0, 0);
        return;
    }

}

// Field evidence for a lost WM_QUIT (lifetime_policy.h): the main window was destroyed and its quit
// never arrived, so the loop exited by draining. Best-effort; a support engineer can read it with
// `reg query HKCU\Software\DeskRally\Client /v LastLostQuitExit`.
static void RecordLostQuitExit(size_t dispatched, bool bounded) {
#ifdef SMOKE_TEST
    SmokeLog("[smoke] lost WM_QUIT: exited by draining (dispatched=%zu bounded=%d)\n", dispatched, bounded ? 1 : 0);
#else
    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
    const ULONGLONG now = (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    const std::wstring value = L"filetime=" + std::to_wstring(now) + L" commit=" + DESKRALLY_COMMIT +
        L" dispatched=" + std::to_wstring(dispatched) + (bounded ? L" bounded" : L"");
    RegSetKeyValueW(HKEY_CURRENT_USER, kClientRegKey, L"LastLostQuitExit", REG_SZ,
        value.c_str(), static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
#endif
}

// ── Entry point ────────────────────────────────────────────────────────────
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    g_hInstance = hInstance;
#ifndef SMOKE_TEST
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!argv) return 1;
        if (argc == 2 && std::wstring(argv[1]) == L"--update-self-test") {
            LocalFree(argv);
            if (FAILED(RoInitialize(RO_INIT_SINGLETHREADED))) return 1;
            LPWSTR runtimeVersion = nullptr;
            const HRESULT result = GetAvailableCoreWebView2BrowserVersionString(nullptr, &runtimeVersion);
            const bool available = SUCCEEDED(result) && runtimeVersion && runtimeVersion[0];
            CoTaskMemFree(runtimeVersion);
            RoUninitialize();
            return available ? 0 : 1;
        }
        if (argc > 1 && std::wstring(argv[1]) == L"--update-worker") {
            const int result = drupdate::RunUpdateWorker(argc, argv);
            LocalFree(argv);
            return result;
        }
        LocalFree(argv);
    }
    drupdate::ClientLock updateLifetime;
    if (!updateLifetime.IsReady()) {
        MessageBoxW(nullptr, L"DeskRally is installing an update, or its update lock is unavailable. "
            L"Please try opening the app again in a moment.", L"DeskRally updates", MB_OK | MB_ICONINFORMATION);
        return 1;
    }
#endif
    if (FAILED(RoInitialize(RO_INIT_SINGLETHREADED))) return 1;
    struct ComCleanup { ~ComCleanup() { RoUninitialize(); } } comCleanup;
    {
        INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_TAB_CLASSES};
        InitCommonControlsEx(&icc);
    }

    // Determine the selected tenant and initial URL from the command line.
    // Tenant is locked here, before the WebView2 environment is created.
    drpolicy::Tenant selectedTenant = drpolicy::Tenant::main();
    std::wstring initialUrl;

#ifdef SMOKE_TEST
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!argv) return 1;
        for (int i = 1; i < argc; ++i) {
            if (std::wstring(argv[i]) == L"--sso-smoke") g_ssoSmoke = true;
            if (std::wstring(argv[i]) == L"--sso-smoke-probe") { g_ssoSmoke = true; g_ssoSmokeProbe = true; }
        }
        LocalFree(argv);
    }
    initialUrl = g_ssoSmoke ? kSsoSmokeConsole : kSmokeTestUrl;
    // selectedTenant stays main for both smoke modes.
#else
    {
        // Without a link, open the console of the organization chosen below.
        drpolicy::ClientUriResult startupResult;
        startupResult.valid  = true;
        startupResult.kind   = drpolicy::ClientUriResult::Kind::Console;
        bool fromLink = false;

        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv) {
            if (argc == 2) {
                std::string uriUtf8 = WideToUtf8(std::wstring(argv[1]));
                auto parsed = drpolicy::parse_client_uri(uriUtf8);
                if (!parsed.valid) {
                    LocalFree(argv);
                    MessageBoxW(nullptr,
                        L"The connection link is not valid.\n\n"
                        L"Accepted formats:\n"
                        L"  deskrally-client://connect/<UUID>\n"
                        L"  deskrally-client://attended/<UUID>\n"
                        L"  deskrally-client://tenant/<organization>/connect/<UUID>\n"
                        L"  deskrally-client://tenant/<organization>/attended/<UUID>\n"
                        L"  deskrally-client://tenant/<organization>/console\n\n"
                        L"Launch DeskRally from the Start menu to open the console normally.",
                        L"DeskRally \x2013 Invalid Launch Parameter",
                        MB_OK | MB_ICONERROR);
                    return 1;
                }
                startupResult = parsed;
                fromLink = true;
            } else if (argc != 1) {
                LocalFree(argv);
                MessageBoxW(nullptr,
                    L"DeskRally Client does not accept multiple command-line arguments.\n\n"
                    L"Launch DeskRally from the Start menu to open the console normally.",
                    L"DeskRally \x2013 Invalid Launch Parameter",
                    MB_OK | MB_ICONERROR);
                return 1;
            }
            LocalFree(argv);
        }

        if (!fromLink) {
            // See drpolicy::choose_startup_tenant. Cancel exits without creating a profile.
            drpolicy::Tenant last = drpolicy::Tenant::main();
            const bool hasLast = ReadLastOrganization(last);
            drpolicy::Tenant chosen = drpolicy::Tenant::main();
            if (drpolicy::choose_startup_tenant(hasLast, last, chosen) == drpolicy::StartupChoice::Ask &&
                !PromptForOrganization(nullptr, chosen)) {
                return 0;
            }
            startupResult.tenant = chosen;
        }
        selectedTenant = startupResult.tenant;
        initialUrl = Utf8ToWide(drpolicy::build_initial_url(startupResult));
    }
#endif

#ifdef SMOKE_TEST
    wchar_t modulePath[32768]{};
    DWORD moduleLength = GetModuleFileNameW(nullptr, modulePath, 32768);
    if (!moduleLength || moduleLength == 32768) return 1;
    g_smokeDirectory = std::wstring(modulePath, moduleLength);
    g_smokeDirectory.resize(g_smokeDirectory.find_last_of(L"\\/"));
    std::wstring logPath = g_smokeDirectory + L"\\smoke-test.log";
    _wfopen_s(&g_smokeLog, logPath.c_str(), L"w");
    if (!g_smokeLog) g_smokeLog = stderr;
    SmokeLog("[smoke] DeskRally smoke test starting\n");
#endif

    HWND hwnd = CreateMainWindow();
    if (!hwnd) {
#ifdef SMOKE_TEST
        SmokeLog("[smoke] FAIL CreateMainWindow\n");
#endif
        return 1;
    }

    // Set initial window title with tenant label.
    SetWindowTextW(hwnd, (std::wstring(kWindowTitle) + L" \x2013 " +
                          TenantLabel(selectedTenant)).c_str());

    // Attach Organization menu (non-fatal if allocation or attachment fails).
    {
        HMENU hMenu = CreateOrgMenu(selectedTenant);
        if (hMenu && !SetMenu(hwnd, hMenu))
            DestroyMenu(hMenu); // SetMenu failed; reclaim to avoid leak
    }

    g_mainState = std::make_shared<WindowState>();
    g_mainState->hwnd           = hwnd;
    g_mainState->selectedTenant = selectedTenant;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA,
        reinterpret_cast<LONG_PTR>(new std::shared_ptr<WindowState>(g_mainState)));
    // The tab strip (docs-tabs-design.md). TCS_FOCUSNEVER keeps keyboard focus in the page.
    g_mainState->tab_ctrl = CreateWindowExW(0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_FOCUSNEVER | TCS_SINGLELINE,
        0, 0, 100, 24, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kTabControlId)), g_hInstance, nullptr);
    if (g_mainState->tab_ctrl) {
        SendMessageW(g_mainState->tab_ctrl, WM_SETFONT,
            reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        SetWindowSubclass(g_mainState->tab_ctrl, TabStripSubclass, 1, reinterpret_cast<DWORD_PTR>(hwnd));
    }
    LayoutTabs(g_mainState);
    SetTimer(hwnd, kSsoTimerId, 1000, nullptr);
#ifndef SMOKE_TEST
    g_updater = std::make_unique<drupdate::Updater>(hwnd);
    SetTimer(hwnd, 20, 60 * 60 * 1000, nullptr);
    if (drupdate::Updater::IsDailyCheckDue()) {
        if (g_updater->CheckForUpdate()) drupdate::Updater::RecordCheckTime();
    }
#endif
#ifdef SMOKE_TEST
    if (!g_ssoSmoke) SetTimer(hwnd, 2, kSmokeTimeoutMs, nullptr);
#endif

    g_initialUrl = initialUrl;
#ifdef SMOKE_TEST
    if (g_ssoSmoke) {
        // Bypass startup authentication UI; this mode tests navigation in the isolated smoke profile.
        StartProfile(g_mainState);
    } else
#endif
    {
    g_helloSetting = ReadHelloSetting(selectedTenant);
    UpdateHelloMenu(hwnd);
    if (g_helloSetting == drhello::Setting::Invalid) {
        ShowError(hwnd, L"Could not read the Windows Hello setting safely. Your saved profile was not opened.");
        SendMessageW(hwnd, WM_CLOSE, 0, 0);
    } else if (g_helloSetting == drhello::Setting::Enabled) {
        // Show the window and bring it forward BEFORE asking Windows Hello. The prompt is owned by
        // this window (RequestVerificationForWindowAsync), and it used to be requested while the
        // window was still hidden (it is first shown once the profile opens). Face and fingerprint
        // sign-in engage only for a prompt in front of a visible owner; PIN entry still worked, so
        // biometrics failed and forcing PIN succeeded (the operator's work PC, 2026-10-19).
        ShowWindow(hwnd, SW_SHOWMAXIMIZED);
        UpdateWindow(hwnd);
        SetForegroundWindow(hwnd);
        StartHello(g_mainState, HelloPurpose::Startup);
    } else {
        StartProfile(g_mainState);
    }

    }

    MSG m{};
    BOOL messageResult = 1;
    bool lostQuit = false;
    for (;;) {
        if (g_mainWindowGone) {
            // Never block again once the main window is gone: dispatch what the teardown queued,
            // exit on its WM_QUIT as before, and exit anyway if that quit was lost.
            const auto drained = drlifetime::drain_after_main_window(
                [&m](bool& isQuit, uintptr_t& code) {
                    if (!PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) return false;
                    isQuit = m.message == WM_QUIT;
                    code = m.wParam;
                    return true;
                },
                [&m] { TranslateMessage(&m); DispatchMessageW(&m); },
                kMaxExitDrainMessages);
            if (drained.quit) {
                messageResult = 0;
            } else {
                lostQuit = true;
                RecordLostQuitExit(drained.dispatched, drained.bounded);
            }
            break;
        }
        // Never block inside GetMessageW: it runs SENT messages' handlers while waiting, and one of
        // them can destroy the window (and lose the quit) without ever returning here. Peek, recheck
        // the latch, and only then wait; the wait itself runs no handlers.
        if (!PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
            if (g_mainWindowGone) continue;
            MsgWaitForMultipleObjectsEx(0, nullptr, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            continue;
        }
        if (m.message == WM_QUIT) {
            messageResult = 0;
            break;
        }
        // Tab shortcuts when the main window or the strip has focus (the page's own focus path is
        // AcceleratorKeyPressed): the same exact decoder; matched keys are consumed, others dispatched.
        if ((m.message == WM_KEYDOWN || m.message == WM_SYSKEYDOWN) && g_mainState &&
            (m.hwnd == g_mainState->hwnd || m.hwnd == g_mainState->tab_ctrl)) {
            drtabs::KeyInput k;
            k.key_down = m.message == WM_KEYDOWN;
            k.system_key = m.message == WM_SYSKEYDOWN;
            k.repeat = (m.lParam & (1 << 30)) != 0;
            k.vk = static_cast<unsigned>(m.wParam);
            k = KeyModifiersNow(k);
            if (PostTabShortcut(g_mainState->hwnd, drtabs::decode(k))) continue;
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_mainState && IsWindow(g_mainState->hwnd)) SendMessageW(g_mainState->hwnd, WM_CLOSE, 0, 0);
#ifdef SMOKE_TEST
    if (g_ssoSmoke) SsoSmokeCompleteResponse(hwnd);
#endif
    g_updater.reset();
    g_mainState.reset();
    g_env.Reset();
    if (messageResult < 0) return 1;

#ifdef SMOKE_TEST
    SmokeLog("[smoke] message loop exited wParam=%d smokeResult=%d lostQuit=%d\n",
             (int)m.wParam, g_smokeResult, lostQuit ? 1 : 0);
    if (g_smokeLog && g_smokeLog != stderr) fclose(g_smokeLog);
    return g_smokeResult;
#else
    return lostQuit ? g_exitCode : (int)m.wParam;
#endif
}
