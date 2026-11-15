// DeskRally desktop auto-updater implementation.
// Requires: winhttp.lib wintrust.lib crypt32.lib version.lib bcrypt.lib

#ifndef UNICODE
#  define UNICODE
#endif
#ifndef _UNICODE
#  define _UNICODE
#endif
#ifndef WINVER
#  define WINVER 0x0A00
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <winhttp.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <bcrypt.h>

// VerQueryValueW / GetFileVersionInfoW
#include <winver.h>

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <functional>

#include "client_update.h"
#include "update_policy.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")

namespace drupdate {

// ── Install-dir constants ──────────────────────────────────────────────────
// Fixed per-user install path.  Never derived from environment at runtime
// in a way that can be influenced by an attacker.
static constexpr wchar_t kInstallSubdir[]  = L"Programs\\DeskRally Client";
static constexpr wchar_t kInstalledExe[]   = L"DeskRallyClient.exe";
static constexpr wchar_t kLockFile[]       = L"running.lock";
static constexpr wchar_t kUpdaterMutex[]   = L"Local\\DeskRallyUpdaterSingle";
// Registry path for updater persistence.
static constexpr wchar_t kRegPath[]        = L"Software\\DeskRally\\Client\\Updater";
static constexpr wchar_t kRegLastCheck[]   = L"LastCheckTime";   // QWORD (FILETIME)
static constexpr wchar_t kRegPendingSha[]  = L"PendingSha256";   // REG_SZ
static constexpr wchar_t kRegPendingPath[] = L"PendingPath";     // REG_SZ
static constexpr wchar_t kRegPendingVer[]  = L"PendingVersion";  // REG_SZ

// Manifest host / path (matched against WinHTTP server name in request).
static std::wstring WideIdentity(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0);
    if (!size) return {};
    std::wstring result(size, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), result.data(), size)) return {};
    return result;
}
static const std::wstring kManifestHostW = WideIdentity(kManifestHost);
static const std::wstring kExpectedPublisherW = WideIdentity(kExpectedPublisher);
static constexpr wchar_t kUpdatesUnconfigured[] = L"updates are not configured in this build";

// WinHTTP takes the hostname and port separately (the policy pin includes both).
static HINTERNET ConnectUpdateHost(HINTERNET session, const wchar_t* host) {
    if (!host || !*host) return nullptr;
    const std::wstring url = L"https://" + std::wstring(host);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) return nullptr;
    const std::wstring name(parts.lpszHostName, parts.dwHostNameLength);
    return WinHttpConnect(session, name.c_str(), parts.nPort, 0);
}
static constexpr wchar_t kManifestPathW[]  = L"/download/client/manifest.json";

static constexpr DWORD kConnectTimeoutMs   = 10000;
static constexpr DWORD kSendTimeoutMs      = 10000;
static constexpr DWORD kReceiveTimeoutMs   = 30000;
static constexpr ULONGLONG kWorkerWaitMs = 7ULL * 24 * 60 * 60 * 1000;

// ── Helpers ────────────────────────────────────────────────────────────────

static std::wstring GetInstallDir() {
    wchar_t local[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local)))
        return {};
    return std::wstring(local) + L"\\" + kInstallSubdir;
}

static std::wstring GetInstalledExePath() {
    auto dir = GetInstallDir();
    if (dir.empty()) return {};
    return dir + L"\\" + kInstalledExe;
}

static std::wstring GetLockFilePath() {
    auto dir = GetInstallDir();
    if (dir.empty()) return {};
    return dir + L"\\" + kLockFile;
}

// True if the path (or any ancestor up to the volume root) is a reparse point.
static bool HasReparseAncestor(const std::wstring& path) {
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\') return true;
    std::wstring cur = path;
    for (;;) {
        WIN32_FILE_ATTRIBUTE_DATA d{};
        if (GetFileAttributesExW(cur.c_str(), GetFileExInfoStandard, &d)) {
            if (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return true;
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) {
            return true;
        }
        std::wstring parent;
        auto slash = cur.find_last_of(L"\\/");
        if (slash == std::wstring::npos || slash == 0) break;
        if (slash == 2 && cur[1] == L':') {
            if (cur.size() == 3) break;
            parent = cur.substr(0, 3);
        } else parent = cur.substr(0, slash);
        if (parent == cur) break;
        cur = parent;
    }
    return false;
}

// Returns the current exe's full path (lowercase for comparison).
static std::wstring GetCurrentExePath() {
    wchar_t buf[32768] = {};
    DWORD len = GetModuleFileNameW(nullptr, buf, 32768);
    if (!len || len == 32768) return {};
    std::wstring s(buf, len);
    for (auto& c : s) c = static_cast<wchar_t>(towlower(static_cast<wint_t>(c)));
    return s;
}

// True if the running exe is at the fixed installed path (case-insensitive).
static bool IsInstalledPath() {
    auto installed = GetInstalledExePath();
    if (installed.empty()) return false;
    auto running   = GetCurrentExePath();
    if (running.empty()) return false;
    // Normalize both to lowercase.
    std::wstring instLow = installed;
    for (auto& c : instLow) c = static_cast<wchar_t>(towlower(static_cast<wint_t>(c)));
    return running == instLow;
}

// Compute SHA-256 of a file; returns hex string or empty on error.
static std::string Sha256File(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string result;

    auto cleanup = [&]() {
        if (hash) BCryptDestroyHash(hash);
        if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(h);
    };

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        { cleanup(); return {}; }

    DWORD hashLen = 0, cbResult = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cbResult, 0)))
        { cleanup(); return {}; }

    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0)))
        { cleanup(); return {}; }

    const DWORD kBuf = 65536;
    std::vector<BYTE> buf(kBuf);
    DWORD read = 0;
    for (;;) {
        if (!ReadFile(h, buf.data(), kBuf, &read, nullptr)) { cleanup(); return {}; }
        if (!read) break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hash, buf.data(), read, 0)))
            { cleanup(); return {}; }
    }

    std::vector<BYTE> digest(hashLen);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(), hashLen, 0)))
        { cleanup(); return {}; }

    cleanup();

    // Convert to lowercase hex.
    result.reserve(hashLen * 2);
    static constexpr char kHex[] = "0123456789abcdef";
    for (BYTE b : digest) {
        result += kHex[b >> 4];
        result += kHex[b & 0xF];
    }
    return result;
}

// Read a file's version resource and return the numeric version as 64-bit
// packed (HIWORD(hi)=major, LOWORD(hi)=minor, HIWORD(lo)=patch, LOWORD(lo)=build).
// Returns 0 on failure.
static uint64_t GetFileNumericVersion(const std::wstring& path) {
    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!sz) return 0;
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(path.c_str(), 0, sz, buf.data())) return 0;
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffiSz = 0;
    if (!VerQueryValueW(buf.data(), L"\\",
            reinterpret_cast<LPVOID*>(&ffi), &ffiSz) || !ffi || ffiSz < sizeof(VS_FIXEDFILEINFO)) return 0;
    if (ffi->dwSignature != 0xFEEF04BD) return 0;
    return (static_cast<uint64_t>(ffi->dwFileVersionMS) << 32) |
            static_cast<uint64_t>(ffi->dwFileVersionLS);
}

// Read a string from the version resource (e.g. "OriginalFilename").
static std::wstring GetVersionString(const std::wstring& path, const wchar_t* name) {
    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!sz) return {};
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(path.c_str(), 0, sz, buf.data())) return {};
    // Try codepage 040904b0 (English/Unicode).
    std::wstring query = std::wstring(L"\\StringFileInfo\\040904b0\\") + name;
    wchar_t* val = nullptr; UINT valLen = 0;
    if (!VerQueryValueW(buf.data(), query.c_str(),
            reinterpret_cast<LPVOID*>(&val), &valLen) || !val) return {};
    return std::wstring(val, valLen > 0 && val[valLen - 1] == L'\0' ? valLen - 1 : valLen);
}

// Verify Authenticode signature + chain validity + publisher subject.
// Uses WinVerifyTrust (validates chain and timestamp).
static bool VerifyAuthenticode(const std::wstring& path, bool checkRevocation = true) {
    if (kExpectedPublisherW.empty()) return false;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    // The About dialog skips the online revocation fetch so it can never hang offline; updates
    // always check the whole chain.
    wd.fdwRevocationChecks = checkRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = checkRevocation ? WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT : WTD_CACHE_ONLY_URL_RETRIEVAL;
    const LONG result = WinVerifyTrust(nullptr, &action, &wd);
    bool accepted = false;
    // Inspect the signer Windows actually validated, before closing its state.
    // A currently-valid but untimestamped signature is deliberately insufficient.
    if (result == ERROR_SUCCESS) {
        auto* data = WTHelperProvDataFromStateData(wd.hWVTStateData);
        auto* signer = data ? WTHelperGetProvSignerFromChain(data, 0, FALSE, 0) : nullptr;
        if (signer && signer->dwError == 0 && signer->csCertChain > 0 &&
            signer->pasCertChain && signer->csCounterSigners > 0 && signer->pasCounterSigners &&
            signer->pasCounterSigners[0].dwError == 0) {
            PCCERT_CONTEXT cert = signer->pasCertChain[0].pCert;
            const DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
            const DWORD size = cert ? CertNameToStrW(cert->dwCertEncodingType,
                &cert->pCertInfo->Subject, flags, nullptr, 0) : 0;
            if (size > 1 && size < 4096) {
                std::vector<wchar_t> subject(size);
                if (CertNameToStrW(cert->dwCertEncodingType, &cert->pCertInfo->Subject,
                    flags, subject.data(), size) == size) {
                    accepted = std::wstring(subject.data()) ==
                        kExpectedPublisherW;
                }
            }
        }
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    return accepted;
}

// Full verification of a candidate binary:
//   1. Authenticode chain valid + publisher subject exact.
//   2. SHA-256 matches expected_sha256.
//   3. OriginalFilename == "DeskRallyClient.exe" in version resource.
//   4. ProductName == "DeskRally".
//   5. Numeric file version > installed version (monotonic guard).
//   6. No reparse ancestor.
static bool VerifyCandidate(const std::wstring& path,
                            const std::string& expected_sha256,
                            uint64_t installed_numeric_version,
                            const std::string& offered_version) {
    if (HasReparseAncestor(path)) return false;
    if (!VerifyAuthenticode(path)) return false;

    auto actual_sha = Sha256File(path);
    if (actual_sha.empty() || actual_sha != expected_sha256) return false;

    auto origFilename = GetVersionString(path, L"OriginalFilename");
    if (origFilename != L"DeskRallyClient.exe") return false;

    auto productName = GetVersionString(path, L"ProductName");
    if (productName != L"DeskRally") return false;

    auto candidate_ver = GetFileNumericVersion(path);
    auto offered = parse_version(offered_version);
    if (!offered.valid) return false;
    const uint64_t expected = (uint64_t(offered.major) << 48) |
        (uint64_t(offered.minor) << 32) | (uint64_t(offered.patch) << 16);
    if (candidate_ver == 0 || candidate_ver != expected) return false;
    // Monotonic: candidate must be strictly greater.
    if (candidate_ver <= installed_numeric_version) return false;

    return true;
}

// WinHTTP GET: returns body as string or empty on error.
// Enforces: HTTPS only, exact host, no redirects, bounded response size.
static std::string WinHttpGet(const wchar_t* host, const wchar_t* path,
                              uint64_t max_bytes) {
    if (!updates_configured() || !host || !*host) return {};
    HINTERNET session = WinHttpOpen(
        L"DeskRallyClient/0.7.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nullptr, nullptr, 0);
    if (!session) return {};

    auto closeSession = [&]{ WinHttpCloseHandle(session); };

    HINTERNET conn = ConnectUpdateHost(session, host);
    if (!conn) { closeSession(); return {}; }

    HINTERNET req = WinHttpOpenRequest(conn, L"GET", path, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); closeSession(); return {}; }

    // Enforce no redirects.
    DWORD disableRedirect = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    if (!WinHttpSetOption(req, WINHTTP_OPTION_DISABLE_FEATURE, &disableRedirect, sizeof(disableRedirect))) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); closeSession(); return {};
    }

    // Timeouts.
    WinHttpSetTimeouts(req, kConnectTimeoutMs, kConnectTimeoutMs,
                       kSendTimeoutMs, kReceiveTimeoutMs);

    auto closeAll = [&]{
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        closeSession();
    };

    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        closeAll(); return {};
    }

    // Verify HTTP 200.
    DWORD status = 0; DWORD statusSz = sizeof(status);
    if (!WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSz,
        WINHTTP_NO_HEADER_INDEX) || status != 200) {
        closeAll(); return {};
    }

    std::string body;
    body.reserve(static_cast<size_t>(std::min(max_bytes, uint64_t(4096))));
    DWORD avail = 0;
    const ULONGLONG deadline = GetTickCount64() + 120000;
    for (;;) {
        if (GetTickCount64() >= deadline || !WinHttpQueryDataAvailable(req, &avail)) { closeAll(); return {}; }
        if (!avail) break;
        if (body.size() + avail > max_bytes) { closeAll(); return {}; }
        size_t oldSz = body.size();
        body.resize(oldSz + avail);
        DWORD read = 0;
        if (!WinHttpReadData(req, body.data() + oldSz, avail, &read)) {
            closeAll(); return {};
        }
        if (!read) { closeAll(); return {}; }
        body.resize(oldSz + read);
    }

    closeAll();
    return body;
}

// Download binary to a staged file, streaming with bounded size.
static bool DownloadToFile(const wchar_t* host, const wchar_t* path,
                           const std::wstring& dest, uint64_t max_bytes) {
    if (!updates_configured() || !host || !*host) return {};
    HINTERNET session = WinHttpOpen(
        L"DeskRallyClient/0.7.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nullptr, nullptr, 0);
    if (!session) return false;

    HINTERNET conn = ConnectUpdateHost(session, host);
    if (!conn) { WinHttpCloseHandle(session); return false; }

    HINTERNET req = WinHttpOpenRequest(conn, L"GET", path, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return false; }

    DWORD disableRedirect = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    if (!WinHttpSetOption(req, WINHTTP_OPTION_DISABLE_FEATURE, &disableRedirect, sizeof(disableRedirect))) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return false;
    }
    WinHttpSetTimeouts(req, kConnectTimeoutMs, kConnectTimeoutMs, kSendTimeoutMs, kReceiveTimeoutMs);

    auto closeAll = [&]{
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
    };

    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        closeAll(); return false;
    }

    DWORD status = 0; DWORD statusSz = sizeof(status);
    if (!WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSz,
        WINHTTP_NO_HEADER_INDEX) || status != 200) {
        closeAll(); return false;
    }

    if (HasReparseAncestor(dest)) { closeAll(); return false; }
    HANDLE fh = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) { closeAll(); return false; }

    uint64_t total = 0;
    DWORD avail = 0;
    std::vector<BYTE> buf(65536);
    bool ok = true;
    const ULONGLONG deadline = GetTickCount64() + 120000;
    for (;;) {
        if (GetTickCount64() >= deadline || !WinHttpQueryDataAvailable(req, &avail)) { ok = false; break; }
        if (!avail) break;
        DWORD toRead = static_cast<DWORD>(
            std::min(static_cast<uint64_t>(avail), static_cast<uint64_t>(buf.size())));
        DWORD read = 0;
        if (!WinHttpReadData(req, buf.data(), toRead, &read) || !read) { ok = false; break; }
        total += read;
        if (total > max_bytes) { ok = false; break; }
        DWORD written = 0;
        if (!WriteFile(fh, buf.data(), read, &written, nullptr) || written != read) {
            ok = false; break;
        }
    }
    if (total != max_bytes || !FlushFileBuffers(fh)) ok = false;
    CloseHandle(fh);
    closeAll();
    if (!ok) DeleteFileW(dest.c_str());
    return ok;
}

// Generate a GUID-based unique filename in the install dir.
static std::wstring UniqueInstallPath(const wchar_t* prefix, const wchar_t* suffix) {
    auto dir = GetInstallDir();
    if (dir.empty()) return {};
    GUID g{}; if (FAILED(CoCreateGuid(&g))) return {};
    wchar_t guidStr[39]{};
    StringFromGUID2(g, guidStr, 39);
    // Strip braces: {xxxxxxxx-...} -> xxxxxxxx...
    std::wstring name(guidStr + 1, 36); // skip '{' and '}'
    // Remove hyphens.
    name.erase(std::remove(name.begin(), name.end(), L'-'), name.end());
    return dir + L"\\" + prefix + name + suffix;
}

// ── Registry helpers ───────────────────────────────────────────────────────

static void RegWriteQWord(HKEY root, const wchar_t* path, const wchar_t* name, uint64_t val) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(root, path, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExW(key, name, 0, REG_QWORD,
        reinterpret_cast<const BYTE*>(&val), sizeof(val));
    RegCloseKey(key);
}

static uint64_t RegReadQWord(HKEY root, const wchar_t* path, const wchar_t* name) {
    uint64_t val = 0; DWORD size = sizeof(val);
    if (RegGetValueW(root, path, name, RRF_RT_REG_QWORD, nullptr, &val, &size) != ERROR_SUCCESS || size != sizeof(val)) return 0;
    return val;
}

static void RegWriteStr(HKEY root, const wchar_t* path, const wchar_t* name, const std::wstring& val) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(root, path, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExW(key, name, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(val.c_str()),
        static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
}

static std::wstring RegReadStr(HKEY root, const wchar_t* path, const wchar_t* name) {
    wchar_t value[32768]{};
    DWORD size = sizeof(value);
    if (RegGetValueW(root, path, name, RRF_RT_REG_SZ, nullptr, value, &size) != ERROR_SUCCESS ||
        size < sizeof(wchar_t) || size > sizeof(value) || size % sizeof(wchar_t) != 0) return {};
    const size_t length = size / sizeof(wchar_t) - 1;
    if (value[length] != 0 || wcslen(value) != length) return {};
    return std::wstring(value, length);
}

// ── ClientLock ────────────────────────────────────────────────────────────

static HANDLE OpenClientLifetimeLock(const std::wstring& path) {
    if (path.empty() || HasReparseAncestor(path)) return INVALID_HANDLE_VALUE;
    return CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
}

ClientLock::ClientLock() {
    if (!IsInstalledPath()) { ready_ = true; return; }
    lock_file_ = OpenClientLifetimeLock(GetLockFilePath());
    ready_ = lock_file_ != INVALID_HANDLE_VALUE;
}

ClientLock::~ClientLock() {
    if (lock_file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(lock_file_);
        lock_file_ = INVALID_HANDLE_VALUE;
    }
}

// ── Updater::Impl ─────────────────────────────────────────────────────────

struct Updater::Impl {
    std::atomic<HWND> notify_hwnd;
    std::atomic<bool> canceled{false};
    mutable std::mutex state_mutex;
    UpdateState state;
    std::atomic<bool> running{false};

    explicit Impl(HWND h) : notify_hwnd(h) {}

    void SetState(const UpdateState& s) {
        {
            std::lock_guard<std::mutex> lk(state_mutex);
            state = s;
        }
        HWND hwnd = notify_hwnd.load();
        if (!canceled.load() && hwnd && IsWindow(hwnd))
            PostMessageW(hwnd, WM_UPDATE_STATUS, 0, 0);
    }

    UpdateState GetState() const {
        std::lock_guard<std::mutex> lk(state_mutex);
        return state;
    }
};

// ── Updater ────────────────────────────────────────────────────────────────

Updater::Updater(HWND notify_hwnd) : impl_(std::make_shared<Impl>(notify_hwnd)) {}

Updater::~Updater() {
    impl_->notify_hwnd.store(nullptr);
    impl_->canceled.store(true);
}

UpdateState Updater::GetState() const {
    return impl_->GetState();
}

bool Updater::IsDailyCheckDue() {
    if (!updates_configured()) return false;
    uint64_t last = RegReadQWord(HKEY_CURRENT_USER, kRegPath, kRegLastCheck);
    if (last == 0) return true;
    FILETIME now_ft{};
    GetSystemTimeAsFileTime(&now_ft);
    uint64_t now64 = (static_cast<uint64_t>(now_ft.dwHighDateTime) << 32) | now_ft.dwLowDateTime;
    // 24 hours in 100ns intervals.
    static constexpr uint64_t k24h = 24ULL * 3600ULL * 10000000ULL;
    return now64 < last || now64 - last >= k24h;
}

void Updater::RecordCheckTime() {
    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
    uint64_t val = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    RegWriteQWord(HKEY_CURRENT_USER, kRegPath, kRegLastCheck, val);
}

struct FileHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit FileHandle(HANDLE value = INVALID_HANDLE_VALUE) : h(value) {}
    ~FileHandle() { if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
};

static HANDLE OpenWorkerLock();
static bool GeneratedPath(const std::wstring& path, const wchar_t* prefix);
static void CleanupPending(const std::wstring& keep);
static std::string NarrowAscii(const std::wstring& value);

// A staged release that is not newer than the installed one can never apply: the worker refuses it as
// a downgrade (code 4). That happens when the app is updated some other way after staging, e.g. a
// manual install of a newer build (dual-homed laptop, 2026-10-21: 0.8.1 staged under a hand-installed
// 0.8.2). Forget the record so CleanupPending removes its file, instead of keeping both forever.
// Caller holds the worker lock, so no worker is reading the record.
static void ForgetStalePending(uint64_t installedVer) {
    const auto staged = RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingPath);
    if (staged.empty() || !installedVer) return;
    const auto stagedVer = drupdate::parse_version(NarrowAscii(RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingVer)));
    Version installed;
    installed.major = static_cast<uint32_t>((installedVer >> 48) & 0xFFFF);
    installed.minor = static_cast<uint32_t>((installedVer >> 32) & 0xFFFF);
    installed.patch = static_cast<uint32_t>((installedVer >> 16) & 0xFFFF);
    installed.valid = true;
    if (stagedVer.valid && version_newer_than(stagedVer, installed)) return;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegPath, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegDeleteValueW(key, kRegPendingPath); RegDeleteValueW(key, kRegPendingSha);
        RegDeleteValueW(key, kRegPendingVer); RegCloseKey(key);
    }
}

bool Updater::CheckForUpdate() {
    if (!updates_configured()) {
        UpdateState disabled;
        disabled.status = UpdateStatus::Failed;
        disabled.error_message = kUpdatesUnconfigured;
        impl_->SetState(disabled);
        return false;
    }
    if (!IsInstalledPath()) return false;
    HANDLE activeWorker = OpenWorkerLock();
    if (activeWorker == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_SHARING_VIOLATION) {
            UpdateState ready; ready.status = UpdateStatus::Ready;
            ready.pending_version = RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingVer);
            impl_->SetState(ready); return true;
        }
        return false;
    }
    CloseHandle(activeWorker);
    if (impl_->running.exchange(true)) return true; // already running

    UpdateState checking;
    checking.status = UpdateStatus::Checking;
    impl_->SetState(checking);
    RecordCheckTime();

    // Capture what we need for the background thread.
    auto imp = impl_;
    auto installedVer = GetFileNumericVersion(GetInstalledExePath());

    std::thread([imp, installedVer]() {
        // Acquire single-updater mutex so multiple concurrent processes serialize.
        HANDLE updaterMutex = CreateMutexW(nullptr, FALSE, kUpdaterMutex);
        DWORD acquired = updaterMutex ? WaitForSingleObject(updaterMutex, 0) : WAIT_FAILED;
        if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED) {
            if (updaterMutex) CloseHandle(updaterMutex);
            UpdateState busy; busy.status = UpdateStatus::Failed;
            busy.error_message = L"Another DeskRally window is already preparing an update.";
            imp->SetState(busy); imp->running.store(false); return;
        }

        auto fail = [&](const wchar_t* msg) {
            UpdateState fs;
            fs.status = UpdateStatus::Failed;
            fs.error_message = msg;
            imp->SetState(fs);
            if (updaterMutex) { ReleaseMutex(updaterMutex); CloseHandle(updaterMutex); }
            imp->running.store(false);
        };

        // Serialize staging with application of a pending release across sessions.
        FileHandle stageLock(OpenWorkerLock());
        if (stageLock.h == INVALID_HANDLE_VALUE) { fail(L"Another updater is active."); return; }
        ForgetStalePending(installedVer);
        CleanupPending(RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingPath));

        // 1. Fetch manifest.
        auto manifestBody = WinHttpGet(kManifestHostW.c_str(), kManifestPathW, kMaxManifestBytes);
        if (manifestBody.empty()) { fail(L"Manifest fetch failed."); return; }

        auto manifest = parse_manifest(manifestBody);
        if (!manifest.valid) { fail(L"Manifest validation failed."); return; }
        const auto failedSha = RegReadStr(HKEY_CURRENT_USER, kRegPath, L"LastFailedSha256");
        if (std::wstring(manifest.sha256.begin(), manifest.sha256.end()) == failedSha) {
            fail(L"This release previously failed its startup check. Waiting for a newer release."); return;
        }

        if (!installedVer) { fail(L"Could not read the installed version."); return; }
        if (imp->canceled.load()) { fail(L"Update check canceled."); return; }
        // 2. Compare versions.
        auto candidateVer = parse_version(manifest.version);
        auto installedVerParsed = [&]() -> Version {
            // Derive installed version from the numeric resource version.
            Version v;
            if (!installedVer) return v;
            v.major = static_cast<uint32_t>((installedVer >> 48) & 0xFFFF);
            v.minor = static_cast<uint32_t>((installedVer >> 32) & 0xFFFF);
            v.patch = static_cast<uint32_t>((installedVer >> 16) & 0xFFFF);
            v.valid = true;
            return v;
        }();

        if (!version_newer_than(candidateVer, installedVerParsed)) {
            UpdateState ns;
            ns.status = UpdateStatus::NoUpdate;
            imp->SetState(ns);
            if (updaterMutex) { ReleaseMutex(updaterMutex); CloseHandle(updaterMutex); }
            imp->running.store(false);
            return;
        }

        // 3. Download.
        {
            UpdateState ds;
            ds.status = UpdateStatus::Downloading;
            imp->SetState(ds);
        }

        // Build download path on the configured origin.
        // The url field in the manifest is already validated to be exactly the expected
        // path.  We build the server-relative path from the fixed prefix.
        std::wstring stagePath = UniqueInstallPath(L"pending-", L".exe");
        if (stagePath.empty()) { fail(L"Could not generate stage path."); return; }

        // Extract server-relative path from the fully-validated manifest URL.
        // Format: https://<configured-host[:port]><path>
        std::string urlRelPrefix = "https://";
        urlRelPrefix += std::string(kManifestHost);
        std::string relPath = manifest.url.substr(urlRelPrefix.size());
        // Convert to wstring.
        int n = MultiByteToWideChar(CP_UTF8, 0, relPath.c_str(), -1, nullptr, 0);
        std::wstring relPathW(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, relPath.c_str(), -1, relPathW.data(), n);
        relPathW.resize(static_cast<size_t>(n - 1));

        if (!DownloadToFile(kManifestHostW.c_str(), relPathW.c_str(), stagePath, manifest.size)) {
            fail(L"Download failed.");
            return;
        }

        // 4. Verify the downloaded binary before recording anything.
        if (HasReparseAncestor(stagePath)) {
            DeleteFileW(stagePath.c_str());
            fail(L"Stage path has reparse ancestor.");
            return;
        }
        if (!VerifyCandidate(stagePath, manifest.sha256, installedVer, manifest.version)) {
            DeleteFileW(stagePath.c_str());
            fail(L"Downloaded binary failed verification.");
            return;
        }

        if (imp->canceled.load()) { DeleteFileW(stagePath.c_str()); fail(L"Update check canceled."); return; }
        // 5. Persist stage path and sha256 for the worker.
        RegWriteStr(HKEY_CURRENT_USER, kRegPath, kRegPendingPath, stagePath);
        RegWriteStr(HKEY_CURRENT_USER, kRegPath, kRegPendingSha,
            std::wstring(manifest.sha256.begin(), manifest.sha256.end()));
        RegWriteStr(HKEY_CURRENT_USER, kRegPath, kRegPendingVer,
            std::wstring(manifest.version.begin(), manifest.version.end()));

        CleanupPending(stagePath);
        CloseHandle(stageLock.h); stageLock.h = INVALID_HANDLE_VALUE;

        UpdateState ready;
        ready.status = UpdateStatus::Ready;
        ready.pending_version = std::wstring(manifest.version.begin(), manifest.version.end());
        imp->SetState(ready);

        if (updaterMutex) { ReleaseMutex(updaterMutex); CloseHandle(updaterMutex); }
        imp->running.store(false);
    }).detach();
    return true;
}

// Only updater-created basenames are accepted; never accept arbitrary CLI paths.
static bool GeneratedPath(const std::wstring& path, const wchar_t* prefix) {
    const auto dir = GetInstallDir();
    const std::wstring stem = dir + L"\\" + prefix;
    if (dir.empty() || path.size() != stem.size() + 32 + 4 ||
        _wcsnicmp(path.c_str(), stem.c_str(), stem.size()) != 0 ||
        path.substr(path.size()-4) != L".exe" || HasReparseAncestor(path)) return false;
    for (size_t i = stem.size(); i < stem.size()+32; ++i)
        if (!((path[i] >= L'0' && path[i] <= L'9') || (path[i] >= L'a' && path[i] <= L'f') ||
              (path[i] >= L'A' && path[i] <= L'F'))) return false;
    return true;
}


// Called only while holding update-worker.lock, so a worker cannot be using
// a stale staged file while it is removed. Never recurse or follow redirects.
static void CleanupPending(const std::wstring& keep) {
    const auto dir = GetInstallDir();
    WIN32_FIND_DATAW entry{};
    HANDLE find = FindFirstFileW((dir + L"\\pending-*.exe").c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        const auto path = dir + L"\\" + entry.cFileName;
        if (!(entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
            path != keep && GeneratedPath(path, L"pending-")) DeleteFileW(path.c_str());
    } while (FindNextFileW(find, &entry));
    FindClose(find);
}

static HANDLE OpenWorkerLock() {
    const auto path = GetInstallDir() + L"\\update-worker.lock";
    if (HasReparseAncestor(path)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
}

bool Updater::Apply() {
    if (!updates_configured()) return false;
    if (!IsInstalledPath() || GetState().status != UpdateStatus::Ready) return false;
    {
        FileHandle probe(OpenWorkerLock());
        if (probe.h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_SHARING_VIOLATION;
    }
    const auto target = GetInstalledExePath();
    const auto stage = RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingPath);
    if (target.empty() || HasReparseAncestor(target) || !GeneratedPath(stage, L"pending-")) return false;
    const auto worker = UniqueInstallPath(L"updater-", L".exe");
    if (!GeneratedPath(worker, L"updater-") || !CopyFileW(target.c_str(), worker.c_str(), TRUE)) return false;
    // Worker arguments carry neither a URL nor a filesystem destination.
    std::wstring command = L"\"" + worker + L"\" --update-worker";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(worker.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, GetInstallDir().c_str(), &startup, &process)) {
        DeleteFileW(worker.c_str()); return false;
    }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return true;
}

static bool StartupSelfTest(const std::wstring& target) {
    std::wstring command = L"\"" + target + L"\" --update-self-test";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, GetInstallDir().c_str(), &startup, &process)) return false;
    FileHandle thread(process.hThread), child(process.hProcess);
    if (WaitForSingleObject(child.h, 20000) != WAIT_OBJECT_0) {
        // This is exclusively our no-UI diagnostic child, never an app window.
        TerminateProcess(child.h, 1); WaitForSingleObject(child.h, 5000); return false;
    }
    DWORD code = 1;
    return GetExitCodeProcess(child.h, &code) && code == 0;
}

// The file transaction is independent of network/UI and exercised with real
// files plus failure-injected verification/startup checks in runtime tests.
static int ReplaceAndValidate(const std::wstring& target, const std::wstring& stage,
    const std::wstring& backup, const std::wstring& failed,
    const std::function<bool(const std::wstring&)>& verify,
    const std::function<bool(const std::wstring&)>& startup) {
    const auto oldHash = Sha256File(target);
    if (oldHash.empty() || HasReparseAncestor(target) || HasReparseAncestor(stage) ||
        HasReparseAncestor(backup) || HasReparseAncestor(failed)) return 8;
    // Make a verified backup before replacement; preserve it even if Windows
    // reports a partial rename failure. The last app may still be unloading its
    // image immediately after releasing the lifetime lock, so allow a short retry.
    if (!CopyFileW(target.c_str(), backup.c_str(), TRUE) || Sha256File(backup) != oldHash) return 8;
    bool replaced = false;
    for (int attempt = 0; attempt != 100; ++attempt) {
        if (ReplaceFileW(target.c_str(), stage.c_str(), nullptr, 0, nullptr, nullptr)) { replaced = true; break; }
        const DWORD error = GetLastError();
        if (error != ERROR_ACCESS_DENIED && error != ERROR_SHARING_VIOLATION) break;
        Sleep(50);
    }
    if (!replaced) {
        if (Sha256File(target) == oldHash) return 8;
        if (!MoveFileExW(backup.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ||
            Sha256File(target) != oldHash) return 10;
        return 9;
    }
    bool accepted = false;
    try { accepted = Sha256File(backup) == oldHash && verify(target) && startup(target); }
    catch (...) { accepted = false; }
    if (accepted) return 0;
    if (Sha256File(backup) != oldHash ||
        !ReplaceFileW(target.c_str(), backup.c_str(), failed.c_str(), 0, nullptr, nullptr) ||
        Sha256File(target) != oldHash) return 10;
    return 9;
}

static std::string NarrowAscii(const std::wstring& value) {
    std::string result;
    for (wchar_t c : value) {
        if (c < 0 || c > 127) return {};
        result.push_back(static_cast<char>(c));
    }
    return result;
}

// The worker's early outcomes (2-7) used to return without a trace: only a failure AFTER the swap began
// (8-10) wrote LastResult, so "it offered the update but never installed it" (a dual-homed laptop, 2026-10-21)
// left nothing to diagnose. Every outcome now records why, readable in Help > About and with
// collect-client-updater-state.ps1.
static const wchar_t* WorkerOutcome(int code) {
    switch (code) {
    // Code 1 is NOT recorded: it means this process was not a staged worker at all (wrong arguments or
    // not running as updater-*.exe), so it has no update to report on. update_runtime_test calls the
    // worker exactly that way, and recording it wrote into the build machine's own client registry.
    case 2: return L"Update not installed: another update worker is already running (code 2).";
    case 3: return L"Update not installed: the downloaded update record is invalid (code 3).";
    case 4: return L"Update not installed: the downloaded file failed verification (code 4).";
    case 5: return L"Update not installed: DeskRally stayed open, or its lock was unavailable (code 5).";
    case 6: return L"Update not installed: the server's current release changed; check again (code 6).";
    case 7: return L"Update not installed: the installed or downloaded file failed re-verification (code 7).";
    default: return nullptr;
    }
}

static int RunUpdateWorkerSteps(int argc, wchar_t** argv);

int RunUpdateWorker(int argc, wchar_t** argv) {
    const int result = RunUpdateWorkerSteps(argc, argv);
    if (const wchar_t* why = WorkerOutcome(result)) RegWriteStr(HKEY_CURRENT_USER, kRegPath, L"LastResult", why);
    return result;
}

static int RunUpdateWorkerSteps(int argc, wchar_t** argv) {
    if (!updates_configured()) return 1;
    if (argc != 2 || std::wstring(argv[1]) != L"--update-worker" ||
        !GeneratedPath(GetCurrentExePath(), L"updater-")) return 1;
    FileHandle workerLock(OpenWorkerLock());
    if (workerLock.h == INVALID_HANDLE_VALUE) return 2;
    const auto target = GetInstalledExePath();
    const auto stage = RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingPath);
    const auto shaWide = RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingSha);
    const auto versionWide = RegReadStr(HKEY_CURRENT_USER, kRegPath, kRegPendingVer);
    const auto sha = NarrowAscii(shaWide), version = NarrowAscii(versionWide);
    if (!GeneratedPath(stage, L"pending-") || HasReparseAncestor(target) || sha.size() != 64 ||
        !parse_version(version).valid) return 3;
    if (!VerifyCandidate(stage, sha, GetFileNumericVersion(target), version)) return 4;

    // The path is never renamed or deleted: existing and newly starting app
    // processes must coordinate on exactly the same file object.
    const auto lockPath = GetLockFilePath();
    if (HasReparseAncestor(lockPath)) return 5;
    FileHandle exclusive;
    const ULONGLONG deadline = GetTickCount64() + kWorkerWaitMs;
    while (GetTickCount64() < deadline) {
        exclusive.h = CreateFileW(lockPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (exclusive.h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_SHARING_VIOLATION) return 5;
        Sleep(1000);
    }
    if (exclusive.h == INVALID_HANDLE_VALUE) return 5;

    // Withdrawal of a release stops even an already downloaded pending update.
    const auto current = parse_manifest(WinHttpGet(kManifestHostW.c_str(), kManifestPathW, kMaxManifestBytes));
    if (!current.valid || current.version != version || current.sha256 != sha) return 6;
    const auto oldVersion = GetFileNumericVersion(target);
    const auto oldHash = Sha256File(target);
    if (!oldVersion || oldHash.empty() || !VerifyCandidate(stage, sha, oldVersion, version)) return 7;
    const auto backup = UniqueInstallPath(L"previous-", L".exe");
    const auto failed = UniqueInstallPath(L"failed-", L".exe");
    if (backup.empty() || failed.empty()) return 8;
    const int result = ReplaceAndValidate(target, stage, backup, failed,
        [&](const std::wstring& path) { return VerifyCandidate(path, sha, oldVersion, version); },
        StartupSelfTest);
    if (result != 0) {
        if (result == 9 || result == 10) RegWriteStr(HKEY_CURRENT_USER, kRegPath, L"LastFailedSha256", shaWide);
        RegWriteStr(HKEY_CURRENT_USER, kRegPath, L"LastResult",
            result == 9 ? L"Update failed; previous version restored." : L"Update could not complete; inspect retained backup.");
        return result;
    }
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegPath, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegDeleteValueW(key, kRegPendingPath); RegDeleteValueW(key, kRegPendingSha);
        RegDeleteValueW(key, kRegPendingVer); RegCloseKey(key);
    }
    RegWriteStr(HKEY_CURRENT_USER, kRegPath, L"LastResult", L"Installed " + versionWide);
    // Keep the prior executable for operator recovery. This per-user process
    // cannot register system-wide pending-reboot deletions; do not try to do so.
    return 0;
}

AboutInfo GetAboutInfo() {
    AboutInfo info;
    wchar_t module[32768]{};
    const DWORD len = GetModuleFileNameW(nullptr, module, 32768);
    if (len && len < 32768) {
        const std::wstring self(module, len);
        info.version = GetVersionString(self, L"FileVersion");
        info.publisher_verified = VerifyAuthenticode(self, /*checkRevocation=*/false);
    }
    info.publisher_pinned = !kExpectedPublisher.empty();
    const auto cn = kExpectedPublisherW.find(L"CN=");
    if (cn != std::wstring::npos) {
        bool quoted = false, escaped = false;
        size_t end = cn + 3;
        for (; end < kExpectedPublisherW.size(); ++end) {
            const wchar_t c = kExpectedPublisherW[end];
            if (escaped) { escaped = false; continue; }
            if (c == L'\\') { escaped = true; continue; }
            if (c == L'"') quoted = !quoted;
            if (c == L',' && !quoted) break;
        }
        info.publisher_name = kExpectedPublisherW.substr(cn + 3, end - cn - 3);
    }
    if (!updates_configured()) {
        info.last_result = kUpdatesUnconfigured;
        return info;
    }
    info.last_result = RegReadStr(HKEY_CURRENT_USER, kRegPath, L"LastResult");
    const uint64_t ft = RegReadQWord(HKEY_CURRENT_USER, kRegPath, kRegLastCheck);
    if (ft) {
        FILETIME utc{static_cast<DWORD>(ft & 0xFFFFFFFF), static_cast<DWORD>(ft >> 32)}, local{};
        SYSTEMTIME st{};
        if (FileTimeToLocalFileTime(&utc, &local) && FileTimeToSystemTime(&local, &st)) {
            wchar_t buf[64]{};
            swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
            info.last_check = buf;
        }
    }
    return info;
}

} // namespace drupdate
