#pragma once
// Pure update policy – no Win32, no WinHTTP.
// Manifest parsing, version comparison, URL validation.
// Testable without GUI or OS dependencies.

#include <string>
#include <string_view>
#include <cstdint>
#include <algorithm>
#include <cctype>

namespace drupdate {

// ── Constants ──────────────────────────────────────────────────────────────
#ifndef DESKRALLY_UPDATE_HOST
#define DESKRALLY_UPDATE_HOST ""
#endif
#ifndef DESKRALLY_UPDATE_PUBLISHER
#define DESKRALLY_UPDATE_PUBLISHER ""
#endif
static constexpr std::string_view kManifestHost = DESKRALLY_UPDATE_HOST;
static constexpr std::string_view kManifestPath       = "/download/client/manifest.json";
static constexpr std::string_view kReleasePathPrefix  = "/download/client/releases/";
static constexpr std::string_view kExpectedPublisher = DESKRALLY_UPDATE_PUBLISHER;
inline bool updates_configured() {
    return !kManifestHost.empty() && !kExpectedPublisher.empty();
}
static constexpr std::string_view kExpectedOrigFilename = "DeskRallyClient.exe";
static constexpr std::string_view kExpectedProductName  = "DeskRally";
// Hard cap: reject any binary > 32 MB offered by the manifest.
static constexpr uint64_t kMaxDownloadBytes = 32u * 1024u * 1024u;
// Manifest response must fit in 4 KB.
static constexpr size_t kMaxManifestBytes = 4096;

// ── Version ────────────────────────────────────────────────────────────────

struct Version {
    uint32_t major = 0, minor = 0, patch = 0;
    bool     valid = false;
};

// Parse "x.y.z" where each component is 0..65535 (Windows FILEVERSION range).
// No leading zeros on multi-digit components, no pre-release, no build metadata.
// Published PE FILEVERSION must be exactly x,y,z,0; the fourth field is always zero.
// Returns invalid Version on any error.
inline Version parse_version(const std::string& s) {
    Version v;
    // "65535.65535.65535" = 17 chars; reject longer strings early.
    if (s.empty() || s.size() > 17) return v;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.') return v;

    auto to_comp = [&](size_t beg, size_t end, uint32_t& out) -> bool {
        size_t len = end - beg;
        if (len == 0 || len > 5) return false;
        if (len > 1 && s[beg] == '0') return false; // leading zero
        uint32_t val = 0;
        for (size_t i = beg; i < end; ++i)
            val = val * 10u + static_cast<uint32_t>(s[i] - '0');
        if (val > 65535u) return false;
        out = val;
        return true;
    };

    size_t p1 = s.find('.');
    if (p1 == std::string::npos) return v;
    size_t p2 = s.find('.', p1 + 1);
    if (p2 == std::string::npos) return v;
    if (s.find('.', p2 + 1) != std::string::npos) return v; // 4th component

    if (!to_comp(0,       p1,       v.major)) return v;
    if (!to_comp(p1 + 1,  p2,       v.minor)) return v;
    if (!to_comp(p2 + 1,  s.size(), v.patch)) return v;
    v.valid = true;
    return v;
}

// True iff candidate is strictly greater than installed (both must be valid).
inline bool version_newer_than(const Version& candidate, const Version& installed) {
    if (!candidate.valid || !installed.valid) return false;
    if (candidate.major != installed.major) return candidate.major > installed.major;
    if (candidate.minor != installed.minor) return candidate.minor > installed.minor;
    return candidate.patch > installed.patch;
}

// ── Manifest ───────────────────────────────────────────────────────────────

struct Manifest {
    std::string version;
    std::string sha256;  // 64 lowercase hex chars
    uint64_t    size = 0;
    std::string url;
    bool        valid = false;
};

// Validate the binary URL is exactly the expected deterministic path for the
// given version and configured host[:port]. No redirects, query/fragment, or userinfo.
inline std::string expected_release_url_for_host(std::string_view host, const std::string& version) {
    if (host.empty() || !parse_version(version).valid) return {};
    return "https://" + std::string(host) + std::string(kReleasePathPrefix) +
        version + "/DeskRallyClient.exe";
}
inline std::string expected_release_url(const std::string& version) {
    if (!updates_configured()) return {};
    return expected_release_url_for_host(kManifestHost, version);
}
inline bool validate_release_url_for_host(std::string_view host,
        const std::string& url, const std::string& version) {
    const auto expected = expected_release_url_for_host(host, version);
    return !expected.empty() && url == expected;
}
inline bool validate_release_url(const std::string& url, const std::string& version) {
    return updates_configured() && validate_release_url_for_host(kManifestHost, url, version);
}
// Parse and validate a manifest JSON body.  Uses a strict bounded flat-object
// parser: exactly the four fields version/sha256/size/url, any key order,
// standard whitespace.  Rejects duplicates, unknown keys, escape sequences,
// control characters, malformed syntax, trailing content, and numeric size
// values with fractions, exponents, or leading zeros.
inline Manifest parse_manifest_for_host(std::string_view host, const std::string& json) {
    Manifest m;
    if (json.size() > kMaxManifestBytes) return m;

    const char* p   = json.data();
    const char* end = p + json.size();

    auto skip_ws = [&]() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
            ++p;
    };

    // Parse a quoted JSON string value.
    // Rejects backslash escapes and any control/DEL characters.
    auto parse_string = [&](std::string& out) -> bool {
        if (p >= end || *p != '"') return false;
        ++p;
        out.clear();
        while (p < end && *p != '"') {
            unsigned char c = static_cast<unsigned char>(*p);
            if (c == '\\' || c < 0x20 || c == 0x7f) return false;
            out += *p++;
        }
        if (p >= end) return false; // unterminated
        ++p; // consume closing '"'
        return true;
    };

    // Parse an unsigned integer.
    // Rejects leading zeros (except bare "0"), fractions, and exponents.
    auto parse_uint64 = [&](uint64_t& out) -> bool {
        if (p >= end || !std::isdigit(static_cast<unsigned char>(*p))) return false;
        if (*p == '0') {
            ++p;
            if (p < end && (std::isdigit(static_cast<unsigned char>(*p)) ||
                            *p == '.' || *p == 'e' || *p == 'E'))
                return false;
            out = 0;
            return true;
        }
        uint64_t val = 0;
        size_t digits = 0;
        while (p < end && std::isdigit(static_cast<unsigned char>(*p))) {
            val = val * 10u + static_cast<uint64_t>(*p++ - '0');
            if (++digits > 13) return false; // overflow guard
        }
        if (p < end && (*p == '.' || *p == 'e' || *p == 'E')) return false;
        out = val;
        return true;
    };

    skip_ws();
    if (p >= end || *p != '{') return m;
    ++p;

    bool seen_version = false, seen_sha256 = false,
         seen_size    = false, seen_url    = false;
    bool first = true;

    while (true) {
        skip_ws();
        if (p >= end) return m;
        if (*p == '}') { ++p; break; }

        if (!first) {
            if (*p != ',') return m;
            ++p;
            skip_ws();
        }
        first = false;

        std::string key;
        if (!parse_string(key)) return m;

        skip_ws();
        if (p >= end || *p != ':') return m;
        ++p;
        skip_ws();

        if (key == "version") {
            if (seen_version) return m;
            seen_version = true;
            if (!parse_string(m.version)) return m;
        } else if (key == "sha256") {
            if (seen_sha256) return m;
            seen_sha256 = true;
            if (!parse_string(m.sha256)) return m;
        } else if (key == "size") {
            if (seen_size) return m;
            seen_size = true;
            if (!parse_uint64(m.size)) return m;
        } else if (key == "url") {
            if (seen_url) return m;
            seen_url = true;
            if (!parse_string(m.url)) return m;
        } else {
            return m; // unknown key
        }
    }

    // Trailing content (beyond optional whitespace) is rejected.
    skip_ws();
    if (p != end) return m;

    if (!seen_version || !seen_sha256 || !seen_size || !seen_url) return m;

    // version must be a valid x.y.z triple (each component 0..65535).
    if (!parse_version(m.version).valid) return m;

    // sha256: exactly 64 lowercase hex chars.
    if (m.sha256.size() != 64) return m;
    for (char c : m.sha256)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return m;

    // size: non-zero, within cap.
    if (m.size == 0 || m.size > kMaxDownloadBytes) return m;

    // URL must match the deterministic release path.
    if (!validate_release_url_for_host(host, m.url, m.version)) return m;

    m.valid = true;
    return m;
}

inline Manifest parse_manifest(const std::string& json) {
    if (!updates_configured()) return {};
    return parse_manifest_for_host(kManifestHost, json);
}

} // namespace drupdate
