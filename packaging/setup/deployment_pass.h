// Deployment passes and agent release attestations (docs/48 C, "Formats"): the C++/CNG verifier
// used by the generic Setup (MODE=PASS). One of three implementations of one format; the Go
// reference is control-plane/deployment_pass.go and the Rust one crates/agent-core/src/
// deployment_pass.rs. All three must give the expected result for every vector in
// control-plane/testdata/deployment-pass-vectors.json (test_pass_vectors.cpp runs them here).
//
// Check order is part of the contract: key > envelope > signature > body > validity.
//
// Header-only, so the vector test compiles exactly the code Setup compiles. Byte values are
// written numerically where a backslash or quote would otherwise appear in a literal.
#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dp {

enum class Kind { Ok, Key, Envelope, Signature, Body, Validity };

inline const char* KindName(Kind k) {
    switch (k) {
    case Kind::Ok: return "ok";
    case Kind::Key: return "key";
    case Kind::Envelope: return "envelope";
    case Kind::Signature: return "signature";
    case Kind::Body: return "body";
    case Kind::Validity: return "validity";
    }
    return "?";
}

struct Result {
    Kind kind = Kind::Ok;
    std::string reason;
    bool ok() const { return kind == Kind::Ok; }
};

inline Result Fail(Kind k, const std::string& why) { return Result{k, why}; }

constexpr size_t kMaxSignedObject = 4096;
constexpr size_t kMaxSignedBody = 2048;
constexpr long long kPassMaxLifetime = 31LL * 24 * 3600;
constexpr long long kReleaseMaxLifetime = 396LL * 24 * 3600;
constexpr long long kClockSkew = 5 * 60;
constexpr long long kMaxMsiSize = 2147483647LL;

// "DRPASS1\0" and "DRREL1\0": the NUL is part of the signed bytes.
static const unsigned char kPassDomain[] = {'D', 'R', 'P', 'A', 'S', 'S', '1', 0};
static const unsigned char kReleaseDomain[] = {'D', 'R', 'R', 'E', 'L', '1', 0};

constexpr unsigned char kQuote = 0x22;
constexpr unsigned char kBackslash = 0x5C;

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

inline bool IsLowerHex(const std::string& s) {
    for (unsigned char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

inline std::string HexDecode(const std::string& s) {  // s already checked: even, lowercase hex
    std::string out;
    auto v = [](unsigned char c) { return (c <= '9') ? c - '0' : c - 'a' + 10; };
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<char>((v(s[i]) << 4) | v(s[i + 1])));
    }
    return out;
}

// Strict UTF-8 (as Go's utf8.Valid): no overlongs, no surrogates, nothing above U+10FFFF.
inline bool ValidUtf8(const std::string& s) {
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { i++; continue; }
        int len;
        uint32_t cp;
        if (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07; }
        else return false;
        if (i + len > n) return false;
        for (int k = 1; k < len; k++) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF))) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;
        i += len;
    }
    return true;
}

inline void AppendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out.push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// Standard padded base64, decoded only if re-encoding reproduces the text exactly (the one
// canonical spelling: no whitespace, no missing or extra padding, no nonzero padding bits).
inline bool Base64Canonical(const std::string& in, std::string& out) {
    static const char kAlpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (in.empty() || in.size() % 4 != 0) return false;
    auto val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    for (size_t i = 0; i < in.size(); i += 4) {
        const bool last = i + 4 == in.size();
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            unsigned char c = static_cast<unsigned char>(in[i + k]);
            if (c == '=' && last && k >= 2) { v[k] = 0; pad++; continue; }
            if (pad > 0) return false;  // data after padding
            v[k] = val(c);
            if (v[k] < 0) return false;
        }
        uint32_t w = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
        out.push_back(static_cast<char>((w >> 16) & 0xFF));
        if (pad < 2) out.push_back(static_cast<char>((w >> 8) & 0xFF));
        if (pad < 1) out.push_back(static_cast<char>(w & 0xFF));
    }
    std::string re;
    for (size_t i = 0; i < out.size(); i += 3) {
        uint32_t w = static_cast<unsigned char>(out[i]) << 16;
        const size_t rem = out.size() - i;
        if (rem > 1) w |= static_cast<unsigned char>(out[i + 1]) << 8;
        if (rem > 2) w |= static_cast<unsigned char>(out[i + 2]);
        re.push_back(kAlpha[(w >> 18) & 63]);
        re.push_back(kAlpha[(w >> 12) & 63]);
        re.push_back(rem > 1 ? kAlpha[(w >> 6) & 63] : '=');
        re.push_back(rem > 2 ? kAlpha[w & 63] : '=');
    }
    return re == in;
}

// ---------------------------------------------------------------------------------------------
// The strict JSON reader: the same closed grammar as Go's strictJSON (objects of known keys,
// strings, integers, arrays of strings). Keys match byte-for-byte after unescaping; an unknown,
// repeated or missing key is an error; integers are plain JSON integers.
// ---------------------------------------------------------------------------------------------

class Strict {
public:
    explicit Strict(const std::string& s) : b_(s) {}
    std::string why;

    void Ws() {
        while (i_ < b_.size()) {
            unsigned char c = static_cast<unsigned char>(b_[i_]);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i_++;
            else return;
        }
    }
    bool AtEnd() { Ws(); return i_ == b_.size(); }

    bool Str(std::string& out) {
        out.clear();
        if (i_ >= b_.size() || static_cast<unsigned char>(b_[i_]) != kQuote) return Err("expected a string");
        i_++;
        for (;;) {
            if (i_ >= b_.size()) return Err("unterminated string");
            unsigned char c = static_cast<unsigned char>(b_[i_]);
            if (c == kQuote) { i_++; return true; }
            if (c < 0x20) return Err("control character in string");
            if (c != kBackslash) { out.push_back(static_cast<char>(c)); i_++; continue; }
            i_++;
            if (i_ >= b_.size()) return Err("unterminated string");
            unsigned char e = static_cast<unsigned char>(b_[i_++]);
            switch (e) {
            case kQuote: case kBackslash: case '/': out.push_back(static_cast<char>(e)); break;
            case 'b': out.push_back(0x08); break;
            case 'f': out.push_back(0x0C); break;
            case 'n': out.push_back(0x0A); break;
            case 'r': out.push_back(0x0D); break;
            case 't': out.push_back(0x09); break;
            case 'u': {
                uint32_t r;
                if (!Hex4(r)) return false;
                if (r >= 0xD800 && r <= 0xDFFF) {
                    // Only a high surrogate immediately followed by a low-surrogate escape.
                    if (r >= 0xDC00 || i_ + 1 >= b_.size() || static_cast<unsigned char>(b_[i_]) != kBackslash || b_[i_ + 1] != 'u')
                        return Err("lone surrogate escape");
                    i_ += 2;
                    uint32_t lo;
                    if (!Hex4(lo)) return false;
                    if (lo < 0xDC00 || lo > 0xDFFF) return Err("lone surrogate escape");
                    r = 0x10000 + ((r - 0xD800) << 10) + (lo - 0xDC00);
                }
                AppendUtf8(out, r);
                break;
            }
            default: return Err("invalid escape");
            }
        }
    }

    bool Integer(long long& v) {
        const size_t start = i_;
        if (i_ < b_.size() && b_[i_] == '-') i_++;
        const size_t digits = i_;
        while (i_ < b_.size() && b_[i_] >= '0' && b_[i_] <= '9') i_++;
        const size_t n = i_ - digits;
        if (n == 0 || (n > 1 && b_[digits] == '0')) { i_ = start; return Err("expected an integer"); }
        if (digits > start && n == 1 && b_[digits] == '0') { i_ = start; return Err("negative zero is not an integer"); }
        if (i_ < b_.size() && (b_[i_] == '.' || b_[i_] == 'e' || b_[i_] == 'E')) { i_ = start; return Err("expected an integer, not a fraction or exponent"); }
        if (n > 18) { i_ = start; return Err("integer out of range"); }  // every in-range field fits in 18 digits
        long long x = 0;
        for (size_t k = digits; k < i_; k++) x = x * 10 + (b_[k] - '0');
        v = (digits > start) ? -x : x;
        return true;
    }

    bool StrArray(std::vector<std::string>& out) {
        out.clear();
        if (i_ >= b_.size() || b_[i_] != '[') return Err("expected an array");
        i_++;
        for (bool first = true;; first = false) {
            Ws();
            if (i_ >= b_.size()) return Err("unexpected end of input");
            if (b_[i_] == ']') { i_++; return true; }
            if (!first) {
                if (b_[i_] != ',') return Err("expected ',' or ']'");
                i_++;
                Ws();
            }
            std::string s;
            if (!Str(s)) return false;
            out.push_back(s);
        }
    }

    // field(key) is called positioned at each value and must consume it.
    template <class F>
    bool Object(const std::vector<std::string>& keys, F field) {
        Ws();
        if (i_ >= b_.size() || b_[i_] != '{') return Err("expected an object");
        i_++;
        std::vector<bool> seen(keys.size(), false);
        for (bool first = true;; first = false) {
            Ws();
            if (i_ >= b_.size()) return Err("unexpected end of input");
            if (b_[i_] == '}' && first) { i_++; break; }
            if (!first) {
                if (b_[i_] == '}') { i_++; break; }
                if (b_[i_] != ',') return Err("expected ',' or '}'");
                i_++;
                Ws();
            }
            std::string key;
            if (!Str(key)) return false;
            size_t idx = keys.size();
            for (size_t k = 0; k < keys.size(); k++) {
                if (keys[k] == key) idx = k;
            }
            if (idx == keys.size()) return Err("unknown field " + key);
            if (seen[idx]) return Err("duplicate field " + key);
            seen[idx] = true;
            Ws();
            if (i_ >= b_.size() || b_[i_] != ':') return Err("expected ':'");
            i_++;
            Ws();
            if (!field(key)) return false;
        }
        for (size_t k = 0; k < keys.size(); k++) {
            if (!seen[k]) return Err("missing field " + keys[k]);
        }
        return true;
    }

private:
    bool Err(const std::string& w) { if (why.empty()) why = w; return false; }
    bool Hex4(uint32_t& r) {
        if (i_ + 4 > b_.size()) return Err("short unicode escape");
        r = 0;
        for (int k = 0; k < 4; k++) {
            unsigned char c = static_cast<unsigned char>(b_[i_ + k]);
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else return Err("bad unicode escape");
            r = (r << 4) | static_cast<uint32_t>(v);
        }
        i_ += 4;
        return true;
    }
    const std::string& b_;
    size_t i_ = 0;
};

// ---------------------------------------------------------------------------------------------
// Field rules (mirroring the Go reference exactly)
// ---------------------------------------------------------------------------------------------

inline bool CheckOrigin(const std::string& s) {
    const std::string scheme = "https://";
    if (s.compare(0, scheme.size(), scheme) != 0) return false;
    std::string host = s.substr(scheme.size());
    std::string port;
    bool hasPort = false;
    const size_t colon = host.find(':');
    if (colon != std::string::npos) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
        hasPort = true;
        if (port.empty()) return false;
    }
    if (host.empty() || host.size() > 253) return false;
    size_t start = 0;
    for (;;) {
        const size_t dot = host.find('.', start);
        const std::string label = host.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (unsigned char c : label) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        }
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    if (hasPort) {
        for (unsigned char c : port) {
            if (c < '0' || c > '9') return false;
        }
        if (port[0] == '0' || port.size() > 5) return false;
        const long n = std::stol(port);
        if (n > 65535 || n == 443) return false;
    }
    return true;
}

inline bool CheckIssuedTo(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    static const char kExtra[] = " .,&'()-";
    for (unsigned char c : s) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        (c != 0 && std::strchr(kExtra, c) != nullptr);
        if (!ok) return false;
    }
    return true;
}

inline bool CheckUuid(const std::string& s) {
    if (s.size() != 36) return false;
    for (size_t i = 0; i < s.size(); i++) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

inline bool CheckProductVersion(const std::string& s) {
    const unsigned long limits[3] = {255, 255, 65535};
    size_t start = 0;
    for (int f = 0; f < 3; f++) {
        const size_t dot = s.find('.', start);
        if ((f < 2) != (dot != std::string::npos)) return false;
        const std::string p = s.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
        if (p.empty() || p.size() > 5) return false;
        for (unsigned char c : p) {
            if (c < '0' || c > '9') return false;
        }
        if (p.size() > 1 && p[0] == '0') return false;
        if (std::stoul(p) > limits[f]) return false;
        start = dot + 1;
    }
    return true;
}

inline int CompareProductVersions(const std::string& a, const std::string& b) {
    size_t ia = 0, ib = 0;
    for (int f = 0; f < 3; f++) {
        const size_t da = a.find('.', ia), db = b.find('.', ib);
        const unsigned long x = std::stoul(a.substr(ia, da == std::string::npos ? std::string::npos : da - ia));
        const unsigned long y = std::stoul(b.substr(ib, db == std::string::npos ? std::string::npos : db - ib));
        if (x != y) return x < y ? -1 : 1;
        ia = da + 1;
        ib = db + 1;
    }
    return 0;
}

inline bool CheckBracedGuid(const std::string& s) {
    if (s.size() != 38 || s.front() != '{' || s.back() != '}') return false;
    for (size_t i = 1; i < 37; i++) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (i == 9 || i == 14 || i == 19 || i == 24) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

inline long long DaysFromCivil(long long y, long long m, long long d) {
    y -= m <= 2;
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const long long yoe = y - era * 400;
    const long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

// Exactly YYYY-MM-DDTHH:MM:SSZ, a real date, as Unix seconds.
inline bool ParseTime(const std::string& s, long long& out) {
    if (s.size() != 20) return false;
    for (size_t i = 0; i < 20; i++) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        bool ok;
        switch (i) {
        case 4: case 7: ok = c == '-'; break;
        case 10: ok = c == 'T'; break;
        case 13: case 16: ok = c == ':'; break;
        case 19: ok = c == 'Z'; break;
        default: ok = c >= '0' && c <= '9';
        }
        if (!ok) return false;
    }
    auto num = [&](size_t a, size_t z) { long long v = 0; for (size_t k = a; k < z; k++) v = v * 10 + (s[k] - '0'); return v; };
    const long long y = num(0, 4), mo = num(5, 7), d = num(8, 10), h = num(11, 13), mi = num(14, 16), se = num(17, 19);
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    const int dim[12] = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (mo < 1 || mo > 12 || d < 1 || d > dim[mo - 1] || h > 23 || mi > 59 || se > 59) return false;
    out = DaysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

inline std::string FormatTime(long long t) {
    long long days = t / 86400, secs = t % 86400;
    if (secs < 0) { secs += 86400; days--; }
    const long long z = days + 719468;
    const long long era = (z >= 0 ? z : z - 146096) / 146097;
    const long long doe = z - era * 146097;
    const long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const long long mp = (5 * doy + 2) / 153;
    const long long d = doy - (153 * mp + 2) / 5 + 1;
    const long long m = mp < 10 ? mp + 3 : mp - 9;
    const long long y = yoe + era * 400 + (m <= 2);
    char buf[32];
    sprintf_s(buf, "%04lld-%02lld-%02lldT%02lld:%02lld:%02lldZ", y, m, d, secs / 3600, secs % 3600 / 60, secs % 60);
    return buf;
}

// ---------------------------------------------------------------------------------------------
// Verified values
// ---------------------------------------------------------------------------------------------

struct DeploymentPass {
    std::string pass_id, issued_to, origin, grant_issuer_pubkey, min_agent_version;
    bool for_setup = false, for_support = false;
    long long issued_at = 0, expires_at = 0;
    std::string HostPort() const { return origin.substr(8); }  // origin is "https://" + host[:port]
    std::string ControlPlaneUrl() const { return origin + "/cp"; }
    std::string SignalingUrl() const { return "wss://" + HostPort() + "/ws"; }
};

struct AgentRelease {
    std::string msi_sha256, product_version, product_code, upgrade_code, arch;
    long long msi_size = 0, issued_at = 0, expires_at = 0;
};

// ---------------------------------------------------------------------------------------------
// CNG: key import, SHA-256, signature
// ---------------------------------------------------------------------------------------------

class RootKey {
public:
    RootKey() = default;
    RootKey(const RootKey&) = delete;
    RootKey& operator=(const RootKey&) = delete;
    ~RootKey() {
        if (key_) BCryptDestroyKey(key_);
        if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
    }
    // 130 lowercase hex: 04 || X || Y. CNG validates the point on import (no
    // BCRYPT_NO_KEY_VALIDATION), so an off-curve point or the point at infinity is refused.
    Result Load(const std::string& hex) {
        if (hex.size() != 130 || !IsLowerHex(hex)) return Fail(Kind::Key, "root key must be 130 lowercase hex characters");
        const std::string raw = HexDecode(hex);
        if (static_cast<unsigned char>(raw[0]) != 0x04) return Fail(Kind::Key, "root key must be an uncompressed point");
        if (BCryptOpenAlgorithmProvider(&alg_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) return Fail(Kind::Key, "no ECDSA P-256 provider");
        std::vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
        auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
        hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        hdr->cbKey = 32;
        std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), raw.data() + 1, 64);
        if (BCryptImportKeyPair(alg_, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key_, blob.data(), static_cast<ULONG>(blob.size()), 0) < 0) {
            key_ = nullptr;
            return Fail(Kind::Key, "root key is not a valid P-256 point");
        }
        return Result{};
    }
    BCRYPT_KEY_HANDLE handle() const { return key_; }

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_KEY_HANDLE key_ = nullptr;
};

inline bool Sha256(const std::vector<std::pair<const void*, size_t>>& parts, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
              BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) >= 0;
    for (const auto& p : parts) {
        if (ok) ok = BCryptHashData(h, static_cast<PUCHAR>(const_cast<void*>(p.first)), static_cast<ULONG>(p.second), 0) >= 0;
    }
    if (ok) ok = BCryptFinishHash(h, out, 32, 0) >= 0;
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// r or s outside [1, n-1] (big-endian compare against the P-256 group order).
inline bool ScalarInRange(const unsigned char* v) {
    static const unsigned char kN[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
    bool zero = true;
    for (int i = 0; i < 32; i++) {
        if (v[i] != 0) zero = false;
    }
    if (zero) return false;
    return std::memcmp(v, kN, 32) < 0;
}

// ---------------------------------------------------------------------------------------------
// Envelope + signature (checks 2 and 3)
// ---------------------------------------------------------------------------------------------

inline Result OpenSignedObject(const RootKey& root, const unsigned char* domain, size_t domainLen, const std::string& raw, std::string& body) {
    if (!root.handle()) return Fail(Kind::Key, "no root key");
    if (raw.size() > kMaxSignedObject) return Fail(Kind::Envelope, "signed object over 4096 bytes");
    if (!ValidUtf8(raw)) return Fail(Kind::Envelope, "signed object is not valid UTF-8");
    Strict p(raw);
    long long format = 0;
    std::string bodyB64, sigHex;
    const bool parsed = p.Object({"format", "body", "sig"}, [&](const std::string& k) {
        if (k == "format") return p.Integer(format);
        if (k == "body") return p.Str(bodyB64);
        return p.Str(sigHex);
    });
    if (!parsed) return Fail(Kind::Envelope, "envelope JSON: " + p.why);
    if (!p.AtEnd()) return Fail(Kind::Envelope, "trailing data after the envelope");
    if (format != 1) return Fail(Kind::Envelope, "unsupported format");
    if (bodyB64.empty()) return Fail(Kind::Envelope, "empty body");
    if (!Base64Canonical(bodyB64, body)) return Fail(Kind::Envelope, "body is not canonical standard padded base64");
    if (sigHex.size() != 128 || !IsLowerHex(sigHex)) return Fail(Kind::Envelope, "sig must be 128 lowercase hex characters");
    const std::string sig = HexDecode(sigHex);
    const auto* r = reinterpret_cast<const unsigned char*>(sig.data());
    if (!ScalarInRange(r) || !ScalarInRange(r + 32)) return Fail(Kind::Signature, "r or s is outside [1, n-1]");
    unsigned char digest[32];
    if (!Sha256({{domain, domainLen}, {body.data(), body.size()}}, digest)) return Fail(Kind::Signature, "SHA-256 failed");
    // CNG takes the 64-byte r || s directly; no low-S rule.
    if (BCryptVerifySignature(root.handle(), nullptr, digest, 32, const_cast<PUCHAR>(r), 64, 0) < 0)
        return Fail(Kind::Signature, "signature does not verify under the root key for this purpose");
    return Result{};
}

// Size, no control bytes (so only spaces as whitespace), UTF-8.
inline Result CheckBodyBytes(const std::string& body) {
    if (body.size() > kMaxSignedBody) return Fail(Kind::Body, "body over 2048 bytes");
    for (unsigned char c : body) {
        if (c < 0x20 || c == 0x7F) return Fail(Kind::Body, "control byte in body");
    }
    if (!ValidUtf8(body)) return Fail(Kind::Body, "body is not valid UTF-8");
    return Result{};
}

inline Result CheckWindow(long long issued, long long expires, long long now) {
    if (now < issued - kClockSkew) return Fail(Kind::Validity, "not valid yet");
    if (now >= expires) return Fail(Kind::Validity, "expired");
    return Result{};
}

inline Result Lifetime(long long issued, long long expires, long long max) {
    if (expires <= issued) return Fail(Kind::Body, "expires_at must be after issued_at");
    if (expires - issued > max) return Fail(Kind::Body, "lifetime exceeds the maximum");
    return Result{};
}

// ---------------------------------------------------------------------------------------------
// Bodies (check 4) and the full verifications
// ---------------------------------------------------------------------------------------------

inline Result ParsePassBody(const std::string& body, DeploymentPass& out) {
    Result r = CheckBodyBytes(body);
    if (!r.ok()) return r;
    Strict p(body);
    std::string purpose, issuedAt, expiresAt;
    long long v = 0;
    std::vector<std::string> uses;
    DeploymentPass d;
    const bool parsed = p.Object(
        {"purpose", "v", "pass_id", "issued_to", "origin", "grant_issuer_pubkey", "uses", "min_agent_version", "issued_at", "expires_at"},
        [&](const std::string& k) {
            if (k == "purpose") return p.Str(purpose);
            if (k == "v") return p.Integer(v);
            if (k == "pass_id") return p.Str(d.pass_id);
            if (k == "issued_to") return p.Str(d.issued_to);
            if (k == "origin") return p.Str(d.origin);
            if (k == "grant_issuer_pubkey") return p.Str(d.grant_issuer_pubkey);
            if (k == "uses") return p.StrArray(uses);
            if (k == "min_agent_version") return p.Str(d.min_agent_version);
            if (k == "issued_at") return p.Str(issuedAt);
            return p.Str(expiresAt);
        });
    if (!parsed) return Fail(Kind::Body, "pass body JSON: " + p.why);
    if (!p.AtEnd()) return Fail(Kind::Body, "trailing data after the body");
    if (purpose != "deskrally-deployment-pass") return Fail(Kind::Body, "purpose");
    if (v != 1) return Fail(Kind::Body, "v");
    if (!CheckUuid(d.pass_id)) return Fail(Kind::Body, "pass_id");
    if (!CheckIssuedTo(d.issued_to)) return Fail(Kind::Body, "issued_to");
    if (!CheckOrigin(d.origin)) return Fail(Kind::Body, "origin");
    if (d.grant_issuer_pubkey.size() != 64 || !IsLowerHex(d.grant_issuer_pubkey)) return Fail(Kind::Body, "grant_issuer_pubkey");
    if (uses.empty()) return Fail(Kind::Body, "uses is empty");
    for (const auto& u : uses) {
        bool* slot = u == "setup" ? &d.for_setup : u == "support" ? &d.for_support : nullptr;
        if (!slot) return Fail(Kind::Body, "uses: unknown value");
        if (*slot) return Fail(Kind::Body, "uses: listed twice");
        *slot = true;
    }
    if (!CheckProductVersion(d.min_agent_version)) return Fail(Kind::Body, "min_agent_version");
    if (!ParseTime(issuedAt, d.issued_at)) return Fail(Kind::Body, "issued_at");
    if (!ParseTime(expiresAt, d.expires_at)) return Fail(Kind::Body, "expires_at");
    r = Lifetime(d.issued_at, d.expires_at, kPassMaxLifetime);
    if (!r.ok()) return r;
    out = d;
    return Result{};
}

inline Result ParseReleaseBody(const std::string& body, AgentRelease& out) {
    Result r = CheckBodyBytes(body);
    if (!r.ok()) return r;
    Strict p(body);
    std::string purpose, issuedAt, expiresAt;
    long long v = 0;
    AgentRelease d;
    const bool parsed = p.Object(
        {"purpose", "v", "msi_sha256", "msi_size", "product_version", "product_code", "upgrade_code", "arch", "issued_at", "expires_at"},
        [&](const std::string& k) {
            if (k == "purpose") return p.Str(purpose);
            if (k == "v") return p.Integer(v);
            if (k == "msi_sha256") return p.Str(d.msi_sha256);
            if (k == "msi_size") return p.Integer(d.msi_size);
            if (k == "product_version") return p.Str(d.product_version);
            if (k == "product_code") return p.Str(d.product_code);
            if (k == "upgrade_code") return p.Str(d.upgrade_code);
            if (k == "arch") return p.Str(d.arch);
            if (k == "issued_at") return p.Str(issuedAt);
            return p.Str(expiresAt);
        });
    if (!parsed) return Fail(Kind::Body, "release body JSON: " + p.why);
    if (!p.AtEnd()) return Fail(Kind::Body, "trailing data after the body");
    if (purpose != "deskrally-agent-release") return Fail(Kind::Body, "purpose");
    if (v != 1) return Fail(Kind::Body, "v");
    if (d.msi_sha256.size() != 64 || !IsLowerHex(d.msi_sha256)) return Fail(Kind::Body, "msi_sha256");
    if (d.msi_size < 1 || d.msi_size > kMaxMsiSize) return Fail(Kind::Body, "msi_size");
    if (!CheckProductVersion(d.product_version)) return Fail(Kind::Body, "product_version");
    if (!CheckBracedGuid(d.product_code)) return Fail(Kind::Body, "product_code");
    if (!CheckBracedGuid(d.upgrade_code)) return Fail(Kind::Body, "upgrade_code");
    if (d.arch != "x64") return Fail(Kind::Body, "arch");
    if (!ParseTime(issuedAt, d.issued_at)) return Fail(Kind::Body, "issued_at");
    if (!ParseTime(expiresAt, d.expires_at)) return Fail(Kind::Body, "expires_at");
    r = Lifetime(d.issued_at, d.expires_at, kReleaseMaxLifetime);
    if (!r.ok()) return r;
    out = d;
    return Result{};
}

inline Result VerifyPass(const RootKey& root, const std::string& raw, long long now, DeploymentPass& out) {
    std::string body;
    Result r = OpenSignedObject(root, kPassDomain, sizeof(kPassDomain), raw, body);
    if (!r.ok()) return r;
    DeploymentPass d;
    r = ParsePassBody(body, d);
    if (!r.ok()) return r;
    r = CheckWindow(d.issued_at, d.expires_at, now);
    if (!r.ok()) return r;
    out = d;
    return Result{};
}

inline Result VerifyRelease(const RootKey& root, const std::string& raw, long long now, AgentRelease& out) {
    std::string body;
    Result r = OpenSignedObject(root, kReleaseDomain, sizeof(kReleaseDomain), raw, body);
    if (!r.ok()) return r;
    AgentRelease d;
    r = ParseReleaseBody(body, d);
    if (!r.ok()) return r;
    r = CheckWindow(d.issued_at, d.expires_at, now);
    if (!r.ok()) return r;
    out = d;
    return Result{};
}

// product_version >= min_agent_version.
inline bool PassAdmitsRelease(const DeploymentPass& p, const AgentRelease& r) {
    return CompareProductVersions(r.product_version, p.min_agent_version) >= 0;
}

// The current time as Unix seconds (the guest's clock: best-effort, docs/48 "Clock limitation").
inline long long UnixNow() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return static_cast<long long>(u.QuadPart / 10000000ULL) - 11644473600LL;
}

}  // namespace dp
