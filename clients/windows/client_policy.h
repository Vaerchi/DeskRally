#pragma once
// Navigation and permission policy for DeskRally native client.
// Pure C++ / STL – no Win32, no COM, no WebView2 headers.

#include <string>
#include <string_view>
#include <utility>
#include <algorithm>
#include <cctype>

#ifndef DESKRALLY_TENANT_ZONE
#define DESKRALLY_TENANT_ZONE "deskrally.com"
#endif

namespace drpolicy {

// ── Tenants ─────────────────────────────────────────────────────────────────
//
// The client knows no organization by name. A tenant is its slug, and its only
// trusted origin is https://<slug>.deskrally.com. Each organization's users see
// only the organizations they open on that PC; a built-in list would show every
// customer the others' names.
//
// A slug is one DNS label: 1-63 of [a-z0-9-], starting and ending alphanumeric.
// The parent zone is ours, so every such name either is a DeskRally console or
// does not resolve. Names used for infrastructure in that zone are reserved
// here AND by the control plane (tenantslug.go), so no tenant can claim one.
// "updater" is reserved for a different reason: a tenant's settings live in
// HKCU\Software\DeskRally\Client\<slug>, registry names ignore case, and the
// updater already owns ...\Client\Updater (client_update.cpp kRegPath).

static constexpr std::string_view kTenantZone = "." DESKRALLY_TENANT_ZONE;
static constexpr std::string_view kMainSlug   = "main";

inline bool is_reserved_slug(std::string_view s) {
    static constexpr std::string_view kReserved[] = {
        "www", "turn", "stun", "api", "app", "admin", "download", "downloads",
        "update", "updates", "updater", "mail", "status", "relay", "signal", "signaling",
    };
    for (auto r : kReserved) if (s == r) return true;
    return false;
}

// Exact grammar; no case folding, so callers normalise first.
inline bool valid_tenant_slug(std::string_view s) {
    if (s.empty() || s.size() > 63) return false;
    for (char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    if (s.front() == '-' || s.back() == '-') return false;
    return !is_reserved_slug(s);
}

class Tenant;
inline bool make_tenant(std::string_view slug, Tenant& out);

// Construct only through make_tenant (or main()), so every Tenant holds a valid slug.
class Tenant {
public:
    static Tenant main() { return Tenant(std::string(kMainSlug)); }
    const std::string& slug() const { return slug_; }
    bool operator==(const Tenant& o) const { return slug_ == o.slug_; }
    bool operator!=(const Tenant& o) const { return slug_ != o.slug_; }
private:
    explicit Tenant(std::string s) : slug_(std::move(s)) {}
    std::string slug_;
    friend bool make_tenant(std::string_view slug, Tenant& out);
};

inline bool make_tenant(std::string_view slug, Tenant& out) {
    if (!valid_tenant_slug(slug)) return false;
    out = Tenant(std::string(slug));
    return true;
}

inline std::string tenant_host(const Tenant& t) {
    return t.slug() + std::string(kTenantZone);
}

inline std::string tenant_origin(const Tenant& t) {
    return "https://" + tenant_host(t);
}

// Window-title label: the slug with its first letter capitalised ("Main", "Loam").
inline std::string tenant_label(const Tenant& t) {
    std::string s = t.slug();
    if (!s.empty() && s[0] >= 'a' && s[0] <= 'z') s[0] = static_cast<char>(s[0] - 'a' + 'A');
    return s;
}

#ifdef SMOKE_TEST
static constexpr std::string_view kSmokeTestHost = "deskrally-smoke.test";
#endif

// ── URL parsing helpers ──────────────────────────────────────────────────────

static inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

struct ParsedUrl {
    std::string scheme;
    std::string userinfo;
    bool        has_userinfo = false; // true even if userinfo is empty string (@ present)
    std::string host;
    std::string port;
    bool        valid = false;
};

static inline ParsedUrl parse_url(const std::string& url) {
    ParsedUrl p;

    // Reject backslash, ASCII control characters, and DEL anywhere in the URL.
    for (unsigned char c : url) {
        if (c == '\\' || c < 0x20 || c == 0x7f) return p;
    }

    // scheme
    auto cs = url.find("://");
    if (cs == std::string::npos) return p;
    p.scheme = to_lower(url.substr(0, cs));
    std::string rest = url.substr(cs + 3);

    // path starts at first '/' or '?' or '#'
    auto path_pos = rest.find_first_of("/?#");
    std::string authority = (path_pos == std::string::npos) ? rest : rest.substr(0, path_pos);

    // userinfo – flag presence of '@' even with empty userinfo
    auto at = authority.find('@');
    if (at != std::string::npos) {
        p.has_userinfo = true;
        p.userinfo     = authority.substr(0, at);
        authority      = authority.substr(at + 1);
    }

    // IPv6 literal
    if (!authority.empty() && authority[0] == '[') {
        auto cb = authority.find(']');
        if (cb == std::string::npos) return p;
        p.host = to_lower(authority.substr(0, cb + 1));
        std::string after = authority.substr(cb + 1);
        if (!after.empty() && after[0] == ':') p.port = after.substr(1);
    } else {
        auto col = authority.rfind(':');
        if (col != std::string::npos) {
            p.host = to_lower(authority.substr(0, col));
            p.port = authority.substr(col + 1);
        } else {
            p.host = to_lower(authority);
        }
    }
    p.valid = true;
    return p;
}

// ── Policy decisions ─────────────────────────────────────────────────────────

enum class NavResult   { Allow, Deny };
enum class PopupResult { Allow, Deny };

// Permitted only for the exact trusted origin of the selected process tenant
// (https, exact host, no userinfo, default/443 port).
inline NavResult check_navigation(const std::string& uri, const Tenant& tenant) {
    if (uri == "about:blank") return NavResult::Deny; // main frame must be trusted

    auto p = parse_url(uri);
    if (!p.valid)              return NavResult::Deny;
    if (p.scheme != "https")   return NavResult::Deny;
    if (p.has_userinfo)        return NavResult::Deny; // reject even empty userinfo (@host)
    if (!p.port.empty() && p.port != "443") return NavResult::Deny;

#ifdef SMOKE_TEST
    if (p.host == kSmokeTestHost) return NavResult::Allow;
#endif

    if (p.host != tenant_host(tenant)) return NavResult::Deny;
    return NavResult::Allow;
}

// Only about:blank is allowed for popups, and only with a user gesture.
inline PopupResult check_popup(const std::string& uri, bool has_user_gesture) {
    if (!has_user_gesture)    return PopupResult::Deny;
    if (uri != "about:blank") return PopupResult::Deny;
    return PopupResult::Allow;
}

enum class PermKind {
    ClipboardRead,
    Microphone,
    Camera,
    Geolocation,
    Notifications,
    Other,
};

enum class PermResult {
    AllowWithConsent,
    Deny,
};

inline PermResult check_permission(PermKind kind) {
    if (kind == PermKind::ClipboardRead) return PermResult::AllowWithConsent;
    return PermResult::Deny;
}

// ── Custom protocol URI parser (deskrally-client://) ─────────────────────────
//
// Legacy format (maps to the main tenant):
//   deskrally-client://connect/<UUID>[/]
//   deskrally-client://attended/<UUID>[/]
//
// Strict format:
//   deskrally-client://tenant/<slug>/{connect|attended}/<UUID>[/]
//   deskrally-client://tenant/<slug>/console[/]
// <slug> is any valid_tenant_slug after lowercasing.
//
// UUID must be exactly 36 chars in 8-4-4-4-12 hexadecimal form.
// Rejects: backslash, control chars (0x00-0x1F) and DEL (0x7F), percent-encoding,
//          userinfo (@), query (?), fragment (#), port (:) in authority, extra path
//          segments, invalid or reserved slugs, malformed UUID, or overlong input.

struct ClientUriResult {
    enum class Kind { Connect, Attended, Console };
    Kind        kind   = Kind::Connect;
    Tenant      tenant = Tenant::main();
    std::string uuid;  // exactly 36 lowercase hex chars with hyphens; empty for Console
    bool        valid  = false;
};

inline ClientUriResult parse_client_uri(const std::string& uri) {
    ClientUriResult r;
    // Longest valid strict URI: 26 ("deskrally-client://tenant/") + 63 (slug)
    // + 10 ("/attended/") + 36 (UUID) + 1 (trailing slash) = 136.
    static constexpr size_t kMaxLen = 136;
    if (uri.size() > kMaxLen) return r;

    for (unsigned char c : uri) {
        if (c == '\\' || c < 0x20 || c == 0x7f || c == '%') return r;
    }

    static constexpr std::string_view kScheme = "deskrally-client://";
    if (uri.size() < kScheme.size()) return r;
    if (to_lower(uri.substr(0, kScheme.size())) != kScheme) return r;

    std::string rest = uri.substr(kScheme.size());

    for (char c : rest) {
        if (c == '@' || c == '?' || c == '#') return r;
    }

    // Authority (action) ends at the first '/'.
    auto slash = rest.find('/');
    if (slash == std::string::npos) return r;

    std::string action_raw = rest.substr(0, slash);
    std::string path       = rest.substr(slash + 1);

    for (char c : action_raw) {
        if (c == ':') return r; // no port
    }
    std::string action = to_lower(action_raw);

    // UUID validator used for both legacy and strict paths.
    auto try_uuid = [](const std::string& s, std::string& out) -> bool {
        if (s.size() != 36) return false;
        for (int i = 0; i < 36; ++i) {
            char c = s[i];
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') return false;
            } else {
                if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
            }
        }
        std::string tmp = s;
        std::transform(tmp.begin(), tmp.end(), tmp.begin(),
                       [](unsigned char x){ return static_cast<char>(std::tolower(x)); });
        out = tmp;
        return true;
    };

    // ── Legacy format: authority is "connect" or "attended" → main tenant ──
    if (action == "connect" || action == "attended") {
        if (!path.empty() && path.back() == '/') path.pop_back();
        if (path.find('/') != std::string::npos) return r;
        if (path.find('?') != std::string::npos || path.find('#') != std::string::npos) return r;
        if (!try_uuid(path, r.uuid)) return r;
        r.kind   = (action == "connect") ? ClientUriResult::Kind::Connect
                                         : ClientUriResult::Kind::Attended;
        r.tenant = Tenant::main();
        r.valid  = true;
        return r;
    }

    // ── Strict format: authority must be "tenant" ─────────────────────────
    if (action != "tenant") return r;

    // path is now: <slug>/{connect|attended|console}[/<UUID>][/]
    auto slash2 = path.find('/');
    if (slash2 == std::string::npos) return r;

    std::string tname     = to_lower(path.substr(0, slash2));
    std::string remaining = path.substr(slash2 + 1);

    Tenant t = Tenant::main();
    if (!make_tenant(tname, t)) return r;

    auto slash3 = remaining.find('/');
    std::string sub_action;
    std::string uuid_part;

    if (slash3 == std::string::npos) {
        sub_action = to_lower(remaining);
        uuid_part  = "";
    } else {
        sub_action = to_lower(remaining.substr(0, slash3));
        uuid_part  = remaining.substr(slash3 + 1);
    }

    if (sub_action == "console") {
        if (!uuid_part.empty()) return r; // extra segment after console
        r.kind   = ClientUriResult::Kind::Console;
        r.tenant = t;
        r.valid  = true;
        return r;
    }

    if (sub_action == "connect" || sub_action == "attended") {
        if (slash3 == std::string::npos) return r; // UUID required
        if (!uuid_part.empty() && uuid_part.back() == '/') uuid_part.pop_back();
        if (uuid_part.find('/') != std::string::npos) return r;
        if (!try_uuid(uuid_part, r.uuid)) return r;
        r.kind   = (sub_action == "connect") ? ClientUriResult::Kind::Connect
                                             : ClientUriResult::Kind::Attended;
        r.tenant = t;
        r.valid  = true;
        return r;
    }

    return r; // unknown sub-action
}

// ── Organization typed by the user ───────────────────────────────────────────
//
// Accepts "loam", "Loam", "loam.deskrally.com" or "https://loam.deskrally.com[/...]"
// (an https:// prefix is stripped, so "https://loam" also means loam). Surrounding
// whitespace is ignored. Anything else, including another domain, userinfo, a port
// or an invalid/reserved slug, is refused.
inline bool parse_org_input(const std::string& raw, Tenant& out) {
    if (raw.size() > 253) return false;
    size_t b = 0, e = raw.size();
    while (b < e && (raw[b] == ' ' || raw[b] == '	')) ++b;
    while (e > b && (raw[e - 1] == ' ' || raw[e - 1] == '	')) --e;
    std::string s = to_lower(raw.substr(b, e - b));
    if (s.rfind("https://", 0) == 0) {
        s = s.substr(8);
        auto end = s.find_first_of("/?#");
        if (end != std::string::npos) s = s.substr(0, end);
    }
    if (s.size() > kTenantZone.size() &&
        s.compare(s.size() - kTenantZone.size(), kTenantZone.size(), kTenantZone) == 0)
        s = s.substr(0, s.size() - kTenantZone.size());
    return make_tenant(s, out);
}

// ── Start-menu launch: which organization ────────────────────────────────────
//
// No link given. Use the organization this Windows user last signed in to from this
// app; otherwise ask. Existing profile folders are deliberately NOT evidence: 0.5
// and older opened Main on every Start-menu launch, and any launch link creates a
// folder before its host is known to work, so a folder says nothing about which
// organization the user belongs to. The first 0.6 launch therefore asks once.
enum class StartupChoice { Use, Ask };

inline StartupChoice choose_startup_tenant(bool has_last, const Tenant& last, Tenant& out) {
    if (has_last) { out = last; return StartupChoice::Use; }
    return StartupChoice::Ask;
}

// ── URL builder ──────────────────────────────────────────────────────────────
//
// Builds the HTTPS initial URL from a valid parsed ClientUriResult.
// The UUID in r is already validated as lowercase hex with correct hyphen positions;
// no further encoding is needed.
// The organization's console page: what the first tab opens for a plain launch, and what every NEW
// tab opens. Never the deskrally-client:// launch URI, which the navigation filter turns into a new
// PROCESS rather than a page.
inline std::string console_url(const Tenant& t) {
    return tenant_origin(t) + "/console";
}

inline std::string build_initial_url(const ClientUriResult& r) {
    std::string host = tenant_host(r.tenant);
    switch (r.kind) {
        case ClientUriResult::Kind::Console:
            return console_url(r.tenant);
        case ClientUriResult::Kind::Connect:
            return "https://" + host + "/console?device=" + r.uuid;
        case ClientUriResult::Kind::Attended:
            return "https://" + host + "/console?attended=" + r.uuid;
    }
    return "https://" + host + "/console"; // unreachable; satisfies compilers
}

// ── Sign-in evidence ──────────────────────────────────────────────────────────
// Is this cookie (as WebView2's cookie manager reports it for https://<host>/) the control plane's
// session cookie, set by the server for exactly this host? The control plane names it
// "__Host-cp_session" whenever it sets Secure cookies, which every production deployment does
// (control-plane/auth.go cookieName), and "cp_session" only otherwise. 0.6.0 matched the plain name
// alone and so never recognised a production sign-in. Both names must still be host-only (domain
// equal to the host), Path "/", Secure and HttpOnly; page script cannot create an HttpOnly cookie,
// so a document.cookie counterfeit never matches.
inline bool is_session_cookie(const std::string& name, const std::string& value, const std::string& domain,
                              const std::string& host, const std::string& path, bool http_only, bool secure) {
    if (name != "__Host-cp_session" && name != "cp_session") return false;
    return !value.empty() && !host.empty() && domain == host && path == "/" && http_only && secure;
}

} // namespace drpolicy
