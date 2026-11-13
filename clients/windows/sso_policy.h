#pragma once
// Main-frame navigation exception ONLY. Permissions and protocol spawning must
// continue to use the unchanged tenant-only check_navigation predicate.
#include "client_policy.h"
#include <cstdint>
#include <limits>
#include <map>

namespace drpolicy {

struct TickActions {
    bool stop_pending_external = false;
    bool navigate_to_tenant_console = false;
};

class SsoFlow {
public:
    enum class Banner { None, TimedOut, Unsupported };

    explicit SsoFlow(Tenant tenant, int64_t window_ms = 10 * 60 * 1000)
        : tenant_(std::move(tenant)), window_ms_(window_ms > 0 ? window_ms : 0) {}

    NavResult on_navigation_starting(uint64_t id, const std::string& uri,
                                     bool redirected, int64_t now_ms) {
        expire(now_ms);
        if (!redirected) {
            // A different non-redirected navigation supersedes older ids.
            auto found = navigations_.find(id);
            if (found == navigations_.end()) {
                navigations_.clear();
                Navigation n;
                n.initial_uri = uri;
                navigations_.emplace(id, std::move(n));
            }
        }
        auto it = navigations_.find(id);
        const bool tenant = is_tenant(uri);
        NavResult result = NavResult::Deny;
        if (tenant) {
            active_ = false;
            result = NavResult::Allow;
        } else {
            const bool entry = is_authorize(uri) &&
                ((!redirected && committed_tenant_) ||
                 (redirected && it != navigations_.end() &&
                  is_tenant_start(it->second.initial_uri)));
            if (entry) {
                if (flow_open_ && expired_) {
                    banner_ = Banner::TimedOut;
                } else {
                    if (!flow_open_) {
                        flow_open_ = true;
                        ++generation_;
                        expired_ = false;
                        const int64_t maximum = (std::numeric_limits<int64_t>::max)();
                        deadline_ms_ = now_ms > maximum - window_ms_
                            ? maximum : now_ms + window_ms_;
                    }
                    active_ = true;
                }
            }
            if (active_) {
                if (is_idp(uri)) result = NavResult::Allow;
                else banner_ = Banner::Unsupported;
            } else {
                // Keep the existing privilege predicate independent of SSO.
                result = check_navigation(uri, tenant_);
            }
        }
        // Redirects replace the currently pending target of this navigation.
        if (it != navigations_.end()) {
            it->second.pending_external = result == NavResult::Allow && !tenant;
            it->second.pending_tenant = result == NavResult::Allow && tenant;
        } else if (result == NavResult::Allow) {
            Navigation n;
            n.pending_external = !tenant;
            n.pending_tenant = tenant;
            navigations_.emplace(id, std::move(n));
        }
        return result;
    }

    void on_navigation_completed(uint64_t id, bool success) {
        auto it = navigations_.find(id);
        if (it == navigations_.end()) return;
        if (!success && it->second.pending_tenant && committed_external_)
            banner_ = Banner::TimedOut; // Offer the native Return action.
        navigations_.erase(it);
    }

    void on_commit(const std::string& uri, int64_t now_ms) {
        expire(now_ms);
        committed_tenant_ = is_tenant(uri);
        committed_external_ = !committed_tenant_;
        committed_host_ = parse_url(uri).host;
        if (committed_tenant_) {
            if (flow_open_) ++generation_;
            active_ = false;
            flow_open_ = false;
            expired_ = false;
            recover_ = false;
            stop_ = false;
            banner_ = Banner::None;
        } else if (flow_open_ && expired_) {
            recover_ = true;
            banner_ = Banner::TimedOut;
        }
    }

    TickActions on_tick(int64_t now_ms) {
        expire(now_ms);
        TickActions actions;
        actions.stop_pending_external = stop_;
        actions.navigate_to_tenant_console = recover_;
        stop_ = false;
        recover_ = false;
        return actions;
    }

    bool external_committed() const { return committed_external_; }
    std::string committed_host() const { return committed_host_; }
    bool ignore_document_title() const { return committed_external_; }
    Banner banner() const { return banner_; }
    void dismiss_banner() { banner_ = Banner::None; }
    std::string tenant_console_url() const { return console_url(tenant_); }
    // Changes when a flow opens and when a tenant commit closes it. A host action decided before a
    // modal must re-check this afterwards, or it can act on a newer flow (impl review v1).
    uint64_t generation() const { return generation_; }

private:
    struct Navigation {
        std::string initial_uri;
        bool pending_external = false;
        bool pending_tenant = false;
    };

    static std::string path(const std::string& uri) {
        const auto scheme = uri.find("://");
        if (scheme == std::string::npos) return "";
        const auto begin = uri.find_first_of("/?#", scheme + 3);
        if (begin == std::string::npos || uri[begin] != '/') return "";
        const auto end = uri.find_first_of("?#", begin);
        return uri.substr(begin, end == std::string::npos ? end : end - begin);
    }

    static bool secure(const ParsedUrl& p) {
        return p.valid && p.scheme == "https" && !p.has_userinfo &&
            (p.port.empty() || p.port == "443");
    }

    bool is_tenant(const std::string& uri) const {
        const auto p = parse_url(uri);
        return secure(p) && p.host == tenant_host(tenant_);
    }

    bool is_tenant_start(const std::string& uri) const {
        return is_tenant(uri) && path(uri) == "/cp/auth/oidc/start";
    }

    static bool is_idp(const std::string& uri) {
        const auto p = parse_url(uri);
        return secure(p) && (p.host == "login.microsoftonline.com" ||
            p.host == "login.live.com" || p.host == "account.live.com" ||
            p.host == "login.microsoft.com");
    }

    static bool is_authorize(const std::string& uri) {
        const auto p = parse_url(uri);
        if (!secure(p) || p.host != "login.microsoftonline.com") return false;
        const std::string s = path(uri);
        const std::string suffix = "/oauth2/v2.0/authorize";
        if (s.size() != 37 + suffix.size() || s[0] != '/' ||
            s.compare(37, suffix.size(), suffix) != 0) return false;
        for (size_t i = 0; i < 36; ++i) {
            const char c = s[i + 1];
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') return false;
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    }

    void expire(int64_t now_ms) {
        if (!flow_open_ || expired_ || now_ms < deadline_ms_) return;
        expired_ = true;
        active_ = false;
        banner_ = Banner::TimedOut;
        for (const auto& item : navigations_)
            if (item.second.pending_external) stop_ = true;
    }

    Tenant tenant_;
    int64_t window_ms_;
    int64_t deadline_ms_ = 0;
    bool flow_open_ = false;
    bool active_ = false;
    bool expired_ = false;
    bool committed_tenant_ = false;
    bool committed_external_ = false;
    bool stop_ = false;
    bool recover_ = false;
    std::string committed_host_;
    Banner banner_ = Banner::None;
    uint64_t generation_ = 0;
    std::map<uint64_t, Navigation> navigations_;
};

} // namespace drpolicy
