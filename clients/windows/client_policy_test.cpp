// Pure policy unit tests – no Win32, no WebView2, no GUI.
// Compile: cl /EHsc /std:c++17 /MT /W4 /WX client_policy_test.cpp /Fe:policy_test.exe
// Run:     policy_test.exe  (exits 0 on pass, 1 on fail)

#include "client_policy.h"
#include "sso_policy.h"
#include "hello_policy.h"
#include "tab_policy.h"
#include "lifetime_policy.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <utility>

using namespace drpolicy;

// Test helper: a tenant from a slug the test asserts is valid.
static Tenant T(const char* slug) {
    Tenant t = Tenant::main();
    if (!make_tenant(slug, t)) { std::printf("[FAIL] fixture slug invalid: %s\n", slug); std::exit(1); }
    return t;
}

static int g_failed = 0;
static int g_passed = 0;

static void check(const char* label, bool cond) {
    if (cond) {
        std::printf("[PASS] %s\n", label);
        ++g_passed;
    } else {
        std::printf("[FAIL] %s\n", label);
        ++g_failed;
    }
}

// Default tenant is Main so existing calls require no changes.
static void nav_allow(const char* label, const std::string& uri, const Tenant& t = Tenant::main()) {
    check(label, check_navigation(uri, t) == NavResult::Allow);
}
static void nav_deny(const char* label, const std::string& uri, const Tenant& t = Tenant::main()) {
    check(label, check_navigation(uri, t) == NavResult::Deny);
}
static void popup_allow(const char* label, const std::string& uri, bool gesture) {
    check(label, check_popup(uri, gesture) == PopupResult::Allow);
}
static void popup_deny(const char* label, const std::string& uri, bool gesture) {
    check(label, check_popup(uri, gesture) == PopupResult::Deny);
}
static void perm_consent(const char* label, PermKind k) {
    check(label, check_permission(k) == PermResult::AllowWithConsent);
}
static void perm_deny(const char* label, PermKind k) {
    check(label, check_permission(k) == PermResult::Deny);
}

static void test_sso() {
    const Tenant tenant = T("loam");
    const std::string home = ("https://loam" + std::string(kTenantZone) + "/console");
    const std::string start = ("https://loam" + std::string(kTenantZone) + "/cp/auth/oidc/start?attempt=1");
    const std::string auth = "https://login.microsoftonline.com/01234567-89AB-cdef-0123-456789abcdef/oauth2/v2.0/authorize?x=1#fragment";
    using B = SsoFlow::Banner;
    const auto allow = NavResult::Allow;
    const auto deny = NavResult::Deny;
    auto fresh = [&]() { SsoFlow f(tenant, 100); f.on_commit(home, 0); return f; };
    {
        auto f = fresh();
        check("sso:A entry", f.on_navigation_starting(1, auth, false, 0) == allow);
        const char* hosts[] = { "login.microsoftonline.com", "login.live.com", "account.live.com", "login.microsoft.com" };
        uint64_t id = 2;
        for (const char* host : hosts) {
            const std::string uri = std::string("https://") + host + ":443/step";
            check("sso:active supported host", f.on_navigation_starting(id++, uri, false, 1) == allow);
            // These model both PermissionRequested and protocol-spawn trust checks.
            check("sso:permission and spawn predicate stays tenant-only", check_navigation(uri, tenant) == deny);
            SsoFlow inactive(tenant);
            check("sso:inactive IdP denied", inactive.on_navigation_starting(1, uri, false, 0) == deny);
        }
        f.on_commit("https://login.live.com/step", 2);
        check("sso:external indicator and title suppression", f.external_committed() && f.ignore_document_title() && f.committed_host() == "login.live.com");
        auto other = fresh();
        const SsoFlow* selected = &f;
        check("sso:activate external tab", selected->ignore_document_title());
        selected = &other;
        check("sso:activate tenant tab", !selected->ignore_document_title());
        check("sso:tenant return allowed", f.on_navigation_starting(20, home, false, 3) == allow);
        check("sso:tenant starting revokes exception", f.on_navigation_starting(21, "https://login.live.com/step", false, 4) == deny);
        f.on_navigation_starting(22, home, false, 5);
        f.on_navigation_completed(22, false);
        check("sso:failed return retains indicator and recovery", f.ignore_document_title() && f.banner() == B::TimedOut && f.tenant_console_url() == home);
        f.on_commit(home, 6);
        check("sso:tenant commit restores chrome", !f.external_committed() && !f.ignore_document_title() && f.banner() == B::None);
    }
    {
        SsoFlow f(tenant, 100);
        check("sso:no committed tenant A denied", f.on_navigation_starting(1, auth, false, 0) == deny);
        f.on_commit("https://evil.example/", 0);
        check("sso:external committed A denied", f.on_navigation_starting(2, auth, false, 0) == deny);
        f.on_navigation_starting(3, start, false, 0);
        check("sso:B entry without tenant commit", f.on_navigation_starting(3, auth, true, 1) == allow);
    }
    {
        auto f = fresh();
        f.on_navigation_starting(1, ("https://loam" + std::string(kTenantZone) + "/cp/machines"), false, 0);
        check("sso:redirect from machines denied despite tenant commit", f.on_navigation_starting(1, auth, true, 1) == deny);
        f.on_navigation_starting(2, start, false, 2);
        f.on_navigation_starting(3, home, false, 3);
        check("sso:superseded provenance denied", f.on_navigation_starting(2, auth, true, 4) == deny);
        f.on_navigation_starting(4, start, false, 5);
        f.on_navigation_completed(4, false);
        check("sso:cancelled provenance erased", f.on_navigation_starting(4, auth, true, 6) == deny);
        f.on_navigation_starting(5, start, false, 7);
        f.on_navigation_completed(5, true);
        check("sso:successful completion erases provenance", f.on_navigation_starting(5, auth, true, 8) == deny);
        f.on_navigation_starting(6, home, false, 9);
        f.on_navigation_starting(6, start, false, 10);
        check("sso:first URI cannot be overwritten", f.on_navigation_starting(6, auth, true, 11) == deny);
    }
    {
        auto f = fresh();
        check("sso:ordinary Microsoft URL cannot enter", f.on_navigation_starting(1, "https://login.live.com/", false, 0) == deny);
        const std::string bad[] = {
            "https://login.microsoftonline.com.evil.example/",
            "https://evil.example/login.microsoftonline.com",
            "http://login.microsoftonline.com/",
            "https://user@login.microsoftonline.com/",
            "https://@login.microsoftonline.com/",
            "https://login.microsoftonline.com:8443/",
            "https://%6cogin.microsoftonline.com/",
            "https://device.login.microsoftonline.com/",
            "https://autologon.microsoftazuread-sso.com/",
            "https://api-123.duosecurity.com/",
            "https://mysignins.microsoft.com/",
            "about:blank"
        };
        for (const auto& uri : bad) {
            auto g = fresh();
            check("sso:hostile inactive denied", g.on_navigation_starting(1, uri, false, 0) == deny);
            g.on_navigation_starting(2, auth, false, 1);
            check("sso:hostile active denied visibly", g.on_navigation_starting(3, uri, false, 2) == deny && g.banner() == B::Unsupported);
            g.dismiss_banner();
            check("sso:unsupported banner dismissible", g.banner() == B::None);
        }
        const std::string prefix = "https://login.microsoftonline.com/";
        check("sso:extra authorize segment denied", f.on_navigation_starting(2, prefix + "01234567-89ab-cdef-0123-456789abcdef/oauth2/v2.0/authorize/extra", false, 1) == deny);
        check("sso:bad GUID denied", f.on_navigation_starting(3, prefix + "g1234567-89ab-cdef-0123-456789abcdef/oauth2/v2.0/authorize", false, 2) == deny);
        // parse_url lowercases hosts; uppercase hosts are accepted, not hostile aliases.
        const std::string upper = "https://LOGIN.MICROSOFTONLINE.COM/01234567-89ab-cdef-0123-456789abcdef/oauth2/v2.0/authorize";
        check("sso:uppercase host normalized by parse_url", f.on_navigation_starting(4, upper, false, 3) == allow);
    }
    {
        auto f = fresh();
        f.on_navigation_starting(1, auth, false, 0);
        f.on_navigation_starting(2, auth, false, 90);
        f.on_navigation_completed(2, true);
        f.on_commit("https://login.microsoftonline.com/", 90);
        check("sso:before deadline", f.on_tick(99).stop_pending_external == false && f.banner() == B::None);
        f.on_tick(100);
        check("sso:stationary expiry non-renewable", f.banner() == B::TimedOut && f.ignore_document_title());
        check("sso:expired IdP denied", f.on_navigation_starting(3, "https://login.live.com/", false, 101) == deny);
    }
    {
        auto f = fresh();
        f.on_navigation_starting(1, auth, false, 0);
        f.on_commit("https://login.microsoftonline.com/", 1);
        f.on_navigation_starting(2, start, false, 80);
        check("sso:pre-expiry B reentry allowed", f.on_navigation_starting(2, auth, true, 90) == allow);
        f.on_navigation_completed(2, true);
        f.on_tick(100);
        check("sso:B reentry did not renew deadline", f.banner() == B::TimedOut);
        f.on_navigation_starting(3, start, false, 101);
        check("sso:expired B reentry denied", f.on_navigation_starting(3, auth, true, 102) == deny && f.banner() == B::TimedOut);
        f.on_commit(home, 103);
        check("sso:tenant commit permits fresh window", f.on_navigation_starting(4, auth, false, 104) == allow);
        f.on_tick(203);
        check("sso:fresh deadline not old deadline", f.banner() == B::None);
        f.on_tick(204);
        check("sso:fresh deadline expires", f.banner() == B::TimedOut);
    }
    {
        auto f = fresh();
        f.on_navigation_starting(1, auth, false, 0);
        const auto actions = f.on_tick(100);
        check("sso:expiry stops pending external with tenant committed", actions.stop_pending_external && !actions.navigate_to_tenant_console && !f.external_committed() && f.banner() == B::TimedOut);
        check("sso:Stop action consumed", !f.on_tick(101).stop_pending_external);
        check("sso:expired A reentry denied", f.on_navigation_starting(2, auth, false, 102) == deny);
        f.dismiss_banner();
        f.on_tick(103);
        check("sso:expiry informational banner stays dismissed", f.banner() == B::None);
        f.on_commit("https://login.microsoftonline.com/late", 104);
        check("sso:late commit recovery", f.on_tick(104).navigate_to_tenant_console && f.banner() == B::TimedOut && f.ignore_document_title());
        check("sso:recovery action consumed", !f.on_tick(105).navigate_to_tenant_console);
        f.on_commit(home, 106);
        check("sso:recovery commit clears indicator", !f.ignore_document_title());
    }
    {
        auto f = fresh();
        f.on_navigation_starting(1, auth, false, 0);
        f.on_navigation_completed(1, false);
        check("sso:completed external does not request Stop", !f.on_tick(100).stop_pending_external);
        auto g = fresh();
        g.on_navigation_starting(1, auth, false, 0);
        g.on_commit("https://login.live.com/raced", 100);
        const auto actions = g.on_tick(100);
        check("sso:commit detects expiry before timer", actions.stop_pending_external && actions.navigate_to_tenant_console && g.banner() == B::TimedOut);
    }
}


// impl review v1: a host action decided before a modal re-checks generation() afterwards.
static void test_sso_generation() {
    using namespace drpolicy;
    SsoFlow f(Tenant::main(), 1000);
    const std::string tenantPage = ("https://main" + std::string(kTenantZone) + "/console");
    const std::string authz = "https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/oauth2/v2.0/authorize?x=1";
    f.on_commit(tenantPage, 0);
    const uint64_t g0 = f.generation();
    check("sso-gen:A entry opens a flow", f.on_navigation_starting(1, authz, false, 10) == NavResult::Allow);
    const uint64_t g1 = f.generation();
    check("sso-gen:new flow bumps generation", g1 == g0 + 1);
    f.on_commit("https://login.microsoftonline.com/x", 20);
    f.on_navigation_starting(2, ("https://main" + std::string(kTenantZone) + "/cp/auth/oidc/start"), false, 30);
    f.on_navigation_starting(2, authz, true, 40);
    check("sso-gen:re-entry in the same flow keeps generation", f.generation() == g1);
    f.on_commit(tenantPage, 50);
    check("sso-gen:tenant commit closing the flow bumps generation", f.generation() == g1 + 1);
    f.on_commit(tenantPage, 60);
    check("sso-gen:tenant commit with no flow keeps generation", f.generation() == g1 + 1);
}

int main() {
    test_sso();
    test_sso_generation();
    // ── Navigation: positive (Main tenant) ──────────────────────────────────
    nav_allow("nav:trusted origin bare",
              ("https://main" + std::string(kTenantZone)));
    nav_allow("nav:trusted origin with path",
              ("https://main" + std::string(kTenantZone) + "/app"));
    nav_allow("nav:trusted origin explicit 443",
              ("https://main" + std::string(kTenantZone) + ":443/app"));
    nav_allow("nav:trusted origin query+fragment",
              ("https://main" + std::string(kTenantZone) + "/app?x=1#frag"));

    // ── Navigation: positive (Loam tenant) ──────────────────────────────────
    nav_allow("nav:loam origin bare",
              ("https://loam" + std::string(kTenantZone)), T("loam"));
    nav_allow("nav:loam origin with path",
              ("https://loam" + std::string(kTenantZone) + "/app"), T("loam"));
    nav_allow("nav:loam origin explicit 443",
              ("https://loam" + std::string(kTenantZone) + ":443/app"), T("loam"));

    // ── Navigation: origin pinning – cross-tenant denial ────────────────────
    nav_deny("nav:loam host denied in main process",
             ("https://loam" + std::string(kTenantZone)));
    nav_deny("nav:main host denied in loam process",
             ("https://main" + std::string(kTenantZone)), T("loam"));

    // ── Navigation: spoof against Loam tenant ───────────────────────────────
    nav_deny("nav:loam subdomain spoof in loam process",
             ("https://evil.loam" + std::string(kTenantZone)), T("loam"));
    nav_deny("nav:loam extra TLD spoof in loam process",
             ("https://loam" + std::string(kTenantZone) + ".evil.com"), T("loam"));
    nav_deny("nav:loam userinfo spoof in loam process",
             ("https://user@loam" + std::string(kTenantZone)), T("loam"));
    nav_deny("nav:loam non-standard port in loam process",
             ("https://loam" + std::string(kTenantZone) + ":8443"), T("loam"));

    // ── Navigation: negative (scheme / host / port) ──────────────────────────
    nav_deny("nav:wrong scheme http",
             ("http://main" + std::string(kTenantZone)));
    nav_deny("nav:wrong scheme ftp",
             ("ftp://main" + std::string(kTenantZone)));
    nav_deny("nav:local file",
             "file:///C:/evil.html");
    nav_deny("nav:about:blank in main frame",
             "about:blank");
    nav_deny("nav:wrong host – subdomain",
             ("https://evil.main" + std::string(kTenantZone)));
    nav_deny("nav:wrong host – lookalike unicode",
             "https://main.deskr\xd0\xb0" "11y.com");   // Cyrillic а (U+0430) in UTF-8
    nav_deny("nav:wrong host – extra TLD",
             ("https://main" + std::string(kTenantZone) + ".evil.com"));
    nav_deny("nav:wrong host – missing subdomain",
             ("https://" + std::string(kTenantZone.substr(1))));
    nav_deny("nav:wrong host – extra subdomain",
             ("https://www.main" + std::string(kTenantZone)));
    nav_deny("nav:non-standard port 8443",
             ("https://main" + std::string(kTenantZone) + ":8443"));
    nav_deny("nav:non-standard port 80",
             ("https://main" + std::string(kTenantZone) + ":80"));
    nav_deny("nav:javascript: scheme",
             "javascript:alert(1)");
    nav_deny("nav:data: URI",
             "data:text/html,<h1>hi</h1>");
    nav_deny("nav:empty string",
             "");
    nav_deny("nav:bare host no scheme",
             ("main" + std::string(kTenantZone)));

    // ── Navigation: negative (userinfo) ──────────────────────────────────────
    nav_deny("nav:credentials in URL user:pass",
             ("https://user:pass@main" + std::string(kTenantZone)));
    nav_deny("nav:empty userinfo – bare @ present",
             ("https://@main" + std::string(kTenantZone)));
    nav_deny("nav:userinfo with empty password",
             ("https://user@main" + std::string(kTenantZone)));

    // ── Navigation: negative (backslash / control chars / DEL) ──────────────
    nav_deny("nav:backslash in authority",
             ("https://main" + std::string(kTenantZone) + "\\evil.com"));
    nav_deny("nav:backslash path confusion",
             ("https://main" + std::string(kTenantZone) + "/path\\segment"));
    nav_deny("nav:control char 0x01 in URL",
             ("https://main" + std::string(kTenantZone) + "/path\x01"));
    nav_deny("nav:control char 0x00 in URL",
             std::string("https://main") + std::string(kTenantZone) + std::string("/\x00path", 6));
    nav_deny("nav:DEL char 0x7F in URL",
             ("https://main" + std::string(kTenantZone) + "/path\x7f"));

    // ── Popup: positive ──────────────────────────────────────────────────────
    popup_allow("popup:about:blank with gesture",
                "about:blank", true);

    // ── Popup: negative ──────────────────────────────────────────────────────
    popup_deny("popup:about:blank without gesture",
               "about:blank", false);
    popup_deny("popup:trusted origin no gesture",
               ("https://main" + std::string(kTenantZone)), false);
    popup_deny("popup:trusted origin with gesture (not about:blank)",
               ("https://main" + std::string(kTenantZone)), true);
    popup_deny("popup:javascript: with gesture",
               "javascript:void(0)", true);
    popup_deny("popup:data: with gesture",
               "data:text/html,x", true);
    popup_deny("popup:http with gesture",
               "http://evil.com", true);
    popup_deny("popup:backslash URL with gesture",
               ("https://main" + std::string(kTenantZone) + "\\@evil.com"), true);

    // ── Permission: positive ─────────────────────────────────────────────────
    perm_consent("perm:clipboard read requires consent",
                 PermKind::ClipboardRead);

    // ── Permission: negative ─────────────────────────────────────────────────
    perm_deny("perm:microphone denied",       PermKind::Microphone);
    perm_deny("perm:camera denied",           PermKind::Camera);
    perm_deny("perm:geolocation denied",      PermKind::Geolocation);
    perm_deny("perm:notifications denied",    PermKind::Notifications);
    perm_deny("perm:other denied",            PermKind::Other);

    // ── Client URI: legacy positive ──────────────────────────────────────────
    {
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000");
        check("uri:connect valid UUID",
              r.valid && r.kind == ClientUriResult::Kind::Connect &&
              r.uuid == "550e8400-e29b-41d4-a716-446655440000" &&
              r.tenant == Tenant::main());
    }
    {
        auto r = parse_client_uri("deskrally-client://attended/550e8400-e29b-41d4-a716-446655440000");
        check("uri:attended valid UUID",
              r.valid && r.kind == ClientUriResult::Kind::Attended &&
              r.tenant == Tenant::main());
    }
    {
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000/");
        check("uri:connect UUID trailing slash allowed",
              r.valid && r.uuid == "550e8400-e29b-41d4-a716-446655440000" &&
              r.tenant == Tenant::main());
    }
    {
        // Uppercase hex letters normalised to lowercase in result
        auto r = parse_client_uri("deskrally-client://connect/550E8400-E29B-41D4-A716-446655440000");
        check("uri:connect uppercase UUID normalised lowercase",
              r.valid && r.uuid == "550e8400-e29b-41d4-a716-446655440000");
    }
    {
        // Scheme case-insensitive
        auto r = parse_client_uri("DESKRALLY-CLIENT://connect/550e8400-e29b-41d4-a716-446655440000");
        check("uri:scheme case insensitive", r.valid && r.tenant == Tenant::main());
    }
    {
        // Legacy always yields Main tenant regardless of UUID content
        auto r = parse_client_uri("deskrally-client://attended/550e8400-e29b-41d4-a716-446655440000/");
        check("uri:legacy attended trailing slash Main tenant",
              r.valid && r.kind == ClientUriResult::Kind::Attended && r.tenant == Tenant::main());
    }

    // ── Client URI: strict positive – Main console ───────────────────────────
    {
        auto r = parse_client_uri("deskrally-client://tenant/main/console");
        check("uri:strict main console",
              r.valid && r.kind == ClientUriResult::Kind::Console &&
              r.tenant == Tenant::main() && r.uuid.empty());
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/main/console/");
        check("uri:strict main console trailing slash",
              r.valid && r.kind == ClientUriResult::Kind::Console && r.tenant == Tenant::main());
    }
    {
        // Case-insensitive tenant and sub-action
        auto r = parse_client_uri("DESKRALLY-CLIENT://TENANT/MAIN/CONSOLE");
        check("uri:strict main console all-caps",
              r.valid && r.kind == ClientUriResult::Kind::Console && r.tenant == Tenant::main());
    }

    // ── Client URI: strict positive – Loam console ───────────────────────────
    {
        auto r = parse_client_uri("deskrally-client://tenant/loam/console");
        check("uri:strict loam console",
              r.valid && r.kind == ClientUriResult::Kind::Console &&
              r.tenant == T("loam") && r.uuid.empty());
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/loam/console/");
        check("uri:strict loam console trailing slash",
              r.valid && r.kind == ClientUriResult::Kind::Console && r.tenant == T("loam"));
    }

    // ── Client URI: strict positive – Main connect/attended ──────────────────
    {
        auto r = parse_client_uri("deskrally-client://tenant/main/connect/550e8400-e29b-41d4-a716-446655440000");
        check("uri:strict main connect",
              r.valid && r.kind == ClientUriResult::Kind::Connect &&
              r.tenant == Tenant::main() && r.uuid == "550e8400-e29b-41d4-a716-446655440000");
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/main/attended/550e8400-e29b-41d4-a716-446655440000/");
        check("uri:strict main attended trailing slash",
              r.valid && r.kind == ClientUriResult::Kind::Attended && r.tenant == Tenant::main());
    }

    // ── Client URI: strict positive – Loam connect/attended ──────────────────
    {
        auto r = parse_client_uri("deskrally-client://tenant/loam/connect/550e8400-e29b-41d4-a716-446655440000");
        check("uri:strict loam connect",
              r.valid && r.kind == ClientUriResult::Kind::Connect &&
              r.tenant == T("loam") && r.uuid == "550e8400-e29b-41d4-a716-446655440000");
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/loam/attended/550e8400-e29b-41d4-a716-446655440000");
        check("uri:strict loam attended",
              r.valid && r.kind == ClientUriResult::Kind::Attended && r.tenant == T("loam"));
    }

    // ── Client URI: cross-tenant origin pinning (tenant field check) ─────────
    {
        // A loam URI parsed and then tenant-compared against Main process → mismatch = deny spawn.
        auto r = parse_client_uri("deskrally-client://tenant/loam/connect/550e8400-e29b-41d4-a716-446655440000");
        check("uri:loam URI tenant mismatch with Main process",
              r.valid && r.tenant != Tenant::main());
    }
    {
        // A main URI compared against Loam process → mismatch = deny spawn.
        auto r = parse_client_uri("deskrally-client://tenant/main/console");
        check("uri:main URI tenant mismatch with Loam process",
              r.valid && r.tenant != T("loam"));
    }
    {
        // Legacy URI always yields Main; caller must compare against selectedTenant.
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000");
        check("uri:legacy connect always Main tenant (mismatch with Loam process)",
              r.valid && r.tenant == Tenant::main() && r.tenant != T("loam"));
    }

    // ── Client URI: invalid unknown tenant ───────────────────────────────────
    // Any valid slug is accepted; the client holds no tenant list. Reserved and
    // malformed slugs are the "unknown tenant" cases now.
    check("uri:unlisted slug 'acme' accepted",
          parse_client_uri("deskrally-client://tenant/acme/console").valid);
    check("uri:reserved slug 'api' rejected",
          !parse_client_uri("deskrally-client://tenant/api/console").valid);
    check("uri:unknown tenant empty rejected",
          !parse_client_uri("deskrally-client://tenant//console").valid);

    // ── Client URI: invalid strict – unknown sub-action ──────────────────────
    check("uri:unknown sub-action 'launch' rejected",
          !parse_client_uri("deskrally-client://tenant/main/launch/550e8400-e29b-41d4-a716-446655440000").valid);
    check("uri:unknown sub-action 'admin' rejected",
          !parse_client_uri("deskrally-client://tenant/loam/admin").valid);

    // ── Client URI: invalid strict – extra segments ──────────────────────────
    check("uri:extra segment after console rejected",
          !parse_client_uri("deskrally-client://tenant/main/console/extra").valid);
    check("uri:extra segment after strict UUID rejected",
          !parse_client_uri("deskrally-client://tenant/loam/connect/550e8400-e29b-41d4-a716-446655440000/extra").valid);

    // ── Client URI: invalid strict – missing UUID ────────────────────────────
    check("uri:strict connect without UUID rejected",
          !parse_client_uri("deskrally-client://tenant/main/connect").valid);
    check("uri:strict attended without UUID rejected",
          !parse_client_uri("deskrally-client://tenant/loam/attended").valid);

    // ── Client URI: invalid strict – incomplete path ─────────────────────────
    check("uri:strict tenant only no action rejected",
          !parse_client_uri("deskrally-client://tenant/main").valid);
    check("uri:strict tenant slash only rejected",
          !parse_client_uri("deskrally-client://tenant/loam/").valid);

    // ── Client URI: invalid UUID format (legacy) ─────────────────────────────
    {
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-44665544000");
        check("uri:UUID too short (35 chars) rejected", !r.valid);
    }
    {
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-4466554400000");
        check("uri:UUID too long (37 chars) rejected", !r.valid);
    }
    {
        auto r = parse_client_uri("deskrally-client://connect/550e84000e29b41d4a71644665544000x");
        check("uri:UUID no hyphens rejected", !r.valid);
    }
    {
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-44665544000g");
        check("uri:UUID non-hex char rejected", !r.valid);
    }
    {
        auto r = parse_client_uri("deskrally-client://connect/550e840-0e29b-41d4-a716-446655440000");
        check("uri:UUID wrong hyphen position rejected", !r.valid);
    }

    // ── Client URI: invalid UUID format (strict) ─────────────────────────────
    check("uri:strict UUID too short rejected",
          !parse_client_uri("deskrally-client://tenant/main/connect/550e8400-e29b-41d4-a716-44665544000").valid);
    check("uri:strict UUID non-hex char rejected",
          !parse_client_uri("deskrally-client://tenant/loam/connect/550e8400-e29b-41d4-a716-44665544000g").valid);

    // ── Client URI: invalid structure ─────────────────────────────────────────
    check("uri:empty string rejected",
          !parse_client_uri("").valid);
    check("uri:wrong scheme rejected",
          !parse_client_uri(("https://main" + std::string(kTenantZone))).valid);
    check("uri:unknown action rejected",
          !parse_client_uri("deskrally-client://launch/550e8400-e29b-41d4-a716-446655440000").valid);
    check("uri:query string rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000?foo=bar").valid);
    check("uri:fragment rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000#frag").valid);
    check("uri:userinfo rejected",
          !parse_client_uri("deskrally-client://user@connect/550e8400-e29b-41d4-a716-446655440000").valid);
    check("uri:port rejected",
          !parse_client_uri("deskrally-client://connect:8080/550e8400-e29b-41d4-a716-446655440000").valid);
    check("uri:extra path segment rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000/extra").valid);
    check("uri:backslash rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000\\evil").valid);
    check("uri:percent-encoding rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-44665544%30000").valid);
    check("uri:double trailing slash rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000//").valid);
    check("uri:overlong input rejected",
          !parse_client_uri(std::string(200, 'a')).valid);
    check("uri:DEL char rejected",
          !parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-44665544000\x7f").valid);
    check("uri:strict query string rejected",
          !parse_client_uri("deskrally-client://tenant/main/console?x=1").valid);
    check("uri:strict fragment rejected",
          !parse_client_uri("deskrally-client://tenant/loam/console#frag").valid);

    // ── console_url: what a NEW tab opens (VM acceptance 10-17: Ctrl+T navigated the
    // deskrally-client:// launch uri, which the navigation filter cancels -> a blank tab) ──
    check("url:new-tab console page is https on the tenant host",
          console_url(T("labtest")) == ("https://labtest" + std::string(kTenantZone) + "/console"));
    check("url:new-tab console page for main",
          console_url(Tenant::main()) == ("https://main" + std::string(kTenantZone) + "/console"));

    // ── build_initial_url: URL value verification ─────────────────────────────
    {
        auto r = parse_client_uri("deskrally-client://connect/550e8400-e29b-41d4-a716-446655440000");
        check("url:legacy connect builds main device URL",
              r.valid && build_initial_url(r) ==
              ("https://main" + std::string(kTenantZone) + "/console?device=550e8400-e29b-41d4-a716-446655440000"));
    }
    {
        auto r = parse_client_uri("deskrally-client://attended/550e8400-e29b-41d4-a716-446655440000");
        check("url:legacy attended builds main attended URL",
              r.valid && build_initial_url(r) ==
              ("https://main" + std::string(kTenantZone) + "/console?attended=550e8400-e29b-41d4-a716-446655440000"));
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/main/console");
        check("url:strict main console URL",
              r.valid && build_initial_url(r) == ("https://main" + std::string(kTenantZone) + "/console"));
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/loam/console");
        check("url:strict loam console URL",
              r.valid && build_initial_url(r) == ("https://loam" + std::string(kTenantZone) + "/console"));
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/loam/connect/550e8400-e29b-41d4-a716-446655440000");
        check("url:strict loam connect device URL",
              r.valid && build_initial_url(r) ==
              ("https://loam" + std::string(kTenantZone) + "/console?device=550e8400-e29b-41d4-a716-446655440000"));
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/main/attended/550e8400-e29b-41d4-a716-446655440000");
        check("url:strict main attended URL",
              r.valid && build_initial_url(r) ==
              ("https://main" + std::string(kTenantZone) + "/console?attended=550e8400-e29b-41d4-a716-446655440000"));
    }

    // ── Tenant slug grammar ──────────────────────────────────────────────────
    {
        Tenant t = Tenant::main();
        check("slug:main valid", make_tenant("main", t) && t.slug() == "main");
        check("slug:digits and hyphen valid", make_tenant("vc-2", t) && t.slug() == "vc-2");
        check("slug:single char valid", make_tenant("a", t));
        check("slug:63 chars valid", make_tenant(std::string(63, 'a'), t));
        check("slug:64 chars rejected", !make_tenant(std::string(64, 'a'), t));
        check("slug:empty rejected", !make_tenant("", t));
        check("slug:uppercase rejected (callers normalise)", !make_tenant("Loam", t));
        check("slug:leading hyphen rejected", !make_tenant("-loam", t));
        check("slug:trailing hyphen rejected", !make_tenant("loam-", t));
        check("slug:dot rejected", !make_tenant("evil.com", t));
        check("slug:underscore rejected", !make_tenant("a_b", t));
        check("slug:space rejected", !make_tenant("a b", t));
        check("slug:non-ascii rejected", !make_tenant("m\xc3\xa4in", t));
        check("slug:reserved www rejected", !make_tenant("www", t));
        check("slug:reserved turn rejected", !make_tenant("turn", t));
        check("slug:reserved download rejected", !make_tenant("download", t));
        // Would share HKCU\Software\DeskRally\Client\Updater with the updater (case-insensitive).
        check("slug:reserved updater rejected", !make_tenant("updater", t));
        // A failed make_tenant leaves the previous value untouched.
        Tenant keep = T("loam");
        check("slug:failure leaves output unchanged", !make_tenant("www", keep) && keep == T("loam"));
    }
    check("zone:leading dot", kTenantZone == std::string(".") + DESKRALLY_TENANT_ZONE);
    check("origin:main", tenant_origin(Tenant::main()) == std::string("https://main.") + DESKRALLY_TENANT_ZONE);
    check("origin:any slug", tenant_origin(T("vc")) == std::string("https://vc.") + DESKRALLY_TENANT_ZONE);
    check("host:main", tenant_host(Tenant::main()) == ("main" + std::string(kTenantZone)));
    check("host:any slug", tenant_host(T("vc")) == ("vc" + std::string(kTenantZone)));
    check("label:capitalised", tenant_label(T("loam")) == "Loam" && tenant_label(Tenant::main()) == "Main");
    check("label:digit first unchanged", tenant_label(T("9x")) == "9x");

    // ── Navigation: any organization pins to its own host only ─────────────
    nav_allow("nav:vc origin in vc process", ("https://vc" + std::string(kTenantZone) + "/console"), T("vc"));
    nav_deny("nav:main host denied in vc process", ("https://main" + std::string(kTenantZone)), T("vc"));
    nav_deny("nav:vc host denied in loam process", ("https://vc" + std::string(kTenantZone)), T("loam"));
    nav_deny("nav:vc host denied in main process", ("https://vc" + std::string(kTenantZone)));
    nav_deny("nav:vc prefix spoof", ("https://vcx" + std::string(kTenantZone)), T("vc"));
    nav_deny("nav:vc suffix spoof", ("https://vc" + std::string(kTenantZone) + ".evil.com"), T("vc"));
    nav_deny("nav:vc subdomain spoof", ("https://a.vc" + std::string(kTenantZone)), T("vc"));

    // ── Client URI: any valid slug ───────────────────────────────────────────
    {
        auto r = parse_client_uri("deskrally-client://tenant/vc/console");
        check("uri:strict vc console", r.valid && r.kind == ClientUriResult::Kind::Console && r.tenant == T("vc"));
    }
    {
        auto r = parse_client_uri("deskrally-client://tenant/VC/connect/550E8400-E29B-41D4-A716-446655440000");
        check("uri:slug lowercased", r.valid && r.tenant == T("vc") &&
              r.uuid == "550e8400-e29b-41d4-a716-446655440000");
    }
    {
        const std::string slug63(63, 'q');
        auto r = parse_client_uri("deskrally-client://tenant/" + slug63 +
                                  "/attended/550e8400-e29b-41d4-a716-446655440000/");
        check("uri:63-char slug with attended UUID and slash fits length bound",
              r.valid && r.tenant.slug() == slug63 && r.kind == ClientUriResult::Kind::Attended);
        check("uri:64-char slug rejected",
              !parse_client_uri("deskrally-client://tenant/" + std::string(64, 'q') + "/console").valid);
    }
    check("uri:reserved slug www rejected", !parse_client_uri("deskrally-client://tenant/www/console").valid);
    check("uri:reserved slug turn rejected", !parse_client_uri("deskrally-client://tenant/turn/console").valid);
    check("uri:dotted slug rejected", !parse_client_uri("deskrally-client://tenant/evil.com/console").valid);
    check("uri:hyphen-edge slug rejected", !parse_client_uri("deskrally-client://tenant/-x/console").valid);
    check("uri:underscore slug rejected", !parse_client_uri("deskrally-client://tenant/a_b/console").valid);
    {
        auto r = parse_client_uri("deskrally-client://tenant/vc/connect/550e8400-e29b-41d4-a716-446655440000");
        check("url:vc connect device URL", r.valid && build_initial_url(r) ==
              ("https://vc" + std::string(kTenantZone) + "/console?device=550e8400-e29b-41d4-a716-446655440000"));
        check("uri:vc link tenant mismatch with loam process", r.valid && r.tenant != T("loam"));
    }

    // ── Organization typed by the user ───────────────────────────────────────
    {
        Tenant t = Tenant::main();
        check("org:plain slug", parse_org_input("loam", t) && t == T("loam"));
        check("org:capitalised", parse_org_input("Loam", t) && t == T("loam"));
        check("org:surrounding whitespace", parse_org_input("  vc\t", t) && t == T("vc"));
        check("org:host form", parse_org_input(("vc" + std::string(kTenantZone)), t) && t == T("vc"));
        check("org:https URL with path", parse_org_input(("https://Loam" + std::string(kTenantZone) + "/console?x=1"), t) && t == T("loam"));
        t = Tenant::main();
        check("org:other domain refused", !parse_org_input("loam.example.com", t) && t == Tenant::main());
        check("org:http refused", !parse_org_input(("http://loam" + std::string(kTenantZone)), t));
        check("org:port refused", !parse_org_input(("https://loam" + std::string(kTenantZone) + ":8443"), t));
        check("org:userinfo refused", !parse_org_input(("https://x@loam" + std::string(kTenantZone)), t));
        check("org:nested subdomain refused", !parse_org_input(("a.loam" + std::string(kTenantZone)), t));
        check("org:zone alone refused", !parse_org_input((std::string(kTenantZone.substr(1))), t));
        check("org:dot-zone alone refused", !parse_org_input((std::string(kTenantZone)), t));
        check("org:empty refused", !parse_org_input("   ", t));
        check("org:reserved refused", !parse_org_input("www", t));
        check("org:overlong refused", !parse_org_input(std::string(300, 'a'), t));
    }

    // ── Start-menu launch choice ─────────────────────────────────────────────
    {
        Tenant out = Tenant::main();
        check("startup:last signed-in organization used",
              choose_startup_tenant(true, T("vc"), out) == StartupChoice::Use && out == T("vc"));
        out = T("loam");
        check("startup:no record asks and leaves output unchanged",
              choose_startup_tenant(false, Tenant::main(), out) == StartupChoice::Ask && out == T("loam"));
    }

    using drhello::Setting;
    check("Hello: absent preference stays off", drhello::read_setting(true, false, 0) == Setting::Disabled);
    check("Hello: DWORD zero off", drhello::read_setting(false, true, 0) == Setting::Disabled);
    check("Hello: DWORD one on", drhello::read_setting(false, true, 1) == Setting::Enabled);
    check("Hello: bad DWORD fails closed", drhello::read_setting(false, true, 2) == Setting::Invalid);
    check("Hello: read error fails closed", drhello::read_setting(false, false, 0) == Setting::Invalid);
    check("Hello: normal profile opens", drhello::may_open_profile(Setting::Disabled, false, false));
    check("Hello: enabled profile waits", !drhello::may_open_profile(Setting::Enabled, false, false));
    check("Hello: verified profile opens", drhello::may_open_profile(Setting::Enabled, true, false));
    check("Hello: unknown setting never opens", !drhello::may_open_profile(Setting::Invalid, true, false));
    check("Hello: closing verified never opens", !drhello::may_open_profile(Setting::Enabled, true, true));
    check("Hello: closing ordinary never opens", !drhello::may_open_profile(Setting::Disabled, false, true));
    check("Hello: current completion accepted", drhello::may_complete(5, 5, true, false));
    check("Hello: stale completion rejected", !drhello::may_complete(5, 4, true, false));
    check("Hello: duplicate completion rejected", !drhello::may_complete(5, 5, false, false));
    check("Hello: completion after close rejected", !drhello::may_complete(5, 5, true, true));
    // ── Sign-in evidence: the session cookie ────────────────────────────────
    // Production sends "__Host-cp_session" (Secure cookies); 0.6.0 matched only "cp_session" and so
    // never recorded the organization (asked on every launch).
    {
        const std::string h = ("main" + std::string(kTenantZone));
        check("cookie:production __Host- name, host-only, / , HttpOnly, Secure",
              is_session_cookie("__Host-cp_session", "tok", h, h, "/", true, true));
        check("cookie:plain name with the same attributes",
              is_session_cookie("cp_session", "tok", h, h, "/", true, true));
        check("cookie:the CSRF cookie is not a session",
              !is_session_cookie("__Host-cp_csrf", "tok", h, h, "/", false, true));
        check("cookie:not HttpOnly (a page-script counterfeit)",
              !is_session_cookie("__Host-cp_session", "tok", h, h, "/", false, true));
        check("cookie:not Secure",
              !is_session_cookie("cp_session", "tok", h, h, "/", true, false));
        check("cookie:another host's cookie",
              !is_session_cookie("__Host-cp_session", "tok", ("loam" + std::string(kTenantZone)), h, "/", true, true));
        check("cookie:a parent-domain cookie",
              !is_session_cookie("cp_session", "tok", (std::string(kTenantZone)), h, "/", true, true));
        check("cookie:a narrower path",
              !is_session_cookie("cp_session", "tok", h, h, "/cp", true, true));
        check("cookie:empty value",
              !is_session_cookie("__Host-cp_session", "", h, h, "/", true, true));
        check("cookie:a lookalike name",
              !is_session_cookie("__Host-cp_session2", "tok", h, h, "/", true, true));
    }

    // ── Tabs: exact shortcut decoding ──────────────────────────────────────
    {
        using drtabs::Cmd;
        using drtabs::KeyInput;
        auto key = [](unsigned vk, bool shift = false) {
            KeyInput k; k.key_down = true; k.vk = vk; k.ctrl = true; k.shift = shift; return k;
        };
        auto is = [](KeyInput k, Cmd c) { return drtabs::decode(k).cmd == c; };
        check("tabs:Ctrl+T new", is(key('T'), Cmd::New));
        check("tabs:Ctrl+W close", is(key('W'), Cmd::Close));
        check("tabs:Ctrl+Tab next", is(key(0x09), Cmd::Next));
        check("tabs:Ctrl+Shift+Tab prev", is(key(0x09, true), Cmd::Prev));
        check("tabs:Ctrl+1 selects index 0", drtabs::decode(key('1')).cmd == Cmd::Select && drtabs::decode(key('1')).index == 0);
        check("tabs:Ctrl+8 selects index 7", drtabs::decode(key('8')).index == 7);
        check("tabs:Ctrl+9 last", is(key('9'), Cmd::Last));
        KeyInput k = key('T'); k.alt = true;
        check("tabs:Ctrl+Alt+T (and AltGr) refused", is(k, Cmd::None));
        k = key('T'); k.system_key = true;
        check("tabs:SYSTEM_KEY_DOWN refused", is(k, Cmd::None));
        k = key('W'); k.win = true;
        check("tabs:Win held refused", is(k, Cmd::None));
        k = key('W'); k.repeat = true;
        check("tabs:auto-repeat refused (no runaway closes)", is(k, Cmd::None));
        k = key(0x09); k.repeat = true;
        check("tabs:auto-repeat refused for switching too", is(k, Cmd::None));
        check("tabs:Ctrl+Shift+T refused (shift must match)", is(key('T', true), Cmd::None));
        check("tabs:Ctrl+Shift+1 refused", is(key('1', true), Cmd::None));
        k = key('T'); k.ctrl = false;
        check("tabs:plain T refused", is(k, Cmd::None));
        k = key('T'); k.key_down = false;
        check("tabs:key up refused", is(k, Cmd::None));
        check("tabs:Ctrl+C left to the page", is(key('C'), Cmd::None));
        check("tabs:Ctrl+0 left to the page", is(key('0'), Cmd::None));
        check("tabs:Ctrl+R left to the page", is(key('R'), Cmd::None));

        check("tabs:cap allows 11 -> 12", drtabs::can_create(11));
        check("tabs:cap refuses at 12 (creating + live)", !drtabs::can_create(12));
        check("tabs:next wraps", drtabs::step(2, 3, true) == 0);
        check("tabs:prev wraps", drtabs::step(0, 3, false) == 2);
        check("tabs:step with one tab stays", drtabs::step(0, 1, true) == 0 && drtabs::step(0, 1, false) == 0);
        check("tabs:select beyond count does nothing", drtabs::select_index(drtabs::decode(key('5')), 3) == -1);
        check("tabs:select in range", drtabs::select_index(drtabs::decode(key('2')), 3) == 1);
        check("tabs:last of 3", drtabs::select_index(drtabs::decode(key('9')), 3) == 2);
        check("tabs:close first of 3 -> new index 0 (the old second)", drtabs::replacement_after_close(0, 3) == 0);
        check("tabs:close middle of 3 -> index 1 (the old third)", drtabs::replacement_after_close(1, 3) == 1);
        check("tabs:close last of 3 -> index 1 (the old second)", drtabs::replacement_after_close(2, 3) == 1);
        check("tabs:close the only tab -> none", drtabs::replacement_after_close(0, 1) == -1);
    }

    // ── Process lifetime: draining after the main window is gone ─────────────
    {
        // A fake queue: each entry is {is_quit, code}. Counts dispatches.
        struct Q { std::vector<std::pair<bool, uintptr_t>> items; size_t next = 0; size_t dispatched = 0; bool repost = false; };
        auto run = [](Q& q, size_t max) {
            return drlifetime::drain_after_main_window(
                [&q](bool& is_quit, uintptr_t& code) {
                    if (q.repost) { is_quit = false; code = 0; return true; }  // something keeps posting
                    if (q.next >= q.items.size()) return false;
                    is_quit = q.items[q.next].first; code = q.items[q.next].second; ++q.next; return true;
                },
                [&q] { ++q.dispatched; }, max);
        };
        Q normal{{{false, 0}, {false, 0}, {true, 3}}};
        auto r = run(normal, 100);
        check("life:teardown work dispatched, then the quit ends it with its code",
              r.quit && r.quit_code == 3 && r.dispatched == 2 && normal.dispatched == 2 && !r.bounded);
        Q lost{{{false, 0}, {false, 0}}};
        r = run(lost, 100);
        check("life:quit lost: drains the queue and exits anyway", !r.quit && r.dispatched == 2 && !r.bounded);
        Q empty{};
        r = run(empty, 100);
        check("life:empty queue, no quit: exits at once", !r.quit && r.dispatched == 0 && !r.bounded);
        Q first{{{true, 0}, {false, 0}}};
        r = run(first, 100);
        check("life:quit first: nothing dispatched", r.quit && r.dispatched == 0);
        Q flood{}; flood.repost = true;
        r = run(flood, 50);
        check("life:a message that keeps re-posting cannot hold the process", r.bounded && r.dispatched == 50 && !r.quit);
    }

    std::printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
