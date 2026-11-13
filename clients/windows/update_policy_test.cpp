// Pure update policy unit tests – no Win32, no WinHTTP, no GUI.
// Compile: cl /EHsc /std:c++17 /MT /W4 /WX update_policy_test.cpp /Fe:update_policy_test.exe
// Run:     update_policy_test.exe  (exits 0 on pass, 1 on fail)

#include "update_policy.h"
#include <cstdio>
#include <string>

using namespace drupdate;
static constexpr std::string_view kTestHost = "updates.example.test";

static int g_failed = 0;
static int g_passed = 0;

static void check(const char* label, bool cond) {
    if (cond) { std::printf("[PASS] %s\n", label); ++g_passed; }
    else       { std::printf("[FAIL] %s\n", label); ++g_failed; }
}

// ── Version parsing ────────────────────────────────────────────────────────

static void test_version_parsing() {
    auto ok = [](const char* s, uint32_t ma, uint32_t mi, uint32_t pa) {
        auto v = parse_version(s);
        return v.valid && v.major == ma && v.minor == mi && v.patch == pa;
    };
    auto bad = [](const char* s) { return !parse_version(s).valid; };

    check("ver:0.5.0",    ok("0.5.0",    0,     5,     0));
    check("ver:1.0.0",    ok("1.0.0",    1,     0,     0));
    check("ver:1.2.3",    ok("1.2.3",    1,     2,     3));
    check("ver:10.20.30", ok("10.20.30", 10,    20,    30));
    check("ver:0.0.0",    ok("0.0.0",    0,     0,     0));
    check("ver:65535.65535.65535", ok("65535.65535.65535", 65535, 65535, 65535));

    check("ver:empty rejected",             bad(""));
    check("ver:bare number rejected",       bad("1"));
    check("ver:two-part rejected",          bad("1.2"));
    check("ver:four-part rejected",         bad("1.2.3.4"));
    check("ver:letter rejected",            bad("1.2.a"));
    check("ver:leading dot rejected",       bad(".1.2.3"));
    check("ver:trailing dot rejected",      bad("1.2.3."));
    check("ver:space rejected",             bad("1.2 3"));
    check("ver:negative rejected",          bad("-1.2.3"));
    check("ver:overlong component",         bad("1234567890.0.0")); // 10 digits
    // Components > 65535 rejected (Windows FILEVERSION range).
    check("ver:65536 rejected",             bad("65536.0.0"));
    check("ver:999999999 rejected",         bad("999999999.999999999.999999999"));
    // Leading zeros on multi-digit components rejected.
    check("ver:leading zero major rejected", bad("01.2.3"));
    check("ver:leading zero minor rejected", bad("1.02.3"));
    check("ver:leading zero patch rejected", bad("1.2.03"));
}

// ── Version comparison ─────────────────────────────────────────────────────

static void test_version_comparison() {
    auto newer = [](const char* a, const char* b) {
        return version_newer_than(parse_version(a), parse_version(b));
    };
    auto not_newer = [](const char* a, const char* b) {
        return !version_newer_than(parse_version(a), parse_version(b));
    };

    check("cmp:0.5.0 > 0.4.0",   newer("0.5.0", "0.4.0"));
    check("cmp:1.0.0 > 0.9.9",   newer("1.0.0", "0.9.9"));
    check("cmp:0.5.1 > 0.5.0",   newer("0.5.1", "0.5.0"));
    check("cmp:2.0.0 > 1.99.99", newer("2.0.0", "1.99.99"));

    check("cmp:equal not newer",  not_newer("0.5.0", "0.5.0"));
    check("cmp:older not newer",  not_newer("0.4.0", "0.5.0"));
    check("cmp:invalid a",        not_newer("bad",   "0.5.0"));
    check("cmp:invalid b",        not_newer("0.5.0", "bad"));
    check("cmp:both invalid",     not_newer("bad",   "bad"));
    check("cmp:0.4.9 < 0.5.0",   not_newer("0.4.9", "0.5.0"));
}

// ── Manifest URL validation ────────────────────────────────────────────────

static void test_url_validation() {
    // Good URL for version 0.5.0
    check("url:valid 0.5.0",
        validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe",
            "0.5.0"));
    check("url:valid 1.2.3",
        validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/1.2.3/DeskRallyClient.exe",
            "1.2.3"));

    // Version mismatch
    check("url:version mismatch rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe",
            "0.6.0"));

    // Wrong host
    check("url:wrong host rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://evil.com/download/client/releases/0.5.0/DeskRallyClient.exe",
            "0.5.0"));
    check("url:loam host rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://loam.deskrally.com/download/client/releases/0.5.0/DeskRallyClient.exe",
            "0.5.0"));

    // Wrong scheme
    check("url:http rejected",
        !validate_release_url_for_host(kTestHost, 
            "http://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe",
            "0.5.0"));

    // Query/fragment appended
    check("url:query rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe?x=1",
            "0.5.0"));
    check("url:fragment rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe#foo",
            "0.5.0"));

    // Wrong filename
    check("url:wrong exe name rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/0.5.0/evil.exe",
            "0.5.0"));

    // Traversal attempt
    check("url:path traversal rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://updates.example.test/download/client/releases/../evil/DeskRallyClient.exe",
            "../evil"));

    // Backslash
    check("url:backslash rejected",
        !validate_release_url_for_host(kTestHost, 
            "https://updates.example.test\\download\\client\\releases\\0.5.0\\DeskRallyClient.exe",
            "0.5.0"));

    // Control character
    check("url:control char rejected",
        !validate_release_url_for_host(kTestHost, 
            std::string("https://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe\x01"),
            "0.5.0"));
}

// ── Manifest parsing ───────────────────────────────────────────────────────

static const char kGoodHash[] =
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
static const char kGoodUrl[] =
    "https://updates.example.test/download/client/releases/0.5.0/DeskRallyClient.exe";

static const std::string kGoodManifest =
    std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
    R"(","size":4194304,"url":")" + kGoodUrl + R"("})";

// Pretty-printed layout matching prepare_update_feed.py output.
static const std::string kPrettyManifest =
    std::string("{\n  \"version\": \"0.5.0\",\n  \"sha256\": \"") + kGoodHash +
    "\",\n  \"size\": 4194304,\n  \"url\": \"" + kGoodUrl + "\"\n}";

static void test_manifest_parsing() {
    // ── Good compact manifest ────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, kGoodManifest);
        check("manifest:valid", m.valid);
        check("manifest:version", m.version == "0.5.0");
        check("manifest:sha256 length", m.sha256.size() == 64);
        check("manifest:size", m.size == 4194304);
        check("manifest:url host", m.url.find("updates.example.test") != std::string::npos);
    }

    // ── Pretty-printed manifest (prepare_update_feed.py format) ─────────────
    {
        auto m = parse_manifest_for_host(kTestHost, kPrettyManifest);
        check("manifest:pretty-printed valid", m.valid);
        check("manifest:pretty version", m.version == "0.5.0");
        check("manifest:pretty size", m.size == 4194304);
    }

    // ── Alternate key order ──────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"url":")") + kGoodUrl +
            R"(","size":4194304,"sha256":")" + kGoodHash +
            R"(","version":"0.5.0"})");
        check("manifest:alternate key order valid", m.valid);
    }

    // ── Too large ────────────────────────────────────────────────────────────
    {
        std::string huge(kMaxManifestBytes + 1, ' ');
        check("manifest:too large rejected", !parse_manifest_for_host(kTestHost, huge).valid);
    }

    // ── Control char ─────────────────────────────────────────────────────────
    {
        std::string j = kGoodManifest;
        j[10] = '\x01';
        check("manifest:control char rejected", !parse_manifest_for_host(kTestHost, j).valid);
    }

    // ── Missing fields ───────────────────────────────────────────────────────
    check("manifest:missing version",
        !parse_manifest_for_host(kTestHost, 
            std::string(R"({"sha256":")") + kGoodHash +
            R"(","size":1000,"url":")" + kGoodUrl + R"("})").valid);
    check("manifest:missing sha256",
        !parse_manifest_for_host(kTestHost, 
            R"({"version":"0.5.0","size":1000,"url":")" +
            std::string(kGoodUrl) + R"("})").valid);
    check("manifest:missing size",
        !parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","url":")" + kGoodUrl + R"("})").valid);
    check("manifest:missing url",
        !parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000})").valid);

    // ── Bad version ──────────────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"bad","sha256":")") + kGoodHash +
            R"(","size":1000,"url":")" + kGoodUrl + R"("})");
        check("manifest:invalid version rejected", !m.valid);
    }

    // ── Version with leading zero ─────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"01.2.3","sha256":")") + kGoodHash +
            R"(","size":1000,"url":"https://updates.example.test/download/client/releases/01.2.3/DeskRallyClient.exe"})");
        check("manifest:leading-zero version rejected", !m.valid);
    }

    // ── Bad sha256 (uppercase hex) ────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            R"({"version":"0.5.0","sha256":"ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890","size":1000,"url":")" +
            std::string(kGoodUrl) + R"("})");
        check("manifest:uppercase sha256 rejected", !m.valid);
    }

    // ── Bad sha256 (63 chars) ─────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            R"({"version":"0.5.0","sha256":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789","size":1000,"url":")" +
            std::string(kGoodUrl) + R"("})");
        check("manifest:short sha256 rejected", !m.valid);
    }

    // ── Size zero ─────────────────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":0,"url":")" + kGoodUrl + R"("})");
        check("manifest:size 0 rejected", !m.valid);
    }

    // ── Size too large ────────────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":33554433,"url":")" + kGoodUrl + R"("})");
        check("manifest:size > 32MB rejected", !m.valid);
    }

    // ── URL version mismatch ──────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000,"url":"https://updates.example.test/download/client/releases/0.6.0/DeskRallyClient.exe"})");
        check("manifest:url version mismatch rejected", !m.valid);
    }

    // ── Wrong host in URL ─────────────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000,"url":"https://evil.com/download/client/releases/0.5.0/DeskRallyClient.exe"})");
        check("manifest:wrong host in url rejected", !m.valid);
    }

    // ── JSON escape in url (rejected) ─────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000,"url":"https:\/\/updates.example.test\/download\/client\/releases\/0.5.0\/DeskRallyClient.exe"})");
        check("manifest:escape in url rejected", !m.valid);
    }

    // ── Whitespace-padded valid manifest ─────────────────────────────────────
    {
        std::string j =
            std::string("{ \"version\" : \"0.5.0\" , \"sha256\" : \"") + kGoodHash +
            "\" , \"size\" : 1048576 , \"url\" : \"" + kGoodUrl + "\" }";
        auto m = parse_manifest_for_host(kTestHost, j);
        check("manifest:whitespace padded valid", m.valid);
    }

    // ── Adversarial: duplicate keys ───────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000,"url":")" + kGoodUrl + R"("})");
        check("manifest:duplicate version key rejected", !m.valid);
    }
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","sha256":")" + kGoodHash +
            R"(","size":1000,"url":")" + kGoodUrl + R"("})");
        check("manifest:duplicate sha256 key rejected", !m.valid);
    }

    // ── Adversarial: unknown key ──────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000,"url":")" + kGoodUrl + R"(","extra":"surprise"})");
        check("manifest:unknown key rejected", !m.valid);
    }

    // ── Adversarial: trailing junk after closing brace ────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, kGoodManifest + " }");
        check("manifest:trailing junk rejected", !m.valid);
    }
    {
        auto m = parse_manifest_for_host(kTestHost, kGoodManifest + "{}");
        check("manifest:concatenated object rejected", !m.valid);
    }

    // ── Adversarial: size with fraction ──────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000.5,"url":")" + kGoodUrl + R"("})");
        check("manifest:fractional size rejected", !m.valid);
    }

    // ── Adversarial: size with exponent ──────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1e6,"url":")" + kGoodUrl + R"("})");
        check("manifest:exponent size rejected", !m.valid);
    }

    // ── Adversarial: size with leading zero ───────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":01000,"url":")" + kGoodUrl + R"("})");
        check("manifest:leading-zero size rejected", !m.valid);
    }

    // ── Adversarial: negative size ────────────────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"({"version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":-1,"url":")" + kGoodUrl + R"("})");
        check("manifest:negative size rejected", !m.valid);
    }

    // ── Adversarial: nested object as value ───────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            R"({"version":{"major":0},"sha256":")" +
            std::string(kGoodHash) + R"(","size":1000,"url":")" + kGoodUrl + R"("})");
        check("manifest:nested object rejected", !m.valid);
    }

    // ── Adversarial: missing opening brace ───────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, 
            std::string(R"("version":"0.5.0","sha256":")") + kGoodHash +
            R"(","size":1000,"url":")" + kGoodUrl + R"(")");
        check("manifest:no opening brace rejected", !m.valid);
    }

    // ── Adversarial: unterminated string value ────────────────────────────────
    {
        auto m = parse_manifest_for_host(kTestHost, R"({"version":"0.5.0)");
        check("manifest:unterminated string rejected", !m.valid);
    }
}

int main() {
    std::printf("=== update_policy tests ===\n\n");
    check("url:empty host refused", expected_release_url_for_host("", "0.5.0").empty());
    check("url:configured port supported", validate_release_url_for_host("updates.example.test:8443",
        "https://updates.example.test:8443/download/client/releases/0.5.0/DeskRallyClient.exe", "0.5.0"));
    if (!updates_configured()) {
        check("url:unconfigured builder refuses", expected_release_url("0.5.0").empty());
        check("manifest:unconfigured parser refuses", !parse_manifest(kGoodManifest).valid);
    } else {
        check("url:configured builder", validate_release_url(expected_release_url("0.5.0"), "0.5.0"));
    }
    test_version_parsing();
    test_version_comparison();
    test_url_validation();
    test_manifest_parsing();
    std::printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
