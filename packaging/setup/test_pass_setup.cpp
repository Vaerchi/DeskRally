// MODE=PASS Setup: LoadPassBundle (what both the consent run and the elevated run call) on real
// files. Compiled with a pass-mode setup_config.h whose SETUP_PASS_ROOT_KEY is the shared vector
// file's TEST root key; the matching TEST scalar arrives as argv[1] so this test can sign its own
// passes and attestations with CNG. No UAC, no msiexec, no network.
#include "setup.cpp"

#include <cstdio>

namespace {

int g_failures = 0;

void Check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_failures++;
}

std::string Q(const std::string& s) { return std::string(1, '"') + s + std::string(1, '"'); }

std::string Base64(const std::string& in) {
    static const char kAlpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t w = static_cast<unsigned char>(in[i]) << 16;
        const size_t rem = in.size() - i;
        if (rem > 1) w |= static_cast<unsigned char>(in[i + 1]) << 8;
        if (rem > 2) w |= static_cast<unsigned char>(in[i + 2]);
        out.push_back(kAlpha[(w >> 18) & 63]);
        out.push_back(kAlpha[(w >> 12) & 63]);
        out.push_back(rem > 1 ? kAlpha[(w >> 6) & 63] : '=');
        out.push_back(rem > 2 ? kAlpha[w & 63] : '=');
    }
    return out;
}

std::string Hex(const unsigned char* p, size_t n) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; i++) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 15]);
    }
    return out;
}

// The TEST root private key, imported from the vector file's public point + scalar.
struct Signer {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool Load(const std::string& pubHex, const std::string& scalarHex) {
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) return false;
        const std::string pub = dp::HexDecode(pubHex), d = dp::HexDecode(scalarHex);
        std::vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 96);
        auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
        hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        hdr->cbKey = 32;
        std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), pub.data() + 1, 64);
        std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB) + 64, d.data(), 32);
        return BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &key, blob.data(), static_cast<ULONG>(blob.size()), 0) >= 0;
    }
    std::string Envelope(const unsigned char* domain, size_t domainLen, const std::string& body) {
        unsigned char digest[32], sig[64];
        ULONG got = 0;
        dp::Sha256({{domain, domainLen}, {body.data(), body.size()}}, digest);
        BCryptSignHash(key, nullptr, digest, 32, sig, 64, &got, 0);
        return "{" + Q("format") + ":1," + Q("body") + ":" + Q(Base64(body)) + "," + Q("sig") + ":" + Q(Hex(sig, 64)) + "}";
    }
};

struct PassSpec {
    std::string origin = "https://lab.deskrally.test";
    std::string uses = "[" + Q("setup") + "," + Q("support") + "]";
    std::string min = "1.3.4";
    long long issued = dp::UnixNow() - 3600, expires = dp::UnixNow() + 20 * 86400;
};

std::string PassBody(const PassSpec& s) {
    return "{" + Q("purpose") + ":" + Q("deskrally-deployment-pass") + "," + Q("v") + ":1," +
           Q("pass_id") + ":" + Q("3f6c1a2e-8b4d-4c1f-9e2a-7d5b6c8e9f01") + "," + Q("issued_to") + ":" + Q("Lab MSP") + "," +
           Q("origin") + ":" + Q(s.origin) + "," + Q("grant_issuer_pubkey") + ":" + Q(std::string(64, 'a')) + "," +
           Q("uses") + ":" + s.uses + "," + Q("min_agent_version") + ":" + Q(s.min) + "," +
           Q("issued_at") + ":" + Q(dp::FormatTime(s.issued)) + "," + Q("expires_at") + ":" + Q(dp::FormatTime(s.expires)) + "}";
}

std::string ReleaseBody(const std::string& version) {
    const long long now = dp::UnixNow();
    return "{" + Q("purpose") + ":" + Q("deskrally-agent-release") + "," + Q("v") + ":1," +
           Q("msi_sha256") + ":" + Q(std::string(64, '5')) + "," + Q("msi_size") + ":12345," +
           Q("product_version") + ":" + Q(version) + "," + Q("product_code") + ":" + Q("{0F347057-1A2B-4C3D-8E9F-0123456789AB}") + "," +
           Q("upgrade_code") + ":" + Q("{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}") + "," + Q("arch") + ":" + Q("x64") + "," +
           Q("issued_at") + ":" + Q(dp::FormatTime(now - 3600)) + "," + Q("expires_at") + ":" + Q(dp::FormatTime(now + 300 * 86400)) + "}";
}

std::wstring g_dir;

void Write(const wchar_t* name, const std::string& data) {
    const std::wstring path = g_dir + L"\\" + name;
    DeleteFileW(path.c_str());
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD w = 0;
    WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &w, nullptr);
    CloseHandle(h);
}

bool Load(PassBundle& b) {
    std::wstring err;
    return LoadPassBundle(g_dir, b, err);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::printf("usage: test_pass_setup <test root scalar hex>\n");
        return 2;
    }
    Signer signer;
    if (!signer.Load(SETUP_PASS_ROOT_KEY, argv[1])) {
        std::printf("FAIL import the TEST root key\n");
        return 1;
    }
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    g_dir = std::wstring(tmp) + L"dr-setup-pass-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(g_dir.c_str(), nullptr);

    const std::string goodPass = signer.Envelope(dp::kPassDomain, sizeof(dp::kPassDomain), PassBody(PassSpec{}));
    const std::string goodRelease = signer.Envelope(dp::kReleaseDomain, sizeof(dp::kReleaseDomain), ReleaseBody("1.3.5"));

    PassBundle b;
    Write(L"deployment-pass.json", goodPass);
    Write(L"agent-release.json", goodRelease);
    Check(Load(b), "a valid pass and attestation load");
    unsigned char d[32];
    dp::Sha256({{goodPass.data(), goodPass.size()}}, d);
    Check(b.pass.HostPort() == "lab.deskrally.test" && b.pass.issued_to == "Lab MSP" && b.release.product_version == "1.3.5",
          "the loaded values are the signed ones");
    const std::string wantSha = Hex(d, 32);
    Check(b.passSha256 == std::wstring(wantSha.begin(), wantSha.end()), "passSha256 is the SHA-256 of the exact pass file");

    // Exactly 4096 bytes (trailing JSON whitespace is allowed) loads; one more byte does not.
    Write(L"deployment-pass.json", goodPass + std::string(4096 - goodPass.size(), ' '));
    Check(Load(b), "a pass file of exactly 4096 bytes loads");
    Write(L"deployment-pass.json", goodPass + std::string(4097 - goodPass.size(), ' '));
    Check(!Load(b), "a 4097-byte pass file is refused");

    Write(L"deployment-pass.json", goodPass);
    DeleteFileW((g_dir + L"\\agent-release.json").c_str());
    Check(!Load(b), "a missing attestation is refused");
    Write(L"agent-release.json", goodRelease);

    PassSpec supportOnly;
    supportOnly.uses = "[" + Q("support") + "]";
    Write(L"deployment-pass.json", signer.Envelope(dp::kPassDomain, sizeof(dp::kPassDomain), PassBody(supportOnly)));
    Check(!Load(b), "a pass without setup is refused");

    PassSpec expired;
    expired.issued = dp::UnixNow() - 40 * 86400;
    expired.expires = dp::UnixNow() - 10 * 86400;
    Write(L"deployment-pass.json", signer.Envelope(dp::kPassDomain, sizeof(dp::kPassDomain), PassBody(expired)));
    Check(!Load(b), "an expired pass is refused");

    Write(L"deployment-pass.json", goodPass);
    Write(L"agent-release.json", signer.Envelope(dp::kReleaseDomain, sizeof(dp::kReleaseDomain), ReleaseBody("1.3.3")));
    Check(!Load(b), "a release older than min_agent_version is refused");
    Write(L"agent-release.json", goodRelease);

    Write(L"deployment-pass.json", signer.Envelope(dp::kReleaseDomain, sizeof(dp::kReleaseDomain), PassBody(PassSpec{})));
    Check(!Load(b), "a pass signed under the release domain is refused");

    // A symlink named like the pass, pointing at a valid pass, is never followed.
    Write(L"real-pass.json", goodPass);
    DeleteFileW((g_dir + L"\\deployment-pass.json").c_str());
    if (CreateSymbolicLinkW((g_dir + L"\\deployment-pass.json").c_str(), (g_dir + L"\\real-pass.json").c_str(),
                            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        Check(!Load(b), "a symlinked pass file is refused");
        DeleteFileW((g_dir + L"\\deployment-pass.json").c_str());
    } else {
        std::printf("SKIP symlink creation unavailable here\n");
    }

    // PASS hashes an MSI above the baked 128 MiB cap (the attestation allows up to 2^31-1).
    {
        const std::wstring big = g_dir + L"\\big.msi";
        HANDLE h = CreateFileW(big.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        LARGE_INTEGER size;
        size.QuadPart = 129LL * 1024 * 1024;
        const bool sized = SetFilePointerEx(h, size, nullptr, FILE_BEGIN) && SetEndOfFile(h);
        LARGE_INTEGER zero = {};
        SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
        std::array<BYTE, 32> digest = {};
        Check(sized && ComputeFileSha256(h, digest), "PASS mode hashes a 129 MiB MSI (above the baked cap)");
        Check(kMaxHashedMsi == 2147483647LL, "PASS mode's hash cap is the attestation's msi_size maximum");
        CloseHandle(h);
        DeleteFileW(big.c_str());
    }

    for (const wchar_t* n : {L"deployment-pass.json", L"agent-release.json", L"real-pass.json"}) DeleteFileW((g_dir + L"\\" + n).c_str());
    RemoveDirectoryW(g_dir.c_str());
    std::printf("%d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
