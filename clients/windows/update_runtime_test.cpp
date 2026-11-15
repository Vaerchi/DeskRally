// Real Windows file-sharing and replacement tests. No installed path, service,
// profile, registry, network download, or user process is modified.
#include "client_update.cpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

static int passed = 0;
static void require(bool value, const char* description) {
    if (!value) throw std::runtime_error(description);
    ++passed;
    std::cout << "[PASS] " << description << '\n';
}
static void write(const std::filesystem::path& path, const char* bytes) {
    std::ofstream out(path, std::ios::binary);
    out << bytes;
    if (!out) throw std::runtime_error("fixture write failed");
}
static std::string read(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

int wmain(int argc, wchar_t** argv) {
    const auto root = std::filesystem::path(drupdate::GetCurrentExePath()).parent_path() /
        (L"deskrally-update-tests-" + std::to_wstring(GetCurrentProcessId()));
    if (!std::filesystem::create_directory(root)) return 2;
    try {
        using namespace drupdate;
        const auto lock = (root / L"running.lock").wstring();
        {
            FileHandle first(OpenClientLifetimeLock(lock));
            FileHandle second(OpenClientLifetimeLock(lock));
            require(first.h != INVALID_HANDLE_VALUE && second.h != INVALID_HANDLE_VALUE,
                "two app lifetime locks coexist");
            FileHandle exclusive(CreateFileW(lock.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                nullptr, OPEN_EXISTING, 0, nullptr));
            require(exclusive.h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION,
                "app lifetime locks prevent update replacement");
            require(!DeleteFileW(lock.c_str()), "live lock cannot be deleted and replaced");
            require(!MoveFileW(lock.c_str(), (root / L"renamed.lock").c_str()),
                "live lock cannot be renamed away");
        }
        {
            FileHandle exclusive(CreateFileW(lock.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                nullptr, OPEN_EXISTING, 0, nullptr));
            require(exclusive.h != INVALID_HANDLE_VALUE, "last app exit permits exclusive update lock");
            FileHandle blocked(OpenClientLifetimeLock(lock));
            require(blocked.h == INVALID_HANDLE_VALUE, "update prevents a new app startup");
        }
        {
            FileHandle next(OpenClientLifetimeLock(lock));
            require(next.h != INVALID_HANDLE_VALUE, "app can restart after update lock releases");
        }
        const auto target = (root / L"client.exe").wstring();
        const auto stage = (root / L"next.exe").wstring();
        const auto backup = (root / L"previous.exe").wstring();
        const auto failed = (root / L"failed.exe").wstring();
        for (int mode = 0; mode != 5; ++mode) {
            for (const auto& path : {target, stage, backup, failed}) std::filesystem::remove(path);
            write(target, "old trusted bytes");
            if (mode != 4) write(stage, "new verified bytes");
            int startCalls = 0;
            const int result = ReplaceAndValidate(target, stage, backup, failed,
                [&](const std::wstring& path) {
                    if (mode == 3) throw std::runtime_error("injected verification failure");
                    return mode != 1 && read(path) == "new verified bytes";
                },
                [&](const std::wstring&) { ++startCalls; return mode != 2; });
            if (mode == 0) {
                require(result == 0 && read(target) == "new verified bytes" && read(backup) == "old trusted bytes",
                    "successful update retains exact prior executable");
            } else {
                require(result == (mode == 4 ? 8 : 9) && read(target) == "old trusted bytes",
                    "failed replacement, verification, exception, or startup preserves prior executable");
                if (mode != 2) require(startCalls == 0, "unverified candidate is never started");
            }
        }
        require(!VerifyAuthenticode(target), "unsigned bytes are rejected");
        require(HasReparseAncestor(L"relative\\file.exe"), "relative destination rejected");
        ClientLock developerLock;
        require(developerLock.IsReady(), "development executable does not acquire installed app lock");
        Updater developerUpdater(nullptr);
        require(!developerUpdater.CheckForUpdate(), "development executable cannot download an update");
        if (!updates_configured()) {
            require(developerUpdater.GetState().error_message == kUpdatesUnconfigured,
                "unconfigured check explains why updates are disabled");
            require(!VerifyAuthenticode(target), "empty publisher fails closed");
            require(WinHttpGet(L"", L"/", 1).empty(), "empty fetch host refused before WinHTTP");
            require(!DownloadToFile(L"", L"/", target, 1), "empty download host refused before WinHTTP");
            require(!GetAboutInfo().publisher_pinned, "About reports publisher is not pinned");
            require(GetAboutInfo().last_result == kUpdatesUnconfigured,
                "About reports updates are not configured");
        }
        // The call below must not write the build machine's own client registry (see this file's header).
        require(WorkerOutcome(1) == nullptr, "a non-worker invocation records no LastResult");
        require(WorkerOutcome(5) != nullptr, "a real worker outcome is recorded");
        wchar_t name[] = L"test"; wchar_t* invalidArgs[] = {name};
        require(RunUpdateWorker(1, invalidArgs) != 0, "worker rejects unsupported arguments before mutation");
        if (argc == 2 && updates_configured()) {
            const std::wstring signedFixture = std::filesystem::absolute(argv[1]).lexically_normal().wstring();
            require(VerifyAuthenticode(signedFixture), "actual timestamped publisher signature accepted");
            const auto sha = Sha256File(signedFixture);
            require(VerifyCandidate(signedFixture, sha, 0, "0.4.0"), "actual signed version and product accepted");
            require(!VerifyCandidate(signedFixture, sha, 0, "0.5.0"), "manifest cannot relabel a signed version");
            require(!VerifyCandidate(signedFixture, std::string(64, '0'), 0, "0.4.0"), "wrong measured hash rejected");
            require(!VerifyCandidate(signedFixture, sha, GetFileNumericVersion(signedFixture), "0.4.0"),
                "same-version signed replay rejected");
        }
        std::filesystem::remove_all(root);
        std::cout << passed << " runtime checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << " (fixtures retained at " << root.string() << ")\n";
        return 1;
    }
}
