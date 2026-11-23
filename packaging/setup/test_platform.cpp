// Local filesystem/API checks only. Never calls RunNormal, RunElevated or any MSI entry point.
#include "setup.cpp"
#include <cstdio>

static int failures = 0;
static void Check(bool value, const char* label) {
    printf("%s %s\n", value ? "PASS" : "FAIL", label);
    if (!value) ++failures;
}

int main() {
    for (const std::wstring& value : {L"", L"a\"b", L"a\\\"b", L"C:\\folder with spaces\\", L"plain"}) {
        const std::wstring command = L"test.exe " + QuoteArg(value);
        int count = 0;
        LPWSTR* argv = CommandLineToArgvW(command.c_str(), &count);
        Check(argv && count == 2 && value == argv[1], "argument round trip through Windows parser");
        if (argv) LocalFree(argv);
    }
    BYTE digest[32] = {};
    Check(!HexToBytes32(L"ab", digest), "short hash refused without reading past its buffer");
    Check(!IsDriveFixed(L"\\\\example.invalid\\share\\file"), "UNC refused before network lookup");

    int cleanupCount = 0;
    { ScopeExit guard{[&] { ++cleanupCount; }}; guard.run(); }
    Check(cleanupCount == 1, "cleanup runs once, not again after a path can be reused");

    wchar_t temp[MAX_PATH + 1] = {};
    if (!GetTempPathW(MAX_PATH, temp)) return 2;
    GUID id = {}; if (FAILED(CoCreateGuid(&id))) return 2;
    wchar_t guid[39] = {}; StringFromGUID2(id, guid, 39);
    const std::wstring root = std::wstring(temp) + L"DeskRallySetupTest-" + std::wstring(guid + 1, 36);
    if (!CreateDirectoryW(root.c_str(), nullptr)) return 2;
    const std::wstring moved = root + L"-moved";
    {
        PathLocks locks;
        Check(locks.hold(root, true), "hold local parent directory handles");
        Check(!MoveFileExW(root.c_str(), moved.c_str(), 0), "held parent cannot be renamed during elevated input open");
    }
    Check(MoveFileExW(root.c_str(), moved.c_str(), 0) != FALSE, "rename succeeds after locks close");
    Check(MoveFileExW(moved.c_str(), root.c_str(), 0) != FALSE, "restore test directory");

    const std::wstring file = root + L"\\input";
    {
        HandleGuard out(CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        DWORD n = 0;
        Check(out.valid() && WriteFile(out.get(), "abc", 3, &n, nullptr) && n == 3, "create small synthetic file");
        std::array<BYTE,32> hash = {};
        Check(!ComputeFileSha256(out.get(), hash), "read error is not treated as EOF when hashing");
        Check(!CopyByHandle(out.get(), out.get()), "read error is not treated as successful copy");
    }
    {
        HandleGuard in(CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        std::array<BYTE,32> hash = {}; BYTE expected[32] = {};
        HexToBytes32(L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected);
        Check(in.valid() && IsRegularHandle(in.get()) && ComputeFileSha256(in.get(), hash) && memcmp(hash.data(), expected,32)==0,
            "hash actual file bytes through a held regular-file handle");
    }
    Check(DeleteFileW(file.c_str()) != FALSE, "remove owned test file");
    {
        // BAKED keeps the 128 MiB artifact cap (PASS widens it: test_pass_setup).
        const std::wstring big = root + L"\\big";
        HandleGuard h(CreateFileW(big.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        LARGE_INTEGER size; size.QuadPart = 129LL * 1024 * 1024;
        std::array<BYTE,32> hash = {};
        Check(h.valid() && SetFilePointerEx(h.get(), size, nullptr, FILE_BEGIN) && SetEndOfFile(h.get()) && !ComputeFileSha256(h.get(), hash),
            "BAKED refuses to hash an MSI over 128 MiB");
        h.reset();
        Check(DeleteFileW(big.c_str()) != FALSE, "remove owned large test file");
    }
    Check(RemoveDirectoryW(root.c_str()) != FALSE, "remove owned empty test directory");
    return failures ? 1 : 0;
}
