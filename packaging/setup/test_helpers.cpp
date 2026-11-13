// Standalone console tests for pure helpers in setup_helpers.h.
// Build: cl.exe /nologo /MT /EHsc /std:c++17 /W4 /WX /O2 test_helpers.cpp /link /SUBSYSTEM:CONSOLE
// Exit 0 = all pass; non-zero = failure (prints which assertion failed).
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "setup_helpers.h"

static int g_failures = 0;

static void Check(bool cond, const char* label) {
    if (cond) {
        printf("[PASS] %s\n", label);
    } else {
        printf("[FAIL] %s\n", label);
        ++g_failures;
    }
}

// ---- ValidateToken -------------------------------------------------------

static void TestToken() {
    // Valid: exactly 43 base64url chars.
    {
        const char* good = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcde";
        Check(ValidateToken(reinterpret_cast<const BYTE*>(good), 43), "token: 43 valid base64url chars");
    }
    // Valid: all-digit.
    {
        const char* all9 = "0000000000000000000000000000000000000000000";
        Check(ValidateToken(reinterpret_cast<const BYTE*>(all9), 43), "token: all digits");
    }
    // Valid: uses - and _.
    {
        const char* dashes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA---";
        Check(ValidateToken(reinterpret_cast<const BYTE*>(dashes), 43), "token: trailing dashes");
        const char* unders = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA___";
        Check(ValidateToken(reinterpret_cast<const BYTE*>(unders), 43), "token: trailing underscores");
    }
    // Too short.
    {
        const char* s42 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 A's minus 1 = 42
        Check(!ValidateToken(reinterpret_cast<const BYTE*>(s42), 42), "token: 42 bytes rejected");
    }
    // Too long (44 bytes).
    {
        const char* s44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 44 A's (trimmed)
        Check(!ValidateToken(reinterpret_cast<const BYTE*>(s44), 44), "token: 44 bytes rejected");
    }
    // Zero length.
    {
        Check(!ValidateToken(reinterpret_cast<const BYTE*>(""), 0), "token: 0 bytes rejected");
    }
    // Standard base64 padding '=' is invalid.
    {
        const char* padded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=A";
        Check(!ValidateToken(reinterpret_cast<const BYTE*>(padded), 43), "token: '=' rejected");
    }
    // Standard base64 '+' is invalid (base64url uses '-').
    {
        const char* plus = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+A";
        Check(!ValidateToken(reinterpret_cast<const BYTE*>(plus), 43), "token: '+' rejected");
    }
    // Standard base64 '/' is invalid (base64url uses '_').
    {
        const char* slash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/A";
        Check(!ValidateToken(reinterpret_cast<const BYTE*>(slash), 43), "token: '/' rejected");
    }
    // Embedded newline is invalid.
    {
        const char* nl = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        BYTE buf[43];
        memcpy(buf, nl, 43);
        buf[20] = '\n';
        Check(!ValidateToken(buf, 43), "token: embedded newline rejected");
    }
    // Space is invalid.
    {
        BYTE buf[43];
        memset(buf, 'A', 43);
        buf[0] = ' ';
        Check(!ValidateToken(buf, 43), "token: leading space rejected");
    }
    // NUL byte is invalid.
    {
        BYTE buf[43];
        memset(buf, 'A', 43);
        buf[10] = 0;
        Check(!ValidateToken(buf, 43), "token: embedded NUL rejected");
    }
}

// ---- QuoteArg ------------------------------------------------------------

static void TestQuoteArg() {
    // Simple path with no spaces.
    {
        std::wstring r = QuoteArg(L"C:\\foo\\bar.exe");
        Check(r == L"\"C:\\foo\\bar.exe\"", "quote: simple path");
    }
    // Path with spaces.
    {
        std::wstring r = QuoteArg(L"C:\\Program Files\\foo.exe");
        Check(r == L"\"C:\\Program Files\\foo.exe\"", "quote: path with spaces");
    }
    // Trailing backslash: must be doubled before closing quote.
    {
        std::wstring r = QuoteArg(L"C:\\foo\\");
        Check(r == L"\"C:\\foo\\\\\"", "quote: trailing backslash doubled");
    }
    // Multiple trailing backslashes.
    {
        std::wstring r = QuoteArg(L"C:\\foo\\\\");
        Check(r == L"\"C:\\foo\\\\\\\\\"", "quote: two trailing backslashes quadrupled");
    }
    // Embedded double quote: must be backslash-escaped.
    {
        std::wstring r = QuoteArg(L"a\"b");
        Check(r == L"\"a\\\"b\"", "quote: embedded double quote escaped");
    }
    // Backslash immediately before embedded quote: backslash + quote both escaped.
    {
        std::wstring r = QuoteArg(L"a\\\"b");
        Check(r == L"\"a\\\\\\\"b\"", "quote: backslash-quote pair escaped");
    }
    // Empty string.
    {
        std::wstring r = QuoteArg(L"");
        Check(r == L"\"\"", "quote: empty string becomes empty quotes");
    }
    // No trailing backslash (interior backslashes not doubled).
    {
        std::wstring r = QuoteArg(L"C:\\a\\b\\c");
        Check(r == L"\"C:\\a\\b\\c\"", "quote: interior backslashes not doubled");
    }
    // Property assignment pattern used for PROVISIONINGFILE.
    {
        std::wstring path = L"C:\\ProgramData\\DeskRally-Setup-abc\\provisioning.json";
        std::wstring prop = L"PROVISIONINGFILE=" + QuoteArg(path);
        // No trailing backslash in path; result must not have escaped backslashes except the literal ones.
        Check(prop == L"PROVISIONINGFILE=\"C:\\ProgramData\\DeskRally-Setup-abc\\provisioning.json\"",
              "quote: property assignment round-trip");
    }
}

// ---- HexToBytes32 --------------------------------------------------------

static void TestHexToBytes32() {
    // All-zeros.
    {
        BYTE out[32] = {};
        bool ok = HexToBytes32(L"0000000000000000000000000000000000000000000000000000000000000000", out);
        bool allZero = true;
        for (int i = 0; i < 32; ++i) if (out[i]) allZero = false;
        Check(ok && allZero, "hex: all-zero string");
    }
    // All-FF.
    {
        BYTE out[32] = {};
        bool ok = HexToBytes32(L"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", out);
        bool allFF = true;
        for (int i = 0; i < 32; ++i) if (out[i] != 0xFF) allFF = false;
        Check(ok && allFF, "hex: all-ff lowercase");
    }
    // Mixed case.
    {
        BYTE out[32] = {};
        bool ok = HexToBytes32(L"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899", out);
        Check(ok && out[0] == 0xAA && out[1] == 0xBB && out[31] == 0x99, "hex: mixed-case round-trip");
    }
    // First byte 0x01, last byte 0xFE.
    {
        BYTE out[32] = {};
        bool ok = HexToBytes32(L"01000000000000000000000000000000000000000000000000000000000000fe", out);
        Check(ok && out[0] == 0x01 && out[31] == 0xFE, "hex: boundary nibbles");
    }
    // Invalid char 'g'.
    {
        BYTE out[32] = {};
        bool ok = HexToBytes32(L"gg000000000000000000000000000000000000000000000000000000000000000", out);
        // Length is 65 here but we only read 64; the invalid char is at position 0.
        ok = HexToBytes32(L"gg00000000000000000000000000000000000000000000000000000000000000", out);
        Check(!ok, "hex: invalid char 'g' rejected");
    }
    // Invalid char space.
    {
        BYTE out[32] = {};
        bool ok = HexToBytes32(L"00 0000000000000000000000000000000000000000000000000000000000000", out);
        // String is 64 wide chars; position 2 is space.
        ok = HexToBytes32(L"00 000000000000000000000000000000000000000000000000000000000000", out);
        // That's only 63 chars... let me build a proper 64-char string with a space at index 2.
        wchar_t bad[65] = {};
        for (int i = 0; i < 64; ++i) bad[i] = L'0';
        bad[2] = L' ';
        ok = HexToBytes32(bad, out);
        Check(!ok, "hex: space at index 2 rejected");
    }
}

// ---- main ----------------------------------------------------------------

int main() {
    printf("=== setup_helpers tests ===\n");
    TestToken();
    TestQuoteArg();
    TestHexToBytes32();
    printf("===========================\n");
    if (g_failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    printf("%d test(s) FAILED.\n", g_failures);
    return 1;
}
