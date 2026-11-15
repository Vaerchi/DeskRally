#pragma once
// Pure helpers shared by setup.cpp and test_helpers.cpp.
// Caller must include <windows.h> before this header.
#include <string>
#include <cwchar>

static const DWORD TOKEN_LENGTH = 43;

inline bool IsBase64UrlChar(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

// Returns true iff data is exactly TOKEN_LENGTH bytes of valid base64url (no padding, no newline).
inline bool ValidateToken(const BYTE* data, DWORD size) {
    if (size != TOKEN_LENGTH) return false;
    for (DWORD i = 0; i < size; ++i)
        if (!IsBase64UrlChar(data[i])) return false;
    return true;
}

// Windows command-line quoting per MSVC CRT rules (same algorithm as packaging/msi/actions.cpp).
inline std::wstring QuoteArg(const std::wstring& s) {
    std::wstring out(1, L'"');
    size_t trailing = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++trailing; continue; }
        out.append(c == L'"' ? trailing * 2 : trailing, L'\\');
        trailing = 0;
        if (c == L'"') out += L'\\';
        out += c;
    }
    out.append(trailing * 2, L'\\');
    return out + L'"';
}

// Parse a 64-character hex string (upper or lower) into 32 bytes. Returns false on invalid input.
inline bool HexToBytes32(const wchar_t* hex, BYTE out[32]) {
    if (!hex || std::wcslen(hex) != 64) return false;
    auto nibble = [](wchar_t c, BYTE& v) -> bool {
        if (c >= L'0' && c <= L'9') { v = static_cast<BYTE>(c - L'0');        return true; }
        if (c >= L'a' && c <= L'f') { v = static_cast<BYTE>(c - L'a' + 10);  return true; }
        if (c >= L'A' && c <= L'F') { v = static_cast<BYTE>(c - L'A' + 10);  return true; }
        return false;
    };
    for (int i = 0; i < 32; ++i) {
        BYTE hi, lo;
        if (!nibble(hex[i * 2], hi) || !nibble(hex[i * 2 + 1], lo)) return false;
        out[i] = static_cast<BYTE>((hi << 4) | lo);
    }
    return true;
}
