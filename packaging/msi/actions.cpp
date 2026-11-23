// Small static-CRT bridge: MSI owns files/services; the agent owns provisioning/enrollment.
// No shell, no enrollment secret in argv, no child output copied into verbose MSI logs.
//
// Auto-update (design v3..v10.1):
//   HealthGate        deferred, after StartServices: checks the installed agent_host.exe carries the
//                     expected version (otherwise the replacement was deferred: "in_use"), then runs
//                     its `msi-health-gate`; failure rolls the whole transaction back.
//   AutoUpdate*       deferred / rollback / commit: `msi-autoupdate` provisioning.
//   TxnCommitted /    commit / rollback actions: write txn.<attempt>.json under the agent root with
//   TxnRolledBack     the anchor protocol (held root handle, owner/DACL validated, handle-relative
//                     create + rename). Implemented HERE, never by running an installed binary,
//                     because during rollback that binary may already be the old one.
// Log lines prefixed "DESKRALLY_GATE:" are read back by the updater (update_msi::log_facts).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <msiquery.h>
#include <objbase.h>
#include <string>
#include <vector>

static std::wstring quote(const std::wstring& text) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : text) {
        if (c == L'\\') { ++slashes; continue; }
        out.append(slashes * (c == L'"' ? 2 : 1), L'\\');
        slashes = 0;
        if (c == L'"') out += L'\\';
        out += c;
    }
    out.append(slashes * 2, L'\\');
    return out + L'"';
}

static bool action_data(MSIHANDLE install, std::wstring& out) {
    DWORD size = 0;
    wchar_t empty[1] = {};
    UINT rc = MsiGetPropertyW(install, L"CustomActionData", empty, &size);
    if ((rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) || size > 32767) return false;
    std::vector<wchar_t> data(size + 1);
    DWORD capacity = size + 1;
    if (MsiGetPropertyW(install, L"CustomActionData", data.data(), &capacity) != ERROR_SUCCESS) return false;
    out.assign(data.data(), capacity);
    return true;
}

static std::vector<std::wstring> split_lines(const std::wstring& value) {
    std::vector<std::wstring> parts;
    size_t start = 0;
    for (;;) {
        size_t nl = value.find(L'\n', start);
        parts.push_back(value.substr(start, nl == std::wstring::npos ? std::wstring::npos : nl - start));
        if (nl == std::wstring::npos) return parts;
        start = nl + 1;
    }
}

static void log_info(MSIHANDLE install, const std::wstring& text) {
    MSIHANDLE record = MsiCreateRecord(0);
    MsiRecordSetStringW(record, 0, text.c_str());
    MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
    MsiCloseHandle(record);
}

// Run the installed agent with fixed arguments; returns its exit code (or ERROR_INSTALL_FAILURE).
static DWORD run_agent(const std::wstring& exe, const std::wstring& args, DWORD timeout_ms) {
    std::wstring command = quote(exe) + L" " + args;
    STARTUPINFOW startup = {}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child = {};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child)) return ERROR_INSTALL_FAILURE;
    DWORD wait = WaitForSingleObject(child.hProcess, timeout_ms), code = ERROR_INSTALL_FAILURE;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess, &code);
    else { TerminateProcess(child.hProcess, ERROR_INSTALL_FAILURE); WaitForSingleObject(child.hProcess, 5000); }
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    return code;
}

static bool is_lower_uuid(const std::wstring& s) {
    if (s.size() != 36) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        wchar_t c = s[i];
        bool dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash ? c != L'-' : !((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
    }
    return true;
}

static bool is_nonce(const std::wstring& s) {
    if (s.size() != 32) return false;
    for (wchar_t c : s) if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
    return true;
}

// "a.b.c" or "a.b.c+hex": digits, dots, plus, lowercase hex only (the Rust side re-validates).
static bool parse_core(const std::wstring& v, DWORD out[3]) {
    if (v.empty() || v.size() > 64) return false;
    size_t plus = v.find(L'+');
    std::wstring core = v.substr(0, plus);
    if (plus != std::wstring::npos) {
        std::wstring meta = v.substr(plus + 1);
        if (meta.empty()) return false;
        for (wchar_t c : meta) if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
    }
    int field = 0; DWORD acc = 0; bool digit = false;
    for (wchar_t c : core) {
        if (c == L'.') { if (!digit || field > 1) return false; out[field++] = acc; acc = 0; digit = false; }
        else if (c >= L'0' && c <= L'9') { acc = acc * 10 + (c - L'0'); if (acc > 65535) return false; digit = true; }
        else return false;
    }
    if (!digit || field != 2) return false;
    out[2] = acc;
    return true;
}

static bool file_version(const std::wstring& path, DWORD out[3]) {
    DWORD ignored = 0, size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0) return false;
    std::vector<unsigned char> buf(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buf.data())) return false;
    VS_FIXEDFILEINFO* info = nullptr; UINT len = 0;
    if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&info), &len) || !info) return false;
    out[0] = HIWORD(info->dwFileVersionMS); out[1] = LOWORD(info->dwFileVersionMS);
    out[2] = HIWORD(info->dwFileVersionLS);
    return true;
}

// ─── Anchor protocol (mirrors crates/agent-windows/src/anchor.rs) ───────────────────────────────

static const DWORD kMutate = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE |
                             WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;

static bool privileged(PSID sid) {
    return IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid);
}

static bool trusted_installer(PSID sid) {
    PSID ti = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti)) return false;
    bool eq = EqualSid(sid, ti) != FALSE;
    LocalFree(ti);
    return eq;
}

// v6 A1: the root's PARENT must not let a non-admin remove entries (or grant itself that right).
static bool parent_cannot_remove_root(const wchar_t* parent) {
    HANDLE h = CreateFileW(parent, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    PSID owner = nullptr; PACL dacl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
    bool ok = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &sd) == ERROR_SUCCESS;
    ok = ok && owner && (privileged(owner) || trusted_installer(owner)) && dacl;
    const DWORD remove = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
        ACE_HEADER* ace = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<void**>(&ace))) { ok = false; break; }
        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE) { ok = false; break; }
        if (ace->AceFlags & INHERIT_ONLY_ACE) continue;
        auto allow = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
        PSID who = reinterpret_cast<PSID>(&allow->SidStart);
        if (!privileged(who) && !trusted_installer(who) && (allow->Mask & remove)) ok = false;
    }
    if (sd) LocalFree(sd);
    CloseHandle(h);
    return ok;
}

// "<16 hex volume serial>-<32 hex file id>", the format the updater passes as DESKRALLY_ANCHOR
// (update_files::anchor_property): the held root must BE the root the attempt recorded.
static bool root_matches(HANDLE root, const std::wstring& expected) {
    FILE_ID_INFO info = {};
    if (!GetFileInformationByHandleEx(root, FileIdInfo, &info, sizeof(info))) return false;
    wchar_t buf[64] = {};
    int n = swprintf_s(buf, L"%016llx-", static_cast<unsigned long long>(info.VolumeSerialNumber));
    for (int i = 0; i < 16 && n > 0; ++i)
        n += swprintf_s(buf + n, 64 - n, L"%02x", info.FileId.Identifier[i]);
    return n == 49 && expected == buf;
}

// A plain directory, not a reparse point, owned by SYSTEM/Administrators, whose DACL grants no
// other principal a mutating right on the object itself; unknown ACE types fail closed.
static bool trusted_root(HANDLE dir) {
    FILE_ATTRIBUTE_TAG_INFO tag = {};
    if (!GetFileInformationByHandleEx(dir, FileAttributeTagInfo, &tag, sizeof(tag))) return false;
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return false;
    PSID owner = nullptr; PACL dacl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(dir, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS) return false;
    bool ok = owner && privileged(owner) && dacl;
    for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
        ACE_HEADER* ace = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<void**>(&ace))) { ok = false; break; }
        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE) { ok = false; break; }
        if (ace->AceFlags & INHERIT_ONLY_ACE) continue;
        auto allow = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
        if (!privileged(reinterpret_cast<PSID>(&allow->SidStart)) && (allow->Mask & kMutate)) ok = false;
    }
    LocalFree(sd);
    return ok;
}

typedef NTSTATUS(NTAPI* NtCreateFileFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtSetInformationFileFn)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

// Write txn.<id>.json = {"attempt_id":"<id>","result":"<result>"} under C:\rmt-agent.
static bool write_txn(const std::wstring& id, const std::wstring& anchor, const char* result) {
    if (!is_lower_uuid(id) || anchor.size() != 49) return false;
    if (!parent_cannot_remove_root(L"C:\\")) return false;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto nt_create = reinterpret_cast<NtCreateFileFn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtCreateFile")));
    auto nt_setinfo = reinterpret_cast<NtSetInformationFileFn>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtSetInformationFile")));
    if (!nt_create || !nt_setinfo) return false;
    // Held without FILE_SHARE_DELETE: the root cannot be renamed or removed while we write.
    HANDLE root = CreateFileW(L"C:\\rmt-agent",
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_ADD_FILE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (root == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR sd = nullptr;
    do {
        if (!trusted_root(root) || !root_matches(root, anchor)) break;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            SDDL_REVISION_1, &sd, nullptr)) break;
        std::wstring final_name = L"txn." + id + L".json";
        std::wstring temp_name = final_name + L".tmp-" + std::to_wstring(GetTickCount64());
        UNICODE_STRING name;
        name.Buffer = temp_name.data();
        name.Length = name.MaximumLength = static_cast<USHORT>(temp_name.size() * sizeof(wchar_t));
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | 0x1000 /* OBJ_DONT_REPARSE */, root, sd);
        IO_STATUS_BLOCK io = {};
        NTSTATUS st = nt_create(&file, GENERIC_WRITE | DELETE | SYNCHRONIZE, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
            0, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | 0x00200000 /* OPEN_REPARSE_POINT */ |
            FILE_WRITE_THROUGH, nullptr, 0);
        if (st < 0) { file = INVALID_HANDLE_VALUE; break; }
        std::string body = "{\"attempt_id\":\"";
        for (wchar_t c : id) body += static_cast<char>(c);
        body += "\",\"result\":\""; body += result; body += "\"}";
        DWORD written = 0;
        if (!WriteFile(file, body.data(), static_cast<DWORD>(body.size()), &written, nullptr) ||
            written != body.size() || !FlushFileBuffers(file)) {
            FILE_DISPOSITION_INFO del = { TRUE };
            SetFileInformationByHandle(file, FileDispositionInfo, &del, sizeof(del));
            break;
        }
        // FILE_RENAME_INFORMATION: Flags @0, RootDirectory @8, FileNameLength @16, FileName @20.
        std::vector<unsigned char> buf(24 + final_name.size() * sizeof(wchar_t), 0);
        *reinterpret_cast<ULONG*>(buf.data()) = 0x1 | 0x2; // REPLACE_IF_EXISTS | POSIX_SEMANTICS
        *reinterpret_cast<HANDLE*>(buf.data() + 8) = root;
        *reinterpret_cast<ULONG*>(buf.data() + 16) = static_cast<ULONG>(final_name.size() * sizeof(wchar_t));
        memcpy(buf.data() + 20, final_name.data(), final_name.size() * sizeof(wchar_t));
        IO_STATUS_BLOCK io2 = {};
        st = nt_setinfo(file, &io2, buf.data(), static_cast<ULONG>(20 + final_name.size() * sizeof(wchar_t)),
            65 /* FileRenameInformationEx */);
        if (st < 0) {
            FILE_DISPOSITION_INFO del = { TRUE };
            SetFileInformationByHandle(file, FileDispositionInfo, &del, sizeof(del));
            break;
        }
        ok = true;
    } while (false);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (sd) LocalFree(sd);
    CloseHandle(root);
    return ok;
}

// ─── Actions ────────────────────────────────────────────────────────────────────────────────────

static UINT configure(MSIHANDLE install) {
    std::wstring value;
    if (!action_data(install, value)) return ERROR_INSTALL_FAILURE;
    size_t split = value.find(L'\n');
    if (split == std::wstring::npos) return ERROR_INSTALL_FAILURE;
    std::wstring exe = value.substr(0, split), rest = value.substr(split + 1);
    // CustomActionData: exe \n provisioning file [\n DIRECTIVE_PUBKEY]. The key (docs/65 D-C3) is public; the
    // agent validates it strictly and pins it set-if-blank.
    std::wstring file = rest, directive_key;
    size_t split2 = rest.find(L'\n');
    if (split2 != std::wstring::npos) { file = rest.substr(0, split2); directive_key = rest.substr(split2 + 1); }
    std::wstring args = L"msi-provision " + quote(file);
    if (!directive_key.empty()) args += L" " + quote(directive_key);
    // Agent enrollment already has a bounded network timeout. Bound unexpected hangs too.
    DWORD code = run_agent(exe, args, 120000);
    if (code == 0) return ERROR_SUCCESS;
    MSIHANDLE record = MsiCreateRecord(1);
    MsiRecordSetStringW(record, 0, L"DeskRally provisioning failed (code [1]). See the MSI provisioning guide. Existing identity is retained; the service was not started.");
    MsiRecordSetInteger(record, 1, static_cast<int>(code));
    MsiProcessMessage(install, INSTALLMESSAGE_ERROR, record);
    MsiCloseHandle(record);
    return ERROR_INSTALL_FAILURE;
}

// CustomActionData: exe \n attempt \n nonce \n expected_version
static UINT health_gate(MSIHANDLE install) {
    std::wstring value;
    if (!action_data(install, value)) return ERROR_INSTALL_FAILURE;
    std::vector<std::wstring> p = split_lines(value);
    DWORD expected[3] = {}, actual[3] = {};
    if (p.size() != 4 || !is_lower_uuid(p[1])) {
        log_info(install, L"DESKRALLY_GATE: verification attempt=unknown (malformed action data)");
        return ERROR_INSTALL_FAILURE;
    }
    const std::wstring& id = p[1];
    if (!is_nonce(p[2]) || !parse_core(p[3], expected)) {
        log_info(install, L"DESKRALLY_GATE: verification attempt=" + id);
        return ERROR_INSTALL_FAILURE;
    }
    // A deferred (in-use) replacement leaves the OLD binary at this path: never run it with the gate.
    if (!file_version(p[0], actual) || actual[0] != expected[0] || actual[1] != expected[1] || actual[2] != expected[2]) {
        log_info(install, L"DESKRALLY_GATE: in_use attempt=" + id);
        return ERROR_INSTALL_FAILURE;
    }
    DWORD code = run_agent(p[0], L"msi-health-gate " + id + L" " + p[2] + L" " + p[3], 200000);
    if (code == 0) {
        log_info(install, L"DESKRALLY_GATE: passed attempt=" + id);
        return ERROR_SUCCESS;
    }
    log_info(install, (code == 2 ? L"DESKRALLY_GATE: verification attempt=" : L"DESKRALLY_GATE: failed attempt=") + id);
    return ERROR_INSTALL_FAILURE;
}

// CustomActionData: exe \n verb [\n txn [\n ring]]   (deprovision: exe \n verb)
static UINT auto_update(MSIHANDLE install, bool must_succeed) {
    const UINT fail = must_succeed ? ERROR_INSTALL_FAILURE : ERROR_SUCCESS;
    std::wstring value;
    if (!action_data(install, value)) return fail;
    std::vector<std::wstring> p = split_lines(value);
    if (p.size() < 2 || p.size() > 4) return fail;
    const std::wstring& verb = p[1];
    std::wstring args = L"msi-autoupdate " + verb;
    if (verb == L"deprovision") {
        if (p.size() != 2) return fail;
    } else if (verb == L"rollback" || verb == L"commit") {
        if (p.size() != 3 || !is_lower_uuid(p[2])) return fail;
        args += L" " + p[2];
    } else if (verb == L"provision") {
        if (p.size() != 4 || !is_lower_uuid(p[2]) || (p[3] != L"canary" && p[3] != L"early" && p[3] != L"general"))
            return ERROR_INSTALL_FAILURE;
        args += L" " + p[2] + L" " + p[3];
    } else {
        return fail;
    }
    DWORD code = run_agent(p[0], args, 120000);
    if (code == 0 || !must_succeed) return ERROR_SUCCESS;
    log_info(install, L"DeskRally auto-update " + verb + L" failed (code " + std::to_wstring(code) + L")");
    return ERROR_INSTALL_FAILURE;
}

// CustomActionData: attempt \n anchor
static UINT txn(MSIHANDLE install, const char* result) {
    std::wstring value;
    // Commit and rollback actions never fail: a failing commit action would start a rollback.
    // A record that is not written leaves the attempt Unresolved until a reboot (never wrong).
    if (action_data(install, value)) {
        std::vector<std::wstring> p = split_lines(value);
        if (p.size() != 2 || !write_txn(p[0], p[1], result))
            log_info(install, L"DeskRally: transaction record not written");
    }
    return ERROR_SUCCESS;
}

// Immediate: a fresh lowercase GUID per transaction, binding provisioning snapshots to it.
static UINT new_txn_id(MSIHANDLE install) {
    GUID g;
    if (FAILED(CoCreateGuid(&g))) return ERROR_INSTALL_FAILURE;
    wchar_t buf[40] = {};
    swprintf_s(buf, L"%08lx-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x",
        g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5],
        g.Data4[6], g.Data4[7]);
    return MsiSetPropertyW(install, L"DESKRALLY_TXN", buf) == ERROR_SUCCESS ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
}

extern "C" __declspec(dllexport) UINT __stdcall ConfigureAgent(MSIHANDLE install) {
    try { return configure(install); }
    catch (...) { return ERROR_INSTALL_FAILURE; }
}
extern "C" __declspec(dllexport) UINT __stdcall HealthGate(MSIHANDLE install) {
    try { return health_gate(install); }
    catch (...) { return ERROR_INSTALL_FAILURE; }
}
extern "C" __declspec(dllexport) UINT __stdcall AutoUpdateProvision(MSIHANDLE install) {
    try { return auto_update(install, true); }
    catch (...) { return ERROR_INSTALL_FAILURE; }
}
extern "C" __declspec(dllexport) UINT __stdcall AutoUpdateCleanup(MSIHANDLE install) {
    try { return auto_update(install, false); }
    catch (...) { return ERROR_SUCCESS; }
}
extern "C" __declspec(dllexport) UINT __stdcall NewTxnId(MSIHANDLE install) {
    try { return new_txn_id(install); }
    catch (...) { return ERROR_INSTALL_FAILURE; }
}
extern "C" __declspec(dllexport) UINT __stdcall TxnCommitted(MSIHANDLE install) {
    try { return txn(install, "committed"); }
    catch (...) { return ERROR_SUCCESS; }
}
extern "C" __declspec(dllexport) UINT __stdcall TxnRolledBack(MSIHANDLE install) {
    try { return txn(install, "rolled_back"); }
    catch (...) { return ERROR_SUCCESS; }
}
