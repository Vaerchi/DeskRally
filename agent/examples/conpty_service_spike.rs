//! docs/76 requirement 5 spike: can a CONSOLE-LESS process (a SYSTEM service / scheduled task in Session 0) host a
//! ConPTY child? Unlike `shell.rs` (the `conpty` crate, whose child attaches to the host's console), this creates the
//! pseudoconsole and the child directly: CreatePseudoConsole + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, bInheritHandles =
//! FALSE, no STARTF_USESTDHANDLES. It writes a command, reads VT output until a marker appears, and writes PASS/FAIL
//! plus the identity and session to the file named by argv[1]. Not shipped; a lab tool.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "conpty_spike.txt".into());
    let report = match spike::run() {
        Ok(s) => format!("PASS\n{s}"),
        Err(e) => format!("FAIL\n{e}"),
    };
    let _ = std::fs::write(&out, report);
}

#[cfg(windows)]
mod spike {
    use std::time::{Duration, Instant};
    use windows::core::{PWSTR, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows::Win32::System::Console::{ClosePseudoConsole, CreatePseudoConsole, COORD, HPCON};
    use windows::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, TerminateProcess,
        UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW, GetCurrentProcessId,
    };

    pub fn run() -> Result<String, String> {
        unsafe {
            let mut session = 0u32;
            let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut session);
            let user = std::env::var("USERNAME").unwrap_or_default();

            // Pipes: we write the child's input (in_w) and read its output (out_r).
            let (mut in_r, mut in_w, mut out_r, mut out_w) = (HANDLE::default(), HANDLE::default(), HANDLE::default(), HANDLE::default());
            CreatePipe(&mut in_r, &mut in_w, None, 0).map_err(|e| format!("CreatePipe in: {e}"))?;
            CreatePipe(&mut out_r, &mut out_w, None, 0).map_err(|e| format!("CreatePipe out: {e}"))?;
            let hpc: HPCON = CreatePseudoConsole(COORD { X: 100, Y: 30 }, in_r, out_w, 0)
                .map_err(|e| format!("CreatePseudoConsole: {e}"))?;
            // The pseudoconsole owns duplicates now.
            let _ = CloseHandle(in_r);
            let _ = CloseHandle(out_w);

            let mut size = 0usize;
            let _ = InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size);
            let mut attr_buf = vec![0u8; size];
            let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr().cast());
            InitializeProcThreadAttributeList(attrs, 1, 0, &mut size).map_err(|e| format!("InitAttr: {e}"))?;
            UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize, Some(hpc.0 as *const _),
                std::mem::size_of::<HPCON>(), None, None).map_err(|e| format!("UpdateAttr: {e}"))?;

            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attrs;
            si.StartupInfo.dwFlags = windows::Win32::System::Threading::STARTF_USESTDHANDLES;
            let mut cmd: Vec<u16> = "powershell.exe -NoProfile -NoLogo\0".encode_utf16().collect();
            let mut pi = PROCESS_INFORMATION::default();
            CreateProcessW(PCWSTR::null(), PWSTR(cmd.as_mut_ptr()), None, None, false, EXTENDED_STARTUPINFO_PRESENT,
                None, PCWSTR::null(), &si.StartupInfo, &mut pi).map_err(|e| format!("CreateProcessW: {e}"))?;

            let marker = "conpty_spike_7731";
            let mut seen = String::new();
            let deadline = Instant::now() + Duration::from_secs(25);
            let mut next_send = Instant::now();
            let mut ok = false;
            while Instant::now() < deadline {
                if Instant::now() >= next_send {
                    let line = format!("Write-Output ('{marker}' + ' ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)\r");
                    let mut wrote = 0u32;
                    let _ = WriteFile(in_w, Some(line.as_bytes()), Some(&mut wrote), None);
                    next_send = Instant::now() + Duration::from_secs(2);
                }
                let mut avail = 0u32;
                if PeekNamedPipe(out_r, None, 0, None, Some(&mut avail), None).is_ok() && avail > 0 {
                    let mut buf = vec![0u8; avail as usize];
                    let mut got = 0u32;
                    if ReadFile(out_r, Some(&mut buf), Some(&mut got), None).is_ok() {
                        seen.push_str(&String::from_utf8_lossy(&buf[..got as usize]));
                        // The echo of our own command contains the marker inside quotes; require it at a line start
                        // followed by a space, which only the command's OUTPUT produces.
                        if seen.lines().any(|l| l.trim_start().starts_with(&format!("{marker} "))) {
                            ok = true;
                            break;
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let _ = TerminateProcess(pi.hProcess, 0);
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            ClosePseudoConsole(hpc);
            DeleteProcThreadAttributeList(attrs);
            let _ = CloseHandle(in_w);
            let _ = CloseHandle(out_r);
            let tail: String = seen.chars().rev().take(600).collect::<Vec<_>>().into_iter().rev().collect();
            let summary = format!("session={session} USERNAME={user}\n--- output tail ---\n{tail}");
            if ok { Ok(summary) } else { Err(format!("marker not seen within 25 s\n{summary}")) }
        }
    }
}
