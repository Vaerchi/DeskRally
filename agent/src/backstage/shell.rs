//! Interactive shell channel over ConPTY.
//!
//! The Windows Pseudo Console (ConPTY) is a terminal: it *emits* VT/ANSI on its output and
//! *consumes* VT on its input. So the agent is a **dumb byte relay** — ConPTY output goes
//! straight to xterm.js in the browser, and xterm.js keystrokes go straight to the input. No
//! ANSI parsing here. See `docs/04-backstage.md`.
//!
//! We use the tested [`conpty`] crate for the pseudoconsole primitive (creating the
//! pseudoconsole and attaching the child via `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` is fiddly
//! to get right by hand). Our value-add is the [`ShellSession::split`] shape — three movable
//! halves so the transport can read, write, and control the shell concurrently — plus the
//! wire codec, server bridge, and RBAC/audit around it.
//!
//! The child runs under the agent's *current* identity here. In production the agent runs as
//! a LocalSystem service and would launch the child under a token from [`super::token`]
//! (logged-in user / SYSTEM / supplied credentials); only the process-creation step changes.

#![cfg(windows)]

use std::io::{Read, Write};

use conpty::io::{PipeReader, PipeWriter};
use conpty::Process;

/// Which built-in shell to launch. An allowlist, not a free-form command line, so this channel
/// can't be turned into an arbitrary-exec primitive that dodges the tool audit.
#[derive(Debug, Clone, Copy)]
pub enum ShellProgram {
    PowerShell,
    Cmd,
}

impl ShellProgram {
    /// Build the process command. We use a `std::process::Command` with explicit args rather
    /// than a command string, because `conpty::spawn(&str)` wraps its input in `cmd /C`, which
    /// would launch cmd instead of the shell we asked for.
    fn to_command(self) -> std::process::Command {
        match self {
            ShellProgram::PowerShell => {
                let mut c = std::process::Command::new("powershell.exe");
                c.arg("-NoLogo");
                c
            }
            ShellProgram::Cmd => std::process::Command::new("cmd.exe"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    #[error("conpty error: {0}")]
    ConPty(String),
}

fn err(e: impl std::fmt::Display) -> ShellError {
    ShellError::ConPty(e.to_string())
}

/// A live shell. Created whole, then [`split`](ShellSession::split) into three movable halves.
pub struct ShellSession {
    proc: Process,
    cols: u16,
    rows: u16,
}

impl ShellSession {
    /// Launch an allowlisted shell at the given terminal size.
    pub fn open(program: ShellProgram, cols: u16, rows: u16) -> Result<Self, ShellError> {
        Self::spawn_command(program.to_command(), cols, rows)
    }

    /// Launch a prepared [`std::process::Command`] under a pseudoconsole. Public for tests;
    /// production callers should prefer [`open`](ShellSession::open) with an allowlisted program.
    pub fn spawn_command(
        command: std::process::Command,
        cols: u16,
        rows: u16,
    ) -> Result<Self, ShellError> {
        let mut proc = Process::spawn(command).map_err(err)?;
        proc.resize(cols as i16, rows as i16).map_err(err)?;
        Ok(Self { proc, cols, rows })
    }

    /// Split into three halves that can each move onto their own task/thread:
    ///   * [`OutputReader`] — blocking reads of child output (reader thread).
    ///   * [`InputWriter`]  — write technician keystrokes (transport task).
    ///   * [`ShellControl`] — resize + lifetime; dropping it tears the shell down.
    pub fn split(mut self) -> Result<(OutputReader, InputWriter, ShellControl), ShellError> {
        let reader = self.proc.output().map_err(err)?;
        let writer = self.proc.input().map_err(err)?;
        Ok((
            OutputReader(reader),
            InputWriter(writer),
            ShellControl { proc: self.proc, cols: self.cols, rows: self.rows },
        ))
    }
}

// SAFETY for the three halves below: each owns its ConPTY resource exclusively and is only
// *moved* to a single thread, never shared. The underlying Windows handles are valid
// process-wide regardless of which thread touches them, so asserting Send is sound. (The
// conpty types are !Send only because they retain raw pointers in their startup info.)

/// Reader half — child output. `read` blocks until data or EOF (0 bytes) when the shell exits.
pub struct OutputReader(PipeReader);
unsafe impl Send for OutputReader {}
impl OutputReader {
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// Writer half — technician keystrokes into the shell.
pub struct InputWriter(PipeWriter);
unsafe impl Send for InputWriter {}
impl InputWriter {
    pub fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }
}

/// Control half — resize and lifetime. Dropping it ends the shell.
pub struct ShellControl {
    proc: Process,
    cols: u16,
    rows: u16,
}
unsafe impl Send for ShellControl {}
impl ShellControl {
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ShellError> {
        if (cols, rows) == (self.cols, self.rows) {
            return Ok(());
        }
        self.proc.resize(cols as i16, rows as i16).map_err(err)?;
        self.cols = cols;
        self.rows = rows;
        Ok(())
    }

    pub fn is_alive(&self) -> bool {
        self.proc.is_alive()
    }

    /// Block until the child exits (or the timeout elapses).
    pub fn wait(&self) {
        let _ = self.proc.wait(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Interactive round-trip: launch PowerShell, write a command, read output until the
    /// marker returns — proving both directions of the pseudoconsole.
    ///
    /// **`#[ignore]` by design.** A ConPTY child attaches to its host's console, and this can
    /// only be verified when the host process owns a real console. Under `cargo test` (and any
    /// console-less / stdio-redirected harness) the child fails to attach and renders to the
    /// wrong console, so this can't run here. The end-to-end path IS verified out-of-band by
    /// launching `shell_server` as its own process and running `ws_probe` against it — see
    /// `docs/05-backstage-implementation.md`. Run manually with:
    ///   cargo test -- --ignored conpty_interactive_roundtrip   (from a real console)
    #[test]
    #[ignore = "ConPTY child needs a real host console; verified via ws_probe (see docs/05)"]
    fn conpty_interactive_roundtrip() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::{channel, RecvTimeoutError};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let marker = "conpty_roundtrip_9182";
        let mut command = std::process::Command::new("powershell.exe");
        command.args(["-NoProfile", "-NoLogo"]);
        let session = ShellSession::spawn_command(command, 80, 25).expect("spawn ConPTY");
        let (mut reader, mut writer, control) = session.split().expect("split");

        // Reader streams chunks back on its own thread; treat transient WouldBlock as "no data
        // yet", not EOF.
        let (tx, rx) = channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        // Retry the command each second to ride out PowerShell startup.
        let done = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        let sender = std::thread::spawn(move || {
            let line = format!("Write-Output {marker}\r\n");
            while !done_w.load(Ordering::Relaxed) {
                let _ = writer.write(line.as_bytes());
                std::thread::sleep(Duration::from_secs(1));
            }
        });

        let mut text = String::new();
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(chunk) => {
                    text.push_str(&String::from_utf8_lossy(&chunk));
                    if text.contains(marker) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        done.store(true, Ordering::Relaxed);
        let _ = sender.join();
        drop(control);

        assert!(
            text.contains(marker),
            "expected {marker:?} to round-trip through ConPTY.\nGot {} bytes:\n{text}",
            text.len()
        );
    }
}
