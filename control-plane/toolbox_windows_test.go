//go:build windows

package controlplane

// The toolbox's command text, launched exactly as the agent launches it
// (crates/agent-windows/src/command_run.rs build_invocation: CreateProcessW with lpCommandLine
// `"<SystemRoot>\...\powershell.exe" -NoProfile -NonInteractive -Command <command>` or
// `"<SystemRoot>\System32\cmd.exe" /C <command>`), on the Windows box running the tests. What
// this proves: Windows argument serialization + PowerShell's parsing deliver the stored script to the
// interpreter byte for byte at the size limits, with quotes, `$`, newlines and non-BMP characters. What
// it does not: the agent's own process plumbing (job object, token, pipes), which the command bar
// already exercises; output is compared as ASCII base64 so console code pages cannot interfere.

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func runAsAgentWould(t *testing.T, shell, command string) string {
	t.Helper()
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Fatal("SystemRoot is not set")
	}
	var exe, line string
	if shell == ToolboxShellPowerShell {
		exe = filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
		line = `"` + exe + `" -NoProfile -NonInteractive -Command ` + command
	} else {
		exe = filepath.Join(root, `System32\cmd.exe`)
		line = `"` + exe + `" /C ` + command
	}
	cmd := exec.Command(exe)
	// A non-empty CmdLine is used verbatim as the WHOLE command line (lpCommandLine), exactly the line
	// the agent builds, program token included.
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s exited with %v: %.500s", shell, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestToolboxPowerShellScriptArrivesByteForByte: the script reports, as base64, the exact text of a
// here-string embedded in itself; the payload carries quotes, $, backticks, CRLF/LF and non-BMP
// characters, and the whole body is padded to the 16 384-byte limit.
func TestToolboxPowerShellScriptArrivesByteForByte(t *testing.T) {
	payload := "single ' double \" back ` dollar $env:X sub $(1+1) € 😀 中文\r\nsecond line\nthird"
	head := "$s = @'\n" + payload + "\n'@\n[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s))\n"
	pad := MaxToolboxPowerShellBytes - len(head) - 1
	body := head + "#" + strings.Repeat("x", pad) // a comment pads to exactly the limit
	if len(body) != MaxToolboxPowerShellBytes {
		t.Fatalf("body is %d bytes, want exactly %d", len(body), MaxToolboxPowerShellBytes)
	}
	f := ToolboxFields{Name: "t", Shell: ToolboxShellPowerShell, RunAs: ToolboxRunAsSystem, Body: body}
	if err := ValidateToolboxFields(&f); err != nil {
		t.Fatalf("the test body itself is invalid: %v", err)
	}
	got := runAsAgentWould(t, ToolboxShellPowerShell, ToolboxCommand(ToolboxShellPowerShell, body))
	// A here-string normalizes its line endings to the script's; compare the LF-normalized payload.
	want := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(payload, "\r\n", "\n")))
	gotNorm := got
	if dec, err := base64.StdEncoding.DecodeString(got); err == nil {
		gotNorm = base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(dec), "\r\n", "\n")))
	}
	if gotNorm != want {
		t.Fatalf("the script did not arrive intact:\n got  %s\n want %s", got, want)
	}
}

// TestToolboxCmdLineAtTheLimitRuns: a cmd item of exactly 7 800 UTF-16 units (with non-BMP characters)
// is accepted by cmd.exe as the agent launches it.
func TestToolboxCmdLineAtTheLimitRuns(t *testing.T) {
	prefix := "echo "
	tail := strings.Repeat("😀", 10) // 20 units
	body := prefix + strings.Repeat("a", MaxToolboxCmdUnits-len(prefix)-20) + tail
	if n := utf16Len(body); n != MaxToolboxCmdUnits {
		t.Fatalf("body is %d units, want %d", n, MaxToolboxCmdUnits)
	}
	f := ToolboxFields{Name: "t", Shell: ToolboxShellCmd, RunAs: ToolboxRunAsSystem, Body: body}
	if err := ValidateToolboxFields(&f); err != nil {
		t.Fatalf("the test body itself is invalid: %v", err)
	}
	out := runAsAgentWould(t, ToolboxShellCmd, ToolboxCommand(ToolboxShellCmd, body))
	if !strings.HasPrefix(out, strings.Repeat("a", 100)) || len(out) < MaxToolboxCmdUnits-40 {
		t.Fatalf("cmd did not run the full line (output %d bytes): %.200s", len(out), out)
	}
}
