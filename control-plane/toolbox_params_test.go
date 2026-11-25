package controlplane

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestToolboxCommandWithParamsNoParamsIsUnchanged(t *testing.T) {
	for _, shell := range []string{ToolboxShellPowerShell, ToolboxShellCmd} {
		got, err := ToolboxCommandWithParams(shell, "Get-Date", nil)
		if err != nil || got != ToolboxCommand(shell, "Get-Date") {
			t.Fatalf("%s: %q, %v", shell, got, err)
		}
	}
}

func TestValidateToolboxParamsRules(t *testing.T) {
	many := map[string]string{}
	for i := 0; i <= MaxToolboxParams; i++ {
		many[fmt.Sprintf("P%d", i)] = "x"
	}
	cases := []struct {
		name   string
		shell  string
		params map[string]string
	}{
		{"cmd item", ToolboxShellCmd, map[string]string{"A": "x"}},
		{"name with a space", ToolboxShellPowerShell, map[string]string{"A B": "x"}},
		{"name starting with a digit", ToolboxShellPowerShell, map[string]string{"1A": "x"}},
		{"name with a quote", ToolboxShellPowerShell, map[string]string{"A'": "x"}},
		{"name of 33 characters", ToolboxShellPowerShell, map[string]string{"A" + strings.Repeat("b", 32): "x"}},
		{"too many", ToolboxShellPowerShell, many},
		{"NUL", ToolboxShellPowerShell, map[string]string{"A": "a\x00b"}},
		{"invalid UTF-8", ToolboxShellPowerShell, map[string]string{"A": "\xff"}},
		{"value too long", ToolboxShellPowerShell, map[string]string{"A": strings.Repeat("x", MaxToolboxParamValueBytes+1)}},
		{"common parameter", ToolboxShellPowerShell, map[string]string{"ErrorAction": "Stop"}},
		{"common parameter alias, any case", ToolboxShellPowerShell, map[string]string{"OV": "x"}},
		{"case-insensitive duplicate", ToolboxShellPowerShell, map[string]string{"User": "a", "user": "b"}},
	}
	for _, c := range cases {
		if err := ValidateToolboxParams(c.shell, c.params); !errors.Is(err, ErrToolboxParams) {
			t.Errorf("%s: err = %v, want ErrToolboxParams", c.name, err)
		}
	}
	ok := map[string]string{"User": "alice", "A_1": strings.Repeat("x", MaxToolboxParamValueBytes)}
	if err := ValidateToolboxParams(ToolboxShellPowerShell, ok); err != nil {
		t.Fatalf("valid params refused: %v", err)
	}
}

func TestToolboxCommandWithParamsFitsTheCommandLine(t *testing.T) {
	// The largest body plus the largest parameter set is refused rather than producing an over-long line.
	body := strings.Repeat("x", MaxToolboxPowerShellBytes)
	params := map[string]string{}
	for i := 0; i < MaxToolboxParams; i++ {
		params[fmt.Sprintf("P%02d", i)] = strings.Repeat("v", MaxToolboxParamValueBytes)
	}
	if _, err := ToolboxCommandWithParams(ToolboxShellPowerShell, body, params); !errors.Is(err, ErrToolboxParams) {
		t.Fatalf("over-long command accepted: %v", err)
	}
	// A realistic run fits, and whatever is accepted stays within the launcher budget.
	cmd, err := ToolboxCommandWithParams(ToolboxShellPowerShell, strings.Repeat("x", 4096), map[string]string{"User": "alice"})
	if err != nil || len(cmd) > MaxToolboxPowerShellCommandUnits {
		t.Fatalf("realistic run: len %d, %v", len(cmd), err)
	}
	if maxToolboxPowerShellLauncher+MaxToolboxPowerShellCommandUnits+1 != 32767 {
		t.Fatalf("launcher budget arithmetic drifted")
	}
}

// The values reach the script as data, whatever they contain (docs/75 D3). Runs real Windows PowerShell; the gate
// runs on Windows. Values that PowerShell would treat as quotes, code or separators must come back byte-identical.
func TestToolboxParamsReachPowerShellAsData(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("needs Windows PowerShell")
	}
	exe, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatalf("powershell.exe: %v", err)
	}
	hostile := []string{
		"plain",
		"it's",
		"‘curly’ ‚ ‛ quotes",
		"$(Write-Output pwned)",
		"`n backtick; Remove-Item x",
		"line1\r\nline2",
		"'; exit 3; '",
		"\" double \"",
		"@{a=1}",
		"😀 ünïcödé",
		"",
	}
	body := "param($A, $B)\n[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($A + [char]0x1F + $B)))"
	for _, v := range hostile {
		cmd, err := ToolboxCommandWithParams(ToolboxShellPowerShell, body, map[string]string{"A": v, "B": "tail"})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		out, err := exec.Command(exe, "-NoProfile", "-NonInteractive", "-Command", cmd).Output()
		if err != nil {
			t.Fatalf("%q: powershell failed: %v (%s)", v, err, out)
		}
		got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
		if err != nil {
			t.Fatalf("%q: output %q is not base64", v, out)
		}
		if want := v + "\x1f" + "tail"; string(got) != want {
			t.Errorf("value %q arrived as %q", v, got)
		}
	}
}
