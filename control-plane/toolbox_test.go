package controlplane

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

func validFields(shell, body string) ToolboxFields {
	return ToolboxFields{Name: "item", Shell: shell, RunAs: ToolboxRunAsSystem, Body: body}
}

func isValidationErr(err error) bool {
	var v *ToolboxValidationError
	return errors.As(err, &v)
}

func TestToolboxPowerShellByteLimit(t *testing.T) {
	ok := validFields(ToolboxShellPowerShell, strings.Repeat("a", MaxToolboxPowerShellBytes))
	if err := ValidateToolboxFields(&ok); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	over := validFields(ToolboxShellPowerShell, strings.Repeat("a", MaxToolboxPowerShellBytes+1))
	if err := ValidateToolboxFields(&over); !isValidationErr(err) {
		t.Fatalf("one byte over: %v, want a validation error", err)
	}
	// Bytes, not characters: 5 462 three-byte characters = 16 386 bytes is over.
	wide := validFields(ToolboxShellPowerShell, strings.Repeat("€", 5462))
	if err := ValidateToolboxFields(&wide); !isValidationErr(err) {
		t.Fatalf("16 386 bytes of three-byte characters: %v, want refused", err)
	}
}

func TestToolboxCmdLimitCountsUTF16Units(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"ascii at limit", strings.Repeat("a", MaxToolboxCmdUnits), true},
		{"ascii over", strings.Repeat("a", MaxToolboxCmdUnits+1), false},
		// Three-byte BMP characters are ONE unit each: 7 800 of them (23 400 bytes) is valid.
		{"three-byte BMP at limit", strings.Repeat("€", MaxToolboxCmdUnits), true},
		{"three-byte BMP over", strings.Repeat("€", MaxToolboxCmdUnits+1), false},
		// Non-BMP characters are TWO units each: 3 900 of them is exactly the limit.
		{"non-BMP at limit", strings.Repeat("😀", MaxToolboxCmdUnits/2), true},
		{"non-BMP over by one unit", strings.Repeat("😀", MaxToolboxCmdUnits/2) + "a", false},
		{"newline", "echo a\necho b", false},
		{"carriage return", "echo a\recho b", false},
	}
	for _, c := range cases {
		f := validFields(ToolboxShellCmd, c.body)
		err := ValidateToolboxFields(&f)
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && !isValidationErr(err) {
			t.Errorf("%s: %v, want a validation error", c.name, err)
		}
	}
}

func TestToolboxBodyRules(t *testing.T) {
	for name, f := range map[string]ToolboxFields{
		"invalid UTF-8":   validFields(ToolboxShellPowerShell, "Write-Output \xff\xfe"),
		"NUL powershell":  validFields(ToolboxShellPowerShell, "a\x00b"),
		"NUL cmd":         validFields(ToolboxShellCmd, "a\x00b"),
		"empty":           validFields(ToolboxShellPowerShell, ""),
		"whitespace only": validFields(ToolboxShellPowerShell, " \n\t "),
		"bad shell":       validFields("bash", "ls"),
		"bad run_as":      {Name: "x", Shell: ToolboxShellCmd, RunAs: "admin", Body: "dir"},
		"no name":         {Name: "  ", Shell: ToolboxShellCmd, RunAs: ToolboxRunAsUser, Body: "dir"},
		"multi-line name": {Name: "a\nb", Shell: ToolboxShellCmd, RunAs: ToolboxRunAsUser, Body: "dir"},
		"long name":       {Name: strings.Repeat("n", 121), Shell: ToolboxShellCmd, RunAs: ToolboxRunAsUser, Body: "dir"},
	} {
		f := f
		if err := ValidateToolboxFields(&f); !isValidationErr(err) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
	f := ToolboxFields{Name: "  Disk usage  ", Description: "  d  ", Shell: ToolboxShellPowerShell, RunAs: ToolboxRunAsUser, Body: "Get-PSDrive"}
	if err := ValidateToolboxFields(&f); err != nil || f.Name != "Disk usage" || f.Description != "d" {
		t.Fatalf("trimmed fields: %+v %v", f, err)
	}
}

var toolboxWrapper = regexp.MustCompile(`^& \(\[scriptblock\]::Create\(\[Text\.Encoding\]::UTF8\.GetString\(\[Convert\]::FromBase64String\('([A-Za-z0-9+/=]*)'\)\)\)\)$`)

// TestToolboxPowerShellCommandRoundTrips: the wrapper is exactly the fixed text around a base64
// literal (nothing from the body can appear outside it), and the literal decodes to the body's bytes.
func TestToolboxPowerShellCommandRoundTrips(t *testing.T) {
	for _, body := range []string{
		"Write-Output 'single' \"double\" `backtick $env:COMPUTERNAME",
		"line1\r\nline2\nline3",
		"'); Remove-Item C:\\ -Recurse; ('",
		"Ünïcödé € 😀 中文",
		strings.Repeat("x", MaxToolboxPowerShellBytes),
	} {
		cmd := ToolboxCommand(ToolboxShellPowerShell, body)
		m := toolboxWrapper.FindStringSubmatch(cmd)
		if m == nil {
			t.Fatalf("command does not match the fixed wrapper: %.120q", cmd)
		}
		dec, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil || string(dec) != body {
			t.Fatalf("round trip failed for %.40q: %v", body, err)
		}
	}
	if got := ToolboxCommand(ToolboxShellCmd, "ipconfig /all"); got != "ipconfig /all" {
		t.Fatalf("cmd item must be sent as-is, got %q", got)
	}
}

// TestToolboxPowerShellCommandFitsTheCommandLine: at the byte limit, the agent's whole command line
// (crates/agent-windows/src/command_run.rs build_invocation, with a SystemRoot as long as MAX_PATH)
// stays inside Windows' 32 767 UTF-16-unit limit.
func TestToolboxPowerShellCommandFitsTheCommandLine(t *testing.T) {
	root := "C:\\" + strings.Repeat("r", 257) // 260 characters
	exe := root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	worst := strings.Repeat("😀", MaxToolboxPowerShellBytes/4) // any body of the max byte size encodes to the same length
	line := `"` + exe + `" -NoProfile -NonInteractive -Command ` + ToolboxCommand(ToolboxShellPowerShell, worst)
	if n := len(utf16.Encode([]rune(line))); n > 32767 {
		t.Fatalf("command line is %d UTF-16 units, over 32 767", n)
	}
	cmdLine := `"` + root + `\System32\cmd.exe" /C ` + strings.Repeat("a", MaxToolboxCmdUnits)
	if n := len(utf16.Encode([]rune(cmdLine))); n > 8191 {
		t.Fatalf("cmd line is %d characters, over cmd.exe's 8 191", n)
	}
}

func TestJSONTextIsStrict(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"plain", `{"body":"Get-Date"}`, true},
		{"escaped pair", `{"body":"\uD83D\uDE00"}`, true},
		{"BMP escape", `{"body":"\u20AC \u0041"}`, true},
		{"escaped backslash then u-text", `{"body":"C:\\uD800"}`, true}, // a backslash followed by the text uD800
		{"lone high at end", `{"body":"\uD83D"}`, false},
		{"high then non-low", `{"body":"\uD83D\u0041"}`, false},
		{"high then text", `{"body":"\uD83Dabcdef"}`, false},
		{"lone low", `{"body":"\uDE00"}`, false},
		{"low then high (reversed)", `{"body":"\uDE00\uD83D"}`, false},
		{"lowercase hex pair", `{"body":"\ud83d\ude00"}`, true},
		{"invalid UTF-8 byte", "{\"body\":\"a\xffb\"}", false},
		{"overlong UTF-8", "{\"body\":\"\xc0\xaf\"}", false},
	}
	for _, c := range cases {
		if got := jsonTextIsStrict([]byte(c.raw)); got != c.ok {
			t.Errorf("%s: jsonTextIsStrict = %v, want %v", c.name, got, c.ok)
		}
	}
}
