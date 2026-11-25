package controlplane

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Toolbox script parameters (docs/75). A PowerShell item declares inputs with its own param() block; a run supplies
// name -> value and the server builds the command, so the run record's exec_sha256 still hashes exactly what is
// dispatched. Values are never stored (docs/75 D6).

const (
	// MaxToolboxParams bounds how many values one run may pass.
	MaxToolboxParams = 16
	// MaxToolboxParamValueBytes bounds one value in UTF-8 bytes.
	MaxToolboxParamValueBytes = 2048
	// maxToolboxPowerShellLauncher is the longest launcher prefix the agent puts before the command: a 260-character
	// SystemRoot (the same worst case TestToolboxPowerShellCommandFitsTheCommandLine assumes).
	maxToolboxPowerShellLauncher = len(`"`) + 260 + len(`\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command `)
	// MaxToolboxPowerShellCommandUnits is the longest command (ASCII, so units == bytes) that still fits the Windows
	// 32 767-unit command line, which counts its terminating NUL, behind that launcher.
	MaxToolboxPowerShellCommandUnits = 32767 - 1 - maxToolboxPowerShellLauncher
)

var toolboxParamName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

// toolboxReservedParams are PowerShell's common parameters and their aliases (lower case). Splatting one would
// change how a curated script handles errors or output (e.g. -ErrorAction Stop) while the record still names the
// item, so they are refused (security review 2026-11-24, SEC-002).
var toolboxReservedParams = map[string]bool{
	"verbose": true, "vb": true, "debug": true, "db": true, "erroraction": true, "ea": true,
	"warningaction": true, "wa": true, "informationaction": true, "infa": true, "progressaction": true, "proga": true,
	"errorvariable": true, "ev": true, "warningvariable": true, "wv": true, "informationvariable": true, "iv": true,
	"outvariable": true, "ov": true, "outbuffer": true, "ob": true, "pipelinevariable": true, "pv": true,
	"whatif": true, "wi": true, "confirm": true, "cf": true,
}

// ErrToolboxParams is the class of every parameter refusal; the message says which rule.
var ErrToolboxParams = errors.New("toolbox parameters")

func paramErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrToolboxParams, fmt.Sprintf(format, a...))
}

// ValidateToolboxParams enforces docs/75 D1 and D4. An empty map is always valid.
func ValidateToolboxParams(shell string, params map[string]string) error {
	if len(params) == 0 {
		return nil
	}
	if shell != ToolboxShellPowerShell {
		return paramErr("only PowerShell items take parameters")
	}
	if len(params) > MaxToolboxParams {
		return paramErr("at most %d parameters", MaxToolboxParams)
	}
	seen := make(map[string]bool, len(params))
	for name, value := range params {
		if !toolboxParamName.MatchString(name) {
			return paramErr("parameter names must be a letter followed by up to 31 letters, digits or underscores")
		}
		lower := strings.ToLower(name)
		if toolboxReservedParams[lower] {
			return paramErr("%s is a PowerShell common parameter and cannot be set from the Toolbox", name)
		}
		// PowerShell names (and hashtable keys) are case-insensitive: two spellings would be a parse error after
		// the run was already recorded (SEC-001).
		if seen[lower] {
			return paramErr("parameter %s is given twice (names are case-insensitive)", name)
		}
		seen[lower] = true
		if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return paramErr("parameter %s must be NUL-free UTF-8", name)
		}
		if len(value) > MaxToolboxParamValueBytes {
			return paramErr("parameter %s is longer than %d bytes", name, MaxToolboxParamValueBytes)
		}
	}
	return nil
}

// ToolboxCommandWithParams is ToolboxCommand plus splatted parameters. With no parameters it returns exactly
// ToolboxCommand's text. Each value reaches PowerShell only as the result of decoding a base64 literal, and each name
// matches toolboxParamName, so nothing supplied at run time is ever parsed as code (docs/75 D3).
func ToolboxCommandWithParams(shell, body string, params map[string]string) (string, error) {
	if err := ValidateToolboxParams(shell, params); err != nil {
		return "", err
	}
	if len(params) == 0 {
		return ToolboxCommand(shell, body), nil
	}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("$__drp = @{")
	for i, name := range names {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString("'")
		b.WriteString(name)
		b.WriteString("' = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('")
		b.WriteString(base64.StdEncoding.EncodeToString([]byte(params[name])))
		b.WriteString("'))")
	}
	b.WriteString("}; ")
	b.WriteString(ToolboxCommand(shell, body))
	b.WriteString(" @__drp")
	cmd := b.String()
	if len(cmd) > MaxToolboxPowerShellCommandUnits {
		return "", paramErr("the script and its parameter values together are too long for one command line")
	}
	return cmd, nil
}

// toolboxParamNames is the sorted name list recorded in the audit (never the values; docs/75 D6).
func toolboxParamNames(params map[string]string) []string {
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
