package controlplane

// Shared Toolbox v1 (docs/design-shared-toolbox.md, migration 0056). A tenant's library of saved
// scripts, SHARED (owner nil, managed with CapManageToolbox) or PERSONAL (visible to and editable by
// its owner only), run inside a live session through the existing RunCommand path. The toolbox adds
// storage, sharing and an audited run REQUEST; it adds no execution authority a session holder does
// not already have through the command bar.
//
// This file holds the pure parts: the item type, body validation (counted the way the agent's real
// invocation counts) and the command the console sends for an item.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	ToolboxShellPowerShell = "powershell"
	ToolboxShellCmd        = "cmd"
	ToolboxRunAsSystem     = "system"
	ToolboxRunAsUser       = "user"

	// MaxToolboxPowerShellBytes bounds a PowerShell body in UTF-8 bytes. The console sends it base64
	// encoded inside a fixed wrapper on `powershell.exe -NoProfile -NonInteractive -Command`; at this
	// size the whole command line stays far inside Windows' 32 767 UTF-16-unit limit (pinned by
	// TestToolboxPowerShellCommandFitsTheCommandLine).
	MaxToolboxPowerShellBytes = 16384
	// MaxToolboxCmdUnits bounds a cmd body in UTF-16 code units: the agent runs
	// `"<SystemRoot>\System32\cmd.exe" /C <command>` and cmd.exe caps a line at 8 191 characters;
	// 7 800 leaves room for the prefix with a SystemRoot up to MAX_PATH.
	MaxToolboxCmdUnits = 7800

	maxToolboxNameChars        = 120
	maxToolboxDescriptionChars = 1000

	// maxToolboxRequestBytes bounds a toolbox request body: the worst JSON escaping is 6 bytes per
	// UTF-16 unit (cmd: 7 800 x 6) or per control-character byte (PowerShell: 16 384 x 6 = 98 304).
	maxToolboxRequestBytes = 128 << 10
)

// ToolboxItem is one saved script. Owner is nil for a shared item.
type ToolboxItem struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"-"`
	Owner       *string   `json:"owner_user_id,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Shell       string    `json:"shell"`
	RunAs       string    `json:"run_as"`
	Body        string    `json:"body"`
	BodySHA256  string    `json:"body_sha256"`
	Version     int64     `json:"version"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Scope is "shared" or "personal".
func (it *ToolboxItem) Scope() string {
	if it.Owner == nil {
		return "shared"
	}
	return "personal"
}

// ToolboxFields are the editable fields (scope and owner are fixed at creation).
type ToolboxFields struct {
	Name        string
	Description string
	Shell       string
	RunAs       string
	Body        string
}

var (
	ErrToolboxNotFound  = errors.New("toolbox item not found")
	ErrToolboxVersion   = errors.New("toolbox item changed since it was read")
	ErrToolboxNameTaken = errors.New("a toolbox item with that name already exists in this scope")
)

// ToolboxValidationError is a 400: the message is safe to show.
type ToolboxValidationError struct{ Msg string }

func (e *ToolboxValidationError) Error() string { return e.Msg }

func toolboxInvalid(format string, a ...any) error {
	return &ToolboxValidationError{Msg: fmt.Sprintf(format, a...)}
}

// ValidateToolboxFields normalizes (trims name/description) and validates f in place.
func ValidateToolboxFields(f *ToolboxFields) error {
	f.Name = strings.TrimSpace(f.Name)
	f.Description = strings.TrimSpace(f.Description)
	if !utf8.ValidString(f.Name) || !utf8.ValidString(f.Description) {
		return toolboxInvalid("name and description must be valid UTF-8")
	}
	if n := utf8.RuneCountInString(f.Name); n < 1 || n > maxToolboxNameChars {
		return toolboxInvalid("name is required (at most %d characters)", maxToolboxNameChars)
	}
	if strings.ContainsAny(f.Name, "\x00\r\n") {
		return toolboxInvalid("name must be a single line")
	}
	if utf8.RuneCountInString(f.Description) > maxToolboxDescriptionChars || strings.ContainsRune(f.Description, 0) {
		return toolboxInvalid("description is at most %d characters", maxToolboxDescriptionChars)
	}
	// The run_as / shell / body rules are shared verbatim with the ad-hoc command-run endpoint
	// (http_command_run.go), so a one-off command and a saved item are validated — and length-capped —
	// identically. Extracted rather than copied so the two paths can never diverge.
	return ValidateCommandShellRunAsBody(f.Shell, f.RunAs, f.Body)
}

// ValidateCommandShellRunAsBody enforces the run_as, shell and body rules common to a saved toolbox
// item and an ad-hoc command run: a valid run_as, non-empty NUL-free UTF-8 body, and the per-shell
// length/line caps the agent's RunCommand decode mirrors (cmd is a single line ≤ MaxToolboxCmdUnits
// UTF-16 units; PowerShell is ≤ MaxToolboxPowerShellBytes bytes). The error wording matches the
// toolbox form so existing messages are unchanged.
func ValidateCommandShellRunAsBody(shell, runAs, body string) error {
	switch runAs {
	case ToolboxRunAsSystem, ToolboxRunAsUser:
	default:
		return toolboxInvalid(`run_as must be "system" or "user"`)
	}
	// Strict UTF-8: invalid input is refused, never replaced, so the stored body (and its hash) is
	// exactly what was submitted.
	if !utf8.ValidString(body) {
		return toolboxInvalid("the script must be valid UTF-8")
	}
	if body == "" || strings.TrimSpace(body) == "" {
		return toolboxInvalid("the script is empty")
	}
	if strings.ContainsRune(body, 0) {
		return toolboxInvalid("the script must not contain NUL characters")
	}
	switch shell {
	case ToolboxShellPowerShell:
		if len(body) > MaxToolboxPowerShellBytes {
			return toolboxInvalid("a PowerShell script is at most %d bytes (this one is %d)", MaxToolboxPowerShellBytes, len(body))
		}
	case ToolboxShellCmd:
		if strings.ContainsAny(body, "\r\n") {
			return toolboxInvalid("a cmd item is a single line")
		}
		if n := utf16Len(body); n > MaxToolboxCmdUnits {
			return toolboxInvalid("a cmd line is at most %d UTF-16 units (this one is %d)", MaxToolboxCmdUnits, n)
		}
	default:
		return toolboxInvalid(`shell must be "powershell" or "cmd"`)
	}
	return nil
}

// utf16Len counts UTF-16 code units (a non-BMP character is 2), as Windows counts a command line.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += len(utf16.Encode([]rune{r}))
	}
	return n
}

// ToolboxBodySHA256 is the hex sha256 of the body's UTF-8 bytes.
func ToolboxBodySHA256(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// ToolboxCommand is the exact `RunCommand.command` text for an item. A cmd item is its line as-is. A
// PowerShell item is a fixed wrapper around the base64 of its UTF-8 bytes; base64's alphabet
// [A-Za-z0-9+/=] cannot leave the single-quoted literal, so the body never meets PowerShell's parser
// as anything but the decoded script.
func ToolboxCommand(shell, body string) string {
	if shell == ToolboxShellCmd {
		return body
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(body))
	return "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + b64 + "'))))"
}

// ToolboxRunRequest is what a run records and returns.
type ToolboxRunRequest struct {
	RequestID string
	Item      ToolboxItem // the single snapshot the audit fields and the command come from
	SessionID string
	MachineID string
	Command   string
}

// ToolboxStore persists items. Every method takes the caller: visibility (`owner IS NULL OR owner =
// caller`) is applied in every query, and each mutation commits with its management-audit event in
// one transaction. The returned event (when non-nil) is for post-commit webhook dispatch only.
type ToolboxStore interface {
	List(ctx context.Context, tenantID, callerID string) ([]ToolboxItem, error)
	Get(ctx context.Context, tenantID, callerID, id string) (*ToolboxItem, error)
	Create(ctx context.Context, tenantID, callerID string, personal bool, f ToolboxFields, id string) (*ToolboxItem, *MgmtAuditEvent, error)
	// Update / Delete: perms says what the caller may change. A SHARED item needs ManageShared; a
	// personal item can be changed only by its owner (anyone else gets ErrToolboxNotFound), and only
	// while the owner may use the toolbox (UsePersonal).
	Update(ctx context.Context, tenantID, callerID string, perms ToolboxPerms, id string, expectedVersion int64, f ToolboxFields) (*ToolboxItem, *MgmtAuditEvent, error)
	Delete(ctx context.Context, tenantID, callerID string, perms ToolboxPerms, id string, expectedVersion int64) (*MgmtAuditEvent, error)
	// RecordRun reads the item once (visible to caller, at expectedVersion), appends
	// toolbox.run_requested with the request's fields, commits, and returns the snapshot.
	// The actor's email is read in the same transaction (attribution survives a later email change).
	RecordRun(ctx context.Context, tenantID, callerID, id string, expectedVersion int64, sessionID, machineID, requestID string) (*ToolboxRunRequest, *MgmtAuditEvent, error)
}

// ToolboxPerms is what a caller may change: SHARED items need CapManageToolbox; PERSONAL items (and
// listing, and run requests) need CapStartSession. A custom role may hold either one alone.
type ToolboxPerms struct {
	ManageShared bool
	UsePersonal  bool
}

// ErrToolboxSharedDenied: a shared item changed by a caller without CapManageToolbox.
var ErrToolboxSharedDenied = errors.New("managing shared toolbox items requires the manage_toolbox capability")

// ErrToolboxPersonalDenied: a personal item changed by a caller without CapStartSession.
var ErrToolboxPersonalDenied = errors.New("personal toolbox items require the start_session capability")
