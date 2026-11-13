package controlplane

// Fleet agent directives (docs/65; review r1 contracts D-C1..D-C9 are binding): reinstall or remove an
// installed agent WITHOUT opening a session. This file holds the model, the store seam and the in-memory
// store that must agree with PgDirectiveStore (pgstore_directive.go); the HTTP surface is
// http_directive.go and the signed artifact is directive_sign.go.
//
// A directive's life:
//
//	requested -> issued -> accepted -> executing -> complete | failed | reboot_pending -> ...
//	    |           |                                   (removal_unconfirmed: a started removal that never reported)
//	    +-> cancelled (cancel window)     +-> expired (never accepted in time)
//
// FORGOTTEN (docs/65 sec. 8) is the control plane's own terminal state for a directive that was still ACTIVE
// when an Owner forgot its machine: it is reached from ANY active state, never by an agent report, and says
// nothing about what the agent did.
//
// REQUESTED is the reservation. Nothing is signed until the cancel window ends and the pending->issued
// transition re-checks EVERYTHING under the tenant issuance lock (D-C4): tenant active, machine still in
// the state the kind needs and in a group both humans still cover, both still holding CapRemoveAgent,
// the policy unchanged, the request not cancelled or expired, the quotas. Authority is never cached from
// request time: an approval or a request is a record of intent, not a credential.
//
// AUDIT FIRST. Every transition writes its management-audit row in the SAME transaction as the state
// change (the fake records the audit row before it mutates), so a failing audit store leaves no
// directive, no issuance and no delivery.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DirectiveState is agent_directive.state.
type DirectiveState string

const (
	DirectiveRequested          DirectiveState = "requested"
	DirectiveIssued             DirectiveState = "issued"
	DirectiveAccepted           DirectiveState = "accepted"
	DirectiveExecuting          DirectiveState = "executing"
	DirectiveRebootPending      DirectiveState = "reboot_pending"
	DirectiveComplete           DirectiveState = "complete"
	DirectiveFailed             DirectiveState = "failed"
	DirectiveRemovalUnconfirmed DirectiveState = "removal_unconfirmed"
	DirectiveCancelled          DirectiveState = "cancelled"
	DirectiveExpired            DirectiveState = "expired"
	// DirectiveForgotten is TERMINAL and CONTROL-PLANE-ONLY (migration 0073): an Owner forgot the machine
	// while this directive was active. Like removal_unconfirmed it is never reported by an agent (the agent's
	// closed state list is crates/protocol/src/directive.rs, and directiveTransitionAllowed names it as neither
	// a source nor a target) and never sent to one (a directive reaches an agent only as its signed artifact,
	// and signaling echoes only the agent's own from/to/ts_ms).
	DirectiveForgotten DirectiveState = "forgotten"
)

// active reports whether the state counts against the one-active-directive-per-device rule (the partial
// unique index agent_directive_one_active in migrations/0068 lists exactly these).
func (s DirectiveState) active() bool {
	switch s {
	case DirectiveRequested, DirectiveIssued, DirectiveAccepted, DirectiveExecuting, DirectiveRebootPending,
		DirectiveRemovalUnconfirmed:
		// removal_unconfirmed stays ACTIVE: a signed uninstall may still be executing on the machine, so the
		// per-machine exclusion and the machine status/group guard must hold until it is resolved.
		return true
	}
	return false
}

const (
	// directiveCancelWindow is how long an UNINSTALL request waits before it may be issued; any
	// CapRemoveAgent holder in the machine's group can cancel in it. Reinstall has no window.
	directiveCancelWindow = 15 * time.Minute
	// directiveRequestTTL is how long a request may wait (approval, a dead sweeper) before it expires. It is
	// deliberately SHORT: a request is a record of intent by sessions that were live when it was made, and
	// the longer it can wait the staler that intent is when the sweeper signs it. An approval restarts the
	// cancel window, so a request approved too late to still leave a full window before this expiry is
	// refused (ErrDirectiveExpired) rather than having its lifetime extended.
	directiveRequestTTL = time.Hour
	// directiveAckMaxAge: an agent acknowledgement older than this is refused (together with a strictly
	// increasing ts_ms per directive this closes replay of an old, validly signed acknowledgement).
	directiveAckMaxAge = time.Hour
	// directiveStepUpMaxAge: an uninstall request needs a TOTP step-up this fresh (checked at REQUEST time).
	directiveStepUpMaxAge = 10 * time.Minute
	// DefaultUninstallHourlyCap / DefaultReinstallDailyCap / DefaultReinstallHourlyCap are the quotas:
	// removals tenant-wide per hour, reinstalls per device per day AND tenant-wide per hour (a reinstall has
	// no cancel window and no approval, so the tenant-wide hourly cap is what stops a stolen session from
	// cycling the whole fleet). Each is counted at request AND again at issuance. Stores carry them as
	// fields so tests can lower them.
	DefaultUninstallHourlyCap = 10
	DefaultReinstallDailyCap  = 3
	DefaultReinstallHourlyCap = 20
	// directiveUnconfirmedAfter: an accepted/executing/reboot_pending directive that has not changed for
	// this long is resolved by the sweeper (uninstall -> removal_unconfirmed, reinstall -> failed).
	directiveUnconfirmedAfter = 2 * time.Hour
	// directivePendingLimit bounds what one registration fetch can return.
	directivePendingLimit = 4
	directiveListLimit    = 200
	maxCancelReasonRunes  = 300
)

// AgentDirective is one directive row. Artifact and Nonce never leave the control plane's stores except in
// the pending fetch for the authenticated device (json:"-" keeps them out of every console view).
type AgentDirective struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	MachineID        string         `json:"machine_id"`
	DeviceID         string         `json:"device_id"`
	KeyFP            string         `json:"key_fp"`
	GroupID          string         `json:"group_id"`
	Kind             DirectiveKind  `json:"kind"`
	State            DirectiveState `json:"state"`
	RequestedBy      string         `json:"requested_by"`
	RequestedAt      time.Time      `json:"requested_at"`
	NotBefore        time.Time      `json:"not_before"`
	RequestExpiresAt time.Time      `json:"request_expires_at"`
	RequireApproval  bool           `json:"require_approval"`
	PolicyVersion    int64          `json:"policy_version"`
	ApprovedBy       string         `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time     `json:"approved_at,omitempty"`
	CancelledBy      string         `json:"cancelled_by,omitempty"`
	CancelledAt      *time.Time     `json:"cancelled_at,omitempty"`
	CancelReason     string         `json:"cancel_reason,omitempty"`
	IssuedAt         *time.Time     `json:"issued_at,omitempty"`
	ExpiresAt        *time.Time     `json:"expires_at,omitempty"`
	DeliveredAt      *time.Time     `json:"delivered_at,omitempty"`
	AckedAt          *time.Time     `json:"acked_at,omitempty"`
	StateDetail      string         `json:"state_detail,omitempty"`
	UpdatedAt        time.Time      `json:"updated_at"`

	Nonce    []byte `json:"-"`
	Artifact string `json:"-"`

	// The credentials the requester and the approver acted under, recorded when they acted and compared with
	// the user's CURRENT state at issuance: a revoked session, a password change or an MFA reset since ends
	// the directive.
	RequestedSession string    `json:"-"`
	RequestedEpoch   time.Time `json:"-"`
	RequestedMFAGen  int64     `json:"-"`
	ApprovedSession  string    `json:"-"`
	ApprovedEpoch    time.Time `json:"-"`
	ApprovedMFAGen   int64     `json:"-"`
	LastAckTsMs      int64     `json:"-"` // ts_ms of the last accepted acknowledgement (strictly increasing)
	// AgentState is the last state the AGENT reported (or, for an unconfirmed removal, the state it was last
	// known to be in), kept apart from the control plane's own outcome (State = removal_unconfirmed) so a late
	// but genuine completion bound to that state can still be accepted.
	AgentState DirectiveState `json:"-"`
}

// DirectiveActor is a human who acted on a directive, with the credential state they acted under: the
// session id, the credential epoch (user_credential.updated_at) and the mfa generation.
type DirectiveActor struct {
	UserID          string
	SessionID       string
	CredentialEpoch time.Time
	MFAGeneration   int64
}

func (d *AgentDirective) requester() DirectiveActor {
	return DirectiveActor{UserID: d.RequestedBy, SessionID: d.RequestedSession, CredentialEpoch: d.RequestedEpoch, MFAGeneration: d.RequestedMFAGen}
}

func (d *AgentDirective) approver() DirectiveActor {
	return DirectiveActor{UserID: d.ApprovedBy, SessionID: d.ApprovedSession, CredentialEpoch: d.ApprovedEpoch, MFAGeneration: d.ApprovedMFAGen}
}

// DirectivePolicy is the tenant's directive policy. Version moves on every CHANGE; a request snapshots it
// and issuance refuses when it moved (D-C4 "policy unchanged").
type DirectivePolicy struct {
	RequireSecondApprover bool  `json:"require_second_approver"`
	Version               int64 `json:"version"`
}

// DirectiveRequestInput is a request. Device, key fingerprint and group are DERIVED from the locked machine
// row inside the store; ExpectGroupID is the group the CALLER authorized against, and a machine that moved
// since is refused (ErrDirectiveMachineChanged).
type DirectiveRequestInput struct {
	MachineID     string
	Kind          DirectiveKind
	RequestedBy   string
	ExpectGroupID string
	// The requesting human's credential state (see DirectiveActor).
	RequestedSession string
	RequestedEpoch   time.Time
	RequestedMFAGen  int64
}

// DirectiveAuthority re-derives, at issuance, whether the actor is still an enabled member holding
// CapRemoveAgent on groupID (the machine's CURRENT group, descendants included - docs/62 sec. 2a) AND is
// still acting under the credentials they used (session live, credential epoch and mfa generation
// unchanged). A nil error means yes; ErrDirectiveAuthorityLost means no; anything else is infrastructure
// and aborts without a state change.
type DirectiveAuthority func(ctx context.Context, who DirectiveActor, groupID string) error

// DirectiveIssueDeps are the collaborators Issue needs from the server layer.
type DirectiveIssueDeps struct {
	Authority DirectiveAuthority
	Issuer    *DirectiveIssuer
}

// Errors. Request-side first.
var (
	ErrDirectiveNotFound          = errors.New("directive not found")
	ErrDirectiveMachineRemoved    = errors.New("machine was removed")
	ErrDirectiveNotRetired        = errors.New("an agent can only be removed from a retired machine")
	ErrDirectiveMachineRetired    = errors.New("an agent on a retired machine can only be removed, not reinstalled")
	ErrDirectiveNoKey             = errors.New("machine has no pinned agent key")
	ErrDirectiveMachineChanged    = errors.New("machine changed since it was authorized; retry")
	ErrDirectiveActiveExists      = errors.New("machine already has an active directive")
	ErrDirectiveQuota             = errors.New("directive quota exceeded")
	ErrDirectiveTenantSuspended   = errors.New("tenant suspended")
	ErrDirectiveSelfApproval      = errors.New("the requester cannot approve their own directive")
	ErrDirectiveApprovalNotNeeded = errors.New("this directive does not require approval")
	ErrDirectiveAlreadyApproved   = errors.New("directive is already approved")
	ErrDirectiveNotPending        = errors.New("directive is not pending")
	ErrDirectiveNotCancellable    = errors.New("directive can no longer be cancelled")
	ErrDirectiveNotIssuable       = errors.New("directive is not issuable")
	ErrDirectiveTooEarly          = errors.New("directive cancel window has not ended")
	ErrDirectiveNeedsApproval     = errors.New("directive is waiting for a second approver")
	ErrDirectiveExpired           = errors.New("directive expired")
	ErrDirectiveAuthorityLost     = errors.New("requester or approver no longer holds remove_agent for the machine's group, or their session or credentials changed since")
	ErrDirectiveBadTransition     = errors.New("not a valid transition for this directive")
	ErrDirectiveBadTimestamp      = errors.New("acknowledgement timestamp is in the future")
	ErrDirectiveStaleAck          = errors.New("acknowledgement is stale: not newer than the last accepted one, or too old")
	ErrDirectiveBadSignature      = errors.New("acknowledgement signature does not verify")
	ErrDirectiveKeyChanged        = errors.New("the device key is not the key this directive was issued for")
	// ErrDirectiveFinalAckWindowClosed: the final-ack window (directiveFinalAckWindow) had passed when the
	// apply read the LOCKED row, whatever the route's earlier snapshot said.
	ErrDirectiveFinalAckWindowClosed = errors.New("the final-acknowledgement window for this directive has passed")
	// ErrForgetNotRetired: a machine can only be forgotten once it is RETIRED (docs/65 sec. 8: retire first,
	// then forget - two deliberate steps). An active or quarantined machine is still in service.
	ErrForgetNotRetired = errors.New("a machine can only be forgotten after it is retired")
)

// ForgetMachineInput is an Owner's "forget this machine" (docs/65 sec. 8). The machine's device id, key and
// status are read from the LOCKED row inside the store; the caller supplies only who acted and the group they
// authorized against.
type ForgetMachineInput struct {
	MachineID string
	// ActorID is the Owner who forgot the machine: the actor of every audit row.
	ActorID string
	// ExpectGroupID is the group the CALLER authorized against (CapRemoveAgent on it); a machine that moved
	// since is refused (ErrDirectiveMachineChanged), exactly as a directive request is.
	ExpectGroupID string
}

// ForgetResult says what a ForgetMachine call did.
type ForgetResult struct {
	// AlreadyRemoved: the machine was already removed (a confirmed removal, or an earlier forget). Nothing was
	// written - no second audit row, no state change - and the caller answers with the current state.
	AlreadyRemoved bool
	// Closed are the directives that were ACTIVE and are now forgotten, as they are NOW (State forgotten; the
	// state each was in is in its directive.forgotten audit row, "from"). At most one: agent_directive_one_active
	// allows one active directive per machine. Empty for a machine with no active directive.
	Closed []AgentDirective
}

// forgottenDetail is the state_detail of a directive closed by a forget: the control plane's own words, not
// the agent's (the row's agent_state keeps the last thing the AGENT reported).
const forgottenDetail = "closed when an owner forgot this machine; the agent never confirmed the removal"

// DirectiveRefusedError is returned when Issue found the directive no longer issuable and ENDED it
// (cancelled by the system). The directive carries the final row.
type DirectiveRefusedError struct{ Reason string }

func (e *DirectiveRefusedError) Error() string { return "directive refused at issuance: " + e.Reason }

// DirectiveSweepItem is one thing the sweeper should do. Action is expire | issue | renotify | unconfirmed.
type DirectiveSweepItem struct {
	TenantID    string
	DirectiveID string
	Action      string
	due         time.Time // when it became due (ordering inside one action rank; the fake only)
}

// DirectiveStore is the persistence seam. Every method is tenant-scoped except SweepCandidates (the one
// cross-tenant read, which only says WHERE to look). The pg store runs under RLS and takes its locks in a
// fixed order: tenant issuance lock (shared), tenant quota lock, machine row, directive row, audit chain.
type DirectiveStore interface {
	// Request reserves a directive. Re-validates the machine under lock: exists, not removed, has a key,
	// still in ExpectGroupID, status retired for an uninstall, no active directive (ErrDirectiveActiveExists),
	// quota (ErrDirectiveQuota), tenant not suspended. Snapshots the tenant policy. Audited.
	Request(ctx context.Context, tenantID string, in DirectiveRequestInput) (*AgentDirective, error)
	// Approve records the second approver. The requester can never approve (ErrDirectiveSelfApproval);
	// ErrDirectiveApprovalNotNeeded when the request did not snapshot the policy. Approval RESTARTS the cancel
	// window (NotBefore = max(NotBefore, now + window)) so it never issues immediately; one that would leave
	// no full window before the request expires is ErrDirectiveExpired. Audited.
	Approve(ctx context.Context, tenantID, id string, approver DirectiveActor) (*AgentDirective, error)
	// Cancel ends a REQUESTED directive; anything later is ErrDirectiveNotCancellable (the returned row says
	// what it is now). Audited.
	Cancel(ctx context.Context, tenantID, id, actorID, reason string) (*AgentDirective, error)
	// Issue is the atomic pending -> issued transition (D-C4). See the type doc.
	Issue(ctx context.Context, tenantID, id string, deps DirectiveIssueDeps) (*AgentDirective, error)
	Get(ctx context.Context, tenantID, id string) (*AgentDirective, error)
	// List returns a machine's directives (machineID != "") or the tenant's, newest first, bounded.
	List(ctx context.Context, tenantID, machineID string) ([]AgentDirective, error)
	// ListActive returns the tenant's ACTIVE directives (state.active(): requested, issued, accepted, executing,
	// reboot_pending, removal_unconfirmed), ordered requested_at DESC, id ASC, strictly AFTER the keyset cursor
	// (before, beforeID) in that order when before is non-zero (requested_at < before OR requested_at = before
	// AND id > beforeID), at most limit (capped at directiveListLimit). It knows nothing of groups: the HTTP handler
	// filters each row by the machine's CURRENT group.
	ListActive(ctx context.Context, tenantID string, before time.Time, beforeID string, limit int) ([]AgentDirective, error)
	// PendingForDevice returns what to relay to the authenticated device: issued directives still within
	// their lifetime plus those already in progress (so a restarted agent can resume), for deviceID at
	// key fingerprint keyFP only. Routing is from the stored rows.
	PendingForDevice(ctx context.Context, tenantID, deviceID, keyFP string) ([]AgentDirective, error)
	// MarkDelivered stamps delivered_at (first relay wins, audited once). A deviceID that is not the row's
	// device is ErrDirectiveNotFound: the id is never a bearer credential.
	MarkDelivered(ctx context.Context, tenantID, id, deviceID string) error
	// ApplyAck applies an acknowledgement whose signature the CALLER already verified against the row's
	// device key. It validates the claimed transition against the stored state (an exact replay of the
	// transition the row already shows is a no-op: applied == false), writes the audit row, and for a
	// completed uninstall tombstones the machine (status removed) in the same transaction.
	ApplyAck(ctx context.Context, tenantID, id, deviceID string, a DirectiveAck) (d *AgentDirective, applied bool, err error)
	// ApplyAckVia is ApplyAck for an acknowledgement that did not arrive through signaling: channel names the
	// route and is recorded in the audit detail (meta "channel"). ApplyAck itself records no channel.
	ApplyAckVia(ctx context.Context, tenantID, id, deviceID string, a DirectiveAck, channel string) (d *AgentDirective, applied bool, err error)
	// FinalAckTarget resolves a directive id (NO tenant context) for the public final-ack route (docs/65 sec.
	// 2b): its tenant, device, key fingerprint, state and the machine's stored public key, ONLY for an
	// uninstall; ErrDirectiveNotFound for anything else (unknown id and wrong kind are indistinguishable).
	// It does NOT filter on machine status: a removed machine still answers. Reads only.
	FinalAckTarget(ctx context.Context, id string) (*DirectiveFinalAckTarget, error)
	// ForgetMachine is an Owner's "forget this machine" (docs/65 sec. 8), the deliberate, irreversible end of a
	// removal that will never be confirmed. ONE transaction under the machine row lock: the machine becomes
	// 'removed' through the SAME tombstone a confirmed removal applies (D-C9), every directive still ACTIVE on it
	// becomes 'forgotten' (a state the agent never reports and never receives), and the audit rows
	// (machine.forgotten, then directive.forgotten per closed directive) are written first. Re-validated under
	// the lock: unknown id ErrMachineNotFound; already removed -> AlreadyRemoved with NOTHING written
	// (idempotent); a machine that left ExpectGroupID ErrDirectiveMachineChanged; any status but retired
	// ErrForgetNotRetired. The caller (the HTTP layer) owns authorization, step-up and the typed confirmation.
	ForgetMachine(ctx context.Context, tenantID string, in ForgetMachineInput) (*ForgetResult, error)
	// Policy / SetPolicy: the tenant's second-approver policy. SetPolicy bumps Version only on a change.
	Policy(ctx context.Context, tenantID string) (DirectivePolicy, error)
	SetPolicy(ctx context.Context, tenantID, actorID string, requireSecond bool) (DirectivePolicy, error)
	// SweepCandidates lists what is due across tenants (bounded); Expire and MarkUnconfirmed act on one
	// item re-checking its condition under lock; both are no-ops (nil, nil) when it no longer applies.
	SweepCandidates(ctx context.Context, limit int) ([]DirectiveSweepItem, error)
	Expire(ctx context.Context, tenantID, id string) (*AgentDirective, error)
	MarkUnconfirmed(ctx context.Context, tenantID, id string) (*AgentDirective, error)
}

// directiveSweepRank is the explicit priority of a sweep action (lower first): conclude what lapsed, then
// issue what is due, then resolve silent executions, then renotify. Within a rank the OLDEST due goes first
// (migrations/0068 cp_directive_sweep_candidates orders the same way).
func directiveSweepRank(action string) int {
	switch action {
	case "expire":
		return 1
	case "issue":
		return 2
	case "unconfirmed":
		return 3
	}
	return 4 // renotify
}

// directiveRenotifyMinAge: an undelivered directive is renotified only once its row has been quiet this long.
const directiveRenotifyMinAge = time.Minute

// directiveTransitionAllowed is the agent-reportable state machine (D-C6). removal_unconfirmed is never a
// reportable target: only the control plane concludes it. forgotten (docs/65 sec. 8) is the control plane's too:
// it is neither a source nor a target here, so no acknowledgement can ever move a directive to or from it.
func directiveTransitionAllowed(from, to DirectiveState) bool {
	switch from {
	case DirectiveIssued:
		return to == DirectiveAccepted || to == DirectiveFailed
	case DirectiveAccepted:
		return to == DirectiveExecuting || to == DirectiveFailed
	case DirectiveExecuting:
		return to == DirectiveFailed || to == DirectiveRebootPending || to == DirectiveComplete
	case DirectiveRebootPending:
		return to == DirectiveExecuting || to == DirectiveFailed || to == DirectiveComplete
	case DirectiveRemovalUnconfirmed:
		return to == DirectiveComplete || to == DirectiveFailed
	}
	return false
}

// DirectiveFinalAckTarget is what the final-ack route needs to verify and window a signed acknowledgement.
type DirectiveFinalAckTarget struct {
	TenantID, DeviceID, KeyFP string
	Kind                      DirectiveKind
	State                     DirectiveState
	MachinePubkey             string    // hex, the machine's CURRENT stored key (even when removed)
	UpdatedAt                 time.Time // when the directive last changed state
	Now                       time.Time // the store's clock, so the window is judged on one clock
}

// directiveFinalAckWindow is how long after an uninstall reached complete / failed the final-ack route keeps
// answering (replays report what was applied). While the directive is still active the route always answers.
const directiveFinalAckWindow = 7 * 24 * time.Hour

// directiveFinalAckChannel is the audit detail naming the route.
const directiveFinalAckChannel = "final_ack"

func directiveAckTarget(s string) DirectiveState { return DirectiveState(s) }

// directiveAckFromMatches reports whether an ack claiming `from` applies to the stored row. Normally the
// stored state must equal from. The one exception: a removal the control plane concluded as
// removal_unconfirmed (it only lost sight of the agent) still accepts the agent's genuine completion or
// failure, bound to the last state the AGENT reported (AgentState) - the agent never learns the control
// plane's own outcome, so it cannot name it. The legacy form from == removal_unconfirmed also still applies.
func directiveAckFromMatches(d *AgentDirective, from, to DirectiveState) bool {
	if d.State == from {
		return true
	}
	return d.State == DirectiveRemovalUnconfirmed && d.AgentState != "" && from == d.AgentState &&
		(to == DirectiveComplete || to == DirectiveFailed)
}

// directiveCompletionMachineOK: before a completed uninstall tombstones the machine, the machine must still
// be the one the directive was issued for (same device id, same enrollment generation). A re-enrolled
// machine is a different identity and is never removed by an old directive's completion.
func directiveCompletionMachineOK(d *AgentDirective, m *Machine) bool {
	return m != nil && m.DeviceID == d.DeviceID && fingerprintOf(m.Pubkey) == d.KeyFP
}

// newDirectiveAuditEvent builds one directive.* management-audit event. An empty actor is the system (the
// sweeper, or the agent's own report, which carries actor_kind).
func newDirectiveAuditEvent(actor, action string, d *AgentDirective, meta map[string]any) *MgmtAuditEvent {
	m := map[string]any{
		"directive_id": d.ID, "machine_id": d.MachineID, "device_id": d.DeviceID,
		"kind": string(d.Kind), "state": string(d.State), "group_id": d.GroupID,
	}
	if actor == "" {
		m["actor_kind"] = "system"
	}
	for k, v := range meta {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	return &MgmtAuditEvent{ActorUserID: actor, Action: action, TargetKind: "agent_directive", TargetID: d.ID, Metadata: raw}
}

// forgetAuditEvents builds the audit rows of ONE forget, in the order both stores append them: machine.forgotten
// first (the Owner's act, naming the directive(s) it closes), then directive.forgotten for each. `closed` holds
// the directives that were active as they were BEFORE the closure (State is the state each was in, the "from" of
// directive.forgotten). Both stores build every row here, so the fake and Postgres cannot drift apart. Every
// row carries agent_confirmed=false: a forgotten machine is NOT a confirmed removal, and no audit row may read
// as one (the confirmed path writes directive.complete and machine.removed instead).
func forgetAuditEvents(actor string, m *Machine, closed []AgentDirective) []*MgmtAuditEvent {
	meta := map[string]any{
		"machine_id": m.ID, "device_id": m.DeviceID, "group_id": m.GroupID,
		"previous_status": m.Status, "agent_confirmed": false,
	}
	if fp := fingerprintOf(m.Pubkey); fp != "" {
		meta["key_fp"] = fp
	}
	if len(closed) > 0 {
		list := make([]map[string]any, 0, len(closed))
		for _, d := range closed {
			list = append(list, map[string]any{"directive_id": d.ID, "kind": string(d.Kind), "state": string(d.State)})
		}
		meta["closed_directives"] = list
	}
	raw, _ := json.Marshal(meta)
	out := []*MgmtAuditEvent{{ActorUserID: actor, Action: "machine.forgotten", TargetKind: "machine", TargetID: m.ID, Metadata: raw}}
	for i := range closed {
		d := closed[i]
		from := string(d.State)
		d.State = DirectiveForgotten
		out = append(out, newDirectiveAuditEvent(actor, "directive.forgotten", &d, map[string]any{
			"from": from, "reason": "machine_forgotten", "agent_confirmed": false}))
	}
	return out
}

// buildDirectiveClaims is the claim set for an issuance at `now` (ms-truncated so the stored row and the
// signed claims agree exactly).
func buildDirectiveClaims(d *AgentDirective, now time.Time) (DirectiveClaims, time.Time, time.Time, []byte, error) {
	nonce, err := newDirectiveNonce()
	if err != nil {
		return DirectiveClaims{}, time.Time{}, time.Time{}, nil, err
	}
	issued := now.UTC().Truncate(time.Millisecond)
	expires := issued.Add(d.Kind.maxTTL())
	return DirectiveClaims{
		TenantID: canonicalUUIDish(d.TenantID), DeviceID: d.DeviceID, DirectiveID: canonicalUUIDish(d.ID),
		Kind: string(d.Kind), KeyFP: d.KeyFP, Nonce: hex.EncodeToString(nonce),
		IssuedAtMs: issued.UnixMilli(), ExpiresAtMs: expires.UnixMilli(),
	}, issued, expires, nonce, nil
}

// directiveLocalChecks are the issuance re-checks that need only the row and the machine: shared by both
// stores so they cannot drift. It returns "" when issuable or the refusal reason.
func directiveLocalChecks(d *AgentDirective, m *Machine, policy DirectivePolicy, quotaOK bool) string {
	switch {
	case m == nil:
		return "the machine no longer exists"
	case m.Status == MachineStatusRemoved:
		return "the machine was removed"
	case d.Kind == DirectiveUninstall && m.Status != MachineStatusRetired:
		return "the machine is no longer retired"
	case d.Kind == DirectiveReinstall && m.Status == MachineStatusRetired:
		return "the machine was retired since the request"
	case m.Pubkey == "":
		return "the machine has no pinned agent key"
	case fingerprintOf(m.Pubkey) != d.KeyFP:
		return "the agent was re-enrolled since the request"
	case d.Kind == DirectiveUninstall && policy.Version != d.PolicyVersion:
		return "the tenant directive policy changed since the request"
	case d.RequireApproval && d.ApprovedBy == "":
		return "approval is missing"
	case !quotaOK:
		return "the directive quota was exceeded"
	}
	return ""
}

// directiveActors is who must still be authorized at issuance: the requester and, when there is one, the
// approver.
func directiveActors(d *AgentDirective) []DirectiveActor {
	out := []DirectiveActor{d.requester()}
	if d.ApprovedBy != "" {
		out = append(out, d.approver())
	}
	return out
}

func fingerprintOf(pubkeyHex string) string {
	fp, err := KeyFingerprint(pubkeyHex)
	if err != nil {
		return ""
	}
	return fp
}

// verifyDirectiveAckFor checks an ack against a stored row and the device's CURRENT pinned key. Shared by
// the HTTP layer: tenant, device, fingerprint and directive id are the ROW's, never the message's.
func verifyDirectiveAckFor(d *AgentDirective, devicePubkeyHex string, a DirectiveAck) error {
	fp := fingerprintOf(devicePubkeyHex)
	if fp == "" || fp != d.KeyFP {
		return ErrDirectiveKeyChanged
	}
	raw, err := hex.DecodeString(devicePubkeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return ErrDirectiveKeyChanged
	}
	if !VerifyDirectiveAck(ed25519.PublicKey(raw), d.TenantID, d.DeviceID, d.ID, d.KeyFP, a) {
		return ErrDirectiveBadSignature
	}
	return nil
}

// -------------------------------------------------------------------------------------
// InMemoryDirectiveStore - must agree with PgDirectiveStore.
// -------------------------------------------------------------------------------------

type InMemoryDirectiveStore struct {
	// coord is shared with the machine store (when it is the in-memory one): machine validation, directive
	// reservation and guarded machine mutations are one critical section. Taken BEFORE mu.
	coord    *sync.Mutex
	mu       sync.Mutex
	rows     map[string]*AgentDirective
	policies map[string]DirectivePolicy
	machines MachineStore
	audit    MgmtAuditStore

	// testAfterMachineRead (tests only) runs in Request, inside the critical section, right after the machine
	// was read and validated: it lets a test hold the reservation open exactly where a concurrent machine
	// mutation used to be able to slip in.
	testAfterMachineRead func()
	// testAfterForgetLock (tests only) runs in ForgetMachine, inside the critical section, right after the
	// machine was read: the twin of the pg machine row lock, held until the hook returns. testAfterAckLock does
	// the same inside ApplyAckVia (after the directive was found, before anything is applied).
	testAfterForgetLock func()
	testAfterAckLock    func()

	// UninstallHourlyCap / ReinstallDailyCap / ReinstallHourlyCap: the quotas (defaults at construction).
	UninstallHourlyCap int
	ReinstallDailyCap  int
	ReinstallHourlyCap int
	// Now is the clock (DB time in pg), swappable in tests. Nil means time.Now.
	Now func() time.Time
	// TenantSuspended mirrors tenant.disabled_at for the fake. Nil = never suspended.
	TenantSuspended func(tenantID string) bool
}

// NewInMemoryDirectiveStore wires the fake over a machine store and an audit store (nil = no audit). When
// the machine store is an InMemoryMachineStore it also installs the machine_directive_guard twin.
func NewInMemoryDirectiveStore(machines MachineStore, audit MgmtAuditStore) *InMemoryDirectiveStore {
	s := &InMemoryDirectiveStore{
		rows: map[string]*AgentDirective{}, policies: map[string]DirectivePolicy{}, machines: machines, audit: audit,
		UninstallHourlyCap: DefaultUninstallHourlyCap, ReinstallDailyCap: DefaultReinstallDailyCap,
		ReinstallHourlyCap: DefaultReinstallHourlyCap,
	}
	s.coord = &sync.Mutex{}
	if mm, ok := machines.(*InMemoryMachineStore); ok {
		s.coord = &mm.coord
		mm.setDirectiveGuard(s.HasActive)
	}
	return s
}

var _ DirectiveStore = (*InMemoryDirectiveStore)(nil)

func (s *InMemoryDirectiveStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	// Microsecond precision, like the timestamptz column: a requested_at the fake hands out round-trips
	// through the keyset cursor exactly as a Postgres one does.
	return time.Now().Truncate(time.Microsecond)
}

func dirKey(tenantID, id string) string {
	return canonicalUUIDish(tenantID) + "\x00" + canonicalUUIDish(id)
}

// HasActive reports whether a machine has an active directive (the fake's machine_directive_guard input).
func (s *InMemoryDirectiveStore) HasActive(tenantID, machineID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.rows {
		if sameUserID(d.TenantID, tenantID) && d.MachineID == machineID && d.State.active() {
			return true
		}
	}
	return false
}

func (s *InMemoryDirectiveStore) record(ctx context.Context, tenantID, actor, action string, d *AgentDirective, meta map[string]any) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.RecordEvent(ctx, tenantID, newDirectiveAuditEvent(actor, action, d, meta))
}

// recordAll appends the events in order, all-or-nothing, like the pg twin's single transaction (see
// appendAuditBatch for how the in-memory audit store keeps that atomic against concurrent writers).
func (s *InMemoryDirectiveStore) recordAll(ctx context.Context, tenantID string, events []*MgmtAuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return appendAuditBatch(ctx, s.audit, tenantID, events)
}

// appendAuditBatch appends one tenant's events in order, all-or-nothing. The in-memory audit store's appendBatch
// does it atomically under its own mutex (stage the chain, then commit every event and the tail together), so a
// concurrent same-tenant writer can never land between the events and a failure never has to delete an event
// another event already chains to. A store without appendBatch (a wrapper) falls back to append + discardEvents,
// which is only as safe as that store's own serialisation.
func appendAuditBatch(ctx context.Context, audit MgmtAuditStore, tenantID string, events []*MgmtAuditEvent) error {
	if a, ok := audit.(interface {
		appendBatch(context.Context, string, []*MgmtAuditEvent) error
	}); ok {
		return a.appendBatch(ctx, tenantID, events)
	}
	hashes := map[string]bool{}
	for _, e := range events {
		if err := audit.RecordEvent(ctx, tenantID, e); err != nil {
			if a, ok := audit.(interface {
				discardEvents(string, map[string]bool)
			}); ok {
				a.discardEvents(tenantID, hashes)
			}
			return err
		}
		hashes[e.Hash] = true
	}
	return nil
}

func (s *InMemoryDirectiveStore) get(tenantID, id string) *AgentDirective {
	return s.rows[dirKey(tenantID, id)]
}

func cloneDirective(d *AgentDirective) *AgentDirective {
	c := *d
	c.Nonce = append([]byte(nil), d.Nonce...)
	return &c
}

func (s *InMemoryDirectiveStore) policy(tenantID string) DirectivePolicy {
	return s.policies[canonicalUUIDish(tenantID)]
}

func (s *InMemoryDirectiveStore) suspended(tenantID string) bool {
	return s.TenantSuspended != nil && s.TenantSuspended(tenantID)
}

// QUOTAS (docs/65 review r3): a quota counts what was ISSUED in the rolling window (issued_at, including
// directives that later expired or failed), plus the live reservations when deciding whether to accept a
// NEW request; issuance counts issuances only. Counting requested_at instead let a request that waited out
// the hour boundary slip past a cap its predecessors had already used.
func (s *InMemoryDirectiveStore) issuedCount(tenantID, machineID string, kind DirectiveKind, since time.Time) int {
	n := 0
	for _, d := range s.rows {
		if !sameUserID(d.TenantID, tenantID) || d.Kind != kind || d.IssuedAt == nil || !d.IssuedAt.After(since) {
			continue
		}
		if machineID != "" && d.MachineID != machineID {
			continue
		}
		n++
	}
	return n
}

// reservedCount counts live reservations (state requested). Reservations are counted SEPARATELY from
// issuances: they gate a new request, never an issuance (the row being issued is itself a reservation).
func (s *InMemoryDirectiveStore) reservedCount(tenantID, machineID string, kind DirectiveKind) int {
	n := 0
	for _, d := range s.rows {
		if !sameUserID(d.TenantID, tenantID) || d.Kind != kind || d.State != DirectiveRequested {
			continue
		}
		if machineID != "" && d.MachineID != machineID {
			continue
		}
		n++
	}
	return n
}

func (s *InMemoryDirectiveStore) Request(ctx context.Context, tenantID string, in DirectiveRequestInput) (*AgentDirective, error) {
	if !in.Kind.Valid() {
		return nil, ErrDirectiveBadTransition
	}
	s.coord.Lock()
	defer s.coord.Unlock()
	m, err := s.machines.GetMachineByID(ctx, tenantID, in.MachineID)
	if err != nil {
		return nil, err
	}
	if s.testAfterMachineRead != nil {
		s.testAfterMachineRead()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.suspended(tenantID) {
		return nil, ErrDirectiveTenantSuspended
	}
	switch {
	case m.Status == MachineStatusRemoved:
		return nil, ErrDirectiveMachineRemoved
	case m.Pubkey == "":
		return nil, ErrDirectiveNoKey
	case m.GroupID != in.ExpectGroupID:
		return nil, ErrDirectiveMachineChanged
	case in.Kind == DirectiveUninstall && m.Status != MachineStatusRetired:
		return nil, ErrDirectiveNotRetired
	case in.Kind == DirectiveReinstall && m.Status == MachineStatusRetired:
		return nil, ErrDirectiveMachineRetired
	}
	for _, d := range s.rows {
		if sameUserID(d.TenantID, tenantID) && d.MachineID == m.ID && d.State.active() {
			return nil, ErrDirectiveActiveExists
		}
	}
	now := s.now().UTC()
	if in.Kind == DirectiveUninstall {
		if s.issuedCount(tenantID, "", in.Kind, now.Add(-time.Hour))+s.reservedCount(tenantID, "", in.Kind) >= s.UninstallHourlyCap {
			return nil, ErrDirectiveQuota
		}
	} else if s.issuedCount(tenantID, m.ID, in.Kind, now.Add(-24*time.Hour))+s.reservedCount(tenantID, m.ID, in.Kind) >= s.ReinstallDailyCap ||
		s.issuedCount(tenantID, "", in.Kind, now.Add(-time.Hour))+s.reservedCount(tenantID, "", in.Kind) >= s.ReinstallHourlyCap {
		return nil, ErrDirectiveQuota
	}
	pol := s.policy(tenantID)
	d := &AgentDirective{
		ID: newUUID(), TenantID: tenantID, MachineID: m.ID, DeviceID: m.DeviceID, KeyFP: fingerprintOf(m.Pubkey),
		GroupID: m.GroupID, Kind: in.Kind, State: DirectiveRequested, RequestedBy: in.RequestedBy,
		RequestedAt: now, NotBefore: now, RequestExpiresAt: now.Add(directiveRequestTTL), UpdatedAt: now,
		RequestedSession: in.RequestedSession, RequestedEpoch: in.RequestedEpoch, RequestedMFAGen: in.RequestedMFAGen,
	}
	if in.Kind == DirectiveUninstall {
		d.NotBefore = now.Add(directiveCancelWindow)
		d.RequireApproval = pol.RequireSecondApprover
		d.PolicyVersion = pol.Version
	}
	if err := s.record(ctx, tenantID, in.RequestedBy, "directive.requested", d, map[string]any{
		"not_before": d.NotBefore, "require_approval": d.RequireApproval}); err != nil {
		return nil, err
	}
	s.rows[dirKey(tenantID, d.ID)] = d
	return cloneDirective(d), nil
}

func (s *InMemoryDirectiveStore) Approve(ctx context.Context, tenantID, id string, approver DirectiveActor) (*AgentDirective, error) {
	approverID := approver.UserID
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	now := s.now().UTC()
	switch {
	case d.State != DirectiveRequested:
		return cloneDirective(d), ErrDirectiveNotPending
	case !now.Before(d.RequestExpiresAt):
		return cloneDirective(d), ErrDirectiveExpired
	case !d.RequireApproval:
		return cloneDirective(d), ErrDirectiveApprovalNotNeeded
	case sameUserID(d.RequestedBy, approverID):
		return cloneDirective(d), ErrDirectiveSelfApproval
	case d.ApprovedBy != "":
		return cloneDirective(d), ErrDirectiveAlreadyApproved
	}
	// Approval restarts the cancel window so it never issues immediately; no room left = expired.
	nb := now.Add(directiveCancelWindow)
	if nb.Before(d.NotBefore) {
		nb = d.NotBefore
	}
	if !nb.Before(d.RequestExpiresAt) {
		return cloneDirective(d), ErrDirectiveExpired
	}
	next := *d
	next.ApprovedBy, next.ApprovedAt, next.UpdatedAt, next.NotBefore = approverID, &now, now, nb
	next.ApprovedSession, next.ApprovedEpoch, next.ApprovedMFAGen = approver.SessionID, approver.CredentialEpoch, approver.MFAGeneration
	if err := s.record(ctx, tenantID, approverID, "directive.approved", &next, map[string]any{"not_before": nb}); err != nil {
		return nil, err
	}
	*d = next
	return cloneDirective(d), nil
}

func (s *InMemoryDirectiveStore) Cancel(ctx context.Context, tenantID, id, actorID, reason string) (*AgentDirective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	if d.State != DirectiveRequested {
		return cloneDirective(d), ErrDirectiveNotCancellable
	}
	now := s.now().UTC()
	next := *d
	next.State, next.CancelledBy, next.CancelledAt, next.CancelReason, next.UpdatedAt =
		DirectiveCancelled, actorID, &now, reason, now
	if next.CancelReason == "" {
		next.CancelReason = "cancelled"
	}
	if err := s.record(ctx, tenantID, actorID, "directive.cancelled", &next, map[string]any{"reason": next.CancelReason}); err != nil {
		return nil, err
	}
	*d = next
	return cloneDirective(d), nil
}

func (s *InMemoryDirectiveStore) Issue(ctx context.Context, tenantID, id string, deps DirectiveIssueDeps) (*AgentDirective, error) {
	if deps.Authority == nil || deps.Issuer == nil {
		return nil, errors.New("directive issuance is not configured")
	}
	s.coord.Lock()
	defer s.coord.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	if s.suspended(tenantID) {
		return nil, ErrDirectiveTenantSuspended
	}
	if d.State != DirectiveRequested {
		return cloneDirective(d), ErrDirectiveNotIssuable
	}
	now := s.now().UTC()
	end := func(state DirectiveState, action, reason string) (*AgentDirective, error) {
		next := *d
		next.State, next.UpdatedAt = state, now
		if state == DirectiveCancelled {
			next.CancelledAt, next.CancelReason = &now, reason
		}
		if err := s.record(ctx, tenantID, "", action, &next, map[string]any{"reason": reason}); err != nil {
			return nil, err
		}
		*d = next
		if state == DirectiveExpired {
			return cloneDirective(d), ErrDirectiveExpired
		}
		return cloneDirective(d), &DirectiveRefusedError{Reason: reason}
	}
	if !now.Before(d.RequestExpiresAt) {
		return end(DirectiveExpired, "directive.expired", "the request was not issued in time")
	}
	if now.Before(d.NotBefore) {
		return cloneDirective(d), ErrDirectiveTooEarly
	}
	if d.RequireApproval && d.ApprovedBy == "" {
		return cloneDirective(d), ErrDirectiveNeedsApproval
	}
	m, merr := s.machines.GetMachineByID(ctx, tenantID, d.MachineID)
	if merr != nil && !errors.Is(merr, ErrMachineNotFound) {
		return nil, merr
	}
	if errors.Is(merr, ErrMachineNotFound) {
		m = nil
	}
	quotaOK := true
	if d.Kind == DirectiveUninstall {
		quotaOK = s.issuedCount(tenantID, "", d.Kind, now.Add(-time.Hour)) < s.UninstallHourlyCap
	} else {
		// Per-device daily and tenant-wide hourly, issuances only (this row is not issued yet).
		quotaOK = s.issuedCount(tenantID, d.MachineID, d.Kind, now.Add(-24*time.Hour)) < s.ReinstallDailyCap &&
			s.issuedCount(tenantID, "", d.Kind, now.Add(-time.Hour)) < s.ReinstallHourlyCap
	}
	if reason := directiveLocalChecks(d, m, s.policy(tenantID), quotaOK); reason != "" {
		return end(DirectiveCancelled, "directive.cancelled", reason)
	}
	for _, who := range directiveActors(d) {
		if err := deps.Authority(ctx, who, m.GroupID); err != nil {
			if errors.Is(err, ErrDirectiveAuthorityLost) {
				return end(DirectiveCancelled, "directive.cancelled", ErrDirectiveAuthorityLost.Error())
			}
			return nil, err
		}
	}
	claims, issued, expires, nonce, err := buildDirectiveClaims(d, now)
	if err != nil {
		return nil, err
	}
	artifact, err := deps.Issuer.Sign(claims)
	if err != nil {
		return nil, err
	}
	next := *d
	next.State, next.IssuedAt, next.ExpiresAt, next.Nonce, next.Artifact, next.UpdatedAt =
		DirectiveIssued, &issued, &expires, nonce, artifact, now
	next.GroupID = m.GroupID
	if err := s.record(ctx, tenantID, "", "directive.issued", &next, map[string]any{
		"requested_by": d.RequestedBy, "approved_by": d.ApprovedBy, "expires_at": expires}); err != nil {
		return nil, err
	}
	*d = next
	return cloneDirective(d), nil
}

func (s *InMemoryDirectiveStore) Get(_ context.Context, tenantID, id string) (*AgentDirective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	return cloneDirective(d), nil
}

func (s *InMemoryDirectiveStore) List(_ context.Context, tenantID, machineID string) ([]AgentDirective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AgentDirective
	for _, d := range s.rows {
		if sameUserID(d.TenantID, tenantID) && (machineID == "" || d.MachineID == machineID) {
			out = append(out, *cloneDirective(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	if len(out) > directiveListLimit {
		out = out[:directiveListLimit]
	}
	return out, nil
}

func (s *InMemoryDirectiveStore) ListActive(_ context.Context, tenantID string, before time.Time, beforeID string, limit int) ([]AgentDirective, error) {
	if limit <= 0 || limit > directiveListLimit {
		limit = directiveListLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AgentDirective
	for _, d := range s.rows {
		if !sameUserID(d.TenantID, tenantID) || !d.State.active() {
			continue
		}
		if !before.IsZero() && !(d.RequestedAt.Before(before) || (d.RequestedAt.Equal(before) && canonicalUUIDish(d.ID) > canonicalUUIDish(beforeID))) {
			continue
		}
		out = append(out, *cloneDirective(d))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].RequestedAt.After(out[j].RequestedAt)
		}
		return canonicalUUIDish(out[i].ID) < canonicalUUIDish(out[j].ID)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *InMemoryDirectiveStore) PendingForDevice(_ context.Context, tenantID, deviceID, keyFP string) ([]AgentDirective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []AgentDirective
	for _, d := range s.rows {
		if !sameUserID(d.TenantID, tenantID) || d.DeviceID != deviceID || d.KeyFP != keyFP {
			continue
		}
		switch d.State {
		case DirectiveIssued:
			if d.ExpiresAt == nil || !d.ExpiresAt.After(now) {
				continue
			}
		case DirectiveAccepted, DirectiveExecuting, DirectiveRebootPending:
		default:
			continue
		}
		out = append(out, *cloneDirective(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.Before(out[j].RequestedAt) })
	if len(out) > directivePendingLimit {
		out = out[:directivePendingLimit]
	}
	return out, nil
}

func (s *InMemoryDirectiveStore) MarkDelivered(ctx context.Context, tenantID, id, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil || d.DeviceID != deviceID {
		return ErrDirectiveNotFound
	}
	if d.DeliveredAt != nil || !d.State.active() {
		return nil
	}
	now := s.now().UTC()
	next := *d
	next.DeliveredAt, next.UpdatedAt = &now, now
	if err := s.record(ctx, tenantID, "", "directive.delivered", &next, nil); err != nil {
		return err
	}
	*d = next
	return nil
}

func (s *InMemoryDirectiveStore) FinalAckTarget(ctx context.Context, id string) (*DirectiveFinalAckTarget, error) {
	s.mu.Lock()
	var d *AgentDirective
	for _, r := range s.rows {
		if strings.EqualFold(canonicalUUIDish(r.ID), canonicalUUIDish(id)) && r.Kind == DirectiveUninstall {
			d = cloneDirective(r)
			break
		}
	}
	now := s.now().UTC()
	s.mu.Unlock()
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	m, err := s.machines.GetMachineByID(ctx, d.TenantID, d.MachineID)
	if err != nil {
		return nil, ErrDirectiveNotFound
	}
	return &DirectiveFinalAckTarget{TenantID: d.TenantID, DeviceID: d.DeviceID, KeyFP: d.KeyFP, Kind: d.Kind,
		State: d.State, MachinePubkey: m.Pubkey, UpdatedAt: d.UpdatedAt, Now: now}, nil
}

func (s *InMemoryDirectiveStore) ApplyAck(ctx context.Context, tenantID, id, deviceID string, a DirectiveAck) (*AgentDirective, bool, error) {
	return s.ApplyAckVia(ctx, tenantID, id, deviceID, a, "")
}

func (s *InMemoryDirectiveStore) ApplyAckVia(ctx context.Context, tenantID, id, deviceID string, a DirectiveAck, channel string) (*AgentDirective, bool, error) {
	to := directiveAckTarget(a.To)
	from := directiveAckTarget(a.From)
	if len(a.Detail) > maxDirectiveDetailBytes {
		return nil, false, ErrDirectiveBadTransition
	}
	s.coord.Lock()
	defer s.coord.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil || d.DeviceID != deviceID {
		return nil, false, ErrDirectiveNotFound
	}
	if s.testAfterAckLock != nil {
		s.testAfterAckLock()
	}
	if channel == directiveFinalAckChannel {
		// Re-check the key the route authenticated against, under the coordination lock (the pg twin does it
		// under the machine row lock).
		m, err := s.machines.GetMachineByID(ctx, tenantID, d.MachineID)
		if err != nil {
			return nil, false, err
		}
		if !directiveCompletionMachineOK(d, m) {
			return cloneDirective(d), false, ErrDirectiveKeyChanged
		}
	}
	now := s.now().UTC()
	// The window is judged HERE too, on the locked row and the store clock, before the replay branch and any
	// mutation (the route's own check is only a fast path against its lookup snapshot).
	if channel == directiveFinalAckChannel && !finalAckWindowOpen(d.State, d.UpdatedAt, now) {
		return cloneDirective(d), false, ErrDirectiveFinalAckWindowClosed
	}
	if time.UnixMilli(a.TsMs).After(now.Add(directiveClockSkew)) {
		return cloneDirective(d), false, ErrDirectiveBadTimestamp
	}
	if !directiveTransitionAllowed(from, to) {
		return cloneDirective(d), false, ErrDirectiveBadTransition
	}
	if d.State == to {
		return cloneDirective(d), false, nil // exact replay of the transition the row already shows
	}
	if !directiveAckFromMatches(d, from, to) {
		return cloneDirective(d), false, ErrDirectiveBadTransition
	}
	// A validly signed OLD ack must not move the row: strictly newer than the last accepted, and recent.
	if a.TsMs <= d.LastAckTsMs || time.UnixMilli(a.TsMs).Before(now.Add(-directiveAckMaxAge)) {
		return cloneDirective(d), false, ErrDirectiveStaleAck
	}
	if from == DirectiveIssued && to == DirectiveAccepted && d.ExpiresAt != nil && !now.Before(*d.ExpiresAt) {
		return cloneDirective(d), false, ErrDirectiveExpired
	}
	next := *d
	next.State, next.AckedAt, next.StateDetail, next.UpdatedAt, next.LastAckTsMs = to, &now, a.Detail, now, a.TsMs
	next.AgentState = to
	var machine *Machine
	if to == DirectiveComplete && d.Kind == DirectiveUninstall {
		m, err := s.machines.GetMachineByID(ctx, tenantID, d.MachineID)
		if err != nil {
			return nil, false, err
		}
		if !directiveCompletionMachineOK(d, m) {
			return cloneDirective(d), false, ErrDirectiveKeyChanged
		}
		machine = m
	}
	meta := map[string]any{"from": a.From, "actor_kind": "agent", "detail": a.Detail}
	if channel != "" {
		meta["channel"] = channel
	}
	// The audit rows are all-or-nothing, like the pg transaction: state is staged in next (d is only overwritten
	// below), and when machine.removed fails the directive.<to> row already appended is discarded.
	events := []*MgmtAuditEvent{newDirectiveAuditEvent("", "directive."+a.To, &next, meta)}
	if machine != nil {
		events = append(events, newDirectiveAuditEvent("", "machine.removed", &next, map[string]any{"via_directive": d.ID}))
	}
	if err := s.recordAll(ctx, tenantID, events); err != nil {
		return nil, false, err
	}
	*d = next
	if machine != nil {
		s.tombstoneMachine(tenantID, d.MachineID)
	}
	return cloneDirective(d), true, nil
}

// tombstoneMachine is the fake's D-C9 tombstone: the ONE place a confirmed removal (ApplyAckVia) and an Owner's
// forget (ForgetMachine) both write it; the pg twin is tombstoneMachineTx. It bypasses SetMachineStatus, whose
// guard refuses a status change while a directive is active, the way the pg single transaction does: the
// caller has just ended the directive. The fake's only machine store is the in-memory one.
func (s *InMemoryDirectiveStore) tombstoneMachine(tenantID, machineID string) {
	if mm, ok := s.machines.(*InMemoryMachineStore); ok {
		mm.tombstone(tenantID, machineID)
	}
}

func (s *InMemoryDirectiveStore) ForgetMachine(ctx context.Context, tenantID string, in ForgetMachineInput) (*ForgetResult, error) {
	// coord is the twin of the pg machine row lock: a request, an issuance, an acknowledgement and this forget
	// serialize on it.
	s.coord.Lock()
	defer s.coord.Unlock()
	m, err := s.machines.GetMachineByID(ctx, tenantID, in.MachineID)
	if err != nil {
		return nil, err
	}
	if s.testAfterForgetLock != nil {
		s.testAfterForgetLock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case m.Status == MachineStatusRemoved:
		return &ForgetResult{AlreadyRemoved: true}, nil // idempotent: nothing written, no second audit row
	case !sameUserID(m.GroupID, in.ExpectGroupID):
		return nil, ErrDirectiveMachineChanged
	case m.Status != MachineStatusRetired:
		return nil, ErrForgetNotRetired
	}
	var active []*AgentDirective
	for _, d := range s.rows {
		if sameUserID(d.TenantID, tenantID) && d.MachineID == m.ID && d.State.active() {
			active = append(active, d)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if !active[i].RequestedAt.Equal(active[j].RequestedAt) {
			return active[i].RequestedAt.Before(active[j].RequestedAt)
		}
		return active[i].ID < active[j].ID
	})
	before := make([]AgentDirective, 0, len(active))
	for _, d := range active {
		before = append(before, *cloneDirective(d))
	}
	// AUDIT FIRST, as everywhere: a failing audit store leaves the machine and every directive untouched.
	// The rows are appended all-or-nothing, like the pg transaction: when a later append fails, the rows already
	// appended are discarded (the help-request fake does the same through discardEvents).
	if err := s.recordAll(ctx, tenantID, forgetAuditEvents(in.ActorID, m, before)); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	closed := make([]AgentDirective, 0, len(active))
	for _, d := range active {
		d.State, d.StateDetail, d.UpdatedAt = DirectiveForgotten, forgottenDetail, now
		closed = append(closed, *cloneDirective(d))
	}
	s.tombstoneMachine(tenantID, m.ID)
	return &ForgetResult{Closed: closed}, nil
}

func (s *InMemoryDirectiveStore) Policy(_ context.Context, tenantID string) (DirectivePolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy(tenantID), nil
}

func (s *InMemoryDirectiveStore) SetPolicy(ctx context.Context, tenantID, actorID string, requireSecond bool) (DirectivePolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.policy(tenantID)
	if cur.RequireSecondApprover == requireSecond {
		return cur, nil
	}
	next := DirectivePolicy{RequireSecondApprover: requireSecond, Version: cur.Version + 1}
	if s.audit != nil {
		raw, _ := json.Marshal(map[string]any{"require_second_approver": requireSecond, "version": next.Version})
		if err := s.audit.RecordEvent(ctx, tenantID, &MgmtAuditEvent{ActorUserID: actorID,
			Action: "tenant.directive_policy_set", TargetKind: "tenant", TargetID: tenantID, Metadata: raw}); err != nil {
			return DirectivePolicy{}, err
		}
	}
	s.policies[canonicalUUIDish(tenantID)] = next
	return next, nil
}

func (s *InMemoryDirectiveStore) SweepCandidates(_ context.Context, limit int) ([]DirectiveSweepItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []DirectiveSweepItem
	for _, d := range s.rows {
		var action string
		switch {
		case d.State == DirectiveRequested && !now.Before(d.RequestExpiresAt):
			action = "expire"
		case d.State == DirectiveRequested && !now.Before(d.NotBefore) && !(d.RequireApproval && d.ApprovedBy == ""):
			action = "issue"
		case d.State == DirectiveIssued && d.ExpiresAt != nil && !now.Before(*d.ExpiresAt):
			action = "expire"
		case (d.State == DirectiveAccepted || d.State == DirectiveExecuting || d.State == DirectiveRebootPending) &&
			!now.Before(d.UpdatedAt.Add(directiveUnconfirmedAfter)):
			action = "unconfirmed"
		case d.State == DirectiveIssued && d.DeliveredAt == nil && !now.Before(d.UpdatedAt.Add(directiveRenotifyMinAge)):
			action = "renotify"
		}
		if action != "" {
			due := d.NotBefore
			switch action {
			case "expire":
				due = d.RequestExpiresAt
				if d.State == DirectiveIssued && d.ExpiresAt != nil {
					due = *d.ExpiresAt
				}
			case "unconfirmed", "renotify":
				due = d.UpdatedAt
			}
			out = append(out, DirectiveSweepItem{TenantID: d.TenantID, DirectiveID: d.ID, Action: action, due: due})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := directiveSweepRank(out[i].Action), directiveSweepRank(out[j].Action); ri != rj {
			return ri < rj
		}
		if !out[i].due.Equal(out[j].due) {
			return out[i].due.Before(out[j].due)
		}
		return out[i].DirectiveID < out[j].DirectiveID
	})
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *InMemoryDirectiveStore) Expire(ctx context.Context, tenantID, id string) (*AgentDirective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	now := s.now().UTC()
	due := (d.State == DirectiveRequested && !now.Before(d.RequestExpiresAt)) ||
		(d.State == DirectiveIssued && d.ExpiresAt != nil && !now.Before(*d.ExpiresAt))
	if !due {
		return nil, nil
	}
	next := *d
	next.State, next.UpdatedAt = DirectiveExpired, now
	if err := s.record(ctx, tenantID, "", "directive.expired", &next, map[string]any{"from": string(d.State)}); err != nil {
		return nil, err
	}
	*d = next
	return cloneDirective(d), nil
}

func (s *InMemoryDirectiveStore) MarkUnconfirmed(ctx context.Context, tenantID, id string) (*AgentDirective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(tenantID, id)
	if d == nil {
		return nil, ErrDirectiveNotFound
	}
	now := s.now().UTC()
	if !(d.State == DirectiveAccepted || d.State == DirectiveExecuting || d.State == DirectiveRebootPending) ||
		now.Before(d.UpdatedAt.Add(directiveUnconfirmedAfter)) {
		return nil, nil
	}
	next := *d
	next.UpdatedAt = now
	next.AgentState = d.State // the last state the agent was known to be in; the outcome below is ours
	next.State, next.StateDetail = DirectiveRemovalUnconfirmed, "the agent never reported a result"
	if d.Kind == DirectiveReinstall {
		next.State = DirectiveFailed
	}
	if err := s.record(ctx, tenantID, "", "directive."+string(next.State), &next, map[string]any{"from": string(d.State)}); err != nil {
		return nil, err
	}
	*d = next
	return cloneDirective(d), nil
}

// validateDirectiveID is a cheap shape check shared by the HTTP layer.
func validateDirectiveID(id string) error {
	if _, err := uuidBytes(strings.TrimSpace(id)); err != nil {
		return fmt.Errorf("directive id: %w", err)
	}
	return nil
}
