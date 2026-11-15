package controlplane

// Signed per-SESSION access policies (loop 79, docs/01 §3/§5) — the control plane telling the
// AGENT what a live support session may do with the guest's input devices.
//
// NAMING, because this package now has two unrelated things called a "session policy":
//
//   - SessionPolicy (tenant_session_policy.go) is SEAT METERING — how many sessions a tenant may
//     hold open and for how long. It never leaves the control plane.
//   - SignedSessionPolicy (this file) is an ACCESS policy — view-only vs control — minted per
//     session, signed with the control plane's long-term Ed25519 identity, and shipped to the
//     agent, which verifies and ENFORCES it. Its Rust twin is `rmt_agent::session_policy`.
//
// Why it exists: view-only has been a self-set toggle (the controller sends SetViewOnly and can
// send it again to turn it off), so an organisational decision could not bind a session. The agent
// already verifies a control-plane-signed artifact for BACKSTAGE (grant.go), but a plain
// view/control session installs nothing signed at all. This mints the missing artifact, reusing
// the same GrantIssuer key and the same canonical-bytes discipline.
//
// The canonical preimage is a byte-for-byte port of Rust's `SessionPolicyClaims::signing_bytes`
// (agent/src/session_policy.rs); TestSessionPolicyGoldenVectorV1 and the Rust
// `session_policy::tests::golden_vector_v1` pin the SAME fixture to the SAME hex on both sides.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// sessionPolicyDomainTag is the 12-byte session-policy-v1 domain-separation tag: ASCII "RMTSPOLv1"
// (9 bytes) followed by three 0x00 bytes. Hex: 52 4d 54 53 50 4f 4c 76 31 00 00 00. Must equal
// Rust's SESSION_POLICY_DOMAIN_TAG.
//
// It MUST differ from grantDomainTag and auditDomainTag. That is load-bearing, not cosmetic: a
// session policy and a backstage grant are signed by the SAME Ed25519 key and both preimages open
// with the same three UUIDs, so without distinct tags a signature over one could be replayed as the
// other. TestDomainTagsArePairwiseDistinct pins all three apart.
var sessionPolicyDomainTag = []byte("RMTSPOLv1\x00\x00\x00")

// SessionAccessLevel is what a session may do with the guest's input devices. The wire values are
// the canonical snake_case strings Rust's `AccessLevel` serde-encodes, and they go into the signing
// bytes verbatim — so these two constants are a cross-language contract, not local vocabulary.
type SessionAccessLevel string

const (
	// SessionAccessViewOnly: the agent DROPS injected input and refuses the write-actions
	// (reboot / tool-launch / command-run / lock / log-off / shut-down). The RESTRICTIVE value,
	// and the one every "could not determine what was meant" path must land on.
	SessionAccessViewOnly SessionAccessLevel = "view_only"
	// SessionAccessControl: full remote control — input is injected, write-actions permitted.
	SessionAccessControl SessionAccessLevel = "control"
)

// Valid reports whether l is one of the two levels the agent understands.
//
// Minting refuses an unknown level rather than passing it through. Without this an empty or
// typo'd level would be signed and shipped; the agent would fail to DECODE it (Rust rejects an
// unknown serde variant) and so would fall back to its own default — which is safe, but turns a
// control-plane bug into a silent, hard-to-diagnose loss of control for the technician. Failing at
// the mint makes it loud and local.
func (l SessionAccessLevel) Valid() bool {
	return l == SessionAccessViewOnly || l == SessionAccessControl
}

// sessionPolicyBody mirrors Rust `SessionPolicy` (agent/src/session_policy.rs).
type sessionPolicyBody struct {
	TechnicianID              string             `json:"technician_id"`
	SessionID                 string             `json:"session_id"`
	MachineID                 string             `json:"machine_id"`
	Access                    SessionAccessLevel `json:"access"`
	AllowRecording            bool               `json:"allow_recording"`
	RequireRecording          bool               `json:"require_recording"`
	MaxSessionDurationSeconds uint32             `json:"max_session_duration_seconds"`
	MaxIdleSeconds            uint32             `json:"max_idle_seconds"`
}

// sessionPolicyClaims mirrors Rust `SessionPolicyClaims`.
type sessionPolicyClaims struct {
	Policy      sessionPolicyBody `json:"policy"`
	IssuedAtMs  int64             `json:"issued_at_ms"`
	ExpiresAtMs int64             `json:"expires_at_ms"`
}

// SignedSessionPolicy mirrors Rust `SignedSessionPolicy`: the claims plus Ed25519 signatures over
// their canonical signing bytes. Two signature fields support mixed-version deployments:
//
//   - Sig (JSON: "sig_v1"): v1-preimage (10-field) signature — the authoritative signature covering
//     ALL policy fields including the enforcement ones. New agents MUST verify this field.
//   - SigCompat (JSON: "sig"): v0-preimage (6-field) signature, emitted ONLY for non-restrictive
//     policies. Deployed agents at 735d5a28 only read "sig" and verify it against the 6-field
//     preimage they compute locally — so this field MUST carry a v0 sig. For restrictive policies
//     this field is OMITTED so old agents fail closed (they cannot verify a missing sig).
//
// Why "sig" must be a v0 (6-field) sig, NOT a v1 sig:
//
//	Deployed agents (735d5a28b3601dc5b87971b912bc61d9dd8ffd35) compute only the first 6 fields
//	(domain_tag through expires_at_ms) as their signing preimage. They verify "sig" against that
//	6-field preimage. Putting a v1-preimage sig in "sig" fails verification on every real deployed
//	agent after a CP upgrade. "sig" and "sig_v1" therefore carry DIFFERENT signatures.
//
// See TestSessionPolicyDeployedBaseCompatibility for the full 6-cell upgrade/downgrade matrix.
type SignedSessionPolicy struct {
	Claims    sessionPolicyClaims `json:"-"`
	Sig       string              `json:"-"` // v1 preimage sig (authoritative); emitted as "sig_v1"
	SigCompat string              `json:"-"` // v0 preimage sig (old-agent compat); emitted as "sig", omitted for restrictive policies
}

// signedSessionPolicyWire is the JSON-marshallable view of SignedSessionPolicy.
// SigV0Compat uses omitempty so restrictive policies omit "sig" entirely — old agents that only
// read "sig" then get a decode error (fail closed) rather than silently accepting the policy.
type signedSessionPolicyWire struct {
	Claims      sessionPolicyClaims `json:"claims"`
	SigV0Compat string              `json:"sig,omitempty"` // v0 preimage sig for deployed agents; absent for restrictive policies
	SigV1       string              `json:"sig_v1"`        // v1 preimage sig (authoritative) — new agents verify this
}

// UnmarshalJSON reads the wire format (sig_v1 → Sig, sig → SigCompat) so that test code that
// round-trips through JSON can use SignedSessionPolicy directly.
func (p *SignedSessionPolicy) UnmarshalJSON(data []byte) error {
	var w signedSessionPolicyWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	p.Claims = w.Claims
	p.Sig = w.SigV1
	p.SigCompat = w.SigV0Compat
	return nil
}

// JSON renders the signed policy as the wire string carried opaquely in the Control channel's
// InstallSessionPolicy message.
func (p SignedSessionPolicy) JSON() (string, error) {
	b, err := json.Marshal(signedSessionPolicyWire{
		Claims:      p.Claims,
		SigV0Compat: p.SigCompat,
		SigV1:       p.Sig,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Access returns the level this policy carries (its only field the callers outside minting care
// about — handlers audit it, tests assert it).
func (p SignedSessionPolicy) Access() SessionAccessLevel { return p.Claims.Policy.Access }

// policyHasNewRestrictions reports whether any of the fields added after the v0 preimage era carry
// a restrictive value. When true, MintSessionPolicy OMITS "sig" so old agents fail closed rather
// than silently accepting a policy whose enforcement bytes they cannot verify.
func policyHasNewRestrictions(allowRecording, requireRecording bool, maxSessionDurationSeconds, maxIdleSeconds uint32) bool {
	return !allowRecording || requireRecording || maxSessionDurationSeconds > 0 || maxIdleSeconds > 0
}

// sessionPolicySigningBytesV0 builds the deployed-baseline (735d5a28b3601dc5b87971b912bc61d9dd8ffd35)
// 6-field preimage, ending at expires_at_ms. Old agents verify the JSON "sig" field against this
// preimage. Returns an error only on a malformed UUID or an unknown access level.
//
// Layout:
//
//	[0..11]    session-policy domain tag ("RMTSPOLv1\x00\x00\x00")
//	[12..27]   technician_id (16 bytes)
//	[28..43]   session_id    (16 bytes)
//	[44..59]   machine_id    (16 bytes)
//	[60..63]   access level length prefix (uint32 big-endian)
//	[64..N]    access level string ("view_only" = 89 bytes total; "control" = 87 bytes total)
//	[N+1..N+8] issued_at_ms  (int64 big-endian)
//	[N+9..N+16] expires_at_ms (int64 big-endian)
func sessionPolicySigningBytesV0(technicianID, sessionID, machineID string, access SessionAccessLevel, issuedAtMs, expiresAtMs int64) ([]byte, error) {
	if !access.Valid() {
		return nil, fmt.Errorf("session policy access level: unknown level %q", string(access))
	}
	tech, err := uuidBytes(technicianID)
	if err != nil {
		return nil, fmt.Errorf("technician_id: %w", err)
	}
	sess, err := uuidBytes(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	mach, err := uuidBytes(machineID)
	if err != nil {
		return nil, fmt.Errorf("machine_id: %w", err)
	}
	var w canonicalWriter
	w.sessionPolicyTag()
	w.raw16(tech)
	w.raw16(sess)
	w.raw16(mach)
	w.lpStr(string(access))
	w.i64(issuedAtMs)
	w.i64(expiresAtMs)
	return w.buf, nil
}

// sessionPolicySigningBytes builds the canonical session-policy-v1 preimage — a byte-for-byte port
// of Rust's SessionPolicyClaims::signing_bytes (10 fields). All integers big-endian; the access
// level is length-prefixed UTF-8; allow_recording and require_recording are single bytes;
// max_session_duration_seconds and max_idle_seconds are u32be.
// Returns an error only on a malformed UUID or an unknown access level.
//
// Layout (bytes, 0-indexed):
//
//	[0..11]     session-policy domain tag ("RMTSPOLv1\x00\x00\x00")
//	[12..27]    technician_id (16 bytes, big-endian UUID)
//	[28..43]    session_id    (16 bytes)
//	[44..59]    machine_id    (16 bytes)
//	[60..63]    access level length prefix (big-endian uint32)
//	[64..N]     access level string ("view_only" or "control")
//	[N+1..N+8]  issued_at_ms  (int64 big-endian)
//	[N+9..N+16] expires_at_ms (int64 big-endian)
//	[N+17]      allow_recording  (u8: 1 or 0)
//	[N+18]      require_recording (u8: 1 or 0)
//	[N+19..N+22] max_session_duration_seconds (u32 big-endian; 0 = unlimited)
//	[N+23..N+26] max_idle_seconds (u32 big-endian; 0 = no idle timeout)
func sessionPolicySigningBytes(technicianID, sessionID, machineID string, access SessionAccessLevel, allowRecording, requireRecording bool, maxSessionDurationSeconds, maxIdleSeconds uint32, issuedAtMs, expiresAtMs int64) ([]byte, error) {
	if !access.Valid() {
		return nil, fmt.Errorf("session policy access level: unknown level %q", string(access))
	}
	tech, err := uuidBytes(technicianID)
	if err != nil {
		return nil, fmt.Errorf("technician_id: %w", err)
	}
	sess, err := uuidBytes(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	mach, err := uuidBytes(machineID)
	if err != nil {
		return nil, fmt.Errorf("machine_id: %w", err)
	}
	var w canonicalWriter
	w.sessionPolicyTag()
	w.raw16(tech)
	w.raw16(sess)
	w.raw16(mach)
	w.lpStr(string(access))
	w.i64(issuedAtMs)
	w.i64(expiresAtMs)
	if allowRecording {
		w.u8(1)
	} else {
		w.u8(0)
	}
	if requireRecording {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.u32(maxSessionDurationSeconds)
	w.u32(maxIdleSeconds)
	return w.buf, nil
}

// MintSessionPolicy builds the canonical preimage for the given session, signs it with the control
// plane's long-term identity, and returns a SignedSessionPolicy whose JSON the Rust agent verifies.
// Times are Unix milliseconds. allowRecording carries the group's ProhibitRecording inverse: true
// means the agent may record; false means recording is banned by policy. requireRecording carries
// the group's RequireRecording value directly: true means the agent MUST record the session
// automatically and may not stop until teardown. maxSessionDurationSeconds is the per-group hard
// session time limit (0 = unlimited); the agent ends the session when the wall-clock limit expires.
// maxIdleSeconds is the per-group idle timeout (0 = no timeout); the agent ends the session when
// no controller input has been received for this many consecutive seconds.
// Fails on a malformed UUID or an unknown access level.
//
// Deliberately a method on GrantIssuer rather than a new issuer type: the agent pins ONE public key
// (`grant_issuer_pubkey`), so a second key would mean a second thing to provision and rotate. The
// domain tag — not a separate key — is what keeps the two artifact types from being confused.
func (gi *GrantIssuer) MintSessionPolicy(technicianID, sessionID, machineID string, access SessionAccessLevel, allowRecording, requireRecording bool, maxSessionDurationSeconds, maxIdleSeconds uint32, issuedAtMs, expiresAtMs int64) (SignedSessionPolicy, error) {
	v1msg, err := sessionPolicySigningBytes(technicianID, sessionID, machineID, access, allowRecording, requireRecording, maxSessionDurationSeconds, maxIdleSeconds, issuedAtMs, expiresAtMs)
	if err != nil {
		return SignedSessionPolicy{}, err
	}
	// One sig over the v1 preimage — covers ALL policy fields.
	v1sig := ed25519.Sign(gi.priv, v1msg)
	v1sigHex := hex.EncodeToString(v1sig)

	// For non-restrictive policies: also emit "sig" = v0-preimage sig so deployed agents (which
	// only read "sig" and verify against their locally-computed 6-field v0 preimage) continue to
	// work. "sig" and "sig_v1" carry DIFFERENT signatures — v0 vs v1 preimage respectively.
	//
	// For restrictive policies: omit "sig" entirely. Deployed agents that cannot read "sig_v1" will
	// get a decode/verify failure — the desired fail-closed behaviour when new restrictions are in
	// force that old agents cannot enforce.
	var sigCompatHex string
	if !policyHasNewRestrictions(allowRecording, requireRecording, maxSessionDurationSeconds, maxIdleSeconds) {
		v0msg, err := sessionPolicySigningBytesV0(technicianID, sessionID, machineID, access, issuedAtMs, expiresAtMs)
		if err != nil {
			return SignedSessionPolicy{}, fmt.Errorf("v0 preimage: %w", err)
		}
		sigCompatHex = hex.EncodeToString(ed25519.Sign(gi.priv, v0msg))
	}

	return SignedSessionPolicy{
		Claims: sessionPolicyClaims{
			Policy: sessionPolicyBody{
				TechnicianID:              technicianID,
				SessionID:                 sessionID,
				MachineID:                 machineID,
				Access:                    access,
				AllowRecording:            allowRecording,
				RequireRecording:          requireRecording,
				MaxSessionDurationSeconds: maxSessionDurationSeconds,
				MaxIdleSeconds:            maxIdleSeconds,
			},
			IssuedAtMs:  issuedAtMs,
			ExpiresAtMs: expiresAtMs,
		},
		Sig:       v1sigHex,
		SigCompat: sigCompatHex,
	}, nil
}
