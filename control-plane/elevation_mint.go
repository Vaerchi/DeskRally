package controlplane

// Signed, session-bound, SINGLE-USE elevation grants (loop 87, docs/01 §3 "Elevate client to admin
// mid-session") — the control plane authorizing ONE command on ONE session to run with the guest's
// LINKED ELEVATED token instead of their ordinary, UAC-filtered one.
//
// WHY THIS IS NOT A SESSION POLICY, and why that is not negotiable. A SignedSessionPolicy
// (session_policy_mint.go) may only ever RESTRICT a session, and that one-way ratchet is the whole
// reason replaying a captured one is harmless — the worst it can do is take away access the holder
// already had. An elevation GRANTS. None of the policy's replay reasoning transfers, so this is its
// own artifact with its own domain tag, its own single-use id, and a much tighter TTL. Its Rust twin
// is `rmt_agent::elevation`, and the agent is the party that ENFORCES it.
//
// WHAT IT BUYS, given the unattended helper is already SYSTEM. SYSTEM outranks an elevated user
// token locally, so it would be fair to ask what this authorizes that RunCommand{as_user:false}
// does not. The answer is the guest's own IDENTITY: SYSTEM authenticates on the network as the
// machine account, cannot decrypt the user's DPAPI-protected secrets, and has neither their profile
// nor their mapped drives. An elevated user token is that user at full admin. The two are not
// points on one privilege lattice, which is why elevation is worth an explicit, audited,
// per-command authorization while SYSTEM (conferred once, by installing the service) is not.
//
// ONE GRANT, ONE COMMAND. There is no elevated "mode" and no lease. The viewer requests a grant per
// elevated command, so every one of them appears in the management audit trail as its own event —
// rather than a session-wide "elevation was granted at 10:05" that says nothing about what was run.
//
// The canonical preimage is a byte-for-byte port of Rust's `ElevationClaims::signing_bytes`
// (agent/src/elevation.rs); TestElevationGoldenVectorV1 and the Rust `elevation::tests::
// golden_vector_v1` pin the SAME fixture to the SAME hex on both sides.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// elevationDomainTag is the 12-byte elevation-v1 domain-separation tag: ASCII "RMTELEVv1" (9 bytes)
// followed by three 0x00 bytes. Hex: 52 4d 54 45 4c 45 56 76 31 00 00 00. Must equal Rust's
// ELEVATION_DOMAIN_TAG.
//
// It MUST differ from every other tag this key signs, and the stake here is the highest of the set:
// an elevation grant is the only artifact that hands over privilege rather than removing it, so a
// tag collision would let a signature minted over a harmless session policy be presented as
// authorization to run a command with the guest's full admin token. TestDomainTagsArePairwiseDistinct
// pins them apart.
var elevationDomainTag = []byte("RMTELEVv1\x00\x00\x00")

// ElevationTokenKind is which token an authorized command runs with. The wire values are the
// canonical snake_case strings Rust's `ElevationToken` serde-encodes, and they go into the signing
// bytes verbatim — a cross-language contract, not local vocabulary.
type ElevationTokenKind string

const (
	// ElevationTokenBase: the interactive user's ordinary (UAC-filtered) token — i.e. no elevation
	// at all. The RESTRICTIVE value and Rust's Default, so every "could not work out what was
	// meant" path lands on it. Never minted by the handler; it exists so the token kind is an
	// explicit CHOICE in the signed preimage rather than an implicit constant.
	ElevationTokenBase ElevationTokenKind = "base"
	// ElevationTokenLinkedElevated: the interactive user's LINKED ELEVATED token — their own full
	// administrator rights, as if they had clicked "Yes" on a UAC prompt. Never SYSTEM.
	ElevationTokenLinkedElevated ElevationTokenKind = "linked_elevated"
)

// Valid reports whether k is one of the two kinds the agent understands.
//
// Minting refuses an unknown kind rather than passing it through, exactly as
// SessionAccessLevel.Valid does and for the same reason: an empty or typo'd kind would otherwise be
// signed and shipped, the agent would fail to DECODE it (Rust rejects an unknown serde variant), and
// a control-plane bug would surface as an unexplained refusal on the guest instead of a loud local
// error.
func (k ElevationTokenKind) Valid() bool {
	return k == ElevationTokenBase || k == ElevationTokenLinkedElevated
}

// elevationBody mirrors Rust `Elevation` (agent/src/elevation.rs).
type elevationBody struct {
	TechnicianID string             `json:"technician_id"`
	SessionID    string             `json:"session_id"`
	MachineID    string             `json:"machine_id"`
	ElevationID  string             `json:"elevation_id"`
	Token        ElevationTokenKind `json:"token"`
}

// elevationClaims mirrors Rust `ElevationClaims`.
type elevationClaims struct {
	Elevation   elevationBody `json:"elevation"`
	IssuedAtMs  int64         `json:"issued_at_ms"`
	ExpiresAtMs int64         `json:"expires_at_ms"`
}

// SignedElevationGrant mirrors Rust `SignedElevationGrant`: the claims plus a hex Ed25519 signature
// over their canonical signing bytes. Marshals to the exact JSON the agent verifies.
type SignedElevationGrant struct {
	Claims elevationClaims `json:"claims"`
	Sig    string          `json:"sig"`
}

// JSON renders the signed grant as the wire string carried opaquely in the Control channel's
// ElevatedRun message.
func (g SignedElevationGrant) JSON() (string, error) {
	b, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Token returns the token kind this grant authorizes (handlers audit it, tests assert it).
func (g SignedElevationGrant) Token() ElevationTokenKind { return g.Claims.Elevation.Token }

// ElevationID returns the grant's single-use id — the value the agent burns, and the value the
// audit event records so a minted grant can be correlated with the command the agent ran.
func (g SignedElevationGrant) ElevationID() string { return g.Claims.Elevation.ElevationID }

// elevationSigningBytes builds the canonical elevation-v1 preimage — a byte-for-byte port of Rust's
// ElevationClaims::signing_bytes. All integers big-endian; the token kind is length-prefixed UTF-8.
// UUIDs are parsed from hyphenated strings to 16 raw bytes, matching Rust's Uuid::as_bytes. Returns
// an error only on a malformed UUID or an unknown token kind.
func elevationSigningBytes(technicianID, sessionID, machineID, elevationID string, token ElevationTokenKind, issuedAtMs, expiresAtMs int64) ([]byte, error) {
	if !token.Valid() {
		return nil, fmt.Errorf("elevation token kind: unknown kind %q", string(token))
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
	elev, err := uuidBytes(elevationID)
	if err != nil {
		return nil, fmt.Errorf("elevation_id: %w", err)
	}
	var w canonicalWriter
	w.elevationTag()
	w.raw16(tech)
	w.raw16(sess)
	w.raw16(mach)
	w.raw16(elev)
	w.lpStr(string(token))
	w.i64(issuedAtMs)
	w.i64(expiresAtMs)
	return w.buf, nil
}

// MintElevation builds the canonical preimage for one elevated command, signs it with the control
// plane's long-term identity, and returns a SignedElevationGrant whose JSON the Rust agent verifies.
// Times are Unix milliseconds. Fails on a malformed UUID or an unknown token kind.
//
// Deliberately a method on GrantIssuer rather than a new issuer type, for the reason
// MintSessionPolicy states: the agent pins ONE public key (`grant_issuer_pubkey`), so a second key
// would mean a second thing to provision and rotate. The domain tag — not a separate key — is what
// keeps the three artifact types from being confused.
//
// elevationID MUST be freshly generated per call (the handler uses newUUID). It is the value the
// agent burns to make the grant single-use; reusing one would make the second grant look like a
// replay of the first.
func (gi *GrantIssuer) MintElevation(technicianID, sessionID, machineID, elevationID string, token ElevationTokenKind, issuedAtMs, expiresAtMs int64) (SignedElevationGrant, error) {
	msg, err := elevationSigningBytes(technicianID, sessionID, machineID, elevationID, token, issuedAtMs, expiresAtMs)
	if err != nil {
		return SignedElevationGrant{}, err
	}
	sig := ed25519.Sign(gi.priv, msg)
	return SignedElevationGrant{
		Claims: elevationClaims{
			Elevation: elevationBody{
				TechnicianID: technicianID,
				SessionID:    sessionID,
				MachineID:    machineID,
				ElevationID:  elevationID,
				Token:        token,
			},
			IssuedAtMs:  issuedAtMs,
			ExpiresAtMs: expiresAtMs,
		},
		Sig: hex.EncodeToString(sig),
	}, nil
}
