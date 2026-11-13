package controlplane

// Backstage grant minting (Milestone H1b).
//
// The agent (agent/src/backstage/grant.rs) will only construct a backstage Dispatcher once it has
// verified an Ed25519-signed `SignedGrant` against a pinned issuer public key. H1 could only mint
// those grants from Rust because the signature covered `serde_json::to_vec(&claims)`, which Go's
// encoding/json cannot reproduce byte-for-byte. H1b fixes that: the signature now covers a
// **canonical v1** binary preimage (see signingBytes) that this file builds byte-for-byte
// identically to the Rust `GrantClaims::signing_bytes`. That lets the Go control plane be the real
// issuer — it holds the long-term key, resolves the authenticated technician's capabilities, and
// mints a short-TTL grant the agent trusts.
//
// The SignedGrant JSON emitted here is exactly the wire shape Rust's `SignedGrant` deserializes
// (claims{grant{technician_id,session_id,machine_id,capabilities[]},issued_at_ms,expires_at_ms},
// sig hex). JSON formatting differences are irrelevant to verification because the SIGNATURE is
// over the canonical bytes, not the JSON — the JSON only has to deserialize into the struct with
// the right field names + values.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// backstageGrantTTL is how long a minted backstage grant stays valid. Deliberately short: the
// browser mints one per backstage session and forwards it immediately, so a leaked grant is only
// briefly useful. The agent additionally tolerates a small clock skew (CLOCK_SKEW_MS in grant.rs).
const backstageGrantTTL = 5 * time.Minute

// sessionPolicyTTL bounds how long an ATTENDED session's access policy stays valid. Generous relative to
// the session ticket because the viewer installs the policy once, when the Control channel opens, which can
// be well after the session record is created (ICE + DTLS + the agent accepting) — and a policy that expired
// in transit would be REJECTED by the agent, leaving an enforced session with no floor. Still bounded, so a
// captured policy is not useful indefinitely; the agent's ratchet is what makes replay harmless anyway.
//
// ATTENDED ONLY since docs/25 F03. Unattended sessions moved to sessionPolicyLeaseTTL below, because for
// them the policy's lifetime IS the revocation window. Attended sessions did not, and the reason is that
// they never needed a lease: an attended guest polls GET /attended-sessions/status every three seconds and
// stops itself when the control plane reports the session ended (spawn_attend_status_poller in host.rs), so
// attended revocation is already five times tighter than any lease and does not depend on the viewer's
// cooperation. Shortening this would buy nothing and would risk stranding a guest VIEW-ONLY FOREVER: there
// is no renewal path for an attended session, so a policy that expired in transit is one the guest can never
// replace — `serve_session_with_ice` runs once per attended process, with no reconnect.
const sessionPolicyTTL = 15 * time.Minute

// sessionPolicyLeaseTTL is how long an UNATTENDED session's access policy stays valid — and therefore how
// long an unattended session survives after the control plane stops re-authorizing it (docs/25 F03).
//
// THIS CONSTANT IS THE REVOCATION WINDOW. `POST /sessions/{id}/end` writes `ended_at`, records a
// `session.end` audit row, and — this was the finding — sends nothing to signaling and nothing to the agent.
// Unattended host dispatch closed only for a peer's COOPERATIVE `EndSession`, a local stop, a transport
// failure or the session lifetime bound, so a hostile controller kept the desktop simply by not cooperating
// and the administrator's primary incident-response control was cosmetic.
//
// The fix is a short renewable LEASE, not a pushed revocation, because there is no authenticated channel
// from the control plane to a running agent: the only agent→control-plane call in this product is one-shot
// enrollment, so a push would mean designing and testing a second agent authentication protocol. The agent
// instead demands a fresh signed policy every so often, the viewer fetches one from POST /sessions/{id}/policy
// (see http_session_lease.go), and this endpoint REFUSES to mint once the session has ended. The controller
// cannot help itself by withholding anything — a controller that stops renewing kills its own session.
//
// WHY THIRTY SECONDS. The operator's target for this finding was a revocation window of about thirty
// seconds, and the window is exactly this TTL: the worst case is a lease minted the instant before an
// administrator clicks End, which then survives its own life. The viewer renews at a third of the remaining
// lease (see the `lease_ttl_ms` in the renewal response), so a session gets three attempts before it lapses
// and one dropped request never costs anyone their session. The agent notices an expiry within one
// LEASE_TICK (2 s), so the honest end-to-end bound to quote an auditor is ~32 s, not 30.
//
// WHY NOT SHORTER. Two things bound it from below. This is also the TTL of the policy minted at
// POST /sessions, which must survive ICE + DTLS + the data channel opening before anything can renew it —
// typically 1-3 s, up to ~5 s through TURN, so thirty seconds is a six-to-ten-fold margin. And the agent's
// expiry check is against ITS OWN wall clock with no tolerance (deliberately: slack on expiry would extend
// the life of the artifact), so this TTL is now the amount by which a machine's clock may run FAST before
// every lease looks expired on arrival. That was previously fifteen minutes and is now thirty seconds — the
// real operational cost of this change, called out here rather than discovered in the field. The agent logs
// `stale_by_ms` on an expired lease precisely so that failure is legible as a clock problem.
const sessionPolicyLeaseTTL = 30 * time.Second

// elevationGrantTTL bounds how long a minted elevation grant stays valid. Deliberately the TIGHTEST
// of the three, and for a reason the other two spell out by contrast: a backstage grant gets 5
// minutes because the browser mints one per backstage session; a session policy gets 15 because it
// has to survive ICE + DTLS setup before the Control channel exists. An elevation grant is minted on
// an ALREADY-OPEN Control channel and forwarded in the same tick, so it needs neither budget — it
// needs only enough slack for the round trip and the agent's one-sided CLOCK_SKEW_MS tolerance.
//
// It is also the only artifact here that hands over privilege, and it is single-use in the agent, so
// the TTL is a second bound on a window that should barely exist. Two minutes matches the session
// ticket's, which is the other short-lived bearer secret in this system.
//
// THE TOLERATED AGENT-CLOCK OFFSET IS THEREFORE [-CLOCK_SKEW_MS, +TTL) = [-30s, +2min), spelled out
// because a reviewer has already read the one-sided tolerance as a defect once. The agent tolerates
// a clock BEHIND the control plane's by CLOCK_SKEW_MS (the not-yet-valid check) and one AHEAD by the
// whole remaining TTL (the expiry check is exact). That asymmetry is deliberate — slack on expiry
// would extend the life of a privilege-granting artifact — but it does mean elevation is the first
// feature a badly fast guest clock breaks, and it breaks LOUDLY and safely: `ElevationError::Expired`
// is reported to the technician as its own refusal, distinct from a key or binding problem, and
// nothing runs. If that is ever seen in the field the fix is the guest's time service, not this
// constant.
const elevationGrantTTL = 2 * time.Minute

// newUUID returns a random RFC-4122 v4 UUID string. Grants need real UUIDs (Rust deserializes the
// ids as uuid::Uuid), so this is used for a generated session_id when the caller does not supply
// one. newID() in session.go returns base64 and is intentionally not reused here.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// -------------------------------------------------------------------------------------
// Backstage capabilities — the agent-side capability vocabulary (agent/src/backstage/rbac.rs).
//
// These are DISTINCT from the management-plane Capability constants in rbac.go: those gate the
// control-plane API (backstage_shell, view_machines, …), whereas these are the fine-grained
// backstage tool permissions the minted grant carries and the agent enforces. Each value IS the
// canonical snake_case serde string the Rust `Capability` uses, so it doubles as `capabilityName`
// — no separate map to drift. `TestBackstageCapabilityNamesAreSnakeCase` guards the shape, and the
// golden vector proves it matches Rust's `capability_name` byte-for-byte.
// -------------------------------------------------------------------------------------

// BackstageCapability is one fine-grained backstage permission carried in a minted grant. Its
// string value is the canonical name signed into the grant (and understood by the agent).
type BackstageCapability string

const (
	// --- read-only (Tier 1) ---
	BackProcessList    BackstageCapability = "process_list"
	BackServiceList    BackstageCapability = "service_list"
	BackEventLogRead   BackstageCapability = "event_log_read"
	BackFileBrowse     BackstageCapability = "file_browse"
	BackFileDownload   BackstageCapability = "file_download"
	BackRegistryRead   BackstageCapability = "registry_read"
	BackSystemInfoRead BackstageCapability = "system_info_read"

	// --- operator (Tier 2) ---
	BackServiceControl BackstageCapability = "service_control"
	BackProcessKill    BackstageCapability = "process_kill"
	BackFileUpload     BackstageCapability = "file_upload"
	BackShellAsUser    BackstageCapability = "shell_as_user"

	// --- admin (Tier 3) ---
	BackRegistryWrite     BackstageCapability = "registry_write"
	BackRegistryHiveLoad  BackstageCapability = "registry_hive_load"
	BackServiceConfig     BackstageCapability = "service_config"
	BackFileDelete        BackstageCapability = "file_delete"
	BackShellAsSystem     BackstageCapability = "shell_as_system"
	BackShellAsCredential BackstageCapability = "shell_as_credential"
	BackUninstallProgram  BackstageCapability = "uninstall_program"
	BackLocalUserAdmin    BackstageCapability = "local_user_admin"
)

// Backstage capability tier presets. A minted grant's capability set is assembled from these
// according to the technician's management-plane authorization (see BackstageCapsFor).
var (
	backstageReadOnlyCaps = []BackstageCapability{
		BackProcessList, BackServiceList, BackEventLogRead, BackFileBrowse,
		BackFileDownload, BackRegistryRead, BackSystemInfoRead,
	}
	backstageOperatorCaps = []BackstageCapability{
		BackServiceControl, BackProcessKill, BackFileUpload, BackShellAsUser,
	}
	backstageAdminCaps = []BackstageCapability{
		BackRegistryWrite, BackRegistryHiveLoad, BackServiceConfig, BackFileDelete,
		BackShellAsSystem, BackShellAsCredential, BackUninstallProgram, BackLocalUserAdmin,
	}
)

// AllBackstageCapabilities is every backstage capability in the same declaration order as the Rust
// `Capability::ALL`. Used for enumeration/validation and to mirror the anti-drift discipline.
var AllBackstageCapabilities = concatCaps(backstageReadOnlyCaps, backstageOperatorCaps, backstageAdminCaps)

func concatCaps(groups ...[]BackstageCapability) []BackstageCapability {
	var out []BackstageCapability
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// BackstageCapsFor resolves the backstage capability set a technician may be granted for a machine,
// from their management-plane *Grant. It is the control plane's policy for translating coarse
// management authorization into the fine-grained grant the agent enforces:
//
//   - CapBackstageShell (group-scoped) is mandatory — without it, no backstage grant is minted.
//   - Everyone who may run backstage gets the read-only + operator tiers.
//   - The admin tier (registry writes, system shells, uninstall, local-user admin) additionally
//     requires CapManageMachines for the machine's group — an ordinary Technician does not get it.
//
// Returns (nil, false) when the technician is not authorized to run backstage on this machine.
func BackstageCapsFor(g *Grant, machineGroupID string) ([]BackstageCapability, bool) {
	if g == nil || !g.AllowsInGroup(CapBackstageShell, machineGroupID) {
		return nil, false
	}
	caps := concatCaps(backstageReadOnlyCaps, backstageOperatorCaps)
	if g.AllowsInGroup(CapManageMachines, machineGroupID) {
		caps = append(caps, backstageAdminCaps...)
	}
	return caps, true
}

// -------------------------------------------------------------------------------------
// Canonical v1 signing bytes — a byte-for-byte port of Rust's `GrantClaims::signing_bytes`
// (agent/src/backstage/canonical.rs). All integers big-endian; lengths are u32.
// -------------------------------------------------------------------------------------

// grantDomainTag is the 12-byte canonical-v1 domain-separation tag: ASCII "RMTGRANTv1" followed by
// two 0x00 bytes. Hex: 52 4d 54 47 52 41 4e 54 76 31 00 00. Must equal Rust's DOMAIN_TAG.
var grantDomainTag = []byte("RMTGRANTv1\x00\x00")

// canonicalWriter mirrors the Rust CanonicalWriter: an append-only builder of the big-endian,
// length-prefixed signing bytes.
type canonicalWriter struct {
	buf []byte
}

func (w *canonicalWriter) tag()      { w.buf = append(w.buf, grantDomainTag...) }
func (w *canonicalWriter) auditTag() { w.buf = append(w.buf, auditDomainTag...) }
func (w *canonicalWriter) sessionPolicyTag() {
	w.buf = append(w.buf, sessionPolicyDomainTag...)
}
func (w *canonicalWriter) elevationTag() {
	w.buf = append(w.buf, elevationDomainTag...)
}

// updateTag is the odd one out: every other tag above namespaces an artifact signed by THIS
// package's GrantIssuer key, while an update manifest is signed by a key that never touches the
// control plane at all (update_manifest.go's header explains why that exception exists). The writer
// method still lives here so all five tag helpers sit together and a reviewer can see the whole set
// at once.
func (w *canonicalWriter) updateTag() {
	w.buf = append(w.buf, updateDomainTag...)
}
func (w *canonicalWriter) updateV2Tag() {
	w.buf = append(w.buf, updateDomainTagV2...)
}
func (w *canonicalWriter) raw16(b [16]byte) { w.buf = append(w.buf, b[:]...) }
func (w *canonicalWriter) u8(v byte)        { w.buf = append(w.buf, v) }

func (w *canonicalWriter) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *canonicalWriter) u64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *canonicalWriter) i32(v int32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	w.buf = append(w.buf, b[:]...)
}

func (w *canonicalWriter) i64(v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	w.buf = append(w.buf, b[:]...)
}

func (w *canonicalWriter) lpStr(s string) {
	w.u32(uint32(len(s)))
	w.buf = append(w.buf, s...)
}

// signingBytes builds the canonical v1 preimage for a grant. technicianID/sessionID/machineID are
// hyphenated UUID strings (parsed to 16 raw bytes, matching Rust's Uuid::as_bytes). Returns an
// error only if a UUID string is malformed.
func signingBytes(technicianID, sessionID, machineID string, caps []BackstageCapability, issuedAtMs, expiresAtMs int64) ([]byte, error) {
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
	w.tag()
	w.raw16(tech)
	w.raw16(sess)
	w.raw16(mach)
	w.u32(uint32(len(caps)))
	for _, c := range caps {
		w.lpStr(string(c))
	}
	w.i64(issuedAtMs)
	w.i64(expiresAtMs)
	return w.buf, nil
}

// uuidBytes parses a canonical 8-4-4-4-12 hyphenated UUID string into its 16 raw bytes, the same
// bytes Rust's Uuid::as_bytes yields. Rejects any other shape (deny-by-default: a bad id must never
// silently produce zero bytes).
func uuidBytes(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return out, fmt.Errorf("not a canonical UUID: %q", s)
	}
	stripped := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	b, err := hex.DecodeString(stripped)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("not a canonical UUID: %q", s)
	}
	copy(out[:], b)
	return out, nil
}

// -------------------------------------------------------------------------------------
// SignedGrant wire shape — the JSON Rust's SignedGrant deserializes.
// -------------------------------------------------------------------------------------

// grantBody mirrors Rust `Grant` (agent/src/backstage/rbac.rs).
type grantBody struct {
	TechnicianID string                `json:"technician_id"`
	SessionID    string                `json:"session_id"`
	MachineID    string                `json:"machine_id"`
	Capabilities []BackstageCapability `json:"capabilities"`
}

// grantClaims mirrors Rust `GrantClaims`.
type grantClaims struct {
	Grant       grantBody `json:"grant"`
	IssuedAtMs  int64     `json:"issued_at_ms"`
	ExpiresAtMs int64     `json:"expires_at_ms"`
}

// SignedGrant mirrors Rust `SignedGrant`: the claims plus a hex Ed25519 signature over their
// canonical v1 signing bytes. Marshals to the exact JSON the agent verifies.
type SignedGrant struct {
	Claims grantClaims `json:"claims"`
	Sig    string      `json:"sig"`
}

// -------------------------------------------------------------------------------------
// GrantIssuer — holds the control plane's long-term Ed25519 key and mints signed grants.
// -------------------------------------------------------------------------------------

// GrantIssuer signs backstage grants with the control plane's long-term Ed25519 private key. Its
// public half (PublicKeyHex) is provisioned into agent config.json as `grant_issuer_pubkey` so the
// agent pins it and rejects grants from any other key.
type GrantIssuer struct {
	priv ed25519.PrivateKey
}

// NewGrantIssuerFromSeed reconstructs an issuer from a 32-byte Ed25519 seed (e.g. loaded from a
// secret store), matching Rust's Identity::from_seed.
func NewGrantIssuerFromSeed(seed []byte) (*GrantIssuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("grant issuer seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &GrantIssuer{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// GenerateGrantIssuer creates a fresh random issuer (dev/first-run). Persist its seed to keep the
// public key stable across restarts, otherwise agents pinned to the old key reject new grants.
func GenerateGrantIssuer() (*GrantIssuer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &GrantIssuer{priv: priv}, nil
}

// PublicKeyHex returns the hex-encoded 32-byte Ed25519 public key to pin in agent config.
func (gi *GrantIssuer) PublicKeyHex() string {
	pub := gi.priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

// Mint builds the canonical v1 preimage for the given claims, signs it, and returns a SignedGrant
// whose JSON the Rust agent verifies. Times are Unix milliseconds. Fails only on a malformed UUID.
func (gi *GrantIssuer) Mint(technicianID, sessionID, machineID string, caps []BackstageCapability, issuedAtMs, expiresAtMs int64) (SignedGrant, error) {
	msg, err := signingBytes(technicianID, sessionID, machineID, caps, issuedAtMs, expiresAtMs)
	if err != nil {
		return SignedGrant{}, err
	}
	sig := ed25519.Sign(gi.priv, msg)
	return SignedGrant{
		Claims: grantClaims{
			Grant: grantBody{
				TechnicianID: technicianID,
				SessionID:    sessionID,
				MachineID:    machineID,
				Capabilities: caps,
			},
			IssuedAtMs:  issuedAtMs,
			ExpiresAtMs: expiresAtMs,
		},
		Sig: hex.EncodeToString(sig),
	}, nil
}
