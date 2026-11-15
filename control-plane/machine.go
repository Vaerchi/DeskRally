package controlplane

// Milestone D1 — the machine repository (control-plane data plane).
//
// This closes a real authorization hole. Before D1 the grant/session handlers resolved a
// machine's group from a field in the REQUEST BODY (`machine_group_id`), so a caller could
// name whichever group handed them the widest capability tier — `BackstageCapsFor` and
// `RequireMachine` both key off the group, and the group was attacker-controlled. D1 makes
// the group come from stored machine data instead, so authorization is scoped to the machine's
// REAL group regardless of what the body claims.
//
// The store follows the repo's existing interface-plus-fakes pattern (UserStore/SessionStore/
// AuditStore): a MachineStore interface, an in-memory fake for tests + the dev skeleton, and a
// pgx implementation for production (see PgMachineStore in pgstore.go) over the `machine` table
// in migrations/0001_core.sql — which already exists, so D1 adds no migration.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// DevDefaultMachineGroupID is the synthetic group the permissive (dev/e2e) machine store maps
// every unknown machine into. It is only meaningful in DEV mode, where the stub authenticator
// is a full-owner over AllGroups(), so the specific group value never narrows anything; it just
// has to be a stable, well-formed id. Production uses the strict PgMachineStore and never sees
// this value.
const DevDefaultMachineGroupID = "00000000-0000-0000-0000-000000000000"

// ErrMachineNotFound is the sentinel returned when a machine id does not resolve in the tenant.
// Handlers translate it to a 404/400 "unknown machine" rather than leaking it as a 500.
var ErrMachineNotFound = errors.New("machine not found")

// Machine lifecycle states (machine.status, migrations/0001's CHECK). New machines default to Active.
const (
	MachineStatusActive      = "active"
	MachineStatusQuarantined = "quarantined"
	MachineStatusRetired     = "retired"
	// MachineStatusRemoved is the terminal tombstone of a completed agent removal (docs/65 D-C9). It is
	// NEVER settable through SetMachineStatus (IsValidMachineStatus excludes it): only an acknowledged
	// uninstall directive writes it, and nothing ever leaves it.
	MachineStatusRemoved = "removed"
)

// ErrMachineHasActiveDirective: the machine has a fleet directive in flight (docs/65 D-C4), so its status
// and group cannot change until that directive is cancelled or finished. The database trigger
// machine_directive_guard (migrations/0068, SQLSTATE DR001) enforces it for pg; the fake mirrors it.
var ErrMachineHasActiveDirective = errors.New("machine has an active directive; cancel it first")

// ErrMachineRemoved: the machine was removed (docs/65 D-C9) and is terminal (SQLSTATE DR002).
var ErrMachineRemoved = errors.New("machine was removed")

// ErrInvalidMachineStatus is returned by SetMachineStatus for a status outside the CHECK set.
var ErrInvalidMachineStatus = errors.New("invalid machine status")

// ErrInvalidMachineGroup is returned by SetMachineGroup when the target group does not resolve within the
// tenant — the pg store maps the composite-FK violation (23503) to it; the handler validates up front.
var ErrInvalidMachineGroup = errors.New("invalid machine group")

// IsValidMachineStatus reports whether s is a settable machine status. The handler and BOTH stores
// gate on it so a status the DB CHECK would reject can never be attempted.
func IsValidMachineStatus(s string) bool {
	return s == MachineStatusActive || s == MachineStatusQuarantined || s == MachineStatusRetired
}

// ErrMachineDeviceIDTaken is the sentinel for enrolling a device_id that already exists — in the
// tenant (UNIQUE (tenant_id, device_id), 0001_core.sql) or in ANY tenant (the global unique index
// added by migrations/0008, which is what stops one tenant from minting session tickets for
// another tenant's agent). Handlers translate it to a 409.
var ErrMachineDeviceIDTaken = errors.New("device_id already enrolled")

// Machine is an enrolled agent endpoint as far as the control-plane API needs it: its identity,
// its tenant, and — the security-critical field — the machine group RBAC scopes against. Name
// maps to the `hostname` column in migrations/0001_core.sql (a display label, not identity).
//
// There are TWO identifiers, and they are NOT interchangeable (migrations/0001_core.sql):
//
//   - ID is the database primary key (`machine.id`, a uuid). It is what the REST `/machines/{id}`
//     path addresses and what session_record.machine_id foreign-keys to.
//   - DeviceID is the STABLE AGENT IDENTITY (`machine.device_id`, text; UNIQUE per tenant). It is
//     the identity the AGENT knows itself by and the value the console/grant path carries: the
//     console does `mintGrant(session.device)` and H3 binds the signed grant to it. So the
//     grant/session/mint paths resolve a machine BY DEVICE ID, not by PK.
//
// Conflating the two is a real authorization bug: resolving a device id against the PK column
// finds no row, so a legitimately enrolled machine fails to mint. GetMachine therefore looks up
// by DeviceID; GetMachineByID looks up by the PK for the REST read path.
type Machine struct {
	ID       string `json:"id"` // database primary key (machine.id)
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"` // stable agent identity (machine.device_id)
	GroupID  string `json:"group_id"`
	Name     string `json:"name"`
	// Pubkey is the agent's long-term Ed25519 public key, hex-encoded (64 hex chars = 32
	// bytes; the `pubkey` bytea column). Pinned at token redemption (M1); empty for machines
	// enrolled through the legacy authenticated /enroll path.
	Pubkey string `json:"pubkey,omitempty"`
	// Ephemeral + ExpiresAt mark an attended-session guest machine (docs/12): a short-lived row
	// hidden from the fleet listing and refused by identity lookup once ExpiresAt passes. Permanent
	// (unattended) machines leave these at their zero values. Columns added by migrations/0013.
	Ephemeral bool       `json:"ephemeral,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Status is the machine's lifecycle state — 'active' | 'quarantined' | 'retired' (machine.status,
	// migrations/0001, CHECK-constrained). New machines default to 'active'; a quarantined or retired
	// machine is refused a new session (handleStartSession) — quarantine is the operator's "stop
	// connecting to this box" switch. Set via POST /machines/{id}/status (CapManageMachines for the group).
	Status string `json:"status,omitempty"`

	// Alias is a tenant-chosen FRIENDLY NAME (machine.alias, migrations/0032) that the console prefers
	// over the agent-reported hostname (Name) when non-empty. It is display-only — nothing authorizes on
	// it — and independent of the hostname, so re-enrollment never clobbers it. Set (or cleared, with an
	// empty string) via PATCH /machines/{id}/alias (CapManageMachines for the group).
	Alias string `json:"alias,omitempty"`

	// RequireSessionPolicy mirrors the AGENT's local `require_session_policy` config flag
	// (crates/agent-windows/src/config.rs), reported at enrollment and refreshed on every register
	// (machine.require_session_policy, migrations/0037). When it is set the agent opens every session
	// VIEW-ONLY and stays there until a signed access policy verifies.
	//
	// The control plane reads it at POST /sessions for one purpose: to mint a policy for a machine whose
	// GROUP does not enforce view-only, which would otherwise strand that agent view-only forever with
	// nothing to discharge it. AGENT-ASSERTED, so it is advisory about the agent's own state and never a
	// grant of authority — it can only cause a policy to be MINTED, never suppress one, which is why it
	// is safe to accept over the unauthenticated enrollment-redeem endpoint.
	RequireSessionPolicy bool `json:"require_session_policy,omitempty"`

	// Note is a free-text operator ANNOTATION (machine.note, migrations/0033) — unstructured context /
	// handoff prose, distinct from the short Alias and from structured machine properties. Display-only.
	// Set (or cleared, with an empty string) via PATCH /machines/{id}/note (CapManageMachines for the group).
	Note string `json:"note,omitempty"`

	// --- console enrichment (migrations/0017) -----------------------------------------------
	// These exist for the access panel (docs/01 §4) and are DISPLAY data: nothing authorizes on
	// them. Group scoping still keys on GroupID, never GroupName.

	// OS is the free-text OS label the agent reported at enrollment ('' when unknown).
	OS string `json:"os,omitempty"`
	// GroupName is machine_group.name for GroupID, resolved by a join at read time so the console
	// can show "Acme / Front Office" instead of a raw uuid. Empty when the group is unresolvable.
	GroupName string `json:"group_name,omitempty"`
	// Online is TRI-STATE on purpose: true (signaling has it connected), false (signaling answered
	// and it was absent), or nil = UNKNOWN (the presence feed could not be consulted). Collapsing
	// unknown into false would tell a technician a healthy machine is down whenever signaling
	// hiccups — see the fail-soft note in presence.go. Only set by the listing handler.
	Online *bool `json:"online,omitempty"`
	// LastSeen is the last time the presence feed reported this device connected, persisted in
	// machine.last_seen. NULL/nil when it has never been seen online.
	LastSeen *time.Time `json:"last_seen,omitempty"`
	// AgentVersion is the agent's self-reported build identity, "<semver>+<short git sha>"
	// (migrations/0039). Refreshed from the presence feed on the same terms as OS. DISPLAY ONLY and
	// agent-asserted: it arrives before proof of possession, so nothing may branch on it to grant
	// authority. Empty means this machine has never reported one.
	AgentVersion string `json:"agent_version,omitempty"`
	// AgentVersionSeenAt is when the CURRENT AgentVersion was FIRST observed — not a heartbeat.
	// Only moves when the version actually changes; use LastSeen for liveness. See 0039's header.
	AgentVersionSeenAt *time.Time `json:"agent_version_seen_at,omitempty"`
	// LoggedInUser is the interactive Windows session user observed in the presence feed (e.g.
	// "CORP\alice" or "alice"). Refreshed on the same terms as OS and AgentVersion: DISPLAY ONLY,
	// agent-asserted, and changes on every user log-in/log-out cycle (migrations/0048).
	// Empty means no user has been observed yet for this machine.
	LoggedInUser string `json:"logged_in_user,omitempty"`
	// MultiSessionCapable is DERIVED, never stored: true exactly when AgentVersion passes the same
	// observerAgentSupported gate POST /sessions applies to access=view_only. The console shows its
	// Observe button only when this is true, and nothing used to set it (the agent's register_agent
	// flag stops at signaling), so Observe was offered for no machine at all (2026-10-19). Deriving it
	// from the enforcing gate means the button and the server can never disagree.
	MultiSessionCapable *bool `json:"multi_session_capable,omitempty"`
	// GrantKeyPinned is the agent-REPORTED, live-only posture (audit #9): false means this machine has no
	// pinned grant issuer key, so the group view-only mandate, session lease and signed grants are advisory
	// on it. Nil = offline or an agent that does not report posture. Never stored, never authorized on.
	GrantKeyPinned *bool `json:"grant_key_pinned,omitempty"`
	// SessionPolicyRequired is the agent-REPORTED, live-only require_session_policy posture (same rules).
	// "Enforced" needs BOTH this and GrantKeyPinned: a pinned key alone does not make policy mandatory.
	SessionPolicyRequired *bool `json:"session_policy_required,omitempty"`
}

// stampDerived sets the fields computed from stored ones, for every machine a response returns.
func stampDerived(ms []Machine) {
	for i := range ms {
		ms[i].MultiSessionCapable = nil
		if observerAgentSupported(ms[i].AgentVersion) {
			yes := true
			ms[i].MultiSessionCapable = &yes
		}
	}
}

// DeviceIdentity is what the signaling server needs in order to authenticate a `register_agent`:
// the tenant the device belongs to and the Ed25519 public key pinned for it at enrollment. It is
// deliberately the WHOLE response body of GET /internal/devices/{device_id}/identity
// (docs/11-agent-identity-contract.md §4.1) — nothing else about the machine is exposed there.
type DeviceIdentity struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id"`
	Pubkey   string `json:"pubkey"` // lowercase hex, 64 chars
	// Status is the machine's lifecycle state (docs/65 D-C1). 'retired' machines resolve only for a
	// caller that asked for the RESTRICTED mode (GET .../identity?restricted=1); 'removed' never resolves.
	Status string `json:"status"`
}

// MachineStore is the persistence seam for machines. Production wires PgMachineStore (RLS-scoped
// via the request transaction); tests and the dev skeleton wire InMemoryMachineStore. Every
// method is tenant-scoped by the caller-supplied tenantID (and, in pgx, additionally by RLS), so
// a machine from another tenant is never resolvable — except LookupDeviceIdentity, which is
// documented pre-tenant and is the one deliberate exception.
type MachineStore interface {
	// GetMachine resolves a single machine within a tenant BY ITS DEVICE ID (the stable agent
	// identity, machine.device_id). This is the identity the grant/session/mint paths carry, so
	// it is the resolution the security-critical authorization checks depend on. Returns
	// ErrMachineNotFound when the device id is unknown (unless the store is permissive — see
	// InMemoryMachineStore).
	GetMachine(ctx context.Context, tenantID, deviceID string) (*Machine, error)
	// GetMachineByID resolves a single machine within a tenant BY ITS PRIMARY KEY (machine.id).
	// This backs the REST `/machines/{id}` read path; it is NOT the identity the grant path uses.
	// Returns ErrMachineNotFound when the id is unknown (permissive stores synthesize instead).
	GetMachineByID(ctx context.Context, tenantID, id string) (*Machine, error)
	// EnrollMachine records a new machine into the tenant. The store assigns the primary key
	// (machine.id); the caller supplies m.DeviceID (the stable agent identity).
	EnrollMachine(ctx context.Context, tenantID string, m *Machine) error
	// ListMachines returns every machine in the tenant (callers further filter by group scope).
	ListMachines(ctx context.Context, tenantID string) ([]Machine, error)
	// SetMachineStatus sets a machine's lifecycle status (active|quarantined|retired) BY PRIMARY KEY,
	// tenant-scoped. ErrInvalidMachineStatus for a status outside the set; ErrMachineNotFound when the
	// id is not in the tenant. A quarantined/retired machine is refused a new session (docs/01 §4).
	SetMachineStatus(ctx context.Context, tenantID, machineID, status string) error
	// SetMachineGroup reassigns a machine (BY PK) to a different group. ErrMachineNotFound if the machine
	// does not resolve within the tenant; ErrInvalidMachineGroup if the target group does not (pg: the
	// composite FK). The CALLER authorizes the move on BOTH the current and target group and validates the
	// target exists; the store just sets group_id.
	SetMachineGroup(ctx context.Context, tenantID, machineID, groupID string) error
	// SetMachineGroupIfTree is SetMachineGroup conditional on the tenant's group tree still being at
	// expectTree (docs/62 R2): the caller authorized the move against a grant read at that version, and
	// who may move what depends on the tree. A change in between is ErrGroupTreeChanged (409, retry).
	SetMachineGroupIfTree(ctx context.Context, tenantID, machineID, groupID string, expectTree int64) error
	// SetMachineAlias sets (or clears, with an empty string) a machine's tenant-chosen friendly name BY
	// PRIMARY KEY, tenant-scoped. ErrMachineNotFound when the id is not in the tenant. The CALLER validates
	// and authorizes; the store just writes machine.alias.
	SetMachineAlias(ctx context.Context, tenantID, machineID, alias string) error
	// SetMachineNote sets (or clears, with an empty string) a machine's free-text operator note BY PRIMARY
	// KEY, tenant-scoped. ErrMachineNotFound when the id is not in the tenant. The CALLER validates and
	// authorizes; the store just writes machine.note.
	SetMachineNote(ctx context.Context, tenantID, machineID, note string) error
	// LookupDeviceIdentity resolves a device id to its tenant + pinned pubkey ACROSS TENANTS.
	// Pre-tenant, like RedeemToken: the signaling server that calls it has no tenant context, and
	// device ids are globally unique (migrations/0008) so the answer is unambiguous. Returns
	// ErrMachineNotFound when the device id is unknown OR has no pinned pubkey — a machine with no
	// key is unauthenticatable BY DESIGN (re-enrol it through POST /enroll/redeem) rather than
	// something to fall back to trusting.
	LookupDeviceIdentity(ctx context.Context, deviceID string) (*DeviceIdentity, error)
	// KeyTombstoned reports whether an agent public key (hex) was pinned on a machine that has since been
	// REMOVED, in ANY tenant (docs/65 D-C9). The public enrollment path asks before it pins a key, so a
	// removed device cannot silently come back; it must be re-installed through a fresh token and a NEW key.
	KeyTombstoned(ctx context.Context, pubkeyHex string) (bool, error)
	// TouchLastSeen records `at` as machine.last_seen for every device id in deviceIDs that belongs
	// to the tenant, returning how many rows it updated. Ids outside the tenant are silently
	// skipped — the presence feed is cross-tenant, so this method is handed ids the tenant may not
	// own, and it must neither write them nor report their existence (migrations/0017).
	//
	// Best-effort by contract: the caller treats a failure as "history not recorded", never as a
	// reason to fail the listing.
	TouchLastSeen(ctx context.Context, tenantID string, deviceIDs []string, at time.Time) (int, error)
	// StampPresence is TouchLastSeen for the background presence sweep (migrations/0079): the same
	// forward-only stamp, but across EVERY tenant, because the sweep has no tenant to pin. Only the
	// control plane's own sweeper calls it, with ids straight from the signaling feed; it returns a
	// count and nothing that says which tenant owns an id. Best-effort by contract, like TouchLastSeen.
	StampPresence(ctx context.Context, deviceIDs []string, at time.Time) (int, error)
	// RecordObservedOS refreshes machine.os for the tenant's own devices from the agent-asserted
	// values the presence feed carried (machine.os is otherwise write-once at enrollment), and
	// returns how many rows actually CHANGED. Only non-empty values within maxMachineNameLen are
	// applied, and only where they differ from the stored os — the steady state writes nothing.
	// Ids outside the tenant are silently skipped, same contract as TouchLastSeen; best-effort by
	// contract, same as TouchLastSeen.
	RecordObservedOS(ctx context.Context, tenantID string, osByDevice map[string]string) (int, error)

	// RecordAgentVersion refreshes machine.agent_version (and stamps agent_version_seen_at) for the
	// tenant's own devices from the agent-asserted presence feed. Exact twin of RecordObservedOS in
	// contract: ids outside the tenant are silently skipped (RLS does it for pg, the tenant key does
	// it for the fake), EMPTY values are skipped so a silent or older agent never blanks a version
	// already recorded, oversized values are skipped, and only ACTUAL CHANGES are counted and
	// written. Best-effort by contract — the caller logs and continues.
	//
	// The two implementations must agree on every one of those rules. A fake that accepts what the
	// database refuses is the divergence class this repo keeps paying for.
	RecordAgentVersion(ctx context.Context, tenantID string, versionByDevice map[string]string) (int, error)
	// RecordRequireSessionPolicy refreshes machine.require_session_policy for the tenant's own devices
	// from the agent-asserted values the presence feed carried, and returns how many rows actually
	// CHANGED. Exact twin of RecordObservedOS in contract — ids outside the tenant are silently skipped,
	// only differing values are written, best-effort by contract — and it exists for the same reason:
	// enrollment writes the column once, but an operator who sets the flag on an ALREADY-ENROLLED agent
	// never re-enrolls, and that population is precisely the one migration 0037 exists to unstrand.
	//
	// Unlike os there is no validity bound to apply: a bool has no malformed value. The flag is
	// agent-asserted and monotone-safe in the direction that matters — see Machine.RequireSessionPolicy.
	RecordRequireSessionPolicy(ctx context.Context, tenantID string, flagByDevice map[string]bool) (int, error)
	// RecordLoggedInUser refreshes machine.logged_in_user for the tenant's own devices from the
	// agent-asserted values the presence feed carried (migrations/0048), and returns how many rows
	// actually CHANGED. Exact twin of RecordObservedOS in contract: ids outside the tenant are
	// silently skipped (RLS for pg, the tenant key for the fake), EMPTY values are skipped so a
	// silent agent can never blank a name already recorded, oversized values are skipped, and only
	// ACTUAL CHANGES are counted and written. Best-effort by contract — the caller logs and continues.
	RecordLoggedInUser(ctx context.Context, tenantID string, userByDevice map[string]string) (int, error)
}

// -------------------------------------------------------------------------------------
// InMemoryMachineStore — concurrency-safe MachineStore fake for tests and the dev skeleton.
//
// It has two modes, chosen at construction:
//
//   - STRICT (NewInMemoryMachineStore): GetMachine for an unknown id returns ErrMachineNotFound.
//     This is the correct, production-like behaviour and what unit tests assert against.
//
//   - PERMISSIVE (NewPermissiveMachineStore): GetMachine for an unknown id returns a synthetic
//     Machine in DefaultGroupID instead of an error. This exists ONLY for DEV mode, where the
//     browser e2e (web/viewer/e2e/secure_grant.spec.ts) mints a grant for a fresh random device
//     id every run without pre-enrolling it. A strict "must be enrolled first" store would break
//     that flow, so dev is deliberately permissive; PRODUCTION always uses the strict
//     PgMachineStore, where an unknown machine is genuinely rejected.
// -------------------------------------------------------------------------------------

type InMemoryMachineStore struct {
	mu       sync.Mutex
	machines map[string]*Machine // key: tenantID + "\x00" + deviceID

	// permissive + defaultGroupID together implement the DEV-only unknown-machine fallback.
	permissive     bool
	defaultGroupID string

	// activeDirective is the fake's machine_directive_guard (docs/65 D-C4): nil = no directive store linked.
	// It is consulted BEFORE mu is taken (the directive store reads machines while holding ITS lock, so the
	// opposite nesting would deadlock); the pg trigger has no such window.
	activeDirective func(tenantID, machineID string) bool
	// coord serializes machine validation + directive reservation (the directive store) with guarded machine
	// mutations (status / group) so the guard is check-AND-act, not check-then-act. The twin of the pg row
	// lock the directive store takes on the machine. LOCK ORDER: coord, then the directive store's mu, then mu.
	coord sync.Mutex

	// tree lets SetMachineGroupIfTree know the group tree version (LinkGroupStores). nil = unconditional.
	// LOCK ORDER: the group store's lock is taken BEFORE mu, never inside it.
	tree groupTreeSource
}

func (s *InMemoryMachineStore) setTreeSource(src groupTreeSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tree = src
}

// NewInMemoryMachineStore constructs an empty STRICT store: unknown machines are rejected with
// ErrMachineNotFound. Use this in tests and anywhere production-like behaviour is wanted.
func NewInMemoryMachineStore() *InMemoryMachineStore {
	return &InMemoryMachineStore{machines: make(map[string]*Machine)}
}

// NewPermissiveMachineStore constructs a PERMISSIVE store for DEV mode: any unknown machine id
// resolves to a synthetic Machine in defaultGroupID (see the type doc for why this is dev-only).
func NewPermissiveMachineStore(defaultGroupID string) *InMemoryMachineStore {
	if defaultGroupID == "" {
		defaultGroupID = DevDefaultMachineGroupID
	}
	return &InMemoryMachineStore{
		machines:       make(map[string]*Machine),
		permissive:     true,
		defaultGroupID: defaultGroupID,
	}
}

var _ MachineStore = (*InMemoryMachineStore)(nil)

func machineKey(tenantID, deviceID string) string { return tenantID + "\x00" + deviceID }

// GetMachine implements MachineStore: resolve by DEVICE ID (the store is keyed by device id).
func (s *InMemoryMachineStore) GetMachine(_ context.Context, tenantID, deviceID string) (*Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.machines[machineKey(tenantID, deviceID)]; ok {
		cp := *m
		return &cp, nil
	}
	if s.permissive {
		// DEV-only: fabricate a machine in the default group so minting works for any (e.g.
		// e2e's random per-run) device id without a prior enroll. Prod's strict store never
		// takes this branch. The synthetic machine has no PK id (never persisted).
		return &Machine{DeviceID: deviceID, TenantID: tenantID, GroupID: s.defaultGroupID, Status: MachineStatusActive}, nil
	}
	return nil, ErrMachineNotFound
}

// GetMachineByID implements MachineStore: resolve by PRIMARY KEY. The map is keyed by device id,
// so this scans for a matching ID (fine for the in-memory fake / dev skeleton).
func (s *InMemoryMachineStore) GetMachineByID(_ context.Context, tenantID, id string) (*Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == id {
			cp := *m
			return &cp, nil
		}
	}
	if s.permissive {
		return &Machine{ID: id, TenantID: tenantID, GroupID: s.defaultGroupID, Status: MachineStatusActive}, nil
	}
	return nil, ErrMachineNotFound
}

// EnrollMachine implements MachineStore. The machine is stored under the given tenant, keyed by its
// DeviceID (the stable agent identity). A primary-key ID is assigned here when the caller did not
// supply one, mirroring the DB's gen_random_uuid() default; a supplied ID is kept.
//
// A device_id already present in ANY tenant is rejected, mirroring the DB's per-tenant
// UNIQUE (tenant_id, device_id) plus the GLOBAL unique index from migrations/0008: a device id
// belongs to exactly one tenant, so no tenant can mint a session ticket naming another tenant's
// agent.
func (s *InMemoryMachineStore) EnrollMachine(_ context.Context, tenantID string, m *Machine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.machines {
		if existing.DeviceID == m.DeviceID {
			return ErrMachineDeviceIDTaken
		}
	}
	cp := *m
	cp.TenantID = tenantID
	if cp.ID == "" {
		cp.ID = newUUID()
	}
	if cp.Status == "" {
		cp.Status = MachineStatusActive // mirror the DB DEFAULT 'active'
	}
	s.machines[machineKey(tenantID, cp.DeviceID)] = &cp
	// Reflect the assigned PK back to the caller (parity with the pg store's RETURNING id).
	m.ID = cp.ID
	return nil
}

// enrollEphemeral records an attended-session guest machine (docs/12): ephemeral, pubkey pinned,
// with an expiry. Used by InMemoryAttendedStore.Redeem — the pg path does the equivalent inside
// cp_attended_redeem. A duplicate device id (a fresh UUID, so only a collision) is rejected.
func (s *InMemoryMachineStore) enrollEphemeral(tenantID, deviceID, groupID, name, pubkeyHex string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.machines {
		if existing.DeviceID == deviceID {
			return ErrMachineDeviceIDTaken
		}
	}
	exp := expiresAt
	s.machines[machineKey(tenantID, deviceID)] = &Machine{
		ID:        newUUID(),
		TenantID:  tenantID,
		DeviceID:  deviceID,
		GroupID:   groupID,
		Name:      name,
		Pubkey:    pubkeyHex,
		Ephemeral: true,
		ExpiresAt: &exp,
		Status:    MachineStatusActive,
	}
	return nil
}

// deleteEphemeral removes an ephemeral machine at session end. No-op if absent or non-ephemeral.
func (s *InMemoryMachineStore) deleteEphemeral(tenantID, deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.machines[machineKey(tenantID, deviceID)]; ok && m.Ephemeral {
		delete(s.machines, machineKey(tenantID, deviceID))
	}
}

// LookupDeviceIdentity implements MachineStore: a cross-tenant scan for the device id, returning
// the pinned agent key.
//
// THE PERMISSIVE (DEV) STORE MUST NOT SYNTHESIZE HERE, and does not. GetMachine's dev fallback
// invents a group so an unenrolled device can be minted for locally; inventing an IDENTITY would
// be categorically different — it would hand the caller a valid tenant + pubkey for ANY device id,
// turning the dev control plane into an identity oracle and defeating the whole point of the
// signaling server's proof-of-possession check. Unknown stays unknown in both modes.
func (s *InMemoryMachineStore) LookupDeviceIdentity(_ context.Context, deviceID string) (*DeviceIdentity, error) {
	if deviceID == "" {
		return nil, ErrMachineNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.DeviceID != deviceID {
			continue
		}
		if m.Pubkey == "" {
			return nil, ErrMachineNotFound
		}
		// An expired ephemeral (attended) machine is unauthenticatable — mirrors the expiry
		// predicate in cp_machine_identity_by_device_id (migrations/0013) so signaling will not
		// authenticate a guest whose attended session has lapsed.
		if m.Ephemeral && m.ExpiresAt != nil && !time.Now().Before(*m.ExpiresAt) {
			return nil, ErrMachineNotFound
		}
		// docs/65 D-C9: a removed machine is a tombstone, never resolvable (mirrors the SQL predicate).
		if m.Status == MachineStatusRemoved {
			return nil, ErrMachineNotFound
		}
		status := m.Status
		if status == "" {
			status = MachineStatusActive
		}
		return &DeviceIdentity{DeviceID: m.DeviceID, TenantID: m.TenantID, Pubkey: m.Pubkey, Status: status}, nil
	}
	return nil, ErrMachineNotFound
}

// KeyTombstoned implements MachineStore (docs/65 D-C9): has this agent public key been pinned on a
// machine that was REMOVED, in any tenant?
func (s *InMemoryMachineStore) KeyTombstoned(_ context.Context, pubkeyHex string) (bool, error) {
	want := strings.ToLower(strings.TrimSpace(pubkeyHex))
	if want == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.Status == MachineStatusRemoved && strings.EqualFold(m.Pubkey, want) {
			return true, nil
		}
	}
	return false, nil
}

// tombstone marks a machine removed (docs/65 D-C9) - only the directive store's completed-uninstall path
// calls it; it bypasses SetMachineStatus (whose guard refuses status changes during a directive) the way the
// pg store's single transaction does, because the directive has just left its active state.
func (s *InMemoryMachineStore) tombstone(tenantID, machineID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == machineID {
			m.Status = MachineStatusRemoved
		}
	}
}

// directiveGuard is the fake's twin of the machine_directive_guard trigger (migrations/0068): set by
// LinkDirectiveStore, it reports whether a machine has an active directive.
func (s *InMemoryMachineStore) setDirectiveGuard(g func(tenantID, machineID string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeDirective = g
}

// TouchLastSeen implements MachineStore: stamp last_seen on the tenant's own machines only. The
// tenant check here is what RLS does for the pg store — a device id from another tenant matches no
// entry and is skipped without a trace.
//
// The stamp only ever moves FORWARD, matching the pg store's `AND (last_seen IS NULL OR
// last_seen < $2)`. Snapshots are cached, so a concurrent listing can carry an older one; letting it
// win would move "offline since" into the past. The two implementations must agree on this or the
// fake silently accepts a regression the database would reject — the divergence class that has
// already cost this repo two criticals.
func (s *InMemoryMachineStore) TouchLastSeen(_ context.Context, tenantID string, deviceIDs []string, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range deviceIDs {
		m, ok := s.machines[machineKey(tenantID, id)]
		if !ok {
			continue
		}
		if m.LastSeen != nil && !m.LastSeen.Before(at) {
			continue
		}
		stamp := at
		m.LastSeen = &stamp
		n++
	}
	return n, nil
}

// StampPresence implements MachineStore: TouchLastSeen across every tenant, clamped to now like
// cp_presence_stamp (a signaling clock running ahead must not pin last_seen in the future, where the
// forward-only rule would freeze it). Device ids are globally unique, so an id stamps at most one machine.
func (s *InMemoryMachineStore) StampPresence(_ context.Context, deviceIDs []string, at time.Time) (int, error) {
	if now := time.Now(); at.After(now) {
		at = now
	}
	want := make(map[string]bool, len(deviceIDs))
	for _, id := range deviceIDs {
		want[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.machines {
		if !want[m.DeviceID] || (m.LastSeen != nil && !m.LastSeen.Before(at)) {
			continue
		}
		stamp := at
		m.LastSeen = &stamp
		n++
	}
	return n, nil
}

// maxAgentVersionLen bounds the stored agent_version. It matches signaling's maxAgentVersionBytes
// (server/signaling/messages.go) on purpose and is enforced AGAIN here: the bound is duplicated at
// both layers because the store holds its own invariants and must not depend on a peer service
// having done its job. Deliberately far smaller than maxMachineNameLen — a build identity is
// "<semver>+<short sha>", so 64 bytes is already generous, and the tighter the bound the less an
// unauthenticated peer can push into a stored column.
const maxAgentVersionLen = 64

// maxLoggedInUserLen bounds the stored logged_in_user. Matches signaling's maxLoggedInUserBytes
// (server/signaling/messages.go) for the same reason as maxAgentVersionLen: a Windows DOMAIN\user
// pair fits comfortably in 64 bytes, and the bound is enforced at both layers independently.
const maxLoggedInUserLen = 64

// RecordAgentVersion implements MachineStore. Mirrors RecordObservedOS exactly — same tenant-key
// check, same empty/oversized skip, same only-when-different counting — because the fake and the pg
// store share ONE contract and a test against the fake says nothing about the store otherwise.
//
// The seen_at stamp moves ONLY when the value changes, matching the pg UPDATE's IS DISTINCT FROM
// guard. A fake that stamped on every report would count rows the database would not.
func (s *InMemoryMachineStore) RecordAgentVersion(_ context.Context, tenantID string, versionByDevice map[string]string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, v := range versionByDevice {
		if v == "" || len(v) > maxAgentVersionLen {
			continue
		}
		m, ok := s.machines[machineKey(tenantID, id)]
		if !ok {
			continue
		}
		if m.AgentVersion == v {
			continue
		}
		m.AgentVersion = v
		stamp := time.Now().UTC()
		m.AgentVersionSeenAt = &stamp
		n++
	}
	return n, nil
}

// RecordObservedOS implements MachineStore. The tenant key check is what RLS does for the pg
// store; the bound and the only-when-different rule mirror its SQL, because a fake that accepts
// what the database refuses is the divergence class this repo keeps paying for.
func (s *InMemoryMachineStore) RecordObservedOS(_ context.Context, tenantID string, osByDevice map[string]string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, os := range osByDevice {
		if os == "" || len(os) > maxMachineNameLen {
			continue
		}
		m, ok := s.machines[machineKey(tenantID, id)]
		if !ok || m.OS == os {
			continue
		}
		m.OS = os
		n++
	}
	return n, nil
}

// RecordRequireSessionPolicy implements MachineStore. Mirrors RecordObservedOS exactly, including
// the only-when-different rule: the fake and the pg store share ONE contract, and a fake that accepts
// what the database refuses (or counts rows the database would not) is the divergence class this repo
// keeps paying for.
func (s *InMemoryMachineStore) RecordRequireSessionPolicy(_ context.Context, tenantID string, flagByDevice map[string]bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, want := range flagByDevice {
		m, ok := s.machines[machineKey(tenantID, id)]
		if !ok || m.RequireSessionPolicy == want {
			continue
		}
		m.RequireSessionPolicy = want
		n++
	}
	return n, nil
}

// RecordLoggedInUser implements MachineStore. Mirrors RecordObservedOS exactly — same tenant-key
// guard, same skip-if-unchanged diffing, same empty-value skip, same bound enforcement.
func (s *InMemoryMachineStore) RecordLoggedInUser(_ context.Context, tenantID string, userByDevice map[string]string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, user := range userByDevice {
		if user == "" || len(user) > maxLoggedInUserLen {
			continue
		}
		m, ok := s.machines[machineKey(tenantID, id)]
		if !ok || m.LoggedInUser == user {
			continue
		}
		m.LoggedInUser = user
		n++
	}
	return n, nil
}

// ListMachines implements MachineStore.
func (s *InMemoryMachineStore) ListMachines(_ context.Context, tenantID string) ([]Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Machine
	for _, m := range s.machines {
		// Ephemeral (attended) guests are not part of the managed fleet — hide them from the listing.
		if m.TenantID == tenantID && !m.Ephemeral {
			if err := appendListRow(&out, *m); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// SetMachineStatus implements MachineStore: set the status BY PRIMARY KEY within the tenant. An invalid
// status is ErrInvalidMachineStatus; an unknown id is ErrMachineNotFound — the permissive (DEV) store
// does NOT synthesize here, because you can only set the status of a machine that actually exists.
func (s *InMemoryMachineStore) SetMachineStatus(_ context.Context, tenantID, machineID, status string) error {
	if !IsValidMachineStatus(status) {
		return ErrInvalidMachineStatus
	}
	s.coord.Lock()
	defer s.coord.Unlock()
	if err := s.directiveGuardFor(tenantID, machineID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == machineID {
			if m.Status == MachineStatusRemoved {
				return ErrMachineRemoved
			}
			m.Status = status
			return nil
		}
	}
	return ErrMachineNotFound
}

// directiveGuardFor mirrors the machine_directive_guard trigger for the fake: a removed machine never changes,
// and a machine with an active directive changes neither status nor group.
func (s *InMemoryMachineStore) directiveGuardFor(tenantID, machineID string) error {
	s.mu.Lock()
	g := s.activeDirective
	var removed bool
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == machineID {
			removed = m.Status == MachineStatusRemoved
		}
	}
	s.mu.Unlock()
	if removed {
		return ErrMachineRemoved
	}
	if g != nil && g(tenantID, machineID) {
		return ErrMachineHasActiveDirective
	}
	return nil
}

// SetMachineGroup implements MachineStore: reassign the machine (BY PK) to groupID. The fake does not have
// the machine_group FK, so it sets unconditionally (the handler validates the target exists); an unknown
// machine is ErrMachineNotFound.
func (s *InMemoryMachineStore) SetMachineGroup(_ context.Context, tenantID, machineID, groupID string) error {
	return s.setMachineGroup(tenantID, machineID, groupID)
}

// SetMachineGroupIfTree implements MachineStore: with a linked group store the tree lock is held across the
// check and the write (group before machine), exactly the pg shared-lock protocol.
func (s *InMemoryMachineStore) SetMachineGroupIfTree(_ context.Context, tenantID, machineID, groupID string, expectTree int64) error {
	s.mu.Lock()
	src := s.tree
	s.mu.Unlock()
	if src == nil {
		return s.setMachineGroup(tenantID, machineID, groupID)
	}
	return src.withTree(tenantID, func(_ GroupTree, version int64) error {
		if version != expectTree {
			return ErrGroupTreeChanged
		}
		return s.setMachineGroup(tenantID, machineID, groupID)
	})
}

func (s *InMemoryMachineStore) setMachineGroup(tenantID, machineID, groupID string) error {
	s.coord.Lock()
	defer s.coord.Unlock()
	if err := s.directiveGuardFor(tenantID, machineID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == machineID {
			m.GroupID = groupID
			return nil
		}
	}
	return ErrMachineNotFound
}

// SetMachineAlias implements MachineStore: set (or clear) the machine's friendly name BY PK within the
// tenant. An unknown id is ErrMachineNotFound — the permissive (DEV) store does NOT synthesize here,
// because you can only rename a machine that actually exists.
func (s *InMemoryMachineStore) SetMachineAlias(_ context.Context, tenantID, machineID, alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == machineID {
			m.Alias = alias
			return nil
		}
	}
	return ErrMachineNotFound
}

// SetMachineNote implements MachineStore: set (or clear) the machine's free-text note BY PK within the
// tenant. An unknown id is ErrMachineNotFound — the permissive (DEV) store does NOT synthesize here.
func (s *InMemoryMachineStore) SetMachineNote(_ context.Context, tenantID, machineID, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.machines {
		if m.TenantID == tenantID && m.ID == machineID {
			m.Note = note
			return nil
		}
	}
	return ErrMachineNotFound
}
