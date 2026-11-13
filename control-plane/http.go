package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -------------------------------------------------------------------------------------
// Seams. The DB driver (pgx) and the OIDC/Zitadel client are not vendored yet, so the two
// integrations the HTTP layer depends on are interfaces. Production wiring supplies real
// implementations; tests and the skeleton supply stubs.
// -------------------------------------------------------------------------------------

// TenantBinder pins the current tenant on the request's DB session. The real implementation
// (PgBinder, binder.go) acquires a pooled connection, runs
// `SELECT set_config('app.current_tenant', $1, false)` on it, and carries it on the context;
// that GUC is what the Row-Level Security policies in migrations/0001_core.sql read. This is
// THE RLS hook.
type TenantBinder interface {
	// BindTenant returns a context carrying a tenant-pinned DB handle plus the release
	// function the middleware defers when the request finishes (it unpins the tenant and
	// returns the connection), or an error if the tenant is unknown / the connection can't
	// be acquired. release may be nil when there is nothing to clean up.
	BindTenant(ctx context.Context, tenantID string) (ctxOut context.Context, release func(), err error)
}

// Principal is the authenticated caller resolved from the request: the user, their tenant,
// and their effective authorization grant (memberships → capabilities, group-scoped).
type Principal struct {
	UserID   string
	TenantID string
	Grant    *Grant
	// SessionID is the id of the server-side session this request authenticated with (empty for
	// StubAuthenticator / non-session callers). It exists so an endpoint can meter or attribute
	// per-SESSION rather than per-account: /me/password keys its throttle on this, so a stolen
	// session cannot burn the victim's account budget and lock them out of the one endpoint that
	// evicts it. Never a secret — it is the row id, not the bearer token.
	SessionID string
	// APIToken marks a principal that authenticated with an API token (apitoken_auth.go) rather than a
	// person's session. Routes that must never be reachable by a token — central recording playback and
	// download (docs/63 C8) — refuse it by THIS flag, not merely by the capability the token lacks, so a
	// future change to the grantable set cannot silently open them.
	APIToken bool
}

// Authenticator resolves a Principal from an inbound request. The skeleton ships a stub;
// see StubAuthenticator and the Zitadel/OIDC TODO below.
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// -------------------------------------------------------------------------------------
// Server + routing (Go 1.22 net/http ServeMux method+path patterns — no chi dependency).
// -------------------------------------------------------------------------------------

// Server holds the HTTP handlers and their dependencies.
type Server struct {
	Auth   Authenticator
	Binder TenantBinder

	// Ready is the OPTIONAL readiness probe for GET /readyz: it reports whether the server's backing
	// dependency (Postgres) is reachable. The binary wires it to pool.Ping; nil (DEV / no DB) makes
	// /readyz report ready unconditionally. Results are cached (http_health.go) so an unauthenticated
	// probe cannot be turned into a DB-load amplifier.
	Ready func(context.Context) error

	// Platform is the platform-operator surface (/platform/*, migration 0055). Nil = not mounted
	// (in-memory/dev mode): every platform route then answers as for a non-operator.
	Platform PlatformStore
	// Adoption is the tenant Owner's own adoption report (GET /adoption, platform_reach.go). Nil = the route answers 500.
	Adoption AdoptionStore
	// Toolbox is the Shared Toolbox store (migration 0056, http_toolbox.go). Nil = not mounted: every
	// toolbox route answers 501.
	Toolbox ToolboxStore
	// GuestEnds commits device-initiated ends with their audit events. Nil = not mounted;
	// the internal route also requires Machines and a configured service token.
	GuestEnds GuestEndStore
	// HelpRequests is the guest help-request ledger (docs/64, migration 0069). Nil = not mounted: no internal
	// help routes, no /help-requests routes, and /internal/capabilities does not advertise help_request_v1.
	HelpRequests HelpRequestStore

	// AuthAPI is the local login / logout / TOTP surface. Optional: when nil (e.g. the
	// pure-RBAC skeleton tests), no /auth/* routes are mounted. In production it is wired
	// alongside a SessionAuthenticator as Auth.
	AuthAPI *AuthService

	OIDC             *PgOIDCStore
	TenantHostSuffix string
	// Keep clients alive across requests so JWKS caching and refresh limits remain effective.
	newEntraClient func(EntraConfig) (*EntraClient, error)
	oidcClientsMu  sync.Mutex
	oidcClients    map[string]oidcCachedClient

	// Audit is the backstage audit-chain ingestion store (H2). Optional: when nil, the
	// POST /audit/ingest route is not mounted. Production wires PgAuditStore; tests wire
	// InMemoryAuditStore.
	Audit AuditStore
	// Production rejects browser-authored or unsigned agent audit records.
	RequireAgentAuditSignatures bool

	// Grants is the backstage grant issuer (H1b): the control plane's long-term Ed25519 key that
	// signs the short-TTL, capability-scoped grants the agent verifies. Optional: when nil, the
	// POST /grant/mint and GET /grant/pubkey routes are not mounted. Production wires a persisted
	// issuer; tests wire one from a fixed seed.
	Grants *GrantIssuer

	// Machines is the machine repository (D1). It is THE source of a machine's group, which the
	// grant/session/machine handlers scope authorization against — replacing the pre-D1 behaviour
	// of trusting a group id in the request body. Production wires the strict PgMachineStore; DEV
	// wires the permissive InMemoryMachineStore so minting works for any (unenrolled) device id.
	// When nil, the machine-backed handlers fail closed with a 500 rather than trusting the body.
	Machines MachineStore

	// MachineProperties is the per-machine custom-property store (machine_property, migrations/0024):
	// operator-set key/value fields on a machine (docs/01 §4). Group scoping for the property handlers
	// is resolved from Machines (never from the body or the property store); this only holds
	// (tenant_id, machine_id, key)->value rows. Production wires PgMachinePropertyStore; DEV/tests wire
	// the in-memory one. When nil, the property handlers fail closed with a 500.
	MachineProperties MachinePropertyStore

	// SessionRecords is the remote-support session repository (session_record). Production wires
	// PgSessionRecordStore; DEV/tests wire InMemorySessionRecordStore. When nil, the session
	// handlers fail closed with a 500.
	SessionRecords SessionRecordStore

	// SessionTransfers is the session transfer / escalation ledger (docs/51, migration 0060). Production
	// wires PgSessionTransferStore; DEV/tests the in-memory fake over the same session store. When nil the
	// transfer routes are not mounted, the end-report hook is a no-op and S1 renewals never answer
	// "session transferred".
	SessionTransfers SessionTransferStore

	// Directives is the fleet-directive ledger (docs/65, migration 0068): reinstall / remove an agent without a
	// session. Needs DirectiveIssuer (the DEDICATED directive signing key, D-C3) and Machines too; with any of
	// them nil the directive routes, the internal signaling routes and the directive_v1 capability are not
	// mounted.
	Directives DirectiveStore
	// DirectiveIssuer signs RMTDIRECTIVEv1 with the key derived from DIRECTIVE_SIGNING_SEED - never the grant
	// issuer. Its public key is returned in the enroll-redeem response so agents pin it (docs/65 D-C3).
	DirectiveIssuer *DirectiveIssuer
	// DirectiveNotifier tells signaling a directive is waiting (best effort; nil = signaling learns on the
	// agent's next registration).
	DirectiveNotifier DirectiveNotifier

	// testAfterStepUp (tests only) runs inside directiveStepUp right after the step-up snapshot was read, so a
	// test can reset the user's MFA exactly between that read and anything that follows it.
	testAfterStepUp func()

	// MgmtAudit is the management-plane audit trail (audit_event): who enrolled/started/minted
	// what in the console. Optional for RECORDING (when nil, handlers skip recording — the
	// pure-RBAC skeleton tests); required for GET /audit, which fails closed when unwired.
	// Recording failures fail the request: an unauditable mutation must not happen silently.
	MgmtAudit MgmtAuditStore

	// Presence is the machine-presence feed (presence.go): the signaling registry, read over
	// GET /internal/presence, that tells GET /machines which agents are actually connected.
	// Optional — when nil (or when the feed is unreachable) the listing reports
	// "presence_known": false and every machine's `online` is omitted, rather than defaulting to
	// offline. Nothing is authorized on presence, so it fails SOFT by design.
	Presence PresenceSource

	// Tenants is the tenant repository: RLS-scoped listing plus privileged provisioning via
	// cp_create_tenant (migrations/0006). When nil, the tenant handlers fail closed with a 500.
	Tenants TenantStore

	// EnrollmentTokens is the enrollment-token repository (M1): mint/list/revoke behind
	// CapManageEnrollment, plus the PUBLIC redeem path (the token is the authorization). The
	// token routes — including POST /enroll/redeem — are only mounted when this is wired.
	EnrollmentTokens EnrollmentTokenStore
	// Nil until an operator supplies a validated, tested native installer release.
	ManagedInstaller *ManagedInstaller

	// APITokens is the API-token repository (docs/01 §8): tenant-admin-minted, capability-scoped
	// bearer credentials for programmatic access. Mint/list/revoke are behind CapManageTenant; the
	// RESOLVE path is the auth front (APITokenAuthenticator), not an HTTP route. Only mounted when
	// this is wired.
	APITokens APITokenStore

	// Attended is the on-demand (attended) session repository (docs/12): the technician mints a
	// one-time code, the guest redeems it for an EPHEMERAL identity, consents, and the SAME
	// signaling/ticket/WebRTC path carries the session. When nil, no /attended-sessions routes are
	// mounted. The consent gate (POST …/connect only mints a ticket after consent) lives in the
	// handler; the guest-facing redeem/consent/status routes go on the root mux (pre-tenant, the
	// code/attend-token is the authorization). Ticket minting reuses Grants.
	Attended AttendedStore

	// SignalingURL is the WS rendezvous endpoint POST /sessions hands back alongside the signed
	// session ticket (env CP_SIGNALING_URL). Empty → DefaultSignalingURL (local dev).
	SignalingURL string

	// DeviceIdentityToken is the shared secret the SIGNALING server presents as
	// `Authorization: Bearer …` on GET /internal/devices/{device_id}/identity, the lookup that lets
	// it verify an agent's proof of possession at register_agent
	// (docs/11-agent-identity-contract.md §4). Production reads it from CP_DEVICE_IDENTITY_TOKEN.
	//
	// The route EXISTS ONLY when this is set to at least DeviceIdentityTokenMinLen characters (and
	// Machines is wired). There is no unauthenticated mode: the endpoint is cross-tenant by
	// construction, so an unauthenticated one would be a fleet-enumeration oracle.
	DeviceIdentityToken string

	// TicketRedemptions is the SHARED single-use ledger for session tickets (ticketredemption.go):
	// the signaling server records each verified ticket's one rendezvous here, so a captured ticket
	// cannot be replayed at a second replica or after a restart — which a per-process map cannot
	// prevent. Production wires PgTicketRedemptionStore (migrations/0023); DEV wires the in-memory
	// one. When nil, POST /internal/session-tickets/redeem is not mounted and signaling falls back
	// to its local map alone (see server/signaling/ticketredeem.go for why that degradation is
	// deliberate rather than fatal).
	TicketRedemptions TicketRedemptionStore

	// IPAllowlist optionally restricts the authenticated console/host API (`protectedChain`) to a set
	// of source networks (docs/01 §14). Nil = open (the default); when set, a request from any other
	// source is refused with 403 at the edge, before auth. Built from CP_ADMIN_IP_ALLOWLIST. The
	// agent-enroll and guest-attend routes are NOT gated — they sit outside protectedChain.
	IPAllowlist *IPAllowlist

	// TenantIPAllowlist optionally restricts the authenticated console/host API to a set of source
	// networks PER TENANT (docs/01 §10 — each MSP fencing its own admins/technicians). Nil = the
	// feature is unwired; an empty list for a tenant = open (no restriction). Unlike IPAllowlist it is
	// enforced AFTER auth (Server.tenantIPAllowMiddleware), because the tenant is unknown at the edge.
	TenantIPAllowlist TenantIPAllowlistStore
	// TenantBranding is the per-tenant white-label store (docs/01 §9): a product name + accent colour
	// the console reads to theme itself. GET is any-authenticated-member; PUT is CapManageTenant. Nil =
	// the /tenant/branding routes are not mounted.
	TenantBranding TenantBrandingStore
	// The security-policy routes (GET/PUT /tenant/security-policy) are mounted when s.Tenants is
	// non-nil and AuthAPI is wired — the GET needs no capability, the PUT is CapManageTenant and
	// uses AuthAPI.Users.FindUserByID for the anti-lockout guard.
	// SessionPolicies is the per-tenant concurrency-limit store (docs/01 §5 seat metering): the max
	// number of OPEN sessions a tenant may hold. handleStartSession reads it and enforces atomically.
	// GET is any-authenticated-member; PUT is CapManageTenant. Nil = no limit is ever applied and the
	// /tenant/session-policy routes are not mounted.
	SessionPolicies TenantSessionPolicyStore
	// GroupSessionPolicies is the per-machine-group concurrency-limit store (docs/01 §5, loop 78): the max
	// number of OPEN sessions a single machine group may hold, enforced by handleStartSession alongside the
	// tenant-wide cap. GET/PUT live under /machine-groups/{id}/session-policy (CapManageGroups). Nil = no
	// per-group limit is ever applied and those routes are not mounted.
	GroupSessionPolicies GroupSessionPolicyStore
	// trustProxyIP mirrors the deployment-wide CP_TRUST_PROXY_IP: when true, a client's source IP is
	// taken from the rightmost X-Forwarded-For hop instead of RemoteAddr, for the per-tenant allow-list
	// too. Set ONLY when exactly one trusted reverse proxy fronts the control plane.
	//
	// UNEXPORTED ON PURPOSE — set it with [Server.SetTrustProxy], which is the only way to reach it
	// from outside the package. See that method for why a plain assignable field was a hazard.
	trustProxyIP bool
	// trustedProxyNets is the F14-secure companion: when non-empty, XFF is only honoured from TCP
	// peers whose address falls in one of these networks. Set with [Server.SetTrustedProxies].
	trustedProxyNets []*net.IPNet

	// DynamicGroups stores saved machine-property predicates (docs/01 §4). A dynamic group's MEMBERS are
	// resolved on demand by the handler (reusing the GET /machines narrow-only intersect), so this store
	// holds only the predicate. Nil = the feature is unwired (handlers fail closed 500).
	DynamicGroups DynamicGroupStore

	// MachineGroups backs the STATIC machine_group rows (the RBAC scope unit + machine.group_id
	// container) — create + list (machinegroup.go). Nil = the routes fail closed 500. Distinct from
	// DynamicGroups (saved predicates).
	MachineGroups MachineGroupStore

	// Webhooks is the per-tenant webhook endpoint store (migration 0047, docs/01 §8). Nil = the
	// /tenant/webhooks routes are not mounted. GET/POST/DELETE require CapManageTenant.
	Webhooks WebhookStore
	// Dispatcher fires audit events to registered webhook endpoints asynchronously. Nil = no
	// webhook deliveries (even if Webhooks is set). Both must be wired for delivery to happen;
	// a tenant can register webhooks without a dispatcher but they will never be called.
	Dispatcher *WebhookDispatcher

	// Throttle meters the UNAUTHENTICATED POST /enroll/redeem (throttle.go) so enrollment-token
	// guessing runs into exponential backoff. Defaults to DefaultThrottleConfig on first use —
	// metering is ON unless DisableThrottle says otherwise.
	Throttle *Throttle
	// DisableThrottle turns metering off. Only for tests that deliberately hammer an endpoint.
	DisableThrottle bool
	throttleOnce    sync.Once
	// FinalAckBurst / FinalAckPerSec bound ALL final-ack requests per client IP, successes included (the
	// failure throttle alone never limits a source that keeps sending validly framed requests). Zero = the
	// defaults: 30 requests, refilling 30 per 10 minutes. Set before the first request.
	FinalAckBurst   int
	FinalAckPerSec  float64
	finalAckOnce    sync.Once
	finalAckLimiter *rateLimiter

	// PublishedAgentVersion is the operator-designated expected agent build, e.g. "0.0.1+abc123".
	// When non-empty, GET /agent-version returns it so the console MachinesPanel can flag machines
	// that are running a different (older) build. Empty = version tracking not enabled. Set from
	// the AGENT_PUBLISHED_VERSION environment variable in production.
	PublishedAgentVersion string

	// Recording is central session-recording storage (docs/63, migration 0066): the agent upload routes,
	// the volume, the master keys and the retention sweeper. Zero value = not mounted.
	Recording RecordingWiring

	// auditStreams caps concurrent audit exports/archives per tenant (http_recording_stream_limit.go).
	auditStreams recStreamLimiter

	// HostPolicy classifies the authority a request arrived on (docs/66 stage 1a, hostpolicy.go) and installs
	// the public-ingress authority gate. Nil = the pre-theming behaviour: every host redeems unscoped.
	HostPolicy *HostPolicy
	// Hostnames is the operator hostname-assignment store behind the /platform hostname routes. Nil = those
	// routes answer as for a non-operator.
	Hostnames HostnameStore
	// RedeemTuning overrides redemption admission and the rejection floor (redeem_admission.go).
	RedeemTuning    RedeemTuning
	redeemAdmitOnce sync.Once
	redeemAdmit     *admissionPool
	// PublicExchangeLimit overrides the 2 s bound on public (edge-marked) exchanges (publicbounds.go). 0 = 2 s.
	PublicExchangeLimit time.Duration

	// BrandingRevisions is the branding revision / approval / publication store (docs/66 stage 1b,
	// brandrev.go). Nil = the Owner revision routes are not mounted, the operator routes answer as for a
	// non-operator and the public branding routes answer the neutral object.
	BrandingRevisions BrandingRevisionStore
	// LogoConverter runs the logo-convert child (logoconv_child.go). Nil = logo upload answers 501.
	LogoConverter *LogoConverter
	// BrandingTuning overrides the public branding schedule and admission (publicbranding.go).
	BrandingTuning  BrandingTuning
	brandAdmitOnce  sync.Once
	brandAdmit      *admissionPool
	brandRate       *rateBudget
	brandCutoffJSON atomic.Int64
	brandCutoffLogo atomic.Int64
	// brandRenderHook is a TEST seam: called on the lookup goroutine after the read, before the render.
	brandRenderHook func(ctx context.Context, logo bool)
	logoRateOnce    sync.Once
	logoRate        *rateBudget
}

// DeviceIdentityTokenMinLen is the shortest service token the device-identity route will mount
// behind. It is a machine-to-machine shared secret with no rate-limit-defeating second factor, so
// anything shorter is a configuration mistake, not a policy choice.
const DeviceIdentityTokenMinLen = 32

// throttle returns the configured limiter, lazily installing the default profile. Returns nil
// (which every Throttle method tolerates) when metering is explicitly disabled.
func (s *Server) throttle() *Throttle {
	if s.DisableThrottle {
		return nil
	}
	s.throttleOnce.Do(func() {
		if s.Throttle == nil {
			s.Throttle = NewThrottle(DefaultThrottleConfig)
		}
	})
	return s.Throttle
}

// NewServer constructs a Server.
func NewServer(auth Authenticator, binder TenantBinder) *Server {
	return &Server{Auth: auth, Binder: binder}
}

// Handler returns the fully-wired http.Handler. Protected API routes sit behind the
// auth → tenant (RLS) middleware chain; the login endpoint is public (you cannot require a
// session in order to create one). TOTP enrollment is protected — you enroll while logged in.
func (s *Server) Handler() http.Handler {
	protected := http.NewServeMux()
	if s.OIDC != nil && s.TenantHostSuffix != "" {
		s.mountOIDCProtected(protected)
	}

	// Tenants (SaaS provisioning surface; self-hosted has exactly one).
	protected.HandleFunc("GET /tenants", s.handleListTenants)
	protected.HandleFunc("POST /tenants", s.handleCreateTenant)
	protected.HandleFunc("GET /platform/me", s.handlePlatformMe)
	protected.HandleFunc("GET /toolbox", s.handleListToolbox)
	protected.HandleFunc("POST /toolbox", s.handleCreateToolboxItem)
	protected.HandleFunc("PUT /toolbox/{id}", s.handleUpdateToolboxItem)
	protected.HandleFunc("DELETE /toolbox/{id}", s.handleDeleteToolboxItem)
	protected.HandleFunc("POST /toolbox/{id}/runs", s.handleRunToolboxItem)
	protected.HandleFunc("GET /platform/tenants", s.handlePlatformListTenants)
	// docs/68: the operator's download reach report (gated like /platform/tenants, audited) and the tenant Owner's own adoption counts.
	protected.HandleFunc("GET /platform/reach", s.handlePlatformReach)
	protected.HandleFunc("GET /adoption", s.handleAdoption)
	protected.HandleFunc("POST /platform/tenants", s.handlePlatformCreateTenant)
	protected.HandleFunc("POST /platform/tenants/{id}/suspend", s.handlePlatformSetSuspended(true))
	protected.HandleFunc("POST /platform/tenants/{id}/resume", s.handlePlatformSetSuspended(false))
	// Tenant hostnames (docs/66 stage 1a, http_hostname.go): operator-only, audited on both chains.
	protected.HandleFunc("GET /platform/hostnames", s.handlePlatformHostnames)
	protected.HandleFunc("GET /platform/tenants/{id}/hostnames", s.handlePlatformHostnames)
	protected.HandleFunc("POST /platform/tenants/{id}/hostnames", s.handlePlatformHostnameAssign)
	protected.HandleFunc("POST /platform/hostnames/{id}/activate", s.handlePlatformHostnameActivate)
	protected.HandleFunc("POST /platform/hostnames/{id}/release", s.handlePlatformHostnameRelease)
	protected.HandleFunc("POST /platform/hostnames/{id}/reactivate", s.handlePlatformHostnameReactivate)
	// Branding review, approval and withdrawal (docs/66 stage 1b, http_brandrev.go): operator-only, audited on
	// both chains, the approval a compare-and-swap.
	protected.HandleFunc("GET /platform/tenants/{id}/branding/review", s.handlePlatformBrandingReview)
	protected.HandleFunc("POST /platform/tenants/{id}/branding/approve", s.handlePlatformBrandingApprove)
	protected.HandleFunc("POST /platform/tenants/{id}/branding/withdraw", s.handlePlatformBrandingWithdraw)

	// Per-tenant IP allow-list (docs/01 §10): list / add / remove the source CIDRs this tenant permits
	// on the authenticated API, gated on CapManageTenant. The handlers fail closed (500) when the store
	// is unwired, like the other management surfaces. DELETE takes the CIDR as a ?cidr= query param
	// (not a path segment) because a CIDR contains a '/'.
	protected.HandleFunc("GET /tenant/ip-allowlist", s.handleGetTenantIPAllowlist)
	protected.HandleFunc("POST /tenant/ip-allowlist", s.handleAddTenantIPAllowlistEntry)
	protected.HandleFunc("DELETE /tenant/ip-allowlist", s.handleDeleteTenantIPAllowlistEntry)

	// Per-tenant branding / white-label (docs/01 §9): GET reads it to theme the console (any
	// authenticated member), PUT sets it behind CapManageTenant. Only mounted when a store is wired.
	// Public branding revisions (docs/66 stage 1b): the Owner creates immutable revisions (CapManageTenant); any
	// authenticated member reads the state. Publication is the operator's (above).
	if s.BrandingRevisions != nil {
		protected.HandleFunc("GET /tenant/branding/revisions", s.handleGetBrandingRevisions)
		protected.HandleFunc("POST /tenant/branding/revisions", s.handleCreateBrandingRevision)
	}
	if s.TenantBranding != nil {
		protected.HandleFunc("GET /tenant/branding", s.handleGetTenantBranding)
		protected.HandleFunc("PUT /tenant/branding", s.handleSetTenantBranding)
	}
	if s.Tenants != nil {
		protected.HandleFunc("GET /tenant/security-policy", s.handleGetTenantSecurityPolicy)
		protected.HandleFunc("PUT /tenant/security-policy", s.handleSetTenantSecurityPolicy)
	}

	// Per-tenant session policy (docs/01 §5 seat metering): GET reads the concurrency limit (any
	// authenticated member), PUT sets it behind CapManageTenant. Only mounted when a store is wired.
	if s.SessionPolicies != nil {
		protected.HandleFunc("GET /tenant/session-policy", s.handleGetSessionPolicy)
		protected.HandleFunc("PUT /tenant/session-policy", s.handleSetSessionPolicy)
	}

	// Webhooks (docs/01 §8): event-driven automation endpoints, all behind CapManageTenant.
	// Only mounted when a store is wired. Dispatcher is separate from the store (dispatch is
	// not gated on the store being nil — both must be wired for delivery to happen).
	if s.Webhooks != nil {
		protected.HandleFunc("GET /tenant/webhooks", s.handleListWebhooks)
		protected.HandleFunc("POST /tenant/webhooks", s.handleCreateWebhook)
		protected.HandleFunc("DELETE /tenant/webhooks/{id}", s.handleDeleteWebhook)
		protected.HandleFunc("GET /tenant/webhooks/{id}/deliveries", s.handleListWebhookDeliveries)
	}

	// Dynamic machine groups (docs/01 §4): saved property predicates. Manage on CapManageGroups, list/
	// resolve on CapViewMachines. `/{id}/machines` resolves members live (the narrow-only intersect).
	protected.HandleFunc("GET /dynamic-groups", s.handleListDynamicGroups)
	protected.HandleFunc("POST /dynamic-groups", s.handleCreateDynamicGroup)
	protected.HandleFunc("DELETE /dynamic-groups/{id}", s.handleDeleteDynamicGroup)
	protected.HandleFunc("GET /dynamic-groups/{id}/machines", s.handleResolveDynamicGroup)

	// Static machine groups (docs/01 §4, machinegroup.go): the RBAC scope unit machines belong to.
	// List on CapViewMachines (org structure), create on CapManageGroups.
	protected.HandleFunc("GET /machine-groups", s.handleListMachineGroups)
	protected.HandleFunc("POST /machine-groups", s.handleCreateMachineGroup)
	protected.HandleFunc("PATCH /machine-groups/{id}", s.handleRenameMachineGroup)
	protected.HandleFunc("POST /machine-groups/{id}/move", s.handleMoveMachineGroup)
	protected.HandleFunc("DELETE /machine-groups/{id}", s.handleDeleteMachineGroup)
	// Per-machine-group concurrency cap (docs/01 §5, loop 78). Both GET and PUT need CapManageGroups
	// (group-scoped): a cap is admin knowledge, not org-chart display. Only mounted when a store is wired.
	if s.GroupSessionPolicies != nil {
		protected.HandleFunc("GET /machine-groups/session-policies", s.handleListGroupSessionPolicies)
		protected.HandleFunc("GET /machine-groups/{id}/session-policy", s.handleGetGroupSessionPolicy)
		protected.HandleFunc("PUT /machine-groups/{id}/session-policy", s.handleSetGroupSessionPolicy)
	}

	// Published agent version: the operator-configured expected build (docs/01 §6).
	// Any authenticated member with CapViewMachines can read it; the console uses it to
	// flag machines running a different (older) build in the fleet table.
	protected.HandleFunc("GET /agent-version", s.handleGetAgentVersion)

	// Machines (the enrolled agent fleet).
	protected.HandleFunc("GET /machines", s.handleListMachines)
	protected.HandleFunc("GET /machines/{id}", s.handleGetMachine)
	// Machine lifecycle status (docs/01 §4): quarantine / retire / reactivate a machine, gated on
	// CapManageMachines for the machine's REAL group. A quarantined/retired machine is refused a new
	// session by handleStartSession.
	protected.HandleFunc("POST /machines/{id}/status", s.handleSetMachineStatus)
	protected.HandleFunc("POST /machines/bulk-status", s.handleBulkSetMachineStatus)
	protected.HandleFunc("POST /machines/{id}/group", s.handleSetMachineGroup)
	protected.HandleFunc("POST /machines/bulk-group", s.handleBulkSetMachineGroup)
	protected.HandleFunc("PATCH /machines/{id}/alias", s.handleSetMachineAlias)
	protected.HandleFunc("PATCH /machines/{id}/note", s.handleSetMachineNote)

	// Fleet directives (docs/65): per-machine reinstall / remove. No bulk route, by design.
	if s.directiveInternalMounted() {
		protected.HandleFunc("POST /machines/{id}/directives", s.handleRequestDirective)
		protected.HandleFunc("GET /machines/{id}/directives", s.handleListMachineDirectives)
		// An Owner's "forget this machine" (docs/65 sec. 8): the removal's own authority, one machine at a time.
		protected.HandleFunc("POST /machines/{id}/forget", s.handleForgetMachine)
		protected.HandleFunc("GET /directives", s.handleListActiveDirectives)
		protected.HandleFunc("GET /directives/{id}", s.handleGetDirective)
		protected.HandleFunc("POST /directives/{id}/approve", s.handleApproveDirective)
		protected.HandleFunc("POST /directives/{id}/cancel", s.handleCancelDirective)
		protected.HandleFunc("GET /tenant/directive-policy", s.handleGetDirectivePolicy)
		protected.HandleFunc("PUT /tenant/directive-policy", s.handleSetDirectivePolicy)
	}

	// Machine custom properties (docs/01 §4): list / upsert / delete a key/value field on a machine.
	// All three sit on the `protected` mux (csrf → auth → tenant) and gate on the machine's REAL
	// group, resolved from the store — read on CapViewMachines, write on CapManageMachines. The key
	// is a single path segment on PUT and DELETE (symmetric), so a slash-bearing key is unreachable
	// on both — property keys are identifiers, not free-form paths.
	protected.HandleFunc("GET /machines/{id}/properties", s.handleListMachineProperties)
	protected.HandleFunc("PUT /machines/{id}/properties/{key}", s.handleSetMachineProperty)
	protected.HandleFunc("DELETE /machines/{id}/properties/{key}", s.handleDeleteMachineProperty)

	// Enrollment — an installer redeems a token to join the fleet.
	protected.HandleFunc("POST /enroll", s.handleEnroll)

	// Enrollment-token management (M1): mint/list/revoke, gated on CapManageEnrollment. The
	// REDEMPTION route is public and mounted on the root mux below.
	if s.EnrollmentTokens != nil {
		protected.HandleFunc("GET /managed-installer", s.handleManagedInstallStatus)
		protected.HandleFunc("POST /managed-installer", s.handleManagedInstallBundle)
		protected.HandleFunc("POST /enrollment-tokens", s.handleMintEnrollmentToken)
		protected.HandleFunc("GET /enrollment-tokens", s.handleListEnrollmentTokens)
		protected.HandleFunc("POST /enrollment-tokens/{id}/revoke", s.handleRevokeEnrollmentToken)
	}

	// API tokens (docs/01 §8): mint/list/revoke, gated on CapManageTenant (Owner-only). The
	// RESOLVE path is not a route — it is the APITokenAuthenticator wired ahead of the session
	// authenticator (main.go). Only mounted when a store is wired.
	if s.APITokens != nil {
		protected.HandleFunc("POST /api-tokens", s.handleMintAPIToken)
		protected.HandleFunc("GET /api-tokens", s.handleListAPITokens)
		protected.HandleFunc("DELETE /api-tokens/{id}", s.handleRevokeAPIToken)
	}

	// Sessions.
	protected.HandleFunc("GET /sessions", s.handleListSessions)
	protected.HandleFunc("POST /sessions", s.handleStartSession)
	if s.HelpRequests != nil {
		protected.HandleFunc("GET /help-requests", s.handleListHelpRequests)
		protected.HandleFunc("POST /help-requests/{id}/accept", s.handleAcceptHelpRequest)
	}
	protected.HandleFunc("POST /sessions/{id}/end", s.handleEndSession)
	protected.HandleFunc("PATCH /sessions/{id}/note", s.handleSetSessionNote)
	// Centrally audit an ad-hoc command before the viewer sends it to the agent (http_command_run.go):
	// the toolbox-run grant's sibling for a command the operator types rather than a saved item.
	protected.HandleFunc("POST /sessions/{id}/command-run", s.handleRunCommand)
	if s.SessionTransfers != nil {
		// Session transfer / escalation (docs/51). Mounted with the session routes; each handler
		// re-derives the caller's authority (holder, addressee, acceptor) itself.
		protected.HandleFunc("POST /sessions/{id}/transfer", s.handleOfferTransfer)
		protected.HandleFunc("GET /sessions/{id}/transfer-candidates", s.handleTransferCandidates)
		protected.HandleFunc("DELETE /session-transfers/{id}", s.handleCancelTransfer)
		protected.HandleFunc("GET /session-transfers/incoming", s.handleIncomingTransfers)
		protected.HandleFunc("GET /session-transfers/outgoing", s.handleOutgoingTransfers)
		protected.HandleFunc("GET /session-transfers/{id}", s.handleGetTransfer)
		protected.HandleFunc("POST /session-transfers/{id}/accept", s.handleAcceptTransfer)
		protected.HandleFunc("POST /session-transfers/{id}/ticket", s.handleTransferTicket)
	}
	protected.HandleFunc("GET /reports/sessions-by-machine", s.handleReportSessionsByMachine)
	protected.HandleFunc("GET /reports/sessions-by-technician", s.handleReportSessionsByTechnician)

	// Attended (on-demand) sessions — technician-facing management (docs/12). The guest-facing
	// redeem/consent/status routes are PUBLIC and mounted on the root mux below.
	if s.Attended != nil {
		protected.HandleFunc("POST /attended-sessions", s.handleCreateAttended)
		protected.HandleFunc("GET /attended-sessions", s.handleListAttended)
		protected.HandleFunc("GET /attended-sessions/{id}", s.handleGetAttended)
		protected.HandleFunc("POST /attended-sessions/{id}/connect", s.handleConnectAttended)
		protected.HandleFunc("POST /attended-sessions/{id}/promote", s.handlePromoteAttended)
		protected.HandleFunc("POST /attended-sessions/{id}/end", s.handleEndAttended)
	}

	// Audit trail. /export streams the hash-chained trail as NDJSON for SIEM collectors;
	// /verify re-walks the tenant's chain server-side (http_mgmtaudit.go).
	protected.HandleFunc("GET /audit", s.handleListAudit)
	protected.HandleFunc("GET /audit/summary", s.handleAuditSummary)
	protected.HandleFunc("GET /audit/export", s.handleExportAudit)
	protected.HandleFunc("GET /audit/verify", s.handleVerifyAudit)
	// Packaged compliance archive: one ZIP of both trails + a manifest (http_audit_archive.go).
	// Same CapViewAudit gate; the backstage half is group-scoped like /audit/backstage/export.
	protected.HandleFunc("GET /audit/archive", s.handleAuditArchive)

	// Backstage audit-chain ingestion (H2) + export. The authenticated controller forwards the
	// agent's hash-chained backstage audit for central, tamper-evident storage; /backstage/export
	// re-emits it as NDJSON for a SIEM collector (http_backstage_audit.go), which is what makes the
	// trail readable outside a psql prompt. Both behind the same auth → tenant (RLS) chain as
	// everything else, but on DIFFERENT capabilities: writing the trail is backstage work
	// (CapBackstageShell), reading it is an auditor's (CapViewAudit). Only mounted when an
	// AuditStore is wired.
	if s.Audit != nil {
		protected.HandleFunc("POST /audit/ingest", s.handleIngestAudit)
		protected.HandleFunc("GET /audit/backstage/export", s.handleExportBackstageAudit)
	}

	// Backstage grant minting (H1b): the authenticated technician requests a signed grant for a
	// target machine, which the browser forwards to the agent via Control::InstallGrant. The
	// issuer public key is exposed so it can be provisioned into agent config.json. Behind the same
	// auth → tenant (RLS) chain; only mounted when an issuer is wired.
	if s.Grants != nil {
		protected.HandleFunc("POST /grant/mint", s.handleMintGrant)
		protected.HandleFunc("GET /grant/pubkey", s.handleGrantPubkey)
		// Elevation grants (loop 87, docs/01 §3). Same issuer, same auth chain, its own domain tag
		// and its own capability — and mounted here rather than beside the other /sessions routes
		// because, like grant minting, it is meaningless without a wired issuer.
		protected.HandleFunc("POST /sessions/{id}/elevation", s.handleMintElevation)
		// Session-lease renewal (docs/25 F03). Mounted here for the same reason: without an issuer
		// there is nothing to sign a lease with — and an issuer-less deployment also runs signaling
		// without ticket verification, so its agents derive "not leased" and never ask for one.
		protected.HandleFunc("POST /sessions/{id}/policy", s.handleRenewSessionPolicy)
	}

	// Protected TOTP enrollment (completed while authenticated).
	if s.AuthAPI != nil {
		protected.HandleFunc("POST /auth/totp/enroll", s.AuthAPI.HandleEnrollTOTP)
		protected.HandleFunc("POST /auth/totp/confirm", s.AuthAPI.HandleConfirmTOTP)
		protected.HandleFunc("POST /auth/step-up", s.AuthAPI.HandleStepUp)
		// Self-service password change. Deliberately on the protected mux (so it inherits
		// CSRF → auth → tenant) and deliberately addressed as /me — the account changed is the
		// PRINCIPAL'S, never an id in the request, so no capability check can be forgotten and
		// no caller can aim it at somebody else.
		protected.HandleFunc("POST /me/password", s.AuthAPI.HandleChangePassword)
		// Self-service email change. Same /me rationale as /me/password: always the principal's
		// own account, no user id in the URL. Requires current-password step-up and rotates all
		// sessions (email is the login identifier, so a change invalidates existing credential proofs).
		protected.HandleFunc("POST /me/email", s.AuthAPI.HandleChangeEmail)
		// Who is signed in, for the console's "Signed in as" line. Always the principal's own account.
		protected.HandleFunc("GET /me", s.AuthAPI.HandleMe)

		// User management (docs/01 §5, auth_user_admin.go): list the tenant's users, INVITE (create) a
		// user, enable/disable their access, and assign their role. List/create/enable/disable gate on
		// CapManageUsers; create + role assignment additionally apply the no-escalation guard
		// (canAdministerUser on the NEW role, so nobody mints a user/role above themselves), and create
		// 409s a duplicate email. Disable applies the canAdministerUser hierarchy guard, refuses
		// self-disable, and revokes the target's live sessions. Role assignment gates on CapManageRoles
		// (a two-way no-escalation check on the target AND the new role) and refuses self-role-change.
		protected.HandleFunc("GET /users", s.AuthAPI.HandleListUsers)
		protected.HandleFunc("GET /roles", s.AuthAPI.HandleListRoles)
		protected.HandleFunc("POST /users", s.AuthAPI.HandleCreateUser)
		protected.HandleFunc("POST /users/{id}/disable", s.AuthAPI.HandleDisableUser)
		protected.HandleFunc("POST /users/{id}/enable", s.AuthAPI.HandleEnableUser)
		protected.HandleFunc("POST /users/{id}/role", s.AuthAPI.HandleSetUserRole)
		protected.HandleFunc("POST /users/{id}/sign-out", s.AuthAPI.HandleSignOutUser)
		protected.HandleFunc("DELETE /users/{id}/lockout", s.AuthAPI.HandleClearUserLockout)

		// Administrative credential provisioning / reset (auth_password_reset.go). These DO name
		// another account, so unlike /me/password they carry a capability check (CapManageUsers)
		// plus a privilege-hierarchy check — see canAdministerUser. The matching REDEMPTION route
		// is public and mounted on the root mux below. Only mounted when a token store is wired.
		if s.AuthAPI.CredentialTokens != nil {
			protected.HandleFunc("POST /users/{id}/password-reset", s.AuthAPI.HandleIssuePasswordReset)
			protected.HandleFunc("DELETE /users/{id}/password-reset", s.AuthAPI.HandleRevokePasswordReset)
		}
	}

	// CSRF check first (cookie-authenticated mutations must double-submit — csrf.go), then
	// authenticate, then pin the tenant for RLS.
	// IP allow-listing wraps the OUTSIDE of the chain: a disallowed source is refused at the edge,
	// before CSRF/auth/tenant, so it never reaches the session store. Nil (unconfigured) is open.
	protectedChain := s.ipAllowMiddleware(s.csrfMiddleware(s.authMiddleware(s.tenantMiddleware(s.tenantIPAllowMiddleware(protected)))))

	// Root mux: public auth endpoints bypass the auth chain; everything else (the "/"
	// catch-all, which net/http treats as least-specific) goes through it. /auth/login (and
	// /enroll/redeem below) are CSRF-EXEMPT — no session exists yet, the body carries the
	// authorization — but /auth/logout acts on the ambient cookie, so it IS csrf-wrapped.
	root := http.NewServeMux()
	if s.OIDC != nil && s.TenantHostSuffix != "" {
		s.mountOIDCPublic(root)
	}
	// Use the complete auth/tenant/IP chain, but do not keep an idle login alive
	// merely because a browser is checking whether it should return to sign-in.
	protected.HandleFunc("GET /auth/session", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	root.HandleFunc("GET /auth/session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx := context.WithValue(r.Context(), sessionObservationKey{}, true)
		protectedChain.ServeHTTP(w, r.WithContext(ctx))
	})
	// PUBLIC Content-Security-Policy violation reports from the console's Report-Only policy (docs/26
	// F10). Browsers send them without credentials; the handler caps, sanitizes and budgets what it
	// logs, and stores nothing. See csp_report.go.
	root.HandleFunc("POST /csp-report", handleCSPReport(defaultCSPReportBudget))
	if s.AuthAPI != nil {
		// Login is CSRF-exempt (no session exists yet) but NOT origin-exempt: without a pre-session
		// defence a cross-site auto-submitting form can log a victim's browser into an ATTACKER's
		// account and silently redirect their work into the attacker's tenant. See originMiddleware.
		root.Handle("POST /auth/login", s.originMiddleware(http.HandlerFunc(s.AuthAPI.HandleLogin)))
		root.Handle("POST /auth/logout", s.csrfMiddleware(http.HandlerFunc(s.AuthAPI.HandleLogout)))
		// PUBLIC credential-token redemption: the caller has no usable credential — that is the
		// whole reason this endpoint exists — so like /enroll/redeem it sits outside the auth →
		// tenant chain and the token in the body IS the authorization. CSRF-exempt for the same
		// reason login is: there is no ambient session to ride. It is NOT origin-wrapped, unlike
		// login, because there is no cross-site harm to prevent: the request needs a secret the
		// attacker's page does not have, and an attacker who HAS that secret can redeem it
		// directly rather than through a victim's browser.
		if s.AuthAPI.CredentialTokens != nil {
			root.HandleFunc("POST /auth/password/redeem", s.AuthAPI.HandleRedeemPasswordReset)
		}
	}
	// INTERNAL signaling routes. Two of them now:
	//
	//   - device identity (M3): resolve a device id to its tenant + pinned agent pubkey, so
	//     signaling can verify proof of possession at register_agent;
	//   - session-ticket redemption: record a verified ticket's ONE rendezvous in the shared ledger,
	//     so a captured ticket cannot be replayed at another replica or after a restart.
	//
	// Both are cross-tenant by construction, so they sit outside the auth → tenant (RLS) chain and
	// are gated on a service token instead — and neither route EXISTS unless that token is
	// configured long enough to be a secret.
	//
	// They share ONE token deliberately. The same process calls both over the same hop, so a second
	// secret would add a second thing to distribute, rotate and get wrong, in exchange for
	// separating two capabilities that are always granted together.
	switch {
	case s.DeviceIdentityToken == "":
		// Not configured: no internal routes at all. The binary's wiring warns about this at startup.
	case len(s.DeviceIdentityToken) < DeviceIdentityTokenMinLen:
		log.Printf("WARNING: device-identity token is shorter than %d characters — the internal "+
			"signaling routes (GET /internal/devices/{device_id}/identity, "+
			"POST /internal/session-tickets/redeem) are NOT mounted; signaling cannot authenticate "+
			"register_agent until a long enough token is configured", DeviceIdentityTokenMinLen)
	default:
		if s.Machines == nil {
			log.Printf("WARNING: a device-identity token is configured but no machine store is wired — " +
				"GET /internal/devices/{device_id}/identity is NOT mounted")
		} else {
			root.HandleFunc("GET /internal/devices/{device_id}/identity", s.handleDeviceIdentity)
		}
		// Mounted independently of the identity route: they are backed by different stores, so a
		// deployment that wires one and not the other should lose only the half it did not wire.
		// An absent ledger is NOT warned about here (unlike the machine store) because it is not an
		// outage: signaling answers a 404 by proceeding on its local verdict, which is exactly how
		// it behaves against a control plane predating this route.
		if s.TicketRedemptions != nil {
			root.HandleFunc("POST /internal/session-tickets/redeem", s.handleRedeemSessionTicket)
		}
		if s.GuestEnds != nil && s.Machines != nil {
			root.HandleFunc("POST /internal/sessions/{id}/guest-ended", s.handleGuestEnded)
			root.HandleFunc("POST /internal/sessions/{id}/ended", s.handleSessionEnded)
		}
		if s.directiveInternalMounted() {
			root.HandleFunc("GET /internal/devices/{device_id}/directives/pending", s.handleInternalDirectivesPending)
			root.HandleFunc("POST /internal/directives/{id}/delivered", s.handleInternalDirectiveDelivered)
			root.HandleFunc("POST /internal/directives/{id}/ack", s.handleInternalDirectiveAck)
		}
		if s.HelpRequests != nil && s.Machines != nil {
			root.HandleFunc("POST /internal/devices/{device_id}/help-request", s.handleHelpRequestCreate)
			root.HandleFunc("POST /internal/devices/{device_id}/help-cancel", s.handleHelpRequestCancel)
			root.HandleFunc("POST /internal/devices/{device_id}/help-status", s.handleHelpRequestStatus)
		}
		// docs/49 v4: signaling probes this before advertising session_ended_v1 to agents.
		root.HandleFunc("GET /internal/capabilities", s.handleInternalCapabilities)
	}
	// PUBLIC token redemption (M1): the installer is unauthenticated — the enrollment token IS
	// the authorization — so this sits beside /auth/login, outside the auth → tenant chain.
	// Only mounted when both the token store and the machine store are wired.
	if s.EnrollmentTokens != nil && s.Machines != nil {
		root.HandleFunc("POST /enroll/redeem", s.handleRedeemEnrollment)
	}
	// PUBLIC removal confirmation (docs/65 sec. 2b): the device-key signature on the final acknowledgement of
	// an uninstall is the whole credential. Mounted exactly when the internal directive routes are.
	if s.directiveInternalMounted() {
		root.HandleFunc("POST /agent/directives/{id}/final-ack", s.handleDirectiveFinalAck)
	}
	// PUBLIC attended guest paths (docs/12): the code / attend-token is the authorization, so like
	// /enroll/redeem these sit outside the auth → tenant chain. redeem is metered; consent/status
	// authenticate by the 256-bit attend token the guest holds.
	if s.Attended != nil {
		root.HandleFunc("POST /attended-sessions/redeem", s.handleRedeemAttended)
		root.HandleFunc("POST /attended-sessions/consent", s.handleConsentAttended)
		root.HandleFunc("GET /attended-sessions/status", s.handleStatusAttended)
		root.HandleFunc("GET /attended-sessions/installer", s.handleAttendedInstallBundle)
		// Support bundle: serves DeskRallySupport.exe + session.code sidecar as a ZIP so the
		// guest does not have to manually type the code. Unauthenticated; code in body only.
		root.HandleFunc("POST /attended-sessions/support-bundle", s.handleAttendedSupportBundle)
		// Which download the join page may offer (docs/48 C): in deployment-pass mode the plain
		// support exe is GENERIC and cannot work without the pass inside the bundle, so the page
		// must offer the bundle only. Public and constant per server; it reveals only the mode.
		root.HandleFunc("GET /attended-sessions/support-mode", s.handleAttendedSupportMode)
		// Promote-complete: guest reports whether the UAC-gated permanent install succeeded.
		// Keyed by attend token Bearer (pre-tenant, same as /status). Rate-shared with status.
		root.HandleFunc("POST /attended-sessions/promote-complete", s.handlePromoteCompleteAttended)
	}
	// PUBLIC branding of the host the guest opened (docs/66 stage 1b, publicbranding.go). Always mounted: with
	// the host policy off, or no store, they answer the neutral object on the same schedule.
	root.HandleFunc("GET /public/branding", s.handlePublicBranding(false))
	root.HandleFunc("GET /public/branding/logo", s.handlePublicBranding(true))
	// Health probes (http_health.go): PUBLIC liveness + readiness for LBs / orchestrators / uptime
	// monitoring, mirroring the signaling server's /healthz. Readiness pings the DB (cached) so an
	// unauthenticated probe cannot amplify into DB load.
	root.HandleFunc("GET /healthz", handleLivez)
	root.HandleFunc("GET /readyz", makeReadyzHandler(newReadinessGate(s.Ready)))

	// Public, versioned HTTP API (docs/01 §7 P1): /api/v1/… aliases of read-only management
	// handlers on the SAME protected chain, plus the (public) OpenAPI spec on root. See publicapi.go.
	s.registerPublicAPI(protected, root)

	// Central recording upload (docs/63): signed agent routes on the ROOT mux, outside the cookie/CSRF/
	// tenant chain (the agent's signature is the authorization). Mounted only when fully wired.
	s.mountRecordingUpload(root)
	// Console side of central recording: policy, list, detail, playlist, stream, download (docs/63 C8) — on
	// the PROTECTED chain, behind CapViewRecordings / CapManageTenant.
	s.mountRecordingConsole(protected)

	root.Handle("/", protectedChain)

	// The authority gate is OUTSIDE everything: a marked public-ingress request with a bad authority is refused
	// before any handler, resolver or database work (docs/66 2b.6). Unmarked (internal) requests pass untouched.
	return s.recoverMiddleware(s.sourceIPMiddleware(s.publicExchangeBounds(s.HostPolicy.EdgeAuthorityGate(root))))
}

// -------------------------------------------------------------------------------------
// Middleware
// -------------------------------------------------------------------------------------

type ctxKey int

const (
	ctxPrincipal ctxKey = iota
)

// authMiddleware resolves the caller's Principal and stashes it on the context.
//
// The real Authenticator is SessionAuthenticator (auth.go): it looks up the opaque session
// token (cookie / Bearer) in the session store, enforces expiry + revocation, rejects
// disabled users, and loads the effective *Grant (roles → capabilities, group scopes) that
// every handler's capability check runs against. StubAuthenticator remains for tests/dev.
//
// TODO(auth): OIDC/SAML federation via Zitadel (docs/02-architecture.md — "Zitadel embedded,
// or own auth core + OIDC/SAML SP") is additive on top of this: map the OIDC `sub` →
// app_user.external_subject, then issue the same server-side session as local login.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Auth.Authenticate(r)
		if err != nil || p == nil {
			// A REFUSAL TO LOOK UP (credential_guard.go): the source is over its budget of failed
			// lookups (429) or the global cap on concurrent unproven lookups is full (503). Neither says
			// anything about the credential, so neither is the opaque 401 — a 401 is a sign-out in the
			// console (a-401-is-a-sign-out), and a legitimate tab must retry, not log the user out.
			if ref := credentialRefusalOf(err); ref != nil {
				writeCredentialRefusal(w, ref)
				return
			}
			// One exception to the otherwise deliberately opaque 401: a SUSPENDED TENANT is named.
			// The caller authenticated correctly and there is nothing they can do at a login form to
			// fix it (login is refused for the same reason), so answering "unauthorized" would send a
			// legitimate technician round a loop that cannot terminate. 403, not 401: the credential
			// is good, the tenancy is not. See ErrTenantSuspended for why this leaks nothing.
			if errors.Is(err, ErrTenantSuspended) {
				writeError(w, http.StatusForbidden, ErrTenantSuspended.Error())
				return
			}
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxPrincipal, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tenantMiddleware pins app.current_tenant for the request via the TenantBinder. Every
// query issued downstream is then RLS-scoped to this tenant by PostgreSQL itself. If the
// tenant can't be bound the request fails closed rather than running unscoped.
func (s *Server) tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		if p == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		releaseBody, ok := bufferTenantBody(w, r)
		if !ok {
			return
		}
		defer releaseBody()
		ctx, release, err := s.Binder.BindTenant(r.Context(), p.TenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not establish tenant context")
			return
		}
		if release != nil {
			defer release()
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tenantIPAllowMiddleware enforces the PER-TENANT IP allow-list (docs/01 §10). It runs INSIDE
// tenantMiddleware (so the tenant is pinned and its CIDRs read RLS-scoped) — the deployment-wide
// guard runs at the edge, but a per-tenant one cannot, because the tenant is unknown before auth.
//
// Fail-open only for "unconfigured", fail-CLOSED for everything else: an unwired store (nil) or a
// tenant with an EMPTY list allows every request (the backward-compatible default), but a store error
// or a source IP not covered by a NON-empty list is a 403 — an address that cannot be shown to be on
// the list is not on it (the same rule as IPAllowlist.Allows). Reuses the ipallow.go matcher so the
// enforcement and the anti-lockout safeguard evaluate identically.
func (s *Server) tenantIPAllowMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.TenantIPAllowlist != nil {
			if p := principalFrom(r.Context()); p != nil {
				cidrs, err := s.TenantIPAllowlist.ListCIDRs(r.Context(), p.TenantID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "could not evaluate the organization IP allow-list")
					return
				}
				if len(cidrs) > 0 {
					// Stored CIDRs are normalized on insert, so ParseIPAllowlist should not error; if it
					// somehow does, fail closed (a list we cannot parse must not silently allow).
					allow, perr := ParseIPAllowlist(strings.Join(cidrs, " "), s.trustProxyIP)
					if allow != nil {
						allow.trustedProxyNets = s.trustedProxyNets
					}
					if perr != nil || !allow.Allows(r) {
						writeError(w, http.StatusForbidden, "access from this network is not allowed for your organization")
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware turns a panic into a 500 instead of dropping the connection.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// http.ErrAbortHandler is the documented way for a handler that has ALREADY sent part of
				// a response to say "this cannot be completed": net/http then drops the connection so the
				// client sees a failed transfer. Swallowing it (and appending a JSON 500 to a half-sent
				// body) would hand the client a response that looks finished — the recording download and
				// stream routes rely on it (docs/63 C8: never release unauthenticated bytes as complete).
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				log.Printf("panic serving %s %s: %v", r.Method, r.URL.Path, rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func principalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxPrincipal).(*Principal)
	return p
}

// -------------------------------------------------------------------------------------
// Handlers. Data access runs against the repository stores; RLS (pinned by the binder /
// withTenant) already scopes every query to the caller's tenant, so none of them carries an
// explicit tenant filter.
// -------------------------------------------------------------------------------------

// recordMgmtAudit appends a management-plane audit event for a handler action. When no
// MgmtAuditStore is wired (pure-RBAC skeleton tests) recording is skipped. A recording FAILURE
// is returned so the handler fails the request: a mutation that cannot be audited must be loud,
// not silent (the mutation itself may already be committed — its own transaction — but the
// caller sees a 500 instead of a success it could assume was recorded).
func (s *Server) recordMgmtAudit(r *http.Request, action, targetKind, targetID string, meta map[string]any) error {
	if s.MgmtAudit == nil {
		return nil
	}
	p := principalFrom(r.Context())
	var raw json.RawMessage
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		raw = b
	}
	e := &MgmtAuditEvent{
		ActorUserID: p.UserID,
		Action:      action,
		TargetKind:  targetKind,
		TargetID:    targetID,
		Metadata:    raw,
	}
	if err := s.MgmtAudit.RecordEvent(r.Context(), p.TenantID, e); err != nil {
		return err
	}
	// After a successful audit write, fire registered webhook endpoints asynchronously.
	// The dispatch is best-effort (fire-and-forget, one retry); audit failure is still
	// reported to the caller and blocks the mutation — webhooks never do.
	if s.Dispatcher != nil {
		s.Dispatcher.Dispatch(p.TenantID, e)
	}
	return nil
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	// RLS confines a normal caller to their own tenant row; the listing is still gated on
	// ManageTenant because tenant settings are a management surface, not technician data.
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Tenants == nil {
		writeError(w, http.StatusInternalServerError, "tenant store not configured")
		return
	}
	tenants, err := s.Tenants.ListTenants(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list tenants")
		return
	}
	// Provisioning moved to POST /platform/tenants (operators only); the console's Platform area
	// owns it, so this listing never offers it.
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants, "can_create": false})
}

// createTenantRequest is the body of POST /tenants (SaaS provisioning surface).
type createTenantRequest struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	DeploymentMode string `json:"deployment_mode"` // optional; defaults to "saas"
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	// Tenant provisioning is a platform-operator action: POST /platform/tenants, which requires the
	// per-user operator grant and a recent second-factor verification, and audits both chains.
	// Every tenant's Owner holds CapManageTenant, so this route could never be the gate.
	writeError(w, http.StatusGone, "tenant provisioning moved to POST /platform/tenants (platform operators only)")
}

// requireTenantIPAllowlist is the shared preamble for the three /tenant/ip-allowlist handlers: gate on
// CapManageTenant (tenant security settings, like the tenant surface) and confirm the store is wired.
// Returns the principal, or writes the error response and returns nil.
func (s *Server) requireTenantIPAllowlist(w http.ResponseWriter, r *http.Request) *Principal {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return nil
	}
	if s.TenantIPAllowlist == nil {
		writeError(w, http.StatusInternalServerError, "tenant ip allow-list store not configured")
		return nil
	}
	return p
}

// handleGetTenantIPAllowlist (GET /tenant/ip-allowlist) returns the tenant's allow-list CIDRs plus the
// caller's CURRENT source IP, so the console can show "your IP is X" beside the list — the signal an
// admin needs to avoid locking themselves out.
func (s *Server) handleGetTenantIPAllowlist(w http.ResponseWriter, r *http.Request) {
	p := s.requireTenantIPAllowlist(w, r)
	if p == nil {
		return
	}
	cidrs, err := s.TenantIPAllowlist.ListCIDRs(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list ip allow-list")
		return
	}
	if cidrs == nil {
		cidrs = []string{} // a tenant with no entries serializes as [], never null
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs, "your_ip": s.callerIPString(r)})
}

// callerIPString is the caller's source IP as the enforcement sees it (RemoteAddr or trusted XFF),
// or "" when it cannot be determined. Echoed to the console and used in the anti-lockout message.
func (s *Server) callerIPString(r *http.Request) string {
	if ip := resolveClientIP(r, s.trustProxyIP, s.trustedProxyNets); ip != nil {
		return ip.String()
	}
	return ""
}

// wouldLockOutCaller reports whether enforcing `resulting` as the tenant's allow-list would refuse the
// CALLER's own current request — i.e. the list is non-empty AND does not cover the caller's source IP.
// An empty resulting list is "open" (never a lockout). Reuses the exact enforcement matcher, so the
// safeguard and the middleware can never disagree. A parse error fails closed (treated as a lockout).
func (s *Server) wouldLockOutCaller(r *http.Request, resulting []string) bool {
	allow, err := ParseIPAllowlist(strings.Join(resulting, " "), s.trustProxyIP)
	if err != nil {
		return true
	}
	if allow != nil {
		allow.trustedProxyNets = s.trustedProxyNets
	}
	return !allow.Allows(r)
}

// handleAddTenantIPAllowlistEntry (POST /tenant/ip-allowlist, body {cidr}) adds one CIDR. It refuses
// (400) any add whose RESULTING list would exclude the caller's own current source IP — the
// anti-lockout safeguard, so an admin cannot fence themselves out of the very API that manages the list.
func (s *Server) handleAddTenantIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	p := s.requireTenantIPAllowlist(w, r)
	if p == nil {
		return
	}
	var body struct {
		CIDR string `json:"cidr"`
	}
	// docs/25 F05: one CIDR string; capped so the decode cannot hold the pinned tenant connection
	// open on a body the client keeps extending.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &body, "malformed request body"); err != nil {
		return
	}
	cidr, err := normalizeCIDR(body.CIDR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Anti-lockout is enforced ATOMICALLY inside the store (advisory-locked read-check-write), so two
	// concurrent mutations cannot each validate against a stale snapshot and jointly lock the caller out
	// (a TOCTOU a handler-side check leaves open). `safe` is the caller-coverage predicate; the store
	// runs it under the per-tenant lock against the true committed state.
	safe := func(resulting []string) bool { return !s.wouldLockOutCaller(r, resulting) }
	if err := s.TenantIPAllowlist.AddCIDRGuarded(r.Context(), p.TenantID, cidr, safe); err != nil {
		if errors.Is(err, ErrWouldLockOut) {
			writeError(w, http.StatusBadRequest, "this would lock you out: your current IP "+s.callerIPString(r)+" is not covered by the resulting allow-list")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not add ip allow-list entry")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.ip_allowlist.add", "tenant", p.TenantID, map[string]any{"cidr": cidr}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidr": cidr})
}

// handleDeleteTenantIPAllowlistEntry (DELETE /tenant/ip-allowlist?cidr=<cidr>) removes one CIDR. The
// CIDR is a query param, not a path segment, because it contains a '/'. It applies the same
// anti-lockout safeguard: removing an entry must not leave a non-empty list that excludes the caller.
func (s *Server) handleDeleteTenantIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	p := s.requireTenantIPAllowlist(w, r)
	if p == nil {
		return
	}
	cidr, err := normalizeCIDR(r.URL.Query().Get("cidr"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Same ATOMIC anti-lockout as the add: the store removes and re-checks caller coverage under the
	// per-tenant advisory lock, so two concurrent deletes of overlapping-coverage entries cannot each
	// see the other's stale snapshot and jointly strand the caller. Removing to an empty (open) list is
	// always safe.
	safe := func(resulting []string) bool { return !s.wouldLockOutCaller(r, resulting) }
	if err := s.TenantIPAllowlist.RemoveCIDRGuarded(r.Context(), p.TenantID, cidr, safe); err != nil {
		if errors.Is(err, ErrWouldLockOut) {
			writeError(w, http.StatusBadRequest, "this would lock you out: your current IP "+s.callerIPString(r)+" would no longer be covered by the allow-list")
			return
		}
		if errors.Is(err, ErrTenantIPAllowlistEntryNotFound) {
			writeError(w, http.StatusNotFound, "no such allow-list entry")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not remove ip allow-list entry")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.ip_allowlist.remove", "tenant", p.TenantID, map[string]any{"cidr": cidr}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "cidr": cidr})
}

// handleListDynamicGroups (GET /dynamic-groups) lists the tenant's saved predicates. A read, gated on
// CapViewMachines (a technician benefits from resolving groups; managing them needs CapManageGroups).
func (s *Server) handleListDynamicGroups(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil {
		writeError(w, http.StatusInternalServerError, "dynamic group store not configured")
		return
	}
	groups, err := s.DynamicGroups.ListDynamicGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list dynamic groups")
		return
	}
	if groups == nil {
		groups = []DynamicGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// createDynamicGroupRequest is the body of POST /dynamic-groups.
type createDynamicGroupRequest struct {
	Name          string `json:"name"`
	PropertyKey   string `json:"property_key"`
	PropertyValue string `json:"property_value"` // optional; "" = "any value" (see MachineIDsWithProperty)
}

// handleCreateDynamicGroup (POST /dynamic-groups) creates a saved predicate. Managing groups needs
// CapManageGroups (Owner/Admin) — CapManageGroups' first consumer.
func (s *Server) handleCreateDynamicGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil {
		writeError(w, http.StatusInternalServerError, "dynamic group store not configured")
		return
	}
	var req createDynamicGroupRequest
	// docs/25 F05: three short strings, each length-checked below; capped so the decode cannot hold
	// the pinned tenant connection open.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.PropertyKey = strings.TrimSpace(req.PropertyKey)
	if req.Name == "" || req.PropertyKey == "" {
		writeError(w, http.StatusBadRequest, "name and property_key are required")
		return
	}
	if len(req.Name) > maxDynamicGroupNameLen || len(req.PropertyKey) > maxDynamicGroupKeyLen ||
		len(req.PropertyValue) > maxDynamicGroupValLen {
		writeError(w, http.StatusBadRequest, "name/property_key/property_value too long")
		return
	}
	g := &DynamicGroup{Name: req.Name, PropertyKey: req.PropertyKey, PropertyValue: req.PropertyValue}
	if err := s.DynamicGroups.CreateDynamicGroup(r.Context(), p.TenantID, g); err != nil {
		if errors.Is(err, ErrDynamicGroupNameTaken) {
			writeError(w, http.StatusConflict, "a dynamic group with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create dynamic group")
		return
	}
	if err := s.recordMgmtAudit(r, "group.create", "group", g.ID, map[string]any{"name": g.Name, "property_key": g.PropertyKey}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"group": g})
}

// handleDeleteDynamicGroup (DELETE /dynamic-groups/{id}) removes a saved predicate. CapManageGroups.
func (s *Server) handleDeleteDynamicGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil {
		writeError(w, http.StatusInternalServerError, "dynamic group store not configured")
		return
	}
	id := r.PathValue("id")
	if err := s.DynamicGroups.DeleteDynamicGroup(r.Context(), p.TenantID, id); err != nil {
		if errors.Is(err, ErrDynamicGroupNotFound) {
			writeError(w, http.StatusNotFound, "dynamic group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete dynamic group")
		return
	}
	if err := s.recordMgmtAudit(r, "group.delete", "group", id, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// handleResolveDynamicGroup (GET /dynamic-groups/{id}/machines) resolves a group's members LIVE. It
// reuses the SAME "narrow-only" resolution as GET /machines: list the tenant's machines, keep only those
// the caller may see (AllowsInGroup), then INTERSECT with the machines carrying the group's property —
// so a dynamic group can never reveal a machine the caller could not already list, nor widen their reach.
func (s *Server) handleResolveDynamicGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil || s.Machines == nil || s.MachineProperties == nil {
		writeError(w, http.StatusInternalServerError, "machine or dynamic group store not configured")
		return
	}
	g, err := s.DynamicGroups.GetDynamicGroup(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrDynamicGroupNotFound) {
			writeError(w, http.StatusNotFound, "dynamic group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not read dynamic group")
		return
	}
	all, err := s.Machines.ListMachines(r.Context(), p.TenantID)
	if err != nil {
		writeListError(w, err, "could not list machines")
		return
	}
	ids, err := s.MachineProperties.MachineIDsWithProperty(r.Context(), p.TenantID, g.PropertyKey, g.PropertyValue)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve dynamic group members")
		return
	}
	members := make([]Machine, 0)
	for _, m := range all {
		// Narrow to the caller's visible machines AND intersect with the predicate (never widen).
		if p.Grant.AllowsInGroup(CapViewMachines, m.GroupID) {
			if _, ok := ids[m.ID]; ok {
				members = append(members, m)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": g, "machines": members})
}

func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	all, err := s.Machines.ListMachines(r.Context(), p.TenantID)
	if err != nil {
		writeListError(w, err, "could not list machines")
		return
	}
	// RLS already scoped the query to the tenant; now filter to the groups the caller's
	// memberships actually cover, so a group-scoped viewer only sees their machines.
	visible := make([]Machine, 0, len(all))
	for _, m := range all {
		if p.Grant.AllowsInGroup(CapViewMachines, m.GroupID) {
			visible = append(visible, m)
		}
	}
	// Optional custom-property filter (docs/01 §4): `?property_key=site[&property_value=HQ]` narrows
	// the listing to machines carrying that property. The matching-id set is INTERSECTED with what the
	// caller can already see (never unioned), so the filter can only narrow a listing — it can never
	// reveal a machine outside the caller's group scope, and an empty `property_value` matches any
	// value. `all` (below) is left untouched so presence history is still recorded fleet-wide.
	if key := strings.TrimSpace(r.URL.Query().Get("property_key")); key != "" {
		if s.MachineProperties == nil {
			writeError(w, http.StatusInternalServerError, "machine property store not configured")
			return
		}
		ids, err := s.MachineProperties.MachineIDsWithProperty(r.Context(), p.TenantID, key, r.URL.Query().Get("property_value"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not filter machines by property")
			return
		}
		filtered := make([]Machine, 0, len(visible))
		for _, m := range visible {
			if _, ok := ids[m.ID]; ok {
				filtered = append(filtered, m)
			}
		}
		visible = filtered
	}
	presenceKnown := s.annotatePresence(r, p.TenantID, visible, all)
	stampDerived(visible)
	writeJSON(w, http.StatusOK, map[string]any{
		"machines": visible,
		// Explicit so the console can say "presence unavailable" instead of silently rendering
		// every machine as offline when the feed is down (see presence.go's fail-soft note).
		"presence_known": presenceKnown,
	})
}

// annotatePresence stamps Online/LastSeen onto the caller's OWN machines from the signaling
// presence feed, and persists last_seen for the ones reported up. Returns whether presence could be
// determined at all.
//
// It takes TWO slices on purpose:
//
//   - `visible` — the machines this caller may see (RLS ∩ their group scope). Only these are
//     ANNOTATED, because only these appear in the response.
//   - `owned` — every machine RLS scoped to the tenant. The last_seen HISTORY is recorded across
//     all of them, because a sighting is a fact about the tenant's fleet, not about who happened to
//     be browsing. Stamping only `visible` meant a group-scoped viewer's page loads recorded
//     nothing for the rest of the tenant, so "offline since 14:32" silently depended on which
//     technician had last opened the console. The write reveals nothing to the caller — they cannot
//     read those rows back — and RLS still confines it to their own tenant.
//
// The tenant-scoping rule (presence.go): the feed is cross-tenant, so this only ever READS it by
// asking "is THIS machine's device id in the set" for machines the tenant already owns. Ids in the
// feed that do not match are never surfaced, counted, or distinguished from ids that do not exist,
// so a shared signaling server cannot leak one MSP's fleet to another.
//
// The result is NOT conditioned on len(visible): "the feed answered and you own nothing here" and
// "the feed is down" are different facts, and collapsing them made an empty fleet indistinguishable
// from an outage in the console.
//
// Everything here is best-effort. A missing source, an unreachable signaling server, or a failed
// last_seen write all degrade the listing to "presence unknown" and never fail the request:
// nothing is authorized on presence, so failing closed would cost availability and buy nothing.
func (s *Server) annotatePresence(r *http.Request, tenantID string, visible, owned []Machine) bool {
	if s.Presence == nil {
		return false
	}
	snapshot, err := s.Presence.FetchPresence(r.Context())
	if err != nil || snapshot == nil {
		if err != nil && !errors.Is(err, ErrPresenceUnavailable) {
			log.Printf("presence lookup for tenant %s failed: %v", tenantID, err)
		}
		return false
	}
	for i := range visible {
		// Take the address of a per-iteration copy, not of the loop variable.
		online := snapshot.IsOnline(visible[i].DeviceID)
		flag := online
		visible[i].Online = &flag
		if !online {
			continue
		}
		if seen, ok := snapshot.LastSeen(visible[i].DeviceID); ok {
			stamp := seen
			visible[i].LastSeen = &stamp
		}
		if pinned, ok := snapshot.GrantKeyPinned(visible[i].DeviceID); ok {
			p := pinned
			visible[i].GrantKeyPinned = &p
		}
		if req, ok := snapshot.SessionPolicyRequired(visible[i].DeviceID); ok {
			r := req
			visible[i].SessionPolicyRequired = &r
		}
	}
	onlineIDs := make([]string, 0, len(owned))
	for i := range owned {
		if snapshot.IsOnline(owned[i].DeviceID) {
			onlineIDs = append(onlineIDs, owned[i].DeviceID)
		}
	}
	// Persist the sighting so "offline for 3h" stays answerable after the agent disconnects and
	// after signaling restarts. Failure is logged, never surfaced — the response above is already
	// correct without it.
	//
	// The stamp is the SNAPSHOT's timestamp, not this process's clock: last_seen means "the last
	// moment we observed this device online", and the observation happened on signaling's clock at
	// snapshot time. Using time.Now() here would mix two clocks into one column, so the value read
	// back for an offline machine would sit slightly after the live value shown while it was up.
	if len(onlineIDs) > 0 {
		at := snapshot.AsOf
		if at.IsZero() {
			at = time.Now().UTC()
		}
		if _, err := s.Machines.TouchLastSeen(r.Context(), tenantID, onlineIDs, at); err != nil {
			log.Printf("could not record last_seen for tenant %s: %v", tenantID, err)
		}
	}
	// Refresh machine.os from the agent-asserted values in the same feed — the column is otherwise
	// write-once at enrollment, so an OS upgrade never reached it. Keyed off the STORED rows
	// (`owned` carries each machine's current os), so the steady state — nothing changed — does not
	// call the store at all. Same scoping rationale as last_seen: `owned`, not `visible`, because
	// an OS upgrade is a fact about the fleet, not about who happened to be browsing. Write-behind
	// on purpose: this response still shows the value this request READ; the next poll shows the
	// refreshed one.
	osUpdates := make(map[string]string)
	for i := range owned {
		if observed, ok := snapshot.ObservedOS(owned[i].DeviceID); ok && observed != owned[i].OS {
			osUpdates[owned[i].DeviceID] = observed
		}
	}
	if len(osUpdates) > 0 {
		if _, err := s.Machines.RecordObservedOS(r.Context(), tenantID, osUpdates); err != nil {
			log.Printf("could not refresh machine.os for tenant %s: %v", tenantID, err)
		}
	}
	// Refresh machine.require_session_policy the same way, and for a sharper reason than inventory:
	// this one CHANGES BEHAVIOUR. handleStartSession mints a session policy for a machine flagged
	// here, and an agent whose operator set the flag AFTER enrollment would otherwise be stranded
	// view-only forever with the control plane never knowing why (migrations/0037). Enrollment ran
	// once, long ago; register_agent runs on every reconnect, which is what makes this the channel
	// that self-heals.
	//
	// ONLY devices that actually REPORTED produce an update — the two-value read is the guard. A
	// silent agent (older build, or one that never registered this session) must leave the stored
	// value alone: writing false for silence would clear a flag an operator deliberately set, which
	// is the exact stranding this feature exists to prevent, only sneakier.
	// Refresh machine.agent_version on exactly the same terms (migrations/0039). This is the hop
	// that makes "what is actually deployed out there" answerable, which every part of agent
	// auto-update depends on (docs/21 §2) — a rollout that cannot be observed cannot be staged,
	// canaried, soaked or rolled back.
	//
	// The two-value read is the same guard as the floor flag's, for the same reason: only a device
	// that actually REPORTED may cause a write, so an older agent's silence never blanks a version
	// already recorded. `owned` and not `visible`, because a deployed build is a fact about the
	// fleet rather than about who is browsing. Diffed against the stored value so the steady state
	// does not call the store at all — which is what keeps agent_version_seen_at meaning "first
	// observed" rather than degenerating into a second copy of last_seen.
	versionUpdates := make(map[string]string)
	for i := range owned {
		if reported, ok := snapshot.ObservedAgentVersion(owned[i].DeviceID); ok && reported != owned[i].AgentVersion {
			versionUpdates[owned[i].DeviceID] = reported
		}
	}
	if len(versionUpdates) > 0 {
		if _, err := s.Machines.RecordAgentVersion(r.Context(), tenantID, versionUpdates); err != nil {
			log.Printf("could not refresh machine.agent_version for tenant %s: %v", tenantID, err)
		}
	}
	floorUpdates := make(map[string]bool)
	for i := range owned {
		if reported, ok := snapshot.RequiresSessionPolicy(owned[i].DeviceID); ok && reported != owned[i].RequireSessionPolicy {
			floorUpdates[owned[i].DeviceID] = reported
		}
	}
	if len(floorUpdates) > 0 {
		if _, err := s.Machines.RecordRequireSessionPolicy(r.Context(), tenantID, floorUpdates); err != nil {
			log.Printf("could not refresh machine.require_session_policy for tenant %s: %v", tenantID, err)
		}
	}
	// Refresh machine.logged_in_user from the agent-asserted interactive-session user in the
	// presence feed (migrations/0048). This is purely display inventory — nothing authorizes on it.
	// The two-value read guards against a silent agent blanking a user already recorded, same as
	// ObservedAgentVersion and ObservedOS. `owned`, not `visible`, for the same scoping reason.
	userUpdates := make(map[string]string)
	for i := range owned {
		if reported, ok := snapshot.ObservedLoggedInUser(owned[i].DeviceID); ok && reported != owned[i].LoggedInUser {
			userUpdates[owned[i].DeviceID] = reported
		}
	}
	if len(userUpdates) > 0 {
		if _, err := s.Machines.RecordLoggedInUser(r.Context(), tenantID, userUpdates); err != nil {
			log.Printf("could not refresh machine.logged_in_user for tenant %s: %v", tenantID, err)
		}
	}
	return true
}

func (s *Server) handleGetMachine(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	// REST read path: `{id}` is the machine's PRIMARY KEY (as returned by GET /machines), so it
	// resolves by PK via GetMachineByID — NOT the device-id resolution the grant/session path uses.
	// The machine's REAL group is resolved from the store (never trusted from the caller), then
	// ViewMachines is gated on THAT group.
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapViewMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	one := []Machine{*m}
	stampDerived(one)
	writeJSON(w, http.StatusOK, map[string]any{"machine": one[0]})
}

// resolveMachineForProperties resolves `{id}` to its stored machine and enforces `cap` against the
// machine's REAL group (resolved from the store, never trusted from the caller) — the exact pattern
// handleGetMachine uses, and the D1 hole it closes. On any failure it has already written the
// response and returns ok=false. It also fails closed when either store is unwired.
// setMachineStatusRequest is the body of POST /machines/{id}/status.
type setMachineStatusRequest struct {
	Status string `json:"status"`
}

// handleSetMachineStatus backs POST /machines/{id}/status: quarantine / retire / reactivate a machine.
// It resolves the machine BY PRIMARY KEY (so authorization scopes on its REAL group, never a body
// claim), gates on CapManageMachines for that group, validates the status against the CHECK set, and
// records a machine.status_set audit event. A quarantined or retired machine is subsequently refused a
// new session by handleStartSession.
func (s *Server) handleSetMachineStatus(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineStatusRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if !IsValidMachineStatus(req.Status) {
		writeError(w, http.StatusBadRequest, "status must be active, quarantined, or retired")
		return
	}
	if err := s.Machines.SetMachineStatus(r.Context(), p.TenantID, m.ID, req.Status); err != nil {
		switch {
		case errors.Is(err, ErrMachineNotFound):
			writeError(w, http.StatusNotFound, "unknown machine")
		case errors.Is(err, ErrInvalidMachineStatus):
			writeError(w, http.StatusBadRequest, "status must be active, quarantined, or retired")
		case errors.Is(err, ErrMachineHasActiveDirective), errors.Is(err, ErrMachineRemoved):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not set machine status")
		}
		return
	}
	// Help requests follow the status IMMEDIATELY (H-C5), before any step that can return early: a failed
	// audit or session reap below must not leave an open request on a machine that is out of service.
	s.cancelHelpForMachine(r, p.TenantID, m.ID, m.Status, req.Status)
	if err := s.recordMgmtAudit(r, "machine.status_set", "machine", m.ID, map[string]any{"status": req.Status}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// Quarantine and retire end live sessions immediately so the concurrency seat is freed and the
	// operator's intent is immediate — new sessions are blocked by refuseOutOfServiceMachine; ending
	// the existing one closes the gap. Best-effort: the machine IS quarantined even if this fails.
	if req.Status != MachineStatusActive && s.SessionRecords != nil {
		if reaped, err := s.SessionRecords.EndSessionsForMachine(r.Context(), p.TenantID, m.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not end live sessions")
			return
		} else if reaped > 0 {
			if aerr := s.recordMgmtAudit(r, "session.reaped", "machine", m.ID,
				map[string]any{"count": reaped, "reason": "machine_" + req.Status}); aerr != nil {
				log.Printf("machine %s quarantined/retired but session.reaped audit failed: %v", m.ID, aerr)
			}
		}
	}
	m.Status = req.Status
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// maxMachineAliasRunes bounds a machine's tenant-set friendly name. Short — it is a display label, not
// free text — and rune-counted so multi-byte names are not mis-measured.
const maxMachineAliasRunes = 100

// setMachineAliasRequest is the body of PATCH /machines/{id}/alias. An absent/empty alias CLEARS the
// alias, reverting the console display to the agent-reported hostname.
type setMachineAliasRequest struct {
	Alias string `json:"alias"`
}

// normalizeMachineAlias validates a tenant-set machine friendly name: it trims surrounding whitespace,
// caps the length at maxMachineAliasRunes RUNES, and rejects control characters (which would garble the
// console table and — for NUL — cannot live in a Postgres text column). An EMPTY alias is valid: it
// clears the override so the hostname shows again.
func normalizeMachineAlias(alias string) (string, error) {
	a := strings.TrimSpace(alias)
	if len([]rune(a)) > maxMachineAliasRunes {
		return "", errors.New("alias must be at most 100 characters")
	}
	if strings.ContainsFunc(a, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("alias contains a control character")
	}
	return a, nil
}

// handleSetMachineAlias backs PATCH /machines/{id}/alias: SET (or clear) a machine's tenant-chosen
// friendly name (docs/01 §4). The agent-reported hostname (Machine.Name) is immutable from the console;
// the alias is a separate, tenant-owned display label the console prefers when non-empty. Resolved BY PK
// and gated on RequireMachine(CapManageMachines, m.GroupID) — the machine's REAL group, never the request
// body — so a group-scoped operator can only rename machines they manage. Audited machine.alias_set.
func (s *Server) handleSetMachineAlias(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineAliasRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	alias, err := normalizeMachineAlias(req.Alias)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Machines.SetMachineAlias(r.Context(), p.TenantID, m.ID, alias); err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set machine alias")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.alias_set", "machine", m.ID, map[string]any{"alias": alias}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	m.Alias = alias
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// maxMachineNoteRunes bounds a machine's free-text operator note. Generous for handoff prose yet small
// enough to keep the column and the fleet listing (the note is in the projection) sane; rune-counted.
const maxMachineNoteRunes = 2000

// setMachineNoteRequest is the body of PATCH /machines/{id}/note. An absent/empty note CLEARS it.
type setMachineNoteRequest struct {
	Note string `json:"note"`
}

// normalizeMachineNote validates a free-text machine note: it caps the length at maxMachineNoteRunes RUNES
// and rejects control characters OTHER than tab / newline / carriage-return (a note is multi-line prose, so
// those are kept; NUL cannot live in a Postgres text column and the other C0 controls would garble a render).
// The note is returned VERBATIM (no trimming) so it round-trips exactly as typed. An EMPTY note is valid: it
// clears the annotation.
func normalizeMachineNote(note string) (string, error) {
	if len([]rune(note)) > maxMachineNoteRunes {
		return "", errors.New("note must be at most 2000 characters")
	}
	for _, r := range note {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", errors.New("note contains a control character")
		}
	}
	return note, nil
}

// handleSetMachineNote backs PATCH /machines/{id}/note: SET (or clear) a machine's free-text operator note
// (docs/01 §4) — unstructured context, distinct from the short alias and from structured properties. Resolved
// BY PK and gated on RequireMachine(CapManageMachines, m.GroupID) — the machine's REAL group, never the request
// body — so a group-scoped operator can only annotate machines they manage. The note CONTENT is NOT put in the
// audit metadata (it may be sensitive); the event records only that a note was set.
func (s *Server) handleSetMachineNote(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineNoteRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	note, err := normalizeMachineNote(req.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Machines.SetMachineNote(r.Context(), p.TenantID, m.ID, note); err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set machine note")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.note_set", "machine", m.ID, map[string]any{}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	m.Note = note
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// setMachineGroupRequest is the body of POST /machines/{id}/group.
type setMachineGroupRequest struct {
	GroupID string `json:"group_id"`
}

// handleSetMachineGroup backs POST /machines/{id}/group: REASSIGN a machine to a different group (§4 fleet
// reorganization). Authorization is TWO-WAY, like role assignment (loop 48): the caller must hold
// CapManageMachines for the machine's CURRENT group (to move it OUT) AND for the TARGET group (to move it
// IN), so a group-scoped operator can only move machines BETWEEN groups they manage — never grab a machine
// from, or dump one into, a group they do not. The target group must resolve within the tenant (a clean 404,
// not the composite-FK 500); the change is audited machine.group_changed with from/to.
func (s *Server) handleSetMachineGroup(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil || s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	// Move OUT: manage the machine where it currently lives.
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineGroupRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// Move IN: manage the destination group too (the no-escalation half).
	if err := p.Grant.RequireMachine(CapManageMachines, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// The target group must be a real group in this tenant (a clean 404 before the store's FK backstop).
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine groups")
		return
	}
	found := false
	var targetName string
	for _, g := range groups {
		if g.ID == req.GroupID {
			found = true
			targetName = g.Name
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "unknown machine group")
		return
	}
	from := m.GroupID
	if err := s.moveMachineToGroup(r.Context(), p, m.ID, req.GroupID); err != nil {
		switch {
		case errors.Is(err, ErrGroupTreeChanged):
			writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
		case errors.Is(err, ErrMachineNotFound):
			writeError(w, http.StatusNotFound, "unknown machine")
		case errors.Is(err, ErrInvalidMachineGroup):
			writeError(w, http.StatusNotFound, "unknown machine group")
		case errors.Is(err, ErrMachineHasActiveDirective), errors.Is(err, ErrMachineRemoved):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not reassign machine group")
		}
		return
	}
	if err := s.recordMgmtAudit(r, "machine.group_changed", "machine", m.ID,
		map[string]any{"from": from, "to": req.GroupID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// Reflect the move in the echoed record: GroupName was joined from the OLD group by GetMachineByID, so
	// recompute it from the resolved TARGET group — otherwise the response's group_id and group_name disagree.
	m.GroupID = req.GroupID
	m.GroupName = targetName
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// moveMachineToGroup reassigns a machine, conditional on the group tree still being at the version the
// caller's grant was read at (docs/62 R2): whether this principal may move this machine depends on the tree,
// so a reparent between the grant read and this write must refuse the move (409 "groups changed, retry")
// rather than apply it on stale authorization. A static grant (an API token) has no version and writes
// unconditionally — it is tenant-wide, which no tree change can narrow.
func (s *Server) moveMachineToGroup(ctx context.Context, p *Principal, machineID, groupID string) error {
	if v := expectTreeVersion(p.Grant); v != nil {
		return s.Machines.SetMachineGroupIfTree(ctx, p.TenantID, machineID, groupID, *v)
	}
	return s.Machines.SetMachineGroup(ctx, p.TenantID, machineID, groupID)
}

// maxBulkStatusMachines bounds one bulk request so a single call cannot fan out into an unbounded number
// of per-machine resolves + audit-chain appends.
const maxBulkStatusMachines = 200

// bulkSetMachineStatusRequest is the body of POST /machines/bulk-status.
type bulkSetMachineStatusRequest struct {
	MachineIDs []string `json:"machine_ids"` // machine PRIMARY KEYs
	Status     string   `json:"status"`
}

// bulkStatusResult is the per-machine outcome of a bulk status change. Error is a short reason on failure
// (unknown machine, denied for its group, …) so the console can show WHICH machines were skipped and why.
type bulkStatusResult struct {
	MachineID string `json:"machine_id"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// handleBulkSetMachineStatus backs POST /machines/bulk-status: apply one status to MANY machines at once
// (§4 fleet management — quarantine a compromised batch, retire a decommissioned rack). Each machine is
// resolved BY PRIMARY KEY and INDEPENDENTLY gated on CapManageMachines for ITS OWN group, exactly like the
// single-machine handler, so a group-scoped caller can only change machines in the groups they manage —
// out-of-group ids come back as a per-machine `denied`, never a blanket success. The status is validated
// ONCE up front. Partial success is normal: the response is 200 with a per-machine results array; a machine
// that fails resolution/authz/write is skipped, not fatal. An up-front tenant-wide Require gate rejects a
// caller who manages NO machines at all (they cannot reach even the per-machine loop).
func (s *Server) handleBulkSetMachineStatus(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	// The caller must manage machines SOMEWHERE (any group); the per-machine RequireMachine below then
	// narrows to each machine's own group (loop-52 "a tenant-wide Require still owes per-group narrowing").
	if err := p.Grant.Require(CapManageMachines); err != nil {
		writeDenied(w, err)
		return
	}
	var req bulkSetMachineStatusRequest
	// The bulk tier (1 MiB, unchanged): this body carries a LIST of machine ids, capped at 200
	// downstream. See maxBulkJSONBodyBytes.
	if err := decodeJSONBody(w, r, maxBulkJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if !IsValidMachineStatus(req.Status) {
		writeError(w, http.StatusBadRequest, "status must be active, quarantined, or retired")
		return
	}
	if len(req.MachineIDs) == 0 {
		writeError(w, http.StatusBadRequest, "machine_ids must not be empty")
		return
	}
	if len(req.MachineIDs) > maxBulkStatusMachines {
		writeError(w, http.StatusBadRequest, "at most 200 machines per request")
		return
	}
	results := make([]bulkStatusResult, 0, len(req.MachineIDs))
	for _, id := range req.MachineIDs {
		results = append(results, s.applyBulkStatusOne(r, p, id, req.Status))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// applyBulkStatusOne resolves ONE machine, group-scopes CapManageMachines on its real group, sets the status,
// and audits it (machine.status_set with a bulk marker) — mirroring handleSetMachineStatus so a bulk change
// is indistinguishable, per machine, from a single one in the audit trail. Every failure is captured in the
// returned result rather than aborting the batch.
func (s *Server) applyBulkStatusOne(r *http.Request, p *Principal, id, status string) bulkStatusResult {
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, id)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return bulkStatusResult{MachineID: id, OK: false, Error: "unknown machine"}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not resolve machine"}
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "denied"}
	}
	if err := s.Machines.SetMachineStatus(r.Context(), p.TenantID, m.ID, status); err != nil {
		if errors.Is(err, ErrMachineHasActiveDirective) || errors.Is(err, ErrMachineRemoved) {
			return bulkStatusResult{MachineID: id, OK: false, Error: err.Error()}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not set status"}
	}
	// Immediately after the status write, before any early return (see handleSetMachineStatus).
	s.cancelHelpForMachine(r, p.TenantID, m.ID, m.Status, status)
	if err := s.recordMgmtAudit(r, "machine.status_set", "machine", m.ID,
		map[string]any{"status": status, "bulk": true}); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not record audit"}
	}
	// Mirror the single-machine handler: quarantine/retire end any live session immediately.
	if status != MachineStatusActive && s.SessionRecords != nil {
		if reaped, err := s.SessionRecords.EndSessionsForMachine(r.Context(), p.TenantID, m.ID); err != nil {
			return bulkStatusResult{MachineID: id, OK: false, Error: "could not end live sessions"}
		} else if reaped > 0 {
			if aerr := s.recordMgmtAudit(r, "session.reaped", "machine", m.ID,
				map[string]any{"count": reaped, "reason": "machine_" + status, "bulk": true}); aerr != nil {
				log.Printf("machine %s quarantined/retired (bulk) but session.reaped audit failed: %v", m.ID, aerr)
			}
		}
	}
	return bulkStatusResult{MachineID: id, OK: true}
}

// bulkSetMachineGroupRequest is the body of POST /machines/bulk-group.
type bulkSetMachineGroupRequest struct {
	MachineIDs []string `json:"machine_ids"` // machine PRIMARY KEYs
	GroupID    string   `json:"group_id"`    // the shared TARGET group
}

// handleBulkSetMachineGroup backs POST /machines/bulk-group: reassign MANY machines to ONE target group at
// once (§4 fleet — re-org a batch of machines into a group). The single handler's TWO-WAY authz is split for
// the SHARED target: the MOVE-IN half — the caller must manage the TARGET group AND the target must exist — is
// a PRECONDITION checked ONCE up front (it is identical for every machine, so a caller who cannot manage the
// target, or a non-existent target, fails the WHOLE request: 403 / 404). The MOVE-OUT half — manage each
// machine's CURRENT group — is per-machine, so a group-scoped caller only moves machines OUT of groups they
// manage; out-of-scope or unknown ids come back per-machine (`denied` / `unknown machine`), never a blanket
// success. Partial success is normal (200 + per-machine `results`); capped at 200. An up-front tenant-wide
// Require gate rejects a caller who manages NO machines at all.
func (s *Server) handleBulkSetMachineGroup(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil || s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageMachines); err != nil {
		writeDenied(w, err)
		return
	}
	var req bulkSetMachineGroupRequest
	// The bulk tier (1 MiB, unchanged): this body carries a LIST of machine ids, capped at 200
	// downstream. See maxBulkJSONBodyBytes.
	if err := decodeJSONBody(w, r, maxBulkJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	if len(req.MachineIDs) == 0 {
		writeError(w, http.StatusBadRequest, "machine_ids must not be empty")
		return
	}
	if len(req.MachineIDs) > maxBulkStatusMachines {
		writeError(w, http.StatusBadRequest, "at most 200 machines per request")
		return
	}
	// MOVE-IN (shared target), checked ONCE: the caller must manage the target group...
	if err := p.Grant.RequireMachine(CapManageMachines, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// ...and the target must be a real group in this tenant (a clean 404 before the per-machine FK backstop).
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine groups")
		return
	}
	found := false
	for _, g := range groups {
		if g.ID == req.GroupID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "unknown machine group")
		return
	}
	results := make([]bulkStatusResult, 0, len(req.MachineIDs))
	for _, id := range req.MachineIDs {
		results = append(results, s.applyBulkGroupOne(r, p, id, req.GroupID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// applyBulkGroupOne resolves ONE machine, group-scopes CapManageMachines on its CURRENT group (the move-OUT
// half — the move-IN half was checked once up front), reassigns it to groupID, and audits machine.group_changed
// with a bulk marker (so a bulk move is indistinguishable, per machine, from a single one). Every failure is
// captured in the returned result rather than aborting the batch.
func (s *Server) applyBulkGroupOne(r *http.Request, p *Principal, id, groupID string) bulkStatusResult {
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, id)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return bulkStatusResult{MachineID: id, OK: false, Error: "unknown machine"}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not resolve machine"}
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "denied"}
	}
	from := m.GroupID
	if err := s.moveMachineToGroup(r.Context(), p, m.ID, groupID); err != nil {
		if errors.Is(err, ErrGroupTreeChanged) {
			return bulkStatusResult{MachineID: id, OK: false, Error: ErrGroupTreeChanged.Error()}
		}
		if errors.Is(err, ErrInvalidMachineGroup) {
			return bulkStatusResult{MachineID: id, OK: false, Error: "unknown machine group"}
		}
		if errors.Is(err, ErrMachineHasActiveDirective) || errors.Is(err, ErrMachineRemoved) {
			return bulkStatusResult{MachineID: id, OK: false, Error: err.Error()}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not reassign group"}
	}
	if err := s.recordMgmtAudit(r, "machine.group_changed", "machine", m.ID,
		map[string]any{"from": from, "to": groupID, "bulk": true}); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not record audit"}
	}
	return bulkStatusResult{MachineID: id, OK: true}
}

func (s *Server) resolveMachineForProperties(w http.ResponseWriter, r *http.Request, cap Capability) (*Machine, bool) {
	if s.Machines == nil || s.MachineProperties == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return nil, false
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return nil, false
	}
	if err := p.Grant.RequireMachine(cap, m.GroupID); err != nil {
		writeDenied(w, err)
		return nil, false
	}
	return m, true
}

// handleListMachineProperties backs GET /machines/{id}/properties: every custom property on the
// machine, gated on CapViewMachines for the machine's group. Returns {"properties": [...]}.
func (s *Server) handleListMachineProperties(w http.ResponseWriter, r *http.Request) {
	m, ok := s.resolveMachineForProperties(w, r, CapViewMachines)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	props, err := s.MachineProperties.ListProperties(r.Context(), p.TenantID, m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list machine properties")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"properties": props})
}

// setMachinePropertyRequest is the body of PUT /machines/{id}/properties/{key}. The key is the path
// segment; only the value travels in the body.
type setMachinePropertyRequest struct {
	Value string `json:"value"`
}

// handleSetMachineProperty backs PUT /machines/{id}/properties/{key}: idempotent upsert of one
// custom property, gated on CapManageMachines for the machine's group. Returns {"property": {...}}.
func (s *Server) handleSetMachineProperty(w http.ResponseWriter, r *http.Request) {
	m, ok := s.resolveMachineForProperties(w, r, CapManageMachines)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	key := r.PathValue("key") // single path segment, already URL-unescaped by ServeMux
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	if len(key) > maxMachinePropertyKeyLen {
		writeError(w, http.StatusBadRequest, "key is too long")
		return
	}
	var req setMachinePropertyRequest
	// docs/25 F05: one property value, itself capped at maxMachinePropertyValueLen (4 KiB) two checks
	// below — but that check could only run AFTER an unbounded decode had already buffered whatever
	// the client sent, with the tenant connection pinned throughout. The transport bound has to come
	// first; the semantic bound stays where it is.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed set-property request body"); err != nil {
		return
	}
	if len(req.Value) > maxMachinePropertyValueLen {
		writeError(w, http.StatusBadRequest, "value is too long")
		return
	}
	if err := s.MachineProperties.SetProperty(r.Context(), p.TenantID, m.ID, key, req.Value); err != nil {
		// A cross-tenant/unknown machine surfaces here as ErrMachineNotFound (the composite FK), even
		// though the resolve above already 404s it — belt and suspenders on the direct-store path.
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set machine property")
		return
	}
	// Audit the mutation; a recording failure fails the request (handleEnroll pattern): an
	// unauditable mutation must not happen silently.
	if err := s.recordMgmtAudit(r, "machine.property.set", "machine", m.ID,
		map[string]any{"key": key}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"property": MachineProperty{Key: key, Value: req.Value}})
}

// handleDeleteMachineProperty backs DELETE /machines/{id}/properties/{key}: remove one custom
// property, gated on CapManageMachines for the machine's group. Deleting an absent key is a 404.
func (s *Server) handleDeleteMachineProperty(w http.ResponseWriter, r *http.Request) {
	m, ok := s.resolveMachineForProperties(w, r, CapManageMachines)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	if err := s.MachineProperties.DeleteProperty(r.Context(), p.TenantID, m.ID, key); err != nil {
		if errors.Is(err, ErrMachinePropertyNotFound) {
			writeError(w, http.StatusNotFound, "unknown property")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete machine property")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.property.delete", "machine", m.ID,
		map[string]any{"key": key}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "key": key})
}

// enrollRequest is the body of POST /enroll: the target group plus optional identity fields. The
// group is what RBAC scopes against, so it is required.
//
// machine_id here is the agent's DEVICE ID (the stable agent identity), the same identifier the
// mint/start-session paths carry — NOT the database primary key, which the store assigns.
type enrollRequest struct {
	MachineID string `json:"machine_id"` // device id; optional — a fresh one is minted when empty
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
	// OS mirrors redeemEnrollmentRequest.OS: the agent's self-reported OS description, stored as
	// machine.os for the console's inventory column. Display-only, never interpreted.
	OS string `json:"os"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapEnrollMachine); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	var req enrollRequest
	// docs/25 F05. The capability check above already runs first, so an unauthorized caller never
	// reaches this decode at all; the cap bounds what an AUTHORIZED one can make the handler buffer
	// while it holds the pinned tenant connection.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed enroll request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// The capability check above is the tenant-wide form: it proves the caller may enroll SOMEWHERE.
	// The group the machine actually lands in is chosen by the CALLER, so it has to be authorized on
	// its own — otherwise an admin scoped to one group can plant machines into any other group in the
	// tenant (measured before this check existed: 201, row written with the foreign group_id).
	//
	// This is the same check handlePromoteAttended already makes for this very capability
	// (`RequireMachine(CapEnrollMachine, sess.GroupID)`), and that GET /machines/{id} makes against a
	// machine's resolved group. It must run AFTER decoding, because the group is in the body.
	if err := p.Grant.RequireMachine(CapEnrollMachine, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// Same free-text bounds as POST /enroll/redeem. This path is authenticated and capability-gated,
	// so the risk is far lower — but both write the same unbounded `text` columns and are echoed
	// into the same listings, and an asymmetry here is exactly the kind of gap that gets found later
	// and assumed to be deliberate. (`name` was unbounded here before `os` existed.)
	if len(req.Name) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if len(req.OS) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "os is too long")
		return
	}
	deviceID := req.MachineID
	if deviceID == "" {
		deviceID = newUUID()
	}
	// The machine is created into the CALLER'S tenant (RLS/the store pin it); the group comes
	// from the request. The store assigns the primary-key id (populated into m.ID on return);
	// device_id is the agent's stable identity. This legacy authenticated path enrolls WITHOUT
	// a pinned pubkey; installers use POST /enroll/redeem (token + pubkey) instead.
	//
	// A caller-supplied device_id is safe here only because device ids are GLOBALLY unique
	// (migrations/0008): claiming one another tenant already owns conflicts instead of minting a
	// second machine that this tenant could then issue session tickets for.
	m := &Machine{TenantID: p.TenantID, DeviceID: deviceID, GroupID: req.GroupID, Name: req.Name, OS: req.OS}
	if err := s.Machines.EnrollMachine(r.Context(), p.TenantID, m); err != nil {
		if errors.Is(err, ErrMachineDeviceIDTaken) {
			writeError(w, http.StatusConflict, "device_id already enrolled")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not enroll machine")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.enroll", "machine", m.ID,
		map[string]any{"device_id": m.DeviceID, "group_id": m.GroupID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"machine": m})
}

// -------------------------------------------------------------------------------------
// Enrollment tokens (M1)
// -------------------------------------------------------------------------------------

// mintEnrollmentTokenRequest is the body of POST /enrollment-tokens. TTLSeconds and MaxUses
// are optional (defaults: DefaultEnrollmentTokenTTL, single-use).
type mintEnrollmentTokenRequest struct {
	GroupID    string `json:"group_id"`
	TTLSeconds int    `json:"ttl_seconds"`
	MaxUses    int    `json:"max_uses"`
}

func (s *Server) handleMintEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	var req mintEnrollmentTokenRequest
	// docs/25 F05: same shape as handleEnroll — the tenant-wide capability gate above precedes the
	// decode, and the cap bounds the authorized caller's body.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed mint-token request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// SECURITY: the tenant-wide Require above only says the caller may manage enrollment SOMEWHERE.
	// The token plants a machine into req.GroupID, and the machine's group is what every downstream
	// authorization check scopes against (BackstageCapsFor, RequireMachine), so the group named here
	// must itself be covered by the caller's memberships. Without this, a group-scoped Admin could
	// mint a token for a group they have no rights over and then reach the machine that redeems it.
	if err := p.Grant.RequireMachine(CapManageEnrollment, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// The ceiling is compared in SECONDS, before the multiplication — the same shape, and for the
	// same reason, as HandleIssuePasswordReset's. Converting first overflows int64 for ttl_seconds
	// above ~9.2e9 (1e10 s is 1e19 ns against a 9.22e18 ceiling), and the wrapped NEGATIVE duration
	// then passes any `ttl > Max…` test, minting a token whose expires_at is already in the past
	// behind a 201: the caller is told they hold an enrollment secret, and every redemption of it
	// fails. Unbounded-but-positive is the other half — see MaxEnrollmentTokenTTL for what an
	// effectively immortal enrollment secret grants.
	const maxTTLSeconds = int(MaxEnrollmentTokenTTL / time.Second)
	ttl := DefaultEnrollmentTokenTTL
	switch {
	case req.TTLSeconds < 0:
		writeError(w, http.StatusBadRequest, "ttl_seconds must be positive")
		return
	case req.TTLSeconds > maxTTLSeconds:
		writeError(w, http.StatusBadRequest, "ttl_seconds exceeds the maximum enrollment-token lifetime")
		return
	case req.TTLSeconds > 0:
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	// The same two halves as the ttl ceiling above — negative refused, unbounded-but-positive
	// refused — because bounding only the LIFETIME left the sharper quantity open: how many machines
	// one secret plants into the group. See MaxEnrollmentTokenUses.
	//
	// There is no arithmetic to overflow here (the value reaches the store as-is), but the
	// destination is NARROWER than the Go int that carries it: enrollment_token.max_uses is a 32-bit
	// PostgreSQL `int`. Uncapped, a request for 2^31 reached the INSERT with a value the column
	// cannot hold and the driver's range error surfaced as a 500 — measured. The cap is far inside
	// that range, so this answers 400 without asking the database.
	maxUses := defaultEnrollmentMaxUses
	switch {
	case req.MaxUses < 0:
		writeError(w, http.StatusBadRequest, "max_uses must be positive")
		return
	case req.MaxUses > MaxEnrollmentTokenUses:
		writeError(w, http.StatusBadRequest, "max_uses exceeds the maximum enrollment-token use count")
		return
	case req.MaxUses > 0:
		maxUses = req.MaxUses
	}
	tok := &EnrollmentToken{
		GroupID:   req.GroupID,
		CreatedBy: p.UserID,
		ExpiresAt: time.Now().Add(ttl),
		MaxUses:   maxUses,
	}
	plaintext, err := s.EnrollmentTokens.MintToken(r.Context(), p.TenantID, tok)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint enrollment token")
		return
	}
	if err := s.recordMgmtAudit(r, "enrollment_token.mint", "enrollment_token", tok.ID,
		map[string]any{"group_id": tok.GroupID, "max_uses": tok.MaxUses}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// The plaintext is shown ONCE, here; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"token": plaintext, "enrollment_token": tok})
}

func (s *Server) handleListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	all, err := s.EnrollmentTokens.ListTokens(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list enrollment tokens")
		return
	}
	// RLS already scoped the query to the tenant; now, like machine and session listing, confine
	// visibility to the groups the caller's memberships actually cover.
	tokens := make([]EnrollmentToken, 0, len(all))
	for _, t := range all {
		if p.Grant.AllowsInGroup(CapManageEnrollment, t.GroupID) {
			tokens = append(tokens, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollment_tokens": tokens})
}

// findEnrollmentToken resolves one of the tenant's tokens by id. The store deliberately exposes no
// single-token read — a token's only identity-bearing column is its hash, which never leaves the
// database — so this filters the (RLS-scoped) listing. Token counts are per-tenant administrative
// data, not a hot path.
func (s *Server) findEnrollmentToken(r *http.Request, tenantID, id string) (*EnrollmentToken, error) {
	tokens, err := s.EnrollmentTokens.ListTokens(r.Context(), tenantID)
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		if tokens[i].ID == id {
			return &tokens[i], nil
		}
	}
	return nil, ErrEnrollmentTokenNotFound
}

func (s *Server) handleRevokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	id := r.PathValue("id")
	// Resolve the token's REAL group from stored data and gate on THAT, mirroring how the machine
	// handlers resolve a machine's group: a group-scoped admin must not be able to revoke (i.e.
	// disrupt enrollment for) a group they hold no rights over. A token outside the caller's scope
	// is reported as unknown, not as forbidden, so the surface does not confirm its existence.
	tok, err := s.findEnrollmentToken(r, p.TenantID, id)
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenNotFound) {
			writeError(w, http.StatusNotFound, "unknown enrollment token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve enrollment token")
		return
	}
	if !p.Grant.AllowsInGroup(CapManageEnrollment, tok.GroupID) {
		writeError(w, http.StatusNotFound, "unknown enrollment token")
		return
	}
	if err := s.EnrollmentTokens.RevokeToken(r.Context(), p.TenantID, id); err != nil {
		if errors.Is(err, ErrEnrollmentTokenNotFound) {
			writeError(w, http.StatusNotFound, "unknown enrollment token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not revoke enrollment token")
		return
	}
	if err := s.recordMgmtAudit(r, "enrollment_token.revoke", "enrollment_token", id, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "id": id})
}

// redeemEnrollmentRequest is the body of the PUBLIC POST /enroll/redeem: the bearer token plus
// the agent's identity. pubkey (hex-encoded 32-byte Ed25519) is REQUIRED — redemption is what
// pins the agent key.
type redeemEnrollmentRequest struct {
	Token string `json:"token"`
	// DeviceID is DEPRECATED and IGNORED. This endpoint is UNAUTHENTICATED — anyone holding any
	// tenant's enrollment token could otherwise name an arbitrary device id, and the device id is
	// exactly what a session ticket authorizes the signaling server to broker to
	// (server/signaling/ticket.go). The identity is therefore minted server-side and returned in
	// the response; the field is retained only so older installers deserialize cleanly.
	DeviceID string `json:"device_id"`
	Pubkey   string `json:"pubkey"`
	Name     string `json:"name"`
	// OS is the agent's self-reported OS description, stored as machine.os (migrations/0017) for
	// the console's inventory column. Display-only: nothing authorizes on it, and it is attacker-
	// controlled on this UNAUTHENTICATED endpoint, so it is length-bounded like Name and never
	// interpreted.
	OS string `json:"os"`
	// RequireSessionPolicy is the agent's self-reported `require_session_policy` config flag
	// (crates/agent-windows/src/config.rs), stored as machine.require_session_policy
	// (migrations/0037). Set means the agent opens every session VIEW-ONLY until a signed access
	// policy verifies, so the control plane must mint one for it even when its group has no mandate
	// — otherwise that agent is stranded view-only forever.
	//
	// Attacker-controlled on this UNAUTHENTICATED endpoint, like OS, and safe for the same kind of
	// reason but a sharper one: the ONLY thing it can do is cause a policy to be minted for the
	// machine the redeemer just created. It cannot suppress a mandate (an enforcing group still
	// mints view_only regardless of this bit) and it cannot reach any other machine. Setting it
	// falsely only makes your own agent receive a policy it will ignore.
	//
	// A POINTER so that ABSENT and FALSE are distinguishable: an older installer that does not send
	// the key must not be read as "the operator turned it off". Absent leaves the column at its
	// migration DEFAULT false, which is the same value, but the distinction is what keeps the
	// re-enroll path honest and mirrors the *bool convention on the attended redeem wire.
	RequireSessionPolicy *bool `json:"require_session_policy"`
}

// maxRedeemBodyBytes caps the UNAUTHENTICATED redeem body, matching HandleLogin's cap on the other
// public endpoint. Without it a single unauthenticated request can make the process buffer an
// arbitrary amount of memory before any credential is checked.
const maxRedeemBodyBytes = 1 << 16

// maxMachineNameLen bounds the free-text display name a redeemer supplies. It is stored verbatim
// (machine.hostname) and echoed back into listings and audit metadata, so it is bounded here rather
// than left to the database's unbounded `text`.
const maxMachineNameLen = 255

// enrollTombstoneDeadline bounds the enroll door's key-tombstone read. Enrollment has no timing floor, so this is
// a plain availability bound, not part of a response schedule.
const enrollTombstoneDeadline = 2 * time.Second

// handleRedeemEnrollment is UNAUTHENTICATED (mounted on the root mux): the enrollment token is
// the authorization. It resolves tenant + group through the atomic SECURITY DEFINER redeem,
// creates the machine tenant-pinned, and pins the agent's Ed25519 public key. Every invalid
// token — unknown, revoked, expired, exhausted — is the same generic 403, so a caller probing
// the endpoint learns nothing about which check failed.
func (s *Server) handleRedeemEnrollment(w http.ResponseWriter, r *http.Request) {
	var req redeemEnrollmentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRedeemBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed redeem request body: "+err.Error())
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if len(req.Name) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if len(req.OS) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "os is too long")
		return
	}
	pub, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "pubkey must be a hex-encoded 32-byte Ed25519 public key")
		return
	}
	// Token guessing is metered per source (there is no account to key on here). Malformed
	// requests above cost no budget — only a real token check does.
	th := s.throttle()
	keys := []string{ipKey("redeem", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	// docs/65 D-C9: an agent key that was pinned on a REMOVED machine is a tombstone. It cannot be enrolled
	// again (a re-install generates a NEW key and enrolls as a NEW machine). Checked before the token is
	// consumed so a refused install does not burn a use.
	// Bounded like the redeem door's check (docs/66 release gate R1): it runs on the anonymous lookup pool, and a
	// slow database must not hold an unauthenticated request there for as long as the client keeps it open.
	tombCtx, cancelTomb := context.WithTimeout(r.Context(), enrollTombstoneDeadline)
	tombstoned, terr := s.Machines.KeyTombstoned(tombCtx, hex.EncodeToString(pub))
	cancelTomb()
	if terr != nil {
		writeError(w, http.StatusInternalServerError, "could not check the agent identity")
		return
	} else if tombstoned {
		writeError(w, http.StatusForbidden, "this agent identity was removed; reinstall to create a new one")
		return
	}
	tok, err := s.EnrollmentTokens.RedeemToken(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenInvalid) {
			th.Fail(keys...)
			writeError(w, http.StatusForbidden, "invalid enrollment token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem enrollment token")
		return
	}
	th.Reset(keys...)
	// SECURITY: the device id is minted SERVER-SIDE, never taken from req.DeviceID. A redeemer who
	// could choose it would be choosing which agent the tenant's session tickets authorize
	// brokering to — see the redeemEnrollmentRequest doc and migrations/0008.
	deviceID := newUUID()
	// Tenant + group come from the REDEEMED TOKEN, never the request; the store pins the
	// tenant itself (this path has no request binder). Normalize the pubkey through the
	// decode so mixed-case hex stores canonically.
	m := &Machine{
		TenantID: tok.TenantID,
		DeviceID: deviceID,
		GroupID:  tok.GroupID,
		Name:     req.Name,
		OS:       req.OS,
		Pubkey:   hex.EncodeToString(pub),
		// Absent means false, which is also the column DEFAULT — but read it through the pointer
		// rather than relying on the zero value, so that an installer which sends `false` and one
		// which sends nothing are handled by the same line rather than by accident.
		RequireSessionPolicy: req.RequireSessionPolicy != nil && *req.RequireSessionPolicy,
	}
	if err := s.Machines.EnrollMachine(r.Context(), tok.TenantID, m); err != nil {
		// A conflict is now only reachable through a uuid collision (the device id is minted
		// here). It stays mapped rather than surfacing as a 500, and the redeemed use stays
		// consumed — this endpoint is unauthenticated, so a failure never hands the use back.
		if errors.Is(err, ErrMachineDeviceIDTaken) {
			writeError(w, http.StatusConflict, "device_id already enrolled")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not enroll machine")
		return
	}
	// Audited with an EMPTY actor: there is no authenticated principal here (recordMgmtAudit
	// needs one, so record directly). A recording failure still fails the request.
	if s.MgmtAudit != nil {
		meta, err := json.Marshal(map[string]any{"token_id": tok.ID, "device_id": m.DeviceID})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
		if err := s.MgmtAudit.RecordEvent(r.Context(), tok.TenantID, &MgmtAuditEvent{
			Action: "machine.enroll", TargetKind: "machine", TargetID: m.ID, Metadata: meta,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	resp := map[string]any{"machine": m}
	if s.DirectiveIssuer != nil {
		// The agent pins this into its ACL-protected config (docs/65 D-C3); an agent without a pinned
		// directive key refuses every directive.
		resp["directive_pubkey"] = s.DirectiveIssuer.PublicKeyHex()
	}
	writeJSON(w, http.StatusCreated, resp)
}

// -------------------------------------------------------------------------------------
// Device identity (M3) — docs/11-agent-identity-contract.md §4.1
// -------------------------------------------------------------------------------------

// deviceIdentityAuthorized reports whether the request carries the configured service token.
// Constant-time so the token cannot be recovered a byte at a time from response latency.
func (s *Server) deviceIdentityAuthorized(r *http.Request) bool {
	want := s.DeviceIdentityToken
	if len(want) < DeviceIdentityTokenMinLen {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}

// handleDeviceIdentity answers GET /internal/devices/{device_id}/identity for the signaling
// server: the tenant + pinned Ed25519 public key for a device id, so signaling can verify that a
// connection claiming that device id holds the enrolled private key.
//
// Posture, all deliberate:
//   - Service-token auth (constant-time), never a tenant principal — the lookup is cross-tenant and
//     signaling belongs to no tenant. The route is not even mounted without the token.
//   - Unknown device and enrolled-but-unpinned are the SAME 404, so the response never distinguishes
//     "no such machine" from "machine I cannot authenticate".
//   - Metered per source like /enroll/redeem, so a token-guessing or id-probing run backs off.
//   - NOT recorded in the management audit trail. This is a read on a hot path — every agent
//     reconnect — and auditing it would drown the trail that exists to record human actions.
func (s *Server) handleDeviceIdentity(w http.ResponseWriter, r *http.Request) {
	th := s.throttle()
	keys := []string{ipKey("device-identity", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := s.Machines.LookupDeviceIdentity(r.Context(), r.PathValue("device_id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			// DELIBERATELY NOT th.Fail — this was a live, unauthenticated, fleet-wide denial of
			// service, and the reasoning is worth keeping because the call looks symmetric with the
			// 401 above.
			//
			// The key is `clientIP(r)`, and this is an INTERNAL route: the client is always the
			// signaling container. So it is not a per-attacker key, it is the ONE key every
			// legitimate agent registration in every tenant shares.
			//
			// Signaling resolves a device identity BEFORE it verifies the caller's Ed25519
			// signature, so an anonymous WebSocket can make it look up arbitrary device ids. Each
			// miss lands here. Five failures lock the key for 15 minutes, every further miss re-arms
			// it, and `th.Reset` below only runs on a success that can no longer happen — so one
			// unauthenticated peer could stop every agent everywhere from registering, indefinitely.
			//
			// The 401 arm SHOULD fail: that is someone guessing the service token, and locking them
			// out is exactly the point. This arm must not, because the caller has already PROVEN it
			// holds the token — a 404 only means "that device is not enrolled", which is an ordinary
			// answer during an enrollment race or for a machine that was removed. The sibling route
			// takes the same shape: `ErrTicketAlreadyRedeemed` returns 409 without failing.
			//
			// docs/23, the first internet-facing audit. CRITICAL.
			writeError(w, http.StatusNotFound, "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve device identity")
		return
	}
	// docs/65 D-C1: a RETIRED machine resolves ONLY for a caller that asked for the restricted mode
	// (directives and acknowledgements, never presence or brokering). A signaling that predates this feature
	// does not ask, so it keeps refusing retired machines exactly as before its upgrade.
	if id.Status == MachineStatusRetired && r.URL.Query().Get("restricted") != "1" {
		th.Reset(keys...)
		writeError(w, http.StatusNotFound, "unknown device")
		return
	}
	th.Reset(keys...)
	writeJSON(w, http.StatusOK, id)
}

// -------------------------------------------------------------------------------------
// Session-ticket redemption — the shared single-use ledger (ticketredemption.go)
// -------------------------------------------------------------------------------------

// sessionTicketRedeemRequest is the body of POST /internal/session-tickets/redeem: the identifying
// claims of a session ticket the SIGNALING SERVER HAS ALREADY VERIFIED. Nothing here is a
// credential — signature, version, expiry, tenant binding and device binding were all checked by
// the caller before it asked, and this endpoint's own authorization is the service token.
type sessionTicketRedeemRequest struct {
	TenantID    string `json:"tenant_id"`
	SessionID   string `json:"session_id"`
	DeviceID    string `json:"device_id"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
}

// sessionTicketRedemptionMaxTTL caps how far in the future a redemption row may be dated. See the
// clamp in handleRedeemSessionTicket for why the caller's number is not simply trusted.
const sessionTicketRedemptionMaxTTL = time.Hour

// handleRedeemSessionTicket answers POST /internal/session-tickets/redeem for the signaling server:
// record this ticket's single use, and say whether it was NEW.
//
//	200 {"redeemed": true}  — first use; the caller may broker.
//	409                     — DEFINITIVE replay; the caller must refuse.
//	anything else           — the ledger could not answer. The caller proceeds on its LOCAL verdict
//	                          and logs loudly (server/signaling/ticketredeem.go documents why).
//
// Posture, deliberately parallel to handleDeviceIdentity above:
//   - Service-token auth (constant-time), never a tenant principal — the ledger is cross-tenant and
//     signaling belongs to no tenant. The route is not even mounted without the token.
//   - Metered per source, so token guessing runs into the same exponential backoff. But a 409 is
//     NOT metered, and that exception is load-bearing: an attacker replaying one captured ticket in
//     a loop would otherwise lock out the signaling server's own IP, and every subsequent
//     redemption would fail open — turning the defence's own rate limiter into the switch that
//     disables it. Only a failed AUTH counts against the source.
//   - NOT recorded in the management audit trail. This fires once per brokered session, on the
//     interactive path, and would drown the trail that exists to record human actions.
func (s *Server) handleRedeemSessionTicket(w http.ResponseWriter, r *http.Request) {
	th := s.throttle()
	keys := []string{ipKey("ticket-redeem", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.TicketRedemptions == nil {
		// Unreachable through Handler() (the route is mounted only when the store is wired), kept
		// because a 500 is the honest answer if that ever stops being true — never a silent 200,
		// which would claim a ticket had been recorded when nothing was.
		writeError(w, http.StatusInternalServerError, "ticket redemption store not configured")
		return
	}
	var req sessionTicketRedeemRequest
	if err := decodeJSONBodyDetailed(w, r, maxRedeemBodyBytes, &req, "malformed redeem request body"); err != nil {
		return
	}
	if req.TenantID == "" || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id and session_id are required")
		return
	}

	// The row's expiry is the TICKET's own exp_ms: that is exactly how long remembering the
	// redemption is worth anything, because from then on verifyTicket refuses the ticket unaided.
	// It is CLAMPED rather than trusted — the caller is authenticated by a shared service token
	// alone, so a compromised or simply buggy one could otherwise date rows years out and pin them
	// past every reap. The ceiling is generous next to the 2-minute sessionTicketTTL, so ordinary
	// clock skew between the two hosts can never shorten a live ticket's entry.
	expiresAt := time.Now().Add(sessionTicketRedemptionMaxTTL)
	if req.ExpiresAtMs > 0 {
		if claimed := time.UnixMilli(req.ExpiresAtMs); claimed.Before(expiresAt) {
			expiresAt = claimed
		}
	}

	if _, err := s.TicketRedemptions.RedeemTicket(r.Context(), req.TenantID, req.SessionID, req.DeviceID, expiresAt); err != nil {
		if errors.Is(err, ErrTicketAlreadyRedeemed) {
			// The one answer the caller acts on. Distinguishable ON PURPOSE — a generic error here
			// would be indistinguishable from an outage and would therefore be ignored.
			writeError(w, http.StatusConflict, ErrTicketAlreadyRedeemed.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem session ticket")
		return
	}
	th.Reset(keys...)
	writeJSON(w, http.StatusOK, map[string]any{"redeemed": true})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return
	}
	all, err := s.SessionRecords.ListSessions(r.Context(), p.TenantID, SessionSummaryFilter{Since: since, Until: until})
	if err != nil {
		writeListError(w, err, "could not list sessions")
		return
	}
	// RLS already scoped to the tenant; now, like machine listing, confine visibility to the
	// machine groups the caller's memberships actually cover.
	visible := make([]SessionRecord, 0, len(all))
	for _, rec := range all {
		if p.Grant.AllowsInGroup(CapViewSessions, rec.MachineGroupID) {
			visible = append(visible, rec)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": s.withRecordingIDs(r.Context(), p, visible)})
}

// sessionListRow is a session record plus, when the CALLER may know of it, the id of the session's central recording.
type sessionListRow struct {
	SessionRecord
	RecordingID string `json:"recording_id,omitempty"`
}

// withRecordingIDs adds `recording_id` to the rows whose machine group the caller holds CapViewRecordings over (docs/63
// C8 scope: the machine's CURRENT group, the same AllowsInGroup the recordings routes use). The existence of a recording
// is information, so for a caller without that capability on that group the field is simply absent: not null, not
// false. API tokens never get it (they cannot hold view_recordings), nor does a deployment whose recording routes are
// not mounted. A lookup failure omits the field; it never fails the session list.
func (s *Server) withRecordingIDs(ctx context.Context, p *Principal, rows []SessionRecord) []sessionListRow {
	out := make([]sessionListRow, len(rows))
	for i := range rows {
		out[i].SessionRecord = rows[i]
	}
	if p.APIToken || s.Recording.Store == nil || !s.Recording.ready() || s.MgmtAudit == nil || s.Machines == nil || len(rows) > RecIDsBySessionMax {
		return out
	}
	if p.Grant.Require(CapViewRecordings) != nil {
		return out
	}
	// Rule 4 of the recording routes: the machine's CURRENT group, not the session-time
	// MachineGroupID, so a machine moved out of scope (or deleted) hides its recording ids too.
	var ids []string
	allowed := make(map[string]bool, len(rows))
	groups := map[string]string{}
	for i := range rows {
		ok, err := s.recMachineAllowed(ctx, p, rows[i].MachineID, groups)
		if err != nil {
			log.Printf("session list: recording scope: %v", err)
			return out
		}
		if ok {
			allowed[rows[i].ID] = true
			ids = append(ids, rows[i].ID)
		}
	}
	if len(ids) == 0 {
		return out
	}
	byID, err := s.Recording.Store.RecordingIDsBySession(ctx, p.TenantID, ids)
	if err != nil {
		log.Printf("session list: recording ids: %v", err)
		return out
	}
	for i := range out {
		if rid, ok := byID[rows[i].ID]; ok && allowed[rows[i].ID] {
			out[i].RecordingID = rid
		}
	}
	return out
}

// startSessionRequest is the body of POST /sessions: the target machine to open a session on.
// machine_id is the agent's DEVICE ID (same identifier as the mint path), resolved via GetMachine.
type startSessionRequest struct {
	MachineID string `json:"machine_id"`
	// omitempty: Go callers (tests, tools) that leave Access unset send no field, which means control.
	// A PRESENT empty string is still refused by startSessionAccess.UnmarshalJSON.
	Access startSessionAccess `json:"access,omitempty"`
}

// compensationContext is for compensating writes that undo a partial success after a later failure.
// It inherits neither the request's cancellation nor its pinned connection: a client disconnect
// cancels r.Context() and closes that connection. The timeout bounds how long compensation can
// hold the handler. Callers must cancel the context immediately after the compensating write.
func compensationContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(withoutBoundConn(context.WithoutCancel(r.Context())), 10*time.Second)
}

func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	var req startSessionRequest
	// docs/25 F05, and the endpoint the external review actually reproduced against. The decode still
	// runs BEFORE authorization, deliberately: the capability enforced here is group-scoped
	// (RequireMachine against the group the STORE says the target machine belongs to), and the target
	// is named in the body — there is nothing to authorize until the body has been read. What the
	// review demonstrated, a read-only principal forcing a >1 MiB buffer before its 403, is closed by
	// the bound instead: the most any caller can now make this handler buffer is 64 KiB, held against
	// the pinned tenant connection for at most the server's ReadTimeout. A tenant-wide
	// Require(CapStartSession) pre-check would refuse a read-only caller before the read entirely, but
	// that is a change to the authorization model rather than to the body bound, and is not made here.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed start-session request body"); err != nil {
		return
	}
	if req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	if req.Access == "" {
		req.Access = "control"
	}
	// Resolve the target machine's REAL group from the store, then gate StartSession on THAT
	// group — not on anything the caller supplied.
	m, err := s.Machines.GetMachine(r.Context(), p.TenantID, req.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	adm, refusal := s.resolveSessionAdmission(r.Context(), p.TenantID, p.UserID, p.Grant, m, string(req.Access))
	if refusal != nil {
		refusal.write(w)
		return
	}
	rec, limits, groupPolicy := adm.Rec, adm.Limits, adm.GroupPolicy
	rec.SourceIP = sourceIPFrom(r.Context()) // session_record.source_ip: where the technician started it from
	s.reapBeforeSessionStart(r, p, adm)
	// Issuance guard (issuance_guard.go), held from BEFORE the session record exists until return: a
	// refusal must not leave an open record holding a concurrency seat (a leaked seat counts against
	// max_concurrent_sessions until reaped). Lock order matches the suspension's: issuance key first,
	// then the audit chain written below.
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	if err := s.SessionRecords.StartSessionWithinLimit(r.Context(), p.TenantID, rec, limits); err != nil {
		writeStartAdmissionError(w, err)
		return
	}
	// Any failure after admission must release the observer slot as well as its seats.
	// Existing explicit EndSession on mint failure remains harmlessly idempotent.
	startDelivered := false
	defer func() {
		if !startDelivered {
			ctx, cancel := compensationContext(r)
			_, err := s.SessionRecords.EndSession(ctx, p.TenantID, rec.ID, time.Now().UTC())
			cancel()
			if err != nil {
				log.Printf("session %s: could not close failed start: %v", rec.ID, err)
			}
		}
	}()
	if err := s.recordMgmtAudit(r, "session.start", "session", rec.ID,
		// agent_version: docs/49's measurement keys each session to the agent build that served it
		// (its last reported identity), so leak and end-reason rates can be compared per release.
		map[string]any{"machine_id": m.ID, "device_id": m.DeviceID, "access": rec.Access, "agent_version": m.AgentVersion}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	resp, brokerRefusal := s.brokerSessionStart(rec, m, p.UserID, p.TenantID, groupPolicy)
	if brokerRefusal != nil {
		// The deferred compensation above ends the record just created, so a refusal never strands a seat.
		brokerRefusal.write(w)
		return
	}
	startDelivered = true
	writeJSON(w, http.StatusCreated, resp)
}

// handleEndSession stamps ended_at on a session (POST /sessions/{id}/end). The session's
// machine group — resolved from the STORED record, never the caller — scopes the EndSession
// capability, mirroring how start/mint resolve the machine's real group.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	rec, err := s.SessionRecords.GetSession(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrSessionRecordNotFound) {
			writeError(w, http.StatusNotFound, "unknown session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve session")
		return
	}
	if err := p.Grant.RequireMachine(CapEndSession, rec.MachineGroupID); err != nil {
		writeDenied(w, err)
		return
	}
	ended, err := s.SessionRecords.EndSession(r.Context(), p.TenantID, rec.ID, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not end session")
		return
	}
	if err := s.recordMgmtAudit(r, "session.end", "session", ended.ID,
		map[string]any{"machine_id": ended.MachineID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": ended})
}

// maxSessionNoteRunes bounds a session note. Generous for a handoff note yet small enough that the
// column and the audit log stay sane; enforced by rune count so multi-byte text is not mis-measured.
const maxSessionNoteRunes = 4000

// setSessionNoteRequest is the body of PATCH /sessions/{id}/note. An absent/empty note clears it.
type setSessionNoteRequest struct {
	Note string `json:"note"`
}

// normalizeSessionNote validates a free-text session note: it caps the length and rejects control
// characters other than tab / newline / carriage-return. NUL cannot live in a Postgres text column,
// and the other C0 controls have no place in a human note and could garble a console that renders it.
// The note is otherwise returned verbatim (no trimming) so it round-trips exactly as typed.
func normalizeSessionNote(note string) (string, error) {
	if len([]rune(note)) > maxSessionNoteRunes {
		return "", errors.New("note must be at most 4000 characters")
	}
	for _, r := range note {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", errors.New("note contains a control character")
		}
	}
	return note, nil
}

// handleSetSessionNote (PATCH /sessions/{id}/note) overwrites a session's free-text operator note
// (docs/01 §7). Gated exactly like ending a session — CapEndSession for the session's machine group
// (a session-MANAGEMENT write, so a read-only viewer who can see the session still cannot annotate it),
// resolved from the STORED session row so group scope cannot be spoofed. The note CONTENT is not put in
// the audit metadata (it may be sensitive); the event records only that a note was set.
func (s *Server) handleSetSessionNote(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	rec, err := s.SessionRecords.GetSession(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrSessionRecordNotFound) {
			writeError(w, http.StatusNotFound, "unknown session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve session")
		return
	}
	if err := p.Grant.RequireMachine(CapEndSession, rec.MachineGroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setSessionNoteRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	note, err := normalizeSessionNote(req.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.SessionRecords.SetSessionNote(r.Context(), p.TenantID, rec.ID, note)
	if err != nil {
		if errors.Is(err, ErrSessionRecordNotFound) {
			writeError(w, http.StatusNotFound, "unknown session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set session note")
		return
	}
	if err := s.recordMgmtAudit(r, "session.note_set", "session", updated.ID,
		map[string]any{"machine_id": updated.MachineID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": updated})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}
	limit := 0 // 0 → store default
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = min(n, 1000)
	}
	// Optional filters (docs/01 §5): ?action= and ?target_kind= are exact-match; ?actor= restricts to
	// one actor_user_id; ?since=/?until= (RFC3339) bound a CLOSED time range [since, until]. All are
	// applied BEFORE the limit, so `limit` bounds the MATCHING events. This lets an auditor pull "every
	// machine.enroll by user X between two timestamps" — the SOC2/HIPAA review query.
	filter, ok := parseAuditFilter(w, r)
	if !ok {
		return
	}
	// ?cursor= continues a previous listing (the next_cursor of a truncated scoped answer, or the
	// position of any event); it is an exact composite position, not a timestamp.
	if v := r.URL.Query().Get("cursor"); v != "" {
		c, derr := decodeAuditCursor(v)
		if derr != nil {
			writeError(w, http.StatusBadRequest, "cursor is malformed")
			return
		}
		filter.Before = c
	}
	var events []MgmtAuditEvent
	var cut *AuditCursor
	var err error
	if scope, _ := p.Grant.ScopeFor(CapViewAudit); scope.All {
		events, err = s.MgmtAudit.ListEventsFiltered(r.Context(), p.TenantID, limit, filter)
	} else {
		// A group-scoped holder sees only events attributable to machines/groups in their scope
		// (http_mgmtaudit_scope.go); fail closed if a lookup errors.
		events, cut, err = s.newMgmtAuditScoper(p).listScoped(r.Context(), limit, filter)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list audit events")
		return
	}
	if events == nil {
		events = []MgmtAuditEvent{}
	}
	resp := map[string]any{"events": events}
	if cut != nil {
		// The scan cap was reached before the trail was exhausted: say so, and say where to resume.
		resp["truncated"] = true
		resp["next_cursor"] = encodeAuditCursor(cut)
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseAuditFilter reads the shared ?action=/?target_kind=/?actor=/?since=/?until= query params into an
// AuditFilter (docs/01 §5). On a malformed since/until it writes a 400 and returns ok=false — the caller
// must return. Shared by GET /audit (list) and GET /audit/summary (Reports).
// parseSinceUntil parses the optional ?since=/?until= RFC3339 query params into a CLOSED [since, until]
// instant range (a zero time = "no bound" on that side). Returns ok=false after writing a 400 if either is
// malformed. Shared by the audit filter and the session-activity reports so both accept the same range syntax.
func parseSinceUntil(w http.ResponseWriter, r *http.Request) (since, until time.Time, ok bool) {
	if v := strings.TrimSpace(r.URL.Query().Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC3339 timestamp")
			return time.Time{}, time.Time{}, false
		}
		since = t
	}
	if v := strings.TrimSpace(r.URL.Query().Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be an RFC3339 timestamp")
			return time.Time{}, time.Time{}, false
		}
		until = t
	}
	return since, until, true
}

func parseAuditFilter(w http.ResponseWriter, r *http.Request) (AuditFilter, bool) {
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return AuditFilter{}, false
	}
	return AuditFilter{
		Action:     strings.TrimSpace(r.URL.Query().Get("action")),
		TargetKind: strings.TrimSpace(r.URL.Query().Get("target_kind")),
		Actor:      strings.TrimSpace(r.URL.Query().Get("actor")),
		Since:      since,
		Until:      until,
	}, true
}

// handleAuditSummary (GET /audit/summary) returns per-action event counts for the §5 Reports view — an
// aggregation of the SAME tenant-scoped, CapViewAudit-gated audit trail GET /audit reads, over the same
// optional ?actor=/?target_kind=/?since=/?until= filter (no ?action= is expected — the summary GROUPS by
// action — though a set ?action= simply narrows to that one action's count).
func (s *Server) handleAuditSummary(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}
	filter, ok := parseAuditFilter(w, r)
	if !ok {
		return
	}
	var summary []AuditActionCount
	var partial bool
	var err error
	if scope, _ := p.Grant.ScopeFor(CapViewAudit); scope.All {
		summary, err = s.MgmtAudit.SummarizeByAction(r.Context(), p.TenantID, filter)
	} else {
		summary, partial, err = s.newMgmtAuditScoper(p).summarizeScoped(r.Context(), filter)
	}
	if err != nil {
		writeListError(w, err, "could not summarize audit")
		return
	}
	if summary == nil {
		summary = []AuditActionCount{}
	}
	resp := map[string]any{"summary": summary}
	if partial {
		// The scoped scan cap cut the walk short: these counts are a lower bound, not the total.
		resp["partial"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReportSessionsByMachine (GET /reports/sessions-by-machine) returns per-machine session counts
// for the §5 Reports view — an aggregation of the SAME tenant-scoped, CapViewSessions-gated session
// records GET /sessions reads. RLS pins the tenant; then, exactly like the session list, the rows are
// confined to the machine groups the caller's memberships cover (a tenant-wide Require(cap) still owes
// the per-group narrowing).
func (s *Server) handleReportSessionsByMachine(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return
	}
	all, err := s.SessionRecords.SummarizeByMachine(r.Context(), p.TenantID, SessionSummaryFilter{Since: since, Until: until})
	if err != nil {
		writeListError(w, err, "could not summarize sessions")
		return
	}
	visible := make([]MachineSessionCount, 0, len(all))
	for _, c := range all {
		if p.Grant.AllowsInGroup(CapViewSessions, c.MachineGroupID) {
			visible = append(visible, c)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions_by_machine": visible})
}

// handleReportSessionsByTechnician (GET /reports/sessions-by-technician) returns per-technician session
// counts + total time for the §5 Reports view. Like the by-machine report it is gated CapViewSessions and
// RLS-pinned to the tenant, but because a technician's sessions span multiple machine groups, the store
// returns per-(technician, group) sub-counts and the NARROWING happens BEFORE aggregation: rows in groups
// the caller cannot view are dropped, then the survivors are summed per technician (a scoped viewer must
// never see a technician's totals from groups outside their scope). The result is sorted most sessions
// first, ties by technician id. The technician is returned by id; the console resolves the label.
func (s *Server) handleReportSessionsByTechnician(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return
	}
	sub, err := s.SessionRecords.SummarizeByTechnician(r.Context(), p.TenantID, SessionSummaryFilter{Since: since, Until: until})
	if err != nil {
		writeListError(w, err, "could not summarize sessions")
		return
	}
	// Narrow FIRST (drop groups the caller cannot view), THEN aggregate per technician.
	byTech := make(map[string]*TechnicianSessionCount)
	order := make([]string, 0)
	for _, c := range sub {
		if !p.Grant.AllowsInGroup(CapViewSessions, c.MachineGroupID) {
			continue
		}
		t, ok := byTech[c.TechnicianID]
		if !ok {
			t = &TechnicianSessionCount{TechnicianID: c.TechnicianID}
			byTech[c.TechnicianID] = t
			order = append(order, c.TechnicianID)
		}
		t.Count += c.Count
		t.TotalSeconds += c.TotalSeconds
	}
	out := make([]TechnicianSessionCount, 0, len(byTech))
	for _, id := range order {
		out = append(out, *byTech[id])
	}
	// Most sessions first; ties by technician id (byte order) for a stable, deterministic result.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].TechnicianID < out[j].TechnicianID
	})
	writeJSON(w, http.StatusOK, map[string]any{"sessions_by_technician": out})
}

// -------------------------------------------------------------------------------------
// Backstage grant minting (H1b)
// -------------------------------------------------------------------------------------

// mintGrantRequest is the body of POST /grant/mint: the target machine, plus an optional session
// id (generated when absent).
type mintGrantRequest struct {
	// MachineID is the agent's DEVICE ID (the stable agent identity the console mints for and H3
	// binds the grant to) — NOT the database primary key. It is resolved via GetMachine (device id).
	MachineID string `json:"machine_id"`
	// MachineGroupID is DEPRECATED and IGNORED as of D1. It used to carry the machine's group
	// from the (untrusted) request body, which let a caller pick whichever group granted them the
	// widest backstage tier. The group is now resolved from the stored machine row instead. The
	// field is retained only so older clients that still send it deserialize cleanly; its value
	// has no effect on authorization.
	MachineGroupID string `json:"machine_group_id"`
	// SessionID is optional; a fresh UUID is minted when empty.
	SessionID string `json:"session_id"`
}

// refuseOutOfServiceMachine writes a 409 and returns true when `m` is administratively out of
// service — the operator's "stop using this box" switch. `verb` completes the sentence "reactivate
// it to <verb>".
//
// ONE function because there are now FOUR endpoints that hand a technician privilege against a
// named machine — handleStartSession, handleMintGrant, handleMintElevation and (since docs/25 F03)
// handleRenewSessionPolicy, which is the one that KEEPS privilege rather than granting it — and loop 88 found
// them disagreeing: the status refusal had been written twice and the third site had never had it,
// so quarantining a machine mid-incident stopped new sessions and elevation grants while a BACKSTAGE
// grant (strictly more capability, and a longer TTL) could still be minted against the same box on
// the session already open. That is this project's `defence-built-but-not-applied` lesson exactly:
// a new guard's call sites must be diffed against its siblings. Route the fourth one through here.
//
// READ WHAT THIS DOES AND DOES NOT BUY, because the first version of this comment over-claimed and
// the answer has since CHANGED — in one direction only, so read both halves.
//
// What it always bought: no new signed, audited authorization is ISSUED against a machine the
// operator has pulled out of service, so the audit trail cannot show privilege being granted on a box
// that was administratively closed, and every path a policy could later be attached to refuses.
//
// What it did NOT buy, and still does not on an UNLEASED session: quarantine does not end a session
// already open. That session keeps arbitrary SYSTEM command execution, tool launch, reboot and
// shutdown, all ungated on the plain Control channel (see `rmt_agent::elevation`'s "what this gate
// IS — and, precisely, what it is not"). An unleased session is one the agent cannot have revoked:
// dev/LAN (signaling vouches for no control-plane session), attended (revoked by its own three-second
// status poll instead), or an agent with no `grant_issuer_pubkey` pinned to verify a lease with.
//
// What it buys SINCE docs/25 F03: on a LEASED session the fifth call site — handleRenewSessionPolicy
// — makes this refusal terminate the live session. The agent holds no authority beyond its current
// lease, the renewal is refused here, and the session tears itself down within one
// sessionPolicyLeaseTTL. Quarantine finally contains rather than merely closes the door behind it.
func refuseOutOfServiceMachine(w http.ResponseWriter, m *Machine, verb string) bool {
	if msg := outOfServiceMachineMsg(m, verb); msg != "" {
		writeError(w, http.StatusConflict, msg)
		return true
	}
	return false
}

// handleMintGrant mints a short-TTL, signed backstage grant for the authenticated technician. It
// runs behind the auth → tenant (RLS) chain, resolves the technician's backstage capabilities for
// the target machine's group (BackstageCapsFor — mandatory CapBackstageShell, admin tier gated on
// CapManageMachines), signs the canonical claims with the issuer key, and returns the SignedGrant
// JSON the browser forwards to the agent via Control::InstallGrant.
func (s *Server) handleMintGrant(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	var req mintGrantRequest
	// docs/25 F05. As at handleStartSession the decode precedes authorization and has to: the tier
	// this route grants is computed by BackstageCapsFor against the group the STORE resolves for
	// req.MachineID, so the body is the input to the authorization decision. The cap is what bounds
	// an unauthorized caller's cost here.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed mint request body"); err != nil {
		return
	}
	if req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}

	// D1 SECURITY FIX: resolve the machine's group from stored data, NOT from req.MachineGroupID
	// (which is ignored). Authorization — BackstageCapsFor — is then scoped to the machine's REAL
	// group, so a caller can no longer name a group to widen their capability tier.
	m, err := s.Machines.GetMachine(r.Context(), p.TenantID, req.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}

	caps, ok := BackstageCapsFor(p.Grant, m.GroupID)
	if !ok {
		writeDenied(w, &DeniedError{Capability: CapBackstageShell, GroupID: m.GroupID})
		return
	}
	// AFTER the capability check, so an unauthorized caller learns nothing about the machine's
	// administrative state (the same ordering the elevation mint uses). Added in loop 88: this was
	// the one privilege-issuing endpoint the operator's quarantine switch did not reach, which made
	// the switch bypassable by minting a backstage grant instead of an elevation one.
	if refuseOutOfServiceMachine(w, m, "use Under the Hood tools") {
		return
	}
	// A group mandated VIEW-ONLY refuses backstage grants too, unless the group carries the explicit
	// opt-out. This is the honesty fix for the label: enforce_view_only makes the AGENT drop input and
	// refuse reboot / tool-launch / command-run / lock / log-off / shut-down (AccessLevel::ViewOnly,
	// agent/src/session_policy.rs), but backstage — the remote shell and the tool panels — rides a
	// SEPARATE trust axis and the agent's backstage path never consults the session's access level. So
	// without this a technician holding CapBackstageShell could run commands as SYSTEM on a machine the
	// console labelled "view only". The two axes stay separate on purpose (see GroupSessionPolicy's scope
	// header); what is closed is the ISSUING of a new authorization against a group the operator declared
	// watch-only.
	//
	// Consistency, not novelty: handleMintElevation (http_elevation.go) has refused an ELEVATION grant on
	// exactly this mandate since it was written. Two privilege-issuing endpoints answering differently
	// about the same admin decision was the actual defect.
	//
	// AllowBackstageUnderViewOnly is the deliberate per-group opt-out for unattended maintenance — a patch
	// window, a scripted remediation — and its FALSE (zero) value is the protected one on purpose; see the
	// field comment and migration 0040. The nil-store and empty-group guards match the elevation twin and
	// the attended path: a deployment with no group-policy store wired (DEV) has no mandate to enforce, and
	// a machine in no group has no group policy to read.
	//
	// On an unattended host this is attribution and policy, not a privilege boundary — the agent already
	// runs as SYSTEM. What it buys is that no signed, audited backstage authorization is ISSUED against
	// such a group, which is the same thing refuseOutOfServiceMachine above buys for a quarantined machine.
	if s.GroupSessionPolicies != nil && m.GroupID != "" {
		eff, gerr := s.EffectivePolicy(r.Context(), p.TenantID, m.GroupID)
		if gerr != nil {
			// Fail CLOSED and say WHICH failure: an unreadable policy is not "no policy" (memory:
			// fail-closed-must-say-which-failure).
			writeError(w, http.StatusInternalServerError, "could not resolve group session policy")
			return
		}
		if eff.Conflict != "" { // docs/62 R4: an unsatisfiable merged policy mints nothing
			writeError(w, http.StatusConflict, eff.Conflict)
			return
		}
		gp := eff.GroupSessionPolicy
		if gp.EnforceViewOnly && !gp.AllowBackstageUnderViewOnly {
			writeError(w, http.StatusConflict,
				"this machine's group is mandated view-only; Under the Hood tools cannot be used on it")
			return
		}
	}

	// An OBSERVER session never receives a backstage grant (security audit 2026-10-18). Without this
	// a technician could open a view_only session — counted against the observer cap and recorded
	// as watch-only — then mint a grant naming it; the agent accepts any grant that matches the live
	// session and technician. The agent also refuses mutating backstage requests on an observer, so
	// this is the issuing side of the same rule, as handleMintElevation already applies it. A
	// session id with no session_record (attended sessions, legacy callers) is not an observer.
	if req.SessionID != "" && s.SessionRecords != nil {
		rec, rerr := s.SessionRecords.GetSession(r.Context(), p.TenantID, req.SessionID)
		switch {
		case rerr == nil && rec.Access == "view_only":
			writeError(w, http.StatusForbidden, "this session is an observer; Under the Hood tools are forbidden")
			return
		case rerr != nil && !errors.Is(rerr, ErrSessionRecordNotFound):
			writeError(w, http.StatusInternalServerError, "could not resolve session")
			return
		}
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = newUUID()
	}

	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	now := issuanceNow()
	signed, err := s.Grants.Mint(p.UserID, sessionID, req.MachineID, caps, now, now+backstageGrantTTL.Milliseconds())
	if err != nil {
		// A malformed technician/machine/session UUID lands here — the grant cannot be built.
		writeError(w, http.StatusBadRequest, "could not mint grant: "+err.Error())
		return
	}
	if err := s.recordMgmtAudit(r, "grant.mint", "machine", m.ID,
		map[string]any{"device_id": m.DeviceID, "session_id": sessionID, "caps": len(caps)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, signed)
}

// handleGrantPubkey returns the issuer's Ed25519 public key (hex) so it can be provisioned into
// agent config.json as `grant_issuer_pubkey`.
func (s *Server) handleGrantPubkey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"grant_issuer_pubkey": s.Grants.PublicKeyHex()})
}

// -------------------------------------------------------------------------------------
// JSON helpers
// -------------------------------------------------------------------------------------

// writeJSON is the single exit for every JSON response this server produces.
//
// `Cache-Control: no-store` is set HERE rather than on the handlers that obviously need it
// (docs/25 F10), and that placement is the point. This API answers with session tokens, signed
// session tickets, backstage grants, enrollment tokens, credential-setup links, API tokens and
// per-tenant fleet data; a per-handler header protects only the ones somebody remembered, and the
// next sensitive endpoint added would be unprotected by default. Exactly the reasoning that put the
// argon2 bound inside VerifyPassword instead of on /auth/login (F01).
//
// `no-store` rather than `no-cache`: no-cache still permits a shared cache to STORE the response and
// merely requires revalidation, which for a bearer-token body is the wrong half of the guarantee.
// Nothing here benefits from caching — the one route that does want it, the installer download, is
// served by Caddy's file_server and never passes through this function.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeDenied(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
}

// -------------------------------------------------------------------------------------
// StubAuthenticator — a placeholder Authenticator so the skeleton runs end-to-end before
// the Zitadel/OIDC integration exists. It returns a fixed Principal. DO NOT ship this.
// -------------------------------------------------------------------------------------

// StubAuthenticator returns the same Principal for every request. Wire it only in dev.
type StubAuthenticator struct {
	Principal *Principal
}

// Authenticate implements Authenticator. TODO(auth): replace with real OIDC/session — see
// the authMiddleware TODO for the required steps.
func (a StubAuthenticator) Authenticate(_ *http.Request) (*Principal, error) {
	return a.Principal, nil
}

// NoopBinder is a TenantBinder that does nothing (no DB in DEV mode / pure-RBAC tests). The
// real binder is PgBinder (binder.go), which pins app.current_tenant on a pooled connection.
type NoopBinder struct{}

// BindTenant implements TenantBinder.
func (NoopBinder) BindTenant(ctx context.Context, _ string) (context.Context, func(), error) {
	return ctx, nil, nil
}
