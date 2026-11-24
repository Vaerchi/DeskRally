package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
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

	// APIWriteLimiter meters public API writes per API token (apitoken_write_limit.go). nil uses the
	// process-wide default; tests set their own so they do not share a budget.
	APIWriteLimiter *apiWriteLimiter

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

	// BindingMode returns a tenant's session-binding policy (docs/69, session_binding.go). Optional:
	// nil means every tenant is at warn.
	BindingMode func(tenantID string) SessionBindingMode

	// BindingEnabled turns session binding on (docs/69): brokered sessions carry `device_binding`. The
	// zero value is off (tests and embedders opt in); the production binary sets it from
	// SessionBindingSwitch, which is on unless CP_SESSION_BINDING=off (docs/69 §3.9).
	BindingEnabled bool

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
	Directives     DirectiveStore
	LAN            LanStore
	WakeOnLAN      bool
	WakeStore      WakeStore
	WakeThrottle   WakeThrottle
	WakeDispatcher WakeDispatcher
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
	protected.HandleFunc("GET /toolbox/{id}/runs", s.handleToolboxRunHistory)
	protected.HandleFunc("GET /machines/{id}/runs", s.handleMachineRunHistory)
	protected.HandleFunc("POST /runs/{request_id}/result", s.handleRunResult)
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
	protected.HandleFunc("GET /dynamic-groups/{id}", s.handleGetDynamicGroup)
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
	if s.WakeOnLAN {
		protected.HandleFunc("POST /machines/{id}/wake", s.handleWake)
	}
	// Machine lifecycle status (docs/01 §4): quarantine / retire / reactivate a machine, gated on
	// CapManageMachines for the machine's REAL group. A quarantined/retired machine is refused a new
	// session by handleStartSession.
	protected.HandleFunc("POST /machines/{id}/status", s.handleSetMachineStatus)
	protected.HandleFunc("POST /machines/bulk-status", s.handleBulkSetMachineStatus)
	protected.HandleFunc("POST /machines/{id}/group", s.handleSetMachineGroup)
	protected.HandleFunc("POST /machines/bulk-group", s.handleBulkSetMachineGroup)
	protected.HandleFunc("POST /machines/bulk-property", s.handleBulkSetMachineProperty)
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
	protected.HandleFunc("GET /machine-fields", s.handleListMachineFields)
	protected.HandleFunc("POST /machine-fields", s.handleChangeMachineFields)
	protected.HandleFunc("PUT /machine-fields/{key}", s.handleChangeMachineFields)
	protected.HandleFunc("DELETE /machine-fields/{key}", s.handleChangeMachineFields)
	protected.HandleFunc("PUT /machine-field-order", s.handleChangeMachineFields)
	protected.HandleFunc("GET /machine-fields/{key}/nonconforming", s.handleMachineFieldReport)

	// Enrollment — an installer redeems a token to join the fleet.
	protected.HandleFunc("POST /enroll", s.handleEnroll)

	// Enrollment-token management (M1): mint/list/revoke, gated on CapManageEnrollment. The
	// REDEMPTION route is public and mounted on the root mux below.
	if s.EnrollmentTokens != nil {
		protected.HandleFunc("GET /managed-installer", s.handleManagedInstallStatus)
		protected.HandleFunc("POST /managed-installer", streaming(s.handleManagedInstallBundle))
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
	// docs/69: the console reports a session it could not verify (session_binding.go).
	protected.HandleFunc("POST /sessions/{id}/binding-failed", s.handleSessionBindingFailed)
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
	protected.HandleFunc("GET /audit/export", streaming(s.handleExportAudit))
	protected.HandleFunc("GET /audit/verify", s.handleVerifyAudit)
	// Packaged compliance archive: one ZIP of both trails + a manifest (http_audit_archive.go).
	// Same CapViewAudit gate; the backstage half is group-scoped like /audit/backstage/export.
	protected.HandleFunc("GET /audit/archive", streaming(s.handleAuditArchive))

	// Backstage audit-chain ingestion (H2) + export. The authenticated controller forwards the
	// agent's hash-chained backstage audit for central, tamper-evident storage; /backstage/export
	// re-emits it as NDJSON for a SIEM collector (http_backstage_audit.go), which is what makes the
	// trail readable outside a psql prompt. Both behind the same auth → tenant (RLS) chain as
	// everything else, but on DIFFERENT capabilities: writing the trail is backstage work
	// (CapBackstageShell), reading it is an auditor's (CapViewAudit). Only mounted when an
	// AuditStore is wired.
	if s.Audit != nil {
		protected.HandleFunc("POST /audit/ingest", s.handleIngestAudit)
		protected.HandleFunc("GET /audit/backstage/export", streaming(s.handleExportBackstageAudit))
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
		// docs/70 release review (1.3.35): LAN ingress and incarnation activation exist only while Wake-on-LAN is
		// ON. With CP_WAKE_ON_LAN unset they are absent (the request falls through to the authenticated
		// catch-all and answers 401), signaling never activates, never advertises lan_v1/wake_v1, and no agent
		// uploads LAN facts.
		if s.LAN != nil && s.WakeOnLAN {
			root.HandleFunc("GET /internal/signaling/incarnation", s.handleGetSignalingIncarnation)
			root.HandleFunc("POST /internal/signaling/incarnation", s.handleActivateSignalingIncarnation)
			root.HandleFunc("POST /internal/devices/lan-epoch", s.handleAllocateLanEpoch)
			root.HandleFunc("POST /internal/devices/lan", s.handleIngestLanReport)
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
	// PUBLIC grant issuer key (docs/69 §3.7 step 2): an installed agent that has no pinned key fetches it
	// once from its own control plane over TLS. It is a PUBLIC key, so exposing it costs nothing.
	if s.Grants != nil {
		root.HandleFunc("GET /agent/grant-issuer-pubkey", s.handleGrantPubkey)
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

	if !s.WakeOnLAN {
		root.HandleFunc("POST /machines/{id}/wake", http.NotFound)
	}
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
			// A STORE FAULT is not a verdict on the credential (auth_outcome.go): 503 + Retry-After, the
			// request is NOT processed (no handler below runs, no Principal is set), and the console does not
			// sign out. Only a definite "no" — or a nil principal with no error — is the 401.
			if err != nil && classifyAuthError(err) == authUnavailable {
				writeAuthUnavailable(w, r, err)
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

// StubAuthenticator and NoopBinder are dev-only and live in devstubs.go (build tag cpdev).
