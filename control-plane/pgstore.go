package controlplane

// pgx-backed implementations of the auth persistence seams (UserStore, SessionStore) and the
// login-time TenantResolver, over the schema in migrations/0001_core.sql + 0002_auth.sql +
// 0003_auth_bootstrap.sql. These live alongside the in-memory fakes (session.go /
// authstore_mem.go), which remain the default test path; production wires these.
//
// Tenant pinning (THE RLS contract): every tenant-scoped query runs inside a transaction that
// first pins the tenant with `SELECT set_config('app.current_tenant', $1, true)`. Because the
// third arg is is_local = true, the setting is scoped to that transaction (like SET LOCAL) and
// is guaranteed to be in effect before any RLS-scoped statement in the same tx runs, then
// discarded at commit/rollback. The two pre-tenant lookups that cannot yet pin a tenant —
// slug→id at login and token→session at request auth — go through the SECURITY DEFINER
// bootstrap functions in 0003, which bypass RLS; the tenant learned there is then pinned for
// every follow-up query.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// withTenant runs fn inside a transaction with app.current_tenant pinned to tenantID, so all
// RLS-scoped queries fn issues are confined to that tenant by PostgreSQL itself.
//
// When the request context carries a PgBinder-bound connection (the per-request RLS pin), the
// transaction runs ON that connection — one connection per request — and the bound tenant must
// MATCH the requested one: a mismatch means confused deputy (some code path asked a store for a
// different tenant than the request was authenticated for), so it fails loudly rather than
// letting the local re-pin silently widen the request to a second tenant.
// The isolation level is pinned to READ COMMITTED at BEGIN rather than inherited. One store
// depends on it for CORRECTNESS, not just performance: PgMgmtAuditStore.RecordEvent serializes
// appends by taking an advisory lock and THEN reading the chain tail. That lock-then-read shape
// is only sound when each statement takes a fresh snapshot — under REPEATABLE READ the snapshot
// is frozen before the lock is ever granted, so a waiter wakes up unable to see the row the
// previous holder just committed, reads a stale tail, stamps a duplicate seq and dies on
// uq_audit_event_tenant_seq. The advisory lock cannot help: it orders the writers, it cannot
// refresh their snapshots.
//
// Inheriting the default made that correctness hinge on an unstated GUC that an operator can flip
// from outside the code entirely — postgresql.conf, ALTER ROLE/DATABASE SET, a managed-Postgres
// preset, or just `?options=-c default_transaction_isolation=repeatable read` on DATABASE_URL,
// which main.go hands to pgxpool verbatim. The result would be a management-plane outage (every
// concurrent audited action in a tenant 500s) with nothing in the logs naming the cause.
//
// This must be done HERE, at BEGIN. `SET LOCAL transaction_isolation` inside the callback is not
// an option: the set_config below is the transaction's first statement and has already fixed the
// snapshot, so Postgres rejects a later change with 25001 "SET TRANSACTION ISOLATION LEVEL must
// be called before any query".
func withTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	var beginner interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	} = pool
	if bc := boundConnFrom(ctx); bc != nil {
		if bc.tenantID != tenantID {
			return fmt.Errorf("tenant mismatch: request is bound to tenant %s but the store was asked for tenant %s", bc.tenantID, tenantID)
		}
		beginner = bc.conn
	}
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit
	// Parameterized because SET does not accept bind params; set_config(..., is_local=true)
	// is the transaction-scoped equivalent of SET LOCAL.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// -------------------------------------------------------------------------------------
// PgUserStore — UserStore over app_user + user_credential + user_totp + membership/role.
// -------------------------------------------------------------------------------------

// PgUserStore is the pgx-backed UserStore.
type PgUserStore struct {
	Pool *pgxpool.Pool
	// TOTP secrets are sealed on the way in and opened on the way out, HERE, so that everything
	// above this line — AuthUser.TOTPSecret, the handlers, VerifyTOTPStep — keeps working with the
	// base32 string it always had. The store owns the storage representation; putting the
	// encryption in the handlers instead would mean every current and future caller of
	// FindUserByID had to remember to decrypt, which is the same shape as gating in handlers rather
	// than in the store. nil = no key configured: legacy rows still read, new secrets are refused.
	TOTP *TOTPCipher
}

// NewPgUserStore constructs a PgUserStore.
//
// Deliberately leaves TOTP nil. `main.go` sets it from TOTP_ENCRYPTION_KEY after construction, and
// nil is the honest "no key" state rather than a silent plaintext fallback — Seal refuses, Open
// still reads legacy rows.
func NewPgUserStore(pool *pgxpool.Pool) *PgUserStore { return &PgUserStore{Pool: pool} }

var _ UserStore = (*PgUserStore)(nil)

// selectUser joins a user to its optional local credential and TOTP enrollment. uuids are
// cast to text so they scan cleanly into Go strings regardless of the driver's uuid codec.
//
// `c.updated_at` — the CREDENTIAL EPOCH (migrations/0018) — is selected here, in the same row as
// `c.password_hash`, and that is the load-bearing detail rather than a convenience. The epoch's job
// is to name the version of the credential a caller acted on; read separately it could name a
// different version than the hash that was verified, and the check would compare the wrong pair.
//
// `tn.disabled_at` — TENANT SUSPENSION — is joined in for the same reason: this projection is read
// on every authenticated request (SessionAuthenticator.Authenticate), so folding the tenant's state
// into it makes re-checking suspension free. The join is INNER and unqualified by tenant on purpose:
// RLS confines `tenant` to `id = current_setting('app.current_tenant')` (0001_core.sql, "the tenant
// row is visible only to itself") and confines `app_user` to the same tenant, so the join can only
// ever match the pinned tenant's own row — and if it somehow matched none, the query returns
// ErrNoUser, which is the fail-closed direction.
const selectUser = `
	SELECT u.id::text, u.tenant_id::text, u.email, u.display_name,
	       (u.disabled_at IS NOT NULL), (tn.disabled_at IS NOT NULL), tn.require_2fa,
	       c.password_hash, c.updated_at,
	       t.secret, (t.confirmed_at IS NOT NULL), t.pending_secret, u.mfa_generation
	FROM app_user u
	JOIN      tenant          tn ON tn.id = u.tenant_id
	LEFT JOIN user_credential c  ON c.user_id = u.id
	LEFT JOIN user_totp       t  ON t.user_id = u.id
	WHERE `

// scanUser takes the cipher as a PARAMETER rather than reading it from a receiver, so that adding a
// third caller cannot forget to decrypt: there is no signature that compiles without deciding.
func scanUser(row pgx.Row, totp *TOTPCipher) (*AuthUser, error) {
	var (
		id, tenantID, email, display string
		disabled, suspended          bool
		require2FA                   bool
		totpConfirmed                bool
		passwordHash                 *string    // NULL when the user has no local credential
		credentialUpdatedAt          *time.Time // ditto — no credential row, no epoch
		secret, pending              []byte     // NULL when not enrolled / nothing pending
		mfaGeneration                int64
	)
	if err := row.Scan(&id, &tenantID, &email, &display, &disabled, &suspended, &require2FA, &passwordHash, &credentialUpdatedAt,
		&secret, &totpConfirmed, &pending, &mfaGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoUser
		}
		return nil, err
	}
	// Decrypt both secrets back to the base32 strings the rest of the code expects. A row written
	// before TOTP_ENCRYPTION_KEY existed is plaintext and opens as itself, so an upgrade does not
	// lock anyone out; see totp_crypt.go.
	//
	// A decrypt FAILURE is fatal to the lookup rather than degraded to "no 2FA". Returning an
	// AuthUser with an empty TOTPSecret would read, three frames up at auth.go:547, as "this user
	// is not enrolled" — and that path skips the second factor entirely. A wrong or rotated key
	// would then silently downgrade every enrolled account to password-only, which is precisely the
	// outcome encrypting the column exists to prevent.
	secretB32, _, err := totp.Open(secret)
	if err != nil {
		return nil, fmt.Errorf("user %s: totp secret: %w", id, err)
	}
	pendingB32, _, err := totp.Open(pending)
	if err != nil {
		return nil, fmt.Errorf("user %s: pending totp secret: %w", id, err)
	}
	u := &AuthUser{
		ID: id, TenantID: tenantID, Email: email, DisplayName: display,
		MFAGeneration:   mfaGeneration,
		Disabled:        disabled,
		TenantSuspended: suspended,
		Require2FA:      require2FA,
		TOTPSecret:      secretB32, // "" when NULL or not enrolled
		TOTPConfirmed:   totpConfirmed,
		TOTPPending:     pendingB32,
	}
	if passwordHash != nil {
		u.PasswordHash = *passwordHash
	}
	if credentialUpdatedAt != nil {
		u.CredentialUpdatedAt = credentialUpdatedAt.UTC()
	}
	return u, nil
}

// FindUserByEmail implements UserStore.
func (s *PgUserStore) FindUserByEmail(ctx context.Context, tenantID, email string) (*AuthUser, error) {
	var out *AuthUser
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		u, err := scanUser(tx.QueryRow(ctx, selectUser+"u.email = $1", email), s.TOTP)
		out = u
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListUsers implements UserStore: the tenant's users as management summaries, ordered by email. RLS
// (via withTenant) confines the SELECT to the pinned tenant, so no explicit tenant WHERE is needed.
func (s *PgUserStore) ListUsers(ctx context.Context, tenantID string) ([]UserSummary, error) {
	out := []UserSummary{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = queryUserSummaries(ctx, tx, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccessSummary implements UserStore: ListUsers' query for ONE user, so /me's access fields come from
// the same SQL at one statement_timestamp() (docs/57 sec. 5).
func (s *PgUserStore) AccessSummary(ctx context.Context, tenantID, userID string) (UserSummary, error) {
	if namesNoUUIDRow(userID) {
		return UserSummary{}, ErrNoUser
	}
	var rows []UserSummary
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		rows, err = queryUserSummaries(ctx, tx, userID)
		return err
	})
	if err != nil {
		return UserSummary{}, err
	}
	if len(rows) == 0 {
		return UserSummary{}, ErrNoUser
	}
	return rows[0], nil
}

// queryUserSummaries is the ListUsers/AccessSummary SELECT; userID "" lists every user in the pinned
// tenant, otherwise just that one.
func queryUserSummaries(ctx context.Context, tx pgx.Tx, userID string) ([]UserSummary, error) {
	out := []UserSummary{}
	// Two PRE-AGGREGATED CTEs so the main SELECT needs no GROUP BY (which would multiply the
	// per-user scope array across the role join and mangle it). `roles` is the user's distinct
	// preset role keys (matching the fake's sorted, de-duplicated list). `scope` is the user's
	// EFFECTIVE group scope, matching Grant.AssignmentScope: if ANY membership is tenant-wide
	// (empty scoped_group_ids) the whole user is tenant-wide ('{}'), otherwise the UNION of the
	// groups their memberships name. A user with no memberships has no CTE row → COALESCE to '{}'
	// (tenant-wide). Arrays kept non-null so the JSON is `[]`, never null. RLS confines membership.
	rows, err := tx.Query(ctx, `
			WITH roles AS (
				SELECT m.user_id,
				       COALESCE(array_agg(DISTINCT r.key ORDER BY r.key) FILTER (WHERE r.key IS NOT NULL), '{}')::text[] AS keys
				FROM membership m
				LEFT JOIN role r ON r.id = m.role_id
				GROUP BY m.user_id
			),
			scope AS (
				SELECT m.user_id,
				       CASE WHEN bool_or(cardinality(m.scoped_group_ids) = 0) THEN '{}'::uuid[]
				            ELSE COALESCE(array_agg(DISTINCT g ORDER BY g) FILTER (WHERE g IS NOT NULL), '{}'::uuid[]) END AS ids
				FROM membership m
				LEFT JOIN LATERAL unnest(m.scoped_group_ids) AS g ON true
				GROUP BY m.user_id
			),
			-- docs/56: NULL when any membership never expires, else the LATEST expiry; expired when
			-- every membership has passed (statement time, GrantFor's clock).
			exp AS (
				SELECT m.user_id,
				       CASE WHEN bool_or(m.expires_at IS NULL) THEN NULL ELSE max(m.expires_at) END AS at,
				       bool_and(m.expires_at IS NOT NULL AND m.expires_at <= statement_timestamp()) AS expired
				FROM membership m
				GROUP BY m.user_id
			),
			-- docs/57: n counts the DISTINCT windows with "no window" as a value (-1/''): the window is
			-- reported only when n = 1 and it is a real one; varies when n > 1 (incl. a windowed +
			-- unrestricted mix). outside: an unexpired membership exists and none of the unexpired ones
			-- is open now (statement time).
			win AS (
				SELECT m.user_id,
				       bool_or(m.window_days IS NULL) AS unrestricted,
				       count(DISTINCT (COALESCE(m.window_days, -1), COALESCE(m.window_start, -1),
				                       COALESCE(m.window_end, -1), COALESCE(m.window_tz, ''))) AS n,
				       min(m.window_days) AS days, min(m.window_start) AS ws, min(m.window_end) AS we,
				       min(m.window_tz) AS tz,
				       bool_or(m.expires_at IS NULL OR m.expires_at > statement_timestamp()) AS live,
				       bool_or((m.expires_at IS NULL OR m.expires_at > statement_timestamp())
				               AND membership_window_open(m.window_days, m.window_start, m.window_end,
				                                          m.window_tz, statement_timestamp())) AS live_open
				FROM membership m
				GROUP BY m.user_id
			)
			SELECT u.id::text, u.email, u.display_name, (u.disabled_at IS NOT NULL),
			       COALESCE(roles.keys, '{}')::text[],
			       COALESCE(scope.ids, '{}'::uuid[])::text[],
			       exp.at, COALESCE(exp.expired, false),
			       COALESCE(win.unrestricted, true), COALESCE(win.n, 0), win.days, win.ws, win.we, win.tz,
			       COALESCE(win.live AND NOT win.live_open, false)
			FROM app_user u
			LEFT JOIN roles ON roles.user_id = u.id
			LEFT JOIN scope ON scope.user_id = u.id
			LEFT JOIN exp ON exp.user_id = u.id
			LEFT JOIN win ON win.user_id = u.id
			WHERE ($1 = '' OR u.id::text = $1)
			ORDER BY u.email
		`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var u UserSummary
		var roles, scope []string
		var unrestricted bool
		var n int64
		var days, ws, we *int16
		var tz *string
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Disabled, &roles, &scope, &u.AccessExpiresAt, &u.AccessExpired,
			&unrestricted, &n, &days, &ws, &we, &tz, &u.AccessOutsideWindow); err != nil {
			return nil, err
		}
		if !unrestricted && n == 1 {
			u.AccessWindow = windowFromRow(days, ws, we, tz)
		}
		u.AccessWindowVaries = n > 1
		if roles == nil {
			roles = []string{}
		}
		if scope == nil {
			scope = []string{}
		}
		u.Roles = roles
		u.ScopedGroupIDs = scope
		out = append(out, u)
	}
	return out, rows.Err()
}

// windowFromRow builds a stored window from its four columns (nil when unset). It is NOT re-validated:
// pg is the authority that evaluates it (docs/57 sec. 3), and Go only displays or preserves it.
func windowFromRow(days, start, end *int16, tz *string) *AccessWindow {
	if days == nil || start == nil || end == nil || tz == nil {
		return nil
	}
	return &AccessWindow{Days: uint8(*days), Start: int(*start), End: int(*end), Zone: *tz}
}

// windowColumns splits a window into its four nullable column values.
func windowColumns(w *AccessWindow) (days, start, end *int16, tz *string) {
	if w == nil {
		return nil, nil, nil, nil
	}
	d, s, e, z := int16(w.Days), int16(w.Start), int16(w.End), w.Zone
	return &d, &s, &e, &z
}

// SetUserRole implements UserStore: replace the user's memberships with a single tenant-wide membership
// of the preset role, in one transaction. The user must exist in the pinned tenant (RLS-scoped) — a
// cross-tenant/unknown id is ErrNoUser, not a silent write. The role must be a global preset — an
// unresolvable key is ErrUnknownRole. Both the DELETE and the INSERT are RLS-confined to the pinned
// tenant (the membership policy's USING/WITH CHECK), so this can neither touch nor create another
// tenant's memberships.
func (s *PgUserStore) SetUserRole(ctx context.Context, tenantID, userID string, role Role, scopedGroupIDs []string) error {
	return s.SetUserAssignment(ctx, tenantID, userID, Assignment{Role: role, ScopedGroupIDs: scopedGroupIDs})
}

// lockOwnersAndCount locks the tenant's Owner membership rows (FOR UPDATE, so concurrent demotions and
// disables of Owners serialize) and returns how many ENABLED users hold a never-expiring Owner
// membership (docs/56 sec. 4.2a). RLS confines both statements to the tenant pinned by withTenant.
func lockOwnersAndCount(ctx context.Context, tx pgx.Tx) (int, error) {
	if _, err := tx.Exec(ctx, `
		SELECT m.id FROM membership m JOIN role r ON r.id = m.role_id
		WHERE r.key = 'owner' AND r.tenant_id IS NULL
		FOR UPDATE OF m`); err != nil {
		return 0, err
	}
	return countPermanentOwners(ctx, tx)
}

func countPermanentOwners(ctx context.Context, tx pgx.Tx) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT m.user_id) FROM membership m
		JOIN role r ON r.id = m.role_id
		JOIN app_user u ON u.id = m.user_id
		WHERE r.key = 'owner' AND r.tenant_id IS NULL AND m.expires_at IS NULL AND m.window_days IS NULL
		  AND u.disabled_at IS NULL
	`).Scan(&n)
	return n, err
}

// SetUserAssignment implements UserStore (docs/56): SetUserRole with an expiry, refusing with
// ErrLastOwner a change that would leave the tenant without an enabled, permanent Owner.
func (s *PgUserStore) SetUserAssignment(ctx context.Context, tenantID, userID string, a Assignment) error {
	role, scopedGroupIDs := a.Role, a.ScopedGroupIDs
	if !IsAssignableRole(role) {
		return ErrUnknownRole
	}
	// An id no `uuid` column could hold is "no such user", not a 500 on the cast (pathid.go).
	if namesNoUUIDRow(userID) {
		return ErrNoUser
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// docs/62 R2: who may assign what depends on the group tree, so the write is conditional on the
		// tree still being at the version the actor's grant was read at.
		if a.ExpectTreeVersion != nil {
			if err := checkGroupTreeVersionTx(ctx, tx, tenantID, *a.ExpectTreeVersion); err != nil {
				return err
			}
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_user WHERE id = $1)`, userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNoUser
		}
		var roleID string
		err := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key = $1 AND tenant_id IS NULL`, string(role)).Scan(&roleID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnknownRole
		}
		if err != nil {
			return err
		}
		before, err := lockOwnersAndCount(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM membership WHERE user_id = $1`, userID); err != nil {
			return err
		}
		if err := insertMembershipInTx(ctx, tx, tenantID, userID, roleID, scopedGroupIDs, a.ExpiresAt, a.Window, a.WindowSupplied); err != nil {
			return err
		}
		after, err := countPermanentOwners(ctx, tx)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return ErrLastOwner // rolls the whole change back
		}
		return nil
	})
}

// insertMembershipInTx writes one membership row. The scope is persisted EXACTLY as given and is NEVER
// collapsed to '{}' for a non-empty input (that would silently widen to tenant-wide); '{}' is written
// only for an empty/nil scope. Group-existence is NOT revalidated here on purpose: the handler
// validates an EXPLICITLY-supplied scope (resolveExplicitScope: 400/404) where the user-facing error
// belongs, while a PRESERVED scope (a role change that omits the field) is carried forward unchanged —
// and an id for a since-deleted group is a safe DANGLING deny (it covers no machine), never a widen, so
// revalidating it here would wrongly fail an unrelated role change (and diverge from the in-memory store).
//
// A SUPPLIED window's zone (verifyZone) must name an entry of THIS database's tz data exactly (docs/57
// sec. 4): pg is the authority that will evaluate it, so a name only Go knows is ErrUnknownTimeZone, not
// a membership that silently never opens. A PRESERVED window is written exactly as stored, unchecked
// (r3): an unrelated edit must not fail on a zone pg has since dropped (that window keeps denying).
func insertMembershipInTx(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID string, scopedGroupIDs []string, expiresAt *time.Time, window *AccessWindow, verifyZone bool) error {
	if window != nil && verifyZone {
		var known bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name = $1)`, window.Zone).Scan(&known); err != nil {
			return err
		}
		if !known {
			return ErrUnknownTimeZone
		}
	}
	days, start, end, tz := windowColumns(window)
	if len(scopedGroupIDs) == 0 {
		scopedGroupIDs = []string{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids, expires_at,
		                        window_days, window_start, window_end, window_tz)
		VALUES ($1, $2, $3, $4::uuid[], $5, $6, $7, $8, $9)`,
		tenantID, userID, roleID, scopedGroupIDs, expiresAt, days, start, end, tz)
	return err
}

// CreateUser implements UserStore: insert a new credential-less app_user with one tenant-wide membership
// of the preset role, atomically. Both writes run under withTenant (RLS pinned; the WITH CHECK confines
// the rows to the caller's tenant). A duplicate email (app_user UNIQUE (tenant_id, email), SQLSTATE
// 23505) surfaces as ErrEmailExists; a non-preset role is ErrUnknownRole. The id is caller-supplied
// (newUUID) — canonical lowercase, matching what gen_random_uuid() would have produced.
func (s *PgUserStore) CreateUser(ctx context.Context, tenantID, userID, email, displayName string, role Role, scopedGroupIDs []string) error {
	return s.CreateUserAssignment(ctx, tenantID, userID, email, displayName, Assignment{Role: role, ScopedGroupIDs: scopedGroupIDs})
}

// CreateUserAssignment implements UserStore: CreateUser with an expiry on the membership (docs/56).
func (s *PgUserStore) CreateUserAssignment(ctx context.Context, tenantID, userID, email, displayName string, a Assignment) error {
	role, scopedGroupIDs := a.Role, a.ScopedGroupIDs
	if !IsAssignableRole(role) {
		return ErrUnknownRole
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if a.ExpectTreeVersion != nil { // docs/62 R2, as in SetUserAssignment
			if err := checkGroupTreeVersionTx(ctx, tx, tenantID, *a.ExpectTreeVersion); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_user (id, tenant_id, email, display_name) VALUES ($1, $2, $3, $4)
		`, userID, tenantID, email, displayName); err != nil {
			return err
		}
		var roleID string
		rerr := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key = $1 AND tenant_id IS NULL`, string(role)).Scan(&roleID)
		if errors.Is(rerr, pgx.ErrNoRows) {
			return ErrUnknownRole
		}
		if rerr != nil {
			return rerr
		}
		return insertMembershipInTx(ctx, tx, tenantID, userID, roleID, scopedGroupIDs, a.ExpiresAt, a.Window, a.WindowSupplied)
	})
	if isUniqueViolation(err) {
		return ErrEmailExists
	}
	return err
}

// SetUserDisabled implements UserStore: set disabled_at to now() (disable) or NULL (enable). RLS
// confines the UPDATE to the pinned tenant; 0 rows affected → the id is not in this tenant → ErrNoUser.
func (s *PgUserStore) SetUserDisabled(ctx context.Context, tenantID, userID string, disabled bool) error {
	if namesNoUUIDRow(userID) {
		return ErrNoUser
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var disabledAt *time.Time
		if disabled {
			now := time.Now().UTC()
			disabledAt = &now
		}
		before := 0
		if disabled {
			var err error
			if before, err = lockOwnersAndCount(ctx, tx); err != nil {
				return err
			}
		}
		ct, err := tx.Exec(ctx, `UPDATE app_user SET disabled_at = $2 WHERE id = $1`, userID, disabledAt)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNoUser
		}
		if disabled && before > 0 {
			after, err := countPermanentOwners(ctx, tx)
			if err != nil {
				return err
			}
			if after == 0 {
				return ErrLastOwner // docs/56 sec. 4.2a: rolls the disable back
			}
		}
		return nil
	})
}

// FindUserByID implements UserStore.
func (s *PgUserStore) FindUserByID(ctx context.Context, tenantID, userID string) (*AuthUser, error) {
	// An id no `uuid` column could hold is "no such user", not a 500 (pathid.go).
	if namesNoUUIDRow(userID) {
		return nil, ErrNoUser
	}
	var out *AuthUser
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		u, err := scanUser(tx.QueryRow(ctx, selectUser+"u.id = $1", userID), s.TOTP)
		out = u
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetTOTP implements UserStore: upsert the user's ENFORCED TOTP secret + confirmed state, always
// clearing any pending enrollment. When confirmed is false the enrollment is (re)armed
// unconfirmed; when true, confirmed_at is set once and preserved. WITH CHECK on user_totp ensures
// tenant_id matches the pinned tenant.
//
// This is the administrative/provisioning path. The HTTP flow uses SetPendingTOTP +
// ConfirmPendingTOTP, because THIS method's clearing of confirmed_at is exactly the downgrade an
// unconfirmed re-enroll must not be able to cause.
func (s *PgUserStore) SetTOTP(ctx context.Context, tenantID, userID, secretB32 string, confirmed bool) error {
	sealed, err := s.TOTP.Seal(secretB32)
	if err != nil {
		return err
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at, pending_secret)
			VALUES ($1, $2, $3, CASE WHEN $4 THEN now() ELSE NULL END, NULL)
			ON CONFLICT (user_id) DO UPDATE
			  SET secret         = EXCLUDED.secret,
			      confirmed_at   = CASE WHEN $4 THEN COALESCE(user_totp.confirmed_at, now()) ELSE NULL END,
			      pending_secret = NULL
		`, userID, tenantID, sealed, confirmed)
		if err != nil {
			return err
		}
		return bumpMFAGeneration(ctx, tx, tenantID, userID)
	})
}

// bumpMFAGeneration gives the user a fresh, never-reused second-factor generation (migrations/0054)
// in the caller's transaction: every session MFA-verified against the previous factor stops
// counting for MFA-gated operations (the platform-operator check) the moment this commits.
func bumpMFAGeneration(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	ct, err := tx.Exec(ctx, `UPDATE app_user SET mfa_generation = nextval('mfa_generation_seq')
		WHERE id = $1 AND tenant_id = $2`, userID, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() != 1 {
		return ErrNoUser
	}
	return nil
}

// SetPendingTOTP implements UserStore: write ONLY pending_secret. An existing confirmed secret and
// its confirmed_at are untouched, so 2FA keeps being enforced throughout a re-enrollment. The
// insert path (first-ever enrollment) stores an empty enforced secret, which login treats as "not
// enrolled".
func (s *PgUserStore) SetPendingTOTP(ctx context.Context, tenantID, userID, secretB32 string) error {
	// Sealed BEFORE the transaction opens. With no key configured this returns ErrTOTPKeyMissing and
	// enrollment fails without having taken a tenant-pinned connection or written anything — the
	// refusal is the whole point, so it should cost nothing and leave no partial row.
	sealed, err := s.TOTP.Seal(secretB32)
	if err != nil {
		return err
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at, pending_secret)
			VALUES ($1, $2, ''::bytea, NULL, $3)
			ON CONFLICT (user_id) DO UPDATE SET pending_secret = EXCLUDED.pending_secret
		`, userID, tenantID, sealed)
		return err
	})
}

// ConfirmPendingTOTP implements UserStore: promote pending_secret → secret and stamp confirmed_at,
// in one statement. The WHERE clause makes it a no-op (→ ErrNoPendingTOTP) when nothing is pending,
// so confirmation can never re-activate an older secret. confirmed_at is refreshed here on purpose:
// it dates the enrollment that is actually being enforced.
func (s *PgUserStore) ConfirmPendingTOTP(ctx context.Context, tenantID, userID string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE user_totp
			   SET secret = pending_secret, confirmed_at = now(), pending_secret = NULL
			 WHERE user_id = $1 AND pending_secret IS NOT NULL AND length(pending_secret) > 0
		`, userID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNoPendingTOTP
		}
		return bumpMFAGeneration(ctx, tx, tenantID, userID)
	})
}

// SetPassword implements UserStore: upsert the user's argon2id PHC hash into user_credential.
//
// The tenant_id written is NOT the parameter — it is SELECTed from the user's own row:
//
//	INSERT INTO user_credential (…) SELECT u.id, u.tenant_id, $2 FROM app_user u WHERE u.id = $1
//
// That subquery reads app_user under RLS, which is confined to the pinned tenant, so a user id
// belonging to another tenant matches NO row, inserts nothing, and surfaces as ErrNoUser. Passing
// the tenant in directly would have let a caller that resolved the wrong user write a credential
// row stamped with the pinned tenant — the RLS WITH CHECK would have happily accepted it, because
// the row it was handed looks in-tenant. Deriving the value from the row being credentialed makes
// "which account does this password unlock" a fact the database decides, not the caller.
//
// ON CONFLICT (user_id) covers the change case. It re-asserts the tenant in its WHERE so a
// pre-existing row for a different tenant (impossible via this path, but the PK is global) is not
// silently repointed; a no-op there also reports ErrNoUser rather than a false success.
// It returns the new CREDENTIAL EPOCH via `RETURNING updated_at` — the value the row actually
// holds, not a Go-side timestamp. Only the stored value identifies the version a session must be
// stamped with. Use wall-clock time with a strictly increasing floor: a password reset
// that waits behind an email change must never move its credential epoch backward.
func (s *PgUserStore) SetPassword(ctx context.Context, tenantID, userID, phcHash string) (time.Time, error) {
	var epoch time.Time
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// SSO fencing design v3.1: the always-present user row fences even a FIRST password,
		// when there is no credential row for issuance to lock. Keep user before credential.
		var locked int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM app_user WHERE id = $1 FOR UPDATE`, userID).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoUser
			}
			return err
		}
		err := tx.QueryRow(ctx, `
			INSERT INTO user_credential (user_id, tenant_id, password_hash, updated_at)
			SELECT u.id, u.tenant_id, $2, now()
			  FROM app_user u
			 WHERE u.id = $1 AND u.disabled_at IS NULL
			ON CONFLICT (user_id) DO UPDATE
			   SET password_hash = EXCLUDED.password_hash,
			       updated_at    = GREATEST(clock_timestamp(), user_credential.updated_at + interval '1 microsecond')
			 WHERE user_credential.tenant_id = EXCLUDED.tenant_id
			RETURNING updated_at
		`, userID, phcHash).Scan(&epoch)
		if errors.Is(err, pgx.ErrNoRows) {
			// No row inserted and no row updated — an unknown/disabled user, or a conflicting row in
			// another tenant that the ON CONFLICT WHERE deliberately refused to repoint. Same
			// fail-closed answer the RowsAffected()==0 check gave before RETURNING was added.
			return ErrNoUser
		}
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return epoch.UTC(), nil
}

// ConsumeTOTPStep implements UserStore: one compare-and-set UPDATE (migrations/0012). The WHERE
// clause is the enforcement — a step at or before the stored one matches no row, so a replayed code
// affects nothing and reports false. Because check and write are the same statement, two concurrent
// logins presenting the same code serialize on the row lock and exactly one wins.
//
// A missing user_totp row also reports false: reaching here means login believed the account has a
// confirmed enrollment, so a missing row is an inconsistency to fail closed on, not to wave through.
func (s *PgUserStore) ConsumeTOTPStep(ctx context.Context, tenantID, userID string, step uint64) (bool, error) {
	var consumed bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE user_totp
			   SET last_step = $2
			 WHERE user_id = $1
			   AND (last_step IS NULL OR last_step < $2)
		`, userID, int64(step))
		if err != nil {
			return err
		}
		consumed = ct.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return consumed, nil
}

// StoredGrantFor implements UserStore: ALL the user's memberships, EXPIRED ONES INCLUDED, each with its
// ExpiresAt (docs/56 sec. 4). For the admin paths only; GrantFor is what authorizes the user. Its scopes are
// EXPANDED through the group tree (docs/62 R1/D3): admin containment needs current coverage, while the
// assigned ids and the expired memberships stay as administrative data. It never authorizes the actor.
func (s *PgUserStore) StoredGrantFor(ctx context.Context, tenantID, userID string) (*Grant, error) {
	var g *Grant
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		g, err = loadGrantTx(ctx, tx, tenantID, userID, true)
		return err
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// GrantFor implements UserStore: resolve the user's memberships into the RBAC *Grant. Each
// membership maps its preset role key + group scope; an empty scoped_group_ids means
// tenant-wide (the DB '{}' convention, mirrored by AllGroups()). A group scope is expanded to
// its descendants by cp_group_subtree (docs/62 D3) — the stored array itself is never rewritten.
func (s *PgUserStore) GrantFor(ctx context.Context, tenantID, userID string) (*Grant, error) {
	var g *Grant
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		g, err = loadGrantTx(ctx, tx, tenantID, userID, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// -------------------------------------------------------------------------------------
// PgSessionStore — SessionStore over user_session. Insert is tenant-pinned; the by-token
// operations go through the RLS-bypassing 0003 bootstrap functions (the token itself is the
// authorization, and the tenant is not yet known at that point).
// -------------------------------------------------------------------------------------

// PgSessionStore is the pgx-backed SessionStore.
type PgSessionStore struct {
	Pool *pgxpool.Pool
}

// NewPgSessionStore constructs a PgSessionStore.
func NewPgSessionStore(pool *pgxpool.Pool) *PgSessionStore { return &PgSessionStore{Pool: pool} }

var _ SessionStore = (*PgSessionStore)(nil)

// Insert implements SessionStore. Runs tenant-pinned; the DB assigns the uuid, which is read
// back into the Session so the caller sees the authoritative id.
func (s *PgSessionStore) Insert(ctx context.Context, sess *Session) error {
	return withTenant(ctx, s.Pool, sess.TenantID, func(tx pgx.Tx) error {
		// credential_epoch (migrations/0018) is written as a NULL when zero, so "this user has no
		// local credential" is stored as the absence it is rather than as year 1.
		var epoch *time.Time
		if !sess.CredentialEpoch.IsZero() {
			e := sess.CredentialEpoch
			epoch = &e
		}
		return tx.QueryRow(ctx, `
			INSERT INTO user_session (tenant_id, user_id, token_hash, created_at, expires_at, last_seen,
			                          credential_epoch, remembered, source_ip, user_agent)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9,'')::inet, NULLIF($10,''))
			RETURNING id::text
		`, sess.TenantID, sess.UserID, sess.TokenHash, sess.CreatedAt, sess.ExpiresAt, sess.LastSeen, epoch, sess.Remembered,
			validIPText(sess.SourceIP), sess.UserAgent).
			Scan(&sess.ID)
	})
}

// GetByTokenHash implements SessionStore via the bootstrap function (RLS-bypassing): the
// tenant is unknown until the row is read.
func (s *PgSessionStore) GetByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	var (
		id, tenantID, userID string
		hash                 []byte
		createdAt, expiresAt time.Time
		lastSeen, revokedAt  *time.Time
		credentialEpoch      *time.Time
		remembered           bool
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, user_id::text, token_hash, created_at, expires_at, last_seen,
		       revoked_at, credential_epoch, remembered
		FROM cp_session_by_token($1)
	`, tokenHash).Scan(&id, &tenantID, &userID, &hash, &createdAt, &expiresAt, &lastSeen, &revokedAt,
		&credentialEpoch, &remembered)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	sess := &Session{
		ID: id, TenantID: tenantID, UserID: userID, TokenHash: hash,
		CreatedAt: createdAt, ExpiresAt: expiresAt, RevokedAt: revokedAt,
		Remembered: remembered,
	}
	if lastSeen != nil {
		sess.LastSeen = *lastSeen
	}
	// A NULL credential_epoch stays the ZERO time, which CredentialEpochMatches treats as older
	// than any credential — so a pre-0018 row the backfill did not reach fails closed rather than
	// authenticating forever against a credential it cannot name.
	if credentialEpoch != nil {
		sess.CredentialEpoch = credentialEpoch.UTC()
	}
	return sess, nil
}

// Revoke implements SessionStore via the bootstrap function.
func (s *PgSessionStore) Revoke(ctx context.Context, tokenHash []byte) error {
	_, err := s.Pool.Exec(ctx, "SELECT cp_session_revoke($1)", tokenHash)
	return err
}

// TouchLastSeen implements SessionStore via the bootstrap function.
func (s *PgSessionStore) TouchLastSeen(ctx context.Context, tokenHash []byte, at time.Time) error {
	_, err := s.Pool.Exec(ctx, "SELECT cp_session_touch_last_seen($1, $2)", tokenHash, at)
	return err
}

// MarkMFAVerified implements SessionStore: record that a TOTP code verified against `generation` was
// presented IN this session, only while that generation is still the user's current one and the
// session is live. Returns false (no error) when it no longer is, e.g. a re-enrollment committed
// between the code check and this update; the session then simply is not MFA-verified.
func (s *PgSessionStore) MarkMFAVerified(ctx context.Context, tenantID, userID, sessionID string, generation int64) (bool, error) {
	if generation <= 0 || !isUUID(sessionID) {
		return false, nil
	}
	var ok bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE user_session
			   SET mfa_verified_at = now(), mfa_generation = $4
			 WHERE id = $3 AND tenant_id = $1 AND user_id = $2
			   AND revoked_at IS NULL AND expires_at > now()
			   AND $4 = (SELECT u.mfa_generation FROM app_user u WHERE u.id = $2 AND u.tenant_id = $1)`,
			tenantID, userID, sessionID, generation)
		if err != nil {
			return err
		}
		ok = ct.RowsAffected() == 1
		return nil
	})
	return ok, err
}

// MFAFresh implements SessionStore: the same predicate cp_platform_check applies (live session of THIS user,
// verified within maxAge on the database clock, verification generation == the user's current one).
func (s *PgSessionStore) MFAFresh(ctx context.Context, tenantID, userID, sessionID string, maxAge time.Duration) (bool, error) {
	if !isUUID(sessionID) || !isUUID(userID) {
		return false, nil
	}
	var ok bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1
			      FROM user_session s
			      JOIN app_user u ON u.id = s.user_id AND u.tenant_id = s.tenant_id
			     WHERE s.id = $3 AND s.tenant_id = $1 AND s.user_id = $2
			       AND s.revoked_at IS NULL AND s.expires_at > now()
			       AND s.mfa_verified_at IS NOT NULL
			       AND s.mfa_verified_at > now() - make_interval(secs => $4)
			       AND u.mfa_generation > 0 AND s.mfa_generation = u.mfa_generation
			       AND u.disabled_at IS NULL)`,
			tenantID, userID, sessionID, maxAge.Seconds()).Scan(&ok)
	})
	return ok, err
}

// StepUpSnapshot implements SessionStore: ONE statement reads the session's verification, the generation it
// was verified against and the user's credential epoch, and requires that generation to still be the user's
// current one. No row = not fresh.
func (s *PgSessionStore) StepUpSnapshot(ctx context.Context, tenantID, userID, sessionID string, maxAge time.Duration) (StepUp, error) {
	if !isUUID(sessionID) || !isUUID(userID) {
		return StepUp{}, nil
	}
	var out StepUp
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var epoch *time.Time
		err := tx.QueryRow(ctx, `
			SELECT s.mfa_generation, c.updated_at
			  FROM user_session s
			  JOIN app_user u ON u.id = s.user_id AND u.tenant_id = s.tenant_id
			  LEFT JOIN user_credential c ON c.user_id = u.id AND c.tenant_id = u.tenant_id
			 WHERE s.id = $3 AND s.tenant_id = $1 AND s.user_id = $2
			   AND s.revoked_at IS NULL AND s.expires_at > now()
			   AND s.mfa_verified_at IS NOT NULL
			   AND s.mfa_verified_at > now() - make_interval(secs => $4)
			   AND u.mfa_generation > 0 AND s.mfa_generation = u.mfa_generation
			   AND u.disabled_at IS NULL`,
			tenantID, userID, sessionID, maxAge.Seconds()).Scan(&out.MFAGeneration, &epoch)
		if errors.Is(err, pgx.ErrNoRows) {
			out = StepUp{}
			return nil
		}
		if err != nil {
			return err
		}
		out.Fresh = true
		if epoch != nil {
			out.CredentialEpoch = epoch.UTC()
		}
		return nil
	})
	return out, err
}

// SessionLive implements SessionStore: the session exists for this user, is not revoked and has not expired.
func (s *PgSessionStore) SessionLive(ctx context.Context, tenantID, userID, sessionID string) (bool, error) {
	if !isUUID(sessionID) || !isUUID(userID) {
		return false, nil
	}
	var ok bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1
			      FROM user_session s
			     WHERE s.id = $3 AND s.tenant_id = $1 AND s.user_id = $2
			       AND s.revoked_at IS NULL AND s.expires_at > now())`,
			tenantID, userID, sessionID).Scan(&ok)
	})
	return ok, err
}

// RevokeAllForUser implements SessionStore: revoke every live session of a user except
// keepTokenHash.
//
// Unlike the other three methods this does NOT use a 0003 bootstrap function, and that is the
// point. Those exist because a token→session lookup happens before any tenant is known; here the
// caller is already authenticated, so the query runs TENANT-PINNED and RLS is the thing that keeps
// `WHERE user_id = $1` from reaching an identically-named user id in another tenant. Adding an
// RLS-bypassing SECURITY DEFINER function for a mass revocation keyed on a caller-supplied user id
// would have been a strictly worse trade.
//
// `revoked_at IS NULL` keeps the count honest (an already-revoked row is not re-stamped and is not
// counted). Expired-but-unrevoked rows ARE revoked: they cost nothing to stamp and it makes the
// post-condition simple — after this call the user holds no session row that could come back.
func (s *PgSessionStore) RevokeAllForUser(ctx context.Context, tenantID, userID string, keepTokenHash []byte) (int, error) {
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// A nil keep hash must revoke everything. `token_hash <> NULL` is NULL (never true), so
		// the comparison is guarded by the IS NULL test rather than relying on the parameter.
		ct, err := tx.Exec(ctx, `
			UPDATE user_session
			   SET revoked_at = now()
			 WHERE user_id = $1
			   AND revoked_at IS NULL
			   AND ($2::bytea IS NULL OR token_hash <> $2::bytea)
		`, userID, keepTokenHash)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// -------------------------------------------------------------------------------------
// PgTenantResolver — login-time slug→id resolution via the bootstrap function.
// -------------------------------------------------------------------------------------

// PgTenantResolver resolves a tenant slug to its id at login. It is the concrete
// TenantResolver wired into AuthService in production.
type PgTenantResolver struct {
	Pool *pgxpool.Pool
}

// NewPgTenantResolver constructs a PgTenantResolver.
func NewPgTenantResolver(pool *pgxpool.Pool) *PgTenantResolver { return &PgTenantResolver{Pool: pool} }

var _ TenantResolver = (*PgTenantResolver)(nil)

// ResolveTenant implements TenantResolver: returns the tenant id for an active slug, or
// ErrNoTenant. The bootstrap function returns SQL NULL for an unknown/disabled tenant, which
// scans into a nil pointer here.
func (r *PgTenantResolver) ResolveTenant(ctx context.Context, slug string) (string, error) {
	var id *string
	err := r.Pool.QueryRow(ctx, "SELECT cp_resolve_tenant_by_slug($1)::text", slug).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNoTenant
		}
		return "", err
	}
	if id == nil {
		return "", ErrNoTenant
	}
	return *id, nil
}

// -------------------------------------------------------------------------------------
// PgMachineStore — MachineStore over the `machine` table (migrations/0001_core.sql). Every
// method runs tenant-pinned via withTenant, so RLS confines it to the caller's tenant; the
// group resolved here is the machine's REAL group, which the handlers use for authorization
// instead of the (attacker-controllable) request body — this is the D1 security fix.
//
// `Machine.Name` maps to the table's `hostname` column (a display label). The machine table has
// TWO identifiers (0001_core.sql): the primary key `id` and the stable agent identity `device_id`
// (UNIQUE per tenant). GetMachine keys on `device_id` — the identity the grant/session/mint paths
// carry (the console mints for `session.device`, H3 binds the grant to it) — while GetMachineByID
// keys on the PK for the REST read path.
// -------------------------------------------------------------------------------------

// PgMachineStore is the pgx-backed MachineStore.
type PgMachineStore struct {
	Pool *pgxpool.Pool
	// LookupPool, when set, serves KeyTombstoned, the one pre-authentication read on the anonymous redeem and enroll
	// doors, under the bounded lifecycle (docs/66 release gate R1). nil uses Pool.
	LookupPool *pgxpool.Pool
}

// NewPgMachineStore constructs a PgMachineStore.
func NewPgMachineStore(pool *pgxpool.Pool) *PgMachineStore { return &PgMachineStore{Pool: pool} }

var _ MachineStore = (*PgMachineStore)(nil)

// scanMachine reads the standard machine projection (id, tenant, device_id, group, hostname,
// pubkey hex — ” when unpinned, i.e. the legacy ”::bytea enrollment) plus the migrations/0017
// console-enrichment columns (os, last_seen) and the joined group name.
//
// The join is LEFT: a machine whose group row is missing must still list (with an empty
// GroupName), because GroupID — not the name — is what authorization scopes against, and a
// display-only lookup failing must never make a machine invisible to the RBAC filter.
func scanMachine(row pgx.Row) (*Machine, error) {
	var m Machine
	var groupName *string
	if err := row.Scan(&m.ID, &m.TenantID, &m.DeviceID, &m.GroupID, &m.Name, &m.Pubkey,
		&m.OS, &m.LastSeen, &groupName, &m.Ephemeral, &m.ExpiresAt, &m.Status, &m.Alias, &m.Note,
		&m.RequireSessionPolicy, &m.AgentVersion, &m.AgentVersionSeenAt, &m.LoggedInUser); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMachineNotFound
		}
		return nil, err
	}
	if groupName != nil {
		m.GroupName = *groupName
	}
	return &m, nil
}

// selectMachine is the standard projection. `ephemeral`/`expires_at` (migrations/0013) are included
// deliberately: they were previously omitted, which silently made `Machine.Ephemeral` ALWAYS false
// out of every PgMachineStore method — so no caller could distinguish an attended-session guest
// from a managed machine, and `json:"ephemeral,omitempty"` meant no client could compensate either.
const selectMachine = `
	SELECT m.id::text, m.tenant_id::text, m.device_id, m.group_id::text, m.hostname,
	       encode(m.pubkey, 'hex'), m.os, m.last_seen, g.name, m.ephemeral, m.expires_at, m.status, m.alias, m.note,
	       m.require_session_policy, m.agent_version, m.agent_version_seen_at, m.logged_in_user
	FROM machine m
	LEFT JOIN machine_group g ON g.id = m.group_id
	WHERE `

// GetMachine implements MachineStore: resolve one machine BY DEVICE ID inside the tenant. RLS
// already scopes the row to the pinned tenant, so no explicit tenant_id filter is needed. This is
// the security-critical path — the grant/session/mint handlers pass the device id — so looking up
// by `device_id` (not the PK) is what lets a legitimately enrolled machine resolve. An unknown
// device id → ErrMachineNotFound.
func (s *PgMachineStore) GetMachine(ctx context.Context, tenantID, deviceID string) (*Machine, error) {
	var out *Machine
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		m, err := scanMachine(tx.QueryRow(ctx, selectMachine+"m.device_id = $1", deviceID))
		out = m
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetMachineByID implements MachineStore: resolve one machine BY PRIMARY KEY inside the tenant,
// backing the REST `/machines/{id}` read path. An unknown id → ErrMachineNotFound, and so does an
// id no `uuid` column could hold (pathid.go) — otherwise `/machines/not-a-uuid` reaches the cast
// and 22P02 surfaces as a 500.
func (s *PgMachineStore) GetMachineByID(ctx context.Context, tenantID, id string) (*Machine, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrMachineNotFound
	}
	var out *Machine
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		m, err := scanMachine(tx.QueryRow(ctx, selectMachine+"m.id = $1", id))
		out = m
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EnrollMachine implements MachineStore: insert a machine row, tenant-pinned (the RLS WITH CHECK
// confines the write to the pinned tenant, and the composite FK forces group_id into the same
// tenant). The primary key is assigned by the DB (gen_random_uuid()) and read back into m.ID, so
// it is genuinely DISTINCT from device_id; device_id is the caller-supplied stable agent identity
// (required + UNIQUE per tenant — a duplicate maps to ErrMachineDeviceIDTaken). m.Pubkey (hex)
// is decoded into the `pubkey` bytea: the agent-key pin from token redemption (M1). Empty stays
// allowed — the legacy authenticated /enroll path enrolls without a key.
func (s *PgMachineStore) EnrollMachine(ctx context.Context, tenantID string, m *Machine) error {
	pub, err := hex.DecodeString(m.Pubkey)
	if err != nil {
		return fmt.Errorf("machine pubkey is not valid hex: %w", err)
	}
	err = withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO machine (tenant_id, device_id, group_id, hostname, pubkey, os, require_session_policy)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id::text
		`, tenantID, m.DeviceID, m.GroupID, m.Name, pub, m.OS, m.RequireSessionPolicy).Scan(&m.ID)
	})
	if isUniqueViolation(err) {
		return ErrMachineDeviceIDTaken
	}
	return err
}

// SetMachineStatus implements MachineStore: UPDATE machine.status BY PRIMARY KEY, tenant-pinned (RLS
// confines the write). An invalid status is ErrInvalidMachineStatus (before touching the DB); an id no
// `uuid` column could hold, or one not in the pinned tenant (0 rows affected), is ErrMachineNotFound.
func (s *PgMachineStore) SetMachineStatus(ctx context.Context, tenantID, machineID, status string) error {
	if !IsValidMachineStatus(status) {
		return ErrInvalidMachineStatus
	}
	if namesNoUUIDRow(machineID) {
		return ErrMachineNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE machine SET status = $2 WHERE id = $1`, machineID, status)
		if err != nil {
			return mapMachineGuardError(err)
		}
		if ct.RowsAffected() == 0 {
			return ErrMachineNotFound
		}
		return nil
	})
}

// SetMachineGroup implements MachineStore: reassign the machine (BY PK) to groupID. The composite FK
// (tenant_id, group_id) → machine_group guarantees the target group is real AND in this tenant, so a bad or
// cross-tenant group id fails the FK (23503), mapped to ErrInvalidMachineGroup; an unknown machine updates
// zero rows → ErrMachineNotFound.
func (s *PgMachineStore) SetMachineGroup(ctx context.Context, tenantID, machineID, groupID string) error {
	return s.setMachineGroup(ctx, tenantID, machineID, groupID, nil)
}

// SetMachineGroupIfTree implements MachineStore: SetMachineGroup conditional on the tenant's group tree
// still being at expectTree (docs/62 R2) — the shared tree lock is held to the end of the transaction, so a
// reparent cannot interleave between the check and the write.
func (s *PgMachineStore) SetMachineGroupIfTree(ctx context.Context, tenantID, machineID, groupID string, expectTree int64) error {
	return s.setMachineGroup(ctx, tenantID, machineID, groupID, &expectTree)
}

func (s *PgMachineStore) setMachineGroup(ctx context.Context, tenantID, machineID, groupID string, expectTree *int64) error {
	if namesNoUUIDRow(machineID) {
		return ErrMachineNotFound
	}
	if namesNoUUIDRow(groupID) {
		return ErrInvalidMachineGroup
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if expectTree != nil {
			if err := checkGroupTreeVersionTx(ctx, tx, tenantID, *expectTree); err != nil {
				return err
			}
		}
		ct, err := tx.Exec(ctx, `UPDATE machine SET group_id = $2 WHERE id = $1`, machineID, groupID)
		if err != nil {
			if isForeignKeyViolation(err) {
				return ErrInvalidMachineGroup
			}
			return mapMachineGuardError(err)
		}
		if ct.RowsAffected() == 0 {
			return ErrMachineNotFound
		}
		return nil
	})
}

// SetMachineAlias implements MachineStore: set (or clear) the machine's friendly name BY PK within the
// tenant. A non-uuid id names no row (→ ErrMachineNotFound before touching the DB); an id that resolves
// to no row updates zero rows → ErrMachineNotFound. The value is written verbatim (the handler validated
// it); RLS confines the UPDATE to the pinned tenant.
func (s *PgMachineStore) SetMachineAlias(ctx context.Context, tenantID, machineID, alias string) error {
	if namesNoUUIDRow(machineID) {
		return ErrMachineNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE machine SET alias = $2 WHERE id = $1`, machineID, alias)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrMachineNotFound
		}
		return nil
	})
}

// SetMachineNote implements MachineStore: set (or clear) the machine's free-text note BY PK within the
// tenant. A non-uuid id names no row (→ ErrMachineNotFound before the DB); a row-count of 0 → ErrMachineNotFound.
// The value is written verbatim (the handler validated it); RLS confines the UPDATE to the pinned tenant.
func (s *PgMachineStore) SetMachineNote(ctx context.Context, tenantID, machineID, note string) error {
	if namesNoUUIDRow(machineID) {
		return ErrMachineNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE machine SET note = $2 WHERE id = $1`, machineID, note)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrMachineNotFound
		}
		return nil
	})
}

// LookupDeviceIdentity implements MachineStore via the SECURITY DEFINER
// cp_machine_identity_by_device_id (migrations/0010). It runs ON THE POOL, not withTenant: the
// caller (the signaling server, through GET /internal/devices/{id}/identity) has no tenant context
// — resolving the tenant is the whole point of the call — so RLS would filter the row away. The
// function excludes rows with no pinned key, so an unpinned machine is indistinguishable from an
// unknown one here and the handler fails closed rather than reporting "enrolled but unverifiable".
func (s *PgMachineStore) LookupDeviceIdentity(ctx context.Context, deviceID string) (*DeviceIdentity, error) {
	if deviceID == "" {
		return nil, ErrMachineNotFound
	}
	var (
		id, tenantID, status string
		pub                  []byte
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT device_id, tenant_id::text, pubkey, status
		FROM cp_machine_identity_by_device_id($1)
	`, deviceID).Scan(&id, &tenantID, &pub, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMachineNotFound
		}
		return nil, err
	}
	if len(pub) == 0 {
		return nil, ErrMachineNotFound
	}
	return &DeviceIdentity{DeviceID: id, TenantID: tenantID, Pubkey: hex.EncodeToString(pub), Status: status}, nil
}

// KeyTombstoned implements MachineStore (docs/65 D-C9) via the SECURITY DEFINER cp_machine_key_removed
// (migrations/0068): the enrollment path has no tenant context for another tenant's rows, so RLS would hide
// exactly the rows this must see. It answers a boolean and nothing else.
func (s *PgMachineStore) KeyTombstoned(ctx context.Context, pubkeyHex string) (bool, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(pubkeyHex))
	if err != nil || len(raw) == 0 {
		return false, nil
	}
	var removed bool
	err = boundedLookup(ctx, lookupPoolOr(s.LookupPool, s.Pool), func(c *pgxpool.Conn) error {
		return c.QueryRow(ctx, `SELECT cp_machine_key_removed($1)`, raw).Scan(&removed)
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

// mapMachineGuardError turns the machine_directive_guard trigger's SQLSTATEs into the store's sentinels.
func mapMachineGuardError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "DR001":
			return ErrMachineHasActiveDirective
		case "DR002":
			return ErrMachineRemoved
		}
	}
	return err
}

// RecordRequireSessionPolicy implements MachineStore: refresh machine.require_session_policy from the
// agent-asserted values the presence feed carried. Enrollment writes the column once (migrations/0037);
// this is what makes an operator's later config change reach the control plane, and that population —
// agents already in the field — is the whole reason 0037 exists. ONE statement over parallel arrays,
// same shape as RecordObservedOS above.
//
// `m.require_session_policy IS DISTINCT FROM u.want` makes the steady state write ZERO rows, so repeated
// presence polls generate no dead tuples. RLS IS THE TENANT FILTER, exactly as in RecordObservedOS:
// foreign ids in the cross-tenant feed match no visible row and are neither written nor counted.
//
// No validity bound, deliberately: unlike os there is no malformed bool. The value is agent-asserted and
// can only cause a policy to be MINTED, never suppressed (see Machine.RequireSessionPolicy).
func (s *PgMachineStore) RecordRequireSessionPolicy(ctx context.Context, tenantID string, flagByDevice map[string]bool) (int, error) {
	ids := make([]string, 0, len(flagByDevice))
	values := make([]bool, 0, len(flagByDevice))
	for id, want := range flagByDevice {
		ids = append(ids, id)
		values = append(values, want)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE machine m SET require_session_policy = u.want
			  FROM unnest($1::text[], $2::boolean[]) AS u(device_id, want)
			 WHERE m.device_id = u.device_id
			   AND m.require_session_policy IS DISTINCT FROM u.want
		`, ids, values)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ListMachines implements MachineStore: every machine in the tenant (RLS-scoped). Callers filter
// the result to the groups their memberships actually cover (Grant.AllowsInGroup).
func (s *PgMachineStore) ListMachines(ctx context.Context, tenantID string) ([]Machine, error) {
	var out []Machine
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// `WHERE NOT m.ephemeral` is the FLEET-LISTING CONTRACT, stated in
		// migrations/0013_attended_sessions.sql ("hidden from the fleet listing") and
		// docs/12 §10.1, and previously honoured only by InMemoryMachineStore — so the fake and
		// the production store disagreed, and every test asserting the contract ran against the
		// fake. Without it an attended guest's short-lived machine row appears in the managed
		// fleet with an enabled Connect button, and a session opened against it FKs a row that
		// `ON DELETE CASCADE` erases when the attended session ends.
		rows, err := tx.Query(ctx, `
			SELECT m.id::text, m.tenant_id::text, m.device_id, m.group_id::text, m.hostname,
			       encode(m.pubkey, 'hex'), m.os, m.last_seen, g.name, m.ephemeral, m.expires_at, m.status, m.alias, m.note,
			       m.require_session_policy, m.agent_version, m.agent_version_seen_at, m.logged_in_user
			FROM machine m
			LEFT JOIN machine_group g ON g.id = m.group_id
			WHERE NOT m.ephemeral
			ORDER BY m.enrolled_at LIMIT 10001
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Machine
			var groupName *string
			if err := rows.Scan(&m.ID, &m.TenantID, &m.DeviceID, &m.GroupID, &m.Name, &m.Pubkey,
				&m.OS, &m.LastSeen, &groupName, &m.Ephemeral, &m.ExpiresAt, &m.Status, &m.Alias, &m.Note,
				&m.RequireSessionPolicy, &m.AgentVersion, &m.AgentVersionSeenAt, &m.LoggedInUser); err != nil {
				return err
			}
			if groupName != nil {
				m.GroupName = *groupName
			}
			if err := appendListRow(&out, m); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TouchLastSeen implements MachineStore: stamp machine.last_seen for the tenant's own devices
// (migrations/0017). ONE statement with the id list as an array, so a 500-machine fleet is one
// round trip rather than 500.
//
// The `last_seen < $2` guard makes the stamp MONOTONIC. The value is the snapshot's timestamp, and
// snapshots are cached for a TTL, so two concurrent listings can carry different-aged snapshots —
// without the guard the one holding the older snapshot rewrites `last_seen` BACKWARDS, and "offline
// since" jumps into the past for no reason the operator can see. It also means a listing that
// learns nothing new writes no rows at all, which drops the write amplification of repeated console
// polls within one cache TTL to zero.
//
// RLS IS THE TENANT FILTER, and that is the whole security argument here. The presence feed is
// cross-tenant (server/signaling/presence.go), so this method is routinely handed device ids
// belonging to OTHER tenants. Because the UPDATE runs tenant-pinned, those ids match no visible
// row: they are not written, and the returned count does not reveal that they exist. There is
// deliberately no explicit `AND tenant_id = $x` — adding one would imply RLS is not trusted here,
// when it is exactly the mechanism relied on everywhere else in this file.
func (s *PgMachineStore) TouchLastSeen(ctx context.Context, tenantID string, deviceIDs []string, at time.Time) (int, error) {
	if len(deviceIDs) == 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE machine SET last_seen = $2
			 WHERE device_id = ANY($1::text[])
			   AND (last_seen IS NULL OR last_seen < $2)
		`, deviceIDs, at)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// StampPresence implements MachineStore through cp_presence_stamp (migrations/0079), the one cross-tenant
// write the presence sweep needs: UPDATE on machine.last_seen only, forward-only, clamped to the
// database's now(). No tenant is pinned, so this is NOT RLS-filtered; the function is what bounds it.
func (s *PgMachineStore) StampPresence(ctx context.Context, deviceIDs []string, at time.Time) (int, error) {
	if len(deviceIDs) == 0 {
		return 0, nil
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT cp_presence_stamp($1::text[], $2)`, deviceIDs, at).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// RecordObservedOS implements MachineStore: refresh machine.os from the agent-asserted values the
// presence feed carried. Enrollment writes the column once (migrations/0017); this is what keeps
// it true across OS upgrades. ONE statement over parallel arrays, same shape as TouchLastSeen.
//
// `m.os IS DISTINCT FROM u.os` makes the steady state write ZERO rows — the value changes only
// after an OS upgrade or the first presence pass over a pre-os enrollment — so repeated console
// polls generate no dead tuples. RLS IS THE TENANT FILTER, exactly as in TouchLastSeen above:
// foreign ids in the cross-tenant feed match no visible row and are neither written nor counted.
//
// The bound is enforced HERE as well as at signaling receipt (boundOSDescription) and at the
// caller: this store holds its own invariants rather than inheriting them from today's only
// feeder. Same constant as enrollment's os/name checks, so the two write paths cannot drift.
func (s *PgMachineStore) RecordObservedOS(ctx context.Context, tenantID string, osByDevice map[string]string) (int, error) {
	ids := make([]string, 0, len(osByDevice))
	values := make([]string, 0, len(osByDevice))
	for id, os := range osByDevice {
		if os == "" || len(os) > maxMachineNameLen {
			continue
		}
		ids = append(ids, id)
		values = append(values, os)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE machine m SET os = u.os
			  FROM unnest($1::text[], $2::text[]) AS u(device_id, os)
			 WHERE m.device_id = u.device_id
			   AND m.os IS DISTINCT FROM u.os
		`, ids, values)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// RecordAgentVersion implements MachineStore. Modelled exactly on RecordObservedOS above, including
// the deliberate absence of an explicit tenant_id predicate: withTenant pins app.current_tenant and
// RLS is the tenant filter, which is what makes it safe to hand this method the CROSS-TENANT device
// list the presence feed produces. Adding a tenant_id filter here would imply RLS is not trusted;
// the cross-tenant test proves it instead.
//
// agent_version_seen_at is stamped inside the same UPDATE and therefore only moves when the version
// actually changed, because the IS DISTINCT FROM guard is what selects the rows. That is the whole
// reason the steady state writes zero rows — see 0039's header.
func (s *PgMachineStore) RecordAgentVersion(ctx context.Context, tenantID string, versionByDevice map[string]string) (int, error) {
	ids := make([]string, 0, len(versionByDevice))
	values := make([]string, 0, len(versionByDevice))
	for id, v := range versionByDevice {
		// Empty is skipped, not written: an older agent that reports nothing must never blank a
		// version already recorded. The length bound is enforced here as well as at signaling
		// because the store holds its own invariants.
		if v == "" || len(v) > maxAgentVersionLen {
			continue
		}
		ids = append(ids, id)
		values = append(values, v)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE machine m SET agent_version = u.v, agent_version_seen_at = now()
			  FROM unnest($1::text[], $2::text[]) AS u(device_id, v)
			 WHERE m.device_id = u.device_id
			   AND m.agent_version IS DISTINCT FROM u.v
		`, ids, values)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// RecordLoggedInUser implements MachineStore. Modelled exactly on RecordObservedOS above,
// including the deliberate absence of an explicit tenant_id predicate — withTenant pins
// app.current_tenant and RLS is the tenant filter. The IS DISTINCT FROM guard makes the
// steady state (no change) write zero rows, matching the spirit of RecordObservedOS.
//
// The bound is enforced HERE as well as at signaling receipt and in the caller, same as every
// other presence-refreshed column.
func (s *PgMachineStore) RecordLoggedInUser(ctx context.Context, tenantID string, userByDevice map[string]string) (int, error) {
	ids := make([]string, 0, len(userByDevice))
	values := make([]string, 0, len(userByDevice))
	for id, user := range userByDevice {
		if user == "" || len(user) > maxLoggedInUserLen {
			continue
		}
		ids = append(ids, id)
		values = append(values, user)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE machine m SET logged_in_user = u.lu
			  FROM unnest($1::text[], $2::text[]) AS u(device_id, lu)
			 WHERE m.device_id = u.device_id
			   AND m.logged_in_user IS DISTINCT FROM u.lu
		`, ids, values)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// -------------------------------------------------------------------------------------
// PgMachinePropertyStore — MachinePropertyStore over machine_property (migrations/0024). Every
// method runs inside withTenant, so RLS confines it to the pinned tenant and no query carries an
// explicit tenant_id filter. The composite FK (tenant_id, machine_id) -> machine(tenant_id, id) is
// what stops a property from naming another tenant's machine even by its PK (see 0024's header).
// -------------------------------------------------------------------------------------

// PgMachinePropertyStore is the pgx-backed MachinePropertyStore.
type PgMachinePropertyStore struct {
	Pool *pgxpool.Pool
}

// NewPgMachinePropertyStore constructs a PgMachinePropertyStore.
func NewPgMachinePropertyStore(pool *pgxpool.Pool) *PgMachinePropertyStore {
	return &PgMachinePropertyStore{Pool: pool}
}

var _ MachinePropertyStore = (*PgMachinePropertyStore)(nil)

// ListProperties implements MachinePropertyStore: every property on a machine in the tenant, ordered
// by key. RLS scopes the rows, so there is no explicit tenant filter. An id no uuid column could hold
// owns nothing (short-circuit rather than 500 at the ::uuid cast, same as GetMachineByID).
func (s *PgMachinePropertyStore) ListProperties(ctx context.Context, tenantID, machineID string) ([]MachineProperty, error) {
	if namesNoUUIDRow(machineID) {
		return nil, nil
	}
	var out []MachineProperty
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT key, value FROM machine_property
			WHERE machine_id = $1
			ORDER BY key
		`, machineID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p MachineProperty
			if err := rows.Scan(&p.Key, &p.Value); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetProperty implements MachinePropertyStore: upsert one key/value, tenant-pinned. RLS WITH CHECK
// confines the write to the pinned tenant; the composite FK additionally forces the property onto a
// machine in the SAME tenant, so a caller can never annotate another tenant's machine even by naming
// its PK. An unknown machine id (or one made invisible cross-tenant) has no (tenant_id, id) row, so
// the FK RAISES 23503 — mapped to ErrMachineNotFound OUTSIDE the closure, exactly like EnrollMachine
// maps a unique violation. A non-uuid id is screened first so it 404s rather than 500ing at the cast.
func (s *PgMachinePropertyStore) SetProperty(ctx context.Context, tenantID, machineID, key, value string) error {
	if namesNoUUIDRow(machineID) {
		return ErrMachineNotFound
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO machine_property (tenant_id, machine_id, key, value)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, machine_id, key)
			DO UPDATE SET value = EXCLUDED.value, updated_at = now()
		`, tenantID, machineID, key, value)
		return err
	})
	if isForeignKeyViolation(err) {
		return ErrMachineNotFound
	}
	return err
}

// DeleteProperty implements MachinePropertyStore: remove one key, tenant-pinned. RLS makes another
// tenant's row invisible to the DELETE's USING clause, so a mis-scoped delete touches 0 rows rather
// than another tenant's data — which is indistinguishable from a genuinely absent key, and both
// return ErrMachinePropertyNotFound (a 404). A non-uuid id owns nothing, likewise not-found.
func (s *PgMachinePropertyStore) DeleteProperty(ctx context.Context, tenantID, machineID, key string) error {
	if namesNoUUIDRow(machineID) {
		return ErrMachinePropertyNotFound
	}
	var affected int64
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			DELETE FROM machine_property WHERE machine_id = $1 AND key = $2
		`, machineID, key)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrMachinePropertyNotFound
	}
	return nil
}

// MachineIDsWithProperty implements MachinePropertyStore: the machine ids in the tenant whose bag has
// `key` (matching `value` exactly when non-empty), RLS-scoped. The PK (tenant_id, machine_id, key)
// means at most one row per (machine, key), so the ids are already unique. The value clause is added
// only when a value is requested — an empty value means "any value", NOT "the empty-string value".
func (s *PgMachinePropertyStore) MachineIDsWithProperty(ctx context.Context, tenantID, key, value string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var err error
		if value == "" {
			rows, err = tx.Query(ctx, `SELECT machine_id::text FROM machine_property WHERE key = $1`, key)
		} else {
			rows, err = tx.Query(ctx, `SELECT machine_id::text FROM machine_property WHERE key = $1 AND value = $2`, key, value)
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = struct{}{}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// -------------------------------------------------------------------------------------
// PgTenantIPAllowlistStore — TenantIPAllowlistStore over tenant_ip_allowlist (migrations/0025). Every
// method runs inside withTenant, so RLS confines it to the pinned tenant and no query carries an
// explicit tenant_id filter. The store holds no IP logic — it is a tenant-scoped string set; the
// handlers own normalization and matching (see tenantipallow.go / ipallow.go).
// -------------------------------------------------------------------------------------

// PgTenantIPAllowlistStore is the pgx-backed TenantIPAllowlistStore.
type PgTenantIPAllowlistStore struct {
	Pool *pgxpool.Pool
}

// NewPgTenantIPAllowlistStore constructs a PgTenantIPAllowlistStore.
func NewPgTenantIPAllowlistStore(pool *pgxpool.Pool) *PgTenantIPAllowlistStore {
	return &PgTenantIPAllowlistStore{Pool: pool}
}

var _ TenantIPAllowlistStore = (*PgTenantIPAllowlistStore)(nil)

// ListCIDRs implements TenantIPAllowlistStore: the tenant's allow-list CIDRs, ordered by cidr. RLS
// scopes the rows, so there is no explicit tenant filter.
func (s *PgTenantIPAllowlistStore) ListCIDRs(ctx context.Context, tenantID string) ([]string, error) {
	var out []string
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT cidr FROM tenant_ip_allowlist ORDER BY cidr`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AddCIDR implements TenantIPAllowlistStore: idempotent insert of one CIDR, tenant-pinned. RLS WITH
// CHECK confines the write to the pinned tenant; ON CONFLICT DO NOTHING makes a re-add a no-op.
func (s *PgTenantIPAllowlistStore) AddCIDR(ctx context.Context, tenantID, cidr string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_ip_allowlist (tenant_id, cidr)
			VALUES ($1, $2)
			ON CONFLICT (tenant_id, cidr) DO NOTHING
		`, tenantID, cidr)
		return err
	})
}

// RemoveCIDR implements TenantIPAllowlistStore: remove one CIDR, tenant-pinned. RLS makes another
// tenant's row invisible to the DELETE, so a mis-scoped delete touches 0 rows rather than another
// tenant's data — indistinguishable from a genuinely absent CIDR, and both return
// ErrTenantIPAllowlistEntryNotFound (a 404).
func (s *PgTenantIPAllowlistStore) RemoveCIDR(ctx context.Context, tenantID, cidr string) error {
	var affected int64
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM tenant_ip_allowlist WHERE cidr = $1`, cidr)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrTenantIPAllowlistEntryNotFound
	}
	return nil
}

// tenantIPAllowlistLockNS namespaces the per-tenant advisory lock (first int4 key of the 2-int form) so
// it cannot collide with any other advisory lock in the system.
const tenantIPAllowlistLockNS = 0x1A110C

// listCIDRsInTx reads the tenant's CIDRs within an existing transaction (ORDER BY cidr), for the
// read-check-write the guarded mutations do under the advisory lock.
func listCIDRsInTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT cidr FROM tenant_ip_allowlist ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddCIDRGuarded implements TenantIPAllowlistStore atomically. It takes a per-tenant advisory-XACT lock
// FIRST, so concurrent guarded mutations to the same tenant SERIALIZE (a second one blocks until this
// transaction commits, then sees the true post-commit state). Under READ COMMITTED a single-transaction
// recheck WITHOUT the lock would not close the race — two concurrent mutations would each miss the
// other's uncommitted change (the project's "one transaction is not atomicity" trap). Reads the current
// list, computes resulting = current ∪ {cidr}, and INSERTs only if `safe(resulting)`; otherwise NO
// change and ErrWouldLockOut. Idempotent (ON CONFLICT DO NOTHING).
func (s *PgTenantIPAllowlistStore) AddCIDRGuarded(ctx context.Context, tenantID, cidr string, safe CoverageCheck) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockTenantIPAllowlist(ctx, tx, tenantID); err != nil {
			return err
		}
		current, err := listCIDRsInTx(ctx, tx)
		if err != nil {
			return err
		}
		resulting := current
		if !contains(current, cidr) {
			resulting = append(append([]string{}, current...), cidr)
		}
		if !safe(resulting) {
			return ErrWouldLockOut
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO tenant_ip_allowlist (tenant_id, cidr)
			VALUES ($1, $2)
			ON CONFLICT (tenant_id, cidr) DO NOTHING
		`, tenantID, cidr)
		return err
	})
}

// RemoveCIDRGuarded implements TenantIPAllowlistStore atomically, mirroring AddCIDRGuarded: advisory
// lock, read current, and if cidr is present compute resulting = current \ {cidr} and DELETE only if
// `safe(resulting)`; ErrTenantIPAllowlistEntryNotFound when absent, ErrWouldLockOut when it would exclude
// the caller. Removing to an empty (open) list is always safe.
func (s *PgTenantIPAllowlistStore) RemoveCIDRGuarded(ctx context.Context, tenantID, cidr string, safe CoverageCheck) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockTenantIPAllowlist(ctx, tx, tenantID); err != nil {
			return err
		}
		current, err := listCIDRsInTx(ctx, tx)
		if err != nil {
			return err
		}
		if !contains(current, cidr) {
			return ErrTenantIPAllowlistEntryNotFound
		}
		resulting := make([]string, 0, len(current))
		for _, c := range current {
			if c != cidr {
				resulting = append(resulting, c)
			}
		}
		if !safe(resulting) {
			return ErrWouldLockOut
		}
		_, err = tx.Exec(ctx, `DELETE FROM tenant_ip_allowlist WHERE cidr = $1`, cidr)
		return err
	})
}

// lockTenantIPAllowlist takes the per-tenant advisory-XACT lock (released automatically at transaction
// end). hashtextextended maps the tenant id to the second int8 key; the constant namespace is the first.
func lockTenantIPAllowlist(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, tenantIPAllowlistLockNS, tenantID)
	return err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------------------
// PgDynamicGroupStore — DynamicGroupStore over dynamic_group (migrations/0026). Every method runs
// inside withTenant, so RLS confines it to the pinned tenant and no query carries an explicit tenant_id
// filter. The DB assigns the id (gen_random_uuid()); a name collision surfaces as ErrDynamicGroupNameTaken.
// -------------------------------------------------------------------------------------

// PgDynamicGroupStore is the pgx-backed DynamicGroupStore.
type PgDynamicGroupStore struct {
	Pool *pgxpool.Pool
}

// NewPgDynamicGroupStore constructs a PgDynamicGroupStore.
func NewPgDynamicGroupStore(pool *pgxpool.Pool) *PgDynamicGroupStore {
	return &PgDynamicGroupStore{Pool: pool}
}

var _ DynamicGroupStore = (*PgDynamicGroupStore)(nil)

// ListDynamicGroups implements DynamicGroupStore: the tenant's groups, ordered by name. RLS scopes rows.
func (s *PgDynamicGroupStore) ListDynamicGroups(ctx context.Context, tenantID string) ([]DynamicGroup, error) {
	var out []DynamicGroup
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, name, property_key, property_value
			FROM dynamic_group ORDER BY name
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g DynamicGroup
			if err := rows.Scan(&g.ID, &g.Name, &g.PropertyKey, &g.PropertyValue); err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetDynamicGroup implements DynamicGroupStore. A non-uuid id owns nothing → not-found (short-circuit
// rather than 500 at the ::uuid cast, same as GetMachineByID).
func (s *PgDynamicGroupStore) GetDynamicGroup(ctx context.Context, tenantID, id string) (*DynamicGroup, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrDynamicGroupNotFound
	}
	var g DynamicGroup
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id::text, name, property_key, property_value
			FROM dynamic_group WHERE id = $1
		`, id).Scan(&g.ID, &g.Name, &g.PropertyKey, &g.PropertyValue)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDynamicGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// CreateDynamicGroup implements DynamicGroupStore: INSERT with a DB-assigned id, RETURNING it into g.ID.
// A duplicate name (the UNIQUE (tenant_id, name)) surfaces as ErrDynamicGroupNameTaken.
func (s *PgDynamicGroupStore) CreateDynamicGroup(ctx context.Context, tenantID string, g *DynamicGroup) error {
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO dynamic_group (tenant_id, name, property_key, property_value)
			VALUES ($1, $2, $3, $4)
			RETURNING id::text
		`, tenantID, g.Name, g.PropertyKey, g.PropertyValue).Scan(&g.ID)
	})
	if isUniqueViolation(err) {
		return ErrDynamicGroupNameTaken
	}
	return err
}

// DeleteDynamicGroup implements DynamicGroupStore: remove one group by id, tenant-pinned. RLS makes
// another tenant's row invisible to the DELETE, so a mis-scoped delete touches 0 rows (not-found),
// never another tenant's data. A non-uuid id owns nothing, likewise not-found.
func (s *PgDynamicGroupStore) DeleteDynamicGroup(ctx context.Context, tenantID, id string) error {
	if namesNoUUIDRow(id) {
		return ErrDynamicGroupNotFound
	}
	var affected int64
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM dynamic_group WHERE id = $1`, id)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrDynamicGroupNotFound
	}
	return nil
}

// -------------------------------------------------------------------------------------
// PgMachineGroupStore — MachineGroupStore over the machine_group table (migrations/0001). Create + list
// only; RLS-scoped via withTenant. Names are not unique (no constraint), so no conflict handling.
// -------------------------------------------------------------------------------------

// PgMachineGroupStore is the pgx-backed MachineGroupStore.
type PgMachineGroupStore struct {
	Pool *pgxpool.Pool
}

// NewPgMachineGroupStore constructs a PgMachineGroupStore.
func NewPgMachineGroupStore(pool *pgxpool.Pool) *PgMachineGroupStore {
	return &PgMachineGroupStore{Pool: pool}
}

var _ MachineGroupStore = (*PgMachineGroupStore)(nil)

// ListMachineGroups implements MachineGroupStore. ORDER BY (name, id) matches the fake's tie-break, so
// the two agree even when names repeat.
func (s *PgMachineGroupStore) ListMachineGroups(ctx context.Context, tenantID string) ([]MachineGroup, error) {
	out := []MachineGroup{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name, parent_id::text FROM machine_group ORDER BY name, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g MachineGroup
			if err := rows.Scan(&g.ID, &g.Name, &g.ParentID); err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateMachineGroup implements MachineGroupStore: INSERT a group (under g.ParentID when set), tenant-pinned;
// the DB assigns the id (gen_random_uuid()) read back into g.ID. RLS WITH CHECK confines the row to the
// pinned tenant, the composite FK confines the parent to it, and the structure trigger enforces the depth
// cap. This is the UNAUTHORIZED primitive; see CreateMachineGroupAs.
func (s *PgMachineGroupStore) CreateMachineGroup(ctx context.Context, tenantID string, g *MachineGroup) error {
	if g.ParentID != nil && *g.ParentID != "" && namesNoUUIDRow(*g.ParentID) {
		return ErrMachineGroupParentInvalid
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return insertGroupTx(ctx, tx, tenantID, g)
	})
}

// RenameMachineGroup implements MachineGroupStore: UPDATE the name, tenant-pinned (RLS confines it). An
// id no `uuid` column could hold, or one not in the pinned tenant (0 rows), is ErrMachineGroupNotFound.
func (s *PgMachineGroupStore) RenameMachineGroup(ctx context.Context, tenantID, id, name string) error {
	return s.renameMachineGroup(ctx, tenantID, id, name, nil)
}

// RenameMachineGroupIfTree implements MachineGroupStore: the rename is conditional on the tenant's group
// tree still being at expectTree (docs/62 R2); the shared tree lock is held to the end of the transaction.
func (s *PgMachineGroupStore) RenameMachineGroupIfTree(ctx context.Context, tenantID, id, name string, expectTree int64) error {
	return s.renameMachineGroup(ctx, tenantID, id, name, &expectTree)
}

func (s *PgMachineGroupStore) renameMachineGroup(ctx context.Context, tenantID, id, name string, expectTree *int64) error {
	if namesNoUUIDRow(id) {
		return ErrMachineGroupNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if expectTree != nil {
			if err := checkGroupTreeVersionTx(ctx, tx, tenantID, *expectTree); err != nil {
				return err
			}
		}
		ct, err := tx.Exec(ctx, `UPDATE machine_group SET name = $2 WHERE id = $1`, id, name)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrMachineGroupNotFound
		}
		return nil
	})
}

// DeleteMachineGroup implements MachineGroupStore: DELETE the row, tenant-pinned. A group with subgroups is
// refused (ErrMachineGroupHasChildren, docs/62 D7); a machine or enrollment token still FK-referencing the
// group raises 23503 (no ON DELETE on those FKs) → ErrMachineGroupInUse, mapped OUTSIDE the closure. A
// non-uuid id, or one not in the pinned tenant (0 rows), is not-found.
func (s *PgMachineGroupStore) DeleteMachineGroup(ctx context.Context, tenantID, id string) error {
	if namesNoUUIDRow(id) {
		return ErrMachineGroupNotFound
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockGroupTreeTx(ctx, tx, tenantID, false); err != nil {
			return err
		}
		return deleteGroupTx(ctx, tx, id)
	})
	if isForeignKeyViolation(err) {
		return ErrMachineGroupInUse
	}
	return err
}

// -------------------------------------------------------------------------------------
// PgAuditStore — AuditStore over backstage_audit_event (migrations/0004_audit.sql). Append runs
// tenant-pinned inside a single transaction: read the session's current tail, verify linkage,
// then bulk-insert. Because the read + insert share one tx and the table has UNIQUE(session_id,
// seq), a concurrent duplicate loses at commit (unique violation) rather than corrupting the
// chain. Append-only: no UPDATE/DELETE path exists.
// -------------------------------------------------------------------------------------

// PgAuditStore is the pgx-backed AuditStore.
type PgAuditStore struct {
	Pool *pgxpool.Pool
}

// NewPgAuditStore constructs a PgAuditStore.
func NewPgAuditStore(pool *pgxpool.Pool) *PgAuditStore { return &PgAuditStore{Pool: pool} }

var _ AuditStore = (*PgAuditStore)(nil)

// tailTx reads a session's current chain tail inside an already tenant-pinned transaction.
func tailTx(ctx context.Context, tx pgx.Tx, sessionID string) (AuditTail, error) {
	var seq int64
	var hash string
	err := tx.QueryRow(ctx, `
		SELECT seq, hash FROM backstage_audit_event
		WHERE session_id = $1
		ORDER BY seq DESC
		LIMIT 1
	`, sessionID).Scan(&seq, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuditTail{}, nil
		}
		return AuditTail{}, err
	}
	return AuditTail{Exists: true, Seq: uint64(seq), Hash: hash}, nil
}

// selectBackstageAuditEvent is the projection every export row is built from. It is deliberately
// EXACTLY the AuditEvent the agent hashed and the controller POSTed — no `ingested_at`, no row id.
// A collector re-hashes the exported line against the canonical audit v1 preimage
// (mgmtaudit_canonical.go's backstage twin) to verify the chain itself, and a line carrying a
// control-plane-side field that the agent's SHA-256 never covered would invite it to hash the
// wrong bytes and conclude the trail was tampered with.
// `ingest_seq` is selected as a trailing column for the CURSOR only — it is control-plane
// metadata, is not part of the agent's SHA-256 preimage, and is never placed in the exported event
// body (the handler returns it as a response header instead). Putting it in the JSON would invite
// a collector to re-hash bytes the agent never hashed and conclude the trail was tampered with.
const selectBackstageAuditEvent = `
	SELECT id::text, seq, session_id::text, technician_id::text, machine_id::text,
	       occurred_at_ms, action, outcome, prev_hash, hash, ingest_seq, agent_pubkey, agent_signature
	FROM backstage_audit_event`

// ListAuditEventsAsc implements AuditStore: one page of the tenant's stored backstage events in
// INGEST order, tenant-pinned so RLS confines the read to the caller's own trail. Returns the
// events and the cursor to resume from (the last row's ingest_seq, or the caller's own cursor when
// the page is empty).
//
// `ORDER BY ingest_seq` matches the cursor predicate exactly, so the unfiltered page is served
// straight from the `uq_backstage_audit_tenant_ingest` index (0019) with no sort — verified by
// EXPLAIN. The session-filtered variant is a plan the PLANNER chooses: it may walk the same index
// applying `session_id` as a Filter, or prefer `idx_backstage_audit_session_seq` and sort. Both
// are correct; only the unfiltered path's plan is asserted here, because that is the one a SIEM
// collector runs continuously.
//
// Note the projection's `session_id::text`: an unqualified `ORDER BY session_id` would have bound
// to THAT output column rather than the table's uuid, sorting by database collation while the
// cursor compared uuids. An earlier version of this function did exactly that; EXPLAIN showed
// `Sort Key: ((session_id)::text)` and a full sort of every row after the cursor on each page.
func (s *PgAuditStore) ListAuditEventsAsc(ctx context.Context, tenantID string, q AuditExportQuery) ([]AuditEvent, int64, error) {
	q = q.normalize()
	// The session filter is a separate static statement rather than a `($4 = '' OR ...)` clause:
	// PostgreSQL does not promise to skip the `::uuid` cast of an empty string just because the
	// other branch is true, and an unfiltered export would then fail with a cast error.
	sql := selectBackstageAuditEvent + `
		WHERE tenant_id = $1 AND ingest_seq > $2
		ORDER BY ingest_seq
		LIMIT $3`
	args := []any{tenantID, q.AfterIngestSeq, q.Limit}
	if q.SessionID != "" {
		sql = selectBackstageAuditEvent + `
			WHERE tenant_id = $1 AND ingest_seq > $2 AND session_id = $4::uuid
			ORDER BY ingest_seq
			LIMIT $3`
		args = append(args, q.SessionID)
	}

	out := []AuditEvent{}
	next := q.AfterIngestSeq
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AuditEvent
			var seq, ingestSeq int64
			var action, outcome []byte
			if err := rows.Scan(&e.ID, &seq, &e.SessionID, &e.TechnicianID, &e.MachineID,
				&e.OccurredAtUnixMs, &action, &outcome, &e.PrevHash, &e.Hash, &ingestSeq, &e.AgentPubkey, &e.AgentSignature); err != nil {
				return err
			}
			e.Seq = uint64(seq)
			// Copy: pgx reuses the scan buffers across rows, so retaining them would leave every
			// event pointing at the last row's JSON.
			e.Action = append(json.RawMessage(nil), action...)
			e.Outcome = append(json.RawMessage(nil), outcome...)
			out = append(out, e)
			next = ingestSeq
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return out, next, nil
}

// AuditTail implements AuditStore.
func (s *PgAuditStore) AuditTail(ctx context.Context, tenantID, sessionID string) (AuditTail, error) {
	var out AuditTail
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		t, err := tailTx(ctx, tx, sessionID)
		out = t
		return err
	})
	if err != nil {
		return AuditTail{}, err
	}
	return out, nil
}

// AppendAudit implements AuditStore: verify linkage against the stored tail and bulk-insert, all
// tenant-pinned in one transaction. On a *LinkageError nothing is inserted (the tx rolls back);
// the RLS WITH CHECK confines every insert to the pinned tenant.
func (s *PgAuditStore) AppendAudit(ctx context.Context, tenantID, sessionID string, events []AuditEvent) (AuditTail, error) {
	var out AuditTail
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Serialize appends per TENANT so `ingest_seq` is a dense, gapless, commit-ordered counter
		// (0019). Without the lock two concurrent sessions' appends read the same max() and either
		// collide on uq_backstage_audit_tenant_ingest or — worse, had the column been a sequence
		// default — commit out of order, which is precisely how a tailing collector skips a row.
		// The lock is transaction-scoped and spans the max(), the linkage check, the INSERTs and
		// the COMMIT — it has to, since it is the commit order that makes ingest_seq meaningful.
		// That is one short transaction, NOT microseconds: a full 1024-event batch measured
		// 50–100 ms locally, most of it the batch insert and the WAL flush. Bounded wait, for the
		// reasons spelled out on PgMgmtAuditStore.RecordEvent: an unbounded waiter pins a pool
		// connection and stalls every tenant, a bounded one fails fast for the tenant under load
		// (as a 500 the forwarder retries, since it keeps the batch buffered until a 2xx).
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
			strconv.FormatInt(mgmtAuditLockWait.Milliseconds(), 10)); err != nil {
			return err
		}
		// Keyed on the CANONICAL tenant id: two spellings of one tenant would otherwise take two
		// different locks and the serialization would silently not happen.
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended('backstage_audit_chain:' || $1, 0))`,
			canonicalUUIDish(tenantID)); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgErrLockNotAvailable {
				return fmt.Errorf("backstage audit: timed out after %s waiting for tenant %s's "+
					"ingest lock; the append was refused rather than queued: %w",
					mgmtAuditLockWait, tenantID, err)
			}
			return err
		}
		tail, err := tailTx(ctx, tx, sessionID)
		if err != nil {
			return err
		}
		// Idempotent re-send: skip the leading events already on the stored chain (see
		// resolveOverlap). A batch that is ENTIRELY stored inserts nothing and reports the tail.
		skip, err := resolveOverlap(tail, events)
		if err != nil {
			return err
		}
		if skip > 0 && skip == len(events) { // an EMPTY batch still reaches verifyLinkage's refusal
			out = tail
			return nil
		}
		events = events[skip:]
		if err := verifyLinkage(tail, events); err != nil {
			return err
		}
		// Next ingest position for this tenant. Filters on tenant_id EXPLICITLY: RLS already
		// scopes it for the app role, but this read DECIDES the value rows are stamped with, and
		// under a pool whose role bypasses RLS (a superuser DATABASE_URL, which nothing rejects at
		// startup) an unfiltered max() would return the globally-highest value and stamp one
		// tenant's counter onto another's trail. Same reasoning as PgMgmtAuditStore's tail read.
		nextIngest := int64(0)
		if err := tx.QueryRow(ctx,
			`SELECT coalesce(max(ingest_seq) + 1, 0) FROM backstage_audit_event WHERE tenant_id = $1`,
			tenantID).Scan(&nextIngest); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for i, e := range events {
			action := e.Action
			if len(action) == 0 {
				action = json.RawMessage("null")
			}
			outcome := e.Outcome
			if len(outcome) == 0 {
				outcome = json.RawMessage("null")
			}
			// ingest_seq runs consecutively across the batch, so a batch is contiguous in the
			// export and a collector never sees half of one.
			batch.Queue(`
				INSERT INTO backstage_audit_event
					(id, tenant_id, session_id, seq, technician_id, machine_id,
					 occurred_at_ms, action, outcome, prev_hash, hash, ingest_seq, agent_pubkey, agent_signature)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			`, e.ID, tenantID, e.SessionID, int64(e.Seq), e.TechnicianID, e.MachineID,
				e.OccurredAtUnixMs, []byte(action), []byte(outcome), e.PrevHash, e.Hash,
				nextIngest+int64(i), e.AgentPubkey, e.AgentSignature)
		}
		br := tx.SendBatch(ctx, batch)
		defer br.Close()
		for range events {
			if _, err := br.Exec(); err != nil {
				return err
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
		last := events[len(events)-1]
		out = AuditTail{Exists: true, Seq: last.Seq, Hash: last.Hash}
		return nil
	})
	if err != nil {
		return AuditTail{}, err
	}
	return out, nil
}
