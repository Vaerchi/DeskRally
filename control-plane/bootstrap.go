package controlplane

// The first account.
//
// WHY THIS EXISTS. Until it did, a real deployment could not be logged into at all. The control
// plane's only unauthenticated routes are POST /auth/login and /auth/logout; every user-creating
// route requires CapManageUsers, i.e. an already-authenticated admin; and no migration seeds a
// tenant or a user. The seeded owner exists only in the DEV branch — the one taken when
// DATABASE_URL is UNSET, which is the opposite of production. So the whole stack could come up
// healthy, with a valid certificate, and have no way in. Found by writing docs/20's runbook and
// checking each step rather than assuming it.
//
// WHAT IT IS NOT. This is not a privilege boundary. It runs with database credentials, so anyone
// who can run it already has the database and could write these rows by hand. Its guard exists to
// stop an ACCIDENT — a deploy script re-running and silently minting a second owner on a live
// tenant — not to stop an attacker who is already inside.
//
// It composes primitives that already exist and are already tested (cp_create_tenant, CreateUser,
// SetPassword, HashPassword) rather than reimplementing account creation. That is deliberate: this
// is the one place that can hand out a login, and the fewer new ways it can differ from the paths
// the application itself uses, the better.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAlreadyBootstrapped is returned when the named tenant already has at least one user.
//
// Refusing is the point. A pipeline that runs bootstrap unconditionally must not quietly add
// another owner to a tenant people are already using — an extra owner nobody asked for is both a
// security surprise and invisible until someone audits the user list.
var ErrAlreadyBootstrapped = errors.New(
	"this tenant already has at least one user, so it has been bootstrapped. Refusing to create " +
		"another owner: use the console's user management to add people, or the password-reset " +
		"flow if you are locked out")

// BootstrapOptions describes the first tenant and its owner.
type BootstrapOptions struct {
	// TenantSlug is what the login form's "tenant" field takes. Required.
	TenantSlug string
	// TenantName is the display name. Defaults to TenantSlug.
	TenantName string
	// Email is the owner's login. Required.
	Email string
	// DisplayName defaults to the local part of Email.
	DisplayName string
	// Password, if empty, is GENERATED and returned in the result. Prefer generating: a password
	// passed on a command line lands in shell history and in `ps` output for every user on the box.
	Password string
	// SelfHosted selects the tenant's deployment_mode ('self_hosted' vs the 'saas' default).
	SelfHosted bool
}

// BootstrapResult reports what was created. Password is set ONLY when this call generated one —
// there is nowhere to look it up afterwards, because only its argon2id digest is stored.
type BootstrapResult struct {
	TenantID          string
	TenantSlug        string
	UserID            string
	Email             string
	Password          string
	GeneratedPassword bool
	TenantCreated     bool
}

// Bootstrap creates the first tenant (if absent) and its owner account.
//
// `pool` may connect as either the owner or `rmt_app`: `cp_create_tenant` is SECURITY DEFINER with
// EXECUTE granted to PUBLIC, and the user/credential writes go through the same tenant-pinned
// helpers the application uses, so the least-privilege DSN is sufficient — and preferable, because
// succeeding with it also proves that DSN works before anyone tries to log in.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, opts BootstrapOptions) (BootstrapResult, error) {
	var res BootstrapResult

	opts.TenantSlug = strings.TrimSpace(opts.TenantSlug)
	opts.Email = strings.TrimSpace(opts.Email)
	if opts.TenantSlug == "" {
		return res, errors.New("tenant slug is required (it is what the login form's tenant field takes)")
	}
	if !ValidTenantSlug(opts.TenantSlug) {
		return res, fmt.Errorf("tenant slug %q is not usable: it is also the tenant's hostname, so it must be "+
			"1-63 lowercase letters, digits or hyphens, start and end with a letter or digit, and not be a "+
			"reserved name", opts.TenantSlug)
	}
	if opts.Email == "" {
		return res, errors.New("owner email is required (it is the login)")
	}
	if !strings.Contains(opts.Email, "@") {
		return res, fmt.Errorf("owner email %q does not look like an email address", opts.Email)
	}
	if opts.TenantName == "" {
		opts.TenantName = opts.TenantSlug
	}
	if opts.DisplayName == "" {
		opts.DisplayName = opts.Email[:strings.Index(opts.Email, "@")]
	}

	users := NewPgUserStore(pool)
	tenants := NewPgTenantResolver(pool)

	// Resolve first. An existing slug is not automatically an error: a bootstrap that created the
	// tenant and then failed before the user must be re-runnable, or the operator is left with a
	// half-made deployment and no way forward that does not involve hand-written SQL.
	tenantID, err := tenants.ResolveTenant(ctx, opts.TenantSlug)
	switch {
	case err == nil:
		n, cerr := countUsers(ctx, pool, tenantID)
		if cerr != nil {
			return res, fmt.Errorf("count existing users: %w", cerr)
		}
		if n > 0 {
			return res, ErrAlreadyBootstrapped
		}
	case errors.Is(err, ErrNoTenant):
		mode := "saas"
		if opts.SelfHosted {
			mode = "self_hosted"
		}
		if err := pool.QueryRow(ctx,
			`SELECT (cp_create_tenant($1, $2, $3)).id::text`,
			opts.TenantSlug, opts.TenantName, mode,
		).Scan(&tenantID); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "42501" {
				// Migration 0055 took cp_create_tenant away from the application role: creating a
				// tenant is an owner (or platform operator) action now.
				return res, fmt.Errorf("create tenant: this connection may not create tenants; run bootstrap "+
					"with MIGRATE_DATABASE_URL (the schema owner) and DATABASE_URL unset, or create the tenant "+
					"from the console's Platform area: %w", err)
			}
			return res, fmt.Errorf("create tenant: %w", err)
		}
		res.TenantCreated = true
	default:
		return res, fmt.Errorf("resolve tenant: %w", err)
	}

	if opts.Password == "" {
		pw, gerr := generatePassword()
		if gerr != nil {
			return res, fmt.Errorf("generate password: %w", gerr)
		}
		opts.Password = pw
		res.GeneratedPassword = true
		res.Password = pw
	}

	// Hash BEFORE the insert, so a hashing failure cannot leave a user row with no credential — an
	// account that exists, cannot log in, and blocks a re-run by making the tenant look bootstrapped.
	hash, err := HashPassword(opts.Password)
	if err != nil {
		return res, fmt.Errorf("hash password: %w", err)
	}

	userID := newUUID()
	// The first owner is tenant-wide (nil scope): bootstrap is the intentional trusted writer, and an
	// owner must be able to administer the whole tenant to assign anyone else's scope.
	if err := users.CreateUser(ctx, tenantID, userID, opts.Email, opts.DisplayName, RoleOwner, nil); err != nil {
		return res, fmt.Errorf("create owner: %w", err)
	}
	if _, err := users.SetPassword(ctx, tenantID, userID, hash); err != nil {
		return res, fmt.Errorf("set owner password: %w", err)
	}

	res.TenantID = tenantID
	res.TenantSlug = opts.TenantSlug
	res.UserID = userID
	res.Email = opts.Email
	return res, nil
}

func countUsers(ctx context.Context, pool *pgxpool.Pool, tenantID string) (int, error) {
	var n int
	// Pinned to the tenant AND filtered explicitly, which is belt and braces on purpose.
	//
	// Relying on the RLS pin alone is wrong here, and a test caught it: this command accepts the
	// OWNER DSN as a fallback (MIGRATE_DATABASE_URL), and **a superuser bypasses row-level security
	// unconditionally** — `FORCE ROW LEVEL SECURITY` constrains the table owner, not a superuser. So
	// an unfiltered count run on the owner connection returns every tenant's users, and bootstrapping
	// a SECOND tenant would be refused as "already bootstrapped" on a deployment that has one.
	//
	// The WHERE clause makes the answer independent of which role connected; the pin stays so this
	// reads like every other query in the package and stays correct if the filter is ever dropped.
	err := withTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM app_user WHERE tenant_id = $1`, tenantID).Scan(&n)
	})
	return n, err
}

// generatePassword returns a high-entropy password safe to print and retype.
//
// 24 bytes ⇒ 192 bits, base64url so it survives copy/paste, a shell, and a browser field without
// quoting questions. Long enough that the login throttle never becomes the only thing standing
// between an attacker and this account.
func generatePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ResetPasswordResult reports what changed. Password is the NEW one, printable once — only its
// argon2id digest is stored, so this is the single opportunity to capture it.
type ResetPasswordResult struct {
	TenantID        string
	UserID          string
	Email           string
	Password        string
	SessionsRevoked int
}

// ResetOwnerPassword sets a NEW generated password for an existing user, out of band.
//
// WHY THIS EXISTS. `Bootstrap` prints a generated password once and stores only its digest, and it
// refuses to run again once the tenant has a user. Every in-product recovery path needs an
// authenticated admin — `HandleIssuePasswordReset` requires CapManageUsers, and there is no SMTP
// path anywhere in the product to mail a link. So losing that one string meant the deployment was
// locked out with nothing left but hand-writing an argon2id digest into Postgres.
//
// This is the operator's way back in. Like [`Bootstrap`], it is NOT a privilege boundary — it needs
// database credentials, and anyone holding those could write the row by hand. It exists so that the
// recovery is a supported command rather than surgery.
//
// EXISTING SESSIONS ARE REVOKED. The credential epoch (migration 0018) already refuses any session
// issued against the previous credential, so this is belt and braces — but it makes the eviction a
// fact in the database and a countable number, which matters because "I lost my password" and
// "somebody else is holding my session" look identical from here.
func ResetOwnerPassword(
	ctx context.Context, pool *pgxpool.Pool, sessions *SessionManager, tenantSlug, email string,
) (ResetPasswordResult, error) {
	var res ResetPasswordResult

	tenantSlug, email = strings.TrimSpace(tenantSlug), strings.TrimSpace(email)
	if tenantSlug == "" || email == "" {
		return res, errors.New("both a tenant slug and an email are required")
	}

	tenantID, err := NewPgTenantResolver(pool).ResolveTenant(ctx, tenantSlug)
	if err != nil {
		if errors.Is(err, ErrNoTenant) {
			return res, fmt.Errorf("no tenant with slug %q", tenantSlug)
		}
		return res, fmt.Errorf("resolve tenant: %w", err)
	}

	users := NewPgUserStore(pool)
	u, err := users.FindUserByEmail(ctx, tenantID, email)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			return res, fmt.Errorf("no user %q in tenant %q", email, tenantSlug)
		}
		return res, fmt.Errorf("find user: %w", err)
	}
	// Named explicitly rather than left to SetPassword's silent no-op: its INSERT carries
	// `WHERE u.disabled_at IS NULL`, so on a disabled account it writes nothing and reports no such
	// user — an answer that would send the operator looking for a typo in the email.
	if u.Disabled {
		return res, fmt.Errorf("user %q is DISABLED; re-enable the account before resetting it", email)
	}

	pw, err := generatePassword()
	if err != nil {
		return res, fmt.Errorf("generate password: %w", err)
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return res, fmt.Errorf("hash password: %w", err)
	}
	if _, err := users.SetPassword(ctx, tenantID, u.ID, hash); err != nil {
		return res, fmt.Errorf("set password: %w", err)
	}

	// After the credential is durable, never before: a revocation followed by a failed write would
	// log the user out and leave them with the OLD password, which is the worst of both.
	if sessions != nil {
		n, rerr := sessions.RevokeOtherSessions(ctx, tenantID, u.ID, "")
		if rerr != nil {
			// Not fatal. The new password is already stored and the credential epoch alone refuses
			// sessions issued against the old one; failing here would tell the operator the reset
			// did not happen when it did.
			log.Printf("reset-password: the password WAS changed, but revoking existing sessions "+
				"failed (%v); the credential epoch still refuses them", rerr)
		} else {
			res.SessionsRevoked = n
		}
	}

	res.TenantID, res.UserID, res.Email, res.Password = tenantID, u.ID, u.Email, pw
	return res, nil
}
