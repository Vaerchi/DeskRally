// Command controlplane is the runnable entry point for the multi-tenant management API.
//
// The control-plane logic lives in package `controlplane` (a library: auth, RBAC, grant minting,
// audit ingestion, pgx stores). This thin `main` wires those pieces into an HTTP server for
// deployment. It has two modes, and the mode is DECLARED rather than inferred (docs/25 F13 — it
// used to be chosen by whether DATABASE_URL happened to be set):
//
//   - Production, the DEFAULT: real Postgres-backed auth. A pgx pool feeds PgUserStore /
//     PgSessionStore / PgTenantResolver / PgAuditStore; the request Authenticator is the
//     SessionAuthenticator (cookie/Bearer session tokens); /auth/login is mounted. Apply the SQL
//     migrations (control-plane/migrations/*.sql, 0001→0006) to the database first — see
//     docs/10-deployment.md. DATABASE_URL is REQUIRED: starting without it is fatal. It must
//     connect as the least-privilege `rmt_app` role provisioned by 0005_app_role.sql, NOT as
//     postgres/the schema owner — Row-Level Security (the multi-tenant isolation guarantee) is
//     BYPASSED for a superuser or table owner, so a privileged DSN silently defeats tenant
//     isolation. That is now VERIFIED at startup against the pool the server serves with, and is
//     fatal unless CP_INSECURE_ALLOW_PRIVILEGED_DB=1.
//
//   - Insecure dev, only when CP_INSECURE_DEV=1: an in-memory StubAuthenticator that treats every
//     request as a full-capability owner, plus an in-memory audit store. No database required, and
//     none permitted — a non-empty DATABASE_URL alongside the flag is refused as contradictory.
//     Confined to LOOPBACK (a bare `:port` is narrowed to 127.0.0.1; a routable bind needs
//     CP_INSECURE_DEV_LISTEN_ANY=1), and it REFUSES the production GRANT_ISSUER_SEED outright,
//     reading CP_INSECURE_DEV_GRANT_SEED instead. For local demos and the VM lab only.
//
// In both modes the backstage grant issuer (GET /grant/pubkey, POST /grant/mint) is wired so the
// agent's `grant_issuer_pubkey` can be provisioned. Set GRANT_ISSUER_SEED (64 hex chars = 32 bytes)
// to keep the issuer public key STABLE across restarts; without it a fresh key is generated each
// boot and agents pinned to the old key will reject new grants.
//
// Environment:
//
//	CP_LISTEN          listen address (default ":8081"). In dev mode a bare ":port" is narrowed to
//	                   127.0.0.1:port.
//	DATABASE_URL       Postgres connection string. REQUIRED in production (absent ⇒ fatal), and
//	                   must be empty in dev mode.
//	CP_INSECURE_DEV    "1"/"true" ⇒ serve the full-owner stub authenticator with no database.
//	                   Loopback-only, refuses GRANT_ISSUER_SEED. NEVER set in production.
//	CP_INSECURE_DEV_LISTEN_ANY
//	                   "1"/"true" ⇒ permit a non-loopback bind in dev mode. This exposes anonymous
//	                   owner access to the network; the VM lab needs it, nothing else should.
//	CP_INSECURE_DEV_GRANT_SEED
//	                   dev-mode grant issuer seed (64 hex chars). Separate from GRANT_ISSUER_SEED so
//	                   a retained production seed can never sign in dev mode.
//	CP_INSECURE_ALLOW_PRIVILEGED_DB
//	                   "1"/"true" ⇒ skip the startup check that the DATABASE_URL role is neither
//	                   SUPERUSER nor BYPASSRLS. Row-level security does not apply to such a role, so
//	                   this turns OFF tenant isolation. Local databases only.
//	GRANT_ISSUER_SEED  32-byte Ed25519 seed, hex-encoded (64 chars); stable issuer key. Production
//	                   only — refused in dev mode.
//	CP_ISSUER_NAME     deployment name used in TOTP provisioning URIs (default "rmt-control-plane")
//	CP_SECURE_COOKIE   "1"/"true" to mark the session cookie Secure (set behind HTTPS/TLS)
//	CP_SESSION_IDLE_MINUTES
//	                   inactivity timeout for a login session (default 30). A session unused for
//	                   this long is rejected even before its absolute 12h expiry. "0" disables it.
//	CP_SIGNALING_URL   signaling WS endpoint returned by POST /sessions alongside the signed
//	                   session ticket (default "ws://127.0.0.1:8080/ws")
//	CP_DEVICE_IDENTITY_TOKEN
//	                   shared secret (32+ chars) the SIGNALING server presents to
//	                   GET /internal/devices/{device_id}/identity so it can verify an agent's
//	                   proof of possession at register_agent. Unset ⇒ the route does not exist and
//	                   signaling cannot authenticate agents. Must equal the signaling server's
//	                   SIGNALING_DEVICE_IDENTITY_TOKEN.
//	CP_PRESENCE_URL    signaling's presence feed, e.g. "http://127.0.0.1:8080/internal/presence".
//	CP_PRESENCE_TOKEN  shared secret (32+ chars) presented to it; must equal the signaling
//	                   server's SIGNALING_PRESENCE_TOKEN. Both unset ⇒ GET /machines reports
//	                   "presence_known": false and omits per-machine online status (not fatal —
//	                   nothing is authorized on presence).
//	CP_ADMIN_IP_ALLOWLIST  comma/space/semicolon list of CIDRs (or bare IPs) permitted to reach the
//	                   AUTHENTICATED console/host API. Empty ⇒ open (default). A malformed list is
//	                   fatal at startup. Agent-enroll and guest-attend routes are NOT gated.
//	CP_TRUSTED_PROXIES comma/space/semicolon list of CIDR ranges (or bare IPs) of reverse-proxy
//	                   peers that are permitted to set X-Forwarded-For (docs/25 F14). When set,
//	                   XFF is honoured only from a peer whose address falls in this list; all other
//	                   peers are judged on their TCP address. Prefer this over CP_TRUST_PROXY_IP
//	                   alone — set it to the Docker Compose network CIDR (e.g. 172.20.0.0/16).
//	CP_TRUST_PROXY_IP  "1"/"true" ⇒ take the client IP for CP_ADMIN_IP_ALLOWLIST, the per-tenant
//	                   allow-list AND the per-IP login/TOTP/redeem throttles from the rightmost
//	                   X-Forwarded-For hop. REQUIRED behind a reverse proxy (docs/18's topology):
//	                   without it every request carries the proxy's address and per-source throttles
//	                   collapse. Use CP_TRUSTED_PROXIES (above) to also restrict which peers may
//	                   set the header; using this flag alone accepts XFF from any TCP peer.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	controlplane "rmt/controlplane"

	"github.com/jackc/pgx/v5/pgxpool"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDuration reads a Go duration (0 = use the default).
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			log.Fatalf("%s=%q: want a positive duration such as 5s", key, v)
		}
		return d
	}
	return def
}

// envInt reads a positive integer.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			log.Fatalf("%s=%q: want a positive integer", key, v)
		}
		return n
	}
	return def
}

func envTrue(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// buildGrantIssuer builds the backstage grant issuer from an ALREADY-RESOLVED seed, or generates a
// fresh (unstable-across-restart) one when the seed is empty.
//
// It takes the seed as an argument rather than reading the environment itself, and that is the
// point (docs/25 F13). While it read `GRANT_ISSUER_SEED` directly it ran BEFORE the mode was
// chosen, so the production signing seed was loaded even when the process went on to serve the
// anonymous full-owner dev stub — a grant-minting oracle for anyone who could reach the port.
// `DecideStartup` now decides which variable may supply the seed, and this function signs with
// whatever it is handed.
func buildGrantIssuer(seedHex string) (*controlplane.GrantIssuer, error) {
	if trimmed := strings.TrimSpace(seedHex); trimmed != "" {
		seed, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, err
		}
		return controlplane.NewGrantIssuerFromSeed(seed)
	}
	// Dev mode warns about this in DecideStartup, naming its own variable; this line is the
	// production path, where the seed to set is GRANT_ISSUER_SEED.
	log.Printf("WARNING: no grant issuer seed configured — generating an ephemeral grant issuer " +
		"key. Its public key changes on every restart, so agents pinned to grant_issuer_pubkey " +
		"will reject grants after a restart. Set GRANT_ISSUER_SEED (64 hex chars) in production.")
	return controlplane.GenerateGrantIssuer()
}

// runMigrate is the `controlplane migrate` subcommand: bring the database up to the migrations in
// MIGRATIONS_DIR, then exit. Same binary, so the deployed image can run it as an init container that
// the server depends_on — no second artifact to keep in step with the schema.
//
// It uses MIGRATE_DATABASE_URL, NOT DATABASE_URL, and that separation is the point. DATABASE_URL
// connects as `rmt_app`, which migrations/0005 creates NOSUPERUSER with only DML grants — it has no
// DDL rights at all. Migrations need the OWNER. Sharing one DSN would mean either migrations that
// cannot run or an application that bypasses row-level security (docs/18 §4b).
// parseSubcommandFlags parses a maintenance subcommand's flags and refuses anything left over. The
// flag package stops at the first non-flag argument and leaves the rest unparsed, so a mistyped
// `reencrypt-totp dry-run` (no dash) used to parse as NO flags and perform the real run; every flag
// after a stray word is silently dropped the same way. These commands write to the database, so an
// argument that was not understood must stop them before they connect.
func parseSubcommandFlags(fs *flag.FlagSet, args []string) {
	if err := checkSubcommandArgs(fs, args); err != nil {
		log.Fatalf("%v", err)
	}
}

func checkSubcommandArgs(fs *flag.FlagSet, args []string) error {
	_ = fs.Parse(args) // ExitOnError: a malformed flag has already exited
	if fs.NArg() > 0 {
		return fmt.Errorf("%s: unexpected argument %q (flags take a leading dash, e.g. -dry-run); nothing was done",
			fs.Name(), fs.Arg(0))
	}
	return nil
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	baseline := fs.Bool("baseline", false,
		"record the on-disk migrations as applied WITHOUT running them, for adopting a database "+
			"that predates this runner. Verify the schema is current first.")
	dir := fs.String("dir", getenv("MIGRATIONS_DIR", "/opt/rmt/migrations"), "migrations directory")
	parseSubcommandFlags(fs, args)

	dbURL := os.Getenv("MIGRATE_DATABASE_URL")
	if dbURL == "" {
		log.Fatalf("migrate: MIGRATE_DATABASE_URL is not set. It must connect as the OWNER/admin " +
			"role, not as rmt_app — rmt_app is NOSUPERUSER with DML grants only and cannot run DDL.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("migrate: connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("migrate: ping: %v", err)
	}

	rep, err := controlplane.Migrate(ctx, pool, *dir, controlplane.MigrateOptions{Baseline: *baseline})
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("migrate: %s", rep.Summary())

	// Provision rmt_app's password AFTER the migrations, because 0005 is what creates the role.
	// Optional so a dev bring-up (which connects as the owner) need not set it; when it IS set, the
	// control plane can connect as a NOSUPERUSER NOBYPASSRLS role and RLS actually applies.
	if pw := os.Getenv("APP_DB_PASSWORD"); pw != "" {
		if err := controlplane.ProvisionAppRolePassword(ctx, pool, pw); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		log.Printf("migrate: rmt_app password provisioned; the control plane can connect as a " +
			"least-privilege role")
	} else {
		log.Printf("migrate: APP_DB_PASSWORD not set — rmt_app has no password, so the only DSN " +
			"that works is the owner's, which BYPASSES row-level security. Fine for local dev; " +
			"set it for any real deployment.")
	}
}

// runBootstrap creates the first tenant and owner. Without it a real deployment cannot be logged
// into at all: the only unauthenticated routes are /auth/login and /auth/logout, and every
// user-creating route needs an already-authenticated admin. See controlplane.Bootstrap.
// runPlatform administers the platform operator grant (migration 0055). It needs the OWNER
// connection (MIGRATE_DATABASE_URL, a role that bypasses RLS): the application role cannot read or
// write the grant, by design. Every change commits together with its audit event on the platform
// tenant's chain.
//
//	controlplane platform set-tenant --slug main
//	controlplane platform grant  --email ed@example.com
//	controlplane platform revoke --email ed@example.com
//	controlplane platform list
func runPlatform(args []string) {
	if len(args) == 0 {
		log.Fatalf("platform: subcommand required: set-tenant | grant | revoke | list")
	}
	fs := flag.NewFlagSet("platform "+args[0], flag.ExitOnError)
	slug := fs.String("slug", "", "platform tenant slug (set-tenant)")
	email := fs.String("email", "", "operator email in the platform tenant (grant, revoke)")
	parseSubcommandFlags(fs, args[1:])
	dbURL := os.Getenv("MIGRATE_DATABASE_URL")
	if dbURL == "" {
		log.Fatalf("platform: set MIGRATE_DATABASE_URL (the schema owner); the application role cannot change the grant")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("platform: connect: %v", err)
	}
	defer pool.Close()
	if err := controlplane.EnsureOwnerBypassesRLS(ctx, pool); err != nil {
		log.Fatalf("platform: %v", err)
	}
	by := "cli"
	if u := os.Getenv("USER"); u != "" {
		by = "cli:" + u
	} else if u := os.Getenv("USERNAME"); u != "" {
		by = "cli:" + u
	}
	switch args[0] {
	case "set-tenant":
		if *slug == "" {
			log.Fatalf("platform set-tenant: --slug is required")
		}
		tid, err := controlplane.PlatformSetTenant(ctx, pool, *slug, by)
		if err != nil {
			log.Fatalf("platform set-tenant: %v", err)
		}
		fmt.Printf("platform tenant: %s (%s)\n", *slug, tid)
	case "grant":
		if *email == "" {
			log.Fatalf("platform grant: --email is required")
		}
		if err := controlplane.PlatformGrant(ctx, pool, *email, by); err != nil {
			log.Fatalf("platform grant: %v", err)
		}
		fmt.Printf("granted: %s\n", *email)
	case "revoke":
		if *email == "" {
			log.Fatalf("platform revoke: --email is required")
		}
		if err := controlplane.PlatformRevoke(ctx, pool, *email, by); err != nil {
			log.Fatalf("platform revoke: %v", err)
		}
		fmt.Printf("revoked: %s\n", *email)
	case "list":
		tslug, rows, err := controlplane.PlatformList(ctx, pool)
		if err != nil {
			log.Fatalf("platform list: %v", err)
		}
		fmt.Printf("platform tenant: %s\n", tslug)
		for _, r := range rows {
			fmt.Printf("  %s  granted %s by %s\n", r.Email, r.GrantedAt.UTC().Format(time.RFC3339), r.GrantedBy)
		}
	default:
		log.Fatalf("platform: unknown subcommand %q (set-tenant | grant | revoke | list)", args[0])
	}
}

func runBootstrap(args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant SLUG — what the login form's `tenant` field takes (required)")
	name := fs.String("name", "", "tenant display name (default: the slug)")
	email := fs.String("email", "", "owner's email, which is the login (required)")
	display := fs.String("display-name", "", "owner's display name (default: the local part of --email)")
	saas := fs.Bool("saas", false, "mark the tenant deployment_mode 'saas' instead of 'self_hosted'")
	parseSubcommandFlags(fs, args)

	// MIGRATE_DATABASE_URL (the schema owner) first. Creating a tenant is reserved to the owner
	// (cp_create_tenant is not granted to rmt_app), so DATABASE_URL, the least-privilege role, can no
	// longer bootstrap. It used to be tried first, which made the native launcher fail: run-service.sh
	// always loads DATABASE_URL from controlplane.env, so even with the owner URL exported the
	// command connected as rmt_app and was refused (server-install acceptance, 2026-11-10).
	// DATABASE_URL remains the fallback only so the refusal names the real cause.
	dbURL := os.Getenv("MIGRATE_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		log.Fatalf("bootstrap: set MIGRATE_DATABASE_URL (the schema owner)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("bootstrap: connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("bootstrap: ping: %v (are the migrations applied?)", err)
	}

	res, err := controlplane.Bootstrap(ctx, pool, controlplane.BootstrapOptions{
		TenantSlug:  *tenant,
		TenantName:  *name,
		Email:       *email,
		DisplayName: *display,
		SelfHosted:  !*saas,
	})
	if errors.Is(err, controlplane.ErrAlreadyBootstrapped) {
		// Non-zero and loud rather than a quiet success: a pipeline that reports "done" while
		// having created nothing is how an operator ends up believing an account exists.
		log.Fatalf("bootstrap: %v", err)
	}
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	// Printed to STDOUT, once, and never stored in recoverable form — only the argon2id digest is
	// persisted, so this output is the single opportunity to capture it.
	fmt.Printf("\ntenant   %s  (%s)\n", res.TenantSlug, res.TenantID)
	fmt.Printf("email    %s\n", res.Email)
	if res.GeneratedPassword {
		fmt.Printf("password %s\n", res.Password)
		fmt.Printf("\nThis password is shown ONCE and cannot be recovered. Save it now, then sign\n" +
			"in and change it. Log in with the tenant slug, the email and this password.\n\n")
	}
	if !res.TenantCreated {
		log.Printf("bootstrap: the tenant already existed and had no users; created the owner in it")
	}
}

// runResetPassword sets a new generated password for an existing user, out of band.
//
// The way back in when the password `bootstrap` printed once is lost: every in-product recovery
// needs an already-authenticated admin, and there is no mail path to send a reset link.
// See controlplane.ResetOwnerPassword.
// runReencryptTOTP converts TOTP secrets written before TOTP_ENCRYPTION_KEY existed into encrypted
// rows, and reports what it found.
//
// This is a subcommand rather than a migration because a migration cannot do it. The key lives in
// this process; SQL has no access to it, and pgcrypto is not installed. `bootstrap` and
// `reset-password` set the precedent for "a data operation that needs Go-side crypto", both for the
// same reason (argon2id). The schema needs no change at all — the column is already bytea and the
// envelope is self-describing.
//
// It is DELIBERATELY not run automatically at startup. Re-encryption rewrites every enrolled user's
// second factor under a key that, if the operator has mis-set it, no longer decrypts anything; doing
// that unattended on boot would convert a recoverable misconfiguration into a fleet-wide 2FA
// lockout. -dry-run reports without writing, and is the default answer to "did I set this up right".
//
// Bypasses the store's tenant pinning on purpose: this is an operator maintenance task over every
// tenant at once, running with the migration DSN, exactly like `migrate`. It reads and rewrites only
// the two secret columns and touches no other state.
func runReencryptTOTP(args []string) {
	fs := flag.NewFlagSet("reencrypt-totp", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	parseSubcommandFlags(fs, args)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("MIGRATE_DATABASE_URL")
	}
	if dbURL == "" {
		log.Fatalf("reencrypt-totp: set DATABASE_URL (preferred) or MIGRATE_DATABASE_URL")
	}

	cipher, err := controlplane.NewTOTPCipher(strings.TrimSpace(os.Getenv("TOTP_ENCRYPTION_KEY")))
	if err != nil {
		log.Fatalf("reencrypt-totp: TOTP_ENCRYPTION_KEY: %v", err)
	}
	if cipher == nil {
		log.Fatalf("reencrypt-totp: TOTP_ENCRYPTION_KEY is not set — there is nothing to encrypt " +
			"secrets WITH. Generate one with `openssl rand -hex 32`, put it in .env, and re-run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("reencrypt-totp: connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("reencrypt-totp: ping: %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT user_id::text, secret, pending_secret FROM user_totp`)
	if err != nil {
		log.Fatalf("reencrypt-totp: read: %v", err)
	}
	type row struct {
		userID          string
		secret, pending []byte
	}
	var todo []row
	var alreadyEncrypted, empty int
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.userID, &r.secret, &r.pending); err != nil {
			rows.Close()
			log.Fatalf("reencrypt-totp: scan: %v", err)
		}
		// Open BOTH columns before deciding. A row can legitimately be half-converted only if a
		// previous run died mid-write, and re-sealing an already-encrypted value would double-wrap
		// it, so each column is judged on its own.
		sPlain, sEnc, serr := cipher.Open(r.secret)
		pPlain, pEnc, perr := cipher.Open(r.pending)
		if serr != nil || perr != nil {
			rows.Close()
			// Fatal, not skipped. A row that will not open under this key means the key is wrong or
			// the deployment has two keys in play; continuing would rewrite the rows that DO open and
			// leave a database that is half under each, which is far harder to recover from than
			// stopping now.
			log.Fatalf("reencrypt-totp: user %s: %v %v — no rows were changed", r.userID, serr, perr)
		}
		if (sEnc || sPlain == "") && (pEnc || pPlain == "") {
			if sPlain == "" && pPlain == "" {
				empty++
			} else {
				alreadyEncrypted++
			}
			continue
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		log.Fatalf("reencrypt-totp: read: %v", err)
	}

	log.Printf("reencrypt-totp: %d plaintext, %d already encrypted, %d with no secret",
		len(todo), alreadyEncrypted, empty)
	if len(todo) == 0 {
		log.Printf("reencrypt-totp: nothing to do")
		return
	}
	if *dryRun {
		log.Printf("reencrypt-totp: -dry-run, writing nothing")
		return
	}

	// One transaction for the whole set: a partial conversion is the state this is hardest to reason
	// about later, and the row count here is bounded by enrolled users.
	tx, err := pool.Begin(ctx)
	if err != nil {
		log.Fatalf("reencrypt-totp: begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	converted := 0
	for _, r := range todo {
		sPlain, _, _ := cipher.Open(r.secret)
		pPlain, _, _ := cipher.Open(r.pending)
		sealed, err := cipher.Seal(sPlain)
		if err != nil {
			log.Fatalf("reencrypt-totp: user %s: seal: %v", r.userID, err)
		}
		sealedPending, err := cipher.Seal(pPlain)
		if err != nil {
			log.Fatalf("reencrypt-totp: user %s: seal pending: %v", r.userID, err)
		}
		// pending_secret is NULL for most rows and must stay NULL rather than become empty bytea:
		// ConfirmPendingTOTP's WHERE tests `IS NOT NULL AND length(...) > 0`, and an empty-but-present
		// value would change nothing today but is a difference waiting to matter.
		var pendingArg any
		if r.pending == nil {
			pendingArg = nil
		} else {
			pendingArg = sealedPending
		}
		if _, err := tx.Exec(ctx,
			`UPDATE user_totp SET secret = $2, pending_secret = $3 WHERE user_id = $1`,
			r.userID, sealed, pendingArg); err != nil {
			log.Fatalf("reencrypt-totp: user %s: update: %v", r.userID, err)
		}
		converted++
	}
	if err := tx.Commit(ctx); err != nil {
		log.Fatalf("reencrypt-totp: commit: %v", err)
	}
	log.Printf("reencrypt-totp: encrypted %d row(s)", converted)
}

func runResetPassword(args []string) {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant SLUG (required)")
	email := fs.String("email", "", "the user's email (required)")
	parseSubcommandFlags(fs, args)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("MIGRATE_DATABASE_URL")
	}
	if dbURL == "" {
		log.Fatalf("reset-password: set DATABASE_URL (preferred) or MIGRATE_DATABASE_URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("reset-password: connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("reset-password: ping: %v", err)
	}

	sessions := controlplane.NewSessionManager(controlplane.NewPgSessionStore(pool))
	res, err := controlplane.ResetOwnerPassword(ctx, pool, sessions, *tenant, *email)
	if err != nil {
		log.Fatalf("reset-password: %v", err)
	}

	fmt.Printf("\ntenant   %s\n", *tenant)
	fmt.Printf("email    %s\n", res.Email)
	fmt.Printf("password %s\n", res.Password)
	fmt.Printf("\nShown ONCE and not recoverable. %d existing session(s) revoked; sign in\n"+
		"with this password and change it.\n\n", res.SessionsRevoked)
}

// themingOffGuard is the startup check for a deployment whose host policy is NOT enabled: active tenant hostname
// assignments would silently lose their redemption scope, so it fails unless the emergency escape hatch is set, in
// which case it warns loudly every interval.
func themingOffGuard(ctx context.Context, p *controlplane.HostPolicy, count func(context.Context) (int64, error),
	escape string, logf func(string, ...any), interval time.Duration) error {
	if p != nil {
		return nil
	}
	escaped, err := controlplane.CheckThemingOffSafety(ctx, count, escape)
	if err != nil {
		return err
	}
	if escaped {
		go controlplane.WarnUnscopedLoop(ctx, interval, logf)
	}
	return nil
}

// splitHostList parses a comma/space separated host list.
func splitHostList(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// buildHostPolicy reads the hostname-theming configuration (docs/66). The policy (authority gate, scoped redemption,
// edge-secret requirement) is turned on ONLY by an explicit CP_HOST_THEMING=on or a non-empty CP_DEFAULT_HOSTS,
// NEVER implicitly by CP_TENANT_HOST_SUFFIX (production already sets that for SSO tenant hosts and has no edge
// marker yet). Otherwise it returns nil: today's behaviour exactly (unscoped redemption, no gate, no secret).
//
//	CP_HOST_THEMING             on = enable the policy (needs CP_EDGE_SECRET); also the publishing switch (stage 1b)
//	CP_DEFAULT_HOSTS            neutral unscoped default host(s); non-empty also enables the policy; with
//	                            CP_HOST_THEMING=on and CP_TENANT_HOST_SUFFIX it defaults to main<suffix>
//	CP_LEGACY_UNSCOPED_HOSTS    explicit unscoped legacy hosts; default loam<suffix>,vc<suffix>; "none" = empty
//	CP_PUBLIC_AUTHORITIES       the authority allowlist the edge gate enforces (same list as SITE_ADDRESS)
//	CP_EDGE_SECRET              shared secret Caddy sends as X-DeskRally-Edge (>= 32 chars, required when enabled)
func buildHostPolicy(suffix string) (*controlplane.HostPolicy, error) {
	explicit := strings.TrimSpace(os.Getenv("CP_DEFAULT_HOSTS"))
	if explicit == "" && !envTrue("CP_HOST_THEMING") {
		return nil, nil
	}
	if explicit == "" && suffix == "" {
		return nil, fmt.Errorf("CP_HOST_THEMING=on needs CP_DEFAULT_HOSTS or CP_TENANT_HOST_SUFFIX to name the default host")
	}
	// The authority gate is what makes a tenant host's scope meaningful (a forged Host must not reach the resolver),
	// so enabling the policy WITHOUT the edge marker secret is a startup error, not a silently open gate.
	if secret := os.Getenv("CP_EDGE_SECRET"); len(secret) < controlplane.EdgeMarkerMinLen {
		return nil, fmt.Errorf("CP_EDGE_SECRET must be set to at least %d characters when host scoping is enabled (CP_HOST_THEMING=on or CP_DEFAULT_HOSTS is set); Caddy sends the same value as %s", controlplane.EdgeMarkerMinLen, controlplane.EdgeMarkerHeader)
	}
	cfg := controlplane.HostPolicyConfig{
		DefaultHosts:      splitHostList(explicit),
		PublicAuthorities: splitHostList(os.Getenv("CP_PUBLIC_AUTHORITIES")),
		EdgeSecret:        os.Getenv("CP_EDGE_SECRET"),
		Theming:           envTrue("CP_HOST_THEMING"),
	}
	if explicit == "" {
		cfg.DefaultHosts = []string{"main" + suffix}
	}
	switch legacy := strings.TrimSpace(os.Getenv("CP_LEGACY_UNSCOPED_HOSTS")); strings.ToLower(legacy) {
	case "":
		if suffix != "" {
			cfg.LegacyUnscopedHosts = []string{"loam" + suffix, "vc" + suffix}
		}
	case "none", "-":
	default:
		cfg.LegacyUnscopedHosts = splitHostList(legacy)
	}
	return controlplane.NewHostPolicy(cfg)
}

func main() {
	// Subcommand dispatch, deliberately minimal: anything that is not a known verb falls through to
	// serving, so every existing invocation (`controlplane` with no args) behaves exactly as before.
	// logo-convert is the logo decode CHILD (docs/66 2b.3): started by the server itself with an EMPTY
	// environment, no database and no network. It must be dispatched before anything reads configuration.
	if len(os.Args) > 1 && os.Args[1] == "logo-convert" {
		os.Exit(controlplane.RunLogoConvertChild(os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrate(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "platform" {
		runPlatform(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		runBootstrap(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		runResetPassword(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "reencrypt-totp" {
		runReencryptTOTP(os.Args[2:])
		return
	}

	// WHICH MODE THIS PROCESS SERVES IN IS DECLARED, NOT INFERRED (docs/25 F13).
	//
	// This used to be `if dbURL != ""`, so an absent DATABASE_URL silently selected a stub
	// authenticator that answers every request as a full-capability owner of every group — on
	// `:8081`, meaning all interfaces, signing with whatever GRANT_ISSUER_SEED was in the
	// environment. Measured at the previous commit: anonymous `GET /users` returned 200 with the
	// user list, and a supplied seed produced a deterministic issuer key, so a retained production
	// seed was genuinely in use. Production is now the default and dev mode must say so.
	//
	// The decision is a pure function in the controlplane package because the truth table belongs
	// somewhere a unit test can reach; the version living here was reachable only by starting a
	// process, which is why it went unexamined.
	decision, derr := controlplane.DecideStartup(controlplane.StartupConfig{
		InsecureDev:      envTrue(controlplane.EnvInsecureDev),
		AllowNonLoopback: envTrue(controlplane.EnvInsecureDevListenAny),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		Listen:           getenv("CP_LISTEN", ":8081"),
		GrantIssuerSeed:  os.Getenv(controlplane.EnvGrantIssuerSeed),
		DevGrantSeed:     os.Getenv(controlplane.EnvInsecureDevGrantSeed),
	})
	if derr != nil {
		log.Fatalf("startup: %v", derr)
	}
	for _, w := range decision.Warnings {
		log.Printf("%s", w)
	}
	listen := decision.Listen
	dbURL := os.Getenv("DATABASE_URL")

	grants, err := buildGrantIssuer(decision.GrantSeed)
	if err != nil {
		log.Fatalf("grant issuer: %v", err)
	}

	var srv *controlplane.Server

	if decision.Mode == controlplane.ModeProduction {
		// Production: Postgres-backed auth + audit.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		poolConfig, perr := pgxpool.ParseConfig(dbURL)
		if perr != nil {
			cancel()
			log.Fatal("invalid DATABASE_URL")
		}
		if !strings.Contains(dbURL, "pool_max_conns") {
			poolConfig.MaxConns = 16
		}
		// docs/66 2f: a connect that never completes must not hold a goroutine (or a pool slot) forever.
		if poolConfig.ConnConfig.ConnectTimeout == 0 {
			poolConfig.ConnConfig.ConnectTimeout = time.Second
		}
		if poolConfig.ConnConfig.RuntimeParams == nil {
			poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
		}
		if _, configured := poolConfig.ConnConfig.RuntimeParams["statement_timeout"]; !configured {
			poolConfig.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
		}
		pool, perr := pgxpool.NewWithConfig(ctx, poolConfig)
		cancel()
		if perr != nil {
			log.Fatalf("connect to DATABASE_URL: %v", perr)
		}
		defer pool.Close()
		// docs/66 release gate R1: anonymous lookups (public branding, attended redeem) get their own small pool,
		// so anonymous traffic on a slow database cannot hold the connections the console needs. Same DSN, role,
		// ConnectTimeout and statement_timeout as the shared pool; CP_LOOKUP_DB_CONNS sizes it (default 8), and all of its
		// connections stay open so no lookup pays a dial inside its 100 ms window. It MUST stay a copy of poolConfig: the
		// role/RLS verification below (docs/25 F13) runs on `pool` only (see controlplane.LookupPoolConfig).
		lookupConfig := controlplane.LookupPoolConfig(poolConfig, envInt("CP_LOOKUP_DB_CONNS", controlplane.DefaultLookupPoolConns))
		lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		lookupPool, perr := pgxpool.NewWithConfig(lookupCtx, lookupConfig)
		lookupCancel()
		if perr != nil {
			log.Fatalf("connect the lookup pool to DATABASE_URL: %v", perr)
		}
		defer lookupPool.Close()

		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if perr := pool.Ping(pingCtx); perr != nil {
			pingCancel()
			log.Fatalf("ping database: %v (did you apply control-plane/migrations/*.sql?)", perr)
		}
		pingCancel()
		lookupPingCtx, lookupPingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if perr := lookupPool.Ping(lookupPingCtx); perr != nil {
			lookupPingCancel()
			log.Fatalf("ping database (lookup pool): %v", perr)
		}
		lookupPingCancel()

		// TENANT ISOLATION IS ROW-LEVEL SECURITY, so verify the role it applies to (docs/25 F13).
		//
		// RLS does not apply to a SUPERUSER or a BYPASSRLS role, and no application code or test can
		// tell the difference — every query succeeds either way, and only cross-tenant visibility
		// changes. The base compose file connects as the bootstrap superuser and the production
		// overlay correctly uses rmt_app, so "isolated" and "silently not isolated" were one DSN in
		// one file, verified by nobody. Checked here, against the pool the server will actually
		// serve with, rather than left as an instruction in a runbook.
		if envTrue(controlplane.EnvAllowPrivilegedDB) {
			log.Printf("WARNING: %s=1 — skipping the database role privilege check. If this role is "+
				"a superuser or holds BYPASSRLS then row-level security does NOT apply and tenants "+
				"are NOT isolated from each other. Acceptable for a local single-tenant database; "+
				"never in production.", controlplane.EnvAllowPrivilegedDB)
		} else {
			roleCtx, roleCancel := context.WithTimeout(context.Background(), 5*time.Second)
			rerr := controlplane.AssertLeastPrivilegeRole(roleCtx, pool)
			roleCancel()
			if rerr != nil {
				log.Fatalf("database role: %v", rerr)
			}
		}

		users := controlplane.NewPgUserStore(pool)
		// TOTP secrets are encrypted at rest under their OWN key, not under GRANT_ISSUER_SEED.
		// That seed already signs backstage grants, elevation grants, session policies and session
		// tickets; making it also decrypt every second factor would mean one compromised value
		// costs both, and the two can then never be rotated independently.
		//
		// A malformed or all-zero key is FATAL, matching CP_DEVICE_IDENTITY_TOKEN's too-short case:
		// the operator meant to configure this, and starting anyway would leave 2FA enrollment
		// broken with no obvious cause. An ABSENT key is not fatal — existing secrets still verify
		// (they open as legacy plaintext) and only new enrollments are refused, so an upgrade
		// cannot lock a deployment out of its own console.
		totpCipher, terr := controlplane.NewTOTPCipher(strings.TrimSpace(os.Getenv("TOTP_ENCRYPTION_KEY")))
		if terr != nil {
			log.Fatalf("TOTP_ENCRYPTION_KEY: %v", terr)
		}
		users.TOTP = totpCipher
		if totpCipher == nil {
			log.Printf("WARNING: TOTP_ENCRYPTION_KEY not set — TOTP secrets cannot be encrypted at " +
				"rest, so new 2FA enrollments are REFUSED. Existing secrets still verify. Generate a " +
				"key with `openssl rand -hex 32`, put it in .env, then run `controlplane reencrypt-totp` " +
				"to convert the rows already on disk.")
		}
		sessions := controlplane.NewSessionManager(controlplane.NewPgSessionStore(pool))
		// Inactivity timeout is tunable for ops (CP_SESSION_IDLE_MINUTES); default 30 min. "0"
		// disables idle enforcement, leaving only the absolute 12h expiry.
		if v := os.Getenv("CP_SESSION_IDLE_MINUTES"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				sessions.IdleTTL = time.Duration(n) * time.Minute
				log.Printf("control-plane: session idle timeout = %d min", n)
			} else {
				log.Printf("WARNING: ignoring invalid CP_SESSION_IDLE_MINUTES=%q", v)
			}
		}
		tenants := controlplane.NewPgTenantResolver(pool)

		// API tokens (docs/01 §8): the authenticator FRONT — an `Authorization: Bearer rmt_api_…`
		// credential resolves to a capability-scoped token principal here; every other request
		// (cookie/session) falls through to the session authenticator unchanged.
		apiTokens := controlplane.NewPgAPITokenStore(pool)
		sessionCookieName := controlplane.DefaultSessionCookie
		if envTrue("CP_SECURE_COOKIE") {
			sessionCookieName = "__Host-" + sessionCookieName
		}
		// Bound the database work an anonymous client can cause with INVALID credentials
		// (credential_guard.go): shape check, per-source failure budget, and a global cap on concurrent
		// unproven lookups sized from the pool (a quarter of it) unless CP_AUTH_LOOKUP_CONCURRENCY says
		// otherwise. ONE guard fronts both the protected chain and /auth/logout, so they share a budget.
		credGuardCfg := controlplane.CredentialGuardConfig{
			MaxLookups: controlplane.DefaultCredentialLookups(int(pool.Config().MaxConns)),
		}
		if v := os.Getenv("CP_AUTH_LOOKUP_CONCURRENCY"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				credGuardCfg.MaxLookups = n
			} else {
				log.Fatalf("CP_AUTH_LOOKUP_CONCURRENCY=%q: want a positive integer", v)
			}
		}
		if v := os.Getenv("CP_AUTH_LOOKUP_QUEUE"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				credGuardCfg.MaxQueue = n
				if n == 0 {
					credGuardCfg.MaxQueue = -1 // zero in the config means "default"; -1 is "no waiting room"
				}
			} else {
				log.Fatalf("CP_AUTH_LOOKUP_QUEUE=%q: want a non-negative integer", v)
			}
		}
		credGuard := controlplane.NewCredentialGuard(credGuardCfg)
		log.Printf("control-plane: anonymous credential lookups: concurrency=%d, %d failures per %s per source",
			credGuardCfg.MaxLookups, controlplane.DefaultCredentialMaxFailures, controlplane.DefaultCredentialWindow)
		auth := &controlplane.GuardedAuthenticator{
			Guard:      credGuard,
			CookieName: sessionCookieName,
			Next: &controlplane.APITokenAuthenticator{
				Tokens: apiTokens,
				Next:   &controlplane.SessionAuthenticator{Sessions: sessions, Users: users, CookieName: sessionCookieName},
			},
		}
		authAPI := &controlplane.AuthService{
			Guard:        credGuard,
			Users:        users,
			Sessions:     sessions,
			Tenants:      tenants,
			Issuer:       getenv("CP_ISSUER_NAME", "rmt-control-plane"),
			SecureCookie: envTrue("CP_SECURE_COOKIE"),
		}

		// PgBinder: THE per-request RLS hook. Each authenticated request gets a pooled
		// connection with app.current_tenant pinned for the request's lifetime, so every
		// store query below runs tenant-confined by PostgreSQL itself (the stores additionally
		// re-pin per-transaction — defense in depth).
		srv = controlplane.NewServer(auth, controlplane.NewPgBinder(pool))
		srv.Ready = pool.Ping // GET /readyz reports DB reachability (cached; http_health.go)
		srv.AuthAPI = authAPI
		srv.TenantHostSuffix = strings.ToLower(strings.TrimSpace(os.Getenv("CP_TENANT_HOST_SUFFIX")))
		if totpCipher != nil {
			srv.OIDC = controlplane.NewPgOIDCStore(pool, totpCipher)
		}
		srv.RequireAgentAuditSignatures = true
		srv.Audit = controlplane.NewPgAuditStore(pool)
		srv.Grants = grants
		// Strict machine repository: a mint/session for an unknown machine is genuinely rejected,
		// and the machine's group (which scopes backstage authorization) comes from stored data.
		machines := controlplane.NewPgMachineStore(pool)
		machines.LookupPool = lookupPool // KeyTombstoned only: the pre-authentication read on the redeem and enroll doors
		srv.Machines = machines
		// Machine custom properties (migration 0024): operator-set key/value fields, RLS-scoped and
		// tenant-consistent via the composite FK to machine(tenant_id, id).
		srv.MachineProperties = controlplane.NewPgMachinePropertyStore(pool)
		// Per-tenant IP allow-list (migration 0025): the source-CIDR set each tenant permits on the
		// authenticated API, RLS-scoped and enforced after auth by Server.tenantIPAllowMiddleware.
		srv.TenantIPAllowlist = controlplane.NewPgTenantIPAllowlistStore(pool)
		// Per-tenant branding / white-label (migration 0028): product name + accent colour.
		srv.TenantBranding = controlplane.NewPgTenantBrandingStore(pool)
		// Per-tenant concurrency limits (docs/01 §5 seat metering); enforced atomically at POST /sessions.
		srv.SessionPolicies = controlplane.NewPgTenantSessionPolicyStore(pool)
		// Per-machine-group concurrency limits (migration 0034); enforced with the tenant cap at POST /sessions.
		srv.GroupSessionPolicies = controlplane.NewPgGroupSessionPolicyStore(pool)
		// Dynamic machine groups (migration 0026): saved machine-property predicates, resolved live.
		srv.DynamicGroups = controlplane.NewPgDynamicGroupStore(pool)
		// Static machine groups (migration 0001): the RBAC scope unit — create + list.
		srv.MachineGroups = controlplane.NewPgMachineGroupStore(pool)
		srv.AuthAPI.MachineGroups = srv.MachineGroups // validate group-scoped assignments (docs/55)
		// Data-plane repositories: support-session records, the management-plane audit trail
		// (append-only for rmt_app per migration 0006), and tenant listing/provisioning.
		srv.SessionRecords = controlplane.NewPgSessionRecordStore(pool)
		mgmtAudit := controlplane.NewPgMgmtAuditStore(pool)
		srv.MgmtAudit = mgmtAudit
		// Platform operator (migration 0055): one store sharing the audit store, so a lifecycle
		// change and both audit appends run in one transaction.
		srv.Platform = controlplane.NewPgPlatformStore(pool, mgmtAudit)
		srv.Adoption = controlplane.NewPgAdoptionStore(pool) // GET /adoption (docs/68): RLS-scoped counts for a tenant Owner
		// Tenant hostnames and scoped redemption (migration 0071, docs/66 stage 1a). The policy is built from
		// configuration only; when it is nil every host redeems unscoped, exactly as before.
		srv.Hostnames = controlplane.NewPgHostnameStore(pool, mgmtAudit)
		// Branding revisions, operator approval and the public branding read (migration 0072, docs/66 stage 1b).
		// Public publishing is gated by the host policy's theming flag (CP_HOST_THEMING=on); with it off the
		// public routes answer the neutral object and never touch the database. Logo upload runs the
		// logo-convert child (2 running, 8 waiting); where the platform cannot limit the child it is refused.
		brandRevs := controlplane.NewPgBrandingRevisionStore(pool, mgmtAudit)
		brandRevs.LookupPool = lookupPool // the anonymous public read only; Owner and operator writes stay on pool
		srv.BrandingRevisions = brandRevs
		srv.LogoConverter = controlplane.NewLogoConverter(2, 8)
		hostPolicy, hpErr := buildHostPolicy(srv.TenantHostSuffix)
		if hpErr != nil {
			log.Fatalf("host policy: %v", hpErr)
		}
		if hostPolicy != nil {
			// A default or legacy host that is ALSO an assignment would be both unscoped and scoped: refuse to start.
			live, lerr := controlplane.LiveHostnamesAmong(context.Background(), pool, hostPolicy.ReservedHosts())
			if lerr != nil {
				log.Fatalf("host policy: cannot check hostname assignments (is migration 0071 applied?): %v", lerr)
			}
			if len(live) > 0 {
				log.Fatalf("host policy: default/legacy host(s) %v also have a tenant hostname assignment; release them first", live)
			}
			srv.HostPolicy = hostPolicy
			log.Printf("host policy: scoped redemption ON (default hosts + legacy unscoped hosts are the only unscoped authorities); edge gate installed=%v theming=%v",
				hostPolicy.GateInstalled(), hostPolicy.Theming())
		}
		// Policy OFF: refuse to start if active assignments exist (their scope would silently vanish). A database
		// failure here is fatal, like every other startup database check.
		if gerr := themingOffGuard(context.Background(), hostPolicy, func(c context.Context) (int64, error) {
			return controlplane.ActiveHostnameCount(c, pool)
		}, os.Getenv("CP_HOST_THEMING_ALLOW_UNSCOPED"), log.Printf, time.Minute); gerr != nil {
			log.Fatalf("host policy: %v", gerr)
		}
		srv.Toolbox = controlplane.NewPgToolboxStore(pool, mgmtAudit)
		srv.GuestEnds = controlplane.NewPgGuestEndStore(pool, mgmtAudit)
		// Guest help requests (migration 0069, docs/64): the request ledger shares the audit store so each
		// transition and its audit row commit together; accept admits its session through the same protocol.
		srv.HelpRequests = controlplane.NewPgHelpRequestStore(pool, mgmtAudit)
		// Session transfer / escalation (migration 0060, docs/51): the offer ledger, sharing the audit store so
		// every transition and its management-audit rows commit in one transaction.
		srv.SessionTransfers = controlplane.NewPgSessionTransferStore(pool, mgmtAudit)
		// Fleet agent directives (migration 0068, docs/65): reinstall / remove an agent without a session. Mounted
		// only when DIRECTIVE_SIGNING_SEED is also set (below): the DEDICATED directive key, never the grant issuer.
		srv.Directives = controlplane.NewPgDirectiveStore(pool, mgmtAudit)
		srv.Tenants = controlplane.NewPgTenantStore(pool)
		// Enrollment tokens (M1): mint/list/revoke behind CapManageEnrollment, plus the public
		// POST /enroll/redeem (atomic redemption via cp_enrollment_token_redeem, migration 0007).
		srv.EnrollmentTokens = controlplane.NewPgEnrollmentTokenStore(pool)
		// API tokens (docs/01 §8): mint/list/revoke behind CapManageTenant. The SAME store instance
		// backs the authenticator front above, so a token minted here resolves there.
		srv.APITokens = apiTokens
		// Attended (on-demand) sessions (docs/12): one-time code → ephemeral consent-gated identity,
		// reusing the same ticket/signaling path (migrations 0013).
		attended := controlplane.NewPgAttendedStore(pool)
		attended.LookupPool = lookupPool // the anonymous redeem lookup only (docs/66 release gate R1)
		srv.Attended = attended
		// The SHARED single-use ledger for session tickets (migration 0023). Without it signaling
		// falls back to its per-process map, which two replicas — or one restart — each honour
		// separately, so a captured ticket brokers again inside its ~2-minute TTL.
		srv.TicketRedemptions = controlplane.NewPgTicketRedemptionStore(pool)
		// Webhooks (docs/01 §8, migration 0047): per-tenant HTTP endpoints that receive a POST
		// whenever a management-plane audit event occurs. The store holds the registrations;
		// the dispatcher fires them asynchronously after every successful recordMgmtAudit call.
		webhookStore := controlplane.NewPgWebhookStore(pool)
		srv.Webhooks = webhookStore
		srv.Dispatcher = &controlplane.WebhookDispatcher{Store: webhookStore}
		// The auth surface writes into the SAME management-plane trail as the console handlers,
		// so 2FA enrollment/confirmation and failed logins show up in GET /audit.
		authAPI.MgmtAudit = srv.MgmtAudit
		// Credential-setup tokens (migration 0020): first-password provisioning and administrative
		// reset — POST/DELETE /users/{id}/password-reset behind CapManageUsers, plus the public
		// POST /auth/password/redeem. Without this the three routes do not exist, and an account
		// with no password has no way to acquire one.
		authAPI.CredentialTokens = controlplane.NewPgCredentialTokenStore(pool)
		// Password history (migration 0051): blocks reuse of the last 4 retired passwords on
		// POST /me/password and POST /auth/password/redeem.
		authAPI.PasswordHistory = controlplane.NewPgPasswordHistoryStore(pool)
		// Central session-recording storage (docs/63, migration 0066): signed agent upload routes, an
		// encrypted volume, retention + orphan quarantine on the reaper tick. Off unless
		// RECORDING_MASTER_KEY is set (a separate secret from GRANT_ISSUER_SEED and TOTP_ENCRYPTION_KEY —
		// losing it loses every recording, so it belongs in the must-back-up set).
		recKeys, kerr := controlplane.RecordingKeyringFromEnv(os.Getenv)
		if kerr != nil {
			log.Fatalf("recording: %v", kerr)
		}
		// A mistyped floor is fatal even while recording is off, never a silent fall-back to another number (docs/63 C11).
		recFloor, flerr := controlplane.RecordingFloorFromEnv(os.Getenv("RECORDING_DISK_FLOOR_MIB"))
		if flerr != nil {
			log.Fatalf("recording: %v", flerr)
		}
		if recKeys != nil {
			audience, aerr := controlplane.NormalizeRecordingAudience(os.Getenv("CP_PUBLIC_ORIGIN"))
			if aerr != nil {
				log.Fatalf("recording: %v", aerr)
			}
			recDir := getenv("RECORDING_DIR", "/var/lib/deskrally/recordings")
			recFiles, ferr := controlplane.OpenRecordingStorage(recDir)
			if ferr != nil {
				log.Fatalf("recording: open volume %s: %v", recDir, ferr)
			}
			srv.Recording = controlplane.RecordingWiring{
				Store: controlplane.NewPgRecordingStore(pool), Files: recFiles, Keys: recKeys, Audience: audience,
				// A restore being reconciled: the orphan pass and quarantine purge stay off (docs/63 C6, C11).
				ReconcileMode:          envTrue("RECORDING_RECONCILE_MODE"),
				ReconcileAcceptMissing: envTrue("RECORDING_RECONCILE_ACCEPT_MISSING"),
				Config:                 controlplane.RecordingUploadConfig{FloorBytes: recFloor},
			}
			log.Printf("control-plane: central recording ENABLED (volume %s, audience %s, reconcile_mode=%v, disk_floor=%d MiB)", recDir, audience, envTrue("RECORDING_RECONCILE_MODE"), recFloor>>20)
		}
		// Store-backed throttle (migration 0015): every replica meters login/TOTP/redeem/attend
		// against ONE shared budget instead of a per-process map that replicas would divide.
		// BOTH owners share one instance (key prefixes namespace the endpoints); without this,
		// each would lazily build its own in-memory default.
		throttleStore := controlplane.NewPgThrottleStore(pool)
		sharedThrottle := controlplane.NewStoreThrottle(controlplane.DefaultThrottleConfig, throttleStore)
		srv.Throttle = sharedThrottle
		authAPI.Throttle = sharedThrottle

		// PROVE THE THROTTLE TABLE IS READABLE BEFORE SERVING A SINGLE REQUEST.
		//
		// Found during a restore rehearsal on the live deployment, and it is the nastiest failure
		// shape a backup can have. A `pg_dump --no-privileges` strips every GRANT. Restoring it and
		// running `migrate` does NOT put them back — the ledger says the schema is current, so
		// `applied=0 skipped=39` and 0005_app_role.sql never re-runs; it only resets rmt_app's
		// password. The result starts cleanly, logs "production mode", derives the correct
		// grant_issuer_pubkey, and then refuses EVERY login with:
		//
		//     HTTP 429 {"error":"too many attempts"}
		//
		// which is a lie. Nobody is being rate-limited. The throttle store cannot SELECT from
		// throttle_counter, so it fails closed — correct behaviour, and indistinguishable from the
		// thing it is not. The true cause appears only in container logs, as
		// `permission denied for table throttle_counter (SQLSTATE 42501)`.
		//
		// The engineer who found it had full log access and still burned three wrong hypotheses,
		// one of which — "throttle locks are rows and survive a restart" — is a true fact that
		// points directly away from the answer. An operator mid-recovery at 3am has less than that.
		//
		// So: refuse to start, and say why. Fail-closed at request time stays exactly as it was;
		// this only moves the DISCOVERY from an outage to a boot log. Consistent with the pool.Ping
		// check above, which already declines to start on a database that cannot answer.
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		tperr := throttleStore.VerifyReadable(probeCtx)
		probeCancel()
		if tperr != nil {
			log.Fatalf("cannot read throttle_counter: %v\n"+
				"    The login/TOTP/enrollment throttle fails CLOSED when its table is unreadable, so "+
				"starting anyway would answer EVERY login with 429 \"too many attempts\" — which looks "+
				"like rate limiting and is not.\n"+
				"    If this database was restored from a backup, the likely cause is a dump taken "+
				"with --no-privileges: it strips every GRANT, and `migrate` will NOT restore them "+
				"(the ledger reports the schema current, so 0005_app_role.sql never re-runs). Re-dump "+
				"without --no-privileges, or re-apply 0005's grants to rmt_app by hand.", tperr)
		}

		log.Printf("control-plane: production mode (Postgres, shared throttle) on %s", listen)
	} else {
		// Dev: no database. Every request is a full-capability owner. NEVER expose publicly.
		log.Printf("WARNING: DATABASE_URL not set — starting in DEV mode with a stub authenticator " +
			"that grants every request full owner capabilities. For local demos only; do not expose.")
		principal := &controlplane.Principal{
			UserID:   "00000000-0000-0000-0000-000000000000",
			TenantID: "00000000-0000-0000-0000-000000000000",
			Grant: controlplane.NewGrant(
				"00000000-0000-0000-0000-000000000000",
				"00000000-0000-0000-0000-000000000000",
				controlplane.NewMembership(controlplane.RoleOwner, controlplane.AllGroups()),
			),
		}
		// API tokens (docs/01 §8): the in-memory store also fronts the stub authenticator, so a
		// token minted via the DEV console actually authenticates — an `Authorization: Bearer
		// rmt_api_…` request resolves to the token's SCOPED principal, while every cookieless
		// request still falls through to the full-owner stub. This is what lets the Playwright e2e
		// prove the token works AND is capability-scoped, not just that the console lists it.
		devAPITokens := controlplane.NewInMemoryAPITokenStore()
		srv = controlplane.NewServer(
			&controlplane.APITokenAuthenticator{
				Tokens: devAPITokens,
				Next:   controlplane.StubAuthenticator{Principal: principal},
			},
			controlplane.NoopBinder{})
		srv.APITokens = devAPITokens
		srv.Audit = controlplane.NewInMemoryAuditStore()
		srv.Grants = grants
		// PERMISSIVE machine store (DEV only): any unknown device id resolves to the default group,
		// so minting works for a fresh per-run device (e.g. the secure_grant e2e) with no prior
		// enroll. Prod uses the strict PgMachineStore above.
		devMachines := controlplane.NewPermissiveMachineStore(controlplane.DevDefaultMachineGroupID)
		srv.Machines = devMachines
		// In-memory machine custom properties so the console properties panel works in demos too.
		srv.MachineProperties = controlplane.NewInMemoryMachinePropertyStore()
		// In-memory per-tenant IP allow-list so the console Security panel works in demos too.
		srv.TenantIPAllowlist = controlplane.NewInMemoryTenantIPAllowlistStore()
		// In-memory branding so the console Appearance panel works in demos too.
		srv.TenantBranding = controlplane.NewInMemoryTenantBrandingStore()
		// In-memory session policy so the console Security panel's session-limit control works in demos too.
		srv.SessionPolicies = controlplane.NewInMemoryTenantSessionPolicyStore()
		// In-memory per-group session caps so the console Machine Groups cap control works in demos too.
		srv.GroupSessionPolicies = controlplane.NewInMemoryGroupSessionPolicyStore()
		// In-memory dynamic groups so the console Groups panel works in demos too.
		srv.DynamicGroups = controlplane.NewInMemoryDynamicGroupStore()
		// In-memory static machine groups so the console Machine Groups panel works in demos too.
		devGroups := controlplane.NewInMemoryMachineGroupStore()
		srv.MachineGroups = devGroups
		// In-memory data-plane stores so the session/audit/tenant surfaces work in demos too.
		devRecords := controlplane.NewInMemorySessionRecordStore()
		srv.SessionRecords = devRecords
		devAudit := controlplane.NewInMemoryMgmtAuditStore()
		srv.MgmtAudit = devAudit
		// In-memory session transfer over the same session records, so the handoff works in demos too.
		srv.SessionTransfers = controlplane.NewInMemorySessionTransferStore(devRecords, devAudit)
		// In-memory help requests (docs/64) over the same machines, session records and audit trail.
		srv.HelpRequests = controlplane.NewInMemoryHelpRequestStore(devMachines, devRecords, devAudit)
		srv.Tenants = controlplane.NewInMemoryTenantStore()
		srv.EnrollmentTokens = controlplane.NewInMemoryEnrollmentTokenStore()
		// User management (docs/01 §5): a seeded in-memory user store + AuthService so the console Users
		// panel (and its Playwright e2e) work in DEV. The stub owner is seeded as the all-zeros user, so
		// GET /users lists it beside a demo technician and self-disable resolves against it. NEVER expose.
		const devTenant = "00000000-0000-0000-0000-000000000000"
		// Seed the dev tenant so PUT /tenant/security-policy's SetRequire2FA succeeds once the
		// anti-lockout guard is lifted (the store returns ErrNoTenant for an absent row, which
		// would 500 for a user who enrolls TOTP and then tries to enable the policy).
		if serr := srv.Tenants.CreateTenant(context.Background(), devTenant, &controlplane.Tenant{
			ID: devTenant, Slug: "dev", Name: "Dev Tenant", DeploymentMode: "saas",
		}); serr != nil {
			log.Fatalf("dev: seed tenant: %v", serr)
		}
		const devTech = "11111111-1111-1111-1111-111111111111"
		// The DEV owner gets a KNOWN password so the credential-setup step-up succeeds in demos and the
		// Playwright e2e: POST /users/{id}/password-reset re-verifies the CALLER's own password before
		// minting a takeover link (auth_password_reset.go). The technician is left credential-less so it is
		// a genuine FIRST-provision target. DEV ONLY — this whole mode is a full-owner stub.
		const devOwnerPassword = "dev-owner-password"
		devOwnerHash, herr := controlplane.HashPassword(devOwnerPassword)
		if herr != nil {
			log.Fatalf("dev: hash owner password: %v", herr)
		}
		devUsers := controlplane.NewInMemoryUserStore()
		devUsers.AddUser(
			&controlplane.AuthUser{ID: devTenant, TenantID: devTenant, Email: "owner@dev.local", DisplayName: "Dev Owner", PasswordHash: devOwnerHash},
			controlplane.NewGrant(devTenant, devTenant, controlplane.NewMembership(controlplane.RoleOwner, controlplane.AllGroups())),
		)
		devUsers.AddUser(
			&controlplane.AuthUser{ID: devTech, TenantID: devTenant, Email: "tech@dev.local", DisplayName: "Dev Technician"},
			controlplane.NewGrant(devTech, devTenant, controlplane.NewMembership(controlplane.RoleTechnician, controlplane.AllGroups())),
		)
		// Nested groups (docs/62): let grants expand through the dev group tree, and let hierarchy mutations and
		// tree-conditional writes see it — the in-memory twin of the database doing it.
		controlplane.LinkGroupStores(devGroups, devUsers, devMachines)
		// Credential-setup tokens (migration 0020) in-memory, so the console Users panel can mint a
		// first-password / reset link and the public POST /auth/password/redeem page can consume it in DEV
		// — the same reason devAPITokens/devUsers exist. Users is set so Mint refuses an unknown or
		// disabled target exactly as the pg store's SECURITY DEFINER functions do.
		devCredentialTokens := controlplane.NewInMemoryCredentialTokenStore()
		devCredentialTokens.Users = devUsers
		srv.AuthAPI = &controlplane.AuthService{
			Users:            devUsers,
			Sessions:         controlplane.NewSessionManager(controlplane.NewInMemorySessionStore()),
			MgmtAudit:        srv.MgmtAudit,
			MachineGroups:    srv.MachineGroups, // validate group-scoped assignments (docs/55)
			CredentialTokens: devCredentialTokens,
			PasswordHistory:  &controlplane.InMemoryPasswordHistoryStore{},
			Issuer:           "rmt-dev",
		}
		// Attended sessions (docs/12): the in-memory store mints ephemeral machines into the same
		// dev machine store, so the guest's device id is resolvable by signaling's identity lookup.
		srv.Attended = controlplane.NewInMemoryAttendedStore(devMachines)
		// A real ledger, but only for THIS process — which is the exact shortcoming this endpoint
		// exists to fix on the signaling side. Acceptable here for the same reason the stub
		// authenticator is: DEV mode is one process, one demo, no replicas.
		srv.TicketRedemptions = controlplane.NewInMemoryTicketRedemptionStore()
		// In-memory webhooks so the console Webhooks panel works in demos too.
		devWebhookStore := controlplane.NewInMemoryWebhookStore()
		srv.Webhooks = devWebhookStore
		srv.Dispatcher = &controlplane.WebhookDispatcher{Store: devWebhookStore}
		log.Printf("control-plane: DEV mode (in-memory) on %s", listen)
	}

	// M2: the signaling rendezvous POST /sessions points viewers at (with a signed session
	// ticket). Empty keeps the library default (ws://127.0.0.1:8080/ws).
	srv.SignalingURL = os.Getenv("CP_SIGNALING_URL")
	// AGENT_PUBLISHED_VERSION: operator-designated expected agent build (docs/01 §6). When set,
	// GET /agent-version returns it and the console MachinesPanel flags outdated machines.
	// Format: "<semver>+<short-sha>", e.g. "0.0.1+abc1234". Empty = version tracking disabled.
	srv.PublishedAgentVersion = os.Getenv("AGENT_PUBLISHED_VERSION")
	// Opt-in until the unsigned installer has passed isolated Windows lifecycle acceptance.
	// Deployment-pass mode (docs/48 C): generic signed binaries bound to this server by a pass.
	passFile, releaseFile := os.Getenv("CP_DEPLOYMENT_PASS_FILE"), os.Getenv("CP_AGENT_RELEASE_ATTESTATION_FILE")
	if dir := os.Getenv("CP_MANAGED_INSTALL_DIR"); dir != "" {
		cfg := controlplane.ManagedInstallerConfig{
			Dir: dir, ControlPlaneURL: os.Getenv("CP_MANAGED_INSTALL_CONTROL_PLANE_URL"), SignalingURL: srv.SignalingURL,
			GrantIssuerPubkey: grants.PublicKeyHex(), DeploymentPassFile: passFile, AgentReleaseFile: releaseFile,
		}
		if passFile != "" || releaseFile != "" {
			if testKey := os.Getenv("CP_DEPLOYMENT_PASS_TEST_ROOT_KEY"); testKey != "" {
				root, err := controlplane.ParseDeploymentRootKey(testKey)
				if err != nil {
					log.Fatalf("CP_DEPLOYMENT_PASS_TEST_ROOT_KEY: %v", err)
				}
				cfg.PassRoot, cfg.TestRoot = root, true
				log.Printf("control-plane: WARNING: deployment passes are verified with a TEST root key (lab origins only)")
			} else {
				root, err := controlplane.DeploymentPassRootKey()
				if err != nil {
					log.Fatalf("CP_DEPLOYMENT_PASS_FILE: %v", err)
				}
				cfg.PassRoot = root
			}
		}
		installer, err := controlplane.LoadManagedInstallerConfig(cfg)
		if err != nil {
			// Pass-mode refusals say which check failed (nothing in them is secret); the baked-mode
			// failure stays deliberately opaque, as before.
			var pe *controlplane.PassModeError
			if errors.As(err, &pe) {
				log.Fatalf("control-plane: %v", pe)
			}
			log.Fatal("control-plane: managed installer release validation failed")
		}
		srv.ManagedInstaller = installer
		if installer.PassMode() {
			log.Printf("control-plane: managed installer in deployment-pass mode")
			for _, w := range installer.PassWarnings() {
				log.Printf("control-plane: WARNING: %s", w)
			}
		}
	} else if passFile != "" || releaseFile != "" {
		log.Fatal("control-plane: CP_DEPLOYMENT_PASS_FILE / CP_AGENT_RELEASE_ATTESTATION_FILE need CP_MANAGED_INSTALL_DIR")
	}

	// CP_TRUSTED_PROXIES (F14): CIDR ranges of reverse-proxy peers that are allowed to set
	// X-Forwarded-For. When set, XFF is only honoured from those peers; all others are judged on
	// their TCP address regardless of CP_TRUST_PROXY_IP. Prefer this over CP_TRUST_PROXY_IP alone
	// for new deployments — set it to the Docker Compose network CIDR (e.g. 172.20.0.0/16).
	//
	// CP_TRUST_PROXY_IP (legacy): when CP_TRUSTED_PROXIES is not set, falls back to honouring XFF
	// from ANY peer. This is the old behaviour and remains for backward compatibility, but should be
	// replaced with CP_TRUSTED_PROXIES which actually validates the TCP source.
	proxyNets, proxyNetsErr := controlplane.ParseTrustedProxies(os.Getenv("CP_TRUSTED_PROXIES"))
	if proxyNetsErr != nil {
		log.Fatalf("CP_TRUSTED_PROXIES: %v", proxyNetsErr)
	}
	legacyTrustProxy := envTrue("CP_TRUST_PROXY_IP")
	if len(proxyNets) > 0 {
		// F14-secure path: restrict XFF to known proxy peers. SetTrustedProxies is called AFTER
		// IPAllowlist is set below so it can propagate the nets to the allow-list.
		log.Printf("control-plane: trusted proxy restriction configured (%d network(s))", len(proxyNets))
	} else if legacyTrustProxy {
		// Legacy path: warn, then arm the old trust-all behaviour.
		log.Printf("WARNING: CP_TRUST_PROXY_IP=true without CP_TRUSTED_PROXIES — XFF is " +
			"accepted from ANY TCP peer; a sibling container or direct backend reachability " +
			"lets an attacker forge source IPs (docs/25 F14). Set CP_TRUSTED_PROXIES to the " +
			"reverse proxy CIDR(s) to close this.")
		srv.SetTrustProxy(true)
	}

	// IP allow-listing for the console/host API (docs/01 §14). Empty = open (default). A malformed
	// list is FATAL: a typo in an access-control list must never silently widen or narrow access.
	// The trustProxy bool reflects the legacy path; SetTrustedProxies below propagates the nets.
	if allow, err := controlplane.ParseIPAllowlist(os.Getenv("CP_ADMIN_IP_ALLOWLIST"), legacyTrustProxy); err != nil {
		log.Fatalf("CP_ADMIN_IP_ALLOWLIST: %v", err)
	} else if allow != nil {
		srv.IPAllowlist = allow
		log.Printf("control-plane: console API IP allow-list ACTIVE (trust_proxy=%v)", legacyTrustProxy || len(proxyNets) > 0)
	}
	// Arm SetTrustedProxies AFTER IPAllowlist is set, so it can propagate the nets to the
	// allow-list's copy in one call.
	if len(proxyNets) > 0 {
		srv.SetTrustedProxies(proxyNets)
	}

	// M3: the device-identity lookup signaling uses to authenticate register_agent. Rejected here
	// rather than silently ignored — a token too short to be a secret is a misconfiguration, and
	// starting anyway would leave signaling unable to authenticate agents with no obvious cause.
	if tok := os.Getenv("CP_DEVICE_IDENTITY_TOKEN"); tok != "" {
		if len(tok) < controlplane.DeviceIdentityTokenMinLen {
			log.Fatalf("CP_DEVICE_IDENTITY_TOKEN is %d characters; it is a machine-to-machine shared "+
				"secret and must be at least %d", len(tok), controlplane.DeviceIdentityTokenMinLen)
		}
		srv.DeviceIdentityToken = tok
	} else {
		log.Printf("WARNING: CP_DEVICE_IDENTITY_TOKEN not set — GET /internal/devices/{id}/identity " +
			"is not mounted, so the signaling server cannot authenticate register_agent. Set it (and " +
			"the matching SIGNALING_DEVICE_IDENTITY_TOKEN) before running signaling in enforcing mode.")
	}

	// Fleet directives (docs/65 D-C3): signed with a DEDICATED key derived from DIRECTIVE_SIGNING_SEED, so a
	// compromise of the grant issuer cannot also order a fleet wipe, and agents pin THIS key separately (the
	// enroll-redeem response carries its public half). Without a seed the directive routes, the internal
	// signaling routes and the directive_v1 capability are simply not mounted.
	if srv.Directives != nil {
		if seed := os.Getenv("DIRECTIVE_SIGNING_SEED"); seed != "" {
			iss, err := controlplane.NewDirectiveIssuerFromHex(seed)
			if err != nil {
				log.Fatalf("DIRECTIVE_SIGNING_SEED: %v", err)
			}
			// The directive key must be DEDICATED: the same key as the grant issuer (which also signs
			// elevation grants, session policies and session-end artifacts) defeats D-C3.
			if err := controlplane.CheckDirectiveKeyDistinct(iss.PublicKeyHex(),
				controlplane.NamedSigningKey{Name: "grant issuer (GRANT_ISSUER_SEED; also signs elevation grants)", PublicHex: grants.PublicKeyHex()}); err != nil {
				log.Fatalf("%v", err)
			}
			srv.DirectiveIssuer = iss
			if url := os.Getenv("CP_SIGNALING_NOTIFY_URL"); url != "" && srv.DeviceIdentityToken != "" {
				srv.DirectiveNotifier = &controlplane.HTTPDirectiveNotifier{BaseURL: url, Token: srv.DeviceIdentityToken}
			} else {
				log.Printf("CP_SIGNALING_NOTIFY_URL not set — directives reach a connected agent only when it next registers")
			}
			go srv.RunDirectiveSweeper(context.Background(), 30*time.Second)
			log.Printf("fleet directives enabled (directive key %s...)", iss.PublicKeyHex()[:8])
		} else {
			log.Printf("WARNING: DIRECTIVE_SIGNING_SEED not set — fleet directives (remote reinstall / remove) are NOT mounted")
			srv.Directives = nil
		}
	}

	// Machine presence for the console's access panel (docs/01 §4): the signaling registry, read
	// over its service-token-gated GET /internal/presence. Both halves must be configured, and the
	// token must match SIGNALING_PRESENCE_TOKEN on the signaling side.
	//
	// Unlike the device-identity token above this is NOT fatal when unset or short: nothing is
	// authorized on presence, so a missing feed degrades GET /machines to "presence unknown"
	// instead of preventing startup. It is still logged, because silently listing every machine as
	// status-unknown is confusing to operate.
	if url, tok := os.Getenv("CP_PRESENCE_URL"), os.Getenv("CP_PRESENCE_TOKEN"); url != "" && tok != "" {
		if len(tok) < controlplane.DeviceIdentityTokenMinLen {
			log.Printf("WARNING: CP_PRESENCE_TOKEN is %d characters; it is a machine-to-machine shared "+
				"secret and should be at least %d — presence is NOT wired",
				len(tok), controlplane.DeviceIdentityTokenMinLen)
		} else {
			srv.Presence = &controlplane.SignalingPresenceSource{URL: url, Token: tok}
			log.Printf("machine presence wired to %s", url)
			// migrations/0079: record last_seen on a timer too, not only when a console lists machines.
			go srv.RunPresenceSweeper(context.Background(), controlplane.DefaultPresenceSweepInterval)
		}
	} else {
		log.Printf("CP_PRESENCE_URL/CP_PRESENCE_TOKEN not set — GET /machines reports " +
			"\"presence_known\": false and omits per-machine online status")
	}

	// Top-level mux: a public health check plus the wired control-plane handler. "/healthz" is a
	// more specific pattern than the control-plane's "/" catch-all, so it is matched first and
	// bypasses the auth chain.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", srv.Handler())

	// docs/25 F01: bound concurrent argon2 work process-wide. Each verification allocates 64 MiB
	// under the default parameters, and login is anonymous, so without this the peak memory is
	// chosen by whoever is sending requests. Tunable because the right number is a function of the
	// host's RAM: CP_PASSWORD_HASH_CONCURRENCY slots at ~64 MiB each.
	hashCfg := controlplane.DefaultHashLimiterConfig
	if v := os.Getenv("CP_PASSWORD_HASH_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			hashCfg.MaxConcurrent = n
		} else {
			log.Fatalf("CP_PASSWORD_HASH_CONCURRENCY=%q: want a positive integer", v)
		}
	}
	if v := os.Getenv("CP_PASSWORD_HASH_QUEUE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			hashCfg.MaxQueue = n
		} else {
			log.Fatalf("CP_PASSWORD_HASH_QUEUE=%q: want a non-negative integer", v)
		}
	}
	controlplane.ConfigurePasswordHashing(hashCfg)
	log.Printf("control-plane: argon2 concurrency=%d queue=%d (~%d MiB peak hash memory)",
		hashCfg.MaxConcurrent, hashCfg.MaxQueue,
		hashCfg.MaxConcurrent*int(controlplane.DefaultArgon2Params.Memory/1024))

	// docs/25 F05: ReadHeaderTimeout alone bounds only the header phase. Without ReadTimeout a
	// slow BODY holds the handler — and therefore the tenant's pinned pool connection — open
	// indefinitely, which is a low-bandwidth route to pool starvation across tenants. WriteTimeout
	// is sized for the largest legitimate response (a 10 000-event audit export, capped by
	// maxMgmtAuditExportLimit) over a slow link; the control plane serves no WebSocket and no
	// streaming endpoint, so neither timeout can cut a long-lived upgraded connection.
	httpServer := controlplane.NewPublicServer(listen, mux, controlplane.PublicServerConfig{
		ReadTimeout: envDuration("CP_READ_TIMEOUT", 0),
	})

	log.Printf("control-plane: grant_issuer_pubkey=%s", grants.PublicKeyHex())

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Operators read the live issuer key from this log line (docs/10 §4), and container logs rotate by
	// size, so a busy day could rotate the startup line away. Repeat it daily; it is a public key.
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("control-plane: grant_issuer_pubkey=%s (daily repeat)", grants.PublicKeyHex())
			}
		}
	}()

	// Background session reaper: proactively closes expired session_record rows for all tenants with
	// a configured max_session_seconds. The lazy per-start reap remains the safety net; this layer
	// keeps the table clean between starts so leaked rows do not silently arm the concurrency cap.
	// 5-minute interval balances reaper promptness against extra DB load; tunable if needed.
	srv.StartRecordingServices(ctx) // startup reconciliation of in-flight recording uploads (no-op unless enabled)
	srv.StartBackgroundReaper(ctx, 5*time.Minute)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("control-plane: listening on %s", listen)
		// HTTP/1.1 only, connection-capped (docs/66 2d.2, 2e.2; listener.go).
		ln, lerr := net.Listen("tcp", httpServer.Addr)
		if lerr != nil {
			errCh <- lerr
			return
		}
		errCh <- httpServer.Serve(controlplane.LimitListener(ln, envInt("CP_MAX_CONNS", controlplane.DefaultMaxConns)))
	}()

	select {
	case <-ctx.Done():
		log.Printf("control-plane: shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutCtx)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("control-plane: server error: %v", err)
		}
	}
}
