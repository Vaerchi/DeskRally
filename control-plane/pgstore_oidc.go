package controlplane

// OIDC persistence owns the fencing protocol, not the HTTP handlers. All locks survive until
// withTenant commits, in connection -> user -> credential -> session order (design v3/v3.1).
import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrOIDCDisabled        = errors.New("OIDC connection is disabled or absent")
	ErrOIDCVersion         = errors.New("OIDC connection version changed")
	ErrOIDCNotLinked       = errors.New("OIDC identity is not linked")
	ErrOIDCUserDisabled    = errors.New("OIDC user is absent or disabled")
	ErrOIDCEpoch           = errors.New("OIDC credential epoch changed")
	ErrOIDCLinkConflict    = errors.New("OIDC identity link conflicts")
	ErrOIDCSessionInvalid  = errors.New("OIDC originating session is invalid")
	ErrOIDCStepUpStale     = errors.New("OIDC step-up is stale")
	ErrOIDCAttemptUsed     = errors.New("OIDC attempt already used")
	ErrOIDCAttemptExpired  = errors.New("OIDC attempt expired")
	ErrOIDCAttemptNotFound = errors.New("OIDC attempt not found")
	ErrOIDCInvalid         = errors.New("invalid OIDC storage input")
	ErrOIDCTenantDisabled  = errors.New("OIDC tenant is disabled")
)

type PgOIDCStore struct {
	Pool   *pgxpool.Pool
	Cipher *TOTPCipher
}

func NewPgOIDCStore(pool *pgxpool.Pool, cipher *TOTPCipher) *PgOIDCStore {
	return &PgOIDCStore{Pool: pool, Cipher: cipher}
}

// Connection has no secret field: reading settings cannot accidentally disclose one.
type OIDCConnection struct {
	TenantID, Profile, EntraTenantID, ClientID string
	Enabled, TrustEntraMFA, HasSecret          bool
	Version                                    int64
	LastTestVersion                            *int64
	LastTestAt                                 *time.Time
	UpdatedAt                                  time.Time
	UpdatedBy                                  *string
}

type OIDCConnectionWrite struct {
	Profile, EntraTenantID, ClientID string
	Enabled, TrustEntraMFA           bool
	ClientSecret                     *string // nil preserves the existing secret; empty is refused
	UpdatedBy                        *string
	// Authority, when set, is the ORIGINATING session that authorized this change (Codex impl review
	// B v1). It is re-validated INSIDE the mutation transaction — ownership, revocation, expiry, MFA
	// generation, credential epoch and a step-up within 5 minutes of post-lock DB time — so a request
	// that passed its step-up and then waited cannot commit after its session was revoked or the step-
	// up expired. The HTTP handler always sets it; nil is for internal callers and tests only.
	Authority *OIDCSettingsAuthority
}

// OIDCSettingsAuthority identifies the session that authorized a connection change.
type OIDCSettingsAuthority struct {
	UserID, SessionID string
	EpochBaseline     time.Time
}

const oidcConnectionColumns = `tenant_id::text, profile, entra_tenant_id::text, client_id::text,
 enabled, trust_entra_mfa, octet_length(client_secret_enc) > 0, version,
 last_test_version, last_test_at, updated_at, updated_by::text`

func scanOIDCConnection(row pgx.Row) (*OIDCConnection, error) {
	var c OIDCConnection
	err := row.Scan(&c.TenantID, &c.Profile, &c.EntraTenantID, &c.ClientID, &c.Enabled,
		&c.TrustEntraMFA, &c.HasSecret, &c.Version, &c.LastTestVersion, &c.LastTestAt, &c.UpdatedAt, &c.UpdatedBy)
	return &c, err
}

func (s *PgOIDCStore) GetConnection(ctx context.Context, tenantID string) (*OIDCConnection, error) {
	var c *OIDCConnection
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		c, err = scanOIDCConnection(tx.QueryRow(ctx, `SELECT `+oidcConnectionColumns+` FROM tenant_oidc WHERE tenant_id=$1`, tenantID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOIDCDisabled
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *PgOIDCStore) PutConnection(ctx context.Context, tenantID string, f OIDCConnectionWrite) (*OIDCConnection, error) {
	if f.Profile != "entra" || !isUUID(f.EntraTenantID) || !isUUID(f.ClientID) {
		return nil, ErrOIDCInvalid
	}
	var sealed []byte
	if f.ClientSecret != nil {
		if *f.ClientSecret == "" {
			return nil, ErrOIDCInvalid
		}
		var err error
		sealed, err = s.Cipher.Seal(*f.ClientSecret)
		if err != nil {
			return nil, err
		}
	}
	var out *OIDCConnection
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// The tenant row serializes first creation, where no connection row exists to lock.
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM tenant WHERE id=$1 FOR UPDATE`, tenantID).Scan(&one); err != nil {
			return err
		}
		old, err := scanOIDCConnection(tx.QueryRow(ctx, `SELECT `+oidcConnectionColumns+` FROM tenant_oidc WHERE tenant_id=$1 FOR UPDATE`, tenantID))
		var authority OIDCIdentityAuthority
		var generation int64
		if f.Authority != nil {
			// Lock order continues tenant_oidc -> app_user -> user_credential -> user_session.
			authority = OIDCIdentityAuthority{TenantID: tenantID, UserID: f.Authority.UserID, EpochBaseline: f.Authority.EpochBaseline}
			a := authority
			var lockErr error
			_, _, generation, lockErr = oidcLockUser(ctx, tx, a, false)
			if lockErr != nil {
				return lockErr
			}
			if lockErr = oidcCheckEpoch(ctx, tx, a.UserID, a.EpochBaseline); lockErr != nil {
				return lockErr
			}
			if lockErr = oidcCheckOrigin(ctx, tx, a, f.Authority.SessionID, generation, 5*time.Minute); lockErr != nil {
				return lockErr
			}
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if sealed == nil {
				return ErrOIDCInvalid
			}
			_, err = tx.Exec(ctx, `INSERT INTO tenant_oidc
			 (tenant_id,profile,entra_tenant_id,client_id,client_secret_enc,enabled,trust_entra_mfa,updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tenantID, f.Profile, f.EntraTenantID, f.ClientID, sealed, f.Enabled, f.TrustEntraMFA, f.UpdatedBy)
		} else if err == nil {
			_, err = tx.Exec(ctx, `UPDATE tenant_oidc SET profile=$2,entra_tenant_id=$3,client_id=$4,
			 client_secret_enc=coalesce($5::bytea,client_secret_enc),enabled=$6,trust_entra_mfa=$7,
			 version=version+1,last_test_version=NULL,last_test_at=NULL,updated_at=clock_timestamp(),updated_by=$8
			 WHERE tenant_id=$1`, tenantID, f.Profile, f.EntraTenantID, f.ClientID, sealed, f.Enabled, f.TrustEntraMFA, f.UpdatedBy)
		}
		if err != nil {
			return err
		}
		if old != nil && (old.EntraTenantID != strings.ToLower(f.EntraTenantID) || old.ClientID != strings.ToLower(f.ClientID)) {
			// Lock users consistently before touching sessions; the connection lock excludes B/C/D.
			rows, err := tx.Query(ctx, `SELECT id FROM app_user WHERE tenant_id=$1 ORDER BY id FOR UPDATE`, tenantID)
			if err != nil {
				return err
			}
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE app_user SET oidc_issuer=NULL,oidc_subject=NULL WHERE tenant_id=$1`, tenantID); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE user_session SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND login_method='oidc' AND revoked_at IS NULL`, tenantID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM oidc_pending_mfa WHERE tenant_id=$1`, tenantID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM oidc_login_attempt WHERE tenant_id=$1`, tenantID); err != nil {
			return err
		}
		out, err = scanOIDCConnection(tx.QueryRow(ctx, `SELECT `+oidcConnectionColumns+` FROM tenant_oidc WHERE tenant_id=$1`, tenantID))
		if err != nil {
			return err
		}
		if f.Authority != nil {
			// The statements above can block (the bulk session revocation waits on any locked OIDC
			// session row), and holding the originating session's lock stops revocation but not TIME:
			// re-check expiry and step-up freshness against DB time once more, last, before commit.
			return oidcCheckOrigin(ctx, tx, authority, f.Authority.SessionID, generation, 5*time.Minute)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func oidcLockConnection(ctx context.Context, tx pgx.Tx, tenantID string, version int64) error {
	return oidcLockConnectionMode(ctx, tx, tenantID, version, "FOR SHARE")
}

// oidcLockConnectionMode is oidcLockConnection with an explicit row-lock strength. RecordTest UPDATEs the
// row it locked, so it takes FOR NO KEY UPDATE up front: a SHARE lock later upgraded by the UPDATE would
// let two concurrent test completions deadlock on the upgrade.
func oidcLockConnectionMode(ctx context.Context, tx pgx.Tx, tenantID string, version int64, mode string) error {
	var enabled bool
	var current int64
	err := tx.QueryRow(ctx, `SELECT enabled,version FROM tenant_oidc WHERE tenant_id=$1 `+mode, tenantID).Scan(&enabled, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOIDCDisabled
	}
	if err != nil {
		return err
	}
	if !enabled {
		return ErrOIDCDisabled
	}
	if current != version {
		return ErrOIDCVersion
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT disabled_at IS NULL FROM tenant WHERE id=$1`, tenantID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrOIDCTenantDisabled
	}
	return nil
}

func oidcEpoch(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func oidcCheckEpoch(ctx context.Context, tx pgx.Tx, userID string, baseline time.Time) error {
	var epoch time.Time
	err := tx.QueryRow(ctx, `SELECT updated_at FROM user_credential WHERE user_id=$1 FOR SHARE`, userID).Scan(&epoch)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !epoch.Equal(baseline) {
		return ErrOIDCEpoch
	}
	return nil
}

type OIDCAttempt struct {
	ID, TenantID                     string
	KeyHash, StateHash               []byte
	Nonce, CodeVerifier, Mode        string
	UserID, SessionID                *string
	EpochBaseline                    time.Time
	ConnectionVersion                int64
	Profile, RedirectURI, ReturnPath string
	// Remember asks for a remembered session (migrations/0080). Login attempts only.
	Remember  bool
	CreatedAt time.Time
	UsedAt    *time.Time
}

func (s *PgOIDCStore) CreateAttempt(ctx context.Context, a *OIDCAttempt) error {
	if a == nil {
		return ErrOIDCInvalid
	}
	u, err := url.Parse(a.ReturnPath)
	if err != nil || !strings.HasPrefix(a.ReturnPath, "/") || strings.HasPrefix(a.ReturnPath, "//") || strings.ContainsAny(a.ReturnPath, "\\\r\n\x00") || u.IsAbs() || u.Host != "" {
		return ErrOIDCInvalid
	}
	if a.CodeVerifier == "" || a.Nonce == "" || len(a.KeyHash) != 32 || len(a.StateHash) != 32 || a.Profile != "entra" {
		return ErrOIDCInvalid
	}
	if a.Mode != "login" && a.Mode != "link" && a.Mode != "test" {
		return ErrOIDCInvalid
	}
	if a.Mode == "login" {
		if a.UserID != nil || a.SessionID != nil || !a.EpochBaseline.IsZero() {
			return ErrOIDCInvalid
		}
	} else if a.UserID == nil || a.SessionID == nil || a.Remember {
		// A link or test attempt issues no session, so it has nothing to remember (0080's CHECK agrees).
		return ErrOIDCInvalid
	}
	sealed, err := s.Cipher.Seal(a.CodeVerifier)
	if err != nil {
		return err
	}
	return withTenant(ctx, s.Pool, a.TenantID, func(tx pgx.Tx) error {
		// Serialize admissions across replicas: a separate HTTP count alone can overshoot.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('oidc-attempt:' || $1::text, 0))`, a.TenantID); err != nil {
			return err
		}
		if err := oidcLockConnection(ctx, tx, a.TenantID, a.ConnectionVersion); err != nil {
			return err
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM oidc_login_attempt WHERE tenant_id=$1 AND used_at IS NULL AND created_at > clock_timestamp()-interval '10 minutes'`, a.TenantID).Scan(&live); err != nil {
			return err
		}
		if live >= 500 {
			// Retire the OLDEST unfinished attempts instead of refusing this one (security audit
			// 2026-10-18). Refusing let ~25 source addresses, each within its 20-per-10-minutes
			// start budget, hold the tenant at the cap and block every Microsoft sign-in for as long
			// as they kept it up. Evicting bounds memory exactly the same, and a flood now mostly
			// displaces itself: to knock out a real user's attempt it must issue hundreds of starts in
			// the half-minute that user spends at Microsoft. Marked used (not deleted): completing an
			// evicted attempt reports "already used", and the user simply starts again.
			if _, err := tx.Exec(ctx, `UPDATE oidc_login_attempt SET used_at = clock_timestamp()
				 WHERE id IN (SELECT id FROM oidc_login_attempt
				               WHERE tenant_id=$1 AND used_at IS NULL AND created_at > clock_timestamp()-interval '10 minutes'
				               ORDER BY created_at, id LIMIT $2)`, a.TenantID, live-499); err != nil {
				return err
			}
		}
		var authority OIDCIdentityAuthority
		var generation int64
		if a.Mode != "login" {
			authority = OIDCIdentityAuthority{TenantID: a.TenantID, UserID: *a.UserID, EpochBaseline: a.EpochBaseline, ConnectionVersion: a.ConnectionVersion}
			var err error
			_, _, generation, err = oidcLockUser(ctx, tx, authority, false)
			if err != nil {
				return err
			}
			if err := oidcCheckEpoch(ctx, tx, authority.UserID, authority.EpochBaseline); err != nil {
				return err
			}
			// Starting authority must survive every preceding lock wait. Completion
			// has its own longer window; it cannot retroactively authorize a start.
			if err := oidcCheckOrigin(ctx, tx, authority, *a.SessionID, generation, 5*time.Minute); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx, `INSERT INTO oidc_login_attempt
		 (tenant_id,key_hash,state_hash,nonce,code_verifier_enc,mode,user_id,session_id,epoch_baseline,connection_version,profile,redirect_uri,return_path,remember)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id::text,created_at`,
			a.TenantID, a.KeyHash, a.StateHash, a.Nonce, sealed, a.Mode, a.UserID, a.SessionID, oidcEpoch(a.EpochBaseline), a.ConnectionVersion, a.Profile, a.RedirectURI, a.ReturnPath, a.Remember).Scan(&a.ID, &a.CreatedAt); err != nil {
			return err
		}
		if a.Mode != "login" {
			// The INSERT can wait on a unique index; re-check the starting authority last, as
			// PutConnection and LinkIdentity do, so a start never commits on a step-up that expired.
			return oidcCheckOrigin(ctx, tx, authority, *a.SessionID, generation, 5*time.Minute)
		}
		return nil
	})
}

// Both hashes participate in lookup: a wrong browser key reveals neither existence nor status.
func (s *PgOIDCStore) ConsumeAttempt(ctx context.Context, tenantID string, stateHash, keyHash []byte) (*OIDCAttempt, error) {
	a := &OIDCAttempt{TenantID: tenantID}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var sealed []byte
		var epoch *time.Time
		err := tx.QueryRow(ctx, `SELECT id::text,key_hash,state_hash,nonce,code_verifier_enc,mode,user_id::text,session_id::text,
		 epoch_baseline,connection_version,profile,redirect_uri,return_path,remember,created_at,used_at
		 FROM oidc_login_attempt WHERE state_hash=$1 AND key_hash=$2 FOR UPDATE`, stateHash, keyHash).
			Scan(&a.ID, &a.KeyHash, &a.StateHash, &a.Nonce, &sealed, &a.Mode, &a.UserID, &a.SessionID, &epoch, &a.ConnectionVersion, &a.Profile, &a.RedirectURI, &a.ReturnPath, &a.Remember, &a.CreatedAt, &a.UsedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOIDCAttemptNotFound
		}
		if err != nil {
			return err
		}
		if a.UsedAt != nil {
			return ErrOIDCAttemptUsed
		}
		if epoch != nil {
			a.EpochBaseline = epoch.UTC()
		}
		// clock_timestamp is evaluated after the row lock wait, unlike transaction-start now().
		err = tx.QueryRow(ctx, `UPDATE oidc_login_attempt SET used_at=clock_timestamp()
		 WHERE id=$1 AND used_at IS NULL AND created_at > clock_timestamp()-interval '10 minutes'
		 RETURNING used_at`, a.ID).Scan(&a.UsedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOIDCAttemptExpired
		}
		if err != nil {
			return err
		}
		var encrypted bool
		a.CodeVerifier, encrypted, err = s.Cipher.Open(sealed)
		if err != nil {
			return err
		}
		if !encrypted {
			return ErrOIDCInvalid
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *PgOIDCStore) CountLiveAttempts(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM oidc_login_attempt WHERE used_at IS NULL AND created_at > clock_timestamp()-interval '10 minutes'`).Scan(&n)
	})
	return n, err
}

type OIDCPendingMFA struct {
	ID, TenantID, UserID, AttemptID, Issuer, Subject string
	EpochBaseline                                    time.Time
	ConnectionVersion                                int64
	CreatedAt                                        time.Time
	UsedAt                                           *time.Time
}

func (s *PgOIDCStore) CreatePendingMFA(ctx context.Context, p *OIDCPendingMFA) error {
	if p == nil || p.Issuer == "" || p.Subject == "" {
		return ErrOIDCInvalid
	}
	return withTenant(ctx, s.Pool, p.TenantID, func(tx pgx.Tx) error {
		if err := oidcLockConnection(ctx, tx, p.TenantID, p.ConnectionVersion); err != nil {
			return err
		}
		// Only a consumed login attempt can produce pending authority; UNIQUE prevents duplicates.
		err := tx.QueryRow(ctx, `INSERT INTO oidc_pending_mfa
		 (tenant_id,user_id,attempt_id,issuer,subject,epoch_baseline,connection_version)
		 SELECT $1,$2,a.id,$4,$5,$6,$7 FROM oidc_login_attempt a
		 WHERE a.id=$3 AND a.mode='login' AND a.used_at IS NOT NULL AND a.connection_version=$7
		 AND a.created_at > clock_timestamp()-interval '10 minutes'
		 RETURNING id::text,created_at`, p.TenantID, p.UserID, p.AttemptID, p.Issuer, p.Subject, oidcEpoch(p.EpochBaseline), p.ConnectionVersion).Scan(&p.ID, &p.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOIDCAttemptNotFound
		}
		if isUniqueViolation(err) {
			return ErrOIDCAttemptUsed
		}
		return err
	})
}

func (s *PgOIDCStore) ConsumePendingMFA(ctx context.Context, tenantID, id string) (*OIDCPendingMFA, error) {
	p := &OIDCPendingMFA{TenantID: tenantID}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var epoch *time.Time
		err := tx.QueryRow(ctx, `SELECT id::text,user_id::text,attempt_id::text,issuer,subject,epoch_baseline,connection_version,created_at,used_at
		 FROM oidc_pending_mfa WHERE id=$1 FOR UPDATE`, id).Scan(&p.ID, &p.UserID, &p.AttemptID, &p.Issuer, &p.Subject, &epoch, &p.ConnectionVersion, &p.CreatedAt, &p.UsedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOIDCAttemptNotFound
		}
		if err != nil {
			return err
		}
		if p.UsedAt != nil {
			return ErrOIDCAttemptUsed
		}
		if epoch != nil {
			p.EpochBaseline = epoch.UTC()
		}
		err = tx.QueryRow(ctx, `UPDATE oidc_pending_mfa SET used_at=clock_timestamp()
		 WHERE id=$1 AND used_at IS NULL AND created_at > clock_timestamp()-interval '5 minutes' RETURNING used_at`, id).Scan(&p.UsedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOIDCAttemptExpired
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// OIDCIdentityAuthority is constructed only after token verification (or pending-MFA consumption).
// Zero EpochBaseline unambiguously means there was no local credential at the baseline read.
type OIDCIdentityAuthority struct {
	TenantID, UserID, Issuer, Subject string
	ConnectionVersion                 int64
	EpochBaseline                     time.Time
	// Remember makes IssueOIDCSession issue a remembered session (30 d absolute, 7 d idle) instead of an
	// ordinary one. It comes only from the consumed login attempt (migrations/0080), never from the callback.
	Remember bool
}

func oidcLockUser(ctx context.Context, tx pgx.Tx, a OIDCIdentityAuthority, update bool) (*string, *string, int64, error) {
	lock := " FOR SHARE"
	if update {
		lock = " FOR UPDATE"
	}
	var issuer, subject *string
	var disabled *time.Time
	var generation int64
	err := tx.QueryRow(ctx, `SELECT oidc_issuer,oidc_subject,disabled_at,mfa_generation FROM app_user WHERE id=$1 AND tenant_id=$2`+lock, a.UserID, a.TenantID).Scan(&issuer, &subject, &disabled, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, 0, ErrOIDCUserDisabled
	}
	if err != nil {
		return nil, nil, 0, err
	}
	if disabled != nil {
		return nil, nil, 0, ErrOIDCUserDisabled
	}
	return issuer, subject, generation, nil
}

func (s *PgOIDCStore) IssueOIDCSession(ctx context.Context, a OIDCIdentityAuthority) (string, *Session, error) {
	if a.Issuer == "" || a.Subject == "" {
		return "", nil, ErrOIDCInvalid
	}
	token, err := newSessionToken()
	if err != nil {
		return "", nil, err
	}
	sess := &Session{TenantID: a.TenantID, UserID: a.UserID, TokenHash: HashToken(token), CredentialEpoch: a.EpochBaseline,
		SourceIP: sourceIPFrom(ctx), UserAgent: userAgentFrom(ctx), Remembered: a.Remember}
	// The same two lifetimes as the password path (Issue / IssueRemembered); Validate picks the idle limit from
	// the persisted remembered flag.
	ttl := DefaultSessionTTL
	if a.Remember {
		ttl = RememberedSessionTTL
	}
	err = withTenant(ctx, s.Pool, a.TenantID, func(tx pgx.Tx) error {
		if err := oidcLockConnection(ctx, tx, a.TenantID, a.ConnectionVersion); err != nil {
			return err
		}
		issuer, subject, _, err := oidcLockUser(ctx, tx, a, false)
		if err != nil {
			return err
		}
		if issuer == nil || subject == nil || *issuer != a.Issuer || *subject != a.Subject {
			return ErrOIDCNotLinked
		}
		if err := oidcCheckEpoch(ctx, tx, a.UserID, a.EpochBaseline); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO user_session
		 (tenant_id,user_id,token_hash,created_at,expires_at,last_seen,credential_epoch,login_method,oidc_connection_version,source_ip,user_agent,remembered)
		 SELECT $1,$2,$3,t,t+($4::double precision * interval '1 second'),t,$5,'oidc',$6,NULLIF($7,'')::inet,NULLIF($8,''),$9
		 FROM (SELECT clock_timestamp() AS t) stamp RETURNING id::text,created_at,expires_at,last_seen`,
			a.TenantID, a.UserID, sess.TokenHash, ttl.Seconds(), oidcEpoch(a.EpochBaseline), a.ConnectionVersion, validIPText(sess.SourceIP), sess.UserAgent, a.Remember).
			Scan(&sess.ID, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeen)
	})
	if err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

// Check freshness only AFTER acquiring the originating-session lock. now() would retain the
// transaction's start time across a long lock wait and could accept an expired step-up.
func oidcCheckOrigin(ctx context.Context, tx pgx.Tx, a OIDCIdentityAuthority, sessionID string, generation int64, freshness time.Duration) error {
	var user string
	var revoked, verified *time.Time
	var expires time.Time
	var recorded *int64
	var epoch *time.Time
	err := tx.QueryRow(ctx, `SELECT user_id::text,revoked_at,expires_at,mfa_verified_at,mfa_generation,credential_epoch
	 FROM user_session WHERE id=$1 FOR SHARE`, sessionID).Scan(&user, &revoked, &expires, &verified, &recorded, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOIDCSessionInvalid
	}
	if err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if user != a.UserID || revoked != nil || !expires.After(now) {
		return ErrOIDCSessionInvalid
	}
	var sessionEpoch time.Time
	if epoch != nil {
		sessionEpoch = *epoch
	}
	if !sessionEpoch.Equal(a.EpochBaseline) {
		return ErrOIDCSessionInvalid
	}
	if verified == nil || verified.After(now) || verified.Before(now.Add(-freshness)) || recorded == nil || generation <= 0 || *recorded != generation {
		return ErrOIDCStepUpStale
	}
	return nil
}

func (s *PgOIDCStore) LinkIdentity(ctx context.Context, a OIDCIdentityAuthority, originatingSessionID string) error {
	if a.Issuer == "" || a.Subject == "" {
		return ErrOIDCInvalid
	}
	err := withTenant(ctx, s.Pool, a.TenantID, func(tx pgx.Tx) error {
		if err := oidcLockConnection(ctx, tx, a.TenantID, a.ConnectionVersion); err != nil {
			return err
		}
		issuer, subject, generation, err := oidcLockUser(ctx, tx, a, true)
		if err != nil {
			return err
		}
		if err := oidcCheckEpoch(ctx, tx, a.UserID, a.EpochBaseline); err != nil {
			return err
		}
		if err := oidcCheckOrigin(ctx, tx, a, originatingSessionID, generation, 10*time.Minute); err != nil {
			return err
		}
		if issuer != nil || subject != nil {
			if issuer != nil && subject != nil && *issuer == a.Issuer && *subject == a.Subject {
				return nil
			}
			return ErrOIDCLinkConflict
		}
		ct, err := tx.Exec(ctx, `UPDATE app_user SET oidc_issuer=$2,oidc_subject=$3 WHERE id=$1 AND oidc_issuer IS NULL AND oidc_subject IS NULL`, a.UserID, a.Issuer, a.Subject)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return ErrOIDCLinkConflict
		}
		// The UPDATE can wait on the unique index while another transaction holds an uncommitted claim
		// to the same identity (Codex impl review B v3); if that one rolls back after our step-up or
		// session expired, the link would commit on stale authority. Re-check last, against DB time.
		return oidcCheckOrigin(ctx, tx, a, originatingSessionID, generation, 10*time.Minute)
	})
	if isUniqueViolation(err) {
		return ErrOIDCLinkConflict
	}
	return err
}

func (s *PgOIDCStore) UnlinkIdentity(ctx context.Context, tenantID, userID string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Disabled connections must still permit recovery by unlinking.
		var one int
		err := tx.QueryRow(ctx, `SELECT 1 FROM tenant_oidc WHERE tenant_id=$1 FOR SHARE`, tenantID).Scan(&one)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE`, userID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrOIDCUserDisabled
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE app_user SET oidc_issuer=NULL,oidc_subject=NULL WHERE id=$1`, userID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE user_session SET revoked_at=clock_timestamp() WHERE user_id=$1 AND login_method='oidc' AND revoked_at IS NULL`, userID)
		return err
	})
}

// Test completion validates the same originating authority as linking, but writes no identity
// and issues no session. All validation and the version-stamped result commit together.
func (s *PgOIDCStore) RecordTest(ctx context.Context, a OIDCIdentityAuthority, originatingSessionID string) error {
	return withTenant(ctx, s.Pool, a.TenantID, func(tx pgx.Tx) error {
		if err := oidcLockConnectionMode(ctx, tx, a.TenantID, a.ConnectionVersion, "FOR NO KEY UPDATE"); err != nil {
			return err
		}
		_, _, generation, err := oidcLockUser(ctx, tx, a, false)
		if err != nil {
			return err
		}
		if err := oidcCheckEpoch(ctx, tx, a.UserID, a.EpochBaseline); err != nil {
			return err
		}
		if err := oidcCheckOrigin(ctx, tx, a, originatingSessionID, generation, 10*time.Minute); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE tenant_oidc SET last_test_version=$2,last_test_at=clock_timestamp() WHERE tenant_id=$1 AND version=$2`, a.TenantID, a.ConnectionVersion)
		return err
	})
}

// Sweep is tenant-scoped so the maintenance caller needs no RLS bypass. Sweep each tenant.
func (s *PgOIDCStore) SweepExpired(ctx context.Context, tenantID string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM oidc_pending_mfa WHERE created_at <= clock_timestamp()-interval '5 minutes'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM oidc_login_attempt WHERE created_at <= clock_timestamp()-interval '10 minutes'
		 AND NOT EXISTS (SELECT 1 FROM oidc_pending_mfa p WHERE p.attempt_id=oidc_login_attempt.id)`)
		return err
	})
}
