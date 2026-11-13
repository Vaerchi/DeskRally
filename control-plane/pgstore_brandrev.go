package controlplane

// Postgres BrandingRevisionStore over migration 0072 (and the 0071 shape).
//
//   - The Owner's edit runs TENANT-SCOPED as the application role (RLS applies): it takes the tenant's
//     pointer-row lock first (the lock every approve, withdraw and assignment change also takes), then
//     inserts the revision and moves only the DRAFT pointer (the only column rmt_app may update).
//   - The operator paths call the SECURITY DEFINER functions of 0072 inside one transaction on the request's
//     connection pinned to the platform tenant, followed by the platform-chain and target-chain audit events
//     (the orchestration of pgstore_hostname.go). Any failure rolls back all of it.
//   - The PUBLIC read runs under the bounded lookup lifecycle of pgbounded.go (docs/66 2f): explicit acquire,
//     a socket deadline, a per-statement timeout, a connection destroyed on any failure.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrBrandingBusy: a lock wait on the tenant's pointer row timed out; retry.
var ErrBrandingBusy = errors.New("branding is busy; retry")

// PublicLookupStatementTimeout is the per-statement timeout of the public read (docs/66 2d.1).
// The SQL carries the same value as a CONSTANT statement (the credential-fence guard refuses built SQL);
// TestPublicLookupStatementTimeoutConstantsAgree pins the two together.
const PublicLookupStatementTimeout = 100 * time.Millisecond

// PgBrandingRevisionStore implements BrandingRevisionStore.
type PgBrandingRevisionStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
	// LookupPool, when set, serves PublicLookup (the anonymous read) instead of Pool, so anonymous traffic cannot hold
	// the connections the console needs (docs/66 release gate R1). nil uses Pool.
	LookupPool *pgxpool.Pool
}

// NewPgBrandingRevisionStore wires the store; the audit store must share the pool.
func NewPgBrandingRevisionStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgBrandingRevisionStore {
	return &PgBrandingRevisionStore{Pool: pool, Audit: audit}
}

var _ BrandingRevisionStore = (*PgBrandingRevisionStore)(nil)

func brandingErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "HS002":
			return ErrBrandingStale
		case "HS003":
			return ErrBrandingNotPublished
		case "55P03":
			return ErrBrandingBusy
		}
	}
	return hostnameErr(err)
}

const revisionCols = `id::text, seq, product_name, accent_color, support_text, support_contact_kind, support_contact_value,
	logo_sha256, (logo_png IS NOT NULL), normalized_hash, created_by, created_at`

func scanRevision(row pgx.Row, tenantID string) (*BrandingRevision, error) {
	r := &BrandingRevision{TenantID: tenantID}
	if err := row.Scan(&r.ID, &r.Seq, &r.ProductName, &r.AccentColor, &r.SupportText, &r.Contact.Kind, &r.Contact.Value,
		&r.LogoSHA256, &r.HasLogo, &r.Hash, &r.CreatedBy, &r.CreatedAt); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *PgBrandingRevisionStore) CreateRevision(ctx context.Context, tenantID, createdBy string, in BrandingRevisionInput) (*BrandingRevision, bool, error) {
	if !isUUID(tenantID) {
		return nil, false, ErrPlatformNoTenant
	}
	var out *BrandingRevision
	created := false
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_branding_pointer (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
			return err
		}
		// The per-tenant branding lock: the pointer row (docs/66 2b.2).
		var draftID *string
		if err := tx.QueryRow(ctx, `SELECT draft_revision_id::text FROM tenant_branding_pointer WHERE tenant_id = $1 FOR UPDATE`,
			tenantID).Scan(&draftID); err != nil {
			return err
		}
		var draftHash, draftLogoSHA string
		var draftLogo []byte
		if draftID != nil {
			if err := tx.QueryRow(ctx, `SELECT normalized_hash, logo_sha256, logo_png FROM tenant_branding_revision WHERE id = $1`,
				*draftID).Scan(&draftHash, &draftLogoSHA, &draftLogo); err != nil {
				return err
			}
		}
		logo := in.LogoPNG
		if in.KeepLogo {
			if draftID == nil || draftLogoSHA == "" {
				return ErrBrandingNoLogoToKeep
			}
			logo = draftLogo
		}
		sha := logoSHA(logo)
		hash := BrandingRevisionHash(in.ProductName, in.AccentColor, in.SupportText, in.Contact.Kind, in.Contact.Value, sha)
		if draftID != nil && draftHash == hash {
			r, err := scanRevision(tx.QueryRow(ctx, `SELECT `+revisionCols+` FROM tenant_branding_revision WHERE id = $1`, *draftID), tenantID)
			out = r
			return err
		}
		var recent, total int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_at > now() - interval '1 hour'), count(*)
			FROM tenant_branding_revision WHERE tenant_id = $1`, tenantID).Scan(&recent, &total); err != nil {
			return err
		}
		if recent >= BrandingRevisionsPerHour || total >= BrandingRevisionsMax {
			return ErrBrandingRateLimited
		}
		var logoArg any
		if len(logo) > 0 {
			logoArg = logo
		}
		r, err := scanRevision(tx.QueryRow(ctx, `
			INSERT INTO tenant_branding_revision (tenant_id, seq, product_name, accent_color, support_text,
				support_contact_kind, support_contact_value, logo_sha256, logo_png, normalized_hash, created_by)
			VALUES ($1, (SELECT COALESCE(max(seq), 0) + 1 FROM tenant_branding_revision WHERE tenant_id = $1),
				$2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING `+revisionCols, tenantID, in.ProductName, in.AccentColor, in.SupportText, in.Contact.Kind,
			in.Contact.Value, sha, logoArg, hash, createdBy), tenantID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_branding_pointer SET draft_revision_id = $2 WHERE tenant_id = $1`, tenantID, r.ID); err != nil {
			return err
		}
		out, created = r, true
		return nil
	})
	if err != nil {
		return nil, false, brandingErr(err)
	}
	return out, created, nil
}

func (s *PgBrandingRevisionStore) OwnerState(ctx context.Context, tenantID string) (*BrandingOwnerState, error) {
	if !isUUID(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	st := &BrandingOwnerState{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var draft, pub, pubAssign, wdRev *string
		var pubAt, wdAt *time.Time
		err := tx.QueryRow(ctx, `SELECT draft_revision_id::text, published_revision_id::text, published_assignment_id::text,
				published_at, withdrawn_at, withdrawn_revision_id::text
			FROM tenant_branding_pointer WHERE tenant_id = $1`, tenantID).Scan(&draft, &pub, &pubAssign, &pubAt, &wdAt, &wdRev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var a BrandingAssignmentRef
		switch err := tx.QueryRow(ctx, `SELECT id::text, host, state FROM tenant_hostname_assignment
			WHERE tenant_id = $1 AND state IN ('pending', 'active')`, tenantID).Scan(&a.ID, &a.Host, &a.State); {
		case err == nil:
			st.Assignment = &a
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		load := func(id *string) (*BrandingRevision, error) {
			if id == nil {
				return nil, nil
			}
			return scanRevision(tx.QueryRow(ctx, `SELECT `+revisionCols+` FROM tenant_branding_revision WHERE id = $1`, *id), tenantID)
		}
		if st.Draft, err = load(draft); err != nil {
			return err
		}
		if st.Published, err = load(pub); err != nil {
			return err
		}
		st.Live = pub != nil && st.Assignment != nil && st.Assignment.State == "active" && pubAssign != nil && st.Assignment.ID == *pubAssign
		st.DraftIsPublished = draft != nil && pub != nil && *draft == *pub
		switch {
		case pub != nil:
			st.PublishedAt = pubAt
		case wdAt != nil:
			st.Withdrawn = &BrandingWithdrawn{At: *wdAt}
			if wdRev != nil {
				st.Withdrawn.RevisionID = *wdRev
			}
		}
		return nil
	})
	if err != nil {
		return nil, brandingErr(err)
	}
	return st, nil
}

func (s *PgBrandingRevisionStore) Review(ctx context.Context, c PlatformCaller, tenantID string) (*BrandingReview, error) {
	if c.SessionID == "" {
		return nil, ErrPlatformDenied
	}
	if !isUUID(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	rv := &BrandingReview{TenantID: tenantID}
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		var revID, pubRev, pubHash, pubAssign, asgID, asgHost, asgState *string
		var d struct {
			seq                                                         *int64
			name, accent, text, ckind, cvalue, logoSHA, hash, createdBy *string
			createdAt                                                   *time.Time
			logo                                                        []byte
		}
		err := tx.QueryRow(ctx, `SELECT revision_id::text, seq, product_name, accent_color, support_text, support_contact_kind,
				support_contact_value, logo_sha256, logo_png, normalized_hash, created_by, created_at,
				published_revision_id::text, published_revision_hash, published_assignment_id::text,
				assignment_id::text, assignment_host, assignment_state, review_generation
			FROM cp_platform_branding_review($1, $2, $3)`, c.UserID, c.SessionID, tenantID).
			Scan(&revID, &d.seq, &d.name, &d.accent, &d.text, &d.ckind, &d.cvalue, &d.logoSHA, &d.logo, &d.hash, &d.createdBy, &d.createdAt,
				&pubRev, &pubHash, &pubAssign, &asgID, &asgHost, &asgState, &rv.Generation)
		if err != nil {
			return err
		}
		str := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		if revID != nil {
			rv.Draft = &BrandingRevision{ID: *revID, TenantID: tenantID, Seq: *d.seq, ProductName: str(d.name), AccentColor: str(d.accent),
				SupportText: str(d.text), Contact: BrandContact{Kind: str(d.ckind), Value: str(d.cvalue)}, LogoSHA256: str(d.logoSHA),
				HasLogo: str(d.logoSHA) != "", LogoPNG: d.logo, Hash: str(d.hash), CreatedBy: str(d.createdBy)}
			if d.createdAt != nil {
				rv.Draft.CreatedAt = *d.createdAt
			}
		}
		rv.PublishedRevisionID, rv.PublishedHash, rv.PublishedAssignmentID = str(pubRev), str(pubHash), str(pubAssign)
		if asgID != nil {
			rv.Assignment = &BrandingAssignmentRef{ID: *asgID, Host: str(asgHost), State: str(asgState)}
		}
		return nil
	})
	if err != nil {
		return nil, brandingErr(err)
	}
	return rv, nil
}

func (s *PgBrandingRevisionStore) Peers(ctx context.Context, c PlatformCaller) ([]BrandPeer, error) {
	if c.SessionID == "" {
		return nil, ErrPlatformDenied
	}
	var out []BrandPeer
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, product_name FROM cp_platform_branding_peers($1, $2)`, c.UserID, c.SessionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p BrandPeer
			if err := rows.Scan(&p.TenantID, &p.ProductName); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, brandingErr(err)
	}
	return out, nil
}

// audited runs run() and then writes the platform-chain and the target tenant's chain events in the same
// transaction (the orchestration of pgstore_hostname.go).
func (s *PgBrandingRevisionStore) audited(ctx context.Context, c PlatformCaller, tenantID, action string, meta map[string]any,
	run func(tx pgx.Tx) (map[string]any, error)) error {
	if c.SessionID == "" || s.Audit == nil {
		return ErrPlatformDenied
	}
	if !isUUID(tenantID) {
		return ErrPlatformNoTenant
	}
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		facts, err := run(tx)
		if err != nil {
			return err
		}
		m := map[string]any{"tenant_id": tenantID}
		for k, v := range meta {
			m[k] = v
		}
		for k, v := range facts {
			m[k] = v
		}
		raw := operatorMeta(c, newUUID(), m)
		if err := s.Audit.appendTx(ctx, tx, c.TenantID, &MgmtAuditEvent{
			ActorUserID: c.UserID, Action: "platform.branding." + action, TargetKind: "tenant_branding", TargetID: tenantID, Metadata: raw,
		}); err != nil {
			return fmt.Errorf("platform audit: %w", err)
		}
		if err := s.Audit.appendTx(ctx, tx, tenantID, &MgmtAuditEvent{
			Action: "tenant.branding." + action, TargetKind: "tenant_branding", TargetID: tenantID, Metadata: raw,
		}); err != nil {
			return fmt.Errorf("tenant audit: %w", err)
		}
		return nil
	})
	return brandingErr(err)
}

func (s *PgBrandingRevisionStore) Approve(ctx context.Context, c PlatformCaller, tenantID string, a BrandingApproval, extra map[string]any) (*BrandingApprovalResult, error) {
	if !isUUID(a.RevisionID) || !isUUID(a.AssignmentID) {
		return nil, ErrBrandingStale
	}
	var res BrandingApprovalResult
	err := s.audited(ctx, c, tenantID, "approve", extra, func(tx pgx.Tx) (map[string]any, error) {
		if err := tx.QueryRow(ctx, `SELECT revision_id::text, normalized_hash, assignment_id::text, assignment_host, assignment_state, product_name
			FROM cp_platform_branding_approve($1, $2, $3, $4, $5, $6, $7, $8)`,
			c.UserID, c.SessionID, tenantID, a.RevisionID, a.Hash, a.AssignmentID, a.Generation, operatorLabel(c)).
			Scan(&res.RevisionID, &res.Hash, &res.AssignmentID, &res.Host, &res.AssignmentState, &res.ProductName); err != nil {
			return nil, err
		}
		return map[string]any{"revision_id": res.RevisionID, "normalized_hash": res.Hash, "assignment_id": res.AssignmentID,
			"host": res.Host, "assignment_state": res.AssignmentState}, nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *PgBrandingRevisionStore) Withdraw(ctx context.Context, c PlatformCaller, tenantID string, extra map[string]any) error {
	return s.audited(ctx, c, tenantID, "withdraw", extra, func(tx pgx.Tx) (map[string]any, error) {
		_, err := tx.Exec(ctx, `SELECT cp_platform_branding_withdraw($1, $2, $3)`, c.UserID, c.SessionID, tenantID)
		return nil, err
	})
}

// PublicLookup is the one public read, under the bounded lifecycle. No row is (nil, nil).
func (s *PgBrandingRevisionStore) PublicLookup(ctx context.Context, host string, wantLogo bool) (*PublishedBranding, error) {
	var out *PublishedBranding
	err := boundedLookup(ctx, lookupPoolOr(s.LookupPool, s.Pool), func(c *pgxpool.Conn) error {
		tx, err := c.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		// Per statement, in the read's transaction (docs/66 2d.1). An error here leaves the connection to be
		// destroyed by boundedLookup: no rollback is attempted on a possibly stalled socket.
		if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = 100"); err != nil {
			return err
		}
		var p PublishedBranding
		err = tx.QueryRow(ctx, `SELECT product_name, accent_color, support_text, support_contact_kind, support_contact_value,
				logo_sha256, logo_png FROM cp_public_branding_lookup($1, $2)`, host, wantLogo).
			Scan(&p.ProductName, &p.AccentColor, &p.SupportText, &p.Contact.Kind, &p.Contact.Value, &p.LogoSHA256, &p.LogoPNG)
		switch {
		case err == nil:
			out = &p
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return err
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return cerr
		}
		if out == nil {
			return pgx.ErrNoRows
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}
