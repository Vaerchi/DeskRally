package controlplane

// The private reach and adoption reports (docs/68). Two audiences, two routes, nothing shared:
//
//	GET /platform/reach   the platform operator: cross-tenant download / update COUNTS from the Caddy log
//	                      (reach/, migration 0078). Same gate as /platform/tenants: an interactive session, a
//	                      configured operator, MFA verified within 12 h; an API token has no session id and can
//	                      never qualify. Every read is audited on the platform chain.
//	GET /adoption         a tenant Owner (CapManageTenant): THIS tenant's own device counts, under RLS.
//
// Neither returns a row-level record of a person or a machine: counts per day, week or version only. The word
// "download" is used only for what the log can support, and each figure carries its caveat in the response.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxReportDays bounds a report range (the database function enforces the same bound for the platform report).
const maxReportDays = 400

// ReachRow is one stored aggregate. Field names say what the figure is: nothing here is called a "download"
// except the human-artifact request count, and that one is labelled a request.
type ReachRow struct {
	Day       string `json:"day"`      // YYYY-MM-DD, UTC
	Artifact  string `json:"artifact"` // a fixed label, or the artifact's path under /download/
	Class     string `json:"class"`    // human | update | other | noise
	Requests  int64  `json:"requests"`
	Completed *int64 `json:"completed_approx"`   // null = the artifact size was unknown
	UniqueIsh *int64 `json:"unique_ish_clients"` // per day and per artifact; null = no figure
	Bytes     int64  `json:"bytes"`
	Partial   bool   `json:"unique_ish_partial"` // the unique-ish figure is a lower bound
}

// reachCaveats are shown with the report, in the words of docs/68 section 3.
var reachCaveats = []string{
	"Requests are not downloads: the human-artifact request count includes bots, retries and previews.",
	"Completed downloads are approximate: a GET answered 200 whose logged size is within 1 KiB of the artifact's current size. Resumed (206) downloads are not stitched together. Null means the artifact size was not known.",
	"Unique-ish clients are a salted per-day, per-artifact count of (address, browser) pairs. NAT merges people and mobile addresses split them. A restart or a missing salt makes the figure a lower bound (flagged). Nothing links one day to the next.",
	"Update traffic (manifests and payloads) is machine traffic and never counts as a download.",
	"Registrations are the real adoption signal. A download cannot be linked to a registration and we do not try.",
}

// DownloadReport is the operator read. It runs cp_platform_downloads (which calls cp_platform_check first) and
// appends the read to the platform's audit chain in the same transaction, so a denied caller leaves no event
// and an allowed one cannot read without leaving one.
func (s *PgPlatformStore) DownloadReport(ctx context.Context, c PlatformCaller, from, to time.Time, correlation string) ([]ReachRow, error) {
	if c.SessionID == "" || s.Audit == nil {
		return nil, ErrPlatformDenied
	}
	var out []ReachRow
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT day::text, artifact, class, requests, completed, uniq, bytes, partial
			FROM cp_platform_downloads($1, $2, $3::date, $4::date)`,
			c.UserID, c.SessionID, from.Format("2006-01-02"), to.Format("2006-01-02"))
		if err != nil {
			return err
		}
		for rows.Next() {
			var r ReachRow
			var requests int32
			var completed, uniq *int32
			if err := rows.Scan(&r.Day, &r.Artifact, &r.Class, &requests, &completed, &uniq, &r.Bytes, &r.Partial); err != nil {
				rows.Close()
				return err
			}
			r.Requests = int64(requests)
			if completed != nil {
				v := int64(*completed)
				r.Completed = &v
			}
			if uniq != nil {
				v := int64(*uniq)
				r.UniqueIsh = &v
			}
			out = append(out, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		meta := operatorMeta(c, correlation, map[string]any{"from": from.Format("2006-01-02"), "to": to.Format("2006-01-02"), "rows": len(out)})
		return s.Audit.appendTx(ctx, tx, c.TenantID, &MgmtAuditEvent{
			ActorUserID: c.UserID, Action: "platform.reach.read", TargetKind: "platform_report", Metadata: meta,
		})
	})
	if err != nil {
		return nil, platformErr(err)
	}
	return out, nil
}

// reportRange reads ?from= and ?to= (YYYY-MM-DD, UTC). Defaults: the last 30 days ending today. The range is
// bounded to maxReportDays so a request cannot ask for an unbounded scan.
func reportRange(r *http.Request, now time.Time) (from, to time.Time, msg string) {
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	to, from = today, today.AddDate(0, 0, -29)
	q := r.URL.Query()
	if v := q.Get("to"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return from, to, "to must be a date, YYYY-MM-DD"
		}
		to = t
		from = to.AddDate(0, 0, -29)
	}
	if v := q.Get("from"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return from, to, "from must be a date, YYYY-MM-DD"
		}
		from = t
	}
	if to.Before(from) {
		return from, to, "from must not be after to"
	}
	if int(to.Sub(from).Hours()/24)+1 > maxReportDays { // both ends inclusive
		return from, to, "the range is at most 400 days"
	}
	return from, to, ""
}

// GET /platform/reach
func (s *Server) handlePlatformReach(w http.ResponseWriter, r *http.Request) {
	c, ok := s.platformCaller(r)
	if !ok || s.Platform == nil {
		writeError(w, http.StatusForbidden, "platform operator access denied")
		return
	}
	from, to, msg := reportRange(r, time.Now().UTC())
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	rows, err := s.Platform.DownloadReport(r.Context(), c, from, to, newUUID())
	if err != nil {
		writePlatformErr(w, err)
		return
	}
	if rows == nil {
		rows = []ReachRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from.Format("2006-01-02"), "to": to.Format("2006-01-02"), "rows": rows, "caveats": reachCaveats,
	})
}

// ---- tenant adoption ------------------------------------------------------------------------------------

// AdoptionReport is one tenant's own adoption counts. Ephemeral (attended-session guest) machines are not
// devices here: they are the guest side of a support session and are counted in the funnel instead.
type AdoptionReport struct {
	From              string         `json:"from"`
	To                string         `json:"to"`
	NewDevicesPerWeek []WeekCount    `json:"new_devices_per_week"` // by machine.enrolled_at, weeks starting Monday (UTC)
	ActiveDevices30d  int64          `json:"active_devices_30d"`   // last_seen within 30 days of the request, whatever the range
	Funnel            AttendedFunnel `json:"attended_funnel"`      // attended sessions CREATED within the range
	AgentVersions     []VersionCount `json:"agent_versions"`       // enrolled, not retired; "unknown" = never reported
}

type WeekCount struct {
	Week  string `json:"week"`
	Count int64  `json:"count"`
}

type VersionCount struct {
	Version string `json:"version"`
	Count   int64  `json:"count"`
}

// AttendedFunnel: issued = a code was created; redeemed = a guest entered it; consented = the guest agreed;
// active = consented and the session reached active (or has since ended).
type AttendedFunnel struct {
	Issued    int64 `json:"issued"`
	Redeemed  int64 `json:"redeemed"`
	Consented int64 `json:"consented"`
	Active    int64 `json:"active"`
}

// AdoptionStore reads the caller's own tenant. The queries run under RLS (withTenant pins the tenant) and also
// filter on tenant_id, so a pool that bypassed RLS would still return one tenant.
type AdoptionStore interface {
	Report(ctx context.Context, tenantID string, from, to time.Time) (*AdoptionReport, error)
}

// PgAdoptionStore implements AdoptionStore over the ordinary tenant tables.
type PgAdoptionStore struct{ Pool *pgxpool.Pool }

func NewPgAdoptionStore(pool *pgxpool.Pool) *PgAdoptionStore { return &PgAdoptionStore{Pool: pool} }

func (s *PgAdoptionStore) Report(ctx context.Context, tenantID string, from, to time.Time) (*AdoptionReport, error) {
	rep := &AdoptionReport{From: from.Format("2006-01-02"), To: to.Format("2006-01-02"),
		NewDevicesPerWeek: []WeekCount{}, AgentVersions: []VersionCount{}}
	f, t := rep.From, rep.To
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT (date_trunc('week', enrolled_at AT TIME ZONE 'UTC'))::date::text, count(*)
			  FROM machine
			 WHERE tenant_id = $1 AND NOT ephemeral
			   AND enrolled_at >= ($2::date::timestamp AT TIME ZONE 'UTC') AND enrolled_at < (($3::date + 1)::timestamp AT TIME ZONE 'UTC')
			 GROUP BY 1 ORDER BY 1`, tenantID, f, t)
		if err != nil {
			return err
		}
		for rows.Next() {
			var w WeekCount
			if err := rows.Scan(&w.Week, &w.Count); err != nil {
				rows.Close()
				return err
			}
			rep.NewDevicesPerWeek = append(rep.NewDevicesPerWeek, w)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM machine
			 WHERE tenant_id = $1 AND NOT ephemeral AND status <> 'retired' AND last_seen >= now() - interval '30 days'`,
			tenantID).Scan(&rep.ActiveDevices30d); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT count(*), count(redeemed_at), count(consented_at),
			       count(*) FILTER (WHERE consented_at IS NOT NULL AND state IN ('active', 'ended'))
			  FROM attended_session
			 WHERE tenant_id = $1 AND created_at >= ($2::date::timestamp AT TIME ZONE 'UTC') AND created_at < (($3::date + 1)::timestamp AT TIME ZONE 'UTC')`,
			tenantID, f, t).Scan(&rep.Funnel.Issued, &rep.Funnel.Redeemed, &rep.Funnel.Consented, &rep.Funnel.Active); err != nil {
			return err
		}
		vr, err := tx.Query(ctx, `
			SELECT CASE WHEN agent_version = '' THEN 'unknown' ELSE split_part(agent_version, '+', 1) END AS v, count(*)
			  FROM machine
			 WHERE tenant_id = $1 AND NOT ephemeral AND status <> 'retired'
			 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 50`, tenantID)
		if err != nil {
			return err
		}
		defer vr.Close()
		for vr.Next() {
			var v VersionCount
			if err := vr.Scan(&v.Version, &v.Count); err != nil {
				return err
			}
			rep.AgentVersions = append(rep.AgentVersions, v)
		}
		return vr.Err()
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// GET /adoption — the tenant Owner's own adoption counts (CapManageTenant). An API token can never hold that
// capability, so it cannot reach this; the store is scoped to the caller's own tenant by RLS and by filter.
func (s *Server) handleAdoption(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil || p.Grant == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Adoption == nil {
		writeError(w, http.StatusInternalServerError, "adoption store not configured")
		return
	}
	from, to, msg := reportRange(r, time.Now().UTC())
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	rep, err := s.Adoption.Report(r.Context(), p.TenantID, from, to)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		writeError(w, http.StatusInternalServerError, "could not build the adoption report")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
