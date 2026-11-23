package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgWakeStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

var _ WakeStore = (*PgWakeStore)(nil)

func (s *PgWakeStore) wakeFacts(ctx context.Context, tenant string, ids []string) (map[string][]wakeFact, error) {
	var facts map[string][]wakeFact
	err := withTenant(ctx, s.Pool, tenant, func(tx pgx.Tx) error {
		var err error
		facts, err = readWakeFacts(ctx, tx, tenant, ids)
		return err
	})
	return facts, err
}

func readWakeFacts(ctx context.Context, tx pgx.Tx, tenant string, ids []string) (map[string][]wakeFact, error) {
	rows, err := tx.Query(ctx, `
		SELECT machine_id::text, mac::text, ipv4_network::text, gateway_mac::text, received_at
		FROM machine_lan
		WHERE machine_id = ANY($1::text[]::uuid[]) AND tenant_id = $2 AND gateway_mac IS NOT NULL
		  AND received_at >= statement_timestamp() - interval '720 hours'
		ORDER BY machine_id, ipv4_network, gateway_mac, mac`, ids, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := make(map[string][]wakeFact)
	for rows.Next() {
		var id string
		var fact wakeFact
		if err := rows.Scan(&id, &fact.MAC, &fact.Network, &fact.Gateway, &fact.ReceivedAt); err != nil {
			return nil, err
		}
		// Skip legacy reports that predate the nonzero unicast validation.
		if !validLanMAC(fact.MAC) || !validLanMAC(fact.Gateway) {
			continue
		}
		facts[id] = append(facts[id], fact)
	}
	return facts, rows.Err()
}

type wakeMembership struct {
	membership       Membership
	expiresAt        *time.Time
	days, start, end *int16
	zone             *string
}

type wakeAuthority struct {
	members []wakeMembership
	token   *APIToken
}

// lockWakeAPIToken locks the calling token's row (revoke UPDATEs it). A named constant for the SQL guard.
const lockWakeAPIToken = `SELECT ` + apiTokenColumns + ` FROM api_token
	WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL FOR SHARE`

func lockWakeAuthority(ctx context.Context, tx pgx.Tx, p *Principal) (wakeAuthority, error) {
	if _, ok := parsePgUUID(p.UserID); !ok {
		return wakeAuthority{}, errWakeChanged
	}
	if p.APIToken {
		token, err := scanAPIToken(tx.QueryRow(ctx, lockWakeAPIToken, p.TenantID, p.UserID))
		return wakeAuthority{token: token}, wakeRequireRow(err)
	}

	rows, err := tx.Query(ctx, `
		SELECT r.key, m.scoped_group_ids::text[],
		       cp_group_subtree(m.tenant_id, m.scoped_group_ids)::text[],
		       m.expires_at, m.window_days, m.window_start, m.window_end, m.window_tz
		FROM membership m JOIN role r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND m.user_id = $2
		ORDER BY (r.key = 'owner' AND r.tenant_id IS NULL) DESC, m.id
		FOR SHARE OF m`, p.TenantID, p.UserID)
	if err != nil {
		return wakeAuthority{}, err
	}
	defer rows.Close()
	var authority wakeAuthority
	for rows.Next() {
		var member wakeMembership
		var role string
		var assigned, covered []string
		if err := rows.Scan(&role, &assigned, &covered, &member.expiresAt,
			&member.days, &member.start, &member.end, &member.zone); err != nil {
			return wakeAuthority{}, err
		}
		member.membership = NewMembership(Role(role), scopeFromStored(assigned, covered))
		authority.members = append(authority.members, member)
	}
	if err := rows.Err(); err != nil {
		return wakeAuthority{}, err
	}
	var enabled int
	err = tx.QueryRow(ctx, `SELECT 1 FROM app_user WHERE id = $1 AND tenant_id = $2 AND disabled_at IS NULL FOR SHARE`,
		p.UserID, p.TenantID).Scan(&enabled)
	return authority, wakeRequireRow(err)
}

func wakeRequireRow(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errWakeChanged
	}
	return err
}

func (a wakeAuthority) authorize(ctx context.Context, tx pgx.Tx, p *Principal, target, relay string) error {
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	var members []Membership
	if a.token != nil {
		if a.token.ExpiresAt != nil && !a.token.ExpiresAt.After(at) {
			return errWakeChanged
		}
		members = append(members, NewCapabilityMembership(a.token.Capabilities, AllGroups()))
	}
	for _, m := range a.members {
		if m.expiresAt != nil && !m.expiresAt.After(at) {
			continue
		}
		var open bool
		err := tx.QueryRow(ctx, `SELECT membership_window_open($1::smallint, $2::smallint,
			$3::smallint, $4::text, $5::timestamptz)`, m.days, m.start, m.end, m.zone, at).Scan(&open)
		if err != nil {
			return err
		}
		if open {
			members = append(members, m.membership)
		}
	}
	grant := NewGrant(p.UserID, p.TenantID, members...)
	if grant.RequireMachine(CapWakeMachine, target) != nil || grant.RequireMachine(CapWakeMachine, relay) != nil {
		return errWakeChanged
	}
	return nil
}

func lockWakeMachine(ctx context.Context, tx pgx.Tx, tenant string, expected Machine) ([]byte, error) {
	var current Machine
	var key []byte
	err := tx.QueryRow(ctx, `
		SELECT device_id, COALESCE(group_id::text, ''), status, ephemeral, pubkey
		FROM machine WHERE id = $1 AND tenant_id = $2 FOR SHARE`, expected.ID, tenant).
		Scan(&current.DeviceID, &current.GroupID, &current.Status, &current.Ephemeral, &key)
	if err != nil {
		return nil, wakeRequireRow(err)
	}
	if current.Status != MachineStatusActive || current.Ephemeral ||
		current.GroupID != expected.GroupID || current.DeviceID != expected.DeviceID {
		return nil, errWakeChanged
	}
	return key, nil
}

func sameWakeFacts(before, after []wakeFact) bool {
	return slices.EqualFunc(before, after, func(a, b wakeFact) bool {
		return a.MAC == b.MAC && a.Network == b.Network && a.Gateway == b.Gateway && a.ReceivedAt.Equal(b.ReceivedAt)
	})
}

func (s *PgWakeStore) issueWake(ctx context.Context, p *Principal, in wakeIssuance) (WakeClaims, error) {
	var claims WakeClaims
	target, relay, dispatch := in.Target.Machine, in.Relay.Machine, in.Dispatch
	err := withTenant(ctx, s.Pool, p.TenantID, func(tx pgx.Tx) error {
		suspended, err := lockTenantIssuance(ctx, tx, p.TenantID)
		if err != nil {
			return wakeRequireRow(err)
		}
		if suspended {
			return errWakeChanged
		}
		if err := lockGroupTreeTx(ctx, tx, p.TenantID, true); err != nil {
			if errors.Is(err, ErrGroupTreeChanged) {
				return errWakeChanged
			}
			return err
		}
		authority, err := lockWakeAuthority(ctx, tx, p)
		if err != nil {
			return err
		}
		// LAN ingest takes this same incarnation fence before the machine lock.
		var current *string
		var revision int64
		if err := tx.QueryRow(ctx, selectSignalingIncarnationForShare).Scan(&current, &revision); err != nil {
			return wakeRequireRow(err)
		}
		if current == nil || *current != dispatch.ConnRef.Incarnation {
			return errWakeChanged
		}
		if _, err := lockWakeMachine(ctx, tx, p.TenantID, target); err != nil {
			return err
		}
		key, err := lockWakeMachine(ctx, tx, p.TenantID, relay)
		if err != nil {
			return err
		}
		if err := authority.authorize(ctx, tx, p, target.GroupID, relay.GroupID); err != nil {
			return err
		}
		if len(key) != 32 || sha256.Sum256(key) != dispatch.DeviceKeySHA256 ||
			hex.EncodeToString(key) != relay.Pubkey {
			return errWakeChanged
		}
		var matches bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM machine_lan_state
				WHERE machine_id = $1 AND epoch = $2 AND epoch_incarnation = $3
				  AND epoch_generation = $4 AND tenant_id = $5 AND last_seq > 0)`,
			relay.ID, dispatch.Epoch, dispatch.ConnRef.Incarnation, dispatch.ConnRef.Generation, p.TenantID).
			Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return errWakeChanged
		}
		facts, err := readWakeFacts(ctx, tx, p.TenantID, []string{target.ID, relay.ID})
		if err != nil {
			return err
		}
		match, ok := wakeMatch(facts[target.ID], facts[relay.ID])
		if !ok || !sameWakeFacts(in.Target.Facts, facts[target.ID]) || !sameWakeFacts(in.Relay.Facts, facts[relay.ID]) {
			return errWakeChanged
		}
		claims = WakeClaims{
			TenantID: p.TenantID, RelayDeviceID: relay.DeviceID,
			RelayKeySHA256: hex.EncodeToString(dispatch.DeviceKeySHA256[:]),
			WakeChallenge:  hex.EncodeToString(dispatch.Challenge[:]), RequestID: in.RequestID,
			TargetMAC: match.MAC, IPv4Network: match.Network, GatewayMAC: match.Gateway,
		}
		if s.Audit == nil {
			return errWakeAuditUnavailable
		}
		event := MgmtAuditEvent{ActorUserID: p.UserID, Action: "machine.wake_requested", TargetKind: "machine", TargetID: target.ID}
		meta := map[string]string{"request_id": in.RequestID, "relay_machine_id": relay.ID}
		if authority.token != nil {
			event.ActorUserID = authority.token.CreatedBy
			meta["api_token_id"] = authority.token.ID
		}
		event.Metadata, err = json.Marshal(meta)
		if err != nil {
			return err
		}
		if err := s.Audit.appendTx(ctx, tx, p.TenantID, &event); err != nil {
			return err
		}
		return authority.authorize(ctx, tx, p, target.GroupID, relay.GroupID)
	})
	if err != nil {
		return WakeClaims{}, err
	}
	return claims, nil
}
