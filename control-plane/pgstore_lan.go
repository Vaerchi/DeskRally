package controlplane

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ LanStore = (*PgMachineStore)(nil)

const selectSignalingIncarnation = `SELECT id::text, revision FROM signaling_incarnation WHERE singleton`

// The locking forms are named constants: the credential-fence guard requires constant SQL identifiers.
const (
	selectSignalingIncarnationForUpdate = selectSignalingIncarnation + " FOR UPDATE"
	selectSignalingIncarnationForShare  = selectSignalingIncarnation + " FOR SHARE"
)

func (s *PgMachineStore) GetSignalingIncarnation(ctx context.Context) (id *string, revision int64, err error) {
	err = s.Pool.QueryRow(ctx, selectSignalingIncarnation).Scan(&id, &revision)
	return
}

func (s *PgMachineStore) ActivateSignalingIncarnation(ctx context.Context, incarnation string, expectedRevision int64) (bool, int64, error) {
	id, valid := parsePgUUID(incarnation)
	if !valid || expectedRevision < 0 {
		return false, 0, errInvalidIncarnation
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, 0, err
	}
	defer tx.Rollback(ctx)
	var current *string
	var revision int64
	if err := tx.QueryRow(ctx, selectSignalingIncarnationForUpdate).Scan(&current, &revision); err != nil {
		return false, 0, err
	}
	ok := current != nil && *current == id
	if !ok && revision == expectedRevision {
		err = tx.QueryRow(ctx, `
			UPDATE signaling_incarnation SET id = $1, revision = revision + 1
			WHERE singleton RETURNING revision`, id).Scan(&revision)
		if err != nil {
			return false, 0, err
		}
		ok = true
	}
	if err := tx.Commit(ctx); err != nil {
		return false, 0, err
	}
	return ok, revision, nil
}

// Lock order is incarnation, then machine. The identity function provides the
// tenant to pin. Eligibility is rechecked on the locked machine before use.
func (s *PgMachineStore) withLanDevice(ctx context.Context, deviceID, pubKey, incarnation string,
	fn func(pgx.Tx, string, string, lanWatermark) (LanOutcome, error)) (LanOutcome, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var current *string
	var revision int64
	if err := tx.QueryRow(ctx, selectSignalingIncarnationForShare).Scan(&current, &revision); err != nil {
		return "", err
	}
	if current == nil || *current != incarnation {
		return LanStaleIncarnation, nil
	}

	var tenantID string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM cp_machine_identity_by_device_id($1)`, deviceID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return LanNotEligible, nil
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID); err != nil {
		return "", err
	}

	var machineID, status string
	var ephemeral bool
	var storedKey []byte
	err = tx.QueryRow(ctx, `
		SELECT id::text, status, ephemeral, pubkey FROM machine WHERE device_id = $1 FOR UPDATE`,
		deviceID).Scan(&machineID, &status, &ephemeral, &storedKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return LanNotEligible, nil
	}
	if err != nil {
		return "", err
	}
	presentedKey, decodeErr := hex.DecodeString(pubKey)
	if status != MachineStatusActive || ephemeral || decodeErr != nil || !matchesLanDeviceKey(storedKey, presentedKey) {
		return LanNotEligible, nil
	}

	var state lanWatermark
	err = tx.QueryRow(ctx, `
		SELECT epoch, COALESCE(epoch_incarnation::text, ''), COALESCE(epoch_generation, 0), last_seq, last_digest
		FROM machine_lan_state WHERE machine_id = $1`, machineID).
		Scan(&state.epoch, &state.incarnation, &state.generation, &state.seq, &state.digest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	outcome, err := fn(tx, tenantID, machineID, state)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return outcome, nil
}

func (s *PgMachineStore) AllocateLanEpoch(ctx context.Context, deviceID, pubKey, incarnation string, generation int64) (int64, LanOutcome, error) {
	id, _ := parsePgUUID(incarnation)
	if !validLanConnection(deviceID, id, generation) {
		return 0, LanBadRequest, nil
	}
	var epoch int64
	outcome, err := s.withLanDevice(ctx, deviceID, pubKey, id, func(tx pgx.Tx, tenantID, machineID string, state lanWatermark) (LanOutcome, error) {
		changed, outcome := state.allocate(id, generation)
		if outcome != "" {
			return outcome, nil
		}
		epoch = state.epoch
		if !changed {
			return "", nil
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO machine_lan_state (tenant_id, machine_id, epoch, epoch_incarnation, epoch_generation)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (machine_id) DO UPDATE
			SET epoch = EXCLUDED.epoch, epoch_incarnation = EXCLUDED.epoch_incarnation,
			    epoch_generation = EXCLUDED.epoch_generation, last_seq = 0, last_digest = NULL`,
			tenantID, machineID, epoch, id, generation)
		return "", err
	})
	if err != nil {
		return 0, "", err
	}
	return epoch, outcome, nil
}

func (s *PgMachineStore) IngestLanReport(ctx context.Context, deviceID, pubKey, incarnation string, generation, epoch, seq int64, digest []byte, entries []LanEntry) (LanOutcome, error) {
	id, _ := parsePgUUID(incarnation)
	if !validLanConnection(deviceID, id, generation) || !validLanReport(epoch, seq, digest, entries) {
		return LanBadRequest, nil
	}
	receivedAt := time.Now().UTC()
	return s.withLanDevice(ctx, deviceID, pubKey, id, func(tx pgx.Tx, tenantID, machineID string, state lanWatermark) (LanOutcome, error) {
		outcome := state.report(id, generation, epoch, seq, digest)
		if outcome != LanApplied {
			return outcome, nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM machine_lan WHERE machine_id = $1`, machineID); err != nil {
			return "", err
		}
		for _, entry := range entries {
			if _, err := tx.Exec(ctx, `
				INSERT INTO machine_lan (tenant_id, machine_id, mac, ipv4_network, gateway_mac, received_at)
				VALUES ($1, $2, $3::text::macaddr, $4::text::cidr, $5::text::macaddr, $6)`,
				tenantID, machineID, entry.MAC, entry.IPv4Network, entry.GatewayMAC, receivedAt); err != nil {
				return "", err
			}
		}
		_, err := tx.Exec(ctx, `
			UPDATE machine_lan_state SET last_seq = $2, last_digest = $3, last_received_at = $4
			WHERE machine_id = $1`, machineID, seq, digest, receivedAt)
		return outcome, err
	})
}

// DeleteLanFactsTx clears enrollment-bound facts and ordering state. Callers
// must hold the machine row lock. A future same-row key rotation must call it too.
func DeleteLanFactsTx(ctx context.Context, tx pgx.Tx, machineID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM machine_lan WHERE machine_id = $1`, machineID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM machine_lan_state WHERE machine_id = $1`, machineID)
	return err
}

func (s *PgMachineStore) PurgeStaleLanFacts(ctx context.Context, olderThan time.Duration) (int64, error) {
	var deleted int64
	err := s.Pool.QueryRow(ctx, `SELECT cp_purge_stale_lan_facts($1)`, time.Now().Add(-olderThan)).Scan(&deleted)
	return deleted, err
}
