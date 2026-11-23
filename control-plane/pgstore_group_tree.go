package controlplane

// The Postgres half of nested machine groups (docs/62, migration 0065): the tenant tree lock, the
// tree-version guard, the grant loader that resolves coverage through cp_group_subtree, and the hierarchy
// mutations of PgMachineGroupStore that authorize inside their own tree-locked transaction (R2).

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// groupTreeLockWait bounds how long a hierarchy mutation or a tree-conditional write waits for the tenant
// tree lock. A timeout is reported as ErrGroupTreeChanged (409, retry) rather than pinning a pool
// connection. A var so a test can shorten it.
var groupTreeLockWait = 3 * time.Second

// pgErrCode returns the SQLSTATE of a pg error, or "".
func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// lockGroupTreeTx takes the per-tenant tree lock: EXCLUSIVE for hierarchy mutations, SHARED for the writes
// that merely depend on the tree staying put (assignment edits, machine moves). It is the same key the
// structure trigger takes, so a mutation and a conditional write serialize whichever side arrives first.
func lockGroupTreeTx(ctx context.Context, tx pgx.Tx, tenantID string, shared bool) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		strconv.FormatInt(groupTreeLockWait.Milliseconds(), 10)); err != nil {
		return err
	}
	var err error
	if shared {
		_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(cp_group_tree_lock_key($1::uuid))`, tenantID)
	} else {
		_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(cp_group_tree_lock_key($1::uuid))`, tenantID)
	}
	if err != nil {
		if pgErrCode(err) == "55P03" { // lock_not_available: a long mutation holds the tree
			return ErrGroupTreeChanged
		}
		return err
	}
	return nil
}

// groupTreeVersionTx reads the tenant's group_tree_version (0 when it has no row yet).
func groupTreeVersionTx(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx,
		`SELECT COALESCE((SELECT version FROM group_tree_version WHERE tenant_id = $1::uuid), 0)`, tenantID).Scan(&v)
	return v, err
}

// checkGroupTreeVersionTx is the conditional-write guard (docs/62 R2): take the tree lock SHARED, then
// require the committed version to equal the one the caller's grant was read at. Holding the shared lock to
// the end of the transaction keeps a hierarchy mutation (exclusive) from interleaving with the write that
// follows. A mismatch is ErrGroupTreeChanged.
func checkGroupTreeVersionTx(ctx context.Context, tx pgx.Tx, tenantID string, expect int64) error {
	if err := lockGroupTreeTx(ctx, tx, tenantID, true); err != nil {
		return err
	}
	v, err := groupTreeVersionTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if v != expect {
		return ErrGroupTreeChanged
	}
	return nil
}

// readGroupTreeTx reads the version FIRST and the structure second (see MachineGroupStore.GroupTree).
func readGroupTreeTx(ctx context.Context, tx pgx.Tx, tenantID string) (GroupTree, int64, error) {
	v, err := groupTreeVersionTx(ctx, tx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(ctx, `SELECT id::text, COALESCE(parent_id::text, '') FROM machine_group`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	tree := GroupTree{}
	for rows.Next() {
		var id, parent string
		if err := rows.Scan(&id, &parent); err != nil {
			return nil, 0, err
		}
		tree[id] = parent
	}
	return tree, v, rows.Err()
}

// scopeFromStored builds a membership scope from the stored array and its expansion. An empty STORED array
// is tenant-wide; a non-empty one is group-limited even when the expansion is empty (every root dangles),
// which covers nothing and never widens (docs/62 R1d).
func scopeFromStored(assigned, covered []string) GroupScope {
	if len(assigned) == 0 {
		return AllGroups()
	}
	set := make(map[string]struct{}, len(covered))
	for _, id := range covered {
		set[id] = struct{}{}
	}
	return Groups(assigned...).withCovered(set)
}

// loadGrantTx resolves a user's grant inside an already tenant-pinned transaction. stored=false is the
// EFFECTIVE grant (expired and out-of-window memberships dropped, on the statement clock); stored=true is
// every stored membership with its expiry and window, for the admin paths. Both resolve each membership's
// scope through cp_group_subtree, so Covers sees descendants (docs/62 D3), and both carry the tree version,
// read BEFORE the memberships so it can only be older than the coverage, never newer.
func loadGrantTx(ctx context.Context, tx pgx.Tx, tenantID, userID string, stored bool) (*Grant, error) {
	version, err := groupTreeVersionTx(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	var members []Membership
	if stored {
		rows, err := tx.Query(ctx, `
			SELECT r.key, m.scoped_group_ids::text[],
			       cp_group_subtree(m.tenant_id, m.scoped_group_ids)::text[],
			       m.expires_at, m.window_days, m.window_start, m.window_end, m.window_tz
			FROM membership m
			JOIN role r ON r.id = m.role_id
			WHERE m.user_id = $1
		`, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var roleKey string
			var assigned, covered []string
			var expiresAt *time.Time
			var days, ws, we *int16
			var tz *string
			if err := rows.Scan(&roleKey, &assigned, &covered, &expiresAt, &days, &ws, &we, &tz); err != nil {
				return nil, err
			}
			members = append(members, NewMembership(Role(roleKey), scopeFromStored(assigned, covered)).
				WithExpiry(expiresAt).WithWindow(windowFromRow(days, ws, we, tz)))
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	} else {
		// docs/56: an expired membership grants nothing. statement_timestamp(), not now(): the
		// transaction-start instant is the wrong clock for "has this expired yet". docs/57: nor does one
		// outside its access window (membership_window_open is true for no window, false on a bad zone).
		rows, err := tx.Query(ctx, `
			SELECT r.key, m.scoped_group_ids::text[],
			       cp_group_subtree(m.tenant_id, m.scoped_group_ids)::text[]
			FROM membership m
			JOIN role r ON r.id = m.role_id
			WHERE m.user_id = $1
			  AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
			  AND membership_window_open(m.window_days, m.window_start, m.window_end, m.window_tz,
			                             statement_timestamp())
		`, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var roleKey string
			var assigned, covered []string
			if err := rows.Scan(&roleKey, &assigned, &covered); err != nil {
				return nil, err
			}
			members = append(members, NewMembership(Role(roleKey), scopeFromStored(assigned, covered)))
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	g := NewGrant(userID, tenantID, members...)
	g.TreeVersion = version
	g.reloadable = true
	return g, nil
}

// actorGrantTx is the grant a hierarchy authorizer sees: the actor's memberships re-read inside this
// transaction (R2) when the request grant came from stored memberships, else the request grant itself.
func actorGrantTx(ctx context.Context, tx pgx.Tx, tenantID string, actor GroupActor) (*Grant, error) {
	if actor.Grant.Reloadable() && actor.UserID != "" && !namesNoUUIDRow(actor.UserID) {
		return loadGrantTx(ctx, tx, tenantID, actor.UserID, false)
	}
	return actor.Grant, nil
}

// GroupTree implements MachineGroupStore.
func (s *PgMachineGroupStore) GroupTree(ctx context.Context, tenantID string) (GroupTree, int64, error) {
	var tree GroupTree
	var v int64
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		tree, v, err = readGroupTreeTx(ctx, tx, tenantID)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return tree, v, nil
}

// insertGroupTx inserts g (parent optional) and maps the structure failures to the shared errors.
func insertGroupTx(ctx context.Context, tx pgx.Tx, tenantID string, g *MachineGroup) error {
	var parent any
	if g.ParentID != nil && *g.ParentID != "" {
		parent = *g.ParentID
	}
	err := tx.QueryRow(ctx, `
		INSERT INTO machine_group (tenant_id, name, parent_id) VALUES ($1, $2, $3::uuid) RETURNING id::text
	`, tenantID, g.Name, parent).Scan(&g.ID)
	return mapGroupWriteErr(err)
}

// mapGroupWriteErr maps the trigger / FK failures a machine_group write can raise.
func mapGroupWriteErr(err error) error {
	if err == nil {
		return nil
	}
	if m := mapGroupStructureErr(err); m != nil {
		return m
	}
	if isForeignKeyViolation(err) {
		return ErrMachineGroupParentInvalid
	}
	return err
}

// CreateMachineGroupAs implements MachineGroupStore (docs/62 R2): lock, read the tree, reload the actor,
// authorize, insert — one transaction.
func (s *PgMachineGroupStore) CreateMachineGroupAs(ctx context.Context, tenantID string, actor GroupActor, g *MachineGroup, authz GroupAuthorizer) error {
	if g.ParentID != nil && *g.ParentID != "" && namesNoUUIDRow(*g.ParentID) {
		return ErrMachineGroupParentInvalid
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockGroupTreeTx(ctx, tx, tenantID, false); err != nil {
			return err
		}
		tree, _, err := readGroupTreeTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if authz != nil {
			grant, err := actorGrantTx(ctx, tx, tenantID, actor)
			if err != nil {
				return err
			}
			if err := authz(grant, tree); err != nil {
				return err
			}
		}
		return insertGroupTx(ctx, tx, tenantID, g)
	})
}

// MoveMachineGroup implements MachineGroupStore. Cycle and depth are decided by the database trigger, not
// pre-checked here, so the trigger is what the pg tests exercise.
func (s *PgMachineGroupStore) MoveMachineGroup(ctx context.Context, tenantID string, actor GroupActor, id string, newParent *string, authz GroupAuthorizer) (*MachineGroup, *string, error) {
	if namesNoUUIDRow(id) {
		return nil, nil, ErrMachineGroupNotFound
	}
	np := strOrEmpty(newParent)
	if np != "" && namesNoUUIDRow(np) {
		return nil, nil, ErrMachineGroupParentInvalid
	}
	var out *MachineGroup
	var old *string
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockGroupTreeTx(ctx, tx, tenantID, false); err != nil {
			return err
		}
		tree, _, err := readGroupTreeTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		canonID, _ := parsePgUUID(id)
		if _, ok := tree[canonID]; !ok {
			return ErrMachineGroupNotFound
		}
		if authz != nil {
			grant, err := actorGrantTx(ctx, tx, tenantID, actor)
			if err != nil {
				return err
			}
			if err := authz(grant, tree); err != nil {
				return err
			}
		}
		if o := tree[canonID]; o != "" {
			old = &o
		}
		var parent any
		if np != "" {
			parent = np
		}
		var g MachineGroup
		var parentOut *string
		err = tx.QueryRow(ctx, `
			UPDATE machine_group SET parent_id = $2::uuid WHERE id = $1
			RETURNING id::text, name, parent_id::text
		`, id, parent).Scan(&g.ID, &g.Name, &parentOut)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrMachineGroupNotFound
			}
			return mapGroupWriteErr(err)
		}
		g.ParentID = parentOut
		out = &g
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, old, nil
}

// DeleteMachineGroupAs implements MachineGroupStore (docs/62 R2 + D7).
func (s *PgMachineGroupStore) DeleteMachineGroupAs(ctx context.Context, tenantID string, actor GroupActor, id string, authz GroupAuthorizer) error {
	if namesNoUUIDRow(id) {
		return ErrMachineGroupNotFound
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockGroupTreeTx(ctx, tx, tenantID, false); err != nil {
			return err
		}
		tree, _, err := readGroupTreeTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		canonID, _ := parsePgUUID(id)
		if _, ok := tree[canonID]; !ok {
			return ErrMachineGroupNotFound
		}
		if authz != nil {
			grant, err := actorGrantTx(ctx, tx, tenantID, actor)
			if err != nil {
				return err
			}
			if err := authz(grant, tree); err != nil {
				return err
			}
		}
		return deleteGroupTx(ctx, tx, id)
	})
	if isForeignKeyViolation(err) {
		return ErrMachineGroupInUse
	}
	return err
}

// deleteGroupTx deletes one group after refusing when it still has subgroups (D7). The composite FK is the
// backstop for a child inserted by someone who does not take the lock.
func deleteGroupTx(ctx context.Context, tx pgx.Tx, id string) error {
	var hasChildren bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM machine_group WHERE parent_id = $1::uuid)`, id).Scan(&hasChildren); err != nil {
		return err
	}
	if hasChildren {
		return ErrMachineGroupHasChildren
	}
	ct, err := tx.Exec(ctx, `DELETE FROM machine_group WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrMachineGroupNotFound
	}
	return nil
}
