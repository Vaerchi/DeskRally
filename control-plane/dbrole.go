package controlplane

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// The connected database role must not be able to bypass row-level security (docs/25 F13).
//
// # Why this is checked at startup and not left to a runbook
//
// Tenant isolation in this product is RLS. Every tenant-scoped query relies on the policies in
// `migrations/0005_app_role.sql` applying to the connection, and they apply only to a role that is
// neither SUPERUSER nor BYPASSRLS. `rmt_app` is created that way; the bootstrap owner is not.
//
// The two are interchangeable to every line of application code and to the entire test suite — the
// queries succeed either way. The only difference is whether one tenant can read another's rows,
// which nothing in a green gate observes. The base compose file uses the bootstrap superuser and
// the production overlay correctly uses `rmt_app`, so the difference between "isolated" and
// "silently not isolated" was one DSN in one file, checked by nobody.
//
// So it is verified where the value is READ — at the connection the server will actually serve
// with — rather than documented as an instruction an operator is trusted to have followed.

// rolePrivilegeQuery asks about the EFFECTIVE role of this connection. `current_user`, not
// `session_user`: if anything ever connects and then `SET ROLE`s, what matters is the role the
// queries will run as, which is what RLS is applied against.
const rolePrivilegeQuery = `SELECT current_user::text, rolsuper, rolbypassrls ` +
	`FROM pg_roles WHERE rolname = current_user`

// RowQuerier is the one method this needs, so a unit test can supply a fake and the real check can
// take a *pgxpool.Pool.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// AssertLeastPrivilegeRole returns nil only if the connected role is provably unable to bypass RLS.
//
// It FAILS CLOSED on an unreadable answer, and says which of the two failures happened. That
// distinction is not cosmetic: this project has already shipped a fail-closed guard whose single
// error message could not tell "you are misconfigured" from "I could not check", and a restored
// deployment then rejected every login with a message that sent the operator looking in the wrong
// place entirely.
func AssertLeastPrivilegeRole(ctx context.Context, q RowQuerier) error {
	var name string
	var super, bypass bool
	if err := q.QueryRow(ctx, rolePrivilegeQuery).Scan(&name, &super, &bypass); err != nil {
		return fmt.Errorf(
			"could not verify the connected database role's privileges (this is NOT a report that "+
				"the role is wrong — the check itself failed, so the query, the connection or "+
				"pg_roles access is the thing to look at): %w", err)
	}
	if super || bypass {
		return fmt.Errorf(
			"the DATABASE_URL role %q is %s, so row-level security DOES NOT APPLY to it and every "+
				"tenant-scoped query can read every tenant's rows. Tenant isolation in this product "+
				"IS row-level security, and application code cannot tell the difference — the "+
				"queries succeed either way. Connect as rmt_app (migrations/0005_app_role.sql "+
				"creates it NOSUPERUSER NOBYPASSRLS; run `controlplane migrate` with APP_DB_PASSWORD "+
				"set to give it a password), or set %s=1 if this is a local database you are "+
				"deliberately running without isolation",
			name, privilegeDescription(super, bypass), EnvAllowPrivilegedDB)
	}
	return nil
}

// privilegeDescription names WHICH privilege was found, because the remedy differs: a superuser
// role is the wrong DSN, whereas a BYPASSRLS non-superuser is usually a role that was granted it
// deliberately and has to be altered.
func privilegeDescription(super, bypass bool) string {
	switch {
	case super && bypass:
		return "both SUPERUSER and BYPASSRLS"
	case super:
		return "a SUPERUSER"
	default:
		return "BYPASSRLS"
	}
}
