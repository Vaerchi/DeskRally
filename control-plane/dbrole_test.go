package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// --- fake-backed unit tests: the four privilege combinations and the unreadable case -------------

type fakeRow struct {
	name   string
	super  bool
	bypass bool
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 3 {
		return errors.New("unexpected column count")
	}
	*(dest[0].(*string)) = r.name
	*(dest[1].(*bool)) = r.super
	*(dest[2].(*bool)) = r.bypass
	return nil
}

type fakeQuerier struct{ row fakeRow }

func (q fakeQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row { return q.row }

func TestLeastPrivilegeRoleAcceptsANonPrivilegedRole(t *testing.T) {
	err := AssertLeastPrivilegeRole(context.Background(), fakeQuerier{fakeRow{name: "rmt_app"}})
	if err != nil {
		t.Fatalf("a NOSUPERUSER NOBYPASSRLS role must be accepted; got: %v", err)
	}
}

// Each privilege is named SEPARATELY, because the remedy differs: a superuser DSN is the wrong
// connection string, whereas a non-superuser holding BYPASSRLS is a role somebody altered.
func TestLeastPrivilegeRoleNamesWhichPrivilegeItFound(t *testing.T) {
	cases := []struct {
		name string
		row  fakeRow
		// The EXACT verdict, compared with equality rather than containment. A substring check is
		// useless here: the remediation text names `NOSUPERUSER NOBYPASSRLS`, so asserting that a
		// superuser's message "does not contain BYPASSRLS" fails on correct output — which is
		// precisely what the first version of this test did. Equality on the verdict itself
		// distinguishes the three cases strictly, and cannot be satisfied by prose elsewhere.
		wantVerdict string
	}{
		{"superuser", fakeRow{name: "postgres", super: true}, "a SUPERUSER"},
		{"bypassrls only", fakeRow{name: "sneaky", bypass: true}, "BYPASSRLS"},
		{"both", fakeRow{name: "postgres", super: true, bypass: true}, "both SUPERUSER and BYPASSRLS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := privilegeDescription(tc.row.super, tc.row.bypass); got != tc.wantVerdict {
				t.Errorf("privilegeDescription(%v, %v) = %q, want %q",
					tc.row.super, tc.row.bypass, got, tc.wantVerdict)
			}
			err := AssertLeastPrivilegeRole(context.Background(), fakeQuerier{tc.row})
			if err == nil {
				t.Fatalf("privileged role %+v must be refused", tc.row)
			}
			msg := err.Error()
			// "is <verdict>" anchors the phrase to the sentence that renders the verdict, so a
			// superuser cannot be reported as merely BYPASSRLS and send the operator off to alter
			// a role when the real problem is the DSN.
			if !strings.Contains(msg, "is "+tc.wantVerdict) {
				t.Errorf("message must render the verdict as %q; got: %s", "is "+tc.wantVerdict, msg)
			}
			if !strings.Contains(msg, tc.row.name) {
				t.Errorf("message must name the role %q so it can be found; got: %s", tc.row.name, msg)
			}
			if !strings.Contains(msg, EnvAllowPrivilegedDB) {
				t.Errorf("message must name the opt-out %q; got: %s", EnvAllowPrivilegedDB, msg)
			}
		})
	}
}

// FAIL CLOSED, BUT SAY WHICH FAILURE. A guard that cannot read its own answer must not report the
// answer it failed to read: this project has already shipped one whose single message could not
// tell "you are misconfigured" from "I could not check", and a restored deployment then rejected
// every login while the operator looked in entirely the wrong place.
func TestLeastPrivilegeRoleDistinguishesAnUnreadableAnswerFromAPrivilegedRole(t *testing.T) {
	boom := errors.New("permission denied for table pg_roles")
	err := AssertLeastPrivilegeRole(context.Background(), fakeQuerier{fakeRow{err: boom}})
	if err == nil {
		t.Fatal("an unreadable privilege check must fail closed, not pass")
	}
	msg := err.Error()
	if !errors.Is(err, boom) {
		t.Errorf("the underlying cause must be wrapped so it is diagnosable; got: %s", msg)
	}
	if !strings.Contains(msg, "the check itself failed") {
		t.Errorf("message must say the CHECK failed rather than imply a verdict; got: %s", msg)
	}
	// It must not assert the thing it could not determine.
	for _, forbidden := range []string{"SUPERUSER", "BYPASSRLS"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("must not name a privilege it never read (%q); got: %s", forbidden, msg)
		}
	}
}

// --- and the same assertions against a REAL database -------------------------------------------
//
// A fake says nothing about what Postgres actually reports: the query has to name real columns of
// a real catalog, and `current_user` has to resolve to the role the pool connects as. Both halves
// run here, on the same database, with opposite expected outcomes — which is what makes this a
// control rather than a demonstration.

func TestLeastPrivilegeRoleAgainstRealPostgres(t *testing.T) {
	ctx := context.Background()
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)

	// The gate's own DSN connects as `postgres`. It MUST be refused — this is the configuration the
	// production overlay avoids and the base compose file does not.
	if err := AssertLeastPrivilegeRole(ctx, suPool); err == nil {
		t.Error("the privileged test role was ACCEPTED against real Postgres; the guard is inert")
	} else if !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("refusal should explain what is lost; got: %v", err)
	}

	// And rmt_app, the role production actually uses, must be accepted.
	appPool := newAppRolePool(t, ctx)
	if err := AssertLeastPrivilegeRole(ctx, appPool); err != nil {
		t.Errorf("rmt_app must be accepted, or production cannot start: %v", err)
	}
}
