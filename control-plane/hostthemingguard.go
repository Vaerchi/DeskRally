package controlplane

// Startup guard for the opt-in host policy (docs/66 runbook). With the policy OFF the control plane redeems
// unscoped, which would silently remove the redemption scope of every ACTIVE tenant hostname assignment. So when
// the policy is off and any active assignment exists, startup is REFUSED, unless the operator sets the explicit
// emergency escape hatch, in which case the process starts and warns loudly every minute.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ThemingEscapeValue is the only value of CP_HOST_THEMING_ALLOW_UNSCOPED that acts as the escape hatch.
const ThemingEscapeValue = "i-understand"

// ErrThemingOffWithAssignments is the startup refusal.
var ErrThemingOffWithAssignments = errors.New("tenant hostnames are assigned but CP_HOST_THEMING is off - " +
	"turning it off would remove their redemption scope; turn it back on, or release the assignments first")

// ActiveHostnameCount reads cp_hostname_active_count (migration 0071).
func ActiveHostnameCount(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var n int64
	err := pool.QueryRow(ctx, `SELECT cp_hostname_active_count()`).Scan(&n)
	return n, err
}

// CheckThemingOffSafety is called at startup ONLY when the host policy is not enabled. A count error is
// returned as is (the caller applies the existing startup behaviour for database failures: fatal, never a new
// fail-open). escaped reports that active assignments exist and the escape hatch let the process start.
func CheckThemingOffSafety(ctx context.Context, count func(context.Context) (int64, error), escape string) (escaped bool, err error) {
	n, err := count(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot check hostname assignments (is migration 0071 applied?): %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if escape == ThemingEscapeValue {
		return true, nil
	}
	return false, fmt.Errorf("%w (%d active)", ErrThemingOffWithAssignments, n)
}

// WarnUnscopedLoop logs the emergency warning immediately and then every interval until ctx ends.
func WarnUnscopedLoop(ctx context.Context, interval time.Duration, logf func(format string, args ...any)) {
	warn := func() {
		logf("WARNING: CP_HOST_THEMING is off and CP_HOST_THEMING_ALLOW_UNSCOPED=%s is set while tenant hostnames are "+
			"ACTIVE: their redemption scope is NOT enforced and any tenant's code redeems on any host. Emergency use only.", ThemingEscapeValue)
	}
	warn()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			warn()
		}
	}
}
