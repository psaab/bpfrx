package dhcpserver

import (
	"fmt"
	"strings"
	"testing"
)

// #4870 A: a `systemctl is-active` query FAILURE (timeout/exec error, as
// distinct from a definitive "inactive" answer) must not be silently mapped to
// "inactive". The old unitIsActive discarded the command error and returned
// false, so on a cluster commit the configured-but-active Kea unit's restart
// was skipped, lastAppliedGen advanced, and the commit returned nil while the
// old Kea kept serving stale policy — a fail-open. The apply path must instead
// fail closed: enforce the config (restart/stop) despite the uncertainty AND
// surface the query error so the commit does not report success.

// isActiveErr is a unitActive seam whose query fails for the named units
// (returning a non-nil error, the tri-state "could not determine" case).
func isActiveErr(errUnits ...string) func(unit string) (bool, error) {
	set := map[string]bool{}
	for _, u := range errUnits {
		set[u] = true
	}
	return func(unit string) (bool, error) {
		if set[unit] {
			return false, fmt.Errorf("systemctl is-active %s: context deadline exceeded", unit)
		}
		return false, nil // definitively inactive
	}
}

// TestClusterCommitIsActiveErrorFailsClosed pins the restart branch. A cluster
// commit (restartInactive=false) whose is-active query errors must restart the
// configured unit to enforce the freshly generated config AND return an error,
// instead of skipping the restart and reporting success.
//
// fail-on-revert: mapping the query error back to "inactive" (the old behavior)
// skips the restart and returns nil, so both assertions below fail.
func TestClusterCommitIsActiveErrorFailsClosed(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	m.SetUnitActiveForTesting(isActiveErr(kea4Svc))

	err := m.ApplyClusterCommit(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("ApplyClusterCommit must fail closed on an is-active query error, got nil")
	}
	if !strings.Contains(err.Error(), kea4Svc) {
		t.Errorf("error should name the unit: %v", err)
	}
	if !calledWith(*calls, "restart "+kea4Svc) {
		t.Errorf("expected kea4 restart to enforce fresh config despite the query error, got %v", *calls)
	}
}

// TestRemovedFamilyIsActiveErrorFailsClosed pins the clear branch. A removed
// family whose is-active query errors must issue the stop authoritatively (a
// stop on an already-inactive unit is harmless) AND surface the error, instead
// of skipping the stop and letting the removed subnet keep being served.
//
// fail-on-revert: mapping the query error to "inactive" skips the stop and
// returns nil, so both assertions fail.
func TestRemovedFamilyIsActiveErrorFailsClosed(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	// v4-only config: the kea6 family is removed. Its is-active query errors.
	m.SetUnitActiveForTesting(isActiveErr(kea6Svc))

	err := m.Apply(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("Apply must fail closed on a removed-family is-active query error, got nil")
	}
	if !strings.Contains(err.Error(), kea6Svc) {
		t.Errorf("error should name the unit: %v", err)
	}
	if !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected kea6 stop to enforce removal despite the query error, got %v", *calls)
	}
}

// TestClusterCommitIsActiveDefinitiveInactiveStillSkips confirms the fix does
// NOT over-restart: a DEFINITIVE inactive answer (nil query error) on a cluster
// commit still skips the restart, exactly as before — only a query FAILURE
// forces enforcement.
func TestClusterCommitIsActiveDefinitiveInactiveStillSkips(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	// Default seam: every unit is definitively inactive (false, nil).

	if err := m.ApplyClusterCommit(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("ApplyClusterCommit: %v", err)
	}
	if calledWith(*calls, "restart "+kea4Svc) {
		t.Errorf("a definitively-inactive unit must not be restarted on a cluster commit, got %v", *calls)
	}
}
