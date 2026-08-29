package upgrade

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestForwardBeaconDataplaneCondition_6607 is the fail-on-revert gate for Gate
// 4's second condition.
//
// It used to be `systemctl is-active xpfd-userspace-dp` — a unit that exists
// NOWHERE in the repository and never has. The helper is a child process xpfd
// spawns, not a systemd unit, so that probe could never report active; OR'd with
// the xpfd probe it could contribute neither a pass nor a fail, and the guard
// degenerated to "xpfd is active". Gate 4's entire job is to confirm the
// candidate kernel actually forwards, and a Type=simple xpfd reports active
// while its helper is down, stale or crash-looping — the exact state an AF_XDP
// shim / verifier / driver mismatch produces. The old shape failed PERMISSIVE,
// so a bad kernel was more likely to be promoted than rolled back.
//
// The acceptance criterion is precisely that the second condition CAN fail:
// healthy xpfd, unhealthy dataplane, beacon must not report forward progress.
func TestForwardBeaconDataplaneCondition_6607(t *testing.T) {
	origUnit := unitActiveProbeCtx
	origPing := beaconPing
	t.Cleanup(func() {
		unitActiveProbeCtx = origUnit
		beaconPing = origPing
	})

	// A healthy xpfd for every case below: the point is that A alone is not
	// enough, so A must never be the reason a case fails.
	var probedUnits []string
	unitActiveProbeCtx = func(_ context.Context, unit string) (bool, error) {
		probedUnits = append(probedUnits, unit)
		return unit == "xpfd", nil
	}
	// A SUCCEEDING ping, so the dataplane condition is the only thing left that
	// can reject. Without this the cases below pass even with the condition
	// deleted — the ping fails against 192.0.2.1 and the beacon returns false
	// for a reason the assertion cannot see.
	pinged := false
	beaconPing = func(string, int) error { pinged = true; return nil }

	for _, tc := range []struct {
		name    string
		status  HelperStatusFunc
		wantErr bool
	}{
		{
			name: "helper not enabled",
			status: func(string, time.Duration) (bool, bool, int, error) {
				return false, false, 0, nil
			},
		},
		{
			name: "helper enabled but not forwarding-armed",
			status: func(string, time.Duration) (bool, bool, int, error) {
				// The #5286 state: the process is up, so is-active says active,
				// but it is not forwarding. This is the case the old probe was
				// structurally incapable of seeing.
				return true, false, 4242, nil
			},
		},
		{
			name: "control socket unreachable",
			status: func(string, time.Duration) (bool, bool, int, error) {
				return false, false, 0, errors.New("dial /run/xpf/userspace-dp.sock: no such file")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &realKernelSystem{
				// A target is set so the ping branch is the ONLY thing left
				// downstream: if the dataplane condition wrongly passes, the
				// case fails for a reason this test can name, rather than
				// silently taking the no-gateway error path.
				BeaconTarget: "192.0.2.1",
				HelperStatus: tc.status,
			}
			ok, err := s.ForwardBeacon(time.Second)
			if ok {
				t.Fatalf("ForwardBeacon reported forward progress with an unhealthy dataplane "+
					"(case: %s) — Gate 4 would promote a kernel that does not forward", tc.name)
			}
			if err != nil {
				t.Fatalf("an unhealthy dataplane must be a clean REJECT (false, nil), not an error: %v", err)
			}
		})
	}

	// The probe must actually be xpfd — a beacon that asked about a unit which
	// does not exist is how this defect happened in the first place.
	for _, u := range probedUnits {
		if u != "xpfd" {
			t.Fatalf("ForwardBeacon probed systemd unit %q; the only unit this repo ships for the "+
				"dataplane is \"xpfd\" (the helper is a child process, not a unit)", u)
		}
	}
	if len(probedUnits) == 0 {
		t.Fatal("ForwardBeacon never probed a systemd unit at all")
	}
	// Every case above must have rejected BEFORE the ping. If any of them
	// reached it, the dataplane condition did not do the rejecting and the
	// assertions were passing for the wrong reason.
	if pinged {
		t.Fatal("ForwardBeacon reached the ping with an unhealthy dataplane — the reject " +
			"came from somewhere other than the dataplane condition")
	}
}

// TestForwardBeaconPassesWhenEverythingHealthy_6607 is the positive control. It
// is what makes the negative cases above meaningful: without it, a beacon that
// rejected unconditionally would satisfy every one of them.
func TestForwardBeaconPassesWhenEverythingHealthy_6607(t *testing.T) {
	origUnit := unitActiveProbeCtx
	origPing := beaconPing
	// #7157: the target-eligibility check runs a real `ip route get` unless the
	// seam is stubbed, and this test then passes or fails on the routing table
	// of whatever machine runs the suite. Measured on one dev box,
	// `ip route get 192.0.2.1` answers `dev ix0` and the case passes by
	// accident; on a host with no route it fails, and on a host whose default
	// egresses a NIC named em*/fab*/fxp* it would fail for a reason this
	// assertion cannot name. Same reasoning as the beaconPing stub below.
	origGet := beaconRouteGet
	t.Cleanup(func() {
		unitActiveProbeCtx = origUnit
		beaconPing = origPing
		beaconRouteGet = origGet
	})
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return true, nil }
	beaconPing = func(string, int) error { return nil }
	beaconRouteGet = func(string) (string, error) {
		return "192.0.2.1 via 172.16.50.1 dev ge-0-0-2.50 src 172.16.50.8 uid 0\n", nil
	}

	s := &realKernelSystem{
		BeaconTarget: "192.0.2.1",
		HelperStatus: func(string, time.Duration) (bool, bool, int, error) {
			return true, true, 1234, nil
		},
		IsManagementIface: func(string) bool { return false },
	}
	if ok, err := s.ForwardBeacon(time.Second); !ok || err != nil {
		t.Fatalf("ForwardBeacon = (%v, %v) with xpfd active, the dataplane armed and the "+
			"ping succeeding; want (true, nil)", ok, err)
	}
}

// TestForwardBeaconRejectsInactiveXpfd_6607 pins precondition A independently,
// so a change that dropped the xpfd check while keeping the dataplane one would
// not slip through green.
func TestForwardBeaconRejectsInactiveXpfd_6607(t *testing.T) {
	origUnit := unitActiveProbeCtx
	origPing := beaconPing
	t.Cleanup(func() {
		unitActiveProbeCtx = origUnit
		beaconPing = origPing
	})
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return false, nil }
	// A SUCCEEDING ping, so precondition A is the only thing that can reject.
	// Without this the case passes even with A deleted — the real ping to
	// 192.0.2.1 fails and the beacon returns false for a reason the assertion
	// cannot see.
	beaconPing = func(string, int) error { return nil }

	s := &realKernelSystem{
		BeaconTarget: "192.0.2.1",
		HelperStatus: func(string, time.Duration) (bool, bool, int, error) {
			return true, true, 1, nil // a perfectly healthy dataplane
		},
	}
	if ok, err := s.ForwardBeacon(time.Second); ok || err != nil {
		t.Fatalf("ForwardBeacon = (%v, %v) with xpfd INACTIVE; want (false, nil)", ok, err)
	}
}

// TestForwardBeaconNilHelperStatusFallsBack_6607 pins the seam-absent contract.
// A nil probe means this caller has no dataplane to ask (a non-xpfd embedder or
// a test), which is "no information", not "unhealthy". Failing closed on it
// would revert every such caller's promotion, so it falls back to precondition A
// alone — and the case must reach the ping branch to prove it got past B.
func TestForwardBeaconNilHelperStatusFallsBack_6607(t *testing.T) {
	origUnit := unitActiveProbeCtx
	t.Cleanup(func() { unitActiveProbeCtx = origUnit })
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return true, nil }

	// Force the no-target branch through the seam rather than hoping this
	// machine has no default route: its distinctive ERROR is the observable
	// proof that control flowed PAST the dataplane condition instead of
	// short-circuiting at it (a nil-status fail-closed returns (false, nil)).
	// Without the seam this assertion passes or fails depending on whether the
	// host running the suite happens to have a gateway.
	origGW := beaconDefaultGateway
	t.Cleanup(func() { beaconDefaultGateway = origGW })
	beaconDefaultGateway = func() string { return "" }

	s := &realKernelSystem{HelperStatus: nil}
	ok, err := s.ForwardBeacon(time.Second)
	if ok {
		t.Fatal("ForwardBeacon passed with no target at all")
	}
	if err == nil {
		t.Fatal("a nil HelperStatus must fall back to precondition A and reach the target " +
			"resolution, not fail closed at the dataplane condition")
	}
	if !strings.Contains(err.Error(), "no forward-beacon target") {
		t.Fatalf("unexpected error %v; want the no-target error that proves the dataplane "+
			"condition was skipped rather than failed", err)
	}
}
