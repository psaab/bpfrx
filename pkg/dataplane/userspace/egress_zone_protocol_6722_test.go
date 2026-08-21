package userspace

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722: the required-protocol gate for the v5 snapshot contract.
//
// v5 DELETES `reth_projection` and adds `egress_zone`. A deletion cannot ride an
// unchanged version the way an additive field can — two binaries either side of
// it both advertise their number and read the same bytes differently — and the
// mixed pairing is not merely "not yet fixed". MEASURED, feeding the v4 Go
// builder's rows to the v5 helper on the reference cluster
// (docs/ha-cluster-userspace.conf, node 0):
//
//	ifindex 24  egress zone 0   (origin/master and the matched v5 pair: lan)
//	ifindex 25  egress zone 0   (origin/master and the matched v5 pair: wan)
//
// Ifindex 25 is the one that settles it: the mixed pairing loses a zone even the
// PRE-#6722 helper resolved, so it is strictly worse than either endpoint rather
// than an intermediate state. Under `default-policy deny-all` that is a silent
// transit outage whose only signature is a version both sides agree on.
//
// FAIL-ON-REVERT:
//
//	change the gate's `==` to `>=`                    -> the newer-helper cell
//	drop the gate from ensureRequiredSnapshotProtocolLocked -> orchestrator cell
//	drop ErrEgressZoneProtocolIncompatible from
//	  requiredProtocolGateSentinels                   -> the sentinel cell
//	drop the `observed <= 0` no-brick early return    -> the unknown-version cell

// preV5SnapshotProtocolVersion is the version a helper built before #6722
// advertises and accepts. A LITERAL, not `ProtocolVersion - 1`: the whole point
// is that the current version must no longer collide with the one whose readers
// cannot see `egress_zone`, so the test pins the historical value rather than
// tracking the constant it is checking.
const preV5SnapshotProtocolVersion = 4

func TestEgressZoneProtocolGate_6722(t *testing.T) {
	cases := []struct {
		name     string
		observed int
		wantErr  bool
		why      string
	}{
		{
			name:     "pre-v5-helper-rejected",
			observed: preV5SnapshotProtocolVersion,
			wantErr:  true,
			why: "a helper on the other side of the field deletion resolves NO " +
				"egress zone for an interface described by several rows, so every " +
				"transit flow out of both reference-cluster RETH ifindexes falls to " +
				"the default policy",
		},
		{
			name:     "matched-helper-accepted",
			observed: ProtocolVersion,
			wantErr:  false,
			why:      "the ordinary case must not be fenced",
		},
		{
			// THE CELL THAT DISTINGUISHES `==` FROM `>=`. A helper NEWER than
			// this binary also refuses our snapshot — its own apply_snapshot and
			// bump_fib gates are exact-equality — so committing against it would
			// report success against a dataplane running the previous image. A
			// `>=` (or `> N`) spelling passes this cell and is the shape that
			// silently stays green at exactly the colliding value.
			name:     "newer-helper-also-rejected",
			observed: ProtocolVersion + 1,
			wantErr:  true,
			why: "the helper's own gate is exact equality, so a NEWER helper " +
				"refuses this snapshot just as an older one does",
		},
		{
			// #1960 no-brick. `lastStatus` is zero before the first handshake,
			// and this gate is unconditional in the CONFIG dimension, so firing
			// on "version unknown" would abort every commit made while the helper
			// is down or still starting.
			name:     "unknown-version-does-not-fire",
			observed: 0,
			wantErr:  false,
			why: "no helper has reported a version, which is not evidence of a " +
				"mismatch; firing here would abort every commit made while the " +
				"helper is down (#1960 no-brick)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = tc.observed

			err := m.ensureEgressZoneProtocolLocked()
			if tc.wantErr && err == nil {
				t.Fatalf("helper at version %d was ACCEPTED, want the gate to fire: %s",
					tc.observed, tc.why)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("helper at version %d was rejected (%v), want accepted: %s",
					tc.observed, err, tc.why)
			}
			if !tc.wantErr {
				return
			}
			if !errors.Is(err, ErrEgressZoneProtocolIncompatible) {
				t.Errorf("error %v does not wrap ErrEgressZoneProtocolIncompatible; "+
					"ApplyConfig keys the disarm + commit-abort contract (#2138) on "+
					"that sentinel, so an unwrapped error would let the commit report "+
					"success against a helper that cannot honour the snapshot", err)
			}
			// The message must name the ORDERING remedy. A version error the
			// operator cannot act on is a support ticket, not a fence.
			for _, want := range []string{"egress_zone", "Restart the userspace dataplane helper"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("gate error does not mention %q; the operator has to be "+
						"told WHICH half to move and in what order. Got: %v", want, err)
				}
			}
		})
	}
}

// The sentinel must be enumerated, or ApplyConfig does not treat a hit as a
// required-protocol gate: IsRequiredProtocolGateError walks this list, and a
// missing entry means the commit is promoted against a disarmed dataplane
// (#2138) instead of aborting.
func TestEgressZoneProtocolSentinelIsEnumerated_6722(t *testing.T) {
	found := false
	for _, s := range requiredProtocolGateSentinels {
		if errors.Is(s, ErrEgressZoneProtocolIncompatible) {
			found = true
		}
	}
	if !found {
		t.Fatalf("ErrEgressZoneProtocolIncompatible is not in " +
			"requiredProtocolGateSentinels, so a commit that hits the gate is not " +
			"recognised as a required-protocol failure and does not abort")
	}
	if !IsRequiredProtocolGateError(ErrEgressZoneProtocolIncompatible) {
		t.Errorf("IsRequiredProtocolGateError does not recognise the sentinel")
	}
}

// And the gate must be REACHED. A gate that exists but is never called is the
// same as no gate; ensureRequiredSnapshotProtocolLocked is the only caller.
func TestEgressZoneProtocolGateIsWiredIntoTheOrchestrator_6722(t *testing.T) {
	m := New()
	m.lastStatus.ConfigSnapshotProtocolVersion = preV5SnapshotProtocolVersion

	// A config with none of the sibling gates' shapes, so any error can only
	// come from the egress-zone gate.
	err := m.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, &config.Config{}))
	if err == nil {
		t.Fatalf("ensureRequiredSnapshotProtocolLocked accepted a pre-v5 helper; " +
			"the egress-zone gate is not wired into the orchestrator, so nothing " +
			"on the commit path fences the version mismatch")
	}
	if !errors.Is(err, ErrEgressZoneProtocolIncompatible) {
		t.Errorf("orchestrator returned %v, want the egress-zone sentinel: a "+
			"different sibling gate firing would make this cell pass for the "+
			"wrong reason", err)
	}
}
