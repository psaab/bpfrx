package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func clusteredCfg8965(peer string) *config.Config {
	c := &config.Config{}
	c.Chassis.Cluster = &config.ClusterConfig{
		NodeID:      0,
		ClusterID:   1,
		PeerAddress: peer,
	}
	return c
}

// #8965: a live control-link peer-address move restarts this node's cluster
// comms on the NEW address and only then pushes the config to a peer still on
// the OLD one. The push no-ops silently, the #5863 reconciler is gated behind
// the connection that no longer exists, and both nodes are durably configured
// -- so retry and reboot REPRODUCE the partition rather than repair it.
//
// The remedy is a refusal rather than a make-before-break, and the reason is
// structural rather than stylistic: THREE apply paths reach applyConfigLocked
// (commitAndApply, syncAndApply, commitConfirmedAndApply), so a stage-and-ACK
// would have to be correct at each and a version landed at one would leave the
// others silently broken. A preflight runs before all three.
func TestControlEndpointMoveIsRefused8965(t *testing.T) {
	t.Run("no running manager is a no-op", func(t *testing.T) {
		if err := clusterControlEndpointCommitPreflight(nil, clusteredCfg8965("10.99.0.2")); err != nil {
			t.Errorf("with no running cluster this gate must not fire: %v", err)
		}
	})

	t.Run("candidate not clustered is a no-op", func(t *testing.T) {
		if err := clusterControlEndpointCommitPreflight(nil, &config.Config{}); err != nil {
			t.Errorf("a non-clustered candidate belongs to the topology gate: %v", err)
		}
	})

	// THE DECISION ITSELF, which is what the earlier version of this cell
	// failed to reach: it exercised only the message builder, so neutering the
	// gate to `return nil` left it green.
	// #9178 CORRECTED ONE ROW OF THIS TABLE. "candidate leaves it unset" was
	// scored as allowed on the reasoning quoted in the gate — "unset on either
	// side means there is no live endpoint to strand". That reasoning covers
	// have=="" (an addition) and is FALSE for want=="" (a deletion), where the
	// live endpoint being stranded is the one being removed. The row now
	// carries the fabric-fallback column that decides it; the full four-cell
	// enumeration lives in the #9178 cell below.
	for _, tc := range []struct {
		name, have, want string
		fabric           bool
		refuse           bool
	}{
		{"a real move is refused", "10.99.0.2", "10.99.5.2", false, true},
		{"unchanged is allowed", "10.99.0.2", "10.99.0.2", false, false},
		{"no running endpoint yet", "", "10.99.5.2", false, false},
		{"candidate deletes it, no fallback", "10.99.0.2", "", false, true},
		{"candidate deletes it, fabric fallback", "10.99.0.2", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := controlEndpointDecision8965(tc.have, tc.want, tc.fabric)
			if tc.refuse && err == nil {
				t.Errorf("have=%q want=%q must be REFUSED: applying it restarts "+
					"comms on the new address before the peer can be told (#8965)",
					tc.have, tc.want)
			}
			if !tc.refuse && err != nil {
				t.Errorf("have=%q want=%q is not a live move and must be allowed: %v",
					tc.have, tc.want, err)
			}
		})
	}
}

// The error must NAME THE PROCEDURE, not just refuse. An operator mid-
// maintenance who is told only "no" will find the way around it, and the way
// around it -- committing the change on each node separately while both run --
// is the same partition by hand. A refusal without a path is worse than the
// defect it prevents.
func TestControlEndpointRefusalNamesTheRemedy8965(t *testing.T) {
	err := controlEndpointDecision8965("10.99.0.2", "10.99.5.2", false)
	if err == nil {
		t.Fatal("a control-endpoint move on a running cluster must be refused (#8965)")
	}
	msg := err.Error()
	for _, want := range []string{
		"10.99.0.2",  // the address it is on
		"10.99.5.2",  // the address it was asked to move to
		"BOTH nodes", // the procedure
		"restart",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q, so it tells the operator to "+
				"stop without telling them how to proceed: %s (#8965)", want, msg)
		}
	}
	// And it must warn off the workaround that reproduces the defect by hand.
	if !strings.Contains(msg, "separately") {
		t.Errorf("the refusal does not warn against committing the change on each "+
			"node separately, which is the same partition performed manually: %s "+
			"(#8965)", msg)
	}
}
