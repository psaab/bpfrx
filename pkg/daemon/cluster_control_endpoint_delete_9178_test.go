package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #9178: the #8965 preflight was built to stop an operator stranding a running
// cluster by changing its control endpoint, and it PASSED the deletion case.
// `have != "" && want == ""` was admitted because the gate returned nil
// whenever either side was empty — two of four inputs decided by a sentence
// ("no live endpoint to strand") that is true for an ADDITION and false for a
// DELETION, where the live endpoint is the one being removed.
//
// The acceptance the issue asked for is the full enumeration: "a four-cell
// table over (have, want) ∈ {'', 'x'}², with the control-link-only and
// fabric-configured topologies as separate columns. A gate that returns nil for
// two of four inputs is the defect, so the test must enumerate all four."

func TestControlEndpointDecisionIsTotal9178(t *testing.T) {
	const live = "10.99.12.2"
	const moved = "10.99.12.9"

	for _, tc := range []struct {
		name       string
		have, want string
		// fabric is the SEPARATE COLUMN: a control-link-only cluster (false)
		// versus one with a fabric transport still configured (true).
		fabric bool
		refuse bool
		why    string
	}{
		// have == "" — nothing live. The original justification holds here.
		{"neither set, no fabric", "", "", false, false,
			"nothing is running and nothing is asked for"},
		{"neither set, fabric", "", "", true, false,
			"same, and the fabric column must not change it"},
		{"addition, no fabric", "", live, false, false,
			"the heartbeat has not started, so there is no live endpoint to strand"},
		{"addition, fabric", "", live, true, false,
			"same"},

		// have != "", want == "" — DELETION. This is the defect.
		{"deletion on a control-link-only cluster", live, "", false, true,
			"no heartbeat AND no sync transport: the apply-then-push partition, " +
				"and durable because the peer never learns why"},
		{"deletion with a fabric fallback", live, "", true, false,
			"clusterSyncTransport falls back to the fabric, so the push still " +
				"lands and the deletion propagates; the heartbeat dies on both " +
				"nodes, which is what was asked for"},

		// have != "", want != "" — the #8965 cases, unchanged.
		{"unchanged, no fabric", live, live, false, false, "not a move"},
		{"unchanged, fabric", live, live, true, false, "not a move"},
		{"move, no fabric", live, moved, false, true,
			"#8965: comms restart on the new address before the peer can be told"},
		{"move, fabric", live, moved, true, true,
			"a fabric fallback does NOT license a move — the control link is " +
				"rebuilt somewhere the peer is not listening either way"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := controlEndpointDecision8965(tc.have, tc.want, tc.fabric)
			if tc.refuse && err == nil {
				t.Errorf("have=%q want=%q fabric=%v must be REFUSED: %s",
					tc.have, tc.want, tc.fabric, tc.why)
			}
			if !tc.refuse && err != nil {
				t.Errorf("have=%q want=%q fabric=%v must be ALLOWED (%s): %v",
					tc.have, tc.want, tc.fabric, tc.why, err)
			}
		})
	}
}

// The deletion refusal must NAME THE PROCEDURE, for the reason #8965 recorded:
// an operator mid-maintenance told only "no" finds the way around it, and the
// way around it — committing on each node separately while both run — is the
// same partition by hand.
func TestDeleteRefusalNamesTheRemedy9178(t *testing.T) {
	err := controlEndpointDecision8965("10.99.12.2", "", false)
	if err == nil {
		t.Fatal("deleting a live control endpoint with no fallback must be refused")
	}
	msg := err.Error()
	for _, want := range []string{"fabric-peer-address", "10.99.12.2", "partition"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q: %s", want, msg)
		}
	}
	// It must not be the MOVE text: a move refusal tells the operator to set
	// the new address on both nodes, which is meaningless when there is no new
	// address, and would send them looking for a value that does not exist.
	if strings.Contains(msg, "set the new address on BOTH nodes") {
		t.Error("the deletion arm emitted the MOVE refusal, whose remedy does " +
			"not apply when there is no new address")
	}
}

// The fabric predicate mirrors clusterSyncTransport's own fallback condition.
// If the two drift, the gate stops asking the question the runtime asks — and
// a deletion is safe exactly when the runtime would fall back.
func TestFabricPredicateMatchesTheRuntimeFallback9178(t *testing.T) {
	for _, tc := range []struct {
		name              string
		fabIface, fabPeer string
		want              bool
	}{
		{"both set", "fab0", "10.99.13.2", true},
		{"no interface", "", "10.99.13.2", false},
		{"no peer", "fab0", "", false},
		{"neither", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := &config.ClusterConfig{
				FabricInterface:   tc.fabIface,
				FabricPeerAddress: tc.fabPeer,
			}
			if got := fabricFallbackConfigured9178(cc); got != tc.want {
				t.Errorf("fabricFallbackConfigured9178 = %v, want %v", got, tc.want)
			}
			// The runtime's own answer, on the same input. The condition that
			// matters is the one daemon_ha_sync.go actually gates the sync
			// goroutine on — `syncIface != "" && syncPeerAddr != ""` — NOT the
			// transport LABEL. clusterSyncTransport returns "fabric" whenever
			// the control link is incomplete, including when the fabric is
			// incomplete too, so the label alone reports a transport that never
			// starts. Reading the label here would have made this cell demand
			// that the gate admit a deletion into a config with no sync at all.
			iface, peer, transport := clusterSyncTransport(cc)
			runtimeStartsSync := iface != "" && peer != ""
			if runtimeStartsSync != tc.want {
				t.Errorf("the gate says fallback=%v but the runtime start "+
					"condition on iface=%q peer=%q (label %q) is %v — the "+
					"commit-time check and the runtime disagree",
					tc.want, iface, peer, transport, runtimeStartsSync)
			}
		})
	}
	if fabricFallbackConfigured9178(nil) {
		t.Error("a nil cluster config reported a fabric fallback")
	}
}

// BIND THE WIRING. The cells above call the DECISION, so all of them stay green
// if the preflight stops passing the fabric column — it would pass the zero
// value, refusing every deletion including the safe one, and nothing would
// notice.
//
// An earlier version of this cell called the decision itself with a
// hand-derived column and CLAIMED to bind the call site. It did not: a mutation
// replacing the argument with `false` survived. Driving the preflight needs a
// running manager with a recorded heartbeat endpoint, which only StartHeartbeat
// writes and which opens sockets — hence
// cluster.SetHeartbeatEndpointForTesting, the same shape as the package's
// existing SetGroupStateForTesting.
func runningAt9178(peer string) *cluster.Manager {
	m := &cluster.Manager{}
	m.SetHeartbeatEndpointForTesting("10.99.12.1", peer, "em0")
	return m
}

func deletionCandidate9178(fabIface, fabPeer string) *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		NodeID:            0,
		ClusterID:         1,
		PeerAddress:       "", // the deletion
		FabricInterface:   fabIface,
		FabricPeerAddress: fabPeer,
	}
	return cfg
}

func TestThePreflightPassesTheFabricColumn9178(t *testing.T) {
	running := runningAt9178("10.99.12.2")

	// WITH a fabric fallback the preflight must ALLOW the deletion. This is
	// the row a hard-coded `false` column breaks.
	if err := clusterControlEndpointCommitPreflight(running,
		deletionCandidate9178("fab0", "10.99.13.2")); err != nil {
		t.Errorf("a deletion WITH a fabric fallback must be allowed: %v", err)
	}

	// WITHOUT one it must REFUSE — so the column is demonstrably load-bearing
	// rather than a constant that happens to match.
	if err := clusterControlEndpointCommitPreflight(running,
		deletionCandidate9178("", "")); err == nil {
		t.Error("a deletion on a control-link-only cluster was allowed: no " +
			"heartbeat and no sync transport, which is the durable partition")
	}
}

// And end-to-end for the #8965 rows the preflight already owned, so this cell
// pins the whole gate rather than only the new arm.
func TestThePreflightStillRefusesAMove9178(t *testing.T) {
	running := runningAt9178("10.99.12.2")
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		NodeID: 0, ClusterID: 1,
		PeerAddress:       "10.99.12.9",
		FabricInterface:   "fab0",
		FabricPeerAddress: "10.99.13.2",
	}
	if err := clusterControlEndpointCommitPreflight(running, cfg); err == nil {
		t.Error("a live control-endpoint MOVE was allowed; a fabric fallback " +
			"does not license it (#8965)")
	}
}
