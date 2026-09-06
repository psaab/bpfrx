package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #8987: a live control-INTERFACE move has the same partition shape as the
// peer-ADDRESS move #8965 gated, and was left uncovered.
//
// Applying it restarts this node's cluster comms on the NEW interface and only
// then pushes the config to a peer still reachable only over the OLD one. The
// push no-ops silently (QueueConfig on a nil connection), the #5863 reconciler
// returns early on !syncPeerConnected, that flag is set in exactly one place
// (the session-sync connect callback) so nothing bootstraps a mismatch in which
// nothing is connected, and both nodes are durably configured -- so retry and
// reboot REPRODUCE the split rather than repair it.
//
// #8965 recorded why it stopped at the address: the manager kept no RUNNING
// value for control-interface, so a gate would have compared config to config
// and could not tell "the operator is changing it" from "this is what it
// already was". Closing that needed plumbing first, and the cells below bind
// the plumbing as carefully as the decision -- because a gate reading the WRONG
// running value refuses and allows in all the same places a correct one does,
// right up until the case that matters.

func clusteredIfaceCfg8987(iface string) *config.Config {
	c := &config.Config{}
	c.Chassis.Cluster = &config.ClusterConfig{
		NodeID:           0,
		ClusterID:        1,
		PeerAddress:      "10.99.12.2",
		ControlInterface: iface,
	}
	return c
}

func TestControlInterfaceMoveIsRefused8987(t *testing.T) {
	t.Run("no running manager is a no-op", func(t *testing.T) {
		if err := clusterControlInterfaceCommitPreflight(nil, clusteredIfaceCfg8987("em1")); err != nil {
			t.Errorf("with no running cluster this gate must not fire: %v", err)
		}
	})

	t.Run("candidate not clustered is a no-op", func(t *testing.T) {
		if err := clusterControlInterfaceCommitPreflight(nil, &config.Config{}); err != nil {
			t.Errorf("a non-clustered candidate belongs to the topology gate: %v", err)
		}
	})

	// THE DECISION ITSELF. #8965's first version exposed only the message
	// builder, so neutering the gate to `return nil` left its cell green. This
	// seam is the decision, so that mutation reds.
	for _, tc := range []struct {
		name, have, want string
		refuse           bool
	}{
		{"a real move is refused", "em0", "em1", true},
		{"unchanged is allowed", "em0", "em0", false},
		{"no running interface yet", "", "em1", false},
		{"candidate leaves it unset", "em0", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := controlInterfaceDecision8987(tc.have, tc.want)
			if tc.refuse && err == nil {
				t.Errorf("have=%q want=%q must be REFUSED: applying it restarts "+
					"comms on the new interface before the peer can be told (#8987)",
					tc.have, tc.want)
			}
			if !tc.refuse && err != nil {
				t.Errorf("have=%q want=%q is not a live move and must be allowed: %v",
					tc.have, tc.want, err)
			}
		})
	}
}

// The running value must come from the HEARTBEAT, not from the config.
//
// This is the cell that distinguishes a correct gate from the plausible wrong
// one, and it is the reason #8965 refused to ship this half rather than
// guessing. Manager.controlInterface is ALSO an interface name and is right
// there -- but UpdateConfig overwrites it on every config apply, so a gate
// reading it compares config to config. That gate would pass every case in
// TestControlInterfaceMoveIsRefused8987 above, because those drive the decision
// function directly and never ask where `have` came from.
func TestRunningControlInterfaceIsTheHeartbeatsNotTheConfigs8987(t *testing.T) {
	m := cluster.NewManager(0, 1)

	// The heartbeat is running on em0.
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)
	if got := m.HeartbeatControlInterface(); got != "em0" {
		t.Fatalf("precondition: running control interface = %q, want em0", got)
	}

	// A config apply now names a DIFFERENT interface. This is exactly the
	// moment the preflight runs, and UpdateConfig is what moves the config-side
	// field underneath it.
	m.UpdateConfig(&config.ClusterConfig{
		NodeID: 0, ClusterID: 1, ControlInterface: "em1", PeerAddress: "10.99.12.2",
	})

	if got := m.HeartbeatControlInterface(); got != "em0" {
		t.Errorf("#8987: the running control interface became %q after a config "+
			"apply. It must stay em0 — the heartbeat is still bound there. A gate "+
			"reading the config-tracking field compares config to config, cannot "+
			"tell an operator's change from the value it already had, and is the "+
			"specific mistake #8965 declined to ship.", got)
	}
	// And the gate built on it must still refuse the move.
	if err := controlInterfaceDecision8987(m.HeartbeatControlInterface(), "em1"); err == nil {
		t.Error("#8987: the move em0 -> em1 was allowed while the heartbeat is " +
			"still on em0 — this is the partition the gate exists to prevent")
	}
}

// The PREFLIGHT — not the decision function — must read the heartbeat's value.
//
// This cell exists because the obvious version of the one above does NOT catch
// the mistake it describes. That one asks Manager for both values and then
// calls controlInterfaceDecision8987 itself, so it proves the ACCESSOR is right
// and the DECISION is right while never exercising the wiring between them.
// Swapping the preflight to read the config-tracking field leaves it green — a
// mutant that survived until this cell was added, and precisely the
// "seam that bypasses the thing under test" #8965's own split warns about.
//
// So: drive the real preflight, with a real Manager whose running interface and
// config-tracked interface DISAGREE. That disagreement is the whole test; it is
// also the exact live state at commit time, when UpdateConfig has taken the
// candidate's value but the heartbeat is still bound where it was.
func TestThePreflightReadsTheRunningInterfaceNotTheConfigured8987(t *testing.T) {
	m := cluster.NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)

	// Move the CONFIG-tracked field to the candidate's value, leaving the
	// heartbeat on em0. A gate reading the config field now sees em1 == em1.
	m.UpdateConfig(&config.ClusterConfig{
		NodeID: 0, ClusterID: 1, ControlInterface: "em1", PeerAddress: "10.99.12.2",
	})

	if err := clusterControlInterfaceCommitPreflight(m, clusteredIfaceCfg8987("em1")); err == nil {
		t.Error("#8987: the preflight ALLOWED a move to em1 while the heartbeat is " +
			"still bound to em0. It is reading a config-tracked value, not the " +
			"running one, so it compares the candidate against itself and can " +
			"never see a move — the exact gate #8965 declined to ship, and it " +
			"passes every decision-level cell.")
	}

	// Control: with the heartbeat and the candidate agreeing, the same preflight
	// must NOT fire — otherwise the assertion above is satisfied by a gate that
	// simply always refuses.
	if err := clusterControlInterfaceCommitPreflight(m, clusteredIfaceCfg8987("em0")); err != nil {
		t.Errorf("#8987: the preflight refused a candidate naming the interface the "+
			"heartbeat is already on: %v", err)
	}
}

// A restart must carry the interface with it, or the gate goes blind exactly
// when the cluster has just re-bound (the #7257 VRF-rebind path).
func TestHeartbeatRestartCarriesTheControlInterface8987(t *testing.T) {
	m := cluster.NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat reported nothing running")
	}
	if got := m.HeartbeatControlInterface(); got != "em0" {
		t.Errorf("#8987: after a heartbeat restart the running control interface "+
			"is %q, want em0. A restart that drops it leaves the gate comparing "+
			"against \"\", which its own unset arm treats as 'nothing to strand' — "+
			"so the move would be silently ALLOWED right after a rebind.", got)
	}
}

// PEER-SYNC MUST NOT BE REFUSED, and the reason is measured rather than
// inherited from #8965.
//
// #8965 is safe on the sync path because PeerAddress is PER-NODE: each node's
// config names the other's address, so a synced text compiles to the local
// node's own value. That argument does NOT transfer, and assuming it did was
// the trap. control-interface is safe for a different and stronger reason: in
// the shipped cluster config (docs/ha-cluster-userspace.conf) `peer-address`
// sits INSIDE `groups node0` / `groups node1` while `control-interface em0`
// sits OUTSIDE them — it is ONE SHARED VALUE, so a synced text carries the
// identical string and the comparison is trivially equal.
func TestPeerSyncedTextDoesNotTripTheInterfaceGate8987(t *testing.T) {
	const running = "em0"
	// A peer-synced text names the same shared interface.
	if err := controlInterfaceDecision8987(running, "em0"); err != nil {
		t.Errorf("#8987: a peer-synced config carrying the SAME shared "+
			"control-interface was refused: %v. Refusing a legitimate sync is the "+
			"new defect this gate had to avoid, not a conservative default — it "+
			"would stop the pair converging.", err)
	}
	// Sanity: the gate is live, so the above is not passing because it never fires.
	if err := controlInterfaceDecision8987(running, "em1"); err == nil {
		t.Error("#8987: the gate did not fire on a genuine move, so the no-op " +
			"assertion above proves nothing about peer-sync")
	}
}

func TestControlInterfaceRefusalNamesTheProcedure8987(t *testing.T) {
	err := controlInterfaceDecision8987("em0", "em1")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{
		"em0", "em1",
		"BOTH nodes",  // the actual remedy
		"restart",     // ... and what to do after
		"Do NOT",      // the workaround that reproduces the defect
		"partitioned", // the consequence, so the operator can weigh it
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("#8987: the refusal must contain %q. An operator told only "+
				"'no' finds the way around it, and the way around it — committing "+
				"on each node separately while both run — is the same partition by "+
				"hand.\ngot: %s", want, msg)
		}
	}
}

// ALL THREE APPLY PATHS. #8987 lists this explicitly: commitAndApply,
// syncAndApply and commitConfirmedAndApply all reach applyConfigLocked, and a
// gate wired at one is the partial-fix shape on a row whose remaining half is
// silent. Driving all three needs a live daemon, so the WIRING is bound
// structurally — the half a behavioural test could not reach anyway.
func TestControlInterfaceGateIsWiredAtEveryApplyPath8987(t *testing.T) {
	const file = "daemon_apply_commit.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	// Count call sites per enclosing function so a gate wired twice in one path
	// cannot stand in for a missing one in another.
	got := map[string]int{}
	sibling := map[string]int{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "clusterControlInterfaceCommitPreflight":
				got[fn.Name.Name]++
			case "clusterControlEndpointCommitPreflight":
				sibling[fn.Name.Name]++
			}
			return true
		})
	}
	// The SIBLING is the control: #8965 is known-good and wired at all three, so
	// it tells us the three paths are still where we think they are. Without it
	// this cell cannot tell "the interface gate is missing from syncAndApply"
	// from "syncAndApply was renamed".
	if len(sibling) != 3 {
		t.Fatalf("#8987: the #8965 address gate is wired at %d functions, not 3 "+
			"(%v). The apply paths moved — fix this guard's model of them before "+
			"trusting its verdict about the interface gate.", len(sibling), sibling)
	}
	for path := range sibling {
		if got[path] == 0 {
			t.Errorf("#8987: %s runs the #8965 ADDRESS gate but not the INTERFACE "+
				"gate. Both halves strand the peer identically; a gate at one path "+
				"is the partial-fix shape on a row whose remaining half is silent.",
				path)
		}
	}
	for path := range got {
		if sibling[path] == 0 {
			t.Errorf("#8987: %s runs the interface gate but not its address "+
				"sibling — the two must stay wired together", path)
		}
	}
}
