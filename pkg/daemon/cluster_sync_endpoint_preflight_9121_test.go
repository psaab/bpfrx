package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9121: the third member of the #8965/#8987 partition family. Those two gate
// the HEARTBEAT pair; the config push rides the SYNC endpoint, and on a
// fabric-transport cluster those are not the same thing.
//
// Every cell here is at the DECISION level, not the message builder —
// controlEndpointDecision8965's own doc records why: the first version of that
// split exposed only the builder, so the cell asserted the text while "when to
// refuse at all" went unexercised and neutering the gate to `return nil` left
// it green.

func fabricOnly9121(iface, addr string) clusterTransportKey {
	return clusterTransportKey{FabricInterface: iface, FabricPeerAddress: addr}
}

func fabricCfg9121(cc *config.ClusterConfig) *config.Config {
	return &config.Config{Chassis: config.ChassisConfig{Cluster: cc}}
}

func TestFabricSyncEndpointMoveIsRefused9121(t *testing.T) {
	err := clusterSyncEndpointCommitPreflight(
		fabricOnly9121("fab0", "10.99.13.2"),
		fabricCfg9121(&config.ClusterConfig{
			ClusterID: 1, NodeID: 0,
			FabricInterface: "fab0", FabricPeerAddress: "10.99.14.2",
		}))
	if err == nil {
		t.Fatal("#9121: a live fabric-peer-address move was ACCEPTED. Applying it " +
			"restarts cluster comms on the new address before the config can be " +
			"pushed to the peer, which is still on the old one; QueueConfig no-ops " +
			"on a nil connection so the push fails SILENTLY and the pair is durably " +
			"partitioned.")
	}
}

// THE CELL THAT ESTABLISHES WHICH SET IS AUTHORITATIVE, and the reason this
// issue exists as a separate one rather than as a field added to #8965.
//
// #8965 and #8987 read the heartbeat pair. In control-link mode that is an
// EXACT proxy for the sync endpoint, and control-link mode is the only shape
// the shipped fixtures configure — so nothing measured the divergence. In
// fabric-transport mode the heartbeat does not start at all
// (daemon_ha_sync.go gates it on ControlInterface != "" && PeerAddress != ""),
// so both gates see an empty running value, take their have=="" arm, and return
// nil on the very commit that partitions the pair. The gate misses TWICE.
//
// This cell asserts the divergence directly, so a future change that "unifies"
// the family back onto the heartbeat pair reds here with the reason attached.
func TestTheHeartbeatPairIsNotTheAuthoritativeSet9121(t *testing.T) {
	// A fabric-transport cluster: no control link, so no heartbeat, so both
	// sibling gates have an empty running value to compare against.
	if err := controlEndpointDecision8965("", "10.99.14.2", false); err != nil {
		t.Fatalf("fixture: #8965 is expected to no-op on an empty running "+
			"heartbeat address; it did not (%v), so this cell is not measuring "+
			"what it claims", err)
	}
	if err := controlInterfaceDecision8987("", "fab0"); err != nil {
		t.Fatalf("fixture: #8987 is expected to no-op on an empty running "+
			"heartbeat interface; it did not (%v)", err)
	}
	// Same commit, the authoritative set: REFUSED.
	err := clusterSyncEndpointCommitPreflight(
		fabricOnly9121("fab0", "10.99.13.2"),
		fabricCfg9121(&config.ClusterConfig{
			ClusterID: 1, NodeID: 0,
			FabricInterface: "fab0", FabricPeerAddress: "10.99.14.2",
		}))
	if err == nil {
		t.Error("#9121: on a fabric-transport cluster both sibling gates no-op " +
			"(no heartbeat -> empty running value) and this one must not. The " +
			"authoritative set for this family is clusterSyncTransport's SELECTED " +
			"PAIR — what carries the config push — not the heartbeat pair, which " +
			"is only a proxy for it and only in control-link mode.")
	}
}

// THE OVER-GATE REFUTATION. #9121's own suggested fix direction said to compare
// "active.FabricPeerAddress / active.Fabric1PeerAddress". Including fab1 would
// be a FALSE REJECTION: fab1 is a REDUNDANT secondary sync path
// (cluster/sync_conn.go: "secondary fabric listen failed, using primary only";
// NewDualSessionSync takes it as a second dial target beside fab0), so a
// fab1-only change restarts comms — clusterTransportKey includes it, correctly,
// for THAT question — while the push still lands over the unchanged fab0.
//
// This is why the gated set had to be DERIVED from the mechanism that selects
// the transport rather than copied from the one that decides the restart.
func TestFabric1IsNotGated9121(t *testing.T) {
	active := clusterTransportKey{
		FabricInterface: "fab0", FabricPeerAddress: "10.99.13.2",
		Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.15.2",
	}
	err := clusterSyncEndpointCommitPreflight(active, fabricCfg9121(&config.ClusterConfig{
		ClusterID: 1, NodeID: 0,
		FabricInterface: "fab0", FabricPeerAddress: "10.99.13.2",
		Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.16.2", // fab1 moved
	}))
	if err != nil {
		t.Errorf("#9121: a fab1-ONLY change was refused: %v.\nfab1 is the "+
			"redundant secondary sync path — the push still lands over the "+
			"unchanged fab0, so this commit does not partition anything and "+
			"refusing it is a false rejection. Gating it was the issue's own "+
			"suggested fix direction; the set has to come from "+
			"clusterSyncTransport, which never selects fab1.", err)
	}
	// The gate is live on this fixture, so the no-op above is a measurement and
	// not a silence: move fab0 instead and it must refuse.
	moved := clusterSyncEndpointCommitPreflight(active, fabricCfg9121(&config.ClusterConfig{
		ClusterID: 1, NodeID: 0,
		FabricInterface: "fab0", FabricPeerAddress: "10.99.14.2",
		Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.15.2",
	}))
	if moved == nil {
		t.Error("#9121: the gate did not fire on a fab0 move from the SAME " +
			"fixture, so the fab1 no-op above proves nothing")
	}
}

// A shape #9121 did not name and no gate held: adding a control link to a
// running fabric-transport cluster moves sync from fabric to control-link while
// the peer is still on the fabric. Same durable partition, by a transport-TYPE
// change rather than an address change. Comparing resolved ENDPOINTS rather
// than fields covers it without a fourth gate.
func TestTransportModeSwitchIsRefused9121(t *testing.T) {
	err := clusterSyncEndpointCommitPreflight(
		fabricOnly9121("fab0", "10.99.13.2"),
		fabricCfg9121(&config.ClusterConfig{
			ClusterID: 1, NodeID: 0,
			ControlInterface: "em0", PeerAddress: "10.99.12.2",
			FabricInterface: "fab0", FabricPeerAddress: "10.99.13.2",
		}))
	if err == nil {
		t.Error("#9121: a commit ADDING a control link to a running " +
			"fabric-transport cluster was accepted. clusterSyncTransport then " +
			"selects the control link while the peer still syncs over the fabric, " +
			"which is the same partition the address gates exist to prevent. " +
			"#8965 cannot see it either (its running heartbeat address is empty).")
	}
}

// PEER-SYNC IS SAFE — the risk a gate on this path actually carries. A refusal
// here stops the pair converging, which is worse than the defect.
//
// MEASURED per arm, not inherited. `fabric-peer-address` is safe for #8965's
// reason: it sits INSIDE `groups node0` / `groups node1` in the shipped cluster
// config (docs/ha-cluster-userspace.conf lines 10 and 39, beside the per-node
// `peer-address`), so a synced text compiles to the LOCAL node's own value.
// `fabric-interface` is safe for #8987's reason instead: it is auto-derived
// from the local fabric member (compiler_derivations.go keys on
// SlotToNodeID(slot) == cc.NodeID), so both nodes carry the identical name.
func TestPeerSyncedFabricTextIsNotRefused9121(t *testing.T) {
	active := fabricOnly9121("fab0", "10.99.13.2")
	same := fabricCfg9121(&config.ClusterConfig{
		ClusterID: 1, NodeID: 0,
		FabricInterface: "fab0", FabricPeerAddress: "10.99.13.2",
	})
	if err := clusterSyncEndpointCommitPreflight(active, same); err != nil {
		t.Errorf("#9121: a peer-synced config resolving to the SAME sync endpoint "+
			"was refused: %v. Refusing a legitimate sync is the new defect this "+
			"gate had to avoid, not a conservative default — it would stop the "+
			"pair converging.", err)
	}
	// Liveness control: same fixture, a genuine move must refuse.
	if err := clusterSyncEndpointCommitPreflight(active, fabricCfg9121(&config.ClusterConfig{
		ClusterID: 1, NodeID: 0,
		FabricInterface: "fab0", FabricPeerAddress: "10.99.14.2",
	})); err == nil {
		t.Error("#9121: the gate did not fire on a genuine move, so the peer-sync " +
			"no-op above proves nothing about peer-sync")
	}
}

// A control-link-to-control-link move stays with #8965/#8987, which run FIRST
// at every call site and produce the specific text for it. Pinned so that
// branch cannot be quietly dropped into a second, differently-worded refusal of
// the same commit.
func TestControlLinkMovesStayWithTheSiblings9121(t *testing.T) {
	err := clusterSyncEndpointCommitPreflight(
		clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.12.2"},
		fabricCfg9121(&config.ClusterConfig{
			ClusterID: 1, NodeID: 0,
			ControlInterface: "em1", PeerAddress: "10.99.20.2",
		}))
	if err != nil {
		t.Errorf("#9121: a control-link move was refused HERE as well as by "+
			"#8965/#8987, which run first: %v. Two refusals in different words "+
			"for one commit is worse than one.", err)
	}
}

// Boot: applyConfig runs before startClusterComms, so the active key is still
// zero — the same guard step 20 relies on. A gate that fired there would refuse
// every boot commit on a fabric cluster.
func TestNeverStartedCommsAreNotGated9121(t *testing.T) {
	if err := clusterSyncEndpointCommitPreflight(clusterTransportKey{},
		fabricCfg9121(&config.ClusterConfig{
			ClusterID: 1, NodeID: 0,
			FabricInterface: "fab0", FabricPeerAddress: "10.99.13.2",
		})); err != nil {
		t.Errorf("#9121: the gate fired with no comms started (%v). The boot "+
			"applyConfig runs before startClusterComms, so this would refuse every "+
			"boot commit on a fabric-transport cluster.", err)
	}
}

func TestSyncEndpointRefusalNamesTheProcedure9121(t *testing.T) {
	err := syncEndpointDecision9121(
		syncEndpoint9121{"fab0", "10.99.13.2", "fabric"},
		syncEndpoint9121{"fab0", "10.99.14.2", "fabric"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{
		"10.99.13.2", "10.99.14.2", "fab0", "fabric",
		"BOTH nodes",  // the actual remedy
		"restart",     // ... and what to do after
		"Do NOT",      // the workaround that reproduces the defect
		"partitioned", // the consequence, so the operator can weigh it
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("#9121: the refusal must contain %q. An operator told only "+
				"'no' finds the way around it, and the way around it — committing "+
				"on each node separately while both run — is the same partition by "+
				"hand.\ngot: %s", want, msg)
		}
	}
}

// ALL THREE APPLY PATHS, as #8987 item 4 requires: commitAndApply, syncAndApply
// and commitConfirmedAndApply all reach applyConfigLocked, and a gate wired at
// one is the partial-fix shape on a row whose remaining half is silent. Driving
// all three needs a live daemon, so the WIRING is bound structurally.
func TestSyncEndpointGateIsWiredAtEveryApplyPath9121(t *testing.T) {
	const file = "daemon_apply_commit.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
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
			case "clusterSyncEndpointCommitPreflight":
				got[fn.Name.Name]++
			case "clusterControlInterfaceCommitPreflight":
				sibling[fn.Name.Name]++
			}
			return true
		})
	}
	// The SIBLING is the control: #8987 is known-good and wired at all three, so
	// it tells us the three paths are still where we think they are. Without it
	// this cell cannot tell "the sync gate is missing from syncAndApply" from
	// "syncAndApply was renamed".
	if len(sibling) != 3 {
		t.Fatalf("#9121: the #8987 interface gate is wired at %d functions, not 3 "+
			"(%v). The apply paths moved — fix this guard's model of them before "+
			"trusting its verdict about the sync gate.", len(sibling), sibling)
	}
	for path := range sibling {
		if got[path] == 0 {
			t.Errorf("#9121: %s runs the #8987 gate but not the SYNC-ENDPOINT "+
				"gate. On a fabric-transport cluster #8965 and #8987 both no-op, so "+
				"this is the only gate holding that shape; wiring it at some paths "+
				"leaves the others silently partitioning.", path)
		}
	}
}
