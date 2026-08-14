package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ownerlessXfrmFabricConfig is the #6691 round 10 reachable shape, shared by the
// round 11 guards: a fabric MEMBER with no `set interfaces` stanza whose netdev
// IS an xfrm device by kernel kind. Nothing but the fabric row speaks for that
// netdev, so its verdict is load-bearing — which is what makes it the case every
// consumer of the verdict has to be checked against.
func ownerlessXfrmFabricConfig(t *testing.T) *config.Config {
	t.Helper()
	return compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		// DELIBERATELY NO `set interfaces ge-0/0/0` — a member needs none.
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	)
}

// TestProtocolGateArmsForAnOwnerlessFabricVerdict is the #6691 round 11 guard
// for B1: the required-protocol gate must arm for a snapshot whose ONLY
// unbindable verdict is a fabric parent's.
//
// Round 10 introduced FabricSnapshot.ParentUnbindable and moved the protocol to
// 7 precisely because a v6 helper decodes the absent field to false and plans an
// AF_XDP binding on the netdev the control plane refused. The gate that exists
// to stop an under-version helper from staying ARMED on its previous-good image
// was written one round earlier and scans snap.Interfaces only, so the very
// verdict that motivated the bump was outside its scope: the snapshot goes out,
// the v6 helper rejects it on the exact-equality version check, the commit
// reports success, and the helper keeps forwarding a plan built on the refused
// netdev. The gate is not an extra safety net here — it is the whole mechanism
// that converts "silently stale" into "operator-visible abort".
//
// Measured at 8c011681c on this config: fab.ParentUnbindable = true, no row
// carries SecureTunnel, gate = nil.
//
// FAIL-ON-REVERT: scope the gate back to a scan of snap.Interfaces (any shape:
// the SecureTunnel flag, an exclusion class, a hand-written fabric loop that
// forgets a future producer) and this reds.
func TestProtocolGateArmsForAnOwnerlessFabricVerdict(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": 20, "ge-0-0-3": 21, "fab0": 22,
	})()
	defer stubXfrmNetdevs(t, "ge-0-0-0")()

	cfg := ownerlessXfrmFabricConfig(t)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	// PREMISE 1: the fabric carries the verdict. Without it there is nothing for
	// the gate to be scoped IN by and the test is vacuous.
	verdict := false
	for _, fab := range snap.Fabrics {
		if fab.ParentLinuxName == "ge-0-0-0" && fab.ParentUnbindable {
			verdict = true
		}
	}
	if !verdict {
		t.Fatalf("premise broken: no fabric row calls ge-0-0-0 unbindable (fabrics %+v)", snap.Fabrics)
	}

	// PREMISE 2: NO interface row carries the secure-tunnel flag. This is what
	// separates the new scope from the old one — with a flagged row present, the
	// pre-round-11 scan arms too and nothing is being distinguished.
	for _, iface := range snap.Interfaces {
		if iface.SecureTunnel {
			t.Fatalf("premise broken: row %q carries SecureTunnel, so the row scan "+
				"arms on its own and this test cannot see the fabric verdict", iface.Name)
		}
	}

	m := New()
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preV5SnapshotProtocolVersion})
	if err := m.ensureSecureTunnelProtocolLocked(snap); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
		t.Fatalf("gate = %v, want %v. The snapshot's only unbindable verdict rides "+
			"on FabricSnapshot.ParentUnbindable, which is exactly the field the v7 "+
			"bump exists for — a helper that predates it refuses this snapshot and "+
			"stays armed on a plan that binds the refused netdev",
			err, ErrSecureTunnelProtocolIncompatible)
	}
}

// TestEveryNetdevProducerIsEnumerated is the #6691 round 11 structural guard: a
// snapshot section that can put a netdev into the gated sets must be one the
// verdict enumeration reads.
//
// This is the guard round 10 did not have. Round 10 added a second producer of
// netdevs (the fabric loops) and taught the tally about it by hand; the
// required-protocol gate kept its own walk and went silent for the new verdict.
// A comment saying "a third contributor must join this tally too" is not a
// guard, and neither is a test that lists today's producers — both restate the
// thing that was forgotten.
//
// So it asserts the PROPERTY and DISCOVERS the producer, in that order:
//
//  1. Every netdev in the ingress-adjudication set has a verdict in
//     snapshotNetdevVotes. This is the invariant itself, and it does not care
//     what produced the netdev — a new snapshot section, or an existing one
//     emitting a netdev it holds no vote for (a fabric loop emitting its OVERLAY
//     alongside its parent is that second shape).
//  2. Zeroing each section in turn names WHICH input produced an uncovered
//     netdev, so the failure points at the producer instead of at a number.
//
// Keyed on the property — "this input decides what is emitted" — not on a field
// name, a type or the presence of a loop, any of which a producer can satisfy or
// dodge without changing what it does. The probe half sees only sections the
// fixture populates (Interfaces, Fabrics, Zones and Routes here); assertion 1
// needs no such luck, since it reads the emitted set directly.
//
// SCOPE: the ingress-adjudication set is the probe's observable. The RSS
// allowlist is derived from a *config.Config (UserspaceBoundLinuxInterfaces
// rebuilds its own snapshot), so it cannot be probed by mutating a snapshot;
// both sets are fed by the same two loops per producer, so a producer that
// reached only the allowlist would be a new shape, not a missed one.
func TestEveryNetdevProducerIsEnumerated(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": 20, "ge-0-0-3": 21, "fab0": 22,
	})()
	defer stubXfrmNetdevs(t)()

	cfg := ownerlessXfrmFabricConfig(t)
	base, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	emitted := func(snap *ConfigSnapshot) map[uint32]struct{} {
		out := make(map[uint32]struct{})
		for _, ifindex := range buildUserspaceIngressIfindexes(snap) {
			out[ifindex] = struct{}{}
		}
		return out
	}
	// The netdevs the enumeration has a verdict about, by ifindex — the key the
	// ingress set is built on.
	covered := func(snap *ConfigSnapshot) map[uint32]struct{} {
		out := make(map[uint32]struct{})
		for _, vote := range snapshotNetdevVotes(snap) {
			if vote.ifindex > 0 {
				out[uint32(vote.ifindex)] = struct{}{}
			}
		}
		return out
	}

	baseEmitted := emitted(base)
	baseCovered := covered(base)
	if len(baseEmitted) < 2 {
		t.Fatalf("premise broken: the fixture emits %d netdevs; the probe needs both "+
			"producers populated or it cannot tell a producer from an inert field", len(baseEmitted))
	}

	// PRIMARY: no netdev reaches the gated set without a verdict. This holds
	// whatever produced it — a new section, or an existing section emitting a
	// netdev it has no vote for (a fabric emitting its OVERLAY as well as its
	// parent would be that second shape, and a probe that only compared set
	// SIZES would call it covered).
	for ifindex := range baseEmitted {
		if _, ok := baseCovered[ifindex]; !ok {
			t.Errorf("ifindex %d is in the ingress-adjudication set with NO verdict in "+
				"snapshotNetdevVotes. It reaches the dataplane through a producer the "+
				"enumeration does not read, so its owner bucket is EMPTY — and a unanimity "+
				"rule over an empty bucket answers \"not refused\" (the #6691 round 9 "+
				"fail-open). The required-protocol gate is scoped by the same enumeration, "+
				"so it cannot see that netdev's verdict either", ifindex)
		}
	}

	// SECONDARY: name the producing SECTION, so the failure above points at the
	// input rather than at a number. Zeroing a section that changes what is
	// emitted identifies it as a producer; its netdevs must leave the coverage
	// with it.
	producers := make(map[string]struct{})
	v := reflect.ValueOf(base).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Type.Kind() != reflect.Slice || !v.Field(i).CanSet() {
			continue
		}
		probe := *base
		reflect.ValueOf(&probe).Elem().Field(i).Set(reflect.Zero(field.Type))

		probeEmitted := emitted(&probe)
		if len(probeEmitted) == len(baseEmitted) {
			continue // inert for the gated set: not a producer.
		}
		producers[field.Name] = struct{}{}
		probeCovered := covered(&probe)
		for ifindex := range baseEmitted {
			_, stillEmitted := probeEmitted[ifindex]
			_, stillCovered := probeCovered[ifindex]
			if !stillEmitted && stillCovered {
				t.Errorf("snapshot section %q emits ifindex %d into the ingress-adjudication "+
					"set, but removing the section leaves the netdev's verdict behind — so the "+
					"verdict belongs to something else and this producer contributes none of "+
					"its own. Every producer must declare its own verdict (snapshotNetdevVotes), "+
					"or the tally counts an owner that is not there and the protocol gate cannot "+
					"see what it ships", field.Name, ifindex)
			}
		}
	}

	// POSITIVE CONTROL. Without it a fixture that stopped populating a section
	// would make every check above vacuous and the test would pass by finding
	// nothing. Assert the probe FOUND the two producers this round knows about —
	// by identity, not by count, so a swap is not silently equal.
	for _, want := range []string{"Interfaces", "Fabrics"} {
		if _, ok := producers[want]; !ok {
			t.Errorf("the probe did not detect %q as a netdev producer (found %v). Either the "+
				"fixture stopped exercising it — which makes every assertion above vacuous — or "+
				"it no longer feeds the gated set", want, producers)
		}
	}

	// And the GATE moves with the same producer set: on this fixture the fabric
	// verdict is the only thing that needs the protocol, so removing that
	// producer must take the scope with it. This is the coupling round 10 broke,
	// asserted rather than commented.
	defer stubXfrmNetdevs(t, "ge-0-0-0")()
	armed, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot (xfrm): %v", err)
	}
	if !snapshotRequiresRefusalProtocol(armed) {
		t.Fatal("premise broken: the xfrm fixture does not require the protocol, so " +
			"dropping the producer cannot be observed")
	}
	noFabrics := *armed
	noFabrics.Fabrics = nil
	if snapshotRequiresRefusalProtocol(&noFabrics) {
		t.Error("the gate still requires the protocol with the fabric rows removed: its " +
			"scope is not derived from the contributors, so a producer can be added " +
			"without entering it")
	}
}

// TestFabricParentVerdictSurvivesACanonicalAlias is the #6691 round 11 guard for
// B3: two spellings of ONE device must not become two owners that disagree.
//
// LinuxIfName maps '/' to '-' and nothing else, so `gr-0/0/3` and `gr-0-0-3` are
// two authored names for one netdev. Both are legal: the fabric member MUST be
// slot-spelled with slashes for InterfaceSlot to resolve it to a node, while the
// interface stanza is a wildcard name the schema accepts in either spelling. The
// strict collision validator cannot object — it compares authored interface-map
// KEYS, and there is only one key here.
//
// Round 10 gave the fabric parent a vote computed from an EXACT map lookup
// (`cfg.Interfaces.Interfaces[parentName]`), so on this config the interface row
// votes unbindable (interface-level tunnel) and the fabric votes bindable (its
// lookup missed the stanza). The unanimity rule reads that disagreement as "not
// refused" and ADMITS the GRE device — a fail-open reachable from a config an
// operator can write, and one round 9 refused correctly because the fabric had
// no vote at all.
//
// Measured at 8c011681c: refusesName(gr-0-0-3) = false, ingress set contains 20.
//
// FAIL-ON-REVERT: return the parent-config lookup to an exact map hit, or let a
// fabric vote count while an interface row already owns the netdev, and this
// reds.
func TestFabricParentVerdictSurvivesACanonicalAlias(t *testing.T) {
	const (
		greIfindex = 20
		lanIfindex = 21
	)
	defer stubLinkSnapshot5619(t, map[string]int{
		"gr-0-0-3": greIfindex, "ge-0-0-3": lanIfindex, "fab0": 22,
	})()
	defer stubXfrmNetdevs(t)()

	cfg := compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		// The member is SLASH-spelled: InterfaceSlot needs that to map slot 0
		// to node 0 and resolve LocalFabricMember at all.
		"set interfaces fab0 fabric-options member-interfaces gr-0/0/3",
		// The stanza is DASH-spelled. Same netdev, different authored name.
		"set interfaces gr-0-0-3 tunnel source 10.0.0.1",
		"set interfaces gr-0-0-3 tunnel destination 10.0.0.2",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	// PREMISE 1: an interface row owns the netdev and calls it unbindable.
	owned := false
	for _, iface := range snap.Interfaces {
		if iface.LinuxName != "gr-0-0-3" || !userspaceOwnsItsNetdev(iface) {
			continue
		}
		owned = true
		if !userspaceUnbindableNetdev(iface) {
			t.Fatalf("premise broken: row %q owns gr-0-0-3 but is bindable, so there "+
				"is no refusal for an alias to defeat", iface.Name)
		}
	}
	if !owned {
		t.Fatal("premise broken: no interface row owns gr-0-0-3 — the dash-spelled " +
			"stanza did not produce a row, so this is the ownerless case, not the alias case")
	}

	// PREMISE 2: the fabric emits the SAME netdev under the slash spelling.
	emits := false
	for _, fab := range snap.Fabrics {
		if fab.ParentLinuxName == "gr-0-0-3" && fab.ParentIfindex == greIfindex {
			emits = true
		}
	}
	if !emits {
		t.Fatalf("premise broken: no fabric row resolves to gr-0-0-3/%d (fabrics %+v)",
			greIfindex, snap.Fabrics)
	}

	if got := buildUserspaceIngressIfindexes(snap); slices.Contains(got, uint32(greIfindex)) {
		t.Errorf("ingress-adjudication set = %v: it contains the GRE device's ifindex %d. "+
			"One device is being counted as two owners that disagree, and a disagreement "+
			"is read as an admission — so a netdev refused by the only row that describes "+
			"it is adjudicated anyway", got, greIfindex)
	}
	if got := UserspaceBoundLinuxInterfaces(cfg); slices.Contains(got, "gr-0-0-3") {
		t.Errorf("RSS/AF_XDP allowlist = %v: an entry is permission to reshape that "+
			"netdev's RSS table and bind an AF_XDP socket to it", got)
	}
	// NEGATIVE CONTROL: the LAN keeps its ifindex, so the guard is refusing the
	// aliased device rather than emptying the set.
	if got := buildUserspaceIngressIfindexes(snap); !slices.Contains(got, uint32(lanIfindex)) {
		t.Errorf("ingress-adjudication set = %v: the zoned LAN ifindex %d is missing", got, lanIfindex)
	}
}

// TestAFabricVoteCannotOverturnAnOwningRow pins the ROLE rule directly (#6691
// round 11), on a snapshot built by hand rather than compiled from a config.
//
// That is deliberate, and it is what makes this test worth having. The two ways
// production could put a disagreeing fabric vote next to an owning row — a
// canonical alias in the member's name, a fabric refresh re-sampling the kernel
// — are fixed at their sources, so no config reaches this state any more. The
// mutation matrix says as much: severing the abstain-when-owned rule while those
// two fixes are in place killed NOTHING, because the two owners now agree and
// unanimity gives the same answer either way.
//
// A rule that holds only because its inputs happen to agree is the round-10
// argument again ("production computes both from identical inputs") — true of
// the code and false of two reachable configs. So this drives the state itself:
// unbindable row, bindable fabric, one netdev. It also guards the snapshot as a
// WIRE object, since the Rust plane runs the mirror of this tally over bytes it
// did not compute; `fabric_vote_cannot_overturn_an_owning_row` drives the same
// shape there.
//
// FAIL-ON-REVERT: let a fabric vote count while an interface row owns the netdev
// (drop the netdevVoteAbstains branch in snapshotNetdevVotes) and this reds.
func TestAFabricVoteCannotOverturnAnOwningRow(t *testing.T) {
	const (
		memberIfindex = 20
		lanIfindex    = 21
	)
	member := InterfaceSnapshot{
		Name:      "ge-0/0/0",
		LinuxName: "ge-0-0-0",
		Ifindex:   memberIfindex,
		Zone:      "trust",
		RXQueues:  1,
		// The row's verdict: this device is a route-based IPsec tunnel.
		SecureTunnel: true,
	}
	snap := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			member,
			{Name: "ge-0/0/3", LinuxName: "ge-0-0-3", Ifindex: lanIfindex, Zone: "trust", RXQueues: 6},
		},
		Fabrics: []FabricSnapshot{{
			Name:            "fab0",
			ParentInterface: "ge-0/0/0",
			ParentLinuxName: "ge-0-0-0",
			ParentIfindex:   memberIfindex,
			// THE DISAGREEMENT: the fabric says the same device is bindable.
			ParentUnbindable: false,
		}},
	}

	// PREMISES: the row must own the netdev and refuse it, or there is no
	// verdict for the fabric vote to overturn.
	if !userspaceOwnsItsNetdev(member) || !userspaceUnbindableNetdev(member) {
		t.Fatalf("premise broken: the member row must own and refuse its netdev "+
			"(owns=%v unbindable=%v)", userspaceOwnsItsNetdev(member), userspaceUnbindableNetdev(member))
	}

	refused := buildUserspaceRefusedNetdevs(snap)
	if !refused.refusesName("ge-0-0-0") || !refused.refusesIfindex(memberIfindex) {
		t.Errorf("refusesName=%v refusesIfindex=%v, want both true. A fabric row voting "+
			"`bindable` was counted beside the only row that describes the device, and the "+
			"resulting DISAGREEMENT was read as an admission. Two owners of one device "+
			"differing is not evidence of bindability — it is evidence that one of them was "+
			"computed from the wrong input",
			refused.refusesName("ge-0-0-0"), refused.refusesIfindex(memberIfindex))
	}
	if got := buildUserspaceIngressIfindexes(snap); slices.Contains(got, uint32(memberIfindex)) {
		t.Errorf("ingress-adjudication set = %v: the fabric loop re-admitted the refused "+
			"netdev %d on its own vote", got, memberIfindex)
	}
	// NEGATIVE CONTROL: the LAN is untouched.
	if got := buildUserspaceIngressIfindexes(snap); !slices.Contains(got, uint32(lanIfindex)) {
		t.Errorf("ingress-adjudication set = %v: lost the LAN ifindex %d", got, lanIfindex)
	}
}

// TestFabricRefreshCannotMoveADeviceVerdict is the #6691 round 11 guard for B2:
// a fabric refresh carries MACs, not verdicts.
//
// buildSnapshot takes ONE kernel xfrm sample and judges the interface rows and
// the fabric parents against it (round 10's own invariant). SyncFabricState then
// rebuilds the fabric rows from a FRESH sample and writes them back over
// lastSnapshot.Fabrics, leaving the interface rows at the old sample — and the
// Rust plane mirrors the split, replacing snapshot.fabrics in place without
// replanning bindings (`update_fabrics`, server/handlers/mod.rs; replan_queues
// runs only from the apply path).
//
// Two consequences, and the second is why this is a blocker rather than a
// latency:
//
//   - The verdict changes with NO replan. The helper keeps the binding it
//     planned under the old verdict until something else triggers an apply.
//   - The Go ingress-adjudication map was installed at apply time from the OLD
//     sample, while the next partial republish (PublishRouteOverlaySnapshot, the
//     scheduler republish, the #5134 worker arm — all `next := *m.lastSnapshot`)
//     ships the NEW verdict and makes Rust replan. An ifindex in the ingress map
//     with no READY binding is drop_degraded_transit (BINDING_MISSING), which is
//     the unsafe direction by this package's own invariant.
//
// The refresh has no business deciding this: it re-resolves peer MACs for
// cross-chassis forwarding. A device-level binding verdict is a property of the
// APPLIED snapshot, taken once with the rows it must agree with, and it changes
// when a new snapshot is applied — which is also the only moment both planes
// recompute together.
//
// Measured at 8c011681c: ingress [20 21] before the refresh, [21] after.
//
// FAIL-ON-REVERT: let SyncFabricState ship a freshly sampled ParentUnbindable
// and this reds.
func TestFabricRefreshCannotMoveADeviceVerdict(t *testing.T) {
	const memberIfindex = 20

	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": memberIfindex, "ge-0-0-3": 21, "fab0": 22,
	})()

	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	var (
		mu       sync.Mutex
		requests []ControlRequest
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				continue
			}
			mu.Lock()
			requests = append(requests, req)
			mu.Unlock()
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{PID: 4321},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	// APPLY TIME: the member netdev is an ordinary NIC. One sample, both halves
	// judged against it.
	restoreXfrm := stubXfrmNetdevs(t)
	cfg := ownerlessXfrmFabricConfig(t)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 1, 0)
	if err != nil {
		restoreXfrm()
		t.Fatalf("buildSnapshot: %v", err)
	}
	restoreXfrm()

	before := buildUserspaceIngressIfindexes(snap)
	if !slices.Contains(before, uint32(memberIfindex)) {
		t.Fatalf("premise broken: ingress set %v does not carry the member ifindex %d "+
			"at apply time, so there is no admitted netdev for a refresh to move", before, memberIfindex)
	}

	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	m.lastSnapshot = snap
	m.generation = snap.Generation
	m.publishedSnapshot = snap.Generation

	// BETWEEN APPLIES: an xfrm device appears under the member's name. The
	// interface rows in lastSnapshot still describe the old kernel — nothing
	// re-derives them outside an apply.
	defer stubXfrmNetdevs(t, "ge-0-0-0")()

	m.SyncFabricState()

	after := buildUserspaceIngressIfindexes(m.lastSnapshot)
	if !slices.Equal(before, after) {
		t.Errorf("ingress-adjudication set moved across a fabric refresh: %v -> %v. "+
			"SyncFabricState re-sampled the kernel and replaced only the fabric rows, "+
			"so the snapshot now mixes fresh fabric evidence with apply-time interface "+
			"evidence — and the helper is not replanned, so the two planes disagree "+
			"about a netdev until something else triggers an apply", before, after)
	}

	// The refresh must still have HAPPENED: pinning the verdict must not be
	// implemented by skipping the update the peer MACs depend on.
	mu.Lock()
	defer mu.Unlock()
	sawUpdateFabrics := false
	for i := range requests {
		if requests[i].Type == "update_fabrics" {
			sawUpdateFabrics = true
		}
	}
	if !sawUpdateFabrics {
		t.Error("no update_fabrics was sent: the fabric refresh is what re-resolves " +
			"the cross-chassis peer MAC, and refusing to send it trades one defect for another")
	}
}
