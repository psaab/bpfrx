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
//
// extra appends further `set` lines for a caller that needs a SECOND shape
// beside this one (#6691 round 12: the enumeration guard needs a VLAN child, the
// one contributor that legitimately emits a netdev it holds no verdict for).
// Callers that pass none get the round-11 fixture unchanged.
func ownerlessXfrmFabricConfig(t *testing.T, extra ...string) *config.Config {
	t.Helper()
	return compileForTest5619(t, append([]string{
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		// DELIBERATELY NO `set interfaces ge-0/0/0` — a member needs none.
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	}, extra...)...)
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
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
	if err := m.ensureSecureTunnelProtocolLocked(snap); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
		t.Fatalf("gate = %v, want %v. The snapshot's only unbindable verdict rides "+
			"on FabricSnapshot.ParentUnbindable, which is exactly the field the v7 "+
			"bump exists for — a helper that predates it refuses this snapshot and "+
			"stays armed on a plan that binds the refused netdev",
			err, ErrSecureTunnelProtocolIncompatible)
	}
}

// TestProtocolGateDoesNotArmWhenARowOwnsTheFabricParent is the OTHER direction
// of round 11's protocol-gate narrowing (#6691 round 12).
//
// snapshotNetdevVotes declares a fabric verdict as needing the wire only where
// it decides something: `verdictNeedsProtocol: fab.ParentUnbindable && !hasOwner`.
// TestProtocolGateArmsForAnOwnerlessFabricVerdict above covers `!hasOwner` ->
// ARMS. Nothing covered `hasOwner` -> DOES NOT ARM: measured at 29b9b84c0,
// dropping `&& !hasOwner` left BOTH suites green, so the conjunct was carried by
// its comment alone.
//
// The narrowing is sound, and stating why is the point of the test rather than a
// caveat on it. With an owning row present the helper reaches the same verdict
// from the row's own PRE-v7 fields — here the row's `tunnel` stanza, which a v6
// helper reads and judges with the same exclusion classes — so the v7 field
// decides nothing for this netdev. Arming anyway would abort a commit over a
// difference that does not exist. That makes the mutation's direction
// CONSERVATIVE (a spurious commit abort against an older helper, not a
// fail-open), which is why this is a missing test rather than a missing guard.
// An unbound conjunct is still a conjunct the next refactor deletes.
//
// FAIL-ON-REVERT: drop `&& !hasOwner` from verdictNeedsProtocol and this reds.
func TestProtocolGateDoesNotArmWhenARowOwnsTheFabricParent(t *testing.T) {
	const greIfindex = 20
	defer stubLinkSnapshot5619(t, map[string]int{
		"gr-0-0-3": greIfindex, "ge-0-0-3": 21, "fab0": 22,
	})()
	// No live xfrm device: the fabric parent is unbindable on its TUNNEL stanza,
	// a pre-v5 field, not on the kernel-kind evidence only Go can sample.
	defer stubXfrmNetdevs(t)()

	cfg := compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces gr-0/0/3",
		// THE OWNING ROW: the member has an interface stanza, so a row speaks
		// for the netdev and the fabric is not the only voice.
		"set interfaces gr-0/0/3 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/3 tunnel destination 10.0.0.2",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	// PREMISE 1: the fabric row DOES call the parent unbindable. Without it the
	// dropped conjunct changes nothing and the test passes for the wrong reason.
	verdict := false
	for _, fab := range snap.Fabrics {
		if fab.ParentLinuxName == "gr-0-0-3" && fab.ParentUnbindable {
			verdict = true
		}
	}
	if !verdict {
		t.Fatalf("premise broken: no fabric row calls gr-0-0-3 unbindable (fabrics %+v), so "+
			"`fab.ParentUnbindable` is already false and dropping `&& !hasOwner` would be "+
			"unobservable here", snap.Fabrics)
	}

	// PREMISE 2: an interface row OWNS that netdev — this is the hasOwner arm,
	// not the ownerless one the sibling test covers.
	owned := false
	for _, iface := range snap.Interfaces {
		if iface.LinuxName == "gr-0-0-3" && userspaceOwnsItsNetdev(iface) {
			owned = true
		}
	}
	if !owned {
		t.Fatal("premise broken: no interface row owns gr-0-0-3, so this is the ownerless " +
			"case and the narrowing under test does not apply")
	}

	// PREMISE 3: no row carries the v5 secure-tunnel flag, which would arm the
	// gate on its own and mask what the fabric's vote contributes.
	for _, iface := range snap.Interfaces {
		if iface.SecureTunnel {
			t.Fatalf("premise broken: row %q carries SecureTunnel, so the gate arms from the "+
				"row scan regardless of the fabric's verdictNeedsProtocol", iface.Name)
		}
	}

	if snapshotRequiresRefusalProtocol(snap) {
		t.Errorf("snapshotRequiresRefusalProtocol = true. An owning row is present, so the "+
			"helper computes this netdev's refusal from the row's own pre-v7 `tunnel` field and "+
			"the v7 fabric flag decides nothing — requiring the protocol here aborts a commit "+
			"against a helper that would have planned the identical binding (fabrics %+v)",
			snap.Fabrics)
	}

	m := New()
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
	if err := m.ensureSecureTunnelProtocolLocked(snap); err != nil {
		t.Errorf("gate = %v, want nil: an under-version helper must still accept a snapshot "+
			"whose only unbindable fabric parent is one an interface row already speaks for", err)
	}

	// NEGATIVE CONTROL: the same gate DOES arm once the owner is taken away, so
	// the nil above is the narrowing and not a dead gate.
	ownerless := *snap
	ownerless.Interfaces = nil
	if !snapshotRequiresRefusalProtocol(&ownerless) {
		t.Error("with the interface rows removed the gate still does not require the protocol: " +
			"the fabric's verdict is not reaching verdictNeedsProtocol at all, so the assertion " +
			"above cannot distinguish the narrowing from an inert gate")
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
//  1. Every netdev in the ingress-adjudication set has a COUNTED verdict in
//     snapshotNetdevVotes, or is a redirect whose verdict lives on its target.
//     This is the invariant itself, and it does not care what produced the
//     netdev — a new snapshot section, or an existing one emitting a netdev it
//     holds no vote for (a fabric loop emitting its OVERLAY alongside its parent
//     is that second shape).
//  2. Zeroing each section in turn names WHICH input produced an uncovered
//     netdev, so the failure points at the producer instead of at a number.
//
// COUNTED, NOT MERELY PRESENT (#6691 round 12, and this is the correctness half
// of assertion 1). Round 11 collected `vote.ifindex` for EVERY vote and never
// looked at `vote.role` — but buildUserspaceRefusedNetdevs skips
// netdevVoteAbstains outright, so an abstaining vote made a netdev "covered"
// while contributing nothing to the tally. That is the EMPTY BUCKET this test's
// own failure text names, so the guard could not see the state it was written
// for: measured at 29b9b84c0, forcing the fabric vote to netdevVoteAbstains (the
// vote object still present, only the role changed) left this test PASSING and
// redded only TestOwnerlessFabricParentIsRefused. Deleting the vote outright DID
// red it — so round 11 bound "a producer is absent from the list" rather than "a
// producer casts no counted verdict", and the second is the defect. It is a live
// trap rather than a hypothetical: netdevVoteAbstains is iota 0, so a third
// contributor registered with a zero-value role lands in the hole by default.
//
// A BARE ROLE FILTER WOULD BE WRONG IN THE OTHER DIRECTION, which is why the
// predicate has a second arm. A VLAN child abstains legitimately AND emits its
// own ifindex: it binds the PARENT (#2917 userspaceBindTargetNetdev), so the
// refusal question about it is answered on the parent — buildUserspaceIngressIfindexes
// asks refusesIfindex(iface.ParentIfindex), never the child's own. Excluding
// every abstain would red this guard at head on the child's ifindex. So the
// honest predicate is "every emitted netdev has a counted verdict, OR is a
// redirect whose target has one", and both arms are asserted to FIRE below so
// neither can go vacuous.
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
//
// THE EMPTY-REFUSED-SET ADDENDUM (#7021), which had been left open. The question
// was what this guard asserts when the refused set is DEGENERATE — the shape in
// which a coverage guard usually goes quietly vacuous. It does not, and the
// answer is measured rather than argued.
//
// Forcing buildUserspaceRefusedNetdevs to return an empty set reds TEN
// top-level tests. Re-measured at fb6b0bc93 by making the function return
// userspaceRefusedNetdevs{} for any non-nil snapshot:
//
//	TestAFabricVoteCannotOverturnAnOwningRow
//	TestAliasTableRefusesOnAReachablePlainSibling
//	TestFabricLoopCannotReadmitARefusedMember
//	TestFabricParentVerdictSurvivesACanonicalAlias
//	TestOwnerlessFabricParentIsRefused
//	TestParentRedirectCannotReadmitTheExcludedXfrmi
//	TestPlainUnitKeepsItsOwnIfindexUnderARefusedParent
//	TestSkewedFabricSampleKeepsIngressAndAllowlistAgreed
//	TestSkewedParentSampleKeepsTheChildOutOfAdjudication
//	TestUserspaceBoundLinuxInterfaces_MatchesBindTargetSSOT
//
// And THIS guard cannot go vacuous on a degenerate snapshot either, by three
// separate constructions rather than by one:
//
//	len(baseEmitted) < 2   is a t.Fatalf PREMISE, not a skip, so a fixture that
//	                       stops emitting fails instead of passing quietly.
//	excused == 0           fires if the fixture loses its redirect shape.
//	fallbackOnly == 0      fires if it loses its ownerless-fabric shape.
//
// So the empty case is guarded, and what was missing was only the write-up.
// Stated plainly: an empty refused set is not a state this guard tolerates
// silently — it is a state ten other tests already refuse, and the two arms
// below refuse a fixture that has drifted into it.
func TestEveryNetdevProducerIsEnumerated(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": 20, "ge-0-0-3": 21, "fab0": 22,
		"ge-0-0-4": 24, "ge-0-0-4.100": 25,
	})()
	defer stubXfrmNetdevs(t)()

	// The ownerless fabric member supplies a netdev whose ONLY counted verdict
	// is the fabric's fallback vote; the VLAN child on ge-0/0/4 supplies a
	// netdev that is emitted with NO counted verdict of its own and is correct.
	// Both shapes are required — one arm of the predicate each — and both are
	// asserted to have fired at the end.
	cfg := ownerlessXfrmFabricConfig(t,
		"set interfaces ge-0/0/4 vlan-tagging",
		"set interfaces ge-0/0/4 unit 100 vlan-id 100 family inet address 10.0.11.1/24",
		"set security zones security-zone trust interfaces ge-0/0/4.100",
	)
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
	// The netdevs the enumeration casts a COUNTED verdict about, split by role.
	// The ROLE filter is netdevVote.counted, the same method
	// buildUserspaceRefusedNetdevs applies, so the role axis of "counted here"
	// and "tallied there" cannot drift — narrowing which roles the tally counts
	// narrows this probe too, and the assertions below go red instead of
	// staying silent. Scope: the ROLE axis only. The `ifindex > 0` test below
	// is this probe's own literal, and production additionally keys its buckets
	// on `name != ""`; neither of those axes is single-sourced here.
	countedVotes := func(snap *ConfigSnapshot) (all, fallback map[uint32]int) {
		all = make(map[uint32]int)
		fallback = make(map[uint32]int)
		for _, vote := range snapshotNetdevVotes(snap) {
			if !vote.counted() || vote.ifindex <= 0 {
				continue
			}
			all[uint32(vote.ifindex)]++
			if vote.role == netdevVoteFallback {
				fallback[uint32(vote.ifindex)]++
			}
		}
		return all, fallback
	}
	covered := func(snap *ConfigSnapshot) map[uint32]int {
		all, _ := countedVotes(snap)
		return all
	}
	// A REDIRECT: a row whose AF_XDP binding lands on a netdev that is not its
	// own, mapped to the netdev the binding — and therefore the refusal question
	// — actually concerns. Derived from userspaceOwnsItsNetdev and
	// ParentIfindex, the same two things the production branch in
	// buildUserspaceIngressIfindexes consults, so this cannot excuse a shape
	// production does not treat as a redirect.
	redirects := func(snap *ConfigSnapshot) map[uint32]uint32 {
		out := make(map[uint32]uint32)
		for _, iface := range snap.Interfaces {
			if userspaceOwnsItsNetdev(iface) || iface.Ifindex <= 0 || iface.ParentIfindex <= 0 {
				continue
			}
			out[uint32(iface.Ifindex)] = uint32(iface.ParentIfindex)
		}
		return out
	}

	baseEmitted := emitted(base)
	baseCounted, baseFallback := countedVotes(base)
	baseRedirects := redirects(base)
	if len(baseEmitted) < 2 {
		t.Fatalf("premise broken: the fixture emits %d netdevs; the probe needs both "+
			"producers populated or it cannot tell a producer from an inert field", len(baseEmitted))
	}

	// PRIMARY: no netdev reaches the gated set without a COUNTED verdict about
	// it or about the netdev its binding redirects onto. This holds whatever
	// produced it — a new section, or an existing section emitting a netdev it
	// casts no counted vote for (a fabric emitting its OVERLAY as well as its
	// parent would be that second shape, and a probe that only compared set
	// SIZES would call it covered).
	excused := 0
	for ifindex := range baseEmitted {
		if baseCounted[ifindex] > 0 {
			continue
		}
		target, isRedirect := baseRedirects[ifindex]
		if !isRedirect {
			t.Errorf("ifindex %d is in the ingress-adjudication set with NO COUNTED verdict in "+
				"snapshotNetdevVotes, and it is not a redirect whose verdict lives on a target. "+
				"It reaches the dataplane through a producer that either the enumeration does not "+
				"read or that registers a vote which abstains, so its owner bucket is EMPTY — and "+
				"a unanimity rule over an empty bucket answers \"not refused\" (the #6691 round 9 "+
				"fail-open). netdevVoteAbstains is iota 0, so a contributor added with a "+
				"zero-value role lands here by default. The required-protocol gate is scoped by "+
				"the same enumeration, so it cannot see that netdev's verdict either", ifindex)
			continue
		}
		if baseCounted[target] == 0 {
			t.Errorf("ifindex %d redirects its binding onto ifindex %d, and NEITHER carries a "+
				"counted verdict. A redirect is excused from having its own verdict only because "+
				"the decision about it is taken on the TARGET (buildUserspaceIngressIfindexes "+
				"asks refusesIfindex(ParentIfindex)); with the target's bucket empty too, that "+
				"question is answered \"not refused\" vacuously", ifindex, target)
			continue
		}
		excused++
	}

	// BOTH ARMS MUST HAVE FIRED. Without this the predicate could pass by never
	// reaching either interesting case: a fixture that lost its VLAN child would
	// make the redirect arm dead (and a bare role filter indistinguishable from
	// this one), and a fixture that lost the ownerless fabric member would make
	// the guard insensitive to the abstain regression it exists for.
	if excused == 0 {
		t.Error("no emitted netdev was excused as a redirect: the fixture no longer contains a " +
			"row that binds a netdev other than its own, so the second arm of the predicate is " +
			"dead code and this guard would be satisfied by a bare `role != abstains` filter — " +
			"which is wrong at head, because a VLAN child abstains legitimately about the " +
			"ifindex it emits")
	}
	fallbackOnly := 0
	for ifindex := range baseEmitted {
		if baseCounted[ifindex] > 0 && baseCounted[ifindex] == baseFallback[ifindex] {
			fallbackOnly++
		}
	}
	if fallbackOnly == 0 {
		t.Error("no emitted netdev is covered ONLY by a fallback vote: the fixture no longer " +
			"contains an ownerless fabric parent, so nothing here would notice if the fabric's " +
			"vote stopped being counted — which is the #6691 round 10 regression and the reason " +
			"the protocol moved to 7")
	}

	// SECONDARY: name the producing SECTION, so the failure above points at the
	// input rather than at a number. Zeroing a section that changes what is
	// emitted identifies it as a producer; its netdevs must leave the coverage
	// with it. "Coverage" here is the COUNTED coverage above — a section that
	// took its emission away while a counted verdict about that netdev stayed
	// behind is a section voting on someone else's device.
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
// FAIL-ON-REVERT — CORRECTED IN #7019, because the clause that stood here named
// two reverts and THIS test reds on neither. Re-measured at fb6b0bc93, each cell
// run against both this test and its sibling:
//
//	revert                                      this test   TestAFabricVote-
//	                                                        CannotOverturnAnOwningRow
//	R1 parent-config lookup -> exact map hit     GREEN       GREEN
//	R2 drop the hasOwner -> abstains branch      GREEN       RED
//	R1 + R2 together                             GREEN       RED
//
// R1 is DOMINATED at this fixture, which is the part worth knowing. A probe on
// the two lookups printed, for the only parent this test produces:
//
//	parentLinux=gr-0-0-3 exact=found+tunnel tolerant=found+tunnel
//	keys=[fab0,gr-0-0-3,ge-0/0/3,]
//
// The alias here is authored the other way round from what the paragraph above
// describes: the fabric MEMBER is slash-spelled and the STANZA is dash-spelled,
// so the stanza key already IS the netdev name and the exact hit finds it. The
// tolerant lookup buys nothing on this config. It is not unbound — reverting it
// reds TestFabricParentVerdictReadsTheClassTable, TestFabricAndBaseRowNeverDisagree
// and TestProtocolGateDoesNotArmWhenARowOwnsTheFabricParent, whose fixtures put
// the alias on the parent — it is simply not bound HERE.
//
// What this test actually binds is the PRODUCER: forcing
// buildUserspaceRefusedNetdevs to return an empty set reds it, along with nine
// others (#7021). So the honest contract is:
//
//	FAIL-ON-REVERT: empty the refused set, and this reds. The two reverts the
//	old clause named are covered by the sibling and by the three class-table
//	tests, not here.
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
