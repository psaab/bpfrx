package dataplane

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// #5275 PR1 — the observe-only arm-coverage proof.
//
// These tests pin the proof's DEFINITION, which is the part that must not
// drift: which surfaces count as covered, and why. The plan's §5/D1 wording
// ("strict program INSTANCE identity on every mapped attach point (native or
// generic)") is a native/generic binary and misses the delegated case
// entirely; implemented literally it would fail-close every VLAN deployment.
//
// They also bind the MANAGER path, not only the classifier: the report is a
// diagnostic whose whole value is being true about live state, and a suite that
// only ever drives classifyArmCoverage with an injected lookup can be fully
// green while the production source of that lookup reports the opposite of the
// truth.

// newProofResult builds a CompileResult carrying only what the proof reads.
func newProofResult(pending []int) *CompileResult {
	return &CompileResult{
		pendingXDP:          pending,
		tunnelIfindexes:     map[int]bool{},
		genericXDPIfindexes: map[int]bool{},
		linkIdxMap:          map[int]netlink.Link{},
		linkCache:           map[string]netlink.Link{},
	}
}

// vlanChild registers ifidx as a VLAN sub-interface of parent, exactly as
// compiler_iface.go marks them: genericXDPIfindexes set, not a tunnel.
func vlanChild(r *CompileResult, ifidx, parent int) {
	r.genericXDPIfindexes[ifidx] = true
	r.linkIdxMap[ifidx] = &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent},
	}
}

// lookupFrom builds an instanceLookup from a table of covered ifindexes.
func lookupFrom(covered map[int]uint32, generic map[int]bool) instanceLookup {
	return func(ifidx int) (uint32, bool, bool) {
		id, ok := covered[ifidx]
		if !ok {
			return 0, false, false
		}
		return id, generic[ifidx], true
	}
}

// swapArmProbes replaces the two live-state probes Manager.attachedInstance
// reads. Neither is reachable from a unit test otherwise: XDP cannot be
// attached without CAP_NET_ADMIN, and link.Link carries an unexported method so
// no fake can satisfy it. A nil argument leaves that probe alone.
func swapArmProbes(t *testing.T, mode func(int) bool, progID func(link.Link) (uint32, bool)) {
	t.Helper()
	oldMode, oldID := xdpLinkModeGeneric, xdpLinkProgramID
	if mode != nil {
		xdpLinkModeGeneric = mode
	}
	if progID != nil {
		xdpLinkProgramID = progID
	}
	t.Cleanup(func() {
		xdpLinkModeGeneric, xdpLinkProgramID = oldMode, oldID
	})
}

// captureLogs redirects the default slog handler for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// TestArmProofGenericFallbackCountsAsArmed pins the STATED DECISION that a
// generic (skb-mode) attach is armed.
//
// It is deliberately a test and not only a comment. A generic shim still
// steers packets to userspace-dp and still enforces policy — slower, but
// #5275 exists to prevent a POLICY-FREE kernel, and this box is not policy
// free. iavf SR-IOV VFs have NO native XDP support at all, so the fallback is
// a supported steady state; failing it closed would brick a supported
// deployment to prevent a condition that is not occurring.
//
// Without this test the decision is an implicit consequence of how the
// readback happens to be written, and a later "tighten the proof" change flips
// those boxes to fail-closed with nobody intending it.
func TestArmProofGenericFallbackCountsAsArmed(t *testing.T) {
	r := newProofResult([]int{10})

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 77}, map[int]bool{10: true}))

	if rep.Uncovered != 0 || rep.Direct != 1 {
		t.Fatalf("generic fallback must count as armed; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a gating build would have REFUSED a box running the shim in skb-mode — " +
			"that is a supported deployment (iavf VFs have no native XDP at all)")
	}
	s := rep.Surfaces[0]
	if s.Kind != CoverageDirect || !s.Generic {
		t.Fatalf("expected direct+generic; got kind=%s generic=%v", s.Kind, s.Generic)
	}
	if s.ProgramID != 77 {
		t.Fatalf("proof did not record the attached program instance; got %d", s.ProgramID)
	}
}

// TestArmProofGenericModeSurvivesASecondCompile is the reason the attach mode
// is read from the KERNEL and not from anything this compile recorded.
//
// attachUserspaceShimXDP falls back to generic ONCE. The m.xdpLinks entry it
// leaves behind survives every later compile — syncInterfaceAttachments detaches
// only ifindexes outside the allowed ingress set, and the pin sweep in
// userspace/manager_compile.go deletes link PINS, not this map — so AttachXDP
// short-circuits on "already attached" and the compile records nothing. Every
// commit, HA config sync and deferred-MAC reapply after the first therefore has
// a FRESH, EMPTY per-compile record while the box is still on skb-mode.
//
// A proof sourced from that record logs "went native" on a box that did not,
// on precisely the population (iavf SR-IOV VFs) whose size this phase exists to
// measure. That is worse than no measurement.
func TestArmProofGenericModeSurvivesASecondCompile(t *testing.T) {
	const ifidx = 7
	swapArmProbes(t,
		func(i int) bool { return i == ifidx },             // kernel: still skb-mode
		func(link.Link) (uint32, bool) { return 42, true }, // bpf_link readback
	)

	m := New()
	m.loaded = true
	m.SelectUserspaceXDPShimEntryProgram()
	m.programs[m.XDPEntryProgram()] = nil
	// What compile #1 left behind after its native->generic fallback.
	m.xdpLinks[ifidx] = nil

	// Compile #2 — a FRESH CompileResult, exactly as CompileConfig builds one
	// on every commit.
	result := newProofResult([]int{ifidx})
	if err := m.attachUserspaceShimXDP(result); err != nil {
		t.Fatalf("second compile attach: %v", err)
	}
	// A real compile-#2 Manager carries a lastCompile (CompileUserspaceShim
	// assigns one at the tail of every compile), so set one. The assertion
	// below must not be dismissible as an artefact of a nil field.
	m.lastCompile = result

	rep := m.ProveArmCoverage(result)
	if len(rep.Surfaces) != 1 {
		t.Fatalf("expected exactly the one required surface; got %+v", rep.Surfaces)
	}
	s := rep.Surfaces[0]
	if s.Kind != CoverageDirect {
		t.Fatalf("the tracked link is attached; expected direct, got %s (%s)", s.Kind, s.Detail)
	}
	if !s.Generic {
		t.Fatalf("proof reported NATIVE for a link the kernel has in skb-mode: %q — "+
			"the second compile short-circuits on \"already attached\" and records no fallback, "+
			"so a per-compile source reads native and the fleet log says the box went native "+
			"when it never left the slow path", rep.SurfaceSummary())
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "7:direct/generic") {
		t.Fatalf("summary must name the LIVE attach mode; got %q", got)
	}
}

// TestArmProofNativeSurfaceIsNotReportedGeneric is the over-reach guard for the
// test above: reading ground truth must not turn every surface generic. A
// driver-mode attach still reports native.
func TestArmProofNativeSurfaceIsNotReportedGeneric(t *testing.T) {
	swapArmProbes(t,
		func(int) bool { return false }, // kernel: driver mode
		func(link.Link) (uint32, bool) { return 9, true },
	)

	m := New()
	m.loaded = true
	m.xdpLinks[5] = nil

	rep := m.ProveArmCoverage(newProofResult([]int{5}))
	if len(rep.Surfaces) != 1 || rep.Surfaces[0].Kind != CoverageDirect {
		t.Fatalf("expected one direct surface; got %+v", rep.Surfaces)
	}
	if rep.Surfaces[0].Generic {
		t.Fatalf("a driver-mode attach must NOT be reported as skb-mode; got %q", rep.SurfaceSummary())
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "5:direct/native") {
		t.Fatalf("expected 5:direct/native; got %q", got)
	}
}

// TestArmProofUntrackedIfindexIsUncovered is the other over-reach guard on the
// Manager path: reading the kernel must not manufacture coverage for an
// ifindex the Manager tracks no link for.
func TestArmProofUntrackedIfindexIsUncovered(t *testing.T) {
	swapArmProbes(t,
		func(int) bool { return true },
		func(link.Link) (uint32, bool) { return 1, true },
	)

	m := New() // no xdpLinks entries at all

	rep := m.ProveArmCoverage(newProofResult([]int{5}))
	if rep.Uncovered != 1 || rep.Direct != 0 {
		t.Fatalf("an ifindex with no tracked link must be uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a required surface with no link at all must be reported as WOULD-GATE")
	}
}

// TestArmProofDelegatedVlanChildResolvesToParent pins the third category the
// plan's native/generic binary misses.
//
// A VLAN sub-interface under the userspace shim is NEVER attached — both
// attach loops skip it and it is recorded in VlanSubInterfaces instead —
// because the PARENT's XDP sees VLAN-tagged frames before kernel VLAN
// demuxing, and attaching the shim to the child breaks IPv6 NDP. Policy is
// enforced, at a different attach point.
//
// A proof demanding an instance on every mapped attach point fails here, and
// the loss cluster (reth0.50 / reth0.80) plus the standalone VM (VLAN 50) both
// have such surfaces — i.e. it would fail-close essentially every real
// deployment.
func TestArmProofDelegatedVlanChildResolvesToParent(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10) // 20 is a VLAN child of 10

	// Only the PARENT carries an instance. That is the correct steady state.
	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 55}, nil))

	if rep.Uncovered != 0 {
		t.Fatalf("a VLAN child covered by its parent must not read as uncovered; got %+v", rep)
	}
	if rep.Direct != 1 || rep.Delegated != 1 {
		t.Fatalf("expected 1 direct (parent) + 1 delegated (child); got %+v", rep)
	}
	if rep.Skipped != 0 {
		t.Fatalf("nothing was declined here; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a gating build would have REFUSED a plain VLAN deployment — " +
			"the loss cluster and the standalone VM both run VLAN sub-interfaces")
	}
	var child SurfaceCoverage
	for _, s := range rep.Surfaces {
		if s.Ifindex == 20 {
			child = s
		}
	}
	if child.Kind != CoverageDelegated || child.Via != 10 {
		t.Fatalf("child must resolve to its covering parent; got kind=%s via=%d", child.Kind, child.Via)
	}
	if child.ProgramID != 55 {
		t.Fatalf("delegated surface must carry the DELEGATE's instance; got %d", child.ProgramID)
	}
}

// TestArmProofDelegationIsResolvedNotAssumed is the other half of the pair
// above, and the reason "skip VLAN children" is not an acceptable shortcut.
//
// If the parent carries no instance, the child is NOT covered — nothing is
// enforcing its traffic. A proof that skipped VLAN children unconditionally
// would pass this box, which is precisely the policy-free-router state #5275
// exists to prevent.
func TestArmProofDelegationIsResolvedNotAssumed(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10)

	// NOTHING is attached — parent included.
	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Delegated != 0 {
		t.Fatalf("a child whose parent carries no instance must NOT read as delegated; got %+v", rep)
	}
	if rep.Uncovered != 2 {
		t.Fatalf("both parent and child are uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a fully unattached dataplane must be reported as WOULD-GATE — " +
			"this is the policy-free kernel #5275 is about")
	}
}

// TestArmProofDelegateMustBeARequiredSurface pins the stronger half of the
// documented invariant — "the parent must itself be DIRECTLY covered" — which a
// bare "does a link exist for the parent" check does not deliver.
//
// Concrete input: `set interfaces ge-0-0-2 disable` with ge-0-0-2.50 still in a
// zone. compiler_iface.go appends the CHILD unconditionally (the VLAN block
// runs before the isDisabled check) and never appends the parent, so the parent
// is not a required surface. On an enabled->disabled commit the parent's
// previous link is still tracked, so a lookup on it succeeds — and the child
// would report covered by a parent that is admin-DOWN, unproven, and about to
// be torn down.
func TestArmProofDelegateMustBeARequiredSurface(t *testing.T) {
	r := newProofResult([]int{20}) // ONLY the child is required
	vlanChild(r, 20, 10)

	// The parent's stale link still reads back an instance.
	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 55}, nil))

	if rep.Delegated != 0 {
		t.Fatalf("delegation to a parent that is not a required surface must NOT count as covered; got %+v", rep)
	}
	if rep.Uncovered != 1 {
		t.Fatalf("the child is uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a VLAN child whose delegate nothing proves armed must be reported as WOULD-GATE")
	}
	if rep.Surfaces[0].Via != 10 {
		t.Fatalf("the record must still name the parent that failed to cover it; got via=%d", rep.Surfaces[0].Via)
	}
}

// TestArmProofUncoveredIsTheZeroValue pins the fail-safe default. An entry that
// was never populated must read as uncovered, so a partially-built report can
// only ever be more conservative, never less.
func TestArmProofUncoveredIsTheZeroValue(t *testing.T) {
	var k SurfaceCoverageKind
	if k != CoverageUncovered {
		t.Fatalf("the zero SurfaceCoverageKind must be Uncovered, got %s — "+
			"an unpopulated entry would otherwise read as covered", k)
	}
	var s SurfaceCoverage
	if s.Kind != CoverageUncovered {
		t.Fatal("a zero SurfaceCoverage must read as uncovered")
	}
}

// TestArmProofReadbackFailureIsUncovered pins that a tracked link whose
// identity cannot be read is not treated as proof of coverage. The lookup
// returning ok=false is exactly what Manager.attachedInstance does when the
// bpf_link info call errors.
func TestArmProofReadbackFailureIsUncovered(t *testing.T) {
	r := newProofResult([]int{10})
	// Link tracked (generic flag known) but the instance readback failed.
	rep := classifyArmCoverage(r, func(int) (uint32, bool, bool) { return 0, true, false })

	if rep.Uncovered != 1 || rep.Direct != 0 {
		t.Fatalf("a failed instance readback must degrade to uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("unreadable link identity must be reported as WOULD-GATE, not assumed benign")
	}
}

// TestArmProofIsDeterministic pins the stable ordering the log line depends on:
// two reports of the same box must be diffable.
func TestArmProofIsDeterministic(t *testing.T) {
	r := newProofResult([]int{30, 10, 20})
	lookup := lookupFrom(map[int]uint32{10: 1, 20: 2, 30: 3}, nil)

	rep := classifyArmCoverage(r, lookup)
	if len(rep.Surfaces) != 3 {
		t.Fatalf("expected 3 surfaces; got %d", len(rep.Surfaces))
	}
	for i, want := range []int{10, 20, 30} {
		if rep.Surfaces[i].Ifindex != want {
			t.Fatalf("surfaces must be in ascending ifindex order; got %+v", rep.Surfaces)
		}
	}
	// The input slice must not be reordered underneath the caller — the proof
	// runs mid-apply against live compile state.
	if r.pendingXDP[0] != 30 {
		t.Fatalf("proof MUTATED the compile result's pendingXDP order: %v", r.pendingXDP)
	}
}

// TestArmProofDoesNotMemoiseIntoTheCompileResult pins the observe-only claim
// literally. cachedLinkByIndex memoises a successful lookup into linkIdxMap AND
// linkCache; the proof must use the non-memoising peek instead, or the claim
// "it mutates nothing" is false and a CompileResult reachable by any other
// reader takes an unannounced map write.
//
// ifindex 1 is loopback in every Linux network namespace, so the lookup here
// SUCCEEDS — which is the case that matters, because cachedLinkByIndex only
// writes on success. lo has no parent, so the surface lands uncovered; the
// assertions are about the caches, not the verdict.
func TestArmProofDoesNotMemoiseIntoTheCompileResult(t *testing.T) {
	r := newProofResult([]int{1})
	// Classify ifindex 1 as a VLAN child so the delegated path resolves it,
	// and deliberately leave it OUT of linkIdxMap so resolution must go to the
	// kernel rather than hitting the pre-seeded entry.
	r.genericXDPIfindexes[1] = true

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))
	if len(rep.Surfaces) != 1 {
		t.Fatalf("expected the one required surface; got %+v", rep.Surfaces)
	}
	if len(r.linkIdxMap) != 0 {
		t.Fatalf("the proof MEMOISED into the CompileResult it is proving: linkIdxMap=%v — "+
			"an observe-only diagnostic must not write into the object it observes", r.linkIdxMap)
	}
	if len(r.linkCache) != 0 {
		t.Fatalf("the proof MEMOISED into the CompileResult it is proving: linkCache=%v", r.linkCache)
	}
}

// TestArmProofSoftSkippedSurfaceIsDistinguishable pins that a surface the
// COMPILER declined to arm is not silently absent.
//
// compiler_iface.go soft-skips three ways — interface not found, VLAN child
// create failed, administratively disabled — each behind nothing but a slog
// line, each leaving the compile SUCCESSFUL and the surface out of pendingXDP.
// Without a record the proof reports Uncovered=0 for a config whose surfaces it
// never even looked at, which reads identically to a fully-armed box.
func TestArmProofSoftSkippedSurfaceIsDistinguishable(t *testing.T) {
	r := newProofResult(nil)
	r.recordUnarmedSurface(UnarmedSurface{
		Name:   "ge-0-0-9",
		Reason: "interface not found in zone trust: no such device",
	})

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if len(rep.Surfaces) != 1 {
		t.Fatalf("a surface the compiler declined must appear in the report; got %+v", rep)
	}
	if rep.Skipped != 1 || rep.Surfaces[0].Kind != CoverageSkipped {
		t.Fatalf("a declined surface must be its own branch, not folded into covered or uncovered; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a netdev that does not exist forwards nothing — declining it is not a policy-free router")
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "ge-0-0-9:skipped") {
		t.Fatalf("the summary must name the declined surface; got %q", got)
	}
}

// TestArmProofSkippedButStillForwardingIsUncovered pins the sharp variant.
//
// `set interfaces ge-0-0-1 disable` whose netlink.LinkSetDown then FAILS is a
// slog.Warn and nothing else: the netdev stays UP, address reconciliation still
// runs, it is still in a security zone, the kernel still forwards through it —
// and no XDP is attached, because the disabled branch skipped the attach. That
// is the policy-free router #5275 exists to prevent, and it must not read as a
// benign operator action.
func TestArmProofSkippedButStillForwardingIsUncovered(t *testing.T) {
	r := newProofResult(nil)
	r.recordUnarmedSurface(UnarmedSurface{
		Name:            "ge-0-0-1",
		Ifindex:         12,
		Reason:          "administratively disabled but link-down FAILED",
		StillForwarding: true,
	})

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Uncovered != 1 || rep.Skipped != 0 {
		t.Fatalf("a skipped surface whose netdev is still UP and forwarding must read as UNCOVERED, "+
			"not as a benign decline; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("an UP, zoned, forwarded-through netdev carrying no XDP is exactly the " +
			"policy-free router #5275 is about — it must be reported as WOULD-GATE")
	}
}

// TestArmProofEmptySurfaceSetGatesNothingButStillReports keeps the two things
// the original empty-set test protected — a box with nothing to arm is not an
// unarmed box, and nil inputs are inert — and adds the distinction the original
// shape implied away: a proof that RAN and enumerated nothing must not read the
// same as a proof that never ran.
func TestArmProofEmptySurfaceSetGatesNothingButStillReports(t *testing.T) {
	rep := classifyArmCoverage(newProofResult(nil), lookupFrom(nil, nil))
	if len(rep.Surfaces) != 0 || rep.WouldGate {
		t.Fatalf("an empty surface set must not report a gate; got %+v", rep)
	}
	if !rep.Ran {
		t.Fatal("a proof that executed against a real compile result must report ran=true, " +
			"or 'nothing to arm' is indistinguishable from 'the proof never ran'")
	}
	// nil result / nil lookup must be inert too — the proof runs on paths where
	// the dataplane may not exist — but they are a DIFFERENT unknown.
	for _, tc := range []struct {
		name string
		rep  ArmCoverageReport
	}{
		{"nil compile result", classifyArmCoverage(nil, lookupFrom(nil, nil))},
		{"nil lookup", classifyArmCoverage(newProofResult([]int{1}), nil)},
	} {
		if tc.rep.WouldGate {
			t.Fatalf("%s must not report a gate", tc.name)
		}
		if tc.rep.Ran {
			t.Fatalf("%s did not run the proof; it must not report ran=true", tc.name)
		}
	}
}

// TestArmProofLogsEvenWhenItEnumeratedNothing pins that the record exists.
//
// This file argues at DidGate that "an absence is indistinguishable from a
// proof that never ran". Suppressing the line on an empty surface set commits
// exactly that error: a box with nothing to arm, a build with the proof removed
// and a daemon that crashed before the proof all produce the same silence.
func TestArmProofLogsEvenWhenItEnumeratedNothing(t *testing.T) {
	buf := captureLogs(t)

	classifyArmCoverage(newProofResult(nil), lookupFrom(nil, nil)).LogArmCoverage("post-attach", 3)

	out := buf.String()
	if !strings.Contains(out, "arm-coverage proof") {
		t.Fatalf("a proof that enumerated nothing emitted NO line — indistinguishable from a "+
			"proof that never ran, which is the failure this file's DidGate rationale rejects; got %q", out)
	}
	if !strings.Contains(out, "ran=true") {
		t.Fatalf("the line must say the proof ran; got %q", out)
	}

	buf.Reset()
	classifyArmCoverage(nil, nil).LogArmCoverage("post-attach", 4)
	if out := buf.String(); !strings.Contains(out, "ran=false") {
		t.Fatalf("a proof that did NOT run must say so on its own line; got %q", out)
	}
}

// TestArmProofStageLabelIsDistinctPerCompile pins that two proofs from ONE
// daemon apply are distinguishable.
//
// daemon_apply_dataplane.go issues a second ApplyConfig in the same apply on the
// RETH deferred-MAC path (reapplyAfterDeferredMAC), so this fires twice with the
// same stage word. Two records carrying an identical label cannot be told apart
// in a log archive — and it is the SECOND that reflects the final state.
func TestArmProofStageLabelIsDistinctPerCompile(t *testing.T) {
	buf := captureLogs(t)
	// A NON-empty report deliberately, so this cell isolates the stage label
	// and does not also move when the empty-report suppression changes.
	rep := classifyArmCoverage(newProofResult([]int{10}), lookupFrom(map[int]uint32{10: 1}, nil))

	rep.LogArmCoverage("post-attach", 1)
	rep.LogArmCoverage("post-attach", 2)

	out := buf.String()
	if strings.Count(out, "stage=post-attach#1") != 1 || strings.Count(out, "stage=post-attach#2") != 1 {
		t.Fatalf("two compiles in one apply must carry DISTINCT stage labels; got %q", out)
	}
}

// TestArmProofReportsBranchPerSurface pins that the record carries the branch
// for EVERY surface, not only the failing ones. The whole point of the
// observe-only phase is measuring the direct/delegated/uncovered mix across
// real deployments; a pass/fail summary cannot answer that, and a report that
// only names failures cannot distinguish a fleet of native boxes from a fleet
// of VLAN boxes.
//
// The delegated token carries the delegate's attach MODE for the same reason: a
// VLAN child behind an skb-mode parent is on the slow path, and without the
// mode it is indistinguishable from one behind a native parent.
func TestArmProofReportsBranchPerSurface(t *testing.T) {
	r := newProofResult([]int{10, 20, 30, 40})
	vlanChild(r, 20, 10) // delegated to 10
	// 40 is attached to nothing at all.
	rep := classifyArmCoverage(r, lookupFrom(
		map[int]uint32{10: 1, 30: 3}, map[int]bool{30: true}))

	got := rep.SurfaceSummary()
	for _, want := range []string{
		"10:direct/native",
		"20:delegated/via-10/native",
		"30:direct/generic",
		"40:uncovered",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("per-surface summary missing %q; got %q", want, got)
		}
	}
}

// TestArmProofDelegatedSummaryCarriesTheDelegateMode is the sibling of the
// above: a child behind a GENERIC parent must render generic, or the skb-mode
// population is undercounted by exactly the VLAN deployments — which is every
// deployment this project ships.
func TestArmProofDelegatedSummaryCarriesTheDelegateMode(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10)

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 1}, map[int]bool{10: true}))

	if got := rep.SurfaceSummary(); !strings.Contains(got, "20:delegated/via-10/generic") {
		t.Fatalf("a VLAN child behind an skb-mode parent must render generic; got %q", got)
	}
}

// TestArmProofDidGateIsDistinctFromWouldGate pins that the two are separate
// fields. Reporting only would_gate makes "the proof said refuse" and "the
// proof refused" indistinguishable in a log archive — and an absent
// enforcement line is also indistinguishable from a proof that never ran.
func TestArmProofDidGateIsDistinctFromWouldGate(t *testing.T) {
	// A box the gating build would refuse.
	rep := classifyArmCoverage(newProofResult([]int{10}), lookupFrom(nil, nil))
	if !rep.WouldGate {
		t.Fatal("precondition: an unattached surface must be would-gate")
	}
	if rep.DidGate {
		t.Fatal("OBSERVE-ONLY VIOLATION: the proof reported that it actually withheld " +
			"something — this phase must never gate")
	}
}

// --- source canaries -------------------------------------------------------
//
// CompileUserspaceShim cannot be driven from a unit test: its first act is
// reading /sys/fs/bpf/xpf/links, which is root-only. The wiring is therefore
// bound structurally. Without these, deleting the production call site or a
// recording site leaves the whole suite green, because every behavioural test
// above drives the classifier directly.

func parseDataplaneFile(t *testing.T, name string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return fset, f
}

func findFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name && fn.Body != nil {
			return fn
		}
	}
	t.Fatalf("func %s not found", name)
	return nil
}

func selectorName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// TestArmProofIsInvokedFromCompileUserspaceShim binds the production call site.
func TestArmProofIsInvokedFromCompileUserspaceShim(t *testing.T) {
	_, file := parseDataplaneFile(t, "loader.go")
	fn := findFuncDecl(t, file, "CompileUserspaceShim")

	var found bool
	var seqIsConstant bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || selectorName(call.Fun) != "LogArmCoverage" {
			return true
		}
		// The receiver must be the proof itself, not a stashed report.
		recv, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		inner, ok := recv.X.(*ast.CallExpr)
		if !ok || selectorName(inner.Fun) != "ProveArmCoverage" {
			return true
		}
		found = true
		if len(call.Args) == 2 {
			if _, isLit := call.Args[1].(*ast.BasicLit); isLit {
				seqIsConstant = true
			}
		}
		return false
	})

	if !found {
		t.Fatal("CompileUserspaceShim no longer calls ProveArmCoverage(...).LogArmCoverage(...) — " +
			"the #5275 measurement is not wired to any production path, and every other test " +
			"in this file drives the classifier directly so nothing else notices")
	}
	if seqIsConstant {
		t.Fatal("the arm-coverage sequence argument is a literal — the RETH deferred-MAC path " +
			"compiles twice per apply, and a constant makes the two records indistinguishable")
	}
}

// surfaceSkipSites are the compiler's SOFT SKIPS: branches that drop a
// configured attach point from the required set while the compile still
// succeeds. Each must record the surface, or the proof cannot tell a declined
// surface from an armed one.
//
// A new soft skip belongs here AND needs a recordUnarmedSurface call. The
// entries below are deliberately NOT every "skipping" log in the function —
// "skipping tx_port for tunnel interface" and "skipping TC for tunnel
// interface" both still arm XDP on the surface, so they are not surface skips.
var surfaceSkipSites = []string{
	"interface not found, skipping",
	"VLAN sub-interface failed, skipping",
	"skipping XDP/TC attachment for disabled interface",
}

// TestArmProofSoftSkipSitesRecordTheSurface binds the three recording sites.
func TestArmProofSoftSkipSitesRecordTheSurface(t *testing.T) {
	_, file := parseDataplaneFile(t, "compiler_iface.go")
	fn := findFuncDecl(t, file, "mapZoneInterface")

	seen := make(map[string]bool, len(surfaceSkipSites))
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		msg := ""
		records := false
		for _, stmt := range block.List {
			expr, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expr.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			switch selectorName(call.Fun) {
			case "Warn", "Info":
				if len(call.Args) == 0 {
					continue
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok {
					continue
				}
				for _, want := range surfaceSkipSites {
					if strings.Contains(lit.Value, want) {
						msg = want
					}
				}
			case "recordUnarmedSurface":
				records = true
			}
		}
		if msg != "" && records {
			seen[msg] = true
		}
		return true
	})

	for _, want := range surfaceSkipSites {
		if !seen[want] {
			t.Fatalf("the soft skip %q does not record the surface it drops — the compile "+
				"succeeds, the surface vanishes from pendingXDP, and the proof reports "+
				"Uncovered=0 for an attach point it never looked at", want)
		}
	}
}
