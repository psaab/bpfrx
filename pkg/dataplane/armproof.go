package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// #5275 PR1 — OBSERVE-ONLY dataplane arm-coverage proof.
//
// A config that COMPILES but whose dataplane fails to ARM degrades a cold-booted
// firewall to a policy-free router: ownership, forwarding and route/VIP
// advertisement are all published in initManagers BEFORE the arm
// (daemon_run_bringup.go:47 vs :414), and an attach failure surfaces through
// d.dp.ApplyConfig as an ORDINARY #5679 deferred error — compileErrorMustAbortApply
// only matches the required-protocol gate — so the apply tail still publishes.
//
// The eventual fix gates release on a positive arm proof. THIS FILE DOES NOT
// GATE ANYTHING. It computes the proof and reports what a gating build would
// have decided, so the divergence rate can be measured across the real fleet
// before the gate is ever load-bearing. `WouldGate` is a diagnostic, never a
// control input; nothing here returns an error that any caller acts on.
//
// SIDE EFFECTS, stated exactly (an "observe-only" claim that is not literally
// true is worse than no claim): the proof writes NO Go state — not the Manager,
// not the CompileResult it is proving — and it READS live kernel and bpf state,
// one RTM_GETLINK plus one BPF_OBJ_GET_INFO per required surface. It runs once
// per compile, never per packet or per poll tick.
//
// STAGE. The plan's §5 takes the FINAL proof after the last mutation that can
// invalidate it (networkd, the RETH MAC link-cycle, the AF_XDP rebind /
// deferred-worker reapply). This proof runs inside CompileUserspaceShim, i.e.
// at the PRELIMINARY attachment stage — it proves the attach-point inventory
// and program-instance identity, and it cannot see XSK binding readiness. The
// divergence rate it measures is therefore the PRELIMINARY-stage rate, which is
// a lower bound on the gate's.
//
// The measurement matters because "armed" today is weaker than the proof:
// attachUserspaceShimXDP treats a NATIVE attach failure as a warning, detaches,
// and re-attaches in generic (skb) mode — only a GENERIC failure returns an
// error. So a box reports itself armed while running the whole shim on the
// fallback path, and iavf SR-IOV VFs (no native XDP support at all) make that a
// supported steady state, not a misconfiguration.

// SurfaceCoverageKind classifies how one required attach point is covered.
//
// CoverageUncovered is deliberately the ZERO value: an entry that was never
// populated must read as NOT covered. For a gate whose job is to fail closed,
// the uninitialised state has to be the conservative one.
type SurfaceCoverageKind int

const (
	// CoverageUncovered — no shim instance here and no proven delegate.
	// This is the only kind a gating build would refuse on.
	CoverageUncovered SurfaceCoverageKind = iota
	// CoverageDirect — a shim program instance is attached at this attach
	// point. Native and generic (skb-mode) both qualify; see below.
	CoverageDirect
	// CoverageDelegated — no attach is expected here BY DESIGN; the parent
	// interface's program covers this surface.
	CoverageDelegated
	// CoverageSkipped — the COMPILER declined to arm this surface and still
	// returned success. Neither proven covered nor proven forwarding-without-
	// policy; a third, distinct unknown. See UnarmedSurface.
	CoverageSkipped
)

func (k SurfaceCoverageKind) String() string {
	switch k {
	case CoverageDirect:
		return "direct"
	case CoverageDelegated:
		return "delegated"
	case CoverageSkipped:
		return "skipped"
	default:
		return "uncovered"
	}
}

// SurfaceCoverage is the proof outcome for one required attach point.
type SurfaceCoverage struct {
	Ifindex int
	// Name is the CONFIGURED interface name. Populated only for a surface the
	// compiler declined to arm, where the ifindex may not exist at all (the
	// netdev was missing, or the VLAN child was never created).
	Name string
	Kind SurfaceCoverageKind
	// Via is the covering parent ifindex when Kind is CoverageDelegated. It is
	// also set on an UNCOVERED VLAN child whose delegate was rejected, so the
	// record names the parent that failed to cover it.
	Via int
	// ProgramID is the attached program INSTANCE (bpf_link readback) for a
	// direct surface, or the delegate's instance for a delegated one. Zero
	// means the readback did not yield one — reported, never inferred.
	ProgramID uint32
	// Generic records that this surface is covered in skb-mode rather than
	// driver-mode XDP. Informational: it does NOT reduce coverage. Read from
	// the KERNEL, not from compile bookkeeping — see xdpLinkModeGeneric.
	Generic bool
	Detail  string
}

// label renders the surface identity for the compact per-surface token: the
// configured name when the proof has one (an unarmed surface may have no
// ifindex at all), otherwise the ifindex.
func (s SurfaceCoverage) label() string {
	if s.Name != "" {
		return s.Name
	}
	return strconv.Itoa(s.Ifindex)
}

// ArmCoverageReport is the whole-surface outcome of one proof run.
type ArmCoverageReport struct {
	Surfaces  []SurfaceCoverage
	Direct    int
	Delegated int
	Skipped   int
	Uncovered int
	// Ran reports that the proof executed against real inputs. False means it
	// did not run at all (no compile result, or no instance lookup) — which is
	// a DIFFERENT unknown from "ran and enumerated nothing", and by this file's
	// own DidGate rationale the two must never be indistinguishable.
	Ran bool
	// WouldGate reports whether a GATING build would have refused to release
	// ownership on this proof. Observe-only: no caller may branch on it.
	WouldGate bool
	// DidGate reports whether anything was ACTUALLY withheld. It is
	// unconditionally false in this phase, and is a distinct field rather than
	// an omission on purpose: the divergence rate has to be readable directly
	// from a record that says "would have gated, did not", not inferred from
	// the ABSENCE of an enforcement line. An absence is indistinguishable from
	// a proof that never ran. The gating PR is what makes this field vary.
	DidGate bool
}

// SurfaceSummary renders one compact, greppable token per surface —
// "<ifindex|name>:<branch>[/<detail>]" — so the per-surface branch is
// recoverable from a single log line instead of requiring one line per
// interface on every apply.
func (rep ArmCoverageReport) SurfaceSummary() string {
	if len(rep.Surfaces) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rep.Surfaces))
	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageDirect:
			parts = append(parts, fmt.Sprintf("%s:direct/%s", s.label(), attachModeName(s.Generic)))
		case CoverageDelegated:
			// The delegate's attach mode is rendered too: a VLAN child behind
			// an skb-mode parent IS on the slow path, and without the mode it
			// is indistinguishable from one behind a native parent — which is
			// exactly the population this phase exists to count.
			parts = append(parts, fmt.Sprintf("%s:delegated/via-%d/%s",
				s.label(), s.Via, attachModeName(s.Generic)))
		case CoverageSkipped:
			parts = append(parts, fmt.Sprintf("%s:skipped", s.label()))
		default:
			parts = append(parts, fmt.Sprintf("%s:uncovered", s.label()))
		}
	}
	return strings.Join(parts, " ")
}

func attachModeName(generic bool) string {
	if generic {
		return "generic"
	}
	return "native"
}

// GENERIC XDP COUNTS AS ARMED — a stated decision, not an emergent property.
//
// A generic (skb-mode) shim is enforcing policy. It is slower — this project
// measures roughly 16% CPU overhead from the per-packet sk_buff — but packets
// still reach userspace-dp and are still evaluated. #5275 exists to prevent a
// POLICY-FREE kernel, and a box on the fallback path is not policy-free.
// Failing it closed would brick a supported deployment (iavf SR-IOV VFs have no
// native XDP at all) to prevent a condition that is not occurring.
//
// This is written down here, and pinned by a test, precisely because it would
// otherwise be an implicit consequence of how the readback happens to be
// written — and a later "tighten the proof" change would flip a supported
// deployment to fail-closed with nobody intending it.

// DELEGATED COVERAGE — the case a native/generic binary misses entirely.
//
// A VLAN sub-interface under the userspace shim is NEVER attached: both attach
// loops skip it (loader.go, and compiler.go's isUserspaceShim branch) and it is
// recorded in Manager.VlanSubInterfaces instead. The reason is in the source at
// both sites — the PARENT's XDP sees VLAN-tagged frames before kernel VLAN
// demuxing, and swapping the shim onto the child breaks IPv6 NDP because
// generic-mode XDP_PASS does not deliver correctly to the kernel NDP stack on
// VLAN devices.
//
// So policy IS enforced for these, at a DIFFERENT attach point. A per-surface
// proof that demands an instance on "every mapped attach point" fails on every
// VLAN sub-interface — the loss cluster runs reth0.50 and reth0.80, the
// standalone VM runs VLAN 50 — i.e. it would fail-close essentially every real
// deployment. The opposite shortcut, skipping VLAN children unconditionally, is
// just as wrong: it would pass a surface whose coverage was never checked.
//
// Delegation is therefore RESOLVED, not assumed, and resolved against the
// proof's OWN classification of the parent: the parent must be a REQUIRED
// surface and must itself classify as CoverageDirect, or the child is
// uncovered. A link that merely happens to be tracked is not enough — an
// enabled->disabled commit leaves the previous parent link in place while the
// parent is admin-DOWN and about to be torn down, and delegating to that would
// report a covered child with nothing enforcing its traffic.

// UnarmedSurface records an attach point the CONFIG required but the compiler
// DECLINED to arm, while the compile itself still SUCCEEDED (#5275).
//
// Three soft skips in compiler_iface.go remove a surface from the required set
// behind nothing but a slog.Warn: the interface was not found, the VLAN
// sub-interface could not be created, and the interface is administratively
// disabled. Without a record the proof cannot tell "the compiler declined to
// arm this" from "this was armed successfully" — both read as clean, because
// the surface is simply absent from pendingXDP.
type UnarmedSurface struct {
	// Name is the configured interface ("ge-0-0-1", or "ge-0-0-2.50" for a
	// VLAN child). Always set: the ifindex may not exist.
	Name string
	// Ifindex is the resolved ifindex, or 0 when the surface has none.
	Ifindex int
	// Reason is the compiler's own reason for declining.
	Reason string
	// StillForwarding marks the sharp variant: the surface was skipped but the
	// netdev is (or may still be) UP, in a security zone, and forwarded through
	// by the kernel with NO XDP attached. `set interfaces <if> disable` whose
	// netlink.LinkSetDown then fails is exactly that — the disable branch logs
	// the failure at WARN and continues, and address reconciliation runs
	// regardless. That is the policy-free-router condition #5275 exists to
	// prevent, so it reads as UNCOVERED rather than merely skipped.
	StillForwarding bool
}

// disabledSurfaceRecord classifies an administratively disabled interface.
//
// Split out of mapZoneInterface deliberately. The only judgement in it is
// StillForwarding, which is the whole difference between a benign operator
// action and a policy-free router — and producing the condition in a test
// (a real netdev whose LinkSetDown fails) needs CAP_NET_ADMIN, while deciding
// what such a failure MEANS does not. In the caller it was unbindable; here it
// is four table rows.
//
// linkErr is the netlink link-resolution error: non-nil means no handle was
// ever obtained, so LinkSetDown was never even attempted. downErr is
// LinkSetDown's own error. The netdev is proven down only when BOTH are nil.
// Anything else leaves it possibly UP, still address-reconciled (that call sits
// outside the disable guard), still in a zone, still forwarded through by the
// kernel, and carrying no XDP.
func disabledSurfaceRecord(name string, ifindex int, linkErr, downErr error) UnarmedSurface {
	s := UnarmedSurface{Name: name, Ifindex: ifindex}
	switch {
	case linkErr != nil:
		s.Reason = fmt.Sprintf("administratively disabled but the link never resolved (%v) — "+
			"never brought down, may still be UP and forwarding with no XDP", linkErr)
		s.StillForwarding = true
	case downErr != nil:
		s.Reason = fmt.Sprintf("administratively disabled but link-down FAILED (%v) — "+
			"netdev may still be UP and forwarding with no XDP", downErr)
		s.StillForwarding = true
	default:
		s.Reason = "administratively disabled (netdev brought down)"
	}
	return s
}

// missingInterfaceRecord classifies a zone interface the compiler could not
// resolve.
//
// "Not found" is NOT the only thing net.InterfaceByName reports through this
// error. It wraps a genuine absence (its own errNoSuchInterface) and a netlink
// DUMP failure (ENOBUFS / ENOMEM / EINTR, surfaced as a syscall.Errno) in the
// same *net.OpError. Only the first proves nothing forwards through the netdev;
// a dump failure says nothing at all about whether it exists, and it may be
// live, UP and in a zone. errNoSuchInterface is unexported, so the distinction
// is drawn from the WRAPPED type — a syscall.Errno means the enumeration
// failed, not that the interface is absent — and an unrecognised error falls to
// the absence branch only because that is what every non-errno error from this
// call means today.
func missingInterfaceRecord(name, zone string, err error) UnarmedSurface {
	s := UnarmedSurface{
		Name:   name,
		Reason: fmt.Sprintf("interface not found in zone %s: %v", zone, err),
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s.Reason = fmt.Sprintf("interface lookup FAILED in zone %s (%v) — "+
			"the netdev enumeration errored, so absence is unproven and it may be UP and forwarding", zone, err)
		s.StillForwarding = true
	}
	return s
}

// ProveArmCoverage computes the arm-coverage proof for the surfaces result
// requires, WITHOUT gating anything (#5275 PR1, observe-only).
//
// It writes no Go state: not the Manager, and not the CompileResult it is
// proving (the link resolution deliberately uses peekLinkByIndex, which does
// not memoise, so the result's caches are untouched). It does READ live kernel
// and bpf state — one RTM_GETLINK for the attach mode plus one bpf_link info
// call per required surface — and never returns an error a caller acts on. A
// readback failure degrades that surface to uncovered and is reported, the
// conservative direction, matching what a gating build would do.
func (m *Manager) ProveArmCoverage(result *CompileResult) ArmCoverageReport {
	if m == nil {
		return ArmCoverageReport{}
	}
	return classifyArmCoverage(result, m.attachedInstance)
}

// instanceLookup reports the program instance bound at an ifindex.
//
// ok=false means "not covered here" — no tracked link, or a readback that
// failed. Injected so the classification is testable without a real bpf_link;
// production always passes Manager.attachedInstance.
type instanceLookup func(ifidx int) (progID uint32, generic bool, ok bool)

// classifyArmCoverage is the whole proof, separated from bpf so it can be
// exercised directly.
func classifyArmCoverage(result *CompileResult, lookup instanceLookup) ArmCoverageReport {
	var rep ArmCoverageReport
	if result == nil || lookup == nil {
		// Ran stays false: this proof did NOT run, which must not read the
		// same as a proof that ran and found nothing wrong.
		return rep
	}
	rep.Ran = true

	// Deterministic order so the log line is stable across boots and two
	// reports can be diffed.
	required := append([]int(nil), result.pendingXDP...)
	sort.Ints(required)
	isRequired := make(map[int]bool, len(required))
	for _, ifidx := range required {
		isRequired[ifidx] = true
	}

	// Pass 1 classifies every DIRECT surface, because a delegated surface
	// resolves against the parent's OWN classification and must not race the
	// order of the required slice.
	direct := make(map[int]SurfaceCoverage, len(required))
	for _, ifidx := range required {
		if isDelegatedSurface(result, ifidx) {
			continue
		}
		direct[ifidx] = coverDirect(lookup, ifidx)
	}

	// Pass 2 emits in ifindex order, resolving delegation against pass 1.
	for _, ifidx := range required {
		if s, ok := direct[ifidx]; ok {
			rep.Surfaces = append(rep.Surfaces, s)
			continue
		}
		rep.Surfaces = append(rep.Surfaces, coverDelegated(result, direct, isRequired, ifidx))
	}

	// Surfaces the compiler declined to arm are NOT in pendingXDP at all. They
	// are appended last so the required-surface ordering above is unchanged.
	rep.Surfaces = append(rep.Surfaces, unarmedCoverage(result)...)

	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageDirect:
			rep.Direct++
		case CoverageDelegated:
			rep.Delegated++
		case CoverageSkipped:
			rep.Skipped++
		default:
			rep.Uncovered++
		}
	}
	rep.WouldGate = rep.Uncovered > 0
	// Observe-only phase: nothing is ever withheld. Set explicitly so the
	// record carries the fact rather than leaving it to be inferred.
	rep.DidGate = false
	return rep
}

// isDelegatedSurface reports whether ifidx is a VLAN sub-interface, which the
// userspace shim covers from the parent rather than attaching to directly.
// This is exactly how compiler_iface.go marks them.
func isDelegatedSurface(result *CompileResult, ifidx int) bool {
	return result.genericXDPIfindexes[ifidx] && !result.tunnelIfindexes[ifidx]
}

// coverDirect classifies one attach point that must carry its own instance.
func coverDirect(lookup instanceLookup, ifidx int) SurfaceCoverage {
	s := SurfaceCoverage{Ifindex: ifidx}
	progID, generic, ok := lookup(ifidx)
	if !ok {
		s.Generic = generic
		s.Detail = "no shim instance attached"
		return s
	}
	s.Kind = CoverageDirect
	s.ProgramID = progID
	s.Generic = generic
	if generic {
		s.Detail = "attached (generic/skb-mode — enforcing, counts as armed)"
	} else {
		s.Detail = "attached (native)"
	}
	return s
}

// coverDelegated classifies one VLAN sub-interface against its parent.
//
// The parent must be a REQUIRED surface and must itself have classified as
// CoverageDirect. Accepting any tracked link would let a child report covered
// against a parent nothing proves is armed — see the DELEGATED COVERAGE note.
//
// The `direct` map already encodes both conditions (it holds exactly the
// required, non-delegated surfaces), so the explicit isRequired check does not
// change the verdict — it sharpens the recorded REASON, which is the whole
// output of an observe-only phase.
func coverDelegated(
	result *CompileResult,
	direct map[int]SurfaceCoverage,
	isRequired map[int]bool,
	ifidx int,
) SurfaceCoverage {
	s := SurfaceCoverage{Ifindex: ifidx}

	lnk, err := result.peekLinkByIndex(ifidx)
	if err != nil {
		s.Detail = fmt.Sprintf("vlan child: parent unresolvable: %v", err)
		return s
	}
	if lnk == nil {
		s.Detail = "vlan child: parent unresolvable: no link"
		return s
	}
	parent := lnk.Attrs().ParentIndex
	if parent <= 0 {
		s.Detail = "vlan child: no parent ifindex"
		return s
	}
	s.Via = parent

	if !isRequired[parent] {
		s.Detail = fmt.Sprintf(
			"vlan child: delegate ifindex %d is not a required surface — nothing proves it armed", parent)
		return s
	}
	pc, ok := direct[parent]
	if !ok {
		s.Detail = fmt.Sprintf(
			"vlan child: delegate ifindex %d is not itself a direct surface", parent)
		return s
	}
	if pc.Kind != CoverageDirect {
		s.Detail = fmt.Sprintf(
			"vlan child: delegate ifindex %d carries no shim instance", parent)
		return s
	}

	s.Kind = CoverageDelegated
	s.ProgramID = pc.ProgramID
	s.Generic = pc.Generic
	s.Detail = fmt.Sprintf("covered by parent ifindex %d", parent)
	return s
}

// unarmedCoverage renders the surfaces the compiler declined to arm.
//
// Ordered by name so two reports of the same box are diffable; the ifindex is
// not a usable sort key here because a missing interface has none.
func unarmedCoverage(result *CompileResult) []SurfaceCoverage {
	if len(result.unarmedSurfaces) == 0 {
		return nil
	}
	out := make([]SurfaceCoverage, 0, len(result.unarmedSurfaces))
	for _, u := range result.unarmedSurfaces {
		s := SurfaceCoverage{
			Ifindex: u.Ifindex,
			Name:    u.Name,
			Kind:    CoverageSkipped,
			Detail:  u.Reason,
		}
		if u.StillForwarding {
			s.Kind = CoverageUncovered
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Ifindex < out[j].Ifindex
	})
	return out
}

// Kernel XDP attach modes (uapi/linux/if_link.h, mirrored in nl/link_linux.go).
const (
	xdpAttachedNone  = 0 // no program attached
	xdpAttachedDrv   = 1 // XDP_ATTACHED_DRV — driver (native) mode
	xdpAttachedSKB   = 2 // XDP_ATTACHED_SKB — generic (skb) mode
	xdpAttachedHW    = 3 // XDP_ATTACHED_HW  — hardware offload
	xdpAttachedMulti = 4 // XDP_ATTACHED_MULTI — programs in more than one mode
)

// xdpModeIsGeneric decides whether a kernel attach mode counts as skb-mode for
// the coverage measurement. Pure, so every mode including the ones a test
// cannot produce is covered by a table.
//
// XDP_ATTACHED_MULTI counts as GENERIC. It means programs are attached in more
// than one mode, so the kernel cannot report a single one — and it is reachable
// here: attachUserspaceShimXDP DISCARDS m.DetachXDP's error on the native
// fallback path, so a failed detach followed by the generic re-attach leaves
// two links on the interface. Reading MULTI as native would undercount the
// slow-path population, which is the same direction as the defect that made
// this flag come from the kernel in the first place.
func xdpModeIsGeneric(attached bool, mode uint32) bool {
	if !attached {
		return false
	}
	return mode == xdpAttachedSKB || mode == xdpAttachedMulti
}

// xdpLinkModeGeneric reports whether ifindex currently carries an XDP program
// in GENERIC (skb) mode, read from the KERNEL.
//
// Ground truth, deliberately, and not control-plane bookkeeping. The
// native->generic fallback in attachUserspaceShimXDP happens ONCE, and the
// resulting m.xdpLinks entry SURVIVES across compiles — syncInterfaceAttachments
// detaches only ifindexes outside the allowed ingress set, and the pin sweep in
// userspace/manager_compile.go deletes link PINS, not the map. So every later
// compile short-circuits on "already attached" and any per-compile record of
// the fallback is empty while the box is still on skb-mode. A proof that read
// that record would report "went native" on every commit after the first, on
// precisely the population (iavf SR-IOV VFs) whose measurement is the point of
// this phase.
//
// A package-level var because a unit test cannot attach XDP.
var xdpLinkModeGeneric = func(ifindex int) bool {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil || l == nil {
		return false
	}
	xdp := l.Attrs().Xdp
	if xdp == nil {
		return false
	}
	return xdpModeIsGeneric(xdp.Attached, xdp.AttachMode)
}

// xdpLinkProgramID reads back the program instance bound to a tracked bpf_link.
//
// A package-level var because link.Link carries an unexported method and cannot
// be implemented outside cilium/ebpf, so Manager.attachedInstance is otherwise
// unreachable from a unit test.
var xdpLinkProgramID = func(l link.Link) (progID uint32, ok bool) {
	if l == nil {
		return 0, false
	}
	info, err := l.Info()
	if err != nil || info == nil {
		return 0, false
	}
	return uint32(info.Program), true
}

// attachedInstance reads back the program instance bound at ifidx.
//
// ok=false means no link is tracked for this ifindex, or the readback failed —
// both degrade the surface to uncovered rather than being papered over.
//
// The generic flag is the LIVE kernel attach mode (xdpLinkModeGeneric), not
// anything this compile recorded, because the mode persists across compiles and
// the per-compile record does not.
func (m *Manager) attachedInstance(ifidx int) (progID uint32, generic bool, ok bool) {
	l, exists := m.xdpLinks[ifidx]
	if !exists {
		return 0, false, false
	}
	generic = xdpLinkModeGeneric(ifidx)
	progID, ok = xdpLinkProgramID(l)
	if !ok {
		// A tracked link whose identity cannot be read is NOT proof of
		// coverage; report it with a zero instance so the divergence is
		// visible rather than assumed benign.
		return 0, generic, false
	}
	return progID, generic, true
}

// LogArmCoverage emits the observe-only proof result (#5275 PR1).
//
// One line per COMPILE — never per packet or per poll tick. Not one line per
// apply: a single daemon apply compiles TWICE on the RETH deferred-MAC path
// (daemon_apply_dataplane.go calls reapplyAfterDeferredMAC), so seq is folded
// into the stage label to keep the two records distinguishable.
//
// The line is emitted UNCONDITIONALLY, including when the proof enumerated no
// surfaces at all. Suppressing it would make "nothing to arm", "the proof did
// not run" and "the build has no proof" identical in a log archive — the very
// failure mode this file's DidGate rationale exists to reject. `ran` separates
// the first two; the absence of the line separates the third.
//
// It states plainly that nothing was gated, so an operator reading a WOULD-GATE
// line does not believe traffic was affected.
func (rep ArmCoverageReport) LogArmCoverage(stage string, seq uint64) {
	// One label for the whole proof run, so the summary line and every
	// per-surface line below correlate to the SAME compile.
	label := fmt.Sprintf("%s#%d", stage, seq)
	slog.Info("dataplane arm-coverage proof",
		"issue", "#5275",
		"stage", label,
		"ran", rep.Ran,
		"direct", rep.Direct,
		"delegated", rep.Delegated,
		"skipped", rep.Skipped,
		"uncovered", rep.Uncovered,
		// Both are emitted every time. would_gate is the measurement;
		// did_gate is the fact that nothing was withheld. Reporting only the
		// first would make "the proof said refuse" and "the proof refused"
		// indistinguishable in a log archive.
		"would_gate", rep.WouldGate,
		"did_gate", rep.DidGate,
		// Per-surface branch, so the direct/delegated/skipped/uncovered mix is
		// recoverable per box without one line per interface.
		"surfaces", rep.SurfaceSummary())
	// Only the surfaces a gating build would have refused on are worth a
	// per-surface line; a fully-covered box stays at one line. A SKIPPED
	// surface gets one too — the compiler declined to arm it and said so only
	// at WARN, so the proof restates it in its own terms.
	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageUncovered:
			slog.Warn("dataplane arm-coverage: surface WOULD fail a gating proof (NOT gated in this build)",
				"issue", "#5275",
				"stage", label,
				"surface", s.label(),
				"detail", s.Detail)
		case CoverageSkipped:
			slog.Warn("dataplane arm-coverage: compiler DECLINED to arm this surface (compile still succeeded)",
				"issue", "#5275",
				"stage", label,
				"surface", s.label(),
				"detail", s.Detail)
		}
	}
}
