package dataplane

import (
	"fmt"
	"log/slog"
	"sort"
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
// control input; nothing in this file mutates Manager state or returns an error
// that any caller acts on.
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
)

func (k SurfaceCoverageKind) String() string {
	switch k {
	case CoverageDirect:
		return "direct"
	case CoverageDelegated:
		return "delegated"
	default:
		return "uncovered"
	}
}

// SurfaceCoverage is the proof outcome for one required attach point.
type SurfaceCoverage struct {
	Ifindex int
	Kind    SurfaceCoverageKind
	// Via is the covering parent ifindex when Kind is CoverageDelegated.
	Via int
	// ProgramID is the attached program INSTANCE (bpf_link readback) for a
	// direct surface, or the delegate's instance for a delegated one. Zero
	// means the readback did not yield one — reported, never inferred.
	ProgramID uint32
	// Generic records that this surface is covered in skb-mode rather than
	// driver-mode XDP. Informational: it does NOT reduce coverage.
	Generic bool
	Detail  string
}

// ArmCoverageReport is the whole-surface outcome of one proof run.
type ArmCoverageReport struct {
	Surfaces  []SurfaceCoverage
	Direct    int
	Delegated int
	Uncovered int
	// WouldGate reports whether a GATING build would have refused to release
	// ownership on this proof. Observe-only: no caller may branch on it.
	WouldGate bool
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
// Delegation is therefore RESOLVED, not assumed: the parent must itself be
// directly covered, or the child is uncovered.

// ProveArmCoverage computes the arm-coverage proof for the surfaces result
// requires, WITHOUT gating anything (#5275 PR1, observe-only).
//
// It is a pure read of compile state plus bpf_link readback: it takes no locks
// beyond the readback, mutates nothing, and never returns an error a caller
// acts on. A readback failure degrades that surface to uncovered and is
// reported — the conservative direction, matching what a gating build would do.
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
	if result == nil || lookup == nil || len(result.pendingXDP) == 0 {
		return rep
	}

	// Deterministic order so the log line is stable across boots and two
	// reports can be diffed.
	required := append([]int(nil), result.pendingXDP...)
	sort.Ints(required)

	for _, ifidx := range required {
		rep.Surfaces = append(rep.Surfaces, coverSurface(result, lookup, ifidx))
	}
	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageDirect:
			rep.Direct++
		case CoverageDelegated:
			rep.Delegated++
		default:
			rep.Uncovered++
		}
	}
	rep.WouldGate = rep.Uncovered > 0
	return rep
}

// coverSurface classifies one required attach point.
func coverSurface(result *CompileResult, lookup instanceLookup, ifidx int) SurfaceCoverage {
	s := SurfaceCoverage{Ifindex: ifidx}

	// Delegated: a VLAN sub-interface under the userspace shim carries no
	// program of its own by design. Resolve the parent rather than assuming
	// either outcome.
	if result.genericXDPIfindexes[ifidx] && !result.tunnelIfindexes[ifidx] {
		lnk, err := result.cachedLinkByIndex(ifidx)
		if err != nil {
			s.Detail = fmt.Sprintf("vlan child: parent unresolvable: %v", err)
			return s
		}
		parent := lnk.Attrs().ParentIndex
		if parent <= 0 {
			s.Detail = "vlan child: no parent ifindex"
			return s
		}
		progID, generic, ok := lookup(parent)
		if !ok {
			s.Via = parent
			s.Detail = fmt.Sprintf("vlan child: delegate ifindex %d carries no shim instance", parent)
			return s
		}
		s.Kind = CoverageDelegated
		s.Via = parent
		s.ProgramID = progID
		s.Generic = generic
		s.Detail = fmt.Sprintf("covered by parent ifindex %d", parent)
		return s
	}

	// Direct: an instance attached here. Native and generic both count.
	progID, generic, ok := lookup(ifidx)
	if !ok {
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

// attachedInstance reads back the program instance bound at ifidx.
//
// ok=false means no link is tracked for this ifindex, or the readback failed —
// both degrade the surface to uncovered rather than being papered over. The
// generic flag comes from Manager state rather than being inferred from the
// link, so a surface deliberately kept on skb-mode is not mistaken for a
// native attach that silently fell back.
func (m *Manager) attachedInstance(ifidx int) (progID uint32, generic bool, ok bool) {
	l, exists := m.xdpLinks[ifidx]
	if !exists || l == nil {
		return 0, false, false
	}
	if lc := m.lastCompile; lc != nil {
		generic = lc.fallbackGenericIfindexes[ifidx] || lc.tunnelIfindexes[ifidx]
	}
	info, err := l.Info()
	if err != nil || info == nil {
		// A tracked link whose identity cannot be read is NOT proof of
		// coverage; report it with a zero instance so the divergence is
		// visible rather than assumed benign.
		return 0, generic, false
	}
	return uint32(info.Program), generic, true
}

// LogArmCoverage emits the observe-only proof result (#5275 PR1).
//
// One line per apply, never per packet or per poll tick. It states plainly that
// nothing was gated, so an operator reading a WOULD-GATE line does not believe
// traffic was affected.
func (rep ArmCoverageReport) LogArmCoverage(stage string) {
	if len(rep.Surfaces) == 0 {
		return
	}
	slog.Info("dataplane arm-coverage proof (observe-only; nothing gated)",
		"issue", "#5275",
		"stage", stage,
		"direct", rep.Direct,
		"delegated", rep.Delegated,
		"uncovered", rep.Uncovered,
		"would_gate", rep.WouldGate)
	// Only the surfaces a gating build would have refused on are worth a
	// per-surface line; a fully-covered box stays at one line.
	for _, s := range rep.Surfaces {
		if s.Kind == CoverageUncovered {
			slog.Warn("dataplane arm-coverage: surface WOULD fail a gating proof (not gated here)",
				"issue", "#5275",
				"stage", stage,
				"ifindex", s.Ifindex,
				"detail", s.Detail)
		}
	}
}
