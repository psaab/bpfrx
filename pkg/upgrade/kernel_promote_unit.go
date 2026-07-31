package upgrade

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrKernelPromotionUnitAbsent marks an arm-time refusal: the systemd unit the
// promotion gate derives the live xpfd from does not exist on this host, so a
// candidate armed here could never be verified or promoted.
var ErrKernelPromotionUnitAbsent = errors.New("kernel promotion unit absent")

// kernelPromotionUnitProbeTimeout bounds the arm-time LoadState query. Short:
// this runs interactively, and an unreachable systemd must not hang `arm`.
const kernelPromotionUnitProbeTimeout = 5 * time.Second

// CheckKernelPromotionUnit refuses to arm a kernel candidate on a host whose
// promotion gate could never run (#6601 r5 MINOR-1).
//
// THE PROBLEM. scripts/image/xpf-kernel-promote — the boot-time outer hop —
// derives the live xpfd from ONE pinned systemd unit, DefaultUnit + ".service".
// It does not infer which unit is the xpf one, deliberately: scanning for a
// <something>.service.d/10-xpf-version.conf would resolve a leftover from a
// renamed or removed unit exactly as readily as the live one, which is the
// indistinguishable-leftover class the gate was rewritten to eliminate. There
// is also no authoritative record to read instead — flip writes its drop-in
// UNDER <unit>.service.d/ without recording the unit name anywhere.
//
// But `xpfd upgrade cut --unit <name>` is a SUPPORTED standalone selector, and
// on such a host flip maintains <name>.service while <SbinDir>/xpfd is still
// repointed by step 6b. The promotion gate then queries a unit that does not
// exist, cannot resolve a binary, and an armed candidate would boot, run
// UNVERIFIED, and never be promoted.
//
// THE FIX IS TO FAIL EARLY, NOT TO GUESS. Refusing at arm time puts the failure
// at the operator's terminal, where it is actionable, instead of at the next
// boot where it is a journal line nobody is watching. This mirrors the #1983
// precedent: NewCLICluster likewise refuses a non-default --unit rather than
// drive control against the wrong daemon, on the same reasoning — until a
// mapping exists, only the default layout is supported, and saying so beats
// acting on a guess.
//
// TRI-STATE, AND ONLY A DEFINITE ABSENCE REFUSES. `systemctl show` exits 0 and
// prints "not-found" for an unknown unit, so a probe ERROR means systemctl
// could not be consulted — which proves nothing about whether the unit exists.
// Collapsing that into "absent" would block arming on any host where systemd
// was briefly unreachable. So:
//
//	LoadState == "not-found"  -> REFUSE (definite: the gate cannot run here)
//	probe error / empty       -> ALLOW  (indeterminate: do not block on nothing)
//	anything else             -> ALLOW  (loaded, masked, bad-setting, ...)
//
// A masked or bad-setting unit is deliberately allowed: the unit EXISTS, so the
// gate can still read its ExecStart, which is all it needs. The boot-time gate
// applies the same known/absent/unknown split, so the two ends agree.
func CheckKernelPromotionUnit(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, kernelPromotionUnitProbeTimeout)
	defer cancel()

	state, err := UnitLoadState(probeCtx, DefaultUnit)
	if err != nil {
		// Indeterminate. Not evidence of absence — allow.
		return nil
	}
	if state != "not-found" {
		return nil
	}
	return fmt.Errorf("%w: systemd reports %s.service not-found, but the kernel "+
		"promotion gate derives the live xpfd from that unit specifically and "+
		"does NOT infer which unit is the xpf one (inferring it would resolve a "+
		"leftover from a renamed unit just as readily as the live one). Arming "+
		"here would boot a candidate kernel that runs UNVERIFIED and is never "+
		"promoted. If this host runs xpfd under a different unit (`xpfd upgrade "+
		"cut --unit <name>`), the kernel channel does not support that layout; "+
		"restore %s.service, or use image-replace (LANE 2) for kernel updates",
		ErrKernelPromotionUnitAbsent, DefaultUnit, DefaultUnit)
}
