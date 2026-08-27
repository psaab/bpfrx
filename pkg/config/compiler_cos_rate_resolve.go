package config

// CoS transmit-rate resolvability predicates.
//
// Split out of compiler_class_of_service.go (#6846). These two answer one
// question — can this scheduler end up with an absolute byte/sec rate? — and
// they are the CONTROL-PLANE mirror of `cos_effective_transmit_rate_bytes` /
// `cos_remainder_rate_bytes` in `userspace-dp/src/afxdp/forwarding_build/cos.rs`.
//
// They belong together because they must agree with that Rust side and with
// each other: this file decides whether an operator is WARNED that a knob is
// inert, and the Rust side decides what the dataplane actually DOES. A drift
// between them is either a warning on a configuration that works, or silence on
// one that does not — and both are the failure #6846 exists to remove.

func cosSchedulersWithShapedBinding(cos *ClassOfServiceConfig) map[string]bool {
	resolved := make(map[string]bool)
	if cos == nil {
		return resolved
	}
	markUnit := func(unit *CoSInterfaceUnit) {
		if unit == nil || unit.SchedulerMap == "" || unit.ShapingRateBytes == 0 {
			return
		}
		sm := cos.SchedulerMaps[unit.SchedulerMap]
		if sm == nil {
			return
		}
		for _, entry := range sm.Entries {
			if entry != nil && entry.Scheduler != "" {
				resolved[entry.Scheduler] = true
			}
		}
	}
	for _, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		markUnit(iface.Level)
		for _, unit := range iface.Units {
			markUnit(unit)
		}
	}
	return resolved
}

// cosSchedulersWithShapedBinding returns the set of scheduler names that are
// bound — via a scheduler-map applied to an interface unit with a non-zero
// root shaping-rate — to at least one shaped interface. A `transmit-rate
// percent <n>` on such a scheduler RESOLVES: forwarding_build/cos.rs computes
// the absolute byte/sec rate against the interface's shaping-rate. A scheduler
// NOT in this set has no shaping base, so its percent stays inert; the
// ValidateConfig advisory flags exactly that residual. Must run AFTER
// resolveCoSTrafficControlProfiles so unit.ShapingRateBytes reflects a folded
// traffic-control-profile shaping-rate (including a resolved shaping-rate
// percent).
// cosSchedulerRateResolves reports whether a scheduler ends up with a
// resolvable absolute transmit rate (#6846).
//
// Three ways to get one, matching cos_effective_transmit_rate_bytes in
// forwarding_build/cos.rs — the two must agree, because this decides whether an
// operator is WARNED and that one decides what the dataplane DOES:
//
//   - an explicit absolute rate, which needs nothing else;
//   - a `percent`, which needs a shaping base to resolve against;
//   - a `remainder`, which needs the same base to take a remainder OF.
//
// The last two share `shaped` — a scheduler bound via a scheduler-map to an
// interface carrying a root shaping-rate — which is why one predicate covers
// both rather than two that can drift apart.
func cosSchedulerRateResolves(sched *CoSScheduler, shaped map[string]bool) bool {
	if sched == nil {
		return false
	}
	if sched.TransmitRateBytes > 0 {
		return true
	}
	if sched.TransmitRatePercent > 0 || sched.TransmitRateRemainder {
		return shaped[sched.Name]
	}
	return false
}
