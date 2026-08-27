package config

import "math"

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
func cosSchedulerRateResolves(cos *ClassOfServiceConfig, sched *CoSScheduler, shaped map[string]bool) bool {
	if sched == nil {
		return false
	}
	if sched.TransmitRateBytes > 0 {
		return true
	}
	if sched.TransmitRatePercent > 0 {
		return shaped[sched.Name]
	}
	if sched.TransmitRateRemainder {
		// A shaping base is NECESSARY for `remainder` but not sufficient: the
		// leftover can be nothing. `percent 60` + `percent 40` + `remainder` is
		// an ordinary Junos shape and leaves exactly zero, and the dataplane
		// declines a zero share rather than resolving to it (zero is its
		// "unshaped" sentinel — see cos_remainder_rate_bytes).
		//
		// Answering "resolves" here for a zero leftover would suppress the
		// commit advisory on a queue that is still inert at runtime: an
		// operator told nothing about a knob that does nothing. That is the
		// exact failure the narrowing was introduced to avoid, in the opposite
		// direction.
		return shaped[sched.Name] && cosRemainderLeftoverIsPositive(cos, sched.Name)
	}
	return false
}

// cosSchedulerTemporalResolves reports whether `buffer-size temporal <us>` has
// a drain rate to convert against (#6846).
//
// DELIBERATELY weaker than cosSchedulerRateResolves. Temporal converts against
// `transmit_rate_bytes` at the forwarding_build call site, and that value is
// `explicit_transmit_rate_bytes.unwrap_or(iface.cos_shaping_rate_bytes_per_sec)`
// — so a queue with no guarantee of its own still drains at the interface
// shaping rate, and its microsecond target still has a byte value. Only a queue
// whose effective rate is ZERO leaves temporal inert.
//
// An earlier revision of #6846 reused cosSchedulerRateResolves here and warned
// that the knob "has no effect" for configurations where it has one — a queue
// whose `remainder` did not resolve still got a temporal-sized buffer off the
// interface rate. The advisory TEXT already named the correct condition ("no
// absolute rate, and no scheduler-map binding to an interface with a root
// shaping-rate"), so the message and the predicate disagreed and the message
// was right. build_cos_state_temporal_converts_against_the_fallback_drain_rate
// pins the runtime fact this predicate depends on.
func cosSchedulerTemporalResolves(sched *CoSScheduler, shaped map[string]bool) bool {
	if sched == nil {
		return false
	}
	return sched.TransmitRateBytes > 0 || shaped[sched.Name]
}

// cosSaturatingAdd mirrors the `u128` saturating accumulation the Rust pre-pass
// uses for `claimed`. Wrapping here would make an over-subscribed set of
// siblings look like a SMALL claim and hand the remainder queue a leftover it
// does not have.
func cosSaturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// cosRemainderLeftoverIsPositive reports whether ANY interface binding gives
// `sched` a non-zero remainder share (#6846).
//
// This is the control-plane mirror of `cos_remainder_rate_bytes` and must apply
// the same rule: subtract the RESOLVED siblings (absolute, or percent through
// resolveCoSPercentRateBytes, the package's single mirror of the Rust rounding
// — this arm was an inline multiply until it drifted, see #6846 F6), count the
// remainder-marked queues, and floor the split. It is ANY rather than ALL because a named scheduler can be bound to
// several interfaces and only needs to do something somewhere for the advisory
// to be wrong.
//
// The duplication is deliberate and bounded: the Go side decides whether an
// operator is WARNED and the Rust side decides what the dataplane DOES, so they
// must agree, and there is no shared representation between them to compute it
// once. TestRemainderAdvisoryTracksTheLeftover6846 pins the AGREEMENT rather
// than either side's literals — each row transcribes a named cell from the Rust
// `remainder_temporal_tests_6846` module and asserts the advisory is silent IFF
// that cell resolves — including one row at a FRACTIONAL percent, the only
// shape that can see a rounding divergence.
// TestRemainderLeftoverThatFloorsToZeroStillWarns6846 pins the floor and
// TestRemainderLeftoverIgnoresAnOutOfRangePercentSibling6846 the domain: the
// three places two implementations of one rule drift first.
func cosRemainderLeftoverIsPositive(cos *ClassOfServiceConfig, name string) bool {
	if cos == nil {
		return false
	}
	positive := false
	forUnit := func(unit *CoSInterfaceUnit) {
		if positive || unit == nil || unit.SchedulerMap == "" || unit.ShapingRateBytes == 0 {
			return
		}
		sm := cos.SchedulerMaps[unit.SchedulerMap]
		if sm == nil {
			return
		}
		var claimed uint64
		var remainderQueues uint64
		bound := false
		for _, entry := range sm.Entries {
			if entry == nil || entry.Scheduler == "" {
				continue
			}
			sib := cos.Schedulers[entry.Scheduler]
			if sib == nil {
				continue
			}
			if entry.Scheduler == name {
				bound = true
			}
			switch {
			case sib.TransmitRateBytes > 0:
				claimed = cosSaturatingAdd(claimed, sib.TransmitRateBytes)
			case sib.TransmitRatePercent > 0:
				// Through the shared mirror, NOT an inline expression. The
				// inline form truncated where Rust ceils, which made this
				// side's leftover larger and suppressed the advisory on
				// configurations the dataplane declines (#6846 F6).
				// Through resolveCoSPercentRateBytes, the package's ONE mirror
				// of the Rust rounding — a 0 return means "no usable rate", and
				// a usable one is always >= 1 because of the min-1 clamp, so
				// `> 0` is an exact test rather than a heuristic.
				if bytes := resolveCoSPercentRateBytes(unit.ShapingRateBytes, sib.TransmitRatePercent); bytes > 0 {
					claimed = cosSaturatingAdd(claimed, bytes)
				}
			case sib.TransmitRateRemainder:
				remainderQueues++
			}
		}
		if !bound || remainderQueues == 0 || claimed >= unit.ShapingRateBytes {
			return
		}
		if (unit.ShapingRateBytes-claimed)/remainderQueues > 0 {
			positive = true
		}
	}
	for _, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		forUnit(iface.Level)
		for _, unit := range iface.Units {
			forUnit(unit)
		}
	}
	return positive
}
