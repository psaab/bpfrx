package config

import (
	"fmt"
	"sort"
)

// validateCoSOversubscriptionWarnings emits commit-time warnings for
// every CoS interface unit whose sum of exact-class transmit rates
// exceeds the unit's configured shaping-rate. Warnings are non-fatal;
// the runtime accepts the config and the new
// oversubscription-policy knob (#1614 A1) governs distribution.
func validateCoSOversubscriptionWarnings(cos *ClassOfServiceConfig) []string {
	var warnings []string
	if cos == nil {
		return warnings
	}
	for ifaceName, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		for unitID, unit := range iface.Units {
			if unit == nil || unit.ShapingRateBytes == 0 || unit.SchedulerMap == "" {
				continue
			}
			schedMap, ok := cos.SchedulerMaps[unit.SchedulerMap]
			if !ok || schedMap == nil {
				continue
			}
			var sumExact uint64
			for _, entry := range schedMap.Entries {
				if entry == nil || entry.Scheduler == "" {
					continue
				}
				sched, ok := cos.Schedulers[entry.Scheduler]
				if !ok || sched == nil || !sched.TransmitRateExact {
					continue
				}
				sumExact += sched.TransmitRateBytes
			}
			if sumExact <= unit.ShapingRateBytes {
				continue
			}
			policyTail := "proportional (default): each class receives classRate × shaping / sumExact (current behaviour)"
			if unit.OversubscriptionPolicy == "guarantee-rate" {
				policyTail = fmt.Sprintf(
					"guarantee-rate %g: small classes honoured to configured rate; larger classes share residual proportionally (see #1614)",
					unit.OversubscriptionGuaranteeFraction,
				)
			}
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service interfaces %s unit %d: sum of exact-class transmit-rates (%d B/s) exceeds shaping-rate (%d B/s); under oversubscription the configured oversubscription-policy=%s",
				ifaceName, unitID, sumExact, unit.ShapingRateBytes, policyTail,
			))
		}
	}
	return warnings
}

// classOfServiceClassifierQueueWarnings (#hb166 T-4) flags a behavior-aggregate
// (DSCP / IEEE 802.1p) classifier code-point on this interface unit that maps
// to a DEFINED forwarding-class whose queue is NOT materialized on the unit
// (the forwarding-class has no scheduler-map entry, so the dataplane never
// builds that queue). Pre-fix such a code-point was a 100% silent blackhole;
// the dataplane now fails SAFE and forwards it on the best-effort queue
// (forwarding_build/cos.rs), but the operator should still see that the
// intended queue does not exist on this interface.
//
// This is a WARN, not a strict reject. A classifier steering to a
// forwarding-class that merely lacks a scheduler-map entry is a valid Junos
// config — Junos queues exist by default without a scheduler-map binding — so
// rejecting it (as the dangling-SCHEDULER gate does for an undefined scheduler
// name) would refuse configs Junos accepts and configs xpf's own test suite
// asserts compile.
//
// The materialization + admission model mirrors
// forwarding_build/cos.rs::build_cos_iface_config exactly so the warning fires
// iff the dataplane would have blackholed the code-point: only when the
// interface is actually admitted to CoS (a resolved scheduler-map, a
// shaping-rate, a classifier code-point that DOES hit a materialized queue, or
// a rewrite targeting a materialized class). An un-admitted interface builds no
// CoS runtime, so its classifier is inert and nothing blackholes — no warning.
func classOfServiceClassifierQueueWarnings(cos *ClassOfServiceConfig, ifaceName string, unit *CoSInterfaceUnit) []string {
	if cos == nil || unit == nil {
		return nil
	}
	dscpCls := cos.DSCPClassifiers[unit.DSCPClassifier]
	ieeeCls := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]
	// #7082: the THIRD behavior-aggregate arm. #6847 added inet-precedence to
	// build_cos_iface_config, and this function's own doc comment promises the
	// model "mirrors build_cos_iface_config EXACTLY so the warning fires iff the
	// dataplane would have blackholed the code-point". With only two arms that
	// sentence was false for every unit whose blackholing classifier was the
	// inet-precedence one: the dataplane fell back to best-effort and the
	// operator was told nothing.
	//
	// Defs, not the name list, is right HERE — unlike the definedness check in
	// compiler_validate_warn.go — because this arm needs the ENTRIES to know
	// which forwarding-classes the classifier maps to. A classifier with no
	// entries maps no code-point and so can blackhole nothing, which is exactly
	// the nil case below.
	inetCls := cos.INetPrecedenceClassifierDefs[unit.INetPrecedenceClassifier]
	if dscpCls == nil && ieeeCls == nil && inetCls == nil {
		// No classifier attached (or the reference is undefined — flagged
		// elsewhere): nothing can blackhole.
		return nil
	}

	// Queues this unit materializes: the DEFINED forwarding-classes named by
	// its scheduler-map, else the synthetic best-effort queue 0 when the
	// scheduler-map resolves to nothing.
	matQueues := map[int]bool{}
	schedMapResolved := false
	if unit.SchedulerMap != "" {
		if sm := cos.SchedulerMaps[unit.SchedulerMap]; sm != nil {
			for className := range sm.Entries {
				if fc := cos.ForwardingClasses[className]; fc != nil {
					matQueues[fc.Queue] = true
					schedMapResolved = true
				}
			}
		}
	}
	if !schedMapResolved {
		matQueues = map[int]bool{0: true}
	}

	// Partition the classifier's referenced forwarding-classes into
	// materialized-queue hits vs blackholed (DEFINED class, unmaterialized
	// queue). An UNDEFINED class is skipped — the dataplane drops it from the
	// classifier table and the undefined-class warn already flags it.
	anyHit := false
	blackholed := map[string]int{}
	seen := map[string]bool{}
	classify := func(class string) {
		if class == "" || seen[class] {
			return
		}
		seen[class] = true
		fc := cos.ForwardingClasses[class]
		if fc == nil {
			return
		}
		if matQueues[fc.Queue] {
			anyHit = true
		} else {
			blackholed[class] = fc.Queue
		}
	}
	if dscpCls != nil {
		for _, e := range dscpCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}
	if ieeeCls != nil {
		for _, e := range ieeeCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}
	if inetCls != nil {
		for _, e := range inetCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}

	// A rewrite rule targeting a materialized class also admits the interface.
	rewriteHit := false
	if rr := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; rr != nil {
		for _, e := range rr.Entries {
			if e == nil {
				continue
			}
			if fc := cos.ForwardingClasses[e.ForwardingClass]; fc != nil && matQueues[fc.Queue] {
				rewriteHit = true
				break
			}
		}
	}

	admitted := schedMapResolved || unit.ShapingRateBytes > 0 || anyHit || rewriteHit
	if !admitted || len(blackholed) == 0 {
		return nil
	}

	classes := make([]string, 0, len(blackholed))
	for class := range blackholed {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	warnings := make([]string, 0, len(classes))
	for _, class := range classes {
		warnings = append(warnings, fmt.Sprintf(
			"class-of-service interface %s unit %d classifier maps code-point(s) to forwarding-class %q (queue %d) which has no scheduler-map entry on this interface; the userspace dataplane forwards matching traffic on the best-effort queue",
			ifaceName, unit.Unit, class, blackholed[class]))
	}
	return warnings
}
