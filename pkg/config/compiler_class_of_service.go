package config

import (
	"fmt"
	"strconv"
	"strings"

	fairnesscontract "github.com/psaab/xpf/pkg/fairness"
)

func compileClassOfService(node *Node, cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	if cos.ForwardingClasses == nil {
		cos.ForwardingClasses = make(map[string]*CoSForwardingClass)
	}
	if cos.DSCPClassifiers == nil {
		cos.DSCPClassifiers = make(map[string]*CoSDSCPClassifier)
	}
	if cos.IEEE8021Classifiers == nil {
		cos.IEEE8021Classifiers = make(map[string]*CoSIEEE8021Classifier)
	}
	if cos.DSCPRewriteRules == nil {
		cos.DSCPRewriteRules = make(map[string]*CoSDSCPRewriteRule)
	}
	if cos.Schedulers == nil {
		cos.Schedulers = make(map[string]*CoSScheduler)
	}
	if cos.SchedulerMaps == nil {
		cos.SchedulerMaps = make(map[string]*CoSSchedulerMap)
	}
	if cos.Interfaces == nil {
		cos.Interfaces = make(map[string]*CoSInterface)
	}
	if cos.TrafficControlProfiles == nil {
		cos.TrafficControlProfiles = make(map[string]*CoSTrafficControlProfile)
	}
	if fcNode := node.FindChild("forwarding-classes"); fcNode != nil {
		// Enforce the FC ↔ queue bijection. Junos semantics give
		// each queue ID one forwarding class, and each FC one
		// queue — schedulers attach to an FC, so two FCs on one
		// queue give the queue two conflicting rate targets, and
		// one FC on two queues leaves classifier / scheduler-map
		// references ambiguous.
		//
		// The userspace dataplane's compile path
		// (`forwarding_build.rs`) iterates the scheduler-map and
		// creates ONE `CoSQueueConfig` per FC. Without this guard
		// either direction of a bijection violation produces
		// inconsistent runtime state that downstream code
		// silently disambiguates three different ways:
		//
		//   * `resolve_cos_queue_idx` returns the first match by
		//     queue_id, so packets for an ambiguous queue go to
		//     whichever duplicate the scheduler-map produced
		//     first.
		//   * The shared-queue lease derives its rate from a
		//     separate path, which can land on yet another value.
		//   * `show class-of-service interface` displays one
		//     entry's FC name alongside a different entry's rate
		//     — a debugger-hostile mismatch on live output.
		//
		// Both directions are rejected:
		//
		//   * queue N → two different FCs (`queue 5 iperf-b`
		//     followed by `queue 5 iperf-c`) surfaced during the
		//     #785 investigation; the scheduler-map would attach
		//     both schedulers to queue 5 at conflicting rates.
		//   * FC X → two different queue numbers (`queue 4 iperf-a`
		//     followed by `queue 5 iperf-a`) — the second silently
		//     overwrote `ForwardingClasses[X].Queue`, leaving any
		//     `classifier`/`scheduler-map` reference to FC X
		//     resolving to the wrong queue at runtime.
		//     (Flagged by Codex review of PR #787; can arise from
		//     `apply-groups` / `${node}` expansion producing
		//     unintended duplicate entries in a user's config.)
		//
		// Idempotent reassignment of the SAME FC to the SAME
		// queue is explicitly allowed so `load merge` /
		// `load override` paths that re-apply the same line
		// remain clean.
		queueOwner := make(map[int]string) // queue_id → FC name
		fcQueue := make(map[string]int)    // FC name → queue_id
		for _, queueNode := range fcNode.FindChildren("queue") {
			if len(queueNode.Keys) < 3 {
				continue
			}
			queue, err := strconv.Atoi(queueNode.Keys[1])
			if err != nil {
				continue
			}
			name := queueNode.Keys[2]
			if existing, claimed := queueOwner[queue]; claimed && existing != name {
				return fmt.Errorf(
					"class-of-service forwarding-classes queue %d: "+
						"forwarding-class %q conflicts with %q "+
						"(a queue can only be owned by one "+
						"forwarding-class; schedulers attach to an "+
						"FC, so two FCs on one queue give the queue "+
						"two conflicting scheduler rates)",
					queue, name, existing,
				)
			}
			if existingQueue, claimed := fcQueue[name]; claimed && existingQueue != queue {
				return fmt.Errorf(
					"class-of-service forwarding-classes "+
						"forwarding-class %q: queue %d conflicts with "+
						"queue %d (an FC can only be assigned to one "+
						"queue; classifier and scheduler-map "+
						"references to %q would otherwise resolve to "+
						"different queues depending on evaluation order)",
					name, queue, existingQueue, name,
				)
			}
			queueOwner[queue] = name
			fcQueue[name] = queue
			cos.ForwardingClasses[name] = &CoSForwardingClass{
				Name:  name,
				Queue: queue,
			}
		}
	}

	if classifiersNode := node.FindChild("classifiers"); classifiersNode != nil {
		for _, inst := range namedInstances(classifiersNode.FindChildren("dscp")) {
			classifier := &CoSDSCPClassifier{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoints, err := collectCoSDSCPCodePoints(lpNode)
					if err != nil {
						return fmt.Errorf("class-of-service classifiers dscp %q: %w", classifier.Name, err)
					}
					if len(codePoints) == 0 {
						continue
					}
					classifier.Entries = append(classifier.Entries, &CoSDSCPClassifierEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						DSCPValues:      codePoints,
					})
				}
			}
			if len(classifier.Entries) > 0 {
				cos.DSCPClassifiers[classifier.Name] = classifier
			}
		}
		for _, inst := range namedInstances(classifiersNode.FindChildren("ieee-802.1")) {
			classifier := &CoSIEEE8021Classifier{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoints, err := collectCoS8021CodePoints(lpNode)
					if err != nil {
						return fmt.Errorf("class-of-service classifiers ieee-802.1 %q: %w", classifier.Name, err)
					}
					if len(codePoints) == 0 {
						continue
					}
					classifier.Entries = append(classifier.Entries, &CoSIEEE8021ClassifierEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						CodePoints:      codePoints,
					})
				}
			}
			if len(classifier.Entries) > 0 {
				cos.IEEE8021Classifiers[classifier.Name] = classifier
			}
		}
		// #4316 (fable-167 F-3b): inet-precedence classifiers are accepted
		// but inert; record their names for the commit advisory.
		for _, inst := range namedInstances(classifiersNode.FindChildren("inet-precedence")) {
			cos.INetPrecedenceClassifiers = append(cos.INetPrecedenceClassifiers, inst.name)
		}
	}

	if rewriteRulesNode := node.FindChild("rewrite-rules"); rewriteRulesNode != nil {
		// #4316 (fable-167 F-3b): inet-precedence and exp rewrite-rules are
		// accepted but inert; record their names for the commit advisory.
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("inet-precedence")) {
			cos.INetPrecedenceRewriteRules = append(cos.INetPrecedenceRewriteRules, inst.name)
		}
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("exp")) {
			cos.EXPRewriteRules = append(cos.EXPRewriteRules, inst.name)
		}
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("dscp")) {
			rewriteRule := &CoSDSCPRewriteRule{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoint, ok, err := collectCoSDSCPRewriteCodePoint(lpNode)
					if err != nil {
						return fmt.Errorf("class-of-service rewrite-rules dscp %q: %w", rewriteRule.Name, err)
					}
					if !ok {
						continue
					}
					rewriteRule.Entries = append(rewriteRule.Entries, &CoSDSCPRewriteRuleEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						DSCPValue:       codePoint,
					})
				}
			}
			if len(rewriteRule.Entries) > 0 {
				cos.DSCPRewriteRules[rewriteRule.Name] = rewriteRule
			}
		}
	}

	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
		sched := &CoSScheduler{Name: inst.name}
		for _, child := range inst.node.Children {
			switch child.Name() {
			case "transmit-rate":
				rate, exact := parseCoSTransmitRate(child)
				if rate > 0 {
					sched.TransmitRateBytes = rate
				}
				sched.TransmitRateExact = sched.TransmitRateExact || exact
			case "priority":
				sched.Priority = nodeVal(child)
			case "buffer-size":
				if v := nodeVal(child); v != "" {
					if percent, err := parsePercentWithSuffixStrict(v); err == nil {
						sched.BufferSizeBytes = 0
						sched.BufferSizePercent = percent
					} else {
						sched.BufferSizeBytes = parseBurstSizeLimit(v)
						sched.BufferSizePercent = 0
					}
				}
			case "surplus-sharing":
				// #915: leaf with no value; presence = true.
				sched.SurplusSharing = true
			case "equal-flow-enforcement":
				sched.EqualFlowEnforcement = true
			case "equal-flow-target-policy":
				// #1746: enum validated by the schema (set time) and
				// validateClassOfServiceStrict (commit time).
				sched.EqualFlowTargetPolicy = nodeVal(child)
			case "codel-target":
				// #1614 A3: value in milliseconds; store as
				// nanoseconds. Empty value = 0 = disabled.
				if v := nodeVal(child); v != "" {
					if ms, err := strconv.ParseUint(v, 10, 64); err == nil {
						sched.CodelTargetNS = ms * 1_000_000
					}
				}
			}
		}
		cos.Schedulers[sched.Name] = sched
	}

	// #4315 (fable-167 F-2): traffic-control-profiles. Each profile carries
	// the Junos hierarchical shaping knobs. The bounded ones (shaping-rate,
	// scheduler-map) are folded into the referencing interface unit by
	// resolveCoSTrafficControlProfiles; guaranteed-rate / delay-buffer-rate
	// are captured but currently inert (see CoSTrafficControlProfile).
	for _, inst := range namedInstances(node.FindChildren("traffic-control-profiles")) {
		tcp := &CoSTrafficControlProfile{Name: inst.name}
		if shapingNode := inst.node.FindChild("shaping-rate"); shapingNode != nil {
			if v := nodeVal(shapingNode); v != "" {
				tcp.ShapingRateBytes = parseBandwidthLimit(v)
			}
		}
		if grNode := inst.node.FindChild("guaranteed-rate"); grNode != nil {
			if v := nodeVal(grNode); v != "" {
				tcp.GuaranteedRateBytes = parseBandwidthLimit(v)
			}
		}
		if dbNode := inst.node.FindChild("delay-buffer-rate"); dbNode != nil {
			if v := nodeVal(dbNode); v != "" {
				tcp.DelayBufferRateBytes = parseBandwidthLimit(v)
			}
		}
		if smNode := inst.node.FindChild("scheduler-map"); smNode != nil {
			tcp.SchedulerMap = nodeVal(smNode)
		}
		cos.TrafficControlProfiles[tcp.Name] = tcp
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
		schedMap := &CoSSchedulerMap{
			Name:    inst.name,
			Entries: make(map[string]*CoSSchedulerMapEntry),
		}
		for _, child := range inst.node.Children {
			if child.Name() != "forwarding-class" || len(child.Keys) < 2 {
				continue
			}
			className := child.Keys[1]
			scheduler := ""
			if len(child.Keys) >= 4 && child.Keys[2] == "scheduler" {
				scheduler = child.Keys[3]
			} else if schedNode := child.FindChild("scheduler"); schedNode != nil {
				scheduler = nodeVal(schedNode)
			}
			schedMap.Entries[className] = &CoSSchedulerMapEntry{
				ForwardingClass: className,
				Scheduler:       scheduler,
			}
		}
		cos.SchedulerMaps[schedMap.Name] = schedMap
	}

	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
		iface := &CoSInterface{
			Name:  inst.name,
			Units: make(map[int]*CoSInterfaceUnit),
		}
		// Interface-level (physical, no `unit`) binding. In Junos a
		// scheduler-map / shaping-rate / classifier / rewrite-rule bound
		// directly under `interfaces geX` applies to every logical unit on
		// the port. Read the same knobs from the interface node itself; the
		// per-unit `unit` children are separate nodes and are unaffected.
		// applyCoSInterfaceLevelBindings folds this into each configured
		// logical unit once the interface stanza is known (#4021).
		level := &CoSInterfaceUnit{Unit: -1}
		parseCoSInterfaceUnitBody(inst.node, level)
		if coSInterfaceUnitHasBinding(level) {
			iface.Level = level
		}
		for _, unitNode := range inst.node.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
			unitID, err := strconv.Atoi(unitNode.Keys[1])
			if err != nil {
				continue
			}
			unit := &CoSInterfaceUnit{Unit: unitID}
			parseCoSInterfaceUnitBody(unitNode, unit)
			if coSInterfaceUnitHasBinding(unit) {
				iface.Units[unitID] = unit
			}
		}
		if len(iface.Units) > 0 || iface.Level != nil {
			cos.Interfaces[iface.Name] = iface
		}
	}

	if fairnessNode := node.FindChild("fairness"); fairnessNode != nil {
		if rssNode := fairnessNode.FindChild("rss-expectation"); rssNode != nil {
			seen := make(map[string]string)
			// #hb166 G-9: rss-expectation is keyed by the STABLE xpf
			// interface name (e.g. ge-0-0-2), not the transient kernel
			// ifindex. The name is resolved to the current ifindex at
			// evaluate time from the live status snapshot, so the
			// expectation survives NIC re-enumeration.
			for _, ifaceNode := range rssNode.FindChildren("interface") {
				if len(ifaceNode.Keys) < 2 {
					continue
				}
				ifaceName := ifaceNode.Keys[1]
				if ifaceName == "" {
					return fmt.Errorf("class-of-service fairness rss-expectation interface: expected non-empty interface name")
				}
				for _, queueNode := range ifaceNode.FindChildren("queue") {
					if len(queueNode.Keys) < 2 {
						continue
					}
					queue, err := strconv.Atoi(queueNode.Keys[1])
					if err != nil || queue < 0 || queue > 255 {
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %q: expected queue 0..255", ifaceName, queueNode.Keys[1])
					}
					expr, err := collectCoSFairnessRSSExpectation(queueNode)
					if err != nil {
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %d: %w", ifaceName, queue, err)
					}
					parsed, err := fairnesscontract.ParseRSSExpectation(expr)
					if err != nil {
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %d: %w", ifaceName, queue, err)
					}
					key := fmt.Sprintf("%s/%d", ifaceName, queue)
					canonical := parsed.Canonical()
					if existing, ok := seen[key]; ok {
						if existing == canonical {
							continue
						}
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %d: duplicate expectation %q conflicts with %q", ifaceName, queue, canonical, existing)
					}
					seen[key] = canonical
					cos.FairnessExpectations = append(cos.FairnessExpectations, &CoSFairnessExpectation{
						Interface:      ifaceName,
						QueueID:        uint8(queue),
						RSSExpectation: canonical,
					})
				}
			}
		}
	}

	return nil
}

// parseCoSInterfaceUnitBody reads the CoS binding knobs (shaping-rate +
// burst-size, scheduler-map, classifiers, rewrite-rules, and the #1614
// oversubscription / priority-low-min-share scheduler knobs) from the
// direct children of node into unit. node may be a `unit N` node or, for
// an interface-level binding, the `interfaces geX` node itself (#4021) —
// both expose the same knob children, and the interface node's `unit`
// children are separate nodes that are not read here.
func parseCoSInterfaceUnitBody(node *Node, unit *CoSInterfaceUnit) {
	if shapingNode := node.FindChild("shaping-rate"); shapingNode != nil {
		if v := nodeVal(shapingNode); v != "" {
			unit.ShapingRateBytes = parseBandwidthLimit(v)
		}
		if burstNode := shapingNode.FindChild("burst-size"); burstNode != nil {
			if v := nodeVal(burstNode); v != "" {
				unit.BurstSizeBytes = parseBurstSizeLimit(v)
			}
		}
	}
	if schedMapNode := node.FindChild("scheduler-map"); schedMapNode != nil {
		unit.SchedulerMap = nodeVal(schedMapNode)
	}
	if tcpNode := node.FindChild("output-traffic-control-profile"); tcpNode != nil {
		unit.OutputTrafficControlProfile = nodeVal(tcpNode)
	}
	if classifiersNode := node.FindChild("classifiers"); classifiersNode != nil {
		if dscpNode := classifiersNode.FindChild("dscp"); dscpNode != nil {
			unit.DSCPClassifier = nodeVal(dscpNode)
		}
		if ieeeNode := classifiersNode.FindChild("ieee-802.1"); ieeeNode != nil {
			unit.IEEE8021Classifier = nodeVal(ieeeNode)
		}
	}
	if rewriteRulesNode := node.FindChild("rewrite-rules"); rewriteRulesNode != nil {
		if dscpNode := rewriteRulesNode.FindChild("dscp"); dscpNode != nil {
			unit.DSCPRewriteRule = nodeVal(dscpNode)
		}
	}
	// #1614 A1: oversubscription-policy { guarantee-rate <X> | proportional }
	//
	// Junos set syntax `set ... oversubscription-policy guarantee-rate 0.7`
	// produces a flat-keys leaf node whose Keys are
	// ["oversubscription-policy", "guarantee-rate", "0.7"]. The
	// hierarchical text shape produces a parent node with a
	// child sub-node for "guarantee-rate" carrying "0.7" as a
	// trailing key or leaf value. Handle both forms.
	if oversubNode := node.FindChild("oversubscription-policy"); oversubNode != nil {
		// Flat-keys path: Keys = [policy_name, value, ...] all on
		// the parent node.
		if len(oversubNode.Keys) >= 2 && oversubNode.Keys[1] == "guarantee-rate" {
			unit.OversubscriptionPolicy = "guarantee-rate"
			if len(oversubNode.Keys) >= 3 {
				if f, err := strconv.ParseFloat(oversubNode.Keys[2], 64); err == nil {
					if f < 0 {
						f = 0
					} else if f > 1 {
						f = 1
					}
					unit.OversubscriptionGuaranteeFraction = f
				}
			}
		} else if len(oversubNode.Keys) >= 2 && oversubNode.Keys[1] == "proportional" {
			unit.OversubscriptionPolicy = "proportional"
		} else if grNode := oversubNode.FindChild("guarantee-rate"); grNode != nil {
			// Hierarchical child-node path.
			unit.OversubscriptionPolicy = "guarantee-rate"
			var raw string
			if v := nodeVal(grNode); v != "" {
				raw = v
			} else if len(grNode.Keys) >= 2 {
				raw = grNode.Keys[len(grNode.Keys)-1]
			}
			if raw != "" {
				if f, err := strconv.ParseFloat(raw, 64); err == nil {
					if f < 0 {
						f = 0
					} else if f > 1 {
						f = 1
					}
					unit.OversubscriptionGuaranteeFraction = f
				}
			}
		} else if oversubNode.FindChild("proportional") != nil {
			unit.OversubscriptionPolicy = "proportional"
		} else if v := nodeVal(oversubNode); v != "" {
			unit.OversubscriptionPolicy = v
		}
	}
	// #1614 A2: priority-low-min-share <bps>
	if minShareNode := node.FindChild("priority-low-min-share"); minShareNode != nil {
		if v := nodeVal(minShareNode); v != "" {
			unit.PriorityLowMinShareBytes = parseBandwidthLimit(v)
		}
	}
}

// coSInterfaceUnitHasBinding reports whether any CoS knob is set on unit.
// An all-zero unit carries no binding and is dropped so it never reaches
// the dataplane snapshot.
func coSInterfaceUnitHasBinding(unit *CoSInterfaceUnit) bool {
	if unit == nil {
		return false
	}
	return unit.ShapingRateBytes > 0 || unit.BurstSizeBytes > 0 || unit.SchedulerMap != "" ||
		unit.DSCPClassifier != "" || unit.IEEE8021Classifier != "" ||
		unit.DSCPRewriteRule != "" || unit.OversubscriptionPolicy != "" ||
		unit.PriorityLowMinShareBytes > 0 || unit.OutputTrafficControlProfile != ""
}

// applyCoSInterfaceLevelBindings folds each interface-level CoS binding
// (CoSInterface.Level, parsed from `class-of-service interfaces geX` with
// no `unit`) into the configured logical units of that interface (#4021).
//
// Junos precedence: an interface-level binding applies to every logical
// unit on the port, and a unit-level binding overrides it PER KNOB. This
// runs as a post-compile pass because the CoS compiler walks only the
// class-of-service subtree and does not know which logical units the
// interface stanza declares; here cfg.Interfaces is fully populated.
//
// After the fold, cos.Interfaces[name].Units carries the EFFECTIVE
// per-unit binding, so the dataplane snapshot and `show class-of-service`
// — which both iterate Units — apply interface-level CoS without any
// interface-level awareness of their own. An interface with an
// interface-level binding but no configured logical unit contributes no
// unit here (a CoS binding needs a logical interface to attach to); Level
// is retained for `show configuration` fidelity.
func applyCoSInterfaceLevelBindings(cfg *Config) {
	if cfg == nil || cfg.ClassOfService == nil {
		return
	}
	for name, cosIface := range cfg.ClassOfService.Interfaces {
		if cosIface == nil || cosIface.Level == nil {
			continue
		}
		ifCfg := cfg.Interfaces.Interfaces[name]
		if ifCfg == nil {
			continue
		}
		for unitNum := range ifCfg.Units {
			unit := cosIface.Units[unitNum]
			if unit == nil {
				unit = &CoSInterfaceUnit{Unit: unitNum}
				cosIface.Units[unitNum] = unit
			}
			mergeCoSInterfaceLevelInto(unit, cosIface.Level)
		}
	}
}

// mergeCoSInterfaceLevelInto fills any knob unset on unit from the
// interface-level binding level. The unit-level value wins whenever it is
// set (unit-level overrides interface-level).
func mergeCoSInterfaceLevelInto(unit, level *CoSInterfaceUnit) {
	if unit == nil || level == nil {
		return
	}
	if unit.ShapingRateBytes == 0 {
		unit.ShapingRateBytes = level.ShapingRateBytes
		// #hb166 G-10: burst-size is grammatically a child of
		// shaping-rate (see parseCoSInterfaceUnitBody), so a shaper is a
		// coupled (rate, burst) pair. Inherit the level burst-size ONLY
		// when the unit is also inheriting the level's rate. A unit that
		// overrides shaping-rate defines its own shaper; pairing the
		// level burst with the unit rate would mismatch them (a level
		// burst sized for a level rate applied to a different unit rate).
		// When the override unit leaves burst unset it stays 0 and the
		// dataplane applies its rate-independent COS_MIN_BURST_BYTES
		// floor, consistent with a fresh unit that sets shaping-rate
		// alone.
		if unit.BurstSizeBytes == 0 {
			unit.BurstSizeBytes = level.BurstSizeBytes
		}
	}
	if unit.SchedulerMap == "" {
		unit.SchedulerMap = level.SchedulerMap
	}
	if unit.OutputTrafficControlProfile == "" {
		unit.OutputTrafficControlProfile = level.OutputTrafficControlProfile
	}
	if unit.DSCPClassifier == "" {
		unit.DSCPClassifier = level.DSCPClassifier
	}
	if unit.IEEE8021Classifier == "" {
		unit.IEEE8021Classifier = level.IEEE8021Classifier
	}
	if unit.DSCPRewriteRule == "" {
		unit.DSCPRewriteRule = level.DSCPRewriteRule
	}
	if unit.OversubscriptionPolicy == "" {
		unit.OversubscriptionPolicy = level.OversubscriptionPolicy
		unit.OversubscriptionGuaranteeFraction = level.OversubscriptionGuaranteeFraction
	}
	if unit.PriorityLowMinShareBytes == 0 {
		unit.PriorityLowMinShareBytes = level.PriorityLowMinShareBytes
	}
}

// resolveCoSTrafficControlProfiles folds each interface unit's
// output-traffic-control-profile binding (fable-167 F-2, #4315) into the
// unit's existing per-unit shaper. For every CoSInterfaceUnit that names a
// profile, the referenced profile's shaping-rate and scheduler-map fill the
// unit's ShapingRateBytes / SchedulerMap when those are not already set
// directly on the unit — a DIRECT unit-level knob wins (Junos gives an
// explicit unit binding precedence over a profile). After this pass the
// dataplane snapshot and `show class-of-service`, which iterate Units and
// read ShapingRateBytes / SchedulerMap, enforce the profile's shaping with no
// awareness of traffic-control-profiles. This is what stops the silent
// zero-shaping: before modeling, output-traffic-control-profile was dropped
// and the shaper never materialized.
//
// A dangling reference (no such profile) leaves the unit's shaper knobs
// unset; ValidateConfig warns so the operator sees the inert binding.
// guaranteed-rate / delay-buffer-rate are NOT folded — the userspace shaper
// has no per-unit consumer for them (accepted-but-inert; warned separately).
//
// Runs AFTER applyCoSInterfaceLevelBindings so an interface-level
// output-traffic-control-profile has already been copied into each unit.
func resolveCoSTrafficControlProfiles(cfg *Config) {
	if cfg == nil || cfg.ClassOfService == nil {
		return
	}
	cos := cfg.ClassOfService
	resolve := func(unit *CoSInterfaceUnit) {
		if unit == nil || unit.OutputTrafficControlProfile == "" {
			return
		}
		tcp := cos.TrafficControlProfiles[unit.OutputTrafficControlProfile]
		if tcp == nil {
			return
		}
		if unit.ShapingRateBytes == 0 {
			unit.ShapingRateBytes = tcp.ShapingRateBytes
		}
		if unit.SchedulerMap == "" {
			unit.SchedulerMap = tcp.SchedulerMap
		}
	}
	for _, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		resolve(iface.Level)
		for _, unit := range iface.Units {
			resolve(unit)
		}
	}
}

func collectCoSFairnessRSSExpectation(queueNode *Node) (string, error) {
	var expr string
	set := func(kind string, nodes []*Node, next func(*Node) string) error {
		if len(nodes) == 0 {
			return nil
		}
		if len(nodes) > 1 {
			return fmt.Errorf("duplicate %s expectation leaf", kind)
		}
		value := next(nodes[0])
		if expr != "" && expr != value {
			return fmt.Errorf("multiple expectations configured: %q and %q", expr, value)
		}
		expr = value
		return nil
	}
	setFlag := func(kind string) error {
		return set(kind, queueNode.FindChildren(kind), func(*Node) string { return kind })
	}
	setValue := func(kind string, names ...string) error {
		var nodes []*Node
		for _, name := range names {
			nodes = append(nodes, queueNode.FindChildren(name)...)
		}
		return set(kind, nodes, func(n *Node) string { return kind + ":" + nodeVal(n) })
	}
	if err := setFlag("any"); err != nil {
		return "", err
	}
	if err := setFlag("balanced"); err != nil {
		return "", err
	}
	if err := setValue("at-least-active-workers", "active-workers", "at-least-active-workers"); err != nil {
		return "", err
	}
	if err := setValue("max-worker-flow-share", "max-worker-flow-share"); err != nil {
		return "", err
	}
	if err := setValue("cstruct-max", "cstruct", "cstruct-max"); err != nil {
		return "", err
	}
	if expr == "" {
		return "", fmt.Errorf("missing expectation; expected any, balanced, at-least-active-workers, max-worker-flow-share, or cstruct-max")
	}
	return expr, nil
}

func parseCoSTransmitRate(node *Node) (uint64, bool) {
	var rate uint64
	exact := false
	for _, key := range node.Keys[1:] {
		if key == "exact" {
			exact = true
			continue
		}
		if parsed := parseBandwidthLimit(key); parsed > 0 {
			rate = parsed
		}
	}
	if node.FindChild("exact") != nil {
		exact = true
	}
	return rate, exact
}

func collectCoSDSCPCodePoints(node *Node) ([]uint8, error) {
	var values []uint8
	seen := make(map[uint8]struct{})
	add := func(raw string) error {
		expanded, err := expandCoSCodePointToken(raw)
		if err != nil {
			return err
		}
		for _, value := range expanded {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
		return nil
	}
	for _, child := range node.FindChildren("code-points") {
		for _, raw := range child.Keys[1:] {
			if err := add(raw); err != nil {
				return nil, err
			}
		}
	}
	// Inline leaf spelling (#1809): "loss-priority low code-points ef;"
	// packs the code points into the loss-priority node's own Keys after
	// the "code-points" token (bracketed lists arrive bracket-stripped).
	for i := 2; i < len(node.Keys); i++ {
		if node.Keys[i] == "code-points" {
			for _, raw := range node.Keys[i+1:] {
				if err := add(raw); err != nil {
					return nil, err
				}
			}
			break
		}
	}
	return values, nil
}

func collectCoS8021CodePoints(node *Node) ([]uint8, error) {
	var values []uint8
	seen := make(map[uint8]struct{})
	// #2447: an 802.1p code-point is the 3-bit PCP field, domain 0..7. A
	// numeric token outside that range is REJECTED at commit rather than
	// silently dropped (pre-fix) or clamped to 7 by the dataplane builder —
	// a clamp would install the classifier for a DIFFERENT traffic class.
	add := func(raw string) error {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			return nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			// Non-numeric token: 802.1p has no symbolic aliases (unlike
			// DSCP). Preserve the pre-fix skip for anything that is not a
			// number so we do not reject Junos-compatibility spellings.
			return nil
		}
		if v < 0 || v > 7 {
			return fmt.Errorf(
				"class-of-service ieee-802.1 classifier code-point %d is out of range (must be 0..7)",
				v)
		}
		value := uint8(v)
		if _, ok := seen[value]; ok {
			return nil
		}
		seen[value] = struct{}{}
		values = append(values, value)
		return nil
	}
	for _, child := range node.FindChildren("code-points") {
		for _, raw := range child.Keys[1:] {
			if err := add(raw); err != nil {
				return nil, err
			}
		}
	}
	// Inline leaf spelling (#1809): "loss-priority low code-points 3;"
	// packs the code points into the loss-priority node's own Keys after
	// the "code-points" token.
	for i := 2; i < len(node.Keys); i++ {
		if node.Keys[i] == "code-points" {
			for _, raw := range node.Keys[i+1:] {
				if err := add(raw); err != nil {
					return nil, err
				}
			}
			break
		}
	}
	return values, nil
}

func collectCoSDSCPRewriteCodePoint(node *Node) (uint8, bool, error) {
	for _, child := range node.FindChildren("code-point") {
		if len(child.Keys) < 2 {
			continue
		}
		values, err := expandCoSCodePointToken(child.Keys[1])
		if err != nil {
			return 0, false, err
		}
		if len(values) > 0 {
			return values[0], true, nil
		}
	}
	for _, child := range node.FindChildren("code-points") {
		for _, raw := range child.Keys[1:] {
			values, err := expandCoSCodePointToken(raw)
			if err != nil {
				return 0, false, err
			}
			if len(values) > 0 {
				return values[0], true, nil
			}
		}
	}
	return 0, false, nil
}

// expandCoSCodePointToken resolves a DSCP code-point token (a symbolic
// alias such as `ef`/`af11`/`cs6` or a numeric value) to its 0..63 DSCP
// value(s).
//
// #2447: a NUMERIC token outside the 6-bit DSCP domain (0..63) is an
// out-of-range error, REJECTED at commit. The pre-fix code silently
// returned nil (dropping the entry), and the dataplane builder masked
// `dscp & 0x3f` — so a configured DSCP 110 silently installed a
// classifier for DSCP 46, a DIFFERENT traffic class, with no commit
// error. A non-numeric, non-alias token (a typo) is NOT an error here —
// it returns no values (the entry is skipped), preserving the pre-fix
// Junos-compatibility behavior for unknown symbolic spellings.
func expandCoSCodePointToken(raw string) ([]uint8, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return nil, nil
	}
	if value, ok := coSDSCPValues[raw]; ok {
		return []uint8{value}, nil
	}
	if v, err := strconv.Atoi(raw); err == nil {
		if v < 0 || v > 63 {
			return nil, fmt.Errorf(
				"class-of-service dscp code-point %d is out of range (must be 0..63)",
				v)
		}
		return []uint8{uint8(v)}, nil
	}
	return nil, nil
}

var coSDSCPValues = map[string]uint8{
	"default": 0,
	"be":      0,
	"ef":      46,
	"af11":    10,
	"af12":    12,
	"af13":    14,
	"af21":    18,
	"af22":    20,
	"af23":    22,
	"af31":    26,
	"af32":    28,
	"af33":    30,
	"af41":    34,
	"af42":    36,
	"af43":    38,
	"cs0":     0,
	"cs1":     8,
	"cs2":     16,
	"cs3":     24,
	"cs4":     32,
	"cs5":     40,
	"cs6":     48,
	"cs7":     56,
}
