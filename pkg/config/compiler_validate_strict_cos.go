package config

import (
	"fmt"
	"math"
	"sort"
)

func validateThreeColorPolicersStrict(policers map[string]*ThreeColorPolicerConfig) error {
	for name, pol := range policers {
		if pol == nil {
			continue
		}
		displayName := pol.Name
		if displayName == "" {
			displayName = name
		}
		if pol.SingleRateConfigured && pol.TwoRateConfigured {
			return fmt.Errorf("firewall three-color-policer %q cannot configure both single-rate and two-rate", displayName)
		}
		if pol.ColorBlindConfigured && pol.ColorAwareConfigured {
			return fmt.Errorf("firewall three-color-policer %q cannot configure both color-blind and color-aware", displayName)
		}
		if pol.CIR == 0 {
			return fmt.Errorf("firewall three-color-policer %q requires positive committed-information-rate", displayName)
		}
		if pol.CBS == 0 {
			return fmt.Errorf("firewall three-color-policer %q requires positive committed-burst-size", displayName)
		}
		if pol.PBS == 0 {
			if pol.TwoRate {
				return fmt.Errorf("firewall three-color-policer %q requires positive peak-burst-size", displayName)
			}
			return fmt.Errorf("firewall three-color-policer %q requires positive excess-burst-size", displayName)
		}
		if pol.TwoRate {
			if pol.PIR == 0 {
				return fmt.Errorf("firewall three-color-policer %q requires positive peak-information-rate", displayName)
			}
			if pol.PIR < pol.CIR {
				return fmt.Errorf("firewall three-color-policer %q peak-information-rate must be >= committed-information-rate", displayName)
			}
			if pol.PBS < pol.CBS {
				return fmt.Errorf("firewall three-color-policer %q peak-burst-size must be >= committed-burst-size", displayName)
			}
		}
	}
	return nil
}

func validatePolicySchedulerReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil || pol.SchedulerName == "" {
			return nil
		}
		if _, ok := cfg.Schedulers[pol.SchedulerName]; ok {
			return nil
		}
		if scope != "" {
			return fmt.Errorf("%s policy %q references undefined scheduler %q", scope, pol.Name, pol.SchedulerName)
		}
		return fmt.Errorf("policy %q references undefined scheduler %q", pol.Name, pol.SchedulerName)
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if err := check("", pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// validateClassOfServiceSchedulerMapRefsStrict hard-rejects a
// class-of-service scheduler-map entry whose `scheduler <name>`
// reference does not resolve to a defined `class-of-service schedulers`
// entry — a commit-time typo. Junos hard-rejects an unresolved
// scheduler reference at commit; this restores that behavior.
//
// Before this gate the reference was warn-only at commit
// (ValidateConfig, compiler_validate_warn.go) and then FAILED OPEN in
// the dataplane: the userspace helper's per-queue builder
// (userspace-dp forwarding_build/cos.rs) resolves the dangling name to
// `None`, leaves `guarantee_enabled` false, sets the queue's transmit
// rate to the WHOLE interface shaping rate, and derives the MAXIMUM
// surplus weight (16). So a premium class (e.g. `ef`) whose scheduler
// name is a typo did not merely lose its guarantee — it silently won
// the LARGEST best-effort surplus share, invisible outside the runtime
// queue rows.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientSchedulerMapRef) so a config persisted by
// an older binary (which only warned) or synced from a peer still boots
// (#1960 no-brick). The dataplane's render-path safety net (the
// scheduler-unresolved SAFE default in forwarding_build/cos.rs, which
// pins surplus_weight to 1) keeps a leniently-loaded dangling reference
// from fail-opening to the maximum best-effort share on that boot.
// Mirrors validatePolicySchedulerReferencesStrict, which rejects an
// undefined scheduler reference from a security policy.
//
// An EMPTY scheduler string is skipped: the grammar requires a name, so
// an empty value arises only in constructed configs and is the same
// "no scheduler assigned" placeholder the warn / strict buffer
// validators skip.
func validateClassOfServiceSchedulerMapRefsStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	// Iterate scheduler-maps and their entries in sorted order so
	// commit-check surfaces a STABLE first-error message (Go map
	// iteration order is randomized).
	mapNames := make([]string, 0, len(cos.SchedulerMaps))
	for name := range cos.SchedulerMaps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, mapName := range mapNames {
		schedMap := cos.SchedulerMaps[mapName]
		if schedMap == nil {
			continue
		}
		classNames := make([]string, 0, len(schedMap.Entries))
		for className := range schedMap.Entries {
			classNames = append(classNames, className)
		}
		sort.Strings(classNames)
		for _, className := range classNames {
			entry := schedMap.Entries[className]
			if entry == nil || entry.Scheduler == "" {
				continue
			}
			if _, ok := cos.Schedulers[entry.Scheduler]; !ok {
				return fmt.Errorf(
					"class-of-service scheduler-map %q forwarding-class %q references undefined scheduler %q",
					schedMap.Name, className, entry.Scheduler)
			}
		}
	}
	return nil
}

// cosLossPriorityValues is the set of loss-priority values Junos accepts on a
// class-of-service DSCP / 802.1p classifier or DSCP rewrite-rule. It mirrors
// cos_loss_priority_index in userspace-dp forwarding_build/cos.rs.
var cosLossPriorityValues = map[string]struct{}{
	"low":         {},
	"medium-low":  {},
	"medium-high": {},
	"high":        {},
}

// validateClassOfServiceLossPriorityStrict hard-rejects a class-of-service
// classifier or DSCP rewrite-rule entry whose `loss-priority` value is not one
// of the four Junos levels (low, medium-low, medium-high, high) — an operator
// typo like `medum-low` (#3995). Junos rejects an unknown loss-priority at
// commit; before this gate the raw string was threaded through to the
// dataplane, where `cos_loss_priority_index` maps an unrecognized value to the
// SAFE default (LOW for the classifier, a wildcard-over-all-loss-priorities for
// the rewrite-rule). That default is correct for fail-safe boot but WRONG for a
// fresh operator edit: the typo silently applies the wrong QoS class instead of
// surfacing the mistake. Reject it loudly at commit / commit-check.
//
// An EMPTY loss-priority is skipped: it is the legitimate "no explicit
// loss-priority" case (the rewrite-rule wildcard / classifier default), the
// same placeholder the other CoS validators skip.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSLossPriority) so a config persisted by an older
// binary — or synced from a peer — still boots (#1960 no-brick); the dataplane
// applies the SAFE default on that boot. Entries are visited in sorted order so
// commit-check surfaces a STABLE first-error message.
// validateCoSUnitClassifierConflict rejects a logical unit that binds BOTH a
// `dscp` and an `inet-precedence` classifier (#6847).
//
// The two read the SAME IPv4 TOS byte — IP precedence is its top 3 bits — so
// binding both is a contradiction, not a composition. There is no defined
// answer to "which wins", and the BA resolution chain would silently pick one
// (DSCP is consulted first, so the inet-precedence binding would simply be
// dead). A silently-dead classifier is the quiet-wrong-QoS failure this gate
// family exists to stop, so reject at commit and make the operator choose.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSUnitClassifierConflict) so a config persisted by an
// older binary — which had NO inet-precedence binding site and so could not
// have produced this combination, but might acquire it via a hand-edited or
// peer-synced file — still boots (#1960 no-brick). On that boot the DSCP
// classifier wins, matching the resolution order.
//
// Units are visited in sorted (interface, unit) order so commit-check surfaces
// a STABLE first-error message.
func validateCoSUnitClassifierConflict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	ifaceNames := make([]string, 0, len(cos.Interfaces))
	for name := range cos.Interfaces {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Strings(ifaceNames)
	for _, ifaceName := range ifaceNames {
		iface := cos.Interfaces[ifaceName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil {
				continue
			}
			if unit.DSCPClassifier != "" && unit.INetPrecedenceClassifier != "" {
				return fmt.Errorf(
					"class-of-service interfaces %s unit %d binds both a dscp classifier (%q) "+
						"and an inet-precedence classifier (%q); they classify the same IPv4 "+
						"TOS byte, so bind at most one",
					ifaceName, unitNum, unit.DSCPClassifier, unit.INetPrecedenceClassifier)
			}
		}
	}
	return nil
}

func validateClassOfServiceLossPriorityStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	checkEntry := func(kind, ruleName, className, lossPriority string) error {
		if lossPriority == "" {
			return nil
		}
		if _, ok := cosLossPriorityValues[lossPriority]; ok {
			return nil
		}
		return fmt.Errorf(
			"class-of-service %s %q forwarding-class %q has unrecognized loss-priority %q "+
				"(must be one of: low, medium-low, medium-high, high)",
			kind, ruleName, className, lossPriority)
	}

	dscpNames := make([]string, 0, len(cos.DSCPClassifiers))
	for name := range cos.DSCPClassifiers {
		dscpNames = append(dscpNames, name)
	}
	sort.Strings(dscpNames)
	for _, name := range dscpNames {
		classifier := cos.DSCPClassifiers[name]
		if classifier == nil {
			continue
		}
		for _, entry := range classifier.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("classifiers dscp", classifier.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	ieeeNames := make([]string, 0, len(cos.IEEE8021Classifiers))
	for name := range cos.IEEE8021Classifiers {
		ieeeNames = append(ieeeNames, name)
	}
	sort.Strings(ieeeNames)
	for _, name := range ieeeNames {
		classifier := cos.IEEE8021Classifiers[name]
		if classifier == nil {
			continue
		}
		for _, entry := range classifier.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("classifiers ieee-802.1", classifier.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	// #6847: the inet-precedence classifier is ENFORCED, so its entries carry
	// a loss-priority to the dataplane exactly as the dscp / ieee-802.1
	// classifiers do. Without this arm a typo (`hgih`) commits CLEAN and the
	// helper's cos_loss_priority_index() falls back to LOW
	// (`unwrap_or(0)` in forwarding_build/cos.rs) — silently wrong drop
	// precedence on the egress rewrite, which is the exact
	// accepted-but-silently-substituted failure this gate family exists to
	// stop and the reason #6847 wired the loss-priority arm at all.
	precNames := make([]string, 0, len(cos.INetPrecedenceClassifierDefs))
	for name := range cos.INetPrecedenceClassifierDefs {
		precNames = append(precNames, name)
	}
	sort.Strings(precNames)
	for _, name := range precNames {
		classifier := cos.INetPrecedenceClassifierDefs[name]
		if classifier == nil {
			continue
		}
		for _, entry := range classifier.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("classifiers inet-precedence", classifier.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	rewriteNames := make([]string, 0, len(cos.DSCPRewriteRules))
	for name := range cos.DSCPRewriteRules {
		rewriteNames = append(rewriteNames, name)
	}
	sort.Strings(rewriteNames)
	for _, name := range rewriteNames {
		rewriteRule := cos.DSCPRewriteRules[name]
		if rewriteRule == nil {
			continue
		}
		for _, entry := range rewriteRule.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("rewrite-rules dscp", rewriteRule.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	// #4228 Gap 4: apply the same loss-priority typo gate to ieee-802.1 (PCP)
	// rewrite-rules. Even though the rule is accepted-but-inert, a `medum-low`
	// typo should be surfaced at commit consistently with the dscp rewrite and
	// the classifiers.
	ieeeRewriteNames := make([]string, 0, len(cos.IEEE8021RewriteRules))
	for name := range cos.IEEE8021RewriteRules {
		ieeeRewriteNames = append(ieeeRewriteNames, name)
	}
	sort.Strings(ieeeRewriteNames)
	for _, name := range ieeeRewriteNames {
		rewriteRule := cos.IEEE8021RewriteRules[name]
		if rewriteRule == nil {
			continue
		}
		for _, entry := range rewriteRule.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("rewrite-rules ieee-802.1", rewriteRule.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateClassOfServiceForwardingClassQueueStrict hard-rejects a
// class-of-service forwarding-class whose queue is outside the accepted
// 0..255 range (#4594). Before this gate the out-of-range queue was
// warn-only (ValidateConfig) and COMMITTED, but the userspace helper
// deserializes the queue id via a checked u8::try_from and fail-closes the
// ENTIRE CoS snapshot on CosQueueIdOutOfRange (#2410) — silently keeping the
// node's STALE CoS forwarding state. The operator sees a committed config that
// is not being enforced (a config/dataplane divergence). Reject it loudly at
// commit / commit-check instead, mirroring the fairness rss-expectation
// queue-range reject in compiler_class_of_service.go and the sibling CoS strict
// gates.
//
// xpf's valid queue range is 0..255 (the dataplane's u8 queue id), NOT the
// Junos-classic 0..7 — see the warn text in compiler_validate_warn.go and the
// CosQueueIdOutOfRange backstop.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSForwardingClassQueue) so a config persisted by an
// older binary — which only warned, then committed — or synced from a peer
// still boots (#1960 no-brick); the dataplane's CosQueueIdOutOfRange fail-close
// keeps the stale-but-safe posture on that boot. Forwarding classes are visited
// in sorted order so commit-check surfaces a STABLE first-error message.
func validateClassOfServiceForwardingClassQueueStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	names := make([]string, 0, len(cos.ForwardingClasses))
	for name := range cos.ForwardingClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		class := cos.ForwardingClasses[name]
		if class == nil {
			continue
		}
		if class.Queue < 0 || class.Queue > 255 {
			return fmt.Errorf(
				"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
				class.Name, class.Queue)
		}
	}
	return nil
}

func validateClassOfServiceStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	for _, sched := range cos.Schedulers {
		if sched == nil {
			continue
		}
		if sched.EqualFlowEnforcement && (!sched.TransmitRateExact || sched.TransmitRateBytes == 0) {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement requires positive transmit-rate exact",
				sched.Name)
		}
		if sched.EqualFlowEnforcement && sched.SurplusSharing {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement cannot be combined with surplus-sharing",
				sched.Name)
		}
		// #1746: the schema enum validator catches bad values on the
		// set path; re-check here so externally-assembled configs
		// cannot smuggle an unknown policy to the dataplane (which
		// would silently parse it as "slowest").
		switch sched.EqualFlowTargetPolicy {
		case "", "slowest", "mean", "ideal-share":
		default:
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-target-policy %q is not one of slowest | mean | ideal-share",
				sched.Name, sched.EqualFlowTargetPolicy)
		}
		// #4228 Gap 2: transmit-rate accepts EITHER an absolute rate,
		// `percent <n>`, or `remainder`. The schema tailValidator enforces
		// mutual exclusivity on the operator commit path; re-check here so an
		// externally-assembled config (Load / HA SyncApply) cannot smuggle a
		// combination the dataplane would resolve ambiguously. The percent
		// operand range is likewise re-validated (the tail path checks it on
		// commit; a constructed config bypasses it).
		trHead := 0
		if sched.TransmitRateBytes > 0 {
			trHead++
		}
		if sched.TransmitRatePercent > 0 {
			trHead++
		}
		if sched.TransmitRateRemainder {
			trHead++
		}
		if trHead > 1 {
			return fmt.Errorf(
				"class-of-service scheduler %q transmit-rate: set exactly one of an absolute rate, `percent <n>`, or `remainder`",
				sched.Name)
		}
		// Reject non-finite explicitly: NaN compares false to BOTH range bounds,
		// so a constructed/peer-synced config could smuggle a NaN percent past a
		// bare `< 0 || > 100` check (Copilot #4320). Inf is caught by `> 100`,
		// but guard it too for a clear message.
		if math.IsNaN(sched.TransmitRatePercent) || math.IsInf(sched.TransmitRatePercent, 0) ||
			sched.TransmitRatePercent < 0 || sched.TransmitRatePercent > 100 {
			return fmt.Errorf(
				"class-of-service scheduler %q transmit-rate percent %.4g is not a finite value in range (0,100]",
				sched.Name, sched.TransmitRatePercent)
		}
		// Both buffer-size forms set simultaneously is ambiguous. The compiler
		// always clears the unused field (see compiler_class_of_service.go
		// buffer-size case), so this can only arise in constructed or
		// externally-assembled configs. Reject early rather than silently
		// applying the "byte-size wins" runtime preference.
		if sched.BufferSizeBytes > 0 && sched.BufferSizePercent > 0 {
			return fmt.Errorf(
				"class-of-service scheduler %q has both buffer-size bytes (%d) "+
					"and buffer-size percent (%.4g%%) set; use one form only",
				sched.Name, sched.BufferSizeBytes, sched.BufferSizePercent)
		}
	}
	// #4228 Gap 2: a traffic-control-profile shaping-rate is EITHER an absolute
	// rate or `percent <n>`. The schema tailValidator enforces this on commit;
	// re-check for externally-assembled configs and re-validate the percent
	// operand range.
	for _, tcp := range cos.TrafficControlProfiles {
		if tcp == nil {
			continue
		}
		if tcp.ShapingRateBytes > 0 && tcp.ShapingRatePercent > 0 {
			return fmt.Errorf(
				"class-of-service traffic-control-profiles %q shaping-rate: set exactly one of an absolute rate or `percent <n>`",
				tcp.Name)
		}
		// Reject non-finite explicitly (NaN slips past a bare range check —
		// Copilot #4320).
		if math.IsNaN(tcp.ShapingRatePercent) || math.IsInf(tcp.ShapingRatePercent, 0) ||
			tcp.ShapingRatePercent < 0 || tcp.ShapingRatePercent > 100 {
			return fmt.Errorf(
				"class-of-service traffic-control-profiles %q shaping-rate percent %.4g is not a finite value in range (0,100]",
				tcp.Name, tcp.ShapingRatePercent)
		}
	}
	// Aggregate percent check: Junos does not allow per-queue buffer
	// allocations to exceed 100% of the interface's total buffer pool.
	// Check each scheduler-map independently and reject overcommit here
	// so the runtime never silently over-allocates. A sum of exactly
	// 100% is permitted (full pool allocation).
	//
	// A small epsilon (1e-9) guards against accumulated IEEE 754 rounding
	// when summing multiple float64 percent values: e.g. 33.33% * 3 may
	// round to 99.99000000000001% rather than exactly 99.99%, so the check
	// must not reject legitimate 100%-summing configs.
	const maxTotalBufferPercent = 100.0
	const bufferPercentEpsilon = 1e-9
	for _, schedMap := range cos.SchedulerMaps {
		if schedMap == nil {
			continue
		}
		var totalPercent float64
		for _, entry := range schedMap.Entries {
			if entry == nil || entry.Scheduler == "" {
				continue
			}
			sched, ok := cos.Schedulers[entry.Scheduler]
			if !ok || sched == nil {
				continue
			}
			totalPercent += sched.BufferSizePercent
		}
		if totalPercent > maxTotalBufferPercent+bufferPercentEpsilon {
			return fmt.Errorf(
				"class-of-service scheduler-map %q: "+
					"sum of buffer-size percent across all schedulers is %.4g%% "+
					"(must not exceed 100%%)",
				schedMap.Name, totalPercent)
		}
	}
	return nil
}
