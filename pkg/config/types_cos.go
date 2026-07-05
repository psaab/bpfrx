package config

// Class-of-service: forwarding classes, DSCP/IEEE-802.1p classifiers and
// rewrite rules, queue schedulers, scheduler-maps, per-interface shaping,
// and fairness expectations.

// ClassOfServiceConfig holds CoS forwarding classes, schedulers,
// scheduler-maps, and per-interface shaping configuration.
type ClassOfServiceConfig struct {
	ForwardingClasses    map[string]*CoSForwardingClass
	DSCPClassifiers      map[string]*CoSDSCPClassifier
	IEEE8021Classifiers  map[string]*CoSIEEE8021Classifier
	DSCPRewriteRules     map[string]*CoSDSCPRewriteRule
	Schedulers           map[string]*CoSScheduler
	SchedulerMaps        map[string]*CoSSchedulerMap
	Interfaces           map[string]*CoSInterface
	FairnessExpectations []*CoSFairnessExpectation
	// INetPrecedenceClassifiers / INetPrecedenceRewriteRules / EXPRewriteRules
	// record the NAMES of `inet-precedence` classifiers, `inet-precedence`
	// rewrite-rules, and `exp` rewrite-rules configured (fable-167 F-3b,
	// #4316). These behavior-aggregate maps are accepted for Junos
	// compatibility but INERT — the userspace dataplane classifies and
	// rewrites on dscp / ieee-802.1 only. Names are recorded solely to drive
	// the accepted-but-inert commit advisory; no runtime structure is built.
	INetPrecedenceClassifiers  []string
	INetPrecedenceRewriteRules []string
	EXPRewriteRules            []string
	// TrafficControlProfiles holds the Junos hierarchical shaping profiles
	// (`class-of-service traffic-control-profiles <name>`). A profile is
	// bound to a logical interface's egress by
	// `interfaces <if> unit N output-traffic-control-profile <name>`;
	// resolveCoSTrafficControlProfiles folds the bounded knobs
	// (shaping-rate, scheduler-map) into the referencing CoSInterfaceUnit so
	// the existing per-unit shaper enforces them. Before this modeling the
	// whole binding was silently dropped — a clean commit with ZERO shaping
	// (fable-167 F-2, #4315).
	TrafficControlProfiles map[string]*CoSTrafficControlProfile
}

// CoSTrafficControlProfile models one Junos traffic-control-profile
// (`class-of-service traffic-control-profiles <name>`). The BOUNDED knobs
// map onto xpf's existing per-unit shaper: ShapingRateBytes becomes the
// unit root shaper and SchedulerMap the unit scheduler-map when the profile
// is bound via output-traffic-control-profile
// (resolveCoSTrafficControlProfiles). GuaranteedRateBytes and
// DelayBufferRateBytes are captured for `show configuration` fidelity and a
// commit advisory but have NO per-unit dataplane consumer yet
// (accepted-but-not-enforced) — there is no absolute per-unit guaranteed-rate
// or delay-buffer reservation in the userspace shaper (the #1614 A1
// guarantee-rate is a proportional FRACTION, a distinct mechanism).
type CoSTrafficControlProfile struct {
	Name                 string
	ShapingRateBytes     uint64 // bytes/sec; 0 = unset
	GuaranteedRateBytes  uint64 // bytes/sec; 0 = unset (accepted-but-inert)
	DelayBufferRateBytes uint64 // bytes/sec; 0 = unset (accepted-but-inert)
	SchedulerMap         string
}

// CoSForwardingClass maps a forwarding-class name to a queue number.
type CoSForwardingClass struct {
	Name  string
	Queue int
}

// CoSDSCPClassifier maps DSCP code points into forwarding classes.
type CoSDSCPClassifier struct {
	Name    string
	Entries []*CoSDSCPClassifierEntry
}

// CoSDSCPClassifierEntry assigns one or more DSCP values to a forwarding class.
type CoSDSCPClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	DSCPValues      []uint8
}

// CoSIEEE8021Classifier maps 802.1p PCP values into forwarding classes.
type CoSIEEE8021Classifier struct {
	Name    string
	Entries []*CoSIEEE8021ClassifierEntry
}

// CoSIEEE8021ClassifierEntry assigns one or more PCP values to a forwarding class.
type CoSIEEE8021ClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	CodePoints      []uint8
}

// CoSDSCPRewriteRule maps forwarding classes to egress DSCP rewrite values.
type CoSDSCPRewriteRule struct {
	Name    string
	Entries []*CoSDSCPRewriteRuleEntry
}

// CoSDSCPRewriteRuleEntry assigns a DSCP rewrite code point to a forwarding class.
type CoSDSCPRewriteRuleEntry struct {
	ForwardingClass string
	LossPriority    string
	DSCPValue       uint8
}

// CoSScheduler defines the Phase 1 class scheduler knobs.
type CoSScheduler struct {
	Name              string
	TransmitRateBytes uint64
	TransmitRateExact bool
	Priority          string
	// BufferSizeBytes preserves the legacy explicit byte-size path.
	BufferSizeBytes uint64
	// BufferSizePercent is the Junos percent form. A value > 0 means
	// userspace resolves the scheduler buffer against the interface CoS
	// burst pool when the scheduler is bound to a queue.
	BufferSizePercent float64
	// SurplusSharing (#915) lifts the surplus-phase skip on
	// transmit-rate exact queues so they can draw from the root
	// shaper's surplus tokens once their own bucket is empty.
	// Only meaningful when TransmitRateExact == true; cleared
	// by ValidateConfig otherwise (warn-and-strip).
	SurplusSharing bool
	// EqualFlowEnforcement opts a positive transmit-rate exact
	// scheduler into shared v8 queue-lease equal-flow suppression.
	// Validation fails closed unless the scheduler has transmit-rate
	// exact with a positive rate and does not also opt into
	// SurplusSharing, whose surplus phase intentionally bypasses the
	// per-queue lease cap.
	EqualFlowEnforcement bool
	// EqualFlowTargetPolicy (#1746) selects the per-flow target the
	// equal-flow publisher enforces: "slowest" (clip to the slowest
	// sampled per-flow rate — the byte-unchanged default; "" maps
	// here), "mean" (clip toward the aggregate-weighted mean achieved
	// per-flow rate), or "ideal-share" (literal scheduler_rate /
	// total_active_flows nominal share; a documented no-op in
	// capacity-limited regimes). Only meaningful with
	// EqualFlowEnforcement; warned (not stripped) otherwise. NO policy
	// lifts slow-worker flows — the cap is one-directional; the
	// work-conserving fix is cross-worker rebalance (#1748).
	EqualFlowTargetPolicy string
	// CodelTargetNS (#1614 A3) is the per-queue CoDel sojourn-time
	// AQM target in nanoseconds. 0 (default) disables CoDel for the
	// queue. Recommended >= 1.5x post-shaper RTT (~5-7 ms on the
	// loss userspace cluster, so 7.5-10 ms = 7_500_000-10_000_000 ns).
	// RFC 8290 baseline is 5 ms; on this cluster 5 ms collides with
	// RTT and may oscillate (see docs/cos-traffic-shaping.md).
	CodelTargetNS uint64
}

// CoSSchedulerMap binds forwarding classes to named schedulers.
type CoSSchedulerMap struct {
	Name    string
	Entries map[string]*CoSSchedulerMapEntry
}

// CoSSchedulerMapEntry is a single forwarding-class -> scheduler binding.
type CoSSchedulerMapEntry struct {
	ForwardingClass string
	Scheduler       string
}

// CoSInterface holds unit-level CoS configuration for an interface.
type CoSInterface struct {
	Name  string
	Units map[int]*CoSInterfaceUnit
	// Level holds a CoS binding applied at the physical interface level
	// (`class-of-service interfaces geX { scheduler-map M; ... }` with no
	// `unit`). In Junos an interface-level binding applies to every
	// logical unit on the port; a unit-level binding overrides it per
	// knob. The compiler folds Level into each configured logical unit
	// after the interface stanza is known (applyCoSInterfaceLevelBindings),
	// so the dataplane snapshot and `show class-of-service` — which both
	// iterate Units — need no interface-level awareness. Nil when the
	// operator configured only per-unit bindings.
	Level *CoSInterfaceUnit
}

// CoSInterfaceUnit defines the Phase 1 root shaper attached to a logical unit.
type CoSInterfaceUnit struct {
	Unit               int
	ShapingRateBytes   uint64
	BurstSizeBytes     uint64
	SchedulerMap       string
	DSCPClassifier     string
	IEEE8021Classifier string
	DSCPRewriteRule    string
	// OutputTrafficControlProfile is the raw
	// `output-traffic-control-profile <name>` reference bound to this unit's
	// egress (fable-167 F-2, #4315). resolveCoSTrafficControlProfiles (run
	// after applyCoSInterfaceLevelBindings) looks up the named profile and
	// folds its shaping-rate + scheduler-map into ShapingRateBytes /
	// SchedulerMap when those are not already set directly on the unit
	// (a direct unit-level knob wins). Retained on the unit for
	// `show configuration` fidelity and the undefined-reference advisory.
	OutputTrafficControlProfile string
	// OversubscriptionPolicy (#1614 A1) is the operator-selectable
	// behaviour when sum of exact-class transmit-rates exceeds the
	// interface's shaping-rate. Empty or "proportional" (default)
	// preserves current scheduler bit-for-bit (when
	// PriorityLowMinShareBytes is also 0). "guarantee-rate"
	// activates the v5 two-phase waterfill allocator.
	OversubscriptionPolicy string
	// OversubscriptionGuaranteeFraction (#1614 A1) is the Phase 1
	// budget fraction (0.0..1.0). Only meaningful when
	// OversubscriptionPolicy == "guarantee-rate". 0.0 makes the
	// allocator a no-op even if the policy is set.
	OversubscriptionGuaranteeFraction float64
	// PriorityLowMinShareBytes (#1614 A2) is the priority-low
	// minimum share in bytes per second. Subtracted from effective
	// scheduler cap before the A1 allocator runs (orthogonal to A1
	// policy choice). Default 0 (no min-share).
	PriorityLowMinShareBytes uint64
}

// CoSFairnessExpectation declares an opt-in RSS/workload expectation for
// one egress CoS queue. Interface is the STABLE xpf interface name (e.g.
// ge-0-0-2); the kernel ifindex it maps to is transient across
// re-enumeration, so the name is resolved to the current ifindex at
// evaluate time from the live status snapshot (#hb166 G-9).
type CoSFairnessExpectation struct {
	Interface      string
	QueueID        uint8
	RSSExpectation string
}
