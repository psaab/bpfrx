package userspace

type ClassOfServiceSnapshot struct {
	ForwardingClasses   []CoSForwardingClassSnapshot    `json:"forwarding_classes,omitempty"`
	DSCPClassifiers     []CoSDSCPClassifierSnapshot     `json:"dscp_classifiers,omitempty"`
	IEEE8021Classifiers []CoSIEEE8021ClassifierSnapshot `json:"ieee8021_classifiers,omitempty"`
	// INetPrecedenceClassifiers (#6847) carries `class-of-service classifiers
	// inet-precedence <name>`. Additive: omitempty keeps the wire
	// byte-identical for every config that does not use one, and an older
	// helper ignores the key.
	INetPrecedenceClassifiers []CoSINetPrecedenceClassifierSnapshot `json:"inet_precedence_classifiers,omitempty"`
	DSCPRewriteRules          []CoSDSCPRewriteRuleSnapshot          `json:"dscp_rewrite_rules,omitempty"`
	Schedulers                []CoSSchedulerSnapshot                `json:"schedulers,omitempty"`
	SchedulerMaps             []CoSSchedulerMapSnapshot             `json:"scheduler_maps,omitempty"`
}

type CoSForwardingClassSnapshot struct {
	Name  string `json:"name"`
	Queue int    `json:"queue"`
}

type CoSDSCPClassifierSnapshot struct {
	Name    string                           `json:"name"`
	Entries []CoSDSCPClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSDSCPClassifierEntrySnapshot struct {
	ForwardingClass string        `json:"forwarding_class,omitempty"`
	LossPriority    string        `json:"loss_priority,omitempty"`
	DSCPValues      WireUint8List `json:"dscp_values,omitempty"`
}

type CoSIEEE8021ClassifierSnapshot struct {
	Name    string                               `json:"name"`
	Entries []CoSIEEE8021ClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSIEEE8021ClassifierEntrySnapshot struct {
	ForwardingClass string        `json:"forwarding_class,omitempty"`
	LossPriority    string        `json:"loss_priority,omitempty"`
	CodePoints      WireUint8List `json:"code_points,omitempty"`
}

// CoSINetPrecedenceClassifierSnapshot carries an IP-precedence
// behavior-aggregate classifier to the dataplane (#6847). IP precedence is the
// top 3 bits of the same DS field the DSCP classifier reads, so a unit binds at
// most one of the two (validateCoSUnitClassifierConflict).
type CoSINetPrecedenceClassifierSnapshot struct {
	Name    string                                     `json:"name"`
	Entries []CoSINetPrecedenceClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSINetPrecedenceClassifierEntrySnapshot struct {
	ForwardingClass string        `json:"forwarding_class,omitempty"`
	LossPriority    string        `json:"loss_priority,omitempty"`
	Precedences     WireUint8List `json:"precedences,omitempty"`
}

type CoSDSCPRewriteRuleSnapshot struct {
	Name    string                            `json:"name"`
	Entries []CoSDSCPRewriteRuleEntrySnapshot `json:"entries,omitempty"`
}

type CoSDSCPRewriteRuleEntrySnapshot struct {
	ForwardingClass string `json:"forwarding_class,omitempty"`
	LossPriority    string `json:"loss_priority,omitempty"`
	DSCPValue       uint8  `json:"dscp_value,omitempty"`
}

type CoSSchedulerSnapshot struct {
	Name              string `json:"name"`
	TransmitRateBytes uint64 `json:"transmit_rate_bytes,omitempty"`
	// TransmitRatePercent (#4228 Gap 2) carries the Junos `transmit-rate
	// percent <n>` share (0,100]. Additive to preserve the legacy
	// transmit_rate_bytes wire contract: an older dataplane ignores it; a
	// newer dataplane resolves it PER-INTERFACE (forwarding_build/cos.rs)
	// against the bound interface's cos_shaping_rate_bytes_per_sec when no
	// absolute transmit_rate_bytes is set. omitempty keeps the wire
	// byte-identical for configs that use an absolute rate.
	TransmitRatePercent float64 `json:"transmit_rate_percent,omitempty"`
	// TransmitRateRemainder (#6846, the #4228 Gap 2 residual) carries the
	// Junos `transmit-rate remainder` form. Additive for the same reason
	// TransmitRatePercent is: an older dataplane ignores it and behaves
	// exactly as before.
	//
	// Unlike percent it is NOT a function of the scheduler alone — it means
	// "whatever the interface's shaping rate has left after every sibling
	// queue on the same scheduler-map has resolved", so it can only be
	// materialized once the sibling set is known. That is why it is carried
	// as a flag and resolved per-interface in forwarding_build::cos rather
	// than pre-computed here.
	TransmitRateRemainder bool   `json:"transmit_rate_remainder,omitempty"`
	TransmitRateExact     bool   `json:"transmit_rate_exact,omitempty"`
	Priority              string `json:"priority,omitempty"`
	BufferSizeBytes       uint64 `json:"buffer_size_bytes,omitempty"`
	// BufferSizePercent is additive to preserve the legacy
	// buffer_size_bytes wire contract. Older dataplanes ignore it;
	// newer dataplanes use it only when buffer_size_bytes is absent.
	BufferSizePercent float64 `json:"buffer_size_percent,omitempty"`
	// BufferSizeTemporalUS (#6846) carries the Junos `buffer-size temporal
	// <microseconds>` form: a queue depth expressed as DRAIN TIME rather
	// than as bytes. Converting it needs the queue's own resolved
	// transmit-rate, so it resolves strictly AFTER the rate — including
	// after `remainder`, when both are set on one queue.
	BufferSizeTemporalUS uint64 `json:"buffer_size_temporal_us,omitempty"`
	// SurplusSharing (#915) opts an exact queue into surplus-phase
	// participation; only meaningful when TransmitRateExact == true.
	SurplusSharing bool `json:"surplus_sharing,omitempty"`
	// EqualFlowEnforcement is an explicit opt-in for shared v8
	// queue-lease equal-flow suppression on positive transmit-rate
	// exact queues.
	EqualFlowEnforcement bool `json:"equal_flow_enforcement,omitempty"`
	// EqualFlowTargetPolicy (#1746) selects the equal-flow per-flow
	// target reduction: "slowest" | "mean" | "ideal-share". omitempty
	// keeps the wire byte-identical for unset configs ("" == the
	// byte-unchanged "slowest" default on the Rust side).
	EqualFlowTargetPolicy string `json:"equal_flow_target_policy,omitempty"`
	// #1614 A3: per-queue CoDel target in nanoseconds. WIRE
	// SURFACE ONLY in PR #1618 — the dequeue-time sojourn check
	// is deferred to a focused follow-up. 0 disables CoDel for
	// the queue (current default and the only behaviour-affecting
	// value today). Recommended >= 1.5x post-shaper RTT per AGY
	// r2 finding #3 when the sojourn check ships.
	CodelTargetNS uint64 `json:"codel_target_ns,omitempty"`
}

type CoSSchedulerMapSnapshot struct {
	Name    string                         `json:"name"`
	Entries []CoSSchedulerMapEntrySnapshot `json:"entries,omitempty"`
}

type CoSSchedulerMapEntrySnapshot struct {
	ForwardingClass string `json:"forwarding_class"`
	Scheduler       string `json:"scheduler,omitempty"`
}
