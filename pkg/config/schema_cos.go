package config

// schema_cos.go carries the traffic-conditioning subtrees of the
// config-mode grammar SSOT (#1891 domain split): `class-of-service`
// and `firewall` (filters are the CoS classifier/rewrite attachment
// point — forwarding-class and DSCP actions). The root composition,
// the schemaNode type, and the split rationale live in schema.go.

var schemaClassOfService = &schemaNode{desc: "Class of service configuration", children: map[string]*schemaNode{
	"forwarding-classes": {desc: "Forwarding class definitions", children: map[string]*schemaNode{
		"queue": {desc: "Map a queue number to a forwarding-class name (one queue per class, one class per queue)", args: 2, multi: true, children: nil},
	}},
	"classifiers": {desc: "Classifiers mapping incoming code points to forwarding classes", children: map[string]*schemaNode{
		"dscp": {desc: "DSCP classifier", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-points": {desc: "DSCP code points to match (alias such as ef, af11, cs6, or numeric 0..63)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
		"ieee-802.1": {desc: "IEEE 802.1p classifier", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-points": {desc: "IEEE 802.1p code points to match (0..7)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
	}},
	"rewrite-rules": {desc: "Egress rewrite rules mapping forwarding classes to code points", children: map[string]*schemaNode{
		"dscp": {desc: "DSCP rewrite rule", args: 1, multi: true, placeholder: "<rewrite-rule-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class whose packets get the rewritten code point", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-point":  {desc: "DSCP code point to write (alias such as ef, af11, cs6, or numeric 0..63)", args: 1, placeholder: "<code-point>", children: nil},
					"code-points": {desc: "DSCP code point to write (alias of code-point; first value is used)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
	}},
	"schedulers": {desc: "Scheduler definitions (transmit rate, priority, buffer)", args: 1, multi: true, placeholder: "<scheduler-name>", children: map[string]*schemaNode{
		// #1319 typed leaves. Re-homed from the cmdtree overlay
		// (cmdtree.ConfigClassOfServiceSchedulers, retired in this PR)
		// onto setSchema so the live config-mode `set ... ?` completer
		// and the SchemaValidate commit-check gate read one tree. The
		// `exact` child predates #1319 and is unchanged — adding fields
		// to transmit-rate does not alter SetPath grouping.
		"transmit-rate": {
			desc:          "Transmit rate in bits per second (e.g. 100k, 10m, 1g)",
			args:          1,
			valueType:     ValueRate,
			valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps",
			valueExamples: []string{"100k", "10m", "1g", "10g"},
			validator:     ValidateRate,
			children: map[string]*schemaNode{
				"exact": {desc: "Cap the queue at the configured rate (no surplus borrowing unless surplus-sharing is set)", children: nil},
			},
		},
		"priority": {
			desc:          "Scheduler priority level",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Scheduler priority (low | medium-low | medium-high | high | strict-high)",
			valueExamples: []string{"low", "medium-low", "medium-high", "high", "strict-high"},
			validator: ValidateEnum([]string{
				"low", "medium-low", "medium-high", "high", "strict-high",
			}),
			children: nil,
		},
		"buffer-size": {
			desc:          "Queue buffer size (bytes with k/m/g suffix, or percent of the interface buffer pool; percents in one scheduler-map must not exceed 100%)",
			args:          1,
			valueType:     ValueByteSizeOrPercent,
			valueDesc:     "Byte-size with explicit k/m/g suffix, or percent of interface CoS burst pool (e.g. 16m, 256k, 10%)",
			valueExamples: []string{"16m", "256k", "10%"},
			validator:     ValidateByteSizeOrPercent,
			children:      nil,
		},
		// `surplus-sharing` (#915) and `equal-flow-enforcement` are
		// presence-only flags — no value to validate.
		"surplus-sharing":        {desc: "Let this exact-rate queue draw surplus bandwidth once its own rate is exhausted (only meaningful with transmit-rate exact)", children: nil},
		"equal-flow-enforcement": {desc: "Enforce equal per-flow rates on this queue (requires positive transmit-rate exact; cannot be combined with surplus-sharing)", children: nil},
		// #1746: equal-flow target policy. Only meaningful with
		// `equal-flow-enforcement`; unset == `slowest` (the
		// byte-unchanged clip-to-slowest default). `mean` and
		// `slowest` are non-work-conserving (commit warning).
		"equal-flow-target-policy": {
			desc:          "Per-flow target policy for equal-flow enforcement (slowest | mean | ideal-share, unset = slowest)",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Equal-flow per-flow target policy (slowest | mean | ideal-share)",
			valueExamples: []string{"slowest", "mean", "ideal-share"},
			validator: ValidateEnum([]string{
				"slowest", "mean", "ideal-share",
			}),
			children: nil,
		},
	}},
	"scheduler-maps": {desc: "Scheduler map assigning schedulers to forwarding classes", args: 1, multi: true, placeholder: "<map-name>", children: map[string]*schemaNode{
		"forwarding-class": {desc: "Forwarding class entry in this map", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
			"scheduler": {desc: "Scheduler to apply to this forwarding class", args: 1, placeholder: "<scheduler-name>", children: nil},
		}},
	}},
	"interfaces": {desc: "Apply CoS to an interface", args: 1, multi: true, placeholder: "<interface-name>", children: map[string]*schemaNode{
		"unit": {desc: "Logical unit number", args: 1, multi: true, placeholder: "<unit-number>", children: map[string]*schemaNode{
			"classifiers": {desc: "Classifiers applied to traffic arriving on this unit", children: map[string]*schemaNode{
				"dscp":       {desc: "DSCP classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
				"ieee-802.1": {desc: "IEEE 802.1p classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
			}},
			"rewrite-rules": {desc: "Rewrite rules applied to traffic leaving this unit", children: map[string]*schemaNode{
				"dscp": {desc: "DSCP rewrite rule to apply", args: 1, placeholder: "<rewrite-rule-name>", children: nil},
			}},
			"shaping-rate": {desc: "Shaping rate for this unit in bits per second (k/m/g suffixes)", args: 1, placeholder: "<rate>", children: map[string]*schemaNode{
				"burst-size": {desc: "Shaping burst size in bytes (k/m/g suffixes)", args: 1, placeholder: "<bytes>", children: nil},
			}},
			"scheduler-map": {desc: "Scheduler map to apply to this unit", args: 1, placeholder: "<map-name>", children: nil},
		}},
	}},
	"fairness": {desc: "Dataplane fairness observability configuration", children: map[string]*schemaNode{
		"rss-expectation": {desc: "Declarative RSS flow-distribution expectations evaluated against live dataplane status (shown in fairness output and exported as Prometheus gauges)", children: map[string]*schemaNode{
			"ifindex": {desc: "Kernel interface index to evaluate (positive integer)", args: 1, multi: true, placeholder: "<ifindex>", children: map[string]*schemaNode{
				"queue": {desc: "CoS queue ID to evaluate (0..255; exactly one expectation per queue)", args: 1, multi: true, placeholder: "<queue-id>", children: map[string]*schemaNode{
					"any":                     {desc: "No expectation; always passes", children: nil},
					"balanced":                {desc: "Expect flows spread across min(flows, workers) workers with per-worker flow counts within 1", children: nil},
					"active-workers":          {desc: "Alias for at-least-active-workers", args: 1, placeholder: "<count>", children: nil},
					"at-least-active-workers": {desc: "Expect at least this many workers with active flows", args: 1, placeholder: "<count>", children: nil},
					"max-worker-flow-share":   {desc: "Expect the busiest worker's share of active flows to be at most this threshold (fraction 0..1 or percent)", args: 1, placeholder: "<share>", children: nil},
					"cstruct":                 {desc: "Alias for cstruct-max", args: 1, placeholder: "<threshold>", children: nil},
					"cstruct-max":             {desc: "Expect the structural CoV ceiling (Cstruct) of the observed flow distribution to be at most this threshold (non-negative number or percent)", args: 1, placeholder: "<threshold>", children: nil},
				}},
			}},
		}},
	}},
}}

var schemaFirewall = &schemaNode{desc: "Firewall filters and policers", children: map[string]*schemaNode{
	"policer": {desc: "Traffic policer", args: 1, multi: true, placeholder: "<name>", children: map[string]*schemaNode{
		"if-exceeding": {desc: "Rate limits for the policer", children: map[string]*schemaNode{
			"bandwidth-limit":  {desc: "Bandwidth limit in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"burst-size-limit": {desc: "Burst size limit in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
		}},
		"logical-interface-policer": {desc: "Logical interface policer (shared across protocol families)", children: nil},
		"then": {desc: "Action for traffic exceeding the limits", children: map[string]*schemaNode{
			"discard":       {desc: "Discard excess traffic (default)", children: nil},
			"loss-priority": {desc: "Set loss priority for excess traffic (high|medium-high|medium-low|low)", args: 1, placeholder: "<priority>", children: nil},
		}},
	}},
	"three-color-policer": {desc: "Three-color policer", args: 1, multi: true, placeholder: "<name>", children: map[string]*schemaNode{
		"single-rate": {desc: "Single-rate three-color policer (CIR/CBS/EBS)", children: map[string]*schemaNode{
			"color-blind":                {desc: "Color-blind mode", children: nil},
			"color-aware":                {desc: "Color-aware mode", children: nil},
			"committed-information-rate": {desc: "Committed information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"committed-burst-size":       {desc: "Committed burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			"excess-burst-size":          {desc: "Excess burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
		}},
		"two-rate": {desc: "Two-rate three-color policer (CIR/CBS/PIR/PBS)", children: map[string]*schemaNode{
			"color-blind":                {desc: "Color-blind mode", children: nil},
			"color-aware":                {desc: "Color-aware mode", children: nil},
			"committed-information-rate": {desc: "Committed information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"committed-burst-size":       {desc: "Committed burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			"peak-information-rate":      {desc: "Peak information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"peak-burst-size":            {desc: "Peak burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
		}},
		"then": {desc: "Action for out-of-profile traffic", children: map[string]*schemaNode{
			"discard":       {desc: "Discard out-of-profile traffic (default)", children: nil},
			"loss-priority": {desc: "Set loss priority for out-of-profile traffic", args: 1, placeholder: "<priority>", children: nil},
		}},
	}},
	"family": {desc: "Protocol family for firewall filters", compoundKey: true, children: map[string]*schemaNode{
		"inet": {desc: "IPv4 firewall filters", children: map[string]*schemaNode{
			"filter": {desc: "Firewall filter", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
				"term": {desc: "Filter term", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
					"from": {desc: "Match conditions", children: map[string]*schemaNode{
						"source-address":          {desc: "Match source address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"destination-address":     {desc: "Match destination address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"source-prefix-list":      {desc: "Match source addresses from a prefix list", children: nil},
						"destination-prefix-list": {desc: "Match destination addresses from a prefix list", children: nil},
						"protocol":                {desc: "Match IP protocol", args: 1, multi: true, placeholder: "<protocol>", children: nil},
						"dscp":                    {desc: "Match DSCP value (name or number)", args: 1, multi: true, placeholder: "<dscp>", children: nil},
						"destination-port":        {desc: "Match destination port", args: 1, multi: true, placeholder: "<port>", children: nil},
						"source-port":             {desc: "Match source port", args: 1, multi: true, placeholder: "<port>", children: nil},
						"icmp-type":               {desc: "Match ICMP type (numeric)", args: 1, multi: true, placeholder: "<type>", children: nil},
						"icmp-code":               {desc: "Match ICMP code (numeric)", args: 1, multi: true, placeholder: "<code>", children: nil},
						"tcp-flags":               {desc: "Match TCP flags", args: 1, multi: true, placeholder: "<flags>", children: nil},
						"is-fragment":             {desc: "Match fragmented packets", children: nil},
						"flexible-match-range": {desc: "Flexible packet field match", children: map[string]*schemaNode{
							"range": {desc: "Named flexible match range", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
								"match-start": {desc: "Match start point (only layer-3 supported)", args: 1, placeholder: "<start>", children: nil},
								"byte-offset": {desc: "Byte offset from match start", args: 1, placeholder: "<bytes>", children: nil},
								"bit-length":  {desc: "Match length in bits (default 32)", args: 1, placeholder: "<bits>", children: nil},
								"range":       {desc: "Match value and mask (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-value": {desc: "Value to match (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-mask":  {desc: "Mask applied to the match value (hex)", args: 1, placeholder: "<mask>", children: nil},
							}},
						}},
					}},
					"then": {desc: "Actions for matching packets", children: map[string]*schemaNode{
						"accept":           {desc: "Accept the packet", children: nil},
						"reject":           {desc: "Reject the packet", children: nil},
						"discard":          {desc: "Discard the packet", children: nil},
						"log":              {desc: "Log matching packets", children: nil},
						"syslog":           {desc: "Log matching packets to the system log", children: nil},
						"routing-instance": {desc: "Forward via routing instance (filter-based forwarding)", args: 1, placeholder: "<instance>", children: nil},
						"count":            {desc: "Count matching packets in a named counter", args: 1, placeholder: "<counter-name>", children: nil},
						// #1319 PR 3 tree-based cross-ref: the dataplane
						// resolves this name against the CONFIGURED
						// forwarding classes and silently defaults the
						// queue on a miss (see validateForwardingClassRef
						// for the runtime citations and the best-effort
						// special case).
						"forwarding-class": {
							desc:          "Assign forwarding class",
							args:          1,
							valueType:     ValueIdentifier,
							valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
							valueExamples: []string{"best-effort"},
							treeValidator: validateForwardingClassRef,
							children:      nil,
						},
						"loss-priority": {desc: "Set packet loss priority (low|medium-low|medium-high|high)", args: 1, placeholder: "<priority>", children: nil},
						"dscp":          {desc: "Rewrite the DSCP value (name or number)", args: 1, placeholder: "<dscp>", children: nil},
						"traffic-class": {desc: "Rewrite the traffic class (DSCP name or number)", args: 1, placeholder: "<traffic-class>", children: nil},
						"policer":       {desc: "Apply a policer to matching traffic", args: 1, placeholder: "<policer-name>", children: nil},
					}},
				}},
			}},
		}},
		"inet6": {desc: "IPv6 firewall filters", children: map[string]*schemaNode{
			"filter": {desc: "Firewall filter", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
				"term": {desc: "Filter term", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
					"from": {desc: "Match conditions", children: map[string]*schemaNode{
						"source-address":          {desc: "Match source address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"destination-address":     {desc: "Match destination address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"source-prefix-list":      {desc: "Match source addresses from a prefix list", children: nil},
						"destination-prefix-list": {desc: "Match destination addresses from a prefix list", children: nil},
						"protocol":                {desc: "Match IP protocol", args: 1, multi: true, placeholder: "<protocol>", children: nil},
						"traffic-class":           {desc: "Match traffic class (DSCP name or number)", args: 1, multi: true, placeholder: "<traffic-class>", children: nil},
						"destination-port":        {desc: "Match destination port", args: 1, multi: true, placeholder: "<port>", children: nil},
						"source-port":             {desc: "Match source port", args: 1, multi: true, placeholder: "<port>", children: nil},
						"icmp-type":               {desc: "Match ICMP type (numeric)", args: 1, multi: true, placeholder: "<type>", children: nil},
						"icmp-code":               {desc: "Match ICMP code (numeric)", args: 1, multi: true, placeholder: "<code>", children: nil},
						"tcp-flags":               {desc: "Match TCP flags", args: 1, multi: true, placeholder: "<flags>", children: nil},
						"is-fragment":             {desc: "Match fragmented packets", children: nil},
						"flexible-match-range": {desc: "Flexible packet field match", children: map[string]*schemaNode{
							"range": {desc: "Named flexible match range", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
								"match-start": {desc: "Match start point (only layer-3 supported)", args: 1, placeholder: "<start>", children: nil},
								"byte-offset": {desc: "Byte offset from match start", args: 1, placeholder: "<bytes>", children: nil},
								"bit-length":  {desc: "Match length in bits (default 32)", args: 1, placeholder: "<bits>", children: nil},
								"range":       {desc: "Match value and mask (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-value": {desc: "Value to match (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-mask":  {desc: "Mask applied to the match value (hex)", args: 1, placeholder: "<mask>", children: nil},
							}},
						}},
					}},
					"then": {desc: "Actions for matching packets", children: map[string]*schemaNode{
						"accept":           {desc: "Accept the packet", children: nil},
						"reject":           {desc: "Reject the packet", children: nil},
						"discard":          {desc: "Discard the packet", children: nil},
						"log":              {desc: "Log matching packets", children: nil},
						"syslog":           {desc: "Log matching packets to the system log", children: nil},
						"routing-instance": {desc: "Forward via routing instance (filter-based forwarding)", args: 1, placeholder: "<instance>", children: nil},
						"count":            {desc: "Count matching packets in a named counter", args: 1, placeholder: "<counter-name>", children: nil},
						// #1319 PR 3 tree-based cross-ref: the dataplane
						// resolves this name against the CONFIGURED
						// forwarding classes and silently defaults the
						// queue on a miss (see validateForwardingClassRef
						// for the runtime citations and the best-effort
						// special case).
						"forwarding-class": {
							desc:          "Assign forwarding class",
							args:          1,
							valueType:     ValueIdentifier,
							valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
							valueExamples: []string{"best-effort"},
							treeValidator: validateForwardingClassRef,
							children:      nil,
						},
						"loss-priority": {desc: "Set packet loss priority (low|medium-low|medium-high|high)", args: 1, placeholder: "<priority>", children: nil},
						"dscp":          {desc: "Rewrite the DSCP value (name or number)", args: 1, placeholder: "<dscp>", children: nil},
						"traffic-class": {desc: "Rewrite the traffic class (DSCP name or number)", args: 1, placeholder: "<traffic-class>", children: nil},
						"policer":       {desc: "Apply a policer to matching traffic", args: 1, placeholder: "<policer-name>", children: nil},
					}},
				}},
			}},
		}},
	}},
}}
