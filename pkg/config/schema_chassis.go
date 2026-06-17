package config

// schema_chassis.go carries the `chassis` subtree of the config-mode
// grammar SSOT (#1891 domain split) — chassis cluster, redundancy
// groups, and RETH configuration. The root composition, the schemaNode
// type, and the split rationale live in schema.go.

var schemaChassis = &schemaNode{desc: "Chassis configuration", children: map[string]*schemaNode{
	// #1319 PR 2 typed leaves (chassis cluster subsystem). Fields-only
	// annotations — no children/args/multi changes, so SetPath flat-set
	// grouping is untouched (TestSetPathGrouping_Golden). Range policy:
	// the binding bound is what the xpf runtime actually consumes
	// (narrowest binary encoding / explicit clamp), checked against
	// Junos vSRX ranges second; deliberate Junos divergences are called
	// out per leaf because xpf's own defaults sit OUTSIDE the Junos
	// ranges for several knobs (the killed Phase-3a plan copied Junos
	// ranges blindly and would have rejected deployed configs).
	// Instance-name slots (`redundancy-group <id>`, the RG-scoped
	// `node <id>`) are NOT value slots — the walker's compiler-faithful
	// contract consumes identity tokens without validation; typing them
	// needs a new walker feature (deferred, see docs/config-schema.md).
	"cluster": {desc: "Chassis cluster (high-availability) configuration", children: map[string]*schemaNode{
		// One byte in the RETH virtual MAC 02:bf:72:CC:RR:NN
		// (cluster.RethMAC, pkg/cluster/reth.go:113) and in the stable
		// link-local (reth.go:124) — 256+ would silently alias MACs.
		// Heartbeat wire is uint16 (heartbeat.go:128), so the MAC byte
		// is the narrowest consumer. Junos vSRX: 0..255 (0 = disabled).
		// Deployed: 22 (docs/ha-cluster-userspace.conf:64).
		"cluster-id": {
			desc:          "Cluster identifier (0..255; one byte of the RETH virtual MAC)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Cluster identifier (0..255; one byte of the RETH virtual MAC)",
			valueExamples: []string{"1"},
			validator:     ValidateInteger(0, 255),
			children:      nil,
		},
		// xpf clusters are strictly two-node: heartbeat NodeID is uint8
		// but every owner/peer decision (SlotToNodeID FPC mapping,
		// election peer model) assumes 0|1. Junos vSRX: node 0..1.
		"node": {
			desc:          "Node identifier (0..1)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Node identifier (0..1)",
			valueExamples: []string{"0", "1"},
			validator:     ValidateInteger(0, 1),
			children:      nil,
		},
		// Junos vSRX reth-count range 1..128. Compiled verbatim
		// (compiler_system.go) and consumed for display (`show chassis
		// cluster information`, pkg/cli/cli_show_cluster.go:182).
		"reth-count": {
			desc:          "Number of RETH interfaces (1..128)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Number of RETH interfaces (1..128)",
			valueExamples: []string{"2"},
			validator:     ValidateInteger(1, 128),
			children:      nil,
		},
		// Milliseconds. xpf-DIVERGENT from Junos (1000..2000 ms): the
		// xpf default is 100 ms (cluster.DefaultHeartbeatInterval,
		// pkg/cluster/heartbeat.go:38) and deployed clusters run 200 ms
		// (docs/ha-cluster-userspace.conf:66) — the Junos floor would
		// reject xpf's own default scale. Runtime truth: any value > 0
		// is honored (group_state.go:55); 0 is rejected here because
		// the runtime silently substitutes the default for it (the
		// silent-coerce trap this gate exists to close). Upper bound is
		// the only genuine runtime ceiling — MaxDurationMillis, above
		// which the time.Duration(ms)*time.Millisecond conversion
		// (group_state.go:56) overflows negative and the heartbeat
		// sender ticker panics. No schema-only cap (Codex, PR #1845).
		"heartbeat-interval": {
			desc:          "Heartbeat send interval in milliseconds (default 100)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Heartbeat send interval in milliseconds (>= 1; xpf default 100, Junos allows 1000..2000)",
			valueExamples: []string{"100", "200", "1000"},
			validator:     ValidateInteger(1, MaxDurationMillis),
			children:      nil,
		},
		// Missed-heartbeat count before the peer is declared lost.
		// xpf-DIVERGENT from Junos (3..8): xpf's default is 5
		// (cluster.DefaultHeartbeatThreshold, heartbeat.go:41) and the
		// runtime honors any value > 0 (group_state.go:58) — a plain
		// int counter, never wire-encoded. Min-only per runtime truth
		// (Codex, PR #1845; the earlier 255 cap was schema-only). 0
		// rejected (silently means default at runtime).
		"heartbeat-threshold": {
			desc:          "Missed heartbeats before the peer is declared lost (default 5)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Missed heartbeats before peer is declared lost (>= 1; xpf default 5, Junos allows 3..8)",
			valueExamples: []string{"3", "5", "8"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"control-link-recovery": {desc: "Control link recovery (accepted for Junos compatibility; no runtime effect)", children: nil},
		// control-ports fpc/port: NOT typed — compileChassis never
		// reads control-ports (compiled-leaf-only invariant).
		"control-ports": {desc: "Control port assignments (accepted for Junos compatibility; ignored)", children: map[string]*schemaNode{
			"fpc": {desc: "FPC slot for the control port (ignored)", args: 1, placeholder: "<slot>", children: map[string]*schemaNode{
				"port": {desc: "Control port number on the FPC (ignored)", args: 1, placeholder: "<port>", children: nil},
			}},
		}},
		// Interface / address leaves stay untyped until the interfaces
		// subsystem PR introduces the IP/identifier value types.
		"control-interface":             {desc: "Control link interface for heartbeats and cluster sync", args: 1, placeholder: "<interface>", children: nil},
		"peer-address":                  {desc: "Cluster peer IP address on the control link", args: 1, placeholder: "<address>", children: nil},
		"fabric-interface":              {desc: "Fabric link interface for session sync and cross-chassis forwarding", args: 1, placeholder: "<interface>", children: nil},
		"fabric-peer-address":           {desc: "Cluster peer IP address on the fabric link", args: 1, placeholder: "<address>", children: nil},
		"configuration-synchronize":     {desc: "Synchronize committed configuration from primary to secondary", children: nil},
		"nat-state-synchronization":     {desc: "NAT state synchronization (accepted for Junos compatibility; no runtime effect)", children: nil},
		"ipsec-session-synchronization": {desc: "Synchronize IPsec SAs to the cluster peer", children: nil},
		// Milliseconds, xpf extension (default 30, pkg/vrrp/vrrp.go).
		// Both bounds are runtime-derived from the VRRPv3 encoding:
		// the ms value is integer-divided to centiseconds
		// (pkg/vrrp/instance.go:915), so <10 ms encodes as Max Advert
		// Int 0 on the wire; the wire field is 12 bits (RFC 5798,
		// packet.go:48-49 masks with 0x0FFF), so the last value that
		// still encodes to the max 4095 cs is 40959 (40959/10 = 4095)
		// and 40960 is the first that aliases (4096 & 0x0FFF = 0).
		// 10..40959 is exactly the encodable range; non-multiples of
		// 10 floor to the same centisecond the runtime sends.
		"reth-advertise-interval": {
			desc:          "VRRP advertisement interval for RETH instances (milliseconds, default 30)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "RETH VRRP advertisement interval in milliseconds (10..40959; default 30)",
			valueExamples: []string{"30", "100"},
			validator:     ValidateInteger(10, 40959),
			children:      nil,
		},
		"hitless-restart": {desc: "Keep dataplane forwarding active during daemon shutdown (HA default is fail-closed)", children: nil},
		// xpf extension. Only "disable-rg" is acted on by the runtime
		// (pkg/cluster/heartbeat_manager.go:362, failover.go:166); any
		// other string compiled silently no-ops — the enum closes that.
		"peer-fencing": {
			desc:          "Fencing action sent to the peer when its heartbeats are lost (disable-rg)",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Fencing action on heartbeat timeout (disable-rg)",
			valueExamples: []string{"disable-rg"},
			validator:     ValidateEnum([]string{"disable-rg"}),
			children:      nil,
		},
		// Milliseconds, xpf extension. 0 = immediate takeover once
		// ready (cluster.DefaultTakeoverHoldTime, manager.go:243);
		// negative is warned-and-ignored at runtime (group_state.go:70)
		// and rejected here. Runtime truth: any positive duration is
		// honored (group_state.go:74), so the only ceiling is
		// MaxDurationMillis — the time.Duration(ms)*time.Millisecond
		// overflow point (group_state.go:75). The earlier 1 h cap was
		// schema-only and removed (Codex, PR #1845).
		"takeover-hold-time": {
			desc:          "Extra delay before takeover in milliseconds (0 = immediate)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Extra delay before takeover in milliseconds (>= 0; 0 = immediate)",
			valueExamples: []string{"0", "5000"},
			validator:     ValidateInteger(0, MaxDurationMillis),
			children:      nil,
		},
		"no-reth-vrrp":           {desc: "Disable VRRP on RETH interfaces (election over the control link only)", children: nil},
		"private-rg-election":    {desc: "Elect RG primaries over the control link without RETH VRRP (default)", children: nil},
		"no-private-rg-election": {desc: "Disable private RG election (use legacy RETH VRRP election)", children: nil},
		"redundancy-group": {desc: "Redundancy group", args: 1, placeholder: "<group-id>", children: map[string]*schemaNode{
			"node": {desc: "Per-node settings for this redundancy group", args: 1, placeholder: "<node-id>", children: map[string]*schemaNode{
				// Junos vSRX: 1..254. Runtime-binding: the priority
				// feeds VRRP and is truncated to uint8 on the wire
				// (pkg/vrrp/instance.go:918); 255 is the RFC 5798
				// IP-owner reserved value (instance.go:256) and 0 is
				// treated as unset (vrrp.go pri==0 → default 100) —
				// both excluded. Heartbeat carries uint16 but VRRP is
				// the narrow consumer. Deployed: 200/100.
				"priority": {
					desc:          "Node priority for primary election (1..254; higher wins)",
					args:          1,
					valueType:     ValueInteger,
					valueDesc:     "Node priority for primary election (1..254; higher wins)",
					valueExamples: []string{"100", "200", "254"},
					validator:     ValidateInteger(1, 254),
					children:      nil,
				},
			}},
			// Runtime truth: any configured count > 0 is used verbatim
			// as the GARP/NA burst length (pkg/vrrp/instance.go GARP
			// loop, pkg/cluster/garp.go SendGratuitousARPBurst — both
			// only special-case <= 0 to the default), read via
			// daemon_ha_vip.go:475 and vrrp.go:94. Min-only per the
			// no-schema-only-caps doctrine (Codex, PR #1845) — Junos
			// caps at 16, but enforcing that here would reject configs
			// the runtime executes fine; a sanity cap belongs in the
			// runtime first. Deployed: 8.
			"gratuitous-arp-count": {
				desc:          "Gratuitous ARP/NA burst count on failover (default 3)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Gratuitous ARP/NA burst count on failover (>= 1; default 3, Junos allows 1..16)",
				valueExamples: []string{"3", "8", "16"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"preempt": {desc: "Allow a higher-priority node to preempt the primary role", children: nil},
			// interface-monitor weight is NOT typed in PR 2: the
			// `<ifname> weight <n>` tokens pack inline into one leaf
			// (children==nil here); typing the weight would require a
			// children/wildcard map, which flips SetPath's
			// replace-vs-container grouping — forbidden by the
			// fields-only rule. Deferred (docs/config-schema.md).
			"interface-monitor": {desc: "Deduct weight from the redundancy group while a monitored interface is down", children: nil},
			"ip-monitoring": {desc: "Probe monitored IPs and deduct weight on failure", children: map[string]*schemaNode{
				// Junos vSRX: 0..255. Weight subtracted from the RG
				// weight, which starts at 255 (group_state.go:29,
				// SetMonitorWeight election.go:324); heartbeat monitor
				// entries carry weight as uint8.
				"global-weight": {
					desc:          "Default weight deducted when a monitored IP fails (0..255)",
					args:          1,
					valueType:     ValueInteger,
					valueDesc:     "Default weight deducted when a monitored IP fails (0..255)",
					valueExamples: []string{"255"},
					validator:     ValidateInteger(0, 255),
					children:      nil,
				},
				// Junos vSRX: 0..255. Compiled verbatim
				// (compiler_system.go IPMonitoring.GlobalThreshold).
				"global-threshold": {
					desc:          "Cumulative failure weight that triggers failover (0..255)",
					args:          1,
					valueType:     ValueInteger,
					valueDesc:     "Cumulative failure weight that triggers failover (0..255)",
					valueExamples: []string{"100"},
					validator:     ValidateInteger(0, 255),
					children:      nil,
				},
				"family": {desc: "Address family of monitored IPs", compoundKey: true, children: map[string]*schemaNode{
					"inet": {desc: "IPv4 monitored addresses", wildcard: &schemaNode{desc: "Monitored IPv4 address", placeholder: "<address>", children: map[string]*schemaNode{
						// Junos vSRX: 0..255. 0 = inherit global-weight
						// (pkg/cluster/monitor.go pollIPMonitors).
						"weight": {
							desc:          "Weight deducted when this IP fails (0 = use global-weight)",
							args:          1,
							valueType:     ValueInteger,
							valueDesc:     "Weight deducted when this IP fails (0..255; 0 = use global-weight)",
							valueExamples: []string{"100", "255"},
							validator:     ValidateInteger(0, 255),
							children:      nil,
						},
					}}},
				}},
			}},
		}},
		// #1956 bare-metal device-map (sibling of cluster, so per-node
		// apply-groups compose). Opt-in stable-identity managed allowlist:
		// binds host NICs by PCI/permanent-MAC to xpf logical names and
		// governs everything else via unmapped-interface-policy. Absent or
		// empty => positional mode (today's behavior). See
		// docs/bare-metal-device-map.md.
		"device-map": {desc: "Bare-metal stable-identity interface map (#1956)", children: map[string]*schemaNode{
			// `interface <logical-name>` is a named-instance container. The
			// identity token is the xpf/vSRX logical name (ge-0/0/3, fxp0);
			// keyValueType marks it typed so `?` completion shows the slot,
			// keyValidator validates the name shape at commit. The regular
			// valueType MUST stay unset (this is a container, not a leaf).
			"interface": {
				desc:             "Bind a host NIC to an xpf logical interface name",
				args:             1,
				placeholder:      "<logical-name>",
				keyValueType:     ValueIdentifier,
				keyValueDesc:     "xpf logical interface name (e.g. ge-0/0/3, fxp0)",
				keyValueExamples: []string{"ge-0/0/3", "fxp0"},
				keyValidator:     ValidateDeviceMapLogicalName,
				children: map[string]*schemaNode{
					"pci": {
						desc:          "PCI bus address of the host NIC (primary identity key)",
						args:          1,
						valueType:     ValuePCIAddr,
						valueDesc:     "PCI bus address (DDDD:BB:DD.F; copy from `show chassis device-map candidates`)",
						valueExamples: []string{"0000:09:00.0"},
						validator:     ValidatePCIAddr,
						children:      nil,
					},
					"mac": {
						desc:          "Permanent (factory) MAC of the host NIC (fallback identity key)",
						args:          1,
						valueType:     ValueMAC,
						valueDesc:     "Permanent MAC address (xx:xx:xx:xx:xx:xx; fallback when PCI moves)",
						valueExamples: []string{"00:11:22:33:44:55"},
						validator:     ValidateMAC,
						children:      nil,
					},
					"key": {
						desc:          "Identity resolution order (default pci-then-mac)",
						args:          1,
						valueType:     ValueEnumOf,
						valueDesc:     "Identity key order (pci-then-mac | mac-then-pci | pci | mac)",
						valueExamples: []string{"pci-then-mac", "mac"},
						validator: ValidateEnum([]string{
							"pci-then-mac", "mac-then-pci", "pci", "mac",
						}),
						children: nil,
					},
				},
			},
			"unmapped-interface-policy": {
				desc:          "Policy for NICs with no map entry (default leave-alone)",
				args:          1,
				valueType:     ValueEnumOf,
				valueDesc:     "Unmapped-NIC policy (leave-alone | manage-down)",
				valueExamples: []string{"leave-alone", "manage-down"},
				validator:     ValidateEnum([]string{"leave-alone", "manage-down"}),
				children:      nil,
			},
		}},
	}},
}}
