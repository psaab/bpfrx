package config

// schema_system.go carries the system-management subtrees of the
// config-mode grammar SSOT (#1891 domain split): `system`, `services`,
// `snmp`, and `event-options`. The root composition, the schemaNode
// type, and the split rationale live in schema.go.

var schemaSystem = &schemaNode{desc: "System configuration", children: map[string]*schemaNode{
	"host-name":     {desc: "System hostname", args: 1, placeholder: "<hostname>", children: nil},
	"domain-name":   {desc: "Domain name", args: 1, placeholder: "<domain>", children: nil},
	"domain-search": {desc: "Domain search list", args: 1, multi: true, placeholder: "<domain>", children: nil},
	"time-zone":     {desc: "System time zone", args: 1, placeholder: "<timezone>", children: nil},
	"no-redirects":  {desc: "Disable ICMP redirects", children: nil},
	// #1319 PR 3: compiled verbatim and written into the resolver
	// drop-in (pkg/daemon/daemon_dns.go:114) — a garbage server
	// string silently produced broken DNS configuration.
	"name-server": {
		desc:          "DNS name server",
		args:          1,
		multi:         true,
		placeholder:   "<address>",
		valueType:     ValueIPAddress,
		valueDesc:     "DNS server IP address (IPv4 or IPv6)",
		valueExamples: []string{"8.8.8.8", "2001:4860:4860::8888"},
		validator:     ValidateIPAddress,
		children:      nil,
	},
	"backup-router": {desc: "Backup router", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
		"destination": {desc: "Destination network", args: 1, placeholder: "<network>", children: nil},
	}},
	"root-authentication": {desc: "Root authentication", children: map[string]*schemaNode{
		"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<password>", children: nil},
		"ssh-ed25519":        {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>", children: nil},
		"ssh-rsa":            {desc: "SSH RSA public key", args: 1, placeholder: "<key>", children: nil},
		"ssh-dsa":            {desc: "SSH DSA public key", args: 1, placeholder: "<key>", children: nil},
	}},
	"archival": {desc: "Configuration archival", children: map[string]*schemaNode{
		"configuration": {desc: "Configuration archival", children: map[string]*schemaNode{
			"transfer-on-commit": {desc: "Transfer on commit", children: nil},
			"archive-sites":      {desc: "Archive site URL", args: 1, placeholder: "<url>", children: nil},
		}},
	}},
	"master-password": {desc: "Master password", children: map[string]*schemaNode{
		"pseudorandom-function": {desc: "Pseudorandom function", args: 1, placeholder: "<function>", children: nil},
	}},
	"license": {desc: "License configuration", children: map[string]*schemaNode{
		"autoupdate": {desc: "Autoupdate", children: map[string]*schemaNode{
			"url": {desc: "Autoupdate URL", args: 1, placeholder: "<url>", children: nil},
		}},
	}},
	"processes": {desc: "Process information", children: nil},
	"internet-options": {desc: "Internet options", children: map[string]*schemaNode{
		"no-ipv6-reject-zero-hop-limit": {desc: "Do not reject IPv6 packets with zero hop limit", children: nil},
	}},
	"ntp": {desc: "NTP configuration", children: map[string]*schemaNode{
		"server": {desc: "NTP server", args: 1, placeholder: "<address>", children: nil},
		"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
			"action": {desc: "Action on threshold", args: 1, placeholder: "<action>", children: nil},
		}},
	}},
	"syslog": {desc: "Syslog configuration", children: map[string]*schemaNode{
		"user": {desc: "Syslog user", args: 1, placeholder: "<user>", children: nil},
		"host": {desc: "Syslog host", args: 1, placeholder: "<host>", children: nil},
		"file": {desc: "Syslog file", args: 1, placeholder: "<filename>", children: nil},
	}},
	"login": {desc: "Login configuration", children: map[string]*schemaNode{
		"user": {desc: "User name", args: 1, placeholder: "<username>", children: map[string]*schemaNode{
			"uid":            {desc: "User ID", args: 1, placeholder: "<uid>", children: nil},
			"class":          {desc: "Login class", args: 1, placeholder: "<class>", children: nil},
			"authentication": {desc: "Authentication methods", children: nil},
		}},
	}},
	"dataplane-type": {desc: "Dataplane type", args: 1, placeholder: "<type>", children: nil},
	"dataplane": {desc: "Dataplane configuration", children: map[string]*schemaNode{
		// cores / memory / socket-mem / rx-mode / ports are DPDK-era
		// knobs whose consumer was deleted in the #1525 retirement —
		// compileUserspaceDataplane has no case for any of them. They
		// stay in the grammar for stored-config compatibility (never
		// break an existing stanza) but have NO effect; the compiler
		// emits a per-knob commit warning instead (#1892,
		// userspaceRetiredKnobWarnings).
		"cores":          {args: 1, desc: "Legacy DPDK core count (retired, ignored)", children: nil},
		"memory":         {args: 1, desc: "Legacy DPDK memory allocation (retired, ignored)", children: nil},
		"socket-mem":     {args: 1, desc: "Legacy DPDK socket memory (retired, ignored)", children: nil},
		"binary":         {args: 1, desc: "Userspace dataplane helper binary path", children: nil},
		"control-socket": {args: 1, desc: "Unix control socket path", children: nil},
		"state-file":     {args: 1, desc: "Helper state file path", children: nil},
		// #1319 PR 3 typed dataplane knobs. Each compiled with the
		// Atoi error swallowed (compileUserspaceDataplane), so
		// garbage silently fell back to the 0 zero-value, which the
		// manager coerces to the default (workers<=0 -> 1,
		// ring-entries<=0 -> 1024; pkg/dataplane/userspace/
		// manager.go:1347-1351). Min-only: the runtime owns any
		// ceiling, and the Rust helper rounds ring sizes up to a
		// power of two itself (afxdp/bind.rs
		// checked_next_power_of_two).
		"workers": {
			args:          1,
			desc:          "Worker thread count",
			valueType:     ValueInteger,
			valueDesc:     "Dataplane worker thread count (>= 1)",
			valueExamples: []string{"4", "6"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"ring-entries": {
			args:          1,
			desc:          "AF_XDP ring entries per queue",
			valueType:     ValueInteger,
			valueDesc:     "AF_XDP ring entries per queue (>= 1; rounded up to a power of two)",
			valueExamples: []string{"1024", "2048"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		// Only these two strings are acted on; anything else was
		// silently ignored (compiler_system.go poll-mode case).
		"poll-mode": {
			args:          1,
			desc:          "Worker poll mode (busy-poll or interrupt)",
			valueType:     ValueEnumOf,
			valueDesc:     "Worker poll mode (busy-poll | interrupt)",
			valueExamples: []string{"busy-poll", "interrupt"},
			validator:     ValidateEnum([]string{"busy-poll", "interrupt"}),
			children:      nil,
		},
		"shared-umem": {desc: "AF_XDP shared-UMEM policy override", children: map[string]*schemaNode{
			"mode":                 {args: 1, desc: "Shared UMEM mode override (auto|off|same-device-debug|cross-nic)", children: nil},
			"interface":            {args: 1, multi: true, desc: "Optional participating Linux interface filter", children: nil},
			"phase0-artifact-file": {args: 1, desc: "Optional machine-readable Phase 0 audit artifact", children: nil},
			"artifact-file":        {args: 1, desc: "Alias for phase0-artifact-file", children: nil},
		}},
		// Only the literal "disable" acts; any other string
		// (including typos) silently meant the enabled default.
		"rss-indirection": {
			args:          1,
			desc:          "mlx5 RSS indirection reshaping (enable|disable)",
			valueType:     ValueEnumOf,
			valueDesc:     "RSS indirection reshaping (enable | disable; default enable)",
			valueExamples: []string{"enable", "disable"},
			validator:     ValidateEnum([]string{"enable", "disable"}),
			children:      nil,
		},
		// Only the literal "true" opts in (#801 B1 gate); any other
		// string silently meant false.
		"claim-host-tunables": {
			args:          1,
			desc:          "Allow xpfd to write host-scope tunables (true|false, default false)",
			valueType:     ValueBool,
			valueDesc:     "Write host-scope tunables (true | false; default false)",
			valueExamples: []string{"true", "false"},
			validator:     ValidateEnum([]string{"true", "false"}),
			children:      nil,
		},
		// cpu-governor stays untyped BY DESIGN: the compiler passes
		// unrecognised governors through so bare-metal operators can
		// request powersave/ondemand without a schema change
		// (compiler_system.go cpu-governor case).
		"cpu-governor": {args: 1, desc: "Host cpufreq governor (performance|schedutil|default; other governors pass through verbatim)", children: nil},
		// 0 is the "use default" zero-value sentinel
		// (resolvedHostTunables, pkg/daemon/host_tunables.go:494),
		// so garbage silently meant the default budget.
		"netdev-budget": {
			args:          1,
			desc:          "net.core.netdev_budget value",
			valueType:     ValueInteger,
			valueDesc:     "net.core.netdev_budget (>= 1)",
			valueExamples: []string{"600"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"coalescence": {desc: "NIC interrupt-coalescence tuning (mlx5)", children: map[string]*schemaNode{
			// Anything but the literal "enable" silently meant
			// disable (compiler_system.go coalescence case); the
			// usec knobs treat <= 0 as "use default"
			// (pkg/daemon/coalescence.go:60-65), so garbage
			// silently fell back too.
			"adaptive": {
				args:          1,
				desc:          "Adaptive coalescing (enable|disable)",
				valueType:     ValueEnumOf,
				valueDesc:     "Adaptive interrupt coalescing (enable | disable)",
				valueExamples: []string{"enable", "disable"},
				validator:     ValidateEnum([]string{"enable", "disable"}),
				children:      nil,
			},
			"rx-usecs": {
				args:          1,
				desc:          "RX coalescing µs",
				valueType:     ValueInteger,
				valueDesc:     "RX interrupt coalescing in microseconds (>= 1)",
				valueExamples: []string{"8"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"tx-usecs": {
				args:          1,
				desc:          "TX coalescing µs",
				valueType:     ValueInteger,
				valueDesc:     "TX interrupt coalescing in microseconds (>= 1)",
				valueExamples: []string{"8"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
		}},
		"rx-mode": {desc: "Legacy DPDK adaptive RX mode (retired, ignored)", children: map[string]*schemaNode{
			"idle-threshold":   {args: 1, desc: "Legacy DPDK RX idle threshold (retired, ignored)", children: nil},
			"resume-threshold": {args: 1, desc: "Legacy DPDK RX resume threshold (retired, ignored)", children: nil},
			"sleep-timeout":    {args: 1, desc: "Legacy DPDK RX sleep timeout (retired, ignored)", children: nil},
		}},
		"ports": {desc: "Legacy DPDK per-port mapping (retired, ignored)", wildcard: &schemaNode{desc: "Legacy DPDK port name (retired, ignored)", placeholder: "<port-name>", children: map[string]*schemaNode{
			"interface": {args: 1, desc: "Legacy DPDK port interface binding (retired, ignored)", children: nil},
			"rx-mode":   {args: 1, desc: "Legacy DPDK per-port RX mode (retired, ignored)", children: nil},
			"cores":     {args: 1, desc: "Legacy DPDK per-port core list (retired, ignored)", children: nil},
		}}},
	}},
	"services": {desc: "System services", children: map[string]*schemaNode{
		"ssh": {desc: "SSH service", children: map[string]*schemaNode{
			// Only allow/deny/deny-password map to sshd
			// PermitRootLogin values; anything else was a silent
			// no-op (pkg/daemon/daemon_system.go:739-748). The old
			// "<permit|deny>" placeholder named values the runtime
			// never accepted.
			"root-login": {
				desc:          "Root login permission",
				args:          1,
				placeholder:   "<allow|deny|deny-password>",
				valueType:     ValueEnumOf,
				valueDesc:     "Root SSH login policy (allow | deny | deny-password)",
				valueExamples: []string{"allow", "deny", "deny-password"},
				validator:     ValidateEnum([]string{"allow", "deny", "deny-password"}),
				children:      nil,
			},
		}},
		"netconf": {desc: "NETCONF service", children: map[string]*schemaNode{
			"ssh": {desc: "NETCONF over SSH", children: nil},
		}},
		"web-management": {desc: "Web management", children: map[string]*schemaNode{
			"http": {desc: "HTTP service", children: map[string]*schemaNode{
				"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
			}},
			"https": {desc: "HTTPS service", children: map[string]*schemaNode{
				"system-generated-certificate": {desc: "Use system-generated certificate", children: nil},
				"interface":                    {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
			}},
			"api-auth": {desc: "API authentication", children: map[string]*schemaNode{
				"user": {desc: "User name", wildcard: &schemaNode{desc: "Basic-auth user name for the REST API", placeholder: "<username>", children: map[string]*schemaNode{
					"password": {desc: "Password", args: 1, placeholder: "<password>", children: nil},
				}}},
				"api-key": {desc: "API key", args: 1, placeholder: "<key>", children: nil},
			}},
		}},
		"dns": {desc: "DNS service", children: nil},
		"dhcp-local-server": {desc: "DHCP local server", children: map[string]*schemaNode{
			"group": {desc: "DHCP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
				"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
			}},
		}},
		"dhcpv6-local-server": {desc: "DHCPv6 local server", children: map[string]*schemaNode{
			"group": {desc: "DHCPv6 group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
				"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
			}},
		}},
	}},
}}

var schemaServices = &schemaNode{desc: "Services configuration", children: map[string]*schemaNode{
	"rpm": {desc: "Real-time Performance Monitoring probes", children: map[string]*schemaNode{
		// #1319 PR 3: the rpm integer knobs already fail compile
		// loudly via parseRPMPositiveInt (> 0 enforced); typing them
		// surfaces the same bound at `?` completion and rejects in
		// the uniform schema-gate error shape before compile.
		"probe-limit": {
			args:          1,
			desc:          "Default maximum consecutive failed probes before stopping a test cycle",
			valueType:     ValueInteger,
			valueDesc:     "Maximum consecutive failed probes (>= 1)",
			valueExamples: []string{"3"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"probe": {args: 1, desc: "RPM probe name", children: map[string]*schemaNode{
			"test": {args: 1, desc: "RPM test name", children: map[string]*schemaNode{
				// Mirrors supportedRPMProbeTypes
				// (compiler_services.go:10) which the compiler
				// already rejects loudly.
				"probe-type": {
					args:          1,
					desc:          "Probe type: icmp-ping, tcp-ping, or http-get",
					valueType:     ValueEnumOf,
					valueDesc:     "Probe type (icmp-ping | tcp-ping | http-get)",
					valueExamples: []string{"icmp-ping", "tcp-ping", "http-get"},
					validator:     ValidateEnum([]string{"icmp-ping", "tcp-ping", "http-get"}),
					children:      nil,
				},
				"target":                {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}, "address": {args: 1, desc: "Target IP address (canonical Junos form)", children: nil}}},
				"source-address":        {args: 1, desc: "Source address for the probe", children: nil},
				"routing-instance":      {args: 1, desc: "Routing instance / VRF for the probe", children: nil},
				"destination-interface": {args: 1, desc: "Egress interface to pin the probe to", children: nil},
				"next-hop":              {args: 1, desc: "Next-hop IP to pin the probe via (reserved probe routing table)", children: nil},
				"probe-interval": {
					args:          1,
					desc:          "Seconds between probes within a test",
					valueType:     ValueInteger,
					valueDesc:     "Seconds between probes (>= 1)",
					valueExamples: []string{"5"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"probe-count": {
					args:          1,
					desc:          "Number of probes per test cycle",
					valueType:     ValueInteger,
					valueDesc:     "Probes per test cycle (>= 1)",
					valueExamples: []string{"3"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"test-interval": {
					args:          1,
					desc:          "Seconds between test cycles",
					valueType:     ValueInteger,
					valueDesc:     "Seconds between test cycles (>= 1)",
					valueExamples: []string{"30"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"thresholds": {desc: "Failure thresholds for the test", children: map[string]*schemaNode{
					"successive-loss": {
						args:          1,
						desc:          "Consecutive losses before marking the test failed",
						valueType:     ValueInteger,
						valueDesc:     "Consecutive losses before failure (>= 1)",
						valueExamples: []string{"3"},
						validator:     ValidateIntegerMin(1),
						children:      nil,
					},
				}},
				"probe-limit": {
					args:          1,
					desc:          "Maximum consecutive failed probes before stopping the current test cycle",
					valueType:     ValueInteger,
					valueDesc:     "Maximum consecutive failed probes (>= 1)",
					valueExamples: []string{"3"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				// The compiler only enforces > 0; the TCP port wire
				// encoding is 16 bits, so 65536+ dialed and failed
				// silently at probe runtime.
				"destination-port": {
					args:          1,
					desc:          "Destination TCP port for tcp-ping probes",
					valueType:     ValueInteger,
					valueDesc:     "Destination TCP port (1..65535)",
					valueExamples: []string{"443"},
					validator:     ValidateInteger(1, 65535),
					children:      nil,
				},
			}},
		}},
	}},
	"ip-monitoring": {desc: "IP monitoring: probe-driven preferred-route failover", children: map[string]*schemaNode{
		"policy": {args: 1, desc: "IP monitoring policy name", placeholder: "<policy-name>", children: map[string]*schemaNode{
			"match": {desc: "Match conditions", children: map[string]*schemaNode{
				"rpm-probe": {args: 1, desc: "RPM probe whose test failures trigger this policy", placeholder: "<probe-name>", children: nil},
			}},
			"then": {desc: "Actions while the matched probe is FAILED", children: map[string]*schemaNode{
				"preferred-route": {desc: "Preferred routes injected at route preference 1", children: map[string]*schemaNode{
					"route": {args: 1, desc: "Destination prefix to inject", placeholder: "<prefix>", children: map[string]*schemaNode{
						"next-hop": {args: 1, desc: "Next-hop IP for the injected route, or a DHCP interface unit (<ifd>.<unit>) to track its learned gateway", children: nil},
						// Min-only, mirroring the compiler's loud
						// >= 0 check; the metric is a pure in-memory
						// tie-break comparator (pkg/ipmon/ipmon.go:361),
						// never wire-encoded.
						"preferred-metric": {
							args:          1,
							desc:          "Metric among injected routes for the same prefix (tie-break)",
							valueType:     ValueInteger,
							valueDesc:     "Tie-break metric among injected routes (>= 0)",
							valueExamples: []string{"10"},
							validator:     ValidateIntegerMin(0),
							children:      nil,
						},
					}},
					"routing-instance": {args: 1, desc: "Inject into a routing instance", placeholder: "<instance>", children: map[string]*schemaNode{
						"route": {args: 1, desc: "Destination prefix to inject", placeholder: "<prefix>", children: map[string]*schemaNode{
							"next-hop": {args: 1, desc: "Next-hop IP for the injected route, or a DHCP interface unit (<ifd>.<unit>) to track its learned gateway", children: nil},
							// See the sibling preferred-metric note.
							"preferred-metric": {
								args:          1,
								desc:          "Metric among injected routes for the same prefix (tie-break)",
								valueType:     ValueInteger,
								valueDesc:     "Tie-break metric among injected routes (>= 0)",
								valueExamples: []string{"10"},
								validator:     ValidateIntegerMin(0),
								children:      nil,
							},
						}},
					}},
				}},
			}},
			// The compiler rejects negatives loudly; the runtime
			// converts to time.Duration (pkg/ipmon/ipmon.go:480), so
			// the only genuine ceiling is the Duration-overflow
			// point (MaxDurationSeconds) — past it the hold went
			// negative and silently inverted the damping.
			"hold-down": {
				args:          1,
				desc:          "Seconds to damp recovery before withdrawing routes (0 = immediate, Junos parity)",
				valueType:     ValueInteger,
				valueDesc:     "Recovery damping in seconds (>= 0; 0 = immediate)",
				valueExamples: []string{"0", "30"},
				validator:     ValidateInteger(0, MaxDurationSeconds),
				children:      nil,
			},
		}},
	}},
	"flow-monitoring": {desc: "Flow export (NetFlow v9 / IPFIX) template configuration", children: map[string]*schemaNode{
		"version9": {desc: "NetFlow version 9 export", children: map[string]*schemaNode{
			"template": {desc: "NetFlow v9 flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
				"flow-active-timeout":   {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
				"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>", children: nil},
				"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
					"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
				}},
			}},
		}},
		"version-ipfix": {desc: "IPFIX flow export", children: map[string]*schemaNode{
			"template": {desc: "IPFIX flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
				"flow-active-timeout":   {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
				"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>", children: nil},
				"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
					"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
				}},
				"ipv4-template": {desc: "IPv4 flow record template options", children: map[string]*schemaNode{
					"export-extension": {desc: "Export extension (accepted; not applied to IPFIX records)", args: 1, placeholder: "<extension>", children: nil},
				}},
				"ipv6-template": {desc: "IPv6 flow record template options", children: map[string]*schemaNode{
					"export-extension": {desc: "Export extension (accepted; not applied to IPFIX records)", args: 1, placeholder: "<extension>", children: nil},
				}},
			}},
		}},
	}},
	"application-identification": {desc: "Enable application identification against the predefined application catalog (port/protocol matching; no L7 DPI)", children: nil},
}}

var schemaSNMP = &schemaNode{desc: "SNMP configuration", children: map[string]*schemaNode{
	"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
		"authorization": {desc: "Authorization level", args: 1, placeholder: "<level>", children: nil},
	}},
	"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", children: nil},
	"v3": {desc: "SNMPv3", children: map[string]*schemaNode{
		"usm": {desc: "USM", children: map[string]*schemaNode{
			"local-engine": {desc: "Local engine", children: map[string]*schemaNode{
				"user": {desc: "User name", args: 1, placeholder: "<user-name>", children: map[string]*schemaNode{
					"authentication-md5":    {desc: "MD5 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"authentication-sha":    {desc: "SHA authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"authentication-sha256": {desc: "SHA256 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"privacy-des":           {desc: "DES privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"privacy-aes128":        {desc: "AES128 privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
				}},
			}},
		}},
	}},
}}

var schemaEventOptions = &schemaNode{desc: "Event policies for automated configuration changes", children: map[string]*schemaNode{
	"policy": {desc: "Event policy", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
		"events": {desc: "Events that trigger this policy", children: nil},
		"within": {desc: "Time window for trigger evaluation", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
			"trigger": {desc: "Trigger condition (on|until <count>)", children: nil},
		}},
		"attributes-match": {desc: "Match event attributes (<event>.<attribute> matches <value>)", children: nil},
		"then": {desc: "Actions when the policy triggers", children: map[string]*schemaNode{
			"change-configuration": {desc: "Apply configuration changes", children: map[string]*schemaNode{
				"commands": {desc: "Configuration commands to apply (set/delete)", children: nil},
			}},
		}},
	}},
}}
