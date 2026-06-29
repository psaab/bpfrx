package config

// schema_system.go carries the system-management subtrees of the
// config-mode grammar SSOT (#1891 domain split): `system`, `services`,
// `snmp`, and `event-options`. The root composition, the schemaNode
// type, and the split rationale live in schema.go.

// junosSyslogSeverities is the fixed Junos syslog severity vocabulary used
// for the value slot of a `<facility> <severity>` system-syslog pair. The
// facility keyword itself is open-ended (a wildcard schema child), but the
// severity is one of these names; anything else is a typo the runtime would
// silently treat as "no severity filter" (logging.ParseSeverity returns 0
// for unknown names). #2008.
var junosSyslogSeverities = []string{
	"any", "none", "emergency", "alert", "critical",
	"error", "warning", "notice", "info", "debug",
}

// syslogFacilitySeverityLeaf builds the wildcard typed leaf used for a
// system-syslog `<facility> <severity>` pair. It is a fresh node per call so
// that each destination (host/file/user) owns an independent wildcard and a
// future edit to one does not alias the others. #2008.
func syslogFacilitySeverityLeaf() *schemaNode {
	return &schemaNode{
		desc:          "Syslog facility (value is the severity threshold)",
		args:          1,
		placeholder:   "<severity>",
		valueType:     ValueEnumOf,
		valueDesc:     "syslog severity threshold",
		valueExamples: []string{"any", "info", "warning", "error"},
		validator:     ValidateEnum(junosSyslogSeverities),
	}
}

var schemaSystem = &schemaNode{desc: "System configuration", children: map[string]*schemaNode{
	"host-name":     {desc: "System hostname", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
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
		// #1944 E1: share ValidateCryptHash with per-user
		// authentication so root's identical plaintext footgun is
		// closed (one validator, one error message).
		"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<crypt-hash>",
			valueType: ValueCryptHash, validator: ValidateCryptHash, children: nil},
		"ssh-ed25519": {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>", children: nil},
		"ssh-rsa":     {desc: "SSH RSA public key", args: 1, placeholder: "<key>", children: nil},
		"ssh-dsa":     {desc: "SSH DSA public key", args: 1, placeholder: "<key>", children: nil},
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
		// #2008 (syslog schema-only): a system syslog host/file/user
		// destination body is a set of `<facility> <severity>` pairs
		// (compiler_system.go syslog loop reads Keys[0]=facility,
		// Keys[1]=severity for every non-`allow-duplicates` child). The
		// facility namespace is open-ended (kern, daemon, auth, local0-7,
		// any, ...) so the FACILITY keyword stays a wildcard — but the
		// SEVERITY value slot is a fixed Junos vocabulary, so a typed
		// wildcard leaf catches a misspelled severity (e.g. `kernel
		// informational`) that the runtime would otherwise treat as "no
		// filter" (ParseSeverity returns 0 for anything it does not know).
		// `allow-duplicates` is an explicit presence-only flag so it is
		// not mistaken for a facility with a missing severity.
		"user": {desc: "Syslog user destination", args: 1, placeholder: "<user>",
			wildcard: syslogFacilitySeverityLeaf()},
		"host": {desc: "Syslog host destination", args: 1, placeholder: "<host>",
			wildcard: syslogFacilitySeverityLeaf(), children: map[string]*schemaNode{
				"allow-duplicates": {desc: "Do not suppress duplicate messages", children: nil},
			}},
		"file": {desc: "Syslog file destination", args: 1, placeholder: "<filename>",
			wildcard: syslogFacilitySeverityLeaf()},
	}},
	"login": {desc: "Login configuration", children: map[string]*schemaNode{
		"user": {desc: "User name", args: 1, placeholder: "<username>", children: map[string]*schemaNode{
			"uid": {desc: "User ID", args: 1, placeholder: "<uid>", children: nil},
			// #2008 H6: enum-validate the login class at commit (RBAC is
			// already enforced in pkg/cli/permissions.go; this closes the
			// commit-accepts-any-string hole). The allowed set is derived from
			// LoginClassPermissions so the schema enum and the runtime RBAC
			// table cannot drift. Mirrors the SNMP `authorization` enum leaf.
			"class": {desc: "Login class", args: 1, placeholder: "<class>",
				valueType: ValueEnumOf, valueDesc: "System-defined login class (super-user | operator | read-only | config-viewer | unauthorized)",
				valueExamples: []string{"super-user", "operator", "read-only"},
				validator:     ValidateEnum(ValidLoginClasses()), children: nil},
			// #1944: close the schema asymmetry the compiler already
			// half-implemented — give `authentication` a value-bearing
			// children map (encrypted-password typed leaf + ssh-* keys).
			"authentication": {desc: "Authentication methods", children: map[string]*schemaNode{
				"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<crypt-hash>",
					valueType: ValueCryptHash, validator: ValidateCryptHash, children: nil},
				"ssh-ed25519": {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>", children: nil},
				"ssh-rsa":     {desc: "SSH RSA public key", args: 1, placeholder: "<key>", children: nil},
				"ssh-dsa":     {desc: "SSH DSA public key", args: 1, placeholder: "<key>", children: nil},
			}},
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
		// manager.go capabilities.go). `workers` stays min-only (the
		// runtime owns its ceiling); `ring-entries` is bounded both
		// ways and required power-of-two as of #2524, because it sizes
		// per-binding UMEM preallocations directly (an unbounded value
		// OOM'd at bring-up rather than failing at commit).
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
			valueDesc:     "AF_XDP ring entries per queue (power of two in [1..16384])",
			valueExamples: []string{"1024", "2048"},
			// #2524: bound [1..MaxRingEntries] AND power-of-two. The
			// helper preallocates ~3×ring_entries UMEM frames per binding
			// (bind.rs), so an unbounded value OOM'd at bring-up instead
			// of failing as a clean commit error.
			validator: ValidateRingEntries,
			children:  nil,
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
			// H5 (#2008): repeatable key-exchange method → sshd
			// KexAlgorithms (pkg/daemon/daemon_system.go applySSHConfig).
			// Junos takes a free-form algorithm-name list; sshd validates
			// the spellings at reload, so no enum here.
			"key-exchange": {
				desc:        "SSH key-exchange method (KexAlgorithms)",
				args:        1,
				multi:       true,
				placeholder: "<key-exchange-method>",
				children:    nil,
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
				"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: map[string]*schemaNode{
					"static-binding": dhcpStaticBindingSchema(),
				}},
			}},
			"dynamic-dns":               dhcpDynamicDNSSchema(),
			"expired-leases-processing": dhcpExpiredLeasesSchema(),
		}},
		"dhcpv6-local-server": {desc: "DHCPv6 local server", children: map[string]*schemaNode{
			"group": {desc: "DHCPv6 group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
				"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: map[string]*schemaNode{
					"static-binding": dhcpStaticBindingSchema(),
				}},
			}},
			"dynamic-dns":               dhcpDynamicDNSSchema(),
			"expired-leases-processing": dhcpExpiredLeasesSchema(),
		}},
		"dynamic-dns": ddnsServicesSchema(),
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
				// #1979 Layer B (Tier 1): FlowActiveTimeout/InactiveTimeout
				// reach the Rust u32 ActiveTimeout/InactiveTimeout wire fields
				// via buildFlowExportSnapshot (Layer A caps <0->0, >u32max->
				// u32max, flow.go coerceWireU32Timeout). Reject the out-of-
				// range value at commit instead of silently coercing it.
				"flow-active-timeout": {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Active flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"60"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Inactive flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"15"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
					"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
				}},
			}},
		}},
		"version-ipfix": {desc: "IPFIX flow export", children: map[string]*schemaNode{
			"template": {desc: "IPFIX flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
				// #1979 Layer B (Tier 1, §4b): the IPFIX timeouts do NOT reach
				// the wire (buildFlowExportSnapshot reads only fm.Version9,
				// flow.go), so this is UX parity only — but typing them is the
				// same one-line change and keeps the two template families
				// consistent. The Layer-A-agreement property test EXCLUDES
				// these (not wire-reaching); plain accept/reject covers them.
				"flow-active-timeout": {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Active flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"60"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Inactive flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"15"}, validator: ValidateInteger(0, maxWireU32), children: nil},
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

// dhcpDynamicDNSSchema returns the typed-leaf schema for the #1387
// DHCP dynamic-DNS block, shared by dhcp-local-server and
// dhcpv6-local-server. Returned as a fresh tree per call so the two
// parents do not share a mutable map. The enums + ttl carry validators
// (the compiler/runtime consume them); the free-form credential and
// target fields (domain, update-server, tsig-*) stay untyped so a valid
// hostname / base64 secret is not rejected at commit — the live rfc2136
// backend that consumes them is warn-validated at commit
// (validateDDNSBackendWarnings) and fail-open at runtime, never a hard
// brick.
func dhcpDynamicDNSSchema() *schemaNode {
	return &schemaNode{desc: "Dynamic DNS updates for DHCP leases (#1387)", children: map[string]*schemaNode{
		"enable": {desc: "Enable dynamic DNS record publishing", children: nil},
		"domain": {
			desc:        "Default DNS domain appended to non-FQDN client names",
			args:        1,
			placeholder: "<domain>",
			children:    nil,
		},
		"ttl": {
			desc:          "TTL (seconds) for published A/AAAA/PTR records (default 300)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Record TTL in seconds (>= 1; default 300 when unset)",
			valueExamples: []string{"300", "3600"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"hostname-source": {
			desc:          "How the published label is derived from the lease",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Label source (client-hostname | fqdn | mac-fallback)",
			valueExamples: []string{"client-hostname", "fqdn", "mac-fallback"},
			validator:     ValidateEnum([]string{"client-hostname", "fqdn", "mac-fallback"}),
			children:      nil,
		},
		"conflict-policy": {
			desc:          "Behaviour on a colliding existing record",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Conflict policy (replace-owned | skip-existing | strict-fail)",
			valueExamples: []string{"replace-owned", "skip-existing", "strict-fail"},
			validator:     ValidateEnum([]string{"replace-owned", "skip-existing", "strict-fail"}),
			children:      nil,
		},
		"backend": {
			desc:          "DNS-update backend (rfc2136 is live; kea-d2 is reserved/unimplemented)",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Update backend (rfc2136 [live] | kea-d2 [reserved, not in image])",
			valueExamples: []string{"rfc2136"},
			validator:     ValidateEnum([]string{"rfc2136", "kea-d2"}),
			children:      nil,
		},
		"update-server": {
			desc:        "Authoritative DNS target for RFC 2136 updates (host[:port])",
			args:        1,
			placeholder: "<host[:port]>",
			children:    nil,
		},
		"tsig-key": {
			desc:        "TSIG key name for authenticated updates",
			args:        1,
			placeholder: "<key-name>",
			children:    nil,
		},
		"tsig-algorithm": {
			desc:        "TSIG algorithm (e.g. hmac-sha256)",
			args:        1,
			placeholder: "<algorithm>",
			children:    nil,
		},
		"tsig-secret": {
			desc:        "TSIG shared secret (sensitive; redacted in show output)",
			args:        1,
			placeholder: "<secret>",
			children:    nil,
		},
		// #2691 P1b / #2665: source/VRF binding for the RFC 2136 UPDATE
		// transport (multi-WAN / VRF parity). All three are free-form leaves
		// (an IP literal / interface name / routing-instance name) — the live
		// backend builds a custom net.Dialer (LocalAddr + SO_BINDTODEVICE / VRF
		// bind) from them; an unusable value is fail-open at runtime (logged,
		// the update falls back to the default table), never a hard commit
		// brick — matching the existing update-server / tsig-* leaves.
		"source-address": {
			desc:        "Source address to bind the RFC 2136 UPDATE socket to (#2665)",
			args:        1,
			placeholder: "<ip>",
			children:    nil,
		},
		"destination-interface": {
			desc:        "Egress interface to pin the RFC 2136 UPDATE to (SO_BINDTODEVICE, #2665)",
			args:        1,
			placeholder: "<interface>",
			children:    nil,
		},
		"routing-instance": {
			desc:        "Routing instance / VRF the RFC 2136 UPDATE egresses from (#2665)",
			args:        1,
			placeholder: "<instance>",
			children:    nil,
		},
	}}
}

// ddnsServicesSchema returns the config-mode schema for the Surface A
// `system services dynamic-dns` provider catalog + engine tunables (#2691 P2,
// plan §5.9). The `provider <name>` block is a repeatable named instance
// (credentials configured once, referenced by per-interface bindings). The
// backend enum is validated (rfc2136 live; dyndns2/cloudflare/route53/generic
// reserved for P3); credentials stay free-form (a valid base64 secret / host
// is not rejected at commit — the live backend is warn-validated at commit and
// fail-open at runtime). forced-refresh / error-backoff-max accept a Go
// duration ("24h") or a bare-seconds integer.
func ddnsServicesSchema() *schemaNode {
	return &schemaNode{desc: "Dynamic DNS provider catalog + engine tunables (Surface A, #2691)", children: map[string]*schemaNode{
		"provider": {desc: "Named DDNS provider", args: 1, placeholder: "<provider-name>", children: map[string]*schemaNode{
			"backend": {
				desc:          "DNS-update backend (rfc2136/dyndns2/duckdns/cloudflare/route53/generic)",
				args:          1,
				valueType:     ValueEnumOf,
				valueDesc:     "Update backend (rfc2136 [live] | dyndns2 | duckdns | cloudflare | route53 | generic)",
				valueExamples: []string{"rfc2136"},
				validator:     ValidateEnum([]string{"rfc2136", "dyndns2", "duckdns", "cloudflare", "route53", "generic"}),
				children:      nil,
			},
			"update-server":         {desc: "Authoritative DNS target for RFC 2136 updates (host[:port])", args: 1, placeholder: "<host[:port]>", children: nil},
			"tsig-key":              {desc: "TSIG key name for authenticated updates", args: 1, placeholder: "<key-name>", children: nil},
			"tsig-algorithm":        {desc: "TSIG algorithm (e.g. hmac-sha256)", args: 1, placeholder: "<algorithm>", children: nil},
			"tsig-secret":           {desc: "TSIG shared secret (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"source-address":        {desc: "Source address to bind the UPDATE socket to (#2665)", args: 1, placeholder: "<ip>", children: nil},
			"destination-interface": {desc: "Egress interface to pin the UPDATE to (SO_BINDTODEVICE, #2665)", args: 1, placeholder: "<interface>", children: nil},
			"routing-instance":      {desc: "Routing instance / VRF the UPDATE egresses from (#2665)", args: 1, placeholder: "<instance>", children: nil},
			// HTTP-provider leaves (#2691 P3).
			"server":            {desc: "dyndns2 update endpoint host or base URL (default: built-in for the named provider)", args: 1, placeholder: "<host|url>", children: nil},
			"username":          {desc: "HTTP Basic-auth username (dyndns2 / generic)", args: 1, placeholder: "<username>", children: nil},
			"password":          {desc: "HTTP Basic-auth password (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"url-template":      {desc: "generic backend update URL template (%h host, %i IP, %u user, %p pass, %% literal)", args: 1, placeholder: "<url-template>", children: nil},
			"ok-response":       {desc: "generic backend success-substring matcher (default: good/nochg/ok/true/updated)", args: 1, placeholder: "<substring>", children: nil},
			"api-token":         {desc: "Cloudflare / DuckDNS API token (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"zone":              {desc: "Cloudflare DNS zone name the record lives in (e.g. example.net)", args: 1, placeholder: "<zone>", children: nil},
			"aws-access-key":    {desc: "Route 53 AWS access-key id (SigV4)", args: 1, placeholder: "<access-key-id>", children: nil},
			"aws-secret-key":    {desc: "Route 53 AWS secret access key (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"aws-region":        {desc: "Route 53 AWS region for SigV4 signing (default: us-east-1)", args: 1, placeholder: "<region>", children: nil},
			"hosted-zone-id":    {desc: "Route 53 hosted-zone id (e.g. Z123456ABCDEF)", args: 1, placeholder: "<zone-id>", children: nil},
			"checkip-url":       {desc: "optional external check-IP URL for behind-NAT address detection (opt-in, #2691 P3)", args: 1, placeholder: "<url>", children: nil},
			"checkip-allowlist": {desc: "comma/space-separated bogus addresses to ignore in a check-IP response (e.g. 1.1.1.1)", args: 1, placeholder: "<addr-list>", children: nil},
		}},
		"forced-refresh":    {desc: "Wire-update floor for an unchanged address (duration, e.g. 24h, or seconds; default 24h)", args: 1, placeholder: "<duration>", children: nil},
		"error-backoff-max": {desc: "Cap for the per-scope error backoff (duration, e.g. 1h, or seconds; default 1h)", args: 1, placeholder: "<duration>", children: nil},
	}}
}

// dhcpExpiredLeasesSchema returns the typed-leaf schema for the #1387
// stale-lease-cleanup slice (Path S): the per-family
// `expired-leases-processing` reclamation block, shared by
// dhcp-local-server and dhcpv6-local-server. Returned fresh per call so
// the two parents do not alias a mutable map (same pattern as
// dhcpDynamicDNSSchema / dhcpStaticBindingSchema).
//
// Floor split (SMR MAJOR-3, fail-safe default): the three TIMERS
// (reclaim/flush/hold) use ValidateIntegerMin(1) because a 0 some Kea
// versions reject would take DHCP DOWN on the fail-closed restart; the
// two CAP knobs (max-leases, max-time) use ValidateIntegerMin(0) because
// Kea documents 0 = unlimited there (a value the model tracks distinctly
// from unset — invariant H2), and unwarned-cycles uses Min(0). Kea has
// no documented hard upper bound on these knobs, so min-only validation
// is correct (no schema-only cap, per the docs/config-schema.md range
// policy).
func dhcpExpiredLeasesSchema() *schemaNode {
	return &schemaNode{desc: "Kea expired-lease reclamation policy (#1387)", children: map[string]*schemaNode{
		"enable": {desc: "Enable expired-lease reclamation tuning", children: nil},
		"reclaim-timer": {
			desc:          "Seconds between reclamation cycles (reclaim-timer-wait-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Seconds (>= 1)",
			valueExamples: []string{"10"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"flush-timer": {
			desc:          "Seconds between reclaimed-lease flush passes (flush-reclaimed-timer-wait-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Seconds (>= 1)",
			valueExamples: []string{"25"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"hold-time": {
			desc:          "Seconds a reclaimed lease is held before removal (hold-reclaimed-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Seconds (>= 1)",
			valueExamples: []string{"600"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"max-leases": {
			desc:          "Maximum leases reclaimed per cycle, 0 = unlimited (max-reclaim-leases)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Leases per cycle (>= 0; 0 = unlimited)",
			valueExamples: []string{"100", "0"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
		"max-time": {
			desc:          "Max milliseconds spent reclaiming per cycle, 0 = unlimited (max-reclaim-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Milliseconds (>= 0; 0 = unlimited)",
			valueExamples: []string{"250", "0"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
		"unwarned-cycles": {
			desc:          "Consecutive capped cycles before Kea warns (unwarned-reclaim-cycles)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Cycles (>= 0)",
			valueExamples: []string{"5"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
	}}
}

// dhcpStaticBindingSchema returns the typed-leaf schema for a #2243
// DHCP-server static (fixed/reserved) host binding, used under both
// dhcp-local-server and dhcpv6-local-server `group <g> pool <p>`. The
// instance key is the client hardware address (MAC), validated by
// ValidateMAC; fixed-address is a typed IP slot. The address-within-subnet,
// duplicate-MAC, and duplicate-address checks need the compiled pool
// (subnet), so they live in validateDHCPStaticBindingsStrict, not here.
// Returned fresh per call so the two parents do not share a mutable map.
func dhcpStaticBindingSchema() *schemaNode {
	return &schemaNode{
		desc:             "Fixed/reserved address binding for a client MAC (#2243)",
		args:             1,
		placeholder:      "<mac-address>",
		keyValueType:     ValueMAC,
		keyValueDesc:     "Client hardware (MAC) address (xx:xx:xx:xx:xx:xx)",
		keyValueExamples: []string{"00:11:22:33:44:55"},
		keyValidator:     ValidateMAC,
		children: map[string]*schemaNode{
			"fixed-address": {
				desc:          "Reserved IP the matching client always receives (must be inside the pool subnet)",
				args:          1,
				valueType:     ValueIPAddress,
				valueDesc:     "Fixed IP address (v4 or v6) within the enclosing pool subnet",
				valueExamples: []string{"10.0.1.50", "2001:db8::50"},
				validator:     ValidateIPAddress,
				children:      nil,
			},
			"host-name": {
				desc:        "Optional reservation hostname (Kea reservation hostname)",
				args:        1,
				placeholder: "<host-name>",
				children:    nil,
			},
		},
	}
}

var schemaSNMP = &schemaNode{desc: "SNMP configuration", children: map[string]*schemaNode{
	"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
		"authorization": {
			desc:          "Authorization level",
			args:          1,
			placeholder:   "<level>",
			valueType:     ValueEnumOf,
			valueDesc:     "Access level granted to the community (read-only | read-write)",
			valueExamples: []string{"read-only", "read-write"},
			validator:     ValidateEnum([]string{"read-only", "read-write"}),
			children:      nil,
		},
	}},
	"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
		"targets": {
			desc:        "Trap target host (IP address or FQDN, optional :port)",
			args:        1,
			multi:       true,
			placeholder: "<target>",
			children:    nil,
		},
		"version": {
			desc:          "SNMP version for this trap group",
			args:          1,
			placeholder:   "<version>",
			valueType:     ValueEnumOf,
			valueDesc:     "Trap protocol version (v1 | v2 | all)",
			valueExamples: []string{"v1", "v2", "all"},
			validator:     ValidateEnum([]string{"v1", "v2", "all"}),
			children:      nil,
		},
		"categories": {desc: "Trap categories to send to this group", args: 1, multi: true, placeholder: "<category>", children: nil},
	}},
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
