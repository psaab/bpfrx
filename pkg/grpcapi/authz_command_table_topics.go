package grpcapi

// Canonical command strings for the two REQUEST-DECODED gRPC methods
// (#7172 cut 5a-2): ShowText's topics and SystemAction's verbs.
//
// This is the other half of authz_command_table.go. That file maps a gRPC
// METHOD to the operational command it performs, and deliberately leaves two
// methods out: ShowText and SystemAction each multiplex many commands through
// one method name, so a single string for either would be a lie. They are
// priced for coarse permissions from the DECODED request (showTextTopicPermission
// / systemActionPermission in authz_methods.go), and for the same reason they
// are mapped to a command from the decoded request here.
//
// ── WHAT THIS FILE VERIFIES, AND WHAT IT DOES NOT ────────────────────────
//
// The tests prove two properties and NEITHER of them is attribution:
//
//   - CANONICALITY. Every value resolves against the operational tree to
//     itself, with every word a real command KEYWORD rather than a word a
//     value slot absorbed. So no entry names a command that cannot be run.
//   - COMPLETENESS. Every topic the ShowText dispatcher serves, and every verb
//     the SystemAction handler serves, has an entry — enumerated out of
//     production source in both directions, so a new topic or verb reds the
//     suite instead of silently going unmapped.
//
// What no test here can prove is that the entry is the RIGHT command:
// `chassis-cluster-status` mapped to `show system uptime` would pass every
// check in this package. ATTRIBUTION IS A REVIEW RESPONSIBILITY, and that is
// a measured conclusion rather than an excuse:
//
//   - DERIVING the command from the topic name does not work. `show ` +
//     topic-with-dashes-as-spaces reproduces only a minority of these entries;
//     the rest drop intermediate hierarchy (`address-book` is
//     `show security address-book`, `alarms` is `show system alarms`,
//     `tunnels` is `show interfaces tunnel`). The exemption list would be the
//     majority of the table, which is not a derivation.
//   - The SERVER's handler name carries no independent signal either: it is
//     camelCase(topic) almost everywhere, so it restates the topic and agrees
//     with it BY CONSTRUCTION.
//
// The only sound attribution source is cmd/cli, which is where the topic is
// chosen — and it is not mechanically walkable (computed topic strings, nested
// switches). Making the client mapping declarative is tracked in #8058; a
// cross-check becomes a table comparison rather than an AST walk once it is.
// Until then these entries were transcribed by READING cmd/cli's dispatch
// (show.go, show_security.go, show_system.go, show_nat.go, show_services.go,
// show_interfaces.go, show_protocols.go, show_flow.go, main.go, clear.go,
// request.go) and are re-checkable only the same way.
//
// ── ARGUMENT-FREE ENTRIES, AND THE GAP THAT CREATES ──────────────────────
//
// Every value is the canonical command with NO operator arguments. Where
// several spellings reach one topic and differ only by arguments, the entry is
// the argument-free one: `show interfaces detail` for `interfaces-detail`, not
// `show interfaces <name> detail`. Where the topic itself is parameter-packed
// (a key ending in ':' — `route-table:<name>`, `screen-statistics:<zone>`,
// `test-policy:from=...`), the entry is the command PREFIX that precedes the
// parameter.
//
// NAMED GAP, not a silent one. pkg/cli's cut-3 gate matches a deny regex
// against the FULL canonicalized line including its arguments and its output
// pipe (evaluateCommandRegex). These strings have neither. So a regex written
// against ARGUMENT text — `deny-commands "show route table secret-vrf"` — matches
// on the box and does NOT match the remote RPC, which under the
// allow-over-deny model of #7172 is an under-deny, i.e. fail-OPEN for that
// class of regex. A regex written against the command PATH — the shape the
// feature is for, and the shape Junos' own examples use — matches identically
// on both surfaces because matching is partial rather than anchored.
//
// Closing it needs a per-topic decoder turning `route-table:secret-vrf` back
// into `show route table secret-vrf`, i.e. 129 bespoke inverse functions, each
// one a new place the remote string can disagree with the on-box string. That
// is a worse trade than the gap, and it is recorded here rather than
// rediscovered.
//
// These tables are INERT: nothing reads them until 5b wires them into
// authorizeRPC.

// showTextTopicCommand maps a ShowText topic to the canonical operational
// command that emits it.
//
// A key ending in ':' is the PREFIX form of a parameter-packed topic and is
// spelled exactly as showTextViewTopics / showTextElevatedTopics spell it, so
// whatever rule 5b uses to price a topic finds a command for the same key.
// The key set is pinned to the dispatcher's own literals in both directions by
// TestEveryShowTextTopicHasACanonicalCommand7172.
var showTextTopicCommand = map[string]string{
	// `show security ...`
	"address-book":     "show security address-book",
	"alg":              "show security alg",
	"applications":     "show security applications",
	"dynamic-address":  "show security dynamic-address",
	"ike":              "show security ike",
	"ipsec-statistics": "show security ipsec statistics",
	"security-alarms":  "show security alarms",
	// `detail` is a keyword child, so this is a longer real command rather
	// than the same path with an argument.
	"security-alarms-detail": "show security alarms detail",
	"security-log":           "show security log",
	"zones-detail":           "show security zones detail",
	"wireguard":              "show security wireguard",
	"wireguard-detail":       "show security wireguard detail",
	"wireguard-public-key":   "show security wireguard public-key",

	// `show security flow ...`. The bare `show security flow` renders the
	// configured timeouts, which is why the topic is named for the render and
	// the command is not.
	"flow-timeouts":        "show security flow",
	"flow-statistics":      "show security flow statistics",
	"flow-traceoptions":    "show security flow traceoptions",
	"sessions-top:bytes":   "show security flow session sort-by bytes",
	"sessions-top:packets": "show security flow session sort-by packets",

	// `show security policies ...`. The from-zone/to-zone selectors travel in
	// the request's FILTER field, not the topic, so these paths are complete.
	"policies-detail":    "show security policies detail",
	"policies-hit-count": "show security policies hit-count",

	// `show security screen ...`. The two ids-option topics differ by a
	// `detail` keyword that follows the option NAME, so the common
	// argument-free prefix is the same for both.
	"screen":                    "show security screen",
	"screen-ids-option:":        "show security screen ids-option",
	"screen-ids-option-detail:": "show security screen ids-option",
	"screen-statistics-all":     "show security screen statistics",
	"screen-statistics:":        "show security screen statistics zone",

	// `show security nat ...`
	"nat-static":             "show security nat static",
	"nat-nptv6":              "show security nat nptv6",
	"nat64":                  "show security nat nat64",
	"nat-source-rule-detail": "show security nat source rule detail",
	"nat-dest-rule-detail":   "show security nat destination rule detail",
	"persistent-nat":         "show security nat source persistent-nat-table",
	"persistent-nat-detail":  "show security nat source persistent-nat-table detail",

	// `show chassis ...`
	"chassis":                       "show chassis",
	"chassis-environment":           "show chassis environment",
	"chassis-forwarding":            "show chassis forwarding",
	"chassis-hardware":              "show chassis hardware",
	"chassis-device-map":            "show chassis device-map",
	"chassis-device-map-candidates": "show chassis device-map candidates",

	// `show chassis cluster ...`
	"chassis-cluster":                          "show chassis cluster",
	"chassis-cluster-status":                   "show chassis cluster status",
	"chassis-cluster-interfaces":               "show chassis cluster interfaces",
	"chassis-cluster-information":              "show chassis cluster information",
	"chassis-cluster-statistics":               "show chassis cluster statistics",
	"chassis-cluster-control-plane-statistics": "show chassis cluster control-plane statistics",
	"chassis-cluster-data-plane-statistics":    "show chassis cluster data-plane statistics",
	"chassis-cluster-data-plane-interfaces":    "show chassis cluster data-plane interfaces",
	"chassis-cluster-data-plane-fairness":      "show chassis cluster data-plane fairness",
	"chassis-cluster-data-plane-flows":         "show chassis cluster data-plane flows",
	"chassis-cluster-fabric-statistics":        "show chassis cluster fabric statistics",
	"chassis-cluster-ip-monitoring-status":     "show chassis cluster ip-monitoring status",

	// `show class-of-service ...`. The bare `class-of-service` topic is the
	// unfiltered `interface` view, NOT the umbrella command — cmd/cli emits it
	// only from `case "interface"`.
	"class-of-service":     "show class-of-service interface",
	"class-of-service:":    "show class-of-service interface",
	"cos-classifier":       "show class-of-service classifier",
	"cos-classifier:":      "show class-of-service classifier",
	"cos-rewrite-rule":     "show class-of-service rewrite-rule",
	"cos-rewrite-rule:":    "show class-of-service rewrite-rule",
	"cos-scheduler-map":    "show class-of-service scheduler-map",
	"cos-scheduler-map:":   "show class-of-service scheduler-map",
	"cos-forwarding-class": "show class-of-service forwarding-class",

	// `show system ...`
	"alarms":              "show system alarms",
	"backup-router":       "show system backup-router",
	"bootstrap-import":    "show system bootstrap-import",
	"buffers":             "show system buffers",
	"buffers-detail":      "show system buffers detail",
	"commit-history":      "show system commit history",
	"core-dumps":          "show system core-dumps",
	"internet-options":    "show system internet-options",
	"kernel-upgrade":      "show system kernel-upgrade",
	"login":               "show system login",
	"ntp":                 "show system ntp",
	"root-authentication": "show system root-authentication",
	"storage":             "show system storage",
	"system-services":     "show system services",
	"system-syslog":       "show system syslog",

	// `show interfaces ...`. `tunnels` is the odd one: the command keyword is
	// singular (`tunnel`), the topic is plural.
	"interfaces-detail":     "show interfaces detail",
	"interfaces-extensive":  "show interfaces extensive",
	"interfaces-statistics": "show interfaces statistics",
	"interfaces-queue":      "show interfaces queue",
	"interfaces-queue:":     "show interfaces queue",
	"tunnels":               "show interfaces tunnel",

	// `show route ...`. `route-all` is the bare `show route`; `route-prefix:`
	// is the same command with a destination in a value slot, so it resolves
	// to the same argument-free path.
	"route-all":       "show route",
	"route-prefix:":   "show route",
	"route-detail":    "show route detail",
	"route-instance":  "show route instance",
	"route-protocol:": "show route protocol",
	"route-summary":   "show route summary",
	"route-table:":    "show route table",
	"route-terse":     "show route terse",

	// `show firewall ...`. `firewall-effective-filter:` is
	// `show firewall filter <name> effective`, whose argument-free prefix stops
	// at the filter name — the same prefix as `firewall-filter:`.
	"firewall":                   "show firewall",
	"firewall-effective":         "show firewall effective",
	"firewall-effective:":        "show firewall effective",
	"firewall-filter:":           "show firewall filter",
	"firewall-effective-filter:": "show firewall filter",

	// `show services ...`
	"rpm":                               "show services rpm",
	"services-dynamic-dns":              "show services dynamic-dns",
	"services-dynamic-dns-detail":       "show services dynamic-dns detail",
	"services-ip-monitoring-status":     "show services ip-monitoring status",
	"application-identification-status": "show services application-identification status",

	// `show dhcp-server ...` / `show dhcp-relay`
	"dhcp-relay":                     "show dhcp-relay",
	"dhcp-server":                    "show dhcp-server",
	"dhcp-server-detail":             "show dhcp-server detail",
	"dhcp-server-dynamic-dns":        "show dhcp-server dynamic-dns",
	"dhcp-server-dynamic-dns-detail": "show dhcp-server dynamic-dns detail",

	// Top-level `show ...` singletons.
	"bfd-peers":                         "show protocols bfd peers",
	"event-options":                     "show event-options",
	"flow-monitoring":                   "show flow-monitoring",
	"flow-monitoring-statistics":        "show flow-monitoring statistics",
	"forwarding-options":                "show forwarding-options",
	"forwarding-options-port-mirroring": "show forwarding-options port-mirroring",
	"ipv6-router-advertisement":         "show ipv6 router-advertisement",
	"lldp":                              "show lldp",
	"lldp-neighbors":                    "show lldp neighbors",
	"log":                               "show log",
	"log:":                              "show log",
	"monitor-security-flow":             "show monitor security flow",
	"policy-options":                    "show policy-options",
	"route-map":                         "show route-map",
	"routing-instances":                 "show routing-instances",
	"routing-instances-detail":          "show routing-instances detail",
	"routing-options":                   "show routing-options",
	"schedulers":                        "show schedulers",
	"snmp":                              "show snmp",
	"snmp-v3":                           "show snmp v3",
	"task":                              "show task",
	"version":                           "show version",
	"vlans":                             "show vlans",

	// The `test ...` family. These are the three topics that are NOT a `show`,
	// which is the same distinction showTextElevatedTopics prices at
	// PermControl — and getting it wrong there is how a read-only class briefly
	// held policy reconnaissance (#5278). The topic name is not the command:
	// `test-zone:` is `test security-zone`.
	"test-policy:":  "test policy",
	"test-routing:": "test routing",
	"test-zone:":    "test security-zone",
}

// systemActionVerbCommand maps a SystemAction verb to the canonical operational
// command that sends it.
//
// The verb is NOT the command and cannot be derived from it: `clear-firewall-
// counters` is sent only by `clear firewall all`, `clear-nat-counters` by
// `clear security nat statistics`, and `clear-policy-counters` by
// `clear security policies hit-count`. Three different `clear` subtrees, three
// verb spellings that share a naming convention with none of them.
//
// PREFIX-FORM verbs are absent on purpose and cannot be listed: the handler's
// default branch parses `cluster-failover*` (#5810) and the `userspace-*`
// dataplane control forms out of a packed string, so they have no case label to
// enumerate and no fixed spelling to key. systemActionPermission already
// charges them the destructive floor; 5b must treat a verb with no entry the
// way it treats an unmapped method rather than assuming this table is total
// over what the handler accepts.
//
// The key set is pinned to the handler's own `switch req.Action` in both
// directions by TestEverySystemActionVerbHasACanonicalCommand7172.
var systemActionVerbCommand = map[string]string{
	// Destructive maintenance — `request system ...`.
	"reboot":             "request system reboot",
	"halt":               "request system halt",
	"power-off":          "request system power-off",
	"zeroize":            "request system zeroize",
	"in-service-upgrade": "request system software in-service-upgrade",

	// The `clear ...` family.
	"clear-config-lock":           "clear system config-lock",
	"clear-arp":                   "clear arp",
	"clear-interfaces-statistics": "clear interfaces statistics",
	"clear-ipv6-neighbors":        "clear ipv6 neighbors",
	"clear-policy-counters":       "clear security policies hit-count",
	"clear-firewall-counters":     "clear firewall all",
	"clear-nat-counters":          "clear security nat statistics",
	"clear-persistent-nat":        "clear security nat source persistent-nat-table",

	// The non-maintenance `request ...` family.
	"ospf-clear":         "request protocols ospf clear",
	"bgp-clear":          "request protocols bgp clear",
	"ipsec-sa-clear":     "request security ipsec sa clear",
	"dhcp-renew":         "request dhcp renew",
	"dynamic-dns-update": "request system dynamic-dns update",
	"dynamic-dns-check":  "request system dynamic-dns check",
}
