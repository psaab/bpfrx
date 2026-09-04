package grpcapi

import "github.com/psaab/xpf/pkg/cmdtree"

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
// THE TABLE ITSELF MOVED TO pkg/cmdtree (#8058, showtext_topic.go) and this is
// a view onto it. It used to be transcribed here independently of the remote
// `cli` binary's command -> topic switches, and nothing made the two agree; a
// topic re-attributed on one side left this one pricing an authz decision
// against a command string no operator could type. Both surfaces now read the
// cmdtree table, so that divergence is unrepresentable rather than a bug to be
// caught by a mirrored test. Add or rename a topic THERE.
//
// Everything this file's checks assert about the table is unchanged and still
// asserted HERE, because they are properties of the SERVER's dispatcher rather
// than of the data: every value canonicalizes to itself (#8057), and the key
// set is pinned to server_show.go's own literals in both directions by
// TestEveryShowTextTopicHasACanonicalCommand7172.
//
// A key ending in ':' is the PREFIX form of a parameter-packed topic and is
// spelled exactly as showTextViewTopics / showTextElevatedTopics spell it, so
// whatever rule 5b uses to price a topic finds a command for the same key.
var showTextTopicCommand = cmdtree.ShowTextTopicCommands()

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
	"rescue-save":        "request system configuration rescue save",
	"rescue-delete":      "request system configuration rescue delete",
}
