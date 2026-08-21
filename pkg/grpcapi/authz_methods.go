package grpcapi

import (
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// authz_methods.go is the method -> required-permission table the #5278
// interceptor consults, plus the SystemAction verb table underneath it.
//
// # Where the numbers come from
//
// Every entry mirrors what pkg/cli/permissions.go requiredPermission charges
// for the COMMAND that reaches the RPC, so the server and the CLI cannot
// disagree about what an action costs:
//
//	show / ping / traceroute / monitor  -> PermView
//	clear                               -> PermClear
//	request / test                      -> PermControl
//	configure                           -> PermConfig
//	request system {reboot,halt,power-off,zeroize},
//	request system software in-service-upgrade,
//	request chassis cluster failover    -> PermMaint
//
// The mapping is command-shaped rather than verb-shaped on purpose. `ShowConfig`
// is PermView because `show configuration` is a `show`, not because reading
// config feels safe: config-viewer and read-only are exactly the classes Junos
// gives that reach, and #4051/#4099 already redact secrets on this render path
// unconditionally. `CommitCheck` is PermConfig because it reads a candidate a
// caller must already have held the configure permission to stage.
//
// # Fail closed
//
// A method absent from this table is charged unmappedMethodPermission, which no
// class but super-user holds, and the miss is logged at Error. That is the
// weaker half of the guarantee; the strong half is
// TestEveryServiceMethodHasAPermission_5278, which enumerates the generated
// SERVICE DESCRIPTOR and fails the build in BOTH directions — a new RPC with no
// entry, and a stale entry naming no RPC. Enumerating the descriptor rather
// than a hand-written list is the point: a guard that compares literals a human
// typed against a count the same human typed cannot fire (the shape caught in
// pkg/dataplane/userspace/ingress_exclusions.go).

// unmappedMethodPermission is what an unmapped method costs: PermAll, which
// only `super-user` holds.
//
// It is not a blanket denial, and the difference is deliberate. Denying uid 0
// would be theater under the shipped pkg/authz contract — root owns the config
// DB on disk and the daemon process — and it would turn a missing table row
// into a totally dead RPC rather than a restricted one. Every class the issue
// is about (read-only, operator, config-viewer, a custom class, an account
// outside the login model) is denied.
const unmappedMethodPermission = config.PermAll

// methodPermissions prices every RPC on BpfrxService by its SHORT method name.
// The key set is pinned to the generated descriptor in both directions by
// TestEveryServiceMethodHasAPermission_5278.
var methodPermissions = map[string]config.LoginClassPermission{
	// --- Config lifecycle: `configure` and everything inside it. -----------
	"EnterConfigure":      config.PermConfig,
	"ExitConfigure":       config.PermConfig,
	"GetConfigModeStatus": config.PermConfig,
	"Set":                 config.PermConfig,
	"Delete":              config.PermConfig,
	"Load":                config.PermConfig,
	"Commit":              config.PermConfig,
	"CommitCheck":         config.PermConfig,
	"CommitConfirmed":     config.PermConfig,
	"ConfirmCommit":       config.PermConfig,
	"Rollback":            config.PermConfig,

	// Config RENDER paths. `show configuration`, `show | compare`, `show system
	// rollback` and `show system commit` are all `show` in the CLI's table, and
	// the raw-AST render redacts secrets unconditionally (#4051/#4099).
	"ShowConfig":   config.PermView,
	"ShowCompare":  config.PermView,
	"ShowRollback": config.PermView,
	"ListHistory":  config.PermView,

	// --- Operational show RPCs: the `show` family. -------------------------
	"GetStatus":                config.PermView,
	"GetGlobalStats":           config.PermView,
	"GetZones":                 config.PermView,
	"GetPolicies":              config.PermView,
	"GetSessions":              config.PermView,
	"GetSessionSummary":        config.PermView,
	"GetZonePairSummary":       config.PermView,
	"GetNATSource":             config.PermView,
	"GetNATDestination":        config.PermView,
	"GetScreen":                config.PermView,
	"GetEvents":                config.PermView,
	"GetInterfaces":            config.PermView,
	"ShowInterfacesDetail":     config.PermView,
	"GetDHCPLeases":            config.PermView,
	"GetDHCPClientIdentifiers": config.PermView,
	"GetRoutes":                config.PermView,
	"GetOSPFStatus":            config.PermView,
	"GetBGPStatus":             config.PermView,
	"GetRIPStatus":             config.PermView,
	"GetISISStatus":            config.PermView,
	"GetIPsecSA":               config.PermView,
	"GetNATPoolStats":          config.PermView,
	"GetNATRuleStats":          config.PermView,
	"GetNATDeterministic":      config.PermView,
	"GetVRRPStatus":            config.PermView,
	"MatchPolicies":            config.PermView, // `show security match-policies`
	"GetSystemInfo":            config.PermView,
	"ShowText":                 config.PermView, // every topic is a `show ...`

	// --- Diagnostics: `ping` / `traceroute` are view-tier verbs on Junos and
	// in the CLI's own table, despite being state-changing-looking streams.
	"Ping":       config.PermView,
	"Traceroute": config.PermView,

	// --- Monitor streams: the `monitor` family is view-tier. The two verbs the
	// CLI elevates to PermControl — `monitor traffic` (a root tcpdump, #4067)
	// and `monitor security flow file|start` (a root-privileged on-disk trace
	// write, #5038) — are NOT reachable through either of these RPCs: neither
	// spawns a capture nor opens a trace file. MonitorPacketDrop is the
	// terminal-only drop stream and MonitorInterface is interface statistics,
	// both of which the CLI itself gates at PermView.
	"MonitorPacketDrop": config.PermView,
	"MonitorInterface":  config.PermView,

	// --- Mutations: the `clear` family. ------------------------------------
	"ClearSessions":             config.PermClear,
	"ClearCounters":             config.PermClear,
	"ClearDHCPClientIdentifier": config.PermClear,

	// --- Tab completion. Completion answers "what could I type here", which is
	// a read of the command tree and (for config-mode value slots) of config
	// the same class may already `show`. View-tier, so a read-only operator
	// keeps a usable CLI; the `unauthorized` class, which holds nothing, loses
	// it along with everything else.
	"Complete": config.PermView,

	// --- The multiplexed system-action verb. The entry here is the FLOOR for a
	// request the interceptor cannot inspect; a decoded request is priced by
	// systemActionPermission below. See methodPermission.
	"SystemAction": config.PermMaint,
}

// systemActionPermissions prices each SystemAction verb the way the CLI prices
// the command that sends it.
//
// SystemAction is one RPC multiplexing three very different permission tiers,
// and folding it up to its destructive floor — which is what pkg/api's REST
// gate must do, because that middleware deliberately never decodes a request
// body — would take `clear arp`, `clear system config-lock`, `request protocols
// bgp clear` and `request dhcp renew` away from the `operator` class that holds
// them today. A unary gRPC interceptor is handed the DECODED request, so the
// verb is available without buffering anything the caller controls.
//
// The key set is pinned to the handler's own switch by
// TestEverySystemActionVerbHasAPermission_5278, which reads the case labels out
// of server_diag_system_action.go rather than from a list typed here.
var systemActionPermissions = map[string]config.LoginClassPermission{
	// Destructive maintenance. `operator` deliberately lacks PermMaint on
	// Junos and here (#4108 F21).
	"reboot":             config.PermMaint,
	"halt":               config.PermMaint,
	"power-off":          config.PermMaint,
	"zeroize":            config.PermMaint,
	"in-service-upgrade": config.PermMaint, // drains this node to secondary (#4859)

	// The `clear ...` family: `clear system config-lock`, `clear arp`,
	// `clear interfaces statistics`, `clear ipv6 neighbors`, and the counter
	// clears — all reached from cmd/cli/clear.go, i.e. parts[0] == "clear".
	"clear-config-lock":           config.PermClear,
	"clear-arp":                   config.PermClear,
	"clear-interfaces-statistics": config.PermClear,
	"clear-ipv6-neighbors":        config.PermClear,
	"clear-policy-counters":       config.PermClear,
	"clear-firewall-counters":     config.PermClear,
	"clear-nat-counters":          config.PermClear,
	"clear-persistent-nat":        config.PermClear,

	// The `request ...` family that is not maintenance: these are sent from
	// cmd/cli/request.go (`request protocols ospf|bgp clear`, `request security
	// ipsec sa clear`, `request dhcp renew`, `request system dynamic-dns
	// update|check`), i.e. parts[0] == "request" without a maintenance verb.
	"ospf-clear":         config.PermControl,
	"bgp-clear":          config.PermControl,
	"ipsec-sa-clear":     config.PermControl,
	"dhcp-renew":         config.PermControl,
	"dynamic-dns-update": config.PermControl,
	"dynamic-dns-check":  config.PermControl,
}

// systemActionPermission prices one SystemAction verb.
//
// An action absent from the table costs PermMaint. That covers the PREFIX-form
// verbs the handler's default branch parses — `cluster-failover*` (#5810) and
// the `userspace-*` dataplane control forms — and any verb added in future.
//
// For cluster-failover that is exactly right: `request chassis cluster failover`
// is PermMaint in the CLI too. For the `userspace-*` forms it OVER-restricts by
// one tier in one direction, and the trade is stated rather than hidden: the
// CLI charges PermMaint for the destructive halves (`disarm`, `unregister`,
// `inject-packet`) and PermControl for the restorative ones (`arm`,
// `register`), so an `operator` loses the ability to RE-ARM a binding over
// gRPC. Recovering that one tier would mean re-implementing three argument
// parsers (ParseForwardingCommand / ParseQueueCommand / ParseBindingCommand)
// inside the authorization gate, where a parse that disagreed with the
// handler's would be a bypass rather than a cosmetic bug. Over-restricting a
// deep dataplane-diagnostic verb to super-user is the cheaper error.
func systemActionPermission(action string) config.LoginClassPermission {
	if p, ok := systemActionPermissions[action]; ok {
		return p
	}
	return config.PermMaint
}

// methodPermission returns the permission a full gRPC method requires, and
// whether the method was found in the table at all.
//
// req is the DECODED request for a unary call and nil for a stream. It is read
// for exactly one method: SystemAction, whose verb selects the tier. A
// SystemAction whose request is missing or of an unexpected type falls back to
// the methodPermissions entry (PermMaint, the destructive floor) — the same
// answer pkg/api's body-agnostic gate gives, reached only when the verb cannot
// be seen.
func methodPermission(fullMethod string, req any) (config.LoginClassPermission, bool) {
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return unmappedMethodPermission, false
	}
	perm, mapped := methodPermissions[method]
	if !mapped {
		return unmappedMethodPermission, false
	}
	if method == systemActionMethodName {
		if sa, isAction := req.(*pb.SystemActionRequest); isAction && sa != nil {
			return systemActionPermission(sa.GetAction()), true
		}
	}
	return perm, true
}

// systemActionMethodName is the one method whose permission depends on its
// request. Named rather than spelled inline so the two places that care about
// it (methodPermission and the verb-table completeness test) cannot drift.
const systemActionMethodName = "SystemAction"
