package config

import "fmt"

// Shared "will this flow collector actually receive records?" predicate.
//
// #6565 row 11 / #7422: `show security flow monitoring` and `show
// forwarding-options` render every configured `flow-server` straight from
// config, so a collector nothing can export to prints as an active export
// target. Port 0 is the worst shape: the CLI suppresses the `:0` suffix
// entirely and prints `Collector: 10.0.0.1`, which is indistinguishable from a
// healthy collector on a default port.
//
// The fix is the same one nat_exclusion_reason.go argues for and NOT an
// applied-set readback. The verdict is a deterministic function of the
// committed config, reached identically by BOTH consumers of a flow-server:
//
//   - buildFlowExportSnapshot (pkg/dataplane/userspace/flow.go) skips the
//     collector — CollectorPort is a Rust u16 on the wire (#1977);
//   - pkg/flowexport, which actually formats and sends the records (#2130),
//     cannot dial it: collectInstanceVersionCollectors omits the port from
//     CollectorConfig.Address when Port <= 0, and net.Dial("udp", "10.0.0.1")
//     fails with "missing port in address" (an out-of-range port fails the
//     same call with "invalid port"). dialCollectors treats that as fatal for
//     the WHOLE collector group, so the collector receives nothing whichever
//     path is consulted.
//
// What the renderers were missing is the PREDICATE, not a data path.
//
// Unlike the NAT and CoS families this one is NOT a lenient-path-only
// backstop. There is no strict commit gate on the flow-server port
// (validateSamplingTemplateRefsStrict checks template references only), so a
// plain `set forwarding-options sampling instance i1 family inet output
// flow-server 10.0.0.1` — no `port` — COMMITS CLEANLY and lands in the active
// config with Port 0. That is the ordinary way to reach this state.
//
// The reason strings are operator-facing and are rendered verbatim, so they
// are part of the contract.

// FlowServerExcludedReason reports why a configured flow-server (collector)
// receives no flow records, or "" when it is installed.
//
// Callers (they must not drift — see the file header):
//
//  1. buildFlowExportSnapshot (pkg/dataplane/userspace/flow.go) skips the
//     collector, and
//  2. cli.showFlowMonitoring, cli.showForwardingOptions and
//     grpcapi.Server.showForwardingOptions annotate it as not installed.
//
// The order of the checks mirrors the builder branch-for-branch: a nil or
// address-less server first (nothing to export to), then the port-0 "absent"
// sentinel, then a port outside the UDP range. Port 0 and an out-of-range port
// report DIFFERENT reasons on purpose — the fix for one is to add a `port` and
// for the other to correct it.
func FlowServerExcludedReason(fs *FlowServer) string {
	if fs == nil || fs.Address == "" {
		return "no collector address configured"
	}
	if fs.Port == 0 {
		return "no `port` configured — the collector is not installed and receives no flow records"
	}
	if fs.Port < 0 || fs.Port > 65535 {
		return fmt.Sprintf("collector port %d is outside the UDP port range 1-65535", fs.Port)
	}
	return ""
}
