// Package diagcmd holds the shared argv-construction logic for the
// ping/traceroute diagnostics that the local CLI, the REST API, and the
// gRPC API all expose. Keeping the VRF-device normalization and the
// option-confusion hardening in one place prevents the three control
// surfaces from drifting apart: before this package existed the local
// CLI unconditionally prepended "vrf-" while REST and gRPC guarded
// against a name that already started with "vrf-", so the same
// `routing-instance vrf-red` produced a non-existent `vrf-vrf-red`
// device on the CLI but the correct `vrf-red` device on the APIs
// (#2143). The "--" end-of-options separator (#2084) likewise had to be
// applied three times; it now lives here too.
package diagcmd

import "strings"

// vrfPrefix is the prefix the daemon uses for the kernel VRF master
// device that backs a Junos routing-instance (a routing-instance named
// "red" is realized as the VRF device "vrf-red"). See pkg/cli/apply.go,
// where the daemon creates the device with this exact prefix.
const vrfPrefix = "vrf-"

// VRFDeviceName maps a Junos routing-instance name to the kernel VRF
// master device name the daemon created for it, applying the "vrf-"
// prefix exactly once. A name that the operator already typed with the
// prefix (e.g. "vrf-red") is returned unchanged; a bare name (e.g.
// "red") gets the prefix added. An empty name yields an empty result so
// callers can branch on "no routing-instance requested".
//
// This is the single source of truth for the prefix: applying it again
// at the call site would re-introduce the #2143 double-prefix bug.
func VRFDeviceName(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, vrfPrefix) {
		return name
	}
	return vrfPrefix + name
}

// PingOptions carries the already-validated, already-clamped ping
// parameters the three control surfaces collect from their respective
// request shapes (CLI argv, REST JSON, gRPC protobuf). The builder owns
// argv layout only — validation and clamping stay with the callers.
type PingOptions struct {
	Target string
	// Count is the ICMP probe count passed to ping -c. Callers clamp it
	// before constructing the options.
	Count string
	// Source is an optional source address (ping -I); empty means omit.
	Source string
	// Size is an optional payload size (ping -s); empty means omit.
	Size string
	// RoutingInstance is the Junos routing-instance name (NOT the
	// vrf-prefixed device name); empty means the global/default table.
	RoutingInstance string
}

// PingArgv builds the full argv for a ping diagnostic. When a
// routing-instance is requested the command is wrapped in
// `ip vrf exec <device> ...` with the device name normalized by
// VRFDeviceName. The user-supplied target is placed after a "--"
// end-of-options separator so a "-"-prefixed target is treated as the
// destination operand rather than a ping flag (#2084).
func PingArgv(opts PingOptions) []string {
	var cmd []string
	if dev := VRFDeviceName(opts.RoutingInstance); dev != "" {
		cmd = append(cmd, "ip", "vrf", "exec", dev)
	}
	cmd = append(cmd, "ping", "-c", opts.Count)
	if opts.Source != "" {
		cmd = append(cmd, "-I", opts.Source)
	}
	if opts.Size != "" {
		cmd = append(cmd, "-s", opts.Size)
	}
	cmd = append(cmd, "--", opts.Target)
	return cmd
}

// TracerouteOptions carries the already-validated traceroute parameters
// the three control surfaces collect from their request shapes.
type TracerouteOptions struct {
	Target string
	// Source is an optional source address (traceroute -s); empty means
	// omit.
	Source string
	// RoutingInstance is the Junos routing-instance name (NOT the
	// vrf-prefixed device name); empty means the global/default table.
	RoutingInstance string
}

// TracerouteArgv builds the full argv for a traceroute diagnostic,
// mirroring PingArgv: VRF wrapping with single-application normalization
// and the "--" end-of-options separator before the target (#2084).
func TracerouteArgv(opts TracerouteOptions) []string {
	var cmd []string
	if dev := VRFDeviceName(opts.RoutingInstance); dev != "" {
		cmd = append(cmd, "ip", "vrf", "exec", dev)
	}
	cmd = append(cmd, "traceroute")
	if opts.Source != "" {
		cmd = append(cmd, "-s", opts.Source)
	}
	cmd = append(cmd, "--", opts.Target)
	return cmd
}
