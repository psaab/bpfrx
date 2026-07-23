// Package sysservices holds the shared, EFFECTIVE management-listener state
// rendered by `show system services`. It is a LEAF package (imports only the
// standard library) so the daemon (which owns the listener lifecycle), the
// local interactive CLI (pkg/cli), and the remote gRPC renderer (pkg/grpcapi)
// can all depend on it without an import cycle.
//
// The point of this package (#6385): both `show system services` renderers —
// the local CLI (pkg/cli/cli_show_system.go) AND the remote gRPC renderer
// (pkg/grpcapi/server_show_system.go, the path the remote `cli` binary reaches)
// — read ONE daemon-owned snapshot of the addresses the listeners ACTUALLY
// bound, not the requested/config-declared values. Before #6385 both renderers
// hardcoded `127.0.0.1:50051 (always on)` / `127.0.0.1:8080 (always on)`, so a
// relocated, loopback-clamped (#5035/#5127), or disabled listener was reported
// wrong, and a dropped local-only patch (the #6384 A10-b2-F5 attempt) left the
// local and remote surfaces disagreeing. Sourcing both from Lines() guarantees
// they can never diverge again.
package sysservices

import "fmt"

// Listeners is the EFFECTIVE (post-clamp, post-bind) address of each management
// listener `show system services` reports. The daemon builds it after the
// listeners bind (Daemon.effectiveListeners); a nil snapshot source in a
// renderer means the CLI was spawned outside a running daemon (offline
// recovery / unit test), where there is no live bind to read.
type Listeners struct {
	// GRPC is the effective gRPC bind address AFTER the #5035 loopback clamp
	// and net.Listen (the address the listener is actually serving). It is
	// empty only in the brief window before the primary gRPC listener has
	// bound; the daemon falls back to the requested --grpc-addr there so the
	// field is effectively always populated at render time.
	GRPC string
	// HTTP is the effective HTTP REST bind address. An EMPTY value means the
	// REST listener is DISABLED — the operator passed an empty --api-addr, so
	// the daemon never started it (Daemon.Run guards startHTTPServer on a
	// non-empty APIAddr). Rendered as "disabled" rather than a fixed
	// `127.0.0.1:8080 (always on)`.
	HTTP string
}

// Lines renders the gRPC / HTTP REST listener rows for `show system services`,
// in render order, driven by the effective addresses. It is the SINGLE
// formatter both the local CLI and remote gRPC renderers call, so the two
// surfaces are byte-identical by construction. An empty address renders
// "disabled".
func (l Listeners) Lines() []string {
	return []string{
		fmt.Sprintf("  gRPC:           %s", orDisabled(l.GRPC)),
		fmt.Sprintf("  HTTP REST:      %s", orDisabled(l.HTTP)),
	}
}

func orDisabled(addr string) string {
	if addr == "" {
		return "disabled"
	}
	return addr
}
