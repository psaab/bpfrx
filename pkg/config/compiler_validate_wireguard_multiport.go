package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateWireguardSingleSteeredPort emits a commit WARNING (never a hard
// reject) when the configuration declares WireGuard tunnels on more than one
// distinct UDP listen port.
//
// Why this is a defect worth a commit-time signal: the AF_XDP shim's WG-RX
// steering gate is a SINGLE scalar. `UserspaceCtrl.wg_listen_port` holds one
// port, `wg_steer_to_kernel` (userspace-xdp/src/lib.rs) compares
// `pkt.flow_dst_port` against `ctrl.wg_listen_port & 0xffff`, and the Go side
// packs that scalar with `snapshotWgListenPort`
// (pkg/dataplane/userspace/maps_sync.go), which returns the FIRST
// mode=="wireguard" tunnel endpoint's port and ignores every later one. So a
// second WireGuard tunnel on a different listen port has its inbound transport
// UDP left unsteered: the kernel WG control socket never sees it, the tunnel
// never completes a handshake, and — before this gate — the config committed
// clean with ZERO operator signal. The tunnel is simply, permanently, silently
// down.
//
// A WARNING, not a reject. The configuration is legal, it is what an operator
// migrating a multi-tunnel WireGuard deployment would naturally author, and its
// FIRST tunnel works exactly as configured today. Rejecting would break a
// partially-working deployment to report a dataplane limitation, and would
// change commit acceptance for configs that commit clean at every released
// version. Generalizing the shim to steer a port SET is #1434 Increment 2 — a
// verifier-gated `userspace-xdp` edit with a documented v6-line-rate
// sensitivity that must clear the loss cluster before it can merge. Until it
// lands, the honest thing is to tell the operator exactly which tunnel is dead
// and why. The warning must therefore describe the CURRENT limitation and name
// the tracking issue; it must not promise the fix, nor rule it out.
//
// Ordering. The winner is computed from EmitTunnelEndpointNames — the same SSOT
// emitter the snapshot builder (buildTunnelEndpointSnapshots) drives — so
// "which port wins" here is derived from, not a second guess at, what the
// dataplane will program. EmitTunnelEndpointNames walks interfaces in sorted
// name order (units ascending), so the winner is stable across commits and
// identical on both HA nodes. One residual gap: the builder additionally
// intersects with the live InterfaceSnapshot rows, so if the winning tunnel's
// interface is absent at runtime the NEXT WG endpoint is programmed instead.
// Commit time cannot see that, so the warning names the config-order winner;
// either way the "more than one port is configured, only one is steered" claim
// holds, which is the part the operator must act on.
//
// A tunnel with WgListenPort == 0 is skipped: the strict WireGuard gate
// (validateOneWireguardTunnel, #3863) hard-rejects a zero/out-of-range
// listen-port at commit, so a zero here only arises on a tolerant load, and it
// contributes no steerable port either way.
func validateWireguardSingleSteeredPort(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	type wgEndpointRef struct {
		name string
		port uint16
	}
	refs := make([]wgEndpointRef, 0, 2)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel == nil || ep.Tunnel.Mode != "wireguard" || ep.Tunnel.WgListenPort == 0 {
			continue
		}
		refs = append(refs, wgEndpointRef{name: ep.Name, port: ep.Tunnel.WgListenPort})
	}
	if len(refs) < 2 {
		return nil
	}

	// The first emitted WG endpoint is the one whose port reaches the shim.
	steered := refs[0]
	strandedPorts := make([]uint16, 0, len(refs)-1)
	strandedTunnels := make(map[uint16][]string, len(refs)-1)
	for _, ref := range refs[1:] {
		if ref.port == steered.port {
			// Same port as the steered one: the one steering scalar already
			// covers it, so nothing is lost to THIS defect. (Two WG tunnels
			// sharing a port collide on the kernel UDP bind — bind_wg_socket
			// sets no SO_REUSEPORT — but that is a different failure and not
			// this gate's subject. This gate fires only on the distinct-port
			// condition the single steering scalar drops.)
			continue
		}
		if _, seen := strandedTunnels[ref.port]; !seen {
			strandedPorts = append(strandedPorts, ref.port)
		}
		strandedTunnels[ref.port] = append(strandedTunnels[ref.port], ref.name)
	}
	if len(strandedPorts) == 0 {
		return nil
	}
	sort.Slice(strandedPorts, func(i, j int) bool { return strandedPorts[i] < strandedPorts[j] })

	stranded := make([]string, 0, len(strandedPorts))
	for _, port := range strandedPorts {
		stranded = append(stranded, fmt.Sprintf("%d (%s)", port, strings.Join(strandedTunnels[port], ", ")))
	}
	strandedNoun, strandedVerb, strandedSubject := "listen-port", "is", "that tunnel"
	if len(strandedPorts) > 1 {
		strandedNoun, strandedVerb, strandedSubject = "listen-ports", "are", "those tunnels"
	}
	// #9016: this text previously said the unsteered tunnel was "dead while
	// appearing configured", that "no inbound WireGuard transport reaches" it
	// and that "no handshake ever completes". That is false, and falsely
	// reassuring: the host-inbound filter admits EVERY configured listen-port
	// (config.WireGuardListenPorts feeds emitHostInboundWireGuardAcceptNetlink,
	// the production netlink installer, not just the nft text renderer), and the
	// helper spawns a control thread with its own bound socket for every
	// wireguard endpoint. What the unsteered port does NOT get is the AF_XDP
	// WireGuard fast path: snapshotWgListenPort returns the FIRST wireguard
	// endpoint's port and the shim compares against that one scalar, so the port
	// is handled by the kernel path instead.
	//
	// An operator told a live tunnel is dead will leave it in place. The honest
	// statement is that it is unsteered, not that it is down.
	//
	// Deliberately NOT claimed here: that the unsteered tunnel's plaintext is
	// uniquely unadjudicated. It is not — NO WireGuard tunnel's decapsulated
	// plaintext is zone-adjudicated, steered or not, and the separate #5618
	// advisory says so for every tunnel in the config (with an acute variant for
	// one assigned a zone). Repeating it here would imply the steered tunnel is
	// adjudicated, which is the same class of false reassurance in the other
	// direction.
	return []string{fmt.Sprintf(
		"wireguard: %d distinct listen-ports are configured, but the dataplane "+
			"steers inbound WireGuard transport for only ONE of them. "+
			"listen-port %d (%s) IS steered onto the AF_XDP WireGuard path. "+
			"%s %s %s NOT steered: %s still receives inbound transport (the "+
			"host-inbound filter admits every configured listen-port and each "+
			"tunnel binds its own socket), but it is served by the KERNEL path "+
			"rather than the dataplane's, so it is not counted or handled there. "+
			"Only one WireGuard listen-port can be steered until multi-port "+
			"steering lands (#1434 Increment 2, deferred). Note this is about "+
			"STEERING only: no WireGuard tunnel's decapsulated plaintext is "+
			"zone-adjudicated today, steered or not — see the separate tunnel "+
			"plaintext advisory, which covers every tunnel in this config.",
		len(strandedPorts)+1, steered.port, steered.name,
		strandedNoun, strings.Join(stranded, ", "), strandedVerb, strandedSubject)}
}
