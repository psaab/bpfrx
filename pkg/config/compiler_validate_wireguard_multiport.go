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
	// THE ASYMMETRY IS THE POINT, and a previous edit of this file denied it.
	//
	// This comment used to say that the unsteered tunnel is "not uniquely
	// unadjudicated" because "NO WireGuard tunnel's decapsulated plaintext is
	// zone-adjudicated, steered or not", citing the #5618 advisory as authority.
	// That is false at HEAD, and the sentence built on it went out to operators.
	//
	// #8274 step 3 changed exactly this. The shim no longer treats a WireGuard
	// TRANSPORT-DATA record for the steered listener as local delivery; the
	// worker claims it and decaps it INSIDE the pipeline. Its own call site
	// (poll_descriptor/mod.rs) states the result: "Everything downstream then
	// sees the INNER packet — flow parse, screen, session, policy, NAT, forward
	// build ... adjudicated under the tunnel's logical ingress zone instead of
	// being written to the wgN TUN for the kernel to forward with no zone policy
	// at all."
	//
	// So the two ports differ in the security property, not merely in which code
	// path serves them:
	//
	//	steered port    transport data -> worker decap -> zone/session/policy
	//	unsteered port  transport data -> kernel -> control thread -> wgN TUN
	//	                                -> kernel forwards, no zone policy
	//
	// `wg_worker_claim` requires `parsed.flow_dst_port == ctrl.wg_listen_port`,
	// a single scalar, so a second port never matches and falls to the generic
	// local-destination arm.
	//
	// The #5618 advisory this used to defer to describes the PRE-#8274 world
	// ("the XDP shim deliberately steers inbound UDP on the configured
	// WireGuard listen port to the KERNEL"), and it fires for every WireGuard
	// tunnel including a single steered one. That is tracked separately; this
	// file must not repeat its claim, because here the claim erases the one
	// difference an operator needs to see.
	return []string{fmt.Sprintf(
		"wireguard: %d distinct listen-ports are configured, but the dataplane "+
			"steers inbound WireGuard transport for only ONE of them. "+
			"listen-port %d (%s) IS steered onto the AF_XDP WireGuard path. "+
			"%s %s %s NOT steered: %s still receives inbound transport (the "+
			"host-inbound filter admits every configured listen-port and each "+
			"tunnel binds its own socket), but it is served by the KERNEL path "+
			"rather than the dataplane's. THE SECURITY POSTURE OF THE TWO IS "+
			"NOT THE SAME: the steered port's decapsulated plaintext is "+
			"adjudicated under the tunnel's ingress zone (screen, session, "+
			"policy, NAT), while an unsteered port's plaintext is written to "+
			"its wgN TUN and forwarded by the KERNEL with no zone policy, no "+
			"session and no counters — an authenticated peer on %s reaches "+
			"whatever the kernel routes to, subject only to that peer's "+
			"allowed-ips (a source-ownership check, not a destination policy). "+
			"Only one WireGuard listen-port can be steered until multi-port "+
			"steering lands (#1434 Increment 2, deferred).",
		len(strandedPorts)+1, steered.port, steered.name,
		strandedNoun, strings.Join(stranded, ", "), strandedVerb, strandedSubject,
		strandedSubject)}
}
