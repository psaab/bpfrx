package config

import (
	"fmt"
	"net"
	"sort"
)

// validateWireguardPeersStrict enforces the multi-peer WireGuard
// commit-time invariants (#1434) over every compiled WG tunnel
// (interface-level and per-unit). It returns warnings on the lenient
// path and a hard error on the strict path.
//
// The gates (all LOCKED by the plan review rounds,
// docs/research/1434-multitunnel-wg/plan.md §5.5/§5.6):
//
//   - Zero-peer = REJECT. A WG tunnel with no peer can never handshake;
//     xpf has no dynamic peer learning (peers are config-static).
//   - Duplicate peer pubkey = REJECT. The Rust engine reconcile only
//     debug_asserts on duplicates (release builds would mis-index the
//     AllowedIPs LPM and the peer slab); the Go control plane is the
//     named owner of the dup-reject contract (engine.rs).
//   - Malformed pubkey = REJECT. A WG static key is exactly 64 hex
//     chars (32-byte X25519). A bad key today fails silently at the
//     dataplane (hydrate_wg_identity drops the whole row).
//   - Malformed preshared-key = REJECT (when present). Same 64-hex
//     shape (#1434 B2).
//   - Mixed endpoint family = REJECT. One WG interface binds one kernel
//     UDP socket = one outer transport family. Peers that DECLARE an
//     endpoint must all agree on v4-vs-v6; a responder-only peer (no
//     endpoint) does not constrain the family.
//
// AllowedIPs broader/narrower overlap across peers is NOT rejected —
// valid WG configs overlap (a catch-all peer plus a more-specific peer),
// and the engine LPM resolves longest-prefix deterministically. An EXACT
// duplicate prefix (same network + length + family) on two different peers
// IS rejected, though: the cryptokey routing table is a prefix->peer map,
// so an exact tie has no longest-prefix winner — the engine's LPM lookup
// resolves it by stable-sort insertion order, silently blackholing the
// loser for that prefix (#2445). Reject it at commit so the operator's
// intent is never masked by an implementation-defined tie-break.
func validateWireguardPeersStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string

	// Deterministic iteration order so the first reported error is stable
	// across runs and both HA nodes report identically.
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)

	emit := func(label string, err error) error {
		if err == nil {
			return nil
		}
		if lenient {
			warnings = append(warnings, fmt.Sprintf("wireguard %s: %v", label, err))
			return nil
		}
		return fmt.Errorf("wireguard %s: %w", label, err)
	}

	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil && ifc.Tunnel.Mode == "wireguard" {
			label := tunnelLabel(ifName, -1, ifc.Tunnel)
			if err := emit(label, validateOneWireguardTunnel(ifc.Tunnel)); err != nil {
				return warnings, err
			}
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, n := range unitNums {
			unit := ifc.Units[n]
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.Mode != "wireguard" {
				continue
			}
			label := tunnelLabel(ifName, n, unit.Tunnel)
			if err := emit(label, validateOneWireguardTunnel(unit.Tunnel)); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}

// tunnelLabel renders an operator-facing identifier for a WG tunnel in
// an error message: the tunnel's own Name when set, else the
// interface[.unit] coordinates.
func tunnelLabel(ifName string, unit int, tc *TunnelConfig) string {
	if tc != nil && tc.Name != "" {
		return tc.Name
	}
	if unit >= 0 {
		return fmt.Sprintf("%s.%d", ifName, unit)
	}
	return ifName
}

// validateOneWireguardTunnel applies the per-tunnel WG peer gates to a
// single tunnel's WgPeers slice.
func validateOneWireguardTunnel(tc *TunnelConfig) error {
	if len(tc.WgPeers) == 0 {
		return fmt.Errorf("tunnel has no peer (a peerless WireGuard tunnel can never handshake; configure at least one `peer <public-key>`)")
	}
	seen := make(map[string]struct{}, len(tc.WgPeers))
	// Cryptokey routing table is a prefix->peer map; an exact-duplicate
	// prefix on two peers has no longest-prefix winner, so the engine LPM
	// resolves it by insertion order and silently strips the loser's
	// routing (#2445). Key by canonical masked CIDR (network address +
	// length + family) so host-bit and zero-compression spelling
	// differences (10.0.0.5/24 vs 10.0.0.0/24, ::1/64 vs ::/64) compare
	// equal; value is the owning peer's pubkey for the error message.
	prefixOwner := make(map[string]string)
	var endpointFamilyV6 *bool
	for i, p := range tc.WgPeers {
		if !isWireguardKeyHex(p.PublicKeyHex) {
			return fmt.Errorf("peer %d has an invalid public key (expected 64 hex chars / 32-byte X25519, got %q)", i, p.PublicKeyHex)
		}
		if _, dup := seen[p.PublicKeyHex]; dup {
			return fmt.Errorf("duplicate peer public key %q (each peer on a WireGuard tunnel must have a unique public key)", p.PublicKeyHex)
		}
		seen[p.PublicKeyHex] = struct{}{}

		if p.PresharedKeyHex != "" && !isWireguardKeyHex(string(p.PresharedKeyHex)) {
			return fmt.Errorf("peer %q has an invalid preshared key (expected 64 hex chars / 32 bytes)", p.PublicKeyHex)
		}

		if p.Endpoint != "" {
			v6, err := endpointIsV6(p.Endpoint)
			if err != nil {
				return fmt.Errorf("peer %q has an invalid endpoint %q: %w", p.PublicKeyHex, p.Endpoint, err)
			}
			if endpointFamilyV6 == nil {
				endpointFamilyV6 = &v6
			} else if *endpointFamilyV6 != v6 {
				return fmt.Errorf("peers declare endpoints of mixed address family; a WireGuard interface binds one UDP socket, so all endpoint-bearing peers must use the same outer family (IPv4 or IPv6)")
			}
		}

		for _, cidr := range p.AllowedIPs {
			canon := canonicalAllowedIPPrefix(cidr)
			if owner, dup := prefixOwner[canon]; dup && owner != p.PublicKeyHex {
				return fmt.Errorf("allowed-ips prefix %s is claimed by two peers (%q and %q); the cryptokey routing table maps a prefix to exactly one peer, so an exact-duplicate prefix has no longest-prefix winner and silently strips one peer's route — give each peer distinct allowed-ips", canon, owner, p.PublicKeyHex)
			}
			// First claimant wins the map entry; a same-peer repeat (the
			// engine dedups exact entries per peer) is harmless and not a
			// conflict.
			if _, exists := prefixOwner[canon]; !exists {
				prefixOwner[canon] = p.PublicKeyHex
			}
		}
	}
	return nil
}

// canonicalAllowedIPPrefix returns a comparison key for a WireGuard
// AllowedIPs prefix. A parseable CIDR is reduced to its canonical masked
// form (network address + prefix length) so two prefixes that denote the
// same cryptokey-routing entry compare equal regardless of host-bit
// spelling or IPv6 zero-compression (10.0.0.5/24 == 10.0.0.0/24,
// 2001:db8::1/32 == 2001:db8::/32). An unparseable string is keyed
// verbatim: malformed-prefix validation is the Rust IpNet boundary's
// concern (orthogonal to #2445), and an exact verbatim repeat still
// surfaces as a duplicate here.
func canonicalAllowedIPPrefix(cidr string) string {
	if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
		return ipNet.String()
	}
	return cidr
}

// isWireguardKeyHex reports whether s is exactly 64 hex characters (a
// 32-byte WireGuard X25519 key). Matches the Rust decode_wg_key_hex
// gate so the commit reject and the dataplane hydrate agree.
func isWireguardKeyHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// endpointIsV6 parses a WireGuard endpoint and reports whether its
// address is IPv6. It accepts the canonical `IP:port` form AND a bare
// IP literal: the flat-set/hierarchical tokenizer splits a `[v6]:port`
// literal on its inner colons and stores only the host, so a v6 endpoint
// authored as config TEXT arrives here as a bare `2001:db8::1` (a
// pre-existing parser limitation, orthogonal to #1434). Either form must
// classify by family for the one-UDP-socket outer-family gate. Returns
// an error only when the value is neither a host:port nor a bare IP.
func endpointIsV6(endpoint string) (bool, error) {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.To4() == nil, nil
		}
	}
	if ip := net.ParseIP(endpoint); ip != nil {
		return ip.To4() == nil, nil
	}
	return false, fmt.Errorf("endpoint %q is not an IP[:port] literal", endpoint)
}
