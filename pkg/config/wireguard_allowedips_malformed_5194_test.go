package config

import (
	"strings"
	"testing"
)

// TestWireguardMalformedAllowedIPsStrictVsLenient_5194 is the #5194 A3-b3-F6
// fail-on-revert guard. A malformed AllowedIPs prefix committed successfully in
// Go, then the Rust hydrate parsed it with ipnet::IpNet and `Err(_) => continue`
// — silently dropping the route while keeping the peer (an all-malformed list =
// a peer that routes nothing, no diagnostic). The fix parses every entry with
// netip.ParsePrefix in strict validation: REJECT at commit, warn on tolerant
// load.
//
// Fail-on-revert: remove the netip.ParsePrefix gate and the strict leg goes RED
// (the malformed prefix commits clean) and the lenient leg loses its warning.
func TestWireguardMalformedAllowedIPsStrictVsLenient_5194(t *testing.T) {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/999",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)

	// Strict commit: hard reject naming allowed-ips.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig must reject a malformed allowed-ips prefix")
	} else if !strings.Contains(err.Error(), "allowed-ips") {
		t.Fatalf("strict error must name allowed-ips, got: %v", err)
	}

	// Tolerant load: must LOAD (no boot blackout) and warn.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a persisted malformed allowed-ips: %v", err)
	}
	if cfg == nil {
		t.Fatal("CompileConfigLenient returned nil config")
	}
	if !warningsContain(cfg.Warnings, "allowed-ips") {
		t.Fatalf("CompileConfigLenient must record an allowed-ips downgrade warning, got: %v", cfg.Warnings)
	}

	// Node-aware tolerant path (HA SyncApply) must also load.
	if _, err := CompileConfigForNodeLenient(tree, 0); err != nil {
		t.Fatalf("CompileConfigForNodeLenient must not fail on a persisted malformed allowed-ips: %v", err)
	}
}

// TestWireguardValidAllowedIPsHostBits_5194 guards against over-rejection: a
// valid CIDR with host bits set (10.1.2.3/24) must still commit — netip
// .ParsePrefix accepts it, the compiler canonicalizes it for dedup.
func TestWireguardValidAllowedIPsHostBits_5194(t *testing.T) {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.2.3/24",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a valid CIDR with host bits set must commit, got: %v", err)
	}
}
