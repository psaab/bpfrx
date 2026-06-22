package config

import (
	"strings"
	"testing"
)

// compileSet compiles a flat-set config via the ParseSetCommand +
// SetPath loop (NEVER NewParser — the parser merges newline-separated
// set lines into one giant node, the dual-AST gotcha). Returns the
// compiled config or the compile error.
func compileSet(t *testing.T, cmds []string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return CompileConfig(tree)
}

func wgTunnel(t *testing.T, cfg *Config, ifName string) *TunnelConfig {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces[ifName]
	if ifc == nil || ifc.Tunnel == nil {
		t.Fatalf("%s tunnel config not found", ifName)
	}
	return ifc.Tunnel
}

const (
	wgKeyA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	wgKeyB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	wgKeyC = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
)

// A single-peer config compiles to exactly one WgPeers entry — the
// pre-#1434 single-peer behavior is preserved through the slice model.
func TestWireguardSinglePeerCompiles(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " endpoint 203.0.113.1:51820",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " persistent-keepalive 25",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	tc := wgTunnel(t, cfg, "wg0")
	if len(tc.WgPeers) != 1 {
		t.Fatalf("WgPeers = %d, want 1", len(tc.WgPeers))
	}
	p := tc.WgPeers[0]
	if p.PublicKeyHex != wgKeyB {
		t.Errorf("PublicKeyHex = %q, want %q", p.PublicKeyHex, wgKeyB)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.1.0.0/16" {
		t.Errorf("AllowedIPs = %v", p.AllowedIPs)
	}
	if p.Endpoint != "203.0.113.1:51820" {
		t.Errorf("Endpoint = %q", p.Endpoint)
	}
	if p.KeepaliveSecs != 25 {
		t.Errorf("KeepaliveSecs = %d, want 25", p.KeepaliveSecs)
	}
}

// Two peers on one WG interface compile to two distinct WgPeers entries.
// Critically: each peer's AllowedIPs stay with that peer (the pre-#1434
// compiler merged all allowed-ips into one bag — the cryptokey-routing
// bug this test guards against).
func TestWireguardDualPeerCompilesFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " endpoint 203.0.113.1:51820",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyC + " allowed-ips 10.2.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyC + " allowed-ips 10.3.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyC + " endpoint 198.51.100.7:51820",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	tc := wgTunnel(t, cfg, "wg0")
	if len(tc.WgPeers) != 2 {
		t.Fatalf("WgPeers = %d, want 2", len(tc.WgPeers))
	}
	byKey := map[string]WgPeerConfig{}
	for _, p := range tc.WgPeers {
		byKey[p.PublicKeyHex] = p
	}
	b, okB := byKey[wgKeyB]
	c, okC := byKey[wgKeyC]
	if !okB || !okC {
		t.Fatalf("missing peer: B=%v C=%v", okB, okC)
	}
	// FAIL-ON-REVERT: the pre-#1434 last-wins/merge bug would put all
	// four CIDRs on one peer and lose the other. Assert per-peer
	// AllowedIPs are NOT cross-contaminated.
	if len(b.AllowedIPs) != 1 || b.AllowedIPs[0] != "10.1.0.0/16" {
		t.Errorf("peer B AllowedIPs = %v, want [10.1.0.0/16] (not merged across peers)", b.AllowedIPs)
	}
	if len(c.AllowedIPs) != 2 || c.AllowedIPs[0] != "10.2.0.0/16" || c.AllowedIPs[1] != "10.3.0.0/16" {
		t.Errorf("peer C AllowedIPs = %v, want [10.2.0.0/16 10.3.0.0/16]", c.AllowedIPs)
	}
	if b.Endpoint != "203.0.113.1:51820" || c.Endpoint != "198.51.100.7:51820" {
		t.Errorf("endpoints crossed: B=%q C=%q", b.Endpoint, c.Endpoint)
	}
}

// The hierarchical AST (peer X { ... } blocks) must compile identically
// to the flat-set form.
func TestWireguardDualPeerCompilesHierarchical(t *testing.T) {
	src := `
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key ` + wgKeyA + `;
                peer ` + wgKeyB + ` {
                    allowed-ips 10.1.0.0/16;
                    endpoint 203.0.113.1:51820;
                }
                peer ` + wgKeyC + ` {
                    allowed-ips 10.2.0.0/16;
                }
            }
        }
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	tc := wgTunnel(t, cfg, "wg0")
	if len(tc.WgPeers) != 2 {
		t.Fatalf("WgPeers = %d, want 2", len(tc.WgPeers))
	}
	keys := map[string]bool{}
	for _, p := range tc.WgPeers {
		keys[p.PublicKeyHex] = true
	}
	if !keys[wgKeyB] || !keys[wgKeyC] {
		t.Fatalf("missing peer keys, got %v", keys)
	}
}

// Duplicate peer pubkey is a hard commit reject (the engine reconcile
// contract owner — engine.rs debug_asserts, production must hard-reject).
func TestWireguardDuplicatePubkeyRejected(t *testing.T) {
	_, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/16",
		// A SECOND peer block under a distinct authored spelling would
		// normally be impossible because the named-instance collapses
		// it; force the dup by re-declaring the same pubkey with a
		// different child so the slice carries two instances.
	})
	// One peer is fine; the dup case needs two instances of the SAME
	// pubkey. The named-instance collapse merges identical-key children
	// into one instance, so a true dup arises only when the hierarchical
	// parser yields two separate `peer <same-key> { }` blocks. Exercise
	// that path here.
	if err != nil {
		t.Fatalf("single-peer baseline must compile: %v", err)
	}
	src := `
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key ` + wgKeyA + `;
                peer ` + wgKeyB + ` { allowed-ips 10.1.0.0/16; }
                peer ` + wgKeyB + ` { allowed-ips 10.2.0.0/16; }
            }
        }
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	_, cerr := CompileConfig(tree)
	if cerr == nil {
		t.Fatal("duplicate peer pubkey must be a commit error")
	}
	if !strings.Contains(cerr.Error(), "duplicate peer public key") {
		t.Errorf("error = %q, want duplicate-pubkey message", cerr)
	}
}

// The same pubkey in different hex CASE is the SAME peer and must be
// rejected as a duplicate (the pubkey is lowercased at parse so the
// dedup, the wire bytes, and the lowercase-hex contract all agree).
// FAIL-ON-REVERT: without the parse-time ToLower, `AA..`/`aa..` both
// survive and orphan a peer in the engine's release-build reconcile.
func TestWireguardDuplicatePubkeyCaseInsensitive(t *testing.T) {
	upper := strings.ToUpper(wgKeyB)
	src := `
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key ` + wgKeyA + `;
                peer ` + wgKeyB + ` { allowed-ips 10.1.0.0/16; }
                peer ` + upper + ` { allowed-ips 10.2.0.0/16; }
            }
        }
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("same pubkey in different case must be a duplicate commit error")
	}
	if !strings.Contains(err.Error(), "duplicate peer public key") {
		t.Errorf("error = %q, want duplicate-pubkey message", err)
	}
}

// The compiler lowercases the peer pubkey so the wire bytes are
// canonical regardless of authored case.
func TestWireguardPubkeyLowercasedAtParse(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + strings.ToUpper(wgKeyB) + " allowed-ips 10.1.0.0/16",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	tc := wgTunnel(t, cfg, "wg0")
	if len(tc.WgPeers) != 1 || tc.WgPeers[0].PublicKeyHex != wgKeyB {
		t.Fatalf("pubkey not lowercased: %v", tc.WgPeers)
	}
}

// A WG tunnel with no peer is a hard commit reject (no dynamic peer
// learning — a peerless WG tunnel can never handshake).
func TestWireguardZeroPeerRejected(t *testing.T) {
	_, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
	})
	if err == nil {
		t.Fatal("zero-peer WG tunnel must be a commit error")
	}
	if !strings.Contains(err.Error(), "no peer") {
		t.Errorf("error = %q, want no-peer message", err)
	}
}

// A malformed (non-64-hex) peer pubkey is a hard commit reject.
func TestWireguardBadPubkeyRejected(t *testing.T) {
	_, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer not-a-valid-key allowed-ips 10.1.0.0/16",
	})
	if err == nil {
		t.Fatal("malformed peer pubkey must be a commit error")
	}
	if !strings.Contains(err.Error(), "invalid public key") {
		t.Errorf("error = %q, want invalid-public-key message", err)
	}
}

// Endpoint-bearing peers that disagree on outer transport family are a
// hard commit reject (one UDP socket = one outer family).
func TestWireguardMixedEndpointFamilyRejected(t *testing.T) {
	// Use the hierarchical AST so the bracketed IPv6 literal survives
	// intact (the flat-set tokenizer splits a `[v6]:port` token on the
	// inner colons — a pre-existing parser limitation orthogonal to the
	// multi-peer model).
	src := `
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key ` + wgKeyA + `;
                peer ` + wgKeyB + ` {
                    allowed-ips 10.1.0.0/16;
                    endpoint 203.0.113.1:51820;
                }
                peer ` + wgKeyC + ` {
                    allowed-ips 10.2.0.0/16;
                    endpoint [2001:db8::1]:51820;
                }
            }
        }
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("mixed endpoint family must be a commit error")
	}
	if !strings.Contains(err.Error(), "mixed address family") {
		t.Errorf("error = %q, want mixed-family message", err)
	}
}

// A responder-only peer (no endpoint) alongside an endpoint-bearing peer
// does NOT trip the mixed-family gate — only DECLARED endpoints
// constrain the family.
func TestWireguardResponderOnlyPeerNoFamilyConstraint(t *testing.T) {
	_, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " endpoint 203.0.113.1:51820",
		// responder-only peer: AllowedIPs but no endpoint.
		"set interfaces wg0 tunnel wireguard peer " + wgKeyC + " allowed-ips 10.2.0.0/16",
	})
	if err != nil {
		t.Fatalf("responder-only peer must not trip the family gate: %v", err)
	}
}

// A malformed preshared-key is a hard commit reject (#1434 B2).
func TestWireguardBadPresharedKeyRejected(t *testing.T) {
	_, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " preshared-key short",
	})
	if err == nil {
		t.Fatal("malformed preshared key must be a commit error")
	}
	if !strings.Contains(err.Error(), "invalid preshared key") {
		t.Errorf("error = %q, want invalid-preshared-key message", err)
	}
}

// A valid per-peer PSK compiles onto the right peer (#1434 B2).
func TestWireguardPresharedKeyCompiles(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/16",
		"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " preshared-key " + wgKeyC,
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	tc := wgTunnel(t, cfg, "wg0")
	if len(tc.WgPeers) != 1 {
		t.Fatalf("WgPeers = %d, want 1", len(tc.WgPeers))
	}
	if got := string(tc.WgPeers[0].PresharedKeyHex); got != wgKeyC {
		t.Errorf("PresharedKeyHex = %q, want %q", got, wgKeyC)
	}
}

// TunnelConfig.String() must redact the private key AND every per-peer
// preshared key. FAIL-ON-REVERT: removing the PSK redaction makes the
// PSK appear verbatim in the formatted output.
func TestTunnelConfigStringRedactsSecrets(t *testing.T) {
	tc := &TunnelConfig{
		Name:              "wg0",
		Mode:              "wireguard",
		WgListenPort:      51820,
		WgLocalPrivkeyHex: Secret(wgKeyA),
		WgPeers: []WgPeerConfig{{
			PublicKeyHex:    wgKeyB,
			AllowedIPs:      []string{"10.1.0.0/16"},
			Endpoint:        "203.0.113.1:51820",
			PresharedKeyHex: Secret(wgKeyC),
		}},
	}
	s := tc.String()
	if strings.Contains(s, wgKeyA) {
		t.Errorf("String() leaked the private key: %q", s)
	}
	if strings.Contains(s, wgKeyC) {
		t.Errorf("String() leaked the per-peer preshared key: %q", s)
	}
	// The PUBLIC key is not a secret and should be visible for triage.
	if !strings.Contains(s, wgKeyB) {
		t.Errorf("String() should surface the public key for triage: %q", s)
	}
	if !strings.Contains(s, "<redacted>") {
		t.Errorf("String() should mark redacted secrets: %q", s)
	}
}
