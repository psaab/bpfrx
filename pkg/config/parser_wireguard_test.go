package config_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

func TestWireGuardConfigParsingAndCompilation(t *testing.T) {
	// AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= is 32 bytes of 0x01
	// AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI= is 32 bytes of 0x02
	input := `security {
    wireguard {
        private-key "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        listen-port 51820;
    }
}
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                private-key "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
                listen-port 51821;
                peer "peerpublickey1base64string=" {
                    endpoint "3fff:0:1::1";
                    port 51820;
                    allowed-ips {
                        3fff:10::/32;
                        3fff:20::/32;
                    }
                    persistent-keepalive 25;
                }
                peer "peerpublickey2base64string=" {
                    endpoint "3fff:0:2::1";
                    port 51820;
                    allowed-ips {
                        3fff:30::/32;
                        3fff:40::/32;
                    }
                    persistent-keepalive 30;
                }
            }
        }
    }
}`

	parser := config.NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse hierarchical: %v", errs)
	}

	// Verify Schema Validation
	if err := cmdtree.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate failed: %v", err)
	}

	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// 1. Verify Global Config
	if cfg.Security.WireGuard.PrivateKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Errorf("global private-key = %q, want %q", cfg.Security.WireGuard.PrivateKey, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	}
	if cfg.Security.WireGuard.ListenPort != 51820 {
		t.Errorf("global listen-port = %d, want %d", cfg.Security.WireGuard.ListenPort, 51820)
	}

	// 2. Verify Interface Config
	ifc, ok := cfg.Interfaces.Interfaces["wg0"]
	if !ok {
		t.Fatalf("interface wg0 not found")
	}
	if ifc.Tunnel == nil {
		t.Fatalf("interface wg0 has no tunnel config")
	}
	if ifc.Tunnel.Mode != "wireguard" {
		t.Errorf("tunnel mode = %q, want %q", ifc.Tunnel.Mode, "wireguard")
	}
	wg := ifc.Tunnel.WireGuard
	if wg == nil {
		t.Fatalf("wireguard config is nil")
	}
	if wg.PrivateKey != "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" {
		t.Errorf("interface private-key = %q, want %q", wg.PrivateKey, "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
	}
	if wg.ListenPort != 51821 {
		t.Errorf("interface listen-port = %d, want %d", wg.ListenPort, 51821)
	}

	if len(wg.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(wg.Peers))
	}

	// Peer 1
	p1 := wg.Peers[0]
	if p1.PublicKey != "peerpublickey1base64string=" {
		t.Errorf("peer 1 public-key = %q, want %q", p1.PublicKey, "peerpublickey1base64string=")
	}
	if p1.Endpoint != "3fff:0:1::1" {
		t.Errorf("peer 1 endpoint = %q, want %q", p1.Endpoint, "3fff:0:1::1")
	}
	if p1.Port != 51820 {
		t.Errorf("peer 1 port = %d, want %d", p1.Port, 51820)
	}
	if p1.PersistentKeepalive != 25 {
		t.Errorf("peer 1 keepalive = %d, want %d", p1.PersistentKeepalive, 25)
	}
	if len(p1.AllowedIPs) != 2 || p1.AllowedIPs[0] != "3fff:10::/32" || p1.AllowedIPs[1] != "3fff:20::/32" {
		t.Errorf("peer 1 allowed-ips = %v, want %v", p1.AllowedIPs, []string{"3fff:10::/32", "3fff:20::/32"})
	}

	// Peer 2
	p2 := wg.Peers[1]
	if p2.PublicKey != "peerpublickey2base64string=" {
		t.Errorf("peer 2 public-key = %q, want %q", p2.PublicKey, "peerpublickey2base64string=")
	}
	if p2.Endpoint != "3fff:0:2::1" {
		t.Errorf("peer 2 endpoint = %q, want %q", p2.Endpoint, "3fff:0:2::1")
	}
	if p2.Port != 51820 {
		t.Errorf("peer 2 port = %d, want %d", p2.Port, 51820)
	}
	if p2.PersistentKeepalive != 30 {
		t.Errorf("peer 2 keepalive = %d, want %d", p2.PersistentKeepalive, 30)
	}
	if len(p2.AllowedIPs) != 2 || p2.AllowedIPs[0] != "3fff:30::/32" || p2.AllowedIPs[1] != "3fff:40::/32" {
		t.Errorf("peer 2 allowed-ips = %v, want %v", p2.AllowedIPs, []string{"3fff:30::/32", "3fff:40::/32"})
	}
}
