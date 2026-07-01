package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3328: gRPC GetZones flattened the host-inbound admission set into one
// host_inbound_services repeated field and exposed no host_inbound_configured.
// ZoneInfo now carries host_inbound_configured, host_inbound_system_services,
// host_inbound_protocols, and interface_host_inbound (#3362).
//
// #3405/#3653: EVERY configured security zone is host-inbound ENFORCING (Junos
// default-deny parity). The dataplane (dataplane/userspace/zones.go) sets
// HostInboundConfigured=true unconditionally; a zone with NO stanza
// default-DENIES host-bound traffic exactly like an explicit empty stanza. The
// RPC bit was re-derived from config shape and reported false for a no-stanza
// zone — the pre-#3405 "false = admit-all" reading, the OPPOSITE of runtime.
// The `open` (no-stanza) assertion is the fail-on-revert guard: reverting to
// the config-shape formula reports configured=false and this test goes RED.

func zoneHostInboundGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
                protocols {
                    ospf;
                }
            }
        }
        security-zone locked {
            host-inbound-traffic;
        }
        security-zone edge {
            interfaces {
                ge-0/0/9.0 {
                    host-inbound-traffic {
                        system-services {
                            https;
                        }
                    }
                }
            }
        }
        security-zone open;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestGetZonesSurfacesHostInboundPosture(t *testing.T) {
	s := &Server{store: zoneHostInboundGRPCStore(t)}

	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones() error = %v", err)
	}

	byName := map[string]*pb.ZoneInfo{}
	for _, z := range resp.GetZones() {
		byName[z.GetName()] = z
	}

	trust, ok := byName["trust"]
	if !ok {
		t.Fatal("trust zone missing from gRPC inventory")
	}
	if !trust.GetHostInboundConfigured() {
		t.Fatal("trust host_inbound_configured = false, want true (#3328 regression)")
	}
	if got := trust.GetHostInboundSystemServices(); len(got) != 2 || got[0] != "ssh" || got[1] != "ping" {
		t.Fatalf("trust host_inbound_system_services = %v, want [ssh ping] (#3328 regression — services flattened)", got)
	}
	if got := trust.GetHostInboundProtocols(); len(got) != 1 || got[0] != "ospf" {
		t.Fatalf("trust host_inbound_protocols = %v, want [ospf] (#3328 regression — protocols flattened)", got)
	}
	if got := trust.GetHostInboundServices(); len(got) != 3 {
		t.Fatalf("trust host_inbound_services (legacy alias) = %v, want 3 entries", got)
	}

	// locked: explicit empty stanza = deny-all, configured=true. Post-#3405 it
	// shares the deny-all POSTURE with `open`; the bit no longer distinguishes
	// them (both true).
	locked, ok := byName["locked"]
	if !ok {
		t.Fatal("locked zone missing")
	}
	if !locked.GetHostInboundConfigured() {
		t.Fatal("locked host_inbound_configured = false, want true (explicit empty stanza = deny-all)")
	}
	if len(locked.GetHostInboundSystemServices()) != 0 || len(locked.GetHostInboundProtocols()) != 0 {
		t.Fatalf("locked host-inbound lists = %v/%v, want empty (deny-all)",
			locked.GetHostInboundSystemServices(), locked.GetHostInboundProtocols())
	}

	// open: NO host-inbound stanza and NO per-interface override. Post-#3405
	// this zone default-DENIES host-bound traffic just like `locked`, so the
	// posture bit MUST be true — it mirrors the dataplane, which sets
	// HostInboundConfigured=true for every configured zone. Fail-on-revert
	// guard for #3653: the pre-#3405 config-shape formula reports false here
	// (the "false = admit-all" lie that contradicted runtime), turning this RED.
	open, ok := byName["open"]
	if !ok {
		t.Fatal("open zone missing")
	}
	if !open.GetHostInboundConfigured() {
		t.Fatal("open host_inbound_configured = false, want true (#3405/#3653: a no-stanza configured zone default-DENIES host-bound traffic; the bit must mirror the dataplane, not the pre-#3405 admit-all reading)")
	}
	if len(open.GetHostInboundSystemServices()) != 0 || len(open.GetHostInboundProtocols()) != 0 {
		t.Fatalf("open host-inbound lists = %v/%v, want empty (no-stanza default-deny)",
			open.GetHostInboundSystemServices(), open.GetHostInboundProtocols())
	}
	if len(open.GetInterfaceHostInbound()) != 0 {
		t.Fatalf("open interface_host_inbound = %v, want none", open.GetInterfaceHostInbound())
	}

	edge, ok := byName["edge"]
	if !ok {
		t.Fatal("edge zone missing")
	}
	if !edge.GetHostInboundConfigured() {
		t.Fatal("edge host_inbound_configured = false, want true (per-interface override makes the zone enforcing; #3362/#3328)")
	}
	if len(edge.GetHostInboundSystemServices()) != 0 || len(edge.GetHostInboundProtocols()) != 0 {
		t.Fatalf("edge zone-level host-inbound lists = %v/%v, want empty (override is per-interface only)",
			edge.GetHostInboundSystemServices(), edge.GetHostInboundProtocols())
	}
	if len(edge.GetInterfaceHostInbound()) != 1 {
		t.Fatalf("edge interface_host_inbound = %v, want 1 entry (#3328 per-interface override dropped)", edge.GetInterfaceHostInbound())
	}
	iface := edge.GetInterfaceHostInbound()[0]
	if iface.GetInterface() != "ge-0/0/9.0" {
		t.Fatalf("edge override interface = %q, want ge-0/0/9.0", iface.GetInterface())
	}
	if !iface.GetConfigured() {
		t.Fatal("edge override configured = false, want true")
	}
	if got := iface.GetSystemServices(); len(got) != 1 || got[0] != "https" {
		t.Fatalf("edge override system_services = %v, want [https]", got)
	}
}
