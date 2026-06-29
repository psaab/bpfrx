package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3328: the REST zone inventory flattened the host-inbound admission set into
// one host_inbound_services list and never exposed whether a host-inbound
// stanza was configured at all, so automation could not tell apart the three
// dataplane postures: no stanza (admit-all), explicit empty stanza (deny-all),
// and a populated set (split into system-services vs protocols). ZoneInfo now
// carries host_inbound_configured, host_inbound_system_services,
// host_inbound_protocols, and per-interface overrides (#3362). These are the
// fail-on-revert guards: drop the population in zonesHandler and the assertions
// below go RED.

// zoneHostInboundAPIStore builds a config exercising every host-inbound
// posture:
//   - trust: zone-level stanza with both system-services AND protocols
//     (populated → configured=true, split lists non-empty),
//   - locked: explicit EMPTY zone-level stanza (deny-all → configured=true,
//     empty split lists),
//   - edge: NO zone-level stanza but a per-interface override on ge-0/0/9.0
//     (enforcing via override → configured=true, empty zone lists, one
//     interface entry),
//   - open: NO host-inbound at all (admit-all → configured=false).
func zoneHostInboundAPIStore(t *testing.T) *configstore.Store {
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

func TestZonesHandlerSurfacesHostInboundPosture(t *testing.T) {
	s := &Server{store: zoneHostInboundAPIStore(t)}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/zones", nil)
	s.zonesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Data    []ZoneInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	byName := map[string]ZoneInfo{}
	for _, z := range resp.Data {
		byName[z.Name] = z
	}

	// trust: populated zone-level stanza. system-services and protocols must be
	// split distinctly (the #3328 ambiguity), configured true.
	trust, ok := byName["trust"]
	if !ok {
		t.Fatalf("trust zone missing from REST inventory; body: %s", rr.Body.String())
	}
	if !trust.HostInboundConfigured {
		t.Fatalf("trust host_inbound_configured = false, want true (#3328 regression)")
	}
	if got := trust.HostInboundSystemServices; len(got) != 2 || got[0] != "ssh" || got[1] != "ping" {
		t.Fatalf("trust host_inbound_system_services = %v, want [ssh ping] (#3328 regression — services flattened)", got)
	}
	if got := trust.HostInboundProtocols; len(got) != 1 || got[0] != "ospf" {
		t.Fatalf("trust host_inbound_protocols = %v, want [ospf] (#3328 regression — protocols flattened)", got)
	}
	// Legacy flattened alias must remain (system-services + protocols).
	if got := trust.HostInbound; len(got) != 3 {
		t.Fatalf("trust host_inbound_services (legacy alias) = %v, want 3 entries", got)
	}

	// locked: explicit empty stanza = deny-all. The whole point of #3328:
	// configured=true distinguishes it from a zone with no stanza (open).
	locked, ok := byName["locked"]
	if !ok {
		t.Fatalf("locked zone missing from REST inventory")
	}
	if !locked.HostInboundConfigured {
		t.Fatalf("locked host_inbound_configured = false, want true (explicit empty stanza = deny-all; #3328 the no-stanza-vs-empty-stanza distinction)")
	}
	if len(locked.HostInboundSystemServices) != 0 || len(locked.HostInboundProtocols) != 0 {
		t.Fatalf("locked host-inbound lists = %v/%v, want empty (deny-all)",
			locked.HostInboundSystemServices, locked.HostInboundProtocols)
	}

	// open: no stanza at all = admit-all. configured MUST be false so it is
	// distinguishable from locked.
	open, ok := byName["open"]
	if !ok {
		t.Fatalf("open zone missing from REST inventory")
	}
	if open.HostInboundConfigured {
		t.Fatalf("open host_inbound_configured = true, want false (no stanza = admit-all; #3328 must not collapse with the empty-stanza deny-all posture)")
	}

	// edge: no zone-level stanza but a per-interface override. The zone is
	// enforcing (configured=true) via the override, the zone-level lists are
	// empty, and the override is surfaced per-interface.
	edge, ok := byName["edge"]
	if !ok {
		t.Fatalf("edge zone missing from REST inventory")
	}
	if !edge.HostInboundConfigured {
		t.Fatalf("edge host_inbound_configured = false, want true (per-interface override makes the zone enforcing; #3362/#3328)")
	}
	if len(edge.HostInboundSystemServices) != 0 || len(edge.HostInboundProtocols) != 0 {
		t.Fatalf("edge zone-level host-inbound lists = %v/%v, want empty (override is per-interface only)",
			edge.HostInboundSystemServices, edge.HostInboundProtocols)
	}
	if len(edge.InterfaceHostInbound) != 1 {
		t.Fatalf("edge interface_host_inbound = %v, want 1 entry (#3328 per-interface override dropped)", edge.InterfaceHostInbound)
	}
	iface := edge.InterfaceHostInbound[0]
	if iface.Interface != "ge-0/0/9.0" {
		t.Fatalf("edge override interface = %q, want ge-0/0/9.0", iface.Interface)
	}
	if !iface.Configured {
		t.Fatalf("edge override configured = false, want true")
	}
	if len(iface.SystemServices) != 1 || iface.SystemServices[0] != "https" {
		t.Fatalf("edge override system_services = %v, want [https]", iface.SystemServices)
	}

	// The interface_host_inbound key must be ABSENT for a zone with no
	// per-interface override (omitempty contract) so existing consumers see no
	// change for configs that don't use #3362.
	var raw struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v", err)
	}
	for _, z := range raw.Data {
		name := ""
		_ = json.Unmarshal(z["name"], &name)
		if name != "trust" {
			continue
		}
		if _, ok := z["interface_host_inbound"]; ok {
			t.Fatalf("trust zone serialized interface_host_inbound for a zone with no per-interface override; want omitted")
		}
	}
}
