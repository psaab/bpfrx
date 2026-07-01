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
// stanza was configured at all. ZoneInfo now carries host_inbound_configured,
// host_inbound_system_services, host_inbound_protocols, and per-interface
// overrides (#3362).
//
// #3405/#3653: EVERY configured security zone is host-inbound ENFORCING (Junos
// default-deny parity). The dataplane (dataplane/userspace/zones.go) sets
// HostInboundConfigured=true unconditionally for every configured zone; a zone
// with NO host-inbound-traffic stanza default-DENIES host-bound traffic exactly
// like an explicit empty stanza. The REST/gRPC bit was re-derived from config
// shape (stanza-or-override) and reported false for a no-stanza zone — the
// pre-#3405 "false = admit-all" reading, the OPPOSITE of runtime. This test
// pins four distinct concepts so the fix cannot regress: (1) the zone exists,
// (2) enforcement posture — always true for a configured zone, (3) the
// zone-level token set (system-services vs protocols, empty = deny-all), and
// (4) the per-interface effective override. The `open` (no-stanza) assertion is
// the fail-on-revert guard: reverting to the config-shape formula reports
// configured=false for `open` and this test goes RED.

// zoneHostInboundAPIStore builds a config exercising every host-inbound
// posture:
//   - trust: zone-level stanza with both system-services AND protocols
//     (populated → configured=true, split lists non-empty),
//   - locked: explicit EMPTY zone-level stanza (deny-all → configured=true,
//     empty split lists),
//   - edge: NO zone-level stanza but a per-interface override on ge-0/0/9.0
//     (enforcing via override → configured=true, empty zone lists, one
//     interface entry),
//   - open: NO host-inbound at all. Post-#3405 this default-DENIES host-bound
//     traffic (configured=true, empty lists) — indistinguishable in POSTURE
//     from `locked`, matching the dataplane.
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

	// locked: explicit empty stanza = deny-all, configured=true. Post-#3405 it
	// has the same POSTURE as `open` (both deny-all); the two are still
	// distinguishable by config shape only through the token/override fields,
	// not this bit.
	locked, ok := byName["locked"]
	if !ok {
		t.Fatalf("locked zone missing from REST inventory")
	}
	if !locked.HostInboundConfigured {
		t.Fatalf("locked host_inbound_configured = false, want true (explicit empty stanza = deny-all)")
	}
	if len(locked.HostInboundSystemServices) != 0 || len(locked.HostInboundProtocols) != 0 {
		t.Fatalf("locked host-inbound lists = %v/%v, want empty (deny-all)",
			locked.HostInboundSystemServices, locked.HostInboundProtocols)
	}

	// open: NO host-inbound stanza and NO per-interface override. Post-#3405
	// this zone default-DENIES host-bound traffic just like `locked`, so the
	// posture bit MUST be true — it mirrors the dataplane, which sets
	// HostInboundConfigured=true for every configured zone. This is the
	// fail-on-revert guard for #3653: the pre-#3405 config-shape formula
	// (HostInboundTraffic != nil || len(InterfaceHostInbound) > 0) reports
	// false here — the "false = admit-all" lie that contradicted runtime — so
	// reverting the fix turns this RED.
	open, ok := byName["open"]
	if !ok {
		t.Fatalf("open zone missing from REST inventory")
	}
	if !open.HostInboundConfigured {
		t.Fatalf("open host_inbound_configured = false, want true (#3405/#3653: a no-stanza configured zone default-DENIES host-bound traffic; the bit must mirror the dataplane, not the pre-#3405 admit-all reading)")
	}
	// A no-stanza zone carries no zone-level tokens and no override — the empty
	// admitted set IS the deny-all, identical in shape to `locked`.
	if len(open.HostInboundSystemServices) != 0 || len(open.HostInboundProtocols) != 0 {
		t.Fatalf("open host-inbound lists = %v/%v, want empty (no-stanza default-deny)",
			open.HostInboundSystemServices, open.HostInboundProtocols)
	}
	if len(open.InterfaceHostInbound) != 0 {
		t.Fatalf("open interface_host_inbound = %v, want none", open.InterfaceHostInbound)
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
