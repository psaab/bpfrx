package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3329: the REST security inventory dropped zone `description`, zone
// `tcp-rst`, and policy `description` that gRPC GetZones/GetPolicies already
// expose from the same config. The two structured APIs disagreed on the
// firewall's posture/audit view. ZoneInfo now carries Description + TcpRst and
// PolicyRule now carries Description. These are the fail-on-revert guards:
// drop the population in security.go (zonesHandler / policiesHandler) and the
// assertions below go RED.

// zonePolicyMetaAPIStore builds a config where one zone sets a description and
// tcp-rst, a second zone sets neither, and a policy carries a description.
func zonePolicyMetaAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            description "owner=neteng ticket=JIRA-42";
            tcp-rst;
        }
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                description "break-glass exception, decommission 2026-12";
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy global-audit {
                description "global owner=secops ticket=JIRA-99";
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
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

// TestZonesHandlerExposesDescriptionAndTCPRst is the #3329 fail-on-revert guard
// for the zone projection: REST must surface a zone's description + tcp-rst and
// omit them for a zone that sets neither.
func TestZonesHandlerExposesDescriptionAndTCPRst(t *testing.T) {
	s := &Server{store: zonePolicyMetaAPIStore(t)}

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

	var sawTrust, sawUntrust bool
	for _, z := range resp.Data {
		switch z.Name {
		case "trust":
			sawTrust = true
			if z.Description != "owner=neteng ticket=JIRA-42" {
				t.Fatalf("trust description = %q, want %q (REST dropped zone description — #3329 regression); body: %s",
					z.Description, "owner=neteng ticket=JIRA-42", rr.Body.String())
			}
			if !z.TcpRst {
				t.Fatalf("trust tcp_rst = false, want true (REST dropped zone tcp-rst — #3329 regression); body: %s",
					rr.Body.String())
			}
		case "untrust":
			sawUntrust = true
			if z.Description != "" {
				t.Fatalf("untrust description = %q, want empty (no description configured)", z.Description)
			}
			if z.TcpRst {
				t.Fatalf("untrust tcp_rst = true, want false (no tcp-rst configured)")
			}
		}
	}
	if !sawTrust {
		t.Fatalf("trust zone missing from REST inventory; body: %s", rr.Body.String())
	}
	if !sawUntrust {
		t.Fatalf("untrust zone missing from REST inventory; body: %s", rr.Body.String())
	}

	// The tcp_rst / description JSON keys must be ABSENT for the unset zone so
	// existing consumers see no behavior change for configs that don't set
	// them (omitempty contract).
	var raw struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v", err)
	}
	for _, z := range raw.Data {
		name := ""
		_ = json.Unmarshal(z["name"], &name)
		if name != "untrust" {
			continue
		}
		if _, ok := z["tcp_rst"]; ok {
			t.Fatalf("untrust zone serialized a tcp_rst key for an unset zone; want omitted")
		}
		if _, ok := z["description"]; ok {
			t.Fatalf("untrust zone serialized a description key for an unset zone; want omitted")
		}
	}
}

// TestPoliciesHandlerExposesDescription is the #3329 fail-on-revert guard for
// the policy projection: REST must surface a policy's description.
func TestPoliciesHandlerExposesDescription(t *testing.T) {
	s := &Server{store: zonePolicyMetaAPIStore(t)}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	// Cover BOTH projection sites in security.go: the zone-pair policy loop
	// AND the global policy loop. Each Description population line is its own
	// RED-on-revert target — deleting either must fail this test.
	var sawZonePair, sawGlobal bool
	for _, policy := range resp.Data {
		for _, rule := range policy.Rules {
			switch rule.Name {
			case "allow-web":
				sawZonePair = true
				if policy.FromZone != "trust" || policy.ToZone != "untrust" {
					t.Fatalf("allow-web grouped under %q/%q, want trust/untrust", policy.FromZone, policy.ToZone)
				}
				if rule.Description != "break-glass exception, decommission 2026-12" {
					t.Fatalf("allow-web description = %q, want %q (REST dropped zone-pair policy description — #3329 regression); body: %s",
						rule.Description, "break-glass exception, decommission 2026-12", rr.Body.String())
				}
			case "global-audit":
				sawGlobal = true
				// Globals stay grouped under the all-zones "*"/"*" PolicyInfo.
				if policy.FromZone != "*" || policy.ToZone != "*" {
					t.Fatalf("global-audit grouped under %q/%q, want */* (global group)", policy.FromZone, policy.ToZone)
				}
				if rule.Description != "global owner=secops ticket=JIRA-99" {
					t.Fatalf("global-audit description = %q, want %q (REST dropped global policy description — #3329 regression); body: %s",
						rule.Description, "global owner=secops ticket=JIRA-99", rr.Body.String())
				}
			}
		}
	}
	if !sawZonePair {
		t.Fatalf("allow-web (zone-pair) policy missing from REST inventory; body: %s", rr.Body.String())
	}
	if !sawGlobal {
		t.Fatalf("global-audit (global) policy missing from REST inventory; body: %s", rr.Body.String())
	}
}
