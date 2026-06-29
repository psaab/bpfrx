package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3336: the REST security policy inventory dropped runtime-carried fields that
// gRPC GetPolicies / the snapshot already model: the match-inversion flags
// (source-address-excluded / destination-address-excluded — a SECURITY display
// inversion: a "match everything EXCEPT bad-net" rule read as "match bad-net"),
// the independent session-init/session-close log modes (collapsed into one
// bool), and the runtime policy_id / rule_id used to join an event back to a
// rule. PolicyRule now carries source_address_excluded /
// destination_address_excluded, log_session_init / log_session_close, and
// policy_id / rule_id. These are the fail-on-revert guards: drop the population
// in security.go (policiesHandler) and the assertions below go RED.

// excludedPolicyAPIStore builds a config with a zone-pair policy that inverts
// its source-address match and logs both session-init+close, a second zone-pair
// policy that inverts neither and logs nothing, and a global policy that
// inverts its destination-address and logs session-close only.
func excludedPolicyAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address bad-net 203.0.113.0/24;
            address mgmt-net 10.0.0.0/8;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy block-except {
                match {
                    source-address bad-net;
                    source-address-excluded;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                    log { session-init; session-close; }
                }
            }
            policy plain-rule {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy global-except-dst {
                match {
                    source-address any;
                    destination-address mgmt-net;
                    destination-address-excluded;
                    application any;
                }
                then {
                    deny;
                    log { session-close; }
                }
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

func TestPoliciesHandlerExposesAddressExclusionAndLogModes(t *testing.T) {
	s := &Server{store: excludedPolicyAPIStore(t)}

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

	rules := map[string]PolicyRule{}
	for _, pi := range resp.Data {
		for _, r := range pi.Rules {
			rules[r.Name] = r
		}
	}

	// Zone-pair inverted rule.
	be, ok := rules["block-except"]
	if !ok {
		t.Fatalf("block-except missing from REST inventory; body: %s", rr.Body.String())
	}
	if !be.SourceAddressExcluded {
		t.Fatalf("block-except source_address_excluded = false, want true "+
			"(REST dropped the match inversion — #3336 regression); body: %s", rr.Body.String())
	}
	if be.DestinationAddressExcluded {
		t.Fatalf("block-except destination_address_excluded = true, want false (only source is excluded)")
	}
	if !be.LogSessionInit || !be.LogSessionClose {
		t.Fatalf("block-except log modes = init:%v close:%v, want both true "+
			"(REST collapsed the log modes — #3336 regression)", be.LogSessionInit, be.LogSessionClose)
	}
	if be.RuleID != "trust->untrust/block-except" {
		t.Fatalf("block-except rule_id = %q, want %q (REST dropped runtime rule_id — #3336 regression)",
			be.RuleID, "trust->untrust/block-except")
	}

	// Plain zone-pair rule: nothing inverted, no log — every #3336 field omitted.
	pl, ok := rules["plain-rule"]
	if !ok {
		t.Fatalf("plain-rule missing from REST inventory; body: %s", rr.Body.String())
	}
	if pl.SourceAddressExcluded || pl.DestinationAddressExcluded || pl.LogSessionInit || pl.LogSessionClose {
		t.Fatalf("plain-rule should set no exclusion/log flags, got %+v", pl)
	}

	// Global inverted rule: destination excluded, log close-only.
	ge, ok := rules["global-except-dst"]
	if !ok {
		t.Fatalf("global-except-dst missing from REST inventory; body: %s", rr.Body.String())
	}
	if !ge.DestinationAddressExcluded {
		t.Fatalf("global-except-dst destination_address_excluded = false, want true "+
			"(REST dropped the global match inversion — #3336 regression); body: %s", rr.Body.String())
	}
	if ge.SourceAddressExcluded {
		t.Fatalf("global-except-dst source_address_excluded = true, want false (only destination is excluded)")
	}
	if ge.LogSessionInit || !ge.LogSessionClose {
		t.Fatalf("global-except-dst log modes = init:%v close:%v, want init false / close true "+
			"(REST collapsed the log modes — #3336 regression)", ge.LogSessionInit, ge.LogSessionClose)
	}
	if ge.RuleID != "junos-global->junos-global/global-except-dst" {
		t.Fatalf("global-except-dst rule_id = %q, want %q",
			ge.RuleID, "junos-global->junos-global/global-except-dst")
	}

	// The new keys must be ABSENT from the plain rule's JSON (omitempty
	// contract) so configs that don't set them see no behavior change.
	var raw struct {
		Data []struct {
			Rules []map[string]json.RawMessage `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v", err)
	}
	for _, pi := range raw.Data {
		for _, r := range pi.Rules {
			name := ""
			_ = json.Unmarshal(r["name"], &name)
			if name != "plain-rule" {
				continue
			}
			for _, k := range []string{
				"source_address_excluded", "destination_address_excluded",
				"log_session_init", "log_session_close",
			} {
				if _, ok := r[k]; ok {
					t.Fatalf("plain-rule serialized %q for an unset field; want omitted", k)
				}
			}
		}
	}
}
