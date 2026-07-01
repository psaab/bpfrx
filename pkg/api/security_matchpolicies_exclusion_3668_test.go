package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// excludedAPIStore mirrors the gRPC excludedPolicyStore fixture: a trust->untrust
// permit that is BOTH source-address-excluded and destination-address-excluded,
// the #3668 negated-address case.
func excludedAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    address-book {
        global {
            address bad-src 10.0.99.0/24;
            address bad-dst 192.0.2.0/24;
        }
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy exclude-permit {
                match {
                    source-address bad-src;
                    source-address-excluded;
                    destination-address bad-dst;
                    destination-address-excluded;
                    application any;
                }
                then { permit; }
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

// exclusionResponse decodes the REST /security/match envelope including the
// #3668 exclusion flags + stable rule_id.
type exclusionResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched                    bool   `json:"matched"`
		PolicyName                 string `json:"policy_name"`
		RuleID                     string `json:"rule_id"`
		SourceAddressExcluded      bool   `json:"source_address_excluded"`
		DestinationAddressExcluded bool   `json:"destination_address_excluded"`
	} `json:"data"`
}

// TestMatchPoliciesRESTCarriesExclusionAndRuleID pins #3668 on the REST surface:
// the /security/match JSON must carry source_address_excluded /
// destination_address_excluded and the stable rule_id, so a stored diagnostic
// against a negated-address rule does not read backwards and can be joined to the
// inventory.
//
// RED-on-revert: removing the RuleID/SourceAddressExcluded/DestinationAddress
// Excluded field copies in matchPoliciesHandler (pkg/api/security.go) drops them
// from the JSON and every assertion below fails. The matcher + gRPC tests pin the
// other layers; this pins the REST mapping they do NOT exercise.
func TestMatchPoliciesRESTCarriesExclusionAndRuleID(t *testing.T) {
	store := excludedAPIStore(t)
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	q := url.Values{
		"from_zone": {"trust"},
		"to_zone":   {"untrust"},
		// Source OUTSIDE bad-src, destination OUTSIDE bad-dst => the excluded
		// rule matches.
		"src_ip":   {"10.0.5.7"},
		"dst_ip":   {"198.51.100.7"},
		"protocol": {"tcp"},
		"dst_port": {"80"},
	}
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp exclusionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success || !resp.Data.Matched {
		t.Fatalf("expected a successful match; body: %s", rr.Body.String())
	}
	if !resp.Data.SourceAddressExcluded {
		t.Errorf("source_address_excluded = false, want true; body: %s", rr.Body.String())
	}
	if !resp.Data.DestinationAddressExcluded {
		t.Errorf("destination_address_excluded = false, want true; body: %s", rr.Body.String())
	}
	want := dpuserspace.StablePolicyRuleID("trust", "untrust", "exclude-permit")
	if resp.Data.RuleID != want {
		t.Errorf("rule_id = %q, want %q", resp.Data.RuleID, want)
	}
}
