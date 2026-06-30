package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3358: the REST security policy inventory exposed the synthetic zone-local
// key (zone-local/<zone>/<name>, minted by the #3061 fold) verbatim in
// src/dst_addresses instead of the authored book name. policiesHandler now
// unqualifies the token via config.DisplayAddressNames. This is the
// fail-on-revert guard: drop the call in security.go and the assertions go RED.

func zoneLocal3358APIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address external 198.51.100.0/24;
        }
    }
    zones {
        security-zone trust {
            address-book {
                address web 10.0.1.100/32;
            }
        }
        security-zone untrust {
            address-book {
                address svc 192.0.2.5/32;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy zl {
                match { source-address web; destination-address svc; application any; }
                then { permit; }
            }
            policy normal {
                match { source-address external; destination-address any; application any; }
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

func TestPoliciesHandlerUnqualifiesZoneLocalNames(t *testing.T) {
	s := &Server{store: zoneLocal3358APIStore(t)}

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
	rules := map[string]PolicyRule{}
	for _, pi := range resp.Data {
		for _, r := range pi.Rules {
			rules[r.Name] = r
		}
	}

	zl, ok := rules["zl"]
	if !ok {
		t.Fatalf("zl missing from REST inventory; body: %s", rr.Body.String())
	}
	if !slices.Equal(zl.SrcAddresses, []string{"web"}) {
		t.Fatalf("zl src_addresses = %v, want [web] "+
			"(REST leaked the synthetic zone-local token — #3358 regression)", zl.SrcAddresses)
	}
	if !slices.Equal(zl.DstAddresses, []string{"svc"}) {
		t.Fatalf("zl dst_addresses = %v, want [svc] "+
			"(REST leaked the synthetic zone-local token — #3358 regression)", zl.DstAddresses)
	}

	normal, ok := rules["normal"]
	if !ok {
		t.Fatalf("normal missing from REST inventory; body: %s", rr.Body.String())
	}
	if !slices.Equal(normal.SrcAddresses, []string{"external"}) {
		t.Fatalf("normal src_addresses = %v, want [external] (global name regressed)", normal.SrcAddresses)
	}
}
