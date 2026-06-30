package grpcapi

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3358: a zone-local address book (#3061) is folded into the global book under
// the synthetic key zone-local/<zone>/<name>. The gRPC GetPolicies inventory and
// the `show security policies detail` text render both exposed that internal
// compiler token verbatim instead of the authored book name. They now unqualify
// it. These are the fail-on-revert guards: drop the config.DisplayAddressName(s)
// calls in server_show_zones.go / server_show_policies_text.go and they go RED.

func zoneLocal3358GRPCStore(t *testing.T) *configstore.Store {
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

func TestGetPoliciesUnqualifiesZoneLocalNames(t *testing.T) {
	s := &Server{store: zoneLocal3358GRPCStore(t)}

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}
	rules := map[string]*pb.PolicyRule{}
	for _, pi := range resp.GetPolicies() {
		for _, r := range pi.GetRules() {
			rules[r.GetName()] = r
		}
	}

	zl := rules["zl"]
	if zl == nil {
		t.Fatalf("zl missing from gRPC inventory")
	}
	if !slices.Equal(zl.GetSrcAddresses(), []string{"web"}) {
		t.Fatalf("zl src_addresses = %v, want [web] "+
			"(gRPC leaked the synthetic zone-local token — #3358 regression)", zl.GetSrcAddresses())
	}
	if !slices.Equal(zl.GetDstAddresses(), []string{"svc"}) {
		t.Fatalf("zl dst_addresses = %v, want [svc] "+
			"(gRPC leaked the synthetic zone-local token — #3358 regression)", zl.GetDstAddresses())
	}

	// Control: a global-book name passes through unchanged.
	normal := rules["normal"]
	if normal == nil {
		t.Fatalf("normal missing from gRPC inventory")
	}
	if !slices.Equal(normal.GetSrcAddresses(), []string{"external"}) {
		t.Fatalf("normal src_addresses = %v, want [external] (global name regressed)", normal.GetSrcAddresses())
	}
}

func TestShowPoliciesDetailTextUnqualifiesZoneLocalNames(t *testing.T) {
	s := &Server{store: zoneLocal3358GRPCStore(t)}

	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()

	if strings.Contains(out, "zone-local/") {
		t.Fatalf("text detail leaked the synthetic zone-local token:\n%s", out)
	}
	// Authored name + resolved CIDR, off the qualified global-book key.
	if !strings.Contains(out, "web (10.0.1.100/32)") {
		t.Fatalf("text detail = %q, want \"web (10.0.1.100/32)\" "+
			"(zone-local source name not unqualified — #3358 regression)", out)
	}
	if !strings.Contains(out, "svc (192.0.2.5/32)") {
		t.Fatalf("text detail = %q, want \"svc (192.0.2.5/32)\" "+
			"(zone-local destination name not unqualified — #3358 regression)", out)
	}
	// Control: global name unchanged.
	if !strings.Contains(out, "external (198.51.100.0/24)") {
		t.Fatalf("text detail = %q, want \"external (198.51.100.0/24)\" (global name regressed)", out)
	}
}
