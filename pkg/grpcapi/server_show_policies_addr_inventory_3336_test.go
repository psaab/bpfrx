package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3336: the gRPC GetPolicies inventory dropped the match-inversion flags
// (source-address-excluded / destination-address-excluded — a SECURITY display
// inversion), collapsed the independent session-init/session-close log modes
// into one bool, and carried no runtime policy_id / rule_id for joining an
// event back to a rule. PolicyRule now carries source_address_excluded /
// destination_address_excluded, log_session_init / log_session_close, and
// policy_id / rule_id. This is the fail-on-revert guard: drop the population in
// server_show_zones.go (GetPolicies) and the assertions below go RED.

func excludedPolicyGRPCStore(t *testing.T) *configstore.Store {
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

func TestGetPoliciesExposesAddressExclusionAndLogModes(t *testing.T) {
	s := &Server{store: excludedPolicyGRPCStore(t)}

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

	be := rules["block-except"]
	if be == nil {
		t.Fatalf("block-except missing from gRPC inventory")
	}
	if !be.GetSourceAddressExcluded() {
		t.Fatalf("block-except source_address_excluded = false, want true " +
			"(gRPC dropped the match inversion — #3336 regression)")
	}
	if be.GetDestinationAddressExcluded() {
		t.Fatalf("block-except destination_address_excluded = true, want false (only source is excluded)")
	}
	if !be.GetLogSessionInit() || !be.GetLogSessionClose() {
		t.Fatalf("block-except log modes = init:%v close:%v, want both true "+
			"(gRPC collapsed the log modes — #3336 regression)", be.GetLogSessionInit(), be.GetLogSessionClose())
	}
	if be.GetRuleId() != "trust->untrust/block-except" {
		t.Fatalf("block-except rule_id = %q, want %q (gRPC dropped runtime rule_id — #3336 regression)",
			be.GetRuleId(), "trust->untrust/block-except")
	}

	pl := rules["plain-rule"]
	if pl == nil {
		t.Fatalf("plain-rule missing from gRPC inventory")
	}
	if pl.GetSourceAddressExcluded() || pl.GetDestinationAddressExcluded() ||
		pl.GetLogSessionInit() || pl.GetLogSessionClose() {
		t.Fatalf("plain-rule should set no exclusion/log flags, got %+v", pl)
	}

	ge := rules["global-except-dst"]
	if ge == nil {
		t.Fatalf("global-except-dst missing from gRPC inventory")
	}
	if !ge.GetDestinationAddressExcluded() {
		t.Fatalf("global-except-dst destination_address_excluded = false, want true " +
			"(gRPC dropped the global match inversion — #3336 regression)")
	}
	if ge.GetSourceAddressExcluded() {
		t.Fatalf("global-except-dst source_address_excluded = true, want false (only destination is excluded)")
	}
	if ge.GetLogSessionInit() || !ge.GetLogSessionClose() {
		t.Fatalf("global-except-dst log modes = init:%v close:%v, want init false / close true "+
			"(gRPC collapsed the log modes — #3336 regression)", ge.GetLogSessionInit(), ge.GetLogSessionClose())
	}
	if ge.GetRuleId() != "junos-global->junos-global/global-except-dst" {
		t.Fatalf("global-except-dst rule_id = %q, want %q",
			ge.GetRuleId(), "junos-global->junos-global/global-except-dst")
	}
}
