package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3476: the local CLI policy/screen display + completion surfaces dereference
// nil zone-pair sets, nil rules, nil global rules, and nil screen-profile map
// values reachable on the tolerant / HA-sync config path (#3474) that the
// runtime walker tolerates. These tests inject those nil slots into the live
// ActiveConfig and drive each CLI surface; reverting any of the
// cli_show_security*.go / completion.go nil guards makes the matching subtest
// panic (RED on revert).

func nilSlotCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    policy-stats {
        system-wide enable;
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
            }
        }
        global {
            policy g1 {
                match { source-address any; destination-address any; application any; }
                then { deny; count; }
            }
        }
    }
    screen {
        ids-option sp {
            tcp { land; syn-flood; }
            icmp { ping-death; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.Policies) == 0 || len(cfg.Security.GlobalPolicies) == 0 {
		t.Fatalf("fixture missing policies")
	}
	cfg.Security.Policies[0].Policies = append(cfg.Security.Policies[0].Policies, nil)
	cfg.Security.Policies = append(cfg.Security.Policies, nil)
	cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, nil)
	cfg.Security.Screen["zz-nil-profile"] = nil
	return store
}

func TestCLIPolicyDisplayNilSlotsNoPanic(t *testing.T) {
	store := nilSlotCLIStore(t)
	cfg := store.ActiveConfig()
	c := &CLI{
		store: store,
		dp: &policyCounterCLIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
	// Each call panics on revert of the zpp/rule guards in the matching loop.
	captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount: %v", err)
		}
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
		if err := c.handleShowSecurity([]string{"policies"}); err != nil {
			t.Fatalf("handleShowSecurity(policies): %v", err)
		}
		if err := c.handleShowSecurity([]string{"policies", "brief"}); err != nil {
			t.Fatalf("handleShowSecurity(policies brief): %v", err)
		}
		if err := c.handleShowSecurity([]string{"policies", "detail"}); err != nil {
			t.Fatalf("handleShowSecurity(policies detail): %v", err)
		}
	})
}

func TestCLIScreenDisplayNilProfileNoPanic(t *testing.T) {
	c := &CLI{store: nilSlotCLIStore(t)} // no dp: skip counter reads, exercise map walk
	captureStdout(t, func() {
		if err := c.handleShowScreen(nil); err != nil {
			t.Fatalf("handleShowScreen: %v", err)
		}
		if err := c.handleShowScreen([]string{"ids-option", "zz-nil-profile"}); err != nil {
			t.Fatalf("handleShowScreen(ids-option nil): %v", err)
		}
		if err := c.handleShowScreen([]string{"ids-option", "zz-nil-profile", "detail"}); err != nil {
			t.Fatalf("handleShowScreen(ids-option nil detail): %v", err)
		}
	})
}

// nilSlotZonesCLIStore mirrors nilSlotZonesGRPCStore for the local CLI: a zone
// referencing a screen profile, a policy set, with a nil referenced profile, a
// nil rule, and a nil zone-pair set injected. Drives the `show security zones`
// detail renderer's present-but-nil screen lookup and policy-summary derefs.
func nilSlotZonesCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            screen sp;
        }
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
    screen {
        ids-option sp {
            tcp { land; syn-flood; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.Policies) == 0 {
		t.Fatalf("fixture missing policies")
	}
	cfg.Security.Screen["sp"] = nil
	cfg.Security.Policies[0].Policies = append(cfg.Security.Policies[0].Policies, nil)
	cfg.Security.Policies = append(cfg.Security.Policies, nil)
	return store
}

func TestCLIShowZonesDetailNilSlotsNoPanic(t *testing.T) {
	store := nilSlotZonesCLIStore(t)
	c := &CLI{store: store} // dp nil: skip counters, run screen+summary in detail mode
	captureStdout(t, func() {
		if err := c.showZonesDisplay(store.ActiveConfig(), true, ""); err != nil {
			t.Fatalf("showZonesDisplay(detail): %v", err)
		}
	})
}

func TestCLIValueProviderPolicyNameNilSlotsNoPanic(t *testing.T) {
	c := &CLI{store: nilSlotCLIStore(t)}
	_ = c.valueProvider(config.ValueHintPolicyName,
		[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"})
	_ = c.valueProvider(config.ValueHintPolicyName,
		[]string{"security", "policies", "global", "policy"})
}
