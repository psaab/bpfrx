package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #7216 boot safety — the #1960 no-brick half, driven through the REAL tolerant
// ingresses rather than inferred from the compiler's lenient flag.
//
// #7216 refuses a static-NAT rule whose selected `match destination-address` is
// empty. Every such config committed clean before this change, so at least one
// is persisted somewhere and at least one HA primary will sync one. Both arrive
// on the tolerant path, and a compile FAILURE there is not a NAT complaint:
// Store.Load leaves ActiveConfig() nil and the daemon falls into the
// bootstrap/lifeline state, which is a whole-box outage in exchange for one
// rule that was already doing nothing.
//
// The rule really was already doing nothing, which is why tolerating it costs
// nothing: rule.Match lowers to StaticNATRuleSnapshot.ExternalIP, and the Rust
// parse_nat_prefix returns None on "", so from_snapshots drops the whole
// mapping. A leniently-loaded config is exactly as it was before this gate.

// static7216StoredConfig is a config a pre-#7216 binary would have committed
// clean: two static-NAT rules, one with a real external prefix and one whose
// `match destination-address` is an authored blank. The GOOD rule is what makes
// this a useful assertion — the tolerated load must keep translating it.
func static7216StoredConfig() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security nat static rule-set RT from zone trust",
		"set security nat static rule-set RT rule GOOD match destination-address 203.0.113.1/32",
		"set security nat static rule-set RT rule GOOD then static-nat prefix 10.0.1.7/32",
		`set security nat static rule-set RT rule BLANK match destination-address ""`,
		"set security nat static rule-set RT rule BLANK then static-nat prefix 10.0.1.5/32",
	}
}

// A stored config carrying a blanked external prefix must BOOT.
//
// RED-on-revert: remove the lenientFirewallRefs downgrade at the
// validateStaticNATSelectedMatchAddressStrict call site and Load returns the
// "#7216" rejection, ActiveConfig() is nil, and this fails at the first
// assertion.
func TestLoad_ToleratesStoredStaticNATBlankPrefix7216(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath, static7216StoredConfig()...)

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored static-NAT rule with a blanked external "+
			"prefix. Failing the compile leaves ActiveConfig() nil and drops the box into "+
			"the bootstrap/lifeline state — a whole-box outage in exchange for one rule "+
			"that was already doing nothing (#1960): %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after a tolerated Load; a silent nil is the same brick " +
			"as an error")
	}
	if len(active.Security.NAT.Static) == 0 || len(active.Security.NAT.Static[0].Rules) != 2 {
		t.Fatalf("the static-NAT rules did not survive the tolerated load: %+v",
			active.Security.NAT.Static)
	}
	rules := active.Security.NAT.Static[0].Rules
	var good, blank string
	for _, r := range rules {
		switch r.Name {
		case "GOOD":
			good = r.Match
		case "BLANK":
			blank = r.Match
		}
	}
	if good != "203.0.113.1/32" {
		t.Fatalf("Store.Load: the GOOD rule's Match = %q, want %q — a tolerated load that "+
			"lost a working translation breaks a live service to complain about its "+
			"neighbour", good, "203.0.113.1/32")
	}
	if blank != "" {
		t.Fatalf("Store.Load: the BLANK rule's Match = %q, want \"\" — the tolerant path "+
			"must leave the lowered value ALONE so behaviour is identical to before this "+
			"gate; the dataplane already drops the rule", blank)
	}

	var warn string
	for _, w := range active.Warnings {
		if strings.Contains(w, "#7216") && strings.Contains(w, "BLANK") {
			warn = w
			break
		}
	}
	if warn == "" {
		t.Fatalf("a tolerated load must SURFACE the condition, naming the rule — a silent "+
			"tolerate is the pre-#7216 behaviour and leaves the operator with no way to "+
			"learn the rule does not exist at runtime. warnings: %v", active.Warnings)
	}

	// The next STRICT operator commit must still reject it — the tolerance is
	// for what is already persisted, not a permanent downgrade.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay STRICT after a tolerated Load; if the tolerant path " +
			"also relaxed the commit check then #7216 was never closed, only renamed")
	}
	if !strings.Contains(err.Error(), "#7216") {
		t.Fatalf("the strict CommitCheck rejection must be the #7216 gate's: %v", err)
	}
}

// HA config sync from a primary that has not been upgraded past #7216 must not
// alarm-loop the standby. Asserted separately from Load rather than assumed to
// follow from it: SyncApply is a different entry point with its own compile
// call, and its #1960 failure mode (a standby that refuses every sync from a
// lower-versioned primary) is different from the boot failure Load guards.
func TestSyncApply_ToleratesStaticNATBlankPrefix7216(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
    nat {
        static {
            rule-set RT {
                from zone trust;
                rule GOOD {
                    match {
                        destination-address 203.0.113.1/32;
                    }
                    then {
                        static-nat prefix 10.0.1.7/32;
                    }
                }
                rule BLANK {
                    match {
                        destination-address "";
                    }
                    then {
                        static-nat prefix 10.0.1.5/32;
                    }
                }
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a static-NAT rule with a blanked external prefix "+
			"from a peer that has not been upgraded past #7216; refusing it makes the "+
			"standby reject every sync and alarm-loop (#1960): %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned a nil config on a tolerated violation")
	}
	if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) != 2 {
		t.Fatalf("the synced static-NAT rules did not survive: %+v", cfg.Security.NAT.Static)
	}
	for _, r := range cfg.Security.NAT.Static[0].Rules {
		switch r.Name {
		case "GOOD":
			if r.Match != "203.0.113.1/32" {
				t.Fatalf("Store.SyncApply: the GOOD rule's Match = %q, want %q",
					r.Match, "203.0.113.1/32")
			}
		case "BLANK":
			if r.Match != "" {
				t.Fatalf("Store.SyncApply: the BLANK rule's Match = %q, want \"\" — the "+
					"tolerant path must leave the lowered value alone", r.Match)
			}
		}
	}
}
