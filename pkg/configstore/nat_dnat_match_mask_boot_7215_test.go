package configstore

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #7215 boot safety — the #1960 no-brick half, driven through the REAL tolerant
// paths rather than inferred from the compiler's lenient flag.
//
// #7215 NARROWS validateDestinationNATAddressesStrict: a `match
// destination-address` whose MASK the dataplane cannot parse (`10.0.0.0/33`)
// now fails the operator's commit. Every config that carries such a value was
// committable before this change, so at least one is persisted somewhere and at
// least one HA primary will sync one. Both of those arrive on the tolerant
// path, and a compile FAILURE there is not a NAT complaint — Store.Load leaves
// ActiveConfig() nil and the daemon falls into the bootstrap/lifeline state,
// which is a whole-box outage in exchange for one inert NAT entry.
//
// The compiler-level tolerance is asserted in pkg/config
// (TestDNATMatchDestinationMask7215LenientWarnsAndKeeps). What is asserted HERE
// is that the two paths a real box takes — a stored config at boot, and an HA
// peer's config over the sync channel — actually reach that tolerance, and that
// what survives is the whole rule, good entry included.
//
// dnat7215StoredConfig is a config a pre-#7215 binary would have committed
// clean: one DNAT rule whose destination list holds a good prefix AND the
// out-of-range mask, authored second.
func dnat7215StoredConfig() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security nat destination pool P1 address 10.0.2.5/32",
		"set security nat destination rule-set RD from zone trust",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.0/24",
		"set security nat destination rule-set RD rule R1 match destination-address 10.0.0.0/33",
	}
}

// dnat7215AssertRuleIntact pins what the tolerant path LOWERED, not merely that
// it did not error.
//
// The good prefix must survive because losing it would silently stop
// translating traffic that was being translated. The malformed one must survive
// too, and that is the counter-intuitive half: the Rust
// `destination_constrained` flag is keyed on the snapshot list being NON-EMPTY,
// so dropping entries Go-side to "clean up" an all-malformed list would clear
// the flag and collapse the rule to MATCH-ANY — turning a fail-CLOSED inert
// entry into a fail-OPEN wildcard translation. Warn, keep, let the dataplane
// drop it per entry.
func dnat7215AssertRuleIntact(t *testing.T, got []string, where string) {
	t.Helper()
	want := []string{"198.51.100.0/24", "10.0.0.0/33"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: destination list = %q, want %q. The GOOD prefix must still be in "+
			"effect after a tolerated load, and the malformed one must be KEPT — the Rust "+
			"destination_constrained flag is keyed on this list being non-empty, so pruning "+
			"it here would collapse an all-malformed rule to MATCH-ANY (fail-OPEN)",
			where, got, want)
	}
}

// A stored config carrying the #7215 mask must BOOT: Load returns nil, an
// active config exists, the rule is intact, and the condition is surfaced as a
// warning rather than swallowed.
//
// RED-on-revert: remove the lenientDestNATAddresses downgrade at the
// runUniformGatesNAT call site and Load returns
// "destination-nat rule-set \"RD\" ... is not a valid IP/CIDR", ActiveConfig()
// is nil, and this fails at the first assertion.
func TestLoad_ToleratesStoredDNATOutOfRangeMask7215(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath, dnat7215StoredConfig()...)

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored DNAT out-of-range mask. Failing the compile "+
			"here leaves ActiveConfig() nil and drops the box into the bootstrap/lifeline "+
			"state — a worse outage than the one inert NAT entry it complains about "+
			"(#1960): %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after a tolerated Load; a silent nil is the same brick " +
			"as an error")
	}
	if active.Security.NAT.Destination == nil ||
		len(active.Security.NAT.Destination.RuleSets) == 0 ||
		len(active.Security.NAT.Destination.RuleSets[0].Rules) == 0 {
		t.Fatalf("the DNAT rule did not survive the tolerated load: %+v",
			active.Security.NAT.Destination)
	}
	dnat7215AssertRuleIntact(t,
		active.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationAddresses,
		"Store.Load")

	var warn string
	for _, w := range active.Warnings {
		if strings.Contains(w, "10.0.0.0/33") {
			warn = w
			break
		}
	}
	if warn == "" {
		t.Fatalf("a tolerated load must SURFACE the condition, naming the value — a silent "+
			"tolerate is the pre-#7215 behaviour and leaves the operator with no way to "+
			"learn the entry is inert. warnings: %v", active.Warnings)
	}

	// The next STRICT operator commit must still reject it — the tolerance is
	// for what is already persisted, not a permanent downgrade.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay STRICT after a tolerated Load; if the tolerant path " +
			"also relaxed the commit check then #7215 was never closed, only renamed")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Fatalf("the strict CommitCheck rejection must name the offending value: %v", err)
	}
}

// HA config sync from a primary that has not been upgraded past #7215 must not
// alarm-loop the standby: SyncApply takes the same tolerant path as Load, and
// the rule it installs must be the same one.
//
// This is asserted separately from Load rather than assumed to follow from it:
// SyncApply is a different entry point with its own compile call, and #1960's
// failure mode on this path (a standby that refuses every sync from a
// lower-versioned primary) is different from the boot failure Load guards.
func TestSyncApply_ToleratesDNATOutOfRangeMask7215(t *testing.T) {
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
        destination {
            pool P1 {
                address 10.0.2.5/32;
            }
            rule-set RD {
                from zone trust;
                rule R1 {
                    match {
                        destination-address [ 198.51.100.0/24 10.0.0.0/33 ];
                    }
                    then {
                        destination-nat {
                            pool P1;
                        }
                    }
                }
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a DNAT out-of-range mask from a peer that has not "+
			"been upgraded past #7215; refusing it makes the standby reject every sync and "+
			"alarm-loop (#1960): %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned a nil config on a tolerated violation")
	}
	if cfg.Security.NAT.Destination == nil ||
		len(cfg.Security.NAT.Destination.RuleSets) == 0 ||
		len(cfg.Security.NAT.Destination.RuleSets[0].Rules) == 0 {
		t.Fatalf("the synced DNAT rule did not survive: %+v", cfg.Security.NAT.Destination)
	}
	dnat7215AssertRuleIntact(t,
		cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationAddresses,
		"Store.SyncApply")
}
