package logging

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// config_facility_advice_7187_test.go — #7187.
//
// pkg/config's commit-time error for an invalid `system syslog` facility names
// the vocabulary an operator may use. pkg/logging owns what those names
// actually DO on the wire. The two are separate lists in separate packages
// because pkg/logging imports pkg/config, so the dependency cannot run the
// other way and they cannot be single-sourced.
//
// WHY THIS ASSERTS AGREEMENT AND DOES NOT PIN EITHER SIDE TO A LITERAL.
// Pinning encodes which side you trust. Here the trusted side was wrong: the
// commit error advertised `security` and `ntp` for years, and pkg/logging had
// ALREADY recorded — verified against the documentation, in
// parse_facility_checked_5797_test.go — that `security` names a different
// hierarchy (`[edit security log]`) and that `ntp` is excluded by the
// empty-second-column rule. A literal on either side would have frozen one of
// those two positions instead of surfacing that they disagreed.
//
// The consequence of the drift was not cosmetic. An operator who read the
// error, wrote `set system syslog host 192.0.2.10 security info`, and committed
// got no error, no `security` records, and everything silently filed to
// local0 — the misfiling that #6830 exists to prevent, reintroduced through the
// help text rather than through the mapping.

// The advice must not promise a name the wire cannot deliver.
func TestConfigFacilityAdviceMatchesTheWireMapping7187(t *testing.T) {
	advertised := config.JunosSyslogFacilityNames()

	// ANTI-VACUITY FLOOR. If the exported list ever came back empty — a rename,
	// a build tag, a getter that stopped copying — every check below would pass
	// over nothing and this test would certify the agreement while measuring
	// none of it.
	if len(advertised) < 10 {
		t.Fatalf("config advertises %d facility names; the list is not reaching this "+
			"test, so a clean result here would certify nothing", len(advertised))
	}

	for _, name := range advertised {
		// `any` is the documented exception: a selector wildcard on the
		// rsyslog-backed file/user destinations, not a numeric facility a host
		// client can stamp. It is valid configuration and correctly has no wire
		// mapping.
		if name == "any" {
			continue
		}
		if _, isJunos := JunosRemoteFacility(name); !isJunos {
			t.Errorf("the commit error advertises %q as a Junos syslog facility, but "+
				"JunosRemoteFacility does not recognise it. An operator who takes that "+
				"advice commits cleanly, gets no records under %q, and has everything "+
				"filed to local0 instead — the misfiling #6830 exists to prevent, "+
				"arriving through the help text rather than the mapping (#7187)",
				name, name)
		}
		if _, known := ParseFacilityChecked(name); !known {
			t.Errorf("the commit error advertises %q but ParseFacilityChecked reports it "+
				"unknown, so the emit path substitutes local0 (#7187)", name)
		}
	}
}

// ...and the advice must not WITHHOLD a name the wire does deliver.
//
// This is the direction that rots silently. Adding a mapping to
// junosRemoteFacility is the natural way to support a new facility, and nothing
// about that edit makes anyone think of an error string in another package. The
// operator then has a facility that works and no way to discover it.
func TestEveryMappedFacilityIsAdvertised7187(t *testing.T) {
	advertised := make(map[string]bool)
	for _, n := range config.JunosSyslogFacilityNames() {
		advertised[n] = true
	}
	if len(advertised) < 10 {
		t.Fatalf("config advertises %d names; the list is not reaching this test", len(advertised))
	}

	// junosRemoteFacility is unexported; JunosRemoteFacility is its reader, so
	// drive it over the names this package's own corpus establishes as real.
	for _, name := range []string{
		"authorization", "change-log", "conflict-log", "daemon", "dfc",
		"firewall", "ftp", "interactive-commands", "kernel", "pfe", "user",
	} {
		if _, isJunos := JunosRemoteFacility(name); !isJunos {
			t.Fatalf("%q is no longer a mapped Junos facility; this test's corpus is "+
				"stale and its result means nothing until it is updated", name)
		}
		if !advertised[name] {
			t.Errorf("%q is a mapped Junos facility that the commit error does NOT "+
				"advertise, so an operator has no way to discover a facility that "+
				"works (#7187)", name)
		}
	}
}

// The two names #7187 removed must stay removed, named individually so a
// regression says WHICH one came back and why it is wrong.
func TestRemovedNonFacilitiesStayRemoved7187(t *testing.T) {
	reasons := map[string]string{
		"security": "`security` names a different hierarchy, [edit security log], not " +
			"[edit system syslog]",
		"ntp": "`ntp` is excluded by the empty-second-column rule: Table 2 carries the " +
			"NTP code with no Junos facility name against it, so it cannot appear in a " +
			"statement at the [edit system syslog] hierarchy level",
	}
	for _, name := range config.JunosSyslogFacilityNames() {
		if why, bad := reasons[name]; bad {
			t.Errorf("the commit error advertises %q again. %s (#7187)", name, why)
		}
	}
}
