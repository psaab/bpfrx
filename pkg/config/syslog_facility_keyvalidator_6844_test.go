package config

import (
	"strings"
	"testing"
)

// syslog_facility_keyvalidator_6844_test.go -- #6844.
//
// `system syslog <dest> <facility> <severity>` models the facility as the
// schema's wildcard KEY. The severity VALUE has been enum-gated since #2008;
// the key carried no keyValidator, so an arbitrary string -- including one
// carrying ';', whitespace, or a newline -- passed SchemaValidate and committed.
//
// #6829 belted the RENDER site, so nothing injected reaches rendered rsyslog
// configuration. This is the other half: the commit path accepted the value, so
// the operator got no error and their configuration silently did not do what it
// said.

// schemaValidateSrc parses src and runs the typed-leaf gate over it, returning
// the gate's error.
//
// It runs SchemaValidate specifically, not CompileConfig, because that is the
// gate under test and because the strictness boundary matters: SchemaValidate is
// strict only on the operator-driven commit path, and Store.compileTreeLenient
// downgrades a violation to a warning on the tolerant Load / SyncApply ingress
// (#1319). Asserting at this layer is what makes the #1960 no-brick contract
// hold without a new lenient opt.
func schemaValidateSrc(t *testing.T, src string) error {
	t.Helper()
	p := NewParser(src)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture failed to PARSE: %v\n%s", perrs, src)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture failed to COMPILE: %v\n%s", err, src)
	}
	return SchemaValidate(tree, cfg)
}

// TestSyslogFacilityKeyRejectsInjectableNames_6844 is the fail-on-revert guard.
//
// Every fixture here is the ISSUE's own reachable case or a near neighbour: an
// ordinary commit, no tolerant load, no peer sync.
func TestSyslogFacilityKeyRejectsInjectableNames_6844(t *testing.T) {
	cases := []struct {
		name     string
		facility string
		why      string
	}{
		{
			name:     "rsyslog selector injection",
			facility: `daemon;*.* /tmp/pwn`,
			why:      "the issue's own example: a second selector line smuggled through the facility",
		},
		{
			name:     "embedded whitespace",
			facility: `daemon extra`,
			why:      "a space splits the rendered selector",
		},
		{
			name:     "leading wildcard",
			facility: `*`,
			why:      "'*' is rsyslog selector punctuation; Junos spells the wildcard `any`",
		},
		{
			name:     "over-long name",
			facility: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			why: "the length bound; without this cell that branch is never executed and " +
				"deleting it leaves the suite green",
		},
		{
			name:     "path separator",
			facility: `../../etc/passwd`,
			why:      "the facility is formatted into a rendered drop-in body",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `system { syslog { file audit { "` + c.facility + `" info; } } }`
			err := schemaValidateSrc(t, src)
			if err == nil {
				t.Fatalf("SchemaValidate ACCEPTED facility %q -- %s.\n"+
					"The commit path must reject it: #6829 keeps it out of the RENDER, "+
					"but with the commit silent the operator is told nothing and their "+
					"configuration does not do what it says.", c.facility, c.why)
			}
			if !strings.Contains(err.Error(), "syslog facility") {
				t.Errorf("rejected, but not by the facility gate: %v", err)
			}
		})
	}
}

// TestSyslogFacilityKeyAcceptsRealNames_6844 is the over-reject control.
//
// Without it, a validator that rejected EVERYTHING would satisfy every cell
// above and look identical in a pass/fail table -- while breaking every real
// syslog config in the fleet.
//
// The list spans all three shapes the vocabulary actually takes: the Junos
// wildcard, hyphenated Junos names, BSD names, and the numbered locals. The
// validator gates SHAPE rather than membership precisely so a Junos facility it
// has never heard of still commits; `dfc` and `pfe` are here to pin that.
func TestSyslogFacilityKeyAcceptsRealNames_6844(t *testing.T) {
	for _, facility := range []string{
		"any",
		"authorization", "change-log", "conflict-log", "daemon", "dfc",
		"firewall", "ftp", "interactive-commands", "kernel", "ntp", "pfe",
		"security", "user",
		"kern", "auth", "syslog",
		"local0", "local7",
	} {
		t.Run(facility, func(t *testing.T) {
			src := `system { syslog { file audit { ` + facility + ` info; } } }`
			if err := schemaValidateSrc(t, src); err != nil {
				t.Errorf("SchemaValidate REJECTED the real facility %q: %v", facility, err)
			}
		})
	}
}

// TestSyslogFacilityKeyGateIsSchemaLayer_6844 pins WHERE the rejection happens,
// which is what makes the #1960 no-brick contract hold without a new lenient
// opt.
//
// The compiler must still accept the value. SchemaValidate is strict only on
// the operator-driven commit path; Store.compileTreeLenient downgrades a
// violation to a warning on the tolerant Load / SyncApply ingress (#1319). If
// this rejection migrated into CompileConfig it would become unconditional, and
// a persisted or peer-synced config carrying such a name would blackout-boot
// the node or alarm-loop HA config sync.
func TestSyslogFacilityKeyGateIsSchemaLayer_6844(t *testing.T) {
	src := `system { syslog { file audit { "daemon;*.* /tmp/pwn" info; } } }`
	p := NewParser(src)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("the COMPILER rejected the injectable facility: %v\n"+
			"That makes the rejection unconditional. It must live in SchemaValidate, "+
			"which is strict only on the commit path, or a persisted / peer-synced "+
			"config carrying this name blackout-boots the node (#1960).", err)
	}
	if err := SchemaValidate(tree, cfg); err == nil {
		t.Fatal("SchemaValidate accepted the injectable facility; the gate is missing")
	}
	_ = cfg
}

// TestSyslogFacilitySeverityStillValidated_6844 is the no-regression cell: the
// VALUE half of the pair was already enum-gated (#2008) and adding a key
// validator must not have displaced it.
func TestSyslogFacilitySeverityStillValidated_6844(t *testing.T) {
	src := `system { syslog { file audit { daemon not-a-severity; } } }`
	if err := schemaValidateSrc(t, src); err == nil {
		t.Fatal("SchemaValidate accepted an invalid SEVERITY; the #2008 value gate was " +
			"displaced by the #6844 key gate rather than joined by it")
	}
}
