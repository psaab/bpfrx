package config

import (
	"strings"
	"testing"
)

// #8447: adding persistent-nat to a rule-referenced source pool on a clustered
// node DISARMS FORWARDING entirely — rx goes to 0 while the interfaces stay up
// and the config commits cleanly.
//
// The behaviour is deliberate and documented (#1449): persistent-NAT leases are
// helper-local and not HA-synchronized, so the dataplane declines to forward
// rather than forward with semantics it cannot honour. The DEFECT is that it
// happened invisibly. The issue spent five rounds of cluster measurement
// rediscovering a contract the daemon already knew, because the only surface
// was a line inside a `show` nobody runs when the symptom is "the link went
// down".

func advisory8447(t *testing.T, setLines []string) []string {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range setLines {
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var hits []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "persistent-nat") && strings.Contains(w, "DISARM FORWARDING") {
			hits = append(hits, w)
		}
	}
	return hits
}

var natBase8447 = []string{
	`set security nat source pool p1 address 172.16.80.200/32`,
	`set security nat source pool p1 port range 51400 to 51499`,
	`set security nat source rule-set rs1 from zone lan`,
	`set security nat source rule-set rs1 to zone wan`,
	`set security nat source rule-set rs1 rule r1 then source-nat pool p1`,
}

func TestClusteredPersistentNATWarnsAtCommit8447(t *testing.T) {
	lines := append([]string{}, natBase8447...)
	lines = append(lines,
		`set security nat source pool p1 persistent-nat permit any-remote-host`,
		`set chassis cluster cluster-id 1`,
		`set chassis cluster node 0`,
		`set chassis cluster authentication-key "s3cr3t-probe-key"`,
	)
	hits := advisory8447(t, lines)
	if len(hits) != 1 {
		t.Fatalf("want exactly one #8447 advisory, got %d: %v\n\n"+
			"This config STOPS TRANSIT on a cluster member. The operator must learn "+
			"that at commit, not when traffic stops.", len(hits), hits)
	}
	// The advisory must name the CONSEQUENCE, not just the condition. "This is
	// unsupported" sends nobody anywhere; "forwarding stops and it will look
	// like a link failure" is what shortens the next five-round investigation.
	for _, want := range []string{"Transit traffic will stop", "show chassis forwarding", "#1449"} {
		if !strings.Contains(hits[0], want) {
			t.Errorf("the advisory must mention %q so it is actionable; got:\n%s", want, hits[0])
		}
	}
}

func TestStandalonePersistentNATDoesNotWarn8447(t *testing.T) {
	// The other side, and the one that stops this from being a warning on every
	// persistent-NAT config. Without a cluster the capability gate does not
	// fire, forwarding is unaffected, and the stanza works exactly as
	// documented. Warning here would train operators to ignore it.
	lines := append([]string{}, natBase8447...)
	lines = append(lines, `set security nat source pool p1 persistent-nat permit any-remote-host`)
	if hits := advisory8447(t, lines); len(hits) != 0 {
		t.Errorf("a STANDALONE persistent-nat config must not warn; got: %v", hits)
	}
}

func TestClusteredWithoutPersistentNATDoesNotWarn8447(t *testing.T) {
	lines := append([]string{}, natBase8447...)
	lines = append(lines, `set chassis cluster cluster-id 1`, `set chassis cluster node 0`,
		`set chassis cluster authentication-key "s3cr3t-probe-key"`)
	if hits := advisory8447(t, lines); len(hits) != 0 {
		t.Errorf("a clustered config with a PLAIN pool must not warn; got: %v", hits)
	}
}

func TestAnUnreferencedPersistentNATPoolDoesNotWarn8447(t *testing.T) {
	// Keyed on the RULE, not the pool table. A pool defined but referenced by
	// no rule translates nothing, so it neither disarms forwarding nor deserves
	// an advisory — and the capability gate has always had this shape. If the
	// two ever disagree, one of them is wrong about whether traffic stops.
	lines := []string{
		`set security nat source pool orphan address 172.16.80.201/32`,
		`set security nat source pool orphan persistent-nat permit any-remote-host`,
		`set chassis cluster cluster-id 1`,
		`set chassis cluster node 0`,
		`set chassis cluster authentication-key "s3cr3t-probe-key"`,
	}
	if hits := advisory8447(t, lines); len(hits) != 0 {
		t.Errorf("an UNREFERENCED persistent-nat pool disarms nothing and must not "+
			"warn; got: %v", hits)
	}
}

// The single-sourcing that makes the advisory trustworthy. The capability gate
// in pkg/dataplane/userspace now CALLS UsesPersistentSourceNATPool rather than
// keeping its own copy, so the advisory cannot promise something the dataplane
// does not do. This cell binds the predicate's contract from the config side;
// the userspace side is bound by its own capability tests.
func TestTheAdvisoryPredicateIsTheGatePredicate8447(t *testing.T) {
	build := func(lines []string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, line := range lines {
			toks, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(toks); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}

	referenced := append([]string{}, natBase8447...)
	referenced = append(referenced, `set security nat source pool p1 persistent-nat permit any-remote-host`)
	if !UsesPersistentSourceNATPool(build(referenced)) {
		t.Error("a rule-referenced persistent-nat pool must be reported — this is the " +
			"condition that disarms forwarding")
	}

	plain := build(natBase8447)
	if UsesPersistentSourceNATPool(plain) {
		t.Error("a plain pool must NOT be reported; reporting it would disarm " +
			"forwarding on configs that are perfectly supported")
	}

	if UsesPersistentSourceNATPool(nil) {
		t.Error("a nil config must not be reported")
	}
}
