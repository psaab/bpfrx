package config

import (
	"strings"
	"testing"
)

// #3229: NAT `match destination-address-name <book-entry>` is an address-book
// reference, the destination twin of the #2416 source-address-name support. The
// compiler must (1) parse it into NATMatch.DestinationAddressName for both
// source and destination NAT, and (2) hard-reject at commit a rule whose name
// is not defined under `security address-book`
// (validateNATSourceAddressNameReferencesStrict, which also gates the
// destination name) so the typo is operator-visible instead of silently failing
// closed.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func dnatDestNameSet(matchName string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security address-book global address svc-a 203.0.113.20/32",
		"set security address-book global address-set svc-net address svc-a",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address-name " + matchName,
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

func snatDestNameSet(matchName string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address svc-a 203.0.113.20/32",
		"set security address-book global address-set svc-net address svc-a",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match destination-address-name " + matchName,
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
}

func TestNATDNATDestinationAddressNameParsed(t *testing.T) {
	tree := buildTree(t, dnatDestNameSet("svc-net"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("DNAT with a defined destination-address-name must compile, got: %v", err)
	}
	if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		t.Fatal("destination NAT rule-set missing after compile")
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if rule.Match.DestinationAddressName != "svc-net" {
		t.Fatalf("DNAT DestinationAddressName = %q, want svc-net (parse dropped)", rule.Match.DestinationAddressName)
	}
}

func TestNATSNATDestinationAddressNameParsed(t *testing.T) {
	tree := buildTree(t, snatDestNameSet("svc-net"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("SNAT with a defined destination-address-name must compile, got: %v", err)
	}
	if len(cfg.Security.NAT.Source) == 0 {
		t.Fatal("source NAT rule-set missing after compile")
	}
	rule := cfg.Security.NAT.Source[0].Rules[0]
	if rule.Match.DestinationAddressName != "svc-net" {
		t.Fatalf("SNAT DestinationAddressName = %q, want svc-net (parse dropped)", rule.Match.DestinationAddressName)
	}
}

func TestNATDNATUnknownDestinationAddressNameRejected(t *testing.T) {
	tree := buildTree(t, dnatDestNameSet("does-not-exist"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a DNAT rule naming an undefined destination-address-name must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-address-name") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "does-not-exist") {
		t.Fatalf("error must name the rule + the undefined book entry, got: %v", err)
	}
}

func TestNATSNATUnknownDestinationAddressNameRejected(t *testing.T) {
	tree := buildTree(t, snatDestNameSet("does-not-exist"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a SNAT rule naming an undefined destination-address-name must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-address-name") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "does-not-exist") {
		t.Fatalf("error must name the rule + the undefined book entry, got: %v", err)
	}
}

// The tolerant load / peer-sync path downgrades the undefined reference to a
// warning so an already-persisted or peer-synced config still boots (#1960).
func TestNATUnknownDestinationAddressNameLenientWarns(t *testing.T) {
	tree := buildTree(t, dnatDestNameSet("does-not-exist"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path must not hard-reject an undefined destination-address-name, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "destination-address-name") && strings.Contains(w, "does-not-exist") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path must record a warning for the undefined reference, got warnings: %v", cfg.Warnings)
	}
}
