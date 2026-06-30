package config

import (
	"slices"
	"testing"
)

// #3358: the synthetic zone-local key (zone-local/<zone>/<name>) minted by the
// #3061 fold is an internal compiler identity, not an operator-facing name.
// ZoneLocalUnqualify reverses zoneLocalQualify so display surfaces can render
// the authored book name + zone scope; DisplayAddressName(s) apply it to flat
// inventory lists. These guard the round-trip and the no-op fall-through for a
// plain token.

func TestZoneLocalUnqualifyRoundTrip(t *testing.T) {
	zone, name, ok := ZoneLocalUnqualify(zoneLocalQualify("trust", "web"))
	if !ok {
		t.Fatalf("ZoneLocalUnqualify(qualify(trust, web)) ok = false, want true")
	}
	if zone != "trust" || name != "web" {
		t.Fatalf("ZoneLocalUnqualify = (%q, %q), want (trust, web)", zone, name)
	}
}

func TestZoneLocalUnqualifyRejectsPlainTokens(t *testing.T) {
	// Plain operator names, prefixes, and malformed inputs must NOT be treated
	// as zone-local keys (no `/` in any operator-typed name guarantees this).
	for _, tok := range []string{
		"web", "any", "any4", "any6", "10.0.0.0/24",
		"zone-local/", "zone-local/trust", "zone-local/trust/", "zone-local//web",
	} {
		if _, _, ok := ZoneLocalUnqualify(tok); ok {
			t.Fatalf("ZoneLocalUnqualify(%q) ok = true, want false", tok)
		}
		if got := DisplayAddressName(tok); got != tok {
			t.Fatalf("DisplayAddressName(%q) = %q, want unchanged", tok, got)
		}
	}
}

func TestDisplayAddressNameUnqualifies(t *testing.T) {
	if got := DisplayAddressName(zoneLocalQualify("untrust", "svc")); got != "svc" {
		t.Fatalf("DisplayAddressName(qualify(untrust, svc)) = %q, want svc", got)
	}
}

func TestDisplayAddressNamesPreservesNilAndMapsTokens(t *testing.T) {
	if got := DisplayAddressNames(nil); got != nil {
		t.Fatalf("DisplayAddressNames(nil) = %v, want nil", got)
	}
	in := []string{zoneLocalQualify("trust", "web"), "external", "any"}
	got := DisplayAddressNames(in)
	want := []string{"web", "external", "any"}
	if !slices.Equal(got, want) {
		t.Fatalf("DisplayAddressNames(%v) = %v, want %v", in, got, want)
	}
	// Must not mutate the caller's slice (it aliases the live compiled config).
	if in[0] != zoneLocalQualify("trust", "web") {
		t.Fatalf("DisplayAddressNames mutated input slice: in[0] = %q", in[0])
	}
}
