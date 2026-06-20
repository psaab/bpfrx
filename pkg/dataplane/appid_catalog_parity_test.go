package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// appCatalogParityDP is a no-op DataPlane that satisfies the table-write calls
// compileApplications makes so the test can drive the real compiler and capture
// CompileResult.AppNames (the map `show security flow session` resolves app_id
// through). Only the application-table methods are exercised.
type appCatalogParityDP struct {
	DataPlane
}

func (appCatalogParityDP) SetApplication(proto uint8, port uint16, appID uint32, timeout uint32, algType uint8, srcLow, srcHigh uint16) error {
	return nil
}
func (appCatalogParityDP) SetAppRange(idx uint32, entry AppRangeEntry) error { return nil }
func (appCatalogParityDP) DeleteStaleApplications(written map[AppKey]bool)   {}

// TestAppCatalogIDsMatchCompileResultAppNames is the #2008 M5 make-or-break
// wire-parity check: the app_id values appid.BuildCatalog assigns (and ships to
// the Rust dataplane, which stamps them on sessions) MUST equal the app_id ->
// name map compileApplications builds (CompileResult.AppNames, which the gRPC
// show path consumes via ResolveSessionName). If the two builders ever drift in
// name set or id assignment, a session stamped with id N would resolve to the
// wrong name (or UNKNOWN) on the show path. This asserts the two maps are equal.
func TestAppCatalogIDsMatchCompileResultAppNames(t *testing.T) {
	cfg := &config.Config{}
	// Enable application-identification so CatalogNames returns the full
	// predefined + user catalog (the includeAll branch) — the broadest id set.
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"my-custom-app": {Name: "my-custom-app", Protocol: "tcp", DestinationPort: "9000-9100"},
		"my-udp-app":    {Name: "my-udp-app", Protocol: "udp", DestinationPort: "7777"},
		// No protocol => any L4 (TCP+UDP fan-out), exercises the proto==0 path.
		"any-l4-app": {Name: "any-l4-app", DestinationPort: "6000"},
	}

	// Real compiler -> AppNames (the SSOT the show path uses). AppIDs is
	// normally allocated by CompileConfig; compileApplications writes into it.
	result := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	if len(result.AppNames) == 0 {
		t.Fatal("compileApplications produced no AppNames")
	}

	// Catalog builder -> AppNames (what gets shipped to Rust).
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	if len(cat.AppNames) != len(result.AppNames) {
		t.Fatalf("AppNames size mismatch: catalog=%d compileApplications=%d",
			len(cat.AppNames), len(result.AppNames))
	}
	for id, name := range result.AppNames {
		if got := cat.AppNames[id]; got != name {
			t.Fatalf("app_id %d: compileApplications=%q catalog=%q (drift breaks show resolution)",
				id, name, got)
		}
	}

	// Spot-check that a known app's catalog entry round-trips through
	// ResolveSessionName: lookup the id the catalog assigned to my-udp-app and
	// confirm ResolveSessionName(appNames, ..., id) returns its name.
	var udpID uint16
	for id, name := range cat.AppNames {
		if name == "my-udp-app" {
			udpID = id
		}
	}
	if udpID == 0 {
		t.Fatal("my-udp-app not assigned an app_id")
	}
	got := appid.ResolveSessionName(result.AppNames, cfg, 17, 7777, udpID)
	if got != "my-udp-app" {
		t.Fatalf("ResolveSessionName(udpID=%d) = %q, want my-udp-app", udpID, got)
	}
}

// TestAppCatalogIDsMatchOnMalformedDestPort is the #2065-review regression: a
// user application with an UNPARSABLE destination-port must NOT consume an
// app_id slot, exactly as the compiler's bad-port `continue` skips its
// loop-tail appID++. Before the fix BuildCatalog bumped appID on a bad port,
// shifting every subsequent id by one vs CompileResult.AppNames so the
// Rust-stamped app_id resolved to the wrong name. With a custom app whose
// SORTED name precedes a good one, the bad app sits at a lower id and the
// divergence is observable: this test FAILS pre-fix.
func TestAppCatalogIDsMatchOnMalformedDestPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		// "aaa-bad" sorts before "zzz-good"; its dest-port is not parseable.
		"aaa-bad":  {Name: "aaa-bad", Protocol: "tcp", DestinationPort: "not-a-port"},
		"zzz-good": {Name: "zzz-good", Protocol: "tcp", DestinationPort: "8443"},
	}

	result := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	// The id->name maps must be identical despite the malformed app.
	if len(cat.AppNames) != len(result.AppNames) {
		t.Fatalf("AppNames size mismatch with a bad-port app: catalog=%d compiler=%d catalog=%v compiler=%v",
			len(cat.AppNames), len(result.AppNames), cat.AppNames, result.AppNames)
	}
	for id, name := range result.AppNames {
		if got := cat.AppNames[id]; got != name {
			t.Fatalf("app_id %d: compiler=%q catalog=%q (bad-port id drift breaks show resolution)",
				id, name, got)
		}
	}
	// zzz-good must resolve through the id the catalog assigned it.
	var goodID uint16
	for id, name := range cat.AppNames {
		if name == "zzz-good" {
			goodID = id
		}
	}
	if goodID == 0 {
		t.Fatal("zzz-good not assigned an app_id")
	}
	if got := appid.ResolveSessionName(result.AppNames, cfg, 6, 8443, goodID); got != "zzz-good" {
		t.Fatalf("ResolveSessionName(goodID=%d) = %q, want zzz-good (id drift)", goodID, got)
	}
}

// TestAppCatalogEntryPortsAndProtos asserts the catalog builder emits the right
// match shape: a port range stays a range, an omitted protocol fans out to TCP
// AND UDP under one shared app_id, and a single-port entry is exact.
func TestAppCatalogEntryPortsAndProtos(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"range-app": {Name: "range-app", Protocol: "tcp", DestinationPort: "9000-9100"},
		"any-l4":    {Name: "any-l4", DestinationPort: "6000"},
	}
	// Reference both in a policy so the non-includeAll path picks them up.
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name: "p", Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"range-app", "any-l4"},
			},
		}},
	}}

	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	var rangeEntry *appid.CatalogEntry
	var anyL4Protos []uint8
	var anyL4ID uint16
	for i := range cat.Entries {
		e := &cat.Entries[i]
		switch e.Name {
		case "range-app":
			rangeEntry = e
		case "any-l4":
			anyL4Protos = append(anyL4Protos, e.Protocol)
			anyL4ID = e.AppID
		}
	}

	if rangeEntry == nil {
		t.Fatal("range-app missing from catalog")
	}
	if rangeEntry.Protocol != 6 || rangeEntry.DstPortLow != 9000 || rangeEntry.DstPortHigh != 9100 {
		t.Fatalf("range-app entry = %+v, want tcp 9000-9100", *rangeEntry)
	}

	if len(anyL4Protos) != 2 {
		t.Fatalf("any-l4 should fan out to 2 protocols, got %v", anyL4Protos)
	}
	sawTCP, sawUDP := false, false
	for _, p := range anyL4Protos {
		if p == 6 {
			sawTCP = true
		}
		if p == 17 {
			sawUDP = true
		}
	}
	if !sawTCP || !sawUDP {
		t.Fatalf("any-l4 protos = %v, want both TCP(6) and UDP(17)", anyL4Protos)
	}
	// Both fan-out entries share one app_id and one name.
	if anyL4ID == 0 {
		t.Fatal("any-l4 app_id is 0")
	}
	if cat.AppNames[anyL4ID] != "any-l4" {
		t.Fatalf("AppNames[%d] = %q, want any-l4", anyL4ID, cat.AppNames[anyL4ID])
	}
}
