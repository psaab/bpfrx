package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4887: catalogProtocolNumber dropped ProtocolNumber's ok bit, so an EXPLICIT
// but unrepresentable protocol token (e.g. `protocol junos-foobar`) that
// survives a tolerant / HA-sync load — strict commit rejects it, but
// CompileConfigLenient keeps it as a warning — collapsed to byte 0. Because the
// catalog fan-out emitted a row whenever the raw protocol string was non-empty,
// that malformed app shipped a live Protocol:0 (HOPOPT) catalog row whose app_id
// the Rust helper stamps on genuine protocol-0 sessions, producing a false AppID
// label for an application whose protocol was known-malformed. The fix honors
// the ok bit: an unresolvable explicit protocol is unemittable.

// TestBuildCatalogUnrepresentableProtocolNoRow asserts a leniently-loaded app
// with an unresolvable explicit protocol (and no ports) ships NO catalog row and
// records NO stampable AppNames name, while a well-formed neighbor still ships.
//
// fail-on-revert: without the protoOK gate, ProtocolNumber("junos-foobar")
// resolves to (0, false) but the discarded ok let the fan-out emit a
// {Protocol:0} row and an AppNames name, so the row/name assertions fail RED.
func TestBuildCatalogUnrepresentableProtocolNoRow(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		// Explicit but unrepresentable protocol, no ports — the exact tolerant
		// shape from the issue.
		"zz-bad-proto": {Name: "zz-bad-proto", Protocol: "junos-foobar"},
		// Well-formed neighbor must still ship — proves the gate does not
		// over-drop.
		"good": {Name: "good", Protocol: "tcp", DestinationPort: "443"},
	})
	// AppID enabled: CatalogNames returns the full user catalog, so the bad app
	// is cataloged even without a port to key on.
	cfg.Services.ApplicationIdentification = true

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	// No catalog row for the unrepresentable protocol.
	if got := entriesForName(cat, "zz-bad-proto"); len(got) != 0 {
		t.Fatalf("unrepresentable-protocol app shipped %d catalog row(s); want 0 (false-label hole)", len(got))
	}
	// No stampable AppNames name — a skewed app_id must resolve to UNKNOWN, not
	// the malformed app.
	if _, ok := appIDForName(cat, "zz-bad-proto"); ok {
		t.Fatal("unrepresentable-protocol app must not record an AppNames name")
	}

	// Defense in depth: no Protocol:0 (HOPOPT) row leaked from the bad app under
	// any name.
	for _, e := range cat.Entries {
		if e.Protocol == 0 {
			t.Fatalf("catalog shipped a Protocol:0 row %+v — the unrepresentable-protocol fan-out leaked", e)
		}
	}

	// The well-formed neighbor must still ship exactly one row.
	if got := entriesForName(cat, "good"); len(got) != 1 {
		t.Fatalf("well-formed app shipped %d catalog row(s); want 1", len(got))
	}
}

// TestBuildCatalogExplicitProtocolZeroStillShips guards the flip side: an
// EXPLICIT `protocol 0` (HOPOPT) resolves to (0, true) and MUST still ship its
// single row — the fix must not conflate the legitimate reserved protocol 0 with
// the unrepresentable (0, false) case.
func TestBuildCatalogExplicitProtocolZeroStillShips(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		"hopopt": {Name: "hopopt", Protocol: "0"},
	})
	cfg.Services.ApplicationIdentification = true

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	rows := entriesForName(cat, "hopopt")
	if len(rows) != 1 {
		t.Fatalf("explicit `protocol 0` shipped %d row(s); want 1 (single-protocol, no fan-out)", len(rows))
	}
	if rows[0].Protocol != 0 {
		t.Fatalf("explicit `protocol 0` row Protocol = %d; want 0", rows[0].Protocol)
	}
	if _, ok := appIDForName(cat, "hopopt"); !ok {
		t.Fatal("explicit `protocol 0` app must record an AppNames name")
	}
}
