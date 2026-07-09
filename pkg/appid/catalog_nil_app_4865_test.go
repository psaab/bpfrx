package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4865: a nil user-application map value (cfg.Applications.Applications["x"] =
// nil) is an explicitly tolerated (#3494) malformed/HA-synced shape — a JSON
// null decodes to a nil *config.Application. config.ResolveApplication returns
// (nil, true) for such a value, so the AppID ingestion boundaries must nil-guard
// it rather than dereference it and panic the control plane.

// TestBuildCatalogNilAppNoPanic asserts BuildCatalog skips a nil application
// value instead of panicking on app.Protocol during snapshot/apply. The nil app
// is referenced by a policy and AppID is enabled, so CatalogNames includes its
// name and BuildCatalog resolves it to (nil, true).
//
// fail-on-revert: without the `if app == nil { continue }` guard,
// catalogProtocolNumber(app.Protocol) dereferences a nil pointer and panics, so
// this test crashes instead of passing.
func TestBuildCatalogNilAppNoPanic(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		"zz-nil-app": nil,
		// A well-formed neighbor must still ship — proves the guard does not
		// over-drop and the tolerant path does not brick.
		"good": {Name: "good", Protocol: "tcp", DestinationPort: "443"},
	})
	cfg.Services.ApplicationIdentification = true

	cat, err := BuildCatalog(cfg) // must not panic
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	// The nil app must not be assigned an id or ship a catalog row.
	if _, ok := appIDForName(cat, "zz-nil-app"); ok {
		t.Fatal("nil application must not be assigned an app_id")
	}
	if got := entriesForName(cat, "zz-nil-app"); len(got) != 0 {
		t.Fatalf("nil application shipped %d catalog row(s); want 0", len(got))
	}

	// The well-formed neighbor must still ship exactly one row (protocol tcp,
	// explicit destination-port, no fan-out).
	if got := entriesForName(cat, "good"); len(got) != 1 {
		t.Fatalf("well-formed app shipped %d catalog row(s); want 1", len(got))
	}
}

// TestResolveSessionNameNilAppNoPanic asserts the AppID-disabled tuple fallback
// (resolveTupleFallback) skips a nil application value instead of panicking on
// app.Protocol while ranging cfg.Applications.Applications.
//
// fail-on-revert: without the `if app == nil { continue }` guard, matchTuple
// dereferences app.Protocol/SourcePort/DestinationPort on the nil entry and
// panics the show/session-name rendering path.
func TestResolveSessionNameNilAppNoPanic(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		"zz-nil-app": nil,
		// A real TCP/443 app so the fallback still has a valid match to return.
		"https-like": {Name: "https-like", Protocol: "tcp", DestinationPort: "443"},
	})
	// AppID disabled: ResolveSessionName routes through resolveTupleFallback.

	// proto=6 (TCP), dstPort=443 matches "https-like"; the nil "zz-nil-app"
	// entry must be skipped, not dereferenced.
	// resolveTupleFallback ranges the whole user-application map (including the
	// nil "zz-nil-app" entry) to pick the deterministic best match, so this one
	// call exercises the nil-skip regardless of Go map iteration order.
	name := ResolveSessionName(nil, cfg, 6, 40000, 443, 0) // must not panic
	if name != "https-like" {
		t.Fatalf("ResolveSessionName = %q, want %q (nil app must be skipped, real match returned)", name, "https-like")
	}
}
