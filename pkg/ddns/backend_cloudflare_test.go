package ddns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_cloudflare_test.go: mock-server tests driving the REAL Cloudflare
// backend through a stateful httptest fake of the Cloudflare API (zones lookup +
// dns_records find/create/update/delete). Asserts the Bearer auth, the
// zone-id-resolve→find→PATCH/POST flow, and the change-vs-create branch.

type cfFakeAPI struct {
	t        *testing.T
	token    string
	zoneName string
	zoneID   string
	// records keyed by id.
	records map[string]cfRecord
	// order is the record ids in insertion order, so the GET handler returns a
	// DETERMINISTIC list (real Cloudflare order is arbitrary, but a stable test
	// order lets a test fix which row is recs[0] — the ordering artifact the
	// value-specific #3739 fix must NOT rely on).
	order   []string
	nextID  int
	patched int
	posted  int
	deleted int
	sawAuth string
}

func newCFFakeAPI(t *testing.T) *cfFakeAPI {
	return &cfFakeAPI{
		t: t, token: "tok-123", zoneName: "example.net", zoneID: "ZONEID1",
		records: map[string]cfRecord{}, nextID: 1,
	}
}

func (f *cfFakeAPI) ok(w http.ResponseWriter, result any) {
	env := map[string]any{"success": true, "errors": []any{}, "result": result}
	_ = json.NewEncoder(w).Encode(env)
}

func (f *cfFakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.sawAuth = r.Header.Get("Authorization")
		if f.sawAuth != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false,
				"errors": []map[string]any{{"code": 9109, "message": "bad token"}}})
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") != f.zoneName {
				f.ok(w, []cfZone{})
				return
			}
			f.ok(w, []cfZone{{ID: f.zoneID, Name: f.zoneName}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/"+f.zoneID+"/dns_records":
			name := r.URL.Query().Get("name")
			rtype := r.URL.Query().Get("type")
			var out []cfRecord
			for _, id := range f.order {
				rec := f.records[id]
				if rec.Name == name && rec.Type == rtype {
					out = append(out, rec)
				}
			}
			f.ok(w, out)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/"+f.zoneID+"/dns_records":
			f.posted++
			var rec cfRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "rec" + itoa(f.nextID)
			f.nextID++
			f.records[rec.ID] = rec
			f.order = append(f.order, rec.ID)
			f.ok(w, rec)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/"):
			f.patched++
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/")
			var upd cfRecord
			_ = json.NewDecoder(r.Body).Decode(&upd)
			cur := f.records[id]
			cur.Content = upd.Content
			f.records[id] = cur
			f.ok(w, cur)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/"):
			f.deleted++
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/")
			delete(f.records, id)
			for i, oid := range f.order {
				if oid == id {
					f.order = append(f.order[:i], f.order[i+1:]...)
					break
				}
			}
			f.ok(w, map[string]string{"id": id})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newCFTestBackend(t *testing.T, srv *httptest.Server, fake *cfFakeAPI) *cloudflareBackend {
	t.Helper()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret(fake.token),
		Zone: fake.zoneName, Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}
	return b
}

func TestCloudflareCreateThenUpdate(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	// First publish → POST (create).
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("first publish must create: posted=%d patched=%d", fake.posted, fake.patched)
	}
	// Same address again → no write (content already correct).
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("noop: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("unchanged content must not write: posted=%d patched=%d", fake.posted, fake.patched)
	}
	// New address → PATCH (update existing). Production threads the previous
	// published value (rec.PrevAddr, #3739) so the renumber patches xpf's OWN
	// row in place rather than creating a second record. Without PrevAddr the
	// value-specific path would (correctly) POST a new row and leak the old one.
	renum := hostRecord(t, "wan.example.net", "203.0.113.9")
	renum.PrevAddr = netip.MustParseAddr("203.0.113.5")
	if err := b.UpsertLease(context.Background(), renum); err != nil {
		t.Fatalf("update: %v", err)
	}
	if fake.patched != 1 || fake.posted != 1 {
		t.Fatalf("address change must patch xpf's own row, not create: patched=%d posted=%d", fake.patched, fake.posted)
	}
	// Verify the live record content.
	var live cfRecord
	for _, r := range fake.records {
		live = r
	}
	if live.Content != "203.0.113.9" {
		t.Fatalf("record content not updated: %q", live.Content)
	}
}

// TestCloudflareRenumberPatchesOnlyOwnedRow is the #3739 H11 fail-on-revert for
// a RENUMBER on a SHARED name: the FQDN carries a FOREIGN A a human set plus
// xpf's own A. A publish of xpf's NEW address (with PrevAddr = xpf's prior value)
// must PATCH only xpf's own row and leave the foreign value intact. The fake
// returns records in insertion order and the foreign row is seeded FIRST, so
// recs[0] is the FOREIGN row: reverting UpsertLease to the old content-blind
// "PATCH recs[0]" rewrites the foreign value to xpf's address → this goes RED.
func TestCloudflareRenumberPatchesOnlyOwnedRow(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	// Foreign row FIRST (so it is recs[0]) + xpf's own prior value.
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")
	ownedA := fake.seedRecord("A", fqdn, "203.0.113.5")

	rec := hostRecord(t, fqdn, "203.0.113.9")
	rec.PrevAddr = netip.MustParseAddr("203.0.113.5") // xpf's prior value
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("renumber: %v", err)
	}
	// Exactly one PATCH (xpf's own row), no POST.
	if fake.patched != 1 || fake.posted != 0 {
		t.Fatalf("renumber must patch xpf's own row only: patched=%d posted=%d", fake.patched, fake.posted)
	}
	// xpf's row now carries the new value.
	if got := fake.records[ownedA].Content; got != "203.0.113.9" {
		t.Fatalf("xpf row not renumbered: content=%q", got)
	}
	// The FOREIGN value must survive untouched (the #3739 clobber).
	if got := fake.records[foreignA].Content; got != "198.51.100.20" {
		t.Fatalf("foreign A was clobbered on renumber: content=%q (want 198.51.100.20)", got)
	}
}

// TestCloudflareFirstPublishOntoForeignName is the #3739 H11 fail-on-revert for a
// FIRST publish onto a name that already carries only a FOREIGN A (no xpf row,
// no PrevAddr). The value-specific upsert must POST a new record and leave the
// foreign one intact. Reverting to the old "found → PATCH recs[0]" rewrites the
// sole (foreign) row to xpf's address → this goes RED (foreign clobbered, and a
// POST that should have happened did not).
func TestCloudflareFirstPublishOntoForeignName(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")

	// No PrevAddr — a genuine first publish onto a name a human already populated.
	if err := b.UpsertLease(context.Background(), hostRecord(t, fqdn, "203.0.113.9")); err != nil {
		t.Fatalf("first publish onto foreign name: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("first publish onto a foreign name must POST, not PATCH: posted=%d patched=%d", fake.posted, fake.patched)
	}
	// The foreign value must survive.
	if got := fake.records[foreignA].Content; got != "198.51.100.20" {
		t.Fatalf("foreign A was clobbered on first publish: content=%q (want 198.51.100.20)", got)
	}
	// xpf's new value now coexists.
	var haveNew bool
	for _, r := range fake.records {
		if r.Content == "203.0.113.9" {
			haveNew = true
		}
	}
	if !haveNew {
		t.Fatal("xpf's new A was not created alongside the foreign record")
	}
}

func TestCloudflareDelete(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	rec := hostRecord(t, "wan.example.net", "203.0.113.5")
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if fake.deleted != 1 || len(fake.records) != 0 {
		t.Fatalf("delete must remove the record: deleted=%d remaining=%d", fake.deleted, len(fake.records))
	}
	// Deleting an already-gone record is a success (no-op).
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

// seedRecord injects a record directly into the fake (bypassing POST) so a test
// can stage the multi-record / wrong-content states the real Cloudflare API can
// hold but the backend's own POST path would never create on its own.
func (f *cfFakeAPI) seedRecord(rtype, name, content string) string {
	id := "seed" + itoa(f.nextID)
	f.nextID++
	f.records[id] = cfRecord{ID: id, Type: rtype, Name: name, Content: content}
	f.order = append(f.order, id)
	return id
}

// TestCloudflareDeleteAllOwnedRecords is the #2770 fail-on-revert: a name can
// carry MULTIPLE records of one type, several of which xpf owns. DeleteLease
// must issue a DELETE for EVERY row whose content equals the owned address,
// must NOT touch a row with foreign content, and must leave a record that
// merely shares the name+type but a different value untouched. If reverted to
// the first-only / content-blind delete this goes RED: either it leaves a
// second owned row behind (deleted < 2) or it clobbers the foreign value.
func TestCloudflareDeleteAllOwnedRecords(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const owned = "203.0.113.5"
	// Two owned rows (duplicate same-value A records) + one foreign value a
	// human set on the same name + an unrelated AAAA that must never be hit.
	ownedA := fake.seedRecord("A", fqdn, owned)
	ownedB := fake.seedRecord("A", fqdn, owned)
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")
	foreignAAAA := fake.seedRecord("AAAA", fqdn, "2001:db8::1")

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, owned)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// EVERY owned row deleted — not just the first.
	if fake.deleted != 2 {
		t.Fatalf("must delete every owned record, got deleted=%d", fake.deleted)
	}
	if _, ok := fake.records[ownedA]; ok {
		t.Fatalf("owned record A still present")
	}
	if _, ok := fake.records[ownedB]; ok {
		t.Fatalf("owned record B still present")
	}
	// The foreign value (human/automation set it later) must survive.
	if _, ok := fake.records[foreignA]; !ok {
		t.Fatalf("foreign A value was clobbered — ownership boundary violated")
	}
	if _, ok := fake.records[foreignAAAA]; !ok {
		t.Fatalf("unrelated AAAA was deleted")
	}
}

// TestCloudflareDeleteOwnershipConflict: the name has records of the right type
// but NONE match the owned content (a human replaced the value xpf published).
// DeleteLease must NOT delete a foreign value — it is a success no-op.
func TestCloudflareDeleteOwnershipConflict(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, "203.0.113.5")); err != nil {
		t.Fatalf("delete (no owned match): %v", err)
	}
	if fake.deleted != 0 {
		t.Fatalf("must not delete a foreign value, got deleted=%d", fake.deleted)
	}
	if _, ok := fake.records[foreignA]; !ok {
		t.Fatalf("foreign value was clobbered on ownership conflict")
	}
}

func TestCloudflareBadTokenIsAuthError(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret("WRONG"),
		Zone: fake.zoneName, Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}
	err = b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("bad token must be an auth error, got %v", err)
	}
}

func TestCloudflareMissingCredsConstructError(t *testing.T) {
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", Zone: "x"}, nil); err == nil {
		t.Fatal("missing api-token must error")
	}
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", APIToken: config.Secret("t")}, nil); err == nil {
		t.Fatal("missing zone must error")
	}
}
