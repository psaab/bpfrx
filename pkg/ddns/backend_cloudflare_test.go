package ddns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			for _, rec := range f.records {
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
	})
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
	// New address → PATCH (update existing).
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.9")); err != nil {
		t.Fatalf("update: %v", err)
	}
	if fake.patched != 1 {
		t.Fatalf("address change must patch: patched=%d", fake.patched)
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

func TestCloudflareBadTokenIsAuthError(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret("WRONG"),
		Zone: fake.zoneName, Server: srv.URL,
	})
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}
	err = b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("bad token must be an auth error, got %v", err)
	}
}

func TestCloudflareMissingCredsConstructError(t *testing.T) {
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", Zone: "x"}); err == nil {
		t.Fatal("missing api-token must error")
	}
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", APIToken: config.Secret("t")}); err == nil {
		t.Fatal("missing zone must error")
	}
}
