package ddns

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// backend_route53_test.go: mock-server tests driving the REAL Route 53 backend
// against an httptest fake that PARSES the SigV4-signed ChangeResourceRecordSets
// XML body and asserts the change batch (action, name, type, value). The
// signature components are validated structurally (the Authorization header is
// present + well-formed; sigv4_test.go pins the cryptographic correctness).

func newR53TestBackend(t *testing.T, srv *httptest.Server) *route53Backend {
	t.Helper()
	b, err := newRoute53Backend(&config.DDNSProvider{
		Name: "r53", Backend: "route53",
		AWSAccessKeyID: "AKIDEXAMPLE", AWSSecretAccessKey: config.Secret("secret-key"),
		AWSRegion: "us-east-1", HostedZoneID: "Z123ABC", Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newRoute53Backend: %v", err)
	}
	// Pin the clock so the signature is deterministic in-test.
	b.now = func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) }
	return b
}

func TestRoute53UpsertChangeBatch(t *testing.T) {
	var gotPath, gotAuth, gotAmzDate string
	var batch changeBatchXML
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAmzDate = r.Header.Get("X-Amz-Date")
		body, _ := io.ReadAll(r.Body)
		if err := xml.Unmarshal(body, &batch); err != nil {
			t.Errorf("server: unmarshal change batch: %v", err)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)

	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if !strings.HasPrefix(gotPath, "/2013-04-01/hostedzone/Z123ABC/rrset") {
		t.Fatalf("wrong API path: %q", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 ") || !strings.Contains(gotAuth, "Signature=") {
		t.Fatalf("missing/invalid SigV4 Authorization: %q", gotAuth)
	}
	if gotAmzDate == "" {
		t.Fatal("missing X-Amz-Date")
	}
	if len(batch.ChangeBatch.Changes.Change) != 1 {
		t.Fatalf("expected one change, got %d", len(batch.ChangeBatch.Changes.Change))
	}
	c := batch.ChangeBatch.Changes.Change[0]
	if c.Action != "UPSERT" {
		t.Fatalf("expected UPSERT, got %q", c.Action)
	}
	if c.ResourceRecordSet.Name != "wan.example.net." || c.ResourceRecordSet.Type != "A" {
		t.Fatalf("wrong rrset: name=%q type=%q", c.ResourceRecordSet.Name, c.ResourceRecordSet.Type)
	}
	rr := c.ResourceRecordSet.ResourceRecords.ResourceRecord
	if len(rr) != 1 || rr[0].Value != "203.0.113.5" {
		t.Fatalf("wrong rdata: %+v", rr)
	}
}

func TestRoute53DeleteAction(t *testing.T) {
	var action string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch changeBatchXML
		body, _ := io.ReadAll(r.Body)
		_ = xml.Unmarshal(body, &batch)
		if len(batch.ChangeBatch.Changes.Change) == 1 {
			action = batch.ChangeBatch.Changes.Change[0].Action
		}
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ChangeResourceRecordSetsResponse/>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	if action != "DELETE" {
		t.Fatalf("expected DELETE action, got %q", action)
	}
}

func TestRoute53ErrorSurfacesCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>nope</Message></Error></ErrorResponse>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)
	err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
	if err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("expected the Route 53 error code surfaced, got %v", err)
	}
}

// TestRoute53DeleteAlreadyGoneIdempotent is the #2771 fail-on-revert guard.
// When the record is already absent at Route 53, a DELETE returns HTTP 400
// InvalidChangeBatch "... but it was not found". DeleteLease MUST treat that as
// idempotent success (nil) so Surface A drops ownership instead of wedging the
// withdraw forever. Reverting the idempotency makes the already-gone error
// propagate as a non-nil failure and this test goes RED.
func TestRoute53DeleteAlreadyGoneIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidChangeBatch</Code>` +
			`<Message>[Tried to delete resource record set [name='wan.example.net.', type='A'] but it was not found]</Message>` +
			`</Error></ErrorResponse>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("already-gone DELETE must be idempotent success (nil), got %v", err)
	}
}

// TestRoute53DeleteGenuineErrorRetries asserts the idempotency does NOT
// over-swallow: a real failure (auth, throttle, or a non-"not found"
// InvalidChangeBatch) must STILL return non-nil so the engine keeps retrying.
func TestRoute53DeleteGenuineErrorRetries(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		code, msg  string
		wantSubstr string
	}{
		{
			name: "auth", status: http.StatusForbidden,
			code: "SignatureDoesNotMatch", msg: "nope",
			wantSubstr: "SignatureDoesNotMatch",
		},
		{
			name: "throttle", status: http.StatusTooManyRequests,
			code: "Throttling", msg: "Rate exceeded",
			wantSubstr: "Throttling",
		},
		{
			// InvalidChangeBatch that is NOT an already-gone delete (a genuine
			// conflicting/malformed batch) must keep retrying / surface.
			name: "invalid-batch-not-gone", status: http.StatusBadRequest,
			code: "InvalidChangeBatch", msg: "[RRSet with DNS name ... is not permitted in zone]",
			wantSubstr: "InvalidChangeBatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>` +
					tc.code + `</Code><Message>` + tc.msg + `</Message></Error></ErrorResponse>`))
			}))
			defer srv.Close()
			b := newR53TestBackend(t, srv)
			err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
			if err == nil {
				t.Fatalf("genuine %s failure must NOT be swallowed (want non-nil)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("want error containing %q, got %v", tc.wantSubstr, err)
			}
		})
	}
}

func TestRoute53MissingCredsConstructError(t *testing.T) {
	if _, err := newRoute53Backend(&config.DDNSProvider{Name: "r", Backend: "route53", HostedZoneID: "Z"}, nil); err == nil {
		t.Fatal("missing keys must error")
	}
	if _, err := newRoute53Backend(&config.DDNSProvider{Name: "r", Backend: "route53",
		AWSAccessKeyID: "A", AWSSecretAccessKey: config.Secret("s")}, nil); err == nil {
		t.Fatal("missing hosted-zone-id must error")
	}
}
