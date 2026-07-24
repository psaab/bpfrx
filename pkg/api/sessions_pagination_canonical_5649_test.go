package api

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6421 / #5649 (codex-181 C181-C11): the REST session-list cursor codec
// (pkg/api/sessions.go) had drifted from the gRPC surface — its
// decodeSessionKeyV4/V6 used a `len(b) < N` check, so any oversized/trailing-
// byte page_token hex-decoded to the SAME cursor as the canonical key (a
// noncanonical opaque token), and parseSessionPageToken had no length cap, so a
// token near the HTTP body limit forced transient base64/hex allocations many
// times the key size before the ABI prefix decode discarded the excess. The
// REST decoders now require the EXACT ABI length and parseSessionPageToken
// rejects tokens over maxPageTokenLen before any decode — matching
// pkg/grpcapi/pagination_canonical_5649_test.go.
//
// FAIL-ON-REVERT: changing the exact-length checks in decodeSessionKeyV4/V6
// back to `<` makes the trailing-byte cases decode successfully and go RED;
// removing the maxPageTokenLen guard makes the oversized case decode instead of
// erroring.
func TestRESTPageTokenCanonical_5649(t *testing.T) {
	// A valid round-trip token still decodes cleanly (no false rejects) and
	// reproduces the exact key — guards the encoder emitting binary.Size bytes.
	v4 := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1111,
		DstPort:  2222,
		Protocol: 6,
	}
	kind, kb, err := parseSessionPageToken(encodePageTokenV4(v4))
	if err != nil || kind != "v4" {
		t.Fatalf("valid v4 round-trip: kind=%q err=%v", kind, err)
	}
	got, err := decodeSessionKeyV4(kb)
	if err != nil {
		t.Fatalf("valid v4 key must decode: %v", err)
	}
	if got != v4 {
		t.Fatalf("v4 round-trip mismatch: got %+v want %+v", got, v4)
	}

	// A token whose hex payload carries a trailing byte beyond the ABI key must
	// be rejected — previously it silently aliased the same cursor.
	raw := make([]byte, binary.Size(v4)+1)
	trailing := "v4:" + hex.EncodeToString(raw)
	tok := base64.RawURLEncoding.EncodeToString([]byte(trailing))
	kind, kb, err = parseSessionPageToken(tok)
	if err != nil || kind != "v4" {
		t.Fatalf("trailing-byte token should still parse as v4: kind=%q err=%v", kind, err)
	}
	if _, err := decodeSessionKeyV4(kb); err == nil {
		t.Fatal("decodeSessionKeyV4 must REJECT a key with a trailing byte (noncanonical token)")
	} else if !strings.Contains(err.Error(), "wrong length") {
		t.Fatalf("trailing-byte reject error %q should mention wrong length", err)
	}

	// The v6 decoder enforces the same exact-length invariant.
	var v6 dataplane.SessionKeyV6
	rawV6 := make([]byte, binary.Size(v6)+1)
	if _, err := decodeSessionKeyV6(rawV6); err == nil {
		t.Fatal("decodeSessionKeyV6 must REJECT an over-length key")
	}

	// An oversized encoded token is rejected before any base64/hex decode. Build
	// a VALID-base64 token far larger than any real cursor: without the cap it
	// base64/hex-decodes cleanly (kind v4, no error) — only the length guard
	// rejects it. A literal size keeps this compiling when the fix is reverted.
	huge := base64.RawURLEncoding.EncodeToString([]byte("v4:" + strings.Repeat("ab", 300)))
	if _, _, err := parseSessionPageToken(huge); err == nil {
		t.Fatal("parseSessionPageToken must REJECT a token far larger than any real cursor")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("oversized reject error %q should mention too long", err)
	}
}

// TestRESTSessionCursorNoncanonical_5649 binds the #5649 hardening to the REST
// entrypoint: it drives sessionsHandler over a dataset larger than one page and
// asserts (a) the positive multi-page walk still works with the binary.Size
// tokens (page size honored, cursor resumes, every row returned once), and (b)
// a noncanonical trailing-byte page_token is rejected with HTTP 400.
//
// FAIL-ON-REVERT: reverting decodeSessionKeyV4 from `!= binary.Size` back to a
// `<` bound makes the trailing-byte token decode to a (bogus) cursor and the
// handler return 200 instead of 400, flipping the want-400 assertion red.
func TestRESTSessionCursorNoncanonical_5649(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()} // 3 v4 + 1 v6 = 4 sessions

	// (a) Positive multi-page walk: page_size 2 over 4 sessions => >=2 pages,
	// every row exactly once, page size never exceeded.
	seen := map[string]bool{}
	token := ""
	pages := 0
	for {
		url := "/api/v1/security/sessions?page_size=2"
		if token != "" {
			url += "&page_token=" + token
		}
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, httptest.NewRequest("GET", url, nil))
		if rr.Code != 200 {
			t.Fatalf("page %d: status %d, want 200; body: %s", pages, rr.Code, rr.Body.String())
		}
		resp := decodeSessions(t, rr.Body.Bytes())
		if len(resp.Sessions) > 2 {
			t.Fatalf("page %d returned %d rows, want <= page_size 2", pages, len(resp.Sessions))
		}
		if resp.PageSize != 2 {
			t.Fatalf("page %d reported page_size %d, want 2", pages, resp.PageSize)
		}
		for _, se := range resp.Sessions {
			k := se.SrcAddr + ":" + se.DstAddr + ":" + se.Protocol
			if seen[k] {
				t.Fatalf("duplicate row across pages: %s", k)
			}
			seen[k] = true
		}
		pages++
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 4 {
		t.Fatalf("cursor pagination returned %d unique rows, want 4", len(seen))
	}
	if pages < 2 {
		t.Fatalf("page_size=2 over 4 rows took %d page(s), want >= 2", pages)
	}

	// (b) A noncanonical v4 token (canonical key + one trailing byte) parses as
	// v4 but must be rejected by the exact-length decoder => HTTP 400.
	var key dataplane.SessionKey
	noncanon := base64.RawURLEncoding.EncodeToString(
		[]byte("v4:" + hex.EncodeToString(make([]byte, binary.Size(key)+1))))
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET",
		"/api/v1/security/sessions?page_size=2&page_token="+noncanon, nil))
	if rr.Code != 400 {
		t.Fatalf("noncanonical page_token: status %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}
