package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// newPolicyMatchStore builds a committed store with one trust->untrust
// policy so matchPoliciesHandler reaches the dst_port parsing (it returns
// early with HTTP 200 when ActiveConfig is nil).
func newPolicyMatchStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// oneSessionDP is an apiRuntimeDataPlane that yields exactly one forward
// IPv4 TCP session, so protocol-filter tests can assert which filter
// strings keep vs drop the row.
type oneSessionDP struct {
	*dataplane.Manager
}

func (d *oneSessionDP) IsLoaded() bool { return true }

func (d *oneSessionDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 5},
		DstIP:    [4]byte{10, 0, 2, 7},
		SrcPort:  ntohs(12345),
		DstPort:  ntohs(443),
		Protocol: 6, // TCP
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		IsReverse:   0,
		IngressZone: 2,
		EgressZone:  3,
	}
	fn(key, val)
	return nil
}

func (d *oneSessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func decodeSessions(t *testing.T, body []byte) SessionListResponse {
	t.Helper()
	var resp struct {
		Success bool                `json:"success"`
		Data    SessionListResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode sessions response: %v; body=%s", err, body)
	}
	return resp.Data
}

// TestRESTZoneFilterFailsClosed asserts the #2934 contract: a malformed or
// out-of-range non-empty zone filter must return HTTP 400, NOT silently
// fall through to the zone=0 "no filter" sentinel (which would widen the
// query to every zone — a cross-zone observability leak).
//
// FAIL-ON-REVERT: reverting sessions.go/security.go back to
// queryUint16(r,"zone",0) makes zone=abc / zone=65536 parse to the default
// 0 and the handler return HTTP 200, flipping every want-400 case red.
func TestRESTZoneFilterFailsClosed(t *testing.T) {
	s := &Server{
		dp:       &oneSessionDP{Manager: dataplane.New()},
		eventBuf: logging.NewEventBuffer(8),
	}

	cases := []struct {
		name string
		url  string
		call func(*httptest.ResponseRecorder, string)
		want int
	}{
		{"sessions zone=abc", "/api/v1/security/sessions?zone=abc",
			func(rr *httptest.ResponseRecorder, u string) {
				s.sessionsHandler(rr, httptest.NewRequest("GET", u, nil))
			}, 400},
		{"sessions zone=65536", "/api/v1/security/sessions?zone=65536",
			func(rr *httptest.ResponseRecorder, u string) {
				s.sessionsHandler(rr, httptest.NewRequest("GET", u, nil))
			}, 400},
		{"sessions zone=2 valid", "/api/v1/security/sessions?zone=2",
			func(rr *httptest.ResponseRecorder, u string) {
				s.sessionsHandler(rr, httptest.NewRequest("GET", u, nil))
			}, 200},
		{"events zone=abc", "/api/v1/security/events?zone=abc",
			func(rr *httptest.ResponseRecorder, u string) {
				s.eventsHandler(rr, httptest.NewRequest("GET", u, nil))
			}, 400},
		{"events zone=70000", "/api/v1/security/events?zone=70000",
			func(rr *httptest.ResponseRecorder, u string) {
				s.eventsHandler(rr, httptest.NewRequest("GET", u, nil))
			}, 400},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.call(rr, tc.url)
			if rr.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d; body: %s",
					tc.name, rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// TestRESTPolicyMatchDstPortFailsClosed asserts the #2934 contract for the
// policy-match simulator: a malformed dst_port must 400, not silently
// become the 0 "any port" wildcard (which yields a misleading verdict).
//
// FAIL-ON-REVERT: reverting to queryInt(r,"dst_port",0) makes dst_port=abc
// become 0 and the handler proceed (HTTP 200), flipping the want-400 case.
func TestRESTPolicyMatchDstPortFailsClosed(t *testing.T) {
	s := &Server{store: newPolicyMatchStore(t)}

	rr := httptest.NewRecorder()
	s.matchPoliciesHandler(rr, httptest.NewRequest("GET",
		"/api/v1/security/policies/match?from_zone=trust&to_zone=untrust&dst_port=abc", nil))
	if rr.Code != 400 {
		t.Fatalf("dst_port=abc: status = %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

// TestRESTProtocolFilterCaseInsensitiveNumeric asserts the #2935 contract:
// the REST session protocol filter must be case-insensitive AND accept a
// numeric IP protocol number, mirroring gRPC/CLI. The fixture yields one
// TCP (proto 6) session.
//
// FAIL-ON-REVERT: restoring `proto := protoName(...); proto != protoFilter`
// makes the lowercase "tcp" and numeric "6" cases drop the row (0 results),
// flipping their want-1 assertions.
func TestRESTProtocolFilterCaseInsensitiveNumeric(t *testing.T) {
	s := &Server{dp: &oneSessionDP{Manager: dataplane.New()}}

	cases := []struct {
		filter string
		want   int
	}{
		{"TCP", 1},
		{"tcp", 1},
		{"6", 1},
		{"udp", 0},
		{"17", 0},
	}
	for _, tc := range cases {
		t.Run("protocol="+tc.filter, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.sessionsHandler(rr, httptest.NewRequest("GET",
				"/api/v1/security/sessions?protocol="+tc.filter, nil))
			if rr.Code != 200 {
				t.Fatalf("protocol=%s: status %d, want 200; body: %s",
					tc.filter, rr.Code, rr.Body.String())
			}
			got := len(decodeSessions(t, rr.Body.Bytes()).Sessions)
			if got != tc.want {
				t.Fatalf("protocol=%s: %d sessions, want %d", tc.filter, got, tc.want)
			}
		})
	}
}

// greSessionDP is an apiRuntimeDataPlane that yields exactly one forward
// IPv4 GRE (proto 47) session, so the #2949 named-protocol rendering and
// NAMED protocol-filter contract can be exercised end-to-end.
type greSessionDP struct {
	*dataplane.Manager
}

func (d *greSessionDP) IsLoaded() bool { return true }

func (d *greSessionDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 5},
		DstIP:    [4]byte{10, 0, 2, 7},
		Protocol: 47, // GRE
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		IsReverse:   0,
		IngressZone: 2,
		EgressZone:  3,
	}
	fn(key, val)
	return nil
}

func (d *greSessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// TestRESTProtoNameNamedSet asserts the #2949 contract: the REST protoName
// renders the SAME named protocol SET as gRPC (appid.ProtocolName SSOT), so
// gre/esp/ipip/ipv6 sessions display a name instead of a bare number. REST
// upper-cases its rendering (its historical TCP/UDP/ICMP display), but the
// named SET — which protocols are named at all — must match gRPC.
//
// FAIL-ON-REVERT: restoring REST's old 4-protocol switch (tcp/udp/icmp/
// icmpv6 only) makes protoName(47)=="47" instead of "GRE", flipping the
// gre/esp/ipip/ipv6 rows of this table red.
func TestRESTProtoNameNamedSet(t *testing.T) {
	cases := []struct {
		proto uint8
		want  string
	}{
		{6, "TCP"},
		{17, "UDP"},
		{1, "ICMP"},
		{58, "ICMPv6"},
		{47, "GRE"},
		{50, "ESP"},
		{4, "IPIP"},
		{41, "IPV6"},
		{99, "99"}, // unnamed -> numeric fallback
	}
	for _, tc := range cases {
		if got := protoName(tc.proto); got != tc.want {
			t.Fatalf("protoName(%d) = %q, want %q", tc.proto, got, tc.want)
		}
	}
}

// TestRESTProtocolFilterNamedGRE asserts the #2949 contract end-to-end: a
// NAMED `protocol=gre` REST session filter (and its numeric form) matches a
// GRE session, and the rendered row displays the named protocol — exactly
// like the gRPC surface. Before #2949, REST rendered GRE numeric and a
// `protocol=gre` filter silently returned no rows.
//
// FAIL-ON-REVERT: restoring REST's old 4-protocol protoName switch makes
// protoName(47)=="47", so the named "gre" filter no longer matches (0 rows)
// and the displayed protocol reverts to "47", flipping the want-1/"GRE"
// assertions red.
func TestRESTProtocolFilterNamedGRE(t *testing.T) {
	s := &Server{dp: &greSessionDP{Manager: dataplane.New()}}

	cases := []struct {
		filter string
		want   int
	}{
		{"gre", 1},
		{"GRE", 1},
		{"47", 1},
		{"esp", 0},
		{"50", 0},
	}
	for _, tc := range cases {
		t.Run("protocol="+tc.filter, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.sessionsHandler(rr, httptest.NewRequest("GET",
				"/api/v1/security/sessions?protocol="+tc.filter, nil))
			if rr.Code != 200 {
				t.Fatalf("protocol=%s: status %d, want 200; body: %s",
					tc.filter, rr.Code, rr.Body.String())
			}
			sess := decodeSessions(t, rr.Body.Bytes()).Sessions
			if len(sess) != tc.want {
				t.Fatalf("protocol=%s: %d sessions, want %d", tc.filter, len(sess), tc.want)
			}
			if tc.want == 1 && sess[0].Protocol != "GRE" {
				t.Fatalf("protocol=%s: rendered protocol = %q, want %q",
					tc.filter, sess[0].Protocol, "GRE")
			}
		})
	}
}

// TestEventFilterExactNotSubstring asserts the #2939 contract: the event
// filter must match protocol/action EXACTLY (case-insensitive), not as a
// substring. protocol=C must NOT match TCP/ICMP/ICMPv6.
//
// FAIL-ON-REVERT: restoring strings.Contains in EventFilter.matches makes
// protocol=C match all three records, flipping the want-0 assertion.
func TestEventFilterExactNotSubstring(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", Protocol: "TCP", Action: "permit"})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", Protocol: "ICMP", Action: "deny"})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", Protocol: "ICMPv6", Action: "permit"})

	cases := []struct {
		name   string
		filter logging.EventFilter
		want   int
	}{
		{"protocol=C substring must not match", logging.EventFilter{Protocol: "C"}, 0},
		{"protocol=TCP exact", logging.EventFilter{Protocol: "TCP"}, 1},
		{"protocol=tcp case-insensitive", logging.EventFilter{Protocol: "tcp"}, 1},
		{"protocol=ICMP exact (not ICMPv6)", logging.EventFilter{Protocol: "ICMP"}, 1},
		{"action=permit exact", logging.EventFilter{Action: "permit"}, 2},
		{"action=per substring must not match", logging.EventFilter{Action: "per"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := len(eb.LatestFiltered(16, tc.filter))
			if got != tc.want {
				t.Fatalf("%s: %d events, want %d", tc.name, got, tc.want)
			}
		})
	}
}
