package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/frr"
)

// #9143: the REST FRR status handlers forked one `vtysh` child per request with
// no admission bound. #6809 gated exactly one branch — GET /routing/bgp?type=routes
// — leaving GET /routing/ospf (both branches) and the bgp SUMMARY branch (which
// the source report missed) unbounded.
//
// WHAT CHANGED ON THE STATUS AXIS, precisely. Nothing that could be returned
// before returns anything different: every pre-existing FRR error still renders
// 500. frr.ErrVtyshBusy is a NEW condition that only the new limiter can
// produce, and it renders 429 + Retry-After — matching the shape #6809's own
// over-cap branch on this very endpoint already returns, and the class
// distinction #9142 established (an admission refusal is not a fault). The
// change is purely additive on the status axis, which is why no client, smoke
// or doc that depended on the old behaviour can be broken by it.

type stubFRRExec9143 struct{ frr.RecordingExecutor }

func withFreshVtyshLimiterAPI9143(t *testing.T, n int) {
	t.Helper()
	orig := diagcmd.VtyshLimiter
	diagcmd.VtyshLimiter = diagcmd.NewLimiter(n)
	t.Cleanup(func() { diagcmd.VtyshLimiter = orig })
}

func frrReq9143(t *testing.T, h http.HandlerFunc, target string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", target, nil))
	return rr
}

// Over-cap FRR status reads answer 429 with Retry-After, on BOTH previously
// unbounded handlers. The saturated-limiter leg and the free-limiter leg run in
// one test so the 429 is measured against the admitted case rather than
// asserted alone.
func TestRESTFRRStatusOverCapIs429_9143(t *testing.T) {
	for _, c := range []struct {
		name   string
		target string
	}{
		{"ospf-neighbors", "/api/v1/routing/ospf"},
		{"ospf-database", "/api/v1/routing/ospf?type=database"},
		{"bgp-summary", "/api/v1/routing/bgp"},
	} {
		t.Run(c.name, func(t *testing.T) {
			withFreshVtyshLimiterAPI9143(t, 1)
			s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &stubFRRExec9143{})}

			h := s.ospfHandler
			if c.name == "bgp-summary" {
				h = s.bgpHandler
			}

			// Admitted control FIRST: without it, a handler that answered
			// 429 unconditionally would pass the over-cap assertion below.
			if rr := frrReq9143(t, h, c.target); rr.Code != http.StatusOK {
				t.Fatalf("with a free slot the read returned %d, want 200; body=%s", rr.Code, rr.Body.String())
			}

			// Saturate, then the same request must be refused.
			release, err := diagcmd.VtyshLimiter.Acquire()
			if err != nil {
				t.Fatalf("pre-acquire: %v", err)
			}
			defer release()

			rr := frrReq9143(t, h, c.target)
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("over-cap %s returned %d, want 429; body=%s", c.target, rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("Retry-After"); got == "" {
				t.Error("429 carries no Retry-After header")
			}
			var resp struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("body is not JSON: %v (%s)", err, rr.Body.String())
			}
			if resp.Success {
				t.Error("refusal reported success=true")
			}
		})
	}
}

// A NON-admission FRR error must stay 500. Without this the mapping could be
// satisfied by answering 429 for every failure, which tells a client to retry a
// genuine FRR fault forever.
func TestRESTFRROrdinaryErrorStays500_9143(t *testing.T) {
	withFreshVtyshLimiterAPI9143(t, 4)
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &failingFRRExec9143{})}

	rr := frrReq9143(t, s.ospfHandler, "/api/v1/routing/ospf?type=database")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("ordinary FRR failure returned %d, want 500 (unchanged from before #9143); body=%s",
			rr.Code, rr.Body.String())
	}
}
