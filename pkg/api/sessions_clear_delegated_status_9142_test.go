package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// #9142: POST /api/v1/security/sessions/clear answered the SAME condition with
// two different status classes depending only on whether an HA session service
// was wired.
//
// sessionWalkLimiter is process-wide and shared by REST and gRPC session
// list/summary/clear (MaxConcurrentSessionWalks = 4), so ordinary
// GET /security/sessions scrapes are what saturate it. When it refuses:
//
//   - standalone (clusterSessionFn nil): the local fallback acquires the
//     limiter itself and answers 429 (#5779).
//   - clustered: the handler delegates to the in-process *grpcapi.Server, whose
//     ClearSessions returns codes.ResourceExhausted from that same limiter —
//     and the handler flattened every delegate error to 500.
//
// Measured before the fix:
//
//	resource-exhausted  status=500 body={"success":false,"error":"rpc error: code = ResourceExhausted desc = session scan concurrency limit reached; retry shortly"}
//	unavailable         status=500 body={"success":false,"error":"rpc error: code = Unavailable desc = dataplane not loaded"}
//
// Two defects in one line: the status class, and the gRPC FRAMING
// ("rpc error: code = ... desc = ...") leaking into a REST JSON body — an
// internal detail of a delegation the REST caller cannot see.
//
// FAIL-ON-REVERT: restore `writeError(w, http.StatusInternalServerError,
// err.Error())` and every cell below goes RED.

func clearWithDelegateErr9142(t *testing.T, err error) *httptest.ResponseRecorder {
	t.Helper()
	fake := &fakeClusterSessionService{clearErr: err}
	s := &Server{
		dp:               &clearAllDP{Manager: dataplane.New()},
		nodeIDFn:         func() int { return 1 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.clearSessionsHandler(rr, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	if !fake.clearCalled {
		t.Fatal("the delegated branch was not taken — this cell is not measuring what it claims")
	}
	return rr
}

func errBody9142(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body is not JSON: %v (%s)", err, rr.Body.String())
	}
	if resp.Success {
		t.Fatalf("error response reported success=true: %s", rr.Body.String())
	}
	return resp.Error
}

func TestRESTClearSessionsDelegatedResourceExhaustedIs429_9142(t *testing.T) {
	rr := clearWithDelegateErr9142(t,
		status.Error(codes.ResourceExhausted, "session clear concurrency limit reached; retry shortly"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("delegated ResourceExhausted -> %d, want 429 (an admission refusal is not a fault); body=%s",
			rr.Code, rr.Body.String())
	}
	msg := errBody9142(t, rr)
	if strings.Contains(msg, "rpc error") || strings.Contains(msg, "code =") {
		t.Errorf("gRPC framing leaked into the REST body: %q", msg)
	}
	if msg != "session clear concurrency limit reached; retry shortly" {
		t.Errorf("message = %q, want the delegate's own message verbatim", msg)
	}
}

// The cell that makes the issue's claim checkable rather than asserted: the
// SAME condition, on the SAME endpoint, in both wirings, in ONE run. Without
// this the 429 above is just a number someone chose.
func TestRESTClearSessionsSameRefusalSameStatusBothWirings_9142(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	// STANDALONE: no cluster service, so the local fallback acquires the
	// saturated limiter itself.
	standalone := &Server{dp: &clearAllDP{Manager: dataplane.New()}}
	rrStandalone := httptest.NewRecorder()
	standalone.clearSessionsHandler(rrStandalone,
		httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	release()

	// CLUSTERED: the delegate refuses with the code the real gRPC handler
	// returns from that same limiter (server_sessions.go).
	rrClustered := clearWithDelegateErr9142(t,
		status.Error(codes.ResourceExhausted, "session clear concurrency limit reached; retry shortly"))

	if rrStandalone.Code != http.StatusTooManyRequests {
		t.Fatalf("standalone leg is not measuring the refusal: status = %d, want 429; body=%s",
			rrStandalone.Code, rrStandalone.Body.String())
	}
	if rrClustered.Code != rrStandalone.Code {
		t.Fatalf("the same endpoint answered the same refusal with %d clustered and %d standalone — "+
			"a client keyed on the status class behaves differently based only on whether HA is wired (#9142)",
			rrClustered.Code, rrStandalone.Code)
	}
}

func TestRESTClearSessionsDelegatedUnavailableIs503_9142(t *testing.T) {
	rr := clearWithDelegateErr9142(t, status.Error(codes.Unavailable, "dataplane not loaded"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("delegated Unavailable -> %d, want 503 (the handler's own dp guard answers 503 for "+
			"the same condition); body=%s", rr.Code, rr.Body.String())
	}
	if msg := errBody9142(t, rr); msg != "dataplane not loaded" {
		t.Errorf("message = %q, want %q", msg, "dataplane not loaded")
	}
}

// Everything else must stay 500. Without this the mapping could be satisfied by
// returning 429 for every failure, which would tell a client to retry a real
// fault forever.
func TestRESTClearSessionsDelegatedOtherCodesStay500_9142(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"internal", status.Error(codes.Internal, "clear all: map delete failed"), "clear all: map delete failed"},
		{"permission-denied", status.Error(codes.PermissionDenied, "not permitted"), "not permitted"},
		{"non-status-error", plainErr9142{}, "delegate exploded without a grpc status"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rr := clearWithDelegateErr9142(t, c.err)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("%s -> %d, want 500; body=%s", c.name, rr.Code, rr.Body.String())
			}
			// status.Convert on a NON-status error yields codes.Unknown with
			// the error's own text, so the default arm loses no information.
			if msg := errBody9142(t, rr); msg != c.want {
				t.Errorf("message = %q, want %q", msg, c.want)
			}
		})
	}
}

type plainErr9142 struct{}

func (plainErr9142) Error() string { return "delegate exploded without a grpc status" }
