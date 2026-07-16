// #5882: the REST session-clear endpoint's local-only fallback drives a
// chunked clear-all (ClearAllSessions) that is NON-atomic — it clears the IPv4
// table then the IPv6 table, so a failure can leave IPv4 already deleted while
// returning PARTIAL v4/v6 counts alongside the error. The fallback must surface
// those partial counts (HTTP 200 body with Failures>0 / FailureSummary) rather
// than discarding them behind a bare HTTP 500, mirroring the gRPC clear-all
// branch and the HA-delegated path.
//
// FAIL-ON-REVERT: restoring `writeError(w, 500, err.Error())` makes the request
// return 500 with no body counts, flipping the want-200 / partial-count / non-
// empty-failure-summary assertions RED.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// clearAllPartialDP returns partial counts + an error, modeling a chunked
// clear-all that cleared IPv4 then failed clearing IPv6.
type clearAllPartialDP struct {
	*dataplane.Manager
}

func (d *clearAllPartialDP) IsLoaded() bool { return true }
func (d *clearAllPartialDP) ClearAllSessions() (int, int, error) {
	return 4, 0, fmt.Errorf("ipv6 chunk delete EIO")
}

func TestRESTClearSessionsPartialCountsSurvive(t *testing.T) {
	// clusterSessionFn unset -> clusterSession() nil -> the local-only
	// ClearAllSessions fallback (the path #5882 fixes).
	dp := &clearAllPartialDP{Manager: dataplane.New()}
	s := &Server{dp: dp}

	rr := httptest.NewRecorder()
	s.clearSessionsHandler(rr, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))

	// #5882: a partial clear-all is a reported partial success (200), not a
	// bare 500 that discards what was actually revoked.
	if rr.Code != http.StatusOK {
		t.Fatalf("clear status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	// writeOK wraps the payload in {"success":true,"data":{...}}.
	var env struct {
		Data ClearSessionsResult `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode body %q: %v", rr.Body.String(), err)
	}
	got := env.Data
	if got.IPv4Cleared != 4 {
		t.Fatalf("IPv4Cleared=%d, want 4 (V4 cleared before V6 failed)", got.IPv4Cleared)
	}
	if got.IPv6Cleared != 0 {
		t.Fatalf("IPv6Cleared=%d, want 0", got.IPv6Cleared)
	}
	if got.Failures == 0 {
		t.Fatalf("clear-all failure not reported: Failures=0, summary=%q", got.FailureSummary)
	}
	if got.FailureSummary == "" {
		t.Fatalf("empty FailureSummary on a partial clear-all failure")
	}
}
