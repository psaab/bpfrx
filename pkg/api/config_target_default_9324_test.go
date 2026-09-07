package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #9324: `GET /api/v1/config/show` fell through to the CANDIDATE when `?target`
// was absent, and `GET /api/v1/config/compare` — which can only render
// candidate-vs-something — was priced PermView with no selector at all.
//
// Measured at HEAD before the fix, with a session holding a staged edit:
//
//	REST show no ?target        -> "... security-zone SECRET-WIP-ZONE ..."
//	REST show ?target=active    -> "system { host-name COMMITTED-ACTIVE; }"
//	REST compare (no selector)  -> "+ security-zone SECRET-WIP-ZONE"
//	restReadPermissions[GET /api/v1/config/show]    = PermView
//	restReadPermissions[GET /api/v1/config/compare] = PermView
//
// Two failure modes, not one. DISCLOSURE: a view-only principal reads another
// session's uncommitted topology, zones, policies and address books (secrets are
// separately redacted, so this is not #4099). SILENT WRONG ANSWER: on an idle box
// the same call returns an EMPTY STRING, so a config-backup client written
// without `?target=active` archives either nothing or somebody's draft and
// cannot tell which.
//
// FAIL-ON-REVERT: restore the `default: ShowCandidateRedacted` arm and
// TestRESTConfigShowDefaultsToActive9324 goes RED.

const committedOnly9324 = `system { host-name COMMITTED-ACTIVE; }`
const stagedEdit9324 = `
system { host-name COMMITTED-ACTIVE; }
security { zones { security-zone SECRET-WIP-ZONE { host-inbound-traffic { system-services ssh; } } } }
`

// stagedStore9324 commits an active config and then stages an UNCOMMITTED edit,
// which is the state the whole issue is about.
func stagedStore9324(t *testing.T) *Server {
	t.Helper()
	store := authzStore(t, committedOnly9324)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("enter configure: %v", err)
	}
	if err := store.LoadOverride(stagedEdit9324); err != nil {
		t.Fatalf("stage the uncommitted edit: %v", err)
	}
	return &Server{store: store}
}

func showBody9324(t *testing.T, s *Server, url string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	s.configShowHandler(rr, httptest.NewRequest(http.MethodGet, url, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("%s -> %d: %s", url, rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Output string `json:"output"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return resp.Data.Output
}

func TestRESTConfigShowDefaultsToActive9324(t *testing.T) {
	s := stagedStore9324(t)

	got := showBody9324(t, s, "/api/v1/config/show")
	if strings.Contains(got, "SECRET-WIP-ZONE") {
		t.Fatalf("no ?target returned another session's uncommitted edit:\n%s", got)
	}
	if !strings.Contains(got, "COMMITTED-ACTIVE") {
		t.Fatalf("no ?target did not return the committed config:\n%s", got)
	}

	// POSITIVE CONTROL 1: the fixture really does hold a staged edit, so the
	// assertion above is about the default and not about an empty candidate.
	cand := showBody9324(t, s, "/api/v1/config/show?target=candidate")
	if !strings.Contains(cand, "SECRET-WIP-ZONE") {
		t.Fatalf("?target=candidate did not return the staged edit — the fixture stages nothing, "+
			"so the default-arm assertion above is vacuous:\n%s", cand)
	}

	// POSITIVE CONTROL 2: an explicit ?target=active is unchanged.
	act := showBody9324(t, s, "/api/v1/config/show?target=active")
	if strings.Contains(act, "SECRET-WIP-ZONE") || !strings.Contains(act, "COMMITTED-ACTIVE") {
		t.Fatalf("?target=active regressed:\n%s", act)
	}
	if act != got {
		t.Errorf("an absent target must render exactly what ?target=active renders:\nabsent=%q\nactive=%q", got, act)
	}
}

// Every format follows the same default — a per-format fall-through would leave
// the disclosure open on `?format=set` while the plain call looked fixed.
func TestRESTConfigShowDefaultsToActiveInEveryFormat9324(t *testing.T) {
	s := stagedStore9324(t)
	for _, f := range []string{"", "set", "json", "xml"} {
		url := "/api/v1/config/show"
		if f != "" {
			url += "?format=" + f
		}
		if got := showBody9324(t, s, url); strings.Contains(got, "SECRET-WIP-ZONE") {
			t.Errorf("format=%q leaked the staged edit with no ?target:\n%s", f, got)
		}
	}
}

// An unrecognised target must be REFUSED, not silently treated as one of them:
// falling through on `?target=activ` is the same fail-open shape as the default
// this issue is about.
func TestRESTConfigShowRejectsUnknownTarget9324(t *testing.T) {
	s := stagedStore9324(t)
	rr := httptest.NewRecorder()
	s.configShowHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config/show?target=activ", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("?target=activ -> %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "SECRET-WIP-ZONE") {
		t.Fatal("a typo'd target leaked the candidate")
	}
}

// The AUTHORIZATION half, driven through readAuthz — the guard itself, not the
// handler — so this binds the wiring rather than restating the table.
func runGuardedConfigRead9324(t *testing.T, s *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	connCtx := s.connContext(context.Background(), slotConn{
		client: tcpAddr6974("127.0.0.1", 40051),
		server: tcpAddr6974("127.0.0.1", 8080),
	})
	r := httptest.NewRequest(http.MethodGet, url, nil).WithContext(connCtx)
	rr := httptest.NewRecorder()
	ran := false
	s.readAuthz(rr, r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		writeOK(w, TextResponse{Output: "handler ran"})
	}))
	if ran && rr.Code != http.StatusOK {
		t.Fatalf("handler ran but status is %d", rr.Code)
	}
	return rr
}

// A read-only principal may read the ACTIVE config and may NOT read a candidate.
func TestReadOnlyPrincipalCannotReadTheCandidate9324(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242), // opsuser, class read-only
	})

	// REFERENCE ARM: the ordinary read is ADMITTED. Without it a fix that
	// refused every config read would satisfy the denial assertions below.
	if rr := runGuardedConfigRead9324(t, s, "/api/v1/config/show"); rr.Code != http.StatusOK {
		t.Fatalf("read-only was refused an ACTIVE config read (%d): %s", rr.Code, rr.Body.String())
	}
	if rr := runGuardedConfigRead9324(t, s, "/api/v1/config/show?target=active"); rr.Code != http.StatusOK {
		t.Fatalf("read-only was refused ?target=active (%d): %s", rr.Code, rr.Body.String())
	}

	if rr := runGuardedConfigRead9324(t, s, "/api/v1/config/show?target=candidate"); rr.Code != http.StatusForbidden {
		t.Errorf("read-only read the CANDIDATE: status %d, want 403", rr.Code)
	}
	// Case-insensitive: ?target=CANDIDATE selects the candidate in the handler
	// only if it matches there too, but the GUARD must not be bypassable by case.
	if rr := runGuardedConfigRead9324(t, s, "/api/v1/config/show?target=CANDIDATE"); rr.Code != http.StatusForbidden {
		t.Errorf("read-only bypassed the candidate gate with ?target=CANDIDATE: status %d, want 403", rr.Code)
	}
	if rr := runGuardedConfigRead9324(t, s, "/api/v1/config/compare"); rr.Code != http.StatusForbidden {
		t.Errorf("read-only read config/compare, which can only render work-in-progress: status %d, want 403", rr.Code)
	}
	// The rollback compare is the same route and equally candidate-based.
	if rr := runGuardedConfigRead9324(t, s, "/api/v1/config/compare?rollback=1"); rr.Code != http.StatusForbidden {
		t.Errorf("read-only read config/compare?rollback=1: status %d, want 403", rr.Code)
	}
}

// A super-user keeps every one of those reads — the gate prices the read, it
// does not remove it.
func TestSuperUserStillReadsTheCandidate9324(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4243), // adminuser, super-user
	})
	for _, u := range []string{
		"/api/v1/config/show",
		"/api/v1/config/show?target=active",
		"/api/v1/config/show?target=candidate",
		"/api/v1/config/compare",
	} {
		if rr := runGuardedConfigRead9324(t, s, u); rr.Code != http.StatusOK {
			t.Errorf("super-user refused %s: status %d, body=%s", u, rr.Code, rr.Body.String())
		}
	}
}

// AUDITED BENIGN, recorded so the verdict is not re-derived: show-rollback reads
// the committed ROLLBACK ARCHIVE (ShowRollbackRedacted -> rollbackEntry), not
// s.candidate, so it discloses no work-in-progress and keeps PermView. export
// always renders ACTIVE and is the in-tree precedent for the new default.
func TestRollbackAndExportReadsStayViewPriced9324(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
	})
	for _, u := range []string{"/api/v1/config/show-rollback", "/api/v1/config/export"} {
		if rr := runGuardedConfigRead9324(t, s, u); rr.Code == http.StatusForbidden {
			t.Errorf("%s became forbidden for read-only; it reads committed state only", u)
		}
	}
}
