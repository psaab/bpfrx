package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #5870: the REST config MUTATION endpoints must run under a NON-empty session
// identity that participates in the shared-candidate holder lock. Before the
// fix they called the store with an empty session ID, which the store treats as
// its internal/system capability and which BYPASSES the holder lock — so a
// stateless REST caller could Set/Delete/Commit the candidate a CLI or gRPC
// configuration session legitimately OWNED, corrupting or smuggling changes into
// another operator's session.
//
// These tests go RED if the REST handlers pass an empty identity: the empty
// value re-enables the store's system bypass, so the rejected mutations
// wrongly succeed and stomp / smuggle the held candidate.

// TestRESTConfigSetDeleteRejectedWhenOtherSessionHoldsCandidate simulates a
// CLI/gRPC session holding the candidate (a non-empty session acquires the lock
// and stages an edit), then asserts a REST set AND a REST delete are rejected
// with a holder conflict and the held candidate is left untouched.
func TestRESTConfigSetDeleteRejectedWhenOtherSessionHoldsCandidate(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	const cliSession = "cli-session-1"
	if err := store.EnterConfigureSession(cliSession); err != nil {
		t.Fatalf("EnterConfigureSession(%q): %v", cliSession, err)
	}
	// The holder stages an edit into the shared candidate.
	if err := store.SetFromInputAs(cliSession, "system host-name held-by-cli"); err != nil {
		t.Fatalf("held-session SetFromInputAs: %v", err)
	}
	before := store.ShowCandidateSet()

	s := &Server{store: store}

	// A REST set targeting the same subtree must be rejected — REST is not the
	// holder — with 409 Conflict (ErrConfigLockedByOther).
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/set",
		strings.NewReader(`{"input":"system host-name stomped-by-rest"}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configSetHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("REST set while CLI holds candidate: status = %d, want 409; body: %s",
			rr.Code, rr.Body.String())
	}

	// A REST delete of the held node must likewise be rejected.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/v1/config/delete",
		strings.NewReader(`{"input":"system host-name"}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configDeleteHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("REST delete while CLI holds candidate: status = %d, want 409; body: %s",
			rr.Code, rr.Body.String())
	}

	// The held session's candidate is byte-for-byte unchanged by the rejected
	// REST mutations.
	after := store.ShowCandidateSet()
	if after != before {
		t.Fatalf("REST mutation stomped the held candidate:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if strings.Contains(after, "stomped-by-rest") {
		t.Fatalf("REST set smuggled a node into the held candidate:\n%s", after)
	}
	if !strings.Contains(after, "held-by-cli") {
		t.Fatalf("REST delete removed the held session's staged node:\n%s", after)
	}
}

// TestRESTConfigCommitRejectedWhenOtherSessionHoldsCandidate asserts a REST
// commit is rejected — and the daemon commit callback is NEVER invoked — while
// a CLI/gRPC session owns the candidate with staged edits. This is the
// commit-smuggling facet of #5870: without the holder gate, a stateless REST
// commit would apply another operator's pending work.
func TestRESTConfigCommitRejectedWhenOtherSessionHoldsCandidate(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	const cliSession = "cli-session-1"
	if err := store.EnterConfigureSession(cliSession); err != nil {
		t.Fatalf("EnterConfigureSession(%q): %v", cliSession, err)
	}
	if err := store.SetFromInputAs(cliSession, "system host-name staged-by-cli"); err != nil {
		t.Fatalf("held-session SetFromInputAs: %v", err)
	}

	var commitCalled bool
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			commitCalled = true
			return store.Commit()
		},
	}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
	s.configCommitHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("REST commit while CLI holds candidate: status = %d, want 409; body: %s",
			rr.Code, rr.Body.String())
	}
	if commitCalled {
		t.Fatalf("REST commit smuggled the CLI session's staged edits into an applied commit " +
			"(commitFn was invoked despite a non-holder REST caller)")
	}
}

// TestRESTConfigMutationAllowedAndHoldsLock asserts the REST path works normally
// when no other session holds the candidate (REST enter acquires the lock, REST
// set applies), AND that REST then genuinely PARTICIPATES as the holder: a
// foreign CLI/gRPC session is rejected while REST owns the candidate (the
// symmetric half of the holder contract).
func TestRESTConfigMutationAllowedAndHoldsLock(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}

	// REST enters config mode under its own server-generated identity.
	sessionID := enterRESTConfigSession(t, s, "")

	// REST set succeeds — REST is the holder.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/set",
		strings.NewReader(`{"input":"system host-name rest-owned"}`))
	withRESTConfigSession(req, sessionID)
	s.configSetHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("REST set as holder: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "rest-owned") {
		t.Fatalf("REST set did not apply to the candidate:\n%s", out)
	}

	// A foreign CLI/gRPC session must now be rejected — REST owns the candidate.
	err := store.SetFromInputAs("cli-foreign", "system host-name cli-stomp")
	if err == nil {
		t.Fatal("foreign CLI set succeeded while REST holds the candidate; " +
			"REST is not participating in the holder lock")
	}
	if !errors.Is(err, configstore.ErrConfigLockedByOther) {
		t.Fatalf("foreign CLI set error = %v; want ErrConfigLockedByOther", err)
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "cli-stomp") {
		t.Fatalf("foreign CLI set stomped the REST-held candidate:\n%s", out)
	}
}
