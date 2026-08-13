package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// authz_bodybudget_5561_test.go guards what the gate's body window may COST
// (#5561 round 10, finding 2): per route, and — the half a per-request cap
// cannot express — in aggregate across every request in flight.
//
// The raw-socket helpers these cases drive (openDeclaredBody, readStatus) live
// in authz_bodywindow_5561_test.go alongside the freshness half of the same
// window.

// waitForAdmittedToSettle blocks until the gate's aggregate reservation reaches
// want, so a case that measures the budget is not reading another case's
// in-flight requests.
func waitForAdmittedToSettle(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if MutationBodyBytesAdmittedForTest() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the gate's aggregate body reservation never settled to %d (now %d)",
		want, MutationBodyBytesAdmittedForTest())
}

// TestGateBodyBufferIsBoundedInAggregate_5561 is the AGGREGATE bound, driven
// on the route with the largest per-request ceiling.
//
// A per-request ceiling says nothing about how many requests a caller opens,
// and the gate holds each buffer for as long as that caller takes to finish
// sending — up to apiReadTimeout (30s), entirely the caller's choice. So an
// authorized principal could pin ceiling x N bytes of daemon heap with N
// sockets and never complete a request: at the 16 MiB whole-configuration
// ceiling, 64 sockets is a gigabyte. That is precisely the availability
// property the two-pass gate is justified by — pass 1 exists so only an
// authorized principal can make the daemon hold a buffer — reinstated at the
// dimension authorization does not bound.
//
// The flood sends REAL bytes, because that is what the budget counts: since
// round 11 a reservation is the memory a request has allocated, not the
// Content-Length it announced (authz_bodybudget_fairness_5561_test.go owns
// that half). Each socket delivers a megabyte of a declared 16 MiB body and
// then stalls, so it holds a megabyte and is charged for a megabyte.
//
// Both halves are asserted:
//
//   - the admitted total never exceeds mutationBodyBudgetBytes, and
//   - the excess is REFUSED (429) rather than admitted to buffer, which is the
//     observable behaviour that says the ceiling is enforced rather than merely
//     measured.
//
// The control keeps it from passing for the wrong reason: some of the burst
// must get in, so a bound that refuses everything is not mistaken for a bound.
func TestGateBodyBufferIsBoundedInAggregate_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})

	const route = "POST /api/v1/config/load"
	declared := int(mutationBodyLoad) // the largest a single route may cost

	waitForAdmittedToSettle(t, 0)

	// A megabyte per socket, and enough sockets that their real bytes exceed
	// the whole budget. `{"content":"` opens a JSON string the caller never
	// closes, so the body is well-formed as far as it goes and the request is
	// waiting on its caller rather than on a parse error.
	const perSocket = 1 << 20
	sent := `{"content":"` + strings.Repeat("a", perSocket-12)
	n := int(MutationBodyBudgetForTest()/perSocket) + 8

	parked, refused := floodDeclaredBodies(t, base, route, n, declared, sent)
	peak := MutationBodyBytesAdmittedForTest()

	if peak > MutationBodyBudgetForTest() {
		t.Fatalf("the gate admitted %d bytes of request body at once against a budget of %d — "+
			"the aggregate the whole bound exists to cap is not capped", peak,
			MutationBodyBudgetForTest())
	}
	if refused == 0 {
		t.Fatalf("%d concurrent requests each holding %d body bytes were ALL admitted to buffer "+
			"(parked=%d, reserved=%d) against a budget of %d. The gate holds each buffer for as "+
			"long as its caller takes to finish sending, so an authorized principal pins "+
			"ceiling x N bytes of daemon heap with N sockets and never completes a request",
			n, perSocket, parked, peak, MutationBodyBudgetForTest())
	}
	// And the refusal is admission control, not a wedge: some requests DID get in.
	if parked == 0 {
		t.Fatalf("every one of %d requests was refused — the budget is rejecting requests it "+
			"has room for, which is an availability regression rather than a bound", n)
	}
}

// TestPerRouteBodyLimitIsEnforced_5561 pins the per-route half: a route whose
// legitimate payload is a handful of scalars must not accept — or buffer — the
// whole-configuration ceiling. Without per-route limits the surface's CHEAPEST
// permission reserves in the same units as its most privileged one, so a
// `read-only` account crowds the aggregate budget out from under the
// configure-authorized commits that budget exists to keep serving.
func TestPerRouteBodyLimitIsEnforced_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		// opsuser is `read-only`: PermView, which /diagnostics/ping requires.
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})

	waitForAdmittedToSettle(t, 0)

	// A body one byte past the diagnostics ceiling, sent in full.
	over := int(mutationBodySmall) + 1
	body := `{"target":"` + strings.Repeat("a", over-13) + `"}`
	if len(body) != over {
		t.Fatalf("probe body is %d bytes, want %d", len(body), over)
	}
	conn := openDeclaredBody(t, base, "POST /api/v1/diagnostics/ping", over, body, nil)
	status, got := readStatus(t, conn, 10*time.Second)
	if !got {
		t.Fatal("POST /api/v1/diagnostics/ping never answered an oversized body")
	}
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a %d-byte body on /diagnostics/ping got %d, want 413. The route's ceiling "+
			"is %d bytes; accepting the whole-configuration ceiling here lets the cheapest "+
			"permission on the surface reserve in a configure-tier unit",
			over, status, mutationBodySmall)
	}

	// Control: a legitimate payload on the same route is NOT refused by the
	// ceiling, so the assertion above is about SIZE and not about the route. An
	// empty target is the handler's own fast 400, which keeps the control off
	// the exec path.
	small := `{"target":""}`
	ok := openDeclaredBody(t, base, "POST /api/v1/diagnostics/ping", len(small), small, nil)
	status, got = readStatus(t, ok, 10*time.Second)
	if !got {
		t.Fatal("the CONTROL ping never answered")
	}
	if status == http.StatusRequestEntityTooLarge || status == http.StatusTooManyRequests {
		t.Fatalf("a %d-byte ping was refused %d — the ceiling is rejecting legitimate "+
			"payloads", len(small), status)
	}
}

// TestEveryGuardedRouteDeclaresABodyLimit_5561 keeps the two route tables in
// lockstep. restMutationPermissions is the ALLOW-list a mutating route must
// appear in to run at all; restMutationBodyLimits is what that route may cost
// while its caller decides when to finish. A route present in the first and
// absent from the second falls back to the TIGHTEST cap rather than the
// largest, so an omission cannot fail open — but it is still an omission, and
// silently capping a new whole-configuration route at 64 KiB is its own defect.
func TestEveryGuardedRouteDeclaresABodyLimit_5561(t *testing.T) {
	for route := range restMutationPermissions {
		if _, ok := restMutationBodyLimits[route]; !ok {
			t.Errorf("route %q is authorized by restMutationPermissions but declares no body "+
				"limit. Add it to restMutationBodyLimits: how much of the caller's body the "+
				"gate will hold, for how many callers at once, is part of the route's "+
				"contract", route)
		}
	}
	for route := range restMutationBodyLimits {
		if _, ok := restMutationPermissions[route]; !ok {
			t.Errorf("route %q declares a body limit but is not in restMutationPermissions, "+
				"so it is DENIED and the limit is dead. Remove it or add the permission",
				route)
		}
	}
}
