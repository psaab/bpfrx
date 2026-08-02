package api

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// authz_bodybudget_fairness_5561_test.go guards the OTHER direction of the
// availability property the gate's body window has to hold (#5561 round 11).
//
// authz_bodybudget_5561_test.go pins the bound: the daemon's heap must not be a
// function of how many sockets a caller opens. A bound alone is not the whole
// property, though, because a bound is a shared resource and a shared resource
// is a denial lever. Round 10's budget was denominated in DECLARED bytes and
// held for the request's whole lifetime, so a caller that declared 64 KiB and
// sent one byte bought 64 KiB of the budget for one byte of traffic — and the
// budget was one undivided pool, so those bytes came out of the share a
// configure-authorized commit needed. The cheapest permission on the surface
// could 429 the most expensive one off it for about a kilobyte of traffic.
//
// So the window is bounded in two ways that have to hold SIMULTANEOUSLY:
//
//	no unbounded memory      — authz_bodybudget_5561_test.go
//	no cheap cross-privilege denial — here
//
// The cases below take that second property apart: what a request is CHARGED
// (bytes it actually holds, not bytes it promised), who its charge can DENY
// (nobody above its own tier) under a cheap flood and under an expensive one,
// the shape of the tier ladder itself, and — since a charge that is never
// returned denies just as effectively — that every exit path gives it back.

// floodDeclaredBodies opens n requests on `route` that each declare `declared`
// bytes and send `sent`, then returns once every one of them has either parked
// inside the gate or been answered. The connections stay open until the case
// ends (openDeclaredBody registers the close), so the reservations they hold —
// whatever the gate decides those are — are live for every assertion below.
func floodDeclaredBodies(t *testing.T, base, route string, n, declared int, sent string) (parked, refused int) {
	t.Helper()
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for i := 0; i < n; i++ {
		conn := openDeclaredBody(t, base, route, declared, sent, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A request admitted to the window parks: it is waiting for a body
			// its caller is never going to finish, so no status arrives. A
			// refused one answers 429 immediately.
			status, got := readStatus(t, conn, 3*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if got && status == http.StatusTooManyRequests {
				refused++
				return
			}
			parked++
		}()
	}
	wg.Wait()
	return parked, refused
}

// TestHalfOpenBodyIsChargedForWhatItHoldsNotWhatItDeclared_5561 pins the
// DENOMINATION of the aggregate budget.
//
// A Content-Length is a promise, not memory. The gate holds a buffer that grows
// as the bytes actually arrive, so a caller that declares a route's whole
// ceiling and sends one byte makes the daemon hold one small allocation — and a
// budget that bounds MEMORY has to charge that, not the declaration. Charging
// the declaration is what turned the bound into a lever: at 64 KiB declared per
// socket and one byte sent, a `read-only` account bought the entire budget with
// about a kilobyte of traffic and held it for the full 30s read timeout,
// renewably.
//
// The assertion is the amplification factor itself: what the flood is charged,
// against what it declared. It deliberately does not name an exact per-request
// cost — the growth schedule is an implementation detail — only that a request
// which has delivered one byte cannot be charged in the units of a request that
// delivered its whole declaration.
func TestHalfOpenBodyIsChargedForWhatItHoldsNotWhatItDeclared_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		// opsuser is `read-only`: PermView, which /diagnostics/ping requires —
		// the cheapest permission on the surface, which is the population the
		// per-principal bound exists to constrain.
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})

	waitForAdmittedToSettle(t, 0)

	const (
		n        = 64
		declared = int(mutationBodySmall) // the route's whole ceiling
	)
	parked, refused := floodDeclaredBodies(t, base, "POST /api/v1/diagnostics/ping", n, declared, "{")
	if parked == 0 {
		t.Fatalf("none of the %d half-open requests parked in the gate (refused=%d) — the case "+
			"never reached the window it measures", n, refused)
	}

	charged := MutationBodyBytesAdmittedForTest()
	promised := int64(n) * int64(declared)
	// One page per parked request is generous for a body that delivered a
	// single byte, and is two orders of magnitude under the declaration.
	if allowed := int64(parked) * 4096; charged > allowed {
		t.Fatalf("%d requests that each DECLARED %d bytes and sent 1 are charged %d bytes of "+
			"the aggregate budget (promised %d, a reasonable ceiling for what they actually "+
			"hold is %d). A budget denominated in declared bytes is bought at %dx the memory "+
			"it stands for, so a caller with the cheapest permission on the surface fills it "+
			"with a kilobyte of traffic and 429s every mutating route for the read timeout",
			parked, declared, charged, promised, allowed, promised/max64(charged, 1))
	}
}

// max64 keeps the diagnostic above from dividing by zero.
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// TestLowPrivilegeCallerCannotDenyAPrivilegedOne_5561 pins who a charge can
// DENY.
//
// The budget is one process-wide counter — that global IS the shared resource
// under test — so the question a bound has to answer is not only "how much"
// but "whose". Round 10's answer was "whoever asks first", which across a
// privilege boundary is a denial primitive: /diagnostics/ping is PermView, the
// permission a `read-only` shell account holds, and /config/set is PermConfig,
// which it does not. A view-tier flood that consumed the undivided budget made
// the configure-tier request that the budget exists to keep serving answer 429.
//
// The two listeners exist only to give the two principals distinct peer
// attributions; production serves both from one listener, and the counter they
// contend for is the same package-level global either way.
//
// The flood here is the cheap shape the finding named — declare the ceiling,
// send one byte — so this case ALSO fails if the denomination regresses. The
// case above is the one that isolates that half.
func TestLowPrivilegeCallerCannotDenyAPrivilegedOne_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, viewBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})
	_, superBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})

	waitForAdmittedToSettle(t, 0)

	// Enough sockets to have filled round 10's whole budget at its declared
	// rate, which is what the finding measured. Every one of them sends a
	// single byte.
	declared := int(mutationBodySmall)
	n := int(MutationBodyBudgetForTest()/int64(declared)) + 8
	parked, refused := floodDeclaredBodies(t, viewBase, "POST /api/v1/diagnostics/ping", n, declared, "{")
	if parked == 0 {
		t.Fatalf("none of the %d view-tier requests parked in the gate (refused=%d) — the case "+
			"never established the state it asserts against", n, refused)
	}

	// Now the privileged caller, on a route the flood's principal cannot even
	// reach. A complete, valid, tiny body: nothing about this request is
	// expensive, and the only thing between it and its handler is the budget.
	body := `{"input":"set system host-name r11"}`
	conn := openDeclaredBody(t, superBase, "POST /api/v1/config/set", len(body), body, nil)
	status, got := readStatus(t, conn, 10*time.Second)
	if !got {
		t.Fatal("the privileged request never answered")
	}
	if status == http.StatusTooManyRequests {
		t.Fatalf("a super-user's POST /api/v1/config/set was refused %d while %d half-open "+
			"PermView requests (%d bytes of traffic in total) held the gate's body budget. A "+
			"`read-only` account can 429 the configure tier off the whole mutating surface "+
			"for the read timeout, renewably — a denial the two-pass gate did not have before "+
			"the budget was added, and the opposite of the availability property it exists for",
			status, parked, parked)
	}
}

// TestViewTierSaturationLeavesHeadroomForTheConfigureTier_5561 pins the
// arbitration itself, with the view tier saturated by bytes it really sent.
//
// The case above shows a CHEAP flood cannot deny. This one shows an EXPENSIVE
// one cannot either: the view tier is driven to its own ceiling with real
// traffic — every request delivers all but the last byte of its declaration —
// and the assertion is that the ceiling it hits is strictly below the budget,
// with at least a whole-configuration load still free behind it. That headroom
// is the thing a configure-tier caller is guaranteed, and no amount of
// view-tier traffic can take it.
//
// The refusals are the load-bearing assertion: they say the view tier is capped
// somewhere, and the peak says it is capped low enough. An undivided budget
// produces neither — it simply admits view-tier traffic until the whole 64 MiB
// is gone.
func TestViewTierSaturationLeavesHeadroomForTheConfigureTier_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, viewBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})
	_, superBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})

	waitForAdmittedToSettle(t, 0)

	// Declare the route ceiling and send all but the final byte, so the gate
	// really is holding what it is charged for. 400 sockets is 25 MiB of body:
	// comfortably past any share the view tier can be given, comfortably short
	// of the whole budget, so a case that sees no refusals has learned that the
	// budget is undivided rather than that the flood was too small.
	const n = 400
	declared := int(mutationBodySmall)
	sent := strings.Repeat("a", declared-1)
	parked, refused := floodDeclaredBodies(t, viewBase, "POST /api/v1/diagnostics/ping", n, declared, sent)
	peak := MutationBodyBytesAdmittedForTest()

	headroom := MutationBodyBudgetForTest() - mutationBodyLoad
	if refused == 0 {
		t.Fatalf("%d view-tier requests holding %d body bytes each were ALL admitted (parked=%d, "+
			"reserved=%d of a %d budget). The budget is one undivided pool, so the view tier can "+
			"walk it up to the last byte and the configure tier gets whatever is left — which "+
			"across a privilege boundary is a denial primitive, not a bound",
			n, declared, parked, peak, MutationBodyBudgetForTest())
	}
	if peak > headroom {
		t.Fatalf("view-tier traffic reserved %d bytes, past the %d that must stay free for the "+
			"configure tier (budget %d less one whole-configuration load, %d). A share the view "+
			"tier can reach into is not a guarantee", peak, headroom,
			MutationBodyBudgetForTest(), int64(mutationBodyLoad))
	}
	if parked == 0 {
		t.Fatalf("every one of %d view-tier requests was refused — the view tier's share is too "+
			"small to serve its own routes, which is an availability regression rather than a "+
			"bound", n)
	}

	// And with the view tier at its ceiling, the configure tier is still served.
	body := `{"input":"set system host-name r11"}`
	conn := openDeclaredBody(t, superBase, "POST /api/v1/config/set", len(body), body, nil)
	status, got := readStatus(t, conn, 10*time.Second)
	if !got {
		t.Fatal("the privileged request never answered")
	}
	if status == http.StatusTooManyRequests {
		t.Fatalf("a super-user's POST /api/v1/config/set was refused %d with the view tier at "+
			"its ceiling (%d bytes reserved). The headroom is reserved but not honoured",
			status, peak)
	}
}

// TestBodyBudgetReservationIsReleasedOnEveryExitPath_5561 binds the RELEASE.
//
// The gate defers the release for the whole request, so every exit path — the
// handler returning, the caller hanging up mid-body, the body overrunning the
// route ceiling — has to give the bytes back. Nothing asserted that directly:
// dropping the release left the aggregate test green in isolation and was
// caught only by whichever unrelated case ran next against a poisoned global,
// which is a guard by accident. Each row below drives one exit path and
// asserts the budget is whole again afterwards.
func TestBodyBudgetReservationIsReleasedOnEveryExitPath_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})

	waitForAdmittedToSettle(t, 0)

	t.Run("handler ran to completion", func(t *testing.T) {
		body := `{"target":""}` // the handler's own fast 400, off the exec path
		conn := openDeclaredBody(t, base, "POST /api/v1/diagnostics/ping", len(body), body, nil)
		if _, got := readStatus(t, conn, 10*time.Second); !got {
			t.Fatal("the completed request never answered")
		}
		waitForAdmittedToSettle(t, 0)
	})

	t.Run("caller hung up mid-body", func(t *testing.T) {
		conn := openDeclaredBody(t, base, "POST /api/v1/diagnostics/ping", int(mutationBodySmall), "{", nil)
		waitForMutationBodyWaiter(t)
		// Abort: the gate's read fails and the handler never runs.
		if err := conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		waitForAdmittedToSettle(t, 0)
	})

	t.Run("body overran the route ceiling", func(t *testing.T) {
		over := int(mutationBodySmall) + 1
		body := `{"target":"` + strings.Repeat("a", over-13) + `"}`
		conn := openDeclaredBody(t, base, "POST /api/v1/diagnostics/ping", over, body, nil)
		status, got := readStatus(t, conn, 10*time.Second)
		if !got {
			t.Fatal("the oversized request never answered")
		}
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("got %d, want 413 — the row did not drive the exit path it names", status)
		}
		waitForAdmittedToSettle(t, 0)
	})
}

// TestEveryGuardedRouteDeclaresABodyTier_5561 keeps the tier ladder covering
// the routes it arbitrates between.
//
// mutationBodyTierCeiling falls back to the SMALLEST share for a permission it
// does not know, which is the right direction to fail — an unconsidered route
// cannot starve a considered one — but it is still a route whose share nobody
// chose. A new mutating permission should be placed on the ladder deliberately.
func TestEveryGuardedRouteDeclaresABodyTier_5561(t *testing.T) {
	for route, required := range restMutationPermissions {
		if _, ok := mutationBodyTierCeilings[required]; !ok {
			t.Errorf("route %q requires permission %q, which declares no share of the gate's "+
				"body budget. Add it to mutationBodyTierCeilings: how much of the aggregate a "+
				"route may drive, and therefore which tiers it can and cannot deny, is part of "+
				"the route's contract", route, authz.PermissionName(required))
		}
	}
}

// TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561 pins the shape of
// the ladder itself, independent of any traffic.
//
// The point of tiering is not that the shares differ; it is that the difference
// is USEFUL — that what a lower tier can take still leaves the higher tiers
// enough to do their largest legitimate job. So the assertions are stated in
// the units of the work being protected: whatever the view/clear tiers consume,
// a whole-configuration load must still fit behind it, and whatever the
// configure tier consumes, the maintenance verbs must still fit behind that.
//
// A ladder that is merely monotonic can still be useless — three tiers at 63,
// 63.5 and 64 MiB order correctly and protect nothing.
func TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561(t *testing.T) {
	budget := MutationBodyBudgetForTest()

	view := mutationBodyTierCeiling(config.PermView)
	clear := mutationBodyTierCeiling(config.PermClear)
	configure := mutationBodyTierCeiling(config.PermConfig)
	maint := mutationBodyTierCeiling(config.PermMaint)

	// No tier may exceed the aggregate: the ladder divides the bound, it does
	// not raise it.
	for _, tc := range []struct {
		name    string
		ceiling int64
	}{{"view", view}, {"clear", clear}, {"configure", configure}, {"maint", maint}} {
		if tc.ceiling > budget {
			t.Errorf("the %s tier may drive the aggregate to %d, past the %d-byte budget — a "+
				"share larger than the whole is not a share", tc.name, tc.ceiling, budget)
		}
	}

	// What the operational tiers cannot reach must still hold a configuration.
	for _, tc := range []struct {
		name    string
		ceiling int64
	}{{"view", view}, {"clear", clear}} {
		if free := budget - tc.ceiling; free < mutationBodyLoad {
			t.Errorf("the %s tier may drive the aggregate to %d of %d, leaving %d — less than "+
				"the %d a single whole-configuration load needs. A `read-only` account can then "+
				"make POST /api/v1/config/load answer 429, which is the cross-privilege denial "+
				"the ladder exists to remove", tc.name, tc.ceiling, budget, free,
				int64(mutationBodyLoad))
		}
	}

	// And what the configure tier cannot reach must still hold the destructive
	// verbs, whose payload is one action word.
	if free := budget - configure; free < mutationBodySmall {
		t.Errorf("the configure tier may drive the aggregate to %d of %d, leaving %d — less "+
			"than the %d POST /api/v1/system/action's own ceiling needs, so a configure-tier "+
			"caller can deny the maintenance tier", configure, budget, free,
			int64(mutationBodySmall))
	}
}
