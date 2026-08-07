package api

import (
	"net/http"
	"sort"
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

// saturateViewTier drives the aggregate budget to the VIEW tier's ceiling and
// returns the peak it settled at.
//
// "To its ceiling" is established by observation rather than by arithmetic: the
// bulk phase gets close with route-ceiling declarations, and then the top-up
// phase adds requests in single-initial-buffer granules until a round of them
// is REFUSED. A refusal is the only externally visible proof that the tier is
// genuinely FULL — that the next charge of mutationBodyInitialBuf will not fit
// — as opposed to merely busy, and a case that asserts what a full view tier
// can and cannot deny has to start from full or it asserts nothing.
func saturateViewTier(t *testing.T, base string) int64 {
	t.Helper()

	// Bulk: 400 sockets each declaring the route's whole ceiling and sending
	// all but the last byte, so each admitted one really holds what it is
	// charged for. 25 MiB of declared body is past any share the view tier can
	// be given and short of the whole budget.
	floodDeclaredBodies(t, base, "POST /api/v1/diagnostics/ping",
		400, int(mutationBodySmall), strings.Repeat("a", int(mutationBodySmall)-1))

	// Top-up. A socket that sends ONE byte parks holding exactly
	// mutationBodyInitialBuf: the read loop takes the byte, the buffer is not
	// full, and the next read blocks on a caller that will never continue. So
	// each round below closes the remaining gap in 512-byte steps, and the
	// round that reports a refusal is the one that hit the wall.
	for round := 0; round < 8; round++ {
		_, refused := floodDeclaredBodies(t, base, "POST /api/v1/diagnostics/ping",
			256, int(mutationBodySmall), "{")
		if refused > 0 {
			return MutationBodyBytesAdmittedForTest()
		}
	}
	t.Fatalf("the view tier never refused a request after %d bulk and 2048 top-up sockets "+
		"(admitted=%d of a %d budget) — the case never reached the saturated state it "+
		"asserts from", 400, MutationBodyBytesAdmittedForTest(), MutationBodyBudgetForTest())
	return 0
}

// TestViewTierFloodCannotDenyTheClearTier_5561 binds the step of the ladder
// that separates a `read-only` account from an `operator`'s clear verbs
// (#5561 round 18, finding 1).
//
// Round 11 gave view, clear and control the SAME share and tested each ceiling
// against the AGGREGATE. Equal shares plus an aggregate test is not a ladder
// between those three: whatever the view tier takes is subtracted from what the
// clear tier can reach, so a view tier driven to its own ceiling leaves the
// clear tier exactly nothing. `read-only` holds PermView; `operator` holds
// PermView, PermClear and PermControl (config.LoginClassPermissions), so clear
// is strictly the higher privilege — and 383 sockets from a read-only shell
// account on POST /api/v1/diagnostics/ping made a super-user's 24-byte
// POST /api/v1/dhcp/identifiers/clear answer 429.
//
// That is the exact denial primitive the ladder exists to remove, and it was
// CREATED by the round-11 tier split rather than inherited: before the split
// there was no budget to exhaust. TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561
// did not catch it because it tested view and clear EACH against the configure
// tier's work and never against each other.
//
// The flood is driven from the read-only account and the clear request from a
// super-user, so the case is a genuine cross-privilege one rather than an
// account denying itself.
func TestViewTierFloodCannotDenyTheClearTier_5561(t *testing.T) {
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
	peak := saturateViewTier(t, viewBase)

	// The one clear-tier route that carries a body. The other two clear verbs
	// are mutationBodyNone and are never charged at all, so this route is the
	// whole blast radius — and it is enough, because a route that cannot be
	// reached is a denied route.
	body := `{"interface":"ge-0-0-0"}`
	conn := openDeclaredBody(t, superBase, "POST /api/v1/dhcp/identifiers/clear", len(body), body, nil)
	status, got := readStatus(t, conn, 10*time.Second)
	if !got {
		t.Fatal("the clear-tier request never answered")
	}
	if status == http.StatusTooManyRequests {
		t.Fatalf("a super-user's POST /api/v1/dhcp/identifiers/clear was refused %d with the "+
			"VIEW tier at its ceiling (%d of %d bytes reserved, view ceiling %d, clear ceiling "+
			"%d). A `read-only` account holding only PermView can therefore deny the clear "+
			"verbs an `operator` holds — the ladder gives clear no share the view tier cannot "+
			"reach into", status, peak, MutationBodyBudgetForTest(),
			mutationBodyTierCeiling(config.PermView), mutationBodyTierCeiling(config.PermClear))
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
//
// Round 18 added the general form below. The two explicit blocks that follow it
// state the two steps by hand and are why finding 1 survived: they check view
// and clear EACH against the CONFIGURE tier's work and never against each
// other, so the view==clear step — a real privilege step, `read-only` versus
// `operator` — was outside every loop.
func TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561(t *testing.T) {
	budget := MutationBodyBudgetForTest()

	// EVERY privilege step, derived — not a restatement of the constants.
	//
	// Both inputs come out of production tables. The ORDER comes from
	// config.LoginClassPermissions through the production evaluator: p is
	// strictly less privileged than q when every class holding q also holds p
	// and some class holds p without q (`read-only` holds view without clear,
	// so view < clear; nothing distinguishes clear from control, so they are
	// incomparable and neither has to reserve for the other). The SIZE comes
	// from restMutationPermissions x restMutationBodyLimits: the largest body
	// any route in the higher tier can legitimately carry.
	//
	// The requirement joins them: because each ceiling is tested against the
	// AGGREGATE, tier q is protected from tier p only if q's ceiling stands
	// above p's by at least one whole q-sized request. A gap of zero is no
	// protection at all, which is precisely what equal shares gave.
	ladder := make([]config.LoginClassPermission, 0, len(mutationBodyTierCeilings))
	for perm := range mutationBodyTierCeilings {
		ladder = append(ladder, perm)
	}
	sort.Slice(ladder, func(i, j int) bool { return ladder[i] < ladder[j] })

	largestBody := map[config.LoginClassPermission]int64{}
	for route, required := range restMutationPermissions {
		if n := mutationBodyLimit(route); n > largestBody[required] {
			largestBody[required] = n
		}
	}
	strictlyBelow := func(p, q config.LoginClassPermission) bool {
		var someClassSeparates bool
		for class := range config.LoginClassPermissions {
			hasP := config.ClassHasPermission(nil, class, p)
			hasQ := config.ClassHasPermission(nil, class, q)
			if hasQ && !hasP {
				return false // a class holds q without p: q is not the higher one
			}
			if hasP && !hasQ {
				someClassSeparates = true
			}
		}
		return someClassSeparates
	}
	for _, low := range ladder {
		for _, high := range ladder {
			if low == high || !strictlyBelow(low, high) {
				continue
			}
			// A tier with no body-carrying route has nothing to reserve for:
			// PermControl is on the ladder today but owns no route, so its rows
			// are vacuous until one is added — at which point they bite.
			need := largestBody[high]
			if gap := mutationBodyTierCeiling(high) - mutationBodyTierCeiling(low); gap < need {
				t.Errorf("the %s tier stands only %d bytes above the %s tier (%d vs %d), less "+
					"than the %d a single %s-tier request can carry. Every ceiling is tested "+
					"against the AGGREGATE, so a %s-tier flood drives the total to its own "+
					"ceiling and leaves the %s tier that gap and no more — a caller holding "+
					"only %s can then 429 a caller holding %s off its own routes, which is the "+
					"cross-privilege denial the ladder exists to remove",
					authz.PermissionName(high), gap, authz.PermissionName(low),
					mutationBodyTierCeiling(high), mutationBodyTierCeiling(low), need,
					authz.PermissionName(high), authz.PermissionName(low),
					authz.PermissionName(high), authz.PermissionName(low),
					authz.PermissionName(high))
			}
		}
	}

	// The other direction: a share small enough to be safe can be too small to
	// SERVE, and shrinking a tier to buy separation would trade a
	// cross-privilege denial for a self-denial.
	//
	// Only the OPERATIONAL tiers are held to this. Their routes carry a few
	// hundred bytes and their callers are the numerous ones. The configure tier
	// deliberately is not: its largest route carries a whole 16 MiB candidate
	// configuration, and 48 MiB holding two or three of those at once is the
	// documented pathological extreme (mutationBodyBudgetBytes), not a
	// regression.
	const minConcurrentOperationalRequests = 64
	for _, perm := range []config.LoginClassPermission{config.PermView, config.PermClear, config.PermControl} {
		largest := largestBody[perm]
		if largest == 0 {
			continue // no body-carrying route in this tier
		}
		if fits := mutationBodyTierCeiling(perm) / largest; fits < minConcurrentOperationalRequests {
			t.Errorf("the %s tier's %d-byte share holds only %d concurrent %d-byte requests, "+
				"below the %d its own routes need. Separating the tiers by starving one of "+
				"them replaces a cross-privilege denial with a self-denial",
				authz.PermissionName(perm), mutationBodyTierCeiling(perm), fits, largest,
				minConcurrentOperationalRequests)
		}
	}

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
