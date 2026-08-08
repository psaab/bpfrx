package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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

	// And the converse (#5561 round 19, finding 2). mutationBodyTierCeiling is
	// only ever called with a ROUTE's required permission, so a row for a
	// permission no route requires is never consulted: it protects nothing and
	// is protected from nothing, while sitting in a table every reader — and
	// every derivation in this file — treats as the set of live tiers.
	//
	// PermControl was exactly that from round 11 until round 19. Its share was
	// documented as biting "once a route is added", which was not true either:
	// the ladder's ordering is derived from the built-in login classes, and no
	// built-in separates clear from control, so the row would still have been
	// skipped. A vacuous row is a number nobody derived; the unlisted-permission
	// fallback assigns the smallest share, which is the safe default a new tier
	// should start from until someone chooses otherwise.
	required := map[config.LoginClassPermission]bool{}
	for _, perm := range restMutationPermissions {
		required[perm] = true
	}
	for perm := range mutationBodyTierCeilings {
		if !required[perm] {
			t.Errorf("mutationBodyTierCeilings gives permission %q a %d-byte share of the body "+
				"budget, but no route in restMutationPermissions requires it. The lookup is keyed "+
				"on a route's required permission, so that share is unreachable — and the ladder "+
				"reads the table's key set as the live tiers, so an unreachable row makes the "+
				"derived privilege steps and the concurrency floors assert over a tier that has "+
				"no work on it", authz.PermissionName(perm), mutationBodyTierCeilings[perm])
		}
	}
}

// tierLadderPermissions returns the tiers mutationBodyTierCeilings names, in a
// stable order.
func tierLadderPermissions() []config.LoginClassPermission {
	ladder := make([]config.LoginClassPermission, 0, len(mutationBodyTierCeilings))
	for perm := range mutationBodyTierCeilings {
		ladder = append(ladder, perm)
	}
	sort.Slice(ladder, func(i, j int) bool { return ladder[i] < ladder[j] })
	return ladder
}

// largestTierBodies maps each tier to the largest body any route requiring that
// permission can legitimately carry — restMutationPermissions crossed with
// restMutationBodyLimits, both production tables.
func largestTierBodies() map[config.LoginClassPermission]int64 {
	largest := map[config.LoginClassPermission]int64{}
	for route, required := range restMutationPermissions {
		if n := mutationBodyLimit(route); n > largest[required] {
			largest[required] = n
		}
	}
	return largest
}

// tierLadderSteps derives every ordered (lower, higher) privilege step among the
// tiers, from config.LoginClassPermissions through the production evaluator: p
// is strictly less privileged than q when every class holding q also holds p and
// some class holds p without q (`read-only` holds view without clear, so
// view < clear).
//
// The derivation reads the SYSTEM-DEFINED classes only — cfg is nil, so
// ResolveClassPermissions consults LoginClassPermissions and nothing else. That
// is a deliberate scope, and stating it is more honest than widening it (#5561
// round 19, finding 2). A CUSTOM class is not bound by this ordering:
// mapJunosPermissions has a distinct arm per Junos token, so
// `set system login class netops permissions clear` compiles to PermClear with
// no PermView, and once any single token can stand alone NO two coarse
// permissions are ordered by subset — every pair separates every other pair in
// both directions. A per-permission ladder cannot express that lattice at all,
// so deriving from it would replace these requirements with an empty set rather
// than a stricter one. What the ladder claims, and what the steps below check,
// is the ordering the shipped classes realize.
func tierLadderSteps() [][2]config.LoginClassPermission {
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
	ladder := tierLadderPermissions()
	var steps [][2]config.LoginClassPermission
	for _, low := range ladder {
		for _, high := range ladder {
			if low != high && strictlyBelow(low, high) {
				steps = append(steps, [2]config.LoginClassPermission{low, high})
			}
		}
	}
	return steps
}

// requireConfigureStepDerived is the control on that derivation.
//
// Both cases below assert over whatever tierLadderSteps returns, so a derivation
// that quietly stopped producing steps would leave them green while checking
// nothing. clear -> configure is the step round 19's finding lived on and the
// one an `operator`-versus-`super-user` denial runs through, so its presence is
// the floor: if it is gone, the loops are not weakened, they are empty.
func requireConfigureStepDerived(t *testing.T, steps [][2]config.LoginClassPermission) {
	t.Helper()
	for _, s := range steps {
		if s[0] == config.PermClear && s[1] == config.PermConfig {
			return
		}
	}
	t.Fatalf("the privilege-step derivation produced %d steps and none of them is "+
		"clear -> configure. Every requirement in this file is quantified over that set, so "+
		"an empty or truncated derivation makes them all vacuously true rather than failing",
		len(steps))
}

// peakChargeForMaxSizeBody measures what the gate's aggregate budget is charged,
// at PEAK, for one request that delivers a body of exactly `limit` bytes.
//
// It MEASURES production rather than restating it: the answer is the smallest
// tier ceiling at which bufferMutationBody admits such a body. bodyBudget.resize
// refuses exactly when the running total would pass the ceiling, so the smallest
// ceiling that never refuses IS the high-water mark the request drives.
// Admission is monotone in the ceiling — the sequence of resize calls a given
// body produces does not depend on it — so the binary search is exact.
//
// The ladder needs this number and not `limit`, because the two differ. A buffer
// that grows by doubling holds the old allocation and the new one across the
// copy and is charged for both, so a body that steps to a route's limit peaks
// half again above it. Round 18's ladder guard was written in body units and so
// could not see a step short by less than that difference — which is how the
// configure-over-clear step shipped one byte under what a 16 MiB config/load
// really drives (#5561 round 19, finding 1). Deriving one side of the comparison
// from production is what makes the guard able to fail.
func peakChargeForMaxSizeBody(t *testing.T, limit int64) int64 {
	t.Helper()
	if limit <= 0 {
		t.Fatalf("peakChargeForMaxSizeBody(%d): a route that carries no body has no peak charge", limit)
	}
	body := bytes.Repeat([]byte("a"), int(limit))
	before := MutationBodyBytesAdmittedForTest()
	admits := func(ceiling int64) bool {
		if held := MutationBodyBytesAdmittedForTest(); held != before {
			t.Fatalf("the aggregate budget moved from %d to %d between probes — the measurement "+
				"is reading someone else's charge, not this body's", before, held)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", bytes.NewReader(body))
		w := httptest.NewRecorder()
		b := &bodyBudget{ceiling: before + ceiling}
		defer b.release()
		if bufferMutationBody(w, r, limit, b) {
			return true
		}
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("a %d-byte body under a %d-byte ceiling answered %d, not the 429 a budget "+
				"refusal writes — the measurement is reading the wrong outcome", limit, ceiling, w.Code)
		}
		return false
	}
	lo, hi := int64(1), 4*limit+mutationBodyInitialBuf
	if !admits(hi) {
		t.Fatalf("a %d-byte body is refused even at a %d-byte ceiling — the search window does "+
			"not contain the peak", limit, hi)
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		if admits(mid) {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
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
//
// Round 19 changed the UNIT. Every requirement below is now stated in what the
// budget is CHARGED for a request, measured off production, rather than in the
// size of the body it carries — see peakChargeForMaxSizeBody.
func TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561(t *testing.T) {
	budget := MutationBodyBudgetForTest()
	waitForAdmittedToSettle(t, 0)

	// EVERY privilege step, derived — not a restatement of the constants.
	//
	// The requirement joins the ORDER (tierLadderSteps) to the SIZE: because
	// each ceiling is tested against the AGGREGATE, tier q is protected from
	// tier p only if q's ceiling stands above p's by at least one whole q-sized
	// request. A gap of zero is no protection at all, which is precisely what
	// equal shares gave.
	//
	// "One whole q-sized request" is MEASURED, not stated. Round 18 wrote
	// `need := largestBody[high]` — body units — while the budget charges the
	// buffer's peak, and the two differ by half again. That is exactly how a
	// configure-over-clear step one byte short of a real 16 MiB config/load
	// passed the guard written to catch it (#5561 round 19, finding 1).
	steps := tierLadderSteps()
	largestBody := largestTierBodies()
	requireConfigureStepDerived(t, steps)

	peak := map[int64]int64{}
	needFor := func(limit int64) int64 {
		if n, ok := peak[limit]; ok {
			return n
		}
		n := peakChargeForMaxSizeBody(t, limit)
		peak[limit] = n
		return n
	}

	for _, step := range steps {
		low, high := step[0], step[1]
		// Defensive: a tier whose routes are all mutationBodyNone is never
		// charged and has nothing to reserve for. No tier is in that state
		// today — requireConfigureStepDerived plus the loop below would
		// otherwise be asserting over an empty set.
		if largestBody[high] == 0 {
			continue
		}
		need := needFor(largestBody[high])
		if gap := mutationBodyTierCeiling(high) - mutationBodyTierCeiling(low); gap < need {
			t.Errorf("the %s tier stands only %d bytes above the %s tier (%d vs %d), less "+
				"than the %d the gate is CHARGED for a single %s-tier request carrying its "+
				"largest body (%d bytes — a growing buffer holds the old allocation and the "+
				"new one across the copy, so the charge is half again the body). Every "+
				"ceiling is tested against the AGGREGATE, so a %s-tier flood drives the total "+
				"to its own ceiling and leaves the %s tier that gap and no more — a caller "+
				"holding only %s can then 429 a caller holding %s off its own routes, which "+
				"is the cross-privilege denial the ladder exists to remove",
				authz.PermissionName(high), gap, authz.PermissionName(low),
				mutationBodyTierCeiling(high), mutationBodyTierCeiling(low), need,
				authz.PermissionName(high), largestBody[high],
				authz.PermissionName(low), authz.PermissionName(high),
				authz.PermissionName(low), authz.PermissionName(high))
		}
	}

	// The other direction: a share small enough to be safe can be too small to
	// SERVE, and shrinking a tier to buy separation would trade a
	// cross-privilege denial for a self-denial.
	//
	// Only the OPERATIONAL tiers are held to this — every tier on the ladder
	// except configure. Their routes carry a few hundred bytes and their callers
	// are the numerous ones. The configure tier deliberately is exempt: its
	// largest route carries a whole 16 MiB candidate configuration, and 48 MiB
	// holding two of those at once is the documented pathological extreme
	// (mutationBodyBudgetBytes), not a regression.
	//
	// The divisor is the CHARGE, not the body: admission is decided on what the
	// aggregate is charged, so a tier's real concurrency is bounded by that. It
	// is a conservative reading — only the request currently growing pays the
	// peak, the settled ones hold their body — and a floor should read low.
	const minConcurrentOperationalRequests = 64
	for _, perm := range tierLadderPermissions() {
		if perm == config.PermConfig {
			continue
		}
		largest := largestBody[perm]
		if largest == 0 {
			continue // no body-carrying route in this tier
		}
		if fits := mutationBodyTierCeiling(perm) / needFor(largest); fits < minConcurrentOperationalRequests {
			t.Errorf("the %s tier's %d-byte share holds only %d concurrent %d-byte requests "+
				"(charged %d each), below the %d its own routes need. Separating the tiers by "+
				"starving one of them replaces a cross-privilege denial with a self-denial",
				authz.PermissionName(perm), mutationBodyTierCeiling(perm), fits, largest,
				needFor(largest), minConcurrentOperationalRequests)
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

	// What the operational tiers cannot reach must still hold a configuration —
	// again in charged bytes, not in body bytes.
	//
	// This check is live and byte-exact, but it is IMPLIED rather than
	// independent, and saying so keeps it from being mistaken for a dimension it
	// does not add: whenever the step-gap loop above and the aggregate check
	// below both pass, budget - clear >= configure - clear >= needFor(load), and
	// the same follows for view through the derived view -> configure step. No
	// ceiling table makes this red alone while both of those are green. It
	// becomes independent only if largestBody[PermConfig] reaches 0, which
	// `continue`s the step loop and is itself guarded by
	// requireConfigureStepDerived. Keep it as a belt; do not count it as a third
	// binding site.
	for _, tc := range []struct {
		name    string
		ceiling int64
	}{{"view", view}, {"clear", clear}} {
		if free := budget - tc.ceiling; free < needFor(mutationBodyLoad) {
			t.Errorf("the %s tier may drive the aggregate to %d of %d, leaving %d — less than "+
				"the %d a single whole-configuration load (%d bytes) is charged. A `read-only` "+
				"account can then make POST /api/v1/config/load answer 429, which is the "+
				"cross-privilege denial the ladder exists to remove", tc.name, tc.ceiling,
				budget, free, needFor(mutationBodyLoad), int64(mutationBodyLoad))
		}
	}

	// And what the configure tier cannot reach must still hold the destructive
	// verbs, whose payload is one action word.
	if free := budget - configure; free < needFor(mutationBodySmall) {
		t.Errorf("the configure tier may drive the aggregate to %d of %d, leaving %d — less "+
			"than the %d POST /api/v1/system/action's own %d-byte ceiling is charged, so a "+
			"configure-tier caller can deny the maintenance tier", configure, budget, free,
			needFor(mutationBodySmall), int64(mutationBodySmall))
	}
}

// TestATierAtItsCeilingCannotRefuseTheTierAboveIt_5561 spends the ladder's
// numbers instead of checking them (#5561 round 19, finding 1).
//
// The case above asks whether each step is wide enough. This one drives a real
// request through it: for every privilege step, the LOWER tier is pinned at its
// own ceiling — the most it can ever hold — and then the largest body a route on
// the HIGHER tier carries is read through production bufferMutationBody under
// the higher tier's real ceiling. Admission is the property. A 429 is the
// cross-privilege denial, and it is what round 18's head produced on the
// clear -> configure step: 48 MiB - 16 MiB is 33554432, one byte under the
// 33554433 a 16 MiB config/load drove, so an `operator` — or any custom class
// holding nothing but `permissions clear` — could 429 a super-user's
// POST /api/v1/config/load for the whole 30s read timeout, renewably.
//
// The pin is placed directly rather than through sockets because reachability of
// a tier ceiling is a separate question, and one the flood cases above already
// answer for the view tier. It is reachable exactly, not approximately: the
// clear tier's one body-carrying route has a 64 KiB ceiling, and 255 requests
// parked at 65536, one at 32768 and 64 at the 512-byte initial buffer sum to
// precisely its 16777216. The 256th cannot reach 65536 — its own last doubling
// would peak at 98304 — which is the same 1.5x this case exists to reserve for.
func TestATierAtItsCeilingCannotRefuseTheTierAboveIt_5561(t *testing.T) {
	waitForAdmittedToSettle(t, 0)

	steps := tierLadderSteps()
	largestBody := largestTierBodies()
	requireConfigureStepDerived(t, steps)

	for _, step := range steps {
		low, high := step[0], step[1]
		if largestBody[high] == 0 {
			continue // no body-carrying route on this tier; nothing to reserve
		}
		t.Run(authz.PermissionName(low)+"_at_ceiling_vs_"+authz.PermissionName(high), func(t *testing.T) {
			lowCeiling := mutationBodyTierCeiling(low)
			highCeiling := mutationBodyTierCeiling(high)
			limit := largestBody[high]

			// Pin the lower tier at the most its own share allows.
			pin := &bodyBudget{ceiling: lowCeiling}
			defer pin.release()
			if !pin.resize(lowCeiling) {
				t.Fatalf("could not pin the %s tier at its own %d-byte ceiling — the case never "+
					"reached the state it asserts from", authz.PermissionName(low), lowCeiling)
			}

			r := httptest.NewRequest(http.MethodPost, "/api/v1/config/load",
				bytes.NewReader(bytes.Repeat([]byte("a"), int(limit))))
			w := httptest.NewRecorder()
			b := &bodyBudget{ceiling: highCeiling}
			defer b.release()
			ok := bufferMutationBody(w, r, limit, b)
			code := w.Code
			b.release()
			pin.release()
			if ok {
				return
			}
			t.Fatalf("with the %s tier pinned at its %d-byte ceiling, one %d-byte %s-tier body — "+
				"the largest a route on that tier carries — was refused %d against a %d-byte "+
				"ceiling. It is charged %d at peak and the step above %s is only %d, so a caller "+
				"holding only %s can 429 a caller holding %s off its own routes: the "+
				"cross-privilege denial the ladder exists to remove",
				authz.PermissionName(low), lowCeiling, limit, authz.PermissionName(high),
				code, highCeiling, peakChargeForMaxSizeBody(t, limit), authz.PermissionName(low),
				highCeiling-lowCeiling, authz.PermissionName(low), authz.PermissionName(high))
		})
	}
}

// TestBufferedBodyLimitBoundaryIsUnchanged_5561 is the OVER-REACH guard for
// round 19's finding 1.
//
// That finding changed HOW the gate detects a body over the route's limit: the
// detecting byte now lands in a one-byte scratch array instead of in a buffer
// grown by a whole doubling to hold it. What it must NOT change is the boundary
// or the bytes — where 413 starts, and that everything under it reaches the
// handler exactly as sent. Both held before the change and both hold after, so
// this case stays GREEN when the charge fix is reverted. That is what makes it a
// guard on the blast radius rather than a restatement of the fix.
func TestBufferedBodyLimitBoundaryIsUnchanged_5561(t *testing.T) {
	waitForAdmittedToSettle(t, 0)

	const limit = mutationBodySmall
	for _, tc := range []struct {
		name string
		size int64
		want int // 0 == must be admitted and handed on intact
	}{
		{"one byte under the limit", limit - 1, 0},
		{"exactly the limit", limit, 0},
		{"one byte over the limit", limit + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), int(tc.size))
			r := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/ping", bytes.NewReader(body))
			w := httptest.NewRecorder()
			// The whole budget, so nothing here turns on the tier ladder: this
			// case is about the limit, not about the share.
			b := &bodyBudget{ceiling: MutationBodyBudgetForTest()}
			defer b.release()

			ok := bufferMutationBody(w, r, limit, b)
			if tc.want != 0 {
				if ok {
					t.Fatalf("a %d-byte body was ADMITTED against a %d-byte route limit. The gate "+
						"is the only thing between an oversized body and a handler whose own "+
						"MaxBytesReader may not trip, so admitting it is a silently accepted "+
						"over-limit request", tc.size, int64(limit))
				}
				if w.Code != tc.want {
					t.Fatalf("a %d-byte body against a %d-byte route limit answered %d, want %d — "+
						"the oversize outcome must stay the one decodeJSONBody produced",
						tc.size, int64(limit), w.Code, tc.want)
				}
				return
			}
			if !ok {
				t.Fatalf("a %d-byte body was refused %d against a %d-byte route limit; it is "+
					"within the limit and must reach the handler", tc.size, w.Code, int64(limit))
			}
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading the body the gate buffered: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("the handler would see %d bytes where the caller sent %d. The gate "+
					"replaces r.Body with its own copy, so a body altered here is a request the "+
					"handler decides on having never been sent", len(got), len(body))
			}
		})
	}
}
