package api

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// authz_bodybudget_customclass_6954_test.go pins the SCOPE of the body-budget
// tier ladder's privilege guarantee.
//
// mutationBodyTierCeilings partitions the aggregate body budget by the
// permission a ROUTE requires, and the step sizes are chosen so that a flood
// confined to one tier cannot push the aggregate past the ceiling of any tier
// with a larger share. That is a statement about TIERS. Reading it as
// "exhausting the budget is not a way to deny someone more privileged than
// you" — which is what the table's comment said, unqualified, before #6954 —
// needs one more premise: that the set of tiers a principal can reach GROWS
// with privilege, i.e. that holding a high permission implies holding every
// permission whose tier sits below it.
//
// That premise is a property of the SYSTEM-DEFINED login classes, not of the
// permission model. config.LoginClassPermissions really is nested
// (read-only subset of operator subset of super-user), and the first case below
// asserts the guarantee over exactly those classes, through the production
// evaluator and the production ceiling table.
//
// A CUSTOM `system login class` is not nested. mapJunosPermissions has a
// distinct arm per Junos token, so `permissions configure` compiles to exactly
// [PermConfig] — configure WITHOUT view — and validateLoginClassRef lets a
// `system login user ... class` reference it, so the configuration commits and
// the runtime evaluator honours it. The second case asserts that the SAME
// predicate the first case checks FAILS for such a class, and the third drives
// it end to end over real HTTP: a principal holding a STRICT SUBSET of another
// principal's permissions refuses that principal's view-tier request.
//
// The third case is the reachability the issue asks for, and it is CHEAPER than
// the issue estimated: the flood does not have to reach its own 48 MiB configure
// ceiling, only the VICTIM's 8 MiB view ceiling, so 8 MiB of traffic is enough.

const (
	authzUIDConfigOnly = 4245 // custom class: `permissions configure` alone
	authzUIDConfigView = 4246 // custom class: `permissions [ configure view ]`
)

// customClassPasswdFixture maps the two UIDs above onto accounts, exactly as
// authzPasswdFixture does for the built-in-class cases.
const customClassPasswdFixture = `root:x:0:0:root:/root:/bin/bash
cfgonly:x:4245:4245::/home/cfgonly:/bin/bash
cfgview:x:4246:4246::/home/cfgview:/bin/bash
`

// customClassAuthzConfig is a configuration an operator can commit TODAY. The
// two classes are the whole point: `configure-only` holds a strict subset of
// what `configure-and-view` holds, and neither is a system-defined class.
const customClassAuthzConfig = `
system {
    host-name authz-custom-class;
    login {
        class configure-only {
            permissions configure;
        }
        class configure-and-view {
            permissions [ configure view ];
        }
        user cfgonly {
            class configure-only;
        }
        user cfgview {
            class configure-and-view;
        }
    }
}
`

// tiersReachableBy returns the ladder tiers a login class may drive traffic on:
// the permissions mutationBodyTierCeilings names that ClassHasPermission grants
// the class. Both halves are production.
func tiersReachableBy(cfg *config.Config, class string) []config.LoginClassPermission {
	var reachable []config.LoginClassPermission
	for _, perm := range tierLadderPermissions() {
		if config.ClassHasPermission(cfg, class, perm) {
			reachable = append(reachable, perm)
		}
	}
	return reachable
}

// floodReach is the highest the aggregate budget can be driven by a principal
// holding only what `class` holds: the largest tier ceiling it can reach.
func floodReach(cfg *config.Config, class string) int64 {
	var reach int64
	for _, perm := range tiersReachableBy(cfg, class) {
		if c := mutationBodyTierCeiling(perm); c > reach {
			reach = c
		}
	}
	return reach
}

// classNames renders a class's reachable tiers for a diagnostic.
func classNames(perms []config.LoginClassPermission) string {
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, authz.PermissionName(p))
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// strictlyMorePrivileged reports whether class `high` holds every ladder tier
// `low` holds and at least one more — the subset order on permission SETS,
// which is what "more privileged" has to mean once classes are not nested.
func strictlyMorePrivileged(cfg *config.Config, low, high string) bool {
	var extra bool
	for _, perm := range tierLadderPermissions() {
		hasLow := config.ClassHasPermission(cfg, low, perm)
		hasHigh := config.ClassHasPermission(cfg, high, perm)
		if hasLow && !hasHigh {
			return false
		}
		if hasHigh && !hasLow {
			extra = true
		}
	}
	return extra
}

// useCustomClassPasswdFixture points the UID resolver at the two custom-class
// accounts. It is customClassPasswdFixture's half of usePasswdFixture.
func useCustomClassPasswdFixture(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(customClassPasswdFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// parkFlood opens ONE POST /api/v1/config/load that delivers want-1 bytes and
// then stalls, and returns once the gate holds exactly `want` bytes for it.
//
// want-1 rather than want: bufferMutationBody grows by doubling BEFORE the read
// that would fill the buffer, so a body that exactly fills a capacity triggers
// one more doubling. want-1 lands the buffer on `want` and leaves it there,
// which is why the settle assertion below can name an exact number instead of a
// range — and why a change to the growth schedule fails here loudly rather than
// silently shifting what the rows either side of the ceiling mean.
//
// The connection is closed by openDeclaredBody's own cleanup, so the charge is
// live for the rest of the caller's subtest and released when it ends.
func parkFlood(t *testing.T, base string, want int64) {
	t.Helper()
	// #6977: the baseline is read before this call's own request exists. It
	// matters here more than anywhere else: parkFlood is called twice in the
	// same case, so a bare "some request is parked" would be satisfied by the
	// PREVIOUS call's park and this one would proceed before its own bytes were
	// charged — and the settle assertion below would be reading a total this
	// call had not finished contributing to.
	parked := MutationBodyWaitersForTest()
	conn := openDeclaredBody(t, base, "POST /api/v1/config/load",
		int(mutationBodyLoad), strings.Repeat("a", int(want-1)), nil)
	_ = conn
	waitForNewMutationBodyWaiter(t, parked)
	waitForAdmittedToSettle(t, want)
}

// TestTierLadderProtectsPrivilegeOverSystemClasses_6954 is the guarantee, stated
// over CLASSES rather than over derived permission steps.
//
// For every pair of system-defined classes where one holds a strict superset of
// the other's ladder tiers, every tier the superset can reach and the subset
// cannot must sit at a ceiling STRICTLY ABOVE everything the subset can drive
// the aggregate to. That is what "a cheap principal cannot deny a privileged
// one" reduces to once it is made checkable: the subset's flood stops below the
// ceiling at which the superset's exclusive traffic is admitted.
//
// Strictly above, not at: bodyBudget.resize refuses a growth that would take
// the aggregate PAST the ceiling, so a flood that reaches exactly the victim's
// ceiling has already refused it.
func TestTierLadderProtectsPrivilegeOverSystemClasses_6954(t *testing.T) {
	classes := make([]string, 0, len(config.LoginClassPermissions))
	for name := range config.LoginClassPermissions {
		classes = append(classes, name)
	}
	sort.Strings(classes)

	var pairs int
	seen := map[string]bool{}
	for _, low := range classes {
		for _, high := range classes {
			if low == high || !strictlyMorePrivileged(nil, low, high) {
				continue
			}
			pairs++
			seen[low+"<"+high] = true
			reach := floodReach(nil, low)
			for _, perm := range tiersReachableBy(nil, high) {
				if config.ClassHasPermission(nil, low, perm) {
					continue // a tier both hold is contention, not a privilege inversion
				}
				if ceiling := mutationBodyTierCeiling(perm); ceiling <= reach {
					t.Errorf("class %q (tiers %s) can drive the aggregate body budget to %d bytes, "+
						"which already refuses the %s tier (ceiling %d) that only the strictly more "+
						"privileged class %q (tiers %s) can reach. A principal in the cheaper class "+
						"denies a principal in the richer one on a route the cheaper class is not "+
						"even authorized to call",
						low, classNames(tiersReachableBy(nil, low)), reach,
						authz.PermissionName(perm), ceiling,
						high, classNames(tiersReachableBy(nil, high)))
				}
			}
		}
	}

	// Anti-vacuity. Every assertion above is quantified over the pairs the
	// derivation finds, so a derivation that stopped producing pairs would
	// leave the case green while checking nothing. These two are the pairs the
	// round-18 finding and the round-19 finding respectively lived on.
	for _, want := range []string{"read-only<operator", "read-only<super-user", "operator<super-user"} {
		if !seen[want] {
			t.Fatalf("the class-pair derivation produced %d pairs and %q is not among them, so the "+
				"requirement above is quantified over a set that does not contain the case it "+
				"exists for", pairs, want)
		}
	}
}

// TestCustomClassEscapesTheTierLaddersPrivilegeOrder_6954 is the SCOPE BOUNDARY
// of the case above (#6954).
//
// It runs the identical predicate against two classes an operator can commit
// today, and requires it to FAIL. That is not an endorsement: it is the
// statement the table's comment and pkg/api/README.md now make, held against
// production so it cannot rot into prose that outlived the code.
//
// IF THIS CASE STARTS FAILING, the ladder no longer has this gap — someone
// re-keyed the reservation on the principal's permission SET or moved it
// per-principal. Delete this case, and delete the scope paragraph it binds from
// mutationBodyTierCeilings' comment and from the README's drain row, rather
// than leaving the code stronger than what it claims.
func TestCustomClassEscapesTheTierLaddersPrivilegeOrder_6954(t *testing.T) {
	store := authzStore(t, customClassAuthzConfig)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("the custom-class configuration did not commit")
	}

	// The premise: both classes exist, and mapJunosPermissions really did give
	// `permissions configure` PermConfig and NOT PermView.
	perms, ok := config.ResolveClassPermissions(cfg, "configure-only")
	if !ok {
		t.Fatal("class configure-only did not resolve — the committed config is not the one this case needs")
	}
	if len(perms) != 1 || perms[0] != config.PermConfig {
		t.Fatalf("class configure-only resolved to %s, want exactly configure. A `permissions "+
			"configure` class that also carries view would make this whole case moot — and would "+
			"mean mapJunosPermissions changed, so the scope note in authz.go must be revisited",
			classNames(perms))
	}
	if !strictlyMorePrivileged(cfg, "configure-only", "configure-and-view") {
		t.Fatal("class configure-and-view no longer holds a strict superset of configure-only's " +
			"ladder tiers, so this case is no longer about a privilege inversion")
	}

	reach := floodReach(cfg, "configure-only")
	var inverted bool
	for _, perm := range tiersReachableBy(cfg, "configure-and-view") {
		if config.ClassHasPermission(cfg, "configure-only", perm) {
			continue
		}
		if mutationBodyTierCeiling(perm) <= reach {
			inverted = true
		}
	}
	if !inverted {
		t.Fatalf("a `permissions configure` class can drive the aggregate to %d bytes and no tier "+
			"exclusive to `permissions [ configure view ]` sits at or below that — the ladder now "+
			"orders custom classes too. Remove this case AND the scope paragraph it binds in "+
			"pkg/api/authz.go (mutationBodyTierCeilings) and pkg/api/README.md", reach)
	}
}

// TestCustomClassSubsetRefusesItsSupersetOverREST_6954 is the same inversion
// driven end to end, so the scope note states a REACHABLE limitation rather
// than a derivation about tables.
//
// Two principals, two custom classes, one process-global budget:
//
//	cfgonly  — class configure-only      — tiers {configure}
//	cfgview  — class configure-and-view  — tiers {configure, view}
//
// cfgview holds a STRICT SUPERSET of what cfgonly holds. cfgonly floods
// POST /api/v1/config/load, which it is authorized for; the flood is admitted
// under the 48 MiB configure ceiling, and once the aggregate reaches the 8 MiB
// VIEW ceiling, cfgview's POST /api/v1/diagnostics/ping is refused 429.
//
// The rows are the pair either side of that ceiling, plus the discriminator
// that the refusal is the ladder and not a stuck gate: at the SAME aggregate,
// the same victim's configure-tier request is still served.
func TestCustomClassSubsetRefusesItsSupersetOverREST_6954(t *testing.T) {
	useCustomClassPasswdFixture(t)
	store := authzStore(t, customClassAuthzConfig)
	_, floodBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDConfigOnly),
	})
	_, victimBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDConfigView),
	})

	viewCeiling := mutationBodyTierCeiling(config.PermView)

	// The gate's own fast 400: a ping with an empty target never reaches the
	// exec path, so an ADMITTED victim request answers immediately.
	const pingBody = `{"target":""}`

	t.Run("aggregate below the victim's tier ceiling: served", func(t *testing.T) {
		waitForGateQuiescent(t)
		parkFlood(t, floodBase, viewCeiling/2)

		conn := openDeclaredBody(t, victimBase, "POST /api/v1/diagnostics/ping", len(pingBody), pingBody, nil)
		status, got := readStatus(t, conn, 10*time.Second)
		if !got {
			t.Fatal("the victim's view-tier request never answered")
		}
		if status != http.StatusBadRequest {
			t.Fatalf("the victim's view-tier request answered %d, want the handler's own 400 for an "+
				"empty ping target. 429 means the row that is supposed to sit UNDER the view "+
				"ceiling (%d bytes, %d charged) is already over it; 403 means the victim is not "+
				"authorized for the route at all, which would make the refusal below a fact about "+
				"authorization rather than about the budget. Either way the pair proves nothing",
				status, viewCeiling, MutationBodyBytesAdmittedForTest())
		}
	})

	t.Run("aggregate at the victim's tier ceiling: refused", func(t *testing.T) {
		waitForGateQuiescent(t)
		parkFlood(t, floodBase, viewCeiling)

		conn := openDeclaredBody(t, victimBase, "POST /api/v1/diagnostics/ping", len(pingBody), pingBody, nil)
		status, got := readStatus(t, conn, 10*time.Second)
		if !got {
			t.Fatal("the victim's view-tier request never answered")
		}
		if status != http.StatusTooManyRequests {
			t.Fatalf("the victim's view-tier request answered %d, not 429, with %d bytes charged "+
				"against its %d-byte view ceiling. The ladder now orders custom classes: remove "+
				"this case AND the scope paragraph it binds in pkg/api/authz.go and "+
				"pkg/api/README.md", status, MutationBodyBytesAdmittedForTest(), viewCeiling)
		}

		// The discriminator. A gate that refused EVERYTHING under load would
		// pass the row above; this row fails it. The victim's configure-tier
		// request draws on the 48 MiB share, which the flood has not reached.
		const setBody = `{"input":"set system host-name r6954"}`
		conn = openDeclaredBody(t, victimBase, "POST /api/v1/config/set", len(setBody), setBody, nil)
		status, got = readStatus(t, conn, 10*time.Second)
		if !got {
			t.Fatal("the victim's configure-tier request never answered")
		}
		if status == http.StatusTooManyRequests {
			t.Fatalf("the victim's configure-tier request was ALSO refused 429 at %d bytes charged, "+
				"under a %d-byte configure ceiling. The 429 above is then not the view tier's "+
				"ceiling but a gate refusing everything, and the case measures nothing",
				MutationBodyBytesAdmittedForTest(), mutationBodyTierCeiling(config.PermConfig))
		}
	})

	// The claim the two rows above make is that a STRICT SUBSET denied a STRICT
	// SUPERSET. Half of that is the flooder's own reach, and it is asserted
	// here rather than assumed: cfgonly is refused 403 on the very route it
	// just denied cfgview on, so the denial runs from a principal that cannot
	// call the route to one that can.
	t.Run("the flooder cannot call the route it denied", func(t *testing.T) {
		waitForGateQuiescent(t)
		conn := openDeclaredBody(t, floodBase, "POST /api/v1/diagnostics/ping", len(pingBody), pingBody, nil)
		status, got := readStatus(t, conn, 10*time.Second)
		if !got {
			t.Fatal("the flooder's view-tier request never answered")
		}
		if status != http.StatusForbidden {
			t.Fatalf("the `permissions configure` principal answered %d on POST "+
				"/api/v1/diagnostics/ping, want 403. If it is authorized for the view tier then "+
				"its class is not a strict subset of the victim's and the rows above are ordinary "+
				"same-tier contention, not a privilege inversion", status)
		}
	})
}
