package api

import (
	"path/filepath"
	"testing"

	"net/url"

	"github.com/psaab/xpf/pkg/configstore"
)

// schedAPIStore builds a config whose only trust->untrust rule is a scheduled
// PERMIT bound to the "after-hours" scheduler, with default-policy deny. The
// dataplane treats this policy as INACTIVE (dropped) whenever per-scheduler
// active-state is unavailable (snapshot builder: nil map => Inactive), so the
// REST match-policies simulator must report default-deny — not a permit — for
// the unavailable-state path (#3414).
func schedAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler after-hours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy night-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name after-hours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMatchPoliciesRESTScheduledPolicyFailsClosedWhenStateUnavailable pins
// #3414: when live per-scheduler active-state cannot be obtained (accessor not
// wired, or it returns ok=false during early boot / NoDataplane), the REST
// match-policies simulator must treat a scheduler-bound policy as INACTIVE —
// exactly as the dataplane snapshot builder does (policyRuleInactive: nil map
// => dropped) — and fall through to the default-policy. Before #3414 the
// handler left the predicate nil on this path, so the scheduled permit was
// simulated as-if-active and the diagnostic certified a PERMIT the dataplane is
// actually skipping.
//
// RED-on-revert: reverting matchPoliciesHandler to the
// `if state, ok := s.policySchedActiveFn(); ok { inactiveFn = ... }` shape
// (predicate stays nil when the accessor is absent or returns ok=false) makes
// the scheduled permit match, so Action flips to "permit" and Matched to true —
// every assertion below fails.
func TestMatchPoliciesRESTScheduledPolicyFailsClosedWhenStateUnavailable(t *testing.T) {
	store := schedAPIStore(t)
	q := url.Values{
		"from_zone": {"trust"},
		"to_zone":   {"untrust"},
		"protocol":  {"tcp"},
		"dst_port":  {"80"},
	}

	// Case A: accessor not wired (policySchedActiveFn == nil) — early boot.
	t.Run("accessor not wired -> fail closed default deny", func(t *testing.T) {
		s := &Server{store: store}
		res := matchAction(t, s, q)
		if res.Data.Matched {
			t.Fatalf("matched = true, want false (scheduled permit must be skipped when state unavailable); got %+v", res.Data)
		}
		if res.Data.Action != "deny (default)" {
			t.Errorf("action = %q, want %q", res.Data.Action, "deny (default)")
		}
		if !res.Data.DefaultUsed {
			t.Errorf("default_used = false, want true (fell through to default-policy)")
		}
	})

	// Case B: accessor wired but reports state unavailable (ok=false), e.g.
	// NoDataplane. Same fail-closed verdict.
	t.Run("accessor ok=false -> fail closed default deny", func(t *testing.T) {
		s := &Server{store: store}
		s.policySchedActiveFn = func() (map[string]bool, bool) { return nil, false }
		res := matchAction(t, s, q)
		if res.Data.Matched {
			t.Fatalf("matched = true, want false (ok=false must fail closed); got %+v", res.Data)
		}
		if res.Data.Action != "deny (default)" {
			t.Errorf("action = %q, want %q", res.Data.Action, "deny (default)")
		}
		if !res.Data.DefaultUsed {
			t.Errorf("default_used = false, want true")
		}
	})

	// Case C (positive control): live state present and the scheduler is
	// ACTIVE -> the scheduled permit matches. Guards against over-fail-closing
	// the available-state path.
	t.Run("scheduler active -> permit", func(t *testing.T) {
		s := &Server{store: store}
		s.policySchedActiveFn = func() (map[string]bool, bool) {
			return map[string]bool{"after-hours": true}, true
		}
		res := matchAction(t, s, q)
		if !res.Data.Matched {
			t.Fatalf("matched = false, want true (scheduler active); got %+v", res.Data)
		}
		if res.Data.Action != "permit" {
			t.Errorf("action = %q, want %q", res.Data.Action, "permit")
		}
		if res.Data.DefaultUsed {
			t.Errorf("default_used = true, want false (scheduled permit matched)")
		}
	})

	// Case D (regression anchor): live state present and the scheduler is
	// INACTIVE -> default deny (the #3104 behavior, unchanged by #3414).
	t.Run("scheduler inactive -> default deny", func(t *testing.T) {
		s := &Server{store: store}
		s.policySchedActiveFn = func() (map[string]bool, bool) {
			return map[string]bool{"after-hours": false}, true
		}
		res := matchAction(t, s, q)
		if res.Data.Matched {
			t.Fatalf("matched = true, want false (scheduler inactive); got %+v", res.Data)
		}
		if res.Data.Action != "deny (default)" {
			t.Errorf("action = %q, want %q", res.Data.Action, "deny (default)")
		}
		if !res.Data.DefaultUsed {
			t.Errorf("default_used = false, want true")
		}
	})
}
