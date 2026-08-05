package daemon

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #5275 PR2 — the revocable dataplane facade.
//
// Two properties matter here and they fail in different ways:
//
//  1. the facade REVOKES (behaviour) — tested directly;
//  2. every external consumer actually HOLDS it (completeness) — tested by
//     scanning the construction sites, because a consumer re-pointed at the raw
//     backend still compiles, still passes every behavioural test, and silently
//     reinstates the alias the facade exists to remove.

// fakeFacadeBackend records that a call reached the backend.
type fakeFacadeBackend struct{ reached int }

func (f *fakeFacadeBackend) hit() { f.reached++ }

func (f *fakeFacadeBackend) ClearAllCounters() error             { f.hit(); return nil }
func (f *fakeFacadeBackend) ClearAllSessions() (int, int, error) { f.hit(); return 1, 2, nil }
func (f *fakeFacadeBackend) ClearFilterCounters() error          { f.hit(); return nil }
func (f *fakeFacadeBackend) ClearNATRuleCounters() error         { f.hit(); return nil }
func (f *fakeFacadeBackend) ClearPolicyCounters() error          { f.hit(); return nil }
func (f *fakeFacadeBackend) Compile(*config.Config) (*dataplane.CompileResult, error) {
	f.hit()
	return nil, nil
}
func (f *fakeFacadeBackend) DeleteDNATEntry(dataplane.DNATKey) error     { f.hit(); return nil }
func (f *fakeFacadeBackend) DeleteDNATEntryV6(dataplane.DNATKeyV6) error { f.hit(); return nil }
func (f *fakeFacadeBackend) DeleteSession(dataplane.SessionKey) error    { f.hit(); return nil }
func (f *fakeFacadeBackend) DeleteSessionV6(dataplane.SessionKeyV6) error {
	f.hit()
	return nil
}
func (f *fakeFacadeBackend) GetMapStats() []dataplane.MapStats { f.hit(); return nil }
func (f *fakeFacadeBackend) GetPersistentNAT() *dataplane.PersistentNATTable {
	f.hit()
	return nil
}
func (f *fakeFacadeBackend) GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error) {
	f.hit()
	return dataplane.SessionValue{}, nil
}
func (f *fakeFacadeBackend) GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	f.hit()
	return dataplane.SessionValueV6{}, nil
}
func (f *fakeFacadeBackend) IsLoaded() bool { f.hit(); return true }
func (f *fakeFacadeBackend) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	f.hit()
	return nil
}
func (f *fakeFacadeBackend) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	f.hit()
	return nil
}
func (f *fakeFacadeBackend) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	f.hit()
	return dataplane.FilterConfig{}, nil
}
func (f *fakeFacadeBackend) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	f.hit()
	return dataplane.CounterValue{}, nil
}
func (f *fakeFacadeBackend) ReadFloodCounters(uint16) (dataplane.FloodState, error) {
	f.hit()
	return dataplane.FloodState{}, nil
}
func (f *fakeFacadeBackend) ReadGlobalCounter(uint32) (uint64, error) { f.hit(); return 7, nil }
func (f *fakeFacadeBackend) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	f.hit()
	return dataplane.InterfaceCounterValue{}, nil
}
func (f *fakeFacadeBackend) ReadNATPortCounter(uint32) (uint64, error) { f.hit(); return 0, nil }
func (f *fakeFacadeBackend) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	f.hit()
	return dataplane.CounterValue{}, nil
}
func (f *fakeFacadeBackend) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	f.hit()
	return dataplane.CounterValue{}, nil
}
func (f *fakeFacadeBackend) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	f.hit()
	return dataplane.CounterValue{}, nil
}
func (f *fakeFacadeBackend) SessionCount() (int, int) { f.hit(); return 3, 4 }

// TestFacadeRevocationStopsEveryCall is the behavioural half. A revoked facade
// must stop calls at the facade — not merely report an error while still
// reaching the backend, which would leave the mutator paths (SetForwardingArmed
// and friends) live for a consumer that captured the handle earlier.
func TestFacadeRevocationStopsEveryCall(t *testing.T) {
	be := &fakeFacadeBackend{}
	f := newDataplaneFacade(be)
	if f == nil {
		t.Fatal("precondition: a satisfying backend must produce a facade")
	}

	// Live: calls reach the backend.
	if !f.IsLoaded() {
		t.Fatal("live facade did not delegate IsLoaded")
	}
	if got, err := f.ReadGlobalCounter(0); err != nil || got != 7 {
		t.Fatalf("live facade did not delegate ReadGlobalCounter: %v %v", got, err)
	}
	liveHits := be.reached
	if liveHits == 0 {
		t.Fatal("precondition: nothing reached the backend while live")
	}

	f.Revoke()

	// Revoked: nothing reaches the backend, and fallible methods say why.
	if f.IsLoaded() {
		t.Error("revoked facade still reports IsLoaded — a consumer would treat the dataplane as usable")
	}
	if _, err := f.ReadGlobalCounter(0); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked read returned %v, want errDataplaneFacadeRevoked", err)
	}
	if err := f.ClearAllCounters(); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked MUTATOR returned %v, want errDataplaneFacadeRevoked", err)
	}
	if _, _, err := f.ClearAllSessions(); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked ClearAllSessions returned %v, want errDataplaneFacadeRevoked", err)
	}
	if v4, v6 := f.SessionCount(); v4 != 0 || v6 != 0 {
		t.Errorf("revoked SessionCount returned %d/%d — a stale count read as live is worse "+
			"than an empty one", v4, v6)
	}
	if be.reached != liveHits {
		t.Fatalf("REVOCATION LEAKED: %d call(s) reached the backend after Revoke()",
			be.reached-liveHits)
	}
}

// TestFacadeRevocationIsSticky pins that revocation cannot be undone. A facade
// that could return to live would let a later code path re-open access the arm
// proof had already refused.
func TestFacadeRevocationIsSticky(t *testing.T) {
	f := newDataplaneFacade(&fakeFacadeBackend{})
	f.Revoke()
	f.Revoke() // idempotent
	if f.live() {
		t.Fatal("facade returned to live after Revoke()")
	}
}

// TestFacadeZeroValueGrantsNothing pins the fail-safe zero. A facade that was
// never constructed through newDataplaneFacade must deny, so a forgotten or
// partially-built one cannot be an open door.
func TestFacadeZeroValueGrantsNothing(t *testing.T) {
	var f dataplaneFacade
	if f.live() {
		t.Fatal("a zero-valued facade is LIVE — the zero state must be closed")
	}
	if f.IsLoaded() {
		t.Error("a zero-valued facade reports IsLoaded")
	}
	// A nil facade must fail closed rather than panic: consumers hold it as an
	// interface and call it without nil-checking.
	var nilF *dataplaneFacade
	if nilF.live() {
		t.Fatal("a nil facade is LIVE")
	}
	if err := nilF.ClearAllCounters(); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("nil facade returned %v, want errDataplaneFacadeRevoked", err)
	}
}

// TestFacadeAbsentBackendStaysNil pins the behaviour-identical claim. Before
// this change each consumer's DP was left nil when the daemon had no dataplane,
// and every consumer already handles nil. Handing them a non-nil facade over
// nothing would flip those nil checks — a behaviour change in a PR whose whole
// claim is that it makes none.
func TestFacadeAbsentBackendStaysNil(t *testing.T) {
	if f := newDataplaneFacade(nil); f != nil {
		t.Fatal("a nil backend must produce a NIL facade, not a facade over nothing")
	}
	if f := newDataplaneFacade(struct{ NotADataplane bool }{}); f != nil {
		t.Fatal("a backend that does not satisfy the surface must produce a NIL facade")
	}
}

// TestSetDataplaneRevokesThePreviousFacade pins the wiring invariant. Replacing
// the dataplane must REVOKE the old facade, not merely repoint d.dpFacade: a
// consumer constructed earlier still holds the OLD object, so leaving it live
// would preserve exactly the alias this change removes.
func TestSetDataplaneRevokesThePreviousFacade(t *testing.T) {
	d := &Daemon{}
	d.dpFacade = newDataplaneFacade(&fakeFacadeBackend{})
	captured := d.dpFacade // what gRPC/REST/CLI would be holding
	if !captured.live() {
		t.Fatal("precondition: the first facade must be live")
	}

	d.setDataplane(nil) // the "drop the dataplane" gesture

	if captured.live() {
		t.Fatal("the handle a consumer captured is STILL LIVE after the daemon dropped " +
			"the dataplane — this is the #5275 defect, reintroduced")
	}
	if d.dp != nil || d.dpFacade != nil {
		t.Fatalf("setDataplane(nil) left dp=%v facade=%v", d.dp, d.dpFacade)
	}
}

// TestEveryExternalConsumerHoldsTheFacade is the COMPLETENESS half, and the
// reason this file scans source rather than only exercising behaviour.
//
// A consumer re-pointed at the raw backend — `grpcDP = probe` instead of
// `grpcDP = d.dpFacade` — compiles, passes every behavioural test above, and
// silently restores the un-revocable alias. Nothing else in the suite can see
// that, because the facade still works perfectly for whoever still holds it.
//
// So: the three construction sites must take their DP from d.dpFacade, and must
// not assert d.dp to a consumer mirror. If a fourth external consumer is added,
// it belongs in this list.
func TestEveryExternalConsumerHoldsTheFacade(t *testing.T) {
	for _, tc := range []struct {
		file     string
		consumer string
		mirror   string
	}{
		{"daemon_run_servers.go", "gRPC", "grpcDataPlane"},
		{"daemon_run_servers.go", "REST", "apiDataPlane"},
		{"daemon_run.go", "CLI", "cliDataPlane"},
	} {
		t.Run(tc.consumer, func(t *testing.T) {
			src, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}
			text := string(src)

			// The assignment must come from the facade.
			assign := regexp.MustCompile(`(?m)^\s*var \w+ ` + tc.mirror + `\b`)
			if !assign.MatchString(text) {
				t.Fatalf("%s: no `var <x> %s` declaration found — this test is anchored on a "+
					"construction shape that no longer exists and must be re-derived, not deleted",
					tc.file, tc.mirror)
			}
			if !strings.Contains(text, "d.dpFacade") {
				t.Fatalf("%s constructs a %s consumer but never reads d.dpFacade — the consumer "+
					"is holding a raw backend alias that d.dp = nil cannot revoke (#5275)",
					tc.file, tc.consumer)
			}

			// And must NOT re-assert the raw backend to this mirror.
			raw := regexp.MustCompile(`d\.dp\.\(` + tc.mirror + `\)`)
			if raw.MatchString(text) {
				t.Fatalf("%s asserts d.dp.(%s) — the %s consumer has been re-pointed at the raw "+
					"backend, reinstating the un-revocable alias the facade removes (#5275)",
					tc.file, tc.mirror, tc.consumer)
			}
		})
	}
}

// TestDataplaneIsAssignedOnlyThroughSetDataplane guards the other half of the
// wiring: a future `d.dp = x` that skips setDataplane leaves the facade
// pointing at a backend the daemon no longer uses, or leaves a dropped
// backend's facade live. The setter is the only place the two stay in lockstep.
func TestDataplaneIsAssignedOnlyThroughSetDataplane(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	direct := regexp.MustCompile(`(?m)^\s*d\.dp = `)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name == "dataplane_facade_wiring.go" {
			continue // the setter itself
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if loc := direct.FindString(string(src)); loc != "" {
			t.Errorf("%s assigns d.dp directly — use d.setDataplane(...) so the external "+
				"consumers' facade cannot drift from the backend (#5275)", name)
		}
	}
}
