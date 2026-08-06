package daemon

import (
	"errors"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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

// The CLI forwarding-control surface. These are the mutators #5275 §7 calls
// directly exploitable on bootstrap-exit, so the revocation test below asserts
// they stop at the facade like everything else.
func (f *fakeFacadeBackend) Status() (dpuserspace.ProcessStatus, error) {
	f.hit()
	return dpuserspace.ProcessStatus{}, nil
}
func (f *fakeFacadeBackend) SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error) {
	f.hit()
	return dpuserspace.ProcessStatus{}, nil
}
func (f *fakeFacadeBackend) SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	f.hit()
	return dpuserspace.ProcessStatus{}, nil
}
func (f *fakeFacadeBackend) SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	f.hit()
	return dpuserspace.ProcessStatus{}, nil
}
func (f *fakeFacadeBackend) InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error) {
	f.hit()
	return dpuserspace.ProcessStatus{}, nil
}

// The runtime capability probes. Each returns a value distinguishable from its
// revoked/absent counterpart so a test can tell "reached the backend" from
// "stopped at the facade" without counting hits.
func (f *fakeFacadeBackend) AppliedNATView() dpuserspace.AppliedNATView {
	f.hit()
	return dpuserspace.AppliedNATView{Available: true}
}
func (f *fakeFacadeBackend) PolicySchedulerActiveState() map[string]bool {
	f.hit()
	return map[string]bool{"sched1": true}
}
func (f *fakeFacadeBackend) IterateSessionsFrom(*dataplane.SessionKey, func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	f.hit()
	return nil
}
func (f *fakeFacadeBackend) IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	f.hit()
	return nil
}

// TestFacadeEveryGateIsBound is the EXHAUSTIVE half of the revocation proof.
//
// It exists because the hand-written assertions below name a dozen methods out
// of ~36 delegators, and a hand-picked sample is a coverage claim nobody can
// check: the other two dozen `if !f.live()` guards could be deleted with a green
// suite. Rather than restate the list and get it wrong again, this walks the
// facade's method set by reflection and drives BOTH directions on every method:
//
//	LIVE     -> the call must REACH the backend (a gate stuck closed is a
//	            silently dead capability, which is F1's failure mode again);
//	REVOKED  -> the call must NOT reach the backend.
//
// A delegator added without a live() guard fails the revoked direction; one
// whose guard never opens fails the live direction. Adding a method to the
// facade extends this test automatically — there is no list to forget.
func TestFacadeEveryGateIsBound(t *testing.T) {
	facadeType := reflect.TypeOf((*dataplaneFacade)(nil))

	// Revoke is the gate's own control surface, not a delegator: it has no
	// backend call to stop and is asserted separately below.
	const controlMethod = "Revoke"

	var checked int
	for i := 0; i < facadeType.NumMethod(); i++ {
		m := facadeType.Method(i)
		if m.Name == controlMethod {
			continue
		}
		checked++
		t.Run(m.Name, func(t *testing.T) {
			// Zero-valued arguments are safe for every signature here: the
			// facade either returns before touching them, or hands them to the
			// fake, which ignores them. Nil callbacks and nil cursors are the
			// point — nothing must dereference them.
			args := func(recv *dataplaneFacade) []reflect.Value {
				in := []reflect.Value{reflect.ValueOf(recv)}
				for a := 1; a < m.Type.NumIn(); a++ {
					in = append(in, reflect.New(m.Type.In(a)).Elem())
				}
				return in
			}

			live := &fakeFacadeBackend{}
			f := newDataplaneFacade(live)
			if f == nil {
				t.Fatal("precondition: a satisfying backend must produce a facade")
			}
			m.Func.Call(args(f))
			if live.reached != 1 {
				t.Fatalf("%s did NOT reach the backend while LIVE (%d calls) — this gate is "+
					"stuck closed, so the capability is dead even with a healthy dataplane",
					m.Name, live.reached)
			}

			f.Revoke()
			before := live.reached
			m.Func.Call(args(f))
			if live.reached != before {
				t.Fatalf("%s REACHED THE BACKEND after Revoke() — this delegator has no live() "+
					"guard, so a consumer holding the revoked handle still drives the dataplane (#5275)",
					m.Name)
			}
		})
	}

	// A narrowed walk (a receiver typo, a method set that stopped resolving)
	// must read as a FAILURE rather than a clean run over nothing. Bump this
	// deliberately when the facade genuinely gains or loses a delegator.
	const wantDelegators = 36
	if checked != wantDelegators {
		t.Fatalf("walked %d delegators, expected %d — if the facade genuinely changed, update "+
			"wantDelegators; if not, the reflection walk has narrowed and is proving less than "+
			"it claims", checked, wantDelegators)
	}
}

// TestFacadeRevocationStopsEveryCall is the behavioural half. A revoked facade
// must stop calls at the facade — not merely report an error while still
// reaching the backend, which would leave the mutator paths (SetForwardingArmed
// and friends) live for a consumer that captured the handle earlier.
//
// TestFacadeEveryGateIsBound above proves NO delegator reaches the backend once
// revoked. This one proves the returned VALUES are right, which reflection
// cannot judge: the sentinel error where there is an error channel, and the
// fail-closed value where there is not (SessionCount 0/0, AppliedNATView
// unavailable, a nil scheduler map that the SSOT predicate reads as inactive).
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
	// The #5275 §7 mutators specifically: these never traverse the apply gate,
	// so a revoked facade that still forwarded them would leave the exact hole
	// the facade exists to close.
	if _, err := f.SetForwardingArmed(true); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked SetForwardingArmed returned %v, want errDataplaneFacadeRevoked", err)
	}
	if _, err := f.SetQueueState(0, true, true); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked SetQueueState returned %v, want errDataplaneFacadeRevoked", err)
	}
	if _, err := f.SetBindingState(0, true, true); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked SetBindingState returned %v, want errDataplaneFacadeRevoked", err)
	}
	if _, err := f.InjectPacket(dpuserspace.InjectPacketRequest{}); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked InjectPacket returned %v, want errDataplaneFacadeRevoked", err)
	}
	// The capability probes. Two of the four have no error channel, so their
	// revoked VALUE is the whole fail-closed contract.
	if v := f.AppliedNATView(); v.Available {
		t.Error("revoked AppliedNATView reports Available — the deterministic-NAT lookup " +
			"would answer from a generation that is no longer applied")
	}
	if st := f.PolicySchedulerActiveState(); st != nil {
		t.Errorf("revoked PolicySchedulerActiveState returned %v, want nil — nil is the SSOT's "+
			"'state unpublished, treat scheduled policies as inactive' value (#3414), and a "+
			"non-nil map would let the detail display keep rendering a policy enabled", st)
	}
	if err := f.IterateSessionsFrom(nil, nil); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked IterateSessionsFrom returned %v, want errDataplaneFacadeRevoked", err)
	}
	if err := f.IterateSessionsV6From(nil, nil); !errors.Is(err, errDataplaneFacadeRevoked) {
		t.Errorf("revoked IterateSessionsV6From returned %v, want errDataplaneFacadeRevoked", err)
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

// TestProductionBackendSatisfiesTheFacadeUnion pins the F2 half of the
// construction gate at RUNTIME as well as at compile time.
//
// newDataplaneFacade returns nil when the backend does not satisfy the whole
// union, and a nil facade nils the dataplane for gRPC AND REST AND the CLI at
// once — every management surface reporting "dataplane not loaded", from a
// green build and a green suite. `var _ facadeBackend =
// (*dpuserspace.LegacyDataPlaneAdapter)(nil)` in dataplane_facade.go is the
// primary belt; this asserts the same fact through the CONSTRUCTOR, so deleting
// that line to make a build pass does not silently delete the protection with
// it.
//
// The adapter is used zero-valued on purpose: the union check reads the method
// SET and calls nothing, so no helper process or socket is involved.
func TestProductionBackendSatisfiesTheFacadeUnion(t *testing.T) {
	if f := newDataplaneFacade(&dpuserspace.LegacyDataPlaneAdapter{}); f == nil {
		t.Fatal("the production dataplane backend (*dpuserspace.LegacyDataPlaneAdapter) does " +
			"NOT satisfy facadeBackend, so newDataplaneFacade returns nil at boot and gRPC, " +
			"REST and the CLI would all report the dataplane as unavailable (#5275)")
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
	// DERIVED, not hand-maintained. The consumer mirrors are discovered by
	// scanning runtime_probes.go for the interfaces the facade must satisfy,
	// so adding a FIFTH external consumer mirror cannot pass by being absent
	// from a list somebody forgot to extend — the scan finds it and then
	// demands a construction site for it.
	probes, err := os.ReadFile("runtime_probes.go")
	if err != nil {
		t.Fatalf("read runtime_probes.go: %v", err)
	}
	mirrorRe := regexp.MustCompile(`(?m)^type (\w*DataPlane) interface \{`)
	var mirrors []string
	for _, m := range mirrorRe.FindAllStringSubmatch(string(probes), -1) {
		mirrors = append(mirrors, m[1])
	}
	sort.Strings(mirrors)

	// Count assertion: an accidental narrowing of the scan (a changed regexp,
	// a renamed declaration) must read as a FAILURE, not as a clean run over
	// fewer files. Bump this deliberately when a consumer is genuinely added
	// or removed.
	const wantMirrors = 3
	if len(mirrors) != wantMirrors {
		t.Fatalf("discovered %d consumer mirrors %v, expected %d — if a consumer was genuinely "+
			"added or removed, update wantMirrors AND give the new one a construction site; if "+
			"not, the scan has narrowed and is no longer proving anything",
			len(mirrors), mirrors, wantMirrors)
	}

	// Every discovered mirror must be constructed from the facade somewhere,
	// and nowhere may re-assert the raw backend to it.
	sources := map[string]string{}
	for _, f := range []string{"daemon_run_servers.go", "daemon_run.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sources[f] = string(b)
	}

	for _, mirror := range mirrors {
		t.Run(mirror, func(t *testing.T) {
			declRe := regexp.MustCompile(`(?m)^\s*var \w+ ` + mirror + `\b`)
			rawRe := regexp.MustCompile(`d\.dp\.\(` + mirror + `\)`)

			var constructedIn string
			for f, text := range sources {
				if rawRe.MatchString(text) {
					t.Fatalf("%s asserts d.dp.(%s) — this consumer has been re-pointed at the "+
						"raw backend, reinstating the un-revocable alias the facade removes (#5275)",
						f, mirror)
				}
				if declRe.MatchString(text) {
					constructedIn = f
				}
			}
			if constructedIn == "" {
				t.Fatalf("no construction site found for %s in %v — a consumer mirror exists with "+
					"no wiring this test can verify; either it is dead and should be deleted, or "+
					"its construction site must be added to the scanned set (#5275)",
					mirror, []string{"daemon_run_servers.go", "daemon_run.go"})
			}
			if !strings.Contains(sources[constructedIn], "d.dpFacade") {
				t.Fatalf("%s constructs a %s consumer but never reads d.dpFacade — the consumer "+
					"holds a raw backend alias that d.dp = nil cannot revoke (#5275)",
					constructedIn, mirror)
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
