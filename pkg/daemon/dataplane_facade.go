package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5275 PR2 — the shared revocable dataplane facade.
//
// THE PROBLEM. Setting d.dp = nil does not contain the backend. gRPC, REST and
// the CLI capture a backend ALIAS at construction (daemon_run_servers.go, and
// cli.New) and hold it for the process lifetime, so they keep a live handle
// after the daemon has dropped its own. Several of the methods they reach are
// mutators — SetForwardingArmed, SetQueueState, SetBindingState via the CLI's
// userspaceDataplaneControl path — that never traverse the apply gate. On
// bootstrap-exit, management already holds the backend when a later arm fails.
//
// THE FIX. Every external consumer holds THIS type instead of the backend.
// Revoking it stops all of them at once, and the revocation is sticky and
// atomic against concurrent calls.
//
// WHAT THIS PR DOES NOT DO. It does not SEAL the facade. The plan's "starts
// SEALED, opened at the final arm proof" is a change to the CONSTRUCTOR and to
// the release path, and belongs with the PR that actually gates; here the facade
// is constructed LIVE and stays live until the daemon drops the dataplane.
//
// IT DOES REVOKE, AND ON A LIVE PATH — do not read the paragraph above as
// "nothing calls Revoke()". setDataplane revokes the outgoing facade at every
// one of its five call sites, and one of them runs after the servers exist:
// runBootstrapExitStartup (daemon_run_naming.go) calls setDataplane(nil) when
// the bootstrap-exit dataplane arm FAILS, long after gRPC/REST/CLI were started
// and captured the handle. The other four are in bringup, which completes before
// any server is constructed, so they revoke a facade nobody holds.
//
// So this PR is NOT behaviour-identical on that one path, and the difference is
// the point of #5275: an arm failure at bootstrap exit used to leave management
// holding a live backend alias — including the ungated mutators below — and now
// revokes it. Every other path is pure indirection. Stating this here rather
// than only in the PR body is deliberate: the safety argument has to survive in
// the artifact that ships.
//
// WHY NOT EMBED THE BACKEND INTERFACE. Embedding would let this file be ~10
// lines: embed the interface, override the few methods that need gating. It is
// the wrong choice, and wrong in a way review would not catch — an embedded
// interface SILENTLY FORWARDS every method not overridden, so any method later
// added to the backend bypasses the gate BY DEFAULT, and the failure direction
// is open. With explicit delegation a new backend method is a COMPILE ERROR
// until someone decides its gate behaviour. The verbosity below is the point:
// it is fail-closed by construction rather than by vigilance. Do not "simplify"
// this by embedding.

// errDataplaneFacadeRevoked is returned by every fallible method once the
// facade is revoked. Callers see a plain error rather than a panic or a
// zero-value that reads as real data.
var errDataplaneFacadeRevoked = errors.New("dataplane handle revoked: the dataplane is not armed for this configuration")

// facadeState is the facade's gate. The ZERO value is CLOSED on purpose: a
// zero-valued dataplaneFacade grants nothing, so a partially-constructed or
// forgotten facade fails closed rather than open. newDataplaneFacade is what
// deliberately opens it.
type facadeState int32

const (
	facadeClosed facadeState = iota // zero value — grants nothing
	facadeLive
	facadeRevoked
)

// facadeBackend is the union of everything an external consumer can reach: the
// three captured mirrors in runtime_probes.go (apiDataPlane, grpcDataPlane,
// cliDataPlane) plus every runtime capability PROBE those consumers assert
// against the handle (dataplane_facade_probes.go). It is declared here so the
// reachable surface is stated in ONE place; the three mirrors keep their own
// declarations and their own compile-time drift checks at their assignment
// sites, and the probes get theirs in dataplane_facade_probes.go.
type facadeBackend interface {
	ClearAllCounters() error
	ClearAllSessions() (int, int, error)
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearPolicyCounters() error
	Compile(cfg *config.Config) (*dataplane.CompileResult, error)
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error
	GetMapStats() []dataplane.MapStats
	GetPersistentNAT() *dataplane.PersistentNATTable
	GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	IsLoaded() bool
	IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	ReadFilterConfig(uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadGlobalCounter(uint32) (uint64, error)
	ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error)
	ReadNATPortCounter(uint32) (uint64, error)
	ReadNATRuleCounter(uint32) (dataplane.CounterValue, error)
	ReadPolicyCounters(uint32) (dataplane.CounterValue, error)
	ReadZoneCounters(uint16, int) (dataplane.CounterValue, error)
	SessionCount() (v4, v6 int)

	// THE RUNTIME CAPABILITY PROBES. Everything below is reached by a type
	// ASSERTION on the handle rather than through an assigned mirror, so a
	// method missing here does not fail to compile anywhere — the assertion
	// simply fails at runtime and the consumer takes its silent fallback.
	// Each shape, its call sites and what its loss costs are documented on the
	// matching mirror in dataplane_facade_probes.go; the compile-time proof
	// that the facade satisfies them lives there too.
	//
	// The forwarding-control mutators additionally must be GATED, not merely
	// present: they are the ones #5275 §7 calls directly exploitable on
	// bootstrap-exit, because they never traverse the apply gate.
	Status() (dpuserspace.ProcessStatus, error)
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)

	AppliedNATView() dpuserspace.AppliedNATView
	PolicySchedulerActiveState() map[string]bool
	IterateSessionsFrom(*dataplane.SessionKey, func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// Compile-time proof that the ONE backend production can put behind the facade
// actually satisfies the union. Without this, renaming a control method on the
// adapter leaves a green build, a green suite, and newDataplaneFacade returning
// nil at boot — every management surface reporting "dataplane not loaded".
//
// *dataplane.Manager is deliberately NOT asserted here even though it satisfies
// all three runtime_probes.go mirrors: it has none of the probe surface above,
// and it is unreachable as a backend. buildRuntimeDataPlane (daemon_run.go)
// resolves TypeUserspace to dpuserspace.Boot() and every other type to a
// retirement sentinel (#1476/#1525) that the caller turns into
// setDataplane(nil). If a future backend is wired in, add its assertion here —
// a type that reaches setDataplane without one gets no facade at all.
var _ facadeBackend = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

// dataplaneFacade is the single handle every external consumer holds.
type dataplaneFacade struct {
	backend facadeBackend
	state   atomic.Int32
}

// newDataplaneFacade wraps backend in a LIVE facade, or returns nil when there
// is nothing to wrap.
//
// Returning nil — rather than a facade over a nil backend — preserves today's
// exact semantics: each consumer's DP field is left nil when the daemon has no
// dataplane (NoDataplane mode), and every consumer already handles a nil DP. A
// non-nil facade wrapping nothing would flip those nil checks and change
// behaviour on a path this change is not meant to touch.
//
// WHY THE SURFACE CHECK IS ALL-OR-NOTHING. A backend that satisfies the read
// mirrors but not the probes could be served a partial facade instead of none.
// It is not, for two reasons. First, such a backend cannot exist in-tree: the
// assertion under facadeBackend proves the only reachable backend satisfies the
// whole union, so a partial path would be dead code shipped untested. Second,
// partial construction reproduces the failure mode this change exists to remove
// — a consumer whose read probes succeed and whose capability probes fail
// degrades SILENTLY, which is exactly how four capabilities were lost in the
// first cut of this PR. One loud failure beats several quiet ones.
//
// So the rejection is LOUD. It is a boot-time misconfiguration that blanks every
// management surface at once; it must not be inferable only from the symptom.
func newDataplaneFacade(backend any) *dataplaneFacade {
	if backend == nil {
		return nil
	}
	b, ok := backend.(facadeBackend)
	if !ok {
		slog.Error("dataplane backend does not satisfy the external-consumer surface; "+
			"gRPC, REST and the CLI will all report the dataplane as unavailable",
			"backend_type", fmt.Sprintf("%T", backend),
			"remediation", "add a compile-time facadeBackend assertion for this type in "+
				"pkg/daemon/dataplane_facade.go and implement the missing methods")
		return nil
	}
	f := &dataplaneFacade{backend: b}
	f.state.Store(int32(facadeLive))
	return f
}

// Revoke closes the facade permanently. It is sticky (a revoked facade never
// returns to live) and safe against concurrent in-flight calls: a call that has
// already passed live() completes against the backend, and every call after the
// store fails closed. Nothing in this PR calls it.
func (f *dataplaneFacade) Revoke() {
	if f == nil {
		return
	}
	f.state.Store(int32(facadeRevoked))
}

// live reports whether calls may reach the backend. A nil facade is not live,
// so a nil receiver fails closed instead of panicking.
func (f *dataplaneFacade) live() bool {
	if f == nil || f.backend == nil {
		return false
	}
	return facadeState(f.state.Load()) == facadeLive
}

func (f *dataplaneFacade) ClearAllCounters() error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.ClearAllCounters()
}

func (f *dataplaneFacade) ClearAllSessions() (int, int, error) {
	if !f.live() {
		return 0, 0, errDataplaneFacadeRevoked
	}
	return f.backend.ClearAllSessions()
}

func (f *dataplaneFacade) ClearFilterCounters() error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.ClearFilterCounters()
}

func (f *dataplaneFacade) ClearNATRuleCounters() error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.ClearNATRuleCounters()
}

func (f *dataplaneFacade) ClearPolicyCounters() error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.ClearPolicyCounters()
}

func (f *dataplaneFacade) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	if !f.live() {
		return nil, errDataplaneFacadeRevoked
	}
	return f.backend.Compile(cfg)
}

func (f *dataplaneFacade) DeleteDNATEntry(key dataplane.DNATKey) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.DeleteDNATEntry(key)
}

func (f *dataplaneFacade) DeleteDNATEntryV6(key dataplane.DNATKeyV6) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.DeleteDNATEntryV6(key)
}

func (f *dataplaneFacade) DeleteSession(key dataplane.SessionKey) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.DeleteSession(key)
}

func (f *dataplaneFacade) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.DeleteSessionV6(key)
}

func (f *dataplaneFacade) GetMapStats() []dataplane.MapStats {
	if !f.live() {
		return nil
	}
	return f.backend.GetMapStats()
}

func (f *dataplaneFacade) GetPersistentNAT() *dataplane.PersistentNATTable {
	if !f.live() {
		return nil
	}
	return f.backend.GetPersistentNAT()
}

func (f *dataplaneFacade) GetSessionV4(a0 dataplane.SessionKey) (dataplane.SessionValue, error) {
	if !f.live() {
		return dataplane.SessionValue{}, errDataplaneFacadeRevoked
	}
	return f.backend.GetSessionV4(a0)
}

func (f *dataplaneFacade) GetSessionV6(a0 dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	if !f.live() {
		return dataplane.SessionValueV6{}, errDataplaneFacadeRevoked
	}
	return f.backend.GetSessionV6(a0)
}

func (f *dataplaneFacade) IsLoaded() bool {
	if !f.live() {
		return false
	}
	return f.backend.IsLoaded()
}

func (f *dataplaneFacade) IterateSessions(a0 func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.IterateSessions(a0)
}

func (f *dataplaneFacade) IterateSessionsV6(a0 func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.IterateSessionsV6(a0)
}

func (f *dataplaneFacade) ReadFilterConfig(a0 uint32) (dataplane.FilterConfig, error) {
	if !f.live() {
		return dataplane.FilterConfig{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadFilterConfig(a0)
}

func (f *dataplaneFacade) ReadFilterCounters(a0 uint32) (dataplane.CounterValue, error) {
	if !f.live() {
		return dataplane.CounterValue{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadFilterCounters(a0)
}

func (f *dataplaneFacade) ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error) {
	if !f.live() {
		return dataplane.FloodState{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadFloodCounters(zoneID)
}

func (f *dataplaneFacade) ReadGlobalCounter(a0 uint32) (uint64, error) {
	if !f.live() {
		return 0, errDataplaneFacadeRevoked
	}
	return f.backend.ReadGlobalCounter(a0)
}

func (f *dataplaneFacade) ReadInterfaceCounters(a0 int) (dataplane.InterfaceCounterValue, error) {
	if !f.live() {
		return dataplane.InterfaceCounterValue{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadInterfaceCounters(a0)
}

func (f *dataplaneFacade) ReadNATPortCounter(a0 uint32) (uint64, error) {
	if !f.live() {
		return 0, errDataplaneFacadeRevoked
	}
	return f.backend.ReadNATPortCounter(a0)
}

func (f *dataplaneFacade) ReadNATRuleCounter(a0 uint32) (dataplane.CounterValue, error) {
	if !f.live() {
		return dataplane.CounterValue{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadNATRuleCounter(a0)
}

func (f *dataplaneFacade) ReadPolicyCounters(a0 uint32) (dataplane.CounterValue, error) {
	if !f.live() {
		return dataplane.CounterValue{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadPolicyCounters(a0)
}

func (f *dataplaneFacade) ReadZoneCounters(a0 uint16, a1 int) (dataplane.CounterValue, error) {
	if !f.live() {
		return dataplane.CounterValue{}, errDataplaneFacadeRevoked
	}
	return f.backend.ReadZoneCounters(a0, a1)
}

func (f *dataplaneFacade) SessionCount() (v4, v6 int) {
	// No error channel here, so a revoked facade reports zero sessions rather
	// than the last known counts — a stale count read as live is worse than an
	// obviously empty one.
	if !f.live() {
		return 0, 0
	}
	return f.backend.SessionCount()
}

func (f *dataplaneFacade) Status() (dpuserspace.ProcessStatus, error) {
	if !f.live() {
		return dpuserspace.ProcessStatus{}, errDataplaneFacadeRevoked
	}
	return f.backend.Status()
}

func (f *dataplaneFacade) SetForwardingArmed(armed bool) (dpuserspace.ProcessStatus, error) {
	if !f.live() {
		return dpuserspace.ProcessStatus{}, errDataplaneFacadeRevoked
	}
	return f.backend.SetForwardingArmed(armed)
}

func (f *dataplaneFacade) SetQueueState(q uint32, registered, armed bool) (dpuserspace.ProcessStatus, error) {
	if !f.live() {
		return dpuserspace.ProcessStatus{}, errDataplaneFacadeRevoked
	}
	return f.backend.SetQueueState(q, registered, armed)
}

func (f *dataplaneFacade) SetBindingState(slot uint32, registered, armed bool) (dpuserspace.ProcessStatus, error) {
	if !f.live() {
		return dpuserspace.ProcessStatus{}, errDataplaneFacadeRevoked
	}
	return f.backend.SetBindingState(slot, registered, armed)
}

func (f *dataplaneFacade) InjectPacket(req dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error) {
	if !f.live() {
		return dpuserspace.ProcessStatus{}, errDataplaneFacadeRevoked
	}
	return f.backend.InjectPacket(req)
}

// AppliedNATView has no error channel, so a revoked facade reports the view as
// UNAVAILABLE. That is the same value the deterministic-NAT lookup already
// produces when the dataplane is absent or has applied nothing (#5794), and
// every caller checks v.Available before reading v.Config — so this fails closed
// into an existing, tested branch rather than handing out a stale snapshot of a
// generation that is no longer applied.
func (f *dataplaneFacade) AppliedNATView() dpuserspace.AppliedNATView {
	if !f.live() {
		return dpuserspace.AppliedNATView{Available: false}
	}
	return f.backend.AppliedNATView()
}

// PolicySchedulerActiveState returns nil once revoked. Read the SSOT predicate
// before "simplifying" that: PolicyInactive treats a NIL map as "state not
// published — a scheduled policy is INACTIVE" (#3414,
// pkg/dataplane/userspace/policies_scheduler.go). So nil is the fail-CLOSED
// value on both surfaces that consume it — the policy-detail display renders
// "State: inactive" and match-policies refuses to certify a scheduled policy as
// active — which is what a revoked dataplane should say. Returning a
// last-known map instead would let the display keep asserting "enabled" for a
// dataplane that is no longer there.
func (f *dataplaneFacade) PolicySchedulerActiveState() map[string]bool {
	if !f.live() {
		return nil
	}
	return f.backend.PolicySchedulerActiveState()
}

func (f *dataplaneFacade) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.IterateSessionsFrom(cursor, fn)
}

func (f *dataplaneFacade) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	if !f.live() {
		return errDataplaneFacadeRevoked
	}
	return f.backend.IterateSessionsV6From(cursor, fn)
}

// Compile-time proof that the facade satisfies all THREE captured mirrors.
//
// These are the assertions that make the facade substitutable at the three
// construction sites. If a mirror gains a method the facade does not implement,
// this fails to compile HERE — before anyone can quietly hand a consumer the
// raw backend again to make it build.
//
// The RUNTIME capability probes get the same treatment, one file over in
// dataplane_facade_probes.go, which also documents what that proof does and does
// not cover.
var (
	_ apiDataPlane  = (*dataplaneFacade)(nil)
	_ grpcDataPlane = (*dataplaneFacade)(nil)
	_ cliDataPlane  = (*dataplaneFacade)(nil)
)
