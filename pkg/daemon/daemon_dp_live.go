package daemon

import (
	"errors"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #2114 (Codex PR #6743 r4): the atomic cell fixes ACQUISITION — every
// daemon-side read of the runtime dataplane goes through dataplane().
// It does not, on its own, stop the acquired handle from ESCAPING: the
// three operator-facing management servers used to snapshot the
// interface value ONCE at startup and hold it for the daemon's
// lifetime, so a later setDataplane(nil) (the bootstrap-exit re-arm
// failure at daemon_run_bringup.go:502, or the retired-backend clear at
// daemon_run_naming.go:251) left gRPC, REST and the console CLI still
// dispatching into a backend the daemon had already disowned. The cell
// said "no dataplane"; `show`/`clear` said otherwise.
//
// liveDataPlane closes that gap by making the value the servers hold a
// daemon-owned indirection rather than a backend handle: every method
// re-reads the cell (one atomic load) and forwards to whatever is
// published AT CALL TIME, or reports unavailable. It is the same idiom
// the forwarding-status sampler already uses
// (forwardingStatusDaemonDataPlane, daemon_forwarding_status.go),
// widened from one method to the full management surface.
//
// SCOPE — what this does NOT do. This is a PUBLICATION protocol, not a
// LIFETIME protocol. It guarantees "the handle I dispatch into is the
// one the daemon currently publishes"; it does NOT bound the lifetime
// of a backend that is still published. The commit-confirmed rollback
// deliberately leaves a torn-down backend in the cell so a corrected
// commit can re-arm THAT object (bootstrap.go:470-475, and the
// retention contract pinned by TestDataplaneCell_RollbackRearmRecurrence),
// so between Teardown() and the re-arm a management call still reaches
// a detached backend and the retained-unarmed registry state proceeds
// exactly as it did pre-#2114. Closing that window needs a
// generation/lease on the backend itself — tracked as #6741, not
// solvable at this boundary.
//
// SCOPE — which consumers are converted. The three OPERATOR-FACING
// management surfaces (gRPC, REST, console CLI) route through
// liveDataPlane. The three DATA-PATH consumers deliberately keep their
// capture-once wiring:
//
//   - conntrack GC (daemon_run.go) and cluster SessionSync
//     (daemon_ha_sync.go) do not take a RuntimeDataPlane at all — they
//     take the DECOMPOSED dataplane.SessionStore / dataplane.Telemetry
//     domains, resolved once by SessionStoreOf/TelemetryOf. Making
//     those live would put an atomic load, an interface assertion and a
//     SessionStoreOf allocation on every per-session GC sweep and sync
//     step; both loops are also lifecycle-scoped to the commsCtx/daemon
//     ctx that the same code path cancels.
//   - the userspace event-stream loop (daemon_ha_userspace_stream.go)
//     resolves a helper-specific EventStream provider once and then owns
//     a live socket subscription; re-resolving per event would not make
//     an already-open stream point somewhere else.
//
// Those three are stated as capture-once in pkg/daemon/README.md rather
// than claimed converted.

// errDataplaneUnpublished is returned by every liveDataPlane forwarder
// when the daemon's cell is empty at call time. Callers that pre-check
// with IsLoaded() (the dominant shape across pkg/grpcapi and pkg/api:
// `dp == nil || !dp.IsLoaded()`) take their existing "dataplane not
// loaded" branch instead and never reach a forwarder.
var errDataplaneUnpublished = errors.New("dataplane not published")

// errDataplaneSurfaceUnsupported is returned when a dataplane IS
// published but does not implement the management surface. Both in-tree
// backends do (see the compile-time assertions below), so this is the
// forward-compatibility arm for a backend that implements
// RuntimeDataPlane without the operator query/clear methods — the same
// condition the pre-r4 call sites expressed by leaving Config.DP nil.
var errDataplaneSurfaceUnsupported = errors.New("published dataplane does not implement the management surface")

// liveDataPlaneSurface is the UNION of the three daemon-local management
// probes (apiDataPlane, grpcDataPlane, cliDataPlane in runtime_probes.go).
// liveDataPlane forwards to it, and the compile-time assertions at the
// bottom of this file require liveDataPlane to satisfy all three probes —
// so a method added to any probe that is missing here fails the build
// rather than silently dropping out of the live path.
type liveDataPlaneSurface interface {
	IsLoaded() bool

	Compile(cfg *config.Config) (*dataplane.CompileResult, error)

	ReadGlobalCounter(index uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)
	ReadNATPortCounter(id uint32) (uint64, error)

	ClearPolicyCounters() error
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearAllCounters() error

	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	SessionCount() (v4, v6 int)

	ClearAllSessions() (v4 int, v6 int, err error)
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	GetPersistentNAT() *dataplane.PersistentNATTable
	GetMapStats() []dataplane.MapStats
}

// liveDataPlane is the daemon-owned management-surface indirection over
// the #2114 cell. It is a VALUE type holding only the daemon pointer, so
// a copy stored in grpcapi.Server.dp / api.Server.dp / cli.CLI.dp carries
// no backend reference at all — there is nothing for a consumer to keep
// alive past a setDataplane(nil).
type liveDataPlane struct{ daemon *Daemon }

// resolve performs the single per-call cell load. Every forwarder below
// starts here; no forwarder may cache the result across calls.
func (a liveDataPlane) resolve() (liveDataPlaneSurface, error) {
	if a.daemon == nil {
		return nil, errDataplaneUnpublished
	}
	rt := a.daemon.dataplane()
	if rt == nil {
		return nil, errDataplaneUnpublished
	}
	s, ok := rt.(liveDataPlaneSurface)
	if !ok {
		return nil, errDataplaneSurfaceUnsupported
	}
	return s, nil
}

// liveDataplane returns the management-surface indirection and whether it
// should be wired at all. ok=false ONLY when the daemon can never publish
// a dataplane (nil receiver, or --no-dataplane config-only mode where the
// cell stays empty for the daemon's lifetime); the call sites then leave
// Config.DP a genuine nil interface, exactly as before r4. In every other
// mode the servers get the live indirection — including bootstrap mode,
// where the backend is constructed but not armed and the forwarders
// simply report the current unarmed truth per call instead of freezing a
// startup-time verdict.
func (d *Daemon) liveDataplane() (liveDataPlane, bool) {
	if d == nil || d.opts.NoDataplane {
		return liveDataPlane{}, false
	}
	return liveDataPlane{daemon: d}, true
}

// --- forwarders -------------------------------------------------------
//
// Uniform shape: resolve, then forward. The methods with no error return
// report the zero value on an unresolved cell, which is the same thing
// the consumers' pre-existing `dp == nil` branches produce.

func (a liveDataPlane) IsLoaded() bool {
	s, err := a.resolve()
	if err != nil {
		return false
	}
	return s.IsLoaded()
}

func (a liveDataPlane) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	s, err := a.resolve()
	if err != nil {
		return nil, err
	}
	return s.Compile(cfg)
}

func (a liveDataPlane) ReadGlobalCounter(index uint32) (uint64, error) {
	s, err := a.resolve()
	if err != nil {
		return 0, err
	}
	return s.ReadGlobalCounter(index)
}

func (a liveDataPlane) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.InterfaceCounterValue{}, err
	}
	return s.ReadInterfaceCounters(ifindex)
}

func (a liveDataPlane) ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadZoneCounters(zoneID, direction)
}

func (a liveDataPlane) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadPolicyCounters(policyID)
}

func (a liveDataPlane) ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.FilterConfig{}, err
	}
	return s.ReadFilterConfig(filterID)
}

func (a liveDataPlane) ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadFilterCounters(ruleIdx)
}

func (a liveDataPlane) ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.FloodState{}, err
	}
	return s.ReadFloodCounters(zoneID)
}

func (a liveDataPlane) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.CounterValue{}, err
	}
	return s.ReadNATRuleCounter(counterID)
}

func (a liveDataPlane) ReadNATPortCounter(id uint32) (uint64, error) {
	s, err := a.resolve()
	if err != nil {
		return 0, err
	}
	return s.ReadNATPortCounter(id)
}

func (a liveDataPlane) ClearPolicyCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearPolicyCounters()
}

func (a liveDataPlane) ClearFilterCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearFilterCounters()
}

func (a liveDataPlane) ClearNATRuleCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearNATRuleCounters()
}

func (a liveDataPlane) ClearAllCounters() error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.ClearAllCounters()
}

func (a liveDataPlane) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.IterateSessions(fn)
}

func (a liveDataPlane) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.IterateSessionsV6(fn)
}

func (a liveDataPlane) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.SessionValue{}, err
	}
	return s.GetSessionV4(key)
}

func (a liveDataPlane) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	s, err := a.resolve()
	if err != nil {
		return dataplane.SessionValueV6{}, err
	}
	return s.GetSessionV6(key)
}

func (a liveDataPlane) SessionCount() (v4, v6 int) {
	s, err := a.resolve()
	if err != nil {
		return 0, 0
	}
	return s.SessionCount()
}

func (a liveDataPlane) ClearAllSessions() (v4 int, v6 int, err error) {
	s, err := a.resolve()
	if err != nil {
		return 0, 0, err
	}
	return s.ClearAllSessions()
}

func (a liveDataPlane) DeleteSession(key dataplane.SessionKey) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteSession(key)
}

func (a liveDataPlane) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteSessionV6(key)
}

func (a liveDataPlane) DeleteDNATEntry(key dataplane.DNATKey) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteDNATEntry(key)
}

func (a liveDataPlane) DeleteDNATEntryV6(key dataplane.DNATKeyV6) error {
	s, err := a.resolve()
	if err != nil {
		return err
	}
	return s.DeleteDNATEntryV6(key)
}

// GetPersistentNAT returns the CURRENTLY published backend's persistent
// NAT table, or nil. Consumers treat nil as "not available"
// (server_diag_system_action.go's clear-persistent-nat arm), so an empty
// cell degrades to that branch rather than handing back the disowned
// backend's table. The returned pointer is a genuine escape for the
// duration of the caller's expression — that is the callers' existing
// contract (they immediately Len()/Clear() it) and is bounded by the
// same #6741 lifetime gap documented above.
func (a liveDataPlane) GetPersistentNAT() *dataplane.PersistentNATTable {
	s, err := a.resolve()
	if err != nil {
		return nil
	}
	return s.GetPersistentNAT()
}

func (a liveDataPlane) GetMapStats() []dataplane.MapStats {
	s, err := a.resolve()
	if err != nil {
		return nil
	}
	return s.GetMapStats()
}

// Compile-time assertions.
//
// The first three are the DRIFT GUARD: liveDataPlane is what the gRPC,
// REST and CLI call sites assign, so a method added to any daemon-local
// probe without a matching forwarder here fails the build at this line
// rather than silently reverting that method to a capture-once path.
//
// The last two require both in-tree backends to satisfy the union, so
// resolve()'s errDataplaneSurfaceUnsupported arm is unreachable for
// anything shipped today.
var (
	_ apiDataPlane  = liveDataPlane{}
	_ grpcDataPlane = liveDataPlane{}
	_ cliDataPlane  = liveDataPlane{}

	_ liveDataPlaneSurface = (*dataplane.Manager)(nil)
	_ liveDataPlaneSurface = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
)
