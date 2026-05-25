// Package cli — runtime interface used by the interactive Junos CLI.
//
// The migration target for #1517 (sub-#1451 S2): replace the legacy
// dataplane.DataPlane parameter/field with cliRuntime, a narrow
// CLI-specific surface that lists exactly the methods pkg/cli/*.go
// invokes via c.dp.*. This mirrors the pattern already shipped by
// pkg/api (apiRuntimeDataPlane), pkg/fwdstatus (DataPlaneAccessor),
// pkg/monitoriface (RuntimeDataPlane), and pkg/conntrack
// (RuntimeDomainProvider).
//
// cliRuntime is a strict subset of dataplane.DataPlane. Every concrete
// dataplane in the tree today (the legacy eBPF Manager, the userspace
// LegacyDataPlaneAdapter, the DPDK manager) already satisfies it.
package cli

import (
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// cliRuntime is the narrow, CLI-specific view of the dataplane.
//
// Do NOT widen this set without a callsite reason. If a new c.dp.<X>
// invocation appears in pkg/cli, add it here and audit whether it
// truly needs to be on the operator-CLI surface, or whether it should
// be served via a typed domain provider on c instead.
type cliRuntime interface {
	// Lifecycle / health
	IsLoaded() bool

	// Compilation (used by candidate-config preview)
	Compile(cfg *config.Config) (*dataplane.CompileResult, error)

	// Counters
	ReadGlobalCounter(idx uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(ruleID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(filterID uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATPortCounter(id uint32) (uint64, error)
	ReadNATRuleCounter(id uint32) (dataplane.CounterValue, error)

	// Sessions
	SessionCount() (v4, v6 int)
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error

	// DNAT static entry delete (used by filtered session clear)
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	// Clear-counter / clear-session bulk ops
	ClearAllCounters() error
	ClearAllSessions() (v4, v6 int, err error)
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearPolicyCounters() error

	// Map stats + persistent NAT table (used by show + clear NAT bindings)
	GetMapStats() []dataplane.MapStats
	GetPersistentNAT() *dataplane.PersistentNATTable
}

// cliUserspaceStatusProvider is implemented by dataplanes that expose
// the userspace helper's ProcessStatus snapshot (queue/binding/CoS).
// Replaces the inline `c.dp.(interface{ Status() ... })` probes in
// cli_show_chassis.go and cli_show_system.go.
type cliUserspaceStatusProvider interface {
	Status() (dpuserspace.ProcessStatus, error)
}

// cliUserspaceControlProvider extends the status provider with the
// mutating control operations used by `request chassis cluster
// data-plane userspace ...` (the sole CLI consumer, handled in
// cli_request.go:handleRequestChassisClusterDataPlane). Replaces the
// larger inline anonymous interface probe in cli_helpers.go's
// userspaceDataplaneControl helper.
type cliUserspaceControlProvider interface {
	cliUserspaceStatusProvider
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}
