package grpcapi

import (
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// grpcRuntime is the gRPC server's domain-specific dataplane
// surface. Listed exactly to the methods the gRPC handlers
// consume on master. Narrower than dataplane.DataPlane;
// intentionally not exported.
type grpcRuntime interface {
	// Liveness probe — guards every counter / iter call site.
	IsLoaded() bool

	// Counters (read).
	ReadGlobalCounter(index uint32) (uint64, error)
	ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
	ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error)
	ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)

	// Counters (clear) — diag/clear paths.
	ClearPolicyCounters() error
	ClearFilterCounters() error
	ClearNATRuleCounters() error
	ClearAllCounters() error

	// Session store (read).
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	SessionCount() (v4, v6 int)

	// Session store (clear / delete) — `clear security flow session ...`.
	ClearAllSessions() (v4 int, v6 int, err error)
	DeleteSession(key dataplane.SessionKey) error
	DeleteSessionV6(key dataplane.SessionKeyV6) error
	DeleteDNATEntry(key dataplane.DNATKey) error
	DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

	// NAT bindings / system buffers.
	GetPersistentNAT() *dataplane.PersistentNATTable
	GetMapStats() []dataplane.MapStats
}

// sessionCursorIterator: optional cursor-based iteration; consumed via
// type assertion in server_sessions.go:getSessionsCursor.
type sessionCursorIterator interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// userspaceStatusProvider: probe for the userspace-specific Status() call.
type userspaceStatusProvider interface {
	Status() (dpuserspace.ProcessStatus, error)
}

// userspaceControlProvider: superset of statusProvider used by the
// diag/control path (queue/binding admin, forwarding-armed, inject).
type userspaceControlProvider interface {
	userspaceStatusProvider
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}
