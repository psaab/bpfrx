package dataplane

import (
	"net/netip"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// PersistentNATBinding holds a NAT port mapping that survives session GC.
type PersistentNATBinding struct {
	SrcIP    netip.Addr
	SrcPort  uint16
	NatIP    netip.Addr
	NatPort  uint16
	PoolName string
	LastSeen time.Time
	Timeout  time.Duration
	// Permit is the three-way persistent-NAT remote scope (#2823/#3193):
	// any-remote-host / target-host / target-host-port. The pre-#2823
	// binary PermitAnyRemoteHost bool could not distinguish target-host
	// from target-host-port in the operator SHOW path (#3193).
	Permit config.PersistentNATPermit
}

// PermitMode returns the human-readable persistent-NAT permit scope for
// the SHOW path, resolving the zero value to the target-host-port default
// (#2823 default / #3193). It renders the actual three-way mode rather
// than the pre-#3193 binary any-remote-host flag.
func (b *PersistentNATBinding) PermitMode() string {
	if b.Permit == "" {
		return string(config.PersistentNATPermitTargetHostPort)
	}
	return string(b.Permit)
}

type persistentNATKey struct {
	SrcIP   netip.Addr
	SrcPort uint16
	Pool    string
}

// PersistentNATPoolInfo holds per-pool persistent NAT configuration.
type PersistentNATPoolInfo struct {
	Timeout time.Duration
	// Permit is the three-way persistent-NAT remote scope (#2823/#3193).
	Permit config.PersistentNATPermit
}

// PersistentNATTable stores NAT bindings that persist after session close.
type PersistentNATTable struct {
	mu          sync.RWMutex
	bindings    map[persistentNATKey]*PersistentNATBinding
	poolConfigs map[string]PersistentNATPoolInfo // pool name -> config
	natIPToPool map[netip.Addr]string            // NAT IP -> pool name
}

// NewPersistentNATTable creates a new persistent NAT table.
func NewPersistentNATTable() *PersistentNATTable {
	return &PersistentNATTable{
		bindings:    make(map[persistentNATKey]*PersistentNATBinding),
		poolConfigs: make(map[string]PersistentNATPoolInfo),
		natIPToPool: make(map[netip.Addr]string),
	}
}

// SetPoolConfig registers a persistent NAT pool configuration.
func (t *PersistentNATTable) SetPoolConfig(poolName string, cfg PersistentNATPoolInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.poolConfigs[poolName] = cfg
}

// RegisterNATIP maps a NAT IP address to its pool name for reverse lookup.
func (t *PersistentNATTable) RegisterNATIP(ip netip.Addr, poolName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.natIPToPool[ip] = poolName
}

// ClearPoolConfigs removes all pool configuration and IP mappings.
// Called before recompilation to ensure stale pools are removed.
func (t *PersistentNATTable) ClearPoolConfigs() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.poolConfigs = make(map[string]PersistentNATPoolInfo)
	t.natIPToPool = make(map[netip.Addr]string)
}

// LookupPool finds the pool name and config for a given NAT IP.
// Returns empty string and zero config if the IP is not in any persistent pool.
func (t *PersistentNATTable) LookupPool(natIP netip.Addr) (string, PersistentNATPoolInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	poolName, ok := t.natIPToPool[natIP]
	if !ok {
		return "", PersistentNATPoolInfo{}, false
	}
	cfg, ok := t.poolConfigs[poolName]
	if !ok {
		return "", PersistentNATPoolInfo{}, false
	}
	return poolName, cfg, true
}

// Lookup finds an existing persistent binding. Returns nil if not found
// or if the binding has expired.
func (t *PersistentNATTable) Lookup(srcIP netip.Addr, srcPort uint16, pool string) *PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := persistentNATKey{SrcIP: srcIP, SrcPort: srcPort, Pool: pool}
	b, ok := t.bindings[key]
	if !ok {
		return nil
	}
	if time.Since(b.LastSeen) > b.Timeout {
		return nil
	}
	return b
}

// Save stores a persistent NAT binding. If a binding with the same source
// IP, port, and pool already exists, LastSeen is updated to the current time.
func (t *PersistentNATTable) Save(b *PersistentNATBinding) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := persistentNATKey{SrcIP: b.SrcIP, SrcPort: b.SrcPort, Pool: b.PoolName}
	if existing, ok := t.bindings[key]; ok {
		existing.LastSeen = time.Now()
		return
	}
	t.bindings[key] = b
}

// GC removes expired bindings. Returns the number of bindings removed.
func (t *PersistentNATTable) GC() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, b := range t.bindings {
		if now.Sub(b.LastSeen) > b.Timeout {
			delete(t.bindings, key)
			removed++
		}
	}
	return removed
}

// ReplaceAll makes the table a SNAPSHOT of bindings, atomically (#8607).
//
// WHY A REPLACE AND NOT A LOOP OF Save. Under the userspace dataplane this
// table is not an accumulator that ages out — it is a copy of state the Rust
// helper owns, and the helper is authoritative for both existence AND expiry.
// Two things follow:
//
//   - Save would be wrong on the way in: it treats a repeat as a refresh and
//     stamps LastSeen = time.Now(), which would reset every binding's remaining
//     lifetime to the full timeout on every refresh and make the SHOW column
//     count down from a value it never had.
//   - GC would be wrong on the way out, and is unreachable anyway: it is called
//     from the conntrack sweep, which daemon_run.go disables outright on this
//     path (`gc.SkipSweep = func() bool { return true }`). A binding the helper
//     has released must disappear because it is ABSENT from the next snapshot,
//     not because a local timer expired it.
//
// Atomic because a renderer holds no lock across All(): a Clear followed by a
// loop of Save has a window in which the table is empty or half-filled, and the
// symptom of that window is the exact "No persistent NAT bindings" line #8607 is
// about — reintroduced as a rare flake instead of a permanent state.
//
// A nil or empty slice empties the table, deliberately: "the helper has no
// bindings" is an answer, and the caller is responsible for not calling this
// when it could not ASK (see the daemon refresher, which skips on error).
func (t *PersistentNATTable) ReplaceAll(bindings []*PersistentNATBinding) {
	next := make(map[persistentNATKey]*PersistentNATBinding, len(bindings))
	for _, b := range bindings {
		if b == nil {
			continue
		}
		next[persistentNATKey{SrcIP: b.SrcIP, SrcPort: b.SrcPort, Pool: b.PoolName}] = b
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bindings = next
}

// Clear removes all bindings.
func (t *PersistentNATTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.bindings = make(map[persistentNATKey]*PersistentNATBinding)
}

// Len returns the number of active bindings.
func (t *PersistentNATTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.bindings)
}

// All returns a snapshot of all current bindings. Each returned pointer
// addresses a fresh COPY of the binding, not the live table entry — so a
// caller iterating the result never aliases table state that a concurrent
// Save()/GC() mutates in place (e.g. Save updating LastSeen under the write
// lock). Returning the live pointers here was a real, -race-detectable data
// race between the SHOW path (pkg/natshow) reading LastSeen and the packet
// path calling Save() (#4811). All PersistentNATBinding fields are value
// types (netip.Addr, ints, string, time.Time, config.PersistentNATPermit),
// so a struct value copy is a complete, independent snapshot.
func (t *PersistentNATTable) All() []*PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*PersistentNATBinding, 0, len(t.bindings))
	for _, b := range t.bindings {
		cp := *b
		result = append(result, &cp)
	}
	return result
}
