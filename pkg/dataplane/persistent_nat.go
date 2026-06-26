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

// All returns a snapshot of all current bindings.
func (t *PersistentNATTable) All() []*PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*PersistentNATBinding, 0, len(t.bindings))
	for _, b := range t.bindings {
		result = append(result, b)
	}
	return result
}
