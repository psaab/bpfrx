package dataplane

import (
	"errors"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

// ErrDataplaneNotArmed is returned by class-1 (fallible, map-required)
// Manager methods when the registry is in the FRESH-unarmed state —
// loaded == false AND no maps populated — where master previously returned
// the per-map "… not found" error (or, on the concurrent path the #2114
// research proved, a fatal concurrent-map read/write against the
// populating Start). Wrapped with %w at each gate site; match with
// errors.Is. It deliberately does NOT fire on the RETAINED-unarmed state
// (Close/Teardown keep the pinned-map registry live for hitless restart
// and bootstrap re-arm): retained reads report the retained state and
// retained mutations reach the retained maps, exactly as master.
var ErrDataplaneNotArmed = errors.New("dataplane not armed")

// registryState is the Manager's armedness classification, computed under
// m.mu (#2114 A3). The two-state unarmed split is load-bearing: FRESH is
// the only state the armed gate fires on.
type registryState int

const (
	// registryFresh: loaded == false AND the map registry is empty — the
	// manager was never armed (New()) or never completed a shim load. This
	// is exactly where master's fallible map accessors returned their
	// "… map not found" errors, so it is where the typed gate error
	// replaces them. (A nonempty m.programs alone does NOT make the
	// manager retained — the predicate reads m.maps emptiness.)
	registryFresh registryState = iota
	// registryRetained: loaded == false with a populated registry — an
	// armed manager's Close (hitless restart keeps the pinned-map handles
	// live), a Teardown-retained bootstrap manager, or a test fixture with
	// injected maps. Every class proceeds exactly as master here.
	registryRetained
	// registryArmed: loaded == true. Store(true) is the publication
	// batch's final in-hold step (publishShimRegistryLocked), so a reader
	// released from a lookup helper's hold observes a fully populated
	// registry.
	registryArmed
)

// String renders the registry state for gate diagnostics.
func (st registryState) String() string {
	switch st {
	case registryFresh:
		return "fresh"
	case registryRetained:
		return "retained"
	case registryArmed:
		return "armed"
	}
	return "unknown"
}

// classifyRegistry computes the armedness classification from the registry
// length. Callers hold m.mu (the loaded flag is atomic, but the
// maps-emptiness read must not race the publication batch's inserts) — the
// two lookup helpers pass their in-hold len(m.maps) reading so the
// classification and the handle selection stay one scoped operation and
// the registry canary's allowlist stays exactly the two helpers + the
// publisher.
func classifyRegistry(loaded *atomic.Bool, numMaps int) registryState {
	if loaded.Load() {
		return registryArmed
	}
	if numMaps == 0 {
		return registryFresh
	}
	return registryRetained
}

// registryLookupHook, when non-nil, runs INSIDE the lookup helpers' m.mu
// hold (#2114 A3 test seam, lock-ownership legs). Protocol: hooks are
// seam-scoped package vars, only ONE ownership hook is armed per test
// (two hooks on the same mutex cannot both be awaited — the second cannot
// execute while the first holds it), and the assertion is either
// TryLock()==false inside the actual access interval or a
// before-lock/after-acquire handshake. Production leaves it nil (one nil
// check per registry lookup, never on the packet path).
var registryLookupHook func()

// muAcquireProbeHook, when non-nil, runs at the ENTRY of the contended
// m.mu surfaces — BEFORE the m.mu.Lock call — in lookupMapLocked,
// lookupProgramLocked, publishShimRegistryLocked, and XDPEntryProgram
// (#2114 A3 test seam, Codex PR #6743 r3-8). The blocking legs signal
// arrival from here: a handshake closed BEFORE the goroutine's contended
// call leaves a preemption window in which the non-completion timeout
// can pass without the goroutine ever reaching the mutex (a false-green
// "it blocked" proof); the in-call pre-lock signal proves the goroutine
// arrived at the contended acquisition. The site argument names the
// function so a test can filter. Production leaves it nil (one nil
// check per call, control plane only).
var muAcquireProbeHook func(site string)

// lookupMapLocked performs the uniform #2114 A3 registry access for
// m.maps: under ONE scoped m.mu hold it classifies the manager's
// armedness and selects the named handle ATOMICALLY, so the gate outcome
// and the handle copy can never race the whole-batch publication.
// present is the comma-ok bit, distinguishing present-but-nil (test
// fixtures insert nil handles) from absent. The caller owns the OUTCOME
// per its class: the helper wraps the lookup, never the outcome.
func (m *Manager) lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState) {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("lookupMapLocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if registryLookupHook != nil {
		registryLookupHook()
	}
	h, present = m.maps[name]
	return h, present, classifyRegistry(&m.loaded, len(m.maps))
}

// lookupProgramLocked is lookupMapLocked for the m.programs registry
// (different value type, same uniform rule).
func (m *Manager) lookupProgramLocked(name string) (p *ebpf.Program, present bool, st registryState) {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("lookupProgramLocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if registryLookupHook != nil {
		registryLookupHook()
	}
	p, present = m.programs[name]
	return p, present, classifyRegistry(&m.loaded, len(m.maps))
}

// shimRegistryPublishHook runs INSIDE the publisher's m.mu hold BEFORE
// the loaded.Store(true) step (#2114 A3 blocked-Start test seam: readers
// gated on the hold observe the pre-arm state and block; after release
// they observe armed). shimRegistryPublishPostStoreHook runs inside the
// hold AFTER Store(true) and before unlock — the pass-then-block seam
// for the loaded-check set (a method that passes its pre-registry
// IsLoaded check once Store(true) has landed and then blocks at registry
// selection). Same one-armed-hook-per-test protocol as
// registryLookupHook. Production leaves both nil.
var shimRegistryPublishHook func()
var shimRegistryPublishPostStoreHook func()

// publishShimRegistryLocked is the ONE whole-batch publication of the
// userspace shim registry (#2114 A3): the program assignment, both map
// insert loops, and the armed flag land as a single m.mu critical
// section. A reader released from a lookup helper's hold observes either
// the pre-arm state or the FULLY populated armed registry — never a
// partial one (the first insertion would otherwise flip fresh→retained
// while population was still partial). Acquisition (collection
// construction, program lookup, pinning) stays OUTSIDE the lock in
// loadUserspaceShimObjectsOnce.
func (m *Manager) publishShimRegistryLocked(prog *ebpf.Program, collMaps, sharedMaps map[string]*ebpf.Map) {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("publishShimRegistryLocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.programs[userspaceShimEntryProg] = prog
	for name, umap := range collMaps {
		m.maps[name] = umap
	}
	for name, smap := range sharedMaps {
		m.maps[name] = smap
	}
	if shimRegistryPublishHook != nil {
		shimRegistryPublishHook()
	}
	// The armed flag is the batch's FINAL in-hold step: population is
	// sequenced-before the release-Store, so a post-release reader sees a
	// fully populated registry.
	m.loaded.Store(true)
	if shimRegistryPublishPostStoreHook != nil {
		shimRegistryPublishPostStoreHook()
	}
}

// closeWindowHook runs inside Close() immediately AFTER the entry
// loaded.Store(false) and BEFORE the link-handle closes (#2114 A3
// Close-window test seam: a concurrent IsLoaded() read observes false
// during the window where master reported true until the exit flip).
// Production leaves it nil.
var closeWindowHook func()

// swapXDPEntryProgHook runs INSIDE swapXDPEntryProg's m.mu section around
// the entry-program field write (#2114 A3 lock-ownership test seam).
// Production leaves it nil.
var swapXDPEntryProgHook func()

// xdpEntryProgSelectorHook runs INSIDE the m.mu section of the
// LoadUserspaceShim selector write (SelectUserspaceXDPShimEntryProgram)
// and the public getter (#2114 A3 two-sided selector seam). Production
// leaves it nil.
var xdpEntryProgSelectorHook func()
