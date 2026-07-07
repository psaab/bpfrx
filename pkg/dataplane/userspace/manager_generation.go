package userspace

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

func (m *Manager) readFIBGeneration() uint32 {
	fibGenMap := m.bpfShim.Map("fib_gen_map")
	if fibGenMap == nil {
		return 0
	}
	var (
		key uint32
		gen uint32
	)
	if err := fibGenMap.Lookup(key, &gen); err != nil {
		return 0
	}
	return gen
}

// bpfKtimeNs returns the current CLOCK_BOOTTIME in nanoseconds, matching
// the clock used by BPF's bpf_ktime_get_ns() for session Created timestamps.
func (m *Manager) bpfKtimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func (m *Manager) bumpGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	return m.generation
}

// BumpFIBGeneration updates the BPF FIB generation counter and sends a
// lightweight FIB generation bump to the userspace helper. If kernel neighbors
// changed since the last publish, an incremental neighbor update is sent first.
// This avoids the full buildSnapshot() + apply_snapshot round-trip that was the
// primary source of control socket contention during route convergence.
//
// Error contract (#1844): a non-nil error means the helper-side
// invalidation is NOT confirmed (shim map bump or the
// bump_fib_generation control message failed) — callers with retry
// semantics (the ip-monitoring actuator's pendingFIBBump) must retry.
// The helperless / no-snapshot early returns are SUCCESS (nil): with
// no published snapshot there are no cached flow routes to invalidate,
// and the next full apply carries its own invalidation. A failed
// incremental NEIGHBOR update is deliberately NOT an error — it has
// its own retry semantics (the cached neighbor view is only advanced
// on success, so the next bump re-diffs and re-sends).
func (m *Manager) BumpFIBGeneration() (uint32, error) {
	newGen, shimErr := m.bpfShim.BumpFIBGeneration()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return newGen, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		return newGen, nil
	}

	// Update the cached snapshot's FIB generation without rebuilding.
	m.lastSnapshot.FIBGeneration = newGen
	m.generation++
	m.lastSnapshot.Generation = m.generation

	// #1197 v4 (Codex code-review v3 #1): refresh the monitored
	// ifindex cache UNCONDITIONALLY — link recreation can happen
	// without any neighbor diff (operator unplugs cable, kernel
	// rebinds a VLAN, etc.), and a stale cache silently drops
	// events on the new ifindex until the next config commit.
	m.rebuildMonitoredIfindexes()

	// Check if kernel neighbors changed — if so, push an incremental update.
	// #1197: use forwarding-effective diff so REACHABLE↔STALE aging churn
	// doesn't trigger unnecessary publishes; filter publish payload to
	// publishable-only entries (matches userspace-dp accept rules).
	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if !neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) {
		publishable := filterPublishableNeighbors(newNeighbors)
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{
			Type:            "update_neighbors",
			Neighbors:       publishable,
			NeighborReplace: true,
		}, &status); err != nil {
			slog.Warn("userspace: failed to publish neighbor update", "err", err)
		} else {
			// Only update cached neighbors after successful publish so
			// a transient failure doesn't suppress future retries.
			m.lastSnapshot.Neighbors = newNeighbors
			m.rebuildNeighborIndex() // #1197
		}
	}

	// Send lightweight FIB generation bump — no full snapshot rebuild.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type: "bump_fib_generation",
		Snapshot: &ConfigSnapshot{
			// #3767 H4: the helper now version-gates bump_fib_generation
			// exactly like apply_snapshot. Stamp the protocol version so a
			// legitimate route-only bump is accepted; an unversioned (0)
			// message is rejected as a mixed-version / corrupt client.
			Version:       ProtocolVersion,
			FIBGeneration: newGen,
		},
	}, &status); err != nil {
		slog.Warn("userspace: failed to bump FIB generation", "err", err)
		return newGen, fmt.Errorf("bump fib generation: %w", err)
	}
	return newGen, shimErr
}
