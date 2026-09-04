package vrrp

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// vrrpInstance timing: advertisement interval derivation (local vs learned),
// master-down interval, and the shared timer stop/drain helper.
// Split out of instance.go for the #8090 modularity floor. Pure move.

// initialMasterDownInterval is the master-down interval run() arms at startup.
//
// EXTRACTED so the deafness policy is checkable rather than a literal inside a
// run-loop local (#7579). It is the STARTUP half of the pair; the release half
// is masterDownAfterSyncHoldRelease below, and the two sharing
// deafMasterDownInterval is what stops one drifting from the other.
func (vi *vrrpInstance) initialMasterDownInterval() time.Duration {
	if !vi.getPreempt() {
		return deafMasterDownInterval
	}
	return vi.masterDownInterval()
}

// masterDownAfterSyncHoldRelease reports the master-down interval to arm when a
// sync-hold release did NOT promote, and whether to re-arm at all (#7579).
//
// Returns (_, false) for a node that IS preempting — including the priority-255
// address owner, for which getPreempt() is true irrespective of the no-preempt
// flag. Such a node wants the short interval and a prompt promotion, and
// re-arming it would be a failover regression.
//
// Returns (deafMasterDownInterval, true) otherwise: the release declined to
// promote, so this node stays BACKUP, and it is entering the second deafness
// window described on deafMasterDownInterval. Self-limiting — handleBackupRx
// resets to the short interval on the first advert heard.
func (vi *vrrpInstance) masterDownAfterSyncHoldRelease() (time.Duration, bool) {
	if vi.getPreempt() {
		return 0, false
	}
	return deafMasterDownInterval, true
}

// advertInterval returns the advertisement interval as a Duration.
// AdvertiseInterval is in milliseconds. The cfg field is snapshotted under
// vi.mu.RLock() — mirroring the other config accessors (masterDownInterval,
// preemptHoldDuration) — so a concurrent locked config update cannot race the
// read that go test -race would otherwise flag (#6230). The lock is released
// before the Duration math, matching the masterDownInterval idiom.
//
// Callers that ALREADY hold vi.mu (masterAdverFloor, reached from
// recordMasterAdvert under vi.mu.Lock) MUST use advertIntervalLocked instead:
// re-taking the RLock while the write lock is held would deadlock.
func (vi *vrrpInstance) advertInterval() time.Duration {
	vi.mu.RLock()
	ms := vi.cfg.AdvertiseInterval
	vi.mu.RUnlock()
	return advertIntervalFromMS(ms)
}

// advertIntervalLocked returns the advertisement interval as a Duration for
// callers that already hold vi.mu (read or write). It performs the same read as
// advertInterval WITHOUT taking the lock, for paths that run under vi.mu.Lock
// (recordMasterAdvert → masterAdverFloor); calling advertInterval there would
// deadlock on the RLock (#6230).
func (vi *vrrpInstance) advertIntervalLocked() time.Duration {
	return advertIntervalFromMS(vi.cfg.AdvertiseInterval)
}

// advertIntervalFromMS converts a configured advertise interval in
// milliseconds (0 or negative → the 1000 ms default) to a Duration.
//
// #8642: the ceiling is as load-bearing as the floor here, and this is the most
// severe site in that sweep. `vg.AdvertiseInterval` is set by a bare
// `strconv.Atoi` with no range check (compiler_interfaces.go), the schema
// ceilings (1..40 for `advertise-interval`, 10..40959 for
// `reth-advertise-interval`) are downgraded to warnings on the tolerant
// Store.Load / peer-sync ingress, and the old `ms <= 0` guard was blind to
// overflow by construction: past MaxDurationMillis the multiply wraps, and with
// `gcd(1e6, 2^64) = 64` the residue bottoms out at **64ns**.
//
// A 64ns advertisement timer on a RETH instance is an advert storm on the
// 30ms heartbeat HA failover timing is built on — the control-path starvation
// CLAUDE.md warns about, at ~1.5e7/s.
func advertIntervalFromMS(ms int) time.Duration {
	return config.MillisToDuration(ms, 1000*time.Millisecond)
}

// effectiveAdvertInterval picks the advertisement interval that drives the
// Master_Down_Interval / Skew_Time computation. Per RFC 5798 §6.1/§6.4.2 a
// BACKUP times the master out on the interval the MASTER advertises
// (Master_Adver_Interval, learned from the received advert's Max Adver Int),
// falling back to the locally-configured interval only before any advert has
// been heard (cold-start). localMS is cfg.AdvertiseInterval in milliseconds;
// learned is the last value recorded by recordMasterAdvert (0 = none yet).
func effectiveAdvertInterval(localMS int, learned time.Duration) time.Duration {
	if learned > 0 {
		return learned
	}
	// #8642: same bound as advertIntervalFromMS — this reads the same
	// unbounded config int, so guarding only the zero end here would leave the
	// cold-start path (before any advert has been heard) carrying the overflow
	// the other path no longer has.
	return config.MillisToDuration(localMS, 1000*time.Millisecond)
}

// masterDownInterval returns the master-down timer value.
// Per RFC 5798: Master_Down_Interval = (3 * Master_Adver_Interval) + Skew_Time
// Skew_Time = ((256 - priority) * Master_Adver_Interval) / 256
//
// Master_Adver_Interval is the interval ADVERTISED BY THE CURRENT MASTER
// (learned from the received advert's Max Adver Int, §6.4.2), NOT this node's
// own configured AdvertiseInterval. Before any advert has been heard
// (masterAdverInterval == 0) the local interval is the fallback. The local
// priority is used for Skew_Time (RFC 5798 §6.1).
func (vi *vrrpInstance) masterDownInterval() time.Duration {
	vi.mu.RLock()
	localMS := vi.cfg.AdvertiseInterval
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	advert := effectiveAdvertInterval(localMS, learned)
	skew := time.Duration(256-vi.getPriority()) * advert / 256
	return 3*advert + skew
}

// stopAndDrainTimer stops t and drains a pending fire from its channel so a
// subsequent Reset arms a clean interval. Safe on an already-stopped or
// already-drained timer.
func stopAndDrainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}
