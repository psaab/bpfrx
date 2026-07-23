package cluster

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// bootEpochPath is where the HA heartbeat boot epoch is persisted. /var/lib/xpf
// is the persistent runtime-state root xpf already uses for durable identity
// counters (SNMP engineBoots, the config DB), so a rebooted appliance re-reads
// the last epoch instead of restarting at zero. Overridable in tests.
var bootEpochPath = "/var/lib/xpf/ha-boot-epoch"

// nextBootEpoch returns this daemon incarnation's boot epoch: a value that
// STRICTLY INCREASES across daemon restarts and reboots. It is
//
//	max(persisted_previous_epoch + 1, wall_clock_nanoseconds)
//
// persisted durably. The two terms cover the two failure modes a single term
// cannot survive on its own:
//
//   - a wall-clock STEP BACKWARDS across a reboot (RTC skew, NTP correction, a
//     manual set-back): persisted+1 dominates, so the new incarnation is still
//     strictly higher than the last one — a genuinely rebooted peer is never
//     mistaken for a replay of its own retired incarnation (no failover wedge).
//   - a LOST / RESET state file (fresh image, wiped /var/lib): the wall clock
//     dominates, so the new incarnation is far above any retired low counter
//     and a replayed old-epoch frame is still below it.
//
// This is the SENDER half of the #6169 across-reboot anti-replay. The RECEIVER
// (heartbeatReceiver.epochAdmit) rejects any authenticated heartbeat whose
// epoch is below the highest it has accepted from the peer, so a retired
// incarnation can never be replayed once a newer one has been seen — closing
// the >=65-recording sustained replay the bounded session ring alone cannot
// (heartbeatReplaySessions). A persist failure is non-fatal: the returned epoch
// is still wall-clock-floored and hence monotonic in the common case, but is
// logged because the NEXT incarnation may not observe it and could repeat a
// value (which only weakens the defense back toward the ring, never wedges a
// live peer).
func nextBootEpoch(path string) uint64 {
	now := uint64(time.Now().UnixNano())

	var prev uint64
	if data, err := os.ReadFile(path); err == nil {
		if n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); perr == nil {
			prev = n
		} else {
			slog.Warn("cluster: HA boot-epoch state unreadable; seeding from wall clock",
				"path", path)
		}
	} else if !os.IsNotExist(err) {
		// A missing file is first boot (prev stays 0 — the wall clock seeds it),
		// not an error. Any other read error is surfaced but still degrades to
		// the wall-clock seed rather than failing heartbeat start.
		slog.Warn("cluster: HA boot-epoch state read error; seeding from wall clock",
			"path", path, "err", err)
	}

	epoch := now
	// prev+1 wraps to 0 only for a corrupt prev == MaxUint64 (~500 years of
	// nanoseconds away), in which case the wall-clock seed simply wins — a safe
	// degrade, never a panic.
	if next := prev + 1; next > epoch {
		epoch = next
	}

	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("cluster: HA boot-epoch state dir create failed; epoch not persisted",
			"path", path, "err", err)
		return epoch
	}
	if err := fsatomic.WriteFileDurable(path, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
		slog.Warn("cluster: HA boot-epoch state persist failed; epoch not persisted",
			"path", path, "err", err)
	}
	return epoch
}

// heartbeatBootEpoch returns this daemon incarnation's boot epoch, computing it
// exactly once (bootEpochOnce) and reusing it across heartbeat restarts. It is
// resolved lazily on the first KEYED heartbeat send, so an unkeyed cluster (and
// the many unkeyed tests) never touch the persistence path. See nextBootEpoch.
func (m *Manager) heartbeatBootEpoch() uint64 {
	m.bootEpochOnce.Do(func() {
		m.bootEpoch = nextBootEpoch(bootEpochPath)
	})
	return m.bootEpoch
}
