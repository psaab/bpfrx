package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// --- #6169 across-reboot heartbeat anti-replay (boot epoch) ----------------
//
// #5477/#6167 gave the receiver a bounded set (heartbeatReplaySessions = 64) of
// per-session high-water counters. That raises an on-link replay attacker's
// cost but is NOT an absolute bar: ring eviction is FIFO and is triggered by
// ANY never-seen session INCLUDING a replayed one, so an attacker holding
// heartbeatReplaySessions+1 captured authenticated sessions can churn the ring
// by replay alone and sustain forged peer liveness indefinitely (measured: 64
// recordings -> 0/640 replays admitted; 65 -> 650/650 admitted).
//
// The complete fix needs a total order the receiver can compare across peer
// incarnations. Session ids are random and unordered, so the frame must carry
// one: a per-daemon-incarnation BOOT EPOCH that strictly increases across
// daemon restarts and reboots. The receiver keeps the highest epoch it has ever
// accepted and rejects anything below it in O(1) state, BEFORE the session ring
// is touched — so a retired incarnation can never be replayed once a newer one
// has been seen, and a rejected frame never churns the ring (the bypass that
// closed the earlier attempt in #6370).
//
// The epoch rides INSIDE the signed span; see marshalHeartbeatAuthEpoch.

const (
	// bootEpochLabel domain-separates the boot-epoch section marker from every
	// other use of the control-link PSK. Versioned so a future section layout
	// change gets a distinct, non-colliding marker for free.
	bootEpochLabel = "xpf-ha-boot-epoch-v1"

	// heartbeatEpochMarkerSize is the length of the key-derived section marker.
	//
	// The marker is HMAC(PSK, bootEpochLabel)[:8], NOT a fixed ASCII magic. A
	// fixed magic would be matchable by ordinary body bytes: the section is
	// located by scanning backwards from the (fixed-size) auth trailer, so the
	// bytes just before it are the tail of the version section — a stable,
	// build-specific string. A colliding software-version string would collide
	// on EVERY frame of that build, deterministically, and because the receiver
	// LATCHES the high-water epoch, a bogus body-derived epoch read as a uint64
	// (~7e18) would sit far above a genuine wall-clock-seeded one (~1.8e18) and
	// permanently lock the peer out. A key-derived marker removes that class
	// entirely: it is a PRF value an attacker cannot compute without the PSK,
	// and an archived legacy body collides only at ~2^-64 per frame.
	heartbeatEpochMarkerSize = 8

	// heartbeatEpochFieldSize is the little-endian uint64 epoch itself.
	heartbeatEpochFieldSize = 8

	// heartbeatEpochSectionSize is the whole optional section: marker + epoch.
	heartbeatEpochSectionSize = heartbeatEpochMarkerSize + heartbeatEpochFieldSize
)

// bootEpochPath is where the boot epoch is persisted. /var/lib/xpf is the
// persistent runtime-state root xpf already uses for durable identity counters
// (SNMPv3 engineBoots, the config DB), so a rebooted appliance re-reads its
// last epoch instead of restarting from zero. Overridden in tests.
var bootEpochPath = "/var/lib/xpf/ha-boot-epoch"

// heartbeatEpochMarker derives this cluster's boot-epoch section marker from
// the control-link PSK. Both nodes hold the same PSK (#6624 makes it mandatory
// for a chassis cluster), so both derive the same marker.
func heartbeatEpochMarker(authKey []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte(bootEpochLabel))
	return mac.Sum(nil)[:heartbeatEpochMarkerSize]
}

// heartbeatFrameEpoch reads the boot epoch out of a heartbeat frame.
//
// CALLER CONTRACT: only call this on a frame whose auth trailer has ALREADY
// been located and whose HMAC has ALREADY verified. Only a verified frame
// authorises treating len-heartbeatAuthTrailerSize as the end of the signed
// body; the keyless / unverified path must never consult the marker, or an
// attacker could steer the epoch by appending bytes.
//
// Returns ok=false for a frame from a peer that does not emit the section (a
// not-yet-upgraded build, or one that could not durably persist its epoch).
// Such a frame is not rejected — it falls through to the legacy session ring
// (dual-accept; see the migration note on heartbeatAuthState.admitAuthed).
func heartbeatFrameEpoch(data, authKey []byte) (uint64, bool) {
	if len(authKey) == 0 || len(data) < heartbeatAuthTrailerSize {
		return 0, false
	}
	bodyEnd := len(data) - heartbeatAuthTrailerSize
	// Never index into (or before) the fixed header: a canonical zero-RG body is
	// 13 bytes, so a short legacy frame must read as "no epoch" rather than
	// slicing out of range.
	if bodyEnd < heartbeatHeaderSize+heartbeatEpochSectionSize {
		return 0, false
	}
	markerAt := bodyEnd - heartbeatEpochSectionSize
	if !hmac.Equal(data[markerAt:markerAt+heartbeatEpochMarkerSize], heartbeatEpochMarker(authKey)) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data[markerAt+heartbeatEpochMarkerSize : bodyEnd]), true
}

// nextBootEpoch computes this daemon incarnation's boot epoch and persists it
// durably, returning ok=false when it could NOT be durably written.
//
// The value is
//
//	max(persisted_previous + 1, wall_clock_nanoseconds)
//
// The two terms cover the two failure modes neither survives alone:
//
//   - Wall clock STEPS BACKWARDS across a restart (RTC skew, an NTP step, a
//     manual set-back): persisted+1 dominates, so the new incarnation is still
//     strictly above the last one and a genuinely restarted peer is never
//     mistaken for a replay of its own retired incarnation.
//   - Persisted state is LOST (fresh image, wiped /var/lib, first boot): the
//     wall clock dominates, so the new incarnation lands far above any retired
//     low counter and replayed old-epoch frames stay below it.
//
// RESOLUTION IS NANOSECONDS, deliberately. A coarser (say second-resolution)
// seed lets two incarnations that start within the same integer second draw
// IDENTICAL seeds — a defect already on record on a sibling change. Here even
// that would be covered by the persisted+1 term, but nanoseconds means the
// wall-clock term alone is already unique across any realistic process
// restart (a daemon restart takes milliseconds).
//
// PERSIST-BEFORE-EMIT: the epoch is only advertised on the wire once it is
// durably on disk. A node that cannot write simply advertises no epoch, and
// its peer falls back to the #6167 session ring — degraded to the previous
// posture, never wedged. That is the whole reason this mechanism costs no HA
// availability: there is no state in which a healthy node's heartbeats become
// unacceptable to a healthy peer.
func nextBootEpoch(path string) (uint64, bool) {
	now := time.Now().UnixNano()
	epoch := uint64(0)
	if now > 0 {
		epoch = uint64(now)
	}

	var prev uint64
	if data, err := os.ReadFile(path); err == nil {
		if n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); perr == nil {
			prev = n
		} else {
			slog.Warn("cluster: HA boot-epoch state unreadable; seeding from wall clock", "path", path)
		}
	} else if !os.IsNotExist(err) {
		// A missing file is first boot (prev stays 0 — the wall clock seeds it),
		// not an error. Any other read error still degrades to the wall-clock
		// seed rather than failing heartbeat start.
		slog.Warn("cluster: HA boot-epoch state read error; seeding from wall clock",
			"path", path, "err", err)
	}

	// prev+1 overflows to 0 only for a corrupt prev == MaxUint64 (~500 years of
	// nanoseconds away). Never wrap: the wall-clock seed simply wins.
	if next := prev + 1; next > epoch && next != 0 {
		epoch = next
	}
	// 0 is the reserved "no epoch" sentinel (see Manager.heartbeatBootEpoch), so
	// never publish it — only reachable with a wall clock at the Unix epoch and
	// no persisted state.
	if epoch == 0 {
		epoch = 1
	}

	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("cluster: HA boot-epoch state dir create failed; heartbeats will carry no epoch "+
			"(anti-replay falls back to the bounded session ring)", "path", path, "err", err)
		return 0, false
	}
	if err := fsatomic.WriteFileDurable(path, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
		slog.Warn("cluster: HA boot-epoch state persist failed; heartbeats will carry no epoch "+
			"(anti-replay falls back to the bounded session ring)", "path", path, "err", err)
		return 0, false
	}
	return epoch, true
}

// heartbeatBootEpoch returns this daemon incarnation's boot epoch, or 0 when it
// is not (yet) available — the reserved "advertise no epoch" sentinel.
//
// Resolution runs ASYNCHRONOUSLY, exactly once per Manager, and is kicked off
// by the first keyed heartbeat send. It must not run inline: resolving fsyncs
// the state file, and an fsync against a wedged disk can block for minutes.
// Blocking the 100ms send loop that long would stop heartbeats altogether and
// cause the very failover this mechanism exists to protect. Until resolution
// completes (and forever, if it fails) the sender simply advertises no epoch
// and the receiver falls back to the bounded session ring.
func (m *Manager) heartbeatBootEpoch() uint64 {
	if m == nil {
		return 0
	}
	m.bootEpochOnce.Do(func() {
		// Read the path on THIS goroutine, not inside the worker: bootEpochPath
		// is a package var that tests override, and a worker reading it later
		// would race with the next test's write.
		path := bootEpochPath
		go func() {
			if epoch, ok := nextBootEpoch(path); ok {
				m.bootEpoch.Store(epoch)
				slog.Info("cluster: HA boot epoch resolved; heartbeats now carry across-reboot anti-replay")
			}
		}()
	})
	return m.bootEpoch.Load()
}
