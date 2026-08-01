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
	"sync"
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
// TWO PROPERTIES MAKE THAT ACTUALLY CLOSE THE ATTACK, and both are easy to get
// wrong:
//
//  1. A frame that carries NO epoch must not be a free bypass. The attacker's
//     captures are, by construction, mostly from BEFORE the upgrade — i.e.
//     epochless. If the receiver accepts epochless frames forever, the attacker
//     replays those and the floor is never consulted at all. Measured on the
//     first cut of this change: with the floor latched at a live peer's epoch,
//     975/975 epochless replays were still admitted. The fix is the DOWNGRADE
//     LATCH (see heartbeatAuthState.admitAuthed) plus a DURABLE floor, so the
//     latch is not reopened by a receiver restart.
//
//  2. The sender must therefore ALWAYS advertise an epoch once it runs a build
//     that can. If a storage fault made a healthy node emit epochless frames, a
//     latched peer would refuse a LIVE node — a split-brain the latch itself
//     created. So persistence failures degrade MONOTONICITY (fall back to the
//     wall clock, which is still monotonic unless the clock steps backwards),
//     never EMISSION. The invariant that buys is crisp, and is exactly what the
//     latch leans on:
//
//     a keyed heartbeat carries no epoch  <=>  the peer runs a pre-#6169 build.
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
	// LATCHES the high-water epoch, a bogus body-derived epoch would sit far
	// above a genuine wall-clock-seeded one and lock the peer out. A key-derived
	// marker removes that class entirely: it is a PRF value an attacker cannot
	// compute without the PSK, and an archived legacy body collides only at
	// ~2^-64 per frame. epochUsableAsFloor is the belt-and-braces second line.
	heartbeatEpochMarkerSize = 8

	// heartbeatEpochFieldSize is the little-endian uint64 epoch itself.
	heartbeatEpochFieldSize = 8

	// heartbeatEpochSectionSize is the whole optional section: marker + epoch.
	heartbeatEpochSectionSize = heartbeatEpochMarkerSize + heartbeatEpochFieldSize

	// epochPlausibleMax is 2200-01-01T00:00:00Z in nanoseconds — see
	// epochUsableAsFloor. A literal because time.Date is not a constant
	// expression; a test pins it against time.Date so it cannot drift.
	epochPlausibleMax uint64 = 7258118400_000000000

	// bootEpochResolveWait bounds how long the FIRST StartHeartbeat waits for
	// the boot epoch to be resolved before it starts sending.
	//
	// Without this wait the sender emits epochless frames for the first tick or
	// two of every daemon start, and a peer that has latched (see admitAuthed)
	// refuses them — a self-inflicted rejoin delay at exactly the moment the
	// cluster is converging. Resolving costs one small fsync, so the wait
	// normally returns in microseconds; the bound is what keeps a wedged disk
	// from turning a control-path call into a hang. Only the first
	// StartHeartbeat of a process can pay it (sync.Once), so a routine VRF
	// rebind never does. On timeout the sender simply starts epochless and
	// heals as soon as the resolve lands.
	bootEpochResolveWait = 2 * time.Second
)

// bootEpochPath is where this node's own boot epoch is persisted, and
// peerEpochFloorPath is where the PEER's high-water epoch (which doubles as the
// downgrade latch) is persisted. /var/lib/xpf is the persistent runtime-state
// root xpf already uses for durable identity counters (SNMPv3 engineBoots, the
// config DB). Both are overridden in tests.
var (
	bootEpochPath      = "/var/lib/xpf/ha-boot-epoch"
	peerEpochFloorPath = "/var/lib/xpf/ha-peer-epoch-floor"
)

// epochUsableAsFloor bounds what the receiver is willing to LATCH as its
// high-water epoch.
//
// The floor is a ONE-WAY DOOR: once raised it rejects everything below it, so a
// bogus far-future value locks the peer out permanently. The epoch is
// nanoseconds-since-the-Unix-epoch by construction (nextBootEpoch), so anything
// at or past the year 2200 is not a timestamp any healthy sender produces:
//
//	now (2026)          ~1.79e18 ns   ->  0.25x the bound
//	year 2200 (bound)    7.26e18 ns
//	MaxUint64            1.84e19 ns   ->  2.5x the bound  (== year 2554)
//
// MaxUint64 is ~528 years out, so it is unreachable by ordinary operation — but
// it IS reachable through a corrupted or hand-edited persist file, which is the
// only path that ever puts an arbitrary uint64 in this field. nextBootEpoch
// refuses to chain from such a value, and this is the receiver-side backstop for
// a peer running a build that does not.
//
// The bound is deliberately ONE-SIDED. A LOW epoch is permissive, not locking —
// it sits below any real floor and is simply rejected, or becomes a low floor
// that admits everything. Bounding below would reject an appliance whose RTC
// died, turning a cosmetic fault into a refused peer. And the bound is absolute
// rather than relative to the receiver's own clock, so a receiver whose own
// clock is wrong does not start refusing a healthy peer.
//
// An epoch that fails this test does NOT reject the frame and does NOT clear the
// downgrade latch — the peer still demonstrably emits epochs. It is simply not
// used as a floor.
func epochUsableAsFloor(epoch uint64) bool {
	return epoch > 0 && epoch < epochPlausibleMax
}

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
// Returns present=false for a frame from a peer running a pre-#6169 build.
func heartbeatFrameEpoch(data, authKey []byte) (epoch uint64, present bool) {
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
// durably. It ALWAYS returns a usable epoch; persisted reports whether the value
// reached stable storage.
//
// The value is
//
//	max(trusted_previous + 1, wall_clock_nanoseconds)
//
// The two terms cover the two failure modes neither survives alone:
//
//   - Wall clock STEPS BACKWARDS across a restart (RTC skew, an NTP step, a
//     manual set-back): previous+1 dominates, so the new incarnation is still
//     strictly above the last one and a genuinely restarted peer is never
//     mistaken for a replay of its own retired incarnation.
//   - Persisted state is LOST (fresh image, wiped /var/lib, first boot): the
//     wall clock dominates, so the new incarnation lands far above any retired
//     low counter and replayed old-epoch frames stay below it.
//
// RESOLUTION IS NANOSECONDS, deliberately. A coarser (say second-resolution)
// seed lets two incarnations that start within the same integer second draw
// IDENTICAL seeds — a defect already on record on a sibling change. Here even
// that would be covered by the previous+1 term, but nanoseconds means the
// wall-clock term alone is already unique across any realistic process restart
// (a daemon restart takes milliseconds).
//
// A persisted value is only chained from when it is PLAUSIBLE
// (epochUsableAsFloor). A corrupted or hand-edited file holding, say,
// MaxUint64-1 would otherwise be incremented to MaxUint64 on one boot and then
// REGRESS on the next (MaxUint64+1 overflows, so the wall clock wins), and a
// peer that had latched MaxUint64 would refuse this node forever — a permanent,
// self-inflicted lockout. Ignoring an implausible previous value degrades to the
// wall-clock seed and REWRITES the file with a sane one, healing it.
//
// PERSISTENCE FAILURE DOES NOT SUPPRESS EMISSION. The caller still advertises
// the returned epoch. Not emitting would be far worse than emitting an
// unpersisted one: a peer that has latched (admitAuthed) refuses epochless
// frames, so a storage fault would take a healthy node off the air. An
// unpersisted epoch is still wall-clock-derived and therefore still monotonic
// across a restart unless the clock ALSO steps backwards — the documented
// double fault.
func nextBootEpoch(path string) (epoch uint64, persisted bool) {
	now := time.Now().UnixNano()
	if now > 0 {
		epoch = uint64(now)
	}

	var prev uint64
	if data, err := os.ReadFile(path); err == nil {
		if n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); perr != nil {
			slog.Warn("cluster: HA boot-epoch state unreadable; seeding from wall clock", "path", path)
		} else if !epochUsableAsFloor(n) {
			// Implausible (corrupt / hand-edited). Chaining from it would push
			// this node's epoch toward MaxUint64, where the NEXT boot regresses.
			slog.Warn("cluster: HA boot-epoch state is implausible; ignoring it and reseeding from the wall clock",
				"path", path, "value", n)
		} else {
			prev = n
		}
	} else if !os.IsNotExist(err) {
		// A missing file is first boot (prev stays 0 — the wall clock seeds it),
		// not an error. Any other read error still degrades to the wall-clock
		// seed rather than failing heartbeat start.
		slog.Warn("cluster: HA boot-epoch state read error; seeding from wall clock",
			"path", path, "err", err)
	}

	if next := prev + 1; next > epoch {
		epoch = next
	}
	// 0 is the reserved "no epoch" sentinel, so never publish it — only
	// reachable with a wall clock at the Unix epoch and no persisted state.
	if epoch == 0 {
		epoch = 1
	}

	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("cluster: HA boot-epoch state dir create failed; this incarnation's epoch is NOT durable "+
			"(a backward clock step across the next restart could regress it)", "path", path, "err", err)
		return epoch, false
	}
	if err := fsatomic.WriteFileDurable(path, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
		slog.Warn("cluster: HA boot-epoch state persist failed; this incarnation's epoch is NOT durable "+
			"(a backward clock step across the next restart could regress it)", "path", path, "err", err)
		return epoch, false
	}
	return epoch, true
}

// peerEpochFloorStore persists the receiver's high-water peer epoch.
//
// The stored value is BOTH the anti-replay floor and the downgrade latch: a
// non-zero floor means "this peer has proved it runs a build that emits
// epochs", which is what lets admitAuthed refuse a later epochless frame. It
// must therefore survive a daemon restart — an in-memory-only latch is cleared
// by exactly the restart an attacker waits for.
//
// Writes are RARE and OFF the receive path: the floor only advances when a new
// peer INCARNATION is seen (a peer reboot), not per frame, and the write runs on
// its own goroutine so an fsync can never stall the heartbeat read loop.
// Failures are logged and otherwise ignored — a floor that cannot be persisted
// still works for the life of this process, and failing OPEN here is deliberate:
// no storage fault may ever make this node refuse a healthy peer.
type peerEpochFloorStore struct {
	path string

	mu      sync.Mutex
	written uint64 // high-water actually committed, so a late goroutine cannot regress the file
}

// load reads the persisted floor, returning 0 when absent, unreadable, or
// implausible. Every failure mode yields 0 — an unlatched, permissive receiver —
// because a receiver that cannot read its own state must not start refusing its
// peer.
func (s *peerEpochFloorStore) load() uint64 {
	if s == nil || s.path == "" {
		return 0
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("cluster: HA peer epoch-floor read error; starting without an across-reboot replay floor",
				"path", s.path, "err", err)
		}
		return 0
	}
	n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if perr != nil || !epochUsableAsFloor(n) {
		slog.Warn("cluster: HA peer epoch-floor is unreadable or implausible; starting without an across-reboot replay floor",
			"path", s.path)
		return 0
	}
	s.mu.Lock()
	s.written = n
	s.mu.Unlock()
	return n
}

// store durably records an advanced floor. Safe to call from any goroutine;
// concurrent calls are serialized and a stale one can never lower the file.
func (s *peerEpochFloorStore) store(epoch uint64) {
	if s == nil || s.path == "" || !epochUsableAsFloor(epoch) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch <= s.written {
		return
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(s.path), 0o755); err != nil {
		slog.Warn("cluster: HA peer epoch-floor dir create failed; the across-reboot replay floor will not survive a restart",
			"path", s.path, "err", err)
		return
	}
	if err := fsatomic.WriteFileDurable(s.path, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
		slog.Warn("cluster: HA peer epoch-floor persist failed; the across-reboot replay floor will not survive a restart",
			"path", s.path, "err", err)
		return
	}
	s.written = epoch
}

// initHeartbeatEpochState prepares both halves of the #6169 across-reboot
// anti-replay and is called from StartHeartbeat BEFORE the sender and receiver
// goroutines start.
//
// Ordering matters in both directions:
//
//   - The peer floor must be loaded before the receiver accepts its first
//     frame, or a replay slips in during the gap and re-anchors a low floor.
//   - This node's own epoch should be resolved before the sender's first send,
//     or a latched peer refuses our opening frames. Resolution is kicked here
//     and waited for with a bound (bootEpochResolveWait); a timeout is safe and
//     self-healing, it just costs a little rejoin latency.
func (m *Manager) initHeartbeatEpochState() {
	if m == nil {
		return
	}
	m.epochInitOnce.Do(func() {
		store := &peerEpochFloorStore{path: peerEpochFloorPath}
		m.peerFloor = store
		floor := store.load()
		m.hbAuth.primeEpochFloor(floor, func(epoch uint64) { go store.store(epoch) })
		if floor > 0 {
			slog.Info("cluster: HA peer epoch floor restored; epochless heartbeats from this peer are now refused",
				"floor", floor)
		}
	})
	// The sender half only matters — and only writes — when frames are signed:
	// the section marker is key-derived, so an unkeyed cluster cannot carry an
	// epoch at all. Gating the resolve on the key keeps an unkeyed node from
	// touching /var/lib/xpf for a mechanism it cannot use. A cluster that is
	// keyed LATER still resolves lazily off the send path
	// (heartbeatSender.send -> heartbeatBootEpoch); it just does not get this
	// bounded pre-send wait until the next heartbeat start.
	//
	// Loading the peer floor above is unconditional: it is a read, and the
	// persist hook it installs only ever fires for an accepted epoch-bearing
	// frame, which likewise requires a key.
	if len(m.controlLinkAuthKey()) == 0 {
		return
	}
	// Kick the sender-side resolve and give it a bounded chance to land before
	// the first heartbeat goes out.
	m.heartbeatBootEpoch()
	select {
	case <-m.bootEpochReady:
	case <-time.After(bootEpochResolveWait):
		slog.Warn("cluster: HA boot epoch not resolved in time; heartbeats start without an epoch until it lands",
			"waited", bootEpochResolveWait)
	}
}

// heartbeatBootEpoch returns this daemon incarnation's boot epoch, or 0 when it
// has not been resolved yet — the reserved "advertise no epoch" sentinel.
//
// Resolution runs ASYNCHRONOUSLY, exactly once per Manager. It must not run
// inline on the send path: resolving fsyncs the state file, and an fsync against
// a wedged disk can block for minutes. Blocking the 100ms send loop that long
// would stop heartbeats altogether and cause the very failover this mechanism
// exists to protect against. StartHeartbeat waits for it with a bound instead
// (initHeartbeatEpochState), so in practice the first frame already carries it.
//
// A persist FAILURE does not suppress the epoch — see nextBootEpoch. The only
// state in which this keeps returning 0 is a disk that never completes the
// write attempt at all.
func (m *Manager) heartbeatBootEpoch() uint64 {
	if m == nil {
		return 0
	}
	m.bootEpochOnce.Do(func() {
		// Read the path on THIS goroutine, not inside the worker: bootEpochPath
		// is a package var that tests override, and a worker reading it later
		// would race with the next test's write.
		path := bootEpochPath
		ready := m.bootEpochReady
		go func() {
			epoch, persisted := nextBootEpoch(path)
			m.bootEpoch.Store(epoch)
			slog.Info("cluster: HA boot epoch resolved; heartbeats now carry across-reboot anti-replay",
				"durable", persisted)
			if ready != nil {
				close(ready)
			}
		}()
	})
	return m.bootEpoch.Load()
}
