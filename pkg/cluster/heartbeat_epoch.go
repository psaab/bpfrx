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
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

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
//     LATCH (see heartbeatAuthState.admitAuthed). It is process-scoped: a
//     durable floor was built, priced against rollback/crash/lock costs, and
//     removed — see the epochSeen field comment.
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
	// read at a SINGLE FIXED OFFSET back from the fixed-size auth trailer
	// (len-68, one index — there is no search loop and nothing unbounded), so
	// the bytes it lands on are the tail of the version section — a stable,
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

	// bootEpochMaxSkew is how far AHEAD of the receiver's own wall clock a peer
	// epoch may be and still be ordered against the floor. A peer epoch beyond
	// it is a broken clock or corrupt state, never a real incarnation.
	//
	// THE SLACK IS ITSELF THE WORST-CASE LOCKOUT, which is why it is an hour
	// and not a year. A bad epoch INSIDE the bound is latched, and a repaired
	// peer returning to real time then sits below the floor until its own
	// wall-clock seed climbs past it — so the bound and the lockout duration
	// are the same number. A year of slack bought nothing over an hour (it only
	// has to exceed real inter-node clock skew, which is milliseconds under NTP
	// and minutes without it) and cost a year-long lockout.
	//
	// An hour still closes the MaxUint64 class by four orders of magnitude, and
	// bounds the in-range case to a self-limiting window instead of one that
	// needs intervention.
	bootEpochMaxSkew uint64 = 60 * 60 * 1_000_000_000

	// epochClockSaneFloor is 2020-01-01T00:00:00Z in nanoseconds: the point
	// below which the LOCAL clock is obviously unset rather than merely wrong.
	//
	// The forward bound is only applied when our own clock is above this. An
	// appliance whose RTC is dead boots at (or near) the Unix epoch and syncs
	// NTP some seconds later; during that window a healthy peer's epoch is
	// ~56 years "ahead" of us, and a naive forward bound would make us refuse
	// our peer at exactly the moment cold-boot split-brain is most likely (the
	// same hazard heartbeatStartupGrace exists for). Falling back to the
	// absolute bound alone there is permissive, never locking.
	epochClockSaneFloor uint64 = 1577836800_000000000

)

// bootEpochPath is where this node's own boot epoch is persisted. /var/lib/xpf
// is the persistent runtime-state root xpf already uses for durable identity
// counters (SNMPv3 engineBoots, the config DB). Overridden in tests.
//
// There is deliberately NO peer-side floor file; see the DURABILITY note on
// heartbeatAuthState.epochSeen for why the receiver latch is process-scoped.
var bootEpochPath = "/var/lib/xpf/ha-boot-epoch"

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

// epochOrderable reports whether a peer epoch may be compared against, and
// latched as, the anti-replay floor. nowNanos is the receiver's own wall clock.
//
// It is epochUsableAsFloor plus a FORWARD bound. The absolute bound alone
// catches garbage, but leaves a single-fault path open: a peer whose clock (or
// persisted state) runs far ahead — yet still lands before year 2200 — would
// latch a floor its own corrected incarnations can never climb back above, and
// nothing would ever accept that peer again. Bounding how far ahead of US an
// epoch may be stops the LATCH, which is the unrecoverable half, so a peer that
// is corrected (or whose state is repaired) is accepted again the moment it
// comes back into range.
//
// A frame whose epoch is not orderable is REJECTED rather than admitted-and-not-
// latched. Admitting it would recreate, in miniature, the epochless bypass this
// mechanism exists to close: a frame the floor cannot order is governed by the
// bounded ring alone, so captured frames from an incarnation that once emitted
// an out-of-range epoch would replay indefinitely. Not orderable, not admitted —
// the same rule as an epochless frame from a latched peer.
func epochOrderable(epoch uint64, nowNanos int64) bool {
	if !epochUsableAsFloor(epoch) {
		return false
	}
	// Only apply the forward bound when OUR clock is credible; see
	// epochClockSaneFloor.
	if nowNanos > 0 && uint64(nowNanos) >= epochClockSaneFloor {
		if epoch > uint64(nowNanos)+bootEpochMaxSkew {
			return false
		}
	}
	return true
}

// withEpochFileLock serializes a read-modify-write of an epoch state file
// across PROCESSES, not merely within one.
//
// Within a process each file has a single writer (sync.Once for the boot epoch,
// a mutex for the peer floor), but nothing in xpf enforces a single daemon
// instance: there is no pidfile, and the gRPC listener sets SO_REUSEPORT
// (pkg/grpcapi/server.go), so a second xpfd does NOT fail on a port collision
// the way it otherwise would. Two overlapping incarnations could therefore
// interleave read-modify-write and publish epochs that are not strictly
// ordered — which is precisely the property the whole mechanism rests on. An
// advisory lock on a sidecar file is cheaper than reasoning about whether the
// race is reachable.
//
// Fails CLOSED: if the lock cannot be taken, the read-modify-write is SKIPPED
// rather than run unlocked. A lock whose failure path executes the critical
// section anyway is not a lock — it reinstates the very race it exists to
// prevent, exactly when the guard cannot fire.
//
// WHY DECLINING IS RIGHT, not merely cheap. Proceeding unlocked does not trade
// correctness for liveness; it trades a TRANSIENT liveness risk for a DURABLE
// one. A raced read-modify-write can leave a lower epoch in the file than an
// overlapping incarnation already emitted. That value is read back as `prev` on
// the next boot, and it is exactly the term that matters after a backward clock
// step — the one case persistence exists for. The epoch then produced can sit
// BELOW the peer's latched floor, where admitAuthedLocked refuses it: the same
// false-peer-death the fail-open was supposed to avoid, moved one restart later
// and made durable rather than transient. Corrupting the state whose only job is
// surviving a clock step is not a safe way to fail.
//
// What declining costs is bounded and transient by comparison: the wall-clock
// epoch is already published and already on the wire (see
// Manager.heartbeatBootEpoch), so only backward-clock-step protection is lost,
// and only until the next resolve succeeds.
//
// The old justification — "a node that cannot lock must not be a node that
// cannot heartbeat" — was a SENDER-liveness argument applied to a call site that
// is not on the heartbeat path at all. This runs on refineBootEpoch's worker,
// off both the send loop and the receive loop, so declining it cannot stop this
// node emitting anything. It also matches its siblings: MkdirAllDurable failure
// already declines and WriteFileDurable failure already declines, so lock
// failure was the only branch of three that proceeded.
func withEpochFileLock(path string, fn func()) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		slog.Warn("cluster: HA epoch state lock unavailable; SKIPPING the persist "+
			"(the wall-clock epoch is already in use; only backward-clock-step "+
			"protection is lost)", "path", path, "err", err)
		return
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		slog.Warn("cluster: HA epoch state lock failed; SKIPPING the persist "+
			"(the wall-clock epoch is already in use; only backward-clock-step "+
			"protection is lost)", "path", path, "err", err)
		return
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	fn()
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

// initHeartbeatEpochState starts this node's boot-epoch resolution, and is
// called from StartHeartbeat. It MUST NOT BLOCK.
//
// It used to wait up to bootEpochResolveWait for the persisted value, back when
// the epoch was only published after that read completed. Once emission moved
// ahead of all I/O (Manager.heartbeatBootEpoch) the wait stopped buying
// anything — and it was actively harmful: StartHeartbeat calls StopHeartbeat
// first, so the wait stalled a node with its heartbeat already STOPPED, and the
// channel it waited on is closed by the refine worker, which under a wedged
// store never returns. Measured on the wedged store: 2.005s / 2.012s / 2.011s,
// three of three paying the full bound, against a dead-peer threshold of 500ms
// at the code default and 1s at the shipped 200ms interval. That is the same
// false-peer-death this change exists to remove, relocated from "emits
// epoch-less frames" to "emits no frames at all" — which a peer cannot tell
// apart. Every routine VRF rebind and HA comms restart would have paid it.
//
// So there is no wait: kick the resolve and return. The wall-clock epoch is
// already published by the time this returns, and the persisted refinement
// lands whenever storage allows.
func (m *Manager) initHeartbeatEpochState() {
	if m == nil {
		return
	}
	// The epoch is only meaningful when frames are signed — the section marker
	// is key-derived, so an unkeyed cluster cannot carry one, and an unkeyed
	// node must not touch /var/lib/xpf for a mechanism it cannot use. A cluster
	// keyed LATER still resolves off the send path.
	if len(m.controlLinkAuthKey()) == 0 {
		return
	}
	m.heartbeatBootEpoch()
}

// bootEpochSeed is the wall-clock value an incarnation advertises before any
// I/O. Factored out so tests drive the SAME seed production uses rather than
// restating it — a restated seed is free to drift from the shipped one.
//
// 0 is the reserved "no epoch" sentinel, so it is never returned; that is only
// reachable with a clock at the Unix epoch.
func bootEpochSeed() uint64 {
	now := time.Now().UnixNano()
	if now > 0 {
		return uint64(now)
	}
	return 1
}

// heartbeatBootEpoch returns this daemon incarnation's boot epoch. It NEVER
// returns 0 for a node that has called it, and it NEVER performs I/O.
//
// This ordering is the whole answer to "a storage fault must not take a healthy
// node off the air". The epoch a peer needs is just a value that strictly
// increases across this node's incarnations, and the wall clock already
// provides that. So the wall-clock value is published SYNCHRONOUSLY, with no
// file access, and every frame carries it from the very first send.
//
// Persistence is a REFINEMENT, not a prerequisite. Its only job is to survive a
// backward clock step, so it runs on a worker: read the previous value and, if
// it would be higher than what we published, raise. Raising mid-incarnation is
// safe — the receiver's floor simply moves up, and our own earlier frames
// become unreplayable, which is the direction we want.
//
// Consequently a hung disk, a blocking flock, or a wedged fsync cannot stop
// this node emitting a valid epoch, and cannot make a latched peer see it as
// epoch-less (and therefore dead). The residual is the double fault only:
// storage that never completes AND a clock that stepped backwards.
func (m *Manager) heartbeatBootEpoch() uint64 {
	if m == nil {
		return 0
	}
	m.bootEpochOnce.Do(func() {
		// Publish immediately, before any I/O can be attempted.
		m.bootEpoch.Store(bootEpochSeed())

		// Read bootEpochPath on THIS goroutine: it is a package var tests
		// override, and a worker reading it later would race the next test.
		path := bootEpochPath
		// bootEpochReady is closed when the refine attempt finishes. Nothing in
		// production waits on it — that wait was removed, see
		// initHeartbeatEpochState — but tests use it to join the worker so a
		// refinement cannot race their assertions or t.TempDir cleanup.
		ready := m.bootEpochReady
		go func() {
			defer func() {
				if ready != nil {
					close(ready)
				}
			}()
			refineBootEpoch(path, &m.bootEpoch)
		}()
	})
	return m.bootEpoch.Load()
}

// refineBootEpoch is the off-path half of heartbeatBootEpoch: consult the
// persisted previous epoch, raise the published value if a backward clock step
// means the wall clock alone would not have exceeded it, and record the result.
//
// Every failure here is survivable and is logged rather than propagated: the
// wall-clock epoch published synchronously is already valid and already on the
// wire.
func refineBootEpoch(path string, published *atomic.Uint64) {
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("cluster: HA boot-epoch state dir create failed; this incarnation's epoch is NOT durable "+
			"(a backward clock step across the next restart could regress it)", "path", path, "err", err)
		return
	}
	withEpochFileLock(path, func() {
		var prev uint64
		if data, err := os.ReadFile(path); err == nil {
			n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			switch {
			case perr != nil:
				slog.Warn("cluster: HA boot-epoch state unreadable; keeping the wall-clock epoch", "path", path)
			case !epochOrderable(n, time.Now().UnixNano()):
				// Corrupt, hand-edited, or written while this node's clock ran
				// ahead. Chaining from it would push this node toward MaxUint64,
				// where the NEXT boot regresses, and would strand it above the
				// range its peer accepts. Ignoring it heals the file.
				slog.Warn("cluster: HA boot-epoch state is out of range; ignoring it and keeping the wall-clock epoch",
					"path", path, "value", n)
			default:
				prev = n
			}
		} else if !os.IsNotExist(err) {
			slog.Warn("cluster: HA boot-epoch state read error; keeping the wall-clock epoch",
				"path", path, "err", err)
		}

		epoch := published.Load()
		if next := prev + 1; next > epoch {
			// The clock stepped backwards: the wall-clock seed did not clear the
			// previous incarnation. Raise so this incarnation still strictly
			// exceeds it.
			epoch = next
			published.Store(epoch)
		}
		if err := fsatomic.WriteFileDurable(path, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
			slog.Warn("cluster: HA boot-epoch state persist failed; this incarnation's epoch is NOT durable "+
				"(a backward clock step across the next restart could regress it)", "path", path, "err", err)
		}
	})
}
