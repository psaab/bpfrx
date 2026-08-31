package cluster

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// heartbeat_epoch_owner_7501.go answers the one question refineBootEpoch cannot
// ask today: WHO wrote the value in the boot-epoch file, and are they still
// running?
//
// ── WHY THE EPOCH ALONE CANNOT ANSWER IT ─────────────────────────────────
//
// refineBootEpoch raises whenever the persisted value is at or above what this
// node published, because that is how a backward clock step is carried across a
// restart. But "a predecessor wrote it after a backward clock step" and "a
// concurrent NEWER incarnation wrote it" leave the IDENTICAL file — a bare
// decimal. So the older of two overlapping incarnations reads the newer one's
// value, treats it as its own predecessor's, and raises ITSELF above it. The
// peer latches that higher epoch from the incarnation that is about to exit and
// refuses the survivor for the life of its process (#7501; the schedule is
// characterized by TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669).
//
// withEpochFileLock does not help: it serializes by lock ACQUISITION, and there
// is no happens-before edge from daemon start to that acquisition.
//
// ── WHY A SIDECAR AND NOT A FIELD ────────────────────────────────────────
//
// The epoch file is written as `strconv.FormatUint(epoch, 10)+"\n"` and read
// with ParseUint over the whole trimmed contents. ANY added field makes that
// parse fail, so an older binary — an ISSU rollback, a mixed-version window —
// would read the file as unreadable and lose backward-clock-step protection.
//
// Keeping the identity in a sidecar leaves the epoch file BYTE-IDENTICAL, which
// makes the compatibility story trivial in both directions rather than only the
// one #7501's criterion 3 asks for: an older binary reads exactly what it
// always did, and this one treats a missing sidecar as "owner unknown", which
// is precisely today's behaviour. #6711's preserve semantics are untouched
// because the branch that implements them never learns the sidecar exists.
//
// ── WHY PID + START TIME AND NOT A LOCK ──────────────────────────────────
//
// A lifetime-held flock would also expose liveness, but it needs a lock whose
// lifetime is the process's, and #7501's criterion 2 forbids a storage fault
// from taking a healthy node off the air. A lock that cannot be taken then has
// no good branch. Reading /proc costs nothing, holds nothing, and when it is
// unavailable this file simply reports "unknown", which degrades to today's
// behaviour rather than to a refusal.
//
// The START TIME is not decoration: a bare pid is reused, and a reused pid
// belonging to an unrelated process would read as "the writer is alive" forever
// after. /proc/<pid>/stat field 22 is the process start time in clock ticks
// since boot, which distinguishes a reused pid from the original within a boot;
// the boot id distinguishes across boots, where the tick counter restarts.

// epochOwner identifies the process that wrote the boot-epoch file.
type epochOwner struct {
	pid       int
	startTick uint64
	boot      bootIncarnation
}

// epochOwnerSidecarPath is the identity file that accompanies the epoch file.
// Written and read under the SAME withEpochFileLock critical section, so the
// pair cannot be observed torn.
func epochOwnerSidecarPath(epochPath string) string {
	return epochPath + ".owner"
}

func (o epochOwner) String() string {
	return fmt.Sprintf("%d %d %s", o.pid, o.startTick, o.boot)
}

// parseEpochOwner is the inverse. A malformed sidecar reports NOT-ok, which
// callers treat as "owner unknown" — the same as a missing one. Refusing to
// guess is the whole point: a wrong identity would license declining to raise
// above a value whose writer is long gone, which strands this node below its
// own peer's floor.
func parseEpochOwner(s string) (epochOwner, bool) {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) != 3 {
		return epochOwner{}, false
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil || pid <= 0 {
		return epochOwner{}, false
	}
	tick, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return epochOwner{}, false
	}
	raw, err := hex.DecodeString(f[2])
	if err != nil || len(raw) != bootIncarnationLen {
		return epochOwner{}, false
	}
	var boot bootIncarnation
	copy(boot[:], raw)
	if !boot.known() {
		return epochOwner{}, false
	}
	return epochOwner{pid: pid, startTick: tick, boot: boot}, true
}

// procRoot is indirected so the tests can drive a synthetic /proc without a
// second process. Production never reassigns it. The boot id comes from
// localBootIncarnation (sync_boot_incarnation.go) rather than a second reader
// of the same file: that helper already caches it, already fails to a
// well-defined "un-incarnated" zero, and a second parse of the same kernel file
// with its own failure posture is exactly how two answers to one question
// start to disagree.
var procRoot = "/proc"

// currentEpochOwner describes THIS process. ok=false when the identity cannot
// be established, in which case the caller writes no sidecar — an absent
// sidecar is honest about not knowing, where a partial one would not be.
func currentEpochOwner() (epochOwner, bool) {
	pid := os.Getpid()
	tick, ok := processStartTick(pid)
	if !ok {
		return epochOwner{}, false
	}
	boot := localBootIncarnation()
	if !boot.known() {
		return epochOwner{}, false
	}
	return epochOwner{pid: pid, startTick: tick, boot: boot}, true
}

// processStartTick reads field 22 of /proc/<pid>/stat.
//
// Parsed from the LAST ')' rather than by splitting the whole line: field 2 is
// the executable name in parentheses and may itself contain spaces and
// parentheses, so a naive Fields() split shifts every later index. That is a
// classic /proc parsing bug and it would silently produce a wrong start time,
// which reads as "this is a different process" and disables the guard.
func processStartTick(pid int) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	s := string(data)
	close := strings.LastIndexByte(s, ')')
	if close < 0 || close+2 > len(s) {
		return 0, false
	}
	// After "(comm) " the remaining fields start at index 3 (state is field 3),
	// so field 22 is offset 19 in the remainder.
	rest := strings.Fields(s[close+1:])
	const startTimeOffsetAfterComm = 19
	if len(rest) <= startTimeOffsetAfterComm {
		return 0, false
	}
	tick, err := strconv.ParseUint(rest[startTimeOffsetAfterComm], 10, 64)
	if err != nil {
		return 0, false
	}
	return tick, true
}

// epochOwnerAlive reports whether o names a process that is STILL RUNNING.
//
// Fails to FALSE on every uncertainty — an unreadable /proc, a different boot,
// a pid that has gone — and false means "treat the value as a predecessor's",
// which is exactly today's behaviour. That direction is deliberate: the guard
// may only ever DECLINE to raise, so being unable to evaluate it costs the
// existing semantics and nothing more. Failing to true would let a stale
// sidecar pin this node below its peer's floor permanently, which is a durable
// version of the very lockout #7501 is about.
func epochOwnerAlive(o epochOwner) bool {
	local := localBootIncarnation()
	if !local.known() || local != o.boot {
		// A different boot: the tick counter restarted, so the recorded value
		// describes nothing on this machine now.
		return false
	}
	tick, ok := processStartTick(o.pid)
	if !ok {
		return false
	}
	return tick == o.startTick
}

// readEpochOwner returns the recorded owner, or ok=false when there is none to
// read. Called inside the epoch lock.
func readEpochOwner(epochPath string) (epochOwner, bool) {
	data, err := os.ReadFile(epochOwnerSidecarPath(epochPath))
	if err != nil {
		return epochOwner{}, false
	}
	return parseEpochOwner(string(data))
}

// writeEpochOwner records THIS process as the writer, alongside a successful
// epoch write. Called inside the epoch lock, immediately after the epoch file
// is written, so the pair is consistent for any reader that also takes it.
//
// A failure here is logged by the caller and is NOT a persist fault: the epoch
// itself is durable, and a missing sidecar degrades to today's behaviour rather
// than to anything worse.
func writeEpochOwner(epochPath string, o epochOwner) error {
	return fsatomic.WriteFileDurable(
		epochOwnerSidecarPath(epochPath), []byte(o.String()+"\n"), 0o644)
}

// selfEpochOwner is currentEpochOwner plus its ok flag, so a caller can carry
// both through a closure without a second /proc read.
type selfEpochOwner struct {
	owner epochOwner
	ok    bool
}

// currentEpochOwnerCached resolves this process's identity once per process.
// pid and start time cannot change while we run, so re-reading /proc on every
// refine pass would be pure cost on the path whose whole design goal is to stay
// off the heartbeat's critical path.
var (
	selfOwnerOnce  sync.Once
	selfOwnerValue selfEpochOwner
)

func currentEpochOwnerCached() selfEpochOwner {
	selfOwnerOnce.Do(func() {
		o, ok := currentEpochOwner()
		selfOwnerValue = selfEpochOwner{owner: o, ok: ok}
	})
	return selfOwnerValue
}

// sameEpochOwner reports whether the sidecar names THIS process.
//
// An unknown self compares equal to nothing, so a node that cannot establish
// its own identity never mistakes another process's value for its own — it
// simply falls back to raising, which is the pre-#7501 behaviour.
func sameEpochOwner(o epochOwner, self selfEpochOwner) bool {
	return self.ok && o == self.owner
}
