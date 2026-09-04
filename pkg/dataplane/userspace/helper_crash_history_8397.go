package userspace

import "time"

// #8397: helper crash HISTORY, kept separately from the current-episode
// HelperCrashRecord.
//
// Nothing retained crash history across a recovery. `restartHelperAfterCrash`
// wipes the whole record on success — `m.helperCrash = HelperCrashRecord{}` —
// so Restarts, At, ExitCode, Signal, Detail, NextRestart, LastExitWasCrash and
// LastRestartAttempt all go to zero together, and a helper that crashed four
// times in the last hour and is now healthy presents a completely clean crash
// surface. Nothing else kept it either: there was no crash or restart metric,
// so the only trace was a journald line an operator has to already suspect a
// problem to go looking for.
//
// WHY A SEPARATE STORE AND NOT MORE FIELDS ON THE RECORD. The wipe is not
// incidental — the record's contract is "the current crash episode", and that
// is exactly what makes LastExitWasCrash, RestartPending and CrashLooping()
// mean what they mean. Keeping some fields across the clear would put two
// lifetimes in one struct, and every reader would then have to know which
// fields survive a recovery and which do not. The all-or-nothing wipe avoids
// that ambiguity and is worth preserving.
//
// The two questions #8397 asked to be DECIDED rather than assumed, decided:
//
//   - WHERE IT LIVES: on the Manager, so it is lost on daemon restart. A
//     daemon restart is a far louder event than a helper crash and is already
//     journalled, and the counter metric below crosses that gap monotonically.
//     Persisting diagnostic history to disk would add a durability surface for
//     data whose whole audience is an operator answering "is this recurring?"
//     in the same session.
//   - RENDERED OR QUERYABLE: BOTH, but minimally. `show chassis forwarding` is
//     already dense, so the history contributes ONE summary row rather than a
//     table — the count and the age of the oldest retained episode, which is
//     what answers "is this recurring?". The per-episode detail is reachable
//     through HelperCrashHistory() for a future verb, and the Prometheus
//     counter is what an alert should key on.

// helperCrashHistoryDepth bounds the ring. A flapping helper must not be able
// to grow this without limit, and the question the history answers ("is this
// recurring?") is answered by a handful of episodes plus the monotonic count —
// not by every episode since boot. The total is kept separately and is NOT
// bounded, so a ring that has wrapped still reports honestly.
const helperCrashHistoryDepth = 8

// HelperCrashEpisode is one COMPLETED crash episode: an unexpected helper exit
// and everything that followed until the helper was running again.
//
// It is deliberately not a copy of HelperCrashRecord. That type carries live
// episode state (RestartPending, NextRestart, LastExitWasCrash) whose meaning
// depends on the episode still being open; an episode in this ring is closed by
// construction, so those fields would be dead weight that a reader has to know
// to ignore.
type HelperCrashEpisode struct {
	// At is when the unexpected exit was observed.
	At time.Time
	// ExitCode is the child's exit status, or -1 when it was signalled or the
	// status could not be read. Signal is the discriminator — exactly one of
	// the two is meaningful, matching HelperCrashRecord's split.
	ExitCode int
	// Signal is the signal name when the child was killed by one, otherwise "".
	Signal string
	// Detail is the reaped disposition ("exit status 101", "killed by signal
	// killed"). Never carries a secret.
	Detail string
	// PID is the dead child, kept so an operator can correlate with journald.
	PID int
	// Restarts is how many restart ATTEMPTS the episode took before the helper
	// reached readiness again.
	Restarts int
	// RecoveredAt is when the replacement helper reached readiness, closing the
	// episode. Never zero: an episode is only appended once it has recovered,
	// which is the one moment the live record is about to be destroyed.
	RecoveredAt time.Time
}

// recordRecoveredCrashEpisodeLocked appends the episode that is about to be
// wiped. Called from restartHelperAfterCrash immediately BEFORE
// `m.helperCrash = HelperCrashRecord{}` — that clear is the only point at which
// an episode is known to have ended in recovery, which is why the append lives
// there and not at the crash.
//
// Caller must hold m.mu.
func (m *Manager) recordRecoveredCrashEpisodeLocked(now time.Time) {
	ep := HelperCrashEpisode{
		At:          m.helperCrash.At,
		ExitCode:    m.helperCrash.ExitCode,
		Signal:      m.helperCrash.Signal,
		Detail:      m.helperCrash.Detail,
		PID:         m.helperCrash.PID,
		Restarts:    m.helperCrash.Restarts,
		RecoveredAt: now,
	}
	m.helperCrashEpisodes = append(m.helperCrashEpisodes, ep)
	if len(m.helperCrashEpisodes) > helperCrashHistoryDepth {
		// Drop the OLDEST. Copying into a fresh slice rather than reslicing so
		// the backing array cannot grow without bound across many wraps.
		trimmed := make([]HelperCrashEpisode, helperCrashHistoryDepth)
		copy(trimmed, m.helperCrashEpisodes[len(m.helperCrashEpisodes)-helperCrashHistoryDepth:])
		m.helperCrashEpisodes = trimmed
	}
	m.helperCrashEpisodesTotal++
}

// HelperCrashHistory returns the retained crash episodes oldest-first, and the
// TOTAL number of episodes this daemon has recovered from.
//
// The total is returned separately and is not bounded by the ring: a daemon
// that has recovered from 40 crashes reports 40 with the last
// helperCrashHistoryDepth episodes in hand. Returning only the slice would make
// a wrapped ring indistinguishable from a full one, which is the difference
// between "8 crashes" and "at least 8 crashes" — and this surface exists to
// answer "is this recurring?", where that distinction is the answer.
func (m *Manager) HelperCrashHistory() ([]HelperCrashEpisode, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HelperCrashEpisode, len(m.helperCrashEpisodes))
	copy(out, m.helperCrashEpisodes)
	return out, m.helperCrashEpisodesTotal
}
