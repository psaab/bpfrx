package cluster

// The #5477 anti-replay ring for the #4107 authenticated control channel.
//
// Split out of heartbeat.go in the #6669 fold: it is a self-contained,
// single-responsibility structure, and heartbeat.go was within a handful of
// lines of the 2000-line [REFACTOR] threshold the modularity audit enforces
// (docs/refactoring-audit-current.txt). Pure code motion — the only edit is to
// the locking note on heartbeatAuthReplay, which had gone stale.

// replaySessionMark is one remembered (session, high-water counter) pair.
type replaySessionMark struct {
	session uint64
	counter uint64
}

// heartbeatAuthReplay tracks per-peer anti-replay state for authenticated
// heartbeats. A sender advertises a random per-process session id and a
// monotonic per-session counter (MarshalHeartbeatAuth). The receiver keeps a
// bounded set of per-session high-water counters and:
//
//   - accepts a strictly increasing counter within a KNOWN session (the live
//     session advancing), and
//   - accepts a genuinely NEW, never-seen session with any counter — a sender
//     restart/reboot picks a fresh random session, so a real reboot (a routine
//     HA event) is never mistaken for a replay and failover is never wedged.
//
// #5477: it REJECTS a return to a session already at or below its remembered
// watermark. Before this, the tracker held exactly ONE (session, counter): any
// session switch reset the watermark, so an on-link attacker who recorded
// authenticated frames from two incarnations A and B could alternate
// A->B->A->B forever — each switch re-anchored and re-admitted the SAME
// recorded A frames, refreshing peer liveness and applying their STALE
// role/priority (a forged liveness/election drive). Session ids are RANDOM
// (unordered), so a strictly-newer test like fullSetSeqGuard cannot be used:
// remembering a bounded per-session watermark is what distinguishes a real
// reboot (new id) from a replay of a retired incarnation (known id, no counter
// advance).
//
// LOCKING: this type does no locking OF ITS OWN, and that is a statement about
// its callers, not about the access pattern. An earlier revision of this note
// said "touched only from the single readLoop goroutine, so it needs no
// locking" — which stopped being true at #5086. The state now lives on the
// MANAGER (heartbeatAuthState.replay), so it outlives any one receiver and is
// reachable from every goroutine that drives a frame; a heartbeat restart
// overlaps a departing readLoop with an arriving one, and the stats surface
// reads adjacent fields concurrently. What makes it safe is that
// heartbeatAuthState.admitAuthed holds heartbeatAuthState.mu across both
// admit() call sites — so mu, not goroutine confinement, is the invariant.
// Do not read this as licence to drop that lock, and do not call admit()
// from anywhere that does not already hold it.
type heartbeatAuthReplay struct {
	marks [heartbeatReplaySessions]replaySessionMark
	// count is the number of occupied slots, saturating at len(marks). next is
	// the FIFO write cursor for eviction once the ring is full. While filling,
	// next == count and the valid entries are marks[:count]; once full, count
	// stays at len(marks) and next cycles, so marks[:count] still spans every
	// live entry for the lookup scan.
	count int
	next  int
}

// admit reports whether (session, counter) is fresh (not a replay) and, when
// fresh, advances the per-session watermark (or records a new session). Callers
// must invoke admit only after the MAC has verified — an unauthenticated caller
// must never mutate replay state — and must hold heartbeatAuthState.mu (see the
// LOCKING note above).
func (a *heartbeatAuthReplay) admit(session, counter uint64) bool {
	// Known session: admit only a strictly-advancing counter. A frame at or
	// below the watermark is a replay — including a return to a RETIRED session
	// whose watermark we still remember (#5477: the attacker cannot exceed the
	// highest counter the genuine peer ever signed for that session).
	for i := 0; i < a.count; i++ {
		if a.marks[i].session == session {
			if counter > a.marks[i].counter {
				a.marks[i].counter = counter
				return true
			}
			return false
		}
	}
	// Never-seen session: a genuine reboot draws a fresh random session, so
	// accept and record a new watermark. Bounded FIFO — evict the oldest once
	// the ring is full (see the heartbeatReplaySessions security bound above).
	a.marks[a.next] = replaySessionMark{session: session, counter: counter}
	a.next = (a.next + 1) % len(a.marks)
	if a.count < len(a.marks) {
		a.count++
	}
	return true
}
