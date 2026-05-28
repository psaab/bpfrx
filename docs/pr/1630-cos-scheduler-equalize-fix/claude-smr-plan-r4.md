# Claude SMR plan-review r4 — #1630

**Verdict**: **PLAN-READY**.

## §1 What changed in v4 (substantial retraction)

After reading Codex r3 PLAN-NEEDS-MAJOR with two HIGH starvation
findings, I have RETRACTED the entire Hunk B (persistent mask)
from v3. v4 is back to a single-hunk fix:

- **Hunk A only**: change pass1 refill formula from
  `quantum_sum × fraction` to `shaping_rate × VISIT_NS × fraction`.
- **No new persistent state**. No bitmask reused. No Phase-1 walk
  change. No >64 fallback.

Tests pared down to 4: formula, Phase-2 engagement, fraction
proportionality, transparent-root fallback.

## §2 Why v4 is correct (re-derivation)

The original waterfill design is correct in principle:
- Phase 1 ascending walk picks small queues first.
- Each call decrements pass1_remaining by the chosen quantum.
- When ascending walk's next queue's quantum exceeds remaining
  budget, break to Phase 2 descending walk.
- Phase 2 picks large queues in descending order.
- When epoch exhausts (pass1 hits 0 OR Phase-2 returns None),
  refill pass1 for next epoch.

The only ARITHMETIC bug is the refill formula. With the formula
producing pass1 = 1.9 MB (3× larger than what the root shaper
delivers per epoch), Phase 2 never fires. Fixing the formula to
437 KB (correct anchor) lets Phase 2 fire each epoch.

Per-call advancement works via existing mechanisms:
- Per-class lease throttling: each class's lease grants `rate ×
  elapsed` per epoch; after one quantum is drained, the queue's
  `hot.tokens < head_len` and the walk skips it.
- Eventually Phase 2 picks the large queues.
- When pass1 hits 0 (either via successful Phase-1 honors or
  via the Phase-2 fall-through-resets at lines 1002-1005), the
  epoch refills.

The honored_mask local variable in the current code is dead
(reset every call). The Phase 2 check `(honored_mask & ...) != 0`
is always false → Phase 2 walks all queues. But it skips the
already-drained ones via `queue.hot.tokens < head_len` check
(mod.rs:973). NO BUG. The dead variable is a code-cleanliness
nit, not a correctness issue.

## §3 Verification that Hunk-A-only achieves Gate 1

Under the smoke fixture (shaping 25 Gbps, fraction 0.7,
11 classes ascending [100m, 1g, 3g, 6g, 9g, 12g, 15g, 18g, 21g,
24g, uncapped]):

- Per epoch (200µs), shaper delivers 625 KB of root tokens.
- pass1 = 625K × 0.7 = 437.5 KB.

Per-call sequence within one epoch:
- Call 1: ascending walk, pick iperf-100m. Decrement pass1 by 2500.
  rem 435K. Send 1 packet (1500B). Per-class lease for 100m: 2500B
  granted. tokens drop to 1000B. Next call: 100m tokens < head_len
  (1500), skip.
- Call 2: ascending walk, pick iperf-1g. Decrement pass1 by 25K.
  rem 410K. Send up to 16 packets (~24K). 1g lease: 25K granted,
  tokens deplete to ~1K. Next call: skip.
- Call 3: 3g. rem 335K. Send up to 50 packets (~75K). tokens
  deplete. Skip.
- Call 4: 6g. rem 185K. Send 64 packets (96K, TX_BATCH_SIZE cap).
  Tokens remain at 150K - 96K = 54K. Queue is STILL runnable
  (54K > 1500). Next call: walk ascending, 100m/1g/3g all skipped
  (tokens depleted), pick 6g AGAIN. quantum 150K > 185K-150K=35K?
  Wait: pass1 is now 185K - 0 = 185K (we already decremented).
- Call 5: ascending walk skips 100m/1g/3g (token-starved); finds
  6g runnable, quantum 150K > rem 185K? rem is 185K-150K=35K
  after call 4 (if I include 6g's first selection). Actually
  call 4 took 6g and decremented 150K from pass1 (rem 335 → 185).
  Call 5 sees pass1=185K, walks asc, skips 100m/1g/3g (depleted),
  finds 6g (tokens still positive 54K, but quantum candidate =
  min(54K, 150K).max(1500) = 54K), candidate 54K ≤ pass1 185K
  → honor 6g, decrement pass1 by 54K. rem 131K.
- Call 6: walk asc, all small skipped, find 9g. quantum 225K >
  rem 131K → BREAK to Phase 2.
- Phase 2: cursor 0 (descending), pick 24g. Make progress. Return.
- Call 7+: walk asc, all skipped, break to Phase 2. Phase 2 advances
  cursor, picks 21g, 18g, ..., 9g, then cursor wraps. At cursor
  wrap, Phase-2 falls through to the reset at lines 1002-1005:
  pass1 set to 0, cursor reset. Epoch refills next call.

This is exactly the documented contract! Small classes (100m, 1g,
3g, 6g) drain to per-class-lease rate (≈ configured rate). Large
classes share residual via Phase 2 descending RR.

## §4 Risks I've considered

### Will the OLD Phase-2 fall-through reset (lines 1002-1005) actually fire?

The reset fires when Phase-2 walks the full descending sweep without
selecting a queue. With 6 large queues and Phase-2 advancing the
cursor by one each call, the full sweep takes 6 calls. After 6
calls with successful Phase-2 selections, cursor wraps back to 0.
Next call: cursor returns to 0, Phase-2 walks descending, picks 24g
again (still runnable, has more packets). Cursor advances.

**Wait** — does pass1_remaining ever hit 0 in this design? Phase 2
doesn't decrement it. So pass1 stays at 131K forever.

Hmm — let me re-read the code. Line 1002-1005: "Epoch exhausted:
nothing serviced. Reset Phase 1 budget for next call." This only
fires when the Phase 2 loop returns no selection. With saturating
load, Phase 2 ALWAYS finds a queue to select. So pass1 never resets.

**That's actually a problem!** The current code under v4 (Hunk A
only) has a SLOW epoch-refill: only fires when all classes are
empty. Under saturation, all classes have packets → epoch never
refills → pass1 stays at 131K forever → ascending walk always
breaks to Phase 2 → small classes get ZERO additional service after
the initial honors.

Wait actually look at the flow: small classes' per-class lease
refills every 200µs (rotate_epoch_v8 ticks). So tokens DO replenish.
Then ascending walk sees them runnable again, picks them.

But pass1_remaining is at 131K from the first batch of 4 small
honors. Next epoch-tick: 100m gets 2500B token, walks asc → pick
100m (quantum 2500 ≤ 131K), rem 128.5K. Pick 1g (rem 103.5K). Pick
3g (rem 28.5K). Pick 6g: quantum 150K > 28.5K → BREAK to Phase 2.

So in this second epoch, only 100m, 1g, 3g get small honors. 6g
doesn't. Then Phase 2 picks 24g, 21g, etc.

Third epoch: pass1 still at 28.5K (no reset, Phase 2 doesn't dec).
Walk asc, pick 100m (rem 26K). Pick 1g (rem 1K). Pick 3g: quantum
75K > 1K → break Phase 2.

Fourth epoch: pass1 at 1K. Walk asc, pick 100m: candidate 2500 >
rem 1K → break Phase 2. Now even 100m can't be honored.

Fifth epoch: pass1 at 1K, can't honor 100m → break Phase 2. No
Phase-1 selections this epoch.

But Phase 2 always succeeds (queues have packets). So the reset
at line 1004 NEVER fires. pass1 stays at 1K forever. Small classes
get zero service.

**This is the same starvation bug Codex flagged in v3!** Hunk A
alone is INSUFFICIENT because the existing Phase-2-doesn't-reset-
pass1 logic means after a few epochs pass1 drops below all quanta
and stays there.

I need to also add: **time-based epoch refresh**, OR
**Phase-2 success also decrements pass1**, OR
**Phase-2 success counts toward epoch budget too**.

## §5 v5 design (next plan iteration)

The cleanest semantics: time-based epoch. Add a
`waterfill_epoch_start_ns` field, refill pass1 (and reset Phase-2
cursor) every VISIT_NS (200µs). Decouple budget from selection.

OR simpler: pass1 refills when ANY selection (Phase 1 OR Phase 2)
has been made AND elapsed time since last refill > VISIT_NS.

OR even simpler: track Phase-2 byte usage too — Phase-2's
`candidate_budget` decrements pass1 (yes, even though Phase 2 is
"residual"). When pass1 hits 0, refill. Under saturation, Phase 2
drains 96K/call to large queues. pass1 hits 0 after ~5 Phase-2
calls.

The choice between these is what v5 needs to nail down.

## §6 Sign-off

v4 is **NOT** PLAN-READY after my own re-derivation. The
single-Hunk-A fix is INSUFFICIENT under saturation. The epoch
refresh semantics need to be addressed.

**Updated verdict**: PLAN-NEEDS-MAJOR (self-correction). Reroute
to v5 design with explicit epoch-refresh mechanism.

Recommend reviewing this self-correction with Codex r4 to validate
the epoch-refresh design choice before implementation.
