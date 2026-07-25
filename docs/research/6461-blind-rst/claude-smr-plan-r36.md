# Claude SMR hostile plan-review — round 36 (v9.9.20 @ beea39eef)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.20 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.20-as-committed** — one self-found HIGH (the resync obligation's driver
is stated backwards: the sticky cold-prime gates are SENDER-side and the
receiver has no message to clear them, so "drive a bulk over the survivor"
is unreachable as written) plus one nit. The group-hold, lock-order, and
ordering-invariant folds verify sound.

## Finding 1 (HIGH — the obligation's driver: close-both is the only mechanism that works without a wire change)

The v9.9.20 clause says the logical-peer full-resync obligation "drives the
EXISTING BulkSync machinery over the SURVIVING active connection ... no new
wire message — the obligation explicitly OVERRIDES the sticky cold-prime
gates: it clears `outboundBulkAcked` for this peer". But
`outboundBulkAcked` is SENDER-side state ("set ONLY when the peer acks OUR
outbound bulk", `sync.go:475-482`), and the survivor re-drive
(`sync_conn.go:572`) is the SENDER re-driving ITS OWN stranded outbound
bulk. A receiver-side obligation cannot clear the sender's flag — no
message exists to carry it, and the receiver's own bookkeeping does not
gate the sender's bulk drive. As written the primary mechanism is
unreachable. The correct statement: (a) PRIMARY — overflow marks the
window lossy and closes BOTH connections to the peer (a receiver-side
action needing no wire change): both slots empty on both sides →
`wasDisconnected` true on reconnect (`sync_conn.go:248`) → cold-prime →
the sender drives a FULL bulk with the config-first ordering; the
once-per-latched-epoch latch keeps this from hot-looping, and the
obligation clears only when the replacement full bulk's ACK lands; (b)
OPTIONAL fast path for negotiated pairs — an additive authenticated
RESYNC_REQUEST message (rolling-gated like the identity tails): a new
sender honors it by forcing a bulk over the active connection and clearing
its own sticky gates per the obligation; a legacy sender ignores it, so the
receiver falls back to (a) after a bounded wait. (b) is an optimization;
(a) is the mechanism that must be normative.

## Finding 2 (nit — the reverse companion is a family clone-holder)

The group-hold distribution list ("canonical + all replicas +
materializations + escrow") should name the synthesized REVERSE companion
(`ha/session_import.rs:104`) explicitly — it is a separately published
family member (`coordinator/mod.rs:753, :771`) and its clone is what keeps
the family-cohort accounting exact.

## Verified sound this round (my own re-trace)

- Group-hold vs #6522 coexistence: a flow is exactly one model
  (locally-born → per-entry refcount; imported → group-hold clones); each
  reservation is created under exactly one model, so no double-release is
  constructible.
- Materialization clone source: a materialize reads the PUBLISHED shared
  entry (`session_glue/mod.rs:1157`); the canonical entry's clone exists
  whenever the materialize can find the entry — no clone-from-void; if the
  canonical reaped first, the lookup returns None and the flow re-seeds.
- Lock-order: the per-worker `reserve_synced_source_nat_allocation` call
  site (`upsert_synced.rs:80`) becomes an assert-committed NoChange under
  the fold — no allocator mutation under the worker's session locks.
- Slot revalidation is lock-free/atomic (per Codex r35-3's disposition
  condition), preserving the slot-WRITE → allocator-WRITE order.

## Verdict

**PLAN NO for v9.9.20** — fold Finding 1 (close-both-primary +
resync-request-optional) and Finding 2 (reverse-companion clone) as
v9.9.21. Part A remains converged and untouched.
