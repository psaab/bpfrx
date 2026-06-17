# Claude SMR hostile plan review — #1916 r4 (final)

**Verdict: PLAN-READY.**

The only delta from r3 (which I passed PLAN-READY) is the Step 2b
timezone control-flow case-split, applied verbatim to Codex r3's
specified resolution. I re-attacked it:

- **Codex r3 MED resolved.** r4 Step 2b no longer "falls through with
  localtime logic unchanged." It splits into: (1) both `/etc/localtime`
  target AND `/etc/timezone` content match → return; (2) localtime
  mismatch → run the existing `os.Remove`+`os.Symlink`; (3) ALWAYS write
  `/etc/timezone` via `WriteFileAtomic` when its content differs,
  including the localtime-already-correct branch. Case (3) is what repairs
  the AGY r2 #3 "timezone-only stale" state WITHOUT touching a correct
  symlink — closing both the AGY loophole and the Codex crash window
  simultaneously.
- **No new regression.** The case-split touches only control flow +
  swaps the `/etc/timezone` writer to `WriteFileAtomic`; the
  `/etc/localtime` symlink mutation is untouched and out of scope (stated
  explicitly). The classification (`/etc/timezone` =
  AtomicGeneratedConfig) is unchanged and correct.
- **Everything else unchanged from r3** (cert=DurableState, D5 strict
  unlink, caller wiring, receiver-aware canary, WithOwner precedence,
  cgo-free lookupUIDGID, D8 failover) — all of which I and the other two
  reviewers already passed.

PLAN-READY. Recommend shipping the recommended option set at
`/engineer 1916`.
