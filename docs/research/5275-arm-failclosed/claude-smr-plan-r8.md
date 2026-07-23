# Claude SMR — hostile plan review r8 (#5275)

Reviewing `plan.md` @ r9. Codex r7 ruled **D1–D4 SOUND** (with two wording fixes)
and isolated **D5 as the one genuinely unsafe** design choice. r9 redesigns D5 and
folds the D1/D4 wording. I verified the D5 building blocks in source.

## Codex r7 accepted D1–D4 (SOUND); r9 folds the two wording fixes
- **D1 wording:** §5 said "both stages" share proof ingredients — corrected to
  PER-STAGE (preliminary = attach inventory + shim instance; final adds digest +
  helper generation + ready bindings), matching the controlling D1. ✓
- **D4 wording:** the ACK is now a **durably-staged recovery receipt** that NEVER
  advances the live-applied generation (not an "applied high-water"), per Codex r7. ✓

## D5 redesign (the r7 blocker) — grounded in shipped mechanisms

Codex r7's fatal trace: a former-primary CRASH restart cannot control the peer's
election (the peer's `lastSeen` timer runs independently, `electSingleNode` before
fencing, heartbeat_manager.go:404; interval can be 1 ms/1, schema_chassis.go:74; Kea
stop is 15 s/call, not ms). Verified firsthand. r9's redesign stops trying to beat
the election:
- **Crash-restart:** the peer's takeover is CORRECT; the restarting fail-closed node
  SCRUBS its stale inherited VIP synchronously (fast verified netlink) + advertises
  weight-zero yield + stops Kea/clears FRR async as teardown debt. No race — only stale
  state to remove; no dual-VIP because the stale VIP is removed and the node owns no RG
  (weight-zero) and forwards nothing (§6 barrier). ✓
- **Live re-arm:** reuse the SHIPPED peer-side liveness-suppression
  (`shouldSuppressPeerHeartbeatTimeout` / `SendLivenessKeepalive`, the bounded
  self-clearing 2 s-recency/5 s-cap guard the heartbeat-restart path already uses,
  heartbeat_manager.go:171) as the promotion interlock while the local fence + yield
  apply; a genuinely dead node still fails over (bounded suppression). ✓
- **§3 reconciliation:** "attraction cleared+verified before takeover" scoped to the
  FAST VIP (synchronous verified); Kea/FRR de-dup async (blocking the yield on 15 s/40 s
  would delay the peer's clean takeover — worse). ✓

I confirmed heartbeat_manager.go:165-190 documents exactly this bounded, self-clearing
peer-side suppression + the `lastSeen` carryover, so the D5 interlock reuses a real,
reviewed mechanism rather than inventing timing control.

## Assessment

With D1–D4 accepted by Codex and D5 redesigned around a shipped mechanism (no
"control the peer's clock" assertion; the peer's takeover is correct and the failed
node only removes stale state + yields), the plan no longer contains a known-unsafe
contract. Every reviewer finding across eight rounds is folded with a mechanism + a
source coordinate; the architecture has been viable since r4 and is now a complete,
source-consistent design contract with its scope honestly phased.

## Residual (implementation, for `/engineer`)
- The D5 async Kea/FRR de-dup must be tracked as durable teardown debt with a bounded
  retry (a stuck Kea stop must not leave the fenced service half-up indefinitely).
- The live-re-arm interlock's bound (5 s cap) must exceed the fast VIP fence + yield
  path (it does — VIP removal is ms); if a future fence step is slow it must move to
  async. An implementation note, not a design gap.

## Verdict

r9 resolves the sole remaining unsafe contract (D5) using shipped mechanisms and
folds the D1/D4 wording; D1–D4 are Codex-accepted. The plan is a complete, viable,
source-consistent design contract — the `/research` deliverable, ready for human
go/no-go and `/engineer`.

VERDICT: PLAN-READY
