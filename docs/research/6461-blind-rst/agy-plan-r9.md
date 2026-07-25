# AGY hostile plan review — round 9 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only, scoped sections). Scope: plan v7.5. Transcript: .scratch/r9-agy-out1.txt (verbatim below).

---

### Design Review Verdicts (#6461 Plan v7.5)

**(1) Authority Gate & RG Stamping: UNSOUND**
- [install.rs:150](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L150) stores `metadata: metadata.clone()` without auto-stamping `owner_rg_id` when `metadata.owner_rg_id == 0`.
- [poll_descriptor/mod.rs:1922](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1922) explicitly passes `owner_rg_id: 0` on local delivery miss ([local_delivery.rs:84-115](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/local_delivery.rs#L84-L115)).
- Only [promote.rs:93-94](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L93-L94) stamps `owner_rg_id` if `<= 0`. `owner_rg_id` is NOT stamped on all forward install paths (`install.rs` & `local_delivery.rs`), causing `demote_owner_rg` ([install.rs:542-547](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L542-L547)) to miss unstamped entries during HA demotion.

**(2) Ticket CAS & Mint-on-Zero ID Allocation: UNSOUND**
- When `wire_session_id == 0`, [install.rs:340-344](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L340-L344) calls `self.alloc_session_id()`.
- [session/mod.rs:784-790](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L784-L790) defines `alloc_session_id(&mut self)` using `self.session_id_worker_hi | low`, which embeds per-worker thread bits.
- Two workers importing or materializing the same id-0 flow execute `alloc_session_id()` on separate worker threads, minting DIFFERENT IDs (`session_id_1 != session_id_2`). `alias.session_id == entry.session_id` fails to match across workers, breaking the CAS.

**(3) Phase-2 Incarnation & Bulk Epoch Ordering: UNSOUND**
- [plan.md:1477-1478](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1477-L1478) (§10.5) specifies the apply condition `update.bulk_epoch >= stored.bulk_epoch`.
- Within the same bulk epoch `E`, if an incremental update $U$ (sent at $t_1$) arrives before a delayed bulk baseline $B$ (sent at $t_0 < t_1$), $B$'s epoch $E$ satisfies $E \ge E$.
- The stale baseline $B$ overwrites the newer incremental state $U$ because `>=` allows equal-epoch delayed baselines to land over newer incrementals without per-side sequence checks.

**(4) Plan-Text Contradictions: UNSOUND**
- **Zero Session ID for HA imports:** [plan.md:646-647](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L646-L647) (§5.2) states legacy/bulk imports can carry `session_id == 0` and mint locally, whereas [plan.md:1596](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1596) (§11.1a) states HA-imported entries ALWAYS carry a nonzero wire `session_id`.
- **Bulk Ordering Claim vs Rule:** [plan.md:1478](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1478) (§10.5) rules `update.bulk_epoch >= stored.bulk_epoch`, but [plan.md:1479](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1479) (§10.5) claims older updates cannot overwrite newer incrementals (violated by equal-epoch `>=`).
- **Close Authority Formula:** [plan.md:631-633](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L631-L633) (§5.2) specifies v7.5 `owner_rg_active(entry)`, while [plan.md:1094-1096](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1094-L1096) retains stale v7.4 text `(locally-born origin || owner_rg_id active locally)`.
