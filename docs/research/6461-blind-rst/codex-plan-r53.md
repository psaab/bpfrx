PLAN NO

1. **BLOCKER — The v2 transcript remains non-interoperable because the capability-bit registry and promised vectors are absent.**

   `plan.md@f8f03bbe9:4059-4079` now correctly defines each transcript term as `u16-LE(length) || raw payload`, excluding the frame header, consistent with [sync_auth.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:289). However, the plan merely lists capabilities at `:3957-3961` and says they are packed LSB-first at `:4071-4075`; it never assigns bit numbers. The claimed literal vectors at `:4081-4082`, `:4100-4109`, and §9 `:4812-4820` contain no key, complete HELLO/capability payload values, HMAC inputs, or expected digests. The formula also says only `HMAC`, while current code uses HMAC-SHA256 at [sync_auth.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:217).

   Concrete trace: implementation A interprets bit 0 as `repair-vN`; implementation B interprets it as `reset-vN`. Both authenticate the same raw `u32(1)` successfully, but only A enters repair completion. B follows legacy `BulkEnd`/`BulkAck` processing at [sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:205), while A waits for `JOURNAL_ACK`, leaving its cold-prime/readiness state unresolved and repeatedly redriven through [sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go:572).

   Required change: add a normative capability-to-bit-number table, explicitly specify HMAC-SHA256, and provide actual keyed hexadecimal constants for the key, both HELLO payloads, both capability payloads, complete role-specific inputs, and both expected digests.

2. **HIGH — `CAPABILITY_CONFIRM` can activate a completion protocol while cold-prime is already running.**

   The plan puts `CAPABILITY_CONFIRM` after wrapper/installation at `plan.md@f8f03bbe9:3981-3984` and enables features immediately after matching confirmations at `:4013-4019`, but defines no session-dispatch barrier or transaction-bound activation. Today the wrapper and slot are installed at [sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go:118), the receive loop starts at `:132`, and cold-prime starts immediately at `:138-194`. Bulk synchronization is one live `BulkStart → rows → BulkEnd` transaction at [sync_bulk.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:50).

   Concrete trace: a confirmation-capable pair using the v1 proof begins cold-prime while `repair-vN` is inactive. Under `plan.md:4168-4174`, that is an install-only prime with no negotiated obligation. Matching confirmations then arrive during emission and activate `repair-vN`. Continuing the original prime can clear cold-prime after emission without reconciliation, leaving stale peer rows; switching protocols mid-window produces incompatible terminal processing. Although obligations are keyed by their creation protocol, the plan does not arm a fresh repair when the capability transitions from inactive to active.

   Required change: either finish `CAPABILITY_CONFIRM` before slot installation/session dispatch and cold-prime, or latch the protocol class for the entire transaction and, after confirmation, explicitly schedule a fresh repair-era full bulk. Add a confirmation-during-cold-prime regression test.

**Round-52 dispositions**

- **r52-1 — PARTIALLY RESOLVED.** Raw-payload framing, field order, widths, and endianness are now defined, but finding 1 leaves the capability namespace and interoperability oracle unspecified.
- **r52-2 — RESOLVED.** The operative plan consistently treats HELLO capabilities as advertisements and requires matching authenticated same-connection confirmations before any v1-proof capability activates. Finding 2 concerns the separate activation/cutover boundary.

Bottom line: the v9.9.51 folds resolve the competing v1 activation rules and most serialization ambiguity, but final sign-off remains blocked. The missing bit registry/vectors permit asymmetric protocol interpretation, and the confirmation cutover can leave the peer incompletely reconciled or readiness unresolved. I found no additional concrete demote-gate or translated-tuple lifetime trace in the combined §5.2/§5.8 mechanism.
