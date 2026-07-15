# Re-triage result: gemini-review-043

**Review base commit:** `0ebdb74b2e8bf04b40495f49b6a64f9146af09fc` (STALE — the
review's file:line citations point at a `/home/ps/git/gemini-xpf` fork checkout).
**Re-triaged against:** `origin/master` @ **`a6fcd463b15c2fdcde283c9914f1e26f65a87435`**
(fetched fresh; ~3300 commits ahead of the review base). Every disposition below
was verified via `git show origin/master:<path>` grepping the SYMBOL, never the
stale local working tree.

## Why a re-triage

A prior pass (2026-07-09, `/tmp/result-gemini-review-043.md` before this
overwrite) filed 28 issues (#4805–#4837) from this review. **All 28 are now
CLOSED** — 26 as `COMPLETED` (real code fixes merged), 2 as invalid/not-a-bug
(#4812 retired-eBPF, #4833 refuted). Master has advanced far enough that every
genuine finding here has since been fixed. This pass re-verifies each finding
against the current tip and confirms nothing material is still open.

## Bottom line

- **0** genuinely-still-open material findings → **0 new issues filed.**
- **28** findings were filed in the prior pass (#4805–#4837), all now CLOSED
  → already-resolved, NOT refiled (per gate 2).
- **2** findings (M3, M4) were already-fixed by pre-existing PRs (#4715/#4716)
  and never refiled → confirmed still fixed on `a6fcd463b`.
- **3** findings were never filed (rejected) → rejection re-confirmed vs
  `a6fcd463b` (H2 refuted, L1 no-content, L12 deliberate/tested).

Total = 0 + 28 + 2 + 3 = 33 findings (7 High + 5 Medium + 21 Low, incl. 1 garbled).

---

## HIGH (7)

### H1 — Standby LocalDelivery → PASS_TO_KERNEL (`handle_refresh_owner_rgs`)
**already-fixed-and-closed-as-#4805 (COMPLETED).** `refresh_owner_rgs.rs` now
recomputes `allow_replace_local` per session (explicit `// #4805` comments;
no hardcoded `false`). Defect gone.

### H2 — Bare IPv6 host appended to `v4nets` in `addCIDRValue`
**dropped — refuted, rejection re-confirmed.** `pkg/policymatch/policymatch.go`
`addCIDRValue` (origin/master :1546) non-v4 branch at :1578 appends to
`*v6nets`, not `*v4nets`. The claimed bug does not exist on master. Never filed;
correctly so.

### H3 — Interface-range `member-range` int64-overflow panic
**already-fixed-and-closed-as-#4807 (COMPLETED).**
`compiler_interface_range.go:273` now compares `en-sn >= interfaceRangeMaxMembers`
BEFORE adding 1 (overflow-safe; documented). Defect gone.

### H4 — Sibling security-zone blocks overwrite (load override)
**already-fixed-and-closed-as-#4818 (COMPLETED).** (#4816 was the closed
duplicate.)

### H5 — Sibling RPM probe/test blocks overwrite (load override)
**already-fixed-and-closed-as-#4820 (COMPLETED).** (#4817 was the closed
duplicate.)

### H6 — Missing `ClearSessionCounts()` → stale BPF session counts
**already-closed-as-#4812 (retired-eBPF, not-a-bug); rejection re-confirmed.**
`session_count_src/dst` have ZERO references in `userspace-xdp/` on master; the
live per-IP limit runs through `new_flow_session_limit_drop`
(`userspace-dp/src/afxdp/poll_descriptor/mod.rs:622`) reading the in-memory Rust
`SessionTable` (`session_limit_src_count`) — no BPF map read, no staleness. The
Go-side `UpdateSessionCount*`/`ClearSessionCounts` (`pkg/conntrack/gc.go:34-36,
459-464`) write a map family the live dataplane never reads. Retired-eBPF dead
path. Not refiled.

### H7 — `Manager.Start()` AB-BA deadlock with monitor poll loop
**already-fixed-and-closed-as-#4828 (COMPLETED).** `Manager.Start()`
(`pkg/cluster/manager.go:411`) now snapshots `old := m.monitor` under `m.mu`,
UNLOCKS, then calls `old.Stop()` outside the lock; `Manager.Stop()` does the same
(snapshot `mon`, unlock, then `mon.Stop()`). The lock is no longer held across
`monitor.Stop()`. Defect gone.

---

## MEDIUM (5)

### M1 — Sibling ssh-known-hosts blocks overwrite (load override)
**already-fixed-and-closed-as-#4821 (COMPLETED).** (#4819 was the closed
duplicate.)

### M2 — `loadRollbackHistory` shifts indices on intermediate read failure
**already-fixed-and-closed-as-#4810 (COMPLETED).**

### M3 — Data race on `Monitor.cachedNlHandle`
**already-fixed (#4715, pre-existing); never refiled; confirmed still fixed.**
`pkg/cluster/monitor.go:63-64` documents "the write cannot race Stop()'s
cachedNlHandle=nil (#4715)"; access is under `mon.mu`. Holds on master.

### M4 — `rg.holdTimer` leak / spurious post-Stop wakeup
**already-fixed (#4716, pre-existing); never refiled; confirmed still fixed.**
`Manager.Stop()` (`manager.go:442-446`) sets `m.stopped = true` and iterates
groups `rg.holdTimer.Stop(); rg.holdTimer = nil`; the callback checks
`m.stopped`. Explicit `#4716` cites. Holds on master.

### M5 — Swallowed netlink errors in `probePinManager.clear()`
**already-fixed-and-closed-as-#4822 (COMPLETED).** `clear()`
(`pkg/routing/probe_pin.go:256`) now aggregates via `errors.Join` (doc comment
:248 "mirroring the pattern in rules.go"). Defect gone.

---

## LOW (21)

| # | Finding | Disposition |
|---|---------|-------------|
| L1 | garbled title "s", no content | **dropped — no content**; nothing to verify. Never filed. |
| L2 | chrony parser test-coverage gap | already-fixed-and-closed-as-#4824 (COMPLETED) |
| L3 | NTP status prints bare header on chronyc failure | already-closed-as-#4833 (refuted after re-verify — `Leap status`/`ntpq`/`timedatectl` fallbacks); rejection stands. Not re-refiled. |
| L4 | `cmd/xpfd/` subcommand dispatch untested | already-fixed-and-closed-as-#4825 (COMPLETED) |
| L5 | `validateFirewallFilterFamilyCollisionsAST` `Keys[0]` no guard | already-fixed-and-closed-as-#4827 (COMPLETED) |
| L6 | SNMP `clients` prefix — mistyped `restrict` fail-open | already-fixed-and-closed-as-#4834 (COMPLETED) |
| L7 | DDNS `forced-refresh`/`error-backoff-max` no commit validation | already-fixed-and-closed-as-#4837 (COMPLETED) |
| L8 | `system backup-router` next-hop/dest unvalidated | already-fixed-and-closed-as-#4808 (COMPLETED) |
| L9 | Journal mutex held across fsync blocks `Tail()` | already-fixed-and-closed-as-#4829 (COMPLETED) |
| L10 | `time.After` leak in `pkg/ra` select blocks | already-fixed-and-closed-as-#4830 (COMPLETED) |
| L11 | VRRP `GroupID=100+rgID` truncates for rgID>155 | already-fixed-and-closed-as-#4826 (COMPLETED) |
| L12 | Empty peer MAC in fabric snapshot | **dropped — deliberate/tested, rejection re-confirmed.** `forwarding/mod.rs:108-120` documents "`peer_mac` is empty until ARP/NDP resolves"; unresolved peer is skipped-and-counted (`xpf_userspace_fabric_link_unresolved_peer_total`), refreshed by `SyncFabricState()`. Never filed. |
| L13 | `PersistentNATTable.All()` shared pointers race | already-fixed-and-closed-as-#4811 (COMPLETED) |
| L14 | `EventStream.writeFrame` conn race | already-fixed-and-closed-as-#4835 (COMPLETED) |
| L15 | `userspaceSupportsSourceNAT` dead code | already-fixed-and-closed-as-#4831 (COMPLETED) |
| L16 | `renderHostInboundMatches` infinite loop on nil ICMPType | already-fixed-and-closed-as-#4813 (COMPLETED) |
| L17 | Bootstrap lifeline record unwritable for non-PCI NIC | already-fixed-and-closed-as-#4815 (COMPLETED) |
| L18 | `bondManager.Apply()` swallows errors | already-fixed-and-closed-as-#4823 (COMPLETED) |
| L19 | Silent selector drop in showTestRouting/showTestZone | showTestZone → already-fixed-and-closed-as-#4814 (COMPLETED); showTestRouting was already-fixed-#4589 |
| L20 | `(*CLI).testRouting` test-coverage gap | already-fixed-and-closed-as-#4832 (COMPLETED) |
| L21 | `SyslogClient` no closed-state check | already-fixed-and-closed-as-#4806 (COMPLETED) |

---

## Summary tally

- **Still-open-filed (new this re-triage): 0**
- **Already-fixed: 30**
  - 26 filed prior pass + closed `COMPLETED` (real fixes on `a6fcd463b`):
    H1, H3, H4, H5, H7, M1, M2, M5, L2, L4, L5, L6, L7, L8, L9, L10, L11, L13,
    L14, L15, L16, L17, L18, L19, L20, L21
  - 2 filed prior pass + closed as invalid/not-a-bug (rejection re-confirmed):
    H6 (#4812 retired-eBPF), L3 (#4833 refuted)
  - 2 already-fixed pre-existing, never refiled, still fixed: M3 (#4715),
    M4 (#4716)
- **Dup: 0** (0 new issues filed → nothing to dedup)
- **Dropped (never filed, rejection re-confirmed vs a6fcd463b): 3**
  H2 (refuted — code appends to v6nets), L1 (garbled/no-content),
  L12 (deliberate/tested fabric unresolved-peer handling)

**Conclusion:** exactly the expected outcome for a re-triage 3300 commits past
the review base — every genuine finding was already filed and has since been
fixed; every prior rejection re-confirms against current master. No new issues
warranted.
