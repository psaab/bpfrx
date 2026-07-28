PLAN NO

Reviewed `plan.md` v10.4.1 at `e28f356e48cb561d2f202a8acbf4ec55a1b1b96a`, read-only. No files were edited.

## Round-87 dispositions

- **r87-1 — RESOLVED.** Sections 3, 5.2(iv), and 5.8 make the miss-derived decision the sole object and prohibit using the purged stored decision for anything except provenance ([plan.md:573](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:573), [plan.md:1214](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1214)). If implemented literally, the fresh decision feeds the flow-cache insert at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900), the `pending_decision` clone at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662), rollback at [poll_descriptor/mod.rs:4890](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4890), buffer/replay at [poll_descriptor/mod.rs:5063](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5063) and [neighbor_dispatch.rs:272](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:272), telemetry at [poll_descriptor/mod.rs:5106](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5106), and reinjection at [poll_descriptor/mod.rs:5126](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5126). No normative route remains for the old stored decision. A LOW test gap remains below.

- **r87-2 — RESOLVED.** The address-only classifier at [promote.rs:32](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:32) still admits the same-address/port-only case, but re-entry through pre-routing DNAT at [poll_descriptor/mod.rs:1014](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1014) recomputes the port remap implemented at [destination.rs:699](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/destination.rs:699). A deleted rule correctly yields no translation under the stated current-configuration semantics. I found no concrete NPTv6 or NAT64 case requiring the discarded stored decision. The re-entry label should nevertheless be named explicitly as the DNAT-stage label at `:1014`; “exactly as None” could otherwise be misread as also taking the earlier cluster-return shortcut.

- **r87-3 — RESOLVED.** Section 9 now requires both forward-hit and reverse-hit positive reciprocity for plain SNAT, SNAT+DNAT hairpin, NPTv6, and NAT64 ([plan.md:1602](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1602)). That exercises the full [`NatDecision::reverse`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:105) plus [`reverse_session_key`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:173) round trip.

- **r86-7 residual — RESOLVED functionally.** Sections 5.2 and 5.8 consistently leave `account_packet` unchanged and place anchor updates in distinct post-admission hooks ([plan.md:624](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:624), [plan.md:1191](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1191)). Section 7’s statement that the new hook rides “the same probe” remains an inaccurate performance editorial, but the old dropped-packet anchor trace is normatively closed.

## New findings

1. **BLOCKER — probation can be refreshed before the packet reaches its commit arm.**

   The plan requires a filtered or TTL-dropped probation packet to perform no refresh ([plan.md:1033](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1033), [plan.md:1124](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1124)), but also says the non-close lookup path and borrow structure remain byte-identical ([plan.md:1201](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1201), [plan.md:1377](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1377)).

   Concrete trace:

   1. A blind close on a shared hit materializes the planned alive probation entry through [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092).
   2. A non-closing TTL=1 or input-filter-dropped ACK then resolves locally.
   3. The unchanged lookup stamps `last_seen_ns`, selects the ordinary established/per-app timeout, and queues the wheel at [lookup.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:146) and `:214-218`.
   4. Only afterward can the input filter drop at [poll_descriptor/mod.rs:592](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:592) or the TTL check consume the packet at [poll_descriptor/mod.rs:846](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846). Probation remains set, but its ≤20-second clock has already expanded/refreshed. Repetition pins the zombie indefinitely.

   This has an availability consequence: synced upserts have no `max_sessions` guard at [install.rs:294](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:294), while fresh installs refuse at [install.rs:113](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:113). Multiple pinned materialized entries can therefore starve new sessions.

   There is also a cache-tail variant: slow-path cache insertion occurs at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900) before final dispatch admission, and later cache hits call `touch_if_stale` at [flow_cache_hit.rs:295](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:295), whose implementation refreshes without a probation check at [session/mod.rs:1118](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1118).

   Required fold: qualify “non-close byte-identical” as non-probation only; probation lookup and `touch_if_stale` must not refresh/requeue before commit. Only the matched-entry successful commit hook may clear probation and install the ordinary timeout. Add filter, TTL, output/CoS, redirect-capacity, and cache-tail tests.

2. **LOW — r87-1 coverage omits rollback and flow-cache consumption.**

   The sole-decision rule normatively protects both, but §9 names only install, publication, buffering, replay, and reinjection.

   Add two regressions:

   - RWoLB `ForwardCandidate`: fresh P2 must be the value inserted at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900). A stale P1 cache entry would make later ACKs emit P1.
   - RWoLB `MissingNeighbor` at session capacity: refusal rollback at [poll_descriptor/mod.rs:4890](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4890) must release fresh P2. Passing stale P1 makes allocator rollback miss the owned tuple at [source.rs:781](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:781), leaking P2.

Editorially, §11 still says “clean pre-SNAT baseline,” §7 references races `(e)`–`(g)` that are actually in §10.6.2, §7’s “same probe” cost statement is stale, and §9’s exactly-one-Close assertion needs the documented transient-seed exclusion.

## Section 11 answers

1. **Terminal cut:** No direct firewall-kill, SNAT-swap, or standby-delete trace remains in the round-87 folds, but the probation refresh trace leaves the shipped fix unsafe on availability.

2. **Retreats:** No; both retreats stand. The distributed protocol and seed-lifecycle completion need not return.

3. **Fold verification:** Sole-decision, DNAT, translated reciprocity, and `account_packet` folds are sound; rollback/cache tests remain missing.

4. **Emission posture:** No new zero- or duplicate-producer trace was found outside the documented transient-seed carve-out.

5. **Arithmetic:** Confirmed: `2^32 / 393,219 ≈ 10,922.58`; `2^32 / 655,355 ≈ 6,553.65`.

6. **Must-ship remainder:** Only the local probation refresh/cache correction and its regressions, plus rollback/cache coverage. No distributed or seed-lifecycle machinery is required.

The round-87 sole-decision, DNAT, translated-family, and accounting folds are substantively correct. The plan is still not ready to implement because its probation rules conflict with the existing pre-filter lookup refresh and omit the cache keepalive site, permitting discarded non-close packets to pin materialized sessions and starve fresh admissions.
tokens used
641,113
PLAN NO

Reviewed `plan.md` v10.4.1 at `e28f356e48cb561d2f202a8acbf4ec55a1b1b96a`, read-only. No files were edited.

## Round-87 dispositions

- **r87-1 — RESOLVED.** Sections 3, 5.2(iv), and 5.8 make the miss-derived decision the sole object and prohibit using the purged stored decision for anything except provenance ([plan.md:573](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:573), [plan.md:1214](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1214)). If implemented literally, the fresh decision feeds the flow-cache insert at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900), the `pending_decision` clone at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662), rollback at [poll_descriptor/mod.rs:4890](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4890), buffer/replay at [poll_descriptor/mod.rs:5063](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5063) and [neighbor_dispatch.rs:272](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:272), telemetry at [poll_descriptor/mod.rs:5106](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5106), and reinjection at [poll_descriptor/mod.rs:5126](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5126). No normative route remains for the old stored decision. A LOW test gap remains below.

- **r87-2 — RESOLVED.** The address-only classifier at [promote.rs:32](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:32) still admits the same-address/port-only case, but re-entry through pre-routing DNAT at [poll_descriptor/mod.rs:1014](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1014) recomputes the port remap implemented at [destination.rs:699](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/destination.rs:699). A deleted rule correctly yields no translation under the stated current-configuration semantics. I found no concrete NPTv6 or NAT64 case requiring the discarded stored decision. The re-entry label should nevertheless be named explicitly as the DNAT-stage label at `:1014`; “exactly as None” could otherwise be misread as also taking the earlier cluster-return shortcut.

- **r87-3 — RESOLVED.** Section 9 now requires both forward-hit and reverse-hit positive reciprocity for plain SNAT, SNAT+DNAT hairpin, NPTv6, and NAT64 ([plan.md:1602](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1602)). That exercises the full [`NatDecision::reverse`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:105) plus [`reverse_session_key`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:173) round trip.

- **r86-7 residual — RESOLVED functionally.** Sections 5.2 and 5.8 consistently leave `account_packet` unchanged and place anchor updates in distinct post-admission hooks ([plan.md:624](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:624), [plan.md:1191](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1191)). Section 7’s statement that the new hook rides “the same probe” remains an inaccurate performance editorial, but the old dropped-packet anchor trace is normatively closed.

## New findings

1. **BLOCKER — probation can be refreshed before the packet reaches its commit arm.**

   The plan requires a filtered or TTL-dropped probation packet to perform no refresh ([plan.md:1033](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1033), [plan.md:1124](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1124)), but also says the non-close lookup path and borrow structure remain byte-identical ([plan.md:1201](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1201), [plan.md:1377](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1377)).

   Concrete trace:

   1. A blind close on a shared hit materializes the planned alive probation entry through [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092).
   2. A non-closing TTL=1 or input-filter-dropped ACK then resolves locally.
   3. The unchanged lookup stamps `last_seen_ns`, selects the ordinary established/per-app timeout, and queues the wheel at [lookup.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:146) and `:214-218`.
   4. Only afterward can the input filter drop at [poll_descriptor/mod.rs:592](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:592) or the TTL check consume the packet at [poll_descriptor/mod.rs:846](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846). Probation remains set, but its ≤20-second clock has already expanded/refreshed. Repetition pins the zombie indefinitely.

   This has an availability consequence: synced upserts have no `max_sessions` guard at [install.rs:294](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:294), while fresh installs refuse at [install.rs:113](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:113). Multiple pinned materialized entries can therefore starve new sessions.

   There is also a cache-tail variant: slow-path cache insertion occurs at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900) before final dispatch admission, and later cache hits call `touch_if_stale` at [flow_cache_hit.rs:295](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:295), whose implementation refreshes without a probation check at [session/mod.rs:1118](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1118).

   Required fold: qualify “non-close byte-identical” as non-probation only; probation lookup and `touch_if_stale` must not refresh/requeue before commit. Only the matched-entry successful commit hook may clear probation and install the ordinary timeout. Add filter, TTL, output/CoS, redirect-capacity, and cache-tail tests.

2. **LOW — r87-1 coverage omits rollback and flow-cache consumption.**

   The sole-decision rule normatively protects both, but §9 names only install, publication, buffering, replay, and reinjection.

   Add two regressions:

   - RWoLB `ForwardCandidate`: fresh P2 must be the value inserted at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900). A stale P1 cache entry would make later ACKs emit P1.
   - RWoLB `MissingNeighbor` at session capacity: refusal rollback at [poll_descriptor/mod.rs:4890](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4890) must release fresh P2. Passing stale P1 makes allocator rollback miss the owned tuple at [source.rs:781](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:781), leaking P2.

Editorially, §11 still says “clean pre-SNAT baseline,” §7 references races `(e)`–`(g)` that are actually in §10.6.2, §7’s “same probe” cost statement is stale, and §9’s exactly-one-Close assertion needs the documented transient-seed exclusion.

## Section 11 answers

1. **Terminal cut:** No direct firewall-kill, SNAT-swap, or standby-delete trace remains in the round-87 folds, but the probation refresh trace leaves the shipped fix unsafe on availability.

2. **Retreats:** No; both retreats stand. The distributed protocol and seed-lifecycle completion need not return.

3. **Fold verification:** Sole-decision, DNAT, translated reciprocity, and `account_packet` folds are sound; rollback/cache tests remain missing.

4. **Emission posture:** No new zero- or duplicate-producer trace was found outside the documented transient-seed carve-out.

5. **Arithmetic:** Confirmed: `2^32 / 393,219 ≈ 10,922.58`; `2^32 / 655,355 ≈ 6,553.65`.

6. **Must-ship remainder:** Only the local probation refresh/cache correction and its regressions, plus rollback/cache coverage. No distributed or seed-lifecycle machinery is required.

The round-87 sole-decision, DNAT, translated-family, and accounting folds are substantively correct. The plan is still not ready to implement because its probation rules conflict with the existing pre-filter lookup refresh and omit the cache keepalive site, permitting discarded non-close packets to pin materialized sessions and starve fresh admissions.
