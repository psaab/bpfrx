PLAN NO

Review pinned to `1998efda5`. Part A remains converged; no one-packet-anytime blind-demote regression was found. No files were edited.

1. **BLOCKER — the proposed cluster-ordered config version does not exist at the cited location.**

   The new rule claims `store.go:88` is a cluster-ordered commit counter ([plan.md:1189](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1189)). It is actually `candidateGen`, a node-local transaction token changed by candidate edits, configuration-mode transitions, rollbacks, and resets ([store.go:72](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/configstore/store.go:72), [store_gen.go:19](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/configstore/store_gen.go:19)). `SyncApply` bumps it only when that node happens to be in configuration mode ([store.go:691](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/configstore/store.go:691)).

   The genuinely comparable config-sync generation is the separate `configGenCounter` ([sync_conn_config.go:222](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_config.go:222)); its receiver callback currently passes only config text, not that generation ([daemon_ha_sync.go:910](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_sync.go:910)).

   Concrete trace: A admits E2 under configuration C2 with local token 10; B’s independent candidate activity has advanced its token to 100. E2 reaches B before B’s C2 invalidation. Comparing `10 < 100` falsely selects and companion-deletes a flow already admitted under C2. The reverse skew can retain stale E1. The plan must explicitly carry the #3931 generation—or another authority-issued epoch—through config apply and `ForwardingState`; “the config is synced” does not make a local counter comparable.

   The preceding operative text also still says “forwarding generation” and cites `manager_generation.go` ([plan.md:1150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1150), [plan.md:1180](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1180)), contradicting the new paragraph.

2. **BLOCKER — INSTALL/Open identity and atomic resend remain assertions, not an operative pipeline.**

   The operative wire section defines only the DELETE identity tail ([plan.md:1294](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1294)). INSTALL/Open appears only in summaries ([plan.md:1801](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1801)); the storage paragraph still refers to “Phase 2’s sidecar” ([plan.md:1406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1406)). There is no `row_version`, atomic `(row, identity, row_version)` snapshot, send-time version recheck, or sender/receiver sidecar lifecycle in the plan.

   Current `SessionValue`, `SessionDelta`, and `SyncedSessionEntry` lack the identity pair ([types.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/types.go:89), [entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283), [worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375)). Bulk and periodic resend read detached BPF rows ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:95), [sync_conn_sweep.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:142)); lifting a BPF row drops all sync-only metadata ([bpf_session_value.go:204](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:204)).

   ABA trace: bulk captures E1’s NAT row; E2 replaces the tuple and identity; a later sidecar lookup obtains I2; E1’s stale translation is sent labelled I2. The receiver can overwrite E2 with stale NAT state or subsequently accept an I2 delete against it. The policy stamps added in §5.2 depend on this same missing install pipeline.

3. **BLOCKER — zero-install cleanup is scoped per entry but deletes an entire family.**

   The new rule waits for the final outcome “for that entry” and checks its `installed_count == 0` before family cleanup ([plan.md:964](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:964)). A logical flow’s forward and synthesized reverse are separate shared entries ([session_import.rs:104](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:104)) and are separately snapshotted, pre-published, and fanned out ([coordinator/mod.rs:753](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:753), [coordinator/mod.rs:771](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:771)).

   If every forward replay rejects while a reverse replay installs, the forward cohort reports zero installs and deletes family/BPF state beneath the installed reverse. Similarly, reactive materialization through [session_glue/mod.rs:1157](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1157) is not counted in replay `installed_count`; final cleanup can delete beneath that live holder. Finalization must cover the complete `(incarnation, allocation, family)` cohort and serialize with non-replay retain.

4. **BLOCKER — §9 still requires the exact legacy Close kill forbidden by the main rule.**

   The main design suppresses every incarnation-dependent Close toward an unnegotiated peer and checks capability at every write/replay ([plan.md:1302](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1302), [plan.md:1330](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1330)). Section 9 instead says plain owner-validated Close deltas continue to legacy peers ([plan.md:2039](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2039)).

   Following §9 preserves the plan’s own trace: legacy B replaces E1 with authoritative same-key E2; new A sends E1’s Close; B ignores identity, accepts the generation, and key-deletes E2 plus NAT companions ([plan.md:1309](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1309), [sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263), [session_store.go:537](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:537)).

5. **HIGH — the claimed compatible-allocator migration is still absent.**

   The plan still specifies only a token owning the exact old allocator handle ([plan.md:1027](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1027)). No collision-domain comparison, pool generation, or A→B reservation sequence exists.

   `SourceNatPoolAllocatorKey` includes `pool_name` ([source.rs:327](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:327)), and reuse requires exact-key equality ([source.rs:726](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:726)). A name-only rename therefore creates allocator B while E1 remains held only in A. B may assign E1’s public tuple to another flow; re-resolving E1 may then swap its pool port mid-connection. Exact PAT, NAT64, and address-only reservations must migrate to every compatible current allocator before A is released.

6. **HIGH — mixed-version fallback delegates cleanup to the legacy selector that can kill authoritative E2.**

   The plan relies on the legacy node’s own invalidation pass ([plan.md:2041](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2041)). That binary publishes the new policy before clearing old sessions ([daemon_apply_commit.go:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:245)) and selects only by reused numeric `PolicyID` ([daemon_policy_invalidate.go:311](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:311)).

   During that window, a surviving rule can inherit a deleted rule’s numeric slot and admit E2; the old pass selects E2 as belonging to the deleted rule and companion-deletes it through [session_store.go:391](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:391). Capability negotiation cannot retrofit the stable selector into an old binary. Mixed-version policy changes need an operational/version gate or an explicitly accepted unsafe window.

7. **MEDIUM — the layout and acceptance contracts remain inconsistent.**

   Section 9 still mandates a distinct “content version” and “admission forwarding generation” ([plan.md:2031](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2031)), although the main design supersedes content-only identity and now names `admission_config_version`. The layout lists only clock/incarnation additions to the shared schema, omitting identity, row-version, and policy-selector fields ([plan.md:1806](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1806)). Section 10.5 also says the ship candidate has no wire change ([plan.md:2400](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2400)), contradicting Part B’s INSTALL/Open and DELETE tails.

8. **LOW — the cursor fold has converged.**

   Both operative locations now use a coordinator-global immutable sequence allocated inside the map lock, an exclusive cursor, and a scan-start high-watermark ([plan.md:1227](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1227), [plan.md:2117](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2117)). The remaining “key as tiebreak” wording is unnecessary because `SessionKey` has no ordering and in-lock sequence allocation is unique; it is not a kill trace.

### Prior-finding dispositions

- **Round 21:** B1 policy selector — **partially resolved**; B2 install identity — **not resolved**; B3 mixed-version propagation — **partially resolved**; H4 permit linearization — **resolved as originally framed**; H5 fence tuple — **resolved**; M6 cursor — **resolved**; M7 contract sweep — **partially resolved**.
- **Round 22:** a install identity — **not resolved**; b mixed delete — **partially resolved**; c policy selector — **partially resolved**; d permit/escrow — **resolved as originally framed**; e cursor — **resolved**; f contract sweep — **partially resolved**.
- **Round 23:** 1/c install identity — **not resolved**; 2/a mixed delete — **partially resolved**; 3/d policy selector — **partially resolved**; 4/b permit lifetime — **resolved as originally framed**; 5 cursor — **resolved**; 6 contract sweep — **partially resolved**.
- **Round 24:** B1 mixed-version delete — **partially resolved**; B2 install identity — **not resolved**; B3 escrow lifetime — **resolved as originally framed**; B4 policy selector — **partially resolved**; M5 cursor — **resolved**; L6 contract sweep — **partially resolved**.
- **Round 25:** B1 legacy Close — **partially resolved**; B2 install identity — **not resolved**; B3 policy stamp — **partially resolved**; H4a rejection cleanup — **partially resolved**; H4b allocator migration — **not resolved**; M5 cursor — **resolved**; LOW contract reconciliation — **partially resolved**.
- **Round 26:** B1 install identity/atomic resend — **not resolved**; B2 capability suppression — **partially resolved**; B3 rejection cleanup — **partially resolved**; H4 allocator migration — **not resolved**; H5 policy home/version — **partially resolved**; M5 cursor — **resolved**.
- **Deferred to Phase-2 track:** none of these findings.

Part A still removes the original one-packet-anytime blind-demotion capability. Part B is not signable: its newly cited “cluster config version” is actually a local candidate token, INSTALL identity remains non-atomic and resend-unsafe, replay cleanup can delete beneath live family members, §9 preserves the new→legacy Close kill, and allocator changes still permit an SNAT collision or port swap. These are concrete HA/SNAT harm paths, not Phase-2 preferences or documented anchor-stall residuals.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
