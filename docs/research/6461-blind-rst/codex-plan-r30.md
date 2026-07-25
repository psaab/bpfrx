PLAN NO

Review pinned to `b3a91a207`; no files were edited. Part A remains converged. The committed plan contains no temporary-stop or persistent-dispatch fold, despite the commit message claiming both.

1. **BLOCKER — allocator compatibility still permits a PAT ↔ address-only collision.**

   The new freeze states the right outcome for detected A→B migrations, but compatibility remains “same address space” and detection uses allocator key/collision domain ([plan.md:1081](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1081), [plan.md:1106](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1106)). `SourceNatPoolAllocatorKey` contains only pool name, addresses, and port range—not `no_translation` or ownership mode ([source.rs:327](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:327)); exact-key reload therefore reuses the same allocator ([source.rs:726](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:726)) without triggering the new migration fence.

   Concrete trace: C1 PAT E1 owns public P in the occupancy bitmap through [allocator.rs:999](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:999). C2 changes the same pool to `port no-translation`. E2 has preserved source port P and the same remote; address-only admission checks only `address_only_owners` ([allocator.rs:1727](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1727)) and succeeds despite P’s bitmap ownership. E1 and E2 now have the identical public reverse tuple. The reverse transition is symmetric: an address-only owner is invisible to new PAT bitmap allocation. Allocation mode/ownership namespace must enter compatibility detection, or mode changes must be classified incompatible and quiesced.

   Detected A→B migration also lacks an explicit holder bridge: tokens own the exact A allocator handle ([plan.md:1057](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1057)), while a post-snapshot materialization can still retain E1 through A ([session_glue/mod.rs:1157](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1157)). The design must bridge A/B retain and release operations or quiesce and retokenize the workers; freezing only fresh allocation does not define B’s safe release point.

2. **BLOCKER — ordinary HA import still cannot represent shared persistent leases.**

   The plan correctly states that generic `reserve_flow` cannot migrate F1/F2 sharing one lease ([plan.md:920](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:920)), but the claimed repair was not committed: the later restore rule still unqualifiedly prescribes `reserve_flow`/`reserve_address_only` ([plan.md:1106](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1106)). More importantly, no clause applies lease-object creation/retention to initial peer INSTALLs.

   The active allocator legitimately gives F1 and F2 the same P under one persistent key, as tested at [tests_pool.rs:2536](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/tests_pool.rs:2536). On standby B, each imported forward uses the generic reservation helper ([upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64), [source.rs:868](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:868)). F1 records P with `persistent_key: None`; F2 fails the occupied-bit check ([allocator.rs:1682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1682)), but the upsert still publishes at `upsert_synced.rs:112`.

   After failover, F1’s teardown takes the non-persistent release branch and frees P ([allocator.rs:1318](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318)); F2 remains live but has no lease membership. A same-remote E3 can then obtain P, producing reverse-NAT misdelivery. Every initial/replayed persistent peer install needs an atomic exact lease-create-or-retain before publication, with failure rejecting the install.

3. **BLOCKER — temporary `stop()`/rebind still has no escrow handoff.**

   The plan continues to scope the two-phase mechanism expressly to “the reconcile sequence” ([plan.md:881](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:881)); no generalized shutdown/rebind text was added.

   `stop_workers` anticipates later rebind and calls `stop()` ([stop_workers.rs:7](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/stop_workers.rs:7)). That reaches `stop_inner(true)` ([coordinator/mod.rs:429](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:429)), joins/drops worker-held state at `:645`, and clears synced/NAT/wire families at `:709`. E1’s final reservation can therefore disappear during a temporary link cycle; rebind can re-resolve E1 or allow E2 to take P. Permanent shutdown remains distinct at `coordinator/mod.rs:441`, so treating every `stop()` as permanent is not a valid fence.

4. **HIGH — §9 still authorizes the exact new→legacy delete it elsewhere suppresses.**

   The inserted text says identity-dependent deletes are suppressed ([plan.md:2296](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2296)), but then calls the old-receiver fallback “gen-based deletes,” retains `new-sender→old-receiver (tail ignored)` at [plan.md:2325](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2325), and still generically says mixed-version pairs fall back to generation deletion at [plan.md:2367](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2367).

   Following those retained clauses sends A’s E1 Close to legacy B. B parses only key and generation ([sync_conn_read.go:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:150)), accepts an equal/fresh generation ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)), and key-deletes current same-key E2 plus companions at `sync_conn_gen.go:493-506`. The matrix remains internally unsatisfiable.

5. **MEDIUM — the selector-schema fold is only partial.**

   Normative §5.8 now correctly places `stable_rule_id_hash` and `admission_config_version` in INSTALL/Open and in the atomic snapshot ([plan.md:1939](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1939)). However, the claimed shared-schema update is absent: the inventory still lists only `last_touch_ns`, `expires_after_ns`, and `flow_incarnation_id` ([plan.md:2010](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2010)); the Go sidecar inventory at `:1952` likewise names only identity and row version. Section 9 additionally retains the superseded “content version” contract at `plan.md:2235-2242`.

   Following the normative tail closes the prior selector trace, so this is not independently verdict-driving. Following the storage inventory, however, drops selectors that cannot be reconstructed from the BPF projection ([bpf_session_value.go:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:168)) and leaves the positional invalidation path at `daemon_policy_invalidate.go:311`.

### r21–r29 dispositions

- **r21:** B1 selector/generation **partially**; B2 install identity **resolved**; B3 owner gate **resolved**; H4 permit linearization **resolved**; H5 identity tuple **resolved**; M6 cursor **resolved**; M7 contract sweep **partially**.
- **r22:** a install identity **resolved**; b mixed delete **partially**; c selector **partially**; d permit/escrow **resolved** for reconcile; e cursor **resolved**; f contract sweep **partially**.
- **r23:** 1/c install identity **resolved**; 2/a mixed delete **partially**; 3/d selector **partially**; 4/b permit lifetime **resolved**; 5 cursor **resolved**; 6 contract sweep **partially**.
- **r24:** B1 mixed delete **partially**; B2 identity source **resolved**; B3 durable escrow **partially**—reconcile covered, temporary stop absent; B4 selector **partially**; M5 cursor **resolved**; L6 sweep **partially**.
- **r25:** B1 legacy Close **partially**; B2 atomic snapshot **resolved**; B3 policy stamp **partially**; H4a rejection cleanup **resolved**; H4b allocator migration **partially**; M5 cursor **resolved**; LOW contract reconciliation **partially**.
- **r26:** B1 row-version pipeline **resolved**; B2 capability tagging **partially** because §9 contradicts it; B3 cleanup **resolved**; H4 allocator migration **partially**; H5 selector carriage **partially**; M5 cursor **resolved**.
- **r27:** config epoch, identity snapshot, complete cohort, mixed-version policy gate, and cursor **resolved**; Close, allocator migration, and schema inventory **partially**.
- **r28:** B1 config epoch **resolved**; B2 in-place migration **partially**; B3 persistent migration **partially**; B4 install-only bulk **resolved**; H5 Close contract **partially**; H6 selector schema **partially**; H7 temporary stop **not resolved**.
- **r29:** B1 cutover **partially**; B2 temporary stop **not resolved**; H3 persistent API contract **not resolved**; H4 selector schema **partially**; H5 mixed-version matrix **not resolved**.
- **Deferred-to-phase2-track:** only the documented imported-anchor/reimport fast-reap residual. None of findings 1–5 is deferred.

### Bottom line

No blind-demote DoS trace remains against Part A, and the config epoch, atomic identity snapshot, cohort cleanup, install-only mixed-version bulk, and cursor remain converged. But concrete mid-flow SNAT collision traces remain across PAT/address-only refresh, persistent peer import, and temporary stop/rebind, while §9 still permits HA propagation of an E1 Close that deletes replacement E2. Therefore v9.9.14 is not ready for final sign-off.

Codex session ID: 019f990b-7ec8-7f01-872a-275842ade004
Resume in Codex: codex resume 019f990b-7ec8-7f01-872a-275842ade004
