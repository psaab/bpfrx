PLAN NO

Reviewed `plan.md` v10.4.0 at `0b3b6d0ab7aad02efe744815f714bdd94e9bf364`, read-only. No files were edited.

## Round-86 dispositions

- **r86-1 — NOT RESOLVED.** For a proven forward-wire hit, the fold correctly prevents P1 leaking into the seed/aliases: the final `pending_decision` feeds installation, publication, and buffering at [poll_descriptor/mod.rs:4785](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4785), and deterministic reacquisition remains allocator-owned. However, the clean decision does not govern every downstream consumer, and “clean pre-SNAT” can erase legitimate pre-routing DNAT—new findings 1 and 2.

- **r86-2 — MOOT-BY-RETREAT.** No confirmation flip or flip-time `session_limit_inc` ships.

- **r86-3 — MOOT-BY-RETREAT.** No flip-time shared-state publication ships.

- **r86-4 — MOOT-BY-RETREAT.** No `session_id`-guarded seed cleanup ships.

- **r86-5 — RESOLVED.** The gate at [plan.md:980](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:980) requires full key/NAT reciprocity and applies `target.is_reverse` only when the matched entry is forward. Reverse hits correctly target the non-reverse forward entry. [`NatDecision::reverse`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:105) and [`reverse_session_key`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:173) round-trip SNAT, composed hairpin, NPTv6, and NAT64 families. A mismatch skips only the companion; the matched entry remains marked.

- **r86-6 — MOOT-BY-RETREAT.** No flipped seed or flip-time Open exists. Stub metadata remains documented master behavior.

- **r86-7 — NOT RESOLVED.** Section 5.2 says `account_packet` is unchanged and the anchor uses a distinct post-admission hook at [plan.md:604](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:604), but §5.8 still says it “gains the seg-view apply” at [plan.md:1171](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1171), and §7 locates the stores inside its probe at [plan.md:1344](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1344). The slow accounting call occurs at [poll_descriptor/mod.rs:3497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3497), before request construction/output filtering at [poll_descriptor/mod.rs:3752](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3752). A literal §5.8 implementation lets a discarded packet move the anchor and alter a later close verdict.

The second retreat is accepted. Seed installation remains uncounted/Open-less, while seed expiry remains Close-less at [install.rs:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:225) and [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342). Thus no HA peer copy exists to orphan. The gaps are master parity, and the cascade history supports leaving their completion to §10.6.2. I do not hold that seed-class completion must ship here.

## New findings

1. **BLOCKER — the clean P2 decision does not govern trailing slow-path reinjection.**

   Purge releases P1 at [promote.rs:194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:194), while the resolver returns the stored P1 decision at [session_glue/mod.rs:1194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1194). Current structure clones it into `pending_decision` at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662), derives P2 there, and buffers P2 at `:5063`. But the common epilogue still passes the separate outer decision to reinjection at [poll_descriptor/mod.rs:5126](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5126). `MissingNeighbor` is eligible, and reinjection applies the supplied NAT before enqueueing at [slow_path.rs:199](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:199).

   Concrete trace: the received forward-wire frame already carries P1; purge frees P1, another flow claims it, and the clean transaction owns/installs P2. The common slow path emits P1 while pending replay later emits P2—an unowned-tuple collision and translated-source change. Merely clearing outer NAT is insufficient because default NAT leaves the already-P1 frame unchanged. The plan must make successful reinjection consume the final owned decision or suppress it; refusal/rollback must remain terminal.

2. **BLOCKER — blanket NAT clearing can erase legitimate DNAT because the transient classifier is address-only.**

   [`is_translated_forward_session_key`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:32) accepts `rewrite_src == key.src_ip || rewrite_dst == key.dst_ip`; it ignores ports and does not prove that the key is the full forward-wire tuple. DNAT supports same-address port remapping at [destination.rs:699](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/destination.rs:699).

   Concrete trace: canonical peer key K carries ordinary SNAT plus DNAT `K.dst:443 → same-IP:8443`. Address equality falsely classifies canonical K as translated even though its wire key differs by SNAT and destination port. After purge, discarding the old NAT loses `rewrite_dst_port=8443`. True-miss DNAT derivation exists only at [poll_descriptor/mod.rs:1014](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1014); the later MissingNeighbor block derives only outbound NPT/SNAT. Policy, seed, aliases, and replay can therefore use port 443 instead of the admitted 8443 tuple. The classifier is pre-existing, but blanket clearing turns it into a new fold regression. Require exact full-wire identity or restart/recompute the complete current pre-routing NAT, routing, zone, and policy pipeline.

3. **LOW — translated-family positive propagation coverage is missing.**

   Existing reverse- and forward-direction tests use default NAT, while §9 adds unrelated-B and mismatch cases at [plan.md:1567](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1567). A mistaken raw-NAT equality check would pass no-NAT tests but skip a valid translated companion. On a reverse hit, the reverse entry then reaps silently while the forward producer/NAT state remains until ordinary timeout. Add positive SNAT, composed SNAT+DNAT hairpin, NPTv6, and NAT64 reverse-hit cases.

Editorially, §7 still references nonexistent races `(e)`–`(g)`, and its seed carve-out omits the reverse-synth mark-on-forward-seed case correctly recorded in §10.6.2. These are not separate runtime findings.

## Section 11 answers

1. **Terminal cut:** Yes—released-P1 reinjection and DNAT erasure remain; neither requires the removed protocol.

2. **Two retreats:** Both stand; seed-lifecycle completion need not ship in this plan.

3. **Round-86 folds:** (a) clean baseline: no; (b) reciprocity: yes; (c) `account_packet` wording: no.

4. **Emission posture:** No new runtime zero/duplicate producer was found outside the intended transient-seed carve-out.

5. **Attack arithmetic:** Confirmed: `2^32 / 393,219 ≈ 10,922.58`; `2^32 / 655,355 ≈ 6,553.65`.

6. **Re-scope:** No distributed or seed-lifecycle machinery must return; the local RWoLB decision/pre-routing fixes, hook wording, and translated-family tests must ship.

The retreat and direction-aware propagation design are sound, but v10.4.0 is not yet safe to implement: the clean-NAT fold can split one transaction between released P1 and owned P2, and can erase a legitimate destination-port translation before policy and seeding. Those are concrete translated-source, policy, and availability traces in the shipped local scope.
tokens used
397,297
PLAN NO

Reviewed `plan.md` v10.4.0 at `0b3b6d0ab7aad02efe744815f714bdd94e9bf364`, read-only. No files were edited.

## Round-86 dispositions

- **r86-1 — NOT RESOLVED.** For a proven forward-wire hit, the fold correctly prevents P1 leaking into the seed/aliases: the final `pending_decision` feeds installation, publication, and buffering at [poll_descriptor/mod.rs:4785](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4785), and deterministic reacquisition remains allocator-owned. However, the clean decision does not govern every downstream consumer, and “clean pre-SNAT” can erase legitimate pre-routing DNAT—new findings 1 and 2.

- **r86-2 — MOOT-BY-RETREAT.** No confirmation flip or flip-time `session_limit_inc` ships.

- **r86-3 — MOOT-BY-RETREAT.** No flip-time shared-state publication ships.

- **r86-4 — MOOT-BY-RETREAT.** No `session_id`-guarded seed cleanup ships.

- **r86-5 — RESOLVED.** The gate at [plan.md:980](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:980) requires full key/NAT reciprocity and applies `target.is_reverse` only when the matched entry is forward. Reverse hits correctly target the non-reverse forward entry. [`NatDecision::reverse`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:105) and [`reverse_session_key`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:173) round-trip SNAT, composed hairpin, NPTv6, and NAT64 families. A mismatch skips only the companion; the matched entry remains marked.

- **r86-6 — MOOT-BY-RETREAT.** No flipped seed or flip-time Open exists. Stub metadata remains documented master behavior.

- **r86-7 — NOT RESOLVED.** Section 5.2 says `account_packet` is unchanged and the anchor uses a distinct post-admission hook at [plan.md:604](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:604), but §5.8 still says it “gains the seg-view apply” at [plan.md:1171](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1171), and §7 locates the stores inside its probe at [plan.md:1344](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1344). The slow accounting call occurs at [poll_descriptor/mod.rs:3497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3497), before request construction/output filtering at [poll_descriptor/mod.rs:3752](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3752). A literal §5.8 implementation lets a discarded packet move the anchor and alter a later close verdict.

The second retreat is accepted. Seed installation remains uncounted/Open-less, while seed expiry remains Close-less at [install.rs:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:225) and [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342). Thus no HA peer copy exists to orphan. The gaps are master parity, and the cascade history supports leaving their completion to §10.6.2. I do not hold that seed-class completion must ship here.

## New findings

1. **BLOCKER — the clean P2 decision does not govern trailing slow-path reinjection.**

   Purge releases P1 at [promote.rs:194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:194), while the resolver returns the stored P1 decision at [session_glue/mod.rs:1194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1194). Current structure clones it into `pending_decision` at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662), derives P2 there, and buffers P2 at `:5063`. But the common epilogue still passes the separate outer decision to reinjection at [poll_descriptor/mod.rs:5126](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5126). `MissingNeighbor` is eligible, and reinjection applies the supplied NAT before enqueueing at [slow_path.rs:199](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:199).

   Concrete trace: the received forward-wire frame already carries P1; purge frees P1, another flow claims it, and the clean transaction owns/installs P2. The common slow path emits P1 while pending replay later emits P2—an unowned-tuple collision and translated-source change. Merely clearing outer NAT is insufficient because default NAT leaves the already-P1 frame unchanged. The plan must make successful reinjection consume the final owned decision or suppress it; refusal/rollback must remain terminal.

2. **BLOCKER — blanket NAT clearing can erase legitimate DNAT because the transient classifier is address-only.**

   [`is_translated_forward_session_key`](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:32) accepts `rewrite_src == key.src_ip || rewrite_dst == key.dst_ip`; it ignores ports and does not prove that the key is the full forward-wire tuple. DNAT supports same-address port remapping at [destination.rs:699](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/destination.rs:699).

   Concrete trace: canonical peer key K carries ordinary SNAT plus DNAT `K.dst:443 → same-IP:8443`. Address equality falsely classifies canonical K as translated even though its wire key differs by SNAT and destination port. After purge, discarding the old NAT loses `rewrite_dst_port=8443`. True-miss DNAT derivation exists only at [poll_descriptor/mod.rs:1014](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1014); the later MissingNeighbor block derives only outbound NPT/SNAT. Policy, seed, aliases, and replay can therefore use port 443 instead of the admitted 8443 tuple. The classifier is pre-existing, but blanket clearing turns it into a new fold regression. Require exact full-wire identity or restart/recompute the complete current pre-routing NAT, routing, zone, and policy pipeline.

3. **LOW — translated-family positive propagation coverage is missing.**

   Existing reverse- and forward-direction tests use default NAT, while §9 adds unrelated-B and mismatch cases at [plan.md:1567](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1567). A mistaken raw-NAT equality check would pass no-NAT tests but skip a valid translated companion. On a reverse hit, the reverse entry then reaps silently while the forward producer/NAT state remains until ordinary timeout. Add positive SNAT, composed SNAT+DNAT hairpin, NPTv6, and NAT64 reverse-hit cases.

Editorially, §7 still references nonexistent races `(e)`–`(g)`, and its seed carve-out omits the reverse-synth mark-on-forward-seed case correctly recorded in §10.6.2. These are not separate runtime findings.

## Section 11 answers

1. **Terminal cut:** Yes—released-P1 reinjection and DNAT erasure remain; neither requires the removed protocol.

2. **Two retreats:** Both stand; seed-lifecycle completion need not ship in this plan.

3. **Round-86 folds:** (a) clean baseline: no; (b) reciprocity: yes; (c) `account_packet` wording: no.

4. **Emission posture:** No new runtime zero/duplicate producer was found outside the intended transient-seed carve-out.

5. **Attack arithmetic:** Confirmed: `2^32 / 393,219 ≈ 10,922.58`; `2^32 / 655,355 ≈ 6,553.65`.

6. **Re-scope:** No distributed or seed-lifecycle machinery must return; the local RWoLB decision/pre-routing fixes, hook wording, and translated-family tests must ship.

The retreat and direction-aware propagation design are sound, but v10.4.0 is not yet safe to implement: the clean-NAT fold can split one transaction between released P1 and owned P2, and can erase a legitimate destination-port translation before policy and seeding. Those are concrete translated-source, policy, and availability traces in the shipped local scope.
