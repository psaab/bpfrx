# #2354 QinQ research — reviewer ID ledger

Plan reviewed: `docs/research/2354-qinq/plan.md`
Plan v1 commit: `903f2d2bb` (branch `research/2354-qinq`, off `origin/master` `b3b8b6029`).

## Round 1 (plan v1)

| Reviewer | Handle | Verdict |
|----------|--------|---------|
| Codex | codex-rescue task `task-mr0z5z4h-xlhx7i` (session `019f19c5-75f3-7a03-8f6b-133f1300b6e7`) | **PLAN-DEFER** |
| AGY | `adversarial-review-mr0z4yi0-l3rsnp` | **PLAN-DEFER** |
| Claude SMR | `docs/research/2354-qinq/claude-smr-plan-r1.md` | PLAN-NEEDS-MINOR → **PLAN-DEFER** |

All three converged on PLAN-DEFER. The "PARTIALLY WRONG" sub-findings (Codex)
and the open questions (AGY) are tightenings for the eventual `/engineer`, not
blockers to the DEFER disposition. Plan v2 (`903f...` + revision) incorporates
every required tightening so a future `/engineer 2354` starts from an accurate,
hazard-pinned plan.

Round-1 findings folded into v2:
1. PR-A device creation before shim delivery = kernel slow-path policy-bypass
   window (all 3 reviewers; `ip_forward=1` at daemon_run.go:1817) → move stacked
   device to PR-B / non-forwarding posture.
2. Fork (b): pin lookup precedence exact-(outer,inner)-before-inner=0-wildcard
   (Codex + AGY) → live key is `FastMap<(i32,u16),i32>` types/forwarding.rs:102.
3. Fork (c): single-tag VLAN devices are netlink-created (ensureVLANSubInterface,
   compiler_iface.go:105, 802.1Q default), NOT networkd → extend the netlink
   mechanism with VlanProtocol=802.1ad + stacking, not a parallel networkd path
   (AGY open-question 3, verified).
4. S-tag egress TPID: PR-C must not use TxVlanTag::from (forces 0x8100) (Codex+SMR).
5. TX in-place rewrite assumes max 18 bytes; 22-byte frame would corrupt payload
   (AGY) → extend InPlaceL2Rewrite / rewrite_prepare_eth_from_parts + headroom.
6. Verifier: constant packet offsets, keep single-tag reserved=0 (Codex+SMR).
7. Inner-tag TPID acceptance ∈ {0x8100,0x88a8} or document narrowing (SMR).
