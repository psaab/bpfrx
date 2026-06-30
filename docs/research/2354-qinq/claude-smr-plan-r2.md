# Claude SMR — plan review r2 — #2354 QinQ transit (convergence)

Reviewing plan v2 against my r1 findings + Codex r1 + AGY r1.

## r1 findings — all folded into v2

| Finding | Source | v2 resolution |
|---------|--------|---------------|
| Kernel slow-path policy-bypass window (device-before-XSK + ip_forward=1) | SMR/Codex/AGY (all 3) | §4a + inv 1b; device creation moved PR-A→PR-B |
| Zone-leak from plain `inner=0` wildcard | Codex + AGY | fork (b) tag-count-scoped lookup + inv 1a + PR-B precedence test |
| Device mechanism netlink-vs-networkd race | AGY q3 (verified) | fork (c) → extend `ensureVLANSubInterface` with `VlanProtocol=802.1ad`, no networkd path |
| S-tag TPID forced to 0x8100 by `TxVlanTag::from` | Codex + SMR | PR-C: build S-tag with `TPID_8021AD` from egress config, §4.6 |
| 18-byte in-place rewrite corrupts 22-byte frame | AGY | inv 2a + PR-C `InPlaceL2Rewrite` extension + headroom check |
| Verifier constant-offset + keep single-tag reserved=0 | Codex + SMR | PR-B spec + inv 5 |
| Inner-tag TPID ∈ {0x8100,0x88a8} narrowing | SMR | PR-B spec + open question 3 |

## Residual disagreements

None. The three reviewers agreed on the disposition (PLAN-DEFER) at r1; the
"PARTIALLY WRONG" sub-findings were tightenings, not disposition changes, and v2
incorporates every one. The single residual unknown (Codex) — verifier insn
budget — is inherently unprovable until `cmd/shimverify` runs in PR-B, and is
recorded as open question 2 + the HIGH verifier risk; it is an implementation
gate, not a plan defect.

## Disposition

The plan is now accurate, the hazards are pinned, and the forks are decided. This
remains a **low-demand additive FEATURE** with zero recorded operator demand and
an explicit author warning against speculative building, gated behind the
highest-risk #1864 verifier event. **Verdict r2: PLAN-DEFER** (`plan-deferred-research`)
— converge the design (done), STOP behind the manual `/engineer 2354` gate until
concrete stacked-VLAN demand exists. PLAN-KILL remains defensible if product
judges QinQ out of scope.

Convergent verdict: **PLAN-DEFER**, unanimous (Codex + AGY + Claude SMR).
