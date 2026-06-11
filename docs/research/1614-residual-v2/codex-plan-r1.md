poll 4: running
poll 5: completed
**Findings**

1. **Minor: the close basis is valid, but the plan overstates the boolean starvation result.** Reading A governs the #1614 close because the SSOT defines starvation as all three predicates: `actual_i < G_i`, unguaranteed bandwidth exists, and `ΣG_k < C_phys` (`docs/fairness-regimes.md:1111-1119`). It also explicitly says simul-load per-class gates cannot assert sums above `C_phys` (`docs/fairness-regimes.md:1143-1151`) and limits the ≥95% absolute gate to solo/few-competitor contexts (`docs/fairness-regimes.md:1155-1169`). Reading B is real design intent, but it is not the ratified close gate. However, `6g` r3 is 4.1535 Gbps against `G_i = 4.20 Gbps` from `docs/research/1614-residual-v2/raw/small4p24g-r3-221627/sim_5204.json`, i.e. 98.9% of `G_i`, so `docs/research/1614-residual-v2/plan.md:186-190` should not say condition 1 simply “fails” across reps. Say “not materially below guarantee within the observed 69.2-71.1% band.”

2. **Minor: attribution to `2e6e0041f` alone is too narrow.** `2e6e0041f` contains the headline Hunk A/B/C mechanism, but #1743 continued with behavior-affecting commits: `fcbdf1f04` symmetric pass1 clamp, `b2fb8028b` never reset Phase-2 cursor on exhausted refill, and `14ac9b08e` gate honored-bit clearing. Current code has final semantics at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:832`, `:896`, and `:1221`. So “#1743 series healed it” is defensible; “commit `2e6e0041f` alone healed it” is not proven. A pre-#1743 redeploy A/B is optional for closing #1614, but required if the claim is single-commit causal attribution.

3. **Minor: the all-6 condition-3 language is too strong.** `docs/research/1614-residual-v2/plan.md:91-94` says `ΣG_k = 21.77 G ≥ achieved aggregate` means SSOT condition 3 “fails.” The SSOT says achieved aggregate is only a lower bound on `C_phys` (`docs/fairness-regimes.md:1121-1125`), so this only means condition 3 is not conservatively proven. It does not affect the decisive `small4+24g` close, but the wording should be softened.

**Checks**

Measurement is sound enough for disposition: decisive TCP has 3 reps (`docs/research/1614-residual-v2/plan.md:58-67`), controls include `small4-alone` 2 reps (`:73-79`) and all-6 2 reps (`:81-91`), and raw iperf numbers match the table. The excluded UDP rows are correctly excluded: 6g/24g UDP are generator-capped around 2.9 Gbps, exactly as stated at `docs/research/1614-residual-v2/plan.md:121-130`. The mixed 6g UDP probe delivered 2.759/2.754 Gbps with 0.00%/0.11% loss, supporting “below guarantee is lossless under pressure” (`:132-138`).

The follow-up is meaningfully different from PLAN-KILLED #1692 only if it keeps the active program promised at `docs/research/1614-residual-v2/plan.md:231-235`: competitor add/remove A/B, inelastic probes, and an unshaped-mix ceiling/PLAN-KILL exit. If it devolves into passive per-worker undergrant interpretation, it repeats the observability wall already acknowledged at `docs/research/1614-residual-v2/plan.md:209-213`.

PLAN-NEEDS-MINOR

Codex session ID: 019eb52a-f7ef-70a2-8b5a-b1f9287bf81a
Resume in Codex: codex resume 019eb52a-f7ef-70a2-8b5a-b1f9287bf81a
