# Claude SMR accuracy self-review — #1649 floor-curve docs PR

Pure-documentation PR. No source changes; binary unaffected; no smoke.
This review is hostile to my own edits: every factual claim is traced to a
source of truth. The #1647 lesson (Copilot caught a wrong doc *correction*)
is the bar — a docs PR must not replace one inaccuracy with another.

Edited files:
- `docs/fairness-regimes.md` — new "Per-flow CoV floor (RSS multinomial)" section
- `CLAUDE.md` — one added bullet under "XDP on SR-IOV Interfaces"

## fairness-regimes.md claims

| Claim | Source of truth | Verdict |
|---|---|---|
| Loss cluster NIC exposes M=6 combined RX queues bound one-per-worker | #1649 research plan (commit `36fcd1b8`) §2.1 (`ethtool -l ge-0-0-2` → `Combined: 6`) + §3 (`select_userspace_queue()` queue-bound delivery, `userspace-xdp/src/lib.rs:371-635`) | GROUNDED |
| RX queue N → worker bound to queue N (`select_userspace_queue`) | research plan §3, cites `userspace-xdp/src/lib.rs:371-635` and `:1322` queue-bound delivery | GROUNDED — I cite the function name, not a line number, to avoid line drift |
| RSS hashes 5-tuple → one of 6 queues; N flows = multinomial draw | research plan §1, §7.0 ("N flows hashed into M RX queues do not distribute one-per-queue") | GROUNDED |
| E[CoV of `{aᵢ}`] table: N=2→1.55, N=6→0.87, N=12→0.62, N=18→0.50, N=24→0.44 | My own occupancy-count Monte-Carlo (400k trials, M=6, i.i.d. uniform), reproduced this session. N=6 value 0.875 matches research plan's stated "CoV ≈ 0.87 (RSS uniform)" exactly. **Copilot round-1 corrected** an earlier draft that listed N=2→0.00 and N=18/24 from a per-flow-share script instead of the occupancy-count model; the table now uses the correct occupancy CoV and is monotonically decreasing | GROUNDED (corrected) — occupancy-count values, cross-checked against research's 0.87 anchor |
| P(perfect 1-per-queue spread at N=6) = 6!/6⁶ ≈ 1.54% | research plan §7.0 / §11 ("P = 6!/6⁶ ≈ 1.54% perfect spread", AGY-verified); my Monte-Carlo gave 1.54% | GROUNDED — closed form + two independent computations agree |
| P(≥1 idle worker) column (98.5% at N=6, etc.) | My own Monte-Carlo this session. Sanity: at N=6 a perfect spread (no idle) is only 1.54%, so P(idle) ≈ 98.5% is consistent with that | GROUNDED |
| ~17% live throughput CoV is one favorable realization, distinct from the 0.87 occupancy CoV | research plan §1 ("~17% CoV at 6 flows ... 2 flows pinned slow ... 4 flows solo ... ≥1 worker idle"). The distinction occupancy-CoV vs throughput-CoV is my analysis: 0.87 is the multinomial *count* CoV, 17% is a measured *throughput* CoV. I explicitly warn against conflating them | GROUNDED + flagged as the one place I add interpretation; the two numbers measure different quantities, which is exactly why I separate them |
| mlx5 VF accepts exact-5-tuple ntuple (`Added rule with ID 1023`) + masked src-port-residue | research plan §2.3, §6 (verbatim ethtool output) | GROUNDED |
| Rule cap = 1024 = `MLX5E_ETHTOOL_FLOW_SPEC_NUM`, NOT 32k | research plan §2.4 ("Capacity = 1024 rules", AGY-verified driver constant; "#1203 assumed 32k — WRONG") | GROUNDED |
| ~1 ms-class firmware cost per rule | research plan §2.5 ("marginal HW-programming cost ≈ 1.1 ms/rule") | GROUNDED — I say "~1 ms-class", which the source supports |
| Static `f(5-tuple)→queue` = i.i.d. draws, balanced=RSS floor / imbalanced=worse | research plan §7.0 "General theorem (Codex r2)" | GROUNDED |
| masked-residue CoV ≈ 0.87 (ephemeral) / ≈1.05 (mod-8) | research plan §7.0 Monte-Carlo block (residue 6/7→RSS = 0.87; mod-8 = 1.05) | GROUNDED |
| Beats floor only with generator-coordinated `--cport` = harness artifact (Phase-0 3.8%) | research plan §7.0, §10 | GROUNDED |
| N≤M even placement needs negative dependence = reactive re-steer = forbidden | research plan §5, §7.0 "negative dependence", §8 | GROUNDED |
| #1203/#789 measured 49–55% CoV at P=12, closed with within-queue-scheduling verdict | research plan §4 (table + verbatim close comment); already in fairness-regimes.md existing #1203 reference | GROUNDED |
| Two external reviewers (Codex + AGY) reproduced Monte-Carlo + confirmed kill | issue #1649 close comment ("Codex + AGY + Claude SMR all PLAN-READY on the kill"); research plan §11 | GROUNDED |
| Aggregate throughput unaffected; floor not scheduler bug | research plan §1 ("Aggregate is fine (~17.2 G, the push ceiling); only per-flow distribution ... uneven"), §8 | GROUNDED |
| #1630 cause-1 = low-rate 100m/1g lazy-rotation credit loss; cause-2 = separate mid-rate ~6% residual on 3g/6g | PR #1650 body + its fairness-regimes.md hunk ("a mid-rate ~6 % residual on 3g/6g is a separate root cause (cause-2)"); issue #1630 | GROUNDED — I describe cause-2 only as PR #1650 already characterizes it (a separate mid-rate residual), I do NOT independently assert a "token-bucket fill" mechanism that is not yet merged/verified |
| Cross-refs #1333/#1304/#1649 + killed chain #1215/#837/#937/#840/#1238/#1243 | issue #1649 (label, body), research plan §9 ("Cross-link #1649, #1203/#789, #840, #937"), MEMORY per-5-tuple kill entries | GROUNDED |

### Coordination with PR #1650 (open, also edits fairness-regimes.md)

PR #1650 (`fix/1630-cause1-credit-carry`) inserts a "Small-class per-class
rate-metering floor (#1630 cause-1)" section near the CoS oversubscription
area (after the guarantee-rate gates, ~line 883). My new section is inserted
much earlier (right after "Structural CoV ceiling — worked examples",
~line 117), so the two hunks do not overlap textually. My #1630 paragraph
*references* PR #1650's section by name rather than duplicating its content.
If #1650 merges first, my PR rebases cleanly (disjoint hunks). If mine merges
first, #1650 rebases cleanly. Item 4 of the brief (note the cause-2 residual)
is satisfied without clobbering: I name cause-2 exactly as #1650 names it.

## CLAUDE.md claim

| Claim | Source of truth | Verdict |
|---|---|---|
| Loss-cluster dataplane ifaces `ge-0-0-1`/`ge-0-0-2` are mlx5_core SR-IOV VFs | research plan §2 (`ethtool -i ge-0-0-2` → `driver: mlx5_core`); existing CLAUDE.md "Network Topology" loss-cluster block already says "mlx5 SR-IOV VF ... mlx5_core xdp native" | GROUNDED — consistent with the doc's own topology section |
| mlx5 VFs support native XDP + exact/masked ntuple steering | research plan §2.3/§2.6/§7.1 ("VF flow-steering is NOT degraded vs PF here"; "mlx5_core xdp native") | GROUNDED |
| 6 combined RX queues → 6 workers | research plan §2.1 | GROUNDED |
| i40e PF-passthrough note is the standalone VM, not this cluster | research plan §7.1 ("top-level CLAUDE.md 'i40e PF passthrough' describes the standalone VM"); the edited line 230 references `enp10s0f0np0` which is the standalone PCI map (CLAUDE.md "Standalone VM" block) | GROUNDED — I ADD a note, I do NOT rewrite the standalone i40e text |

### Hostile check on the iavf bullet

The pre-existing CLAUDE.md bullet says "iavf (VF driver) has NO native XDP
support ... VFs use the iavf driver which forces generic mode." My added
bullet says mlx5 VFs DO support native XDP. Is that a contradiction I
introduced?

No. The iavf claim is specifically about **Intel** VFs (iavf = Intel
Adaptive VF driver). mlx5 is a different vendor's VF driver and does support
native XDP on this hardware (research plan §2.6/§7.1 verified native XDP on
the actual mlx5 VF). My bullet is scoped to "mlx5_core SR-IOV VFs" and does
not generalize. The two bullets are about different drivers and are both
correct. I did not weaken or contradict the iavf bullet.

## Residual uncertainties (disclosed)

1. The E[CoV of `{aᵢ}`] and P(idle) table rows for N ∈ {2,12,18,24} are my
   occupancy-count Monte-Carlo, not lifted from the research doc (which
   published only the N=6 anchor 0.87 and the 1.54% perfect-spread figure).
   The N=6 row matches the published anchor to 3 significant figures, which
   validates the model; the other rows follow from the same simulation. They
   are rounded to 2 dp and labeled "Monte-Carlo" in the text, not presented as
   measured live data. The N=2/18/24 rows were corrected after Copilot
   round-1 (N=2 from 0.00 to 1.55, closed form E[CoV] = (5/6)√2 + (1/6)√5 ≈
   1.55) — see the round-1 section below.
2. The "~17% throughput CoV" is a single live observation from the research
   §1, not a distribution. I present it as one realization, not a curve
   point, precisely to avoid implying it is the expected per-flow CoV (which
   would be higher).

## Copilot round-1 findings and resolutions

Copilot returned 5 comments on the first push (SHA `782c5aa3f151`); all 5
addressed:

1. **N=2 occupancy CoV = 0.00 is wrong (fairness-regimes.md table).** Correct.
   The first draft used the per-flow-*share* CoV (0 when 2 flows sit on 2
   distinct workers) in a table labeled *occupancy-count* CoV. With N=2 over
   M=6 the count vector is mostly zeros → E[CoV] = (5/6)√2 + (1/6)√5 ≈ 1.55
   (matches Monte-Carlo 400k). FIXED: re-ran the occupancy-count Monte-Carlo
   for all rows — N=2→1.55, N=18→0.50, N=24→0.44 (the latter two were also off
   in the draft, from the same wrong script). The curve is now correctly
   monotonically decreasing and the prose explains why small N is high
   (`N < M` forces `M − N` idle queues).
2. **Throughput-CoV "lower for every realization" overstates it.** Correct —
   a perfect 1-per-queue placement has occupancy CoV 0 but can show nonzero
   throughput variance. FIXED: narrowed to the observed skewed `N=6` case;
   added the explicit caveat that the correspondence does not hold universally.
3/4/5. **`docs/research/1649-initial-placement/plan.md` is not on master**
   (it lives on branch `research/1649-initial-placement`), so the citation
   would be a dead in-tree path after merge. Correct merge-quality defect.
   FIXED: replaced the in-tree path with a stable reference — "issue #1649,
   research plan at commit `36fcd1b8`" — in fairness-regimes.md, CLAUDE.md, and
   this doc. (The branch + commit are the durable provenance; readers fetch the
   plan via `git show 36fcd1b8:docs/research/1649-initial-placement/plan.md` or
   the issue.)

These corrections are exactly the #1647 failure mode the brief warned about
(a wrong doc *correction*); Copilot caught the occupancy/share metric mix-up
before merge.

## Copilot round-2 findings and resolutions

Copilot returned 3 comments on the round-1 fix (SHA `cda06b31b`); all 3
addressed:

1. **"most common N=6 realization is 4 solo + 1 pair" is wrong.** Correct.
   Partition probabilities for N=6 into M=6 (Monte-Carlo 500k): two-pairs
   `[2,2,1,1,0,0]` ≈ 35% is most common; "4 solo + 1 pair" `[2,1,1,1,1,0]`
   ≈ 23% is second. FIXED: reworded to "common realizations are mild — e.g.
   two-pairs (≈35%) or 4-solo+1-pair (≈23%)" instead of claiming the latter is
   most common.
2. **"Aggregate throughput is unaffected" overstates it.** Correct — the
   doc's own Gate 3 scales the cap by `Nₐ/Nᵥ`, so idle-worker RSS draws reduce
   saturated aggregate. FIXED: restated as "primarily a per-flow distribution
   effect," explicitly noting idle-worker draws can lower saturated aggregate
   and that Gate 3's scaled cap already accounts for it; the `-P 6` near-ceiling
   observation is called out as a property of that draw, not a guarantee.
3. **Dangling in-file cross-reference to the #1650 section.** Correct — the
   "Small-class per-class rate-metering floor" section only exists after PR
   #1650 merges, so if this PR lands first the reference dangles. FIXED:
   qualified it as a future/open-PR reference ("added by the #1630 cause-1 PR
   #1650; until it lands, see issue #1630") instead of an in-file section link.

## Verdict

ACCURACY-CLEAN (post round-2). Every claim traces to the #1649 research plan (commit `36fcd1b8`),
PR #1650 / issue #1630 for the cause-1/cause-2 split, issue #1649 for the
3-reviewer kill, or my own reproduced Monte-Carlo (anchored to the research's
published 0.87 / 1.54% values). The CLAUDE.md edit ADDS a scoped note and does
not rewrite the standalone-VM i40e text, satisfying the brief's "verify before
correcting" requirement. No contradiction introduced with the existing iavf
bullet (different driver).
