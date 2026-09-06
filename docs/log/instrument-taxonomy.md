# Wrong instrument vs wrong population

- **Timestamp**: 2026-09-05
  - **Action**: recorded in `docs/engineering-style.md` the distinction
    lane-8388 drew, because the two failures look identical in an instrument's
    output and are not fixable by the same move.

    lane-8526 enumerated four layers at which one class got mis-measured in a
    single day. All four are **wrong-instrument**: the right control at that
    layer finds each, and each did once someone added it.

    lane-8388 found a fifth and it is **wrong-population**. The #8939 collector
    admits a leaf only when `children == nil && wildcard == nil && !multi`,
    discarding 63% of containers before the census runs — a number I had
    published as disclosure two hours earlier. Their own login-class fix turned
    `permissions` from read to inert, and `permissions` is `multi`, so the
    census could not have measured it under ANY outcome. The row left the loser
    list, which reads as the fix working.

    They had the accidental explanation first — "the container was already a
    loser, so the row leaving looks like success" — and went looking for the
    structural one. My denominator supplied it. That is the difference between
    a disclosure and a diagnosis.

    > An aggregate ratchet cannot see a fix that breaks a neighbour inside the
    > same row. A ratchet cannot see anything its filter removed at all. The
    > first needs the dimensions kept separate; the second needs a SECOND
    > INSTRUMENT.

    No control at the other four layers can reach it, because a control
    interrogates what the filter passed. What found it was a second instrument
    — the spelling-differential gate — reporting per-spelling verdicts over a
    differently-filtered population.
  - **File(s)**: docs/engineering-style.md, docs/log/instrument-taxonomy.md
