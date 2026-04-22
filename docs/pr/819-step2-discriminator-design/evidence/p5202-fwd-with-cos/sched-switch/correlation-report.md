# step2 sched_switch correlation report — `p5202-fwd-with-cos`

Spearman rank correlation between step1 shape[3..=6] (the D1 4-64 us mass fraction) and step2 off-CPU time in the same bucket range, across 12 snapshot blocks.

## Verdict

- **OUT** — duty_cycle_pct=0.000 < 1.0

## Summary

- Spearman rho: **n/a**  (p-value: n/a)
- duty-cycle: **0.000 %**  of 60 s nominal
- voluntary (S/D/I/T/t/X/Z/P) total: 0 ns
- involuntary (R/R+) total:           0 ns
- stat_runtime_check WARN blocks: [11] (1 of 12)

## Per-block table

| b | T_D1 (shape[3..=6]) | off_cpu_time_3to6 (ns) | vol | invol | stat |
|---|----:|----:|----:|----:|:---:|
| 0 | 0.7280 | 0 | 0 | 0 | PASS |
| 1 | 0.9068 | 0 | 0 | 0 | PASS |
| 2 | 0.9179 | 0 | 0 | 0 | PASS |
| 3 | 0.9251 | 0 | 0 | 0 | PASS |
| 4 | 0.9221 | 0 | 0 | 0 | PASS |
| 5 | 0.9216 | 0 | 0 | 0 | PASS |
| 6 | 0.9252 | 0 | 0 | 0 | PASS |
| 7 | 0.9240 | 0 | 0 | 0 | PASS |
| 8 | 0.9239 | 0 | 0 | 0 | PASS |
| 9 | 0.9191 | 0 | 0 | 0 | PASS |
| 10 | 0.9205 | 0 | 0 | 0 | PASS |
| 11 | 0.9196 | 0 | 0 | 0 | WARN |

## Scatter (TSV)

```tsv
b	T_D1	off_cpu_time_3to6
0	0.727955	0
1	0.906838	0
2	0.917911	0
3	0.925146	0
4	0.922055	0
5	0.921628	0
6	0.925233	0
7	0.923984	0
8	0.923867	0
9	0.919063	0
10	0.920466	0
11	0.919608	0
```
