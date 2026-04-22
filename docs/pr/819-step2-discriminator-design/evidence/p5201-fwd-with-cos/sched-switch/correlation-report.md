# step2 sched_switch correlation report — `p5201-fwd-with-cos`

Spearman rank correlation between step1 shape[3..=6] (the D1 4-64 us mass fraction) and step2 off-CPU time in the same bucket range, across 12 snapshot blocks.

## Verdict

- **OUT** — duty_cycle_pct=0.000 < 1.0

## Summary

- Spearman rho: **0.2963**  (p-value: 0.3497)
- duty-cycle: **0.000 %**  of 60 s nominal
- voluntary (S/D/I/T/t/X/Z/P) total: 118305 ns
- involuntary (R/R+) total:           60525 ns
- stat_runtime_check WARN blocks: [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] (11 of 12)

## Per-block table

| b | T_D1 (shape[3..=6]) | off_cpu_time_3to6 (ns) | vol | invol | stat |
|---|----:|----:|----:|----:|:---:|
| 0 | 0.9839 | 0 | 0 | 0 | WARN |
| 1 | 0.9993 | 0 | 0 | 0 | PASS |
| 2 | 0.9996 | 0 | 0 | 0 | WARN |
| 3 | 0.9994 | 0 | 0 | 0 | WARN |
| 4 | 0.9991 | 0 | 0 | 0 | WARN |
| 5 | 0.9993 | 0 | 0 | 0 | WARN |
| 6 | 0.9993 | 97723 | 37198 | 60525 | WARN |
| 7 | 0.9995 | 19125 | 19125 | 0 | WARN |
| 8 | 0.9996 | 16864 | 16864 | 0 | WARN |
| 9 | 0.9988 | 15119 | 15119 | 0 | WARN |
| 10 | 0.9997 | 29999 | 29999 | 0 | WARN |
| 11 | 0.9996 | 0 | 0 | 0 | WARN |

## Scatter (TSV)

```tsv
b	T_D1	off_cpu_time_3to6
0	0.983918	0
1	0.999319	0
2	0.999606	0
3	0.999410	0
4	0.999126	0
5	0.999317	0
6	0.999324	97723
7	0.999524	19125
8	0.999553	16864
9	0.998811	15119
10	0.999708	29999
11	0.999603	0
```
