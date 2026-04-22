# step3 tx-kick correlation report — `p5202-fwd-with-cos`

Threshold-T1 verdict on per-block kick retry count and mean kick latency (sendto → return) against top-quartile T_D1 blocks. See #819 §3.2 / §5.3 and #827 plan §4.4 for thresholds.

## Verdict

- **INCONCLUSIVE** — max_retry_in_elevated=0, max_kick_mean_in_elevated=6481 ns — neither IN nor OUT thresholds met

## Summary

- rho(T_D1, retry_count_delta): n/a (p=n/a)
- rho(T_D1, kick_latency_mean_ns): -0.9231 (p=1.862e-05)
- elevated threshold (T_D1 3rd-largest): 0.9254
- elevated blocks: [4, 8, 9] (size 3)
- max retry_count_delta in elevated: 0
- max kick_latency_mean_ns in elevated: 6480.5
- blocks with no kick activity: 0

## Per-block table

| b | T_D1 | elev | retry_Δ | count_Δ | sum_ns_Δ | mean_ns | in | out |
|---|----:|:-:|----:|----:|----:|----:|:-:|:-:|
| 0 | 0.7230 |  | 0 | 14200 | 154697976 | 10894 |  |  |
| 1 | 0.9145 |  | 0 | 381764 | 2680945505 | 7023 |  |  |
| 2 | 0.9251 |  | 0 | 438873 | 2833221090 | 6456 |  |  |
| 3 | 0.9232 |  | 0 | 447296 | 2892134088 | 6466 |  |  |
| 4 | 0.9254 | * | 0 | 439716 | 2849586559 | 6481 |  |  |
| 5 | 0.9206 |  | 0 | 432305 | 2826547843 | 6538 |  |  |
| 6 | 0.9191 |  | 0 | 398231 | 2742268198 | 6886 |  |  |
| 7 | 0.9247 |  | 0 | 444812 | 2826215752 | 6354 |  |  |
| 8 | 0.9260 | * | 0 | 455317 | 2834885444 | 6226 |  |  |
| 9 | 0.9271 | * | 0 | 446667 | 2812019839 | 6296 |  |  |
| 10 | 0.9217 |  | 0 | 432479 | 2836553778 | 6559 |  |  |
| 11 | 0.9212 |  | 0 | 431194 | 2847408955 | 6604 |  |  |

## Scatter (TSV)

```tsv
b	T_D1	retry_count_delta	kick_latency_mean_ns	elevated
0	0.722991	0	10894.224	0
1	0.914530	0	7022.520	0
2	0.925112	0	6455.674	0
3	0.923221	0	6465.817	0
4	0.925372	0	6480.516	1
5	0.920568	0	6538.319	0
6	0.919081	0	6886.124	0
7	0.924713	0	6353.731	0
8	0.925974	0	6226.180	1
9	0.927150	0	6295.562	1
10	0.921708	0	6558.824	0
11	0.921231	0	6603.545	0
```
