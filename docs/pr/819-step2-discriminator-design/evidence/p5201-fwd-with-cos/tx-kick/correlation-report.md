# step3 tx-kick correlation report — `p5201-fwd-with-cos`

Threshold-T1 verdict on per-block kick retry count and mean kick latency (sendto → return) against top-quartile T_D1 blocks. See #819 §3.2 / §5.3 and #827 plan §4.4 for thresholds.

## Verdict

- **INCONCLUSIVE** — max_retry_in_elevated=0, max_kick_mean_in_elevated=4417 ns — neither IN nor OUT thresholds met

## Summary

- rho(T_D1, retry_count_delta): n/a (p=n/a)
- rho(T_D1, kick_latency_mean_ns): -0.7343 (p=0.006543)
- elevated threshold (T_D1 3rd-largest): 0.9992
- elevated blocks: [1, 10, 11] (size 3)
- max retry_count_delta in elevated: 0
- max kick_latency_mean_ns in elevated: 4417.2
- blocks with no kick activity: 0

## Per-block table

| b | T_D1 | elev | retry_Δ | count_Δ | sum_ns_Δ | mean_ns | in | out |
|---|----:|:-:|----:|----:|----:|----:|:-:|:-:|
| 0 | 0.9843 |  | 0 | 25003 | 134067205 | 5362 |  |  |
| 1 | 0.9992 | * | 0 | 288261 | 1273318371 | 4417 |  |  |
| 2 | 0.9988 |  | 0 | 288989 | 1198506460 | 4147 |  |  |
| 3 | 0.9991 |  | 0 | 288412 | 1267272880 | 4394 |  |  |
| 4 | 0.9990 |  | 0 | 287812 | 1272423479 | 4421 |  |  |
| 5 | 0.9989 |  | 0 | 288288 | 1344366146 | 4663 |  |  |
| 6 | 0.9970 |  | 0 | 285097 | 1360123902 | 4771 |  |  |
| 7 | 0.9975 |  | 0 | 299556 | 1366671807 | 4562 |  |  |
| 8 | 0.9976 |  | 0 | 288099 | 1317077947 | 4572 |  |  |
| 9 | 0.9991 |  | 0 | 291251 | 1261681191 | 4332 |  |  |
| 10 | 0.9993 | * | 0 | 300079 | 1270100096 | 4233 |  |  |
| 11 | 0.9994 | * | 0 | 296452 | 1268003940 | 4277 |  |  |

## Scatter (TSV)

```tsv
b	T_D1	retry_count_delta	kick_latency_mean_ns	elevated
0	0.984319	0	5362.045	0
1	0.999224	0	4417.241	1
2	0.998783	0	4147.239	0
3	0.999067	0	4393.967	0
4	0.999028	0	4421.023	0
5	0.998936	0	4663.275	0
6	0.997038	0	4770.741	0
7	0.997501	0	4562.325	0
8	0.997636	0	4571.616	0
9	0.999085	0	4331.938	0
10	0.999292	0	4232.552	1
11	0.999384	0	4277.266	1
```
