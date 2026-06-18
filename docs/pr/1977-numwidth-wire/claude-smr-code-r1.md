# Claude SMR — #1977 code review (PR #1978)

**Verdict: MERGE-READY** (4th reviewer; verified the diff against the converged plan).

## Verified directly

- **All 11 fields coerced** at the build boundary (flow.go): 4 MSS
  (IPsecVPN/GreIn/GreOut in the struct literal + AllTCP via the defensive line)
  → `coerceWireU16`; 3 session timeouts (TCP/UDP/ICMP) → `coerceWireSessionTimeout`;
  CollectorPort → skip-and-continue; SamplingRate → `<=0→1` + cap u32max;
  Active/InactiveTimeout → `coerceWireU32Timeout`. None passed through raw.
- **Overflow-safe session cap**: caps at `config.MaxDurationSeconds`
  (=`MaxInt64/1e9`≈9.22e9); `int(MaxDurationSeconds)` is exact on amd64 (int=int64),
  and `9.22e9 × 1e9 ≈ 9.22e18 < u64::MAX` — so Rust `from_seconds`'s unchecked
  `secs*1e9` cannot overflow (Codex r2 confirmed the arithmetic).
- **CollectorPort**: `port==0` keeps the benign "absent" skip (no warn);
  `port<0 || >65535` warns + skips THAT server and continues scanning the
  remaining flow-servers — does not abort the whole export. Correct.
- **SamplingRate**: keeps the existing `<=0→1` normalization, adds the
  `>u32max` cap. `int64(rate) > math.MaxUint32` is the right comparison on a
  64-bit int.
- **Sole chokepoint**: `buildFlowSnapshot`/`buildFlowExportSnapshot` are called
  only from `buildSnapshot` (verified at plan time) → covers all input paths.
- **Logging**: `slog.Warn` fires only inside the builders (per config commit),
  never per-packet/poll — complies with the project logging rules.
- **Tests**: drive the REAL builders with out-of-range configs and assert
  in-range for all 11 + in-range passthrough unchanged + out-of-range port
  skips + helper tables (incl. TCPMSSAllTCP); Rust decodes a full ControlRequest
  with max-range numbers and rejects a negative (the defended mechanism).
- **In-range behavior**: unchanged (passthrough assertions).

## Notes

- Full Go suite green; full Rust suite has 1 pre-existing flake
  (`concurrent_recovery_processes_each_command_exactly_once`, worker_queue —
  untouched by this PR; passed 3/3+5/5 during #1976) — re-rerun to confirm
  not a regression.
- Layer B (commit-time `ValidateInteger`) correctly deferred to a follow-up;
  Layer A alone closes the safety hole on all paths.
