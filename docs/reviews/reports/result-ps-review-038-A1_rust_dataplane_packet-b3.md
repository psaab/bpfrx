# Triage result — ps-review-038 A1_rust_dataplane_packet batch 3/3 (b3)

- **Subsystem**: A1_rust_dataplane_packet (userspace-dp Rust dataplane — batch 3/3: fairness_eval harness, hot_hash_seed, io_uring_write, prefix/prefix_set, server handlers/helpers/lifecycle, slowpath, state_writer, tcp_flags, ip_proto, xsk_ffi)
- **Base**: header base d4506d4450e23f9a3fc572206b3c82f6b6c99029; verified against **current origin/master 57d24d9aed4b64680831a1765a128921e79c00f7** (base == master lineage; all three cited files read on current master, code unchanged from what the review quotes)
- **Repo**: real bpfrx (not avacado) — all cited symbols present, real file paths, real invariants (#1630/#1614 fairness gate, #2515/#2794, #2962/#4054, #3766/#3789, #2523/#2744, #2970/#2974, #2957/#3009).
- **Outcome counts**: 3 findings → **0 HIGH/MED**, **2 GENUINE-RESIDUAL (LOW, CI-harness robustness)**, **1 NOT-MATERIAL (defense-in-depth, unreachable on 64-bit)**. 0 CONFABULATED, 0 DUP, 0 ALREADY-FIXED.

This is an unusually honest batch: the reviewer self-rated every finding **Low** and marked the bulk of the 40 files as explicit NEGATIVE results with correct invariant reasoning. Nothing touches the packet-forwarding hot path, zone/global policy, host-inbound, NAT, VRRP/HA, or default-deny. The two genuine residuals are robustness gaps in the **offline `fairness-eval` CI harness binary** (not the dataplane); the third is an unreachable defense-in-depth cast.

---

## Finding 1 — fairness_eval CLI numeric args silently fall back to defaults — GENUINE-RESIDUAL (LOW)

- **Symbol EXISTS**: `userspace-dp/src/fairness_eval/args.rs:63-75` on current master matches the review verbatim. `--warmup-secs`/`--final-burst-secs`/`--n-workers`/`--shaper-rate-bps` all use `args.next().and_then(|s| s.parse().ok()).unwrap_or(<default>)`. Contrast: `--cos-ifindex`/`--cos-queue-id` route through `parse_required_numeric_arg` (args.rs:140) which `exit(2)`s on parse failure. The helper exists but is not applied to these four flags — so the fix direction is trivially available and NOT already applied.
- **Reachability / actual path**: An operator/automation invocation with an overflowing or mistyped value (`--n-workers 99999999999`, `--shaper-rate-bps 25G`) → `parse::<T>()` returns `Err` → `.ok()` = `None` → `unwrap_or(default)`. No warning. The value silently reverts to the default.
- **Partial upstream guard (weakens, does not close)**: args.rs:113-124 already adds `if expect_saturation && shaper_rate_bps == 0 { exit(2) }` and `if expect_saturation && n_workers == 0 { exit(2) }` (the Copilot #2 fix). This closes the single most damaging sub-case the review cites (`shaper=0` under saturation → false Gate-3 result). It does **not** cover: (a) a `--shaper-rate-bps 25G` typo silently → 0 when the operator *intended* a cap but did not pass `--expect-saturation`; (b) `--n-workers 0` explicit without `--expect-saturation` → `aggregate_per_worker` over `0..0` → empty distribution → `max_worker_flow_share`=0 → verdict PASS on empty data; (c) `--warmup-secs`/`--final-burst-secs` have no guard at all.
- **Severity reasoning — LOW (agree with reviewer)**:
  - *Blast radius*: bounded to the **offline `fairness-eval` analysis binary** — reads iperf JSON + Prometheus TSV, emits PASS/FAIL. Never on the dataplane, never network-reachable, never run in production. "Reachable" = a local operator/CI mistyping a flag they are actively watching.
  - *Exploitability*: none (no attacker surface). The failure requires a self-inflicted CLI typo.
  - *Bounding factors that keep it LOW*: the `--n-workers` default (6) is the correct loss-cluster denominator, so the common overflow case silently lands on the *right* value; the worst saturation sub-case is already guarded; automation passes fixed tested args.
  - *Why not INFO*: it is a real gate — a false PASS here could merge a CoS fairness regression (#1630/#1614), so it is above pure cosmetics.
  - *Why not MEDIUM*: no production/hot-path/security exposure; requires operator error; most-damaging path already guarded.
- **Dedup**: NOT a dup. Session backlog #4517-#4581 fairness/CoS items (workers-clamp/#4572 heartbeat zero-init, cached-policer, etc.) and the fable-166 V-* reducer fixes concern the *evaluator/metric* logic, not CLI arg parsing. Review's dedup (#4278-#4272, #4249-#4245) confirmed. Grep shows no telemetry/guard added for these four flags.
- **Disposition**: GENUINE-RESIDUAL, LOW. Fix: route the four flags through `parse_required_numeric_arg` (or a `parse_optional_numeric_arg` that errors on bad value, defaults on absence) and validate `n_workers > 0` unconditionally. lane=**rust** (pure `userspace-dp` cargo binary; no #1864 shim gate).

---

## Finding 2 — fairness_eval TSV parsers silently skip malformed rows — GENUINE-RESIDUAL (LOW)

- **Symbol EXISTS**: `userspace-dp/src/fairness_eval/inputs.rs:176-235` (`parse_binding_flows_tsv`) and `:251-274` (`parse_cos_flows_tsv`) match the review. Each column `parse()` failure does `continue`; the 6/3-col length mismatch and 5-col mismatch also `continue` with the literal comment `// Other formats: silently skipped.` (line 235). Grep confirms **no** skipped-row counter or `eprintln!` warning exists — so NOT already-fixed.
- **Reachability / actual path**: A corrupted/truncated Prometheus scrape TSV row (partial flush, truncated exposition) → non-numeric field or wrong column count → `continue` → row dropped with no signal. If corruption is systematic to one worker, that worker's samples are undercounted → median/`distribution_a_i` skews → CoV gate can flip PASS↔FAIL silently.
- **Severity reasoning — LOW (agree; reviewer Confidence Medium)**:
  - *Blast radius*: same offline `fairness-eval` CI binary as F1 — a wrong local gate result, no production/dataplane/security exposure.
  - *Exploitability*: none; requires a corrupted input file, not attacker-controlled.
  - *Bounds keeping it LOW*: TSVs are produced by the harness's own Prometheus scrape in a controlled run; whole-file truncation is more likely than surgical single-worker corruption and would usually also trip other sanity checks; a lenient parser skipping garbage is a defensible design choice, so this is a "warn, don't fail" observability nit rather than a correctness bug.
  - *Why not INFO*: silent data loss into a merge gate is a real (if unlikely) false-result vector.
  - *Why not MEDIUM*: no security/hot-path impact, controlled inputs, self-inflicted.
- **Dedup**: NOT a dup (review checked #4278-#4240, #4422, #4499; none cover silent TSV skip). Distinct file/mechanism from F1 though same "silent fallback in the CI harness" theme — could be folded into one hardening issue.
- **Disposition**: GENUINE-RESIDUAL, LOW. Fix: count skipped rows and `eprintln!` a warning when non-zero (mirroring the existing 3-vs-6-col legacy warn), optionally a `--strict` mode. lane=**rust**.

---

## Finding 3 — xsk_ffi `Umem::frame` offset `as isize` truncation — NOT-MATERIAL (defense-in-depth, unreachable)

- **Symbol EXISTS**: `userspace-dp/src/xsk_ffi.rs:372-385` on master matches. `offset = u64::from(pitch) * u64::from(idx.0)`; guarded by `if area_len.checked_sub(u64::from(pitch)) < Some(offset) { return None; }`; then `.offset(offset as isize)`.
- **Reachability analysis (refutes materiality on the real target)**:
  - The `checked_sub` guard already enforces `offset <= area_len - pitch <= area_len`. So `offset` can never exceed the actual allocated UMEM region length.
  - On the only supported target (Linux **x86_64**, `isize` = 64-bit), `area_len` for the largest legal config is bounded: max `ring_entries` 16384, `frames ≈ ring_entries * 3 ≈ 49152`, `frame_size` 4096 → `area_len ≈ 200 MiB`. Thus `offset < 200 MiB << isize::MAX (9.2e18)`. `offset as isize` is a lossless widen for every reachable value. No aliasing possible today.
  - The review **itself** concedes this ("So not reachable today", "safe today") and assigns **Confidence: Low**. The truncation only bites on a hypothetical 32-bit build (`isize` = 2^31-1) or a jumbo `frame_size` that no code path constructs. xpf ships x86_64-only.
- **Why NOT-MATERIAL rather than a genuine LOW**: there is no crafted input reachable on the real target that makes `offset` exceed `isize::MAX`; the guarded precondition mathematically bounds it below the platform limit. It is a pure defense-in-depth / future-portability hygiene note, not a reachable defect. The suggested `.add(offset as usize)` swap is a reasonable idiomatic cleanup but changes no observable behavior on any supported build.
- **Dedup**: NOT a dup of #4572 (workers truncation) or #4526/#4525; but disposition is NOT-MATERIAL regardless.
- **Disposition**: NOT-MATERIAL (defense-in-depth). Optional cosmetic hardening only. Excluded from genuineResiduals.

---

## Modules confirmed NEGATIVE (spot-checked reasoning holds)

The reviewer's per-module NEGATIVE results are consistent with the code: `hot_hash_seed` never-zero/OnceLock/getrandom-fallback; `io_uring_write` stale-CQE drain + EINTR/permanent-error split (#2478); `prefix`/`prefix_set` shift-by-32 guarded via `prefix_len==0` + ipnet-validated bounds; `slowpath` token-bucket + packet-fd atomic write (#2471/#2912); `state_writer` O_EXCL unique temp + fsync file+parent + full-instance liveness sweep (#2957/#3009/#2147); server handlers' fail-closed size cap (#2523/#2744), raise-only sysctls (#2970), non-socket unlink refusal (#2974), off-lock export (#2962/#4054), fail-closed snapshot preflight (#3766/#3789), rebind-no-stop (#1921). No policy/NAT/host-inbound/VRRP bypass in this batch — correct, these are supporting infra.

## Bottom line
2 genuine LOW residuals (F1, F2 — both fairness-eval CI-harness robustness/observability, lane=rust, no shim risk) + 1 NOT-MATERIAL defense-in-depth (F3). No HIGH/MEDIUM, nothing on the dataplane hot path, nothing security-reachable.
