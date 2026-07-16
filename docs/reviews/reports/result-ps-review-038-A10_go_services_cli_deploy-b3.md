# Triage Result: ps-review-038-A10_go_services_cli_deploy-b3

- **Subsystem**: A10 batch 3/3 — Go services / CLI / deploy test harness + `fairness-eval` (files: `test/incus/*.py` ×14, `test/xsk-repro/*` ×4, `pkg/scheduler/*.go` ×4, `userspace-dp/src/bin/fairness-eval.rs` ×1)
- **Base**: review base `d4506d4450e23f9a3fc572206b3c82f6b6c99029` — triaged against current `origin/master` **cc451b6b58112328143c8afa654bdb8e48074a99**
- **Repo**: real bpfrx (symbols verified on master)
- **Outcome counts**: 1 finding total → **1 DUP**, 0 GENUINE-RESIDUAL, 0 CONFABULATED, 0 ALREADY-FIXED, 0 NOT-MATERIAL, 0 DELIBERATE
- Module notes reference (scheduler concurrent-evaluate "see ps-037", A1_b3 sibling) are descriptive pointers, NOT additional findings. The `Findings:` block contains exactly one item.

---

## Finding 1: fairness-eval --n-workers/--shaper-rate silently defaults on parse error — DUP (#4590, F1)

**Severity claimed**: Low / Confidence High. **Disposition: DUP of open issue #4590.**

**Symbol EXISTS — confirmed on master.** `userspace-dp/src/fairness_eval/args.rs` `parse_args()`:
```rust
"--warmup-secs"     => { warmup_secs      = args.next().and_then(|s| s.parse().ok()).unwrap_or(5); }
"--final-burst-secs"=> { final_burst_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(1); }
"--n-workers"       => { n_workers        = args.next().and_then(|s| s.parse().ok()).unwrap_or(6); }
"--shaper-rate-bps" => { shaper_rate_bps  = args.next().and_then(|s| s.parse().ok()).unwrap_or(0); }
```
The `.and_then(|s| s.parse().ok()).unwrap_or(N)` pattern silently substitutes the default when the value fails to parse (e.g. `--n-workers 6x` → 6). The scenario in the finding is accurate: a CLI typo produces a wrong fairness-verdict denominator rather than an error.

**Why DUP, not genuine-residual.** This is the exact F1 residual already filed and OPEN as **#4590** — title: *"Rust fairness-eval CI-harness + HA/config LOW hardening batch from ps-037/038 audit (fairness-eval arg/TSV robustness ...)"*, body bullet: *"ps-038-A1_rust F1/F2: fairness_eval CI-harness — silent CLI arg fallback (F1) + silent TSV row skip (F2). RUST (fairness-eval harness only, not the dataplane hot path). Fix: error/warn instead of silent."* The review file itself cross-references it: *"parseInt with unwrap_or(0) silently defaults on bad input - see A1_b3 finding."* Same file, same `unwrap_or` fallback, same fix direction — this is the A1_b3/F1 finding surfacing again in the A10 slice because `fairness-eval.rs` is listed in both scopes.

**Bounding context (why it is correctly LOW and file-only, not drive-now).**
- **Not production dataplane.** `fairness-eval` is a CI/eval binary consumed by `test/incus/fairness-harness.sh`; the file header says so and the review's own module note flags it as a test/eval binary. No forwarding, security, or runtime-config surface.
- **Partial hardening already present.** The strict `parse_required_numeric_arg`/`parse_required_string_arg` helpers were added (Copilot #2) for `--cos-ifindex`/`--cos-queue-id`/`--cos-flows`/`--rss-expectation`, and an `expect_saturation && shaper_rate_bps == 0` / `n_workers == 0` fast-fail guard exists — so the cap-math path is already guarded against the zero case. The residual is only the four remaining lenient numeric flags (`--warmup-secs`, `--final-burst-secs`, `--n-workers`, `--shaper-rate-bps`) when a non-numeric string parses to the default without `--expect-saturation`.
- No security/exploit surface; the A2-style "HIGH refuted by upstream guard" pattern does not apply (this is genuinely Low and self-declared as such).

**No action beyond the existing tracker.** Fix, if driven, folds into #4590: route these four flags through the existing `parse_required_numeric_arg` helper. Lane: rust (harness binary).

---

## Confabulation / hardened-path checks
- All cited symbols (`fairness-eval.rs`, `fairness_eval/args.rs`, the `unwrap_or` fallbacks) exist on master — nothing confabulated.
- Other listed files (`test/incus/*.py`, `test/xsk-repro/*`, `pkg/scheduler/*.go`) carried NO findings in this batch; module notes for them are descriptive only. No A2/#4572-style upstream-guard refutation needed since the single finding is confirmed-real-but-already-tracked.

**Net: 0 novel genuine residuals. The one finding is a DUP of open #4590 (F1).**
