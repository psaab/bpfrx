# Plan: #929 — Same-class iperf-b mouse-latency harness

Issue: #929
Umbrella: #911 (gates the validation of #913/#918/#914/#920)
Diagnosis: `docs/pr/905-mouse-latency/findings.md` + #911 issue body

## 1. Problem

`test/incus/test-mouse-latency.sh` hardcodes `ELEPHANT_PORT=5201`
(iperf-a class) and `MOUSE_PORT=7` (best-effort class), exercising
the CROSS-class case. The #911 failure mode is SAME-class — both
elephants and mice in iperf-b — which the existing harness can't
measure. Any fix to the same-class HOL gate (#913 already shipped,
#918/#914/#920 next) lacks a validation gate without this harness.

## 2. Goal

Add same-class measurement capability to the mouse-latency test
matrix without breaking the existing cross-class baseline:

- Existing default invocation continues to produce cross-class
  data (no regression in the #905 dataset).
- A new code path runs the matrix with elephants + mice both in
  iperf-b: port 5202 (elephants) + port 7 (mice, hitting the
  operator's existing echo daemon), with a CoS classifier term
  that overrides port 7's default best-effort classification and
  routes it to iperf-b instead.
- **No new echo daemon required** — the port 7 listener that the
  cross-class default already uses is reused. The cross-class
  fixture leaves port 7 as best-effort; the same-class fixture
  reclassifies it as iperf-b. Switch by re-applying the fixture.

(Plan v1 specified a separate port 5212 listener that the
operator would stand up. v2 simplified to reuse port 7 after
the operator confirmed they only run a single echo. The CoS
term still differentiates same-class from cross-class via the
fixture being applied, not the destination port.)

## 3. Approach

Three changes in `test/incus/`:

### 3.1 Parameterize `test-mouse-latency.sh`

Replace the unconditional assignments

```bash
ELEPHANT_PORT=5201
MOUSE_PORT=7
SHAPER_BPS=$((1 * 1000 * 1000 * 1000))  # 1 Gb/s for iperf-a
```

with environment-overrideable defaults (Codex R1: `SHAPER_BPS`
must move with `ELEPHANT_PORT` because the settle/collapse
gates compare against it; same-class iperf-b is at 10 Gb/s):

```bash
ELEPHANT_PORT="${ELEPHANT_PORT:-5201}"
MOUSE_PORT="${MOUSE_PORT:-7}"
MOUSE_CLASS="${MOUSE_CLASS:-best-effort}"
# Default 1 Gb/s for iperf-a; same-class iperf-b wrapper sets 10 Gb/s.
SHAPER_BPS="${SHAPER_BPS:-$((1 * 1000 * 1000 * 1000))}"
```

Pass `MOUSE_CLASS` and `SHAPER_BPS` through to the per-cell
metadata (manifest.json) so post-hoc analysis can distinguish
same-class runs from cross-class and verify the gate threshold
matches the configured shape.

### 3.2 New CoS terms file `cos-iperf-same-class.set`

Existing `cos-iperf-config.set` maps:
- 5201 → iperf-a
- 5202 → iperf-b
- 5203 → iperf-c
- 5204 → best-effort

New same-class file inherits everything from `cos-iperf-config.set`
plus adds a term that overrides port 7's default best-effort
classification and routes it to iperf-b — putting mouse traffic
into the same queue as the elephants on port 5202.

```text
# Append to cos-iperf-same-class.set:
set firewall family inet filter bandwidth-output term 4 from destination-port 7
set firewall family inet filter bandwidth-output term 4 then forwarding-class iperf-b
set firewall family inet filter bandwidth-output term 4 then count iperf-b-mouse
set firewall family inet filter bandwidth-output term 4 then accept
```

(Plus matching IPv6 term.)

(v2 note: an earlier revision used port 5212 for the mouse so
that port 7 would never be classified as iperf-b. v2 dropped
that requirement — using port 7 means no second echo listener
on 172.16.80.200, and the same-class-vs-cross-class distinction
lives entirely in which CoS fixture is applied.)

`apply-cos-config.sh` learns a `--same-class` flag that selects
which file to apply. Default stays cross-class.

**Flag parsing (Codex R3):** the existing script treats `$1` as
`TARGET`, so `--same-class` must be parsed BEFORE positional
arguments. Use a small while-getopts-style loop at the top of
the script:

```bash
SAME_CLASS=0
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --same-class) SAME_CLASS=1; shift ;;
        --) shift; break ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done
TARGET="${1:?target required}"
```

Without explicit parsing, `--same-class` would be silently
treated as the target hostname — easy to miss in CI logs.

### 3.3 Echo daemon (no new listener required)

`TARGET_V4=172.16.80.200` is the iperf3 target host (the
operator's external echo server), NOT `cluster-userspace-host`
(which is the SOURCE of the test traffic).

v2 design: the same-class wrapper reuses the existing port 7
TCP echo daemon on 172.16.80.200 — no new listener required.
Same-class vs cross-class is a CoS-fixture distinction, not a
destination-port distinction.

The probe currently exercises **TCP only** (per
`mouse_latency_probe.py`). UDP same-class is OUT OF SCOPE for
this PR — there's no UDP echo path the probe would exercise.

### 3.4 New wrapper `test-mouse-latency-same-class.sh`

Wraps `test-mouse-latency-matrix.sh` with the right env:

```bash
#!/usr/bin/env bash
set -euo pipefail
exec env \
    ELEPHANT_PORT=5202 \
    MOUSE_PORT=7 \
    MOUSE_CLASS=iperf-b \
    SHAPER_BPS=$((10 * 1000 * 1000 * 1000)) \
    "$(dirname "$0")/test-mouse-latency-matrix.sh" "$@"
```

`apply-cos-config.sh` is invoked with the `--same-class` flag
when `MOUSE_CLASS == iperf-b`. The target-side echo daemon on
172.16.80.200:7 is the same one the cross-class default uses
(verified via preflight, §3.5).

**CoS apply is per-rep** (per existing harness behavior at
`test-mouse-latency.sh:157`). Switching `MOUSE_CLASS` between
runs requires re-applying the matching CoS fixture before each
rep — already handled because each rep calls
`apply-cos-config.sh` and the wrapper sets `MOUSE_CLASS`
end-to-end.

**Concurrent matrices: enforced via flock (Gemini R2).** CoS is
global mutable cluster state. Documentation alone is insufficient
— overlapping invocations corrupt both datasets silently. Add a
file-based lock at the top of `test-mouse-latency-matrix.sh`
(and reuse it from the same-class wrapper, which calls into
matrix.sh):

```bash
LOCK_FILE="${TMPDIR:-/tmp}/test-mouse-latency-matrix.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || {
    echo "ABORT: another mouse-latency matrix is already running" >&2
    echo "       (lock held on $LOCK_FILE)" >&2
    exit 1
}
```

`flock -n` returns immediately if the lock is held, so accidental
double-runs fail loudly instead of silently interleaving.

### 3.5 Preflight check

Add a preflight step in `test-mouse-latency.sh` that probes the
mouse port. Uses `bash /dev/tcp` rather than `nc -zw1` because
the source container doesn't ship netcat by default (cluster
smoke v2 caught this: the original `nc` form aborted every rep
with "command not found"):

```bash
incus_exec "$SOURCE" timeout 2 bash -c \
    "exec 3<>/dev/tcp/${TARGET_V4}/${MOUSE_PORT}" \
    > /dev/null 2>&1 \
    || { echo "ABORT: mouse echo not reachable on ${TARGET_V4}:${MOUSE_PORT}"; exit 1; }
```

Fails fast if echo daemon isn't up on the target port.

## 4. What this is NOT

- Not a change to MQFQ semantics (that's #913, shipped).
- Not a change to flow cache or batch size (#918, #920).
- Not a change to admission caps (#914).
- Not a new metric — same `mouse_latency_probe.py` / matrix runner.

## 5. Files touched

- `test/incus/test-mouse-latency.sh` — env-var parameterization
  + preflight + manifest.json metadata.
- `test/incus/apply-cos-config.sh` — `--same-class` flag.
- `test/incus/cos-iperf-same-class.set` — NEW; same-class CoS
  terms.
- `test/incus/test-mouse-latency-same-class.sh` — NEW; thin
  wrapper.
- No new echo daemon required (v2 design): same-class wrapper
  reuses the existing port 7 listener on 172.16.80.200 that the
  cross-class default already exercises.
- `docs/pr/929-same-class-harness/findings.md` — smoke results.

## 6. Test strategy

### 6.1 Smoke

```bash
ELEPHANT_PORT=5202 MOUSE_PORT=7 MOUSE_CLASS=iperf-b \
SHAPER_BPS=$((10*1000*1000*1000)) \
    ./test/incus/test-mouse-latency.sh 0 1 60 /tmp/sm
```

Asserts:
- Preflight passes (echo reachable on 172.16.80.200:7).
- `cos-apply.log` shows the same-class term applied.
- **Firewall classifier verification (Codex R1)**: extract
  `show configuration | display set | match "filter
  bandwidth-output term 4"` from the post-apply config and
  assert it contains `from destination-port 7` and
  `forwarding-class iperf-b`. Don't rely on
  `show class-of-service interface` alone — that only verifies
  scheduler/shaper binding, not the firewall term ordering.
- `probe.json` produced with non-zero `completed` count.
- `manifest.json` has `mouse_class: "iperf-b"`,
  `shaper_bps: 10000000000` fields.

### 6.2 Regression

Run the existing cross-class smoke (no env overrides) and
verify nothing changed. Compare `probe.json` numbers to the
last cross-class baseline run from #913 (~5ms p99 idle).

### 6.3 End-to-end

Run `test-mouse-latency-same-class.sh /tmp/sc` with the full
12-cell matrix (~6 hours wall budget per #905 plan §4.7).
Capture the gate ratios at iperf-b.

This dataset is the validation gate for #913/#918/#914/#920.

## 7. Acceptance

- [ ] Smoke (§6.1) produces valid same-class probe.json.
- [ ] Regression (§6.2) cross-class baseline unchanged.
- [ ] E2E matrix (§6.3) completes within wall budget.
- [ ] Gate ratio computable from same-class data.
- [ ] Documentation in `findings.md`.

## 8. Risks

- **Echo daemon scope creep.** If the existing echo on port 7
  is hardcoded to one port, adding a second port may require
  cluster-side config change beyond this PR. Document the
  choice in `findings.md`; fall back to a small Python
  `socketserver` if needed.
- **CoS classifier ordering.** The new firewall term must NOT
  shadow existing terms. Plan: add as `term 4`, after the
  existing `term 0..3` (5201/5202/5203/5204 → iperf-a/b/c/be).
  **Verify post-apply by extracting the firewall config**:
  `show configuration | display set | match "filter
  bandwidth-output term 4"` and asserting it contains
  `from destination-port 7` and `forwarding-class iperf-b`
  (per §6.1). `show class-of-service interface` is supplemental
  only — it shows scheduler/shaper binding, not firewall term
  ordering.
- **Cluster-state contamination.** Running same-class
  immediately after cross-class leaves the same-class CoS term
  installed. Document that `apply-cos-config.sh` (no
  `--same-class`) must run before any cross-class baseline run.
- **Preflight false negative.** `nc -zw1` may fail under
  transient network conditions; document that the operator
  should retry the smoke once.

## 9. Acceptance checklist

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (HPC + OS expert framing); MERGE YES.
- [ ] Implemented; smoke passes.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.
