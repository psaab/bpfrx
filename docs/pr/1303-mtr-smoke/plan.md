# #1303 — IPv6 mtr smoke false-fail: robust forwarding signal

Status: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

## Issue framing

`scripts/userspace-phase-cycle.sh` runs the userspace HA smoke, which
delegates to `scripts/userspace-ha-validation.sh`. The IPv6 leg of
`validate_traceroute_visibility()` records a one-cycle `mtr -6` report
to a public IPv6 target (`2607:f8b0:4005:814::200e`, a Google address)
and validates it via `validate_mtr_report "ipv6" ... 1`.

#1303 reports a false-fail: a healthy IPv6 dataplane (TTL probe ok,
LAN IPv6 ping 3/3, 22 Gb/s iperf, 0 TX errors) was flagged broken
because the **external final hop** did not answer the ICMPv6 probe
(`9.|-- ??? 100.0%`). The final-hop responder is outside our control;
the smoke must not hinge on it.

## What's already shipped (must compose with)

#1301 (commit `68f41ffda`) already added the `allow_unresolved_destination`
parameter and passes `1` for IPv6. Today the IPv6 logic is:

```
first = hop_lines[0]; last = hop_lines[-1]
if "???" in first: FAIL  (first hop unresolved)
if "???" in last or "100.0%" in last:
    if allow_unresolved_destination: warn + PASS
    FAIL
PASS
```

This **already** stops the issue's exact failure from being fatal —
but it over-corrects into a near no-op for IPv6: the only thing the
IPv6 mtr check now proves is that **hop 1 resolved**. Hop 1 is the
firewall's own LAN-side address answering an ICMPv6 TTL-expired for a
packet addressed to it as the gateway. That is pure L3-local liveness,
**not** evidence the dataplane forwarded anything. If the IPv6
dataplane were genuinely broken (forwards nothing past itself), the
report would be `1.|-- <fw>` then `2.|-- ??? 100.0%` ... and the
current check would warn + PASS. That is the "weaken into a no-op"
trap #1303 explicitly forbids.

So #1303 is really two-sided:
1. Don't fail on an unresolved external **final** hop (already done).
2. Still fail if the IPv6 dataplane forwards nothing — i.e. the smoke
   must assert *forwarding past the firewall*, not just first-hop
   liveness.

The docs (`docs/userspace-ha-validation.md:233-234`) currently codify
the weak "resolved first hop" rule; they must be updated to the new
contract.

## What the robust IPv6-forwarding signal is

A traceroute/mtr hop list to a public target through the firewall is:

```
1. <firewall LAN gateway>     <- L3-local liveness (host -> fw)
2. <first upstream router>    <- REQUIRES the fw to have forwarded the
3. <next upstream router>        packet off-box and routed the reply back
...
N. <public destination>       <- often silent (out of our control)
```

The packet reaching **hop ≥ 2** and the TTL-expired reply coming back
is direct proof the userspace dataplane forwarded the IPv6 packet off
the LAN and the return path works. The external destination answering
hop N is not.

**Robust rule (IPv6, `allow_unresolved_destination=1`):**
- no hop lines → FAIL (mtr produced nothing).
- first hop `???` → FAIL (cannot even reach the firewall).
- **require at least one resolved hop at index ≥ 1** (a hop *beyond*
  the first answered) → this is the forwarding-past-the-firewall
  signal. If every hop after the first is `???`, FAIL with a
  forwarding-specific message.
- given forwarding is proven, an unresolved/100%-loss **final** hop is
  recorded as a warning and PASSES.

This still catches a genuinely-broken IPv6 dataplane (only the firewall
answers; nothing forwards) and stops false-failing on an unanswered
external endpoint.

IPv4 behaviour is unchanged: `allow_unresolved_destination=0` still
requires the final destination (`1.1.1.1`, a reliable responder) to
resolve. The new "resolved hop beyond first" requirement is strictly
*additional* for IPv4 too (1.1.1.1 resolving as the last hop already
implies forwarding), so it does not weaken IPv4.

## Concrete design

The validation Python is currently an inline heredoc inside
`validate_mtr_report()`, which is untestable in isolation. Extract it
to a standalone, importable + CLI module so the classification logic
can be unit-tested against canned mtr reports reproducing both the
false-fail and the genuine-break.

New file `scripts/mtr_report_check.py`:

```python
def classify_mtr_report(label, report, allow_unresolved_destination):
    """Return (ok: bool, message: str).

    ok=False  -> hard failure (caller dies with message)
    ok=True   -> pass; message is the summary/warning line to log
    """
    hop_lines = [l for l in report.splitlines() if re.match(r"\s*\d+\.\|--", l)]
    if not hop_lines:
        return False, f"{label} mtr produced no hop lines"
    first, last = hop_lines[0], hop_lines[-1]
    if "???" in first:
        return False, f"{label} mtr first hop unresolved: {first}"

    last_unresolved = ("???" in last) or ("100.0%" in last)

    # Forwarding signal: at least one RESOLVED hop BEYOND the first.
    # A hop that printed a name/address means a TTL-expired reply came
    # back from a router past the firewall -> forwarding happened. We
    # deliberately do NOT also require that hop to be loss-free: with
    # MTR_REPORT_CYCLES=1 a single resolved intermediate can show
    # 100.0% loss on that one cycle yet still prove a reply arrived.
    # "???" (no name at all) is the only thing that means "no reply".
    forwarded = any("???" not in h for h in hop_lines[1:])

    if last_unresolved:
        if not allow_unresolved_destination:
            return False, f"{label} mtr destination unresolved: {last}"
        if not forwarded:
            # Only the firewall answered; nothing forwarded off-box.
            return False, (
                f"{label} mtr shows no forwarding past the first hop "
                f"(all hops beyond the firewall unresolved): {last}"
            )
        return True, (
            f"{label} mtr: ok (destination unresolved, forwarding "
            f"confirmed past first hop): {last}"
        )

    # Last hop resolved -> destination answered -> forwarding implied.
    return True, f"{label} mtr: ok"
```

CLI entrypoint: `argv = [label, report, allow_unresolved("0"/"1")]`,
print message, exit 0 on ok else exit 1. This preserves the existing
shell contract: `validate_mtr_report` calls
`python3 scripts/mtr_report_check.py "$label" "$report" "$allow"`,
captures stdout, `die`s on non-zero, else `tee`s the message.

`validate_mtr_report()` shell wrapper becomes:

```bash
validate_mtr_report() {
    local label="$1" path="$2" allow_unresolved_destination="${3:-0}"
    local report result
    report="$(run_host "cat ${path}")"
    if ! result="$(python3 "${SCRIPT_DIR}/mtr_report_check.py" \
        "$label" "$report" "$allow_unresolved_destination" 2>&1)"; then
        die "$result"
    fi
    printf '%s\n' "$result" | tee -a "$summary_file"
}
```

(`SCRIPT_DIR` is already defined at the top of the script.)

## Edge cases the classifier must handle

- Single hop line total, resolved, last==first, destination answered →
  PASS (degenerate but valid: destination is one hop away).
- Single hop line total, `???` → first-hop-unresolved FAIL (cannot
  reach firewall). Correct: this is a real break.
- A named-but-100%-loss intermediate hop: counts AS forwarding
  evidence (it replied to a TTL-expired at least once → forwarding
  happened). Only `???` (no name) means no reply. This keeps the
  predicate robust to mtr's 1-cycle loss flakiness.
- mtr `--report-cycles=1`: loss is 0.0% or 100.0% only; the forwarding
  predicate keys on name-resolution (`???`), not loss%, so it is
  robust to that.

## Hidden invariants preserved

- Shell contract: stdout = log line, exit code = pass/fail, `die` on
  failure. Unchanged.
- IPv4 leg semantics unchanged (allow=0 path identical outcome).
- No new remote command, no new control-socket traffic, no hot path.
- `set -euo pipefail` safe: the `if ! result=$(...)` form already
  tolerates non-zero exit without tripping `-e`.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (smoke) | LOW | IPv4 outcome identical; IPv6 strictly stronger (adds forwarding assertion) but tolerant of external final hop. |
| Lifetime/borrow | N/A | Shell + Python, no Rust. |
| Performance | NONE | Off the dataplane; runs once per validation. |
| Architectural mismatch | LOW | Pure extraction + one added predicate; no new boundary. |

The one real risk: could "at least one resolved hop beyond the first"
itself false-fail on a network where the immediate upstream router
rate-limits ICMPv6 TTL-expired but a *later* hop answers? The predicate
scans **all** hops beyond the first, so any single resolved hop in
positions 2..N satisfies it. A network where literally no upstream
router (across all positions) answers but the path still works is
indistinguishable from a real forwarding break via traceroute alone —
and in that case the TTL probe + LAN ping legs (separate gates) still
provide coverage. Documented as the residual.

## Test plan

- New `scripts/test_mtr_report_check.py` (unittest), covering:
  1. IPv6 false-fail repro (issue's exact 9-hop report, hops 1-8
     resolved, hop 9 `??? 100.0%`, allow=1) → PASS with warning.
  2. IPv6 genuine break (hop 1 fw resolved, hops 2-9 all `??? 100.0%`,
     allow=1) → FAIL with forwarding-specific message. **This is the
     no-op guard.**
  3. IPv6 first-hop unresolved (allow=1) → FAIL.
  4. IPv6 healthy full path (all hops resolved incl. destination,
     allow=1) → PASS, no warning.
  5. IPv4 destination unresolved (allow=0) → FAIL (unchanged).
  6. IPv4 healthy (allow=0) → PASS.
  7. no hop lines → FAIL.
  8. single resolved hop, destination answered → PASS.
- `shellcheck scripts/userspace-ha-validation.sh` clean.
- `python3 -m py_compile` both Python files.
- Existing `scripts/userspace_ha_validation_matrix_test.py` still
  passes (dry-run matrix path untouched).
- The script still runs end-to-end (cluster smoke owned by parent).

## Out of scope

- Switching `MTR_V6_TARGET` to a controlled LAN responder (issue's
  alternative suggestion). Keeping the public target preserves
  external-path coverage; the robust predicate makes the public
  target's final-hop silence non-fatal. Not changing the target keeps
  the diff minimal and the external-reachability signal intact.
- IPv4 leg behaviour changes.
- Any dataplane/Rust change.

## Open questions for adversarial review

1. Is "≥1 resolved hop beyond the first" the right forwarding proof,
   or can a healthy network legitimately show every intermediate hop
   `???` while still forwarding (ICMP rate-limiting on every upstream)?
   If so, is the TTL-probe + LAN-ping coverage enough to justify it,
   or should the forwarding signal instead be cross-checked against the
   separate LAN IPv6 ping result?
2. The forwarding predicate now keys on name-resolution (`???`), not
   loss%, specifically to survive mtr 1-cycle loss flakiness. Is there
   a case where a hop prints a resolved name without an actual
   TTL-expired reply having arrived (e.g. mtr caching a prior name)?
   If so the predicate could over-count forwarding. Verify mtr does
   not print a name for a hop that produced zero replies this run.
3. Should the genuine-break case (only firewall answers) be a hard
   FAIL, or is that too aggressive given mtr's 1-cycle flakiness — i.e.
   should `MTR_REPORT_CYCLES` be bumped for IPv6 so the forwarding
   predicate is statistically stable before we make it load-bearing?
4. Is extracting the Python to a standalone file the right call, or
   does it fragment the validator (one more file to keep in sync)?
   Inline-but-tested-via-subprocess is the alternative.
5. Does the IPv4 leg need the same "forwarding past first hop"
   assertion for symmetry, or is "final hop 1.1.1.1 resolved"
   sufficient (it already implies forwarding)?

If reviewers conclude the change is wrong-shaped or the forwarding
predicate is unsound, PLAN-KILL / PLAN-NEEDS-MAJOR is an acceptable
verdict.
