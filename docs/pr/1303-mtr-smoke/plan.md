# #1303 — IPv6 mtr smoke false-fail: controlled forwarding signal

Status: DRAFT v2 — v1 PLAN-KILLED by Codex + AGY (both converged on the
same fatal). Redesigned per their required-redesign direction.

## v1 outcome (preserved)

v1 proposed making the public `mtr -6` itself prove forwarding by
requiring ">=1 resolved hop beyond the first." Both reviewers
PLAN-KILLed it with the **same** counter-example:

- A healthy IPv6 path can forward while every intermediate transit
  router rate-limits/suppresses ICMPv6 time-exceeded, and the public
  final hop is also silent. With `MTR_REPORT_CYCLES=1` a single drop
  forces `???`. The report is then `1.|-- <fw>` / `2..N.|-- ???`,
  which is **indistinguishable** from a genuine forwarding break.
  v1's predicate hard-fails that healthy path — a NEW false-fail
  class, i.e. trading one external-dependent failure for another.
  (Codex finding 1; AGY finding 1.)
- AGY also caught: v1's single-hop degenerate falsely PASSes a broken
  dataplane (mtr stops after hop 1) (AGY 2); the `"100.0%"` literal is
  fragile — mtr truncates to `100.0` at column width so a named-but-
  dead final hop slips through as "resolved" (AGY 4); `"???" not in h`
  counts ICMP-error presentations as forwarding (Codex 2); plus a
  copy-paste syntax error in the v1 snippet (AGY 3).

Both reviewers' required redesign is the same: **do not use external
public traceroute intermediate hops to prove forwarding.** Use a
controlled forwarding signal; treat the public mtr as non-fatal.

## The controlled forwarding signal already exists

`userspace-ha-validation.sh` lines 860-862 already run, as a HARD gate
under `set -euo pipefail` (no `|| true`):

```bash
info "basic reachability checks"
run_host "ping -c 2 -W 1 ${V4_TEST_TARGET} >/tmp/userspace-ping-v4.out"
run_host "ping -6 -c 2 -W 1 ${V6_TEST_TARGET} >/tmp/userspace-ping-v6.out"
```

`V6_TEST_TARGET=2001:559:8585:80::200` is the iperf target on the
firewall's WAN-side `reth0.80`. The LAN host (`cluster-userspace-host`)
sits on the LAN side; its only IPv6 route to the `...:80::/64` prefix
is the RA-learned default route (lines 855-856) pointing at the
firewall. So this ping is **host -> firewall LAN (reth1.0) -> firewall
WAN (reth0.80) -> target -> reply back** — it cannot succeed unless the
userspace dataplane forwards IPv6 in both directions. It is the
controlled, in-our-control proof of IPv6 dataplane forwarding, and it
already hard-fails the smoke if forwarding is broken.

The deterministic IPv6 TTL=1 probe (`validate_ttl_probe "ipv6"`,
lines 438-439) independently asserts the firewall answers ICMPv6
time-exceeded — the egress/hop-decrement path.

These two gates are exactly the issue's suggested approach #1
("IPv6 TTL probe success plus LAN IPv6 ping success as sufficient
dataplane smoke coverage").

## Design

Two coupled changes:

### 1. IPv6 public mtr becomes a non-fatal recorded artifact

For IPv6 (`allow_unresolved_destination=1`) the public `mtr -6` to
`2607:f8b0:4005:814::200e` no longer hard-fails on ANY hop pattern —
final hop, intermediate hops, or "all `???` past the firewall." It is
recorded as an informational/warning line into `$summary_file` and the
artifact file. Rationale: every fatal interpretation of a public
external traceroute depends on ICMPv6 behavior we do not control, as
both reviewers proved. The forwarding-correctness signal is the
controlled ping + TTL probe, NOT this external trace.

This is **not** a no-op for the smoke as a whole: a genuinely-broken
IPv6 dataplane is caught by the controlled `ping -6` at line 862
(hard fail) and by `validate_ttl_probe "ipv6"` (hard fail). The
external mtr's job is reduced to operator-visible path observability,
which is all an uncontrolled external traceroute can honestly provide.

The IPv6 mtr is still REQUIRED to run and to produce parseable output;
"mtr produced no hop lines" (the local mtr binary failing, bad target
syntax, etc.) remains a recorded warning, not a crash — `set -e` safe.

### 2. Make the controlled-ping forwarding role explicit + assert it

The existing line-862 ping output is captured but never parsed — a
non-zero `ping` exit is the only failure signal, and `ping -6` to an
unreachable host on Linux can still exit 0 in some "Destination
unreachable" ICMP cases. Add an explicit assertion that the controlled
IPv6 ping actually received replies (so a broken dataplane that lets
`ping` exit 0 without delivery still fails). New helper:

```bash
validate_reachability() {
    local label="$1" path="$2"
    local out
    out="$(run_host "cat ${path}")"
    # "0 received" / "0 packets received" => no forwarding => hard fail.
    if grep -Eq '(^| )0( packets)? received' <<<"$out"; then
        die "${label} reachability: target not reached (no replies): ${out}"
    fi
    if ! grep -Eq '[1-9][0-9]* (packets )?received' <<<"$out"; then
        die "${label} reachability: could not confirm replies: ${out}"
    fi
    printf '%s reachability: ok\n' "$label" | tee -a "$summary_file"
}
```

Wire it after the two pings:

```bash
run_host "ping -c 2 -W 1 ${V4_TEST_TARGET} >/tmp/userspace-ping-v4.out"
run_host "ping -6 -c 2 -W 1 ${V6_TEST_TARGET} >/tmp/userspace-ping-v6.out"
validate_reachability "ipv4 forwarding" "/tmp/userspace-ping-v4.out"
validate_reachability "ipv6 forwarding" "/tmp/userspace-ping-v6.out"
```

This upgrades the implicit ping gate into an explicit, named
forwarding-correctness gate so the smoke's IPv6-break detection no
longer rests on `ping`'s exit code alone.

### 3. Extract + harden the mtr classifier (for the IPv4 leg)

The IPv4 leg STILL hard-gates on the final hop (`1.1.1.1`, a reliable
responder — `allow_unresolved_destination=0`). AGY finding 4 (the
`100.0%`-vs-`100.0` truncation false-pass) is a real bug on that leg:
a dead-but-named final hop currently slips through. Fix by parsing the
loss column numerically instead of substring-matching `"100.0%"`.

Extract the inline heredoc to `scripts/mtr_report_check.py` (importable
+ CLI) so it can be unit-tested:

```python
def hop_loss_pct(line):
    """Parse mtr --report hop loss column. Returns float or None."""
    # mtr --report: "  N.|-- host   LOSS%   SNT ..." ; the loss token is
    # the first field after the host that ends in '%' OR is numeric.
    m = re.search(r"\|--\s+(\S+)\s+([0-9]+\.[0-9]+)%?", line)
    return float(m.group(2)) if m else None

def hop_unresolved(line):
    return "???" in line

def classify_mtr_report(label, report, allow_unresolved_destination):
    hop_lines = [l for l in report.splitlines() if re.match(r"\s*\d+\.\|--", l)]
    if not hop_lines:
        # Local mtr failure: warning if IPv6-style allow, else hard fail.
        if allow_unresolved_destination:
            return True, f"{label} mtr: warning produced no hop lines"
        return False, f"{label} mtr produced no hop lines"
    first, last = hop_lines[0], hop_lines[-1]
    if hop_unresolved(first):
        return False, f"{label} mtr first hop unresolved: {first}"

    last_loss = hop_loss_pct(last)
    last_dead = hop_unresolved(last) or (last_loss is not None and last_loss >= 100.0)

    if last_dead:
        if allow_unresolved_destination:
            # IPv6 public trace: never fatal; controlled ping+TTL gate it.
            return True, f"{label} mtr: warning destination unresolved: {last}"
        return False, f"{label} mtr destination unresolved: {last}"
    return True, f"{label} mtr: ok"
```

Note: this version DROPS v1's unsound "forwarded = resolved hop beyond
first" predicate entirely (both reviewers killed it). IPv6 mtr is now
purely informational; IPv4 mtr keeps its final-hop gate but with
correct numeric loss parsing.

Shell wrapper (`validate_mtr_report`) calls
`python3 "${SCRIPT_DIR}/mtr_report_check.py" "$label" "$report" "$allow"`,
`die`s on non-zero exit, tees the message. Contract unchanged.

## Why this is not a no-op (the #1303 hard requirement)

| Failure mode | Caught by |
|---|---|
| IPv6 dataplane forwards nothing | `validate_reachability "ipv6 forwarding"` (line 862 ping, now asserted) — HARD FAIL |
| IPv6 hop-decrement / egress broken | `validate_ttl_probe "ipv6"` — HARD FAIL |
| IPv6 cannot even reach firewall | `validate_reachability` (0 received) — HARD FAIL |
| External public final hop silent | IPv6 mtr: WARNING (correct — out of our control) |
| Healthy path, all upstream ICMPv6 rate-limited | IPv6 mtr: WARNING (correct — no longer false-fails) |
| IPv4 final hop (1.1.1.1) dead/named-dead | IPv4 mtr: HARD FAIL (now via numeric loss, fixes AGY 4) |

The genuine-break catcher moved from the unsound external-trace
predicate to the controlled forwarding ping — under our control,
already present, now explicitly asserted.

## Hidden invariants preserved

- Shell contract of `validate_mtr_report`: stdout=log, exit=pass/fail,
  `die` on fail, `set -euo pipefail` safe (`if ! result=$(...)` form).
- IPv4 mtr leg stays a hard gate (stronger: numeric loss parse).
- No new remote command beyond reusing the existing ping outputs.
- No hot path, no Rust, no control-socket traffic.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral (smoke) | LOW | IPv6 break still hard-fails via controlled ping+TTL; external trace correctly demoted to warning; IPv4 leg strengthened. |
| False-pass | LOW | `validate_reachability` asserts replies received, closing the "ping exit 0 without delivery" gap AGY-style. |
| False-fail | LOW | external-dependent fatal paths removed; controlled gates are under our control. |
| Architectural | LOW | reuses existing ping gate; classifier extraction is mechanical. |

## Test plan

`scripts/test_mtr_report_check.py` (unittest):
1. IPv6 issue repro (hops 1-8 resolved, hop 9 `??? 100.0`, allow=1)
   → PASS with warning.
2. IPv6 all-upstream-`???` (hop1 fw, hops 2-9 `???`, allow=1) → PASS
   with warning (this is the case v1 wrongly hard-failed; the break is
   now caught by the ping gate, not here).
3. IPv6 first-hop unresolved (allow=1) → FAIL.
4. IPv4 final hop `1.1.1.1` resolved 0% loss (allow=0) → PASS.
5. IPv4 final hop `??? 100.0` (allow=0) → FAIL.
6. **IPv4 final hop named but `100.0` loss, no `%`** (allow=0) → FAIL
   (the AGY-4 truncation case — must NOT false-pass).
7. IPv4 final hop named `0.0%` → PASS.
8. no hop lines, allow=0 → FAIL; allow=1 → PASS (warning).
9. `hop_loss_pct` unit cases incl. `100.0` vs `100.0%` vs `0.0%`.

Plus shell-level coverage of `validate_reachability` parsing
(0-received → fail; N-received → ok), runnable without the cluster:
add cases to `scripts/userspace_ha_validation_matrix_test.py` or a
small dedicated reachability-parse test by sourcing the function.

- `shellcheck scripts/userspace-ha-validation.sh` clean.
- `python3 -m py_compile` both Python files.
- Existing matrix test still passes.
- Cluster smoke: owned by PARENT (this is a smoke-script change; the
  only real validation is running it on the loss userspace cluster).

## Out of scope

- Changing `MTR_V6_TARGET` to a controlled responder (issue option 3):
  unnecessary now that the public trace is non-fatal and the
  controlled ping carries the forwarding signal. Keeping the public
  target preserves operator-visible external path observability.
- IPv4 mtr demotion: IPv4 keeps its final-hop gate (1.1.1.1 is a
  reliable responder, unlike the public IPv6 target).
- Any dataplane/Rust change.

## Open questions for adversarial review (round 2)

1. Is the controlled `ping -6 2001:559:8585:80::200` genuinely a
   forwarding path (host→fw→WAN target), or could the host reach it
   without transiting the dataplane (e.g. an unexpected on-link route)?
   Topology in CLAUDE.md says LAN host reaches `...:80::/64` only via
   RA default → firewall; confirm no shortcut.
2. Is `validate_reachability`'s grep robust across iputs/busybox ping
   summary formats on the LAN host image? ("2 received" vs "2 packets
   received" vs "received, 0% packet loss").
3. Should the IPv6 mtr warning still be surfaced loudly enough that a
   regression in external path observability is noticeable, or is a
   tee'd warning sufficient?
4. Is demoting the IPv6 mtr to pure-warning acceptable given the issue
   says "must still catch a genuinely-broken IPv6 dataplane"? (Claim:
   yes, because the catch moved to the controlled ping+TTL gates, which
   are hard fails — verify the table above is complete.)
5. Numeric loss parse: does `hop_loss_pct`'s regex correctly extract
   the loss column on real `mtr --report` lines (host field can be a
   name, an IPv6 addr with colons, or `(waiting for reply)`)? Provide
   a counter-example if it mis-parses.

If reviewers conclude the IPv6-mtr demotion weakens coverage below the
issue's bar, PLAN-NEEDS-MAJOR / PLAN-KILL is acceptable.
