# #1303 — IPv6 mtr smoke false-fail: controlled forwarding signal

Status: PLAN-READY v3 — Codex (task-mpru1jxi-2lvvap) + AGY
(adversarial-review-mpru1nhk-15b7f2) both PLAN-READY on v3, confirming
every round-2 finding (F1-F5) resolved. v1 PLAN-KILLED (both); v2
PLAN-NEEDS-MAJOR (both endorsed the architecture). Two non-blocking
plan-doc nits from Codex r3 folded in (test expectation `100.0`→None;
route-guard scope wording).

## v2 round-2 outcome (preserved)

Codex `task-mprtshsb-53ejd4` and AGY `adversarial-review-mprtsms7-iqwmzq`
both returned NEEDS-MAJOR and both explicitly endorsed the v2
architecture ("the right direction" / "the absolute correct solution").
Overlapping findings, all applied in v3:

- **F1 (both): `hop_loss_pct` regex false-pass.** `\S+` for the host
  field fails on `(waiting for reply)` (has spaces) → `last_dead`
  evaluates False → a dead IPv4 final hop PASSES. Also must accept an
  integer `%` (`100%`, not only `100.0%`). Fix: non-greedy host match
  + optional decimals, and treat `(waiting for reply)` as unresolved.
- **F2 (both): `set -e` crashes before the downgrade can run.** The
  current `run_mtr_report` runs `mtr` naked under `set -e`
  (userspace-ha-validation.sh:382); a nonzero remote `mtr` exit kills
  the validator before `validate_mtr_report` can downgrade IPv6 to a
  warning. Same for the line-862 pings: 100% loss exits `ping` nonzero
  and kills the script before `validate_reachability` prints its
  descriptive `die`. Fix: capture mtr/ping with `… 2>&1 || true` so
  the classifier/assertion owns the verdict.
- **F3 (both): coverage scope.** The controlled target `::200` sits on
  the firewall's directly-connected WAN subnet (`reth0.80`), so the
  ping proves *forwarding to the connected WAN subnet*, not external
  WAN default-gateway ND / next-hop / off-link routing. The TTL=1
  probe expires at the firewall LAN side. With the public mtr demoted,
  total loss of *external internet* IPv6 routing would pass with only
  a warning. v3 resolves this by **scoping the gate explicitly** to
  "dataplane forwarding to the controlled WAN target" and crediting
  the existing IPv6 `iperf3` leg (TCP to the same controlled target,
  closing Codex's "TCP-broken-while-ICMP-works" gap). External
  internet IPv6 routing is **declared observability-only** — it is not
  what #1303's dataplane smoke is chartered to prove, and an
  uncontrolled public traceroute cannot honestly gate on it.
- **F4 (AGY): locale.** Force `LC_ALL=C` on the pings so the
  `received` parse survives non-English locales.
- **F5 (both, defensive): route-sanity drift guard.** Assert
  `ip -6 route get $V6_TEST_TARGET` on the LAN host is neither `local`
  nor `dev lo` nor an on-link `:80::/64` route, so the "ping transits
  the firewall" premise can't silently drift.
- **F6 (both, acknowledged residual): kernel-forwarding leak.** `ping`
  cannot prove the packet went through `xpfd`/AF_XDP vs the kernel
  stack. Out of scope to fully close here; the existing helper/runtime
  readiness gates (`wait_for_vm_cli`, forwarding-armed checks) cover
  "xpfd is alive", and iperf3 saturation would not reach 22 Gb/s via a
  generic kernel path. Documented, not silently ignored.

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

The IPv6 mtr is still REQUIRED to run, but `run_mtr_report` now
captures it as `… 2>&1 || true` (F2) so a nonzero remote `mtr` exit
cannot kill the validator before the classifier downgrades. "mtr
produced no hop lines" for IPv6 (local mtr binary failing, bad target
syntax) is a recorded warning, not a crash.

**Scope (F3):** external internet IPv6 routing is observability-only
here. The dataplane-forwarding gate is the controlled ping + TTL +
IPv6 iperf3 to `::200`. The public mtr warning surfaces external-path
regressions to the operator's eye without making an uncontrolled
endpoint load-bearing.

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

Wire it after the two pings, with `LC_ALL=C` (F4) so the `received`
parse survives non-English locales, and `2>&1 || true` (F2) so a 100%
-loss `ping` does not crash the script before `validate_reachability`
emits its descriptive `die`:

```bash
run_host "LC_ALL=C ping -c 2 -W 1 ${V4_TEST_TARGET} >/tmp/userspace-ping-v4.out 2>&1 || true"
run_host "LC_ALL=C ping -6 -c 2 -W 1 ${V6_TEST_TARGET} >/tmp/userspace-ping-v6.out 2>&1 || true"
validate_reachability "ipv4 forwarding" "/tmp/userspace-ping-v4.out"
validate_reachability "ipv6 forwarding" "/tmp/userspace-ping-v6.out"
```

This upgrades the implicit ping gate into an explicit, named
forwarding-correctness gate so the smoke's IPv6-break detection no
longer rests on `ping`'s exit code alone.

**Route-sanity drift guard (F5):** before trusting the ping as a
forwarding proof, assert the LAN host has no shortcut to the target.
Added once near the existing reachability block:

```bash
assert_forwarding_route() {
    local label="$1" target="$2"
    local route
    route="$(run_host "ip -6 route get ${target} 2>&1 || true")"
    case "$label" in ipv4*) route="$(run_host "ip route get ${target} 2>&1 || true")" ;; esac
    if grep -Eq '\blocal\b|\bdev lo\b' <<<"$route"; then
        die "${label} forwarding-route sanity: ${target} resolves on-box (no transit): ${route}"
    fi
    printf '%s forwarding-route: %s\n' "$label" "$route" | tee -a "$summary_file"
}
```

(IPv6 uses `ip -6 route get`; IPv4 uses `ip route get`. The check
fails if the target is `local` or routed via `dev lo` — i.e. assigned
on the host itself, which would mean the ping never transits the
firewall. It does not attempt to enumerate every possible on-link
shortcut; `local`/`dev lo` is the concrete drift mode that would make
the ping a non-transit no-op, and both reviewers confirmed that grep is
correct for it.)

### 3. Extract + harden the mtr classifier (for the IPv4 leg)

The IPv4 leg STILL hard-gates on the final hop (`1.1.1.1`, a reliable
responder — `allow_unresolved_destination=0`). Two round-2 false-pass
bugs to fix on that leg (F1):

1. The loss column must be parsed **numerically**, not by substring
   `"100.0%"` (mtr truncates to `100.0` at column width, and emits
   integer `100%` in some builds).
2. The host field can contain spaces (`(waiting for reply)`), so a
   host-anchored regex like `\S+` mis-stops. **Anchor on the loss
   token instead**: in `mtr --report` the loss percentage is the only
   field that ends in `%` (and it is always the first such token after
   `|--`). Parse that, and treat `(waiting for reply)` as unresolved.

Extract the inline heredoc to `scripts/mtr_report_check.py` (importable
+ CLI) so it can be unit-tested:

```python
WAITING = "(waiting for reply)"

def hop_loss_pct(line):
    """Parse the mtr --report loss column.

    The loss% is the only field on an mtr --report hop line that ends
    in '%' (e.g. '0.0%', '100.0%', '100%'). Anchor on it directly so a
    host field that contains spaces (e.g. '(waiting for reply)') does
    not break parsing. Returns float, or None if no '%' token found.
    """
    m = re.search(r"(\d+(?:\.\d+)?)%", line)
    return float(m.group(1)) if m else None

def hop_unresolved(line):
    return "???" in line or WAITING in line

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
    # Dead final hop: explicit "???"/"(waiting for reply)", OR a parsed
    # loss >= 100, OR — conservatively — a line whose loss column could
    # not be parsed at all (treat unknown as dead so we never silently
    # pass an unparseable final row).
    last_dead = (
        hop_unresolved(last)
        or last_loss is None
        or last_loss >= 100.0
    )

    if last_dead:
        if allow_unresolved_destination:
            # IPv6 public trace: never fatal; controlled ping+TTL+iperf3
            # gate forwarding. This is observability-only.
            return True, f"{label} mtr: warning destination unresolved: {last}"
        return False, f"{label} mtr destination unresolved: {last}"
    return True, f"{label} mtr: ok"
```

Note `last_loss is None → dead`: if the loss column is unparseable the
IPv4 leg fails closed (hard fail) rather than silently passing, and
the IPv6 leg warns. This closes the `(waiting for reply)` false-pass
both reviewers raised, even for mtr output shapes we did not anticipate.

Note: this version DROPS v1's unsound "forwarded = resolved hop beyond
first" predicate entirely (both reviewers killed it). IPv6 mtr is now
purely informational; IPv4 mtr keeps its final-hop gate but with
correct numeric loss parsing.

Shell wrapper (`validate_mtr_report`) calls
`python3 "${SCRIPT_DIR}/mtr_report_check.py" "$label" "$report" "$allow"`,
`die`s on non-zero exit, tees the message. Contract unchanged.

## Why this is not a no-op (the #1303 hard requirement)

The chartered scope of this smoke leg is **IPv6 dataplane forwarding
to the controlled WAN target**, not external internet IPv6 routing.
Within that scope:

| Failure mode | Caught by | In scope? |
|---|---|---|
| IPv6 dataplane forwards nothing (ICMP) | `validate_reachability "ipv6 forwarding"` (line 862 ping, asserted, `\|\| true`-captured) — HARD FAIL | yes |
| IPv6 dataplane forwards ICMP but not TCP | existing IPv6 `iperf3` to `::200` — HARD FAIL (closes Codex F3) | yes |
| IPv6 hop-decrement / firewall ICMPv6 path broken | `validate_ttl_probe "ipv6"` — HARD FAIL | yes |
| IPv6 host cannot reach firewall at all | `validate_reachability` (0 received) — HARD FAIL | yes |
| LAN host has on-box shortcut to `::200` (drift) | `assert_forwarding_route` — HARD FAIL | yes |
| External public final hop silent | IPv6 mtr: WARNING (uncontrollable endpoint) | observability |
| Healthy path, all upstream ICMPv6 rate-limited | IPv6 mtr: WARNING (no longer false-fails) | observability |
| External internet IPv6 routing broken beyond WAN link | IPv6 mtr: WARNING only | **declared observability-only** (F3) |
| IPv4 final hop (1.1.1.1) dead / `(waiting for reply)` / `100%` | IPv4 mtr: HARD FAIL (numeric loss parse, fail-closed) | yes |

The genuine-break catcher moved from the unsound external-trace
predicate to the controlled ping + TTL + iperf3 gates — all under our
control, all hard fails. The only thing demoted to a warning is what
an uncontrolled public traceroute can honestly tell us: external path
observability. That demotion is the explicit, scoped tradeoff #1303
asks for; it is NOT a blanket no-op, as the table's "yes" rows show.

## Hidden invariants preserved

- Shell contract of `validate_mtr_report`: stdout=log, exit=pass/fail,
  `die` on fail, `set -euo pipefail` safe (`if ! result=$(...)` form).
- IPv4 mtr leg stays a hard gate (stronger: numeric loss parse).
- No new remote command beyond reusing the existing ping outputs.
- No hot path, no Rust, no control-socket traffic.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral (smoke) | LOW | IPv6 break still hard-fails via controlled ping+TTL+iperf3; external trace correctly demoted to warning; IPv4 leg strengthened (numeric loss, fail-closed). |
| False-pass | LOW | `validate_reachability` asserts replies received; classifier fails closed on unparseable loss; `(waiting for reply)` treated as dead. |
| False-fail | LOW | external-dependent fatal paths removed; `LC_ALL=C` removes locale flake; controlled gates are under our control. |
| Architectural | LOW | reuses existing ping gate; classifier extraction is mechanical; route-sanity guard prevents premise drift. |

## Test plan

`scripts/test_mtr_report_check.py` (unittest):
1. IPv6 issue repro (hops 1-8 resolved, hop 9 `??? 100.0%`, allow=1)
   → PASS with warning.
2. IPv6 all-upstream-`???` (hop1 fw, hops 2-9 `???`, allow=1) → PASS
   with warning (this is the case v1 wrongly hard-failed; the break is
   now caught by the controlled ping gate, not here).
3. IPv6 first-hop unresolved (allow=1) → FAIL.
4. IPv4 final hop `1.1.1.1` resolved `0.0%` (allow=0) → PASS.
5. IPv4 final hop `??? 100.0%` (allow=0) → FAIL.
6. **IPv4 final hop `(waiting for reply)  100.0`** (no `%`, spaces in
   host) (allow=0) → FAIL (the F1 false-pass both reviewers found —
   must NOT pass; covers both the spaces-in-host and the `%`-truncation
   sub-cases).
7. IPv4 final hop named `0.0%` → PASS.
8. IPv4 final hop `100%` integer loss → FAIL.
9. IPv4 final hop with an **unparseable loss column** → FAIL
   (fail-closed via `last_loss is None`).
10. IPv6 final hop `(waiting for reply) 100.0` (allow=1) → PASS warning.
11. no hop lines, allow=0 → FAIL; allow=1 → PASS (warning).
12. `hop_loss_pct` unit: `100.0%`→100.0, `100.0`→None (no `%` token —
    fails closed downstream), `0.0%`→0.0, `100%`→100.0, line with no
    `%` → None.
13. `hop_unresolved` unit: `???`→True, `(waiting for reply)`→True,
    resolved host→False.
14. IPv6 addr host with colons in the loss-token line parses correctly
    (loss anchor must not confuse `::` with the `%` token).

Plus shell-level coverage of `validate_reachability` and
`assert_forwarding_route` parsing, runnable without the cluster
(source the functions in a bats-free shell test, feed canned ping /
`ip route get` output): 0-received → fail; N-received → ok; localized
input still parses under `LC_ALL=C` capture; `local`/`dev lo` route →
fail. Add to `scripts/userspace_ha_validation_matrix_test.py` (it
already shells out to the validator) or a dedicated parse test.

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

## Open questions for adversarial review (round 3)

All round-2 findings (F1-F6) are applied above. Remaining questions:

1. Does anchoring `hop_loss_pct` on the **first `\d+(\.\d+)?%` token**
   ever mis-fire on a real `mtr --report` line — e.g. could a hostname
   or IPv6 address ever contain a `<digits>%` substring before the
   loss column? (Loss is normally the first `%`-suffixed field; verify
   no host field shape precedes it.)
2. Is `last_loss is None → dead` (fail-closed) too aggressive for the
   IPv4 leg — could a legitimate healthy `mtr` final line ever lack a
   parseable `%` loss token? If so the IPv4 leg would false-fail.
3. Does `assert_forwarding_route`'s `local`/`dev lo` grep correctly
   distinguish the transit case from the on-box case across the LAN
   host's `ip route get` output shape?
4. Is the F3 scope decision (external internet IPv6 routing =
   observability-only, dataplane-to-controlled-WAN-target = gated)
   the right charter line for #1303, or should a controlled
   off-WAN-link IPv6 target be added to gate WAN egress too? (That
   would re-introduce an external dependency the issue is trying to
   remove — argue it either way.)
5. Any residual `set -euo pipefail` hazard in the new `\|\| true`
   captures or the `assert_forwarding_route` `case`?

If reviewers conclude the IPv6-mtr demotion weakens coverage below the
issue's bar, PLAN-NEEDS-MAJOR / PLAN-KILL is acceptable.
