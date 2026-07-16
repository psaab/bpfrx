# Triage result — ps-review-040-A8-b1

- **Subsystem:** A8 — Control Plane REST/gRPC API & Diagnostics (`pkg/api`, `pkg/grpcapi`)
- **Review base commit:** 0ebdb74b2e8bf04b40495f49b6a64f9146af09fc
- **Triaged against:** origin/master @ `95b33d49634d56086269a62a92e213dae7926f88` (base != master; fetched fresh)
- **Repo:** real bpfrx (`github.com:psaab/xpf`) — both cited paths exist on master; no avacado-fork citations.
- **Outcome counts:** 2 substantive findings → 1 NOT-MATERIAL/DELIBERATE, 1 GENUINE-RESIDUAL (LOW, cosmetic). ~110 "negative results" are coverage padding, no defects asserted — not triaged individually.

---

## Finding 1 — Basic auth timing side-channel (auth.go:81-83) — NOT-MATERIAL / DELIBERATE

**Symbol exists.** `pkg/api/auth.go` `checkAuthorization` Basic path is exactly as cited:
```go
expected, exists := cfg.Users[user]
passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1
return exists && passMatch
```

**The finding's core premise is factually wrong.** It claims #4157 fixed only the
APIKey/Bearer path and left the Basic-auth username-existence leak unaddressed.
The #4157 diff (commit `6993d7827`) shows the Basic path WAS rewritten precisely
for this: the old `if !exists { return false }` early-return (which skipped the
compare entirely = a large, measurable gap) was deleted and replaced with an
unconditional compare + `return exists && passMatch`. The in-code comment states
the intent: "ALWAYS run the constant-time compare — even for an unknown user — so
response timing does not reveal whether the username exists (#4157)." So the
material gap the finding describes (instant-return-because-compare-skipped vs
looping) no longer exists — the compare always runs.

**The residual the finding actually describes is documented-accepted and
unexploitable.** What remains is that `subtle.ConstantTimeCompare(pass, expected)`
short-circuits on a length mismatch, and for a non-existent user `expected` is the
empty string. So an attacker who guesses a password of the exact right length
could, in principle, distinguish "loop ran" from "length-mismatch immediate
return." This is:
  1. **Explicitly documented as acceptable** in the sibling `constantTimeAPIKeyMatch`
     comment in the same file: "ConstantTimeCompare returns 0 immediately when the
     two byte slices differ in length; that reveals only length, not content, which
     is acceptable here." Same `subtle` package, same short-circuit property — a
     deliberate project posture, not an oversight.
  2. **Nanosecond-scale and network-unexploitable.** The difference is an immediate
     return vs a XOR loop over an 8-64 byte string — tens of nanoseconds — swamped
     by base64 decode, `strings.Cut`, map lookup, goroutine scheduling, JSON
     response marshaling, TLS, and multi-microsecond-to-millisecond network jitter.
  3. **On a loopback-default API.** The HTTP API binds 127.0.0.1 by default; auth is
     only meaningful on an explicit routable rebind (#4162), and even then this is a
     length oracle, not a content oracle.

**Severity:** Finding says Medium; realistic is INFO. Not a genuine residual — the
material leak was closed by #4157 and the residual is a documented-accepted,
network-unexploitable property of `crypto/subtle`. Filing/fixing would be
theater (the finding's own SHA-256-both-sides fix only equalizes length, which
`subtle` already documents as acceptable to leak). **Disposition: NOT-MATERIAL
(#4157 already hardened; residual DELIBERATE).**

---

## Finding 2 — naive shift `1 << (bits-ones)` for IPv6 det-NAT host count (metrics_nat.go:42-52) — GENUINE-RESIDUAL (LOW, cosmetic)

**Symbol exists, unchanged.** `pkg/api/metrics_nat.go` `collectNATPoolMetrics` is
exactly as cited; last touched in #1564 (`838657aa3`), untouched by the
#4517-#4685 hardening range.
```go
ones, bits := n.Mask.Size()
hostCount = 1 << uint(bits-ones)
```

**Reachable with a valid, supported config.** IPv6 deterministic NAT is a
first-class, tested configuration: `deterministic_nat_flatset_3864_test.go:187`
commits `port deterministic host address 2001:db8::/32` on a `CGNAT64-POOL` and
asserts it "must commit clean (#3864)." So `Deterministic.HostAddress` legitimately
carries an IPv6 prefix.

**Real wrong output, confirmed empirically.** In Go, `1<<64` and `1<<96` on a
64-bit `int` are DEFINED to be 0 (I ran it: `1<<64=0`, `1<<80=0`, `1<<96=0`), not
undefined behaviour as the finding claims. The compiler constrains committed IPv6
det-NAT prefixes to /32 or /64 (`compiler_nat.go:926`), so `bits-ones` is 96 or 64
— both `>= 64` → `hostCount == 0`. The Prometheus info-gauge
`xpf_nat_pool_deterministic_info` therefore reports `host_count="0"` for every IPv6
det-NAT pool. (IPv4 is fine: max shift 32, `1<<32` fits int64.)

**Why it's LOW / cosmetic, and the finding's framing is off:**
  - It is a **metric LABEL** inaccuracy only. The gauge VALUE is always `1.0`; the
    wrong "0" appears in the 3rd label string. No crash (Go shift is defined, so no
    panic/DoS), no impact on NAT allocation, forwarding, or security.
  - The compiler already does the right thing for IPv6 — it never shifts by
    `128-ones`; it caps subscriber capacity by pool blocks (`totalBlocks`,
    `compiler_nat.go:929-940`). The metrics collector simply failed to mirror that
    IPv6-aware branch.
  - The finding's proposed fix (`math.MaxInt`) is itself wrong: 2^96 subscribers is
    nonsensical, and MaxInt is no more useful for planning than 0. The correct fix
    is to mirror the compiler — for `bits==128`, report the pool block/subscriber
    capacity, not `2^(128-ones)`.
  - Not in the dedup index (that lists a REST NAT-dest uint16 display truncation);
    novel, reachable, not-dup, not-fixed.

**Severity:** LOW (observability-only; ill-defined "correct" value; no functional
blast radius). Filed as the single genuine residual, with the caveat that the fix
should mirror `compiler_nat.go`'s IPv6 branch rather than the finding's MaxInt
suggestion. **Disposition: GENUINE-RESIDUAL (LOW).**

---

## Negative-results block (items #1-#113)

Pure coverage proof — each asserts an invariant holds and names no defect. Spot-
checked several against master (auth constant-time #4157, /metrics auth gate #4162,
body cap 16 MiB, exec `WaitDelay` 5s, session cursor bounds `len<13`/`len<37`,
fabric-auth ±1 window) — all consistent with current code. Nothing to triage; no
findings asserted.
