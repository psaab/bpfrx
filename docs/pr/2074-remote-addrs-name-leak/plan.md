# #2074 — renderConfig leaks the gateway NAME into swanctl remote_addrs

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

In `pkg/ipsec/policy.go` `renderConfig` (line 38), `remoteAddr` is
seeded from `vpn.Gateway` — the gateway *reference*. It is only
overwritten when the referenced gateway object exists in
`ipsecCfg.Gateways` AND that object carries a non-empty `Address`
(line 43) or `DynamicHostname` (line 45). When a VPN names a gateway
that

  (a) does not exist in `ipsecCfg.Gateways` (typo in
      `vpn ... ike gateway <name>`), or
  (b) exists but was committed with neither `address` nor
      `dynamic hostname`,

`remoteAddr` stays equal to the raw gateway-reference string and lines
73-75 emit `remote_addrs = <gateway-name>`. strongSwan then tries to
DNS-resolve a config-object name, the IKE SA never establishes, and the
operator gets no diagnostic — there is no IPsec cross-reference check at
commit time (`compiler_ipsec.go` returns no errors;
`schema_validators.go` has no gateway-reference validator). The tunnel
is silently dead.

## Honest scope / value framing

This is a correctness fix for a misconfiguration footgun, not a perf
change. The win: an operator who fat-fingers a gateway name (or omits
the gateway address) gets a loud apply-time error in the journal /
CLI stderr instead of a tunnel that comes up "configured" but never
passes traffic. Blast radius is one function (`renderConfig`) plus a
focused unit test. If reviewers conclude the change is wrong-shaped
(e.g. it should be a commit-time validator instead), PLAN-KILL /
PLAN-NEEDS-MAJOR is an acceptable verdict.

## Critical compatibility constraint (the legacy inline-gateway shape)

The existing tests (`ipsec_test.go` TestGenerateConfig_Basic line 14,
TestGenerateConfig_TrafficSelectors line 856, many others) set
`Gateway: "10.0.2.1"` — a **literal IP used directly as the gateway
field**, with NO entry in `ipsecCfg.Gateways`. Today that flows through
line 38 unchanged and correctly emits `remote_addrs = 10.0.2.1`. This
is a supported shape and MUST keep working. Likewise a literal hostname
(`Gateway: "peer.example.com"`) used inline is legitimate.

Therefore the fix must NOT blanket-reject "no Gateways-map entry". It
must distinguish:

| Case | `Gateways[vpn.Gateway]` | `vpn.Gateway` literal? | Today | Desired |
|------|------------------------|------------------------|-------|---------|
| 1. resolved gw, has Address | found, Address!="" | n/a | `remote_addrs=Address` | unchanged |
| 2. resolved gw, has DynamicHostname | found, DynHost!="" | n/a | `remote_addrs=DynHost` | unchanged |
| 3. inline literal IP/host | not found | yes (parses as IP or DNS-name) | `remote_addrs=<literal>` | unchanged |
| 4. dangling/typo name | not found | NO (not an IP, not a hostname) | `remote_addrs=<NAME>` (BUG) | error, no leak |
| 5. gw exists, addressless | found, both empty | NO | `remote_addrs=<NAME>` (BUG) | error, no leak |

Cases 4 and 5 are the bug. Cases 1-3 are preserved bit-for-bit.

## Why resolve-or-error (NOT fail-commit)

`renderConfig` already returns `error`. Its only real consumer is
`Manager.Apply` (`manager.go:67`), reached from:

- `pkg/daemon/daemon_apply.go:1054` — `slog.Warn("failed to apply IPsec
  config", ...)` (post-commit runtime apply).
- `pkg/cli/apply.go:161` — `fmt.Fprintf(os.Stderr, "warning: IPsec
  apply failed: %v\n", ...)`.

Both are POST-commit apply paths that only warn; neither aborts the
commit. There is no IPsec rendering on the commit/compile path. So:

- Returning an error from `renderConfig` for cases 4/5 turns the silent
  dead tunnel into a **visible apply-time warning** with the offending
  VPN + gateway named. That is a strict improvement and stays inside the
  issue's `pkg/ipsec/policy.go` target.
- True **fail-commit** would require a NEW cross-reference validator in
  `pkg/config` (schema_walk / compiler_ipsec) — a different file, a
  larger blast radius, and explicitly noted by the issue as absent
  today. That is deferred (see Out of scope) and could be a follow-up
  issue. The issue text permits "omit/skip with a clear error OR fail
  commit" — we choose the in-scope, already-plumbed error path.

The key invariant the issue demands either way: **a gateway NAME must
never be rendered into `remote_addrs`.** This plan guarantees that by
construction — the only strings that can reach `remote_addrs` are a
resolved gateway Address/DynamicHostname or a `vpn.Gateway` value that
is itself a syntactically valid IP or hostname.

## Concrete design

Replace the resolution block (current lines 37-51) with an explicit
resolver that yields either a usable remote address or an error.

```go
// Resolve the remote gateway endpoint. remote_addrs must be a real
// IP / hostname that strongSwan can use — never a bare gateway
// config-object name (#2074). A name that leaks here produces a
// silently-dead tunnel (strongSwan DNS-resolves the object name and
// the IKE SA never comes up).
localAddr := vpn.LocalAddr
var gw *config.IPsecGateway
remoteAddr := ""
if g, ok := ipsecCfg.Gateways[vpn.Gateway]; ok {
    gw = g
    switch {
    case gw.Address != "":
        remoteAddr = gw.Address
    case gw.DynamicHostname != "":
        remoteAddr = gw.DynamicHostname
    default:
        // Case 5: the gateway exists but has neither an address nor a
        // dynamic hostname. We have nothing routable to hand
        // strongSwan; do NOT fall back to the object name.
        return "", fmt.Errorf(
            "vpn %s: ike gateway %q has no address or dynamic-hostname; "+
                "cannot render remote_addrs", name, vpn.Gateway)
    }
    if gw.LocalAddress != "" && localAddr == "" {
        localAddr = gw.LocalAddress
    }
} else if isUsableRemoteEndpoint(vpn.Gateway) {
    // Case 3: legacy inline shape — the VPN names the peer endpoint
    // directly as a literal IP or hostname, with no Gateways entry.
    remoteAddr = vpn.Gateway
} else if vpn.Gateway != "" {
    // Case 4: dangling reference — a non-empty gateway value that is
    // neither a known gateway object nor a usable IP/hostname. Emitting
    // it as remote_addrs would leak the name.
    return "", fmt.Errorf(
        "vpn %s: ike gateway %q is not defined and is not a valid "+
            "address or hostname", name, vpn.Gateway)
}
// vpn.Gateway == "" with no map entry => remoteAddr stays "" and the
// existing `if remoteAddr != ""` guard at the emit site skips the line
// (unchanged behavior — some configs legitimately omit remote_addrs).
```

`isUsableRemoteEndpoint` — a small, local, allocation-light predicate:

```go
// isUsableRemoteEndpoint reports whether s is something strongSwan can
// place in remote_addrs directly: a literal IP address, or a plausible
// DNS hostname / FQDN. It deliberately REJECTS bare config-object
// names that contain none of the structure of a hostname (so a typo'd
// gateway reference is caught rather than DNS-probed forever). It is
// intentionally conservative on the accept side for IPs and permissive
// for hostnames, because a real hostname is operator-supplied and we
// must not break legitimate inline FQDN gateways.
func isUsableRemoteEndpoint(s string) bool {
    if s == "" {
        return false
    }
    if net.ParseIP(s) != nil {
        return true
    }
    return isPlausibleHostname(s)
}
```

The hostname predicate is the one design lever the reviewers should
attack hardest. Junos gateway object names and Junos hostnames overlap
in character set (both allow letters, digits, hyphens). A name like
`gw-to-hq` is a *valid Junos object name* AND a *syntactically valid
single-label hostname*. We cannot perfectly disambiguate by syntax
alone. Two candidate rules (decide in review):

- **Rule A (require a dot / FQDN-ish):** accept as a hostname only if
  it contains a `.` (so `peer.example.com` passes, `gw-to-hq` is
  rejected as a likely object-name typo). Pro: catches the common
  single-label typo. Con: rejects a legitimate inline single-label
  hostname (rare — operators almost always use an FQDN or IP for a VPN
  peer, and the single-label case has a clean migration: define a
  proper `gateway` with `address`/`dynamic hostname`).
- **Rule B (RFC-952/1123 label validity):** accept any string that is a
  syntactically valid hostname (each label 1-63 chars, alnum +
  internal hyphen, total ≤253). This accepts `gw-to-hq` — which means a
  typo'd object name that *happens* to be hostname-shaped still leaks
  (as a hostname, not an object name, but still a dead tunnel). It only
  catches names with illegal hostname chars (`/`, space, `_` if we
  forbid underscore, etc.).

**Plan recommendation: Rule A.** It is the only rule that actually
catches case (a) from the issue — a typo'd single-label gateway name —
while still passing every realistic inline gateway (IP or FQDN). The
existing tests all use literal IPs for the inline shape, so Rule A
breaks none of them. We document the single-label-hostname limitation
in the IPsec README and the error message guides the operator to the
fix (`set security ike gateway <name> address <ip>`).

This is an explicit OPEN QUESTION for reviewers — if both reviewers
prefer Rule B (or a fail-commit redesign), the plan changes.

## Public API preservation

- `renderConfig(*config.IPsecConfig) (string, error)` — signature
  unchanged.
- `generateConfig(*config.IPsecConfig) string` — signature unchanged.
  It already discards the error (`cfg, _ := m.renderConfig(...)`).
  IMPORTANT: on the new error paths `renderConfig` returns
  `("", err)`, so `generateConfig` now returns `""` for cases 4/5
  where it previously returned a (broken) config string. Callers of
  `generateConfig` are TEST-ONLY (`ipsec_test.go`) — no production
  caller. Verified by grep. Tests that exercise the legacy inline IP
  shape are unaffected (case 3).
- `Manager.Apply` behavior unchanged for valid configs; for cases 4/5
  it now returns the new error (previously wrote a broken file and
  reloaded). Both Apply call sites already handle a non-nil error
  (warn). This means: on a dangling/addressless gateway, the apply now
  leaves the PREVIOUS swanctl config in place (the atomic write is
  skipped because `renderConfig` errored before the write) rather than
  overwriting it with a config that names a dead peer. Strict
  improvement.

## Hidden invariants the change must preserve

1. **`gw` is consumed downstream** (lines 52, 57, 60-64, 78-91,
   103-116). For case 3 (inline literal) and case 4, `gw` stays `nil`
   exactly as today. For cases 1/2/5 `gw` is set as today. The early
   `return` on case 5 happens AFTER `gw` is set but that's fine — we
   never reach the downstream uses.
2. **`localAddr` fallback from `gw.LocalAddress`** (current line 48-50)
   only happens in the resolved-gateway branch — preserved.
3. **Empty-gateway VPNs** (`vpn.Gateway == ""`, no map entry) must
   still render with NO `remote_addrs` line, not an error. Handled: the
   final `else if vpn.Gateway != ""` guards the error so empty stays
   `remoteAddr == ""` → existing emit guard skips the line.
4. **No new allocations on the hot path** — render runs only on config
   apply (cold path), so this is not perf-sensitive, but the predicate
   is still allocation-light (no regexp; manual byte scan).
5. **sanitizeSwanctlValue is NOT applied to remote_addrs today** and we
   do not change that — an IP/hostname has no control chars; the
   predicate already rejects anything pathological.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Cases 1-3 bit-identical; only 4/5 change, and they were already broken. Test-only `generateConfig` callers. |
| Lifetime / borrow (N/A Go) | — | Go; no borrow checker. |
| Performance regression | NONE | Cold config-apply path only. |
| Architectural mismatch | LOW-MED | Risk is the hostname predicate rule (A vs B) and the resolve-vs-fail-commit axis. Surfaced as open questions; PLAN-KILL acceptable if reviewers want a commit-time validator instead. |

## Test plan (control-plane — NO dataplane smoke)

This is a swanctl-render change with no dataplane/forwarding impact, so
the triple-review smoke matrix (iperf3 / CoS / failover) does NOT
apply. Coverage is a focused, NON-TAUTOLOGICAL `pkg/ipsec` unit test
that FAILS against pre-fix code:

1. `go build ./...` clean.
2. New `TestRenderConfig_GatewayNameNeverLeaks`:
   - Sub-case resolved gw with Address → `remote_addrs = <IP>`, and
     assert the rendered output does NOT contain the gateway object
     name on a `remote_addrs` line.
   - Sub-case dangling/typo gateway name (no map entry, not an IP/host)
     → `renderConfig` returns a non-nil error AND (defensively) the
     returned string does not contain `remote_addrs = <name>`.
   - Sub-case gateway exists but addressless → non-nil error, no leak.
   - Sub-case legacy inline literal IP (case 3) → no error,
     `remote_addrs = <IP>` (guards against over-rejection).
   - Sub-case empty gateway → no error, no `remote_addrs` line.
   - Pre-fix proof: the dangling-name sub-case asserts the error; on
     unpatched code `renderConfig` returns nil error + a leaked name,
     so the test fails pre-fix (non-tautological).
3. Full `go test ./pkg/ipsec/...` green (existing 25+ render tests must
   still pass — proves cases 1-3 preserved).
4. `go test ./...` (or at least `./pkg/ipsec/... ./pkg/config/...`)
   green.

## Out of scope (explicitly)

- Commit-time / schema cross-reference validation of IPsec gateway
  references (would belong in `pkg/config/schema_walk.go` /
  `compiler_ipsec.go`). Tracked as a possible follow-up; the issue
  notes this layer is absent and does not require adding it here.
- Validating `gw.Address` / `gw.DynamicHostname` *content* (we trust
  the existing parser/schema for those leaves).
- Any change to the inline-literal-IP gateway shape beyond the
  guard.

## Open questions for adversarial review

1. **Hostname predicate Rule A vs Rule B** — is requiring a `.` for an
   inline hostname (Rule A) too aggressive? Does any real config use a
   bare single-label inline hostname as a VPN peer? If so Rule A breaks
   it. Defend or kill.
2. **Resolve-vs-fail-commit** — is returning a render error (warned,
   not commit-blocking) sufficient, or must this be a commit-time
   validator? The issue allows either; is the chosen in-scope path the
   right altitude?
3. **`generateConfig` now returns `""`** for cases 4/5. Confirm there is
   truly no non-test caller (I grepped; double-check) and that an empty
   string from `generateConfig` can never reach a production write path.
4. **Addressless-but-DPD/identity-only gateway (case 5)** — is there any
   legitimate strongSwan config where a connection has NO `remote_addrs`
   but the gateway object still carries IKE settings (e.g. responder-
   only / `%any` peer)? If yes, erroring on case 5 is wrong and we
   should instead emit no `remote_addrs` line (silent, but valid for a
   responder). This is the highest-risk question.
5. **Stale-config-on-error semantics** — on cases 4/5 the apply now
   skips the atomic write and leaves the prior swanctl config. Is
   "keep last good config + warn" the right failure mode, or should a
   broken VPN tear down ALL VPNs? (I argue keep-last-good is correct —
   one typo'd VPN shouldn't drop healthy tunnels.)
6. **Does `vpn.Gateway` ever legitimately hold a `%any`-style wildcard**
   that strongSwan accepts but `net.ParseIP`/hostname rejects? If so,
   Rule A/B both wrongly error. Check the parser.
