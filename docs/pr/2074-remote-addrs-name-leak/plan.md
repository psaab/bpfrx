# #2074 — renderConfig leaks the gateway NAME into swanctl remote_addrs

**Status:** DRAFT v2 — addresses round-1 hostile review (reviewer A
PLAN-NEEDS-MINOR, reviewer B PLAN-NEEDS-MAJOR). Both converged on the
whole-render-abort blast-radius defect; B escalated on altitude
(warn-only does not make `commit` fail). v2 adopts a **two-layer fix**:
a commit-time cross-reference validator (primary, loud at `commit`) plus
a **skip-and-continue** render-side belt (never zeroes healthy tunnels).

## Round-1 review resolution (what changed in v2)

- **R1 (both reviewers, blocking): whole-render abort.** v1 returned an
  error from inside the per-VPN loop, so one bad VPN aborted rendering
  of ALL VPNs — and on cold boot / first apply (no last-good file) that
  zeroes EVERY tunnel, strictly worse than the single-tunnel bug. v2
  changes the render path to **skip the offending VPN's connection block
  and continue**, rendering all healthy VPNs, then returns the rendered
  config plus a joined (non-fatal-to-other-VPNs) error so `Apply` still
  writes the good tunnels and still surfaces a warning.
- **R2 (reviewer B, blocking): altitude / does it actually fix the
  bug.** A post-commit `slog.Warn` leaves `commit` green on a dead
  tunnel. v2 adds the PRIMARY fix at commit time: a cross-reference
  validator in `pkg/config/compiler_ipsec.go` (the VPN loop already has
  both `VPNs` and `Gateways` in scope) that FAILS the commit when a VPN
  references a gateway that is neither a defined gateway object nor a
  usable inline IP/hostname. The operator now gets a loud `commit`
  error, directly answering the issue's "no diagnostic" complaint. The
  render-side guard remains as the by-construction belt.
- **R3 (reviewer B): Rule A false-positive on inline single-label
  hostname.** With the commit validator as the hard gate, the render
  guard's job is only "never emit a bare NAME" — and because the
  commit validator already rejects an unusable reference, a legit
  single-label inline hostname that resolves via the system resolver is
  no longer at risk of a *fatal* render abort (render skips+warns at
  most, and the commit validator uses the SAME predicate so the operator
  is told at commit). The predicate keeps Rule A (require a dot for a
  bare hostname) but the single-label limitation is now a *documented
  commit-check behavior*, not a silent render regression. Added table
  row 6.
- **R4 (reviewer B): non-tautological test fixture.** v2 pins the
  dangling-name fixture to benign PSK auth so `resolveIKESettings` /
  `normalizePSK` cannot error first, and adds a multi-VPN test
  (healthy + dangling) asserting the healthy VPN's `remote_addrs` IS
  rendered AND an error is returned — the regression guard for R1.
- **R5 (reviewer B): overstated invariant.** v1 Hidden-invariant #5
  wrongly claimed remote_addrs is "by construction" always a real
  IP/host — cases 1/2 pass `gw.Address`/`gw.DynamicHostname` through raw
  without the predicate. v2 states this honestly: content of a defined
  gateway's address/dynamic-hostname is trusted to the parser/schema
  (unchanged, out of scope); the guarantee is narrower and exact: *a
  bare gateway config-object NAME never reaches remote_addrs.*
- **Reviewer A: README deliverable + missing table rows + case-5
  comment.** All folded in (concrete deliverable below; rows 6-8 added;
  responder-only note added).
- **OQ4/OQ6 closed as not-applicable:** grep confirms NO `%any` /
  responder / wildcard concept anywhere in `pkg/ipsec/` or
  `compiler_ipsec.go`; `vpn.Gateway` is a single non-`multi` token
  (`schema_security.go`), so list/range/subnet forms cannot arrive
  inline. The case-5 error branch carries a comment that it forecloses a
  future responder-only peer.

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

Cases 4 and 5 are the bug. Cases 1-3 are preserved bit-for-bit. Two
more rows for completeness (reviewer A R-A8):

| Case | Description | Today | Desired |
|------|-------------|-------|---------|
| 6. inline single-label hostname | not found, dotless, not IP | `remote_addrs=<host>` (works iff resolver finds it) | commit-check rejects (Rule A); render skips+warns. Migration: define a `gateway` with `address`/`dynamic hostname`. |
| 7. defined gw, Address is itself an FQDN | found, Address="peer.ex.com" | `remote_addrs=peer.ex.com` | unchanged — Case-1 passthrough, content NOT re-validated |
| 8. gw object NAMED like an IP, referenced | found (map key="10.0.2.1") | map lookup wins → uses object's Address | unchanged — map precedence over literal |

Case 6 is the only behavior change for a *currently-working* config
(a bare single-label hostname resolvable via DNS search / `/etc/hosts`).
That is rare for a VPN peer, is now a loud `commit` error with a clear
migration, and is documented in the README. Rows 7/8 are unchanged
passthroughs called out so the implementer does not "fix" them.

## Decision: two-layer fix (commit-validator PRIMARY + render belt)

Round-1 reviewer B correctly argued that a render-only warning leaves
`commit` reporting success on a dead tunnel — relocating the diagnostic
to the journal, not removing it. So the issue's "operator gets no
diagnostic" complaint is answered at the COMMIT layer:

**Layer 1 — commit-time validator (primary, hard gate).**
`compileIPsec` (`compiler_ipsec.go:185-382`) parses both `ike { gateway
}` (via `compileIKE`, run first per `compiler_security.go:39-44`) and
`ipsec { gateway }` and the VPNs, all into `sec.IPsec.Gateways` /
`sec.IPsec.VPNs`. At the END of `compileIPsec` (after the VPN loop,
line 378 — both gateway sections are populated by then), add a
cross-reference pass: for each VPN with a non-empty `Gateway`, if it is
neither a key in `sec.IPsec.Gateways` NOR a usable inline IP/hostname,
return an error → `compileSecurity` wraps it → `Compile` returns it →
**`commit` fails** with a clear message naming the VPN and gateway.
`commit check` catches it too (same compile path). This is the loud,
correct-altitude fix.

Verified safe against existing tests: `parser_security_test.go` commits
`vpn site-a gateway 10.1.0.1` (inline IP — passes), `vpn site-b gateway
10.2.0.1` (inline IP — passes), and `vpn ... gateway remote-gw` with a
defined `gateway remote-gw address 203.0.113.1` (defined object —
passes). No existing committed config references a dangling/addressless
gateway, so none breaks.

**Layer 2 — render-side belt (defense-in-depth, skip-and-continue).**
`renderConfig` is the last line. Even though Layer 1 makes the bad
config un-committable, the render guard guarantees BY CONSTRUCTION that
a bare gateway NAME can never reach `remote_addrs` — covering any future
path that reaches render without the compile gate (HA config sync,
direct `IPsecConfig` construction, tests). Crucially, per R1, the render
guard does NOT abort the whole file: it **skips the offending VPN's
connection block, continues rendering the healthy VPNs**, and returns
the rendered config plus a joined error. So one bad VPN never zeroes
healthy tunnels on cold boot.

`renderConfig`'s error consumers are both POST-commit apply paths that
only warn (`daemon_apply.go:1054` slog.Warn; `cli/apply.go:161`
stderr) — so Layer 2's returned error is informational; the rendered
(healthy-VPNs) config is still written by `Apply`.

**The exact guarantee:** *a bare gateway config-object NAME never
reaches `remote_addrs`* (Layer 2, by construction) AND *a config that
would produce one is rejected at `commit`* (Layer 1). The CONTENT of a
defined gateway's `address` / `dynamic hostname` is trusted to the
existing parser/schema (unchanged, out of scope) — the guarantee is
specifically about the gateway-NAME leak, which is exactly the bug.

## Concrete design

### Layer 2 — render (`pkg/ipsec/policy.go`), skip-and-continue

A shared resolver returns either a usable remote address or an error.
The per-VPN loop, on a resolver error, records the error, `continue`s
(skips that connection block), and renders the rest. After the loop,
`renderConfig` returns the rendered config and the joined error.

```go
func resolveRemoteAddr(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN,
    name string) (remoteAddr, localAddr string, gw *config.IPsecGateway, err error) {

    localAddr = vpn.LocalAddr
    if g, ok := ipsecCfg.Gateways[vpn.Gateway]; ok {
        gw = g
        switch {
        case gw.Address != "":
            remoteAddr = gw.Address
        case gw.DynamicHostname != "":
            remoteAddr = gw.DynamicHostname
        default:
            // Case 5: gateway exists but has neither an address nor a
            // dynamic hostname — nothing routable. Do NOT fall back to
            // the object name. (Forecloses a future responder-only /
            // %any peer that legitimately omits remote_addrs; revisit
            // this branch if/when that is added — no such concept
            // exists in the parser today.)
            return "", localAddr, gw, fmt.Errorf(
                "ike gateway %q has no address or dynamic-hostname",
                vpn.Gateway)
        }
        if gw.LocalAddress != "" && localAddr == "" {
            localAddr = gw.LocalAddress
        }
        return remoteAddr, localAddr, gw, nil
    }
    if isUsableRemoteEndpoint(vpn.Gateway) {
        // Case 3: legacy inline shape — peer endpoint named directly as
        // a literal IP or (dotted) hostname, no Gateways entry.
        return vpn.Gateway, localAddr, nil, nil
    }
    if vpn.Gateway != "" {
        // Case 4/6: dangling reference / dotless single-label name that
        // is neither a known gateway nor a usable IP/hostname. Emitting
        // it as remote_addrs would leak the name.
        return "", localAddr, nil, fmt.Errorf(
            "ike gateway %q is not defined and is not a valid address "+
                "or hostname", vpn.Gateway)
    }
    // vpn.Gateway == "" with no map entry => remoteAddr "" => the
    // existing `if remoteAddr != ""` emit guard skips the line.
    return "", localAddr, nil, nil
}
```

Loop integration (replacing current lines 37-51), skip-and-continue:

```go
var renderErrs []error
for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
    vpn := ipsecCfg.VPNs[name]
    remoteAddr, localAddr, gw, rerr := resolveRemoteAddr(ipsecCfg, vpn, name)
    if rerr != nil {
        // Skip ONLY this VPN's connection block; keep rendering the
        // rest so one typo never zeroes healthy tunnels (#2074 R1).
        renderErrs = append(renderErrs, fmt.Errorf("vpn %s: %w", name, rerr))
        continue
    }
    fmt.Fprintf(&b, "  %s {\n", sanitizeSwanctlValue(name))
    ... // unchanged emit body, using remoteAddr/localAddr/gw
}
...
// after building secrets:
return b.String(), errors.Join(renderErrs...)
```

`errors.Join(nil...)` is `nil`, so the no-error path is unchanged.
The secrets loop also skips a VPN whose render errored (it would be
harmless to emit secrets for a skipped connection, but skipping keeps
the output minimal and avoids a dangling `ike-<name>` secret).

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

**Decision: Rule A.** It is the only rule that catches case (a) from the
issue — a typo'd single-label gateway name — while passing every
realistic inline gateway (IP or FQDN). Every existing test uses a
literal IP for the inline shape, so Rule A breaks none of them. With the
commit validator (Layer 1) as the hard gate using the SAME predicate,
the single-label-inline-hostname limitation is a *documented commit-check
behavior* with a clear migration (`set security ike gateway <name>
address <ip>`), not a silent render regression. `isPlausibleHostname` is
a manual byte scan (no regexp): non-empty, contains a `.`, every label
1-63 alnum + internal hyphen, total ≤253.

### Layer 1 — commit validator (`pkg/config/compiler_ipsec.go`)

At the end of `compileIPsec` (after the VPN loop, current line 378 —
both `ike{gateway}` and `ipsec{gateway}` sections are populated by then;
`compileIKE` runs first), add:

```go
// #2074: a VPN that references a gateway which is neither a defined
// gateway object nor a usable inline IP/hostname would render
// `remote_addrs = <gateway-name>` — a config-object name strongSwan
// can't use, producing a silently-dead tunnel. Reject it at commit so
// the operator gets a diagnostic instead of a dead tunnel.
for _, vpn := range sec.IPsec.VPNs {
    if vpn.Gateway == "" {
        continue
    }
    if _, ok := sec.IPsec.Gateways[vpn.Gateway]; ok {
        continue // resolves to a defined gateway object
    }
    if isUsableRemoteEndpoint(vpn.Gateway) {
        continue // legacy inline literal IP / dotted hostname
    }
    return fmt.Errorf("vpn %s: ike gateway %q is not defined and is "+
        "not a valid address or hostname", vpn.Name, vpn.Gateway)
}
```

The predicate `isUsableRemoteEndpoint` lives in `pkg/ipsec` but the
validator runs in `pkg/config`, and **`pkg/config` must not import
`pkg/ipsec`** (ipsec already imports config — an import cycle). So the
predicate is defined in `pkg/config` (e.g. `isUsableIPsecEndpoint` in
`compiler_ipsec.go`) and `pkg/ipsec` either re-implements the identical
two-line predicate locally or calls the exported `config` helper. Plan
choice: define `config.IsUsableIPsecEndpoint` (exported) once in
`pkg/config` and have `pkg/ipsec` call it — single source of truth, no
cycle (ipsec→config is the existing, allowed direction). This is the one
implementation detail to get right; flagged for review.

Iteration order: the validator iterates a map, so error ORDER is
non-deterministic across multiple bad VPNs. For a deterministic error
(stable tests / operator experience), sort VPN names first
(`sortedVPNNames`-style) and return the first failure. Plan: sort, then
validate.

Does the addressless-gateway case (case 5) belong in Layer 1 too? Yes:
extend the validator to also reject a VPN whose referenced gateway
object exists but has neither `Address` nor `DynamicHostname`. Same
loop, after the `ok` check: `if gw.Address=="" && gw.DynamicHostname==""
{ return err }`. This makes BOTH leak cases (4 and 5) un-committable.

## Public API preservation

- `renderConfig(*config.IPsecConfig) (string, error)` — signature
  unchanged. Semantics: now returns the rendered config for the HEALTHY
  VPNs plus a joined error naming any skipped VPNs (was: a single fatal
  error aborting the whole file — the R1 defect).
- `generateConfig(*config.IPsecConfig) string` — signature unchanged.
  It discards the error. With skip-and-continue it now returns the
  healthy-VPN config (NOT `""`) even when one VPN is malformed — strictly
  better than v1's `""`. Callers are TEST-ONLY (`ipsec_test.go`); no
  production caller. Verified by grep.
- `Manager.Apply` — for a fully-valid config: unchanged. For a config
  with one bad VPN reaching render (only possible via a path that
  bypasses the commit validator, e.g. HA sync / direct construction):
  it writes the healthy-VPN config AND returns the joined error, which
  both call sites warn. Healthy tunnels stay up; the bad one is omitted
  with a logged reason. No cold-boot zero-tunnels regression.
- New exported `config.IsUsableIPsecEndpoint(string) bool` — additive,
  no existing symbol changed.

## Hidden invariants the change must preserve

1. **`gw` is consumed downstream** (lines 52, 57, 60-64, 78-91,
   103-116). For case 3 (inline literal) `gw` stays `nil` as today.
   For cases 1/2 `gw` is set as today and the connection is rendered.
   For cases 4/5/6 the VPN is SKIPPED before any downstream use of `gw`
   (the `continue`), so no downstream `gw` access happens for a skipped
   VPN — correct.
2. **`localAddr` fallback from `gw.LocalAddress`** only happens in the
   resolved-gateway branch (cases 1/2) — preserved inside the resolver.
3. **Empty-gateway VPNs** (`vpn.Gateway == ""`, no map entry) still
   render with NO `remote_addrs` line and NO error — the resolver
   returns `("","",nil,nil)`, the connection IS emitted, and the
   existing `if remoteAddr != ""` emit guard skips only the line.
4. **No new hot-path allocations** — render + compile run only on config
   apply / commit (cold path). The predicate is allocation-light (no
   regexp; manual byte scan). `errors.Join` allocates only when there
   ARE errors.
5. **Exact guarantee (corrected from v1's overstated claim):** a bare
   gateway config-object NAME never reaches `remote_addrs`. The CONTENT
   of a *defined* gateway's `Address` / `DynamicHostname` (cases 1/2) is
   passed through raw and is NOT re-validated — that is unchanged,
   trusted to the parser/schema, and explicitly out of scope.
   `sanitizeSwanctlValue` is still not applied to `remote_addrs`
   (unchanged); an IP/dotted-hostname has no control chars and the
   predicate rejects anything that is neither.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Cases 1-3,7,8 bit-identical; only the already-broken leak cases (4/5/6) change. generateConfig now returns MORE (healthy config) not less. |
| Import cycle | LOW | Predicate lives in `pkg/config` (exported), called from `pkg/ipsec` (ipsec→config is the existing allowed direction). Explicitly verified at build. |
| Cold-boot / first-apply | RESOLVED | Skip-and-continue means a bad VPN never zeroes healthy tunnels — the R1 defect is fixed. |
| Performance regression | NONE | Cold config-apply / commit path only. |
| Architectural mismatch | LOW | Commit-validator is the right altitude (loud at `commit`); render guard is defense-in-depth. |

## Test plan (control-plane — NO dataplane smoke)

A swanctl-render + config-compile change with no dataplane/forwarding
impact, so the iperf3 / CoS / failover smoke matrix does NOT apply.
Coverage is focused, NON-TAUTOLOGICAL unit tests that FAIL pre-fix:

1. `go build ./...` clean (verifies no import cycle).
2. `pkg/ipsec` render tests — new `TestRenderConfig_GatewayNameNeverLeaks`:
   - resolved gw with Address → `remote_addrs = <IP>`, and assert the
     output does NOT contain the gateway object name on a `remote_addrs`
     line.
   - dangling/typo name (no map entry, not IP/host) → `renderConfig`
     returns non-nil error AND the returned string contains NO
     `remote_addrs = <name>` line. Fixture uses benign PSK auth (no
     bogus auth-method) so `resolveIKESettings`/`normalizePSK` cannot
     error first — guarantees the assertion targets the leak path, not a
     pre-existing error (R4).
   - addressless gw (exists, no Address/DynamicHostname) → non-nil
     error, no leak.
   - dotless single-label name (case 6) → non-nil error, no leak.
   - legacy inline literal IP (case 3) → no error, `remote_addrs = <IP>`
     (over-rejection guard).
   - dotted inline hostname (case 3 FQDN) → no error,
     `remote_addrs = peer.example.com`.
   - empty gateway → no error, no `remote_addrs` line, connection still
     emitted.
   - **multi-VPN skip-and-continue (R1 regression guard):** one healthy
     VPN + one dangling VPN → assert the HEALTHY VPN's `remote_addrs`
     IS present in the output AND a non-nil error is returned AND the
     dangling name does NOT appear in `remote_addrs`. On unpatched code
     v1-style would have aborted the whole file → this proves the
     skip-and-continue behavior.
   - Pre-fix proof: every error-asserting sub-case fails on unpatched
     code (which returns nil error + leaked name).
3. `pkg/config` compile tests — new `TestCompileIPsec_DanglingGatewayRejected`:
   - VPN referencing an undefined gateway name → `Compile`/`compileIPsec`
     returns a non-nil error (commit fails). Fails pre-fix.
   - VPN referencing a gateway object with no address → error.
   - VPN with inline literal IP gateway (no object) → NO error (case 3;
     mirrors `parser_security_test.go` `vpn site-a gateway 10.1.0.1`).
   - VPN referencing a defined gateway with an address → NO error.
4. Full `go test ./pkg/ipsec/... ./pkg/config/...` green (existing 25+
   render tests + all parser/compiler tests must still pass — proves
   cases 1-3,7,8 preserved and no committed-config regression).
5. `go test ./...` green (or the affected packages + their importers).

## Documentation deliverable (project docs-contract)

`pkg/ipsec/README.md` updated (concrete, not a passing mention):
- The **never-leak invariant**: a gateway config-object NAME never
  reaches `remote_addrs`.
- The **commit-time rejection**: a VPN referencing an undefined or
  addressless gateway now fails `commit`/`commit check`.
- The **Rule-A single-label-inline-hostname limitation** + migration
  (`set security ike gateway <name> address <ip>` or `dynamic hostname
  <fqdn>`).
- The **render-side keep-healthy/skip-bad** behavior for paths that
  bypass commit (HA sync / direct construction).

## Out of scope (explicitly)

- Validating `gw.Address` / `gw.DynamicHostname` *content* (trusted to
  the existing parser/schema for those leaves).
- Schema-layer (`schema_walk.go`) validation — the commit gate lives in
  the compiler (`compileIPsec`), which is sufficient and is where the
  cross-reference data is already assembled.
- Any change to the inline-literal-IP gateway shape beyond the guard.
- Responder-only / `%any` peer support (no such concept exists today;
  the case-5 branch carries a comment to revisit if it is added).

## Open questions for adversarial review (v2)

1. **Predicate location / import cycle** — defining
   `config.IsUsableIPsecEndpoint` and calling it from `pkg/ipsec` keeps
   one SSOT and respects ipsec→config. Confirm no cycle and that this is
   the cleanest placement (vs duplicating the 2-line predicate).
2. **Commit-validator placement** — end of `compileIPsec` (after the VPN
   loop). Confirm both `ike{gateway}` and `ipsec{gateway}` sections are
   fully populated at that point (compileIKE runs before compileIPsec per
   `compiler_security.go:39-44`; both write `sec.IPsec.Gateways`). Any
   ordering hazard?
3. **Does committing the validator break ANY existing test config?**
   Reviewers should independently grep `parser_*_test.go` /
   `compiler_*_test.go` for VPN gateway references and confirm all
   resolve to a defined gateway or an inline IP (I found
   `10.1.0.1`/`10.2.0.1`/`remote-gw` — all pass).
4. **Skip-and-continue secrets** — when a VPN is skipped in the
   connections loop, its `secrets{}` entry should also be skipped.
   Confirm the secrets loop is gated by the same skip set (the plan skips
   it). Any case where a secret is still needed for a skipped conn? (No
   — no connection, no SA.)
5. **`errors.Join` import + nil semantics** — `errors.Join()` with no
   args / all-nil returns nil. Confirm the no-error path is byte-identical
   (existing tests using `generateConfig`/`renderConfig` see nil error).
6. **Is rejecting case 5 at commit ever wrong?** Confirmed no
   responder-only/`%any` concept exists in the parser today; the branch
   is commented to revisit. Reviewers: re-verify by grep.
