# #2074 — renderConfig leaks the gateway NAME into swanctl remote_addrs

**Status:** PLAN-READY (v3) — round-3 hostile review returned PLAN-READY
from both independent reviewers (the two round-2 PLAN-NEEDS-MAJOR
blockers verified fixed against source; only minor prose/import-precision
folded in: validator edits `compileExpanded`, add `log/slog` to
policy.go). Addresses round-2 hostile review (both reviewers
PLAN-NEEDS-MAJOR). Round-2 found two source-confirmed blocking defects in
v2: (1) `Manager.Apply` bails on a render error BEFORE the write, so v2's
"return (healthyConfig, joinedErr)" discards the healthy config and the
skip-and-continue belt is inert; (2) v2 placed the commit validator
inside `compileIPsec` with a hard `return`, which (a) depends on
`ike`-before-`ipsec` stanza order (false — `compileSecurity` iterates in
document order) and (b) runs on the LENIENT load/peer-sync path too,
breaking boot of a pre-fix/peer-synced dangling-gateway config
(fail-closed-on-load, the #1960 regression class).

v3's corrected two-layer design:
- **Layer 1** is a strict-accumulator validator
  `validateIPsecGatewayReferencesStrict(cfg)` operating on the
  FULLY-COMPILED `*Config` (both `ike{}` and `ipsec{}` gateways
  populated, stanza-order-independent), with a `lenientIPsecGatewayRefs`
  downgrade — EXACTLY the `validateDeviceMapStrict` (#1956) /
  `validatePolicyMatchAddressesStrict` (#2008) template. Strict on
  commit/commit-check; warns on load/peer-sync.
- **Layer 2** is the MINIMAL render belt (reviewer B point 5): on a leak
  case `renderConfig` **skips that VPN's connection block, `slog.Warn`s,
  and continues** — it does NOT add a new error return, so the unchanged
  `Apply` writes the healthy config. No `Apply` rewrite, no `errors.Join`,
  no skip-set-for-error needed. By construction a bare NAME never reaches
  `remote_addrs`, and healthy tunnels are never zeroed.

## Round-2 review resolution (what changed in v3)

- **R2-1 (both, blocking): Apply discards healthy config on render
  error.** `manager.go:67-70` does `if err != nil { return err }` before
  `WriteFileAtomic`. v3 sidesteps this entirely: the render belt no
  longer RETURNS an error for the gateway-leak cases — it skips the bad
  VPN, `slog.Warn`s, and continues. `renderConfig`'s error return is
  reserved for its existing reasons (auth method, PSK decode) only. So
  `Apply` is UNCHANGED, always writes the healthy config, and never
  zeroes healthy tunnels. (We considered "write-then-warn in Apply" but
  the skip-and-log render belt is simpler and needs no signature/Apply
  churn.)
- **R2-2 (both, blocking): Layer-1 ordering + lenient-path break.** v3
  moves the validator OUT of `compileIPsec` to a strict-accumulator-style
  pass on the fully-compiled `*Config` (after `compileSecurity`
  returns, where `cfg.Security.IPsec.Gateways` holds BOTH `ike{}` and
  `ipsec{}` gateways regardless of authoring order), and gates it with
  `opts.lenientIPsecGatewayRefs` so the lenient load/peer-sync paths
  (`CompileConfigLenient`, `CompileConfigForNodeLenient`) WARN instead of
  failing to boot. Mirrors `validateDeviceMapStrict` (#1956) exactly.
- **R2-3: secrets-loop skip** — with the minimal belt, the connections
  loop builds a `skipped map[string]bool`; the secrets loop consults it
  so a skipped connection emits no orphan secret. Concrete, not prose.
- **R2-4: errors import** — no longer needed (no `errors.Join` in the
  minimal belt). Dropped.
- **R2-5: Layer-2 complexity** — adopted reviewer B's minimal belt.

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

### Layer 2 — render belt (`pkg/ipsec/policy.go`), minimal skip-and-log

A resolver classifies the gateway. On a leak case (4/5/6) it returns
`ok=false`; the connections loop SKIPS that VPN, records it in a
`skipped` set, `slog.Warn`s, and continues. `renderConfig` returns NO
new error (its existing error return — auth method, PSK decode — is
untouched), so the unchanged `Apply` writes the healthy config.

```go
// resolveRemoteAddr returns the swanctl remote_addrs value (a real
// IP / dotted hostname) for a VPN, plus the resolved local addr and
// gateway. ok=false means there is nothing usable to render — the
// caller MUST skip the connection so a bare gateway config-object NAME
// never leaks into remote_addrs (#2074). The hard diagnostic is the
// commit-time validator (Layer 1); this is the by-construction belt for
// any path that reaches render without passing local commit (HA sync /
// direct construction / a config committed before this fix).
func resolveRemoteAddr(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN) (
    remoteAddr, localAddr string, gw *config.IPsecGateway, ok bool) {

    localAddr = vpn.LocalAddr
    if g, found := ipsecCfg.Gateways[vpn.Gateway]; found {
        gw = g
        switch {
        case gw.Address != "":
            remoteAddr = gw.Address
        case gw.DynamicHostname != "":
            remoteAddr = gw.DynamicHostname
        default:
            // Case 5: gateway exists but addressless. (Forecloses a
            // future responder-only / %any peer that legitimately omits
            // remote_addrs; no such concept in the parser today —
            // revisit if added.)
            return "", localAddr, gw, false
        }
        if gw.LocalAddress != "" && localAddr == "" {
            localAddr = gw.LocalAddress
        }
        return remoteAddr, localAddr, gw, true
    }
    if config.IsUsableIPsecEndpoint(vpn.Gateway) {
        return vpn.Gateway, localAddr, nil, true // Case 3: inline IP/FQDN
    }
    if vpn.Gateway == "" {
        // Empty gateway: emit the connection with NO remote_addrs line
        // (unchanged behavior — some configs legitimately omit it).
        return "", localAddr, nil, true
    }
    // Case 4/6: dangling / dotless name — not renderable.
    return "", localAddr, nil, false
}
```

Connections loop (replacing current lines 33-51 head):

```go
skipped := make(map[string]bool)
for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
    vpn := ipsecCfg.VPNs[name]
    remoteAddr, localAddr, gw, ok := resolveRemoteAddr(ipsecCfg, vpn)
    if !ok {
        skipped[name] = true
        slog.Warn("skipping IPsec VPN: gateway not renderable "+
            "(undefined or addressless) — fix the ike gateway reference",
            "vpn", name, "gateway", vpn.Gateway)
        continue
    }
    fmt.Fprintf(&b, "  %s {\n", sanitizeSwanctlValue(name))
    ... // unchanged emit body, using remoteAddr/localAddr/gw
}
```

Secrets loop consults `skipped` (real code is a separate loop):

```go
for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
    if skipped[name] {
        continue // no connection => no orphan ike-<name> secret
    }
    ... // unchanged secret emission
}
```

`renderConfig`'s signature and existing error returns are UNCHANGED;
no `errors.Join`, no new error path, no `Apply` change. The no-skip path
is byte-identical to today (empty `skipped`, every `ok==true`).

`IsUsableIPsecEndpoint` — exported from `pkg/config` (so the SAME
predicate backs Layer 1 and Layer 2 with no import cycle), a small
allocation-light predicate:

```go
// IsUsableIPsecEndpoint reports whether s is something strongSwan can
// place in remote_addrs directly: a literal IP address, or a plausible
// dotted DNS hostname / FQDN. It deliberately REJECTS bare config-object
// names with no hostname structure (so a typo'd gateway reference is
// caught, not DNS-probed forever). Lives in pkg/config so both the
// commit validator (pkg/config) and the render belt (pkg/ipsec, which
// imports config) share one SSOT — no import cycle.
func IsUsableIPsecEndpoint(s string) bool {
    if s == "" {
        return false
    }
    if net.ParseIP(s) != nil {
        return true
    }
    return isPlausibleHostname(s) // Rule A: requires a dot
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
address <ip>`), not a silent render regression. `isPlausibleHostname`
(unexported, in `pkg/config`) is a manual byte scan (no regexp):
non-empty, contains a `.`, every label 1-63 alnum + internal hyphen,
total ≤253.

### Layer 1 — commit validator (strict-accumulator, `pkg/config`)

Do NOT place the check inside `compileIPsec` (round-2 R2-2: stanza order
+ lenient-path break). Instead add a validator on the FULLY-COMPILED
`*Config`, slotted into the existing strict-validator chain in
**`compileExpanded`** (`compiler.go:277`, NOT the outer
`compileConfigWithOpts`/`compileConfigForNodeWithOpts` — both of those
call `compileExpanded(tree, opts)` with the threaded opts, so editing
`compileExpanded` makes the validator fire on standalone AND node-aware
commits and honor the lenient flag on `SyncApply`), right after
`validateDeviceMapStrict` (`compiler.go:549`) /
`validatePolicyMatchAddressesStrict` / `ValidateEventAttributesMatch` —
the exact `validateDeviceMapStrict` (#1956) / `#2008` template:

```go
// #2074: an IPsec VPN that references a gateway which is neither a
// defined gateway object nor a usable inline IP/hostname would render
// `remote_addrs = <gateway-name>` — a config-object name strongSwan
// cannot use, a silently-dead tunnel. Strict on commit/commit-check;
// lenient on load/peer-sync so a pre-fix or peer-synced config that
// carries such a VPN still BOOTS (warn, don't fail-closed-on-load —
// #1960 class). Runs on the fully-compiled *Config so both ike{} and
// ipsec{} gateways are populated regardless of stanza order.
if err := validateIPsecGatewayReferencesStrict(cfg); err != nil {
    if opts.lenientIPsecGatewayRefs {
        cfg.Warnings = append(cfg.Warnings,
            fmt.Sprintf("ipsec gateway reference (downgraded to warning "+
                "on tolerant path): %v", err))
    } else {
        return nil, err
    }
}
```

```go
func validateIPsecGatewayReferencesStrict(cfg *Config) error {
    ipsec := &cfg.Security.IPsec
    names := make([]string, 0, len(ipsec.VPNs)) // sort for deterministic error
    for name := range ipsec.VPNs {
        names = append(names, name)
    }
    sort.Strings(names)
    for _, name := range names {
        vpn := ipsec.VPNs[name]
        if vpn.Gateway == "" {
            continue // legitimately omitted remote endpoint
        }
        if gw, ok := ipsec.Gateways[vpn.Gateway]; ok {
            if gw.Address == "" && gw.DynamicHostname == "" {
                return fmt.Errorf("security ipsec vpn %s: ike gateway %q "+
                    "has no address or dynamic hostname", name, vpn.Gateway)
            }
            continue // resolves to a defined, addressed gateway
        }
        if IsUsableIPsecEndpoint(vpn.Gateway) {
            continue // legacy inline literal IP / dotted hostname
        }
        return fmt.Errorf("security ipsec vpn %s: ike gateway %q is not "+
            "defined and is not a valid address or hostname",
            name, vpn.Gateway)
    }
    return nil
}
```

`opts.lenientIPsecGatewayRefs` is added to `compileOpts` and set
`true` in BOTH `CompileConfigLenient` and `CompileConfigForNodeLenient`
(alongside `lenientDeviceMap` etc.). Commit / commit-check
(`CompileConfig` / `CompileConfigForNode`) leave it `false` → hard
reject. This rejects BOTH leak cases (4 dangling, 5 addressless) at
commit, and boots a pre-fix/peer-synced config with a warning.

## Public API preservation

- `renderConfig(*config.IPsecConfig) (string, error)` — signature AND
  error semantics UNCHANGED. It returns the rendered config for the
  HEALTHY VPNs; a leak-case VPN is silently skipped (with a `slog.Warn`),
  NOT turned into a returned error. The error return remains reserved for
  its existing causes (auth method, PSK decode). This is the key R2-1
  fix: because `renderConfig` does not error on the leak case, the
  unchanged `Apply` writes the healthy config (it never reaches its
  `if err != nil { return err }` guard for the leak case).
- `generateConfig(*config.IPsecConfig) string` — unchanged; returns the
  healthy-VPN config. Callers are TEST-ONLY (`ipsec_test.go`); verified.
- `Manager.Apply` — UNCHANGED (no edit). Fully-valid config: identical.
  A bad VPN reaching render (only via a path that bypassed local commit:
  HA sync / direct construction / pre-fix config): the connection is
  omitted, a warning is logged, the healthy config is written and
  reloaded. No cold-boot zero-tunnels regression.
- `compileOpts` — additive `lenientIPsecGatewayRefs bool` field; set in
  the two lenient entry points. No existing field changed.
- New exported `config.IsUsableIPsecEndpoint(string) bool` and new
  unexported `validateIPsecGatewayReferencesStrict` / `isPlausibleHostname`
  — additive.
- `pkg/ipsec/policy.go` MUST add `"log/slog"` to its import block for the
  belt's `slog.Warn` (currently imports only fmt/net/sort/strconv/strings
  + config; `slog` is used elsewhere in the package but each file imports
  its own). `go build` (test-plan item 1) catches an omission.

## Hidden invariants the change must preserve

1. **`gw` is consumed downstream** (policy.go 52, 57, 60-64, 78-91,
   103-116). For case 3 (inline literal) `gw` stays `nil` as today.
   For cases 1/2 `gw` is set as today and the connection is rendered.
   For cases 4/5/6 the VPN is SKIPPED (the `continue`) before any
   downstream use of `gw` — no downstream `gw` access for a skipped VPN.
2. **`localAddr` fallback from `gw.LocalAddress`** only in the
   resolved-gateway branch (cases 1/2) — preserved inside the resolver.
3. **Empty-gateway VPNs** (`vpn.Gateway == ""`, no map entry) still
   render WITH the connection block and NO `remote_addrs` line and NO
   error — the resolver returns `("",localAddr,nil,true)`, so the
   connection IS emitted and the existing `if remoteAddr != ""` emit
   guard skips only the line. (Verify: this exact shape exists in
   `ipsec_test.go` — VPNs with no gateway, e.g. cert/TS-only configs.)
4. **No new hot-path allocations** — render + compile run only on config
   apply / commit (cold path). Predicate is allocation-light (no regexp;
   manual byte scan). `skipped` map allocates one small map per render.
5. **Exact guarantee (corrected from v1's overstated claim):** a bare
   gateway config-object NAME never reaches `remote_addrs`. The CONTENT
   of a *defined* gateway's `Address` / `DynamicHostname` (cases 1/2) is
   passed through raw and is NOT re-validated — unchanged, trusted to the
   parser/schema, out of scope. `sanitizeSwanctlValue` is still not
   applied to `remote_addrs` (unchanged).
6. **Lenient compile MUST still boot** a config carrying a leak-case VPN
   (pre-fix persisted / peer-synced) — `lenientIPsecGatewayRefs` warns,
   does not fail. This is the R2-2 fix (avoids #1960 fail-closed-on-load).

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Cases 1-3,7,8 bit-identical; only the already-broken leak cases (4/5/6) change. renderConfig error semantics unchanged. |
| Import cycle | LOW | Predicate in `pkg/config` (exported), called from `pkg/ipsec` (ipsec→config is the existing allowed direction). Verified at build. |
| Cold-boot / first-apply zero-tunnels | RESOLVED | renderConfig does NOT error on the leak case → Apply writes the healthy config. The R2-1 defect is fixed by construction. |
| Lenient load fail-closed (#1960 class) | RESOLVED | `lenientIPsecGatewayRefs` downgrades to a warning on load/peer-sync. The R2-2 defect is fixed. |
| Stanza-order false-reject | RESOLVED | Validator runs on the fully-compiled `*Config`, not inside `compileIPsec` — order-independent. |
| Performance regression | NONE | Cold config-apply / commit path only. |

## Test plan (control-plane — NO dataplane smoke)

A swanctl-render + config-compile change with no dataplane/forwarding
impact, so the iperf3 / CoS / failover smoke matrix does NOT apply.
Coverage is focused, NON-TAUTOLOGICAL unit tests that FAIL pre-fix:

1. `go build ./...` clean (verifies no import cycle).
2. `pkg/ipsec` render tests — new `TestRenderConfig_GatewayNameNeverLeaks`
   (render belt; renderConfig does NOT error on the leak case — it skips):
   - resolved gw with Address → `remote_addrs = <IP>` present, and the
     gateway object NAME does NOT appear on any `remote_addrs` line.
   - dangling/typo name (no map entry, not IP/host) → the output
     contains NO `remote_addrs = <name>` line AND no connection block
     for that VPN (skipped). Fixture uses benign PSK auth so an
     unrelated error path is not what's under test (R4). Pre-fix: this
     fails because unpatched code emits `remote_addrs = <name>`.
   - addressless gw (exists, no Address/DynamicHostname) → skipped, no
     leak. Pre-fix: fails (emits `remote_addrs = <name>`).
   - dotless single-label name (case 6) → skipped, no leak. Pre-fix
     fails.
   - legacy inline literal IP (case 3) → `remote_addrs = <IP>` present
     (over-rejection guard).
   - dotted inline hostname (case 3 FQDN) → `remote_addrs =
     peer.example.com` present.
   - empty gateway → connection emitted, NO `remote_addrs` line.
   - **multi-VPN skip-and-keep (R2-1 regression guard):** one healthy
     VPN + one dangling VPN → the HEALTHY VPN's connection AND its
     `remote_addrs` ARE present in the output; the dangling name does
     NOT appear anywhere in `remote_addrs`; the dangling VPN has no
     `ike-<name>` secret. This proves the healthy config is never zeroed.
3. `pkg/config` compile tests — new
   `TestValidateIPsecGatewayReferences`:
   - **commit (strict) rejects:** `CompileConfig` of a tree with a VPN
     referencing an undefined gateway → non-nil error. Fails pre-fix.
   - strict rejects a VPN referencing an addressless gateway object.
   - strict ACCEPTS a VPN with an inline literal IP gateway (case 3;
     mirrors `parser_security_test.go` `vpn site-a gateway 10.1.0.1`).
   - strict ACCEPTS a VPN referencing a defined gateway with an address.
   - **stanza-order independence (R2-2):** a tree where the `ipsec`
     stanza is authored BEFORE the `ike` stanza, with the VPN's gateway
     defined under `ike { gateway ... address ... }` → `CompileConfig`
     returns NO error (proves the validator runs on the fully-compiled
     config, not order-dependently). Fails the v2 design.
   - **lenient load warns, does not fail (R2-2 / #1960):**
     `CompileConfigLenient` of a tree with a dangling-gateway VPN →
     NO error returned AND a warning recorded in `cfg.Warnings`. Proves
     a pre-fix/peer-synced config still boots.
4. Full `go test ./pkg/ipsec/... ./pkg/config/...` green (existing 25+
   render tests + all parser/compiler tests still pass — proves cases
   1-3,7,8 preserved and no committed-config regression).
5. `go test ./...` green (or the affected packages + their importers,
   incl. `pkg/configstore` which uses the lenient compile entry points).

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
- Schema-layer (`schema_walk.go`) validation — the commit gate lives as
  a strict-accumulator validator on the compiled `*Config`
  (`validateIPsecGatewayReferencesStrict`), which is sufficient and is
  where the cross-reference data is fully assembled (both `ike{}` and
  `ipsec{}` gateways).
- Any change to the inline-literal-IP gateway shape beyond the guard.
- Responder-only / `%any` peer support (no such concept exists today;
  the case-5 path carries a comment to revisit if it is added).

## Open questions for adversarial review (v3)

1. **Predicate location / import cycle** — `config.IsUsableIPsecEndpoint`
   in `pkg/config`, called from `pkg/ipsec`. Confirm no cycle (config
   must NOT import ipsec) and that one SSOT predicate for both layers is
   the right call.
2. **Validator placement** — strict-accumulator-style on the compiled
   `*Config`, gated by `opts.lenientIPsecGatewayRefs`, mirroring
   `validateDeviceMapStrict`. Confirm `cfg.Security.IPsec.Gateways` holds
   BOTH `ike{}` and `ipsec{}` gateways at that point regardless of stanza
   order, and that the lenient flag is set in BOTH `CompileConfigLenient`
   and `CompileConfigForNodeLenient`.
3. **Apply is genuinely unchanged AND writes healthy config** —
   `renderConfig` does NOT return a new error for the leak case (it
   skips+warns), so `Apply`'s `if err != nil { return err }` is never
   tripped by the leak. Confirm this actually means the healthy config
   reaches `WriteFileAtomic` + reload (the R2-1 fix), with no Apply edit.
4. **Lenient load really boots** — confirm `CompileConfigLenient` /
   `CompileConfigForNodeLenient` return nil error (warning only) for a
   dangling-gateway VPN, so an upgraded/peer-synced node boots (#1960
   class). Which callers use these? (`pkg/configstore`, HA `SyncApply`.)
5. **Secrets-loop skip** — the connections loop builds `skipped
   map[string]bool`; the secrets loop consults it. Confirm no orphan
   `ike-<name>` secret for a skipped connection, and that no healthy VPN
   is wrongly skipped.
6. **Existing test configs** — independently grep `parser_*_test.go` /
   `compiler_*_test.go` for VPN gateway references; confirm all resolve
   to a defined+addressed gateway or an inline IP (so neither layer
   regresses a committed config).
7. **Is rejecting case 5 ever wrong?** No responder-only/`%any` concept
   in the parser today; re-verify by grep.
