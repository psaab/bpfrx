# #2124 — Policy application term with an unparseable named protocol fails OPEN to match-any

**Status:** DRAFT v2 — Codex r1 PLAN-NEEDS-MAJOR addressed; pending r2

## v2 changelog (addresses Codex r1 PLAN-NEEDS-MAJOR)

Codex r1 (task-mqn9wfro-ef9dsh) returned PLAN-NEEDS-MAJOR with three
findings, all valid and verified against source:

1. **`validateProtocol` is warning-only — the Go capability gate is
   LOAD-BEARING, not optional.** v1 falsely claimed truly-unknown
   protocols are already a hard commit error. They are NOT
   (`compiler.go` appends a warning; `CommitCheck`/`store.go` never
   promotes app-protocol warnings to errors; `parser_ast_test.go`
   asserts warning-only). → Layer G (capability gate) is promoted to
   the **PRIMARY** fix.
2. **Action-blind `never_match` is NOT universally fail-closed.** A
   malformed `deny`/`reject` rule that stops matching lets traffic fall
   through to a later permit / default-permit. AND Rust drops terms for
   bad PORTS too (port validation also warning-only), so a blanket
   all-dropped guard would change standard-path behavior for invalid-
   port deny rules. → Drop per-rule action-blind `never_match` as the
   primary mechanism. Make the gate (action-agnostic whole-config
   refuse-to-arm) primary; the Rust residual backstop uses a
   whole-snapshot `SnapshotIntegrityError` (reject snapshot, keep
   last-good) which is action-agnostic.
3. **Duplicate protocol maps are a divergence hazard.** Go ALREADY has
   complete named→number maps: `pkg/dataplane.protocolNumber`
   (compiler.go:1196) and `pkg/appid.catalogProtocolNumber`
   (catalog.go:128), both covering esp/ah/sctp/vrrp/igmp/pim/egp +
   junos aliases. → Do NOT add a third map. Centralize via an exported
   `(uint8, bool)` variant and reuse it; preserve numeric `0`.

The v1 design below is superseded by §4'/§5' (primed sections). The
original §4/§5 are retained for history but marked SUPERSEDED.

---


## 1. Issue framing (in my words)

A security policy `permit` rule that matches on a user-defined
`application` whose `protocol` is a *named* IANA protocol the Rust
matcher cannot parse — `sctp`, `esp`, `ah`, `vrrp`, `igmp`, `pim`,
`egp` — silently **fails OPEN to match-any**, so the rule permits ALL
traffic between the zone pair instead of only the intended protocol.

Verified end-to-end in the issue (3/3 adversarial votes):

- Go `validateProtocol` (`pkg/config/compiler.go:2371`) *accepts*
  `sctp/vrrp/igmp/pim/egp/ah/esp` at commit (warning-only, never a hard
  error), so the config commits clean.
- Go `normalizeUserspaceApplicationProtocol`
  (`pkg/dataplane/userspace/manager.go:1782`) only lowercases — `"esp"`
  stays `"esp"`, non-empty.
- The capability gate `expandUserspacePolicyApplications`
  (`manager.go:1712`) only returns `ok=false` for an *empty* protocol
  string (`manager.go:1732`). A non-empty-but-Rust-unparseable protocol
  returns `ok=true`, so `ForwardingSupported` stays true and the
  snapshot arms normally — routing AROUND the existing deliberate
  fail-closed gate (`manager.go` `deriveUserspaceCapabilities` /
  `ForwardingSupported=false`).
- Rust `parse_protocol` (`userspace-dp/src/policy.rs:1148`) returns
  `None` for those named protocols; `parse_applications`
  (`policy.rs:1127`) drops the term via `continue`. If that was the
  rule's only term, `rule.applications` is empty →
  `CompiledApplications::from_matches(&[])` sets `match_any:true`
  (`policy.rs:304-310`) → `matches()` returns true for EVERY
  protocol/port (`policy.rs:333-335`) → `try_match_rule` treats the
  rule as matching everything (`policy.rs:983`).

Net: a `permit` policy intended to allow ONLY ESP (or AH/SCTP/...)
permits ALL traffic for that zone-pair — a real security-policy bypass.
Doubly bad because the codebase already has a deliberate fail-CLOSED
design for policy semantics it cannot honor (`ForwardingSupported=false`
→ dataplane refuses to arm); this gap fails OPEN *inside* the matcher
instead.

## 2. Honest scope / value framing

This is a **security correctness fix**, not a perf refactor — the
"value" is closing a verified policy-bypass, not saving cycles. The
churn is small and surgical (one Rust file's parse path + a Go
canonicalization + tests). There is no architectural premise that can
be "too small to justify" — a fail-OPEN in a firewall policy matcher
is a must-fix. *(The skill's "PLAN-KILL if the perf gain is too small"
clause does not apply; PLAN-KILL here would mean "this design is wrong /
introduces a worse hazard", which IS a valid verdict.)*

## 3. What's already shipped / precedent the fix must compose with

- **#2008 address-side fail-closed precedent** — the EXACT same hazard
  class was fixed for the address side. `PolicyRule` carries per-side,
  per-family `source_v4_empty` / `source_v6_empty` /
  `destination_v4_empty` / `destination_v6_empty` flags
  (`policy.rs:120-131`): "configured but matches NOTHING → force NOT
  match (fail-closed)". The application-side fix MIRRORS this: a rule
  whose application terms were all configured-but-unparseable must
  become **never-match**, not match-any.
- **`PROTO_*` constants** already centralized in
  `userspace-dp/src/ip_proto.rs` (`ESP=50`, `GRE=47`, `OSPF=89`,
  `IPIP=4`, etc.) per #1826. New protocol numbers (AH=51, SCTP=132,
  VRRP=112, IGMP=2, PIM=103, EGP=8) get added there.
- **Predefined junos apps** (`pkg/config/predefined.go`) only use
  `tcp/udp/icmp/gre/89/4` — all already parse. The risk vector is
  **user-defined** `applications` with named L3 protocols.
- **`SnapshotIntegrityError` is a whole-snapshot hammer.** The preflight
  in `snapshot_refresh.rs:69` REJECTS the ENTIRE snapshot and keeps
  previous state on any integrity error. Using it for one typo'd
  protocol would freeze the whole policy plane — wrong granularity.
  Rejected in favor of per-rule fail-closed (§5.2).

## 4'. Decision: which layer(s) fix it (v2 — PRIMED)

Three layers, with the **Go capability gate as the PRIMARY,
action-agnostic fix** (Codex r1 F1/F2):

- **Layer G (Go capability gate — PRIMARY):** make
  `expandUserspacePolicyApplications` (manager.go:1712) reject any
  application term whose protocol OR ports the Rust matcher cannot
  represent. Returning `ok=false` trips the EXISTING, deliberate
  `userspaceSupportsSecurityPolicies → ForwardingSupported=false`
  whole-config fail-closed gate (manager.go:1479,1556). This is
  ACTION-AGNOSTIC: nothing arms, so both `permit` AND `deny` rules are
  honored-or-nothing-forwards. There is no permit/deny asymmetry, no
  fall-through, no over-match. It is also OPERATOR-VISIBLE (forwarding
  refuses to arm — surfaced in status) rather than a silent per-rule
  runtime outcome. For the protocols we now SUPPORT (esp/ah/sctp/...),
  Layer G canonicalizes them to numeric strings the Rust matcher
  already parses, so the gate stays `ok=true` and they WORK. Only
  TRULY-unrepresentable terms (unknown protocol, malformed port) trip
  the gate.

- **Layer R (Rust — make the named set work + last-resort backstop):**
  (a) extend `parse_protocol` to map the named IANA protocols to their
  numbers, so a snapshot carrying a named protocol (e.g. an
  un-canonicalized or hand-crafted snapshot, or a future direct path)
  still matches correctly rather than fails open. (b) Backstop: if a
  rule's `application_terms` are NON-empty but ALL drop as unparseable
  (which Layer G should now prevent end-to-end), raise a
  `SnapshotIntegrityError` so the whole snapshot is rejected and the
  previous good state is kept (the existing preflight path,
  snapshot_refresh.rs:69). This is ACTION-AGNOSTIC (no per-rule
  permit/deny asymmetry) and never silently collapses a rule to
  match-any. It only fires on a corrupt/inconsistent snapshot that
  bypassed Layer G — a true integrity violation, the correct trigger
  for that mechanism.

- **Centralization (Codex r1 F3):** add an exported
  `dataplane.ProtocolNumber(name string) (uint8, bool)` and refactor
  the existing `protocolNumber` + `pkg/appid.catalogProtocolNumber` to
  delegate to one source of truth, eliminating the divergence hazard.
  Layer G uses it to canonicalize/validate. `ProtocolNumber` returns
  `(n, true)` for a valid name OR a `0..255` numeric (INCLUDING `"0"` /
  HOPOPT, preserving the deliberate-`protocol 0` case Codex flagged),
  and `(0, false)` only for a genuinely unrepresentable token.

- **Layer C (commit-time):** OUT OF SCOPE for the fix; documented as a
  known property. `validateProtocol` already accepts the named set
  (warning-only); with Layers G+R they now work end-to-end. A
  truly-unknown protocol still warns at commit and then trips Layer G's
  refuse-to-arm at apply — operator-visible at apply time. A stricter
  commit-time hard reject (#1960 doctrine) is a reasonable follow-up
  but is deferred (Q5) to keep this PR a focused security fix.

## 5'. Concrete design (v2 — PRIMED)

### 5'.1 Centralize the named→number map (`pkg/dataplane`)

`pkg/dataplane/compiler.go` currently has `protocolNumber(name) uint8`
returning `0` for BOTH unknown and `"0"`. Add:

```go
// ProtocolNumber resolves an IANA protocol name or numeric string to its
// number. ok=false means the token is neither a known name nor a valid
// 0..255 numeric (so 0/HOPOPT resolves to (0, true), distinct from the
// unrepresentable (0, false) case).
func ProtocolNumber(name string) (uint8, bool) { ... }
```

`protocolNumber` becomes `n, _ := ProtocolNumber(name); return n`
(behavior-preserving). `pkg/appid.catalogProtocolNumber` is refactored
to delegate to `dataplane.ProtocolNumber` (it mirrors the same table per
its own doc comment) — eliminating the third copy. A parity test asserts
the two former tables agree with the centralized one for the full named
set + boundary numerics (0, 255, 256→false, ""→false).

### 5'.2 Layer G: validate protocol AND ports in the capability gate

In `expandUserspacePolicyApplications` (manager.go:1712), after
resolving each application, validate representability BEFORE building the
snapshot term:

```go
proto := normalizeUserspaceApplicationProtocol(app.Protocol)
if proto == "" {
    return nil, false               // existing empty-protocol gate
}
// NEW: protocol must be representable by the Rust matcher.
num, ok := dataplane.ProtocolNumber(proto)
if !ok {
    return nil, false               // unrepresentable -> fail closed (refuse to arm)
}
// Canonicalize named protocols to their number so the wire snapshot is
// always Rust-parseable (belt-and-suspenders for mixed-version helpers).
proto = strconv.Itoa(int(num))
// NEW: ports must parse the way the Rust parse_port_spec does.
if !userspacePortSpecRepresentable(app.SourcePort) ||
   !userspacePortSpecRepresentable(app.DestinationPort) {
    return nil, false               // malformed port -> fail closed
}
```

`userspacePortSpecRepresentable` mirrors Rust `parse_port_spec`
(empty=ok; named service aliases http/https/...; single 1..65535;
`low-high` with `low>0 && low<=high`). This closes the bad-PORT
fail-open (Codex r1 F2) at the same action-agnostic gate.

`normalizeUserspaceApplicationProtocol` keeps its `icmp6→icmpv6` mapping;
the numeric canonicalization happens via `ProtocolNumber` above so we do
NOT add a fourth named-protocol list to it.

### 5'.3 Layer R(a): extend Rust `parse_protocol`

Add named arms (numbers from `ip_proto.rs`, with new constants
`PROTO_IGMP=2 PROTO_EGP=8 PROTO_AH=51 PROTO_PIM=103 PROTO_VRRP=112
PROTO_SCTP=132`):

```rust
"esp" => Some(PROTO_ESP), "ah" => Some(PROTO_AH),
"sctp" => Some(PROTO_SCTP), "vrrp" => Some(PROTO_VRRP),
"igmp" => Some(PROTO_IGMP), "pim" => Some(PROTO_PIM),
"egp" => Some(PROTO_EGP), "icmp6" => Some(PROTO_ICMPV6), // alias
```

Numeric `_ => parse::<u8>()` preserved (so `"0"`/`"132"` still parse).

### 5'.4 Layer R(b): residual backstop via SnapshotIntegrityError

`parse_applications` reports whether it had terms and dropped all of
them. `parse_policy_state_with_counters` (the only constructor of rules,
already returns `Result<_, SnapshotIntegrityError>`) raises a new
`SnapshotIntegrityError::UnrepresentableApplicationProtocol { rule_id,
protocol }` when a rule has NON-empty `application_terms` but ALL terms
dropped. The preflight (snapshot_refresh.rs:69) already rejects the
whole snapshot and keeps previous state on any integrity error — so a
corrupt snapshot that slipped past Layer G fails closed action-
agnostically instead of collapsing a rule to match-any.

Genuine-empty `application_terms` (Junos `application any` / no
`match application`) is UNCHANGED → match-any (correct). The default
rule and `PolicyRule::default()` keep `match_any:true, never_match
absent` — no new field on the hot struct; the integrity check lives in
the parser, not in `matches()` (zero per-packet cost). This also means
NO `matches()` signature/branch change and NO #2008-style per-rule flag
— simpler than v1.

### 4./5. (v1, SUPERSEDED — retained for history)


Per the issue's "Suggested fix", BOTH complementary layers, because each
covers a different failure mode and the defense-in-depth matches the
existing #2008 + capability-gate posture:

- **Layer R (Rust, the core fix):** (a) extend `parse_protocol` to map
  the standard named protocols Junos/`validateProtocol` accepts to their
  IANA numbers, so legitimate configs WORK; (b) for any STILL-
  unparseable term, the rule fails CLOSED (never-match), never
  match-any.
- **Layer G (Go, defense-in-depth + parity):** canonicalize named
  protocols to their numeric strings in
  `normalizeUserspaceApplicationProtocol` so the wire snapshot always
  carries a Rust-parseable protocol for the accepted set; and tighten
  the capability gate so a protocol NEITHER Go-canonicalizable NOR
  Rust-parseable trips the existing `ForwardingSupported=false`
  fail-closed path (operator-visible at apply time).
- **Layer C (commit-time, #1960 doctrine):** evaluated below; recommend
  KEEPING `validateProtocol` lenient (warn) for the now-supported named
  set (no behavior change — they now work), but this is an open question
  for reviewers (§11 Q5).

## 5. Concrete design

### 5.1 Layer R(a): extend `parse_protocol` (`policy.rs:1148`)

Add the named→number mappings for the protocols `validateProtocol`
already accepts, drawing the numbers from `ip_proto.rs`:

```rust
fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" => Some(PROTO_ICMPV6),   // accept icmp6 alias too
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        "esp" => Some(PROTO_ESP),                   // 50
        "ah" => Some(PROTO_AH),                     // 51
        "sctp" => Some(PROTO_SCTP),                 // 132
        "vrrp" => Some(PROTO_VRRP),                 // 112
        "igmp" => Some(PROTO_IGMP),                 // 2
        "pim" => Some(PROTO_PIM),                   // 103
        "egp" => Some(PROTO_EGP),                   // 8
        _ => protocol.parse::<u8>().ok(),
    }
}
```

New constants in `ip_proto.rs`: `PROTO_IGMP=2`, `PROTO_EGP=8`,
`PROTO_AH=51`, `PROTO_PIM=103`, `PROTO_VRRP=112`, `PROTO_SCTP=132`.
These are load-bearing IANA wire numbers; values cross-checked against
the registry.

Note: `junos-*` aliases are NOT handled here — the Go compiler resolves
predefined `junos-*` apps to their concrete protocol BEFORE the snapshot
(`predefined.go`), so the Rust side never sees a literal `junos-xxx`
protocol string. Confirmed: no predefined app carries a non-numeric,
non-tcp/udp protocol other than `gre`/`89`/`4`, all already parsed.

### 5.2 Layer R(b): fail CLOSED on unparseable terms (the security core)

The dangerous transition is "term list NON-empty, but every term
dropped → `from_matches(&[])` → match_any". Distinguish the two empty
cases:

- `application_terms` genuinely empty (no app constraint, Junos
  `application any` / no `match application`) → match-any (correct,
  unchanged).
- `application_terms` NON-empty but ALL dropped as unparseable →
  **never-match** (fail closed).

Implementation — mirror #2008's `*_empty` flag exactly. Change
`parse_applications` to also report whether any term was dropped, and
`CompiledApplications::from_matches` to take that signal:

```rust
struct CompiledApplications {
    match_any: bool,
    never_match: bool,   // NEW: configured terms all unparseable -> fail closed
    by_protocol: FxHashMap<u8, ProtoTerms>,
}

fn matches(&self, protocol: u8, src_port: u16, dst_port: u16) -> bool {
    if self.never_match {        // fail-closed short-circuit (checked first)
        return false;
    }
    if self.match_any {
        return true;
    }
    ...
}
```

`parse_applications` returns `(Vec<ApplicationMatch>, bool dropped_any)`
(or a small struct). Constructor logic at `policy.rs:669-670`:

```rust
let (applications, had_terms, dropped_any) =
    parse_applications(&snap.application_terms);
let compiled_apps =
    CompiledApplications::from_parsed(&applications, had_terms, dropped_any);
```

`from_parsed` rules:
- `had_terms == false` → `match_any: true` (genuinely no constraint).
- `had_terms == true && applications.is_empty()` (all dropped) →
  `never_match: true`. **Fail closed.**
- otherwise → grouped `by_protocol`, both flags false.

The existing `from_matches(&[])` → match_any path is preserved ONLY for
the genuine-empty case; the all-dropped case diverges to never_match.
`PolicyRule::default()` keeps `match_any:true` semantics for the
zero-config default rule (it has no terms → `had_terms=false`), so the
default-rule behavior is unchanged.

### 5.3 Layer G: Go canonicalization + gate parity

`normalizeUserspaceApplicationProtocol` (`manager.go:1782`) maps the
named protocols to their numeric strings so the wire snapshot is always
Rust-parseable for the accepted set:

```go
func normalizeUserspaceApplicationProtocol(proto string) string {
    switch strings.ToLower(strings.TrimSpace(proto)) {
    case "icmp6": return "icmpv6"
    case "esp":   return "50"
    case "ah":    return "51"
    case "sctp":  return "132"
    case "vrrp":  return "112"
    case "igmp":  return "2"
    case "pim":   return "103"
    case "egp":   return "8"
    default:      return strings.ToLower(strings.TrimSpace(proto))
    }
}
```

This makes Layer R(a) and Layer G mutually redundant for the accepted
set (belt-and-suspenders): even an OLD helper binary that lacks R(a)
gets a numeric protocol it can already parse. Open question Q3: do we
canonicalize in Go AND extend Rust, or pick one? Recommendation: BOTH —
the Rust extension is the durable fix (handles direct numeric + named),
the Go canonicalization protects mixed-version helper rollouts.

Capability-gate tightening: `expandUserspacePolicyApplications` returns
`ok=false` for a protocol that, after canonicalization, the Rust matcher
still cannot represent (i.e. not in the named set and not a 0-255
numeric). That trips `ForwardingSupported=false` → operator sees the
policy refuse to arm rather than silently fail-closing one rule at
runtime. This is the loud, early signal; Layer R(b) is the last-resort
runtime backstop if anything slips through (e.g. a hand-crafted
snapshot).

### 5.4 Layer C: commit-time (evaluated, recommend minimal)

`validateProtocol` ALREADY accepts the named set (warns nothing — it's
silently allowed). With R+G the named set now WORKS end-to-end, so no
NEW commit rejection is needed for them. The residual case (a protocol
NOT in `validateProtocol`'s set AND not numeric) is ALREADY a hard
`commit` error (`return fmt.Errorf("invalid protocol %q")`). So the
commit layer is effectively already correct for the truly-unknown case.
Recommendation: NO new commit-time validation in this PR beyond a
possible doc note; treat any further strict/lenient toggle as out of
scope (Q5).

## 6. Public API preservation

- `parse_protocol` signature unchanged (`&str -> Option<u8>`).
- `evaluate_policy*` signatures unchanged.
- `parse_policy_state*` signatures unchanged.
- `CompiledApplications` is a private struct; adding a field +
  `from_parsed` is internal. `from_matches` may be retained as a thin
  wrapper for the genuine-empty/normal paths or replaced by
  `from_parsed` — internal-only either way.
- Go `normalizeUserspaceApplicationProtocol`,
  `expandUserspacePolicyApplications` signatures unchanged.

## 7. Hidden invariants the change must preserve

- **Default rule stays match-any.** `PolicyRule::default()` and any rule
  with no `application_terms` MUST remain match-any. Guard: `had_terms`
  is false for the empty input → match_any path unchanged.
- **`match_any` short-circuit ordering.** `never_match` must be checked
  BEFORE `match_any` in `matches()` (a rule can't be both, but defensive
  ordering — never_match is the fail-closed sentinel).
- **Side-effect ordering / preflight.** No new `SnapshotIntegrityError`
  is introduced, so the preflight-reject-whole-snapshot behavior is
  untouched. Per-rule fail-closed is purely a `matches()` outcome.
- **HA session-sync portability.** No on-wire snapshot field changes in
  Rust (the flag is derived, not serialized). Go canonicalization
  changes the protocol STRING on the wire (esp→"50"), which both old and
  new helpers parse — verify no consumer keys on the literal "esp".
- **Numeric protocol still works.** `protocol 132` etc. must still
  parse (the `_ => parse::<u8>()` arm is preserved).
- **Allocation:** `parse_applications` already allocates a `Vec`; the
  dropped-any signal is a `bool`, no new hot-path allocation. `matches()`
  gains one bool check — negligible, runs per packet on the slow
  (session-install) path, not per-forwarded-packet.

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Only changes the all-dropped case (today match-any, a BUG) to never-match. Genuine-empty + normal paths byte-identical. Default rule unchanged. |
| Lifetime / borrow-checker | LOW | Adding a `bool` field + returning a tuple. No new borrows. |
| Performance regression | LOW | One extra `bool` branch in `matches()`; parse path is config-apply, not per-packet forward. |
| Architectural mismatch | LOW | Directly mirrors the shipped #2008 `*_empty` fail-closed pattern — same author-intended design, same struct. Not a novel architecture. |

## 9'. Test plan (v2 — PRIMED)

Rust (`userspace-dp/src/policy_tests.rs`):
- **Known named protocol now matches** — a rule with one term
  `{protocol:"sctp", destination_port:"9999"}` permits SCTP/9999 and
  DENIES TCP/443 (proves R(a), NOT match-any). Repeat for `esp`
  (protocol-only, no port) → permits ESP, denies TCP. **Non-tautological:**
  on pre-fix code the term drops → match-any → TCP/443 wrongly Permit.
- **Numeric still parses** — `{protocol:"132"}` permits SCTP, denies TCP.
- **All-dropped raises SnapshotIntegrityError** — a rule with NON-empty
  `application_terms` all unparseable
  (`{protocol:"definitely-not-a-proto"}`) makes
  `parse_policy_state_with_counters` return
  `Err(UnrepresentableApplicationProtocol{..})`. **Non-tautological:**
  pre-fix it returns Ok with a match-any rule.
- **Genuine-empty stays match-any (Ok)** — empty `application_terms`
  parses Ok and match-anys (regression guard; default behavior).
- **Mixed parseable+unparseable** — terms `[{esp},{bogus}]`: with R(a)
  esp parses → ≥1 real term → Ok, NOT all-dropped, matches ESP. (The
  bogus term still drops; rule is not all-dropped so no integrity
  error — consistent with Layer G being the front-line reject.)
- **`PolicyRule::default()` unchanged** — match-any preserved.
- `cargo test --release` green; 5/5 flake on the new integrity-error
  test.

Go (`pkg/dataplane/`, `pkg/dataplane/userspace/`, `pkg/appid/`):
- **`ProtocolNumber` parity** — for the full named set + junos aliases,
  `ProtocolNumber` agrees with the old `protocolNumber` and
  `catalogProtocolNumber`; `("0")→(0,true)`, `("256")→(0,false)`,
  `("")→(0,false)`, `("bogus")→(0,false)`.
- **Gate fails closed on unknown protocol** — an app with protocol
  `"bogus"` → `expandUserspacePolicyApplications` returns `ok=false` →
  `userspaceSupportsSecurityPolicies` false → `ForwardingSupported`
  false. **Non-tautological:** pre-fix `ok=true`.
- **Gate fails closed on malformed port** — app with
  `DestinationPort:"99999"` (or `"5-1"`) → `ok=false`.
- **Gate canonicalizes + accepts named protocol** — app with `esp` →
  `ok=true`, emitted snapshot term Protocol == `"50"`.
- **Existing working configs unchanged** — tcp/udp/icmp/gre/ospf +
  numeric still `ok=true`.
- `go test ./pkg/dataplane/... ./pkg/appid/... ./pkg/config/...` green.

### 9. (v1, SUPERSEDED)

1. **Known named protocol now matches** — a permit rule with one
   application term `{protocol:"sctp", destination_port:"9999"}` permits
   SCTP/9999 and DENIES TCP/443 (proves R(a) + that it is NOT match-any).
   Repeat for `esp` (protocol-only, no port) → permits ESP, denies TCP.
2. **Unknown token fails CLOSED** — a permit rule with one term
   `{protocol:"bogus-proto", ...}` does NOT permit TCP/443 (default
   `deny` wins). **Non-tautological:** this test FAILS on pre-fix code
   (today it match-anys → Permit). Assert `state.rules[0]` matches
   nothing.
3. **Numeric still parses** — `{protocol:"132"}` permits SCTP, denies
   TCP (regression guard for the numeric arm).
4. **Genuine-empty stays match-any** — rule with empty
   `application_terms` still match-anys (regression guard for the
   default behavior).
5. **Mixed parseable+unparseable** — a rule with terms
   `[{esp}, {bogus}]`: the parseable term still matches ESP, the rule
   is NOT match-any (the bogus term is dropped, the rule has ≥1 real
   term → normal by_protocol, never_match=false). Confirms drop of one
   term among many does NOT trip never_match.
6. `cargo test --release` full suite green; 5/5 flake on the new
   `application_unknown_protocol_fails_closed` test.

Go (`pkg/dataplane/userspace/`):
7. `normalizeUserspaceApplicationProtocol("esp") == "50"` etc.; unknown
   passes through unchanged.
8. `expandUserspacePolicyApplications` capability-gate test: an app with
   a truly-unknown protocol → `ok=false` (trips fail-closed); an app
   with `esp` → `ok=true` and canonicalized to "50".
9. `GOCACHE=/dev/shm/cache go test ./pkg/dataplane/... ./pkg/config/...`
   green.

Smoke: **NOT run by this agent.** Hot-path/security change — per the
task directive, the PARENT runs the `/security-matrix` directional
smoke after merge (trust→untrust ALLOW, untrust→trust BLOCK, plain
forwarding throughput). Stated explicitly in the PR + return.

## 10. Out of scope (explicitly)

- A new strict/lenient commit-time `validateProtocol` toggle (Q5) —
  the named set now works; truly-unknown is already a commit error.
- Adding the named protocols to the `AppCatalog` show-path (app-id
  naming) — separate concern (matcher vs. display); no fail-open there.
- SnapshotIntegrityError-based whole-snapshot rejection for unparseable
  protocols — rejected as wrong granularity (§3).
- Extending the *port* spec parser — orthogonal.

## 11. Open questions for adversarial review (each PLAN-KILL-able)

1. **Fail-closed vs. SnapshotIntegrityError.** Is per-rule never-match
   the right granularity, or should an unparseable protocol reject the
   whole snapshot (loud, but freezes the entire policy plane on one
   typo)? I argue per-rule (mirrors #2008, surgical) — refute if a
   whole-snapshot reject is safer.
2. **Default-rule / genuine-empty safety.** Does any code path construct
   a rule with `had_terms=true` but legitimately expecting match-any
   (e.g. a wildcard term that intentionally parses to nothing)? If so,
   never_match would wrongly fail-close a legit rule. I believe NO — an
   empty `application_terms` is the only match-any case — verify.
3. **Go-canonicalize AND Rust-extend, or one?** Doing both is
   belt-and-suspenders for mixed-version helper rollout. Is the double
   maintenance worth it, or does it create a divergence hazard (two
   lists of named protocols to keep in sync)? Could centralize the
   named→number map.
4. **Protocol-number correctness.** Verify AH=51, SCTP=132, VRRP=112,
   IGMP=2, PIM=103, EGP=8, ESP=50 against IANA. A wrong number is a
   silent mis-match (worse than fail-open in a subtle way).
5. **Commit-time layer.** Should #1960-doctrine strict/lenient commit
   validation be added for protocol names NOW, or is "named set works +
   unknown is already a commit error" sufficient? I argue sufficient.
6. **`icmp6` alias.** Adding `"icmp6"` to `parse_protocol` — is there any
   path where Go sends `icmp6` un-normalized to Rust? (Go normalizes
   icmp6→icmpv6 already; the Rust alias is defensive.) Harmless?
7. **Capability-gate interaction.** With Go canonicalizing esp→"50", the
   gate sees a numeric protocol and returns ok=true → forwarding arms →
   Rust parses "50" fine. Correct. But does tightening the gate for
   *truly*-unknown protocols risk regressing a currently-working config
   that relies on a protocol the gate would now reject? (It shouldn't —
   anything the gate now rejects is exactly the fail-open set.) Verify.
