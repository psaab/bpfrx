# #1431 — userspace filters: preserve cache invariants for future per-packet match fields

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

PR #1430 closed the immediate filter-log enforcement gaps by treating
DSCP — the one per-packet match field currently representable in
`FilterTerm` outside the 5-tuple — as cache-sensitive metadata:

- DSCP-sensitive input/output filters decline flow-cache insertion.
- Established session hits re-evaluate DSCP-sensitive input filters.
- Forwarding rotations that add, remove, or semantically change
  DSCP-sensitive input filters conservatively purge affected sessions.
- The purge comparison uses stable filter/term names and three-color
  policer shape, not compiler-positional IDs.

#1431 carries the round-5 follow-up forward: TOS (non-DSCP bits),
IPv4/IPv6 fragment fields, IPv4 IHL, IP options, TCP flags, ICMP
type/code, and any other future per-packet match are NOT currently
represented in `FilterTerm`. The Go config struct `FirewallFilterTerm`
already names some of them (`TCPFlags`, `IsFragment`, `ICMPType`,
`ICMPCode`, `FlexMatch`), but the wire DTO `FirewallTermSnapshot`
and the Rust `FilterTerm` never carry them. The next time any of
those fields lands in the userspace AST, the implementer must
either add it to the session/flow-cache key or treat it as
cache-sensitive — and the codebase must make the wrong choice loud
rather than silent.

The required invariant from the issue, verbatim:

> When a filter match depends on packet fields that are not part of
> the cache key, the dataplane must not reuse a first-packet
> forwarding decision for later packets that can differ on those
> fields.

## 2. Honest scope/value framing

This work is primarily a **contract + harness PR**, not a runtime
change. No new per-packet match field is being added in this scope.
The win is structural: when someone in a future PR adds
`tcp_flags_match`, `fragment_offset_match`, `ihl_match`, or a
`flex_match`, the codebase forces them to pick a side (cache-key vs
cache-sensitive) and instruments tests that would fail if they
silently picked neither.

Absolute scale of the runtime perf hit if we get this wrong:
the failure mode is a stale flow-cache hit for a packet that
should have been dropped or rerouted. The user-visible symptom
on a misconfigured filter is the same class of bug #1430
already fixed for DSCP: a first-packet accept on `dscp 0` gets
replayed for later packets with `dscp 46` and the EF-discard
term is silently bypassed. The user-visible symptom on a
forwarding rotation is stale session reuse against a changed
filter. Both are correctness bugs, not perf bugs.

If reviewers conclude the contract / harness can be replaced
by a one-paragraph README addition and a single grep for new
match fields, **PLAN-KILL is an acceptable verdict**. The
question is whether the failure mode is plausible enough — and
the codebase's existing #1430 helpers are centralized enough —
to need a compile-time or test-time tripwire.

## 3. What's already shipped / partially batched

PR #1430 landed the DSCP-specific implementation, which serves
as the reference pattern. The relevant surface today (`master`
@ `e07f733a6`):

- `FilterTerm.dscp_match_enabled` / `dscp_bitmap` —
  `userspace-dp/src/filter/mod.rs:61-62`
- `Filter.has_dscp_match_terms` aggregate —
  `userspace-dp/src/filter/mod.rs:117`
- Per-interface DSCP-match sets on `FilterState` —
  `userspace-dp/src/filter/mod.rs:423,437`
- `interface_input_filter_has_dscp_match` /
  `interface_output_filter_has_dscp_match` helpers —
  `userspace-dp/src/filter/engine/cache_sensitive.rs:177,189`
- Flow-cache insertion gate using both helpers —
  `userspace-dp/src/afxdp/flow_cache.rs:297-309`
- Session-hit DSCP re-evaluation —
  `userspace-dp/src/afxdp/poll_descriptor/mod.rs:217-244`
- Rotation purge —
  `userspace-dp/src/afxdp/worker/loop_body/mod.rs:295-330`
- `input_dscp_filter_families_changed()` —
  `userspace-dp/src/filter/engine/cache_sensitive.rs:167-175`
- `filter_term_semantics_match()` /
  `dscp_sensitive_filter_semantics_match()` —
  `userspace-dp/src/filter/engine/cache_sensitive.rs:104-143`
- README cache-sensitive doc paragraph —
  `userspace-dp/src/filter/README.md:31-38`
- DSCP-specific flow-cache + filter tests —
  `userspace-dp/src/afxdp/flow_cache_tests.rs:643-745`,
  `userspace-dp/src/filter/tests.rs:1683+`,
  `userspace-dp/src/filter/tests.rs:1733-2000`

The 5-tuple session/flow-cache key today —
`userspace-dp/src/session/key.rs:9-17`:

```rust
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}
```

Per-packet fields not in the key today: DSCP (already cache-
sensitive), TCP flags, fragment offset / MF bit, IHL, IPv6 ext
headers, IP options, ICMP type/code (in the L4 layout but not
in the key for non-ICMP / for ICMP-of-different-direction), the
flex-match window. The wire `FirewallTermSnapshot`
(`userspace-dp/src/protocol/security.rs:60-89`) names:
`source_addresses`, `destination_addresses`, `protocols`,
`source_ports`, `destination_ports`, `dscp_values`, `action`,
`count`, `log`, `policer`, `routing_instance`,
`forwarding_class`, `dscp_rewrite`. **None of the per-packet
non-5-tuple non-DSCP fields are on the wire today**, confirming
the issue's "intentionally deferred" framing.

## 4. Concrete design

### 4.1 The contract (written, machine-checked where possible)

Add a new doc section to `userspace-dp/src/filter/README.md`
titled **"Cache-key invariants for per-packet match fields"**.
Required content for the doc:

1. A table listing every match field on `FirewallTermSnapshot`
   (wire) AND every match field on `FilterTerm` (runtime). For
   each row: **in cache key?** (`src_ip`/`dst_ip`/`protocol`/
   `src_port`/`dst_port`/`addr_family` ⇒ yes; DSCP ⇒ no, cache-
   sensitive; future ⇒ must be filled in).
2. A two-sentence rule: *"Adding a per-packet match field to
   `FilterTerm` requires picking exactly one of (a) extending
   `SessionKey` and all its consumers, or (b) treating the
   filter as cache-sensitive via the #1430 pattern. The
   compiler aggregate `Filter.has_X_match_terms` and the
   per-interface `FilterState.iface_filter_v{4,6}_has_X_match`
   set are the two structural hooks the cache-sensitive path
   uses."*
3. The list of files the implementer MUST update for path (b),
   pointing at the existing DSCP-pattern call sites (the eight
   bullets in §3 above). This is the runbook.

### 4.2 The structural hooks (compile-time tripwire)

Introduce a single trait + per-field tag, replacing the
informal "by convention" pattern with a structural type-level
hook. Sketch:

```rust
// userspace-dp/src/filter/cache_contract.rs (new file)

/// Marker for a packet field that participates in filter matching
/// but is NOT in the 5-tuple `SessionKey`. Every such field MUST
/// either be added to `SessionKey` (and prove stability for every
/// consumer) or be treated as cache-sensitive — see
/// `userspace-dp/src/filter/README.md` "Cache-key invariants".
pub(crate) trait PerPacketMatchField {
    /// Stable name used in the per-interface `has_X_match` set
    /// names and in the README contract table.
    const FIELD_NAME: &'static str;

    /// Returns `true` iff this match field is part of `SessionKey`.
    /// If `false`, the implementor MUST wire a cache-sensitive
    /// per-interface set on `FilterState` AND a
    /// `Filter.has_<field>_match_terms` aggregate AND a
    /// `<field>_sensitive_filter_semantics_match()` predicate.
    const IN_SESSION_KEY: bool;
}

/// Compile-time list of every per-packet match field the codebase
/// is aware of. Adding a per-packet match field is a *deliberate*
/// edit to this list — if you skip it, the
/// `cache_contract_lists_all_fields` test fails by counting
/// `FilterTerm` `*_match_enabled` flags vs entries here.
pub(crate) const PER_PACKET_MATCH_FIELDS: &[(&str, bool)] = &[
    ("src_ip",      true),
    ("dst_ip",      true),
    ("protocol",    true),
    ("src_port",    true),
    ("dst_port",    true),
    ("dscp",        false), // cache-sensitive, see #1430
    // Future entries land here. Picking `true` requires extending
    // SessionKey and ALL its consumers. Picking `false` requires
    // the cache-sensitive runbook in README.md.
];

#[cfg(test)]
mod cache_contract_tests {
    // Tripwire 1: count `*_match_enabled` flags on FilterTerm via a
    //             tiny proc-macro-free derive (manual constant list
    //             updated by hand; reviewers verify by diff).
    // Tripwire 2: every cache-sensitive field has a matching
    //             FilterState.iface_filter_v{4,6}_has_<name>_match
    //             field — checked by a `compile_pass` test that
    //             references each field by name.
    // Tripwire 3: every cache-sensitive field has a matching
    //             `Filter.has_<name>_match_terms` flag — same.
    // Tripwire 4: a synthetic filter with an opt-in fake new
    //             per-packet match field exercises the test
    //             harness in §4.3 and FAILS the harness if the
    //             implementer forgets to gate flow-cache insertion.
}
```

**Honest about the type-system limits:** Rust does not give us
a "for every field on this struct, prove a trait is implemented"
check without a proc-macro derive (which this repo intentionally
avoids in `userspace-dp`). So tripwire 1 is a manual constant
list plus a unit test that counts the `*_match_enabled` /
`*_match` boolean flags on `FilterTerm` via `std::mem::size_of`
or by a small `compile_error!` macro that fires when the count
mismatches. The harness in §4.3 is the real enforcement; the
trait is documentation in code.

### 4.3 The test harness (real enforcement)

A generic harness at
`userspace-dp/src/filter/cache_invariant_harness.rs` (tests-only)
that takes:

- A `FilterTerm` builder that opts a single per-packet match
  field into the cache-sensitive class.
- Two packets with the same 5-tuple but **different** values
  for the chosen field.
- The expected behavior on each: first-packet accept, second-
  packet deny (or vice-versa).

The harness then walks:

1. `FlowCacheEntry::from_forward_decision()` with the first
   packet — MUST return `None` if the field is declared cache-
   sensitive.
2. Established session hit path — MUST re-evaluate the input
   filter against the second packet's field value.
3. Rotation: swap the filter snapshot for one whose sensitive
   field content has changed — `purge_sessions_for_input_*`
   MUST fire.
4. Negative parity: declare the field "in cache key" and verify
   the cache DOES insert (proves the harness can distinguish
   the two arms).

The DSCP case becomes the first concrete instantiation of this
harness, replacing the bespoke
`from_forward_decision_skips_cache_for_dscp_matched_*` tests at
`userspace-dp/src/afxdp/flow_cache_tests.rs:643-745` with a
parameterized call — but only after parity is proven against
the existing bespoke tests (keep them, add the harness on top).

The harness is the **real** acceptance criterion: when a future
PR adds e.g. TCP flags matching, the implementer extends
`PER_PACKET_MATCH_FIELDS`, picks an arm, and adds one call to
the harness. If they skip the cache-sensitive gates, the
harness FAILS. If they extend `SessionKey` correctly, the
"in cache key" arm of the harness PASSES.

### 4.4 What about path (a) — extending `SessionKey`?

Path (a) is the "add the field to the key" arm. It's
inherently a much bigger refactor (HA sync, session_table
indices, reverse-NAT lookup, key serialization). The plan does
**not** preemptively add helpers for this arm — instead, the
README contract requires the implementer to file an issue
against `session/key.rs` enumerating: HA sync compatibility,
session_table reverse indices, flow_cache key derivation,
session expiry hash, key comparison cost. The cache-contract
test for path (a) is: the field appears in `SessionKey`'s
`Hash + Eq` derive — checked by a `compile_pass` test that
references the field by name.

## 5. Public API preservation

- `FilterTerm` struct layout unchanged (only an additional doc
  comment + an attached trait impl).
- `Filter` struct gains no fields (the `has_X_match_terms` flag
  is added per-field by future PRs; this PR ships only the
  existing `has_dscp_match_terms`).
- `FilterState` gains no fields.
- `interface_input_filter_has_dscp_match` /
  `interface_output_filter_has_dscp_match` /
  `input_dscp_filter_families_changed` — signatures unchanged.
- `FlowCacheEntry::from_forward_decision` — signature unchanged;
  body unchanged except possibly factoring the DSCP gate into a
  helper named `flow_cache_can_insert_for_field` to make the
  per-field gate visually consistent.
- `purge_sessions_for_input_dscp_filter_revalidation` —
  signature unchanged.
- Wire DTO `FirewallTermSnapshot` — UNCHANGED. This PR adds no
  wire fields.
- `SessionKey` — UNCHANGED.

## 6. Hidden invariants the change must preserve

1. **Side-effect ordering on cached hits.** The cache-sensitive
   gate runs BEFORE flow-cache insertion. Re-evaluation runs
   BEFORE acting on a session hit. The rotation purge runs
   BEFORE the new filter is applied to in-flight packets. The
   harness must exercise all three orderings.
2. **Allocation rules on the hot path.** No allocation in the
   gate, the re-eval, or the rotation comparison. The existing
   helpers are allocation-free; the harness must NOT
   introduce hot-path allocation.
3. **HA sync portability.** The contract states that path (a)
   — adding to `SessionKey` — requires updating HA sync. The
   harness for path (a) must include a smoke that the new key
   bytes serialize and deserialize.
4. **Stable-name purge comparison.** The existing
   `dscp_sensitive_filter_semantics_match` ignores compiler-
   positional `Filter.id` / `FilterTerm.id`. Any future per-
   field equivalent MUST follow the same rule. The harness
   provides a regression for "changing the term order without
   changing content does not purge".
5. **Three-color policer runtime shape.** Already in the
   existing comparison helper — the contract preserves this.
6. **lo0 filters.** lo0 input filters are evaluated against
   host-bound traffic. The contract MUST list lo0 as a
   participant — currently `FilterState.lo0_filter_v{4,6}_fast`
   is NOT in the DSCP `has_dscp_match` per-interface set. If
   lo0 filters can also be DSCP-sensitive (they can — they're
   regular filters), the current implementation has a gap: a
   lo0 input filter with DSCP match terms would NOT decline
   flow-cache insertion. **Open question for reviewers — see
   §11 Q1.**
7. **Output filter family symmetry.** The DSCP gate handles
   both input and output. Any future cache-sensitive field
   MUST handle both arms.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression risk | LOW | No runtime path changes (harness + doc). DSCP gate still exercised by existing tests; the parameterized harness adds coverage, not replacement. |
| Lifetime / borrow-checker risk | LOW | Harness consumes existing `pub(crate)` helpers; no new lifetimes introduced. |
| Performance regression risk | NONE | No hot-path changes. Possibly a tiny refactor to a `flow_cache_can_insert_for_field` helper — measured `#[inline(always)]` to compile-out. |
| Architectural mismatch risk | MEDIUM | The trait + constant-list "tripwire" is informal — Rust can't enforce "every per-packet field on FilterTerm is in the list" without a proc-macro. If reviewers conclude this is doc-by-another-name, PLAN-KILL is appropriate. The harness is the real enforcement. |

## 8. Test plan

- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` — clean.
- `cargo test --release` — full cargo suite (952+ tests).
- 5× flake check on
  `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
  and `_output_filter` plus the new harness tests.
- `go test ./...` — 30 Go packages (no Go-side code changes are
  planned; this is regression coverage only).
- Smoke on `loss:xpf-userspace-fw0/1` — v4+v6, push+reverse,
  CoS-off + per-class. Strictly regression: no behavior change
  is expected.
- New tests added:
  - `cache_contract_lists_all_known_match_fields` — counts
    `*_match_enabled` flags on `FilterTerm` against the list.
  - `cache_sensitive_harness_dscp_input` — reproduces #1430's
    DSCP input gate via the parameterized harness.
  - `cache_sensitive_harness_dscp_output` — same for output.
  - `cache_sensitive_harness_rotation_purge` — exercises
    rotation against a DSCP semantics change.
  - `cache_sensitive_harness_fake_field_uncovered_fails` — uses
    a synthetic test-only field tagged cache-sensitive but
    deliberately not wired into the flow-cache gate; harness
    must FAIL, proving it catches the future "implementer
    forgot to wire it" case.
  - `cache_contract_lo0_filter_is_listed` — if §11 Q1 resolves
    "lo0 is in scope", proves the lo0 filter participates.

## 9. Out of scope (explicitly)

- Adding TCP flags / fragment / IHL / IP options matching to
  the wire DTO or to `FilterTerm`. That's the next PR after
  this one (or, more likely, the next several PRs — one per
  field).
- Adding any per-packet match field to `SessionKey`. Path (a)
  in §1.3 of the issue body is documented but not exercised.
- Removing the bespoke
  `from_forward_decision_skips_cache_for_dscp_matched_*` tests
  in favor of the harness — keep both for safety; remove
  bespoke in a follow-up after the harness has soaked.
- proc-macro derive of `PerPacketMatchField`. `userspace-dp`
  avoids proc-macros to keep build times honest; the manual
  constant list + tests are the chosen mechanism.
- Lo0 filter DSCP gap closure (if §11 Q1 resolves to "yes, gap
  exists"). That's a bug fix that should ship in its own PR
  with `Closes #<new-bug>`, because it changes runtime
  behavior. This PR documents the gap if it exists.

## 10. Validation — pre-PR

- `cargo build --release` clean.
- `cargo test --release filter::` clean.
- `cargo test --release flow_cache` clean.
- `cargo test --release cache_contract` clean (new tests).
- 5× flake on each new test.
- Go suite clean.
- Smoke matrix per CLAUDE.md (Pass A + Pass B).

## 11. Open questions for adversarial review

**Q1 — lo0 filter DSCP gap.** The existing #1430 implementation
gates flow-cache on per-interface `iface_filter_v{4,6}_has_dscp_match`,
but `lo0_filter_v{4,6}_fast` (host-bound traffic) is not in
that set. Is this a real correctness gap that must be fixed
before #1431 ships, or is host-bound traffic structurally
exempt because it does not go through the flow-cache? Walk
`userspace-dp/src/afxdp/poll_descriptor/` to verify the
host-bound path. **PLAN-KILL the harness scope if Q1's answer
forces the harness to also cover lo0 — that's a behavioral fix,
not a contract.**

**Q2 — is the constant list `PER_PACKET_MATCH_FIELDS` doing
real work?** It's a hand-maintained list. The "real
enforcement" is the harness. Is the constant list bringing
value over and above a one-paragraph README "when you add a
per-packet match field, do X" runbook? If reviewers conclude
"the list adds churn without enforcement", strip §4.2 and ship
the harness + README alone. **PLAN-KILL §4.2 specifically is
fine; it does not kill the whole PR.**

**Q3 — does the harness handle ICMP correctly?** ICMP packets
use src_port/dst_port to carry type/code. Adding "ICMP type
match" as a per-packet field is ambiguous — it might already
be in the cache key (because type lives in the port field for
ICMP sessions). The harness must NOT misclassify ICMP type as
cache-sensitive. Reviewer must verify
`userspace-dp/src/session/key.rs:28-...` (`forward_wire_key`
ICMP branch).

**Q4 — is `dscp_sensitive_filter_semantics_match` generalizable?**
It currently inlines DSCP-specific aggregate-flag comparisons
(`old.has_dscp_match_terms == new.has_dscp_match_terms`). For
TCP flags or IHL the equivalent flag would be
`has_tcp_flags_match_terms` / `has_ihl_match_terms`. Should
the helper be parameterized today (via a closure or a
`CacheSensitiveFieldDescriptor` trait), or should each future
field paste its own helper? Cost-benefit: parameterizing today
adds churn for one consumer (DSCP); pasting later doubles the
maintenance surface. **Lean: paste later. Reviewer feedback
welcome.**

**Q5 — is the trade-off honest?** This PR is contract +
harness, no runtime change. Is the failure mode (silent flow-
cache bypass when a future per-packet field is added) actually
a plausible failure? PR #1430 round 4 caught the original DSCP
gap; the same review discipline would catch the next one. If
review discipline is the real defense, this PR is theater.
**PLAN-KILL with this reasoning is welcome.** The
counter-argument: #1430 went through 5 review rounds before
the round-5 carry-item was acknowledged. A test-time tripwire
catches the same class of bug without depending on a 5-round
review.

**Q6 — does this conflict with #1373 retirement work?** The
eBPF dataplane is being retired (#1373 / #1476). Filter
semantics moving forward live only in `userspace-dp`. So the
contract is naturally Rust-side only. The README change is in
`userspace-dp/src/filter/README.md`, not in any eBPF doc. No
conflict expected. Reviewer should verify.

**Q7 — performance.** Confirmed: no hot-path changes. If §4.2
adds a `compile_error!` macro, it fires at build time, not
runtime. The harness is `cfg(test)` only. No measurable
runtime cost expected. Reviewer must verify that the (possibly)
factored `flow_cache_can_insert_for_field` helper folds back to
the existing two-call pattern at `#[inline(always)]` (we have
seen the compiler fail to inline through a trait-bound generic
in the past — keep this concrete).

---

If reviewers conclude the perf gain is too small to justify
the churn, **PLAN-KILL is an acceptable verdict.**
