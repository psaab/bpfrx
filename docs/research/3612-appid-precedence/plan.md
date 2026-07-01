# Plan of action — #3612: AppID enabled catalog (lowest app_id) vs disabled fallback (specificity) precedence divergence

Research branch: `research/3612-appid-precedence`
Base: `origin/master` @ f1d00ffeb (issue provenance was 9419bbc2c; line
numbers in the issue body are stale — this doc re-grounds every reference at
f1d00ffeb).
Source: Codex review 001, M04 (folds L03). Class: design-fork → /research.

> NOTE: this is a `/research` deliverable. It stops at a converged plan.
> No production code is touched on this branch. Implementation happens later
> via `/engineer 3612` against the recommended path.

---

## 1. Status

**PLAN-READY. Recommended path: PATH A — unify the ENABLED (Rust) catalog
label path onto the SAME binary specificity rule the DISABLED (Go) fallback
already uses (#2578), then pin agreement with a cross-language parity test.**

The divergence is **real, reachable, and unintended**. It is a **display /
observability** inconsistency only — it does NOT affect packet
allow/deny enforcement (enforcement uses a separate boolean matcher,
`CompiledApplications::matches`, not the label catalog). Severity Medium
(operator trust / forensic-label integrity), matching the issue's Codex M04.

Not a PLAN-KILL: the divergence is reachable with an ordinary two-app
overlapping config and there is **no product justification** for the two paths
to disagree (xpf has no L7 DPI engine — both paths are pure protocol+port tuple
matchers, so they should produce identical labels for identical traffic).

---

## 2. Framing

### 2.1 The two precedence rules (confirmed at f1d00ffeb, file:line)

**ENABLED path — Rust `AppCatalog`, precedence = lowest `app_id`.**
The dataplane stamps a session's `app_id` via `AppCatalog::lookup_directional`
(`userspace-dp/src/policy.rs:1606-1651`), reached through the
`lookup_forward` (`policy.rs:1658`) and `lookup_admitted` (`policy.rs:1683`)
wrappers. Overlap tiebreak:

```rust
// policy.rs:1645-1650
match (exact, scan_hit) {
    (Some(a), Some(b)) => a.min(b),   // <-- lowest app_id wins
    (Some(a), None) | (None, Some(a)) => a,
    (None, None) => 0,
}
```

`exact` is the exact single-dest-port bucket (`AppProtoEntries::exact_dst`),
`scan_hit` is the first (lowest-id) match in the scan list
(ranges + source-constrained + protocol-only). Because app_ids are assigned
sequentially from 1 in **sorted-name order** (`pkg/appid/catalog.go:66-92`;
`BuildCatalog` iterates `CatalogNames(...)` → `sortedNames` → `sort.Strings`),
**lowest app_id == alphabetically-first application name**. Specificity is NOT
consulted in the final tiebreak. The rule is documented as "First writer wins
(lowest app_id)" (`policy.rs:651-653`, `538-548`) and pinned by
`policy_tests.rs::app_catalog_overlap_lowest_id_wins` (`policy_tests.rs:3644`).

**DISABLED path — Go `resolveTupleFallback`, precedence = specificity.**
When `services application-identification` is off, no `app_id` is stamped, so
`ResolveSessionName` (`pkg/appid/runtime.go:162-181`) falls to
`resolveTupleFallback` (`runtime.go:199-233`):

```go
// runtime.go:214-222  (#2578)
portBased := app.DestinationPort != "" || app.SourcePort != ""
if best == "" || (portBased && !bestPortBased) ||
    (portBased == bestPortBased && name < best) {
    best = name
    bestPortBased = portBased
}
```

Precedence: **binary specificity** — any port-constrained app (dst OR src port
set) beats a protocol-only app; ties broken by **app name** (`name < best`).
Established deliberately by #2578 (hostile-review follow-up to #2548/#2577) to
kill the earlier non-deterministic first-match map iteration; pinned by
`runtime_test.go::TestResolveTupleFallbackPrefersPortOverProtocol`
(`runtime_test.go:320`, 256 randomized iterations).

### 2.2 Concrete divergence (proven against the code above)

Config with two overlapping custom TCP applications:

| name       | protocol | destination-port | app_id (sorted-name) | class          |
|------------|----------|------------------|----------------------|----------------|
| `aaa-tcp`  | tcp      | (none)           | 1                    | protocol-only  |
| `zzz-https`| tcp      | 443              | 2                    | port-based     |

Session: TCP, `src=<ephemeral>`, `dst=443` (forward flow, `is_reverse=false`).

- **ENABLED** `lookup_directional(6, ephemeral, 443, false)`:
  `exact_dst[443] = 2` → `exact = Some(2)`; scan has `aaa-tcp` id 1 with
  `(0,0)` dst/src = "no constraint" → `scan_hit = Some(1)`;
  `2.min(1) = 1` → app_id 1 → **`aaa-tcp`** (broad, protocol-only).
- **DISABLED** `resolveTupleFallback(6, ephemeral, 443, cfg)`:
  both match; `zzz-https` is `portBased` and beats `aaa-tcp` →
  **`zzz-https`** (specific).

Same 5-tuple → different application label depending solely on the AppID knob.
This reproduces the issue's `aaa-tcp` vs `zzz-https-special` example exactly.

**Same-tier cases already AGREE.** When both matches are port-based (or both
protocol-only), the enabled path's `a.min(b)` (lowest id) and the disabled
path's `name < best` (alphabetically first) coincide — because id order ==
sorted-name order. So the two rules diverge **only across the specificity tier
boundary** (port-based vs protocol-only). This is why the existing
`app_catalog_overlap_lowest_id_wins` sub-cases (both port-based) keep passing
under PATH A — see §5.1 / §8.

### 2.3 What Junos/vSRX does — and why it is not the deciding factor

Junos application-identification (JDPI) is a **signature/behavior L7 engine**;
when it is on, the identified application overrides port heuristics. When it is
off, the session's application is resolved by service (protocol + port) match.
Public Junos docs describe **policy** evaluation as top-to-bottom first-match
([Juniper — Security Policy Applications], [Custom Policy Applications]) and
warn operators to always constrain custom applications by destination-port
([PacketForum — custom services on SRX]) — but do **not** publish an
authoritative tiebreak for two overlapping custom applications of differing
specificity resolving a *session label*.

The decisive point is internal, not external: **xpf has no L7 DPI**. Both the
"enabled" catalog and the "disabled" fallback are the same class of matcher —
protocol + port tuple → app name. The enabled `app_id` is not richer
identification; it is the same tuple match performed in Rust with a different
tiebreak. Therefore there is **no data-source reason** for the two to differ,
and "correct" reduces to "pick the more useful rule and apply it in both
places." **Specificity is the more useful rule**: (a) it is already the
deliberately-vetted disabled-path choice (#2577/#2578); (b) a port-specific app
(`junos-https`) beating a broad protocol-only catch-all matches operator
expectation; (c) "lowest app_id = alphabetically-first name" is an arbitrary
artifact of id assignment and carries no meaning to an operator.

---

## 3. Scope / value

**Value:** application labels are operator-facing security/forensic evidence —
`show security flow session`, the `application <name>` session filter (show AND
clear), RT_FLOW SESSION_CREATE/CLOSE, policy-deny and filter-log records, and
the Prometheus/API session views. A label that flips with the AppID knob erodes
trust and can make `clear security flow session application <x>` act on a
different set of sessions depending on the knob. Unifying removes a
whole class of "why does the same flow show two names?" confusion.

**Blast radius (all display/observability, NO enforcement):**
- ENABLED stamping consumers (Rust): `resolve_flow_app_id` →
  `event_emit.rs:90` (RT_FLOW / event-stream), `session_delta.rs:226,281`
  (conntrack publish / permit audit, via `lookup_admitted`),
  `forward_request.rs:211`, `poll_descriptor/filter.rs:271,341,397`.
- Label consumers (Go): `pkg/grpcapi/server_show_flow.go:241,272`,
  `pkg/grpcapi/server_sessions.go:159,205,474,519,635,660` (incl. the app
  filter used by show/clear), `pkg/api/sessions.go:971,1015,1080,1134`,
  `pkg/cli/session_filter.go:237,282`, `pkg/cli/cli_show_flow.go:368`.
- **Enforcement is untouched:** allow/deny uses
  `CompiledApplications::matches` (`policy.rs:1452`), a boolean matcher wholly
  independent of the `AppCatalog` label. PATH A does not touch it.

**Reachability:** requires two configured applications overlapping on the same
protocol where one is protocol-only and one is port-constrained, both present in
the catalog. With AppID enabled, `CatalogNames(cfg, includeAll=true)` includes
all predefined + user apps, so both are catalogued. A realistic operator config
(e.g. a broad `my-tcp { protocol tcp; }` plus a specific
`my-svc { protocol tcp; destination-port 8443; }`) hits it.

---

## 4. What exists (code-grounded integration surface)

- **Rust label catalog:** `AppCatalog` (`policy.rs:539-1697`):
  `from_snapshot` (`:1555`) buckets exact-single-dst entries into `exact_dst`
  and everything else (ranges, src-constrained, protocol-only) into `scan`
  (`:646-666`); `lookup_directional` (`:1606`) is the resolver; `lookup_forward`
  / `lookup_admitted` are the call-site wrappers (`:1658`, `:1683`). A scan
  entry is **protocol-only** iff `dst_low==0 && dst_high==0 && src_low==0 &&
  src_high==0`; otherwise it is **port-constrained**. `exact_dst` entries are
  always port-constrained.
- **Go catalog builder:** `pkg/appid/catalog.go` `BuildCatalog` — ids from 1 in
  sorted-name order; `CatalogEntry` carries `(Protocol, DstPortLow/High,
  SrcPortLow/High)`. Shipped to Rust via
  `pkg/dataplane/userspace/flow.go:144 buildAppCatalogSnapshot` →
  `AppCatalogEntrySnapshot` (`protocol.go:1089`), the input to
  `AppCatalog::from_snapshot`.
- **Go fallback:** `pkg/appid/runtime.go` `resolveTupleFallback` (`:199`) +
  `matchTuple` (`:239`) + `portInSpec` (`:262`). Binary `portBased` + name
  tiebreak. Also consults a **hardcoded 15-entry `builtinFallbacks`** map
  (`runtime.go:19-36`) after user apps — see §9 (set-membership divergence).
- **Existing parity harness:** `pkg/dataplane/appid_catalog_parity_test.go`
  (`TestAppCatalogIDsMatchCompileResultAppNames`) already asserts the Go id↔name
  maps agree across the two Go builders — the natural sibling location for a
  *label-resolution* parity test, though the Rust side of resolution lives in
  `userspace-dp` and needs its own mirrored assertion (see §5.3).
- **Tests pinning the current rules:**
  `policy_tests.rs::app_catalog_overlap_lowest_id_wins` (`:3644`, enabled) and
  `runtime_test.go::TestResolveTupleFallbackPrefersPortOverProtocol` (`:320`,
  disabled). PATH A updates the former's comment + adds a cross-tier case;
  leaves the latter unchanged.

---

## 5. Concrete design per path

### PATH A (RECOMMENDED) — unify enabled onto binary specificity

Change `AppCatalog::lookup_directional` so the final tiebreak prefers a
**port-constrained** hit over a **protocol-only** hit, and only falls back to
protocol-only when no port-constrained entry matches. Within a tier, keep the
existing lowest-id winner (which already == the disabled path's name tiebreak).

**5.1 Rust change (`userspace-dp/src/policy.rs`)**

Two viable shapes; the plan recommends **A1** (tag the scan entry) for clarity:

- **A1:** add a `port_constrained: bool` field to `AppScanEntry`, set in
  `from_snapshot` (`port_constrained = !(dst_low==0 && dst_high==0 &&
  src_low==0 && src_high==0)`). In `lookup_directional`, track the lowest-id
  port-constrained scan hit and the lowest-id protocol-only scan hit separately
  (scan is ascending-id, so the first of each is the lowest-id of each; break
  once both are found). Then:
  ```
  port_based = min(exact, first_port_constrained_scan)   // both port-based
  result     = port_based.or(protocol_only_scan_hit).unwrap_or(0)
  ```
- **A2:** no struct change — compute the protocol-only-ness inline in the scan
  loop from the range fields. Equivalent; slightly denser.

`exact` is always port-constrained, so it participates in the port-based tier.
For same-tier overlaps the result is byte-identical to today (`a.min(b)`), so
this is a **strict, additive** change to only the cross-tier case.

Perf: the scan loop already iterates in the worst case; the change replaces an
early `break`-on-first with a `break`-once-both-tiers-seen and two `Option`
mins. Negligible on the cold path (RT_FLOW / session-create), which is where
these resolvers run — the established fast path does not re-resolve.

**5.2 Contract alignment note**
The disabled path's `portBased` is `DestinationPort != "" || SourcePort != ""`.
The Rust `port_constrained` predicate above is the exact wire mirror (a
`source-port`-only app has `src != (0,0)` → port-constrained on both sides).
Document this shared rule in `pkg/appid/README.md` and
`docs/services-application-identification.md` as the single precedence contract:
**specificity tier (port-constrained > protocol-only), then lowest app_id ==
alphabetically-first name.**

**5.3 Parity test (cross-language)**
- **Rust:** update `app_catalog_overlap_lowest_id_wins` comment to
  "lowest id wins *within the same specificity tier*"; add
  `app_catalog_prefers_port_constrained_over_protocol_only` — protocol-only at
  id 1, exact-port at id 2, session on that port → expect id 2 (RED before the
  fix, GREEN after).
- **Go:** the `TestResolveTupleFallbackPrefersPortOverProtocol` already pins the
  Go side; add a sibling asserting the same expected name under the SAME app set.
- **Shared fixture (make-or-break):** add a canonical fixture of
  `(apps, tuple) → expected label` (JSON under `userspace-dp/tests/fixtures/`,
  mirroring `protocol_wire_v1.json`) consumed by BOTH a Go test (drives
  `BuildCatalog` + `resolveTupleFallback`) and a Rust test (drives
  `from_snapshot` + `lookup_directional` with the ids `BuildCatalog` would
  assign). Assert the resolved NAME is identical for every fixture row. This is
  the L03 "parity test asserting both agree" the issue asks for and the guard
  that keeps them from re-diverging. (Engineer-time detail: the Rust side can
  reconstruct ids deterministically from sorted-name order; the fixture should
  record the expected id/name so the test is self-checking.)

### PATH B (REJECTED) — unify disabled onto lowest-id

Flip `resolveTupleFallback` back to lowest-id/name-only (drop the `portBased`
tier). Rejected: directly regresses #2577/#2578 (a hostile-review-driven
correctness fix), and "alphabetically-first name wins" is meaningless to
operators — a specific `junos-https` would lose to a broad `aaa-tcp` purely
because "a" < "z". Wrong direction.

### PATH C (REJECTED) — document the divergence as intended

Rejected: intent-to-diverge is only defensible if the enabled path reflects a
richer identification source (real DPI) the disabled path cannot. xpf has no
DPI; both are tuple matchers. There is no product story that justifies two
answers for the same flow. Documenting it would enshrine a bug.

---

## 6. API preservation & hidden invariants

- **Wire format unchanged.** `AppCatalogEntrySnapshot` /
  `AppCatalogEntry` fields are untouched; `from_snapshot` still consumes the
  same rows. No `protocol_wire_v1.json` regen needed (label resolution is not a
  wire field). Confirm during /engineer.
- **id↔name lock-step preserved.** PATH A changes only WHICH matching id is
  returned, never how ids are assigned. `TestAppCatalogIDsMatchCompileResult
  AppNames` and `TestAppCatalogIDsMatchOnMalformedDestPort` stay green.
- **Directional service-slot invariant (#3321) preserved.** The fix operates
  after `(service_port, client_port)` selection; forward/reverse slot logic is
  unchanged. `lookup_admitted`'s post-NAT `rewrite_dst_port` (#3416) still feeds
  the service slot before the tier decision.
- **Same-tier determinism preserved.** Within a tier the winner is still the
  lowest id (= sorted-name first), so no new nondeterminism and no reordering of
  existing labels for same-tier configs.
- **Fast path untouched.** Resolvers run on the cold/session-create path; the
  established fast path does not call them.

---

## 7. Risk table

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Relabels sessions for existing overlapping configs (operators see a new name after upgrade) | Med (only cross-tier overlaps) | Low (label is now the *specific* app, which is the expected/better answer; enforcement unchanged) | Document in release note + README/state doc; the new label matches the already-shipped disabled-path behavior, so it is a convergence, not a fresh surprise |
| R2 | Rust tier logic mis-classifies a src-port-only app as protocol-only | Low | Med (would re-introduce a divergence) | `port_constrained` predicate mirrors Go `portBased` exactly incl. `SourcePort`; add a src-port-only fixture row to the parity test |
| R3 | Existing `app_catalog_overlap_lowest_id_wins` breaks | Low | Low | Both its sub-cases are same-tier (all port-based) → unchanged; only comment updated. Verified in §2.2/§8 |
| R4 | Cross-language fixture drift / brittleness | Med | Low | Self-checking fixture records expected id+name; single JSON SSOT consumed by both sides; CI runs both `go test ./pkg/appid/... ./pkg/dataplane/...` and `cargo test` |
| R5 | Perf regression on cold path | Very low | Low | Change is O(scan) already; two Option-mins + tier check; no fast-path impact |
| R6 | Misses adjacent divergences (§9) and ships a partial fix | Med | Low | Explicitly scope §9 items to follow-up issues; this fix closes the tiebreak divergence #3612 names |

---

## 8. Test plan

**Unit (deterministic, fail-on-revert):**
1. Rust `app_catalog_prefers_port_constrained_over_protocol_only`
   (`policy_tests.rs`): protocol-only id 1 + exact-port id 2 on the port →
   expect id 2. Also a range(id 3, port-based) vs protocol-only(id 1) case →
   expect id 3. Both RED before, GREEN after.
2. Rust `app_catalog_src_port_only_is_port_constrained`: a `source-port`-only
   app (dst `(0,0)`, src set) beats a protocol-only sibling.
3. Rust: keep `app_catalog_overlap_lowest_id_wins` (same-tier) GREEN — proves
   no same-tier regression; update comment only.
4. Go: sibling of `TestResolveTupleFallbackPrefersPortOverProtocol` asserting
   the SAME expected name for the §2.2 app set.

**Cross-language parity (the core acceptance test — "same traffic classifies
identically appid-on vs appid-off"):**
5. Shared fixture `(apps, tuple) → expected name` covering: (a) protocol-only vs
   exact-port, (b) protocol-only vs range, (c) exact vs range (same tier),
   (d) src-port-only vs protocol-only, (e) no-overlap sanity. A Go test resolves
   each row via `resolveTupleFallback` (appid-off model) AND a Rust test
   resolves via `lookup_directional` over the `BuildCatalog`-equivalent entries
   (appid-on model); both MUST equal the fixture's expected name. This fails if
   the two paths ever re-diverge.

**Regression / build:**
6. `go build ./...`, `go vet ./pkg/appid/... ./pkg/dataplane/...`, `gofmt -l`,
   `go test ./pkg/appid/... ./pkg/dataplane/... ./pkg/grpcapi/... ./pkg/api/...`.
7. `cargo test -p userspace-dp` (full, not filtered — per the campaign lesson
   that filtered subsets mask REDs).

**Live smoke (loss userspace cluster, /engineer time, optional but recommended):**
8. Configure the §2.2 overlapping apps; open a TCP/443 flow through the DUT;
   `show security flow session application zzz-https` with AppID enabled AND
   disabled → the session appears under the specific name in BOTH; RT_FLOW
   SESSION_CREATE carries the specific name in both. No enforcement change
   (permit/deny identical).

---

## 9. Out of scope (adjacent divergences → separate follow-up issues)

These are real but distinct from the tiebreak precedence #3612 names; call them
out so the fix is not over-scoped, and file follow-ups rather than silently
widening:

- **S1 — fallback set membership.** The disabled path's non-user fallback is a
  hardcoded 15-entry `builtinFallbacks` (`runtime.go:19-36`), NOT the full
  `config.PredefinedApplications` the enabled catalog uses. A predefined-only
  app (e.g. `junos-ldap` tcp/389) resolves under AppID-on but returns "" under
  AppID-off. This is a set-coverage gap, orthogonal to the tiebreak. → follow-up.
- **S2 — reverse-direction service-slot handling.** `lookup_directional`
  selects the service slot by `is_reverse` (#3321); `resolveTupleFallback`
  always treats `dstPort` as the service port and has no reverse flag, so a
  reverse-keyed conntrack entry can mislabel on the disabled path. Distinct from
  specificity. → follow-up (or fold into PATH A if the engineer finds it cheap).
- **S3 — README/state-doc signature drift.** `pkg/appid/README.md`'s
  `ResolveSessionName` signature is pre-#3428 (missing `srcPort`); refresh as
  part of the doc update in §5.2.

---

## 10. Open questions (for reviewers / user)

1. **Tier model depth:** adopt the disabled path's **binary** specificity
   (port-constrained > protocol-only), or a **3-tier** model (exact > range >
   protocol-only)? Binary is recommended — it is what the disabled path already
   does, so it guarantees parity; a 3-tier enabled path would itself re-diverge
   from the binary disabled path. If 3-tier is wanted, BOTH paths must move
   together. (Default: binary.)
2. **Should S2 (reverse direction) be folded into this PR or deferred?** It is a
   real appid-on/appid-off asymmetry but independent of the tiebreak; folding
   risks scope creep on the label path. (Default: defer to follow-up.)
3. **Release-note posture for R1 relabels:** is a state-doc/release note
   sufficient, or is a config-gated transition needed? (Recommended: doc only —
   the new label is strictly the better/specific one and merely matches
   already-shipped disabled-path behavior.)
4. **Parity fixture location/shape:** shared JSON under
   `userspace-dp/tests/fixtures/` consumed by both languages, or two mirrored
   in-code tables? (Recommended: shared JSON — single SSOT, drift-proof.)
5. **Confirm no enforcement dependency:** is there ANY code path where the
   stamped `app_id` (as opposed to `CompiledApplications::matches`) feeds an
   allow/deny/NAT decision? Investigation says no (label-only), but /engineer
   should re-grep `val.AppID` / `session.app_id` consumers before merge to keep
   the "display-only" claim honest.
6. **Predefined overlaps:** do any two *predefined* junos applications overlap
   across the specificity boundary on the same protocol (making the divergence
   reachable with zero custom apps)? Spot-check during /engineer; if yes, R1
   reachability rises from "custom-config" to "default-ish".

---

## 11. Recommendation

Ship **PATH A**: make `AppCatalog::lookup_directional` (the enabled/Rust label
path) prefer a port-constrained match over a protocol-only match, tie-broken by
lowest app_id — the exact binary-specificity rule `resolveTupleFallback` (the
disabled/Go fallback) already implements (#2578). Add a cross-language parity
test over a shared fixture so the two paths cannot silently re-diverge, and
document the single precedence contract in `pkg/appid/README.md` +
`docs/services-application-identification.md`.

Rationale: the divergence is a genuine, reachable, display-layer classification
bug with no product justification (no DPI → both paths are the same tuple
matcher and must agree). Specificity is the correct unifying rule (vetted by
#2577/#2578, matches operator expectation, and "lowest-id = name-first" is
meaningless). The change is strictly additive for same-tier configs (existing
labels and tests unchanged), touches only the cold path, and leaves enforcement
(`CompiledApplications::matches`) completely untouched.

Sources for §2.3:
- Juniper — Security Policy Applications and Application Sets
  (juniper.net/documentation/.../policy-application-sets-configuration.html)
- Juniper — Custom Policy Applications
  (juniper.net/documentation/.../security-policy-custom-applications.html)
- PacketForum — "Be extremely careful when creating custom services on SRX"
