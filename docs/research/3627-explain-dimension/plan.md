# #3627 part-B (M07/L02) — match-policies explain mode + host-inbound service token: plan of action

- Issue: psaab/xpf#3627 (part-A / M06 "echo queried zones" already MERGED via PR #3638)
- Research branch: `research/3627-explain-dimension`
- Base: origin/master `63d1052e2`
- Revision: r2 (folds Codex + AGY + Claude-SMR hostile plan review; see §12)
- Verdict (converged): **PLAN-DEFER** (`plan-deferred-research`) for part-B, split:
  - **B2 (per-dimension miss explanation): KILL** — unanimous across all three
    reviewers. Not Junos parity; the OR-over-apps ambiguity forces a coarse
    `application` dimension that does not deliver the requested
    protocol/src-port/dst-port answers for the common wrong-port case, so ROI is
    near-zero. Do not build.
  - **B1 (host-inbound admitting token + message accuracy): DEFER** — real
    diagnostic-accuracy value (post-#3405 a no-stanza zone default-DENIES
    host-inbound, so the current "local delivery proceeds" message is actively
    misleading, not merely incomplete), but it is a DIAGNOSTIC-tool accuracy gap,
    NOT a dataplane enforcement bug (the kernel-nft + Rust paths already deny
    correctly). The r1 design was not implementation-ready (it carried the stale
    pre-#3405 "no-stanza = open" model and an under-specified classifier); r2
    corrects the design so a future `/engineer` can pick it up. Build **B1a**
    (structured SSOT) only — B1b is too weak (all three agree).
- Reviewer split: 2-of-3 DEFER (Codex + Claude SMR). AGY dissented to
  PLAN-READY-for-B1 on a "critical security-posture bug" premise that is refuted
  by #3405 (the enforcement paths deny correctly; only the diagnostic is
  incomplete) — so the converged disposition is DEFER, not READY. All three agree
  B2 is KILL and that the r1 plan was not build-ready as written.

---

## 1. Issue framing

`show security match-policies` / REST `GET /api/v1/security/match` / gRPC
`MatchPolicies` are the operator-side security-policy simulator. They return a
binary outcome plus the matched policy's attributes:

- **On a match**: policy name, id, scope zones, action, src/dst addresses,
  applications.
- **On a no-match**: only `action = "<default> (default)"` + `default_used`.
- **On host-inbound** (`to-zone junos-host`, no host-bound policy matched):
  only the fixed string `host-inbound (local delivery; not governed by
  transit/global/default policy)`.

Part-B is the design-fork half of the review-122 finding:

- **B2 (M07)**: on a NEGATIVE result the simulator cannot say **which match
  dimension** eliminated the candidate policies (zone-pair / source-address /
  destination-address / application / source-port / destination-port /
  protocol). The operator must fall back to `show security policies from-zone X
  to-zone Y` + eyeball, or iterative query relaxation, or a packet capture.
- **B1 (L02)**: the host-inbound response does not name the **system-service /
  protocol token** that admitted local delivery (`ssh` / `ping` / `all` / a
  `protocols` token). Worse, the current fixed string asserts local delivery
  *unconditionally*, but real admission is gated by the ingress zone's
  `host-inbound-traffic { system-services; protocols; }` (enforced in the kernel
  nft `chain input` mirror + the Rust XSK classifier). So the current message
  can over-state admission.

Fix direction from the issue: an OPTIONAL explain/debug mode gated behind a
request flag so the hot path stays lean; return the host-inbound service token
in host-inbound diagnostics.

## 2. Honest scope/value framing

This is a **diagnostic tool**, not the dataplane. It runs on the operator plane
(REST/gRPC/CLI) at human interaction rates, never per packet. "Don't bloat the
hot match path" is therefore not really about CPU — it is about not adding
per-candidate allocation/traversal to the DEFAULT match path, which is called
programmatically (e.g. session-table cross-reference tooling). The explain work
must be **opt-in** and must **reuse the exact same matcher** so it cannot drift
from the verdict it explains.

Value, stated honestly:

- **B1 (host-inbound token): genuinely useful + near-parity + accuracy fix.**
  It closes a real gap — the current message implies unconditional local
  delivery, but `host-inbound-traffic` gates it. Naming the admitting token (or
  reporting "no host-inbound-traffic service admits this" → the nft filter would
  drop) is more correct, not just more verbose. Still inferrable today via
  `show security zones <zone>` (which lists the tokens) + mental port mapping.

- **B2 (per-dimension explanation): marginal nicety, NOT Junos parity.** Real
  Junos `show security match-policies` returns the first matching policy or "No
  matching policy found"; the `result-count N` extension returns the first N
  *matching* policies (shadow analysis). Neither explains **why** a policy did
  NOT match, dimension by dimension. So B2 is a value-add BEYOND vSRX, not a
  parity requirement. The operator can already infer the failing dimension for
  small rule sets by comparing the query against `show security policies
  from-zone X to-zone Y`. Value grows with rule-set size (hundreds of rules),
  where eyeballing is tedious.

Given Low severity + workarounds + the two caveats in §8, the recommendation is
DEFER, not build-now. KILL is defensible for B2 alone; B1 is worth keeping alive.

## 3. Current state — confirmed against origin/master 63d1052e2

**Matcher returns only match/no-match/host-unmatched, no per-dimension data.**

- `pkg/policymatch/policymatch.go`:
  - `Result` (lines 277-328) carries `Matched / Global / DefaultUsed /
    HostInboundUnmatched / FromZone / ToZone / PolicyID / PolicyName /
    Description / Action / SrcAddresses / DstAddresses / Applications`. There is
    **no** miss-reason field and **no** host-inbound-service field.
  - `ruleMatches(cfg, q, pol) bool` (624-642) is the per-rule gate: scheduler →
    source address → destination address → application, each returning `false`
    on the first failure. **The failing dimension is computed internally and
    then discarded** — exactly the information B2 wants.
  - `matchAddr` (669-716), `matchApp` (891-920), `matchSingleApp` (922-1014):
    `matchApp` ORs over the app list; `matchSingleApp` checks protocol → ICMP
    type/code → dest-port → src-port, each `return false` on first failure.
  - `matchJunosHost` (497-532) returns `HostInboundUnmatched:true` with **no**
    token — it only consults `security policies … to-zone junos-host` rules, NOT
    the ingress zone's `host-inbound-traffic` stanza. The admitting token is not
    modelled here at all.
- Handlers are thin adapters that map `Result` → response:
  - REST `pkg/api/security.go` `matchPoliciesHandler` (433-624); response type
    `pkg/api/types.go` `MatchPoliciesResult` (440-491) — M06 `QueriedFromZone/
    QueriedToZone` already present (PR #3638). No explain / host-inbound-service
    fields.
  - gRPC `pkg/grpcapi/server_cluster.go` `MatchPolicies` (123-282);
    `proto/xpf/v1/xpf.proto` `MatchPoliciesResponse` (712-…) fields 1-14 used;
    15+ free. `MatchPoliciesRequest` fields 1-9 used; 10+ free.
  - CLI `pkg/cli/cli_show_security.go` `showMatchPolicies` (368-539); the
    host-inbound branch (504-508) prints the fixed "local delivery proceeds"
    lines with no token. Remote `cmd/cli` + gRPC `ShowText` `test-policy:`
    (`showTestPolicy`) are the other simulator adapters (see
    `pkg/policymatch/README.md`).

**Host-inbound token knowledge already has an SSOT — but as nft strings, not a
structured tuple table.**

- `pkg/config/host_inbound_tokens.go`: `KnownHostInboundSystemServices`,
  `KnownHostInboundProtocols`, `HostInboundL2Protocols`,
  `HostInboundServiceFamily`, `HostInboundProtocolFamily`,
  `HostInboundAllExpansionProtocols()` — the recognized-token + family SSOT.
- `pkg/daemon/daemon_nft.go`: `hostInboundServiceMatches(token, family)` (588-666)
  and `hostInboundProtocolMatches(token, family)` (672-760) map each token to nft
  match **strings** ("tcp dport 22", "icmp type echo-request", "meta l4proto 89",
  "udp dport { 3784, 3785, 4784 }", …). `hostInboundAllowsAll` (486-493) handles
  `all`/`any-service`. `ident-reset` → reject (TCP/113), not admit.
- `pkg/dataplane/userspace/zones.go`: `BuildZoneHostInboundViews(cfg)` (140-…)
  returns per-zone `ZoneHostInboundView{Zone, Interfaces, SystemServices,
  Protocols, V4Addrs, V6Addrs}` — the resolved effective token set per zone
  (incl. interface-level overrides, #3362).
- Rust mirror: `userspace-dp/src/afxdp/forwarding/host_inbound.rs`
  `classify_system_service` / `classify_protocol`; held in lockstep by
  `TestHostInboundNftMatchesKnownTokens` +
  `TestHostInboundRustClassifierMatchesGoSSOT` (#3486).

Key consequence: to *classify* a query tuple to an admitting token, we need a
**structured** (l4proto, ports[], icmp-type, family, verdict) table. Today only
the nft **string** form + the Rust form exist. That is the crux of B1's design
(and its main risk — a third representation must not drift).

## 4. What's already shipped / relevant

- **#3042** unified the three per-surface shadow matchers into `policymatch` —
  the whole point was to KILL divergent matchers. Any B2 explain path **must
  not** reintroduce a parallel matcher; it must be a refactor of the single one.
- **#3638 / part-A / M06**: `queried_from_zone` / `queried_to_zone` on every
  response. Done; not re-litigated here.
- **#3285 / #3375**: host-inbound verdict string + `DisplayAction` SSOT.
- **#3331 / #3623**: matched-policy scope zones + stable `PolicyID` (pointer
  presence). B2 per-candidate explanation would reuse `RuntimePolicyIDs` for the
  candidate ids.
- **#3200 / #3311 / #3341 / #3225 / #3486**: the host-inbound token SSOT + family
  scoping + nft/Rust parity web B1 must plug into.

## 5. Concrete design — phased, minimal-first

Two independent slices. Ship order if built: **B1, then B2.** Both are opt-in
and additive; neither changes any existing verdict.

### B1 — host-inbound admitting service token

**Where the logic lives.** A structured classifier in
`pkg/dataplane/userspace` (already imported by `policymatch`; keeps layering
clean — `policymatch → dpuserspace`, never `policymatch → daemon`). Signature:

```go
// HostInboundAdmit reports which host-inbound-traffic token admits the query
// tuple for the ingress zone's view, mirroring the nft/Rust classifiers.
func HostInboundAdmit(view ZoneHostInboundView, proto uint8, dstPort int,
    icmpType *uint8, family string) (token string, admitted bool)
```

It walks `view.SystemServices` then `view.Protocols`, returns `("all", true)` /
`("any-service", true)` immediately for the full-admit tokens, else the first
token whose structured match admits the tuple. `ident-reset` is reported as
NOT-admit (it resets, matching nft). Returns `("", false)` when nothing admits.

**Drift control (the crux).** Do NOT hand-write a third token→port table. Two
options, in preference order:

- **B1a (drift-proof, more work):** extract a single structured SSOT
  `HostInboundServiceMatch(token, family) []L4Match` /
  `HostInboundProtocolMatch(...)` in `pkg/config` (extending
  `host_inbound_tokens.go`), where `L4Match{Proto uint8; Ports []PortRange;
  ICMPType *uint8}`. Refactor `pkg/daemon` `hostInbound*Matches` to *render* nft
  strings from this table, and have the new classifier *match* against it. One
  table, three consumers (nft render, Rust parity test, classifier). The
  existing `TestHostInbound*` parity tests continue to guard it.
- **B1b (lighter, bounded drift): REJECTED (all three reviewers).** A
  self-contained classifier + domain-parity test bounds *which* tokens are known
  but NOT per-token *port* correctness — so it can claim "ssh admitted tcp/22"
  while a future nft edit moves ssh to a different port and only nft+Rust get the
  parity test. For a feature whose entire claim is "this token admitted THIS
  tuple", port-level drift is disqualifying. B1a is therefore MANDATORY if B1 is
  ever built: extract the structured `L4Match` SSOT, make the `pkg/daemon` nft
  builder RENDER from it, add a Rust parity test asserting per-tuple (not just
  domain) equivalence with `host_inbound.rs`. This is real work on a
  security-sensitive path (R5) — a core reason B1 DEFERS rather than shipping.

**CORRECTED post-#3405 admission model (Codex catch — r1 was wrong).** r1 said
"no-stanza zone = admit-all (open)". That is STALE. Since #3405 EVERY configured
security zone is host-inbound-ENFORCING (Junos default-deny parity): a zone with
interfaces but NO `host-inbound-traffic` stanza carries
`HostInboundConfigured=true` with EMPTY token sets → `admits()` returns false for
every service → default-DENY, identical to an empty `host-inbound-traffic { }`
(verified `pkg/dataplane/userspace/zones.go:198,475`, RED-on-revert test
`zones_host_inbound_test.go` `TestNoStanzaZoneDefaultDeniesBothSurfaces`). So the
current simulator "local delivery proceeds" message is ACTIVELY MISLEADING for a
no-stanza zone (the box would drop the packet), not merely incomplete. This
STRENGTHENS B1's rationale but INVALIDATES the r1 "reuse HostInboundConfigured
open/closed distinction" wiring — there is no open case among configured zones.

**Classifier scoping (Codex + AGY catch — r1 under-specified).** A zone-only
lookup can LIE. The classifier must, faithfully to the enforcement paths:
  - key on the **effective per-interface view**, not the zone: #3362
    `BuildZoneHostInboundViews` can emit MULTIPLE views per zone (zone-level ∪
    per-interface override), each scoped to that interface's firewall-local
    addresses. The query has no ingress interface, so the honest model is: report
    admission if ANY view for the ingress zone admits the tuple, and name the
    token — with a caveat that a per-interface override may narrow it. (A future
    surface could accept an optional interface selector.)
  - honor the **global pre-accepts (#3171)**: ICMP/ND/PMTUD and the ESP/AH data
    plane are accepted BEFORE any per-zone deny; the classifier must report those
    as admitted regardless of the zone token set (else it under-reports).
  - exclude the **lifeline interfaces** (fxp0/em0/fab*) that never reach the
    classifier (their addresses are dropped from the view).
  - handle a **missing dst_ip / protocol**: with no protocol the tuple cannot be
    classified against a port/proto token — return "indeterminate", never a false
    admit.

**Wiring into the simulator.** `matchJunosHost` gains access to the ingress
zone's view(s) (build once in `Match`, thread in). `Result` gains a
PRESENCE-SAFE field (Codex catch — a bare `string ""` cannot distinguish "not
computed" / "no token admits" / "global pre-accept" / "admitted by token"):

```go
type HostInboundAdmission struct {
    Status HostInboundStatus // notComputed | denied | globalAccept | tokenAdmit
    Token  string            // set only when Status==tokenAdmit
}
HostInbound *HostInboundAdmission // nil off the host path
```

**Response schema (additive, presence-safe).**

- REST `MatchPoliciesResult`: `HostInbound *HostInboundAdmission
  \`json:"host_inbound,omitempty"\`` (nested object with a status string), NOT a
  bare `host_inbound_service` string.
- proto `MatchPoliciesResponse`: a new `HostInboundAdmission host_inbound = 15;`
  message (status enum + token string), so absence and the four states are
  distinguishable on the wire.
- CLI host-inbound branch prints the status: `admitted by system-services ssh` /
  `admitted by global ICMP/ND accept` / `DENIED by host-inbound-traffic (no
  service admits this tuple; the box would drop it)` / `indeterminate (specify
  protocol)`.

### B2 — per-dimension miss explanation — **VERDICT: KILL** (unanimous)

Retained for the record; NOT to be built. All three reviewers agree the
OR-over-apps coarseness (below) plus non-Junos-parity + Low severity make ROI
near-zero. The design sketch stays so a future reader understands *why* it was
killed, not merely that it was.

**Refactor, don't fork (would have been mandatory).** Replace the boolean gate
with a reason-returning gate; the boolean becomes a trivial wrapper so there is
exactly ONE matcher:

```go
type MissDim int
const (
    MissNone MissDim = iota
    MissScheduler
    MissSourceAddress
    MissDestinationAddress
    MissApplication
)
func ruleMissReason(cfg, q, pol) MissDim // MissNone == would-match
func ruleMatches(cfg, q, pol) bool { return ruleMissReason(cfg, q, pol) == MissNone }
```

**Granularity is honestly coarse for the application axis.** The issue lists
`application / source-port / destination-port / protocol` as *separate*
dimensions, but the runtime application matcher (`matchApp`) ORs over the app
list and `matchSingleApp` checks protocol→icmp→dst-port→src-port *per app*. Under
OR there is no single unambiguous sub-reason (app A fails on protocol, app B on
port). So B2 reports **`application`** as one dimension. It MAY attach a
best-effort, explicitly-non-authoritative hint for the single-app case
("closest: junos-http destination-port 80 ≠ 8080"), but must never present the
sub-dimension as authoritative. This is a deliberate, documented limitation.

**Candidate attribution.** Do not report a single "the" failing dimension —
that is arbitrary when candidates fail differently. Instead, when
`Query.ExplainMiss` is set AND the result is a no-match, walk the candidate tier
set and record one entry per candidate policy the query reached.

**The tier traversal itself must be FACTORED OUT of `Match`, not re-walked
alongside it (Codex catch).** A `ruleMissReason` wrapper alone is insufficient:
if explain re-implements the tier loop (exact zone-pair → merged single-wildcard
→ both-any → scoped globals → the #3355 zone-id-0 guard → the junos-host path),
it can drift from `Match`'s exact eligibility/merge/scoping logic — the #3042
divergence bug one level up. The refactor must extract a single candidate
iterator that BOTH `Match` (first-hit) and explain (all-candidates-with-reason)
consume. This is a larger refactor of the core matcher than r1 implied — another
reason KILL (not DEFER) is right for B2: the SSOT-safe way to build it is
disproportionate to its value. The per-candidate record shape would have been:

```go
type MissExplain struct {
    PolicyName string
    PolicyID   uint32   // via RuntimePolicyIDs, same as matched
    Global     bool
    FromZone   string   // candidate scope
    ToZone     string
    Miss       MissDim  // first failing dimension for THIS candidate
}
```

`Result` gains `Explain []MissExplain` (nil unless requested). If the zone pair
itself is undefined/id-0 (the #3355 straight-to-default path) or the zone pair
has zero candidate policies, `Explain` is empty and the render says "no
candidate policies in this zone pair" — which *is* the dimension answer
(zone-pair eliminated everything).

**Opt-in flag threading.**

- Query: `ExplainMiss bool`.
- REST: `?explain=1` (default off). Populate `Explain` in `MatchPoliciesResult`
  only when set.
- proto: `MatchPoliciesRequest` `bool explain = 10;`; `MatchPoliciesResponse`
  `repeated PolicyMiss explain = 16;` (new message mirroring `MissExplain`).
- CLI: `show security match-policies … explain` trailing keyword → tabular
  "Candidate policies not matched:" block.

**Cost isolation.** The explain traversal runs only when the flag is set. The
default path calls `ruleMatches` (unchanged wrapper) and allocates nothing new.

## 6. API / interface preservation

- All new fields are additive with `omitempty` / new proto field numbers
  (REST 15/16 JSON keys, proto req field 10, resp fields 15 & 16). No existing
  field changes type or meaning. Old clients ignore unknown JSON keys / proto
  fields.
- `Result` gains fields only; existing consumers unaffected (they read the
  fields they already read).
- `ruleMatches` keeps its exact signature and semantics (wrapper over
  `ruleMissReason`) — zero behavior change proven by the existing
  `policymatch_test.go` suite staying green with no edits.
- gRPC `ShowText` `test-policy:` topic and remote `cmd/cli`: explain is optional;
  they may keep the non-explain output initially (documented as a follow-up
  surface, not a parity gap since explain is opt-in everywhere).

## 7. Hidden invariants the change must preserve

- **Single matcher (#3042).** B2 must be a refactor; NO second traversal that
  can disagree with the verdict. The wrapper identity `ruleMatches ==
  (ruleMissReason == MissNone)` is the guard; a test asserts explain entries are
  consistent with the verdict (a candidate reported `MissNone` is impossible on a
  no-match result).
- **Host gate has no transit fallback (#3285).** B1 must not turn "no admitting
  token" into a transit default verdict — the host path stays host-only. The
  token is *additional* context, not a new verdict tier.
- **Host-inbound SSOT parity (#3200/#3311/#3341/#3225/#3486).** B1's classifier
  must join the parity web (B1a) or at least the domain-parity test (B1b) so
  `ident-reset`=reject, L2 (`isis`)=no-op, family scoping (dhcp=v4/dhcpv6=v6,
  ospf=v4/ospf3=v6), and `protocols all` expansion all agree with nft + Rust.
- **Post-#3405 host-inbound default-deny.** EVERY configured zone enforces
  host-inbound; a no-stanza zone default-DENIES (not open). B1 must model deny as
  the baseline and report the global pre-accepts (#3171 ICMP/ND/PMTUD, ESP/AH)
  and lifeline exclusions faithfully, or it will over- or under-report admission.
- **Fail-closed input validation** (ports/proto/ICMP/IP) stays at the adapter
  boundary; explain adds no new silent-coerce path.

## 8. Risk assessment

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | B1 classifier drifts from nft/Rust token→port truth → simulator reports a token that does not actually admit (false confidence) | Med (if B1b) / Low (if B1a) | Med | B1a single structured SSOT feeding nft render + classifier + parity test; else domain-parity test + explicit "port correctness not machine-verified" caveat |
| R2 | B2 reintroduces a shadow matcher that disagrees with the verdict (the exact #3042 class of bug) | Low (design forbids it) | High | Mandatory refactor: boolean = wrapper over reason; consistency test |
| R3 | B2 sub-dimension (protocol/src-port/dst-port) reported authoritatively despite OR-over-apps ambiguity → misleading | Med | Med | Report coarse `application`; sub-hint explicitly non-authoritative + single-app-only |
| R4 | Candidate-attribution confuses operators ("which policy is it blaming?") | Med | Low | Per-candidate list, not one blamed dimension; empty list = zone-pair eliminated all |
| R5 | Scope creep: B1a refactor of the nft builder touches a security-sensitive path | Med | Med | Behavior-preserving render refactor guarded by existing nft golden/parity tests; or choose B1b |
| R6 | Low ROI — a Low-severity nicety consuming build+quad-review budget with existing workarounds | High | Low | This plan; DEFER unless demand appears |
| R7 | B1 classifier keys on zone not the #3362 per-interface view / address / global pre-accepts → reports a token that does not actually admit for that interface | Med | Med | Classifier scoping model in §5 (per-view union + #3171 pre-accepts + lifeline exclusion + indeterminate on missing proto) |
| R8 | B2 explain re-walks the tier set beside `Match` and drifts from its eligibility/merge/scoping (#3042 one level up) | Med | High | Factor a single candidate iterator out of `Match`; but the cost is why B2 is KILLed |
| R9 | Presence-hostile schema (`string host_inbound_service`) cannot distinguish not-computed / denied / global-accept / token-admit | Med | Med | Nested `HostInboundAdmission{status,token}` object + proto message (§5) |

## 9. Test plan

If built (per slice):

- **B1**
  - `pkg/dataplane/userspace`: table test `HostInboundAdmit` — ssh→tcp/22 admits,
    tcp/23 does not; ping→icmp echo (v4) + icmpv6 echo (v6); `all`/`any-service`
    admit everything; `ident-reset` NOT admit; family scoping (dhcp v4-only,
    dhcpv6 v6-only, ospf v4 / ospf3 v6); `protocols all` expansion admits bgp/179
    but not ssh/22; L2 `isis` never admits an IP tuple.
  - Parity: extend/observe `TestHostInboundNftMatchesKnownTokens` domain (B1b) or
    the structured-SSOT parity test (B1a).
  - `pkg/policymatch`: `Match` with `to-zone junos-host` returns
    `HostInboundService` = the admitting token; no-admit zone returns "".
  - `pkg/api` + `pkg/grpcapi`: `host_inbound_service` present on the host path,
    absent otherwise; REST/gRPC agree (SSOT).
  - `pkg/cli`: host-inbound branch prints the admitting token / "would be
    dropped".
- **B2**
  - `pkg/policymatch`: refactor-parity — full existing `*_test.go` suite green
    with NO edits (proves `ruleMatches` wrapper is behavior-identical).
  - `ruleMissReason` table test: each dimension in isolation (scheduler-inactive,
    src-addr miss, dst-addr miss, application miss) returns the right `MissDim`.
  - `Match` with `ExplainMiss`: no-match in a populated zone pair returns one
    `MissExplain` per candidate with the correct first-failing dimension; empty
    zone pair / undefined zone returns empty `Explain`.
  - Consistency invariant test: on any no-match `Result`, no `Explain` entry has
    `Miss == MissNone`.
  - `pkg/api`/`pkg/grpcapi`/`pkg/cli`: `explain` flag off = byte-identical to
    today; on = the explain block; default path allocates no explain data.
- **Whole**: `go test ./pkg/policymatch/... ./pkg/api/... ./pkg/grpcapi/...
  ./pkg/cli/... ./pkg/dataplane/userspace/... ./pkg/daemon/...` (the last two for
  B1 parity). No dataplane smoke needed — pure operator-plane, no forwarding
  path touched.
- **Docs**: update `pkg/policymatch/README.md`, `pkg/api/README.md`,
  `pkg/grpcapi/README.md`, `proto/README.md`, and `pkg/cli/README.md` for the new
  opt-in fields (module-doc contract per CLAUDE.md).

## 10. Out of scope (explicit)

- Any change to the dataplane forwarding / enforcement path — this is
  operator-plane diagnostics only.
- Changing any existing verdict, action string, or default field.
- Junos `result-count N` first-N-matching-policies shadow analysis (a different
  feature; not requested here).
- Reworking `matchApp` OR semantics to make sub-dimension attribution
  authoritative (would change matching cost/shape for a cosmetic hint).
- Making explain mandatory / default-on.

## 11. Open questions for adversarial review

1. **DEFER vs KILL vs READY.** Is B1 (accuracy fix + near-parity) strong enough
   to argue PLAN-READY for B1 alone while B2 defers/kills? Or is the whole
   part-B a DEFER? Or is B2 low-value enough to KILL outright?
2. **B1a vs B1b.** Is the structured-SSOT refactor (B1a, drift-proof, touches the
   nft builder) justified for a Low item, or is the domain-parity-only classifier
   (B1b) an acceptable risk with a documented caveat?
3. **B2 attribution model.** Is per-candidate `[]MissExplain` the right shape, or
   would operators prefer a single "closest miss" summary (and accept its
   arbitrariness)?
4. **Coarse application dimension.** Is reporting `application` (not
   protocol/src-port/dst-port) acceptable given the OR-over-apps ambiguity, or
   does the coarseness defeat B2's purpose for the common
   "wrong-port/wrong-protocol" case — arguing for KILL?
5. **Accuracy-fix carve-out.** The current host-inbound message over-states
   unconditional local delivery. Should the "host-inbound-traffic gates this"
   correction ship as a small standalone fix EVEN IF the token-naming feature
   defers/kills? (It is arguably a correctness bug, not a nicety.)

## 12. Adversarial review convergence (r1 → r2)

Three plan reviewers (Copilot joins later at `/engineer` on the code PR, which
there will be none of unless the user reactivates B1). Verified against
origin/master `63d1052e2`.

- **Codex (hostile, `codex exec` read-only in the worktree): VERDICT PLAN-DEFER.**
  "B2 is low-value, non-Junos-parity, and too coarse to justify build budget,
  while B1 is a real accuracy problem but the written plan is not
  implementation-ready because it carries stale no-stanza/open semantics and an
  under-specified host-inbound classifier model. Build nothing from this plan
  as-is; rewrite B1 around #3405 truth, per-interface/address-selected views, and
  a real structured/parity story, and leave B2 deferred or killed." Substantive
  catches folded into r2: (a) the #3405 no-stanza-DENY correction (r1 factual
  error); (b) B1 classifier must key on the per-interface view/address + global
  pre-accepts; (c) B2 candidate iterator must be factored out of `Match`, not
  re-walked; (d) presence-hostile `string host_inbound_service` → nested
  status+token.

- **AGY (adversarial): VERDICT PLAN-READY for B1 / PLAN-KILL for B2.** Agreed B2
  is KILL (OR-over-apps coarseness → near-zero value) and that B1a (structured
  SSOT feeding nft render + classifier + per-tuple Rust parity) is mandatory and
  B1b too weak. Dissented on B1 urgency, framing the missing host-inbound gating
  as a "critical security-posture validation bug (false-positive admission)".
  **Rebuttal (why the converged disposition is DEFER, not READY):** the
  match-policies simulator is a DIAGNOSTIC tool; it does not enforce. Post-#3405
  the kernel-nft primary path and the Rust AF_XDP secondary path already
  default-DENY host-inbound correctly — there is no dataplane false-positive
  admission. The gap is that the diagnostic TOOL over-states admission, i.e. an
  accuracy defect in an operator convenience, not a security hole. Combined with
  Codex's "not implementation-ready as written", B1 is DEFER: correct the design
  (done in r2), pick it up later if demand appears.

- **Claude SMR (hostile, `claude-smr-plan-r1.md`): VERDICT PLAN-DEFER.** B2
  KILL-defensible in isolation (coarse `application` near-fatal for the common
  wrong-port case); B1 real-but-modest value with no cheap-and-safe build option
  (B1a scope-creep on the nft path, B1b port-drift trap); the one cheap correct
  extract is a message-completeness one-liner, not the token machinery. Rejected
  PLAN-READY (ROI too low for a Low item).

**Convergence:** unanimous **B2 = KILL**; **B1 = DEFER** by 2-of-3 (Codex +
Claude SMR), AGY's lone READY-for-B1 resting on a security-severity premise
refuted by #3405 (enforcement is correct; only the diagnostic is incomplete) and
undercut by all three agreeing the r1 plan was not build-ready. Global research
disposition: **PLAN-DEFER** for part-B, with the corrected B1a design preserved
here for future pickup and B2 killed.

**If the user wants any near-term motion** (optional, not required by this
verdict): the cheapest correct slice is a standalone one-line correction of the
host-inbound verdict string so it no longer implies unconditional local delivery
(e.g. "governed by this zone's host-inbound-traffic system-services/protocols")
— shipping accuracy without the structured classifier, per-view scoping, or
schema changes. That is a `/engineer`-sized micro-fix, not part-B.
