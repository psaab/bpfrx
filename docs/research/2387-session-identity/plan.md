# #2387 — session/flow identity is the bare 5-tuple: the DENY-vs-ISOLATE decision

**Revision:** v6-r1 (DRAFT — awaiting r1 hostile review)
**Verified against:** origin/master @ `e80db2eae`
**Branch:** `research/2387-session-identity` (docs only — no production source)

> **Relationship to the existing decision record.** `docs/research/2387-vrf-flow-identity/plan.md`
> is on master and is the converged **v4 PLAN-DEFER (3-of-3)** decision record, plus a
> **v5 §0 engineering-time addendum that was never hostile-reviewed**. That addendum
> retracts the single biggest cost objection that justified the deferral. This document
> is the review pass on that retraction. It does **not** re-litigate the v4 body — §4b
> (PBR reachability), §4e (dead `routing_table` slot) and §7 (reverse-match symmetry)
> are adopted as-is, each re-verified first-hand below. At `/engineer` time the two
> documents should be consolidated into one; keeping both is a doc-coherence hazard.

---

## 1. Status

**DRAFT v6-r1.** The prior pass converged **PLAN-DEFER 3-of-3** on two grounds:

- **(a)** widening `SessionKey` forces an HA session-sync **wire hard break**, a
  `CurrentHAProtocolVersion` bump and a non-rolling both-nodes upgrade; and
- **(b)** an open product-scope question — "is overlapping-subnet multi-tenant VRF
  supported?"

**Ground (a) is false.** I re-verified this first-hand (§4.3): the discriminator does
not have to ride in the fixed-width key block. **Ground (b) is settled in practice**:
Track A shipped the overlap check as a *warning*, so the config commits today and the
operator is told the topology is not session-isolated.

Track A is **complete and shipped**. The issue is now a single binary decision, and
this document exists to drive that decision to a converged verdict.

## 2. Issue framing

`SessionKey` (`userspace-dp/src/session/key.rs:10-17`) is exactly:

```
{ addr_family: u8, protocol: u8, src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16 }
```

**Re-verified on `e80db2eae`: unchanged.** No ingress ifindex, no VLAN, no zone, no
VRF. Two flows sharing a 5-tuple in different forwarding contexts share one conntrack
entry, so the second flow inherits the first's cached egress / NAT binding / policy
verdict without its own policy ever being evaluated.

### Blast radius — recounted (the parent's figures were slightly stale)

| Metric | Prior figure | **Measured on `e80db2eae`** |
|---|---|---|
| `SessionKey` refs, Rust | 725 | **743** (413 outside test files) |
| `SessionKey {` struct literals, Rust | — | **301** (191 under `src/`, 110 in test files) |
| `SessionKey` refs, Go | — | **1154** — but this is the *separate* `dataplane.SessionKey` C-mirror type, a fixed-layout byte struct, not the Rust type. Counting it in one blast-radius number conflates two types. |

The honest framing: **301 struct-literal sites** is the mechanical churn (a field
added to a struct literal), and roughly a third of those are test fixtures. The
"743" and "1154" reference counts overstate the edit surface — most references are
`&SessionKey` parameter passing that needs no change at all.

## 3. Honest scope / value framing

The defect is **real and reachable**, not theoretical, and I confirmed the
reachability trace first-hand (§4.1-§4.2). But it requires a specific config:
overlapping L3 across two routing-instances **plus** PBR `then routing-instance` to
make each VRF actually forward. That config commits today with a warning.

Against that: the fix touches the conntrack identity — the single most
security-critical data structure in the dataplane — on the per-packet lookup path,
across ~300 literal sites and two wire surfaces.

*If reviewers conclude the cost is not justified, PLAN-KILL is an acceptable verdict.*
A PLAN-KILL here would rest **solely** on cost/benefit, not on unreachability: the
collision is live, and I have the ordering proof. A PLAN-KILL should then say so
explicitly and leave the shipped A.1 warning as the permanent operator contract.

## 4. What I verified first-hand

### 4.1 The collision is reachable — the concrete two-flow trace

1. `routing-instance tenant-a` and `tenant-b` each carry `10.0.0.10` on a VLAN
   sub-unit of one parent NIC. This **commits** (with the A.1 warning —
   `pkg/config/compiler_validate_vrf_overlap.go:214`).
2. Each ingress interface carries a PBR filter `then routing-instance <ri>`, which is
   the *only* per-packet table override in the dataplane and makes each VRF forward
   correctly.
3. Flow 1 (tenant-a) `10.0.0.10:12345 -> 198.51.100.10:443` installs a session keyed
   by the bare 5-tuple, caching tenant-a's egress, NAT binding and policy verdict.
4. Flow 2 (tenant-b), **identical 5-tuple**, hits flow 1's session and is handed flow
   1's cached decision.

**What goes wrong:** all four of the failure modes the parent asked me to distinguish,
not merely a confusing counter — wrong egress (tenant-b's packet leaves via tenant-a's
interface), wrong NAT binding, wrong policy (tenant-b's policy is never evaluated),
and therefore a genuine cross-tenant **session hijack** for any party that can guess
or observe a co-tenant's 5-tuple.

### 4.2 The ordering proof — the fast path runs before PBR (verified, not inherited)

In `userspace-dp/src/afxdp/poll_descriptor/mod.rs`:

- `resolve_flow_session_decision(...)` is called at **line 432** and short-circuits on
  a session hit.
- `ingress_route_table_override(...)` — the PBR evaluation — is at **line 1327**.
- The comment at **line 1242** states the override is on the "session-MISS path".
- The comment at **line 461** states `resolve_flow_session_decision` "never runs
  policy evaluation".

So an established-session hit **never re-evaluates PBR or policy**. This is the crux
of reachability and it holds on current master.

**A load-bearing detail for the design:** `resolve_flow_session_decision` already
receives `meta.ingress_ifindex as i32` **and** `packet_fabric_ingress` as parameters
(lines 447-449). The ingress context is *already threaded into the fast path* — it is
simply not part of the key. This is what makes Path B (below) cheap.

### 4.3 The wire question — v4 §4d is WRONG; the append is additive (Q3)

v4 §4d concluded a key widening is a hard wire break. That conclusion does not follow,
because **the discriminator need not live in the key block.** Verified in
`pkg/cluster/sync_protocol.go`:

`decodeSessionV4Payload` (line 374) reads its mandatory prefix under `if off+N >
len(payload) { return ...false }`, then reads **five successive optional trailing
VALUE fields**, each gated `if off+N <= len(payload)`, and **returns `true`
regardless**:

| Field | Issue | Line |
|---|---|---|
| `ReverseKey` block | — | 440 |
| `ALGType` / `LogFlags` | — | 452 |
| `Fib*` block | — | 458 |
| `Generation` | #2170 | 471 |
| `AppTimeout` | #3301 | 477 |
| `PolicyCounterIdx` | #3301 | 481 |
| `ConfigEpoch` | #5274 | 487 |
| `RTFlowSessionID` | #5212 | 493 |

`decodeSessionV6Payload` is the structural twin (gates at 571/583/589/602/608/612/
618/624). The repo states the rule in terms at `sync_protocol.go:930`: *"This is a
length-gated trailing field like the #3931 config-gen — it does NOT bump
SessionSyncWireVersion."* On the Rust↔Go control socket, `SessionSyncRequest` is
`#[serde(default)]` throughout, so the same append is additive by construction.

**Consequence:** `CurrentHAProtocolVersion` (`pkg/cluster/heartbeat.go:35`;
`SessionSyncWireVersion` aliases it at `pkg/cluster/sync.go:36`) does **not** move,
the #1930 mixed-base ISSU gate is **not** tripped, and the upgrade stays **rolling**.

**Mixed-version behaviour, stated plainly (the parent's #1961-class concern).** Intern
**domain 0 = the default routing-instance** — *not* a separate "unknown" sentinel. An
old peer's omitted field then decodes to the default VRF, which is exactly correct for
every non-VRF deployment. In a **non-VRF cluster the mixed-version window is
bit-identical** to today. In a VRF cluster the degradation is bounded and
fail-*closed*: a peer-synced session for a non-default VRF lands in domain 0, does not
match a domain-N packet, and that flow re-establishes after failover. **It never
cross-forwards.** This is not a one-sided-field no-transit risk: the failure mode is a
re-established flow, not a blackhole.

**Caveat I am flagging against my own conclusion:** the additive path is only additive
**if the domain is carried in the VALUE.** The `ReverseKey` embedded in the value
(line 440) is a *fixed 16-byte block*; widening the Rust key does **not** automatically
widen it, so the design must carry ingress and egress domain as two separate trailing
`u32`s and reconstruct the reverse key's domain from them. If an implementer instead
grows the reverse-key block in place, §4d's hard-break conclusion becomes true again.
**This is the single most likely way to get the implementation wrong.**

### 4.4 Hot-path cost — measured where measurable, unmeasured where not (Q4)

**Measured** (compiled the two struct shapes with `rustc -O`):

```
size_of::<SessionKey>()      = 40   align = 2
size_of::<SessionKeyWide>()  = 44   align = 4     (+ routing_domain: u32)
size_of::<IpAddr>()          = 17
```

So the key grows **40 → 44 bytes, +10%**, and alignment moves 2 → 4. **Both sizes fit
in a single 64-byte cache line**, so key-local cache-line occupancy is unchanged —
this is a size fact, not a throughput claim.

**Structural, not benchmarked:** the maps are `HashMap<SessionKey, V, FxSeededState>`
(`userspace-dp/src/session/mod.rs:23,42-44`) and `FastMap<SessionKey, _>`
(`afxdp/session_delta.rs:156-158`). `#[derive(Hash)]` hashes field-by-field, so the
added `u32` costs **exactly one additional `write_u32` into FxHasher per key hash** —
one multiply-xor-rotate — plus 4 bytes per map entry.

> **I am striking a number from the existing converged plan.** Its §8 risk table
> states the performance cost as **"~1-3%"**. That figure is **not backed by any
> measurement in the repo or in the plan**, and it should not survive into an
> implementation brief. Per this project's own rule — no measurement claim without a
> runnable repro — the correct statement is: *the cost is one extra `write_u32` per
> hash and +4 B per entry; the throughput delta is **unmeasured**.*

**What must be measured before anyone commits** (none of it is optional):
1. `cargo bench` / criterion on `SessionTable` lookup+install at 40 vs 44 bytes —
   the isolated hash+probe delta.
2. Sustained iperf3 v4 **and** v6 through the loss userspace cluster, push and
   reverse, against `172.16.80.200` / `2001:559:8585:80::200`, before vs after.
3. `perf record` to confirm no new cache-miss hotspot in the session-lookup path.
4. Session-table memory at scale: +4 B/entry across the configured session ceiling.
5. `make test-failover` — mandatory, the identity crosses the cross-chassis wire.

### 4.5 The corner cases any domain-aware change must handle

Verified first-hand where noted:

- **GRE decap — SAFE, no special handling.** `userspace-dp/src/afxdp/gre.rs:760` sets
  the inner meta's `ingress_ifindex: endpoint.logical_ifindex` — the *tunnel logical*
  interface, not the underlay port. A decapped flow therefore presents a stable
  ingress identity on every packet. **Verified.**
- **Fabric cross-chassis ingress — needs an explicit exemption.** The frame arrives on
  the fabric link but the session was admitted on the peer's real ingress interface,
  so the domains legitimately differ. `packet_fabric_ingress` is already a parameter
  to `resolve_flow_session_decision` (line 448) — **verified** — so the exemption is a
  one-line gate.
- **Peer-synced sessions** — carry the domain per §4.3, or must not be fail-closed
  against.
- **Inter-VRF route-leaked flows** — the §7 residual: forward ingresses VRF-A and
  egresses VRF-B, so the reply's computed domain differs from the stored one. Storing
  **both** ingress and egress domain in `SessionMetadata` (which already stores the
  `ingress_zone`/`egress_zone` pair and already swaps it in
  `build_reverse_session_from_forward_match`) resolves it.
- **Transient/seeded sessions** (neighbor seed, local-delivery, NAT64 companions) —
  resolve to the default domain; must not be fail-closed against.

### 4.6 Track A is shipped and complete

- **A.1** — commit warning on overlapping L3 across routing-instances: PR #4327
  (`408cfc7ee`), `pkg/config/compiler_validate_vrf_overlap.go`.
- **A.2** — flow cache keyed on the **logical** (VLAN) ingress ifindex: `42bc6bc88`
  (PR #6614). **This removes the flow-cache half of the collision. The conntrack
  table is now the sole remaining collision surface.**
- **A.3** — limitation documented in `userspace-dp/src/afxdp/forwarding/README.md`.
- Also shipped in #6614: `bd1f7b991` rejects overlapping/duplicate source-NAT and
  NAT64 pools at commit.

**Nothing in Track A remains.** Any further work is Track B.

## 5. Multiple Path Options

`resolve_flow_session_decision` already has the ingress context (§4.2), so the
question is *what it does with it*, not whether it can see it.

### Why "decline the hit and fall through to the slow path" is NOT an option

Worth stating because it is the first cheap-looking idea anyone proposes.
`SessionTable::install_with_protocol_with_origin` opens with an **unconditional**
`let _previous = self.remove_entry(&key);` (`userspace-dp/src/session/install.rs:139`
— **verified**). So a fast path that merely *declines* a cross-domain hit and lets the
packet take the session-miss path causes that path to **re-install under the same bare
5-tuple and evict the incumbent VRF's session**. Two colliding flows then evict each
other on *every packet*: per-packet SNAT re-allocation (the translated tuple changes
mid-flow, so the flow breaks outright), plus SESSION_CREATE/CLOSE RT_FLOW churn and an
HA delta storm. **This is worse than the bug.**

The same reasoning collapses "make install not evict a different-domain incumbent"
into Path C: holding two entries for one 5-tuple *requires* the key to disambiguate.

### Path A — do nothing further; A.1 warning is the permanent contract

Close #2387 as PLAN-KILL. The operator is warned at commit; the limitation is
documented. **Cost:** zero. **Leaves:** a real cross-tenant session-hijack surface in a
config the product accepts. Defensible only as an explicit product statement that
overlapping-subnet multi-tenant VRF is out of scope — which the shipped A.1 *warning*
(rather than a reject) currently contradicts.

### Path B — DENY: fail-closed drop on a cross-domain hit

Store the admitting `routing_domain` in `SessionMetadata` (the **VALUE**, not the
key). On the fast path, compare the packet's domain against the session's; on
mismatch, **drop + increment a dedicated counter** — do not fall through to install.

- **Cost:** small. Rust-only. **No key change, no wire change, no struct-literal
  churn.** The metadata already carries an `ingress_zone`/`egress_zone` pair, so the
  storage slot pattern exists.
- **Closes:** the hijack. Tenant-b can no longer inherit tenant-a's decision.
- **Does not deliver:** coexistence. Tenant-b's legitimate flow is dropped.
- **Two objections:**
  1. **Not Junos semantics.** A Junos session table is per-routing-instance; identical
     5-tuples in two instances coexist. This is the vendor-parity project's stated
     north star.
  2. **It hands a tenant a denial primitive against a co-tenant** who guesses or
     observes its 5-tuple — trading a confidentiality/integrity bug for an
     availability one.
  3. It contradicts the **already-shipped A.1 warning text**, which tells the operator
     flows may cross-forward *"until the session identity is VRF-aware"* — i.e. the
     shipped operator contract points at Path C.

### Path C — ISOLATE: widen the identity with a routing-domain discriminator (the issue's literal ask)

- **C-P0** — intern the routing-instance name to a dense `routing_domain: u32`
  (domain 0 = default). The building block exists: `ifindex_to_routing_instance`
  (`afxdp/types/forwarding.rs:69`, built at `forwarding_build/interfaces.rs:56-57`).
  Never hash the RI *name* on the hot path. Carry it in the **dead `meta.routing_table`
  slot** (v4 §4e — hard-coded 0 since the #1476 BPF deletion), so `UserspaceDpMeta`
  stays size-96 and its mirrored `offset_of!` asserts are untouched.
- **C-P2** — add `routing_domain: u32` to `SessionKey` and to the reverse-key
  transforms in `session/key.rs`. Store **ingress and egress** domain in
  `SessionMetadata` so route-leaked flows reverse-match correctly (§4.5).
- **C-P3** — append **two** trailing `u32` VALUE fields to each of the two wire
  surfaces, length-gated, **no version bump** (§4.3, and heed its caveat: do **not**
  grow the embedded reverse-key block).

**Cost:** ~301 struct-literal edits (a third in tests), +4 B/key, one extra
`write_u32` per hash, an additive wire append, and a mandatory `make test-failover`.
**Delivers:** the issue's literal ask and vendor parity.

### Path D — ISOLATE-narrow: Path C, but the discriminator is only non-zero where overlap exists

Identical mechanism to C, but the control plane assigns a non-zero domain **only to
routing-instances that the A.1 overlap check actually flags**. Every other deployment
runs with `routing_domain == 0` on every session.

- **Value:** the *behavioural* delta is confined to exactly the configs that can
  collide. Non-overlapping and non-VRF deployments — the overwhelming majority — are
  bit-identical in behaviour, which makes the smoke/perf risk far easier to argue and
  the mixed-version window trivially safe.
- **Cost:** the *mechanical* cost is the same as C (the field still exists in the
  struct and on the wire), so this is not a cheaper implementation — it is a **lower-risk
  rollout** of the same implementation.
- **Objection to raise in review:** it makes the domain assignment depend on a
  config-analysis result, so a config edit can change a *live* session's domain
  meaning. Domain identity must be stable for the life of a session, or re-keyed on
  a config generation change. **This is the option's main correctness hazard and
  reviewers should attack it.**

### Recommendation (to be tested by review, not asserted)

**Path C, staged, with Path D's rollout discipline** — i.e. implement the full
discriminator, but validate that non-overlapping deployments are behaviourally
identical. Rationale: the cost objection that drove the v4 deferral is retired (§4.3);
Path B's semantic objections are not retired by anything; Path A contradicts the
shipped A.1 text. Path C is a **PR series**, not one PR: C-P0 (domain plumbing, no
behaviour change) → C-P2 (identity) → C-P3 (wire) is the natural split, each with its
own RED-on-revert test.

## 6. Public API preservation

Paths A/B: no signature changes. Paths C/D change the `SessionKey` struct — by
definition not preservable; it is `pub(crate)`, so the blast radius is
crate-internal. The **wire** stays compatible (§4.3), which is the property that
actually matters for a rolling upgrade.

## 7. Hidden invariants the change must preserve

- **Conntrack reverse-match symmetry — the correctness trap.** The reply ingresses on
  the *egress* interface, so **ingress-zone and ingress-ifindex are asymmetric** across
  forward vs reply. Putting either in the key **breaks reply matching**. This is the
  direct answer to the parent's Q2: *ifindex and zone are not merely coarser or less
  stable choices — they are **incorrect**.* Only the routing-domain is symmetric for
  intra-VRF flows. (It also disposes of the ifindex-instability-across-rename concern:
  ifindex is disqualified on symmetry before stability is even reached.)
- **Route-leaked asymmetry** — the one case where the domain is *also* asymmetric;
  handled by storing both ingress and egress domain (§4.5).
- **`UserspaceDpMeta` size/offset invariant** — size-96 with `offset_of!` asserts
  mirrored in `types/mod.rs` and `userspace-xdp/src/lib.rs`. Reusing the dead
  `routing_table` slot keeps this intact.
- **No per-packet allocation** — the domain must be an interned `u32` lookup, never a
  per-packet `String` clone or a name hash.
- **#3096 NAT-scope coherence** — a cached fast-path decision must only be reused for
  a flow in the same scope it was admitted under. This is the invariant #2387 violates.
- **The embedded reverse-key block is fixed-width** (§4.3 caveat).

## 8. Risk assessment

| Class | Path A | Path B (DENY) | Path C/D (ISOLATE) |
|---|---|---|---|
| Behavioural regression | NONE | MED — a mis-derived domain drops a legitimate flow (self-DoS) | MED-HIGH — a mis-derived domain either fails to match (self-DoS) or cross-matches |
| HA mixed-version | NONE | NONE (value-only, no sync semantics) | **LOW** — additive, no version bump, non-VRF clusters bit-identical (§4.3) — *was rated HIGH in v4; that rating is withdrawn* |
| Wire / struct | NONE | NONE | LOW-MED — +4 B key, two additive trailing wire fields, golden fixture regen |
| Performance | NONE | NONE | **UNMEASURED** — one extra `write_u32`/hash, +4 B/entry; must be benchmarked (§4.4) |
| Security posture | leaves a hijack surface | closes hijack, opens a co-tenant DoS | closes hijack without opening a DoS |
| Semantics | contradicts shipped A.1 text | contradicts shipped A.1 text + Junos parity | matches both |

## 9. Test plan

- **RED-on-revert, the issue's stated regression:** two VLAN sub-units on one parent,
  two routing-instances, each with PBR `then routing-instance`, identical 5-tuples,
  differing policy/NAT ⇒ assert **no** session reuse across the boundary **and**
  correct reply-direction match *within* each VRF. Reverting `routing_domain` makes it
  RED because flow 2 inherits flow 1's egress.
- **Negative control** (per this project's mutation discipline): a **non**-overlapping
  two-VRF config must be behaviourally identical before and after — this is what
  proves the guard is scoped, not merely present.
- **Route-leaked corner:** a rib-group / `next-table` inter-VRF flow must still
  reverse-match. This is the highest-value test and the one most likely to be skipped.
- **Fabric exemption:** a peer-owned session redirected over the fabric must still
  match despite a differing ingress domain.
- **Wire:** V4 **and** V6 encode→decode round-trip of the two new trailing fields;
  a **short-payload (legacy peer) decode** test proving `ok=true` with the fields
  defaulting to domain 0; golden `protocol_wire_v1.json` regenerated.
- **HA live:** `make test-failover` on the loss userspace cluster — mandatory.
- **Perf:** the five measurements in §4.4. No merge on an unmeasured perf claim.

## 10. Out of scope

- Per-VRF **default** FIB / per-VRF local-delivery sets (v4's Track B-ext) — a separate
  enhancement, **not** a prerequisite, since PBR is already the per-VRF forwarding
  mechanism.
- Flipping A.1 from warning to hard reject.
- Replacing the redundant `addr_family` field to keep the key at 40 bytes. It *is*
  structurally redundant with the `IpAddr` enum tag, but micro-packing a
  security-critical key to save 4 bytes trades review risk for nothing measurable.
  **Considered and rejected.**
- Any change to the eBPF retirement posture.

## 11. Open questions for adversarial review

1. **The binary: DENY (Path B) or ISOLATE (Path C/D)?** Attack the claim that Path B's
   co-tenant-DoS and Junos-parity objections outweigh its much smaller footprint.
2. **Is §4.3 right that this is additive?** Specifically attack the caveat: is there a
   path where the domain *must* enter the embedded reverse-key block, re-creating the
   hard break? This is the highest-consequence claim in the document.
3. **Path D's stability hazard:** if domain ids are assigned from a config-analysis
   result, what happens to a live session when the config changes? Is a
   config-generation re-key required, and does that make D strictly worse than C?
4. **Is the route-leaked corner really cheap?** v4 deferred dual-domain handling as
   expensive; §4.5 claims it is cheap because `SessionMetadata` already swaps a
   zone pair. Refute or confirm.
5. **Is there a symmetric discriminator cheaper than a routing-domain id** already
   present on both forward and reply packets? §7 disqualifies zone and ifindex on
   symmetry — is that disqualification airtight?
6. **Does the ~301-literal churn estimate hold**, or does adding a field to
   `SessionKey` cascade into the C mirror (`bpf/headers/xpf_conntrack.h`) and the Go
   mirror (`pkg/dataplane/types.go`) in ways that make the edit surface much larger?
7. **Is PLAN-KILL the right answer anyway?** The trigger config is niche and now
   warned-about. Argue the cost/benefit case for closing #2387 with Path A.
