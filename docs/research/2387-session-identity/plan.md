# #2387 — session/flow identity is the bare 5-tuple: the DENY-vs-ISOLATE decision

**Revision:** v6-r4 — incorporates r3 reviews (Claude SMR + AGY; Codex pending)

**v6-r4 changelog — the plan got materially CHEAPER:**
- **AGY r3 refuted my rejection of hashing, and it was right.** The tree already
  has `StableRoutingInstanceTableID(name)` — a pure FNV-1a function of the RI
  name — **plus a commit gate that rejects colliding configs**, already wired at
  `pkg/config/compiler.go:229`. Verified. **This deletes the entire allocate-once
  interner, its config-carried table, the never-reissue rule, the flush-on-delete
  path and the rollback design** that v6-r3 introduced (§5). A pure function of
  the name gives cluster agreement, restart persistence, rollback coherence and
  immunity to add/delete renumbering *for free*.
- **Claude SMR r3 (SMR-10) + AGY r3 R2(b) independently:** §4.3b's version gate
  fixes the steady state but leaves the **off→on transition** open — sessions
  imported while the peer was v1 carry `routing_domain = 0` and re-run the exact
  fail-open trace when enforcement engages. New §4.3c.
- AGY r3 **VERIFIED** the §7a VXLAN/IP-in-IP rejections (conceding its own r2
  suggestion was wrong) and **VERIFIED** the C-P2 key.rs signatures as
  implementable.
- AGY r3 returned **PLAN-KILL** on cost/benefit. §3a answers it — including the
  part of its cost basis that its own R1 finding removes.

**v6-r3 changelog — two defects found in v6-r2, both in the fix rather than the bug:**
- **AGY r2 REFUTED §4.3a's fail-closed claim.** It is fail-closed for domain-N
  packets but **fail-OPEN for domain-0 packets** during a mixed-version window.
  Resolved in §4.3b by **version-gating enforcement** — and that flips §11 Q2
  from "defer the capability signal to #5804" to "#2387 needs it for its own
  correctness".
- **Claude SMR r2 (SMR-7)** found "static deterministic interning" — v6-r2's own
  replacement for the withdrawn Path D — re-creates the cross-forwarding bug
  through routine config churn. Replaced with an explicit allocate-once /
  never-reissue invariant in §5 C-P0.
- §7a extended with the ICMP-error and NAT64 producers. **AGY's suggested VXLAN
  and IP-in-IP producers were verified NOT to exist in this codebase and are
  rejected.**
- §4.3a's `performSyncHandshake` PSK-gating, the 1:1 map, the chain claim and the
  byte budget were all independently VERIFIED by AGY r2.
**Verified against:** origin/master @ `e80db2eae`
**Branch:** `research/2387-session-identity` (docs only — no production source)

**v6-r2 changelog:**
- **AGY REFUTED Path D** (ISOLATE-narrow) on a live-session stability hazard.
  Path D is **withdrawn**; §5 now mandates static deterministic interning.
- **Claude SMR** found the plan blind to the maintainer-prescribed chain
  **#4983 → #2387 → #5804**. New §2.5. C-P3 is rewritten as an *extensible*
  mechanism — a bespoke single-field append would force #5804 into a second
  wire break.
- §4.3 split into **narrowing-safe vs widening-unsafe**; the two issues have
  opposite mixed-version polarity through the same mechanism.
- **§4.3a is new and corrects my own SMR-2:** a connection-setup capability
  handshake **does** exist (F23 `performSyncHandshake`) — but it is **gated on a
  PSK being configured**, which is the constraint that matters.
- §5 Path B now cites the **1:1 `key_to_handle` map** as the structural reason
  it is forced, not merely inferior.
- Literal counts reconciled with explicit grep scope; chain-wide byte budget added.

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
| `SessionKey {` struct literals, Rust | — | **297** — see scope note below |

**Grep scope, stated because three independent sweeps got three answers** (301 /
297 / 291). The canonical figure is `grep -rn 'SessionKey\s*{' --include='*.rs'
userspace-dp/src` = **297**. Adding `userspace-xdp/src` gives 301; a stricter
regex gives 291. Of the 297, **175 are in files named `tests*.rs`**, leaving
**122 construction sites in non-test-named files** — and some of those are
`#[cfg(test)]` blocks inside production files, so 122 is an upper bound on real
production churn.
| `SessionKey` refs, Go | — | **1154** — but this is the *separate* `dataplane.SessionKey` C-mirror type, a fixed-layout byte struct, not the Rust type. Counting it in one blast-radius number conflates two types. |

The honest framing: **301 struct-literal sites** is the mechanical churn (a field
added to a struct literal), and roughly a third of those are test fixtures. The
"743" and "1154" reference counts overstate the edit surface — most references are
`&SessionKey` parameter passing that needs no change at all.

## 2.5 Chain position — #2387 is the middle link, and it owns the wire decision

**This is the finding that most changes the design, and v6-r1 missed it entirely.**

Issue **#5804** carries a maintainer-directed scoping decision stating that
**#4983, #2387 and #5804 are one decision** — all three widen the *same*
`SessionKey` — and prescribing a **chain, not parallel lanes**:

> **#4983 → #2387 → #5804**

on the rationale that parallel lanes would *"manufacture conflicts in one struct
and produce three partial answers to one question"*, with **#2387 as the
designated owner of the HA-wire decision, paid for once**.

| Issue | What it adds to the identity | State | Branch/PR |
|---|---|---|---|
| #4983 | true ingress-interface identity (session **filter** today approximates via zone→interfaces) | OPEN, `plan-deferred` | none |
| **#2387** | `routing_domain` | OPEN, `plan-deferred-operator` | research only |
| #5804 | GRE key / PPTP call-ID discriminator | OPEN, `plan-deferred-research` | none pushed; uncommitted work touching neither `SessionKey` nor the wire |

**Three consequences this plan must absorb:**

1. **C-P3 cannot be a bespoke single-field append.** If #2387 ships "+1 trailing
   `u32`", #5804 must invent a *second* wire mechanism — the duplicated hard break
   the chain ordering exists to prevent. C-P3 must be specified as a mechanism
   #5804 can **extend**.
2. **Is #4983 a hard blocker?** **No.** #2387 imports no symbol and no wire field
   from #4983, so calling this BLOCKED would be false precision. The chain order is
   a *risk-sequencing preference* with a real rationale — #4983 is VALUE-only and
   old-peer-safe, so it proves the meta→logical-ingress plumbing somewhere a bug is
   **cosmetic** (a wrong `show session` filter) rather than a forwarding fault. That
   rationale is worth honouring, and this plan recommends honouring it, but it is
   not a dependency.
3. **The byte budget belongs to the chain, not to #2387** (§4.4).

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

## 3a. AGY r3 returned PLAN-KILL — the case, and the answer

AGY r3's verdict, verbatim in substance: the trigger config is a niche edge case
already mitigated by the shipped A.1 warning and A.2 flow-cache keying, and the
accumulated cost — *"widening `SessionKey` across ~297 literal sites, introducing an
unworkable stateful interner, bumping `CurrentHAProtocolVersion`, and altering the core
`parseHAProtocolCompatible` upgrade gate predicate"* — outweighs the benefit.

**This is a serious verdict and it must not be argued away. Two of its four cost items
are real; two are not.**

| AGY's cost item | Status after v6-r4 |
|---|---|
| ~297 struct-literal sites | **real**, though most are test fixtures and most of the 743 references need no edit |
| "unworkable stateful interner" | **removed** — by AGY's own R1 finding. The interner is a pure function of the RI name reusing existing machinery (§5). AGY's verdict priced a cost that its own review had just deleted. |
| `CurrentHAProtocolVersion` bump | **real**, but rolling-compatible via the declared floor |
| altering `parseHAProtocolCompatible` | **real, and the sharpest objection in the review** — it is the gate deciding whether *any* release is rolling-upgradable |

So the honest post-r4 cost is: **~297 mostly-test literal edits, a pure-function domain
derivation, a rolling-compatible version bump, a flush on the enforcement transition,
and one change to the upgrade-compatibility predicate.** That is materially smaller
than the basis AGY assessed, because r4 removed the interner it objected to.

**The counter-case for PLAN-KILL that survives:** the `parseHAProtocolCompatible`
change has blast radius beyond this issue — it relaxes the rolling-upgrade gate for
every future release. A reviewer may reasonably judge that a niche, warned-about
config does not justify touching that gate. **That is the strongest remaining argument
for PLAN-KILL and this plan does not claim to refute it** — it is a judgement about
risk appetite, and it belongs to the maintainer.

**The counter-case against PLAN-KILL:** the shipped A.1 warning text tells the operator
their config is not session-isolated *"until the session identity is VRF-aware"* — a
written promise that the isolation is coming. PLAN-KILL would make that text
permanently misleading, so a PLAN-KILL **must** be accompanied by rewriting A.1's
warning into a statement of permanent non-support. That is a small, concrete
obligation and it should not be skipped.

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
`u32`s (`IngressRoutingDomain`, `EgressRoutingDomain`) and reconstruct the reverse
key's domain from them. If an implementer instead grows the reverse-key block in
place, every field after it shifts and §4d's hard-break conclusion becomes true again.
**This is the single most likely way to get the implementation wrong.** AGY
independently confirmed this caveat.

### 4.3a Narrowing-safe, widening-unsafe — the polarity that governs the chain

The safety property above is **specific to this discriminator** and must not be
generalized to the chain, because the same mechanism has opposite polarity for #5804:

| | Old peer omits the field → decodes 0 | Effect on identity | Posture |
|---|---|---|---|
| **#2387 `routing_domain`** | 0 is interned as the **default** routing-instance | a domain-N packet **fails to match**; flow re-establishes | **narrows — fail-CLOSED** |
| **#5804 GRE discriminator** | 0 reads as "no key" | two distinct keyed tunnels **alias onto one session** | **widens — fail-OPEN, a security fault** |

#5804's own acceptance criteria demand "mixed-version **reject**, not widen". A bare
length-gated trailing field cannot deliver that. So the chain needs a capability
signal, and #2387 is the issue positioned to introduce it.

**Is there a negotiated-capability path already in the tree to reuse?** **Yes,
partially — and the caveat is the important part.** `performSyncHandshake`
(`pkg/cluster/sync_auth.go:314`, feature F23) is a **connection-setup capability
handshake** that exchanges a HELLO before any session frame flows, negotiates a
posture, implements **dual-accept** for rolling upgrades, and already carries a
**downgrade-guard** — "once a peer has authenticated, a later UNAUTHENTICATED
connection from it is rejected". That downgrade-guard is structurally the same shape
as #5804's reject-not-widen requirement, and the HELLO is the natural place to hang a
feature bit.

**The constraint that matters:** the handshake *"runs ONLY when a local key is
configured. An unkeyed node ... sends nothing special and is indistinguishable from —
and fully compatible with — a legacy peer"* (`sync_auth.go:322-326`). So on a cluster
with no `authentication-key`, **no handshake happens at all** and there is no place to
carry a capability bit. Any chain-wide negotiation design must either accept that it
only protects keyed clusters, or introduce an unconditional capability exchange.

### 4.3b The fail-closed claim was WRONG at domain 0 — and fixing it decides the capability question

**AGY r2 refuted §4.3a's "it never cross-forwards", and the refutation is correct.**
The trace:

1. An un-upgraded peer syncs a session for `tenant-a` (domain N). It omits the field.
2. The upgraded node decodes `routing_domain = 0` and installs the session **under
   domain 0** — because we chose "0 = the default routing-instance".
3. A **new flow in the default VRF** (genuinely domain 0) arrives with the same 5-tuple.
4. It looks up `(5-tuple, domain 0)` and **matches tenant-a's session** — inheriting
   its egress, NAT binding and policy verdict.

So the interning choice that makes non-VRF clusters bit-identical is exactly what
makes a VRF cluster **fail-OPEN for default-VRF traffic** during the upgrade window.
The polarity table in §4.3a holds for domain-N packets only.

**Note this is not a small residue:** it re-creates #2387's original cross-forwarding
bug, in the one window where an operator is least able to observe it, and in exactly
the overlapping-subnet config the feature exists to protect.

**Why the obvious fixes fail.** Using a distinct `UNKNOWN` sentinel instead of 0 is
fail-closed, but then *every* legacy-peer-synced session fails to match — including in
**non-VRF clusters**, which destroys the "bit-identical" property and turns a
mixed-version failover into mass session loss. That is a worse trade.

**The resolution: gate enforcement on the peer's protocol version, not on the field.**
During the window, the upgraded node must behave **exactly as today** — 5-tuple only,
no domain comparison — and engage domain enforcement only once the peer is known to
speak it. The signal already exists and, crucially, is **not PSK-gated**:

- The heartbeat carries `HAProtocolVersion` in **every packet**, encoded at
  `pkg/cluster/heartbeat.go:286` and decoded at `:374`. Unlike the F23 handshake this
  is unconditional — an unkeyed cluster still exchanges it.

**The catch, and the scope it implies.** The ISSU driver requires the two versions to
be **exactly equal**: `parseHAProtocolCompatible` (`pkg/upgrade/cluster_cli.go:253`)
is documented *"Compatible iff N == M … a bump means the wire semantics changed and
the release is NOT rolling-upgradable"*. So a naive bump would make the release
non-rolling — reviving the very objection §4.3 retired.

But `MinCompatHAProtocolVersion` (`heartbeat.go:46`) **exists for precisely this case**
— *"the OLDEST HA protocol version `CurrentHAProtocolVersion` can still interoperate
with"* — and it is currently **vestigial: it has no non-test consumer in the tree**
(verified). The design is therefore:

1. bump `CurrentHAProtocolVersion` → 2, set `MinCompatHAProtocolVersion` = 1;
2. change `parseHAProtocolCompatible` to honour the declared floor (`peer >=
   MinCompat`) instead of exact equality;
3. enforce domain matching only when the peer advertises >= 2.

Result: no fail-open, no session loss, and the upgrade **stays rolling** — but via a
declared-compatibility contract rather than by avoiding the version bump.

**This is real, high-consequence scope: it modifies the upgrade safety gate.** It is
well-founded (the constant exists for this and is unused), but it must be priced, and
it must not be smuggled in as a one-liner.

**Consequently §11 Q2 lands on (i), not (ii):** #2387 must carry the capability signal
**for its own correctness**, not as a favour to #5804. That also disposes of the
PSK-gating problem — the heartbeat version is unconditional, so the F23 handshake is
*not* the mechanism to use here. #5804 may still need a finer-grained feature bit for
its reject-not-widen requirement; that remains its own scope.

**Cost consequence for this plan:** v6-r1 priced the capability question at zero and
v6-r2 left it open. It is neither. C-P3 carries a protocol-version bump plus a change
to the ISSU compatibility predicate.

### 4.3c The version gate fixes the steady state; the TRANSITION needs an action

Claude SMR r3 and AGY r3 independently found the same hole in §4.3b. The gate is
specified as a steady-state predicate ("enforce when peer >= 2"), but it gates on a
**peer state that changes over time**, and each transition needs handling.

**(a) Unknown peer version → NOT-ENFORCING, explicitly.** On a fresh boot or after a
heartbeat gap the peer's version is unknown. The default must be **not to enforce**,
because "unknown" is indistinguishable from "legacy peer". This is the opposite of the
usual fail-closed instinct, which is exactly why it must be written down: an
implementer reaching for "fail closed on unknown" produces a self-DoS, and one
reaching for "enforce by default" produces the fail-open. Neither is right by accident.

**(b) Carried-forward sessions — the real hole.** Sessions imported from the peer while
it was still v1 **do not disappear when the peer upgrades**. They sit in the table
carrying `routing_domain = 0` — a value that was never sent and never meant anything.
When enforcement flips on, AGY r2's original refuted trace runs again in full: a
genuine default-VRF flow with a matching 5-tuple hits a session that belongs to
tenant-a. AGY r3 adds the mirror case: domain-N packets *fail* against those same
sessions, dropping legitimate VRF traffic.

The gate cannot close this, because it is evaluated per packet against the peer's
*current* version while the poisoned sessions were admitted under the *previous* one.
**State admitted under the old regime is carried forward into the new one** — a
transition no amount of steady-state reasoning can see.

**Required — the flip must be a transition with an action.** Two options:

- **Flush** every peer-imported session admitted while the peer was < v2. The cluster
  already performs a bulk resync on connect, so the cost is one resync during an
  upgrade — a window that is already disruptive by definition.
- **Mark** each imported session at admission with whether its domain was
  authoritative, and exempt non-authoritative entries from domain comparison for their
  lifetime. Cheaper at the moment of transition, but adds a per-session bit and a
  second matching path that must itself be tested.

**This plan chooses FLUSH**, because the window is an upgrade, bulk resync is already
the cluster's normal recovery behaviour, and a per-session exemption bit is a second
mechanism to get wrong on the security-critical path.

**(c) Every off→on transition, not just the first.** A peer version regression
(rollback, or flapping heartbeats) turns enforcement off; the subsequent re-upgrade
re-opens case (b). The flush obligation attaches to **every** off→on transition. The
plan should also require a **dampener** on the enforcement flip so a flapping peer
cannot drive repeated flushes — this project already has the pattern in the GARP
dampener.

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

**Two costs v6-r1 under-counted** (Claude SMR): the key is also compared on **every
flow-cache hit** (`flow_cache.rs:204`), and it feeds `set_index` bucket derivation
(`flow_cache.rs:870`) — so the **bucket distribution shifts for all protocols**, not
only those carrying a non-zero domain. A distribution shift is not a hash-cost
argument; it must appear in the measurement plan as a flow-cache hit-rate check.

**The byte budget belongs to the chain, not to #2387.** Measured in isolation this
looks like +10%. Across the prescribed chain:

| Stage | `size_of::<SessionKey>()` |
|---|---|
| today | 40 |
| + #2387 `routing_domain: u32` | **44** |
| + #5804 discriminator as a plain `u32` | **48** (+20% on today) |
| + #5804 as a *typed* `TunnelDiscriminator` **enum** | **past 48** — an enum costs 8 B on its own (discriminant + padding) |

**Rule this imposes on the chain, and #2387 is the issue that must state it:** every
discriminator must be a **plain fixed-width integer**, with anything variable (a VRF
name, a tunnel identity) **interned to a dense id at config-compile time**. Never a
`String`, never a typed enum in the key, never a name hashed on the hot path.

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

**The structural reason, which is stronger than the eviction argument** (Claude SMR):
`SessionTable.key_to_handle` is `SeededKeyMap<u32>`
(`userspace-dp/src/session/mod.rs:548`) — strictly **1:1, at most one live session per
key**. So a discriminator held *outside* the key has exactly two possible behaviours
under that map — evict the other context's session, or refuse to create yours — and
**both are cross-tenant faults**. Any non-key approach first requires converting
`key_to_handle` to 1:N and re-auditing every reader that assumes one-session-per-key
(the assumption is documented at `userspace-dp/src/session/README.md:409-415`). That
conversion is not cheaper than widening the key; it is the same work plus a
correctness re-audit.

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

**Cost:** ~297 struct-literal edits (most in test files), +4 B/key, one extra
`write_u32` per hash, an additive wire append, **a rolling-compatible
`CurrentHAProtocolVersion` bump plus the `parseHAProtocolCompatible` change (§4.3b)**,
the allocate-once interner and its config-carried table (§5), and a mandatory
`make test-failover`. **Delivers:** the issue's literal ask and vendor parity.

### ~~Path D — ISOLATE-narrow~~ — WITHDRAWN in v6-r2

v6-r1 proposed assigning a non-zero domain **only** to routing-instances the A.1
overlap check flags, so non-overlapping deployments stayed behaviourally identical.
v6-r1 flagged its own stability hazard and invited attack. **AGY refuted it, and the
refutation is correct:**

> Committing a configuration change mid-flight (e.g. adding or removing a PBR term or
> interface) alters the compiler's overlap detection, causing routing-domain IDs for
> active VRFs to change or reset to 0. Active in-memory sessions keyed under old
> domain IDs will mismatch new packets, **dropping established production traffic.**

This is worse than the bug it fixes: #2387 mis-forwards traffic only in a niche
overlapping config, whereas Path D would drop **established sessions in any VRF
deployment** on an unrelated commit. A domain id must be stable for the life of a
session, and deriving it from a config-analysis result cannot guarantee that.

**Path D is withdrawn.**

#### RESOLVED in v6-r4: the mechanism already exists in the tree

**Everything in the two subsections below is retained for the record but is now
SUPERSEDED.** v6-r2 and v6-r3 spent two review rounds designing an allocate-once
interner because I assumed a name-hash was unsafe. **AGY r3 refuted that, and I
verified the refutation:**

- `StableRoutingInstanceTableID(name)` (`pkg/config/routinginstanceid.go:48`) maps an
  RI name into a reserved band via **FNV-1a**, xor-folding the high half so the modulo
  samples the whole hash. It is explicitly *"a pure function of the name"*.
- `validateRoutingInstanceTableIDCollisionAST` (`:126`) is a **strict commit gate**
  that **rejects** any config where two routing-instances collide. It is wired into the
  compiler at `pkg/config/compiler.go:229` **and** `:397`, and it unions names across
  every `routing-instances` root and every `groups` block, including the per-node
  cluster expansions.

So the project already solved exactly this problem, and solved it the way I argued
against: **hash, then reject collisions at commit.** My collision objection was wrong
because it assumed collisions would be silent; they are not — they are a commit error.

**C-P0 therefore becomes: derive `routing_domain` as a pure function of the
routing-instance name, reusing the existing stable-id machinery, and extend the
existing collision gate to cover the domain-id derivation.** What this deletes,
entirely:

| v6-r3 scope | Status in v6-r4 |
|---|---|
| monotonic allocate-once allocator | **deleted** — pure function |
| name→id table carried in the config | **deleted** — nothing to persist |
| never-reissue-after-delete rule | **deleted** — a name always maps to the same id |
| flush-on-RI-delete | **deleted** — no stale id can be reused |
| daemon-restart persistence | **deleted** — recomputed |
| `rollback` coherence design | **deleted** — pure function of the config text |
| SMR-7's add/delete renumbering hazard | **cannot occur** — no positional derivation |
| AGY r2's HA interner divergence | **cannot occur** — both nodes compute the same value |

AGY also argued the config-carried table was *unworkable* (auto-mutating human-edited
Junos text, split-brain on out-of-order commits, rollback restoring text without the
table). I agree, and that objection is now moot rather than merely answered.

**This is the single largest cost reduction across the whole v6 series, and it came
from a reviewer refuting me.** The two subsections below are the superseded design.

#### [SUPERSEDED] The replacement, stated as an invariant — because v6-r2's version of it was also defective

v6-r2 said only "static and deterministic interning across all routing-instances".
**Claude SMR r2 and AGY r2 independently found that this is not sufficient**, and the
most natural reading of it is actively dangerous:

- If ids are **derived from the current RI set** (e.g. sorted names → 1, 2, 3…), then
  deleting one routing-instance **renumbers its successors**. Every live session in
  every higher-numbered RI is then keyed on an id denoting a **different VRF** — not a
  failure to match, but a **match against the wrong tenant**. That is #2387's original
  bug, re-created by its own fix, and triggered by an unrelated commit.
- **Id reuse** after a delete/re-add has the same shape: a stale session matches a new
  tenant.
- **AGY additionally found the HA half:** two nodes that build their tables at
  different times (one has been running through several commits, the other just
  rebooted from a fresh snapshot) would assign **different ids to the same RI name**.
  A session synced from node A then matches a *different* VRF on node B. This is a
  live-cluster fault, not just an upgrade-window one.

**The invariant, which C-P0 must implement and test:**

> A `routing_domain` id is **allocated once per routing-instance identity and never
> re-derived from the current RI set**. Allocation is monotonic; the name→id table is
> **carried in the configuration** and therefore (a) identical on both cluster nodes
> via the existing config sync, (b) persisted across daemon restart, and (c) restored
> correctly by `rollback`. Deleting an RI **retires** its id; a retired id is **never
> reissued**. On RI deletion, sessions in that domain are explicitly **flushed** rather
> than left to age out under an id that no longer denotes anything.

**Why the table is carried in the config rather than hashed — a deliberate rejection
of AGY's recommendation.** AGY r2 proposed a deterministic string hash (FNV-1a of the
RI name, 0 reserved for `default`) to guarantee both nodes agree. That does solve
agreement and persistence with no new state — but **a hash has collisions**, and a
collision between two RI names maps two distinct tenants onto one domain id, which is
**precisely the cross-tenant match this entire issue exists to prevent**. Trading a
guaranteed-correct table for a 2^-32 silent security fault is the wrong trade in a
security boundary. Config-carried allocation gets agreement from the config sync that
already exists, and gets persistence and rollback for free, with **no collision
possible**. Reviewers should push back if they disagree, but the collision argument
should be answered rather than waved past.

Non-VRF deployments still see `routing_domain == 0` everywhere, which preserves the
rollout-safety value Path D was reaching for, without the hazard.

### Recommendation (to be tested by review, not asserted)

**Path C, staged, with static deterministic interning** (Path D's rollout discipline
is withdrawn; its *goal* — non-VRF deployments behaviourally identical — is preserved
by domain 0). Rationale: the cost objection that drove the v4 deferral is retired
(§4.3); Path B is structurally forced into a cross-tenant fault by the 1:1
`key_to_handle` map, not merely semantically inferior; Path A contradicts the shipped
A.1 warning text.

Path C is a **PR series**, not one PR:

| PR | Content | Wire? | Gate |
|---|---|---|---|
| **C-P0** | dense static interning of RI names → `routing_domain: u32`; populate the dead `meta.routing_table` slot at **every** ingress producer (native ingress, local delivery, GRE decap, fabric ingress). **No behaviour change** — nothing reads it yet. | no | unit |
| **C-P2** | add `routing_domain` to `SessionKey` + the four transforms in `session/key.rs`; store ingress **and** egress domain in `SessionMetadata`; fabric exemption. | no | RED-on-revert + negative control |
| **C-P3** | `IngressRoutingDomain` / `EgressRoutingDomain` as length-gated trailing VALUE fields, V4 **and** V6; reverse-key domain reconstruction; **`CurrentHAProtocolVersion` → 2 + `MinCompat` = 1 + the `parseHAProtocolCompatible` change + version-gated enforcement (§4.3b)**. | yes | `make test-failover` + short-payload decode + **mixed-version enforcement-off** test |

**C-P0 additionally owns** the allocate-once/never-reissue interner, its
config-carried name→id table, and the flush-on-RI-delete path (§5). That is more than
"plumbing" and should not be under-scoped.

**C-P2's signature changes, made explicit** (AGY r2 required this). `SessionKey`
carries the *ingress* domain, so the reverse/translated transforms cannot derive the
reply's domain from the key alone — the reply's domain is the **egress** domain, which
lives in `SessionMetadata`. All four transforms in `userspace-dp/src/session/key.rs`
must therefore take it as a parameter:

- `reverse_wire_key(forward_key, nat, egress_domain)` (`:94`)
- `reverse_canonical_key(forward_key, nat, egress_domain)` (`:145`)
- `translated_session_key(key, nat, egress_domain)` (`:73`)
- `forward_wire_key(forward_key, nat)` (`:28`) — keeps the ingress domain, unchanged

`reply_matches_forward_session` must thread it through to both. **For intra-VRF flows
ingress == egress and this is a no-op**, which is exactly why the change is safe in
the common case and why a route-leaked test is mandatory to prove it is not vacuous.

Splitting C-P0 out is what makes this reviewable: it is a pure plumbing PR whose
correctness can be checked without touching identity, and it is also the PR that most
resembles #4983 — which is the chain's argument for doing #4983 first.

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

### 7a. Where `routing_domain` must be populated (AGY r1 required this be explicit)

C-P0 is only correct if **every** producer of a session-bearing ingress stamps the
slot. A missed producer leaves domain 0 on a real VRF flow, which under Path C means a
**silent failure to match** — a self-DoS, not a security hole, but a production outage
all the same. The inventory:

| Ingress producer | Domain source | Note |
|---|---|---|
| native interface ingress | `ifindex_to_routing_instance[ingress_ifindex]` → interned id | the common case |
| PBR-steered | the PBR-resolved routing-instance (`ingress_route_table_override`) | must agree with the FIB table actually used |
| GRE decap | the **tunnel logical** interface's RI | `gre.rs:760` already rebinds `ingress_ifindex` to `endpoint.logical_ifindex`, so this falls out of the native rule — **verified** |
| fabric cross-chassis | **exempt** — do not compare | `packet_fabric_ingress` is already a parameter at `poll_descriptor/mod.rs:448` |
| local delivery / host-inbound | default domain | `forwarding/host_inbound.rs` |
| neighbor-seed, other transient installs | default domain | must not be fail-closed against |
| **host-generated ICMP error state** (ICMP unreachable / time-exceeded / PTB) | inherit the **triggering packet's** domain — do **not** fall back to 0 | `afxdp/icmp_embed/`, `afxdp/icmp_ptb.rs` — AGY r2 |
| **NAT64 / NPTv6 synthetic translation flows** | the domain of the admitting side | `nat64.rs` — AGY r2; interacts with the cross-family key transform |
| peer-synced sessions | the wire field; absent → **do not enforce** (§4.3b), not "0 = default" | corrected in v6-r3 |

**Two producers AGY r2 asked for were verified NOT to exist and are deliberately
omitted:** **VXLAN decap** (no VXLAN implementation in `userspace-dp/src` — the sole
grep hit is a GRE local-delivery test filename) and **IP-in-IP decap** (`PROTO_IPIP`
appears only as a *policy match* protocol in `policy.rs`, with no decapsulation path).
Adding inventory rows for non-existent code would make the plan look more complete
while making it less true.

## 8. Risk assessment

| Class | Path A | Path B (DENY) | Path C (ISOLATE) |
|---|---|---|---|
| Behavioural regression | NONE | MED — a mis-derived domain drops a legitimate flow (self-DoS) | MED-HIGH — a mis-derived domain either fails to match (self-DoS) or cross-matches |
| HA mixed-version | NONE | NONE (value-only, no sync semantics) | **MED** — the *payload* is additive, but §4.3b's fail-open at domain 0 forces version-gated enforcement, so C-P3 carries a `CurrentHAProtocolVersion` bump **and** a change to the ISSU compatibility predicate. Still **rolling** (via the declared `MinCompat` floor), so v4's "HIGH / non-rolling flag day" rating remains withdrawn — but v6-r1's "LOW / no version bump" was too optimistic. |
| Wire / struct | NONE | NONE | LOW-MED — +4 B key, two additive trailing wire fields, golden fixture regen |
| Upgrade-gate blast radius | NONE | NONE | **MED (new in v6-r3)** — `parseHAProtocolCompatible` decides whether *any* release is rolling-upgradable. Loosening it to a declared floor is what the unused `MinCompatHAProtocolVersion` was written for, but it widens what the gate permits for every future release, not just this one. |
| Performance | NONE | NONE | **UNMEASURED** — one extra `write_u32`/hash, +4 B/entry; must be benchmarked (§4.4) |
| Security posture | leaves a hijack surface | closes hijack, opens a co-tenant DoS | closes hijack without opening a DoS |
| Semantics | contradicts shipped A.1 text | contradicts shipped A.1 text + Junos parity | matches both |

## 9. Test plan

**Per-path matching obligations (Claude SMR r2).** The domain argument must be made
for each lookup path, not just the primary one — v6-r2 asserted it globally. The paths
are: the direct-primary `key_to_handle` probe (**1:1**); the **reverse companion**
built by `build_reverse_session_from_forward_match`; and the **NAT-translated alias**
via `reverse_translated_index`, which is a **1:N multimap with validate-on-lookup**
(`#4438`) — a different structure, so the "1:1 forces the fault" reasoning in §5 does
**not** transfer to it and it needs its own test. Each path needs a case proving a
cross-domain packet does not match, and an intra-domain reply still does.

- **Interner stability (new in v6-r3, and the highest-value test in the plan):** add
  RI `b`, commit; establish a session in RI `c`; delete RI `a`; commit; assert `c`'s
  session **still matches** and its domain id is **unchanged**. This is RED against any
  positional/derived interning scheme, which is exactly the defect v6-r2 shipped.
  A second case: delete an RI and assert its id is **not reissued** to a new RI, and
  that its sessions were flushed.
- **Mixed-version enforcement-off (new in v6-r3):** with the peer advertising
  `HAProtocolVersion` 1, assert the upgraded node performs **no** domain comparison —
  i.e. behaviour is byte-identical to today, and specifically that a domain-0 packet
  does **not** match a legacy-synced session that would have collided under §4.3b's
  refuted trace.
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

**Resolved in r1** — Path D's stability hazard (AGY refuted it; Path D withdrawn);
the additivity caveat (AGY independently confirmed the fixed-width reverse-key block);
the ifindex/zone symmetry disqualification (AGY confirmed airtight); the literal-count
scope (reconciled to 297 with the grep stated).

**Open for r2:**

1. **The binary: DENY (Path B) or ISOLATE (Path C)?** With the 1:1 `key_to_handle`
   finding, Path B's two possible behaviours are both cross-tenant faults. Is that
   dispositive, or is a bounded co-tenant DoS still preferable to the churn of C?
2. **[LANDED in v6-r3 on (i) — attack the landing, not the question.]** §4.3b resolves
   the mixed-version fail-open by version-gating enforcement on the heartbeat's
   `HAProtocolVersion`, which requires bumping `CurrentHAProtocolVersion` to 2, setting
   `MinCompatHAProtocolVersion` = 1, and changing `parseHAProtocolCompatible` from
   exact equality to a declared-floor comparison. **Is changing the ISSU compatibility
   predicate acceptable?** It is the safety gate that decides whether a release is
   rolling-upgradable; loosening it to honour a declared floor is what the unused
   constant was written for, but it is a real widening of what the gate permits. If
   reviewers reject this, the fail-open at domain 0 has no cheap fix and the plan
   should probably go back to PLAN-DEFER.
3. **Does the chain ordering bind?** #4983 is a sequencing preference, not a
   dependency (§2.5). Should #2387 nonetheless wait for it, given #4983 is OPEN with
   no branch and would otherwise be the safer place to prove the plumbing?
4. **Is the route-leaked corner really cheap?** v4 deferred dual-domain handling as
   expensive; §4.5 claims it is cheap because `SessionMetadata` already swaps a zone
   pair. Refute or confirm.
5. **Is the §7a producer inventory complete?** A missed ingress producer is a silent
   self-DoS. Name any producer the table omits.
6. **Does the churn estimate hold**, or does adding a field to `SessionKey` cascade
   into the C mirror (`bpf/headers/xpf_conntrack.h`) and the Go mirror
   (`pkg/dataplane/types.go`)? AGY says the Go mirror stays 16 B if the domain rides
   in `SessionValue` — confirm or refute.
7. **Is PLAN-KILL the right answer anyway?** The trigger config is niche and now
   warned-about. Argue the cost/benefit case for closing #2387 with Path A.
