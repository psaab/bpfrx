OpenAI Codex v0.146.0
--------
[1mworkdir:[0m /home/ps/git/bpfrx/.claude/worktrees/2387res
[1mmodel:[0m gpt-5.6-sol
[1mprovider:[0m openai
[1mapproval:[0m never
[1msandbox:[0m workspace-write [workdir, /tmp, $TMPDIR]
[1mreasoning effort:[0m ultra
[1mreasoning summaries:[0m none
[1msession id:[0m 019fd53e-5e38-7572-b0d8-64d1a9aab610
--------
[36muser[0m
HOSTILE plan review. FAIL the plan if its claims are wrong. Do not confirm-by-default.

REPO: /home/ps/git/bpfrx/.claude/worktrees/2387res (worktree at origin/master e80db2eae).
READ-ONLY. Do not modify files.
PLAN: docs/research/2387-session-identity/plan.md (revision v6-r3).

BUDGET YOUR TIME. Do not read the whole repo. Verify the SIX claims below at the exact
file:line each cites, then stop and give a verdict. Prior rounds already CONFIRMED the
reachability trace, the 1:1 key_to_handle map, the byte budget and the length-gated
wire decoder — do NOT re-verify those.

Verify each of these and answer CONFIRMED or REFUTED with file:line evidence:

C1. Plan §4.3b claims the heartbeat carries `HAProtocolVersion` in EVERY packet
    (pkg/cluster/heartbeat.go:286 encode, :374 decode) and that this is NOT gated on a
    PSK being configured — unlike performSyncHandshake (pkg/cluster/sync_auth.go:330,
    which returns early when no key is set). If true, the peer's protocol version is a
    capability signal usable on an unkeyed cluster. Verify both halves.

C2. Plan §4.3b claims `parseHAProtocolCompatible` (pkg/upgrade/cluster_cli.go:253)
    requires EXACT equality of local and peer versions, so a naive
    CurrentHAProtocolVersion bump makes the release non-rolling. Verify.

C3. Plan §4.3b claims `MinCompatHAProtocolVersion` (pkg/cluster/heartbeat.go:46)
    exists but is VESTIGIAL — no non-test consumer anywhere in the tree. Verify by
    grepping. If it HAS a production consumer, the plan's proposed design is wrong.

C4. Plan §4.3b's core safety argument: during a mixed-version window an un-upgraded
    peer omits the routing_domain field, the upgraded node decodes it as 0, and because
    0 is interned as the DEFAULT routing-instance, a genuine default-VRF flow with the
    same 5-tuple MATCHES the peer's tenant-a session and cross-forwards. The plan calls
    this fail-OPEN and fixes it by not enforcing domain matching until the peer
    advertises the new version. ATTACK THIS: is the version-gate actually sufficient,
    or is there a window (e.g. version learned late, peer flapping, heartbeat lost,
    session synced before the version is known) where enforcement engages against
    sessions imported without a domain? Be concrete.

C5. Plan §5 requires routing_domain ids be allocated ONCE per routing-instance, never
    re-derived from the current RI set, never reissued after delete, with the name->id
    table carried in the CONFIG so both cluster nodes agree via config sync. It
    explicitly REJECTS a name-hash (FNV-1a) because hash collisions map two tenants to
    one domain id. ATTACK: is config-carried allocation actually workable here — does
    xpf's config sync guarantee both nodes see the same table, and does `rollback`
    restore it coherently? Is the collision objection to hashing fair, or overstated?

C6. Plan §7a claims VXLAN decap and IP-in-IP decap do NOT exist in userspace-dp and so
    were deliberately omitted from the ingress-producer inventory. Verify. Then say
    whether the inventory is otherwise COMPLETE — name any session-bearing ingress
    producer it misses.

THEN: give the terminal verdict on the plan as a whole. PLAN-KILL is legitimate — the
trigger config is niche (overlapping subnets across routing-instances plus PBR
`then routing-instance`) and the firewall already warns at commit. If the cost is not
justified, say PLAN-KILL.

END WITH EXACTLY ONE LINE, on its own line, choosing ONE value:
VERDICT: <PLAN-READY or PLAN-NEEDS-REVISION or PLAN-NEEDS-MAJOR-REVISION or PLAN-KILL or PLAN-DEFER>
then 2-4 sentences of justification and, if not PLAN-READY/PLAN-KILL, a numbered list
of required changes.

[35m[3mcodex[0m[0m
I’ll treat every claim as adversarially unproven. I’m splitting the six checks among read-only reviewers for parallel evidence gathering, then I’ll independently audit the cited lines and reconcile any disagreement; I will not revisit the four items already confirmed in prior rounds.
[35m[3mexec[0m[0m
[1m/bin/bash -lc "pwd && git rev-parse HEAD && git status --short && rg -n '"'^#{1,6} .*4'"\\.3b|"'^#{1,6} .*5|''^#{1,6} .*7a|HAProtocolVersion|MinCompatHAProtocolVersion|routing_domain|FNV|VXLAN|IP-in-IP'"' docs/research/2387-session-identity/plan.md"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
/home/ps/git/bpfrx/.claude/worktrees/2387res
8b2ce31fd4fc7ef6a30e6425c2dcc492cb500aa3
1:# #2387 — session/flow identity is the bare 5-tuple: the DENY-vs-ISOLATE decision
15:- §7a extended with the ICMP-error and NAT64 producers. **AGY's suggested VXLAN
16:  and IP-in-IP producers were verified NOT to exist in this codebase and are
55:  `CurrentHAProtocolVersion` bump and a non-rolling both-nodes upgrade; and
101:## 2.5 Chain position — #2387 is the middle link, and it owns the wire decision
118:| **#2387** | `routing_domain` | OPEN, `plan-deferred-operator` | research only |
220:**Consequence:** `CurrentHAProtocolVersion` (`pkg/cluster/heartbeat.go:35`;
251:| **#2387 `routing_domain`** | 0 is interned as the **default** routing-instance | a domain-N packet **fails to match**; flow re-establishes | **narrows — fail-CLOSED** |
275:### 4.3b The fail-closed claim was WRONG at domain 0 — and fixing it decides the capability question
281:2. The upgraded node decodes `routing_domain = 0` and installs the session **under
305:- The heartbeat carries `HAProtocolVersion` in **every packet**, encoded at
315:But `MinCompatHAProtocolVersion` (`heartbeat.go:46`) **exists for precisely this case**
316:— *"the OLDEST HA protocol version `CurrentHAProtocolVersion` can still interoperate
320:1. bump `CurrentHAProtocolVersion` → 2, set `MinCompatHAProtocolVersion` = 1;
348:size_of::<SessionKeyWide>()  = 44   align = 4     (+ routing_domain: u32)
374:| + #2387 `routing_domain: u32` | **44** |
399:### 4.5 The corner cases any domain-aware change must handle
435:## 5. Multiple Path Options
476:Store the admitting `routing_domain` in `SessionMetadata` (the **VALUE**, not the
498:- **C-P0** — intern the routing-instance name to a dense `routing_domain: u32`
504:- **C-P2** — add `routing_domain: u32` to `SessionKey` and to the reverse-key
513:`CurrentHAProtocolVersion` bump plus the `parseHAProtocolCompatible` change (§4.3b)**,
557:> A `routing_domain` id is **allocated once per routing-instance identity and never
566:of AGY's recommendation.** AGY r2 proposed a deterministic string hash (FNV-1a of the
577:Non-VRF deployments still see `routing_domain == 0` everywhere, which preserves the
593:| **C-P0** | dense static interning of RI names → `routing_domain: u32`; populate the dead `meta.routing_table` slot at **every** ingress producer (native ingress, local delivery, GRE decap, fabric ingress). **No behaviour change** — nothing reads it yet. | no | unit |
594:| **C-P2** | add `routing_domain` to `SessionKey` + the four transforms in `session/key.rs`; store ingress **and** egress domain in `SessionMetadata`; fabric exemption. | no | RED-on-revert + negative control |
595:| **C-P3** | `IngressRoutingDomain` / `EgressRoutingDomain` as length-gated trailing VALUE fields, V4 **and** V6; reverse-key domain reconstruction; **`CurrentHAProtocolVersion` → 2 + `MinCompat` = 1 + the `parseHAProtocolCompatible` change + version-gated enforcement (§4.3b)**. | yes | `make test-failover` + short-payload decode + **mixed-version enforcement-off** test |
647:### 7a. Where `routing_domain` must be populated (AGY r1 required this be explicit)
667:omitted:** **VXLAN decap** (no VXLAN implementation in `userspace-dp/src` — the sole
668:grep hit is a GRE local-delivery test filename) and **IP-in-IP decap** (`PROTO_IPIP`
678:| HA mixed-version | NONE | NONE (value-only, no sync semantics) | **MED** — the *payload* is additive, but §4.3b's fail-open at domain 0 forces version-gated enforcement, so C-P3 carries a `CurrentHAProtocolVersion` bump **and** a change to the ISSU compatibility predicate. Still **rolling** (via the declared `MinCompat` floor), so v4's "HIGH / non-rolling flag day" rating remains withdrawn — but v6-r1's "LOW / no version bump" was too optimistic. |
680:| Upgrade-gate blast radius | NONE | NONE | **MED (new in v6-r3)** — `parseHAProtocolCompatible` decides whether *any* release is rolling-upgradable. Loosening it to a declared floor is what the unused `MinCompatHAProtocolVersion` was written for, but it widens what the gate permits for every future release, not just this one. |
703:  `HAProtocolVersion` 1, assert the upgraded node performs **no** domain comparison —
710:  correct reply-direction match *within* each VRF. Reverting `routing_domain` makes it
751:   `HAProtocolVersion`, which requires bumping `CurrentHAProtocolVersion` to 2, setting
752:   `MinCompatHAProtocolVersion` = 1, and changing `parseHAProtocolCompatible` from

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba docs/research/2387-session-identity/plan.md | sed -n '265,335p;545,585p;640,680p;690,760p'
git status -sb
git log -3 --oneline --decorate"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   265	as #5804's reject-not-widen requirement, and the HELLO is the natural place to hang a
   266	feature bit.
   267	
   268	**The constraint that matters:** the handshake *"runs ONLY when a local key is
   269	configured. An unkeyed node ... sends nothing special and is indistinguishable from —
   270	and fully compatible with — a legacy peer"* (`sync_auth.go:322-326`). So on a cluster
   271	with no `authentication-key`, **no handshake happens at all** and there is no place to
   272	carry a capability bit. Any chain-wide negotiation design must either accept that it
   273	only protects keyed clusters, or introduce an unconditional capability exchange.
   274	
   275	### 4.3b The fail-closed claim was WRONG at domain 0 — and fixing it decides the capability question
   276	
   277	**AGY r2 refuted §4.3a's "it never cross-forwards", and the refutation is correct.**
   278	The trace:
   279	
   280	1. An un-upgraded peer syncs a session for `tenant-a` (domain N). It omits the field.
   281	2. The upgraded node decodes `routing_domain = 0` and installs the session **under
   282	   domain 0** — because we chose "0 = the default routing-instance".
   283	3. A **new flow in the default VRF** (genuinely domain 0) arrives with the same 5-tuple.
   284	4. It looks up `(5-tuple, domain 0)` and **matches tenant-a's session** — inheriting
   285	   its egress, NAT binding and policy verdict.
   286	
   287	So the interning choice that makes non-VRF clusters bit-identical is exactly what
   288	makes a VRF cluster **fail-OPEN for default-VRF traffic** during the upgrade window.
   289	The polarity table in §4.3a holds for domain-N packets only.
   290	
   291	**Note this is not a small residue:** it re-creates #2387's original cross-forwarding
   292	bug, in the one window where an operator is least able to observe it, and in exactly
   293	the overlapping-subnet config the feature exists to protect.
   294	
   295	**Why the obvious fixes fail.** Using a distinct `UNKNOWN` sentinel instead of 0 is
   296	fail-closed, but then *every* legacy-peer-synced session fails to match — including in
   297	**non-VRF clusters**, which destroys the "bit-identical" property and turns a
   298	mixed-version failover into mass session loss. That is a worse trade.
   299	
   300	**The resolution: gate enforcement on the peer's protocol version, not on the field.**
   301	During the window, the upgraded node must behave **exactly as today** — 5-tuple only,
   302	no domain comparison — and engage domain enforcement only once the peer is known to
   303	speak it. The signal already exists and, crucially, is **not PSK-gated**:
   304	
   305	- The heartbeat carries `HAProtocolVersion` in **every packet**, encoded at
   306	  `pkg/cluster/heartbeat.go:286` and decoded at `:374`. Unlike the F23 handshake this
   307	  is unconditional — an unkeyed cluster still exchanges it.
   308	
   309	**The catch, and the scope it implies.** The ISSU driver requires the two versions to
   310	be **exactly equal**: `parseHAProtocolCompatible` (`pkg/upgrade/cluster_cli.go:253`)
   311	is documented *"Compatible iff N == M … a bump means the wire semantics changed and
   312	the release is NOT rolling-upgradable"*. So a naive bump would make the release
   313	non-rolling — reviving the very objection §4.3 retired.
   314	
   315	But `MinCompatHAProtocolVersion` (`heartbeat.go:46`) **exists for precisely this case**
   316	— *"the OLDEST HA protocol version `CurrentHAProtocolVersion` can still interoperate
   317	with"* — and it is currently **vestigial: it has no non-test consumer in the tree**
   318	(verified). The design is therefore:
   319	
   320	1. bump `CurrentHAProtocolVersion` → 2, set `MinCompatHAProtocolVersion` = 1;
   321	2. change `parseHAProtocolCompatible` to honour the declared floor (`peer >=
   322	   MinCompat`) instead of exact equality;
   323	3. enforce domain matching only when the peer advertises >= 2.
   324	
   325	Result: no fail-open, no session loss, and the upgrade **stays rolling** — but via a
   326	declared-compatibility contract rather than by avoiding the version bump.
   327	
   328	**This is real, high-consequence scope: it modifies the upgrade safety gate.** It is
   329	well-founded (the constant exists for this and is unused), but it must be priced, and
   330	it must not be smuggled in as a one-liner.
   331	
   332	**Consequently §11 Q2 lands on (i), not (ii):** #2387 must carry the capability signal
   333	**for its own correctness**, not as a favour to #5804. That also disposes of the
   334	PSK-gating problem — the heartbeat version is unconditional, so the F23 handshake is
   335	*not* the mechanism to use here. #5804 may still need a finer-grained feature bit for
   545	  failure to match, but a **match against the wrong tenant**. That is #2387's original
   546	  bug, re-created by its own fix, and triggered by an unrelated commit.
   547	- **Id reuse** after a delete/re-add has the same shape: a stale session matches a new
   548	  tenant.
   549	- **AGY additionally found the HA half:** two nodes that build their tables at
   550	  different times (one has been running through several commits, the other just
   551	  rebooted from a fresh snapshot) would assign **different ids to the same RI name**.
   552	  A session synced from node A then matches a *different* VRF on node B. This is a
   553	  live-cluster fault, not just an upgrade-window one.
   554	
   555	**The invariant, which C-P0 must implement and test:**
   556	
   557	> A `routing_domain` id is **allocated once per routing-instance identity and never
   558	> re-derived from the current RI set**. Allocation is monotonic; the name→id table is
   559	> **carried in the configuration** and therefore (a) identical on both cluster nodes
   560	> via the existing config sync, (b) persisted across daemon restart, and (c) restored
   561	> correctly by `rollback`. Deleting an RI **retires** its id; a retired id is **never
   562	> reissued**. On RI deletion, sessions in that domain are explicitly **flushed** rather
   563	> than left to age out under an id that no longer denotes anything.
   564	
   565	**Why the table is carried in the config rather than hashed — a deliberate rejection
   566	of AGY's recommendation.** AGY r2 proposed a deterministic string hash (FNV-1a of the
   567	RI name, 0 reserved for `default`) to guarantee both nodes agree. That does solve
   568	agreement and persistence with no new state — but **a hash has collisions**, and a
   569	collision between two RI names maps two distinct tenants onto one domain id, which is
   570	**precisely the cross-tenant match this entire issue exists to prevent**. Trading a
   571	guaranteed-correct table for a 2^-32 silent security fault is the wrong trade in a
   572	security boundary. Config-carried allocation gets agreement from the config sync that
   573	already exists, and gets persistence and rollback for free, with **no collision
   574	possible**. Reviewers should push back if they disagree, but the collision argument
   575	should be answered rather than waved past.
   576	
   577	Non-VRF deployments still see `routing_domain == 0` everywhere, which preserves the
   578	rollout-safety value Path D was reaching for, without the hazard.
   579	
   580	### Recommendation (to be tested by review, not asserted)
   581	
   582	**Path C, staged, with static deterministic interning** (Path D's rollout discipline
   583	is withdrawn; its *goal* — non-VRF deployments behaviourally identical — is preserved
   584	by domain 0). Rationale: the cost objection that drove the v4 deferral is retired
   585	(§4.3); Path B is structurally forced into a cross-tenant fault by the 1:1
   640	  `routing_table` slot keeps this intact.
   641	- **No per-packet allocation** — the domain must be an interned `u32` lookup, never a
   642	  per-packet `String` clone or a name hash.
   643	- **#3096 NAT-scope coherence** — a cached fast-path decision must only be reused for
   644	  a flow in the same scope it was admitted under. This is the invariant #2387 violates.
   645	- **The embedded reverse-key block is fixed-width** (§4.3 caveat).
   646	
   647	### 7a. Where `routing_domain` must be populated (AGY r1 required this be explicit)
   648	
   649	C-P0 is only correct if **every** producer of a session-bearing ingress stamps the
   650	slot. A missed producer leaves domain 0 on a real VRF flow, which under Path C means a
   651	**silent failure to match** — a self-DoS, not a security hole, but a production outage
   652	all the same. The inventory:
   653	
   654	| Ingress producer | Domain source | Note |
   655	|---|---|---|
   656	| native interface ingress | `ifindex_to_routing_instance[ingress_ifindex]` → interned id | the common case |
   657	| PBR-steered | the PBR-resolved routing-instance (`ingress_route_table_override`) | must agree with the FIB table actually used |
   658	| GRE decap | the **tunnel logical** interface's RI | `gre.rs:760` already rebinds `ingress_ifindex` to `endpoint.logical_ifindex`, so this falls out of the native rule — **verified** |
   659	| fabric cross-chassis | **exempt** — do not compare | `packet_fabric_ingress` is already a parameter at `poll_descriptor/mod.rs:448` |
   660	| local delivery / host-inbound | default domain | `forwarding/host_inbound.rs` |
   661	| neighbor-seed, other transient installs | default domain | must not be fail-closed against |
   662	| **host-generated ICMP error state** (ICMP unreachable / time-exceeded / PTB) | inherit the **triggering packet's** domain — do **not** fall back to 0 | `afxdp/icmp_embed/`, `afxdp/icmp_ptb.rs` — AGY r2 |
   663	| **NAT64 / NPTv6 synthetic translation flows** | the domain of the admitting side | `nat64.rs` — AGY r2; interacts with the cross-family key transform |
   664	| peer-synced sessions | the wire field; absent → **do not enforce** (§4.3b), not "0 = default" | corrected in v6-r3 |
   665	
   666	**Two producers AGY r2 asked for were verified NOT to exist and are deliberately
   667	omitted:** **VXLAN decap** (no VXLAN implementation in `userspace-dp/src` — the sole
   668	grep hit is a GRE local-delivery test filename) and **IP-in-IP decap** (`PROTO_IPIP`
   669	appears only as a *policy match* protocol in `policy.rs`, with no decapsulation path).
   670	Adding inventory rows for non-existent code would make the plan look more complete
   671	while making it less true.
   672	
   673	## 8. Risk assessment
   674	
   675	| Class | Path A | Path B (DENY) | Path C (ISOLATE) |
   676	|---|---|---|---|
   677	| Behavioural regression | NONE | MED — a mis-derived domain drops a legitimate flow (self-DoS) | MED-HIGH — a mis-derived domain either fails to match (self-DoS) or cross-matches |
   678	| HA mixed-version | NONE | NONE (value-only, no sync semantics) | **MED** — the *payload* is additive, but §4.3b's fail-open at domain 0 forces version-gated enforcement, so C-P3 carries a `CurrentHAProtocolVersion` bump **and** a change to the ISSU compatibility predicate. Still **rolling** (via the declared `MinCompat` floor), so v4's "HIGH / non-rolling flag day" rating remains withdrawn — but v6-r1's "LOW / no version bump" was too optimistic. |
   679	| Wire / struct | NONE | NONE | LOW-MED — +4 B key, two additive trailing wire fields, golden fixture regen |
   680	| Upgrade-gate blast radius | NONE | NONE | **MED (new in v6-r3)** — `parseHAProtocolCompatible` decides whether *any* release is rolling-upgradable. Loosening it to a declared floor is what the unused `MinCompatHAProtocolVersion` was written for, but it widens what the gate permits for every future release, not just this one. |
   690	built by `build_reverse_session_from_forward_match`; and the **NAT-translated alias**
   691	via `reverse_translated_index`, which is a **1:N multimap with validate-on-lookup**
   692	(`#4438`) — a different structure, so the "1:1 forces the fault" reasoning in §5 does
   693	**not** transfer to it and it needs its own test. Each path needs a case proving a
   694	cross-domain packet does not match, and an intra-domain reply still does.
   695	
   696	- **Interner stability (new in v6-r3, and the highest-value test in the plan):** add
   697	  RI `b`, commit; establish a session in RI `c`; delete RI `a`; commit; assert `c`'s
   698	  session **still matches** and its domain id is **unchanged**. This is RED against any
   699	  positional/derived interning scheme, which is exactly the defect v6-r2 shipped.
   700	  A second case: delete an RI and assert its id is **not reissued** to a new RI, and
   701	  that its sessions were flushed.
   702	- **Mixed-version enforcement-off (new in v6-r3):** with the peer advertising
   703	  `HAProtocolVersion` 1, assert the upgraded node performs **no** domain comparison —
   704	  i.e. behaviour is byte-identical to today, and specifically that a domain-0 packet
   705	  does **not** match a legacy-synced session that would have collided under §4.3b's
   706	  refuted trace.
   707	- **RED-on-revert, the issue's stated regression:** two VLAN sub-units on one parent,
   708	  two routing-instances, each with PBR `then routing-instance`, identical 5-tuples,
   709	  differing policy/NAT ⇒ assert **no** session reuse across the boundary **and**
   710	  correct reply-direction match *within* each VRF. Reverting `routing_domain` makes it
   711	  RED because flow 2 inherits flow 1's egress.
   712	- **Negative control** (per this project's mutation discipline): a **non**-overlapping
   713	  two-VRF config must be behaviourally identical before and after — this is what
   714	  proves the guard is scoped, not merely present.
   715	- **Route-leaked corner:** a rib-group / `next-table` inter-VRF flow must still
   716	  reverse-match. This is the highest-value test and the one most likely to be skipped.
   717	- **Fabric exemption:** a peer-owned session redirected over the fabric must still
   718	  match despite a differing ingress domain.
   719	- **Wire:** V4 **and** V6 encode→decode round-trip of the two new trailing fields;
   720	  a **short-payload (legacy peer) decode** test proving `ok=true` with the fields
   721	  defaulting to domain 0; golden `protocol_wire_v1.json` regenerated.
   722	- **HA live:** `make test-failover` on the loss userspace cluster — mandatory.
   723	- **Perf:** the five measurements in §4.4. No merge on an unmeasured perf claim.
   724	
   725	## 10. Out of scope
   726	
   727	- Per-VRF **default** FIB / per-VRF local-delivery sets (v4's Track B-ext) — a separate
   728	  enhancement, **not** a prerequisite, since PBR is already the per-VRF forwarding
   729	  mechanism.
   730	- Flipping A.1 from warning to hard reject.
   731	- Replacing the redundant `addr_family` field to keep the key at 40 bytes. It *is*
   732	  structurally redundant with the `IpAddr` enum tag, but micro-packing a
   733	  security-critical key to save 4 bytes trades review risk for nothing measurable.
   734	  **Considered and rejected.**
   735	- Any change to the eBPF retirement posture.
   736	
   737	## 11. Open questions for adversarial review
   738	
   739	**Resolved in r1** — Path D's stability hazard (AGY refuted it; Path D withdrawn);
   740	the additivity caveat (AGY independently confirmed the fixed-width reverse-key block);
   741	the ifindex/zone symmetry disqualification (AGY confirmed airtight); the literal-count
   742	scope (reconciled to 297 with the grep stated).
   743	
   744	**Open for r2:**
   745	
   746	1. **The binary: DENY (Path B) or ISOLATE (Path C)?** With the 1:1 `key_to_handle`
   747	   finding, Path B's two possible behaviours are both cross-tenant faults. Is that
   748	   dispositive, or is a bounded co-tenant DoS still preferable to the churn of C?
   749	2. **[LANDED in v6-r3 on (i) — attack the landing, not the question.]** §4.3b resolves
   750	   the mixed-version fail-open by version-gating enforcement on the heartbeat's
   751	   `HAProtocolVersion`, which requires bumping `CurrentHAProtocolVersion` to 2, setting
   752	   `MinCompatHAProtocolVersion` = 1, and changing `parseHAProtocolCompatible` from
   753	   exact equality to a declared-floor comparison. **Is changing the ISSU compatibility
   754	   predicate acceptable?** It is the safety gate that decides whether a release is
   755	   rolling-upgradable; loosening it to honour a declared floor is what the unused
   756	   constant was written for, but it is a real widening of what the gate permits. If
   757	   reviewers reject this, the fail-open at domain 0 has no cheap fix and the plan
   758	   should probably go back to PLAN-DEFER.
   759	3. **Does the chain ordering bind?** #4983 is a sequencing preference, not a
   760	   dependency (§2.5). Should #2387 nonetheless wait for it, given #4983 is OPEN with
## research/2387-session-identity...origin/master [ahead 5]
8b2ce31fd (HEAD -> research/2387-session-identity) research(#2387): v6-r3 follow-up — retire two stale no-version-bump claims
6ec5a057e research(#2387): plan v6-r3 — fold r2; two defects found in the FIX
8751d5a08 research(#2387): plan v6-r2 — fold Claude SMR + AGY r1

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/heartbeat.go | sed -n '25,65p;230,305p;345,395p'
nl -ba pkg/cluster/sync_auth.go | sed -n '300,350p'
nl -ba pkg/upgrade/cluster_cli.go | sed -n '225,275p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
    25		heartbeatVersion = 1
    26	
    27		// LegacyHAProtocolVersion is the compatibility version implicitly used by
    28		// older heartbeats that predate explicit HA protocol advertisement.
    29		LegacyHAProtocolVersion uint16 = 1
    30	
    31		// CurrentHAProtocolVersion is the HA/session-transfer compatibility version
    32		// used to decide whether mixed software builds can still hand off RGs. Bump
    33		// this only when heartbeat/session-sync/failover wire semantics change in a
    34		// way that breaks mixed-version interoperability.
    35		CurrentHAProtocolVersion = LegacyHAProtocolVersion
    36	
    37		// MinCompatHAProtocolVersion is the OLDEST HA protocol version
    38		// CurrentHAProtocolVersion can still interoperate with — the back-compat
    39		// floor the #1930 INC-3 mixed-base image-replace gate advertises. It is NOT
    40		// LegacyHAProtocolVersion: legacy is a fixed historical constant (1), whereas
    41		// this is the deliberate "how far back are we compatible" decision that an
    42		// author MUST re-evaluate on every CurrentHAProtocolVersion bump. They are
    43		// equal today (this build speaks 1 and is compatible back to 1); a future
    44		// incompatible bump raises Current AND sets this floor to the oldest peer the
    45		// new build can still sync with (which may equal Current if no back-compat).
    46		MinCompatHAProtocolVersion = CurrentHAProtocolVersion
    47	
    48		// maxHeartbeatSize is the max packet size we'll read/write.
    49		// 1472 = 1500 MTU - 20 IP header - 8 UDP header.
    50		maxHeartbeatSize = 1472
    51	
    52		// DefaultHeartbeatInterval is the default heartbeat send interval.
    53		DefaultHeartbeatInterval = 100 * time.Millisecond
    54	
    55		// DefaultHeartbeatThreshold is the default missed heartbeat count before peer is lost.
    56		DefaultHeartbeatThreshold = 5
    57	
    58		// heartbeatStartupGrace is the cold-boot config-apply grace window. For
    59		// this long after a receiver starts, the local config apply phase (VRF
    60		// binding, FRR reload, fabric creation, RETH MAC down/up) can disrupt the
    61		// control-link UDP receive path for 10-15+ seconds. BOTH peer-liveness
    62		// decisions hold behind this floor so a simultaneous cold boot cannot
    63		// split-brain:
    64		//   - seen-then-lost: suppress peer-lost entirely — a recovering node must
    65		//     not declare a live peer dead on the first dropped heartbeat.
   230		off := heartbeatHeaderSize
   231		for _, g := range groups {
   232			buf[off] = g.GroupID
   233			binary.LittleEndian.PutUint16(buf[off+1:off+3], g.Priority)
   234			buf[off+3] = g.Weight
   235			buf[off+4] = g.State
   236			off += heartbeatGroupSize
   237		}
   238	
   239		var version []byte
   240		const heartbeatVersionTrailerSize = 1 + 2 // version length byte + HA protocol version
   241		versionReserve := heartbeatVersionTrailerSize
   242		if pkt.SoftwareVersion != "" {
   243			version = []byte(pkt.SoftwareVersion)
   244			if len(version) > maxHeartbeatSoftwareVersionSize {
   245				version = version[:maxHeartbeatSoftwareVersionSize]
   246			}
   247			if off+heartbeatVersionTrailerSize+len(version) <= maxHeartbeatSize-tailReserve {
   248				versionReserve = heartbeatVersionTrailerSize + len(version)
   249			} else {
   250				version = nil
   251			}
   252		}
   253	
   254		// Append monitor section, fitting as many monitors as possible.
   255		monCountOff := off // remember offset of NumMonitors byte
   256		buf[off] = 0       // NumMonitors — updated below
   257		off++
   258		numMon := 0
   259		for _, mon := range pkt.Monitors {
   260			nameBytes := []byte(mon.Interface)
   261			entrySize := 4 + len(nameBytes) // RGID + Flags + Weight + NameLen + name
   262			if off+entrySize > maxHeartbeatSize-versionReserve-tailReserve {
   263				break
   264			}
   265			buf[off] = mon.RGID
   266			flags := uint8(0)
   267			if mon.Up {
   268				flags |= 1
   269			}
   270			buf[off+1] = flags
   271			buf[off+2] = mon.Weight
   272			buf[off+3] = uint8(len(nameBytes))
   273			off += 4
   274			copy(buf[off:off+len(nameBytes)], nameBytes)
   275			off += len(nameBytes)
   276			numMon++
   277		}
   278		buf[monCountOff] = uint8(numMon)
   279		if off+versionReserve+tailReserve <= maxHeartbeatSize {
   280			buf[off] = uint8(len(version))
   281			off++
   282			if len(version) > 0 {
   283				copy(buf[off:off+len(version)], version)
   284				off += len(version)
   285			}
   286			binary.LittleEndian.PutUint16(buf[off:off+2], normalizeHAProtocolVersion(pkt.HAProtocolVersion))
   287			off += 2
   288		}
   289		return buf[:off]
   290	}
   291	
   292	// UnmarshalHeartbeat decodes a heartbeat packet from wire format.
   293	func UnmarshalHeartbeat(data []byte) (*HeartbeatPacket, error) {
   294		if len(data) < heartbeatHeaderSize {
   295			return nil, fmt.Errorf("heartbeat too short: %d bytes", len(data))
   296		}
   297		if string(data[0:4]) != heartbeatMagic {
   298			return nil, fmt.Errorf("invalid heartbeat magic: %q", string(data[0:4]))
   299		}
   300		if data[4] != heartbeatVersion {
   301			return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
   302		}
   303	
   304		pkt := &HeartbeatPacket{
   305			NodeID:            data[5],
   345				nameLen := int(data[off+3])
   346				off += 4
   347				if off+nameLen > len(data) {
   348					monitorSectionComplete = false
   349					break // truncated name — return what we have
   350				}
   351				name := string(data[off : off+nameLen])
   352				off += nameLen
   353				pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
   354					RGID:      rgID,
   355					Weight:    weight,
   356					Up:        up,
   357					Interface: name,
   358				})
   359			}
   360		}
   361		versionSectionComplete := false
   362		if monitorSectionComplete && off < len(data) {
   363			versionLen := int(data[off])
   364			off++
   365			if off+versionLen <= len(data) {
   366				pkt.SoftwareVersion = string(data[off : off+versionLen])
   367				off += versionLen
   368				versionSectionComplete = true
   369			} else {
   370				return pkt, nil
   371			}
   372		}
   373		if monitorSectionComplete && versionSectionComplete && off+2 <= len(data) {
   374			pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
   375		}
   376	
   377		return pkt, nil
   378	}
   379	
   380	// --- #4107 control-channel authentication (heartbeat/election) -------------
   381	//
   382	// The cluster heartbeat drives election: handlePeerHeartbeat rebuilds peer RG
   383	// state directly from the packet and runs runElection(), so a forged cleartext
   384	// heartbeat can force the local node PRIMARY or demote the peer. When a shared
   385	// PSK (chassis cluster authentication-key) is configured, the sender appends an
   386	// HMAC-SHA256 trailer over the whole frame plus an anti-replay nonce, and the
   387	// receiver rejects a heartbeat that fails (or, once both nodes are keyed, lacks)
   388	// authentication BEFORE it can refresh peer liveness or drive election.
   389	//
   390	// Dual-accept (rolling upgrade): a node without a key emits and accepts legacy
   391	// frames; a keyed node accepts an unauthenticated frame until it has observed
   392	// the peer authenticate (proving both nodes hold the key), after which an
   393	// unauthenticated frame is a downgrade attack and is rejected. This mirrors the
   394	// #4126 VRRP-checksum dual-accept migration: accept both wire forms during the
   395	// upgrade window, enforce once both sides speak the new form.
   300		typ = hdr[4]
   301		length := binary.LittleEndian.Uint32(hdr[8:12])
   302		if length > 16*1024*1024 {
   303			return 0, nil, fmt.Errorf("cluster sync: handshake frame too large: %d", length)
   304		}
   305		if length > 0 {
   306			payload = make([]byte, length)
   307			if _, err := io.ReadFull(conn, payload); err != nil {
   308				return 0, nil, err
   309			}
   310		}
   311		return typ, payload, nil
   312	}
   313	
   314	// performSyncHandshake runs the connection-setup auth-capability handshake on a
   315	// freshly connected sync connection and returns the negotiated mode, the
   316	// per-connection frame key (non-nil only when authenticated), an optional first
   317	// frame a legacy/unkeyed peer already sent (the caller must process it before
   318	// reading further), and an error when the connection must be dropped (bad PSK
   319	// proof, a downgrade attempt, or an I/O failure).
   320	//
   321	// The handshake runs ONLY when a local key is configured. An unkeyed node
   322	// (legacy build, or a new build with no key yet) sends nothing special and is
   323	// indistinguishable from — and fully compatible with — a legacy peer, so
   324	// existing no-key deployments and tests are unaffected (dual-accept).
   325	//
   326	// HELLO and PROOF are written concurrently with reading the peer's frame so the
   327	// handshake works over a fully-synchronous transport (net.Pipe in tests): a
   328	// strict write-then-read on both symmetric peers would deadlock.
   329	func (s *SessionSync) performSyncHandshake(conn net.Conn) (syncAuthMode, []byte, *pendingFrame, error) {
   330		key := s.authKey()
   331		if len(key) == 0 {
   332			// No local key ⇒ no handshake; legacy behavior (dual-accept).
   333			return syncAuthUnauthenticated, nil, nil, nil
   334		}
   335	
   336		if err := conn.SetDeadline(time.Now().Add(syncHandshakeTimeout)); err != nil {
   337			return syncAuthUnauthenticated, nil, nil, err
   338		}
   339		defer conn.SetDeadline(time.Time{})
   340	
   341		localNonce := make([]byte, syncAuthNonceSize)
   342		if _, err := rand.Read(localNonce); err != nil {
   343			return syncAuthUnauthenticated, nil, nil, fmt.Errorf("cluster sync: handshake nonce: %w", err)
   344		}
   345		hello := make([]byte, 0, 2+syncAuthNonceSize)
   346		hello = append(hello, syncAuthVersion, 1) // version, keyed=1
   347		hello = append(hello, localNonce...)
   348	
   349		writeErr := make(chan error, 1)
   350		go func() { writeErr <- writeMsg(conn, syncMsgAuthHello, hello) }()
   225				continue
   226			}
   227			if ll == "" {
   228				// Reached the end of the sync section with no Status line (e.g.
   229				// "Not configured"): fail closed.
   230				break
   231			}
   232			if strings.HasPrefix(ll, "status:") {
   233				val := strings.TrimSpace(strings.TrimPrefix(ll, "status:"))
   234				return val == "up"
   235			}
   236		}
   237		// No sync-link Status line rendered: fail closed (do not assume sync is up).
   238		return false
   239	}
   240	
   241	// parseHAProtocolCompatible compares the local and peer HA protocol
   242	// version lines from `show chassis cluster status` (FormatStatus):
   243	//
   244	//	HA protocol version: N
   245	//	Peer HA protocol version: M
   246	//
   247	// Compatible iff N == M (the rolling contract: mixed N/N+1 nodes only
   248	// hand off RGs when CurrentHAProtocolVersion matches; a bump means the
   249	// wire semantics changed and the release is NOT rolling-upgradable). If
   250	// the peer line is ABSENT (peer not alive / version unknown) we return
   251	// false so the driver does not proceed blind — PeerAlive already gates
   252	// the happy path, and a missing peer-version here fails closed.
   253	func parseHAProtocolCompatible(s string) bool {
   254		var local, peer int
   255		haveLocal, havePeer := false, false
   256		for _, line := range strings.Split(s, "\n") {
   257			l := strings.TrimSpace(line)
   258			ll := strings.ToLower(l)
   259			if strings.HasPrefix(ll, "peer ha protocol version:") {
   260				if n, ok := trailingInt(l); ok {
   261					peer, havePeer = n, true
   262				}
   263				continue
   264			}
   265			if strings.HasPrefix(ll, "ha protocol version:") {
   266				if n, ok := trailingInt(l); ok {
   267					local, haveLocal = n, true
   268				}
   269			}
   270		}
   271		if !haveLocal || !havePeer {
   272			return false
   273		}
   274		return local == peer
   275	}

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/heartbeat.go | sed -n '80,125p;175,240p;400,500p;650,760p'
rg -n 'MarshalHeartbeat\\(|HAProtocolVersion' pkg/cluster --glob '*.go'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
    80		// the version section, so a signed frame is wire-compatible with a legacy
    81		// or not-yet-keyed peer (dual-accept during a rolling upgrade).
    82		heartbeatAuthMagic = "XPFA"
    83	
    84		// heartbeatAuthMACSize is the HMAC-SHA256 digest length.
    85		heartbeatAuthMACSize = 32
    86	
    87		// heartbeatAuthTrailerSize = magic(4) + session(8) + counter(8) + HMAC(32).
    88		// session+counter are the anti-replay nonce: a random per-sender-process
    89		// session id plus a monotonic per-session counter.
    90		heartbeatAuthTrailerSize = 4 + 8 + 8 + heartbeatAuthMACSize
    91	)
    92	
    93	// HeartbeatPacket is the wire format for cluster heartbeats.
    94	// Layout:
    95	//
    96	//	[0:4]   Magic "BPFX"
    97	//	[4]     Version (1)
    98	//	[5]     NodeID
    99	//	[6:8]   ClusterID (little-endian uint16)
   100	//	[8]     NumGroups
   101	//	[9..]   Per-group entries (5 bytes each):
   102	//	          [0] GroupID
   103	//	          [1:3] Priority (little-endian uint16)
   104	//	          [3] Weight
   105	//	          [4] State
   106	//	After groups:
   107	//	  NumMonitors (1 byte)
   108	//	  Per-monitor:
   109	//	    [0] RGID
   110	//	    [1] Flags (bit0=up)
   111	//	    [2] Weight
   112	//	    [3] NameLen
   113	//	    [4..4+NameLen] Interface name
   114	//	After monitors:
   115	//	  Optional VersionTrailer:
   116	//	    [0] VersionLen
   117	//	    [1..1+VersionLen] SoftwareVersion bytes
   118	//	    [..] uint16 little-endian HAProtocolVersion
   119	//
   120	// The trailing version trailer is optional; packets may end after the monitor
   121	// section. When present, the trailer always starts with a length byte, even if
   122	// the software version string is empty, so newer readers can unambiguously find
   123	// the HA protocol version. Older readers ignore any bytes after the optional
   124	// software-version field, and newer readers treat a missing trailer as the
   125	// legacy protocol version.
   175	// fire, but the heartbeat sender runs every heartbeat-interval, so an
   176	// unguarded per-send log would flood journald (#4434).
   177	var oversizeHeartbeatGroupsWarn sync.Once
   178	
   179	func normalizeHAProtocolVersion(version uint16) uint16 {
   180		if version == 0 {
   181			return LegacyHAProtocolVersion
   182		}
   183		return version
   184	}
   185	
   186	// MarshalHeartbeat encodes a heartbeat packet to wire format.
   187	// The output is capped at maxHeartbeatSize. RG group entries are always
   188	// included (they are critical for election). When SoftwareVersion is present,
   189	// space for it is reserved first so monitor truncation never drops version
   190	// metadata. If monitors would cause the packet to exceed the limit, the monitor
   191	// section is truncated and the version field is preserved.
   192	func MarshalHeartbeat(pkt *HeartbeatPacket) []byte {
   193		return marshalHeartbeatBody(pkt, 0)
   194	}
   195	
   196	// marshalHeartbeatBody encodes the heartbeat wire body, keeping tailReserve
   197	// bytes free at the tail of the frame for a trailer the caller appends (the
   198	// #4107 auth trailer). tailReserve==0 is the plain legacy encoding, byte-for-
   199	// byte what MarshalHeartbeat always produced. The election-critical header +
   200	// RG groups are always written and the SOFTWARE version is reserved next; only
   201	// the best-effort monitor section is truncated to fit within
   202	// maxHeartbeatSize-tailReserve. Because the reserve is honored WHILE building
   203	// the body, a keyed frame ALWAYS has room for its HMAC — a heartbeat is never
   204	// silently downgraded to unsigned (the #4107 invariant; see
   205	// MarshalHeartbeatAuth).
   206	func marshalHeartbeatBody(pkt *HeartbeatPacket, tailReserve int) []byte {
   207		buf := make([]byte, maxHeartbeatSize)
   208		copy(buf[0:4], heartbeatMagic)
   209		buf[4] = heartbeatVersion
   210		buf[5] = pkt.NodeID
   211		binary.LittleEndian.PutUint16(buf[6:8], pkt.ClusterID)
   212		// #4434: bound the group section to the heartbeat wire limit. The count
   213		// byte and each per-group id byte are uint8 and the frame is a fixed
   214		// buffer, so an over-size redundancy-group set would overflow the count
   215		// (256 -> 0, desyncing it from the records actually written) or index
   216		// past the buffer and panic. The commit gate rejects such a config; this
   217		// defensive cap keeps a leniently-loaded / peer-synced config panic-safe
   218		// and the count byte consistent with the body.
   219		groups := pkt.Groups
   220		if len(groups) > maxHeartbeatGroups {
   221			oversizeHeartbeatGroupsWarn.Do(func() {
   222				slog.Warn("cluster: redundancy-group count exceeds heartbeat wire "+
   223					"limit; advertising only the first groups",
   224					"groups", len(pkt.Groups), "wire_limit", maxHeartbeatGroups)
   225			})
   226			groups = groups[:maxHeartbeatGroups]
   227		}
   228		buf[8] = uint8(len(groups))
   229	
   230		off := heartbeatHeaderSize
   231		for _, g := range groups {
   232			buf[off] = g.GroupID
   233			binary.LittleEndian.PutUint16(buf[off+1:off+3], g.Priority)
   234			buf[off+3] = g.Weight
   235			buf[off+4] = g.State
   236			off += heartbeatGroupSize
   237		}
   238	
   239		var version []byte
   240		const heartbeatVersionTrailerSize = 1 + 2 // version length byte + HA protocol version
   400	// is a per-session monotonic send counter; together they are the anti-replay
   401	// nonce (a new session re-anchors the receiver after a restart/reboot; a
   402	// strictly increasing counter rejects intra-session replays). When authKey is
   403	// empty the output is byte-identical to MarshalHeartbeat — a node without a key
   404	// emits legacy frames (dual-accept). The key is never logged.
   405	//
   406	// INVARIANT: once a key is configured, the returned frame is ALWAYS signed. The
   407	// trailer space is reserved WHILE building the body (marshalHeartbeatBody drops
   408	// best-effort monitor entries to make room), so a heartbeat is never silently
   409	// downgraded to unsigned — a silent downgrade would make an ENFORCING peer
   410	// reject every frame and split the cluster (dual-primary). At realistic RG +
   411	// monitor counts the reserve never even bites; the belt-and-suspenders guard
   412	// below is unreachable and fails LOUD rather than emitting cleartext.
   413	func MarshalHeartbeatAuth(pkt *HeartbeatPacket, authKey []byte, session, counter uint64) []byte {
   414		if len(authKey) == 0 {
   415			return marshalHeartbeatBody(pkt, 0)
   416		}
   417		// Reserve the trailer up front so the signed frame is guaranteed to fit.
   418		body := marshalHeartbeatBody(pkt, heartbeatAuthTrailerSize)
   419		if len(body)+heartbeatAuthTrailerSize > maxHeartbeatSize {
   420			// Unreachable: the RG group count is uint8-bounded and monitors were
   421			// already truncated to leave the reserve. Guard so a future change can
   422			// never SILENTLY downgrade a keyed heartbeat to unsigned (which an
   423			// enforcing peer rejects → split-brain). Fail loud and still sign
   424			// rather than emit an unsigned frame.
   425			slog.Error("cluster: keyed heartbeat exceeds frame cap after monitor truncation; signing anyway to preserve the auth invariant",
   426				"body_bytes", len(body), "cap", maxHeartbeatSize)
   427		}
   428		trailer := make([]byte, heartbeatAuthTrailerSize)
   429		copy(trailer[0:4], heartbeatAuthMagic)
   430		binary.LittleEndian.PutUint64(trailer[4:12], session)
   431		binary.LittleEndian.PutUint64(trailer[12:20], counter)
   432		// Sign the body PLUS magic+session+counter (everything but the digest), so
   433		// the nonce and the whole packet are bound by the MAC.
   434		mac := hmac.New(sha256.New, authKey)
   435		mac.Write(body)
   436		mac.Write(trailer[:20])
   437		copy(trailer[20:], mac.Sum(nil))
   438	
   439		out := make([]byte, 0, len(body)+heartbeatAuthTrailerSize)
   440		out = append(out, body...)
   441		out = append(out, trailer...)
   442		return out
   443	}
   444	
   445	// heartbeatAuthTrailer locates the auth trailer at the tail of a raw heartbeat
   446	// frame and returns its nonce. present is false when the frame carries no
   447	// trailer (a legacy / not-yet-keyed peer).
   448	func heartbeatAuthTrailer(data []byte) (session, counter uint64, present bool) {
   449		if len(data) < heartbeatAuthTrailerSize {
   450			return 0, 0, false
   451		}
   452		start := len(data) - heartbeatAuthTrailerSize
   453		if !bytes.Equal(data[start:start+4], []byte(heartbeatAuthMagic)) {
   454			return 0, 0, false
   455		}
   456		session = binary.LittleEndian.Uint64(data[start+4 : start+12])
   457		counter = binary.LittleEndian.Uint64(data[start+12 : start+20])
   458		return session, counter, true
   459	}
   460	
   461	// verifyHeartbeatMAC recomputes the HMAC over the signed span (everything but
   462	// the trailing 32-byte digest) and compares it in constant time. It presumes a
   463	// trailer is present (heartbeatAuthTrailer returned present) and authKey is
   464	// non-empty; it returns false otherwise.
   465	func verifyHeartbeatMAC(data, authKey []byte) bool {
   466		if len(authKey) == 0 || len(data) < heartbeatAuthTrailerSize {
   467			return false
   468		}
   469		signed := data[:len(data)-heartbeatAuthMACSize]
   470		got := data[len(data)-heartbeatAuthMACSize:]
   471		mac := hmac.New(sha256.New, authKey)
   472		mac.Write(signed)
   473		return hmac.Equal(got, mac.Sum(nil))
   474	}
   475	
   476	// heartbeatReplaySessions bounds how many distinct sender sessions the
   477	// anti-replay tracker remembers a counter watermark for. Each genuine peer
   478	// reboot picks a fresh random session (randomSessionID) and consumes one slot;
   479	// the oldest watermark is evicted FIFO once the ring is full.
   480	//
   481	// #5477 security bound — and its honest limit. The retired-session watermarks
   482	// must be bounded (a peer that reboots forever cannot grow the ring without
   483	// limit). This map RAISES the on-link REPLAY attacker's cost — from the
   484	// pre-#5477 single-watermark A->B->A loop (only 2 recorded incarnations) to
   485	// heartbeatReplaySessions+1 distinct recorded incarnations — but it is NOT an
   486	// absolute bar:
   487	//
   488	//   - HMAC-SHA256 over the nonce blocks fabricating a valid frame for any NEW
   489	//     session id, and blocks fabricating a counter beyond the highest the
   490	//     genuine peer ever signed for a session. So the attacker can only REPLAY
   491	//     the session incarnations they captured off the wire.
   492	//   - With FEWER than heartbeatReplaySessions+1 recorded incarnations, every
   493	//     replay of a retired session is at/below its remembered watermark and is
   494	//     rejected — the sustained A->B->A loop #5477 targets is fully closed.
   495	//   - With heartbeatReplaySessions+1 OR MORE recorded incarnations the bound is
   496	//     defeatable by REPLAY ALONE (no reboot, no minting): a replayed frame
   497	//     whose session is not currently in the ring is "never-seen" from the
   498	//     ring's view, so admit() re-records it and evicts the oldest FIFO entry.
   499	//     FIFO always leaves exactly one just-evicted session to replay back in as
   500	//     never-seen, so an attacker holding >= heartbeatReplaySessions+1
   650	// notePeerAuthenticated records that the peer proved it holds the PSK. From
   651	// then on an unauthenticated frame from it is a downgrade attack.
   652	func (s *heartbeatAuthState) notePeerAuthenticated() {
   653		s.peerAuthSeen.Store(true)
   654	}
   655	
   656	// heartbeatAuthState returns the Manager's process-lifetime control-channel
   657	// auth state — the state a new heartbeatReceiver binds to so a restart does
   658	// not reset anti-replay (#5086). A nil Manager (unit tests constructing a
   659	// standalone receiver) gets a fresh private state rather than a nil deref, so
   660	// a test receiver behaves exactly like a never-restarted production one.
   661	func (m *Manager) heartbeatAuthState() *heartbeatAuthState {
   662		if m == nil {
   663			return &heartbeatAuthState{}
   664		}
   665		return &m.hbAuth
   666	}
   667	
   668	// heartbeatAuthDecision applies the #4107 dual-accept policy for one received
   669	// heartbeat and returns whether to accept it (and, when rejected, a short
   670	// reason for logging — never the key or packet bytes).
   671	//
   672	//	keyConfigured — the local ControlLinkAuthKey is set (we can verify).
   673	//	present       — the frame carried an auth trailer.
   674	//	macOK         — the trailer's HMAC verified (only meaningful when present).
   675	//	nonceFresh    — the nonce passed anti-replay (only meaningful when macOK).
   676	//	peerAuthSeen  — we have previously accepted an authenticated heartbeat from
   677	//	                the peer (sticky: proves the peer holds the key, so both
   678	//	                nodes are keyed and an unauthenticated frame is now forged).
   679	//
   680	// Policy:
   681	//   - No local key: dual-accept everything — this node cannot verify and may be
   682	//     the not-yet-upgraded / not-yet-keyed side of a rolling upgrade.
   683	//   - Local key + auth trailer: enforce — reject a bad HMAC or a replayed nonce.
   684	//   - Local key + no trailer + peer never authenticated: dual-accept — the peer
   685	//     has not started signing yet (rolling upgrade / key not yet synced).
   686	//   - Local key + no trailer + peer HAS authenticated: reject — a downgrade to
   687	//     cleartext once both nodes are keyed is an attack.
   688	func heartbeatAuthDecision(keyConfigured, present, macOK, nonceFresh, peerAuthSeen bool) (bool, string) {
   689		if !keyConfigured {
   690			return true, ""
   691		}
   692		if present {
   693			if !macOK {
   694				return false, "hmac verification failed"
   695			}
   696			if !nonceFresh {
   697				return false, "stale nonce (replay)"
   698			}
   699			return true, ""
   700		}
   701		if peerAuthSeen {
   702			return false, "missing auth trailer (enforced: peer previously authenticated)"
   703		}
   704		return true, ""
   705	}
   706	
   707	// randomSessionID returns a random 64-bit anti-replay session id. On the
   708	// (practically impossible) crypto/rand failure it falls back to the monotonic
   709	// clock, which is still process-unique for the receiver's re-anchor logic.
   710	func randomSessionID() uint64 {
   711		var b [8]byte
   712		if _, err := rand.Read(b[:]); err != nil {
   713			return uint64(MonotonicNanos())
   714		}
   715		return binary.LittleEndian.Uint64(b[:])
   716	}
   717	
   718	// PeerGroupState holds the last-known state of a peer's redundancy group.
   719	type PeerGroupState struct {
   720		GroupID  int
   721		Priority int
   722		Weight   int
   723		State    NodeState
   724	}
   725	
   726	// heartbeatSender sends periodic heartbeat packets.
   727	type heartbeatSender struct {
   728		mgr        *Manager
   729		conn       *net.UDPConn
   730		peerAddr   *net.UDPAddr
   731		interval   time.Duration
   732		stopCh     chan struct{}
   733		wg         sync.WaitGroup
   734		sent       atomic.Uint64
   735		sendErrors atomic.Uint64
   736	
   737		// #4107 anti-replay: a random per-SENDER session id plus a monotonic
   738		// per-session counter. A new sender (StartHeartbeat/RestartHeartbeat)
   739		// re-seeds authSession so the receiver re-anchors after a restart/reboot.
   740		// Per-sender, NOT per-process: a heartbeat restart mints a fresh session
   741		// without a daemon boot, which is what makes heartbeatReplaySessions a
   742		// bound on peer SESSIONS rather than on peer daemon incarnations.
   743		authSession uint64
   744		authCounter atomic.Uint64
   745	}
   746	
   747	// heartbeatReceiver listens for peer heartbeat packets.
   748	type heartbeatReceiver struct {
   749		mgr        *Manager
   750		conn       *net.UDPConn
   751		threshold  int
   752		interval   time.Duration
   753		stopCh     chan struct{}
   754		wg         sync.WaitGroup
   755		lastSeen   atomic.Int64 // CLOCK_MONOTONIC nanos of last heartbeat (MonotonicNanos)
   756		received   atomic.Uint64
   757		recvErrors atomic.Uint64
   758		startedAt  time.Time // when receiver started (for initial peer-lost detection)
   759	
   760		// auth is the #4107 control-channel auth state (anti-replay watermarks +
pkg/cluster/cluster_test.go:1466:func TestHAProtocolVersionMismatchIgnoresUnknownPeerAfterTimeout(t *testing.T) {
pkg/cluster/cluster_test.go:1468:	m.SetHAProtocolVersion(2)
pkg/cluster/cluster_test.go:1476:		HAProtocolVersion: 2,
pkg/cluster/cluster_test.go:1483:	mismatch, local, peer := m.HAProtocolVersionMismatch()
pkg/cluster/heartbeat.go:27:	// LegacyHAProtocolVersion is the compatibility version implicitly used by
pkg/cluster/heartbeat.go:29:	LegacyHAProtocolVersion uint16 = 1
pkg/cluster/heartbeat.go:31:	// CurrentHAProtocolVersion is the HA/session-transfer compatibility version
pkg/cluster/heartbeat.go:35:	CurrentHAProtocolVersion = LegacyHAProtocolVersion
pkg/cluster/heartbeat.go:37:	// MinCompatHAProtocolVersion is the OLDEST HA protocol version
pkg/cluster/heartbeat.go:38:	// CurrentHAProtocolVersion can still interoperate with — the back-compat
pkg/cluster/heartbeat.go:40:	// LegacyHAProtocolVersion: legacy is a fixed historical constant (1), whereas
pkg/cluster/heartbeat.go:42:	// author MUST re-evaluate on every CurrentHAProtocolVersion bump. They are
pkg/cluster/heartbeat.go:46:	MinCompatHAProtocolVersion = CurrentHAProtocolVersion
pkg/cluster/heartbeat.go:118://	    [..] uint16 little-endian HAProtocolVersion
pkg/cluster/heartbeat.go:132:	HAProtocolVersion uint16
pkg/cluster/heartbeat.go:179:func normalizeHAProtocolVersion(version uint16) uint16 {
pkg/cluster/heartbeat.go:181:		return LegacyHAProtocolVersion
pkg/cluster/heartbeat.go:192:func MarshalHeartbeat(pkt *HeartbeatPacket) []byte {
pkg/cluster/heartbeat.go:286:		binary.LittleEndian.PutUint16(buf[off:off+2], normalizeHAProtocolVersion(pkt.HAProtocolVersion))
pkg/cluster/heartbeat.go:307:		HAProtocolVersion: LegacyHAProtocolVersion,
pkg/cluster/heartbeat.go:374:		pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
pkg/cluster/heartbeat.go:818:		data = MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:13:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_test.go:20:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:50:	if got.HAProtocolVersion != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:51:		t.Errorf("ha protocol version = %d, want %d", got.HAProtocolVersion, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:60:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:68:	if got.HAProtocolVersion != LegacyHAProtocolVersion {
pkg/cluster/heartbeat_test.go:69:		t.Errorf("ha protocol version = %d, want legacy %d", got.HAProtocolVersion, LegacyHAProtocolVersion)
pkg/cluster/heartbeat_test.go:108:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:125:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:147:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_test.go:167:	if mismatch, local, peer := m.HAProtocolVersionMismatch(); mismatch || local != CurrentHAProtocolVersion || peer != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:168:		t.Fatalf("ha protocol mismatch = %v local=%d peer=%d, want false/%d/%d", mismatch, local, peer, CurrentHAProtocolVersion, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:220:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:260:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:285:	if got2.HAProtocolVersion != LegacyHAProtocolVersion {
pkg/cluster/heartbeat_test.go:286:		t.Errorf("ha protocol version from old format = %d, want %d", got2.HAProtocolVersion, LegacyHAProtocolVersion)
pkg/cluster/heartbeat_test.go:303:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:339:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:373:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:384:	if got.HAProtocolVersion != LegacyHAProtocolVersion {
pkg/cluster/heartbeat_test.go:385:		t.Fatalf("ha protocol version = %d, want %d", got.HAProtocolVersion, LegacyHAProtocolVersion)
pkg/cluster/heartbeat_test.go:423:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:487:	if pkt.HAProtocolVersion != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:488:		t.Errorf("HAProtocolVersion = %d, want %d", pkt.HAProtocolVersion, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:509:	mismatch, local, peer := m.HAProtocolVersionMismatch()
pkg/cluster/heartbeat_test.go:510:	if local != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:511:		t.Fatalf("local ha protocol version = %d, want %d", local, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:513:	if peer != LegacyHAProtocolVersion {
pkg/cluster/heartbeat_test.go:514:		t.Fatalf("peer ha protocol version = %d, want %d", peer, LegacyHAProtocolVersion)
pkg/cluster/heartbeat_test.go:516:	wantMismatch := CurrentHAProtocolVersion != LegacyHAProtocolVersion
pkg/cluster/heartbeat_test.go:526:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_test.go:531:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_test.go:541:	if got.HAProtocolVersion != LegacyHAProtocolVersion {
pkg/cluster/heartbeat_test.go:542:		t.Fatalf("ha protocol version = %d, want legacy default %d", got.HAProtocolVersion, LegacyHAProtocolVersion)
pkg/cluster/ifmon_weight_divergence_6549_test.go:42:	wire := MarshalHeartbeat(m.buildHeartbeat())
pkg/cluster/ifmon_weight_divergence_6549_test.go:285:		pkt, err := UnmarshalHeartbeat(MarshalHeartbeat(m.buildHeartbeat()))
pkg/cluster/status.go:18:	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
pkg/cluster/status.go:19:	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
pkg/cluster/status.go:117:	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
pkg/cluster/status.go:118:	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
pkg/cluster/heartbeat_manager.go:270:		HAProtocolVersion: m.localHAProtocolVersion,
pkg/cluster/heartbeat_manager.go:325:	m.peerHAProtocolVersion = normalizeHAProtocolVersion(pkt.HAProtocolVersion)
pkg/cluster/heartbeat_manager.go:429:	m.peerHAProtocolVersion = 0
pkg/cluster/manager.go:140:	localHAProtocolVersion uint16
pkg/cluster/manager.go:141:	peerHAProtocolVersion  uint16
pkg/cluster/manager.go:399:		localHAProtocolVersion:         CurrentHAProtocolVersion,
pkg/cluster/heartbeat_rg_cap_4434_test.go:29:	data := MarshalHeartbeat(pkt) // must not panic
pkg/cluster/heartbeat_rg_cap_4434_test.go:50:	data := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_rg_cap_4434_test.go:69:	data := MarshalHeartbeat(pkt)
pkg/cluster/ifmon_weight_daemon_apply_6549_test.go:501:			pkt, err := UnmarshalHeartbeat(MarshalHeartbeat(m.buildHeartbeat()))
pkg/cluster/heartbeat_auth_test.go:15:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_auth_test.go:62:	legacy := MarshalHeartbeat(pkt)
pkg/cluster/heartbeat_auth_test.go:86:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/sync.go:29:// sync schema version explicit for the gate. It tracks CurrentHAProtocolVersion
pkg/cluster/sync.go:30:// (NOT LegacyHAProtocolVersion): the sync wire schema and the HA protocol have
pkg/cluster/sync.go:31:// evolved together, so a CurrentHAProtocolVersion bump that changes the
pkg/cluster/sync.go:36:const SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)
pkg/cluster/sync.go:68:	// CurrentHAProtocolVersion / SessionSyncWireVersion bump — the change is
pkg/cluster/peer_state.go:88:// SetHAProtocolVersion records the local HA compatibility version advertised to
pkg/cluster/peer_state.go:90:func (m *Manager) SetHAProtocolVersion(version uint16) {
pkg/cluster/peer_state.go:93:	m.localHAProtocolVersion = normalizeHAProtocolVersion(version)
pkg/cluster/peer_state.go:96:// HAProtocolVersions returns the currently known local and peer HA protocol versions.
pkg/cluster/peer_state.go:97:func (m *Manager) HAProtocolVersions() (local, peer uint16) {
pkg/cluster/peer_state.go:100:	return m.localHAProtocolVersion, m.peerHAProtocolVersion
pkg/cluster/peer_state.go:103:// HAProtocolVersionMismatch reports whether both sides advertised incompatible
pkg/cluster/peer_state.go:107:func (m *Manager) HAProtocolVersionMismatch() (bool, uint16, uint16) {
pkg/cluster/peer_state.go:110:	local := normalizeHAProtocolVersion(m.localHAProtocolVersion)
pkg/cluster/peer_state.go:111:	if !m.peerAlive || m.peerHAProtocolVersion == 0 {
pkg/cluster/peer_state.go:114:	peer := normalizeHAProtocolVersion(m.peerHAProtocolVersion)

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/heartbeat.go | sed -n '1,28p;124,175p;790,830p'
nl -ba pkg/cluster/heartbeat_manager.go | sed -n '245,335p;400,445p'
nl -ba pkg/cluster/peer_state.go | sed -n '80,125p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
     1	package cluster
     2	
     3	import (
     4		"bytes"
     5		"crypto/hmac"
     6		"crypto/rand"
     7		"crypto/sha256"
     8		"encoding/binary"
     9		"fmt"
    10		"log/slog"
    11		"net"
    12		"sync"
    13		"sync/atomic"
    14		"time"
    15	)
    16	
    17	const (
    18		// HeartbeatPort is the UDP port used for cluster heartbeat.
    19		HeartbeatPort = 4784
    20	
    21		// heartbeatMagic identifies xpf cluster heartbeat packets.
    22		heartbeatMagic = "BPFX"
    23	
    24		// heartbeatVersion is the current protocol version.
    25		heartbeatVersion = 1
    26	
    27		// LegacyHAProtocolVersion is the compatibility version implicitly used by
    28		// older heartbeats that predate explicit HA protocol advertisement.
   124	// software-version field, and newer readers treat a missing trailer as the
   125	// legacy protocol version.
   126	type HeartbeatPacket struct {
   127		NodeID            uint8
   128		ClusterID         uint16
   129		Groups            []HeartbeatGroup
   130		Monitors          []HeartbeatMonitor
   131		SoftwareVersion   string
   132		HAProtocolVersion uint16
   133	}
   134	
   135	// HeartbeatGroup is a per-RG entry in the heartbeat.
   136	type HeartbeatGroup struct {
   137		GroupID  uint8
   138		Priority uint16
   139		Weight   uint8
   140		State    uint8
   141	}
   142	
   143	// HeartbeatMonitor is a per-interface monitor entry in the heartbeat.
   144	type HeartbeatMonitor struct {
   145		RGID      uint8
   146		Weight    uint8
   147		Up        bool
   148		Interface string
   149	}
   150	
   151	// heartbeatHeaderSize is Magic(4) + Version(1) + NodeID(1) + ClusterID(2) + NumGroups(1).
   152	const heartbeatHeaderSize = 9
   153	
   154	// heartbeatGroupSize is GroupID(1) + Priority(2) + Weight(1) + State(1).
   155	const heartbeatGroupSize = 5
   156	
   157	// maxHeartbeatGroups is the largest number of redundancy-group entries the
   158	// heartbeat wire format can carry. The group-count field (buf[8]) and every
   159	// per-group id byte are uint8, so a 256th group would overflow the count to 0
   160	// and desync it from the records still written; and the frame is a fixed
   161	// maxHeartbeatSize buffer written as 9 + N*5 bytes, so ~293 groups index past
   162	// it and panic. 255 is the binding uint8 count limit and also fits the buffer
   163	// (9 + 255*5 = 1284 <= maxHeartbeatSize). The commit-time gate
   164	// config.validateChassisClusterStrict rejects any config above this; the
   165	// marshaler caps here as a defensive backstop so it stays panic-safe and the
   166	// count byte always matches the body even on a leniently-loaded / peer-synced
   167	// config (#4434).
   168	const maxHeartbeatGroups = 255
   169	
   170	const maxHeartbeatSoftwareVersionSize = 255
   171	
   172	// oversizeHeartbeatGroupsWarn logs the defensive group-count truncation in
   173	// marshalHeartbeatBody at most once per process. Once
   174	// config.validateChassisClusterStrict gates commits this path should never
   175	// fire, but the heartbeat sender runs every heartbeat-interval, so an
   790		s.wg.Add(1)
   791		go s.run()
   792	}
   793	
   794	func (s *heartbeatSender) run() {
   795		defer s.wg.Done()
   796		ticker := time.NewTicker(s.interval)
   797		defer ticker.Stop()
   798	
   799		for {
   800			select {
   801			case <-s.stopCh:
   802				return
   803			case <-ticker.C:
   804				s.send()
   805			}
   806		}
   807	}
   808	
   809	func (s *heartbeatSender) send() {
   810		pkt := s.mgr.buildHeartbeat()
   811		// #4107: sign the frame when a control-channel PSK is configured. The key
   812		// is fetched fresh each tick so a commit that sets/clears it takes effect
   813		// without a heartbeat restart. Never logged.
   814		var data []byte
   815		if key := s.mgr.controlLinkAuthKey(); len(key) > 0 {
   816			data = MarshalHeartbeatAuth(pkt, key, s.authSession, s.authCounter.Add(1))
   817		} else {
   818			data = MarshalHeartbeat(pkt)
   819		}
   820		if _, err := s.conn.WriteToUDP(data, s.peerAddr); err != nil {
   821			s.sendErrors.Add(1)
   822			slog.Debug("cluster: heartbeat send failed", "err", err)
   823		} else {
   824			s.sent.Add(1)
   825		}
   826	}
   827	
   828	func (s *heartbeatSender) stop() {
   829		close(s.stopCh)
   830		s.wg.Wait()
   245			return true
   246		}
   247		slog.Error("cluster: heartbeat restart failed after retries")
   248		return false
   249	}
   250	
   251	// buildHeartbeat creates a heartbeat packet from current state.
   252	func (m *Manager) buildHeartbeat() *HeartbeatPacket {
   253		m.mu.RLock()
   254		mon := m.monitor
   255		m.mu.RUnlock()
   256	
   257		// Collect local interface statuses outside the lock (monitor has its own).
   258		var localStatuses []InterfaceMonitorInfo
   259		if mon != nil {
   260			localStatuses = mon.LocalInterfaceStatuses()
   261		}
   262	
   263		m.mu.RLock()
   264		defer m.mu.RUnlock()
   265	
   266		pkt := &HeartbeatPacket{
   267			NodeID:            uint8(m.nodeID),
   268			ClusterID:         uint16(m.clusterID),
   269			SoftwareVersion:   m.localSoftwareVersion,
   270			HAProtocolVersion: m.localHAProtocolVersion,
   271		}
   272		for _, rg := range m.groups {
   273			pkt.Groups = append(pkt.Groups, HeartbeatGroup{
   274				GroupID:  uint8(rg.GroupID),
   275				Priority: uint16(rg.LocalPriority),
   276				Weight:   clampWireWeight(rg.Weight),
   277				State:    uint8(rg.State),
   278			})
   279		}
   280	
   281		// Include local interface monitor statuses.
   282		for _, ls := range localStatuses {
   283			pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
   284				RGID:      uint8(ls.RedundancyGroup),
   285				Weight:    clampWireWeight(ls.Weight),
   286				Up:        ls.Up,
   287				Interface: ls.Interface,
   288			})
   289		}
   290		return pkt
   291	}
   292	
   293	// clampWireWeight narrows a weight onto the single-byte heartbeat weight field
   294	// by SATURATING instead of truncating (#6549).
   295	//
   296	// This is the last belt, not the fix. `uint8(w)` wraps — 355 leaves as 99 —
   297	// which is what let a node's local weight and its advertised weight disagree
   298	// and put two primaries on the LAN. The fix is that the weight domain is closed
   299	// upstream (rgWeightFromDebt for rg.Weight, config.ClampInterfaceMonitorWeight
   300	// for the per-monitor weight), so every value that reaches here is already in
   301	// [0,255] and this is an identity. Saturating rather than wrapping means a
   302	// future writer that bypasses those helpers degrades to a bounded, monotonic
   303	// weight instead of silently aliasing to an unrelated one.
   304	func clampWireWeight(w int) uint8 {
   305		if w < 0 {
   306			return 0
   307		}
   308		if w > maxRedundancyGroupWeight {
   309			return maxRedundancyGroupWeight
   310		}
   311		return uint8(w)
   312	}
   313	
   314	// handlePeerHeartbeat processes an incoming peer heartbeat.
   315	func (m *Manager) handlePeerHeartbeat(pkt *HeartbeatPacket) {
   316		m.mu.Lock()
   317		defer m.mu.Unlock()
   318		now := time.Now()
   319	
   320		wasAlive := m.peerAlive
   321		m.peerAlive = true
   322		m.peerEverSeen = true
   323		m.peerNodeID = int(pkt.NodeID)
   324		m.peerSoftwareVersion = pkt.SoftwareVersion
   325		m.peerHAProtocolVersion = normalizeHAProtocolVersion(pkt.HAProtocolVersion)
   326	
   327		// Rebuild peer group states from scratch — prunes stale RGs that
   328		// the peer no longer reports (fix #92).
   329		newPeerGroups := make(map[int]PeerGroupState, len(pkt.Groups))
   330		for _, g := range pkt.Groups {
   331			newPeerGroups[int(g.GroupID)] = PeerGroupState{
   332				GroupID:  int(g.GroupID),
   333				Priority: int(g.Priority),
   334				Weight:   int(g.Weight),
   335				State:    NodeState(g.State),
   400	
   401		m.mu.Lock()
   402		defer m.mu.Unlock()
   403		if !m.peerAlive {
   404			return // already marked lost while guard ran
   405		}
   406		// Re-check heartbeat STALENESS, not just peerAlive. m.mu is released
   407		// across the guard call above, so the receiver read path can run
   408		// handlePeerHeartbeat — setting peerAlive and advancing lastSeen — for
   409		// ANY guard duration, not only a slow guard fn (a configured slow guard
   410		// merely widens the window). peerAlive is essentially always true here
   411		// (it was true on entry and a fresh heartbeat only keeps it true), so
   412		// checking it cannot detect that a heartbeat landed during the window —
   413		// re-reading lastSeen against the live clock can. If the heartbeat is
   414		// fresh again, the peer is not lost: abort to avoid a spurious peer-loss
   415		// and the unnecessary failover churn that follows (#2080).
   416		if m.peerHeartbeatFreshLocked() {
   417			slog.Debug("cluster: aborting peer heartbeat timeout, fresh heartbeat arrived during guard window")
   418			return
   419		}
   420		if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
   421			slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
   422			return
   423		}
   424	
   425		m.peerAlive = false
   426		m.peerGroups = make(map[int]PeerGroupState)
   427		m.peerMonitors = nil
   428		m.peerSoftwareVersion = ""
   429		m.peerHAProtocolVersion = 0
   430		slog.Warn("cluster: peer heartbeat timeout, marking peer lost")
   431		m.history.Record(EventHeartbeat, -1, "Peer heartbeat timeout")
   432	
   433		// Clear ManualFailover on all RGs: the peer is dead, so the surviving
   434		// node MUST be able to take over. Without this, a previous manual
   435		// transfer-out would keep the local node parked in secondary-hold even
   436		// though there is no longer a peer to hand ownership to.
   437		for _, rg := range m.groups {
   438			if rg.ManualFailover {
   439				slog.Info("cluster: clearing manual failover (peer lost)", "rg", rg.GroupID)
   440				rg.ManualFailover = false
   441				rg.ManualFailoverAt = time.Time{}
   442				m.recalcWeight(rg)
   443			}
   444		}
   445	
    80	
    81	// SoftwareVersions returns the currently known local and peer software versions.
    82	func (m *Manager) SoftwareVersions() (local, peer string) {
    83		m.mu.RLock()
    84		defer m.mu.RUnlock()
    85		return m.localSoftwareVersion, m.peerSoftwareVersion
    86	}
    87	
    88	// SetHAProtocolVersion records the local HA compatibility version advertised to
    89	// the peer. Zero falls back to the legacy compatibility version.
    90	func (m *Manager) SetHAProtocolVersion(version uint16) {
    91		m.mu.Lock()
    92		defer m.mu.Unlock()
    93		m.localHAProtocolVersion = normalizeHAProtocolVersion(version)
    94	}
    95	
    96	// HAProtocolVersions returns the currently known local and peer HA protocol versions.
    97	func (m *Manager) HAProtocolVersions() (local, peer uint16) {
    98		m.mu.RLock()
    99		defer m.mu.RUnlock()
   100		return m.localHAProtocolVersion, m.peerHAProtocolVersion
   101	}
   102	
   103	// HAProtocolVersionMismatch reports whether both sides advertised incompatible
   104	// HA/session-transfer versions. When the peer is absent or has not yet
   105	// advertised a version, mismatch stays false so disconnect/readiness logic can
   106	// report the more accurate transport-state reason.
   107	func (m *Manager) HAProtocolVersionMismatch() (bool, uint16, uint16) {
   108		m.mu.RLock()
   109		defer m.mu.RUnlock()
   110		local := normalizeHAProtocolVersion(m.localHAProtocolVersion)
   111		if !m.peerAlive || m.peerHAProtocolVersion == 0 {
   112			return false, local, 0
   113		}
   114		peer := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
   115		return local != peer, local, peer
   116	}
   117	
   118	// PeerMonitorStatuses returns the peer's interface monitor states from heartbeat.
   119	// Returns nil if peer is not alive or no monitor data received.
   120	func (m *Manager) PeerMonitorStatuses() []InterfaceMonitorInfo {
   121		m.mu.RLock()
   122		defer m.mu.RUnlock()
   123		if len(m.peerMonitors) == 0 {
   124			return nil
   125		}

[35m[3mcodex[0m[0m
Initial evidence supports C1 and C2, with one wording caveat: new encoders reserve space for the trailer on every emitted heartbeat, while legacy packets may omit it and decode as protocol 1. I’m now tracing the lifetime and ownership of the peer-version state because that is where the plan’s safety argument can fail even if the wire facts are correct.
[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n --hidden --glob '"'!docs/research/2387-session-identity/plan.md'"' --glob '"'!.git/**'"' '\\bMinCompatHAProtocolVersion\\b' .
rg -n --hidden --glob '"'!.git/**'"' '\\bCurrentHAProtocolVersion\\b' pkg cmd userspace-dp config 2>/dev/null | head -200"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
./cmd/xpfd/main.go:195:		fmt.Printf("ha-protocol-min-compat=%d\n", cluster.MinCompatHAProtocolVersion)
./pkg/cluster/heartbeat.go:37:	// MinCompatHAProtocolVersion is the OLDEST HA protocol version
./pkg/cluster/heartbeat.go:46:	MinCompatHAProtocolVersion = CurrentHAProtocolVersion
./_Log.md:31312:  added cluster.MinCompatHAProtocolVersion (a deliberate floor, re-eval per
./docs/pr/1930-inc3-image-replace/claude-smr-review.md:12:- `pkg/cluster/heartbeat.go` — `MinCompatHAProtocolVersion`
cmd/xpfd/main.go:194:		fmt.Printf("ha-protocol-version=%d\n", cluster.CurrentHAProtocolVersion)
pkg/upgrade/cluster_cli.go:248:// hand off RGs when CurrentHAProtocolVersion matches; a bump means the
userspace-dp/tests/vrf_session_identity_doc_guard.rs:26://!     `CurrentHAProtocolVersion` bump (plan §0a, correcting plan §4d).
userspace-dp/tests/vrf_session_identity_doc_guard.rs:89:        "`CurrentHAProtocolVersion` never moves.",
userspace-dp/src/afxdp/forwarding/README.md:363:  mixed-version window and `CurrentHAProtocolVersion` never moves.
pkg/cluster/sync.go:29:// sync schema version explicit for the gate. It tracks CurrentHAProtocolVersion
pkg/cluster/sync.go:31:// evolved together, so a CurrentHAProtocolVersion bump that changes the
pkg/cluster/sync.go:36:const SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)
pkg/cluster/sync.go:68:	// CurrentHAProtocolVersion / SessionSyncWireVersion bump — the change is
pkg/cluster/heartbeat.go:31:	// CurrentHAProtocolVersion is the HA/session-transfer compatibility version
pkg/cluster/heartbeat.go:35:	CurrentHAProtocolVersion = LegacyHAProtocolVersion
pkg/cluster/heartbeat.go:38:	// CurrentHAProtocolVersion can still interoperate with — the back-compat
pkg/cluster/heartbeat.go:42:	// author MUST re-evaluate on every CurrentHAProtocolVersion bump. They are
pkg/cluster/heartbeat.go:46:	MinCompatHAProtocolVersion = CurrentHAProtocolVersion
pkg/cluster/heartbeat_test.go:13:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_test.go:50:	if got.HAProtocolVersion != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:51:		t.Errorf("ha protocol version = %d, want %d", got.HAProtocolVersion, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:147:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_test.go:167:	if mismatch, local, peer := m.HAProtocolVersionMismatch(); mismatch || local != CurrentHAProtocolVersion || peer != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:168:		t.Fatalf("ha protocol mismatch = %v local=%d peer=%d, want false/%d/%d", mismatch, local, peer, CurrentHAProtocolVersion, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:487:	if pkt.HAProtocolVersion != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:488:		t.Errorf("HAProtocolVersion = %d, want %d", pkt.HAProtocolVersion, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:510:	if local != CurrentHAProtocolVersion {
pkg/cluster/heartbeat_test.go:511:		t.Fatalf("local ha protocol version = %d, want %d", local, CurrentHAProtocolVersion)
pkg/cluster/heartbeat_test.go:516:	wantMismatch := CurrentHAProtocolVersion != LegacyHAProtocolVersion
pkg/cluster/heartbeat_test.go:526:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/manager.go:399:		localHAProtocolVersion:         CurrentHAProtocolVersion,
pkg/cluster/README.md:835:  case and ignores them — no `CurrentHAProtocolVersion` bump (the change is
pkg/cluster/heartbeat_auth_test.go:15:		HAProtocolVersion: CurrentHAProtocolVersion,
pkg/cluster/heartbeat_auth_test.go:86:		HAProtocolVersion: CurrentHAProtocolVersion,

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba cmd/xpfd/main.go | sed -n '175,205p'
rg -n 'ha-protocol-min-compat|version-json|parseHAProtocolCompatible|HA protocol version' pkg/upgrade cmd pkg/cluster --glob '*.go'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   175	}
   176	
   177	func main() {
   178		switch classifyCommand(os.Args) {
   179		case cmdVersion:
   180			fmt.Printf("xpfd %s (commit %s, built %s)\n", version, commit, buildTime)
   181			return
   182	
   183		case cmdProtocolVersions:
   184			// `xpfd protocol-versions` emits the compile-time HA / session-sync /
   185			// config-DB version constants this binary embeds, machine-parseably
   186			// (key=value lines). #1930 INC-3 LANE-2: the mixed-base image-replace gate
   187			// reads these from the STAGED binary (unpacked from the new image, run on
   188			// the deploy host) to decide — WITHOUT booting the image — whether the new
   189			// image's HA/session-sync protocol is back-compatible with the still-running
   190			// peer. Pairs with the bake version manifest (a file read where the binary
   191			// can't be run, e.g. cross-arch). Keep keys stable: external tooling parses
   192			// them.
   193			fmt.Printf("xpf-version=%s\n", version)
   194			fmt.Printf("ha-protocol-version=%d\n", cluster.CurrentHAProtocolVersion)
   195			fmt.Printf("ha-protocol-min-compat=%d\n", cluster.MinCompatHAProtocolVersion)
   196			// The CROSS-CHASSIS session-sync wire schema (pkg/cluster/sync.go) —
   197			// NOT the daemon↔helper local control socket (userspace.ProtocolVersion),
   198			// which has nothing to do with whether two CHASSIS can sync sessions.
   199			fmt.Printf("session-sync-protocol-version=%d\n", cluster.SessionSyncWireVersion)
   200			fmt.Printf("configdb-envelope-version=%d\n", configstore.EnvelopeFormatVersion)
   201			fmt.Printf("configdb-min-reader-version=%d\n", configstore.EnvelopeMinReaderVersion)
   202			return
   203	
   204		case cmdCleanup:
   205			// #5322: cleanup takes NO flags or positional arguments; like #4869's
pkg/cluster/cluster_test.go:1429:	if !strings.Contains(out, "HA protocol version: 1") {
pkg/cluster/cluster_test.go:1435:	if !strings.Contains(out, "Peer HA protocol version: 1") {
pkg/cluster/cluster_test.go:1458:	if !strings.Contains(out, "HA protocol version: 1") {
pkg/cluster/cluster_test.go:1461:	if !strings.Contains(out, "Peer HA protocol version: 1") {
cmd/xpfd/main.go:195:		fmt.Printf("ha-protocol-min-compat=%d\n", cluster.MinCompatHAProtocolVersion)
pkg/cluster/status.go:38:	fmt.Fprintf(&b, "HA protocol version: %d\n", localProtocol)
pkg/cluster/status.go:44:		fmt.Fprintf(&b, "Peer HA protocol version: %d\n", peerProtocol)
pkg/cluster/status.go:161:	fmt.Fprintf(&b, "  HA protocol version: %d\n", localProtocol)
pkg/cluster/status.go:167:		fmt.Fprintf(&b, "  Peer HA protocol version: %d\n", peerProtocol)
pkg/cluster/heartbeat.go:37:	// MinCompatHAProtocolVersion is the OLDEST HA protocol version
pkg/cluster/heartbeat.go:123:// the HA protocol version. Older readers ignore any bytes after the optional
pkg/cluster/heartbeat.go:240:	const heartbeatVersionTrailerSize = 1 + 2 // version length byte + HA protocol version
pkg/cluster/heartbeat_test.go:126:	expected := heartbeatHeaderSize + 2*heartbeatGroupSize + 1 + 1 + 2 // +1 NumMonitors, +1 version length, +2 HA protocol version
pkg/cluster/peer_state.go:96:// HAProtocolVersions returns the currently known local and peer HA protocol versions.
pkg/cluster/sync.go:28:// (compatibility has ridden the HA protocol version); this constant makes the
pkg/cluster/sync.go:35:// diverges from the HA protocol version, replace this with its own counter.
pkg/upgrade/cluster_cli.go:147:	// The HA protocol version lines are in the STATUS topic
pkg/upgrade/cluster_cli.go:153:	return parseHAProtocolCompatible(s), nil
pkg/upgrade/cluster_cli.go:241:// parseHAProtocolCompatible compares the local and peer HA protocol
pkg/upgrade/cluster_cli.go:244://	HA protocol version: N
pkg/upgrade/cluster_cli.go:245://	Peer HA protocol version: M
pkg/upgrade/cluster_cli.go:253:func parseHAProtocolCompatible(s string) bool {
pkg/upgrade/cluster_cli_test.go:480:	match := "HA protocol version: 1\nPeer HA protocol version: 1\n"
pkg/upgrade/cluster_cli_test.go:481:	mismatch := "HA protocol version: 1\nPeer HA protocol version: 2\n"
pkg/upgrade/cluster_cli_test.go:482:	noPeer := "HA protocol version: 1\n"
pkg/upgrade/cluster_cli_test.go:484:	if !parseHAProtocolCompatible(match) {
pkg/upgrade/cluster_cli_test.go:487:	if parseHAProtocolCompatible(mismatch) {
pkg/upgrade/cluster_cli_test.go:490:	if parseHAProtocolCompatible(noPeer) {
pkg/upgrade/cluster_cli_test.go:496:// protocol version lines parseHAProtocolCompatible keys on.
pkg/upgrade/cluster_cli_test.go:505:	if !strings.Contains(st, "HA protocol version:") {
pkg/upgrade/cluster_cli_test.go:506:		t.Fatalf("FormatStatus lacks 'HA protocol version:' the parser keys on:\n%s", st)
pkg/upgrade/imageversions.go:24:	// HAProtocolMinCompat is the OLDEST HA protocol version this image can still
pkg/upgrade/imageversions.go:70:		case "ha-protocol-min-compat":
pkg/upgrade/imageversions.go:115:	"ha-protocol-min-compat",
pkg/upgrade/imageversions_test.go:7:ha-protocol-min-compat=1
pkg/upgrade/imageversions_test.go:94:ha-protocol-min-compat=1
pkg/upgrade/imageversions_test.go:110:	iv2, _ := parseImageVersions("ha-protocol-version=2\nha-protocol-min-compat=1\nsession-sync-protocol-version=70000\n")

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/upgrade/imageversions.go | sed -n '1,145p'
rg -n 'HAProtocolMinCompat|SessionSyncProtocol|ImageVersions|protocol-versions' pkg/upgrade cmd --glob '*.go' --glob '"'!**/*_test.go'"'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
     1	package upgrade
     2	
     3	import (
     4		"bufio"
     5		"fmt"
     6		"strconv"
     7		"strings"
     8	)
     9	
    10	// ImageVersions are the compile-time protocol/version constants a baked image's
    11	// xpfd embeds, used by the #1930 INC-3 LANE-2 mixed-base image-replace gate to
    12	// decide — BEFORE swapping the second HA node — whether the new image can run
    13	// alongside the still-running peer's OLD image without dropping sessions.
    14	//
    15	// Two sources produce the same key=value set:
    16	//   - `xpfd protocol-versions` run against the staged binary unpacked from the
    17	//     new image (canonical; the binary IS the protocol).
    18	//   - the bake `.manifest` (the bake recorded the same fields), for a pure file
    19	//     read where running the staged binary is inconvenient (cross-arch).
    20	type ImageVersions struct {
    21		XPFVersion string
    22		// HAProtocol is the HA/session-transfer protocol version this image SPEAKS.
    23		HAProtocol uint16
    24		// HAProtocolMinCompat is the OLDEST HA protocol version this image can still
    25		// interoperate with (back-compat floor). An image speaking N that can still
    26		// talk to N-1 sets MinCompat=N-1.
    27		HAProtocolMinCompat uint16
    28		// SessionSyncProtocol is the userspace session-sync frame/control protocol.
    29		SessionSyncProtocol int
    30		// ConfigDBEnvelope is the config-DB envelope grammar version.
    31		ConfigDBEnvelope int
    32		// ConfigDBMinReader is the minimum envelope-format version a reader must
    33		// support to load a DB this image writes.
    34		ConfigDBMinReader int
    35	
    36		// present tracks which fields were actually parsed (missing keys are a
    37		// fail-closed signal for the gate, not silent zero values).
    38		present map[string]bool
    39	}
    40	
    41	// parseImageVersions reads the `key=value` (protocol-versions) or `key: value`
    42	// (manifest) lines into an ImageVersions. Unknown keys are ignored; the gate
    43	// checks Has() for the fields it requires and fails closed if any is absent.
    44	func parseImageVersions(text string) (*ImageVersions, error) {
    45		iv := &ImageVersions{present: map[string]bool{}}
    46		sc := bufio.NewScanner(strings.NewReader(text))
    47		for sc.Scan() {
    48			line := strings.TrimSpace(sc.Text())
    49			if line == "" || strings.HasPrefix(line, "#") {
    50				continue
    51			}
    52			var k, v string
    53			if i := strings.IndexAny(line, "=:"); i >= 0 {
    54				k = strings.TrimSpace(line[:i])
    55				v = strings.TrimSpace(line[i+1:])
    56			} else {
    57				continue
    58			}
    59			// The manifest re-keys with underscores; accept both separators.
    60			k = strings.ReplaceAll(k, "_", "-")
    61			switch k {
    62			case "xpf-version":
    63				iv.XPFVersion = v
    64				iv.present[k] = true
    65			case "ha-protocol-version":
    66				if n, err := strconv.ParseUint(v, 10, 16); err == nil {
    67					iv.HAProtocol = uint16(n)
    68					iv.present[k] = true
    69				}
    70			case "ha-protocol-min-compat":
    71				if n, err := strconv.ParseUint(v, 10, 16); err == nil {
    72					iv.HAProtocolMinCompat = uint16(n)
    73					iv.present[k] = true
    74				}
    75			case "session-sync-protocol-version":
    76				// Parse as unsigned 16-bit, matching the on-wire constant
    77				// (cluster.SessionSyncWireVersion is a uint16) AND the Python gate's
    78				// _u16() — a signed strconv.Atoi here would accept a negative value
    79				// that the Python gate rejects (fail-closed), and a peer reporting
    80				// e.g. -1 against a new image also at -1 would falsely pass the
    81				// exact-match check (Go/Python parity bypass; r4 Codex HIGH).
    82				if n, err := strconv.ParseUint(v, 10, 16); err == nil {
    83					iv.SessionSyncProtocol = int(n)
    84					iv.present[k] = true
    85				}
    86			case "configdb-envelope-version":
    87				// Unsigned for the same Go/Python parity reason (kept symmetric with
    88				// session-sync even though config-DB versions are informational for
    89				// the HA gate today).
    90				if n, err := strconv.ParseUint(v, 10, 16); err == nil {
    91					iv.ConfigDBEnvelope = int(n)
    92					iv.present[k] = true
    93				}
    94			case "configdb-min-reader-version":
    95				if n, err := strconv.ParseUint(v, 10, 16); err == nil {
    96					iv.ConfigDBMinReader = int(n)
    97					iv.present[k] = true
    98				}
    99			}
   100		}
   101		if err := sc.Err(); err != nil {
   102			return nil, fmt.Errorf("scan protocol versions: %w", err)
   103		}
   104		return iv, nil
   105	}
   106	
   107	// has reports whether the named key was parsed.
   108	func (iv *ImageVersions) has(key string) bool { return iv.present[key] }
   109	
   110	// requiredKeys are the fields the mixed-base gate must see to make a decision.
   111	// Config-DB versions are informational for the HA gate (the replaced node
   112	// re-bootstraps its DB from text), so they are NOT required here.
   113	var requiredKeys = []string{
   114		"ha-protocol-version",
   115		"ha-protocol-min-compat",
   116		"session-sync-protocol-version",
   117	}
   118	
   119	// MixedBaseVerdict is the outcome of the gate.
   120	type MixedBaseVerdict struct {
   121		// SessionsSurvive is true only when the new image's HA + session-sync
   122		// protocols are back-compatible with the still-running peer, so the
   123		// post-swap mixed-base cluster keeps syncing sessions across the failover.
   124		SessionsSurvive bool
   125		// Reason is a human-readable explanation (always set).
   126		Reason string
   127	}
   128	
   129	// GateMixedBaseSwap decides whether a LANE-2 image-replace of the SECOND node
   130	// (to `newImg`) can preserve sessions while the FIRST node still runs the old
   131	// image advertising `peerHAProtocol` / `peerSessionSync`. It is fail-closed: any
   132	// missing field, any protocol the peer cannot speak, returns SessionsSurvive
   133	// =false (the operator must replace both nodes and accept a connection drop).
   134	//
   135	// Back-compat rule: sessions survive iff the peer's live HA protocol lies within
   136	// the new image's [MinCompat, HAProtocol] window AND the session-sync protocol
   137	// matches exactly (the userspace frame format is not versioned for skew — a
   138	// mismatch means the replaced node cannot decode the peer's synced sessions).
   139	func GateMixedBaseSwap(newImg *ImageVersions, peerHAProtocol uint16, peerSessionSync int) MixedBaseVerdict {
   140		if newImg == nil {
   141			return MixedBaseVerdict{false, "no image version info — fail closed (replace both nodes, sessions drop)"}
   142		}
   143		for _, k := range requiredKeys {
   144			if !newImg.has(k) {
   145				return MixedBaseVerdict{false, fmt.Sprintf(
cmd/xpfd/main.go:104:	case "protocol-versions":
cmd/xpfd/main.go:184:		// `xpfd protocol-versions` emits the compile-time HA / session-sync /
pkg/upgrade/imageversions.go:10:// ImageVersions are the compile-time protocol/version constants a baked image's
pkg/upgrade/imageversions.go:16://   - `xpfd protocol-versions` run against the staged binary unpacked from the
pkg/upgrade/imageversions.go:20:type ImageVersions struct {
pkg/upgrade/imageversions.go:24:	// HAProtocolMinCompat is the OLDEST HA protocol version this image can still
pkg/upgrade/imageversions.go:27:	HAProtocolMinCompat uint16
pkg/upgrade/imageversions.go:28:	// SessionSyncProtocol is the userspace session-sync frame/control protocol.
pkg/upgrade/imageversions.go:29:	SessionSyncProtocol int
pkg/upgrade/imageversions.go:41:// parseImageVersions reads the `key=value` (protocol-versions) or `key: value`
pkg/upgrade/imageversions.go:42:// (manifest) lines into an ImageVersions. Unknown keys are ignored; the gate
pkg/upgrade/imageversions.go:44:func parseImageVersions(text string) (*ImageVersions, error) {
pkg/upgrade/imageversions.go:45:	iv := &ImageVersions{present: map[string]bool{}}
pkg/upgrade/imageversions.go:72:				iv.HAProtocolMinCompat = uint16(n)
pkg/upgrade/imageversions.go:83:				iv.SessionSyncProtocol = int(n)
pkg/upgrade/imageversions.go:108:func (iv *ImageVersions) has(key string) bool { return iv.present[key] }
pkg/upgrade/imageversions.go:139:func GateMixedBaseSwap(newImg *ImageVersions, peerHAProtocol uint16, peerSessionSync int) MixedBaseVerdict {
pkg/upgrade/imageversions.go:156:	if peerHAProtocol < newImg.HAProtocolMinCompat || peerHAProtocol > newImg.HAProtocol {
pkg/upgrade/imageversions.go:160:			peerHAProtocol, newImg.HAProtocolMinCompat, newImg.HAProtocol)}
pkg/upgrade/imageversions.go:169:	if peerSessionSync != newImg.SessionSyncProtocol {
pkg/upgrade/imageversions.go:173:			peerSessionSync, newImg.SessionSyncProtocol)}
pkg/upgrade/imageversions.go:178:		newImg.HAProtocol, newImg.HAProtocolMinCompat, peerHAProtocol, newImg.SessionSyncProtocol)}

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/sync.go | sed -n '1,130p;130,300p'
rg -n 'peer.*lost|PeerLost|session.*flush|flush.*session|Clear.*session|Delete.*session|sync.*session|SessionSync' pkg/cluster userspace-dp/src --glob '*.go' --glob '*.rs' | head -300"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
     1	package cluster
     2	
     3	import (
     4		"context"
     5		"encoding/binary"
     6		"errors"
     7		"fmt"
     8		"log/slog"
     9		"net"
    10		"sync"
    11		"sync/atomic"
    12		"time"
    13	
    14		"github.com/psaab/xpf/pkg/dataplane"
    15		"github.com/psaab/xpf/pkg/dhcpserver"
    16	)
    17	
    18	// syncMagic identifies cluster session-sync protocol packets.
    19	var syncMagic = [4]byte{'B', 'P', 'S', 'Y'}
    20	
    21	// SessionSyncWireVersion is the schema version of the CROSS-CHASSIS session-sync
    22	// wire protocol (the `syncMagic`/`syncMsg*`/`syncHeader` binary format below —
    23	// NOT the daemon↔helper local control socket `userspace.ProtocolVersion`). It is
    24	// the version the #1930 INC-3 mixed-base image-replace gate must compare across
    25	// a mixed-base cluster: two nodes can only sync sessions if they speak the same
    26	// sync wire schema. Bump this whenever the `syncMsg*` set or `syncHeader`
    27	// changes incompatibly. The header has no on-wire version field today
    28	// (compatibility has ridden the HA protocol version); this constant makes the
    29	// sync schema version explicit for the gate. It tracks CurrentHAProtocolVersion
    30	// (NOT LegacyHAProtocolVersion): the sync wire schema and the HA protocol have
    31	// evolved together, so a CurrentHAProtocolVersion bump that changes the
    32	// `syncMsg*`/`syncHeader` format carries the sync version with it. Deriving
    33	// from the fixed Legacy constant would silently pin the gate to the stale
    34	// schema version after an HA bump (Copilot). If the sync wire format ever
    35	// diverges from the HA protocol version, replace this with its own counter.
    36	const SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)
    37	
    38	const (
    39		syncMsgSessionV4              = 1
    40		syncMsgSessionV6              = 2
    41		syncMsgDeleteV4               = 3
    42		syncMsgDeleteV6               = 4
    43		syncMsgBulkStart              = 5
    44		syncMsgBulkEnd                = 6
    45		syncMsgHeartbeat              = 7
    46		syncMsgConfig                 = 8
    47		syncMsgIPsecSA                = 9
    48		syncMsgFailover               = 10
    49		syncMsgFence                  = 11
    50		syncMsgClockSync              = 12
    51		syncMsgBarrier                = 13
    52		syncMsgBarrierAck             = 14
    53		syncMsgBulkAck                = 15
    54		syncMsgFailoverAck            = 16
    55		syncMsgFailoverCommit         = 17
    56		syncMsgFailoverCommitAck      = 18
    57		syncMsgPrepareActivation      = 19
    58		syncMsgFailoverBatch          = 20
    59		syncMsgFailoverBatchAck       = 21
    60		syncMsgFailoverBatchCommit    = 22
    61		syncMsgFailoverBatchCommitAck = 23
    62		syncMsgHeartbeatAck           = 24
    63		// #2239 HA DHCP-server lease sync (PATH C). A full-set push of the
    64		// active lease records this node serves, per family. These are ADDITIVE
    65		// and length-gated: a peer that predates the feature hits the default
    66		// receive case and ignores them, and the records use the #2170
    67		// trailing-field discipline so the schema can grow. Deliberately NO
    68		// CurrentHAProtocolVersion / SessionSyncWireVersion bump — the change is
    69		// additive AND end-to-end gated on the `dhcp-lease-synchronization` config
    70		// knob, so a mixed-base pair (one side new, one old) is safe and must
    71		// still be allowed to sync SESSIONS; bumping the wire version would make
    72		// the #1930 INC-3 mixed-base gate falsely refuse session sync across the
    73		// pair. If a FUTURE change to these messages becomes incompatible, bump
    74		// the version then.
    75		syncMsgDHCPLeaseV4 = 25
    76		syncMsgDHCPLeaseV6 = 26
    77	)
    78	
    79	// syncHeader is the wire header for each sync message.
    80	type syncHeader struct {
    81		Magic  [4]byte
    82		Type   uint8
    83		Pad    [3]byte
    84		Length uint32
    85	}
    86	
    87	const syncHeaderSize = 12
    88	const syncWriteDeadline = 2 * time.Second
    89	const failoverAckTimeout = 20 * time.Second
    90	const syncReadDeadline = 10 * time.Second
    91	const syncPeerSilenceTimeout = 30 * time.Second
    92	
    93	// SyncStats tracks session synchronization statistics.
    94	type SyncStats struct {
    95		SessionsSent      atomic.Uint64
    96		SessionsReceived  atomic.Uint64
    97		SessionsInstalled atomic.Uint64
    98		DeletesSent       atomic.Uint64
    99		DeletesReceived   atomic.Uint64
   100		BulkSyncs         atomic.Uint64
   101		ConfigsSent       atomic.Uint64
   102		ConfigsReceived   atomic.Uint64
   103		// ConfigsStaleIgnored counts config-sync messages dropped by the #3931
   104		// config-generation ordering guard: an incoming config whose monotonic
   105		// generation was NOT strictly newer than the last-applied one (an
   106		// out-of-order / reordered older config). A nonzero value means the
   107		// guard prevented a rapid-commit reorder (C1 applied after C2) from
   108		// leaving the standby on the older config.
   109		ConfigsStaleIgnored atomic.Uint64
   110		// ConfigsApplyFailed counts config-sync messages that were admitted by the
   111		// #3931 ordering guard but whose apply did NOT take effect on this node —
   112		// a compile/promote failure (a mixed-build ISSU syntax error, a store
   113		// rejection) or a transient RG0-primary rejection. On such a failure the
   114		// config high-water mark (lastAppliedConfigGen) is deliberately NOT
   115		// advanced, so the primary's re-push of the SAME generation is re-admitted
   116		// and the standby re-converges instead of being silently stranded on the
   117		// prior config (M-2/#4151). A persistently-nonzero value means a standby is
   118		// repeatedly failing to apply the peer's config — investigate divergence.
   119		ConfigsApplyFailed atomic.Uint64
   120		IPsecSASent        atomic.Uint64
   121		IPsecSAReceived    atomic.Uint64
   122		// IPsecSAStaleIgnored counts IPsec SA full-sets dropped by the #5706
   123		// ordering guard: an incoming (incarnation, seq) that was NOT strictly
   124		// newer than the last-applied pair — a full-set reordered across the
   125		// redundant fabric streams. A nonzero value means the guard prevented a
   126		// stale IPsec SA set from regressing the standby's held set.
   127		IPsecSAStaleIgnored atomic.Uint64
   128		// #2239 HA DHCP-server lease sync counters. Sent/Received count
   129		// full-set lease push MESSAGES (one per family per push); Seeded counts
   130		// leases written into a freshly-started Kea on takeover; errors fold
   130		// leases written into a freshly-started Kea on takeover; errors fold
   131		// into the shared Errors counter (fail-open posture).
   132		DHCPLeasesSent     atomic.Uint64
   133		DHCPLeasesReceived atomic.Uint64
   134		// DHCPLeasesStaleIgnored counts DHCP lease full-sets dropped by the #5706
   135		// ordering guard (per family), the DHCP analog of IPsecSAStaleIgnored: a
   136		// reordered older lease set that would otherwise have regressed the
   137		// standby's held set for a family.
   138		DHCPLeasesStaleIgnored atomic.Uint64
   139		DHCPLeasesSeeded       atomic.Uint64
   140		FencesSent             atomic.Uint64
   141		FencesReceived         atomic.Uint64
   142		Errors                 atomic.Uint64
   143		DeletesDropped         atomic.Uint64
   144		// DeletesStaleIgnored counts deletes refused by the #2170 install-
   145		// generation guard: a journaled/deferred delete whose generation was
   146		// strictly older than the currently-installed same-key entry. A nonzero
   147		// value means the guard prevented a stale delete from killing a live
   148		// same-5-tuple replacement session.
   149		DeletesStaleIgnored atomic.Uint64
   150		// InstallsStaleIgnored counts session installs refused because their
   151		// generation was strictly older than the currently-stored entry — the
   152		// delayed-stale-install variant (#2170 SMR C3). Refusing these keeps
   153		// the per-key stored generation monotonic so a later stale delete can
   154		// still be matched and refused.
   155		InstallsStaleIgnored atomic.Uint64
   156		// SessionsStaleConfigIgnored counts session installs refused by the #5274
   157		// config-epoch guard: the peer stamped the session with the config-sync
   158		// generation (#3931) it held at admit time, and that epoch was strictly
   159		// OLDER than this node's lastAppliedConfigGen — i.e. the peer has since
   160		// committed (and this node applied) a newer config that may DENY the
   161		// session. Refusing the install prevents a stale PERMIT from landing after
   162		// this node's clearSessionsForDeletedPolicies sweep for the newer config
   163		// (the immediate-policy-invalidation gap across the HA boundary).
   164		SessionsStaleConfigIgnored atomic.Uint64
   165		// GenMapOverflow counts how many times a #2170 generation map (sender
   166		// echo or receiver stored) was at genGuardMapCap and a NEW key therefore
   167		// could not be recorded (#2198 F1). The key degrades to gen-0 (safe,
   168		// unconditional) behavior. A nonzero value means a churn workload pushed
   169		// a generation map to its cap; the map is never cleared, so existing live
   170		// keys retain their stored generation and the guard stays correct for
   171		// them.
   172		GenMapOverflow atomic.Uint64
   173		// PreAuthRejected counts inbound sync connections dropped by the #5303
   174		// pre-auth admission cap: a connection accepted while the pre-auth setup
   175		// pool was saturated (a flood of connections that stall before
   176		// authentication). Excess connections are closed immediately and never
   177		// allocate the large session-sync socket buffers. A nonzero value means the
   178		// cap absorbed a connection flood on the sync/control network; the reserved
   179		// tail (preAuthPeerReserve) still admits the legitimate peer's reconnect.
   180		PreAuthRejected    atomic.Uint64
   181		Connected          atomic.Bool
   182		BulkSyncStartTime  atomic.Int64
   183		BulkSyncEndTime    atomic.Int64
   184		BulkSyncSessions   atomic.Uint64
   185		LastConfigSyncTime atomic.Int64
   186		LastConfigSyncSize atomic.Uint64
   187		LastFenceSeq       atomic.Uint64
   188		LastFenceAckAt     atomic.Int64
   189	}
   190	
   191	// SyncStatsSnapshot is a point-in-time copy of SyncStats with plain
   192	// non-atomic fields, safe to copy by value and pass across API boundaries.
   193	type SyncStatsSnapshot struct {
   194		SessionsSent               uint64
   195		SessionsReceived           uint64
   196		SessionsInstalled          uint64
   197		DeletesSent                uint64
   198		DeletesReceived            uint64
   199		BulkSyncs                  uint64
   200		ConfigsSent                uint64
   201		ConfigsReceived            uint64
   202		ConfigsStaleIgnored        uint64
   203		ConfigsApplyFailed         uint64
   204		IPsecSASent                uint64
   205		IPsecSAReceived            uint64
   206		IPsecSAStaleIgnored        uint64
   207		DHCPLeasesSent             uint64
   208		DHCPLeasesReceived         uint64
   209		DHCPLeasesStaleIgnored     uint64
   210		DHCPLeasesSeeded           uint64
   211		FencesSent                 uint64
   212		FencesReceived             uint64
   213		Errors                     uint64
   214		DeletesDropped             uint64
   215		DeletesStaleIgnored        uint64
   216		InstallsStaleIgnored       uint64
   217		SessionsStaleConfigIgnored uint64
   218		GenMapOverflow             uint64
   219		PreAuthRejected            uint64
   220		Connected                  bool
   221		ActiveFabric               int
   222		BulkSyncStartTime          int64
   223		BulkSyncEndTime            int64
   224		BulkSyncSessions           uint64
   225		LastConfigSyncTime         int64
   226		LastConfigSyncSize         uint64
   227		LastFenceSeq               uint64
   228		LastFenceAckAt             int64
   229	}
   230	
   231	// TransferReadinessSnapshot captures session-sync state that determines whether
   232	// manual failover can proceed without depending on bootstrap timing.
   233	//
   234	// #5563: it also carries the config-sync generations so a planned/manual
   235	// failover refuses to promote a config-stale standby. PeerConfigGen is the
   236	// highest config generation this node has RECEIVED from the peer (the config
   237	// sender's current committed generation as observed by the receiver);
   238	// AppliedConfigGen is the highest generation this node has SUCCESSFULLY
   239	// applied. When PeerConfigGen > AppliedConfigGen the standby is running an
   240	// older policy/zone/application snapshot than the primary committed —
   241	// promoting it fail-opens after a tightening commit and false-denies after a
   242	// loosening commit.
   243	type TransferReadinessSnapshot struct {
   244		Connected             bool
   245		PendingBulkAckEpoch   uint64
   246		PendingBulkAckAge     time.Duration
   247		BulkReceiveInProgress bool
   248		BulkReceiveEpoch      uint64
   249		BulkReceiveSessions   int
   250		PeerConfigGen         uint64
   251		AppliedConfigGen      uint64
   252	}
   253	
   254	// ConfigStale reports whether this node has received a newer config generation
   255	// from the peer than it has successfully applied — i.e. it is behind the
   256	// primary's committed config. A legacy peer (or a fresh node that has neither
   257	// received nor applied any generation) reports both generations as 0, which is
   258	// NOT stale, so the gate stays scoped to the genuine behind-the-primary case
   259	// and never blanket-blocks (#5563).
   260	func (s TransferReadinessSnapshot) ConfigStale() bool {
   261		return s.PeerConfigGen > s.AppliedConfigGen
   262	}
   263	
   264	// ReadyForManualFailover reports whether the sync path is settled enough to
   265	// use as a manual-failover transport without waiting for bootstrap work.
   266	//
   267	// #5563: a standby that has received a newer config generation than it has
   268	// applied is refused — a planned/manual promotion must not run a stale
   269	// security policy. The unplanned/crash failover path is a separate
   270	// availability-vs-security tradeoff and is NOT gated here.
   271	func (s TransferReadinessSnapshot) ReadyForManualFailover() bool {
   272		return s.PendingBulkAckEpoch == 0 && !s.BulkReceiveInProgress && !s.ConfigStale()
   273	}
   274	
   275	// Reason explains the current transfer-readiness blocker, if any.
   276	func (s TransferReadinessSnapshot) Reason() string {
   277		switch {
   278		case s.PendingBulkAckEpoch != 0:
   279			age := s.PendingBulkAckAge
   280			if age < 0 {
   281				age = 0
   282			}
   283			return fmt.Sprintf("peer still receiving outbound bulk epoch=%d age=%s", s.PendingBulkAckEpoch, age.Round(100*time.Millisecond))
   284		case s.BulkReceiveInProgress:
   285			return fmt.Sprintf("local bulk receive still in progress epoch=%d sessions=%d", s.BulkReceiveEpoch, s.BulkReceiveSessions)
   286		case s.ConfigStale():
   287			return fmt.Sprintf("standby config stale: applied gen=%d behind peer committed gen=%d", s.AppliedConfigGen, s.PeerConfigGen)
   288		default:
   289			return ""
   290		}
   291	}
   292	
   293	// SessionSync manages TCP-based session state replication between cluster
   294	// peers for stateful failover.
   295	type SessionSync struct {
   296		localAddr string
   297		peerAddr  string
   298		sessions  dataplane.SessionStore
   299		telemetry dataplane.Telemetry
   300		stats     SyncStats
pkg/cluster/cluster_test.go:1270:		t.Fatal("peer should be marked lost after transfer-commit grace expires")
userspace-dp/src/protocol/control.rs:126:    pub session_sync: Option<SessionSyncRequest>,
userspace-dp/src/protocol/control.rs:323:    /// #5674: peer-synced session imports rejected by the coordinator's
userspace-dp/src/protocol/control.rs:324:    /// aggregate admission bound (`upsert_synced_session`). Locally-created
userspace-dp/src/protocol/control.rs:1008:pub(crate) struct SessionSyncRequest {
userspace-dp/src/protocol/control.rs:1090:    /// pre-#3301 synced-session behavior (rolling-upgrade safe).
userspace-dp/src/protocol/control.rs:1113:    /// non-empty value is the SIGNAL that this synced forward session is a NAT64
userspace-dp/src/protocol/control.rs:1129:    /// wire so a peer-synced session ADOPTS the originating node's id rather than
userspace-dp/src/protocol/control.rs:1134:    /// (`build_synced_session_entry` -> `SessionInstall::session_id` ->
userspace-dp/src/protocol/binding.rs:1220:    /// the Go control plane can stamp the synced session's log flags. The
pkg/cluster/manager.go:131:	peerEverSeen bool // true once first heartbeat received; distinguishes "never heard" from "lost"
pkg/cluster/manager.go:250:	// during the guard aborts the spurious peer-lost transition. Defaults to
pkg/cluster/manager.go:257:	// bind retry). The daemon wires it to SessionSync.SendLivenessKeepalive
pkg/cluster/manager.go:299:	// syncReady is true once bulk session sync has been received (or timed
pkg/cluster/manager.go:301:	// equivalent of VRRP sync-hold — gates RG promotion until session state
pkg/cluster/manager.go:305:	// syncTransport records whether session sync uses "fabric" or
pkg/cluster/sync_auth_test.go:30:func runHandshake(s *SessionSync, conn net.Conn) <-chan handshakeResult {
pkg/cluster/sync_auth_test.go:39:func newAuthSync(t *testing.T, key []byte, authSeen bool) *SessionSync {
pkg/cluster/sync_auth_test.go:41:	s := NewSessionSync(":0", ":0", nil)
pkg/cluster/sync_auth_test.go:85:	frame := encodeRawMessage(syncMsgSessionV4, []byte("session-payload"))
pkg/cluster/sync_auth_test.go:205:	s := NewSessionSync(":0", ":0", nil) // no provider
pkg/cluster/sync_conn_config.go:28:// SessionSync.configApplyFailGrace and SessionSync.afterFuncFn.
pkg/cluster/sync_conn_config.go:33:func (s *SessionSync) nowMono() int64 {
pkg/cluster/sync_conn_config.go:43:func (s *SessionSync) configApplyGrace() time.Duration {
pkg/cluster/sync_conn_config.go:53:func (s *SessionSync) afterFunc(d time.Duration, f func()) *time.Timer {
pkg/cluster/sync_conn_config.go:81:func (s *SessionSync) noteConfigApplyFailure(applyErr error) {
pkg/cluster/sync_conn_config.go:118:func (s *SessionSync) raiseWanted(now int64) bool {
pkg/cluster/sync_conn_config.go:129:func (s *SessionSync) raiseConfigApplyHealthLocked() {
pkg/cluster/sync_conn_config.go:138:func (s *SessionSync) armConfigApplyGraceTimerLocked() {
pkg/cluster/sync_conn_config.go:149:func (s *SessionSync) stopConfigApplyGraceTimerLocked() {
pkg/cluster/sync_conn_config.go:157:// in-flight callback (epoch bump), used on SessionSync teardown (Stop) so no
pkg/cluster/sync_conn_config.go:159:func (s *SessionSync) stopConfigApplyGraceTimer() {
pkg/cluster/sync_conn_config.go:170:func (s *SessionSync) fireConfigApplyGraceExpiry(epoch uint64) {
pkg/cluster/sync_conn_config.go:194:// SessionSync but KEEPS the cluster Manager (daemon stopClusterComms), so a CF
pkg/cluster/sync_conn_config.go:195:// raised by a PRIOR SessionSync instance would otherwise stay stuck forever:
pkg/cluster/sync_conn_config.go:200:func (s *SessionSync) noteConfigApplySuccess() {
pkg/cluster/sync_conn_config.go:226:func (s *SessionSync) nextConfigGen() uint64 {
pkg/cluster/sync_conn_config.go:234:func (s *SessionSync) QueueConfig(configText string) {
pkg/cluster/sync_conn_config.go:267:func (s *SessionSync) shouldApplyConfigGen(gen uint64) bool {
pkg/cluster/sync_conn_config.go:280:func (s *SessionSync) recordAppliedConfigGen(gen uint64) {
pkg/cluster/sync_conn_config.go:296:func (s *SessionSync) beginConfigApply(gen uint64) {
pkg/cluster/sync_conn_config.go:308:func (s *SessionSync) endConfigApply() {
pkg/cluster/sync_conn_config.go:325:func (s *SessionSync) configApplyLoop(ctx context.Context) {
pkg/cluster/sync_conn_config.go:345:			// runs inside OnConfigReceived, so a synced session stamped with an
pkg/cluster/heartbeat_manager.go:176://     SessionSync.SendLivenessKeepalive, which refreshes the peer's
pkg/cluster/heartbeat_manager.go:414:	// fresh again, the peer is not lost: abort to avoid a spurious peer-loss
pkg/cluster/heartbeat_manager.go:430:	slog.Warn("cluster: peer heartbeat timeout, marking peer lost")
pkg/cluster/heartbeat_manager.go:439:			slog.Info("cluster: clearing manual failover (peer lost)", "rg", rg.GroupID)
userspace-dp/src/protocol/tests.rs:1713:    s.insert("session_sync_request".into(), dump(&SessionSyncRequest::default()));
userspace-dp/src/protocol/tests.rs:2377:// #2170: the SessionSyncRequest install generation must round-trip as a
userspace-dp/src/protocol/tests.rs:2379:// (serde default). Wire parity with the Go SessionSyncRequest.Generation field.
userspace-dp/src/protocol/tests.rs:2382:    let req = SessionSyncRequest {
userspace-dp/src/protocol/tests.rs:2387:    let json = serde_json::to_string(&req).expect("serialize SessionSyncRequest");
userspace-dp/src/protocol/tests.rs:2388:    let back: SessionSyncRequest =
userspace-dp/src/protocol/tests.rs:2389:        serde_json::from_str(&json).expect("deserialize SessionSyncRequest");
userspace-dp/src/protocol/tests.rs:2394:    let legacy: SessionSyncRequest =
userspace-dp/src/protocol/tests.rs:2396:            .expect("legacy SessionSyncRequest without generation decodes");
userspace-dp/src/protocol/tests.rs:2405:    let req = SessionSyncRequest {
userspace-dp/src/protocol/tests.rs:2411:    let json = serde_json::to_string(&req).expect("serialize SessionSyncRequest");
userspace-dp/src/protocol/tests.rs:2412:    let back: SessionSyncRequest =
userspace-dp/src/protocol/tests.rs:2413:        serde_json::from_str(&json).expect("deserialize SessionSyncRequest");
userspace-dp/src/protocol/tests.rs:2417:    let legacy: SessionSyncRequest =
userspace-dp/src/protocol/tests.rs:2419:            .expect("legacy SessionSyncRequest without log flags decodes");
userspace-dp/src/protocol/tests.rs:2433:    let req = SessionSyncRequest {
userspace-dp/src/protocol/tests.rs:2440:    let json = serde_json::to_string(&req).expect("serialize SessionSyncRequest");
userspace-dp/src/protocol/tests.rs:2441:    // Wire keys must match the Go SessionSyncRequest json tags exactly.
userspace-dp/src/protocol/tests.rs:2451:    let back: SessionSyncRequest =
userspace-dp/src/protocol/tests.rs:2452:        serde_json::from_str(&json).expect("deserialize SessionSyncRequest");
userspace-dp/src/protocol/tests.rs:2457:    let legacy: SessionSyncRequest =
userspace-dp/src/protocol/tests.rs:2459:            .expect("legacy SessionSyncRequest without policy fields decodes");
pkg/cluster/sync_admission.go:11:// 256 KiB read+write buffered socket (configureSessionSyncConn ran BEFORE the
pkg/cluster/sync_admission.go:55:// the auth handshake succeeds. Production points it at configureSessionSyncConn.
pkg/cluster/sync_admission.go:56:var configureConnFn = configureSessionSyncConn
pkg/cluster/sync_admission.go:66:func (s *SessionSync) beginSetup(conn net.Conn, inbound bool) bool {
pkg/cluster/sync_admission.go:92:func (s *SessionSync) finishSetup(conn net.Conn) {
pkg/cluster/sync_admission.go:111:func (s *SessionSync) closeSetupConns() {
pkg/cluster/sync_admission.go:127:func (s *SessionSync) notePreAuthRejected(conn net.Conn) {
pkg/cluster/sync_admission.go:146:func (s *SessionSync) isPeerRemote(conn net.Conn) bool {
pkg/cluster/runtime.go:1:// Package cluster — backend-neutral runtime surface for SessionSync.
pkg/cluster/runtime.go:4:// dataplane.DataPlane parameter type from NewSessionSync /
pkg/cluster/runtime.go:5:// NewDualSessionSync / SetDataPlane. The cluster session-sync hot path
pkg/cluster/runtime.go:25:// SessionSync. It captures exactly the domains the HA hot path needs:
pkg/cluster/runtime.go:28:// methods here means SessionSync gains a new runtime dependency and
userspace-dp/src/server/handlers/mod.rs:34:mod sync_session;
userspace-dp/src/server/handlers/mod.rs:231:            "sync_session" => sync_session::handle(&mut guard, request.session_sync, &mut response),
userspace-dp/src/server/handlers/mod.rs:328:    // drained session deltas — has been flushed to the peer.
userspace-dp/src/policy_tests.rs:675:// `flush_session_deltas_session_close_reresolves_policy_id_after_reorder`
userspace-dp/src/policy_tests.rs:763:    // fabric / tunnel; or a peer-synced session carrying only the wire scalar)
pkg/cluster/sync_conn_sweep.go:11:func (s *SessionSync) StartSyncSweep(ctx context.Context) {
pkg/cluster/sync_conn_sweep.go:38:func (s *SessionSync) sweepIntervals() (time.Duration, time.Duration) {
pkg/cluster/sync_conn_sweep.go:50:		if enabled, active, idle := profiler.SessionSyncSweepProfile(); enabled {
pkg/cluster/sync_conn_sweep.go:65:func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool {
pkg/cluster/sync_conn_sweep.go:79:func (s *SessionSync) syncSweep() int {
pkg/cluster/sync_conn_sweep.go:112:	// records) armed forceResync — the standby may still hold sessions the
pkg/cluster/sync_conn_sweep.go:119:		slog.Warn("cluster sync: forcing full bulk resync after delete-journal overflow (standby may retain stale sessions)")
pkg/cluster/sync_conn_sweep.go:202:		slog.Debug("cluster sync: sweep synced sessions", "count", count)
pkg/cluster/sync_admission_test.go:50:	s := NewSessionSync("10.0.0.1:9999", "10.0.0.2:9999", nil)
pkg/cluster/sync_admission_test.go:101:	s := NewSessionSync("10.0.0.1:9999", "10.0.0.2:9999", nil)
pkg/cluster/sync_admission_test.go:201:	// Stop() on a never-Started SessionSync: cancel is nil (guarded), listeners
pkg/cluster/election_test.go:32:func TestElection_PeerLost_BecomesPrimary(t *testing.T) {
pkg/cluster/election_test.go:54:	// We should become primary (peer lost, weight > 0).
pkg/cluster/election_test.go:779:func TestElection_PeerLost_BypassesReadinessGate(t *testing.T) {
pkg/cluster/heartbeat_guard_recheck_test.go:13:// peer-lost transition.
pkg/cluster/heartbeat_guard_recheck_test.go:54:		t.Fatal("peer marked lost despite a fresh heartbeat arriving during the guard window (#2080)")
pkg/cluster/heartbeat_guard_recheck_test.go:63:// genuinely stale), the peer must still be marked lost. This guards against an
pkg/cluster/heartbeat_guard_recheck_test.go:95:		t.Fatal("peer should be marked lost when the heartbeat is genuinely stale after the guard")
pkg/cluster/heartbeat_guard_recheck_test.go:104:// reports not-fresh, so the peer-lost transition proceeds exactly as it did
pkg/cluster/heartbeat_guard_recheck_test.go:126:		t.Fatal("peer should be marked lost with no receiver/seam (default fall-through)")
pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:18:// synced session install racing on the receiveLoop is compared against the
pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:42:func waitFenceCleared(t *testing.T, s *SessionSync) {
pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:71:	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:142:	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:188:	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
pkg/cluster/failover.go:18://     peer-lost cascade.
pkg/cluster/sync_conn_race_4962_test.go:37:	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/sync_conn_race_4962_test.go:93:	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/sync_conn_race_4962_test.go:127:	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
userspace-dp/src/server/handlers/sync_session.rs:1:// #1345: per-verb handler for sync_session. Body byte-identical to
userspace-dp/src/server/handlers/sync_session.rs:5:use super::super::helpers::{build_synced_session_entry, build_synced_session_key};
userspace-dp/src/server/handlers/sync_session.rs:7:use crate::{ControlResponse, SessionSyncRequest};
userspace-dp/src/server/handlers/sync_session.rs:11:    session_sync: Option<SessionSyncRequest>,
userspace-dp/src/server/handlers/sync_session.rs:14:    let Some(sync_req) = session_sync else {
userspace-dp/src/server/handlers/sync_session.rs:20:        "upsert" => match build_synced_session_entry(&sync_req, guard.afxdp.zone_name_to_id_ref()) {
userspace-dp/src/server/handlers/sync_session.rs:22:                guard.afxdp.upsert_synced_session(entry);
userspace-dp/src/server/handlers/sync_session.rs:29:        "delete" => match build_synced_session_key(&sync_req) {
userspace-dp/src/server/handlers/sync_session.rs:31:                guard.afxdp.delete_synced_session(key);
pkg/cluster/peer_state.go:18:// peer-lost transition proceeds exactly as before this re-check existed.
pkg/cluster/sync_config_epoch_5274_test.go:11:// The peer stamps every synced session with the #3931 config-sync generation
pkg/cluster/sync_config_epoch_5274_test.go:45:func installWithConfigEpochV4(ss *SessionSync, key dataplane.SessionKey, epoch uint64) {
pkg/cluster/sync_config_epoch_5274_test.go:51:func installWithConfigEpochV6(ss *SessionSync, key dataplane.SessionKeyV6, epoch uint64) {
pkg/cluster/sync_config_epoch_5274_test.go:66:	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
pkg/cluster/sync_config_epoch_5274_test.go:116:	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
pkg/cluster/sync_config_epoch_5274_test.go:147:	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
pkg/cluster/sync_config_epoch_5274_test.go:259:// config-sync generation (#3931 configGenCounter) onto every queued session
pkg/cluster/sync_config_epoch_5274_test.go:265:	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
pkg/cluster/sync_bulk_override_5085_test.go:23:func pumpBulk(t *testing.T, senderSS, receiverSS *SessionSync) {
pkg/cluster/sync_bulk_override_5085_test.go:84:	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
pkg/cluster/sync_bulk_override_5085_test.go:102:	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
pkg/cluster/sync_bulk_override_5085_test.go:132:	// PRIMARY: empty live table (no syncable sessions).
pkg/cluster/sync_bulk_override_5085_test.go:134:	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
pkg/cluster/sync_bulk_override_5085_test.go:147:	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
pkg/cluster/sync_bulk_override_5085_test.go:175:	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
pkg/cluster/bulkend_epoch_log_race_5718_test.go:29:	s := &SessionSync{}
pkg/cluster/heartbeat.go:55:	// DefaultHeartbeatThreshold is the default missed heartbeat count before peer is lost.
pkg/cluster/heartbeat.go:64:	//   - seen-then-lost: suppress peer-lost entirely — a recovering node must
pkg/cluster/heartbeat.go:758:	startedAt  time.Time // when receiver started (for initial peer-lost detection)
pkg/cluster/heartbeat.go:990:	// During the cold-boot grace, suppress peer-lost entirely. The config
pkg/cluster/heartbeat.go:994:	// declares peer lost — creating split-brain. (r.startedAt is a direct
pkg/cluster/heartbeat.go:1003:	// fired a false peer-lost on a healthy cluster (#1792).
pkg/cluster/sync_protocol.go:31:// than the heartbeat timeout falsely declares the peer lost (#1792).
pkg/cluster/sync_protocol.go:200:	// trailing field). A peer-synced session ADOPTS this id on import instead of
pkg/cluster/sync_protocol.go:326:// encodeDeleteV4 emits a delete message for a v4 session key. The 16-byte
pkg/cluster/sync_protocol.go:688:// is why #3931 does NOT bump SessionSyncWireVersion: that gate governs whether
pkg/cluster/sync_protocol.go:689:// SESSIONS sync at all across a mixed pair, and bumping it would break session
pkg/cluster/sync_protocol.go:733:// self-detecting via the magic, so NO SessionSyncWireVersion bump — the same
pkg/cluster/sync_protocol.go:846:// append-only and does NOT bump SessionSyncWireVersion.
pkg/cluster/sync_protocol.go:931:	// SessionSyncWireVersion.
pkg/cluster/election.go:33://   - If peer is lost, local becomes primary (if weight > 0)
pkg/cluster/status.go:293:				fmt.Fprintf(&b, "  Last bulk sync: %s (duration: %s, sessions: %d)\n",
pkg/cluster/status.go:296:				fmt.Fprintf(&b, "  Bulk sync in progress since %s (sessions: %d)\n",
pkg/cluster/fullset_seq_test.go:125:	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/fullset_seq_test.go:164:	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/fullset_seq_test.go:234:	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/fullset_seq_test.go:256:	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/fullset_seq_test.go:350:	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/fullset_seq_test.go:448:	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
pkg/cluster/sync_config_gen_test.go:73:	s := &SessionSync{}
pkg/cluster/sync_config_gen_test.go:101:	s := &SessionSync{}
pkg/cluster/sync_config_gen_test.go:125:	s := &SessionSync{}
pkg/cluster/sync_config_gen_test.go:150:	s := &SessionSync{}
pkg/cluster/sync_config_gen_test.go:206:func drainConfigApply(t *testing.T, s *SessionSync) {
pkg/cluster/sync_config_gen_test.go:227:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_gen_test.go:258:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_gen_test.go:285:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_gen_test.go:313:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_gen_test.go:370:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_conn_write.go:16:func (s *SessionSync) PauseIncrementalSync(reason string) {
pkg/cluster/sync_conn_write.go:20:		slog.Info("cluster sync: incremental sync paused", "reason", reason, "depth", depth, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
pkg/cluster/sync_conn_write.go:25:func (s *SessionSync) ResumeIncrementalSync(reason string) {
pkg/cluster/sync_conn_write.go:33:		slog.Info("cluster sync: incremental sync resumed", "reason", reason, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
pkg/cluster/sync_conn_write.go:36:func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
pkg/cluster/sync_conn_write.go:56:func (s *SessionSync) QueueSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
pkg/cluster/sync_conn_write.go:63:func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
pkg/cluster/sync_conn_write.go:69:// QueueDeleteV4 queues a v4 session deletion for synchronization. If the peer
pkg/cluster/sync_conn_write.go:77:func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
pkg/cluster/sync_conn_write.go:85:// QueueDeleteV6 queues a v6 session deletion for synchronization. If the peer
pkg/cluster/sync_conn_write.go:87:func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
pkg/cluster/sync_conn_write.go:95:// armDeleteResync marks that a delete-journal overflow dropped session-delete
pkg/cluster/sync_conn_write.go:105:func (s *SessionSync) armDeleteResync() bool {
pkg/cluster/sync_conn_write.go:114:func (s *SessionSync) journalDelete(msg []byte) {
pkg/cluster/sync_conn_write.go:135:func (s *SessionSync) flushDeleteJournal() {
pkg/cluster/sync_conn_write.go:188:func (s *SessionSync) rejournalTail(tail [][]byte) {
pkg/cluster/sync_conn_write.go:241:func (s *SessionSync) SendLivenessKeepalive() {
pkg/cluster/sync_conn_write.go:257:func (s *SessionSync) sendClockSync(conn net.Conn) {
pkg/cluster/sync_conn_write.go:268:func (s *SessionSync) sendLoop(ctx context.Context) {
userspace-dp/src/screen/mod.rs:654:    /// flood thresholds, so a legit high-pps synced session can false-trip a
userspace-dp/src/screen/mod.rs:723:        // high-pps synced session false-trip a flood Drop, dropping exactly
pkg/cluster/lease_sync_wire_test.go:159:		t.Errorf("newer-peer record lost known fields: %+v", got)
pkg/cluster/lease_sync_wire_test.go:171:		t.Errorf("legacy-peer record lost leading field address: %+v", got2)
pkg/cluster/lease_sync_wire_test.go:217:	s := &SessionSync{}
pkg/cluster/lease_sync_wire_test.go:255:	s := &SessionSync{}
pkg/cluster/lease_sync_wire_test.go:425:	s := &SessionSync{}
pkg/cluster/heartbeat_neverseen_floor_test.go:132:	// peer is marked lost at threshold*interval staleness.
pkg/cluster/heartbeat_neverseen_floor_test.go:142:		t.Fatal("seen-then-lost peer not declared dead after the grace (lost-peer path regressed)")
pkg/cluster/sync_bulk.go:40:func (s *SessionSync) doBulkSync() error {
pkg/cluster/sync_bulk.go:53:func (s *SessionSync) BulkSync() error {
pkg/cluster/sync_bulk.go:134:	slog.Info("cluster sync: bulk sync iterating v6", "epoch", epoch, "sessions", count, "skipped", skipped)
pkg/cluster/sync_bulk.go:184:	slog.Info("cluster sync: bulk sync writing end marker", "epoch", epoch, "sessions", count, "skipped", skipped)
pkg/cluster/sync_bulk.go:196:	slog.Info("cluster sync: bulk sync complete", "sessions", count, "skipped", skipped, "epoch", epoch)
pkg/cluster/sync_bulk.go:202:func (s *SessionSync) PendingBulkAck() (epoch uint64, age time.Duration, ok bool) {
pkg/cluster/sync_bulk.go:222:func (s *SessionSync) TransferReadiness() TransferReadinessSnapshot {
pkg/cluster/sync_bulk.go:245:func (s *SessionSync) sendBarrierAck(conn net.Conn, seq uint64) {
pkg/cluster/sync_bulk.go:272:func (s *SessionSync) completeBarrierWait(seq uint64) {
pkg/cluster/sync_bulk.go:282:func (s *SessionSync) sendBulkAck(conn net.Conn, epoch uint64) {
pkg/cluster/sync_bulk.go:305:func (s *SessionSync) writeBarrierMessage(payload []byte, timeout time.Duration) error {
pkg/cluster/sync_bulk.go:331:func (s *SessionSync) WaitForPeerBarrier(timeout time.Duration) error {
pkg/cluster/sync_bulk.go:380:			"timed out waiting for session sync barrier ack seq=%d sessions_sent=%d sessions_received=%d sessions_installed=%d queue_len=%d",
pkg/cluster/sync_bulk.go:394:func (s *SessionSync) WaitForPeerBarriersDrained(timeout time.Duration) error {
pkg/cluster/sync_config_health_6387_test.go:31://     tears down the SessionSync but keeps the cluster Manager, so a CF raised by
pkg/cluster/sync_config_health_6387_test.go:47:// the SessionSync's Stop() calls on the handle are safe no-ops.
pkg/cluster/sync_config_health_6387_test.go:134:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_health_6387_test.go:221:// BUG 2. A comms transport change tears down the SessionSync (daemon
pkg/cluster/sync_config_health_6387_test.go:223:// state cannot live only in the SessionSync: instance A raises CF on the shared
pkg/cluster/sync_config_health_6387_test.go:241:	a := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_health_6387_test.go:263:	// of the bug is that the CF outlives the SessionSync.
pkg/cluster/sync_config_health_6387_test.go:267:		t.Fatal("tearing down instance A must not clear the manager CF (it outlives the SessionSync)")
pkg/cluster/sync_config_health_6387_test.go:270:	// --- instance B: a fresh SessionSync on the SAME manager; its first
pkg/cluster/sync_config_health_6387_test.go:272:	b := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_health_6387_test.go:310:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/sync_config_health_6387_test.go:417:	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
pkg/cluster/peer_primary_5497_test.go:21:		{"peer primary but dead (lost)", false, statePtr(StatePrimary), false},
pkg/cluster/hooks.go:78:// SessionSync.SendLivenessKeepalive so the peer's heartbeat-timeout
userspace-dp/src/server/tests.rs:12:    bindings_settled, build_synced_session_entry, clear_pre_persist_lock_probe,
userspace-dp/src/server/tests.rs:21:    SessionSyncRequest, UserspaceCapabilities, MAX_CONTROL_REQUEST_BYTES,
userspace-dp/src/server/tests.rs:370:// --- sync_session -------------------------------------------------------
userspace-dp/src/server/tests.rs:373:fn sync_session_missing_request_is_rejected() {
userspace-dp/src/server/tests.rs:374:    let response = run_request(new_state(ProcessStatus::default()), req("sync_session"));
userspace-dp/src/server/tests.rs:384:fn sync_session_unknown_operation_is_rejected() {
userspace-dp/src/server/tests.rs:385:    let mut request = req("sync_session");
userspace-dp/src/server/tests.rs:386:    request.session_sync = Some(SessionSyncRequest {
userspace-dp/src/server/tests.rs:388:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:402:fn sync_session_delete_with_valid_key_succeeds() {
userspace-dp/src/server/tests.rs:403:    let mut request = req("sync_session");
userspace-dp/src/server/tests.rs:404:    request.session_sync = Some(SessionSyncRequest {
userspace-dp/src/server/tests.rs:412:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:419:fn sync_session_upsert_with_valid_entry_succeeds() {
userspace-dp/src/server/tests.rs:420:    let mut request = req("sync_session");
userspace-dp/src/server/tests.rs:421:    request.session_sync = Some(SessionSyncRequest {
userspace-dp/src/server/tests.rs:432:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:439:fn sync_session_upsert_with_malformed_mac_is_rejected() {
userspace-dp/src/server/tests.rs:440:    let mut request = req("sync_session");
userspace-dp/src/server/tests.rs:441:    request.session_sync = Some(SessionSyncRequest {
userspace-dp/src/server/tests.rs:448:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:460:fn sync_session_delete_with_unparseable_ip_is_rejected() {
userspace-dp/src/server/tests.rs:461:    let mut request = req("sync_session");
userspace-dp/src/server/tests.rs:462:    request.session_sync = Some(SessionSyncRequest {
userspace-dp/src/server/tests.rs:468:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:482:fn rebind_preserves_synced_sessions() {
userspace-dp/src/server/tests.rs:487:    // synced-session map (mod.rs:488). The reconcile pipeline's `tear_down`
userspace-dp/src/server/tests.rs:509:    let mut upsert = req("sync_session");
userspace-dp/src/server/tests.rs:510:    upsert.session_sync = Some(SessionSyncRequest {
userspace-dp/src/server/tests.rs:521:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:532:        "synced session should be present after upsert"
userspace-dp/src/server/tests.rs:544:        "#1921: rebind wiped the synced-session map — did rebind::handle \
userspace-dp/src/server/tests.rs:3050:// forward v6 key. Before #4565 `build_synced_session_entry` set `nat64: false`
userspace-dp/src/server/tests.rs:3068:    let req = SessionSyncRequest {
userspace-dp/src/server/tests.rs:3084:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:3086:    let entry = build_synced_session_entry(&req, &zones).expect("build nat64 entry");
userspace-dp/src/server/tests.rs:3126:    // A non-NAT64 synced session (empty nat64_snat_v4) is unaffected: no nat64
userspace-dp/src/server/tests.rs:3128:    let plain = SessionSyncRequest {
userspace-dp/src/server/tests.rs:3141:        ..SessionSyncRequest::default()
userspace-dp/src/server/tests.rs:3143:    let plain_entry = build_synced_session_entry(&plain, &zones).expect("build plain entry");
pkg/cluster/sync_auth.go:125:func (s *SessionSync) SetAuthProvider(p SyncAuthProvider) {
pkg/cluster/sync_auth.go:132:func (s *SessionSync) authKey() []byte {
pkg/cluster/sync_auth.go:145:func (s *SessionSync) syncPeerAuthSeen() bool {
pkg/cluster/sync_auth.go:244:// syncAuthDecision applies the #4107 dual-accept policy for a session-sync
pkg/cluster/sync_auth.go:329:func (s *SessionSync) performSyncHandshake(conn net.Conn) (syncAuthMode, []byte, *pendingFrame, error) {
pkg/cluster/sync_auth.go:415:func (s *SessionSync) wrapSyncConn(fabricIdx int, conn net.Conn, mode syncAuthMode, frameKey []byte) *authConn {
pkg/cluster/sync_config_epoch_active_active_6284_test.go:14:// stamps onto every synced session, stampInstallGen*) advances ONLY on the
pkg/cluster/sync_config_epoch_active_active_6284_test.go:47:	// A non-authority node's synced-out sessions all carry the SAME frozen
pkg/cluster/sync_config_epoch_active_active_6284_test.go:57:	ssApplied := NewSessionSync(":0", "10.0.0.2:4785", dpApplied)
pkg/cluster/sync_config_epoch_active_active_6284_test.go:78:	ssAuth := NewSessionSync(":0", "10.0.0.2:4785", dpAuth)
pkg/cluster/sync_config_epoch_active_active_6284_test.go:99:	ssB := NewSessionSync(":0", "10.0.0.2:4785", dpB)
pkg/cluster/sync_config_epoch_active_active_6284_test.go:112:		t.Fatalf("non-authority node must stamp its OWN synced-out sessions with the frozen boot-seed epoch %d (not the receive high-water 11), got %d", frozenEpoch, ownV4.ConfigEpoch)
pkg/cluster/sync_config_epoch_active_active_6284_test.go:130:	ssApplied := NewSessionSync(":0", "10.0.0.2:4785", dpApplied)
pkg/cluster/sync_config_epoch_active_active_6284_test.go:143:	ssAuth := NewSessionSync(":0", "10.0.0.2:4785", dpAuth)
pkg/cluster/sync_failover.go:47:func (s *SessionSync) failoverRGInUseLocked(rgIDs []int) bool {
pkg/cluster/sync_failover.go:71:func (s *SessionSync) SendFailover(rgID int) (uint64, error) {
pkg/cluster/sync_failover.go:128:func (s *SessionSync) SendFailoverBatch(rgIDs []int) (uint64, error) {
pkg/cluster/sync_failover.go:221:func (s *SessionSync) SendFailoverCommit(rgID int, reqID uint64) error {
pkg/cluster/sync_failover.go:277:func (s *SessionSync) SendFailoverCommitBatch(rgIDs []int, reqID uint64) error {
pkg/cluster/sync_failover.go:381:func (s *SessionSync) SendFence() error {
pkg/cluster/sync_failover.go:402:func (s *SessionSync) SendPrepareActivation(rgID int) {
pkg/cluster/sync_failover.go:423:func (s *SessionSync) handleRemoteFailover(conn net.Conn, rgID int, reqID uint64) {
pkg/cluster/sync_failover.go:452:func (s *SessionSync) handleRemoteFailoverBatch(conn net.Conn, rgIDs []int, reqID uint64) {
pkg/cluster/sync_failover.go:477:func (s *SessionSync) handleRemoteFailoverCommit(conn net.Conn, rgID int, reqID uint64) {
pkg/cluster/sync_failover.go:492:func (s *SessionSync) handleRemoteFailoverCommitBatch(conn net.Conn, rgIDs []int, reqID uint64) {
pkg/cluster/sync_failover.go:507:func (s *SessionSync) sendFailoverResult(conn net.Conn, msgType uint8, rgID int, reqID uint64, status uint8, detail string) {
pkg/cluster/sync_failover.go:538:func (s *SessionSync) completeFailoverWait(rgID int, reqID uint64, ack failoverAck) {
pkg/cluster/sync_failover.go:553:func (s *SessionSync) completeFailoverBatchWait(key string, reqID uint64, ack failoverAck) {

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/upgrade/imageversions.go | sed -n '129,185p'
nl -ba pkg/upgrade/cluster_cli.go | sed -n '120,165p'
rg -n 'GateMixedBaseSwap\\(' --glob '*.go' --glob '"'!**/*_test.go'"' ."[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   129	// GateMixedBaseSwap decides whether a LANE-2 image-replace of the SECOND node
   130	// (to `newImg`) can preserve sessions while the FIRST node still runs the old
   131	// image advertising `peerHAProtocol` / `peerSessionSync`. It is fail-closed: any
   132	// missing field, any protocol the peer cannot speak, returns SessionsSurvive
   133	// =false (the operator must replace both nodes and accept a connection drop).
   134	//
   135	// Back-compat rule: sessions survive iff the peer's live HA protocol lies within
   136	// the new image's [MinCompat, HAProtocol] window AND the session-sync protocol
   137	// matches exactly (the userspace frame format is not versioned for skew — a
   138	// mismatch means the replaced node cannot decode the peer's synced sessions).
   139	func GateMixedBaseSwap(newImg *ImageVersions, peerHAProtocol uint16, peerSessionSync int) MixedBaseVerdict {
   140		if newImg == nil {
   141			return MixedBaseVerdict{false, "no image version info — fail closed (replace both nodes, sessions drop)"}
   142		}
   143		for _, k := range requiredKeys {
   144			if !newImg.has(k) {
   145				return MixedBaseVerdict{false, fmt.Sprintf(
   146					"new image manifest missing %q — fail closed (replace both nodes, sessions drop)", k)}
   147			}
   148		}
   149		if peerHAProtocol == 0 {
   150			return MixedBaseVerdict{false,
   151				"peer HA protocol unknown (peer not advertising) — fail closed"}
   152		}
   153		// The peer must be able to talk to the new image: the peer's version must be
   154		// >= the new image's back-compat floor AND <= what the new image speaks (a
   155		// peer NEWER than the new image is a downgrade we do not gate as safe).
   156		if peerHAProtocol < newImg.HAProtocolMinCompat || peerHAProtocol > newImg.HAProtocol {
   157			return MixedBaseVerdict{false, fmt.Sprintf(
   158				"peer HA protocol %d outside new image window [%d,%d] — not back-compatible; "+
   159					"replace BOTH nodes (sessions drop)",
   160				peerHAProtocol, newImg.HAProtocolMinCompat, newImg.HAProtocol)}
   161		}
   162		// Session-sync frame format is exact-match (unversioned for skew). An UNKNOWN
   163		// peer session-sync (0) fails closed — we cannot prove the synced frames will
   164		// decode (r3 Codex HIGH: 0 was previously skipped as "compatible").
   165		if peerSessionSync == 0 {
   166			return MixedBaseVerdict{false,
   167				"peer session-sync protocol unknown — fail closed (replace both nodes, sessions drop)"}
   168		}
   169		if peerSessionSync != newImg.SessionSyncProtocol {
   170			return MixedBaseVerdict{false, fmt.Sprintf(
   171				"session-sync protocol differs (peer %d, new image %d) — synced sessions "+
   172					"would not decode across the mixed cluster; replace BOTH nodes (sessions drop)",
   173				peerSessionSync, newImg.SessionSyncProtocol)}
   174		}
   175		return MixedBaseVerdict{true, fmt.Sprintf(
   176			"new image HA protocol %d (compat floor %d) accepts peer %d; session-sync %d matches — "+
   177				"mixed-base swap preserves sessions",
   178			newImg.HAProtocol, newImg.HAProtocolMinCompat, peerHAProtocol, newImg.SessionSyncProtocol)}
   179	}
   120		s, err := g.information()
   121		if err != nil {
   122			return false, err
   123		}
   124		return parseSyncEstablished(s), nil
   125	}
   126	
   127	func (g *grpcCluster) DrainComplete() (bool, error) {
   128		// DrainComplete needs BOTH the local node's RG states (Secondary) AND
   129		// the PEER node's RG states (Primary) — i.e. the peer has actually
   130		// taken ownership, not merely that the local node demoted itself. The
   131		// status topic (FormatStatus) renders both the local AND peer node
   132		// lines per RG; the information topic renders only the local view. So
   133		// drain-complete is evaluated against the STATUS topic.
   134		st, err := g.statusText()
   135		if err != nil {
   136			return false, err
   137		}
   138		// Also require the peer alive + sync up from the information topic.
   139		info, err := g.information()
   140		if err != nil {
   141			return false, err
   142		}
   143		return parseDrainComplete(st) && parsePeerAlive(info) && parseSyncEstablished(info), nil
   144	}
   145	
   146	func (g *grpcCluster) HAProtocolCompatible() (bool, error) {
   147		// The HA protocol version lines are in the STATUS topic
   148		// (FormatStatus), not information (FormatInformation).
   149		s, err := g.statusText()
   150		if err != nil {
   151			return false, err
   152		}
   153		return parseHAProtocolCompatible(s), nil
   154	}
   155	
   156	// statusText fetches the rendered `show chassis cluster status` text.
   157	func (g *grpcCluster) statusText() (string, error) {
   158		cli, closeFn, err := g.dial()
   159		if err != nil {
   160			return "", err
   161		}
   162		defer closeFn()
   163		ctx, cancel := g.ctx()
   164		defer cancel()
   165		resp, err := cli.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-cluster-status"})
./pkg/upgrade/imageversions.go:139:func GateMixedBaseSwap(newImg *ImageVersions, peerHAProtocol uint16, peerSessionSync int) MixedBaseVerdict {

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n '"'^func '"\\(s \\*SessionSync\\).*Session|syncMsgSessionV4|decodeSessionV4|SessionsInstalled|install.*Session' pkg/cluster --glob '*.go' --glob '"'!**/*_test.go'"'
rg -n 'NewSessionSync\\(|SetClusterManager|clusterMgr|manager \\*Manager|mgr \\*Manager' pkg/cluster cmd --glob '*.go' --glob '"'!**/*_test.go'"' | head -200"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 70ms:[0m
pkg/cluster/sync.go:805:func NewSessionSync(localAddr, peerAddr string, rt clusterRuntime) *SessionSync {
pkg/cluster/monitor.go:199:func NewMonitor(mgr *Manager, groups []*config.RedundancyGroup) *Monitor {
pkg/cluster/heartbeat.go:778:func newHeartbeatSender(mgr *Manager, conn *net.UDPConn, peerAddr *net.UDPAddr, interval time.Duration) *heartbeatSender {
pkg/cluster/heartbeat.go:838:func newHeartbeatReceiver(mgr *Manager, conn *net.UDPConn, threshold int, interval time.Duration) *heartbeatReceiver {

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/sync_conn_read.go | sed -n '70,135p'
nl -ba pkg/cluster/sync_conn_gen.go | sed -n '420,490p'
nl -ba pkg/cluster/sync.go | sed -n '293,390p;790,850p;925,955p;1060,1125p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
    70			}
    71			// #4107 F23: on an authenticated connection every frame carries a
    72			// per-connection sequence + HMAC trailer. Read and verify it before the
    73			// message is trusted; a bad HMAC (forgery/tamper) or a non-increasing
    74			// sequence (replay/regression) drops the connection.
    75			if ac, ok := conn.(*authConn); ok && ac.authed() {
    76				trailer := make([]byte, syncAuthFrameTrailerSize)
    77				if _, err := io.ReadFull(conn, trailer); err != nil {
    78					if ctx.Err() != nil {
    79						return
    80					}
    81					slog.Debug("cluster sync: read auth trailer error", "err", err)
    82					return
    83				}
    84				if err := ac.verifyFrame(hdrBuf, payload, trailer); err != nil {
    85					slog.Warn("cluster sync: frame authentication failed, dropping connection",
    86						"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
    87					s.stats.Errors.Add(1)
    88					return
    89				}
    90			}
    91			missedHeartbeats = 0
    92			s.lastPeerRxMono.Store(MonotonicNanos())
    93			s.handleMessage(conn, hdr.Type, payload)
    94		}
    95	}
    96	func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {
    97		switch msgType {
    98		case syncMsgSessionV4:
    99			s.stats.SessionsReceived.Add(1)
   100			if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
   101				count := s.stats.BulkSyncSessions.Add(1)
   102				if count == 1 || count%64 == 0 {
   103					s.bulkMu.Lock()
   104					epoch := s.bulkRecvEpoch
   105					s.bulkMu.Unlock()
   106					slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v4", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
   107				}
   108			}
   109			if s.sessions != nil {
   110				if key, val, ok := decodeSessionV4Payload(payload); ok {
   111					if val.IsReverse == 0 {
   112						s.bulkMu.Lock()
   113						if s.bulkInProgress {
   114							s.bulkRecvV4[key] = struct{}{}
   115						}
   116						s.bulkMu.Unlock()
   117					}
   118					offset := s.peerClockOffset.Load()
   119					val.Created = rebaseTimestamp(val.Created, offset)
   120					val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
   121					s.installClusterSyncedV4(key, val)
   122				}
   123			}
   124		case syncMsgSessionV6:
   125			s.stats.SessionsReceived.Add(1)
   126			if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
   127				count := s.stats.BulkSyncSessions.Add(1)
   128				if count == 1 || count%64 == 0 {
   129					s.bulkMu.Lock()
   130					epoch := s.bulkRecvEpoch
   131					s.bulkMu.Unlock()
   132					slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v6", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
   133				}
   134			}
   135			if s.sessions != nil {
   420	// read FIRST and folded with a max: on the success-release ordering (high-water
   421	// stored, THEN fence cleared) this guarantees a reader that observes fence==0
   422	// has already observed the advanced high-water, so the effective threshold
   423	// never dips — closing the sub-µs sweep-vs-advance stale-permit race.
   424	func (s *SessionSync) configEpochStale(epoch uint64) bool {
   425		if epoch == 0 {
   426			return false
   427		}
   428		barrier := s.applyingConfigGen.Load()
   429		if applied := s.lastAppliedConfigGen.Load(); applied > barrier {
   430			barrier = applied
   431		}
   432		return epoch < barrier
   433	}
   434	
   435	func (s *SessionSync) installClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) {
   436		if s.sessions == nil {
   437			return
   438		}
   439		record, apply := s.installGenGuardV4(key, val.Generation)
   440		if !apply {
   441			s.stats.InstallsStaleIgnored.Add(1)
   442			slog.Debug("cluster sync: ignored stale-generation v4 install",
   443				"incoming_gen", val.Generation)
   444			return
   445		}
   446		if s.configEpochStale(val.ConfigEpoch) {
   447			s.stats.SessionsStaleConfigIgnored.Add(1)
   448			slog.Debug("cluster sync: ignored stale-config-epoch v4 install (peer moved to a newer config that may deny this session)",
   449				"session_config_epoch", val.ConfigEpoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
   450			return
   451		}
   452		if err := s.sessions.PutClusterSyncedV4(key, val); err == nil {
   453			s.recordInstalledGenV4(key, record)
   454			s.stats.SessionsInstalled.Add(1)
   455			s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, nil)
   456			if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
   457				s.OnForwardSessionInstalled()
   458			}
   459		} else {
   460			s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, err)
   461		}
   462	}
   463	
   464	func (s *SessionSync) installClusterSyncedV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
   465		if s.sessions == nil {
   466			return
   467		}
   468		record, apply := s.installGenGuardV6(key, val.Generation)
   469		if !apply {
   470			s.stats.InstallsStaleIgnored.Add(1)
   471			slog.Debug("cluster sync: ignored stale-generation v6 install",
   472				"incoming_gen", val.Generation)
   473			return
   474		}
   475		if s.configEpochStale(val.ConfigEpoch) {
   476			s.stats.SessionsStaleConfigIgnored.Add(1)
   477			slog.Debug("cluster sync: ignored stale-config-epoch v6 install (peer moved to a newer config that may deny this session)",
   478				"session_config_epoch", val.ConfigEpoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
   479			return
   480		}
   481		if err := s.sessions.PutClusterSyncedV6(key, val); err == nil {
   482			s.recordInstalledGenV6(key, record)
   483			s.stats.SessionsInstalled.Add(1)
   484			s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, nil)
   485			if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
   486				s.OnForwardSessionInstalled()
   487			}
   488		} else {
   489			s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, err)
   490		}
   293	// SessionSync manages TCP-based session state replication between cluster
   294	// peers for stateful failover.
   295	type SessionSync struct {
   296		localAddr string
   297		peerAddr  string
   298		sessions  dataplane.SessionStore
   299		telemetry dataplane.Telemetry
   300		stats     SyncStats
   301		mu        sync.Mutex
   302		conn0     net.Conn
   303		conn1     net.Conn
   304		writeMu   sync.Mutex
   305		// authProvider supplies the shared control-link PSK + the cross-channel
   306		// downgrade-guard signal for #4107 F23 session-sync stream auth. Optional:
   307		// nil (or an empty key) ⇒ legacy unauthenticated stream (dual-accept).
   308		authProvider atomic.Pointer[syncAuthProviderBox]
   309		// syncAuthedEver is the sticky sync-channel downgrade-guard: once any sync
   310		// connection authenticates, a later unauthenticated connection is rejected.
   311		syncAuthedEver atomic.Bool
   312	
   313		// #5303 pre-auth admission gate. Bounds the inbound sync connections that
   314		// are in setup (pre-handshake) at once so a flood of connections that stall
   315		// before authentication cannot exhaust FDs/goroutines/socket-memory and deny
   316		// a legitimate peer's reconnect. preAuthInFlight counts admitted-but-not-yet-
   317		// resolved inbound setups; setupConns tracks EVERY connection currently in
   318		// its pre-wire setup window (inbound AND outbound) so Stop() can close them
   319		// and unblock a stalled handshake — the bool value records whether the entry
   320		// holds a counted inbound admission slot. preAuthLogMono rate-limits the
   321		// rejection warning to ~1/sec. All three are guarded by preAuthMu.
   322		preAuthMu       sync.Mutex
   323		preAuthInFlight int
   324		setupConns      map[net.Conn]bool
   325		preAuthLogMono  atomic.Int64
   326	
   327		listener   net.Listener
   328		localAddr1 string
   329		peerAddr1  string
   330		listener1  net.Listener
   331		cancel     context.CancelFunc
   332		wg         sync.WaitGroup
   333		sendCh     chan []byte // buffered channel for outgoing messages
   334	
   335		// incrementalPauseDepth temporarily pauses background incremental producers
   336		// during ordered handoff operations.
   337		incrementalPauseDepth atomic.Int32
   338	
   339		// OnConfigReceived is called when a config sync message arrives from the
   340		// peer. It returns nil ONLY when the config was actually applied (or is
   341		// already the active config); a non-nil error means the apply did not take
   342		// effect (a compile/promote failure, or a transient RG0-primary rejection).
   343		// The single-consumer configApplyLoop advances the config high-water mark
   344		// (lastAppliedConfigGen) ONLY on a nil return, so an apply failure leaves
   345		// the standby eligible for the primary's re-push instead of silently
   346		// stranded on the prior config (M-2/#4151).
   347		OnConfigReceived func(configText string) error
   348		// OnConfigApplyHealth reports the config-sync APPLY health edge (#6387).
   349		// failing=true fires (once per streak) when a received config generation
   350		// has stayed un-applied — apply hard-failing, high-water pinned per
   351		// M-2/#4151 — for longer than the stale-duration grace
   352		// (configApplyFailGrace); the raise is driven by an independent grace-expiry
   353		// timer so a STABLE connection with one persistent apply failure surfaces CF
   354		// without a second delivery. failing=false fires on EVERY successful apply
   355		// (an idempotent clear), NOT only the first success after a local raise:
   356		// a comms transport change tears down this SessionSync but keeps the cluster
   357		// Manager, so the replacement instance must be able to clear a CF the OLD
   358		// instance raised — gating the clear on this instance's own local raised
   359		// flag would leave the manager annotation stuck forever. reason is the raw
   360		// apply error on a raise (the Manager sanitizes/bounds it before storage)
   361		// and empty on a clear. The daemon wires this to Manager.SetConfigSyncHealth
   362		// so a persistently stranded standby surfaces as a CF monitor-failure /
   363		// degraded health instead of only the terse `Transfer ready: no` string.
   364		// Diagnostic only — it NEVER gates failover.
   365		OnConfigApplyHealth func(failing bool, reason string)
   366		// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
   367		OnIPsecSAReceived func(connectionNames []string)
   368		// OnDHCPLeasesReceived is called when a DHCP-server lease set arrives from
   369		// the peer (#2239). family is 4 or 6; the standby holds these so it can
   370		// seed Kea on takeover. Fires after the peer*DHCPLeases store is updated.
   371		OnDHCPLeasesReceived func(family int, leases []dhcpserver.SyncLease)
   372		// OnRemoteFailover is called when the peer requests a transfer-out for one RG.
   373		// reqID is the request-scoped identifier carried on the wire; the demoted
   374		// owner binds its auto-restore lease to it so a stale commit cannot clear a
   375		// newer request's lease (#5079).
   376		OnRemoteFailover func(rgID int, reqID uint64) error
   377		// OnRemoteFailoverCommit finalizes the demoted side of an acknowledged handoff.
   378		// reqID identifies the request being committed so the owner can clear the
   379		// matching auto-restore lease (#5079).
   380		OnRemoteFailoverCommit func(rgID int, reqID uint64) error
   381		// OnRemoteFailoverBatch is called when the peer requests a multi-RG transfer-out.
   382		OnRemoteFailoverBatch func(rgIDs []int, reqID uint64) error
   383		// OnRemoteFailoverCommitBatch finalizes a previously acknowledged multi-RG handoff.
   384		OnRemoteFailoverCommitBatch func(rgIDs []int, reqID uint64) error
   385		// WaitFailoverApplied, if set, blocks until the local node has ACTUATED
   386		// the transfer-out just requested via OnRemoteFailover for one RG — i.e.
   387		// the async demotion event has been consumed and the old owner fenced
   388		// (VRRP resigned to priority-0 / VIPs removed / rg_active cleared). It
   389		// gates the failoverAckApplied reply so the peer cannot promote while this
   390		// node still externally owns the RG. OnRemoteFailover only ENQUEUES the
   790	//
   791	// The runtime parameter is backend-neutral (see clusterRuntime in runtime.go).
   792	// In-tree callers either pass nil at construction time and wire the runtime
   793	// later via SetRuntime (the daemon's pattern, see daemon_ha_sync.go) or pass a
   794	// runtime that already implements Sessions()/Telemetry() — both
   795	// *dataplane.Manager and *dataplane/userspace.LegacyDataPlaneAdapter satisfy
   796	// that contract. Callers that hold only a value typed as dataplane.DataPlane
   797	// (the legacy bridge does NOT expose Sessions()/Telemetry() directly) can
   798	// either: (a) wrap it in a small local type that adds Sessions() and
   799	// Telemetry() returning dataplane.SessionStoreOf(dp) /
   800	// dataplane.TelemetryOf(dp) and
   801	// pass that wrapper here — Go structural typing accepts any value with the
   802	// right method set even though clusterRuntime is package-private — or (b)
   803	// pass nil and use the deprecated SetDataPlane alias, which performs the
   804	// same adaptation internally.
   805	func NewSessionSync(localAddr, peerAddr string, rt clusterRuntime) *SessionSync {
   806		s := &SessionSync{
   807			localAddr:                  localAddr,
   808			peerAddr:                   peerAddr,
   809			sendCh:                     make(chan []byte, 4096),
   810			deleteJournalCap:           deleteJournalDefaultCap,
   811			failoverWaiters:            make(map[int]failoverWaiter),
   812			failoverCommitWaiters:      make(map[int]failoverWaiter),
   813			failoverBatchWaiters:       make(map[string]failoverWaiter),
   814			failoverBatchCommitWaiters: make(map[string]failoverWaiter),
   815		}
   816		s.initGenState()
   817		s.SetRuntime(rt)
   818		return s
   819	}
   820	
   821	// initGenState seeds the #2170 install-generation counter from CLOCK_MONOTONIC
   822	// nanos and initializes the sender/receiver generation maps. Seeding from the
   823	// boot-relative monotonic clock keeps the counter from regressing below a
   824	// value the peer may already hold after this node restarts (process restart)
   825	// WITHIN a single OS boot.
   826	//
   827	// CROSS-BOOT (OS reboot) the monotonic clock resets, so this node's counter
   828	// can come up LOWER than a generation the peer stored from our previous boot.
   829	// That is handled on the RECEIVER side, not here: when a (reconnecting,
   830	// possibly rebooted) peer begins its bulk re-prime, the receiver resets its
   831	// per-key stored generations (resetRecvGen, called from the syncMsgBulkStart
   832	// handler, #2198 F2). The bulk re-prime — which re-installs every owned
   833	// session — then lands unconditionally and re-records each key's fresh
   834	// generation, so the install guard accepts it instead of refusing it as stale
   835	// (the stale-RETAIN inverse of #2170). A persisted cross-boot high-water mark
   836	// is therefore unnecessary.
   837	func (s *SessionSync) initGenState() {
   838		seed := uint64(MonotonicNanos())
   839		if seed == 0 {
   840			seed = 1
   841		}
   842		s.genCounter.Store(seed)
   843		s.genSentV4 = make(map[dataplane.SessionKey]uint64)
   844		s.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
   845		s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
   846		s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
   847		// #3931: seed the config generation from the same monotonic base so the
   848		// sender's config-gen never regresses below a value the peer may hold
   849		// across this node's restarts within a boot, and create the ordered
   850		// config-apply queue drained by configApplyLoop. Buffered generously —
   925	//
   926	// Deprecated: use SetRuntime. Both legacy *dataplane.Manager and the
   927	// userspace LegacyDataPlaneAdapter satisfy clusterRuntime via Sessions()/
   928	// Telemetry(); no adapter is needed.
   929	func (s *SessionSync) SetDataPlane(dp dataplane.DataPlane) {
   930		if dp == nil {
   931			s.SetRuntimeDomains(nil, nil)
   932			return
   933		}
   934		s.SetRuntimeDomains(dataplane.SessionStoreOf(dp), dataplane.TelemetryOf(dp))
   935	}
   936	
   937	// SetRuntimeDomains sets the backend-neutral domains used by session sync.
   938	// The old BPF-shaped dataplane is intentionally kept outside SessionSync's
   939	// steady-state paths; callers that still own a legacy dataplane adapt it at the
   940	// boundary with dataplane.SessionStoreOf/TelemetryOf.
   941	func (s *SessionSync) SetRuntimeDomains(sessions dataplane.SessionStore, telemetry dataplane.Telemetry) {
   942		s.sessions = sessions
   943		s.telemetry = telemetry
   944	}
   945	
   946	// Stats returns a point-in-time snapshot of sync statistics.
   947	func (s *SessionSync) Stats() SyncStatsSnapshot {
   948		s.mu.Lock()
   949		var activeFabric int
   950		if s.conn0 != nil {
   951			activeFabric = 0
   952		} else if s.conn1 != nil {
   953			activeFabric = 1
   954		} else {
   955			activeFabric = -1
  1060				initialized = true
  1061			}
  1062			if time.Now().After(deadline) {
  1063				return fmt.Errorf("timed out waiting for session sync idle sessions_sent=%d deletes_sent=%d queue_len=%d", lastSent, lastDeletes, lastQueue)
  1064			}
  1065			time.Sleep(sampleInterval)
  1066		}
  1067	}
  1068	
  1069	func (s *SessionSync) snapshotZoneOwnership() map[uint16]bool {
  1070		s.zoneRGMu.RLock()
  1071		m := s.zoneRGMap
  1072		s.zoneRGMu.RUnlock()
  1073		snap := make(map[uint16]bool, len(m))
  1074		for zoneID := range m {
  1075			snap[zoneID] = s.ShouldSyncZone(zoneID)
  1076		}
  1077		return snap
  1078	}
  1079	
  1080	func (s *SessionSync) reconcileStaleSessions() {
  1081		s.bulkMu.Lock()
  1082		if !s.bulkInProgress {
  1083			s.bulkMu.Unlock()
  1084			return
  1085		}
  1086		recvV4 := s.bulkRecvV4
  1087		recvV6 := s.bulkRecvV6
  1088		zoneSnap := s.bulkZoneSnapshot
  1089		s.bulkInProgress = false
  1090		s.bulkRecvV4 = nil
  1091		s.bulkRecvV6 = nil
  1092		s.bulkZoneSnapshot = nil
  1093		s.bulkMu.Unlock()
  1094		start := time.Now()
  1095		slog.Info("cluster sync: reconcile stale sessions starting", "recv_v4", len(recvV4), "recv_v6", len(recvV6), "zones", len(zoneSnap))
  1096		// #5085: do NOT skip on an empty received set. A completed bulk window
  1097		// (BulkStart -> BulkEnd, #5272-gated on bulkInProgress) is authoritative:
  1098		// an EMPTY authoritative snapshot means the peer legitimately holds no
  1099		// syncable sessions, so every eligible-absent stale peer-owned session
  1100		// MUST be reconciled away. The previous empty-bulk skip masked the #5085
  1101		// bug (the event-stream override sent empty markers), letting stale
  1102		// sessions survive cold-prime. The snapshot is now authoritative and
  1103		// lossless (doBulkSync always runs BulkSync's direct-write window), so the
  1104		// natural reconcile against an empty set is correct — no dangerous
  1105		// "empty means delete-all" heuristic, just the normal absent-key delete.
  1106		if s.sessions == nil {
  1107			slog.Info("cluster sync: reconcile stale sessions skipped (no dataplane)")
  1108			return
  1109		}
  1110		if len(zoneSnap) == 0 {
  1111			slog.Info("cluster sync: reconcile stale sessions skipped (no zone snapshot)")
  1112			return
  1113		}
  1114		shouldSyncAtBulkStart := func(zoneID uint16) bool {
  1115			if v, ok := zoneSnap[zoneID]; ok {
  1116				return v
  1117			}
  1118			return true
  1119		}
  1120		var deleted int
  1121		result, err := s.sessions.ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput{
  1122			ReceivedV4:     recvV4,
  1123			ReceivedV6:     recvV6,
  1124			ShouldSyncZone: shouldSyncAtBulkStart,
  1125			DeleteReason:   dataplane.DeleteReasonClusterStale,

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'doBulkSync|BulkSync\\(|syncReady|OnForwardSessionInstalled|peerHAProtocolVersion|HAProtocolVersions\\(' pkg/cluster cmd --glob '*.go' --glob '"'!**/*_test.go'"'
nl -ba pkg/cluster/sync_bulk.go | sed -n '1,85p;85,210p'
rg -n 'reconcileStaleSessions\\(' pkg/cluster --glob '*.go' --glob '"'!**/*_test.go'"'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
pkg/cluster/status.go:19:	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
pkg/cluster/status.go:118:	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
pkg/cluster/manager.go:141:	peerHAProtocolVersion  uint16
pkg/cluster/manager.go:299:	// syncReady is true once bulk session sync has been received (or timed
pkg/cluster/manager.go:303:	syncReady bool
pkg/cluster/sync_conn_sweep.go:120:		if err := s.doBulkSync(); err != nil {
pkg/cluster/sync_conn_gen.go:456:		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
pkg/cluster/sync_conn_gen.go:457:			s.OnForwardSessionInstalled()
pkg/cluster/sync_conn_gen.go:485:		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
pkg/cluster/sync_conn_gen.go:486:			s.OnForwardSessionInstalled()
pkg/cluster/sync_bulk.go:14:// doBulkSync delivers the cold-start / survivor-fabric re-drive bulk session
pkg/cluster/sync_bulk.go:22:// DELETED. BulkSync() builds exactly that snapshot with LOSSLESS direct writes
pkg/cluster/sync_bulk.go:23:// under writeMu (no lossy sendCh drops) and filters by owned zone, so doBulkSync
pkg/cluster/sync_bulk.go:24:// ALWAYS ends with BulkSync().
pkg/cluster/sync_bulk.go:36:// BulkSync() now guarantees the receiver always sees an authoritative window.
pkg/cluster/sync_bulk.go:40:func (s *SessionSync) doBulkSync() error {
pkg/cluster/sync_bulk.go:47:	return s.BulkSync()
pkg/cluster/sync_bulk.go:53:func (s *SessionSync) BulkSync() error {
pkg/cluster/sync_conn.go:194:		if err := s.doBulkSync(); err != nil {
pkg/cluster/sync_conn.go:579:		// have dropped). Re-drive doBulkSync over the survivor.
pkg/cluster/sync_conn.go:589:		// s.mu, and doBulkSync -> BulkSync -> getActiveConn
pkg/cluster/sync_conn.go:615:				if err := s.doBulkSync(); err != nil {
pkg/cluster/heartbeat_manager.go:325:	m.peerHAProtocolVersion = normalizeHAProtocolVersion(pkt.HAProtocolVersion)
pkg/cluster/heartbeat_manager.go:429:	m.peerHAProtocolVersion = 0
pkg/cluster/sync_state.go:16:	if m.syncReady == ready {
pkg/cluster/sync_state.go:19:	m.syncReady = ready
pkg/cluster/sync_state.go:27:	return m.syncReady
pkg/cluster/sync.go:405:	// OnForwardSessionInstalled fires when a forward synced session is installed locally.
pkg/cluster/sync.go:406:	OnForwardSessionInstalled func()
pkg/cluster/sync.go:410:	// BEFORE the authoritative BulkSync in doBulkSync (it does NOT replace it,
pkg/cluster/sync.go:413:	// snapshot — and is retained only as a test/extension seam. doBulkSync
pkg/cluster/sync.go:496:	// debounced goroutine to re-run doBulkSync over the survivor; this CAS
pkg/cluster/sync.go:1103:	// lossless (doBulkSync always runs BulkSync's direct-write window), so the
pkg/cluster/peer_state.go:97:func (m *Manager) HAProtocolVersions() (local, peer uint16) {
pkg/cluster/peer_state.go:100:	return m.localHAProtocolVersion, m.peerHAProtocolVersion
pkg/cluster/peer_state.go:111:	if !m.peerAlive || m.peerHAProtocolVersion == 0 {
pkg/cluster/peer_state.go:114:	peer := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
     1	package cluster
     2	
     3	import (
     4		"encoding/binary"
     5		"fmt"
     6		"log/slog"
     7		"net"
     8		"runtime"
     9		"time"
    10	
    11		"github.com/psaab/xpf/pkg/dataplane"
    12	)
    13	
    14	// doBulkSync delivers the cold-start / survivor-fabric re-drive bulk session
    15	// snapshot to the peer.
    16	//
    17	// #5085: the RECEIVER's authoritative stale-session reconcile
    18	// (reconcileStaleSessions) runs against exactly the key set delimited by a
    19	// BulkStart -> SessionV4/V6... -> BulkEnd window (bulkRecvV4/bulkRecvV6). It is
    20	// therefore only correct when that window carries a COMPLETE, authoritative
    21	// snapshot: a session merely absent from the window is treated as stale and
    22	// DELETED. BulkSync() builds exactly that snapshot with LOSSLESS direct writes
    23	// under writeMu (no lossy sendCh drops) and filters by owned zone, so doBulkSync
    24	// ALWAYS ends with BulkSync().
    25	//
    26	// BulkSyncOverride, if set, is a best-effort fast-population pre-step (the #418
    27	// event-stream export). It is NO LONGER wired in production (see
    28	// startClusterComms) and is retained only as a test/extension seam. Event-stream
    29	// delivery is async and LOSSY (QueueSessionV4/V6 -> non-blocking sendCh, cap
    30	// 4096): under load it drops session frames, and reconciling against that
    31	// incomplete set would DELETE live peer-owned sessions merely dropped in transit.
    32	// Historically the override path sent an EMPTY BulkStart/BulkEnd here
    33	// (sendBulkMarkers), so the receiver recorded zero keys and skipped stale
    34	// reconciliation entirely — a stale peer-owned session the standby held survived
    35	// cold-prime (the #5085 bug). Whether or not an override runs, the trailing
    36	// BulkSync() now guarantees the receiver always sees an authoritative window.
    37	// #5272 is preserved: BulkSync sends a real BulkStart (sets the receiver's
    38	// bulkInProgress), so only a genuine transfer — never a spurious no-transfer
    39	// BulkEnd — reconciles.
    40	func (s *SessionSync) doBulkSync() error {
    41		if s.BulkSyncOverride != nil {
    42			slog.Info("cluster sync: running bulk sync override (fast-population pre-step)")
    43			if err := s.BulkSyncOverride(); err != nil {
    44				slog.Warn("cluster sync: bulk sync override failed; authoritative BulkSync still runs", "err", err)
    45			}
    46		}
    47		return s.BulkSync()
    48	}
    49	
    50	// BulkSync sends all locally-owned forward sessions to the peer inside a
    51	// BulkStart -> sessions -> BulkEnd window, using lossless direct writes so the
    52	// receiver reconciles stale peer-owned sessions against the true snapshot.
    53	func (s *SessionSync) BulkSync() error {
    54		s.bulkSendMu.Lock()
    55		defer s.bulkSendMu.Unlock()
    56	
    57		if s.sessions == nil {
    58			return fmt.Errorf("session store not ready")
    59		}
    60		conn := s.getActiveConn()
    61		if conn == nil {
    62			return fmt.Errorf("no peer connection")
    63		}
    64	
    65		// Assign a monotonically increasing epoch to this bulk transfer.
    66		epoch := s.bulkSendNext.Add(1)
    67		var epochBuf [8]byte
    68		binary.LittleEndian.PutUint64(epochBuf[:], epoch)
    69	
    70		stats := s.Stats()
    71		slog.Info("cluster sync: bulk sync starting",
    72			"epoch", epoch,
    73			"local", connLocalAddrString(conn),
    74			"remote", connRemoteAddrString(conn),
    75			"sessions_sent", stats.SessionsSent,
    76			"sessions_received", stats.SessionsReceived,
    77			"sessions_installed", stats.SessionsInstalled,
    78			"queue_len", len(s.sendCh),
    79			"queue_cap", cap(s.sendCh))
    80	
    81		// Send bulk start marker with epoch.
    82		s.writeMu.Lock()
    83		err := writeMsg(conn, syncMsgBulkStart, epochBuf[:])
    84		s.writeMu.Unlock()
    85		if err != nil {
    85		if err != nil {
    86			s.pendingBulkAckEpoch.Store(0)
    87			s.pendingBulkAckSince.Store(0)
    88			s.handleDisconnect(conn)
    89			return err
    90		}
    91	
    92		var count, skipped int
    93		slog.Info("cluster sync: bulk sync iterating v4", "epoch", epoch)
    94		// Send owned v4 forward sessions.
    95		err = s.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
    96			if val.IsReverse != 0 {
    97				return true
    98			}
    99			if !s.ShouldSyncZone(val.IngressZone) {
   100				skipped++
   101				return true
   102			}
   103			s.stampInstallGenV4(key, &val)
   104			msg := encodeSessionV4Payload(key, val)
   105			s.writeMu.Lock()
   106			err := writeMsg(conn, syncMsgSessionV4, msg)
   107			s.writeMu.Unlock()
   108			if err != nil {
   109				s.handleDisconnect(conn)
   110				slog.Warn("bulk sync v4 write error", "err", err)
   111				return false
   112			}
   113			count++
   114			// Yield briefly every 64 sessions to let barrier/bulk ack
   115			// writers acquire writeMu. Go's mutex is not fair — a tight
   116			// lock/unlock loop can starve other goroutines waiting on
   117			// the same mutex.
   118			if count%64 == 0 {
   119				runtime.Gosched()
   120			}
   121			return true
   122		})
   123		if err != nil {
   124			s.pendingBulkAckEpoch.Store(0)
   125			s.pendingBulkAckSince.Store(0)
   126			return fmt.Errorf("bulk sync v4 iterate: %w", err)
   127		}
   128		slog.Info("cluster sync: bulk sync iterated v4",
   129			"epoch", epoch,
   130			"sessions", count,
   131			"skipped", skipped)
   132	
   133		// Send owned v6 forward sessions.
   134		slog.Info("cluster sync: bulk sync iterating v6", "epoch", epoch, "sessions", count, "skipped", skipped)
   135		err = s.sessions.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
   136			if val.IsReverse != 0 {
   137				return true
   138			}
   139			if !s.ShouldSyncZone(val.IngressZone) {
   140				skipped++
   141				return true
   142			}
   143			s.stampInstallGenV6(key, &val)
   144			msg := encodeSessionV6Payload(key, val)
   145			s.writeMu.Lock()
   146			err := writeMsg(conn, syncMsgSessionV6, msg)
   147			s.writeMu.Unlock()
   148			if err != nil {
   149				s.handleDisconnect(conn)
   150				slog.Warn("bulk sync v6 write error", "err", err)
   151				return false
   152			}
   153			count++
   154			if count%64 == 0 {
   155				runtime.Gosched()
   156			}
   157			return true
   158		})
   159		if err != nil {
   160			s.pendingBulkAckEpoch.Store(0)
   161			s.pendingBulkAckSince.Store(0)
   162			return fmt.Errorf("bulk sync v6 iterate: %w", err)
   163		}
   164		slog.Info("cluster sync: bulk sync iterated v6",
   165			"epoch", epoch,
   166			"sessions", count,
   167			"skipped", skipped)
   168	
   169		// Record the pending bulk-ack epoch BEFORE writing the BulkEnd marker
   170		// to the wire (record-then-send, mirroring the #2170/#2198 gen-guard
   171		// discipline). The peer's ack is processed on the read goroutine
   172		// (handleMessage, syncMsgBulkAck), which is independent of this send
   173		// goroutine. If we stored the pending epoch AFTER the write, a fast
   174		// peer could ack the BulkEnd and have the read goroutine process the
   175		// ack (seeing pendingBulkAckEpoch==0, so it drops it) before this
   176		// goroutine recorded the pending state. We would then latch a phantom
   177		// pending epoch that no future ack ever clears — permanently blocking
   178		// manual failover (#3912). Recording first guarantees the ack can only
   179		// ever observe the pending epoch already in place.
   180		s.pendingBulkAckEpoch.Store(epoch)
   181		s.pendingBulkAckSince.Store(time.Now().UnixNano())
   182	
   183		// Send bulk end marker with matching epoch.
   184		slog.Info("cluster sync: bulk sync writing end marker", "epoch", epoch, "sessions", count, "skipped", skipped)
   185		s.writeMu.Lock()
   186		err = writeMsg(conn, syncMsgBulkEnd, epochBuf[:])
   187		s.writeMu.Unlock()
   188		if err != nil {
   189			s.pendingBulkAckEpoch.Store(0)
   190			s.pendingBulkAckSince.Store(0)
   191			s.handleDisconnect(conn)
   192			return err
   193		}
   194	
   195		s.stats.BulkSyncs.Add(1)
   196		slog.Info("cluster sync: bulk sync complete", "sessions", count, "skipped", skipped, "epoch", epoch)
   197		return nil
   198	}
   199	
   200	// PendingBulkAck reports the latest outbound bulk epoch that is still awaiting
   201	// peer acknowledgement, if any.
   202	func (s *SessionSync) PendingBulkAck() (epoch uint64, age time.Duration, ok bool) {
   203		epoch = s.pendingBulkAckEpoch.Load()
   204		if epoch == 0 {
   205			return 0, 0, false
   206		}
   207		since := s.pendingBulkAckSince.Load()
   208		if since == 0 {
   209			return epoch, 0, true
   210		}
pkg/cluster/sync_conn_read.go:242:		s.reconcileStaleSessions()
pkg/cluster/sync.go:1080:func (s *SessionSync) reconcileStaleSessions() {

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/sync_conn.go | sed -n '145,215p;500,635p'
nl -ba pkg/cluster/sync_conn_read.go | sed -n '205,250p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   145			}
   146			// Re-read the resync arm AFTER flushDeleteJournal: a rejournalTail
   147			// eviction during that flush (or a journalDelete drop while we were
   148			// disconnected) arms forceResync, and dropped deletes are only
   149			// recoverable via a full authoritative bulk snapshot (#5450).
   150			// Consume the resync arm with CAS (symmetric with syncSweep) BEFORE the
   151			// bulk, so a NEW overflow that arms forceResync DURING this bulk survives
   152			// to trigger the next resync instead of being cleared by an unconditional
   153			// Store(false) (#5450 MINOR 1); a consumed arm is re-armed on bulk
   154			// failure so a later sweep/reconnect retries.
   155			forcedConsumed := s.forceResync.CompareAndSwap(true, false)
   156			// #5480: ALWAYS re-push our authoritative session table on a fresh
   157			// connection after a full (both-fabric) disconnect — not only on a
   158			// first-ever cold start (bulkEverCompleted false) or a #5450
   159			// delete-journal-overflow forced resync. bulkEverCompleted is a sticky,
   160			// process-local flag: once the survivor completes one bulk it stays true
   161			// forever, so the old `coldStart || forcedConsumed` reconnect gate wrongly
   162			// SKIPPED the re-push when the PEER rebooted and lost its session table
   163			// (the peer's own flag reset to false, but ours stayed true). The rebooted
   164			// peer then sends only its own empty bulk and OnPeerConnected re-pushes
   165			// non-session state, so the standby ends up with NO synced sessions — and
   166			// blackholes every established flow on the next failover to it.
   167			//
   168			// The survivor cannot locally tell a rebooted peer (empty table, needs
   169			// priming) from a pure fabric flap (peer kept its table): the sync
   170			// handshake carries no peer-cold / boot-incarnation / table-count signal,
   171			// and an unkeyed dual-accept peer sends no HELLO at all. So it re-primes
   172			// unconditionally. Re-priming is safe and idempotent — the receiver
   173			// upserts every session and reconcileStaleSessions on the peer prunes what
   174			// we no longer own — and a both-fabric disconnect means incremental deltas
   175			// may have been missed during the outage, so the "already primed"
   176			// assumption no longer holds even for a peer that never rebooted.
   177			//
   178			// Cost: one redundant full bulk on a genuine both-fabric flap. It is
   179			// bounded — this arm fires ONLY on a both-fabric down->up transition, never
   180			// on a routine single-fabric flip (those hit the becameActive/else branches
   181			// below and still do NOT re-bulk). The blackhole it prevents is far worse
   182			// than the redundant transfer (correctness over the optimization). A more
   183			// surgical fix that keeps the #466 flap-suppression optimization needs a
   184			// peer boot-incarnation field in the sync handshake — a wire change tracked
   185			// on #5480 and deferred here.
   186			switch {
   187			case forcedConsumed && !coldStart:
   188				slog.Warn("cluster sync: forcing full bulk resync on reconnect after delete-journal overflow (standby may retain stale sessions)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
   189			case coldStart:
   190				slog.Info("cluster sync: starting bulk sync on cold start", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
   191			default:
   192				slog.Info("cluster sync: re-priming bulk sync on reconnect (peer may have rebooted and lost its session table, #5480)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
   193			}
   194			if err := s.doBulkSync(); err != nil {
   195				slog.Warn("cluster sync: bulk sync failed", "err", err, "fabric", fabricIdx)
   196				if forcedConsumed {
   197					s.forceResync.Store(true)
   198				}
   199			} else {
   200				// #4962: the authoritative cold-prime landed on the (surviving)
   201				// active connection, discharging the outstanding obligation. Consume
   202				// the needColdPrime latch so routine single-fabric flips do NOT
   203				// re-bulk; a later full-disconnect epoch re-arms it via installConn.
   204				// On FAILURE the latch stays armed, so the next accept that becomes
   205				// active re-drives the bulk instead of dropping it.
   206				s.needColdPrime.Store(false)
   207			}
   208		} else if d.becameActive {
   209			slog.Info("cluster sync: active fabric changed, resuming incremental sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "active_before", d.activeBefore, "active_after", d.activeAfter)
   210		} else {
   211			slog.Info("cluster sync: connection added without bulk sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
   212		}
   213	}
   214	
   215	// connColdPrimeDecision is the atomically-computed outcome of installing a sync
   500			ackedBarriers := s.barrierAckSeq.Load()
   501			s.barrierWaitMu.Lock()
   502			clearedWaiters := len(s.barrierWaiters)
   503			staleWaiters := s.barrierWaiters
   504			s.barrierWaiters = nil
   505			s.barrierWaitMu.Unlock()
   506			for _, ch := range staleWaiters {
   507				close(ch)
   508			}
   509			s.failoverWaitMu.Lock()
   510			failoverWaiters := s.failoverWaiters
   511			failoverCommitWaiters := s.failoverCommitWaiters
   512			failoverBatchWaiters := s.failoverBatchWaiters
   513			failoverBatchCommitWaiters := s.failoverBatchCommitWaiters
   514			clearedFailoverWaiters := len(failoverWaiters)
   515			clearedFailoverCommitWaiters := len(failoverCommitWaiters)
   516			clearedFailoverBatchWaiters := len(failoverBatchWaiters)
   517			clearedFailoverBatchCommitWaiters := len(failoverBatchCommitWaiters)
   518			s.failoverWaiters = make(map[int]failoverWaiter)
   519			s.failoverCommitWaiters = make(map[int]failoverWaiter)
   520			s.failoverBatchWaiters = make(map[string]failoverWaiter)
   521			s.failoverBatchCommitWaiters = make(map[string]failoverWaiter)
   522			s.failoverWaitMu.Unlock()
   523			for _, waiter := range failoverWaiters {
   524				select {
   525				case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
   526				default:
   527				}
   528				close(waiter.ch)
   529			}
   530			for _, waiter := range failoverCommitWaiters {
   531				select {
   532				case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
   533				default:
   534				}
   535				close(waiter.ch)
   536			}
   537			for _, waiter := range failoverBatchWaiters {
   538				select {
   539				case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
   540				default:
   541				}
   542				close(waiter.ch)
   543			}
   544			for _, waiter := range failoverBatchCommitWaiters {
   545				select {
   546				case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
   547				default:
   548				}
   549				close(waiter.ch)
   550			}
   551			s.clockSynced.Store(false)
   552			s.pendingBulkAckEpoch.Store(0)
   553			s.pendingBulkAckSince.Store(0)
   554			s.bulkMu.Lock()
   555			hadBulkInProgress := s.bulkInProgress
   556			s.bulkInProgress = false
   557			s.bulkRecvEpoch = 0
   558			s.bulkRecvV4 = nil
   559			s.bulkRecvV6 = nil
   560			s.bulkZoneSnapshot = nil
   561			s.bulkMu.Unlock()
   562			if hadBulkInProgress {
   563				slog.Info("cluster sync: reset in-progress bulk receive on disconnect")
   564			}
   565			slog.Info("cluster sync: peer disconnected (all fabrics down)")
   566			if pendingBarriers != 0 || ackedBarriers != 0 || clearedWaiters != 0 || clearedFailoverWaiters != 0 || clearedFailoverCommitWaiters != 0 || clearedFailoverBatchWaiters != 0 || clearedFailoverBatchCommitWaiters != 0 {
   567				slog.Info("cluster sync: reset barrier state after disconnect", "pending_seq", pendingBarriers, "acked_seq", ackedBarriers, "cleared_waiters", clearedWaiters, "cleared_failover_waiters", clearedFailoverWaiters, "cleared_failover_commit_waiters", clearedFailoverCommitWaiters, "cleared_failover_batch_waiters", clearedFailoverBatchWaiters, "cleared_failover_batch_commit_waiters", clearedFailoverBatchCommitWaiters)
   568			}
   569			if s.OnPeerDisconnected != nil {
   570				go s.OnPeerDisconnected()
   571			}
   572		} else if !s.outboundBulkAcked.Load() {
   573			// #4090: a survivor fabric is still up but the cold-start bulk
   574			// never completed. The bulk streams over a SINGLE connection
   575			// (BulkSync pins s.getActiveConn once); if that
   576			// connection dropped mid-stream the bulk is stranded — it is not
   577			// retried on the survivor and handleNewConnection will not
   578			// re-trigger it (its wasDisconnected gate needs BOTH fabrics to
   579			// have dropped). Re-drive doBulkSync over the survivor.
   580			//
   581			// #4360: this gates on outboundBulkAcked, NOT bulkEverCompleted.
   582			// The re-drive's job is to get OUR outbound bulk to the peer; a
   583			// small INBOUND bulk (peer->us) completing first sets
   584			// bulkEverCompleted but says nothing about whether the peer
   585			// received our table, so keying on the shared flag would wrongly
   586			// suppress the re-drive of a stranded outbound bulk.
   587			//
   588			// This MUST be a goroutine, not inline: handleDisconnect holds
   589			// s.mu, and doBulkSync -> BulkSync -> getActiveConn
   590			// re-locks s.mu (self-deadlock if run inline). The CAS guard bounds
   591			// re-drives to one in-flight at a time so a survivor that also flaps
   592			// (its own write failure re-entering handleDisconnect) cannot spawn a
   593			// storm; the flag is reset when the re-drive goroutine returns.
   594			if s.bulkRedriveInFlight.CompareAndSwap(false, true) {
   595				slog.Info("cluster sync: scheduling cold-start bulk re-drive on survivor fabric",
   596					"had_conn0", s.conn0 != nil, "had_conn1", s.conn1 != nil)
   597				s.wg.Add(1)
   598				go func() {
   599					defer s.wg.Done()
   600					defer s.bulkRedriveInFlight.Store(false)
   601					// A concurrent reconnect (both-fabric drop then reconnect)
   602					// may have already re-primed via handleNewConnection.
   603					// #4360: re-check the SAME outbound-only flag the gate above
   604					// used — bulkEverCompleted may be true from an inbound bulk
   605					// while our outbound bulk is still un-acked, and bailing on
   606					// it here would make the fix inert.
   607					if s.outboundBulkAcked.Load() {
   608						return
   609					}
   610					// Reset the stranded pending-ack epoch so the re-run's fresh
   611					// epoch supersedes it (a latched phantom pending epoch would
   612					// block manual failover, #3912).
   613					s.pendingBulkAckEpoch.Store(0)
   614					s.pendingBulkAckSince.Store(0)
   615					if err := s.doBulkSync(); err != nil {
   616						slog.Warn("cluster sync: cold-start bulk re-drive failed", "err", err)
   617					}
   618				}()
   619			}
   620		}
   621	}
   205		case syncMsgBulkEnd:
   206			var epoch uint64
   207			if len(payload) >= 8 {
   208				epoch = binary.LittleEndian.Uint64(payload[:8])
   209			}
   210			s.bulkMu.Lock()
   211			if !s.bulkInProgress {
   212				// #5272: a BulkEnd with NO bulk transfer actually in progress
   213				// on our side is spurious or replayed — a buggy / mixed-version
   214				// / replaying peer frame, or a BulkEnd that arrives after we
   215				// tore the transfer down on disconnect. Completing it here would
   216				// reconcile-as-done, ACK, latch bulkEverCompleted, and fire
   217				// OnBulkSyncReceived, which RELEASES the VRRP sync hold: the node
   218				// would become MASTER-eligible while forwarding with an empty /
   219				// stale peer session table (stateful failover broken — a mid-
   220				// session failover blackholes). Only a real BulkStart -> ... ->
   221				// BulkEnd transfer may release the safety gate. This is LOCAL
   222				// state (no wire field, no version bump), so a legacy peer's
   223				// legitimate bulk still completes.
   224				s.bulkMu.Unlock()
   225				slog.Debug("cluster sync: ignoring BulkEnd with no bulk transfer in progress", "got", epoch)
   226				break
   227			}
   228			if s.bulkRecvEpoch != epoch {
   229				// #5718 (codex-182 C-HA C01b): snapshot the mutex-protected
   230				// expected epoch BEFORE releasing bulkMu. Reading s.bulkRecvEpoch
   231				// in the log arguments after Unlock races a concurrent BulkStart
   232				// on another fabric receive loop (which writes bulkRecvEpoch under
   233				// bulkMu, sync_conn_read.go BulkStart handler) — a diagnostic-only
   234				// data race the Go memory model forbids and go test -race flags.
   235				want := s.bulkRecvEpoch
   236				s.bulkMu.Unlock()
   237				slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch", "expected", want, "got", epoch)
   238				break
   239			}
   240			s.bulkMu.Unlock()
   241			s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
   242			s.reconcileStaleSessions()
   243			slog.Info("cluster sync: bulk transfer complete", "epoch", epoch, "sessions", s.stats.BulkSyncSessions.Load(), "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
   244			s.sendBulkAck(conn, epoch)
   245			s.bulkEverCompleted.Store(true)
   246			if s.OnBulkSyncReceived != nil {
   247				go s.OnBulkSyncReceived()
   248			}
   249		case syncMsgBulkAck:
   250			if len(payload) < 8 {

[35m[3mexec[0m[0m
[1m/bin/bash -lc "git diff --name-only e80db2eae691b020075471f0f4e92e70949b9a77..HEAD
nl -ba scripts/deploy/xpf-deploy.py | sed -n '2105,2150p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 139ms:[0m
docs/research/2387-session-identity/agy-plan-r1.md
docs/research/2387-session-identity/agy-plan-r2.md
docs/research/2387-session-identity/claude-smr-plan-r1.md
docs/research/2387-session-identity/claude-smr-plan-r2.md
docs/research/2387-session-identity/plan.md
docs/research/2387-session-identity/reviewer-ids.md
  2105	    return None
  2106	
  2107	
  2108	def _u16(s):
  2109	    """Parse a uint16 (matches the Go strconv.ParseUint(.,10,16) gate semantics —
  2110	    MEDIUM Codex: Python int() would accept -1 / 70000). Returns None on failure
  2111	    so the caller fails closed, exactly as the Go gate's `present` map does."""
  2112	    try:
  2113	        n = int(s)
  2114	    except (TypeError, ValueError):
  2115	        return None
  2116	    if n < 0 or n > 0xFFFF:
  2117	        return None
  2118	    return n
  2119	
  2120	
  2121	def _gate_mixed_base(new_img, peer):
  2122	    """EXACT Python mirror of upgrade.GateMixedBaseSwap (unit-tested in Go).
  2123	    Returns (sessions_survive: bool, reason: str). Fail-closed on any missing or
  2124	    out-of-range field, an unknown peer HA, an out-of-window peer, or an unknown
  2125	    / mismatched peer session-sync."""
  2126	    required = ["ha-protocol-version", "ha-protocol-min-compat",
  2127	                "session-sync-protocol-version"]
  2128	    for k in required:
  2129	        if k not in new_img:
  2130	            return False, f"new image manifest missing {k!r} — fail closed (replace both, sessions drop)"
  2131	    img_ha = _u16(new_img["ha-protocol-version"])
  2132	    img_floor = _u16(new_img["ha-protocol-min-compat"])
  2133	    img_sync = _u16(new_img["session-sync-protocol-version"])
  2134	    if img_ha is None or img_floor is None or img_sync is None:
  2135	        return False, "unparsable/out-of-range new image versions — fail closed"
  2136	    peer_ha = _u16(peer.get("ha-protocol-version", "0"))
  2137	    peer_sync = _u16(peer.get("session-sync-protocol-version", "0"))
  2138	    if peer_ha is None or peer_sync is None:
  2139	        return False, "unparsable/out-of-range peer versions — fail closed"
  2140	    if peer_ha == 0:
  2141	        return False, "peer HA protocol unknown — fail closed"
  2142	    if peer_ha < img_floor or peer_ha > img_ha:
  2143	        return (False, f"peer HA protocol {peer_ha} outside new image window "
  2144	                f"[{img_floor},{img_ha}] — replace BOTH nodes (sessions drop)")
  2145	    # An UNKNOWN peer session-sync (0) fails closed — same as the Go gate
  2146	    # (r3 Codex HIGH: 0 must NOT be skipped as compatible).
  2147	    if peer_sync == 0:
  2148	        return False, ("peer session-sync protocol unknown — fail closed "
  2149	                       "(replace both nodes, sessions drop)")
  2150	    if peer_sync != img_sync:

[35m[3mcodex[0m[0m
C3 is already a hard refutation: the compatibility floor is live production behavior, exported by `xpfd`, parsed by the upgrade library, and enforced by deployment tooling. More importantly, the same `CurrentHAProtocolVersion` bump would also bump `SessionSyncWireVersion`, whose mixed-base check is exact-match—so the plan’s “still rolling” conclusion is presently false unless it explicitly decouples those counters.
[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'QueueConfig\\(|OnConfigReceived|syncMsgConfig|encodeConfig|decodeConfig|configText' pkg/cluster pkg/daemon cmd --glob '*.go' --glob '"'!**/*_test.go'"'
rg -n '\\brollback\\b|Rollback|rollback' pkg cmd --glob '*.go' --glob '"'!**/*_test.go'"' | head -250"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 98ms:[0m
pkg/cluster/sync_conn_read.go:298:	case syncMsgConfig:
pkg/cluster/sync_conn_read.go:301:		configText, gen := decodeConfigPayload(payload)
pkg/cluster/sync_conn_read.go:302:		s.stats.LastConfigSyncSize.Store(uint64(len(configText)))
pkg/cluster/sync_conn_read.go:303:		slog.Info("cluster sync: config received from peer", "size", len(configText), "gen", gen)
pkg/cluster/sync_conn_read.go:316:		// of spawning a racing `go OnConfigReceived`. The receiveLoop is
pkg/cluster/sync_conn_read.go:323:			case s.configApplyCh <- configApplyItem{gen: gen, text: configText}:
pkg/cluster/sync_conn_read.go:330:				slog.Error("cluster sync: config apply queue full, dropping config (will re-converge on next push)", "gen", gen, "size", len(configText))
pkg/cluster/sync_conn_config.go:234:func (s *SessionSync) QueueConfig(configText string) {
pkg/cluster/sync_conn_config.go:240:	payload := encodeConfigPayload(configText, gen)
pkg/cluster/sync_conn_config.go:242:	err := writeMsg(conn, syncMsgConfig, payload)
pkg/cluster/sync_conn_config.go:251:	slog.Info("cluster sync: config sent to peer", "size", len(configText), "gen", gen)
pkg/cluster/sync_conn_config.go:278:// from the single-consumer configApplyLoop after OnConfigReceived returns nil,
pkg/cluster/sync_conn_config.go:290:// of an apply (#6284, item 2). It is set BEFORE OnConfigReceived runs — so it
pkg/cluster/sync_conn_config.go:317:// `go OnConfigReceived` per message.
pkg/cluster/sync_conn_config.go:320:// apply succeeds (recordAppliedConfigGen, gated on OnConfigReceived returning
pkg/cluster/sync_conn_config.go:337:			if s.OnConfigReceived == nil {
pkg/cluster/sync_conn_config.go:345:			// runs inside OnConfigReceived, so a synced session stamped with an
pkg/cluster/sync_conn_config.go:351:			if err := s.OnConfigReceived(item.text); err != nil {
pkg/cluster/sync.go:46:	syncMsgConfig                 = 8
pkg/cluster/sync.go:339:	// OnConfigReceived is called when a config sync message arrives from the
pkg/cluster/sync.go:347:	OnConfigReceived func(configText string) error
pkg/cluster/sync.go:573:	// (encodeConfigPayload), so a rapid commit pair carries strictly
pkg/cluster/sync.go:577:	// goroutine per message (the pre-#3931 `go OnConfigReceived` hazard). It
pkg/cluster/sync.go:583:	// successful apply (recordAppliedConfigGen, gated on OnConfigReceived
pkg/cluster/sync.go:596:	// to apply BEFORE calling OnConfigReceived (which runs the receiver's
pkg/cluster/sync.go:608:	// from the peer (recorded at enqueue in the syncMsgConfig handler, BEFORE
pkg/cluster/sync.go:853:	// next commit/reconnect re-push (see the syncMsgConfig handler).
pkg/daemon/daemon_apply_commit.go:331:func (d *Daemon) syncAndApply(ctx context.Context, configText string, chassisPreserve func(*config.ConfigTree)) (compiled *config.Config, retErr error) {
pkg/daemon/daemon_apply_commit.go:354:	compiled, syncErr = d.store.SyncApply(configText, chassisPreserve)
pkg/daemon/daemon_apply_commit.go:437:	// ActiveApplied() reads (configTextDigest(s.active.Format())).
pkg/daemon/daemon_ha_sync.go:366:	configText := d.store.ShowActive()
pkg/daemon/daemon_ha_sync.go:367:	if configText == "" {
pkg/daemon/daemon_ha_sync.go:370:	ss.QueueConfig(configText)
pkg/daemon/daemon_ha_sync.go:377:		d.markConfigSyncPushed(configText)
pkg/daemon/daemon_ha_sync.go:385:func configGenerationHash(configText string) uint64 {
pkg/daemon/daemon_ha_sync.go:387:	_, _ = h.Write([]byte(configText))
pkg/daemon/daemon_ha_sync.go:402:// markConfigSyncPushed records that configText's generation has been pushed to
pkg/daemon/daemon_ha_sync.go:407:func (d *Daemon) markConfigSyncPushed(configText string) {
pkg/daemon/daemon_ha_sync.go:408:	gen := configGenerationHash(configText)
pkg/daemon/daemon_ha_sync.go:467:	configText := d.store.ShowActive()
pkg/daemon/daemon_ha_sync.go:468:	if configText == "" {
pkg/daemon/daemon_ha_sync.go:471:	gen := configGenerationHash(configText)
pkg/daemon/daemon_ha_sync.go:492:		"reason", reason, "epoch", epoch, "generation", gen, "size", len(configText))
pkg/daemon/daemon_ha_sync.go:497:	ss.QueueConfig(configText)
pkg/daemon/daemon_ha_sync.go:544:func (d *Daemon) handleConfigSync(configText string) error {
pkg/daemon/daemon_ha_sync.go:551:		incomingText := strings.TrimSpace(configText)
pkg/daemon/daemon_ha_sync.go:565:				"size", len(configText))
pkg/daemon/daemon_ha_sync.go:571:	slog.Info("cluster: accepting config sync from peer", "size", len(configText))
pkg/daemon/daemon_ha_sync.go:578:	if _, err := d.syncAndApply(context.Background(), configText, nil); err != nil {
pkg/daemon/daemon_ha_sync.go:910:			ss.OnConfigReceived = func(configText string) error {
pkg/daemon/daemon_ha_sync.go:911:				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
pkg/daemon/daemon_ha_sync.go:912:				return d.handleConfigSync(configText)
cmd/xpfd/seed_runtime.go:17:// versions/current so a later in-place upgrade always has a real rollback
cmd/xpfd/main.go:243:		// the verified, atomic, rollback-capable STOP->FLIP->START cut to the
cmd/xpfd/main.go:256:		// every appliance a real, immutable rollback target before the first
cmd/xpfd/upgrade.go:26:// Exit codes: 0 success, 1 error (including a rollback report).
cmd/xpfd/upgrade.go:135:// clear the rollback journal / return the node to HA election) while the
cmd/xpfd/upgrade.go:142:// rollback path (standalone auto-rollback; HA surfaces the failure).
cmd/xpfd/upgrade.go:251:	configDBDir := fs.String("configdb-dir", upgrade.DefaultConfigDBDir, "config DB dir (for rollback snapshot)")
cmd/xpfd/upgrade.go:255:		"post-start helper-health deadline before auto-rollback (standalone)")
cmd/cli/shared.go:317:// parseRollbackSelector converts a rollback slot/index token into the int32
cmd/cli/shared.go:318:// the rollback RPCs carry. strconv.Atoi returns a 64-bit int on this target,
cmd/cli/shared.go:322:// display/compare selectors silently rendered the WRONG rollback with a
cmd/cli/shared.go:327:// min is the smallest accepted value: 0 for the mutating `rollback` (0 =
cmd/cli/shared.go:331:func parseRollbackSelector(token, usage string, min int32) (int32, error) {
cmd/cli/shared.go:335:			return 0, fmt.Errorf("rollback number %q out of range; %s", token, usage)
cmd/cli/shared.go:485:	case "rollback":
cmd/cli/shared.go:491:			// silently fall through to rollback 0 (which discards the
cmd/cli/shared.go:492:			// candidate). min=0 keeps `rollback 0` valid (revert to
cmd/cli/shared.go:493:			// active). See parseRollbackSelector for the int32-wrap
cmd/cli/shared.go:495:			v, err := parseRollbackSelector(parts[1], "rollback: rollback number must be a non-negative integer within int32 range", 0)
cmd/cli/shared.go:501:		_, err := c.client.Rollback(c.ctx(), &pb.RollbackRequest{N: n})
cmd/cli/show.go:16://	show_system.go     show system (commit/rollback/uptime/...)
cmd/cli/show.go:377:		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
cmd/cli/show.go:378:			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
cmd/cli/show.go:383:			n, err := parseRollbackSelector(rest, "usage: show | compare rollback <N>", 1)
cmd/cli/show.go:387:			resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: n})
cmd/cli/main.go:272:// confirmPending reports whether a commit-confirmed rollback is armed, using a
cmd/cli/main.go:369:		// #4868: `commit confirmed` is the rollback guard when changing
cmd/cli/main.go:399:	// — that would be a management-stranding change with no rollback timer.
cmd/cli/show_system.go:24:	case "rollback":
cmd/cli/show_system.go:31:				n, err := parseRollbackSelector(args[2], "usage: show system rollback compare <N>", 1)
cmd/cli/show_system.go:36:					RollbackN: n,
cmd/cli/show_system.go:50:			n, err := parseRollbackSelector(args[1], "usage: show system rollback <N>", 1)
cmd/cli/show_system.go:62:					RollbackN: n,
cmd/cli/show_system.go:74:			resp, err := c.client.ShowRollback(c.ctx(), &pb.ShowRollbackRequest{
cmd/cli/show_system.go:90:			fmt.Println("No rollback history available")
cmd/cli/show_system.go:94:			fmt.Printf("  rollback %d: %s\n", e.Index, e.Timestamp)
pkg/ddns/surface_a.go:1324:	// idiom). The in-process rollback below still handles a NON-crash wire failure.
pkg/ddns/surface_a.go:1361:	// if so, the newer state wins and we must NOT clobber it with a rollback or a
pkg/ddns/state.go:253:	// rollback in publishLocked never ran): on restart the unchanged-owned skip
pkg/cmdtree/tree.go:668:			"rollback": {Desc: "Show rolled back configuration", Children: map[string]*Node{
pkg/cmdtree/tree.go:669:				"compare": {Desc: "Compare rollback with active config"},
pkg/cmdtree/tree.go:1149:		"confirmed": {Desc: "Automatically rollback if not confirmed"},
pkg/cmdtree/tree.go:1159:	"rollback": {Desc: "Roll back to a previous committed configuration"},
pkg/eventengine/engine.go:171:	// in commit/rollback history WHICH policy fired and WHY.
pkg/eventengine/engine.go:855:// IS the rollback), apply every planned op, validate the WHOLE candidate with
pkg/eventengine/engine.go:934:	// remediation lands in commit/rollback history attributed to the policy and
pkg/eventengine/engine.go:973:// reading commit/rollback history can tell which policy mutated the config and
pkg/eventengine/engine.go:1363:			// non-idempotent then-batch and spams commit/rollback history.
pkg/cli/cli_config.go:218:		// #4868: `commit confirmed` is the operator's rollback guard, so a
pkg/cli/cli_config.go:251:	// management-stranding change with no rollback timer. Reject it before any
pkg/cli/cli_config.go:260:	// commit, this is a pure confirmation — cancel the rollback timer, no new
pkg/cli/cli_config.go:261:	// commit (avoids a spurious history/rollback entry). If the operator
pkg/cli/cli_config.go:381:		// Check for "| compare rollback N"
pkg/cli/cli_config.go:382:		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
pkg/cli/cli_config.go:383:			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
pkg/cli/cli_config.go:386:				return fmt.Errorf("usage: show | compare rollback <N>")
pkg/cli/cli_config.go:390:				diff, err = c.store.ShowCompareRollbackRedacted(n)
pkg/cli/cli_config.go:392:				diff, err = c.store.ShowCompareRollback(n)
pkg/cli/cli_show_system.go:893:	case "rollback":
pkg/cli/cli_show_system.go:894:		// Secret redaction (#4099): rollback slots render a historical config
pkg/cli/cli_show_system.go:897:		// *Redacted store methods so `show system rollback N [| display set]`
pkg/cli/cli_show_system.go:902:			// "show system rollback compare N" — diff rollback N against active
pkg/cli/cli_show_system.go:905:					return fmt.Errorf("usage: show system rollback compare <N>")
pkg/cli/cli_show_system.go:909:					return fmt.Errorf("usage: show system rollback compare <N>")
pkg/cli/cli_show_system.go:913:					diff, err = c.store.ShowCompareRollbackRedacted(n)
pkg/cli/cli_show_system.go:915:					diff, err = c.store.ShowCompareRollback(n)
pkg/cli/cli_show_system.go:928:			// "show system rollback N" — show specific rollback content.
pkg/cli/cli_show_system.go:931:				return fmt.Errorf("usage: show system rollback <N>")
pkg/cli/cli_show_system.go:937:					content, err = c.store.ShowRollbackSetRedacted(n)
pkg/cli/cli_show_system.go:939:					content, err = c.store.ShowRollbackSet(n)
pkg/cli/cli_show_system.go:948:					diff, err = c.store.ShowCompareRollbackRedacted(n)
pkg/cli/cli_show_system.go:950:					diff, err = c.store.ShowCompareRollback(n)
pkg/cli/cli_show_system.go:963:					content, err = c.store.ShowRollbackRedacted(n)
pkg/cli/cli_show_system.go:965:					content, err = c.store.ShowRollback(n)
pkg/cli/cli_show_system.go:975:		// List all rollback entries with timestamps.
pkg/cli/cli_show_system.go:978:			fmt.Println("No rollback history available")
pkg/cli/cli_show_system.go:982:			fmt.Printf("  rollback %d: %s\n", i+1, entry.Timestamp.Format("2006-01-02 15:04:05"))
pkg/cli/permissions.go:68:// configuration` (all formats), `show system rollback`, `show system
pkg/daemon/daemon_policy_invalidate.go:113:// Caller must hold d.applySem (all commit/sync/rollback call sites do), so this
pkg/daemon/daemon_policy_invalidate.go:119:// this into the commit/sync/rollback result rather than let it be lost to a log
pkg/daemon/daemon_policy_invalidate.go:219:// Caller must hold d.applySem (all commit/sync/rollback call sites do).
pkg/daemon/daemon_policy_invalidate.go:252:// Caller must hold d.applySem (all commit/sync/rollback call sites do).
pkg/daemon/daemon_policy_invalidate.go:270:// Caller must hold d.applySem (all commit/sync/rollback call sites do), so this
pkg/daemon/daemon_policy_invalidate.go:280:// can join it into the commit/sync/rollback result instead of the security gap
pkg/daemon/daemon_policy_invalidate.go:333:	// into the commit/sync/rollback result (#5578) — the failure is no longer
pkg/daemon/device_map.go:487:// the rollback target) against present hardware and rejects a commit that
pkg/daemon/device_map.go:490:// rollbackTarget is the config that would be restored on a confirmed-commit
pkg/daemon/device_map.go:492:func (d *Daemon) deviceMapCommitPreflight(candidate, rollbackTarget *config.Config) error {
pkg/daemon/device_map.go:495:	rbActive := rollbackTarget != nil && rollbackTarget.Chassis.DeviceMap.Active()
pkg/daemon/device_map.go:508:		// confirmed-commit rollback could not undo (its rollback target was
pkg/daemon/device_map.go:531:	// V-3(a): validate the rollback target too, so a confirmed-commit
pkg/daemon/device_map.go:533:	// unconditionally (OQ-15.2 — no rollback-time abort, no split-brain).
pkg/daemon/device_map.go:534:	if rollbackTarget != nil {
pkg/daemon/device_map.go:535:		if reason := deviceMapStrandsManagement(rollbackTarget, nics, protectedForConfig(rollbackTarget), lifelineName); reason != "" {
pkg/daemon/device_map.go:536:			return fmt.Errorf("commit confirmed rejected: the rollback target (current active "+
pkg/daemon/daemon_run_servers.go:373:		// disk (failed HA sync / auto-rollback persist, retry pending).
pkg/daemon/daemon_run_servers.go:375:		// #3441: surface configstore rollback-history-degraded state so
pkg/daemon/daemon_run_servers.go:377:		// xpf_config_rollback_persist_degraded reads 1 while the most
pkg/daemon/daemon_run_servers.go:378:		// recent commit failed to durably persist its text rollback
pkg/daemon/daemon_run_servers.go:381:		RollbackHistoryDegradedFn: d.store.RollbackHistoryDegraded,
pkg/daemon/daemon_run_servers.go:505:// REST/config API (set / commit / rollback / DHCP / system-action) to the
pkg/daemon/daemon_run_servers.go:585:	// mutating config endpoints (set / commit / rollback / DHCP / system-action)
pkg/cluster/heartbeat.go:606:// A->B->A rollback re-opened in full: an attacker holding captured
pkg/daemon/daemon_apply_reset.go:12:// job is purely to make a racing commit / HA-sync / rollback / reconcile abort
pkg/daemon/daemon_ha.go:434:// Without this, the armed rollback timer would still fire on the demoted
pkg/daemon/daemon_ha.go:435:// standby (PromoteRollback carries no read-only guard), reverting its
pkg/daemon/daemon_ha.go:469:		// so its rollback timer does not fire on the demoted standby and
pkg/daemon/bootstrap.go:7:// first-commit rollback only.
pkg/daemon/bootstrap.go:84:// rollback-to-bootstrap. Keyed by PCI address, NOT name (a name-keyed record
pkg/daemon/bootstrap.go:170:	// (case 5 never-committed, incl. the post-first-commit-rollback state).
pkg/daemon/bootstrap.go:206:// resolved) and again on rollback-to-bootstrap. It is deterministic and
pkg/daemon/bootstrap.go:252:	// rollback the DB holds an EMPTY tree with committed=0. On the next
pkg/daemon/bootstrap.go:260:	//     never-committed incl. post-first-commit-rollback (case 5) →
pkg/daemon/bootstrap.go:278:// startup and at most once more on rollback-to-bootstrap, so an atomic is
pkg/daemon/bootstrap.go:311:// box for cosmetic benefit. Post-rollback state = renamed NICs + lifeline
pkg/daemon/bootstrap.go:317:// the caller. When any step fails the daemon reports the rollback as DEGRADED
pkg/daemon/bootstrap.go:319:// falsely logging "rollback complete". A nil return means every step
pkg/daemon/bootstrap.go:332:	// so the lifecycle is exercised by the rollback unit tests too (it is a
pkg/daemon/bootstrap.go:347:		// executed ⇒ the rollback summarizes as clean, matching what those
pkg/daemon/bootstrap.go:355:	// teardown must never be logged/returned as a clean rollback.
pkg/daemon/bootstrap.go:360:				slog.Error("bootstrap rollback: teardown step FAILED",
pkg/daemon/bootstrap.go:364:		slog.Error("bootstrap rollback DEGRADED: one or more teardown steps failed; the "+
pkg/daemon/bootstrap.go:373:	slog.Warn("bootstrap rollback complete: takeover removed, management lifeline preserved; " +
pkg/daemon/bootstrap.go:379:// in the first-confirmed-commit bootstrap rollback (#5868). name identifies
pkg/daemon/bootstrap.go:388:// rollback teardown (#5868). It returns a joined error naming every failed
pkg/daemon/bootstrap.go:390:// iff any step failed. The caller MUST report the rollback as DEGRADED and
pkg/daemon/bootstrap.go:391:// MUST NOT log or persist "rollback complete" while degraded is true — a
pkg/daemon/bootstrap.go:408:// first-confirmed-commit bootstrap rollback (#5868) and returns the per-step
pkg/daemon/bootstrap.go:410:// earlier failures — a bootstrap rollback tears down as much as it can — but
pkg/daemon/bootstrap.go:445:				slog.Info("bootstrap rollback: removed takeover .network file", "file", name)
pkg/daemon/bootstrap.go:621:// and survives rollback-to-bootstrap.
pkg/daemon/bootstrap.go:630:	// rollback-to-bootstrap) so the daemon can always recover the
pkg/daemon/bootstrap.go:828://     protected set survives rename/restart/rollback,
pkg/daemon/daemon_run.go:130:	// Register the daemon-owned commit-confirmed timeout rollback executor
pkg/daemon/daemon_run.go:135:	// promotion + dataplane re-apply atomically; see executeConfirmedRollback.
pkg/daemon/daemon_run.go:136:	d.store.SetRollbackExecutor(d.executeConfirmedRollback)
pkg/daemon/daemon_run.go:194:	// DHCP / feed applies and executeConfirmedRollback still pass
pkg/daemon/daemon_run.go:622:		// applyConfigFn stays wired for non-commit paths (rollback,
pkg/daemon/daemon_apply.go:41:// in-process CLI commits, CLI auto-rollback, cluster sync recv).
pkg/daemon/daemon_apply.go:62:	// rollback) path. Stamp it applied so a peer config-sync of the same text
pkg/daemon/daemon_apply.go:139:// DHCP / feed and confirmed-rollback callers pass a non-cancellable context so
pkg/daemon/daemon_apply.go:140:// their applies always complete (see applyConfig / executeConfirmedRollback).
pkg/daemon/daemon_apply.go:157:	// entered the terminal reset generation. The commit / sync / rollback entry
pkg/routing/probe_pin.go:153:// rollback RuleDel itself fails, the stale rule is logged and left for
pkg/routing/probe_pin.go:227:			// the rollback itself fails.
pkg/daemon/daemon_natpoolalarm.go:74:// and stop+discard (bootstrap rollback / shutdown) of the monitor. The
pkg/daemon/daemon_natpoolalarm.go:121:// monitor is running (Swap returns nil). Called from bootstrap rollback
pkg/daemon/daemon.go:218:	// RUNTIME (bootstrap exit arms it; bootstrap rollback stops+discards
pkg/daemon/daemon.go:488:	// event engine, in-process CLI commits, CLI auto-rollback).
pkg/daemon/daemon.go:503:	// executeConfirmedRollback, the applyConfigLocked reconcile, and the
pkg/daemon/daemon.go:520:	// it lets bootstrap_rollback_report_test.go inject synthetic teardown
pkg/daemon/daemon.go:538:	// commit-confirmed timeout rollback re-sync (resyncRolledBackConfigToPeer,
pkg/daemon/daemon_apply_commit.go:76:// by a concurrent REST/CLI candidate edit (set/delete/load/rollback), which do
pkg/daemon/daemon_apply_commit.go:192:	// the commit conflicts and re-validates. Plain commit has no auto-rollback
pkg/daemon/daemon_apply_commit.go:315:// (applyAndSyncCommitted, #4034) and the commit-confirmed rollback re-sync
pkg/daemon/daemon_apply_commit.go:433:	// commit-confirmed rollback) landing in that post-release window, whose own
pkg/daemon/daemon_apply_commit.go:535:	// and arms a rollback timer that would re-apply after the wipe).
pkg/daemon/daemon_apply_commit.go:542:	// rollback target (the currently-active config, restored on a confirmed-commit
pkg/daemon/daemon_apply_commit.go:546:	// rollback-time abort). The pre-flight and the promotion are now bound to one
pkg/daemon/daemon_apply_commit.go:549:	// The rollback target (active) is stable across the transaction: it changes
pkg/daemon/daemon_apply_commit.go:555:			// config. The rollback target on a confirm timeout is the current
pkg/daemon/daemon_apply_commit.go:562:			// The rollback target on a confirm timeout is the current active
pkg/daemon/daemon_apply_commit.go:611:// executeConfirmedRollback is the daemon-owned commit-confirmed timeout
pkg/daemon/daemon_apply_commit.go:612:// rollback transaction (#1922 Item 1a). The configstore confirm timer
pkg/daemon/daemon_apply_commit.go:613:// fires this (via SetRollbackExecutor) on its own goroutine, NOT under
pkg/daemon/daemon_apply_commit.go:615:// state (PromoteRollback) and re-applies the rolled-back config to the
pkg/daemon/daemon_apply_commit.go:619:// fixes both bugs the old CLI-registered centralRollbackFn callback had:
pkg/daemon/daemon_apply_commit.go:625:// every store call made while applySem is held (PromoteRollback, and the
pkg/daemon/daemon_apply_commit.go:629:func (d *Daemon) executeConfirmedRollback(gen uint64) {
pkg/daemon/daemon_apply_commit.go:633:	// #5281: a confirm-timeout rollback that fires after a factory reset wipe
pkg/daemon/daemon_apply_commit.go:634:	// would PromoteRollback (re-persisting the SSOT) and re-apply the rolled-back
pkg/daemon/daemon_apply_commit.go:640:	// Pre-rollback active config (the abandoned unconfirmed config, C2) for the
pkg/daemon/daemon_apply_commit.go:641:	// #4234 deletion-clear: a rollback that removes a policy the abandoned commit
pkg/daemon/daemon_apply_commit.go:645:	prevCfg, ok := d.store.PromoteRollback(gen)
pkg/daemon/daemon_apply_commit.go:648:		// pending rollback target — nothing happened, nothing to apply.
pkg/daemon/daemon_apply_commit.go:654:		// never-committed marker (PromoteRollback). A normal apply of an
pkg/daemon/daemon_apply_commit.go:666:		// This is a fire-and-forget rollback-timer callback with no downstream
pkg/daemon/daemon_apply_commit.go:668:		// re-surface it once at the rollback-decision layer so the DEGRADED
pkg/daemon/daemon_apply_commit.go:672:			slog.Error("commit-confirmed first-commit rollback to bootstrap mode is DEGRADED: "+
pkg/daemon/daemon_apply_commit.go:681:		// rollback target below, where the standby holds a real abandoned
pkg/daemon/daemon_apply_commit.go:685:	// #1956 V-3/OQ-15.2: the non-nil rollback target is applied
pkg/daemon/daemon_apply_commit.go:688:	// pre-flight checks BOTH candidate and rollback target), so by the time
pkg/daemon/daemon_apply_commit.go:693:	// The rollback re-apply is driven with a non-cancellable context (#2926):
pkg/daemon/daemon_apply_commit.go:694:	// the store has already been promoted to the rollback target, so the
pkg/daemon/daemon_apply_commit.go:698:		slog.Error("commit confirmed auto-rollback dataplane apply failed", "err", err)
pkg/daemon/daemon_apply_commit.go:707:		slog.Error("commit confirmed auto-rollback: policy session invalidation was PARTIAL; "+
pkg/daemon/daemon_apply_commit.go:713:	// active. PromoteRollback above reverted only THIS node's store to C1;
pkg/daemon/daemon_apply_commit.go:721:	// after PromoteRollback, so the pushed text is always the rollback target.
pkg/daemon/daemon_apply_commit.go:726:// resyncRolledBackConfigToPeer pushes the just-promoted rollback-target config
pkg/daemon/daemon_apply_commit.go:728:// pushCommittedConfigToPeer so the confirm-timeout rollback path is unit-testable
pkg/daemon/daemon_apply_commit.go:729:// without a live cluster transport: rollback_resync_test.go injects
pkg/daemon/daemon_apply_commit.go:732:// PromoteRollback so d.store.ShowActive() (read inside syncConfigToPeer ->
pkg/daemon/kernel_selfrecover.go:76:		// pending — bypassing the candidate-election hold and the promote/rollback
pkg/grpcapi/server_config.go:313:	// rollback of) the pending commit-confirmed.
pkg/grpcapi/server_config.go:323:func (s *Server) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
pkg/grpcapi/server_config.go:324:	// #4589 A8-01: n==0 is the valid Junos `rollback 0` (revert to active);
pkg/grpcapi/server_config.go:327:	// range". Reject it up front with a clear message. Unlike ShowRollback
pkg/grpcapi/server_config.go:329:	// rejected. Fail-closed either way — no wrong rollback target.
pkg/grpcapi/server_config.go:332:			"invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N)
pkg/grpcapi/server_config.go:334:	if err := s.store.RollbackAs(connSessionID(ctx), int(req.N)); err != nil {
pkg/grpcapi/server_config.go:337:	return &pb.RollbackResponse{}, nil
pkg/grpcapi/server_config.go:384:	// rollback_n is a change-control selector: 0 reserves candidate-vs-active,
pkg/grpcapi/server_config.go:385:	// positive values select a 1-based rollback slot. A negative value used to
pkg/grpcapi/server_config.go:388:	if req.RollbackN < 0 {
pkg/grpcapi/server_config.go:390:			"invalid rollback_n %d: must be non-negative (0 = candidate vs active)", req.RollbackN)
pkg/grpcapi/server_config.go:392:	if req.RollbackN > 0 {
pkg/grpcapi/server_config.go:393:		diff, err := s.store.ShowCompareRollbackRedacted(int(req.RollbackN))
pkg/grpcapi/server_config.go:402:func (s *Server) ShowRollback(_ context.Context, req *pb.ShowRollbackRequest) (*pb.ShowRollbackResponse, error) {
pkg/grpcapi/server_config.go:403:	// #4556 M-01: n selects a 1-based rollback slot. A non-positive n
pkg/grpcapi/server_config.go:407:	// message, mirroring the REST show-rollback leg and the ShowCompare
pkg/grpcapi/server_config.go:408:	// rollback_n guard (#3443 M6).
pkg/grpcapi/server_config.go:411:			"invalid n %d: rollback index must be a positive integer", req.N)
pkg/grpcapi/server_config.go:416:		output, err = s.store.ShowRollbackSetRedacted(int(req.N))
pkg/grpcapi/server_config.go:418:		output, err = s.store.ShowRollbackRedacted(int(req.N))
pkg/grpcapi/server_config.go:423:	return &pb.ShowRollbackResponse{Output: output}, nil
pkg/grpcapi/server_diag_system_action.go:92:// persists the .configdb SSOT / rollback slots / journal to (#5280). Deriving it
pkg/upgrade/cutover.go:15:	// SkipStartHealthRollback disables the post-start auto-rollback (used
pkg/upgrade/cutover.go:16:	// by the HA path, where rollback is operator-driven, plan §8 inv. 8).
pkg/upgrade/cutover.go:17:	SkipStartHealthRollback bool
pkg/upgrade/cutover.go:37:	// AllowNoRollbackFirstCut sanctions a cut whose PreviousVersion is empty
pkg/upgrade/cutover.go:40:	// rollback target exists (PreviousVersion != "" — flip/start failure can
pkg/upgrade/cutover.go:42:	// sanctions a no-rollback first cut (no prior daemon to preserve). In the
pkg/upgrade/cutover.go:49:	// is refused as an unexpected loss of the rollback target rather than
pkg/upgrade/cutover.go:53:	AllowNoRollbackFirstCut bool
pkg/upgrade/cutover.go:224:	// them BEFORE any path use — including the rollback-resume below, whose
pkg/upgrade/cutover.go:239:	// Resume an interrupted auto-rollback FIRST (Codex r1 Critical#1): a
pkg/upgrade/cutover.go:240:	// crash mid-rollback must complete the rollback to PreviousVersion, not
pkg/upgrade/cutover.go:241:	// resume the failed forward cut. rollback() clears the journal on
pkg/upgrade/cutover.go:244:		r.logf("upgrade: resuming interrupted rollback to %s", j.PreviousVersion)
pkg/upgrade/cutover.go:245:		if rbErr := r.rollback(j); rbErr != nil {
pkg/upgrade/cutover.go:246:			return fmt.Errorf("resume rollback: %w", rbErr)
pkg/upgrade/cutover.go:323:			// own auto-rollback — we do NOT silently adopt an unstarted
pkg/upgrade/cutover.go:324:			// half-cut as the next rollback base.
pkg/upgrade/cutover.go:329:			// like an unhealthy half-cut and route to its auto-rollback rather
pkg/upgrade/cutover.go:343:				if rbErr := r.rollback(j); rbErr != nil {
pkg/upgrade/cutover.go:344:					return fmt.Errorf("stale half-cut unhealthy (%v) AND rollback failed: %w", finishErr, rbErr)
pkg/upgrade/cutover.go:346:				// Rollback cleared the journal and restored PreviousVersion;
pkg/upgrade/cutover.go:370:					// stale-recovery evidence) and start a NEW cut whose rollback
pkg/upgrade/cutover.go:382:						"refusing to start a new cut with an unverified rollback target while "+
pkg/upgrade/cutover.go:400:				return fmt.Errorf("current version (rollback target) is not a safe "+
pkg/upgrade/cutover.go:404:		// The rollback target RECORDED as PreviousVersion must be a genuinely
pkg/upgrade/cutover.go:409:		// a flip/start failure STOP the daemon with an unrestorable rollback
pkg/upgrade/cutover.go:415:		// The first-cut sanction (AllowNoRollbackFirstCut) is ONLY for a
pkg/upgrade/cutover.go:418:		// not-a-symlink / incomplete / I/O-unreadable) still had a rollback
pkg/upgrade/cutover.go:422:		sanctionedFirstCut := !prevPresent && opts.AllowNoRollbackFirstCut
pkg/upgrade/cutover.go:424:		// rollback target must be refused BEFORE any journal is persisted. If
pkg/upgrade/cutover.go:431:		// reads the new `current`, and proceeds with a real rollback target.
pkg/upgrade/cutover.go:449:		// rollback target, and does NOT match this cut's source generation
pkg/upgrade/cutover.go:450:		// cannot be safely replaced (RemoveAll-ing a live/rollback dir mid-cut
pkg/upgrade/cutover.go:465:		// live/rollback test rather than re-reading via an error-discarding

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'type .*Routing.*Instance|RoutingInstances|routing-instances|RoutingInstance' pkg/config --glob '*.go' | head -250
rg -n 'func \\(.*Config.*\\) Format|func \\(.*ConfigTree.*\\) Format|ShowActive\\(' pkg/config pkg/configstore --glob '*.go' --glob '"'!**/*_test.go'"' | head -200"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
pkg/config/types_routing.go:472:	RoutingInstance string   // destination routing-instance (VRF)
pkg/config/types_routing.go:637:// RoutingInstanceConfig represents a VRF-based routing instance.
pkg/config/types_routing.go:638:type RoutingInstanceConfig struct {
pkg/config/types.go:277:	RoutingInstances  []*RoutingInstanceConfig
pkg/config/compiler_static_route_disposition_conflict_5633_test.go:52:			"set routing-instances secret instance-type virtual-router",
pkg/config/compiler_static_route_disposition_conflict_5633_test.go:99:			"set routing-instances blue instance-type virtual-router",
pkg/config/compiler_static_route_disposition_conflict_5633_test.go:100:			"set routing-instances blue routing-options static route 10.9.0.0/16 discard",
pkg/config/compiler_static_route_disposition_conflict_5633_test.go:101:			"set routing-instances blue routing-options static route 10.9.0.0/16 next-hop 10.9.0.1",
pkg/config/compiler_static_route_disposition_conflict_5633_test.go:110:		if !strings.Contains(err.Error(), "routing-instances blue") {
pkg/config/compiler_static_route_disposition_conflict_5633_test.go:156:			"set routing-instances secret instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap.go:37:// DISTINCT routing-instances carry overlapping L3 address space. This is the
pkg/config/compiler_validate_vrf_overlap.go:41:// routing-instances that share a 5-tuple collide in the conntrack map. The
pkg/config/compiler_validate_vrf_overlap.go:66:// routing-instances for overlap (net/netip Prefix.Overlaps — contains-or-equal).
pkg/config/compiler_validate_vrf_overlap.go:102:	// addresses. cfg.RoutingInstances is a slice (deterministic order); each
pkg/config/compiler_validate_vrf_overlap.go:104:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_validate_vrf_overlap.go:142:			if term == nil || term.RoutingInstance == "" {
pkg/config/compiler_validate_vrf_overlap.go:147:				addPrefix(term.RoutingInstance, addr, origin)
pkg/config/compiler_validate_vrf_overlap.go:150:				addPrefix(term.RoutingInstance, addr, origin)
pkg/config/compiler_validate_vrf_overlap.go:165:	// Compare every unordered pair of distinct routing-instances. Sort RI names
pkg/config/compiler_validate_vrf_overlap.go:213:								"overlapping L3 across routing-instances is forwarded via "+
pkg/config/compiler_validate_vrf_overlap.go:221:								"overlapping L3: overlapping L3 across routing-instances is "+
pkg/config/compiler_validate_vrf_overlap_2387_test.go:10:// so two flows in different routing-instances that share a 5-tuple collide in
pkg/config/compiler_validate_vrf_overlap_2387_test.go:13:// routing-instances carry overlapping L3 address space.
pkg/config/compiler_validate_vrf_overlap_2387_test.go:44:		"set routing-instances RI-A instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:45:		"set routing-instances RI-A interface ge-0/0/1.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:46:		"set routing-instances RI-B instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:47:		"set routing-instances RI-B interface ge-0/0/2.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:65:		"set routing-instances RI-A instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:66:		"set routing-instances RI-A interface ge-0/0/1.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:67:		"set routing-instances RI-B instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:68:		"set routing-instances RI-B interface ge-0/0/2.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:81:		"set routing-instances RI-A instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:82:		"set routing-instances RI-A interface ge-0/0/1.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:83:		"set routing-instances RI-A interface ge-0/0/2.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:91:	// No routing-instances at all — plain master-table config. No warn.
pkg/config/compiler_validate_vrf_overlap_2387_test.go:102:	// The same destination prefix steered into two different routing-instances
pkg/config/compiler_validate_vrf_overlap_2387_test.go:106:		"set routing-instances RI-A instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:107:		"set routing-instances RI-B instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:128:		"set routing-instances RI-A instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:129:		"set routing-instances RI-A interface ge-0/0/1.0",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:130:		"set routing-instances RI-B instance-type virtual-router",
pkg/config/compiler_validate_vrf_overlap_2387_test.go:131:		"set routing-instances RI-B interface ge-0/0/2.0",
pkg/config/firewall_ri_output_direction_3432_test.go:13:// route lookup. validateFilterRoutingInstanceDirectionStrict makes the
pkg/config/firewall_ri_output_direction_3432_test.go:16:// FAIL-ON-REVERT: remove the validateFilterRoutingInstanceDirectionStrict
pkg/config/firewall_ri_output_direction_3432_test.go:22:		"set routing-instances blue instance-type forwarding",
pkg/config/firewall_ri_output_direction_3432_test.go:46:		"set routing-instances blue6 instance-type forwarding",
pkg/config/firewall_ri_output_direction_3432_test.go:63:		"set routing-instances blue instance-type forwarding",
pkg/config/firewall_ri_output_direction_3432_test.go:91:		"set routing-instances blue instance-type forwarding",
pkg/config/compiler_system.go:711:		RoutingInstance:      props["routing-instance"],
pkg/config/compiler_system.go:728:		p.DestinationInterface == "" && p.RoutingInstance == "" &&
pkg/config/compiler_nat_target_parity_hb167_test.go:192:func TestStaticNATThenRoutingInstanceAdvisory(t *testing.T) {
pkg/config/compiler_nat_target_parity_hb167_test.go:205:	if rule.ThenRoutingInstance != "vr-blue" {
pkg/config/compiler_nat_target_parity_hb167_test.go:206:		t.Fatalf("ThenRoutingInstance = %q, want vr-blue (target RI silently dropped)", rule.ThenRoutingInstance)
pkg/config/compiler_nat_target_parity_hb167_test.go:215:func TestStaticNATThenInetRoutingInstanceAdvisory(t *testing.T) {
pkg/config/compiler_nat_target_parity_hb167_test.go:237:	if rule.ThenRoutingInstance != "vr-green" {
pkg/config/compiler_nat_target_parity_hb167_test.go:238:		t.Fatalf("ThenRoutingInstance = %q, want vr-green", rule.ThenRoutingInstance)
pkg/config/compiler_nat_target_parity_hb167_test.go:251:// RED on revert (first-match scan): ThenRoutingInstance is recorded as the entry
pkg/config/compiler_nat_target_parity_hb167_test.go:253:func TestStaticNATThenRoutingInstanceLastOccurrence(t *testing.T) {
pkg/config/compiler_nat_target_parity_hb167_test.go:272:	if rule.ThenRoutingInstance != "MYVRF" {
pkg/config/compiler_nat_target_parity_hb167_test.go:273:		t.Fatalf("ThenRoutingInstance = %q, want MYVRF (trailing RI; a first-match scan wrongly returns the entry name %q)", rule.ThenRoutingInstance, "routing-instance")
pkg/config/compiler_nat_target_parity_hb167_test.go:281:func TestStaticNATThenPrefixNameRoutingInstanceNormal(t *testing.T) {
pkg/config/compiler_nat_target_parity_hb167_test.go:295:	if rule.ThenRoutingInstance != "MYVRF" {
pkg/config/compiler_nat_target_parity_hb167_test.go:296:		t.Fatalf("ThenRoutingInstance = %q, want MYVRF", rule.ThenRoutingInstance)
pkg/config/compiler_nat_target_parity_hb167_test.go:301:func TestDNATPoolRoutingInstanceAdvisory(t *testing.T) {
pkg/config/compiler_nat_target_parity_hb167_test.go:314:	if p == nil || p.RoutingInstance != "vr-red" {
pkg/config/compiler_nat_target_parity_hb167_test.go:315:		t.Fatalf("DNAT pool RoutingInstance not recorded (got %+v)", p)
pkg/config/compiler_nat_target_parity_hb167_test.go:323:func TestSourceNATPoolRoutingInstanceAdvisory(t *testing.T) {
pkg/config/compiler_nat_target_parity_hb167_test.go:333:	if p == nil || p.RoutingInstance != "vr-orange" {
pkg/config/compiler_nat_target_parity_hb167_test.go:334:		t.Fatalf("source pool RoutingInstance not recorded (got %+v)", p)
pkg/config/parser_ast_test.go:1140:	input := `routing-instances {
pkg/config/parser_ast_test.go:1250:	if tcpTest.RoutingInstance != "att-vr" {
pkg/config/parser_ast_test.go:1251:		t.Errorf("routing-instance: got %q, want att-vr", tcpTest.RoutingInstance)
pkg/config/parser_ast_test.go:1595:	deepCommands := []string{"set routing-instances deep-vr instance-type virtual-router", "set routing-instances deep-vr routing-options static route 10.0.0.0/8 next-hop 192.168.1.1", "set routing-instances deep-vr protocols ospf area 0.0.0.0 interface eth0", "set routing-instances deep-vr protocols bgp local-as 65001", "set routing-instances deep-vr protocols bgp group peer peer-as 65002", "set routing-instances deep-vr protocols bgp group peer neighbor 10.1.0.1"}
pkg/config/parser_ast_test.go:1609:	if len(cfg3.RoutingInstances) != 1 {
pkg/config/parser_ast_test.go:1610:		t.Errorf("expected 1 routing instance, got %d", len(cfg3.RoutingInstances))
pkg/config/parser_ast_test.go:1612:	ri := cfg3.RoutingInstances[0]
pkg/config/parser_ast_test.go:2293:	if unit0.Tunnel.RoutingInstance != "my-vrf" {
pkg/config/parser_ast_test.go:2294:		t.Errorf("tunnel routing-instance = %q, want my-vrf", unit0.Tunnel.RoutingInstance)
pkg/config/parser_ast_test.go:2545:	input := `routing-instances {
pkg/config/parser_ast_test.go:2581:func TestMultipleRoutingInstances(t *testing.T) {
pkg/config/parser_ast_test.go:2582:	input := `routing-instances {
pkg/config/parser_ast_test.go:2621:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_ast_test.go:2622:		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
pkg/config/parser_ast_test.go:2624:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2626:		if want := StableRoutingInstanceTableID(ri.Name); ri.TableID != want {
pkg/config/parser_ast_test.go:2630:	var dmzVR *RoutingInstanceConfig
pkg/config/parser_ast_test.go:2632:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2663:	var tunnelVR *RoutingInstanceConfig
pkg/config/parser_ast_test.go:2665:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2679:func TestMultipleRoutingInstancesSetSyntax(t *testing.T) {
pkg/config/parser_ast_test.go:2680:	lines := []string{"set routing-instances tunnel-vr instance-type virtual-router", "set routing-instances tunnel-vr interface tunnel0", "set routing-instances tunnel-vr routing-options static route 10.0.50.0/24 next-hop 10.0.40.1", "set routing-instances dmz-vr instance-type virtual-router", "set routing-instances dmz-vr interface dmz0", "set routing-instances dmz-vr routing-options interface-routes rib-group inet dmz-leak", "set routing-instances dmz-vr routing-options static route 0.0.0.0/0 next-hop 10.0.30.1", "set routing-options rib-groups dmz-leak import-rib dmz-vr.inet.0", "set routing-options rib-groups dmz-leak import-rib inet.0"}
pkg/config/parser_ast_test.go:2695:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_ast_test.go:2696:		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
pkg/config/parser_ast_test.go:2698:	var dmzVR *RoutingInstanceConfig
pkg/config/parser_ast_test.go:2700:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_derivations.go:31://     protocols/routing-instances are both populated.
pkg/config/compiler_derivations.go:97:	// routing-instances are populated regardless of their order under root.
pkg/config/parser_ipmonitoring_test.go:24:		"set routing-instances ISP-B instance-type virtual-router",
pkg/config/parser_ipmonitoring_test.go:50:	if master.RoutingInstance != "" || master.Destination != "0.0.0.0/0" ||
pkg/config/parser_ipmonitoring_test.go:55:	if ri.RoutingInstance != "ISP-B" || ri.NextHop != "172.16.80.1" {
pkg/config/parser_ipmonitoring_test.go:95:routing-instances {
pkg/config/parser_ipmonitoring_test.go:120:	if pol.PreferredRoutes[1].RoutingInstance != "ISP-B" {
pkg/config/host_inbound_managed_routing_mismatch_4455_test.go:96:	cfgG.RoutingInstances = []*RoutingInstanceConfig{{Name: "vr1", OSPF: ospfOn("ge-0/0/0.0")}}
pkg/config/compiler_rpm_routing_instance_2496_test.go:8:// TestRPMRoutingInstanceStrictRejects pins the #2496 commit-time gate: an
pkg/config/compiler_rpm_routing_instance_2496_test.go:22:func TestRPMRoutingInstanceStrictRejects(t *testing.T) {
pkg/config/compiler_rpm_routing_instance_2496_test.go:24:		"set routing-instances ISP-B instance-type forwarding",
pkg/config/compiler_rpm_routing_instance_2496_test.go:38:// TestRPMRoutingInstanceLenientWarns pins the no-brick contract (#1960
pkg/config/compiler_rpm_routing_instance_2496_test.go:43:func TestRPMRoutingInstanceLenientWarns(t *testing.T) {
pkg/config/compiler_rpm_routing_instance_2496_test.go:45:		"set routing-instances ISP-B instance-type forwarding",
pkg/config/compiler_rpm_routing_instance_2496_test.go:59:// TestRPMRoutingInstanceConfiguredAccepted confirms NO regression: an RPM
pkg/config/compiler_rpm_routing_instance_2496_test.go:63:func TestRPMRoutingInstanceConfiguredAccepted(t *testing.T) {
pkg/config/compiler_rpm_routing_instance_2496_test.go:66:			"set routing-instances ISP-B instance-type forwarding",
pkg/config/vrf_overlap_budget_5194_test.go:27:				RoutingInstance: ri,
pkg/config/vrf_overlap_budget_5194_test.go:36:	// Two filters so the terms land in two distinct routing-instances.
pkg/config/vrf_overlap_budget_5194_test.go:67:			{Name: "a", RoutingInstance: "vrfA", SourceAddresses: []string{"10.0.0.0/24"}},
pkg/config/vrf_overlap_budget_5194_test.go:70:			{Name: "b", RoutingInstance: "vrfB", SourceAddresses: []string{"10.0.0.0/24"}},
pkg/config/compiler_routing.go:27:	// In routing-instances, the rib name is "<instance>.inet6.0" (e.g., "ATT.inet6.0").
pkg/config/compiler_routing.go:403:func compileRoutingInstances(node *Node, cfg *Config) error {
pkg/config/compiler_routing.go:410:	// add/remove/reorder of siblings. See StableRoutingInstanceTableID.
pkg/config/compiler_routing.go:416:		ri := &RoutingInstanceConfig{
pkg/config/compiler_routing.go:418:			TableID: StableRoutingInstanceTableID(instanceName),
pkg/config/compiler_routing.go:482:		cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
pkg/config/compiler_routing.go:485:	// #3855: enforce the never-share-a-table invariant. StableRoutingInstanceTableID
pkg/config/compiler_routing.go:487:	// rare, and the strict commit gate (validateRoutingInstanceTableIDCollisionAST)
pkg/config/compiler_routing.go:493:	// routing-instance tables; the decision matches QuarantinedRoutingInstanceNames
pkg/config/compiler_routing.go:495:	if len(cfg.RoutingInstances) > 1 {
pkg/config/compiler_routing.go:496:		names := make([]string, 0, len(cfg.RoutingInstances))
pkg/config/compiler_routing.go:497:		for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_routing.go:500:		if quarantined := QuarantinedRoutingInstanceNames(names); len(quarantined) > 0 {
pkg/config/compiler_routing.go:501:			kept := cfg.RoutingInstances[:0]
pkg/config/compiler_routing.go:502:			for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_routing.go:513:			cfg.RoutingInstances = kept
pkg/config/compiler_routing.go:533:// compileProtocols/compileRoutingInstances have populated cfg.
pkg/config/compiler_routing.go:539:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_routing.go:1252:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:28:			"set routing-instances leaker instance-type virtual-router",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:29:			"set routing-instances target instance-type virtual-router",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:30:			"set routing-instances leaker routing-options static route 10.0.0.0/8 next-table target.inet.0",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:36:		if !strings.Contains(err.Error(), "routing-instances leaker") ||
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:47:			"set routing-instances leaker instance-type virtual-router",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:48:			"set routing-instances leaker routing-options static route 10.0.0.0/8 next-table Nope.inet.0",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:61:			"set routing-instances leaker instance-type virtual-router",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:62:			"set routing-instances leaker routing-options rib leaker.inet6.0 static route ::/0 next-table Nope.inet6.0",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:68:		tree := hierTree(t, `routing-instances {
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:95:		"set routing-instances leaker instance-type virtual-router",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:96:		"set routing-instances target instance-type virtual-router",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:97:		"set routing-instances leaker routing-options static route 10.0.0.0/8 next-table target.inet.0",
pkg/config/compiler_routing_nexttable_perinstance_5830_test.go:122:			"set routing-instances Comcast instance-type virtual-router",
pkg/config/firewall_ri_conflict_3308_test.go:14:// validateFilterRoutingInstanceConflictStrict still makes it an operator-visible
pkg/config/firewall_ri_conflict_3308_test.go:17:// FAIL-ON-REVERT: remove the validateFilterRoutingInstanceConflictStrict
pkg/config/firewall_ri_conflict_3308_test.go:21:func TestFilterRoutingInstanceDiscardConflict_3308(t *testing.T) {
pkg/config/firewall_ri_conflict_3308_test.go:23:		"set routing-instances blue instance-type forwarding",
pkg/config/firewall_ri_conflict_3308_test.go:46:func TestFilterRoutingInstanceRejectConflict_3308(t *testing.T) {
pkg/config/firewall_ri_conflict_3308_test.go:48:		"set routing-instances red instance-type forwarding",
pkg/config/firewall_ri_conflict_3308_test.go:67:func TestFilterRoutingInstanceConflictV6_3308(t *testing.T) {
pkg/config/firewall_ri_conflict_3308_test.go:69:		"set routing-instances blue6 instance-type forwarding",
pkg/config/firewall_ri_conflict_3308_test.go:84:func TestFilterRoutingInstanceAcceptAllowed_3308(t *testing.T) {
pkg/config/firewall_ri_conflict_3308_test.go:86:		"set routing-instances blue instance-type forwarding",
pkg/config/firewall_ri_conflict_3308_test.go:94:		"set routing-instances blue instance-type forwarding",
pkg/config/compiler_opts.go:802:	// lenientFilterRoutingInstanceConflict (#3308) downgrades the firewall-filter
pkg/config/compiler_opts.go:804:	// (validateFilterRoutingInstanceConflictStrict) from a hard compile error to
pkg/config/compiler_opts.go:813:	lenientFilterRoutingInstanceConflict bool
pkg/config/compiler_opts.go:826:	// deterministically. Sibling of lenientFilterRoutingInstanceConflict (#3308).
pkg/config/compiler_opts.go:891:	// <name>` FBF (Finding C, validateFirewallRoutingInstanceReferencesStrict)
pkg/config/compiler_opts.go:1179:	// lenientRoutingInstanceTableIDCollision (#3855) downgrades the stable
pkg/config/compiler_opts.go:1181:	// (validateRoutingInstanceTableIDCollisionAST) from a hard compile error to a
pkg/config/compiler_opts.go:1186:	// still BOOTS (#1960 no-brick); compileRoutingInstances then QUARANTINES the
pkg/config/compiler_opts.go:1189:	lenientRoutingInstanceTableIDCollision bool
pkg/config/compiler_opts.go:1360:	// lenientRPMRoutingInstance (#2496) downgrades the RPM test
pkg/config/compiler_opts.go:1362:	// (validateRPMRoutingInstanceStrict) from a hard compile error to a
pkg/config/compiler_opts.go:1374:	lenientRPMRoutingInstance bool
pkg/config/compiler_opts.go:2113:		lenientFilterRoutingInstanceConflict:   true,
pkg/config/compiler_opts.go:2139:		lenientRoutingInstanceTableIDCollision: true,
pkg/config/compiler_opts.go:2151:		lenientRPMRoutingInstance:              true,
pkg/config/compiler_dhcp_ddns_test.go:267:	if d.RoutingInstance != "VRF-WAN" {
pkg/config/compiler_dhcp_ddns_test.go:268:		t.Fatalf("routing-instance not compiled: %q", d.RoutingInstance)
pkg/config/routemap_chain_bound.go:121:	for _, ri := range cfg.RoutingInstances {
pkg/config/bgp_neighbor_peeras_2963_test.go:82:func TestBGPNeighborMissingPeerASRoutingInstanceRejected(t *testing.T) {
pkg/config/bgp_neighbor_peeras_2963_test.go:84:		"set routing-instances VR1 instance-type virtual-router",
pkg/config/bgp_neighbor_peeras_2963_test.go:85:		"set routing-instances VR1 protocols bgp local-as 65010",
pkg/config/bgp_neighbor_peeras_2963_test.go:86:		"set routing-instances VR1 protocols bgp group GEXT neighbor 10.1.1.1",
pkg/config/compiler_validate_warn.go:747:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_validate_warn.go:1057:				if rule != nil && rule.ThenRoutingInstance != "" {
pkg/config/compiler_validate_warn.go:1058:					addRI(fmt.Sprintf("static rule-set %q rule %q then static-nat routing-instance %q", rs.Name, rule.Name, rule.ThenRoutingInstance))
pkg/config/compiler_validate_warn.go:1063:			if p := cfg.Security.NAT.SourcePools[name]; p != nil && p.RoutingInstance != "" {
pkg/config/compiler_validate_warn.go:1064:				addRI(fmt.Sprintf("source pool %q routing-instance %q", name, p.RoutingInstance))
pkg/config/compiler_validate_warn.go:1069:				if p := cfg.Security.NAT.Destination.Pools[name]; p != nil && p.RoutingInstance != "" {
pkg/config/compiler_validate_warn.go:1070:					addRI(fmt.Sprintf("destination pool %q routing-instance %q", name, p.RoutingInstance))
pkg/config/router_id_2980_test.go:124:func TestRoutingInstanceRouterIDInvalidRejected(t *testing.T) {
pkg/config/router_id_2980_test.go:126:		"set routing-instances VR1 instance-type virtual-router",
pkg/config/router_id_2980_test.go:127:		"set routing-instances VR1 protocols ospf router-id nope",
pkg/config/router_id_2980_test.go:128:		"set routing-instances VR1 protocols ospf area 0.0.0.0 interface ge-0/0/1",
pkg/config/compiler_validate_strict_filter.go:219:// validateFirewallRoutingInstanceReferencesStrict hard-rejects a
pkg/config/compiler_validate_strict_filter.go:222:// defined under `routing-instances <name>`.
pkg/config/compiler_validate_strict_filter.go:241:func validateFirewallRoutingInstanceReferencesStrict(cfg *Config) error {
pkg/config/compiler_validate_strict_filter.go:245:	defined := make(map[string]bool, len(cfg.RoutingInstances))
pkg/config/compiler_validate_strict_filter.go:246:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_validate_strict_filter.go:263:				if term == nil || term.RoutingInstance == "" || defined[term.RoutingInstance] {
pkg/config/compiler_validate_strict_filter.go:268:						"routing-instance %q (define `routing-instances %s` or "+
pkg/config/compiler_validate_strict_filter.go:273:					family, name, term.Name, term.RoutingInstance, term.RoutingInstance)
pkg/config/compiler_validate_strict_filter.go:386:// validateFilterRoutingInstanceDirectionStrict hard-rejects an OUTPUT-attached
pkg/config/compiler_validate_strict_filter.go:421:func validateFilterRoutingInstanceDirectionStrict(cfg *Config) error {
pkg/config/compiler_validate_strict_filter.go:426:	hasRoutingInstance := func(filters map[string]*FirewallFilter, name string) bool {
pkg/config/compiler_validate_strict_filter.go:432:			if term != nil && term.RoutingInstance != "" {
pkg/config/compiler_validate_strict_filter.go:469:				if r.name == "" || !hasRoutingInstance(r.filters, r.name) {
pkg/config/compiler_validate_strict_filter.go:1367:// validateFilterRoutingInstanceConflictStrict hard-rejects a firewall-filter
pkg/config/compiler_validate_strict_filter.go:1383:// The conflict is on the typed fields term.RoutingInstance (the
pkg/config/compiler_validate_strict_filter.go:1393:func validateFilterRoutingInstanceConflictStrict(cfg *Config) error {
pkg/config/compiler_validate_strict_filter.go:1409:				if term == nil || term.RoutingInstance == "" {
pkg/config/compiler_validate_strict_filter.go:1420:						family, name, term.Name, term.RoutingInstance, term.Action)
pkg/config/compiler_validate_strict_filter.go:1453:// validateFilterRoutingInstanceConflictStrict, #3308.)
pkg/config/compiler_validate_strict_filter.go:1461:// validateFilterRoutingInstanceConflictStrict.
pkg/config/static_nat_mapped_port_malformed_5523_test.go:385:		if rule.ThenRoutingInstance != "mapped-port" {
pkg/config/static_nat_mapped_port_malformed_5523_test.go:386:			t.Fatalf("the routing-instance target must be captured as \"mapped-port\", got %q", rule.ThenRoutingInstance)
pkg/config/static_nat_mapped_port_malformed_5523_test.go:403:		if rule.ThenRoutingInstance != "blue" {
pkg/config/static_nat_mapped_port_malformed_5523_test.go:404:			t.Fatalf("routing-instance target want \"blue\", got %q", rule.ThenRoutingInstance)
pkg/config/compiler_bgp_as_3870_test.go:65:		"set routing-instances RED instance-type virtual-router",
pkg/config/compiler_bgp_as_3870_test.go:66:		"set routing-instances RED protocols bgp group G peer-as 65010",
pkg/config/compiler_bgp_as_3870_test.go:67:		"set routing-instances RED protocols bgp group G neighbor 10.1.0.2",
pkg/config/compiler_bgp_as_3870_test.go:68:		"set routing-instances BLUE instance-type virtual-router",
pkg/config/compiler_bgp_as_3870_test.go:69:		"set routing-instances BLUE routing-options autonomous-system 65055",
pkg/config/compiler_bgp_as_3870_test.go:70:		"set routing-instances BLUE protocols bgp group G peer-as 65020",
pkg/config/compiler_bgp_as_3870_test.go:71:		"set routing-instances BLUE protocols bgp group G neighbor 10.2.0.2",
pkg/config/compiler_bgp_as_3870_test.go:73:	var red, blue *RoutingInstanceConfig
pkg/config/compiler_bgp_as_3870_test.go:74:	for _, ri := range c.RoutingInstances {
pkg/config/compiler_undefined_ref_2217_test.go:19://     referencing a routing-instance not defined under `routing-instances`
pkg/config/compiler_undefined_ref_2217_test.go:127:func TestFBFRoutingInstanceRefUndefinedRejectedFlatSet(t *testing.T) {
pkg/config/compiler_undefined_ref_2217_test.go:142:func TestFBFRoutingInstanceRefUndefinedRejectedHierarchical(t *testing.T) {
pkg/config/compiler_undefined_ref_2217_test.go:170:func TestFBFRoutingInstanceRefDefinedCommitsFlatSet(t *testing.T) {
pkg/config/compiler_undefined_ref_2217_test.go:172:		"set routing-instances ISP-B instance-type forwarding",
pkg/config/compiler_undefined_ref_2217_test.go:180:	if got := cfg.Firewall.FiltersInet["f1"].Terms[0].RoutingInstance; got != "ISP-B" {
pkg/config/compiler_undefined_ref_2217_test.go:185:func TestFBFRoutingInstanceRefUndefinedLenientWarns(t *testing.T) {
pkg/config/parser_security_test.go:134:routing-instances {
pkg/config/parser_security_test.go:165:	if dscpFilter.Terms[0].RoutingInstance != "Comcast-GigabitPro" {
pkg/config/parser_security_test.go:166:		t.Errorf("expected routing-instance Comcast-GigabitPro, got %q", dscpFilter.Terms[0].RoutingInstance)
pkg/config/parser_security_test.go:203:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_security_test.go:204:		t.Errorf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
pkg/config/parser_security_test.go:208:	setCommands := []string{"set routing-instances ATT instance-type forwarding", "set firewall family inet filter test-filter term t1 from dscp af43", "set firewall family inet filter test-filter term t1 then routing-instance ATT", "set firewall family inet filter test-filter term default then accept"}
pkg/config/parser_security_test.go:239:	setCommands := []string{"set routing-instances sfmix instance-type forwarding", "set firewall family inet filter pbr term route from destination-address 10.255.192.40/30", "set firewall family inet filter pbr term route from destination-address 1.0.0.1/32", "set firewall family inet filter pbr term route from source-address 192.203.228.0/24", "set firewall family inet filter pbr term route from source-address 198.182.225.0/24", "set firewall family inet filter pbr term route then routing-instance sfmix"}
pkg/config/parser_security_test.go:267:	if term.RoutingInstance != "sfmix" {
pkg/config/parser_security_test.go:268:		t.Errorf("expected routing-instance sfmix, got %q", term.RoutingInstance)
pkg/config/static_nat_mapped_port_shapes_5523_test.go:306:		if rule.ThenRoutingInstance != "blue" {
pkg/config/static_nat_mapped_port_shapes_5523_test.go:307:			t.Fatalf("trailing routing-instance must be captured as blue, got %q", rule.ThenRoutingInstance)
pkg/config/compiler_nat_scope_3079_test.go:69:		if rs.FromRoutingInstance != "blue" {
pkg/config/compiler_nat_scope_3079_test.go:70:			t.Fatalf("FromRoutingInstance = %q, want blue", rs.FromRoutingInstance)
pkg/config/compiler_nat_scope_3079_test.go:99:		if rs.ToRoutingInstance != "red" {
pkg/config/compiler_nat_scope_3079_test.go:100:			t.Fatalf("ToRoutingInstance = %q, want red", rs.ToRoutingInstance)
pkg/config/compiler_nat_scope_3079_test.go:141:		if rs.FromRoutingInstance != "blue" {
pkg/config/compiler_nat_scope_3079_test.go:142:			t.Fatalf("FromRoutingInstance = %q, want blue", rs.FromRoutingInstance)
pkg/config/compiler_nat_scope_3079_test.go:176:		if rs.FromRoutingInstance != "blue" {
pkg/config/ast_format.go:13:func (t *ConfigTree) FormatInheritance() string {
pkg/config/ast_format.go:30:func (t *ConfigTree) FormatPathInheritance(path []string) string {
pkg/config/ast_format.go:81:func (t *ConfigTree) Format() string {
pkg/config/ast_format.go:151:func (t *ConfigTree) FormatPath(path []string) string {
pkg/config/ast_format.go:173:func (t *ConfigTree) FormatSet() string {
pkg/config/ast_format.go:181:func (t *ConfigTree) FormatPathSet(path []string) string {
pkg/config/ast_format.go:435:func (t *ConfigTree) FormatJSON() string {
pkg/config/ast_format.go:445:func (t *ConfigTree) FormatPathJSON(path []string) string {
pkg/config/ast_format.go:462:func (t *ConfigTree) FormatXML() string {
pkg/config/ast_format.go:472:func (t *ConfigTree) FormatPathXML(path []string) string {
pkg/configstore/store_format.go:32:func (s *Store) ShowActive() string {
pkg/configstore/store.go:773:// whitespace-normalized so it matches the ShowActive()/incoming-text comparison

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'func StableRoutingInstanceTableID|StableRoutingInstanceTableID|QuarantinedRoutingInstanceNames|validateRoutingInstanceTableIDCollision' pkg/config --glob '*.go' --glob '"'!**/*_test.go'"'
nl -ba pkg/config/types_routing.go | sed -n '625,665p'
nl -ba pkg/config/compiler_routing.go | sed -n '390,525p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
pkg/config/compiler_routing.go:410:	// add/remove/reorder of siblings. See StableRoutingInstanceTableID.
pkg/config/compiler_routing.go:418:			TableID: StableRoutingInstanceTableID(instanceName),
pkg/config/compiler_routing.go:485:	// #3855: enforce the never-share-a-table invariant. StableRoutingInstanceTableID
pkg/config/compiler_routing.go:487:	// rare, and the strict commit gate (validateRoutingInstanceTableIDCollisionAST)
pkg/config/compiler_routing.go:493:	// routing-instance tables; the decision matches QuarantinedRoutingInstanceNames
pkg/config/compiler_routing.go:500:		if quarantined := QuarantinedRoutingInstanceNames(names); len(quarantined) > 0 {
pkg/config/compiler_opts.go:1181:	// (validateRoutingInstanceTableIDCollisionAST) from a hard compile error to a
pkg/config/compiler.go:229:	riTableIDWarnings, riTableIDErr := validateRoutingInstanceTableIDCollisionAST(
pkg/config/compiler.go:397:	riTableIDWarnings, riTableIDErr := validateRoutingInstanceTableIDCollisionAST(
pkg/config/routinginstanceid.go:26:// StableRoutingInstanceTableID maps a routing-instance name to a STABLE kernel
pkg/config/routinginstanceid.go:48:func StableRoutingInstanceTableID(name string) int {
pkg/config/routinginstanceid.go:78:// for node0, View 3 for node1), used by validateRoutingInstanceTableIDCollisionAST.
pkg/config/routinginstanceid.go:103:// validateRoutingInstanceTableIDCollisionAST checks the UNION of routing-instance
pkg/config/routinginstanceid.go:104:// names across three views of the candidate config for StableRoutingInstanceTableID
pkg/config/routinginstanceid.go:124:// QUARANTINES the later-sorting colliding instance (see QuarantinedRoutingInstanceNames)
pkg/config/routinginstanceid.go:126:func validateRoutingInstanceTableIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
pkg/config/routinginstanceid.go:170:		id := StableRoutingInstanceTableID(name)
pkg/config/routinginstanceid.go:183:		// (QuarantinedRoutingInstanceNames) so two routing-instances never
pkg/config/routinginstanceid.go:195:// QuarantinedRoutingInstanceNames returns the set of routing-instance names that
pkg/config/routinginstanceid.go:197:// StableRoutingInstanceTableID collides with an earlier (alphabetically-sorted)
pkg/config/routinginstanceid.go:203:// (validateRoutingInstanceTableIDCollisionAST) makes — the later-sorting
pkg/config/routinginstanceid.go:215:// (StableRoutingInstanceTableID is a pure function of the name and the sorted
pkg/config/routinginstanceid.go:219:func QuarantinedRoutingInstanceNames(names []string) map[string]struct{} {
pkg/config/routinginstanceid.go:229:		id := StableRoutingInstanceTableID(name)
   625	// endpoint (#1434). A tunnel with no endpoint-bearing peer is
   626	// responder-only/roaming; callers (e.g. the MTU overhead pick) treat
   627	// that as the conservative v6 case.
   628	func (tc *TunnelConfig) WgHasEndpoint() bool {
   629		for _, p := range tc.WgPeers {
   630			if p.Endpoint != "" {
   631				return true
   632			}
   633		}
   634		return false
   635	}
   636	
   637	// RoutingInstanceConfig represents a VRF-based routing instance.
   638	type RoutingInstanceConfig struct {
   639		Name              string
   640		Description       string
   641		InstanceType      string         // "virtual-router" or "vrf"
   642		Interfaces        []string       // interfaces belonging to this instance
   643		StaticRoutes      []*StaticRoute // per-instance static routes
   644		Inet6StaticRoutes []*StaticRoute // per-instance rib inet6.0 static routes
   645		OSPF              *OSPFConfig    // per-instance OSPF (optional)
   646		OSPFv3            *OSPFv3Config  // per-instance OSPFv3 (optional)
   647		BGP               *BGPConfig     // per-instance BGP (optional)
   648		RIP               *RIPConfig     // per-instance RIP (optional)
   649		ISIS              *ISISConfig    // per-instance IS-IS (optional)
   650		// AutonomousSystem is this instance's `routing-options autonomous-system`
   651		// (#3870). When the instance's BGP omits `local-as`, the BGP AS is
   652		// resolved from this instance-level AS if set, else the GLOBAL
   653		// routing-options autonomous-system (Junos inheritance). 0 = unset.
   654		AutonomousSystem          uint32
   655		TableID                   int    // Linux kernel routing table number (auto-assigned)
   656		InterfaceRoutesRibGroup   string // interface-routes { rib-group inet <name>; }
   657		InterfaceRoutesRibGroupV6 string // interface-routes { rib-group inet6 <name>; }
   658	}
   390		// so the family+index separator is the LAST ".inet" occurrence, not the
   391		// first. strings.Index truncated a routing-instance NAME that itself
   392		// contained ".inet" (an accepted dotted instance, e.g. "a.inet.b" whose
   393		// table is "a.inet.b.inet.0") at the embedded ".inet", corrupting the
   394		// emitted next-table identity to "a" and misrouting the leak (#5632). Anchor
   395		// on the trailing suffix with LastIndex; for a single-".inet" table the two
   396		// are identical, so ordinary names are unaffected.
   397		if idx := strings.LastIndex(table, ".inet"); idx > 0 {
   398			return table[:idx]
   399		}
   400		return table
   401	}
   402	
   403	func compileRoutingInstances(node *Node, cfg *Config) error {
   404		// Assign each routing-instance a STABLE kernel routing table id derived from
   405		// its NAME (#3855), never a positional counter. Positional assignment
   406		// (100, 101, … by config order) renumbered every survivor after a deleted
   407		// or reordered instance, so pkg/routing/vrf.go saw a stale table id on an
   408		// UNTOUCHED VRF and deleted+recreated its live device — a forwarding outage
   409		// on an unrelated VRF, on both HA nodes. A name-hashed id is invariant under
   410		// add/remove/reorder of siblings. See StableRoutingInstanceTableID.
   411		for _, child := range node.Children {
   412			if child.IsLeaf || len(child.Keys) == 0 {
   413				continue
   414			}
   415			instanceName := child.Keys[0]
   416			ri := &RoutingInstanceConfig{
   417				Name:    instanceName,
   418				TableID: StableRoutingInstanceTableID(instanceName),
   419			}
   420	
   421			for _, prop := range child.Children {
   422				switch prop.Name() {
   423				case "description":
   424					ri.Description = nodeVal(prop)
   425				case "instance-type":
   426					ri.InstanceType = nodeVal(prop)
   427				case "interface":
   428					// Multi-value leaf (#3904): `interface [ i1 i2 ]` collapses
   429					// onto Keys[1:] (this is an opaque implicit leaf) and/or child
   430					// nodes in both AST shapes. Read EVERY interface via
   431					// firewallMatchValues; the prior nodeVal(prop) read kept only
   432					// the first, stranding the remaining ports OUTSIDE the routing-
   433					// instance (they stayed in the default table — a VRF isolation
   434					// break).
   435					ri.Interfaces = append(ri.Interfaces, firewallMatchValues(prop)...)
   436				case "routing-options":
   437					var ro RoutingOptionsConfig
   438					if err := compileRoutingOptions(prop, &ro); err != nil {
   439						return fmt.Errorf("instance %s routing-options: %w", instanceName, err)
   440					}
   441					ri.StaticRoutes = ro.StaticRoutes
   442					ri.Inet6StaticRoutes = ro.Inet6StaticRoutes
   443					// #3870: capture the instance-level autonomous-system so a
   444					// per-instance BGP that omits local-as can inherit it (falling
   445					// back to the global routing-options AS in resolveBGPAutonomousSystem).
   446					ri.AutonomousSystem = ro.AutonomousSystem
   447					// Parse interface-routes rib-group
   448					if irNode := prop.FindChild("interface-routes"); irNode != nil {
   449						if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
   450							for _, rgChild := range rgNode.Children {
   451								switch rgChild.Name() {
   452								case "inet":
   453									ri.InterfaceRoutesRibGroup = nodeVal(rgChild)
   454								case "inet6":
   455									ri.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
   456								}
   457							}
   458							// Also handle inline: "rib-group inet NAME"
   459							for i := 1; i < len(rgNode.Keys)-1; i++ {
   460								switch rgNode.Keys[i] {
   461								case "inet":
   462									ri.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
   463								case "inet6":
   464									ri.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
   465								}
   466							}
   467						}
   468					}
   469				case "protocols":
   470					var proto ProtocolsConfig
   471					if err := compileProtocols(prop, &proto); err != nil {
   472						return fmt.Errorf("instance %s protocols: %w", instanceName, err)
   473					}
   474					ri.OSPF = proto.OSPF
   475					ri.OSPFv3 = proto.OSPFv3
   476					ri.BGP = proto.BGP
   477					ri.RIP = proto.RIP
   478					ri.ISIS = proto.ISIS
   479				}
   480			}
   481	
   482			cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
   483		}
   484	
   485		// #3855: enforce the never-share-a-table invariant. StableRoutingInstanceTableID
   486		// folds into a 900k-slot reserved band so a collision is astronomically
   487		// rare, and the strict commit gate (validateRoutingInstanceTableIDCollisionAST)
   488		// rejects one outright — but if we are reached on a lenient path (tolerant
   489		// load / peer-sync / a config a pre-#3855 binary persisted) with two names
   490		// folding to the same kernel table, DROP the later-sorting instance rather
   491		// than let two vrf-<name> devices bind the same table (a cross-VRF route
   492		// leak). This is the runtime half of #3719's zone quarantine, ported to
   493		// routing-instance tables; the decision matches QuarantinedRoutingInstanceNames
   494		// exactly so both HA nodes drop the identical instance.
   495		if len(cfg.RoutingInstances) > 1 {
   496			names := make([]string, 0, len(cfg.RoutingInstances))
   497			for _, ri := range cfg.RoutingInstances {
   498				names = append(names, ri.Name)
   499			}
   500			if quarantined := QuarantinedRoutingInstanceNames(names); len(quarantined) > 0 {
   501				kept := cfg.RoutingInstances[:0]
   502				for _, ri := range cfg.RoutingInstances {
   503					if _, drop := quarantined[ri.Name]; drop {
   504						cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
   505							"routing-instance %q QUARANTINED: its stable table id %d collides with"+
   506								" another instance's — no VRF created, its routes and inter-VRF"+
   507								" leaks are not programmed until one instance is renamed (#3855)",
   508							ri.Name, ri.TableID))
   509						continue
   510					}
   511					kept = append(kept, ri)
   512				}
   513				cfg.RoutingInstances = kept
   514			}
   515		}
   516		return nil
   517	}
   518	
   519	// resolveBGPAutonomousSystem fills a BGP local-AS from `routing-options
   520	// autonomous-system` when `protocols bgp local-as` was not set (#3870).
   521	//
   522	// Junos accepts the BGP AS at TWO hierarchy points: the global
   523	// `routing-options autonomous-system <N>` (the canonical vSRX placement) and
   524	// the more specific `protocols bgp local-as <N>` override. The FRR renderer
   525	// gates `router bgp` on BGPConfig.LocalAS > 0 (policy_render.go), and only

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/config/routinginstanceid.go | sed -n '1,250p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"hash/fnv"
     6		"sort"
     7	)
     8	
     9	// RoutingInstanceTableIDBase and RoutingInstanceTableIDSpan define the reserved
    10	// kernel routing-table band for STABLE, name-hashed routing-instance table IDs
    11	// (#3855). Every configured routing-instance's kernel table lands in
    12	// [RoutingInstanceTableIDBase, RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan-1]
    13	// = [100000, 999999].
    14	//
    15	// The band sits ABOVE every other reserved kernel-table constant this project
    16	// uses — the kernel-reserved local/main/default tables (253/254/255), the mgmt
    17	// VRF table (999, pkg/daemon), and the RPM probe-pin band (ProbeTableBase
    18	// 7000..7049) — so a stable routing-instance table can never collide with any
    19	// of them. It also stays >= 100 (the historical routing-instance table floor
    20	// several callers and tests still assume) by construction.
    21	const (
    22		RoutingInstanceTableIDBase = 100000
    23		RoutingInstanceTableIDSpan = 900000 // [100000, 999999]
    24	)
    25	
    26	// StableRoutingInstanceTableID maps a routing-instance name to a STABLE kernel
    27	// routing table id: FNV-1a/64 xor-folded and mapped into the reserved band
    28	// [RoutingInstanceTableIDBase, RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan-1].
    29	//
    30	// The id is a pure function of the instance NAME alone — never of the rest of
    31	// the routing-instance set, the compile order, or allocation history. This is
    32	// the #3075 StableZoneID / #1873 StableTunnelEndpointID pattern applied to
    33	// routing-instance kernel tables:
    34	//
    35	//	Positional assignment (the pre-#3855 defect) gave instances 100, 101, 102…
    36	//	by config order, so DELETING or REORDERING one instance RENUMBERED every
    37	//	survivor that followed it. pkg/routing/vrf.go then saw the survivor's kernel
    38	//	VRF device carry a now-stale table id, DELETED it and recreated it with the
    39	//	new number — a link down/up + route reprogram, i.e. a forwarding OUTAGE on a
    40	//	VRF the operator never touched, on BOTH HA nodes.
    41	//
    42	// Deriving the table id from the NAME makes it invariant under add/remove/
    43	// reorder of siblings: an untouched instance keeps its table id, so vrf.go's
    44	// recreate-on-table-mismatch never fires spuriously. A genuine reconfig (rename
    45	// → different name → different id) still recreates correctly. Both HA nodes and
    46	// a cold-booting node compute identical ids from identical config with zero
    47	// synced/persisted state.
    48	func StableRoutingInstanceTableID(name string) int {
    49		h := fnv.New64a()
    50		_, _ = h.Write([]byte(name))
    51		s := h.Sum64()
    52		// xor-fold the high half down so the modulo samples the whole hash, then
    53		// map into the reserved band. Pure function of the name.
    54		folded := s ^ (s >> 32)
    55		return RoutingInstanceTableIDBase + int(folded%uint64(RoutingInstanceTableIDSpan))
    56	}
    57	
    58	// collectRoutingInstanceNamesAST appends the routing-instance names declared
    59	// under a "routing-instances" node into out. Mirrors compileRoutingInstances
    60	// (compiler_routing.go): each non-leaf child's Keys[0] is the instance name in
    61	// both the hierarchical and flat-set AST shapes.
    62	func collectRoutingInstanceNamesAST(riNode *Node, out map[string]struct{}) {
    63		if riNode == nil {
    64			return
    65		}
    66		for _, child := range riNode.Children {
    67			if child.IsLeaf || len(child.Keys) == 0 {
    68				continue
    69			}
    70			if name := child.Keys[0]; name != "" {
    71				out[name] = struct{}{}
    72			}
    73		}
    74	}
    75	
    76	// emitNodeExpandedRoutingInstanceNames returns the routing-instance names that
    77	// survive expanding the candidate tree for chassis-cluster node nodeID (View 2
    78	// for node0, View 3 for node1), used by validateRoutingInstanceTableIDCollisionAST.
    79	// It is the post-`${node}`/apply-groups view: a `${node}`-interpolated or
    80	// wildcard apply-group instance name is only concrete after expansion.
    81	//
    82	// It mirrors emitNodeExpandedZoneNames (zoneid.go): RECURSION-FREE by
    83	// construction (clone + expand + read the names straight off the AST, never
    84	// calling CompileConfig*), and per-node expansion errors are NON-FATAL (the
    85	// view contributes the EMPTY set), so a config that defines only `groups node0`
    86	// and references `${node}` does not turn a legitimate node1-expansion miss into
    87	// a spurious commit failure. View 1's pre-expansion union still covers any
    88	// collision inside the un-expandable group.
    89	func emitNodeExpandedRoutingInstanceNames(tree *ConfigTree, nodeID int, out map[string]struct{}) {
    90		clone := tree.Clone()
    91		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
    92		if err := clone.ExpandGroupsWithVars(vars); err != nil {
    93			return
    94		}
    95		// #5691: union across every top-level `routing-instances` root — a split
    96		// config can declare instances in a second stanza that compileSections still
    97		// compiles.
    98		for _, ri := range clone.FindChildren("routing-instances") {
    99			collectRoutingInstanceNamesAST(ri, out)
   100		}
   101	}
   102	
   103	// validateRoutingInstanceTableIDCollisionAST checks the UNION of routing-instance
   104	// names across three views of the candidate config for StableRoutingInstanceTableID
   105	// collisions (#3855), mirroring validateZoneIDCollisionAST (#3075) and
   106	// validateTunnelEndpointIDCollisionAST (#1873):
   107	//
   108	//	View 1 — the PRE-expansion presence union across the main "routing-instances"
   109	//	  hierarchy AND every "groups" block. It runs on the pre-expansion tree so
   110	//	  the check covers the union of instance names across all groups, keeping the
   111	//	  accept/reject decision identical on both chassis-cluster nodes.
   112	//	View 2 — the instance names that survive expanding the candidate for node0.
   113	//	View 3 — the same for node1.
   114	//
   115	// All three views are pure functions of the SAME candidate config, so the union
   116	// stays a pure function of config (HA symmetry preserved) and is monotone over
   117	// View 1 (Views 2/3 only ADD rejects).
   118	//
   119	// Strict (commit / commit-check) returns an error so an operator can never
   120	// commit a config whose two routing-instance names fold to the same kernel
   121	// table — two VRFs sharing a table would MERGE their routes (a cross-VRF leak).
   122	// Lenient (load / peer-sync of an already-active config) returns a warning so an
   123	// upgraded node still boots (#1960 no-brick); compileRoutingInstances then
   124	// QUARANTINES the later-sorting colliding instance (see QuarantinedRoutingInstanceNames)
   125	// so the two never actually share a kernel table.
   126	func validateRoutingInstanceTableIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
   127		names := make(map[string]struct{})
   128		// View 1 — pre-expansion presence union (main + every groups block). Union
   129		// across EVERY top-level `routing-instances` root (#5691): a split config can
   130		// declare instances in a second stanza, and compileSections compiles them
   131		// all, so a first-root-only scan would miss a collision spanning the roots.
   132		for _, ri := range tree.FindChildren("routing-instances") {
   133			collectRoutingInstanceNamesAST(ri, names)
   134		}
   135		for _, child := range tree.Children {
   136			if child.Name() != "groups" {
   137				continue
   138			}
   139			for _, group := range child.Children {
   140				// Node{Keys:["groups","node0"]} merges the group name into
   141				// Keys[1]; the children are then the group body. The other shape
   142				// nests the group name as a child node.
   143				if len(child.Keys) >= 2 {
   144					for _, ri := range child.FindChildren("routing-instances") {
   145						collectRoutingInstanceNamesAST(ri, names)
   146					}
   147					break
   148				}
   149				for _, ri := range group.FindChildren("routing-instances") {
   150					collectRoutingInstanceNamesAST(ri, names)
   151				}
   152			}
   153		}
   154		// Views 2/3 — post-expansion instance names for node0 and node1. Both
   155		// computed on both nodes from the shared candidate, so the union stays
   156		// HA-symmetric; per-node expansion errors contribute the empty set.
   157		emitNodeExpandedRoutingInstanceNames(tree, 0, names)
   158		emitNodeExpandedRoutingInstanceNames(tree, 1, names)
   159		if len(names) < 2 {
   160			return nil, nil
   161		}
   162		sorted := make([]string, 0, len(names))
   163		for name := range names {
   164			sorted = append(sorted, name)
   165		}
   166		sort.Strings(sorted)
   167		byID := make(map[int]string, len(sorted))
   168		var warnings []string
   169		for _, name := range sorted {
   170			id := StableRoutingInstanceTableID(name)
   171			owner, taken := byID[id]
   172			if !taken {
   173				byID[id] = name
   174				continue
   175			}
   176			msg := fmt.Sprintf(
   177				"routing-instance table-id collision between %q and %q (both fold to kernel table %d) — rename one instance (#3855)",
   178				owner, name, id)
   179			if !lenient {
   180				return nil, fmt.Errorf("routing-instances: %s", msg)
   181			}
   182			// Lenient: keep booting but QUARANTINE the later-sorting instance
   183			// (QuarantinedRoutingInstanceNames) so two routing-instances never
   184			// share a kernel table. Word the warning so the operator knows the box
   185			// is running degraded: the quarantined instance is dropped, its VRF is
   186			// not created and its routes/PBR/next-table leaks are not programmed
   187			// until one instance is renamed.
   188			warnings = append(warnings, fmt.Sprintf("%s; the later-sorting instance %q is QUARANTINED"+
   189				" (no VRF created, its routes and inter-VRF leaks not programmed) —"+
   190				" its forwarding is DISABLED until one instance is renamed", msg, name))
   191		}
   192		return warnings, nil
   193	}
   194	
   195	// QuarantinedRoutingInstanceNames returns the set of routing-instance names that
   196	// MUST NOT be programmed into the kernel/dataplane because their
   197	// StableRoutingInstanceTableID collides with an earlier (alphabetically-sorted)
   198	// instance's table id. For each kernel table claimed by more than one name, the
   199	// sorted-FIRST name keeps the table and every later name that folds to the same
   200	// table is quarantined.
   201	//
   202	// This is the RUNTIME enforcement of the promise the lenient collision warning
   203	// (validateRoutingInstanceTableIDCollisionAST) makes — the later-sorting
   204	// instance is dropped — so two routing-instances never share a kernel table.
   205	// Programming both would MERGE two VRFs: one instance's routes, next-table
   206	// leaks and PBR would stand in for the other (pkg/routing/vrf.go binds a
   207	// vrf-<name> device to the kernel table by number; two devices on one table is
   208	// a cross-VRF route leak). The STRICT commit path REJECTS a collision outright;
   209	// the LENIENT path (tolerant load / peer-sync / a config a pre-#3855 binary
   210	// persisted with positional ids and no stable-hash collision check) keeps
   211	// booting but quarantines the colliding instance here, preserving the #1960
   212	// no-brick intent.
   213	//
   214	// The decision is a pure function of the instance-name SET
   215	// (StableRoutingInstanceTableID is a pure function of the name and the sorted
   216	// tie-break is deterministic), so both HA nodes and a cold-booting node compute
   217	// the IDENTICAL quarantine set from the identical config. Returns nil when no
   218	// table collides (the common case).
   219	func QuarantinedRoutingInstanceNames(names []string) map[string]struct{} {
   220		if len(names) < 2 {
   221			return nil
   222		}
   223		sorted := make([]string, len(names))
   224		copy(sorted, names)
   225		sort.Strings(sorted)
   226		owner := make(map[int]string, len(sorted))
   227		var quarantined map[string]struct{}
   228		for _, name := range sorted {
   229			id := StableRoutingInstanceTableID(name)
   230			if existing, taken := owner[id]; taken {
   231				if existing == name {
   232					// Defensive: a duplicated name in the input slice is the same
   233					// instance, not a collision.
   234					continue
   235				}
   236				if quarantined == nil {
   237					quarantined = make(map[string]struct{})
   238				}
   239				quarantined[name] = struct{}{}
   240				continue
   241			}
   242			owner[id] = name
   243		}
   244		return quarantined
   245	}

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/config/types.go | sed -n '230,295p'
nl -ba pkg/configstore/store_format.go | sed -n '1,70p'
nl -ba pkg/cluster/sync_protocol.go | sed -n '670,720p'
nl -ba pkg/daemon/daemon_ha_sync.go | sed -n '350,385p;535,590p;900,920p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   230			}
   231		}
   232	
   233		// Fallback for refs not modeled in cfg.Interfaces.Interfaces:
   234		// preserve the suffix and translate slashes only.
   235		return LinuxIfName(c.ResolveReth(ref))
   236	}
   237	
   238	// DHCPLeaseKey returns the lease-lookup key that pkg/dhcp.Manager
   239	// keys leases by for the given config-level interface ref and unit
   240	// number. Mirrors the construction in
   241	// pkg/daemon/daemon_dhcp.go:56-95:
   242	//
   243	//	key = LinuxIfName(configRef) + ("." + strconv(unit.VlanID)) when > 0
   244	//
   245	// configRef is the CONFIG-LEVEL name (e.g. "reth0"), not the resolved
   246	// physical member — the daemon's DHCP Start() is invoked with the
   247	// config-level name.
   248	//
   249	// Returns ("", false) when the unit doesn't exist in cfg.
   250	func (c *Config) DHCPLeaseKey(configRef string, unitNum int) (string, bool) {
   251		configRef = strings.SplitN(configRef, ".", 2)[0]
   252		if c.Interfaces.Interfaces == nil {
   253			return "", false
   254		}
   255		ifc, ok := c.Interfaces.Interfaces[configRef]
   256		if !ok || ifc == nil {
   257			return "", false
   258		}
   259		unit, ok := ifc.Units[unitNum]
   260		if !ok || unit == nil {
   261			return "", false
   262		}
   263		key := LinuxIfName(configRef)
   264		if unit.VlanID > 0 {
   265			key = key + "." + strconv.Itoa(unit.VlanID)
   266		}
   267		return key, true
   268	}
   269	
   270	// Config is the top-level typed configuration, compiled from the AST.
   271	type Config struct {
   272		Security          SecurityConfig
   273		Interfaces        InterfacesConfig
   274		Applications      ApplicationsConfig
   275		RoutingOptions    RoutingOptionsConfig
   276		Protocols         ProtocolsConfig
   277		RoutingInstances  []*RoutingInstanceConfig
   278		Firewall          FirewallConfig
   279		ClassOfService    *ClassOfServiceConfig
   280		Services          ServicesConfig
   281		ForwardingOptions ForwardingOptionsConfig
   282		System            SystemConfig
   283		PolicyOptions     PolicyOptionsConfig
   284		Schedulers        map[string]*SchedulerConfig
   285		Chassis           ChassisConfig
   286		EventOptions      []*EventPolicy
   287		BridgeDomains     []*BridgeDomainConfig
   288		Warnings          []string // non-fatal validation warnings
   289	}
   290	
   291	// IRBToBridge returns a mapping of IRB interface reference (e.g. "irb.0") to
   292	// bridge device name (e.g. "br-bd0") for all bridge domains with a routing-interface.
   293	func IRBToBridge(bds []*BridgeDomainConfig) map[string]string {
   294		m := make(map[string]string)
   295		for _, bd := range bds {
     1	package configstore
     2	
     3	import (
     4		"encoding/json"
     5		"fmt"
     6		"strings"
     7	
     8		"github.com/psaab/xpf/pkg/config"
     9	)
    10	
    11	// ShowCandidate returns the candidate configuration as hierarchical text.
    12	func (s *Store) ShowCandidate() string {
    13		s.mu.RLock()
    14		defer s.mu.RUnlock()
    15		if s.candidate != nil {
    16			return s.candidate.Format()
    17		}
    18		return ""
    19	}
    20	
    21	// ShowCandidatePath returns the candidate configuration subtree at the given path.
    22	func (s *Store) ShowCandidatePath(path []string) string {
    23		s.mu.RLock()
    24		defer s.mu.RUnlock()
    25		if s.candidate != nil {
    26			return s.candidate.FormatPath(path)
    27		}
    28		return ""
    29	}
    30	
    31	// ShowActive returns the active configuration as hierarchical text.
    32	func (s *Store) ShowActive() string {
    33		s.mu.RLock()
    34		defer s.mu.RUnlock()
    35		return s.active.Format()
    36	}
    37	
    38	// ShowActivePath returns the active configuration subtree at the given path.
    39	func (s *Store) ShowActivePath(path []string) string {
    40		s.mu.RLock()
    41		defer s.mu.RUnlock()
    42		return s.active.FormatPath(path)
    43	}
    44	
    45	// ShowCandidateSet returns the candidate configuration as flat set commands.
    46	func (s *Store) ShowCandidateSet() string {
    47		s.mu.RLock()
    48		defer s.mu.RUnlock()
    49		if s.candidate != nil {
    50			return s.candidate.FormatSet()
    51		}
    52		return ""
    53	}
    54	
    55	// ActiveConfig returns the compiled active configuration.
    56	func (s *Store) ActiveConfig() *config.Config {
    57		s.mu.RLock()
    58		defer s.mu.RUnlock()
    59		return s.compiled
    60	}
    61	
    62	// CompileCandidate strictly compiles the current candidate WITHOUT mutating
    63	// any store state (no promote, no persist, no confirm-timer). It is the
    64	// read-only pre-commit hook the daemon's #1956 device-map commit pre-flight
    65	// uses to resolve the proposed map against live hardware BEFORE the store
    66	// promotes it — so a map that would strand management on next boot is
    67	// rejected while the operator is still connected, not at the next reboot.
    68	// Returns the same compiled config Commit() would, or the commit-check error.
    69	func (s *Store) CompileCandidate() (*config.Config, error) {
    70		s.mu.RLock()
   670	// The config-sync payload historically was the raw UTF-8 config text with no
   671	// framing. #3931 appends a monotonic config generation so the receiver can
   672	// order a rapid commit pair (C1 then C2) and refuse a reordered older config.
   673	// Because the config text is arbitrary bytes (no fixed layout to length-gate a
   674	// leading field against), the generation is carried as a TRAILING framing:
   675	//
   676	//	[config text bytes][configGenMagic (8)][gen (uint64 LE, 8)]
   677	//
   678	// A NEW receiver (decodeConfigPayload) detects the magic at the tail and peels
   679	// off the trailing 16 bytes; a payload without the magic is a LEGACY sender's
   680	// raw config text and decodes with gen=0 (applied unconditionally, preserving
   681	// the pre-#3931 behavior). The magic bytes are deliberately non-printable so
   682	// they cannot collide with real Junos config text. NOTE the one asymmetric
   683	// direction: a NEW sender's framed payload reaching a LEGACY receiver (only
   684	// possible in the brief mixed-version ISSU window) is treated by that old
   685	// receiver as config text with 16 trailing binary bytes, which its Junos
   686	// parser rejects — the config-sync apply fails and the old node retains its
   687	// current config (fail-safe, no crash, no divergence worse than today). This
   688	// is why #3931 does NOT bump SessionSyncWireVersion: that gate governs whether
   689	// SESSIONS sync at all across a mixed pair, and bumping it would break session
   690	// sync for the whole mixed-base window (the #2239 lesson). Config-gen is
   691	// additive and self-detecting via the magic.
   692	var configGenMagic = [8]byte{0x00, 0xff, 'x', 'p', 'f', 'C', 'G', 0x00}
   693	
   694	// encodeConfigPayload builds a config-sync payload carrying the config text
   695	// and a trailing generation (see the codec note above).
   696	func encodeConfigPayload(configText string, gen uint64) []byte {
   697		buf := make([]byte, 0, len(configText)+16)
   698		buf = append(buf, configText...)
   699		buf = append(buf, configGenMagic[:]...)
   700		buf = binary.LittleEndian.AppendUint64(buf, gen)
   701		return buf
   702	}
   703	
   704	// decodeConfigPayload splits a config-sync payload into its config text and
   705	// generation. A payload without the trailing configGenMagic is a legacy
   706	// sender's raw config text and yields gen=0.
   707	func decodeConfigPayload(payload []byte) (configText string, gen uint64) {
   708		if len(payload) >= 16 && bytes.Equal(payload[len(payload)-16:len(payload)-8], configGenMagic[:]) {
   709			gen = binary.LittleEndian.Uint64(payload[len(payload)-8:])
   710			return string(payload[:len(payload)-16]), gen
   711		}
   712		return string(payload), 0
   713	}
   714	
   715	// --- #5706 full-set state-sync ordering wire codec ------------------------
   716	//
   717	// IPsec SA and DHCP-server lease sync are FULL-SET pushes: each message
   718	// REPLACES the peer's held set wholesale. Two fabric receiveLoops
   719	// (conn0/conn1) process a peer's frames concurrently, so a full-set can be
   720	// delivered OUT OF ORDER across the redundant streams — a stale older set
   350	
   351	// pushConfigToPeer sends the active config to the cluster peer unconditionally
   352	// (does not check primary/secondary status). Used both by normal commit sync
   353	// and by the peer-reconnect path where the stable node pushes its config
   354	// regardless of whether it was preempted.
   355	func (d *Daemon) pushConfigToPeer() {
   356		ss := d.getSessionSync()
   357		if ss == nil {
   358			return
   359		}
   360		// Check if config sync is enabled.
   361		cfg := d.store.ActiveConfig()
   362		if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
   363			return
   364		}
   365		// Get the active config tree as text.
   366		configText := d.store.ShowActive()
   367		if configText == "" {
   368			return
   369		}
   370		ss.QueueConfig(configText)
   371		// #5863: record the reconcile marker so the level-triggered reconciler
   372		// treats this generation as already pushed on the current connection
   373		// epoch and does not redundantly re-push it. Only mark when a peer
   374		// connection is actually up — QueueConfig no-ops with no active conn, and
   375		// a later (re)connect bumps the epoch so the reconciler pushes fresh.
   376		if d.syncPeerConnected.Load() {
   377			d.markConfigSyncPushed(configText)
   378		}
   379	}
   380	
   381	// configGenerationHash reduces the active config text to a compact generation
   382	// token (#5863). The reconciler pushes at most once per (peer-connection-epoch
   383	// × generation); a new commit changes the text and therefore the generation,
   384	// so a config change while a peer stays connected re-pushes exactly once.
   385	func configGenerationHash(configText string) uint64 {
   535	// Config sync is unidirectional: primary → secondary only. If this node
   536	// is the RG0 primary (config authority), incoming config is rejected to
   537	// prevent a reconnecting secondary from overwriting the authoritative config.
   538	//
   539	// It returns nil ONLY when the config was actually applied (or already matches
   540	// the active config); a non-nil error means the apply did not take effect. The
   541	// config high-water mark advances ONLY on a nil return (M-2/#4151), so a
   542	// rejection or a compile/promote failure leaves the standby eligible for the
   543	// primary's re-push instead of being silently stranded on the prior config.
   544	func (d *Daemon) handleConfigSync(configText string) error {
   545		if d.cluster != nil && d.cluster.IsLocalPrimary(0) {
   546			slog.Warn("cluster: rejecting config sync (this node is RG0 primary)")
   547			return errConfigSyncRejectedPrimary
   548		}
   549		if d.store != nil {
   550			activeText := strings.TrimSpace(d.store.ShowActive())
   551			incomingText := strings.TrimSpace(configText)
   552			// #4957: the shortcut requires BOTH that the incoming config is the active
   553			// tree AND that the active tree actually completed its apply. SyncApply
   554			// promotes s.active BEFORE applyConfigLocked and (per the #1799
   555			// degrade-not-fail doctrine) does NOT roll it back on a non-fatal apply
   556			// failure, so active-text equality alone would treat a promoted-but-
   557			// UNAPPLIED config as converged: the primary's same-generation re-push
   558			// would take this fast path, return nil, and advance the config high-water
   559			// past a config whose dataplane never converged (a stale/disarmed standby
   560			// that reports the generation applied — visible at failover). Gating on
   561			// ActiveApplied() lets a re-push of a config whose prior apply failed fall
   562			// through to syncAndApply and RE-ATTEMPT the apply instead.
   563			if activeText == incomingText && d.store.ActiveApplied() {
   564				slog.Info("cluster: skipping config sync apply (config already matches active and is applied)",
   565					"size", len(configText))
   566				// Already converged to this config — a nil return lets the
   567				// high-water advance so a duplicate re-push is correctly skipped.
   568				return nil
   569			}
   570		}
   571		slog.Info("cluster: accepting config sync from peer", "size", len(configText))
   572	
   573		// #846: route through syncAndApply so the peer's
   574		// SyncApply(active promotion) + applyConfig run atomically
   575		// under d.applySem. Without this, a local commitAndApply could
   576		// interleave between the two and briefly leave store and kernel
   577		// disagreeing.
   578		if _, err := d.syncAndApply(context.Background(), configText, nil); err != nil {
   579			slog.Error("cluster: config sync apply failed", "err", err)
   580			return err
   581		}
   582		// #4957/#6296: on full success syncAndApply itself stamps the applied marker
   583		// — from a digest captured for the config it applied, while still holding
   584		// applySem — so a duplicate re-push takes the converged shortcut above, and a
   585		// config that only PROMOTED active but failed to apply does NOT (keeping the
   586		// high-water pinned until a retry lands). The stamp moved INTO syncAndApply
   587		// (from a post-applySem-release MarkActiveApplied here) so a concurrent
   588		// secondary-side promoter mutating s.active in the release window can no
   589		// longer make the marker key the wrong, unapplied active digest (#6296).
   590		slog.Info("cluster: config sync applied successfully")
   900							return
   901						}
   902						time.Sleep(time.Second)
   903					}
   904				}()
   905	
   906				// Wire sync stats into cluster manager for CLI display.
   907				d.cluster.SetSyncStats(ss)
   908	
   909				// Wire config sync callback: when secondary receives config from primary.
   910				ss.OnConfigReceived = func(configText string) error {
   911					d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
   912					return d.handleConfigSync(configText)
   913				}
   914	
   915				// #6387: surface a persistent config-sync APPLY failure as a
   916				// node-global CF monitor-failure / degraded health. configApplyLoop
   917				// fires this on the time-based stale-duration edge (raise) and on
   918				// the first post-failure success (clear); the cluster manager stores
   919				// it as a diagnostic-only annotation. This never gates failover —
   920				// manual failover stays gated solely by ConfigStale(); crash

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'ConfigSync' pkg/config pkg/daemon pkg/cluster --glob '*.go' --glob '"'!**/*_test.go'"'
nl -ba pkg/config/types_chassis.go 2>/dev/null | sed -n '1,180p'
rg -n 'config-sync' pkg/config --glob '*.go' --glob '"'!**/*_test.go'"' | head -100"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
pkg/cluster/readiness.go:9:// maxConfigSyncReasonLen bounds the stored/rendered config-sync failure reason
pkg/cluster/readiness.go:11:const maxConfigSyncReasonLen = 200
pkg/cluster/readiness.go:13:// SetConfigSyncHealth records the node-global config-sync APPLY health (#6387),
pkg/cluster/readiness.go:17:// bounded/sanitized (sanitizeConfigSyncReason) before storage so an arbitrary
pkg/cluster/readiness.go:25:func (m *Manager) SetConfigSyncHealth(failing bool, reason string) {
pkg/cluster/readiness.go:30:		m.configSyncFailReason = sanitizeConfigSyncReason(reason)
pkg/cluster/readiness.go:36:// sanitizeConfigSyncReason reduces an apply error to a single bounded status
pkg/cluster/readiness.go:42:func sanitizeConfigSyncReason(reason string) string {
pkg/cluster/readiness.go:50:	if r := []rune(reason); len(r) > maxConfigSyncReasonLen {
pkg/cluster/readiness.go:51:		reason = string(r[:maxConfigSyncReasonLen]) + "…"
pkg/cluster/status.go:343:		configNano := syncStats.LastConfigSyncTime
pkg/cluster/status.go:347:				configTime.Format("Jan 02 15:04:05"), syncStats.LastConfigSyncSize)
pkg/cluster/status.go:371:	cfgEvents := m.history.Events(EventConfigSync)
pkg/cluster/manager.go:348:	// takeover stays ungated). Set via SetConfigSyncHealth; guarded by m.mu.
pkg/cluster/events.go:17:	EventConfigSync                      // config sync events
pkg/cluster/events.go:32:	case EventConfigSync:
pkg/cluster/sync_conn_read.go:300:		s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
pkg/cluster/sync_conn_read.go:302:		s.stats.LastConfigSyncSize.Store(uint64(len(configText)))
pkg/cluster/sync_conn_config.go:15:// daemon's level-triggered reconcileConfigSyncToPeer is idempotent after the
pkg/cluster/sync_conn_config.go:64:// (daemon reconcileConfigSyncToPeer is level-triggered but idempotent), so a
pkg/cluster/sync_conn_config.go:105:	// SetConfigSyncHealth, a cheap two-field setter under m.mu, so the fixed
pkg/cluster/sync_conn_config.go:358:				// Debug, not Warn: handleConfigSync (the callback) already logs
pkg/daemon/daemon_apply_commit.go:281:	// the new primary syncs this same config back, handleConfigSync's converged
pkg/daemon/daemon_apply_commit.go:414:	// incoming text, the next equal-active-text re-push takes handleConfigSync's
pkg/daemon/daemon_apply_commit.go:430:	// re-read of s.active at stamp time. Before #6296 handleConfigSync stamped
pkg/daemon/daemon_apply_commit.go:445:		// #5578: surface a PARTIAL session invalidation to handleConfigSync
pkg/daemon/daemon_apply_commit.go:469:		// session-invalidation), matching the prior handleConfigSync gate which
pkg/daemon/daemon_apply_commit.go:473:		// marked applied — the #4957 invariant handleConfigSync's shortcut relies on.
pkg/daemon/daemon_apply_commit.go:583:// (rg0ConfigSyncAuthority) — the same rule the push site (syncConfigToPeer)
pkg/daemon/daemon_apply_commit.go:601:	return d.commitAndApply(ctx, comment, rg0ConfigSyncAuthority(d.cluster))
pkg/daemon/daemon_apply_commit.go:608:	return d.commitConfirmedAndApply(ctx, minutes, rg0ConfigSyncAuthority(d.cluster))
pkg/daemon/daemon_apply.go:63:	// takes handleConfigSync's converged shortcut instead of pointlessly
pkg/daemon/daemon_apply.go:68:	// never marked applied — the same #4957 invariant handleConfigSync relies on.
pkg/cluster/sync.go:185:	LastConfigSyncTime atomic.Int64
pkg/cluster/sync.go:186:	LastConfigSyncSize atomic.Uint64
pkg/cluster/sync.go:225:	LastConfigSyncTime         int64
pkg/cluster/sync.go:226:	LastConfigSyncSize         uint64
pkg/cluster/sync.go:361:	// and empty on a clear. The daemon wires this to Manager.SetConfigSyncHealth
pkg/cluster/sync.go:958:	return SyncStatsSnapshot{SessionsSent: s.stats.SessionsSent.Load(), SessionsReceived: s.stats.SessionsReceived.Load(), SessionsInstalled: s.stats.SessionsInstalled.Load(), DeletesSent: s.stats.DeletesSent.Load(), DeletesReceived: s.stats.DeletesReceived.Load(), BulkSyncs: s.stats.BulkSyncs.Load(), ConfigsSent: s.stats.ConfigsSent.Load(), ConfigsReceived: s.stats.ConfigsReceived.Load(), ConfigsStaleIgnored: s.stats.ConfigsStaleIgnored.Load(), ConfigsApplyFailed: s.stats.ConfigsApplyFailed.Load(), IPsecSASent: s.stats.IPsecSASent.Load(), IPsecSAReceived: s.stats.IPsecSAReceived.Load(), IPsecSAStaleIgnored: s.stats.IPsecSAStaleIgnored.Load(), DHCPLeasesSent: s.stats.DHCPLeasesSent.Load(), DHCPLeasesReceived: s.stats.DHCPLeasesReceived.Load(), DHCPLeasesStaleIgnored: s.stats.DHCPLeasesStaleIgnored.Load(), DHCPLeasesSeeded: s.stats.DHCPLeasesSeeded.Load(), FencesSent: s.stats.FencesSent.Load(), FencesReceived: s.stats.FencesReceived.Load(), Errors: s.stats.Errors.Load(), DeletesDropped: s.stats.DeletesDropped.Load(), DeletesStaleIgnored: s.stats.DeletesStaleIgnored.Load(), InstallsStaleIgnored: s.stats.InstallsStaleIgnored.Load(), SessionsStaleConfigIgnored: s.stats.SessionsStaleConfigIgnored.Load(), GenMapOverflow: s.stats.GenMapOverflow.Load(), PreAuthRejected: s.stats.PreAuthRejected.Load(), Connected: s.stats.Connected.Load(), ActiveFabric: activeFabric, BulkSyncStartTime: s.stats.BulkSyncStartTime.Load(), BulkSyncEndTime: s.stats.BulkSyncEndTime.Load(), BulkSyncSessions: s.stats.BulkSyncSessions.Load(), LastConfigSyncTime: s.stats.LastConfigSyncTime.Load(), LastConfigSyncSize: s.stats.LastConfigSyncSize.Load(), LastFenceSeq: s.stats.LastFenceSeq.Load(), LastFenceAckAt: s.stats.LastFenceAckAt.Load()}
pkg/daemon/daemon_nft_netlink.go:57:// (cluster.Manager.SetConfigSyncHealth is fed applyErr.Error() by PR-1) name the
pkg/daemon/daemon_ha.go:450:		d.reconcileConfigSyncToPeer("rg0-promotion")
pkg/daemon/daemon_ha_sync.go:318:// rg0ConfigSyncAuthority is the SINGLE, transport-independent rule for whether
pkg/daemon/daemon_ha_sync.go:332:func rg0ConfigSyncAuthority(cl *cluster.Manager) bool {
pkg/daemon/daemon_ha_sync.go:345:	if !rg0ConfigSyncAuthority(d.cluster) {
pkg/daemon/daemon_ha_sync.go:362:	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
pkg/daemon/daemon_ha_sync.go:377:		d.markConfigSyncPushed(configText)
pkg/daemon/daemon_ha_sync.go:402:// markConfigSyncPushed records that configText's generation has been pushed to
pkg/daemon/daemon_ha_sync.go:407:func (d *Daemon) markConfigSyncPushed(configText string) {
pkg/daemon/daemon_ha_sync.go:417:// reconcileConfigSyncToPeer is the level-triggered config-sync reconciler
pkg/daemon/daemon_ha_sync.go:440:func (d *Daemon) reconcileConfigSyncToPeer(reason string) {
pkg/daemon/daemon_ha_sync.go:451:	if !rg0ConfigSyncAuthority(d.cluster) {
pkg/daemon/daemon_ha_sync.go:463:	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
pkg/daemon/daemon_ha_sync.go:521:			d.reconcileConfigSyncToPeer("reconcile-loop")
pkg/daemon/daemon_ha_sync.go:526:// errConfigSyncRejectedPrimary is returned by handleConfigSync when this node
pkg/daemon/daemon_ha_sync.go:532:var errConfigSyncRejectedPrimary = errors.New("config sync rejected: this node is RG0 primary")
pkg/daemon/daemon_ha_sync.go:534:// handleConfigSync processes a config received from the cluster peer.
pkg/daemon/daemon_ha_sync.go:544:func (d *Daemon) handleConfigSync(configText string) error {
pkg/daemon/daemon_ha_sync.go:547:		return errConfigSyncRejectedPrimary
pkg/daemon/daemon_ha_sync.go:911:				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
pkg/daemon/daemon_ha_sync.go:912:				return d.handleConfigSync(configText)
pkg/daemon/daemon_ha_sync.go:923:				d.cluster.SetConfigSyncHealth(failing, reason)
pkg/daemon/daemon_ha_sync.go:928:			// edge — reconcileConfigSyncToPeer re-evaluates the RG0-authority +
pkg/daemon/daemon_ha_sync.go:956:				d.reconcileConfigSyncToPeer("peer-connect")
pkg/daemon/daemon_run_servers.go:55:// (rg0ConfigSyncAuthority) and is transport-independent — the #5054 invariant.
pkg/config/compiler_system.go:1873:		ch.Cluster.ConfigSync = true
pkg/config/types_chassis.go:113:	ConfigSync          bool   // enable config synchronization to peer on commit
     1	package config
     2	
     3	// Chassis cluster, redundancy groups, interface/IP monitoring, event
     4	// policies, and bridge domains.
     5	
     6	// ChassisConfig holds chassis-level configuration (clustering, etc).
     7	type ChassisConfig struct {
     8		Cluster *ClusterConfig
     9		// DeviceMap is the #1956 bare-metal stable-identity managed allowlist.
    10		// nil OR an empty entry set means positional mode (today's behavior);
    11		// device-map mode is selected on len(DeviceMap.Entries) > 0, never on
    12		// DeviceMap != nil (an empty `chassis device-map {}` block must not
    13		// trip the silent-all-unconfigured trap — R-7/V-7).
    14		DeviceMap *DeviceMapConfig
    15	}
    16	
    17	// DeviceMapConfig is the #1956 bare-metal device-map: an opt-in stanza that
    18	// binds host NICs (by stable identity — PCI bus address with permanent-MAC
    19	// fallback) to xpf logical names, and governs everything NOT named here via
    20	// UnmappedPolicy. See docs/bare-metal-device-map.md and the plan in
    21	// docs/research/1956-bare-metal-device-map/.
    22	type DeviceMapConfig struct {
    23		// Entries binds each logical name to a stable host identity.
    24		Entries []DeviceMapEntry
    25		// UnmappedPolicy governs NICs with no entry:
    26		//   "leave-alone" (default in device-map mode): never renamed, never
    27		//                 marked always-down, never address-stripped.
    28		//   "manage-down": today's claim-all behavior (bring unconfigured NICs
    29		//                 down). Provided for operators who DO want xpf to own
    30		//                 the whole box.
    31		UnmappedPolicy string
    32	}
    33	
    34	// DeviceMapPolicyLeaveAlone / DeviceMapPolicyManageDown are the two
    35	// unmapped-interface-policy values. Leave-alone is the bare-metal default.
    36	const (
    37		DeviceMapPolicyLeaveAlone = "leave-alone"
    38		DeviceMapPolicyManageDown = "manage-down"
    39	)
    40	
    41	// DeviceMapKey* are the per-entry identity key-order values (V-5). The
    42	// default (empty) is treated as pci-then-mac.
    43	const (
    44		DeviceMapKeyPCIThenMAC = "pci-then-mac"
    45		DeviceMapKeyMACThenPCI = "mac-then-pci"
    46		DeviceMapKeyPCI        = "pci"
    47		DeviceMapKeyMAC        = "mac"
    48	)
    49	
    50	// DeviceMapEntry binds one xpf logical name to one host NIC identity.
    51	type DeviceMapEntry struct {
    52		// LogicalName is the xpf/vSRX name the bound NIC is renamed to
    53		// (e.g. "ge-0/0/3", "fxp0"). Stored Junos-style with slashes; the
    54		// daemon converts to the Linux kernel name (ge-0-0-3) via LinuxIfName.
    55		LogicalName string
    56		// PCIAddr is the primary identity key (DDDD:BB:DD.F), "" if unset.
    57		PCIAddr string
    58		// MAC is the permanent/factory-MAC fallback key, "" if unset. Compared
    59		// against PermHWAddr, never the running MAC (RETH virtual-MAC alternates
    60		// — R-3/R-6).
    61		MAC string
    62		// KeyOrder selects the resolution priority chain (DeviceMapKey*).
    63		// "" => pci-then-mac.
    64		KeyOrder string
    65	}
    66	
    67	// EffectiveKeyOrder returns the entry's key-order, defaulting empty to
    68	// pci-then-mac.
    69	func (e DeviceMapEntry) EffectiveKeyOrder() string {
    70		if e.KeyOrder == "" {
    71			return DeviceMapKeyPCIThenMAC
    72		}
    73		return e.KeyOrder
    74	}
    75	
    76	// EffectiveUnmappedPolicy returns the device-map's unmapped-interface-policy,
    77	// defaulting empty to leave-alone (the bare-metal-safe default — an operator
    78	// who wrote a map clearly wants selective management).
    79	func (d *DeviceMapConfig) EffectiveUnmappedPolicy() string {
    80		if d == nil || d.UnmappedPolicy == "" {
    81			return DeviceMapPolicyLeaveAlone
    82		}
    83		return d.UnmappedPolicy
    84	}
    85	
    86	// Active reports whether device-map mode is engaged: a non-nil config with at
    87	// least one entry. An empty `device-map {}` block is positional mode (R-7).
    88	func (d *DeviceMapConfig) Active() bool {
    89		return d != nil && len(d.Entries) > 0
    90	}
    91	
    92	// ClusterConfig defines chassis cluster settings for HA.
    93	type ClusterConfig struct {
    94		ClusterID int
    95		NodeID    int
    96		// NodeIDSet records whether the `chassis cluster node` leaf was
    97		// actually present (and parsed to an integer) in the compiled config,
    98		// as opposed to NodeID sitting at its zero default. It is load-bearing
    99		// for the node-identity cross-check (#4185): a config that carries a
   100		// cluster stanza but no explicit `node` leaf must NOT be treated as
   101		// "node 0" when reconciling against the /etc/xpf/node-id file, or an
   102		// absent leaf on a node-1 box would false-reject as a mismatch.
   103		NodeIDSet           bool
   104		RethCount           int
   105		HeartbeatInterval   int    // milliseconds, 0=default(1000)
   106		HeartbeatThreshold  int    // missed heartbeats before lost, 0=default(3)
   107		ControlInterface    string // interface for heartbeat traffic (e.g. "hb0")
   108		PeerAddress         string // peer node's control link IP (e.g. "10.99.0.2")
   109		FabricInterface     string // interface for session/config sync (e.g. "fab0")
   110		FabricPeerAddress   string // peer's fabric link IP (e.g. "10.99.1.2")
   111		Fabric1Interface    string // secondary fabric interface (e.g. "fab1")
   112		Fabric1PeerAddress  string // peer's secondary fabric IP
   113		ConfigSync          bool   // enable config synchronization to peer on commit
   114		ControlLinkRecovery bool   // enable control-link-recovery
   115		// ControlLinkAuthKey is the #4107 shared PSK that authenticates cluster
   116		// control-channel messages. When set, the heartbeat/election channel is
   117		// signed with HMAC-SHA256; a forged or unauthenticated heartbeat is
   118		// rejected once BOTH nodes carry the key (dual-accept during a rolling
   119		// upgrade so a mixed-version cluster does not split-brain). ${node}-
   120		// agnostic: the SAME key on both nodes, synced by config-sync. Secret-
   121		// typed so it is redacted on every show/log/JSON/YAML path and never
   122		// echoed into an error string.
   123		ControlLinkAuthKey    Secret
   124		NATStateSync          bool   // enable NAT state synchronization (session sync with NAT fields)
   125		IPsecSASync           bool   // enable IPsec SA synchronization (connection name sync for failover re-initiation)
   126		DHCPLeaseSync         bool   // enable DHCP-server lease synchronization (#2239 PATH C: lease state held on standby, seeded into Kea on takeover)
   127		RethAdvertiseInterval int    // RETH VRRP advertisement interval in milliseconds, 0=default(30)
   128		HitlessRestart        bool   // preserve BPF state on shutdown (default false in HA — fail-closed)
   129		PeerFencing           string // peer fencing action on heartbeat timeout: "", "disable-rg"
   130		TakeoverHoldTime      int    // milliseconds, 0=immediate takeover once ready
   131		NoRethVRRP            bool   // cluster directly manages VIPs (no VRRP for RETH interfaces)
   132		PrivateRGElection     bool   // election over control link only, suppress RETH VRRP
   133		RedundancyGroups      []*RedundancyGroup
   134	}
   135	
   136	// RedundancyGroup defines a cluster redundancy group.
   137	type RedundancyGroup struct {
   138		ID                 int
   139		NodePriorities     map[int]int // node-id -> priority
   140		GratuitousARPCount int
   141		Preempt            bool
   142		StrictVIPOwnership bool
   143		InterfaceMonitors  []*InterfaceMonitor
   144		IPMonitoring       *IPMonitoring
   145	}
   146	
   147	// InterfaceMonitor defines an interface health monitor within a redundancy group.
   148	type InterfaceMonitor struct {
   149		Interface string
   150		Weight    int
   151	}
   152	
   153	// IPMonitoring defines IP reachability monitoring for a redundancy group.
   154	type IPMonitoring struct {
   155		GlobalWeight    int
   156		GlobalThreshold int
   157		Targets         []*IPMonitorTarget
   158	}
   159	
   160	// IPMonitorTarget defines a single IP address to probe for reachability.
   161	type IPMonitorTarget struct {
   162		Address string
   163		Weight  int
   164	}
   165	
   166	// EventPolicy defines an event-driven policy (event-options).
   167	type EventPolicy struct {
   168		Name            string
   169		Events          []string
   170		WithinClauses   []*EventWithin
   171		AttributesMatch []string // raw "field matches pattern" strings
   172		ThenCommands    []string // change-configuration commands
   173	}
   174	
   175	// EventWithin defines a temporal trigger clause.
   176	type EventWithin struct {
   177		Seconds      int
   178		TriggerOn    int // trigger on N
   179		TriggerUntil int // trigger until N
   180	}
pkg/config/compiler_security_addressbook.go:278:	// config-sync / validation. Each set gets a direct-address set and a
pkg/config/zoneid.go:108://	  zone must fail commit on node1 too, or config-sync would split (originator
pkg/config/compiler_interface_range.go:300:	// reachable at commit AND on the tolerant / HA config-sync load path).
pkg/config/compiler_ipsec_trafficselector.go:89:					// but the hierarchical / load-merge / HA-config-sync parse path
pkg/config/tunnelid.go:214://	  config-sync would split (originator accepts, peer rejects).
pkg/config/ast_groups.go:15:	// exhaust the goroutine stack on commit / HA config-sync. A legitimate Junos
pkg/config/schema_chassis.go:105:		// nodes — ${node}-agnostic, synced by config-sync. Secret-typed
pkg/config/compiler_system.go:1307:				// config-sync paths (a warn-and-keep-last-writer gate would
pkg/config/types_chassis.go:120:	// agnostic: the SAME key on both nodes, synced by config-sync. Secret-
pkg/config/compiler_peer_effective_snat.go:50:	// Compile the peer view the SAME way the standby ingests a config-synced
pkg/config/types_system.go:1663:	// config-sync — no per-lease replication is needed for the static case
pkg/config/compiler_interface_unit_alias.go:73://	  config-sync would split — originator accepts, peer rejects).
pkg/config/interfaces_iter.go:5:// The lenient load / HA config-sync path admits PRESENT-BUT-NIL InterfaceConfig
pkg/config/interfaces_iter.go:49:// slot (tolerant load / HA config-sync, #3494/#5068) as ABSENT — a read-only
pkg/config/parser.go:32:// entry point that parses a config blob: config load/commit, HA config-sync, and

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'type Store struct|rollback.*\\[|history|RollbackAs|func \\(s \\*Store\\) Rollback|CommitAs|func \\(s \\*Store\\) Commit' pkg/configstore --glob '*.go' --glob '"'!**/*_test.go'"'
nl -ba pkg/configstore/store.go | sed -n '1,130p;520,700p;730,820p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
pkg/configstore/store.go:15://     confirm-timer machinery, and rollback-history
pkg/configstore/store.go:62:type Store struct {
pkg/configstore/store.go:67:	history   *History
pkg/configstore/store.go:272:	// path — but the text rollback history (loadRollbackHistory reads it at
pkg/configstore/store.go:313:		history:                NewHistory(50),
pkg/configstore/store.go:681:	// Push current active to history.
pkg/configstore/store.go:682:	s.history.Push(&HistoryEntry{
pkg/configstore/history.go:1:// Package configstore provides history management for config store.
pkg/configstore/history.go:18:// History is a fixed-size ring buffer for configuration history.
pkg/configstore/history.go:34:// MaxSize returns the maximum history size.
pkg/configstore/history.go:39:// Len returns the current number of entries in the history.
pkg/configstore/history.go:56:		return nil, fmt.Errorf("history position %d out of range [0, %d)", n, h.size)
pkg/configstore/factory_reset.go:194://     (prior-tenant commit history; legacy fat lines may carry full config).
pkg/configstore/store_persist.go:95:		// history, so the recovery the daemon advertises ("fix the config from
pkg/configstore/store_persist.go:100:		// history. Without this, s.active stayed the empty New() tree and the
pkg/configstore/store_persist.go:101:		// history was never loaded — the operator saw an empty config and no
pkg/configstore/store_persist.go:333:// commit and only history.MaxSize() of them are kept.
pkg/configstore/store_persist.go:830:	// AtomicGeneratedConfig (#1894): archives are best-effort history
pkg/configstore/store_persist.go:851:// durably persist its text rollback history files (#3441 L1). The commit
pkg/configstore/store_persist.go:853:// #1799 path — but loadRollbackHistory would read a stale/lossy history
pkg/configstore/store_persist.go:856:func (s *Store) RollbackHistoryDegraded() bool {
pkg/configstore/journal/journal.go:6:// history view re-read and re-unmarshaled the entire file — O(lifetime
pkg/configstore/journal/journal.go:24:// an over-threshold legacy file to segment .1 intact, so old history
pkg/configstore/journal/journal.go:57:// full-config history, saveRollbackFiles in pkg/configstore) carry the
pkg/configstore/store_commit.go:52:// history entry and the durable JSONL audit journal.
pkg/configstore/store_commit.go:58:// history / `show system commit` views after allocating memory and disk
pkg/configstore/store_commit.go:69:func (s *Store) CommitCheck() (*config.Config, error) {
pkg/configstore/store_commit.go:89:func (s *Store) Commit() (*config.Config, error) {
pkg/configstore/store_commit.go:94:// with an optional comment/description attached to the history and journal entries.
pkg/configstore/store_commit.go:102:// change, no history push, no journal entry, no rollback-file save.
pkg/configstore/store_commit.go:105:func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
pkg/configstore/store_commit.go:122:func (s *Store) CommitWithDescriptionGen(description string, expectedGen uint64) (*config.Config, error) {
pkg/configstore/store_commit.go:213:	// Push current active to history with description
pkg/configstore/store_commit.go:214:	s.history.Push(&HistoryEntry{
pkg/configstore/store_commit.go:368:func (s *Store) CommitConfirmed(minutes int) (*config.Config, error) {
pkg/configstore/store_commit.go:385:func (s *Store) CommitConfirmedGen(minutes int, expectedGen uint64) (*config.Config, error) {
pkg/configstore/store_commit.go:481:	// Push current active to history
pkg/configstore/store_commit.go:482:	s.history.Push(&HistoryEntry{
pkg/configstore/store_commit.go:730:func (s *Store) ConfirmCommit() error { return s.ConfirmCommitAs("") }
pkg/configstore/store_commit.go:732:// ConfirmCommitAs is ConfirmCommit scoped to a config-lock holder session
pkg/configstore/store_commit.go:736:func (s *Store) ConfirmCommitAs(sessionID string) error {
pkg/configstore/store_commit.go:965:func (s *Store) Rollback(n int) error { return s.RollbackAs("", n) }
pkg/configstore/store_commit.go:967:// RollbackAs is Rollback scoped to a config-lock holder session (#5059).
pkg/configstore/store_commit.go:969:func (s *Store) RollbackAs(sessionID string, n int) error {
pkg/configstore/store_commit.go:1017:	entry, err := s.history.Get(n - 1)
pkg/configstore/store_commit.go:1027:// ListHistory returns all history entries, most recent first (goroutine-safe).
pkg/configstore/store_commit.go:1031:	return s.history.List()
pkg/configstore/store_commit.go:1088:func (s *Store) CommitDiffSummary() string {
pkg/configstore/store_commit.go:1136:// saveRollbackFiles writes rollback history entries to numbered files.
pkg/configstore/store_commit.go:1140:// are the CANONICAL rollback history (loadRollbackHistory reads them at
pkg/configstore/store_commit.go:1153:	entries := s.history.List() // most-recent-first
pkg/configstore/store_commit.go:1196:	// degraded text rollback history with no signal. Record the loss in a
pkg/configstore/store_commit.go:1204:			Detail: "one or more rollback history files failed to persist; rollback history may be stale after restart",
pkg/configstore/store_commit.go:1218:	for i := startN; i <= s.history.MaxSize()+1; i++ {
pkg/configstore/store_commit.go:1230:// loadRollbackHistory reads numbered rollback files and populates the history.
pkg/configstore/store_commit.go:1238:	for i := 1; i <= s.history.MaxSize(); i++ {
pkg/configstore/store_commit.go:1246:			// history still loads.
pkg/configstore/store_commit.go:1308:		s.history.Push(entries[i])
pkg/configstore/store_commit.go:1312:		slog.Info("loaded rollback history", "entries", len(entries))
     1	// Package configstore implements the Junos-style candidate/active
     2	// configuration management with commit and rollback support.
     3	//
     4	// The Store type is split across several same-package files for
     5	// readability (#2158 code-motion, no behavior change):
     6	//   - store.go         — Store struct, New, node/cluster accessors, the
     7	//     compile/schema-validate pipeline, SyncApply
     8	//   - store_persist.go — Load/Save, writeActive*, journal helpers, the
     9	//     #1799 degrade-and-retry persist machinery,
    10	//     config archival, and rescue config
    11	//   - store_lock.go    — config-mode enter/exit locking + edit-path nav
    12	//   - store_command.go — candidate edit verbs (set/delete/copy/...) and
    13	//     the flat-line replay (LoadSet/LoadMerge/...)
    14	//   - store_commit.go  — commit / commit-confirmed / rollback, the
    15	//     confirm-timer machinery, and rollback-history
    16	//     file persistence
    17	//   - store_format.go  — the Show* render family + read-only accessors
    18	package configstore
    19	
    20	import (
    21		"crypto/sha256"
    22		"encoding/hex"
    23		"fmt"
    24		"log/slog"
    25		"path/filepath"
    26		"strings"
    27		"sync"
    28		"sync/atomic"
    29		"time"
    30	
    31		"github.com/psaab/xpf/pkg/config"
    32		"github.com/psaab/xpf/pkg/configstore/journal"
    33	)
    34	
    35	// JournalEntry is the audit-log record type, owned by the journal
    36	// subpackage since #1896 (compact v2 entries: no config payloads —
    37	// full trees live in the rollback slots; see journal.Entry).
    38	type JournalEntry = journal.Entry
    39	
    40	// MaxConfigSize bounds a single configuration payload accepted by any parse
    41	// entry point: LoadOverride, LoadMerge, LoadSet, and the HA SyncApply ingress.
    42	// Real configurations are well under 1 MiB; this generous 16 MiB ceiling
    43	// rejects a hostile or corrupt payload with a clean error before the parser
    44	// runs, so a pathological input cannot exhaust memory or (together with the
    45	// pkg/config lexer/depth guards) the goroutine stack. It is the
    46	// transport-independent backstop for the grpc.MaxRecvMsgSize / http
    47	// .MaxBytesReader caps, covering any caller — a future one, or an HA peer —
    48	// that reaches these methods without passing through the gRPC/REST limits
    49	// (fable-review-164 H-2).
    50	const MaxConfigSize = 16 << 20 // 16 MiB
    51	
    52	// checkConfigSize rejects an over-large payload before it reaches the parser.
    53	func checkConfigSize(content string) error {
    54		if len(content) > MaxConfigSize {
    55			return fmt.Errorf("config too large: %d bytes exceeds maximum %d bytes",
    56				len(content), MaxConfigSize)
    57		}
    58		return nil
    59	}
    60	
    61	// Store manages the candidate and active configuration.
    62	type Store struct {
    63		mu        sync.RWMutex
    64		active    *config.ConfigTree
    65		candidate *config.ConfigTree
    66		compiled  *config.Config // compiled active config
    67		history   *History
    68		dirty     bool
    69		configDir bool // true if in configuration mode
    70		filePath  string
    71	
    72		// candidateGen is a MONOTONIC token that changes whenever the candidate
    73		// tree changes identity or content — every set/delete/load/rename/copy/
    74		// insert/annotate/(de)activate mutation, every rollback, every
    75		// enter/exit/reclaim of configuration mode, the peer-sync candidate reset,
    76		// and the post-commit candidate reset. It backs the #5848 generation-bound
    77		// commit transaction: the daemon snapshots+compiles the candidate and reads
    78		// this token atomically (CompileCandidateGen), runs its external
    79		// device-map hardware pre-flight on that immutable snapshot OUTSIDE the store
    80		// lock, then commits ONLY if the token is unchanged (CommitWithDescriptionGen
    81		// / CommitConfirmedGen). A concurrent candidate edit between snapshot and
    82		// promote bumps the token, so the commit returns
    83		// ErrCandidateGenerationConflict instead of silently promoting an unexamined
    84		// generation. It is authoritative over content: a candidate edited and then
    85		// reverted to byte-identical content still yields a new token (the examined
    86		// generation is gone), so the conservative outcome is a conflict/retry.
    87		// ALWAYS bumped via bumpCandidateGenLocked under s.mu.Lock.
    88		candidateGen uint64
    89	
    90		// Persistent storage
    91		db      *DB
    92		journal *journal.Journal
    93	
    94		// writeActiveFn is a test seam for active-config persistence
    95		// (#1799). nil (production) means s.db.WriteActive. Set via
    96		// SetWriteActiveForTesting; never assigned on production paths.
    97		writeActiveFn func(*config.ConfigTree) error
    98	
    99		// writeActiveMarkerFn is the marker-aware test seam for the #1922
   100		// step-0 committed marker. nil (production) routes to
   101		// db.WriteActiveMarker. Set via SetWriteActiveMarkerForTesting.
   102		writeActiveMarkerFn func(*config.ConfigTree, bool) error
   103	
   104		// everCommitted is the #1922 step-0 marker as loaded/observed in
   105		// memory: true once a config has been successfully committed or
   106		// synced to this store (or loaded from a committed/legacy DB), false
   107		// on a fresh store and after the Item 1b first-commit rollback writes
   108		// the never-committed marker. The boot predicate (BootClassify) reads
   109		// it to disambiguate operator-committed-empty (normal) from
   110		// never-committed (bootstrap). Default false on a new Store; Load sets
   111		// it from the on-disk envelope marker (absent/legacy DB => true).
   112		everCommitted bool
   113	
   114		// #1799 Option B (degrade-not-fail) state for the persist paths
   115		// that must proceed in memory even when the disk write fails
   116		// (SyncApply HA convergence, performAutoRollback safety revert).
   117		// persistDegraded is surfaced via ConfigPersistDegraded() to the
   118		// /health 503 check and the xpf_daemon_config_persist_degraded
   119		// gauge. persistRetryActive is the singleton guard for the
   120		// background retry goroutine (exactly one loop at a time). The
   121		// backoff fields are test seams; zero means the production
   122		// defaults (1s initial, doubling to a 60s cap).
   123		persistDegraded            bool
   124		persistRetryActive         bool
   125		persistRetryInitialBackoff time.Duration
   126		persistRetryMaxBackoff     time.Duration
   127	
   128		// persistMarkerCommitted records the #1922 step-0 committed flag the
   129		// degraded-persist retry loop must re-write. Defaults true; set false
   130		// ONLY by the Item 1b first-commit rollback so a FAILED never-committed
   520	// any operator-driven candidate commit / commit-check path.
   521	//
   522	// Rationale: Store.Load and Store.SyncApply compile a config the operator
   523	// did NOT just author — a persisted active config on local boot, or a
   524	// config pushed from a possibly-un-upgraded cluster primary. A strict
   525	// reject here would (a) fail Store.Load on an upgraded node carrying a
   526	// legacy config, leaving the daemon with no active config (operational
   527	// blackout), and (b) fail Store.SyncApply on an upgraded standby
   528	// receiving such a config from an un-upgraded primary, alarm-looping HA
   529	// config sync. The operator's next strict candidate commit rejects it.
   530	//
   531	// (The original #1733 equal-flow worker-cap downgrade that motivated
   532	// this split was retired in #1830 (e) — the dataplane no longer caps
   533	// equal-flow-enforcement at 32 workers.)
   534	func (s *Store) compileTreeLenient(tree *config.ConfigTree) (*config.Config, error) {
   535		// #1319 PR 2: the typed-leaf SchemaValidate gate is STRICT only on the
   536		// operator-driven commit / commit-check path (compileTree). Here — the
   537		// tolerant Store.Load / Store.SyncApply ingress for configs the
   538		// operator did NOT just author — a violation downgrades to a warning.
   539		// A persisted config written by an older binary (pre-gate, or before a
   540		// leaf's range was typed/tightened) may carry values the current gate
   541		// rejects; hard-failing would blackout-boot the node (Load) or
   542		// alarm-loop HA config sync (SyncApply), even though the compiler
   543		// accepted the value when it was committed and still compiles it the
   544		// same way today. This is the same doctrine as the #1733/#1798/#1814
   545		// lenient compile gates (see freetext.go); the operator's next strict
   546		// commit rejects the stale value loudly.
   547		if err := s.schemaValidateExpandedTree(tree); err != nil {
   548			slog.Warn("typed-leaf schema violation in tolerated config; continuing (a strict commit would reject this)",
   549				"err", err, "issue", "#1319")
   550		}
   551		var compiled *config.Config
   552		var err error
   553		if s.nodeID >= 0 {
   554			compiled, err = config.CompileConfigForNodeLenient(tree, s.nodeID)
   555		} else {
   556			compiled, err = config.CompileConfigLenient(tree)
   557		}
   558		// #4185 (review Finding 2): the lenient Load/SyncApply path must NOT
   559		// hard-reject a node-id mismatch (that would blackout-boot the node or
   560		// alarm-loop HA config sync — the #1960 doctrine), but a silent literal
   561		// `chassis cluster node` leaf that disagrees with this node's identity
   562		// (e.g. leaf 0 reaching a node-1 box via config-sync) causes a heartbeat-id
   563		// collision + wrong FPC naming with no diagnostic. Warn (non-fatal) so the
   564		// observability hole is closed without bricking the standby. The operator's
   565		// next strict commit rejects it outright (crossCheckNodeID).
   566		if err == nil {
   567			if mismatch := crossCheckNodeID(compiled, s.nodeID); mismatch != nil {
   568				slog.Warn("node identity mismatch in tolerated config; continuing (a strict commit would "+
   569					"reject this) — heartbeat identity and FPC naming may diverge from ${node} expansion",
   570					"err", mismatch, "issue", "#4185")
   571			}
   572			if raErr := crossCheckRAIntervals(compiled); raErr != nil {
   573				slog.Warn("router-advertisement interval violation in tolerated config; continuing "+
   574					"(a strict commit would reject this) — the RA sender floors the periodic timer at 1s",
   575					"err", raErr, "issue", "#4525")
   576			}
   577		}
   578		return compiled, err
   579	}
   580	
   581	func (s *Store) schemaValidateExpandedTree(tree *config.ConfigTree) error {
   582		return schemaValidateExpandedTreeForNode(tree, s.nodeID)
   583	}
   584	
   585	func schemaValidateExpandedTreeForNode(tree *config.ConfigTree, nodeID int) error {
   586		if tree == nil {
   587			return nil
   588		}
   589		// #2008 H1: strip `inactive:` subtrees BEFORE group expansion so the
   590		// schema/check path agrees with the compile path (strip -> expand ->
   591		// validate; see compileConfigWithOpts in compiler.go). ExpandGroups
   592		// (ast_groups.go) collects every `apply-groups` node by name WITHOUT
   593		// checking Inactive, so without this an `inactive: apply-groups foo`
   594		// would still expand group foo (false-validating inherited content the
   595		// compiler will never apply) and an `inactive: apply-groups missing`
   596		// would still fail commit-check as an undefined group. Stripping here —
   597		// not only inside SchemaValidateWithDefinitions, which runs AFTER
   598		// expansion — makes the marker actually deactivate group inheritance.
   599		// WithoutInactive is a no-op (no clone) on the all-active path; the
   600		// pre-strip tree is still passed as defsSource so a definition living
   601		// only in an un-applied peer-node group keeps satisfying shared-section
   602		// references (#1319 PR 3), with that defsSource stripped of inactive
   603		// nodes inside SchemaValidateWithDefinitions.
   604		stripped := tree.WithoutInactive()
   605		expanded := stripped.Clone()
   606		if nodeID >= 0 {
   607			vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
   608			if err := expanded.ExpandGroupsWithVars(vars); err != nil {
   609				return fmt.Errorf("apply-groups: %w", err)
   610			}
   611			// Pass the PRE-expansion candidate as the cross-reference
   612			// definitions source: expansion removes the groups stanza, and
   613			// definitions living only in un-applied peer-node groups must
   614			// keep satisfying shared-section references (#1319 PR 3).
   615			return config.SchemaValidateWithDefinitions(expanded, tree, nil)
   616		}
   617		if err := expanded.ExpandGroups(); err != nil {
   618			if strings.Contains(err.Error(), `undefined group "${node}"`) {
   619				vars := map[string]string{"node": "node0"}
   620				if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
   621					return fmt.Errorf("apply-groups: %w", err2)
   622				}
   623			} else {
   624				return fmt.Errorf("apply-groups: %w", err)
   625			}
   626		}
   627		return config.SchemaValidateWithDefinitions(expanded, tree, nil)
   628	}
   629	
   630	// SyncApply applies a config received from the cluster primary.
   631	// Bypasses cluster read-only checks. The chassisPreserve function, if set,
   632	// lets the caller patch the parsed tree before compiling (e.g. to preserve
   633	// local chassis cluster settings).
   634	func (s *Store) SyncApply(content string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
   635		// H-2: the HA peer config-sync ingress is a network-reachable parse entry
   636		// point (a hostile/corrupt peer config over the fabric). Reject an
   637		// over-large payload before parsing so one bad peer cannot crash the
   638		// standby.
   639		if err := checkConfigSize(content); err != nil {
   640			return nil, err
   641		}
   642		s.mu.Lock()
   643		defer s.mu.Unlock()
   644	
   645		tree, errs := config.NewParser(content).Parse()
   646		if len(errs) > 0 {
   647			return nil, fmt.Errorf("sync config parse error: %v", errs[0])
   648		}
   649	
   650		// Let caller patch the tree (e.g. preserve local chassis cluster settings).
   651		if chassisPreserve != nil {
   652			chassisPreserve(tree)
   653		}
   654	
   655		// Rolling-upgrade tolerance (AGY r4 finding on #1476): an
   656		// un-upgraded primary may push a config that still selects
   657		// the retired DPDK or eBPF dataplane. Strict-validator-driven
   658		// sync rejection would alarm-loop the cluster. Rewrite the
   659		// retired leaf so the standby boots through cleanly while the
   660		// operator updates the primary.
   661		rewriteRetiredDataplaneType(tree, SyncCaller)
   662	
   663		// #1798 migration: same tolerance as Load — a peer-synced config
   664		// from a possibly-un-upgraded primary may carry control characters
   665		// in free-text values. Scrub the tree in place with a warning so
   666		// HA config sync does not alarm-loop and the standby's stored tree
   667		// stays clean for any later strict commit.
   668		for _, p := range config.SanitizeTreeControlChars(tree) {
   669			slog.Warn("sanitized control characters in peer-synced config value",
   670				"path", p, "issue", "#1798")
   671		}
   672	
   673		// Tolerant compile: a config peer-synced from a possibly-un-upgraded
   674		// primary must not alarm-loop HA sync (see compileTreeLenient for
   675		// the validator downgrades).
   676		compiled, err := s.compileTreeLenient(tree)
   677		if err != nil {
   678			return nil, fmt.Errorf("sync config compile error: %w", err)
   679		}
   680	
   681		// Push current active to history.
   682		s.history.Push(&HistoryEntry{
   683			Config:    s.active.Clone(),
   684			Timestamp: time.Now(),
   685		})
   686	
   687		s.active = tree
   688		s.compiled = compiled
   689		s.dirty = false
   690	
   691		// If in config mode, update candidate too.
   692		if s.configDir {
   693			s.candidate = s.active.Clone()
   694			s.bumpCandidateGenLocked() // #5848: candidate reset by authoritative load/sync
   695		}
   696	
   697		// #3861: an authoritative config synced from the cluster primary
   698		// supersedes any commit-confirmed window still pending on THIS node
   699		// (e.g. a node that armed `commit confirmed`, failed over to standby,
   700		// then received a sync from the new primary). The pending timer's
   730		//
   731		// #1922 step-0: a successful config sync from the primary counts as a
   732		// commit for the never-vs-empty disambiguation — a synced secondary has
   733		// an authoritative config and must never read as never-committed. Set
   734		// the markers BEFORE the persist so a failed-then-healed write (the
   735		// retry loop) also stamps committed=1.
   736		s.everCommitted = true
   737		s.persistMarkerCommitted = true
   738		if err := s.writeActive(s.active); err != nil {
   739			s.noteActivePersistFailureLocked("config_sync", err)
   740			// #5473: the synced config that supersedes the pending confirm window
   741			// is NOT durable. Keep confirm.json and defer its removal until the
   742			// retry lands the synced config durably — a crash before then boots
   743			// into a state where the persisted rollback still fires.
   744			if syncSupersededConfirm {
   745				s.confirmResolvePendingPersist = true
   746			}
   747		} else {
   748			s.persistDegraded = false
   749			// The synced config is durable. Drop the confirm.json this sync
   750			// superseded now that the replacement is on disk.
   751			if syncSupersededConfirm {
   752				// #5835: a failed removal retains retry debt + degraded health
   753				// rather than being swallowed.
   754				s.resolveConfirmRemovalLocked("config_sync_remove")
   755			}
   756			// Also finalize any removal deferred by an EARLIER failed resolution
   757			// write (e.g. a prior rollback whose persist failed): the synced config
   758			// is durable, so that stale window is definitively superseded too.
   759			// No-op unless such a removal was pending.
   760			s.clearConfirmResolutionPendingLocked()
   761		}
   762	
   763		s.journalLog(&JournalEntry{
   764			Action:     "config_sync",
   765			ConfigHash: journalConfigHash(s.active),
   766		})
   767	
   768		s.saveRollbackFiles()
   769		return compiled, nil
   770	}
   771	
   772	// configTextDigest returns a stable hex digest of a rendered config's text,
   773	// whitespace-normalized so it matches the ShowActive()/incoming-text comparison
   774	// handleConfigSync already performs (both sides are the canonical hierarchical
   775	// render a primary pushes via ShowActive).
   776	func configTextDigest(text string) string {
   777		sum := sha256.Sum256([]byte(strings.TrimSpace(text)))
   778		return hex.EncodeToString(sum[:])
   779	}
   780	
   781	// MarkActiveApplied records that the CURRENT active config has completed a full
   782	// apply to the dataplane/kernel (#4957). The daemon calls it after a successful
   783	// applyConfigLocked for the active config — the boot apply, a committed config,
   784	// and a peer config-sync. It stamps the digest of the active text so a later
   785	// ActiveApplied() can tell whether the tree that is active NOW is the one that
   786	// converged. A no-op is safe if active is nil (nothing to have applied).
   787	func (s *Store) MarkActiveApplied() {
   788		s.mu.Lock()
   789		defer s.mu.Unlock()
   790		if s.active == nil {
   791			s.appliedDigest = ""
   792			return
   793		}
   794		s.appliedDigest = configTextDigest(s.active.Format())
   795	}
   796	
   797	// ActiveApplied reports whether the CURRENT active config is the one that most
   798	// recently completed a full apply (#4957). It is FALSE in the window after active
   799	// has been promoted (SyncApply/Commit/Load) but before the subsequent apply
   800	// succeeds — including the #4957 case where a peer-synced config was promoted to
   801	// active but its apply FAILED and was never rolled back (degrade-not-fail). A nil
   802	// active, or a never-applied store, reads as not-applied.
   803	func (s *Store) ActiveApplied() bool {
   804		s.mu.RLock()
   805		defer s.mu.RUnlock()
   806		if s.active == nil || s.appliedDigest == "" {
   807			return false
   808		}
   809		return s.appliedDigest == configTextDigest(s.active.Format())
   810	}
   811	
   812	// ActiveDigest returns the convergence digest of the CURRENT active config
   813	// text — exactly the value ActiveApplied() compares appliedDigest against
   814	// (configTextDigest(s.active.Format()), the ShowActive render). It lets a
   815	// caller CAPTURE the digest of the config it is about to apply, under its own
   816	// apply serialization, and stamp that captured value later via
   817	// MarkAppliedDigest — instead of re-reading s.active at stamp time. A concurrent
   818	// promoter (a local commit / commit-confirmed rollback) that mutated s.active
   819	// between the apply and a post-serialization stamp would otherwise make
   820	// MarkActiveApplied key the marker to a different, never-applied tree (the #6296

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/configstore/store_commit.go | sed -n '190,230p;955,1030p;1130,1185p'
nl -ba pkg/configstore/history.go | sed -n '1,75p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   190			s.noteActivePersistFailureLocked("commit_postrename", err)
   191			// #5473: this commit's config C is VISIBLE on disk (post-rename: the
   192			// rename landed, only the dir-fsync is uncertain) and supersedes any
   193			// commit-confirmed window whose earlier resolution write failed. Finalize
   194			// the deferred (retained) confirm.json removal now — symmetric with the
   195			// success branch. Without this the stale flag persists into the degraded
   196			// retry, whose heal would then delete a LATER-armed window's fresh record
   197			// (or, for a plain commit, a stale PrevTree=A record lingers and a crash
   198			// reverts this just-committed C back to A). No-op unless a removal was
   199			// deferred.
   200			s.clearConfirmResolutionPendingLocked()
   201		} else {
   202			s.persistDegraded = false       // disk now holds the current config
   203			s.everCommitted = true          // #1922 step-0: a real commit has succeeded
   204			s.persistMarkerCommitted = true // #1922: degraded-retry writes committed=1
   205			// #5473: this commit's config is now durable and supersedes any
   206			// commit-confirmed window whose earlier resolution write failed. Drop
   207			// the deferred (retained) confirm.json so a reboot does not re-drive a
   208			// stale rollback that this commit has replaced. No-op unless a removal
   209			// was deferred.
   210			s.clearConfirmResolutionPendingLocked()
   211		}
   212	
   213		// Push current active to history with description
   214		s.history.Push(&HistoryEntry{
   215			Config:    s.active.Clone(),
   216			Timestamp: time.Now(),
   217			Comment:   description,
   218		})
   219	
   220		// Promote candidate to active
   221		s.active = s.candidate
   222		s.candidate = s.active.Clone()
   223		s.bumpCandidateGenLocked() // #5848: fresh candidate — advance the generation
   224		s.compiled = compiled
   225		s.dirty = false
   226		s.touchConfigLockLocked() // #4476: a commit is activity — refresh the lease
   227	
   228		// #3861: a PLAIN commit during a pending commit-confirmed window is
   229		// the confirmation (Junos semantics: any subsequent explicit commit
   230		// confirms a pending `commit confirmed`). The frontend `commit` path
   955	// gen must be the confirmGen captured when the calling timer was armed.
   956	func (s *Store) performAutoRollback(gen uint64) {
   957		if _, ok := s.PromoteRollback(gen); !ok {
   958			return
   959		}
   960		slog.Warn("commit confirmed timed out, configuration rolled back")
   961	}
   962	
   963	// Rollback reverts the candidate to a previous configuration.
   964	// n=0 reverts to active; n>0 reverts to the nth previous commit.
   965	func (s *Store) Rollback(n int) error { return s.RollbackAs("", n) }
   966	
   967	// RollbackAs is Rollback scoped to a config-lock holder session (#5059).
   968	// sessionID == "" bypasses ownership (internal/system caller).
   969	func (s *Store) RollbackAs(sessionID string, n int) error {
   970		s.mu.Lock()
   971		defer s.mu.Unlock()
   972	
   973		// #3893: `rollback N` mutates the candidate; reject it on a read-only
   974		// secondary. This is the user-session verb, distinct from the internal
   975		// commit-confirmed timeout revert PromoteRollback (which promotes the
   976		// active config directly and is intentionally NOT gated).
   977		if err := s.ensureWritableLocked(); err != nil {
   978			return err
   979		}
   980		// #5059: reject a rollback issued by a session that is not the config-lock
   981		// holder — it mutates the shared candidate.
   982		if err := s.ensureHolderLocked(sessionID); err != nil {
   983			return err
   984		}
   985		if s.candidate == nil {
   986			return fmt.Errorf("not in configuration mode")
   987		}
   988		s.touchConfigLockLocked() // #4476: a rollback is activity — refresh the lease
   989	
   990		if n == 0 {
   991			s.candidate = s.active.Clone()
   992			s.bumpCandidateGenLocked() // #5848: candidate replaced by rollback 0
   993			s.dirty = false
   994			return nil
   995		}
   996	
   997		entry, err := s.rollbackEntry(n)
   998		if err != nil {
   999			return err
  1000		}
  1001		s.candidate = entry.Config.Clone()
  1002		s.bumpCandidateGenLocked() // #5848: candidate replaced by rollback n
  1003		s.dirty = true
  1004		return nil
  1005	}
  1006	
  1007	// rollbackEntry resolves rollback slot n (1-based) to its HistoryEntry.
  1008	// It returns a clear error both when n is out of range and when the slot
  1009	// was tombstoned at load time because its on-disk file could not be read
  1010	// or parsed (#4810) — the caller must never silently fall through to a
  1011	// DIFFERENT slot's config just because an intermediate slot was skipped.
  1012	// See loadRollbackHistory: a tombstone (HistoryEntry with a nil Config)
  1013	// occupies the slot's exact position so `rollback N` / `show ... rollback
  1014	// N` always resolve slot N, never slot N+1. Callers must hold s.mu (read
  1015	// or write — History reads are not independently synchronized).
  1016	func (s *Store) rollbackEntry(n int) (*HistoryEntry, error) {
  1017		entry, err := s.history.Get(n - 1)
  1018		if err != nil {
  1019			return nil, err
  1020		}
  1021		if entry.Config == nil {
  1022			return nil, fmt.Errorf("rollback slot %d is unreadable (failed to load at startup); see log for detail", n)
  1023		}
  1024		return entry, nil
  1025	}
  1026	
  1027	// ListHistory returns all history entries, most recent first (goroutine-safe).
  1028	func (s *Store) ListHistory() []*HistoryEntry {
  1029		s.mu.RLock()
  1030		defer s.mu.RUnlock()
  1130	
  1131	// rollbackPath returns the file path for rollback slot n (1-based).
  1132	func (s *Store) rollbackPath(n int) string {
  1133		return filepath.Join(filepath.Dir(s.filePath), fmt.Sprintf("%s.%d", filepath.Base(s.filePath), n))
  1134	}
  1135	
  1136	// saveRollbackFiles writes rollback history entries to numbered files.
  1137	// Must be called under write lock.
  1138	//
  1139	// Durability split (#1894, adjudicated in the plan round): these files
  1140	// are the CANONICAL rollback history (loadRollbackHistory reads them at
  1141	// boot; the DB rollback slots have no production callers). Slot 1 — the
  1142	// immediate `rollback 1` target — is written durably; slots 2..N use
  1143	// the atomic writer (never missing, never torn, so loadRollbackHistory's
  1144	// break-on-first-missing stays sound; they may lag behind after a power
  1145	// cut). One trailing SyncDir then makes the whole shuffle AND the
  1146	// stale-slot unlinks durable for the cost of a single dir fsync,
  1147	// instead of ~50 file+dir fsync pairs under the store mutex.
  1148	func (s *Store) saveRollbackFiles() {
  1149		if s.filePath == "" {
  1150			return
  1151		}
  1152	
  1153		entries := s.history.List() // most-recent-first
  1154		degraded := false
  1155		for i, entry := range entries {
  1156			if entry.Config == nil {
  1157				// #4810: a tombstoned slot (unreadable/corrupt at load, see
  1158				// loadRollbackHistory) has no config text to persist. Leave
  1159				// its on-disk file untouched — writing would dereference a
  1160				// nil Config, and removing it would let a NEXT boot's
  1161				// os.IsNotExist break() truncate every slot after it. The
  1162				// slot stays visibly broken (same tombstone next boot) until
  1163				// an operator fixes it out-of-band, instead of silently
  1164				// losing later, otherwise-fine slots.
  1165				continue
  1166			}
  1167			path := s.rollbackPath(i + 1)
  1168			data := entry.Config.Format()
  1169			var err error
  1170			// Owner-only 0600 (#4056): the rollback slots (xpf.conf.N) hold the
  1171			// full committed config TEXT, which always includes cleartext secret
  1172			// leaves (IKE PSK, auth keys, SNMP community) — Format() does not
  1173			// redact or encrypt. World-readable 0644 exposed every firewall
  1174			// secret to any local user; 0600 keeps them owner-only. The daemon
  1175			// owns the files, so loadRollbackHistory still reads them back.
  1176			if i == 0 {
  1177				err = rbWriteFileDurable(path, []byte(data), 0600)
  1178			} else {
  1179				err = rbWriteFileAtomic(path, []byte(data), 0600)
  1180			}
  1181			if err != nil {
  1182				slog.Warn("failed to write rollback file", "path", path, "err", err)
  1183				degraded = true
  1184			}
  1185		}
     1	// Package configstore provides history management for config store.
     2	package configstore
     3	
     4	import (
     5		"fmt"
     6		"time"
     7	
     8		"github.com/psaab/xpf/pkg/config"
     9	)
    10	
    11	// HistoryEntry represents a snapshot of a configuration tree.
    12	type HistoryEntry struct {
    13		Config    *config.ConfigTree
    14		Timestamp time.Time
    15		Comment   string
    16	}
    17	
    18	// History is a fixed-size ring buffer for configuration history.
    19	type History struct {
    20		entries []*HistoryEntry
    21		head    int
    22		size    int
    23		maxSize int
    24	}
    25	
    26	// NewHistory creates a History with the given maximum size.
    27	func NewHistory(max int) *History {
    28		return &History{
    29			entries: make([]*HistoryEntry, max),
    30			maxSize: max,
    31		}
    32	}
    33	
    34	// MaxSize returns the maximum history size.
    35	func (h *History) MaxSize() int {
    36		return h.maxSize
    37	}
    38	
    39	// Len returns the current number of entries in the history.
    40	func (h *History) Len() int {
    41		return h.size
    42	}
    43	
    44	// Push adds an entry, overwriting the oldest if full.
    45	func (h *History) Push(entry *HistoryEntry) {
    46		h.entries[h.head] = entry
    47		h.head = (h.head + 1) % h.maxSize
    48		if h.size < h.maxSize {
    49			h.size++
    50		}
    51	}
    52	
    53	// Get returns the entry at position n (0 = most recent, size-1 = oldest).
    54	func (h *History) Get(n int) (*HistoryEntry, error) {
    55		if n < 0 || n >= h.size {
    56			return nil, fmt.Errorf("history position %d out of range [0, %d)", n, h.size)
    57		}
    58		idx := (h.head - 1 - n + h.maxSize) % h.maxSize
    59		return h.entries[idx], nil
    60	}
    61	
    62	// List returns all entries, most recent first.
    63	func (h *History) List() []*HistoryEntry {
    64		result := make([]*HistoryEntry, h.size)
    65		for i := 0; i < h.size; i++ {
    66			idx := (h.head - 1 - i + h.maxSize) % h.maxSize
    67			result[i] = h.entries[idx]
    68		}
    69		return result
    70	}

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n -i '\\bvxlan\\b|vxlan_|_vxlan|PROTO_IPIP|\\bipip\\b|ip-in-ip|ip_in_ip' userspace-dp/src userspace-dp/tests || true
rg -n -i 'decap|decaps|tunnel' userspace-dp/src/afxdp userspace-dp/src | head -300"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 131ms:[0m
userspace-dp/src/ip_proto.rs:12:pub(crate) const PROTO_IPIP: u8 = 4;
userspace-dp/src/ip_proto.rs:91:        "ipip" | "junos-ip-in-ip" | "junos-ipip" => Some(PROTO_IPIP),
userspace-dp/src/policy_snapshot_error.rs:196:    /// only tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric, no
userspace-dp/src/policy.rs:120:    PROTO_AH, PROTO_EGP, PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6, PROTO_IGMP, PROTO_IPIP,
userspace-dp/src/policy.rs:3688:        "4" | "ipip" => Some(PROTO_IPIP),
userspace-dp/src/filter/README.md:24:    gre/ospf/ipip/esp/ah/sctp/vrrp/igmp/pim/egp + the specific
userspace-dp/src/filter/tests.rs:6091:// only tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric and silently
userspace-dp/src/filter/tests.rs:6225:    assert_scoped_to("junos-ip-in-ip", 4);
userspace-dp/src/filter/tests.rs:6264:        "junos-ip-in-ip",
userspace-dp/src/filter/tests.rs:6265:        "junos-ipip",
userspace-dp/src/filter/tests.rs:6266:        "ipip",
userspace-dp/src/filter/compiler.rs:800:/// carry (tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric, no
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:26:        // GRE/IPIP require concrete outer source/destination. WireGuard
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:57:                    "xpf-userspace-dp: tunnel endpoint {} outer source {} and destination {} are different address families; skipping this endpoint (a GRE/IPIP tunnel encapsulates in one outer family — #5162)",
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1259:    for bad in ["", "ipip", "vxlan", "GRE", "wireguard ", "gre6", "geneve"] {
userspace-dp/src/nat/tests_dnat_proto.rs:263:    assert_eq!(proto_number("ipip"), Some(4));
userspace-dp/src/nat/tests_dnat_proto.rs:274:    assert_eq!(proto_number("junos-ip-in-ip"), Some(4));
userspace-dp/src/nat/tests_dnat_proto.rs:275:    assert_eq!(proto_number("junos-ipip"), Some(4));
userspace-dp/src/afxdp/shared_ops.rs:54:/// promotes, HA sync imports, and tunnel-local installs — so zero here is
userspace-dp/src/afxdp/shared_ops.rs:686:        forward_match.decision.resolution.tunnel_endpoint_id != 0
userspace-dp/src/afxdp/shared_ops.rs:796:    allow_unseeded_tunnel_local: bool,
userspace-dp/src/afxdp/shared_ops.rs:815:    if allow_unseeded_tunnel_local
userspace-dp/src/afxdp/types/tx.rs:213:pub(in crate::afxdp) struct LocalTunnelTxPlan {
userspace-dp/src/afxdp/gre.rs:120:/// #2315: count of GRE-decap frames DROPPED because the outer header
userspace-dp/src/afxdp/gre.rs:125:/// `xpf_userspace_gre_decap_ecn_illegal_drops_total`. A nonzero value
userspace-dp/src/afxdp/gre.rs:126:/// means a misbehaving/misconfigured tunnel ingress copied ECT onto the
userspace-dp/src/afxdp/gre.rs:130:pub(in crate::afxdp) static GRE_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);
userspace-dp/src/afxdp/gre.rs:132:/// #2317: count of WireGuard-decap inner packets DROPPED by the same
userspace-dp/src/afxdp/gre.rs:134:/// counter so the two tunnel families are independently observable.
userspace-dp/src/afxdp/gre.rs:136:/// `xpf_userspace_wg_decap_ecn_illegal_drops_total`. The WG decap path
userspace-dp/src/afxdp/gre.rs:141:/// `apply_decap_ecn_combine` below. A nonzero value means a misbehaving
userspace-dp/src/afxdp/gre.rs:143:pub(in crate::afxdp) static WG_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);
userspace-dp/src/afxdp/gre.rs:156:/// flags inner flows whose encapped size exceeds the tunnel path MTU —
userspace-dp/src/afxdp/gre.rs:166:/// this guard's `tunnel_outer_mtu - outer_ip - gre` math reduces to), sets
userspace-dp/src/afxdp/gre.rs:175:/// #2782: count of native-GRE decap frames DROPPED because the
userspace-dp/src/afxdp/gre.rs:186:/// VALIDATE the checksum; a verified frame decaps normally, a corrupt
userspace-dp/src/afxdp/gre.rs:189:/// `xpf_userspace_gre_decap_checksum_invalid_drops_total`. A nonzero
userspace-dp/src/afxdp/gre.rs:192:pub(in crate::afxdp) static GRE_DECAP_CHECKSUM_INVALID_DROPS: AtomicU64 = AtomicU64::new(0);
userspace-dp/src/afxdp/gre.rs:195:/// propagation on tunnel encap (#2303). Returns the full 8-bit
userspace-dp/src/afxdp/gre.rs:202:///     tunnel.
userspace-dp/src/afxdp/gre.rs:206:///     into the inner ECN at DECAP (loss-free congestion signalling
userspace-dp/src/afxdp/gre.rs:208:///     DECAP-side combine (outer ECN → inner ECN) is `decap_ecn_combine`
userspace-dp/src/afxdp/gre.rs:209:///     below, wired into `try_native_gre_decap_from_frame` (#2315). This
userspace-dp/src/afxdp/gre.rs:249:/// decap combine. `frame` is the full received frame; `meta.l3_offset`
userspace-dp/src/afxdp/gre.rs:290:/// RFC 6040 §4.2 decapsulation outcome for a single (inner, outer) ECN
userspace-dp/src/afxdp/gre.rs:293:pub(in crate::afxdp) enum DecapEcn {
userspace-dp/src/afxdp/gre.rs:304:/// ARRIVING outer ECN, decide how the inner ECN must change at decap.
userspace-dp/src/afxdp/gre.rs:320:/// at decap — is never copied from the outer).
userspace-dp/src/afxdp/gre.rs:326:/// `__INET_ECN_decapsulate` upgrades to ECT(1) instead; both are RFC
userspace-dp/src/afxdp/gre.rs:331:pub(in crate::afxdp) fn decap_ecn_combine(inner_ecn: u8, outer_ecn: u8) -> DecapEcn {
userspace-dp/src/afxdp/gre.rs:340:        (NOT_ECT, CE) => DecapEcn::Drop,
userspace-dp/src/afxdp/gre.rs:341:        (NOT_ECT, _) => DecapEcn::Keep,
userspace-dp/src/afxdp/gre.rs:343:        (CE, _) => DecapEcn::Keep,
userspace-dp/src/afxdp/gre.rs:345:        (_, CE) => DecapEcn::SetCe,
userspace-dp/src/afxdp/gre.rs:350:        // `__INET_ECN_decapsulate` upgrades to ECT(1); both are
userspace-dp/src/afxdp/gre.rs:354:        (ECT_0, ECT_1) => DecapEcn::Keep,
userspace-dp/src/afxdp/gre.rs:357:        _ => DecapEcn::Keep,
userspace-dp/src/afxdp/gre.rs:361:/// Apply the RFC 6040 §4.2 decap ECN combine IN PLACE to the inner IP
userspace-dp/src/afxdp/gre.rs:376:/// `illegal_drops` is the per-tunnel-family drop counter bumped on the
userspace-dp/src/afxdp/gre.rs:378:/// #2315 / #2317), so this one body is shared by both decap paths.
userspace-dp/src/afxdp/gre.rs:380:pub(in crate::afxdp) fn apply_decap_ecn_combine(
userspace-dp/src/afxdp/gre.rs:394:            match decap_ecn_combine(ecn_of_tos(tos), outer_ecn) {
userspace-dp/src/afxdp/gre.rs:395:                DecapEcn::Keep => true,
userspace-dp/src/afxdp/gre.rs:396:                DecapEcn::Drop => {
userspace-dp/src/afxdp/gre.rs:400:                DecapEcn::SetCe => {
userspace-dp/src/afxdp/gre.rs:415:            match decap_ecn_combine(inner_ecn, outer_ecn) {
userspace-dp/src/afxdp/gre.rs:416:                DecapEcn::Keep => true,
userspace-dp/src/afxdp/gre.rs:417:                DecapEcn::Drop => {
userspace-dp/src/afxdp/gre.rs:421:                DecapEcn::SetCe => {
userspace-dp/src/afxdp/gre.rs:438:/// unchanged. Used after the decap ECN combine mutates the TOS byte.
userspace-dp/src/afxdp/gre.rs:461:/// Match a received GRE (proto-47) outer tuple to a GRE-mode tunnel
userspace-dp/src/afxdp/gre.rs:465:/// `gre_decap_index`, which only contains `mode == "gre"` / `"ip6gre"`
userspace-dp/src/afxdp/gre.rs:466:/// endpoints — so a GRE frame is NEVER decapped against a WireGuard or
userspace-dp/src/afxdp/gre.rs:475:/// `mode` is re-checked via `tunnel_mode_kind` so a future build-side
userspace-dp/src/afxdp/gre.rs:477:fn match_tunnel_endpoint(
userspace-dp/src/afxdp/gre.rs:484:) -> Option<&TunnelEndpoint> {
userspace-dp/src/afxdp/gre.rs:486:        .gre_decap_index
userspace-dp/src/afxdp/gre.rs:489:        let Some(endpoint) = forwarding.tunnel_endpoints.get(id) else {
userspace-dp/src/afxdp/gre.rs:492:        // Kind re-check (defense in depth): only GRE-mode rows decap as
userspace-dp/src/afxdp/gre.rs:494:        if tunnel_mode_kind(&endpoint.mode) != TunnelKind::Gre {
userspace-dp/src/afxdp/gre.rs:541:                // packet end. Fail CLOSED (drop / no decap) when the
userspace-dp/src/afxdp/gre.rs:621:pub(super) fn try_native_gre_decap_from_frame(
userspace-dp/src/afxdp/gre.rs:662:            GRE_DECAP_CHECKSUM_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
userspace-dp/src/afxdp/gre.rs:685:    let endpoint = match_tunnel_endpoint(
userspace-dp/src/afxdp/gre.rs:700:    // #2315: RFC 6040 §4.2 decap-side ECN combine. The outer ECN (read
userspace-dp/src/afxdp/gre.rs:710:        && !apply_decap_ecn_combine(
userspace-dp/src/afxdp/gre.rs:714:            &GRE_DECAP_ECN_ILLEGAL_DROPS,
userspace-dp/src/afxdp/gre.rs:718:        // apply_decap_ecn_combine).
userspace-dp/src/afxdp/gre.rs:747:    // #921: GRE decap fires from afxdp.rs (pre-flow-cache), so this
userspace-dp/src/afxdp/gre.rs:748:    // is the per-packet path on GRE-tunnel workloads. Direct ID
userspace-dp/src/afxdp/gre.rs:771:        // #2486: mark this inner packet as GRE-decapped so the forward
userspace-dp/src/afxdp/gre.rs:773:        // GRE-decapped SYN is the exact direction where an inner LAN peer
userspace-dp/src/afxdp/gre.rs:775:        meta_flags: GRE_DECAP_INGRESS_FLAG,
userspace-dp/src/afxdp/gre.rs:817:        .tunnel_endpoints
userspace-dp/src/afxdp/gre.rs:818:        .get(&decision.resolution.tunnel_endpoint_id)?;
userspace-dp/src/afxdp/gre.rs:866:    // SAME resolved outer MTU the rest of the tunnel path uses
userspace-dp/src/afxdp/gre.rs:867:    // (`tunnel_outer_mtu`, #2300 SSOT — the real transport ifindex, not
userspace-dp/src/afxdp/gre.rs:868:    // the logical tunnel ifindex). The 4-byte GRE key, when present, is
userspace-dp/src/afxdp/gre.rs:874:    let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
userspace-dp/src/afxdp/types/forwarding.rs:3:// route entries, egress and tunnel-endpoint descriptors, fabric-link
userspace-dp/src/afxdp/types/forwarding.rs:20:/// key fields use (`TunnelEndpoint`/`WgRuntimePeer` in this file).
userspace-dp/src/afxdp/types/forwarding.rs:95:    pub(in crate::afxdp) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
userspace-dp/src/afxdp/types/forwarding.rs:96:    pub(in crate::afxdp) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
userspace-dp/src/afxdp/types/forwarding.rs:98:    /// decap fast path. Keyed by the OUTER tuple as seen FROM THE
userspace-dp/src/afxdp/types/forwarding.rs:103:    /// (proto-47) packet can NEVER be decapped against a WireGuard or
userspace-dp/src/afxdp/types/forwarding.rs:109:    /// `tunnel_endpoints.values().find(...)` scan (agy #4).
userspace-dp/src/afxdp/types/forwarding.rs:110:    pub(in crate::afxdp) gre_decap_index: FastMap<(i32, IpAddr, IpAddr), Vec<u16>>,
userspace-dp/src/afxdp/types/forwarding.rs:111:    /// WireGuard engines keyed by tunnel_endpoint_id (#1432 S2a). One
userspace-dp/src/afxdp/types/forwarding.rs:116:    /// live sessions survive a commit that does not touch the tunnel.
userspace-dp/src/afxdp/types/forwarding.rs:120:    pub(in crate::afxdp) has_wg_tunnels: bool,
userspace-dp/src/afxdp/types/forwarding.rs:274:    pub(in crate::afxdp) tunnel_interfaces: FastSet<i32>,
userspace-dp/src/afxdp/types/forwarding.rs:281:    /// tunnels between the same endpoints map to distinct sessions. The
userspace-dp/src/afxdp/types/forwarding.rs:581:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:588:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:595:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:609:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:620:    /// `ifindex` / `tunnel_endpoint_id` accessors below select the FIRST
userspace-dp/src/afxdp/types/forwarding.rs:648:    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
userspace-dp/src/afxdp/types/forwarding.rs:651:            .map(|nh| nh.tunnel_endpoint_id)
userspace-dp/src/afxdp/types/forwarding.rs:663:    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
userspace-dp/src/afxdp/types/forwarding.rs:666:            .map(|nh| nh.tunnel_endpoint_id)
userspace-dp/src/afxdp/types/forwarding.rs:677:    /// `{ ifindex, tunnel_endpoint_id, next_hop }` shape so existing FIB
userspace-dp/src/afxdp/types/forwarding.rs:682:        tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:693:                tunnel_endpoint_id,
userspace-dp/src/afxdp/types/forwarding.rs:707:        tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:718:                tunnel_endpoint_id,
userspace-dp/src/afxdp/types/forwarding.rs:751:pub(in crate::afxdp) struct TunnelEndpoint {
userspace-dp/src/afxdp/types/forwarding.rs:787:/// (#1434). Decoded/parsed from the wire `TunnelWgPeerSnapshot`.
userspace-dp/src/afxdp/types/forwarding.rs:817:impl std::fmt::Debug for TunnelEndpoint {
userspace-dp/src/afxdp/types/forwarding.rs:820:        f.debug_struct("TunnelEndpoint")
userspace-dp/src/afxdp/types/forwarding.rs:992:    ///     tunnel-delivery channel) — this is the intended destination.
userspace-dp/src/afxdp/types/forwarding.rs:1036:    pub(crate) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:1:// decapsulated missing-neighbor handling, replay filtering, and DNAT-table publish/delete.
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:27:fn txn_decapped_missing_neighbor_not_buffered_tagged() {
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:28:    assert_decapped_missing_neighbor_never_buffered_or_retried(80);
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:38:fn txn_decapped_missing_neighbor_not_buffered_untagged() {
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:39:    assert_decapped_missing_neighbor_never_buffered_or_retried(0);
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:43:/// #1902 regression pin for the UNCHANGED path: a NON-decapped packet
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:49:fn txn_non_decap_missing_neighbor_buffers_and_retries_correctly() {
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:74:        "a non-decapped cold-neighbor packet must still buffer"
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:79:            .pending_neigh_decap_drops
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:82:        "the decap gate must not touch UMEM-paired packets"
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:156:/// preserved synced-session replay list by purged tunnel ids must
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:158:/// reverse companion (tunnel_endpoint_id == 0) of a dropped forward
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:178:    let tunnel_resolution = ForwardingResolution {
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:183:        tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:190:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:191:        ..tunnel_resolution
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:223:    // Case 1: tunnel-marked forward + unmarked derived reverse
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:226:        make(&forward_key, tunnel_resolution, false),
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:234:    // Case 2: reverse-marked tunnel entry drops standalone; its
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:240:        make(&reverse_key, tunnel_resolution, true),
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:247:    let mut entries = vec![make(&forward_key, tunnel_resolution, false)];
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:264:///     tunnel-id 0, so NOT purged on its own) is swept because its parent
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:293:    let tunnel_resolution = |id: u16| ForwardingResolution {
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:298:        tunnel_endpoint_id: id,
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:337:    // (src_port 40000). It carries tunnel-id 0, so it is never purged on its
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:353:    entries.push(make(&survivor_other, tunnel_resolution(0), false));
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:360:        entries.push(make(&fk, tunnel_resolution(id), false));
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:362:        // forward early. tunnel-id 0 → not purged on its own; it must drop
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:365:            entries.push(make(&derived_companion, tunnel_resolution(0), true));
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:369:            entries.push(make(&survivor_shares_ip, tunnel_resolution(0), false));
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:379:    entries.push(make(&reverse_only, tunnel_resolution(131), true));
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:386:    entries.push(make(&survivor_tail, tunnel_resolution(0), false));
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:402:    // The derived reverse companion (tunnel-id 0, never purged on its own)
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:594:// traceroute Time-Exceeded) carried over a native-GRE tunnel whose inner
userspace-dp/src/afxdp/types/runtime.rs:39:pub(in crate::afxdp) struct LocalTunnelSourceHandle {
userspace-dp/src/afxdp/types/runtime.rs:46:    pub(in crate::afxdp) wake: Option<Arc<TunnelWake>>,
userspace-dp/src/afxdp/types/runtime.rs:50:impl LocalTunnelSourceHandle {
userspace-dp/src/afxdp/types/runtime.rs:65:/// tunnel_endpoint_id in `Coordinator::tunnel_sources`. Mirrors
userspace-dp/src/afxdp/types/runtime.rs:75:pub(crate) struct LocalTunnelSourceEntry {
userspace-dp/src/afxdp/types/runtime.rs:77:    pub(in crate::afxdp) handle: Option<LocalTunnelSourceHandle>,
userspace-dp/src/afxdp/types/runtime.rs:79:    /// tunnel name. Attachment drift is the ONLY restart condition.
userspace-dp/src/afxdp/types/runtime.rs:81:    pub(in crate::afxdp) spawned_tunnel_name: String,
userspace-dp/src/afxdp/types/runtime.rs:86:    /// into `local_tunnel_deliveries` is restricted to entries with a
userspace-dp/src/afxdp/types/runtime.rs:88:    pub(in crate::afxdp) delivery_tx: Option<LocalTunnelDelivery>,
userspace-dp/src/afxdp/types/runtime.rs:94:/// tunnel_endpoint_id in `Coordinator::wg_control_threads`.
userspace-dp/src/afxdp/types/runtime.rs:106:    pub(in crate::afxdp) handle: Option<LocalTunnelSourceHandle>,
userspace-dp/src/afxdp/types/runtime.rs:114:    /// resolved tunnel name. Attachment drift is a stale condition —
userspace-dp/src/afxdp/types/runtime.rs:118:    pub(in crate::afxdp) spawned_tunnel_name: String,
userspace-dp/src/afxdp/types/runtime.rs:554:    pub(in crate::afxdp) local_tunnel_deliveries:
userspace-dp/src/afxdp/types/runtime.rs:555:        &'a Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
userspace-dp/src/afxdp/icmp.rs:5:/// #2486: per-packet marker set by native GRE decap
userspace-dp/src/afxdp/icmp.rs:6:/// (`try_native_gre_decap_from_frame`) so the forward-frame builder can
userspace-dp/src/afxdp/icmp.rs:8:/// GRE-decapped SYN. Without this marker the inner SYN was forwarded
userspace-dp/src/afxdp/icmp.rs:18:pub(super) const GRE_DECAP_INGRESS_FLAG: u8 = 0x40;
userspace-dp/src/afxdp/icmp.rs:317:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:1:// NAT64 translation/exhaustion accounting and tunnel-gate delivery.
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:517:// === #1873 R-C: blanket tunnel gate at the slow-path chokepoint ===
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:520:/// #1873 R-C: a tunnel-marked inner packet must NEVER be enqueued to
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:528:fn tunnel_marked_frame_never_reaches_slow_path() {
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:537:        let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:538:        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:543:            &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:546:            tunnel_marked_decision(disposition),
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:552:            live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:554:            "case {i}: tunnel gate did not fire"
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:565:            "tunnel_encap_unresolved",
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:575:fn tunnel_marked_build_failure_drops_instead_of_slow_path() {
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:576:    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:577:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:583:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:590:        tunnel_marked_decision(ForwardingDisposition::ForwardCandidate),
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:595:        live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:602:/// #1873 R-C: the local_tunnel_deliveries branch (GRE local-origin
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:606:fn tunnel_gate_keeps_local_tunnel_delivery_open() {
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:607:    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:610:    // sender; the worker slow path signals it via LocalTunnelDelivery.
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:611:    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:613:    deliveries.insert(9, LocalTunnelDelivery { tx, wake });
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:614:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:615:    let mut decision = tunnel_marked_decision(ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:621:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:630:        live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:633:    let delivered = rx.try_recv().expect("local tunnel delivery still open");
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:638:/// #1873 R-E: a tunnel-marked decision whose OUTER next-hop is
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:640:/// in-place rewrite cannot encapsulate, so a buffered tunnel inner
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:643:/// In this fixture the tunnel endpoint carries no redundancy_group and
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:644:/// the egress RG is unowned, so the HA gate resolves the tunnel-marked
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:648:/// was dropped+counted at the R-C tunnel gate
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:649:/// (`tunnel_encap_unresolved_drops`). After #1913 the chokepoint gates
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:656:fn txn_tunnel_marked_missing_neighbor_not_buffered() {
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:665:    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:688:    // No neighbors: the tunnel's OUTER destination (203.0.113.9 via the
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:690:    // with tunnel_endpoint_id preserved.
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:714:    // First packet: residual HAInactive (rg=0) tunnel-marked frame.
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:718:        "tunnel-marked frame must never be admitted to pending_neigh (#1873 R-E)"
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:728:        "HAInactive tunnel frame must NOT be reinjected to the kernel slow path (#1913)"
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:733:            .tunnel_encap_unresolved_drops
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:736:        "HAInactive frame is gated before the R-C tunnel gate post-#1913"
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:743:    // tunnel decision and must again be dropped — never buffered for
userspace-dp/src/afxdp/tests_nat64_tunnel.rs:762:        "tunnel-marked frame must skip pending_neigh admission on the re-run too (#1873 R-E)"
userspace-dp/src/afxdp/tx/dispatch/mod.rs:148:/// path. When `mtu` is 0 (no MTU resolvable / unknown tunnel kind)
userspace-dp/src/afxdp/tx/dispatch/mod.rs:169:    uses_native_tunnel: bool,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:191:    let mtu = if is_nat64 || uses_native_tunnel {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:353:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:536:                // #1873 R-C tunnel_encap_unresolved_drops gate). We touch
userspace-dp/src/afxdp/tx/dispatch/mod.rs:537:                // neither frame, so the Owned (GRE-decapped copy) vs Live
userspace-dp/src/afxdp/tx/dispatch/mod.rs:726:                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:740:                    uses_native_tunnel,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:773:                    && !uses_native_tunnel
userspace-dp/src/afxdp/tx/dispatch/mod.rs:987:                    let direct_built = if is_nat64 || uses_native_tunnel {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:1383:                local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:1539:    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/tx/dispatch/tests/ptb.rs:138:    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
userspace-dp/src/afxdp/tx/dispatch/tests/ptb.rs:161:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1:// GRE-to-self delivery, junos-host / host-inbound local delivery, and native GRE decap.
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:25:/// session-hit leg must ALSO deliver the decapped inner packet
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:40:    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:42:    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:43:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:54:            &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:61:            "{pass} pass delivery must be the decapped INNER packet byte-identical"
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:73:/// post-decap inner meta's l3_offset (14) — the payload started with
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:92:/// #1885 blast radius: NON-decapped local delivery was enqueued TWICE
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:94:/// decap-aware chokepoint — both pass the same disposition filter).
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:96:/// tunnel channel funnels to the kernel slow-path TUN; with no
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:118:    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:120:    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:121:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:130:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:136:        "a non-tunnel-ingress local packet must NOT hit the gr- channel"
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:174:    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:176:    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:177:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:186:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:236:    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:238:    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:239:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:248:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:697:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:725:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:748:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:850:/// #1885 decap-level consistency pin: on VLAN-TAGGED ingress the decap
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:856:fn native_gre_decap_tagged_ingress_yields_self_consistent_frame_meta() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:861:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:862:        .expect("tagged GRE-to-self outer frame must decap");
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:864:        &decap.frame[decap.meta.l3_offset as usize..],
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:868:    assert_eq!(decap.meta.ingress_ifindex, 77);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:869:    assert_eq!(decap.meta.addr_family, libc::AF_INET as u8);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:874:/// checksum) MUST decap to the inner packet — exactly the inner bytes at
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:875:/// the correct offset. Before #2782 the decap path returned `None` the
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:880:fn native_gre_decap_checksum_present_yields_inner_packet() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:892:    let before = crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:893:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:894:        .expect("checksum-present GRE frame must decap (RFC 2784 §2.1 / RFC 2890)");
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:896:        &decap.frame[decap.meta.l3_offset as usize..],
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:898:        "decapped inner must be byte-identical and at the correct offset"
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:900:    assert_eq!(decap.meta.addr_family, libc::AF_INET as u8);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:902:        crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:911:/// RFC 2890; the decap must skip ALL three to land on the inner payload.
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:915:fn native_gre_decap_checksum_key_sequence_present_yields_inner_packet() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:929:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:930:        .expect("C+Key+Seq GRE frame must decap with all optional fields skipped");
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:932:        &decap.frame[decap.meta.l3_offset as usize..],
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:934:        "decapped inner must be byte-identical with C+Key+Seq present"
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:941:/// `gre_decap_checksum_invalid_drops_total` counter must advance by one
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:942:/// and the decap must return `None`.
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:944:fn native_gre_decap_checksum_invalid_drops_and_counts() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:956:    let before = crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:958:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:962:        crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:975:fn native_gre_decap_checksum_present_truncated_header_fails_closed() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:993:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1000:/// match ONLY a non-GRE (here: WireGuard) tunnel row must NOT be
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1001:/// decapsulated as GRE. Pre-#2327 `match_tunnel_endpoint` scanned
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1002:/// `tunnel_endpoints.values()` ignoring `mode`, so any row whose outer
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1003:/// tuple lined up was decapped as GRE. We mutate the built state so the
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1005:/// "wireguard" — the GRE decap must return `None` (no match / drop),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1006:/// never decap the WireGuard endpoint's traffic as GRE. If the
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1007:/// kind-segregation in `match_tunnel_endpoint` / the build-side
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1008:/// `gre_decap_index` is reverted, this row reappears and the assert
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1011:fn gre_decap_does_not_match_wireguard_row_with_same_outer_tuple() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1015:    // the kind-segregated decap index (as the WG build path would).
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1017:    if let Some(ep) = forwarding.tunnel_endpoints.get_mut(&id) {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1020:    forwarding.gre_decap_index.clear();
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1026:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1027:        "a GRE frame matching only a WireGuard row must NOT decap as GRE"

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n -i 'wireguard.*decap|wg.*decap|decap.*wireguard|decap.*wg|WG_DECAP' userspace-dp/src/afxdp --glob '*.rs'
rg -n 'try_native_gre_decap_from_frame|process_wg|wireguard' userspace-dp/src/afxdp.rs userspace-dp/src/afxdp --glob '*.rs' | head -300"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 167ms:[0m
userspace-dp/src/afxdp/coordinator/status.rs:271:    /// #2317: WireGuard-decap inner packets dropped by the RFC 6040 §4.2
userspace-dp/src/afxdp/coordinator/status.rs:275:    /// `xpf_userspace_wg_decap_ecn_illegal_drops_total`; a nonzero value
userspace-dp/src/afxdp/coordinator/status.rs:278:    pub fn wg_decap_ecn_illegal_drops_total(&self) -> u64 {
userspace-dp/src/afxdp/coordinator/status.rs:279:        crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed)
userspace-dp/src/afxdp/types/forwarding.rs:103:    /// (proto-47) packet can NEVER be decapped against a WireGuard or
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1005:/// "wireguard" — the GRE decap must return `None` (no match / drop),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1006:/// never decap the WireGuard endpoint's traffic as GRE. If the
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1011:fn gre_decap_does_not_match_wireguard_row_with_same_outer_tuple() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1015:    // the kind-segregated decap index (as the WG build path would).
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1027:        "a GRE frame matching only a WireGuard row must NOT decap as GRE"
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:152:    /// `wireguard` — WireGuard engine encap/decap.
userspace-dp/src/afxdp/gre.rs:132:/// #2317: count of WireGuard-decap inner packets DROPPED by the same
userspace-dp/src/afxdp/gre.rs:136:/// `xpf_userspace_wg_decap_ecn_illegal_drops_total`. The WG decap path
userspace-dp/src/afxdp/gre.rs:143:pub(in crate::afxdp) static WG_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);
userspace-dp/src/afxdp/gre.rs:466:/// endpoints — so a GRE frame is NEVER decapped against a WireGuard or
userspace-dp/src/afxdp/wg/dscp.rs:31://! (`GRE_DECAP_ECN_ILLEGAL_DROPS` / `WG_DECAP_ECN_ILLEGAL_DROPS`).
userspace-dp/src/afxdp/coordinator/wg_control/sock.rs:201:/// data on the WG listen socket so the RFC 6040 §4.2 decap ECN combine
userspace-dp/src/afxdp/coordinator/wg_control/sock.rs:211:/// `IPV6_RECVTCLASS`) on a WG UDP socket so the decap ECN combine can see
userspace-dp/src/afxdp/coordinator/wg_control/sock.rs:233:            "xpf-wg: IP_RECVTOS not enabled (fd {fd}): {} — decap ECN combine inactive for v4",
userspace-dp/src/afxdp/coordinator/wg_control/sock.rs:250:                "xpf-wg: IPV6_RECVTCLASS not enabled (fd {fd}): {} — decap ECN combine inactive for v6",
userspace-dp/src/afxdp/coordinator/wg_control/dispatch.rs:175:                    // the GRE decap combine body, with the WG-specific
userspace-dp/src/afxdp/coordinator/wg_control/dispatch.rs:191:                                &crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS,
userspace-dp/src/afxdp/coordinator/wg_control/dispatch.rs:228:                Err(crate::afxdp::wg::DecapError::MalformedInner) => {
userspace-dp/src/afxdp/wg/tests.rs:10:use super::engine::{DecapError, EncapError, WgEngine, WgEngineConfig, WgPeerConfig};
userspace-dp/src/afxdp/wg/tests.rs:773:        // padded length must be zero — WG §5.4.6. The decap already
userspace-dp/src/afxdp/wg/tests.rs:1382:            "decap must accept a record whose trailing WG padding is \
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:654:// #2317: recvmsg / cmsg outer-ECN capture + RFC 6040 §4.2 WG decap
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:747:/// The WG decap site reuses the shared `apply_decap_ecn_combine`: an
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:785:/// passes `WG_DECAP_ECN_ILLEGAL_DROPS` (asserted separately below with
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:790:    use crate::afxdp::gre::{WG_DECAP_ECN_ILLEGAL_DROPS, apply_decap_ecn_combine};
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:808:    let wg_before = WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:816:        &WG_DECAP_ECN_ILLEGAL_DROPS,
userspace-dp/src/afxdp/coordinator/wg_control/wg_control_tests.rs:819:        WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed) >= wg_before + 1,
userspace-dp/src/afxdp/frame/wg_tests.rs:406:/// the responder (returned `.1`) can `try_decap` the resulting WG record,
userspace-dp/src/afxdp/frame/wg_tests.rs:1223:        .try_decap(wg_record, &mut recovered)
userspace-dp/src/afxdp/wg/engine.rs:1178:    /// (WG confirm-on-first-inbound-data). Called from `try_decap` after
userspace-dp/src/afxdp/wg/engine.rs:1568:            WgCounters::bump(&self.counters.decap_keepalives);
userspace-dp/src/afxdp/wg/engine.rs:1616:                WgCounters::bump(&self.counters.decap_packets);
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:738:                wg_decap_inner_ipv4_total_len(seg, &resp_engine)
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:850:            let _ = wg_decap_inner_ipv4_total_len(seg, &resp_engine);
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:1455:    /// — the revert case — a GRE frame that this WG decap cannot read).
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:1456:    fn wg_decap_inner_ipv4_total_len(seg: &[u8], engine: &WgEngine) -> usize {
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:1461:            .try_decap(wg_record, &mut plain)
rg: userspace-dp/src/afxdp.rs: No such file or directory (os error 2)
userspace-dp/src/afxdp/types/forwarding.rs:112:    /// per `mode == "wireguard"` endpoint. Shared (`Arc`) so workers
userspace-dp/src/afxdp/types/forwarding.rs:774:    // mode == "wireguard".
userspace-dp/src/afxdp/types/forwarding.rs:835:                &if self.mode == "wireguard" {
userspace-dp/src/afxdp/forwarding/mss.rs:115:/// For a `mode == "wireguard"` endpoint the GRE MSS formula
userspace-dp/src/afxdp/forwarding/mss.rs:154:    if endpoint.mode == "wireguard" {
userspace-dp/src/afxdp/gre.rs:209:///     below, wired into `try_native_gre_decap_from_frame` (#2315). This
userspace-dp/src/afxdp/gre.rs:621:pub(super) fn try_native_gre_decap_from_frame(
userspace-dp/src/afxdp/icmp.rs:6:/// (`try_native_gre_decap_from_frame`) so the forward-frame builder can
userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs:59:    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs:93:    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs:135:        try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state).is_none(),
userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs:160:    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:576:            mode: "wireguard".to_string(),
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:688:    fn wireguard_segmentation_uses_wg_inner_mtu_not_gre() {
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:817:    fn wireguard_segmentation_emits_wg_outer_never_gre() {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:541:            if endpoint.mode != "wireguard" {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:815:        if endpoint.mode != "wireguard" {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:947:        if endpoint.mode != "wireguard" || !self.forwarding.wg_engines.contains_key(&id) {
userspace-dp/src/afxdp/coordinator/status.rs:925:    /// One row per `mode == "wireguard"` tunnel endpoint with a live
userspace-dp/src/afxdp/coordinator/status.rs:939:            .filter(|(_, ep)| ep.mode == "wireguard")
userspace-dp/src/afxdp/coordinator/tests.rs:2757:            mode: "wireguard".to_string(),
userspace-dp/src/afxdp/coordinator/tests.rs:3114:            mode: "wireguard".to_string(),
userspace-dp/src/afxdp/coordinator/tests.rs:3270:            mode: "wireguard".to_string(),
userspace-dp/src/afxdp/coordinator/tests.rs:3522:/// gre→wireguard (reachable because ids are name-derived) prunes the
userspace-dp/src/afxdp/coordinator/tests.rs:3525:fn gre1881_mode_flip_to_wireguard_prunes_gre_entry() {
userspace-dp/src/afxdp/coordinator/wg_control/mod.rs:3://! One supervised aux thread per `mode == "wireguard"` tunnel endpoint,
userspace-dp/src/afxdp/icmp_ptb_tests.rs:903:fn post_transform_inner_mtu_wireguard_is_pad_aware() {
userspace-dp/src/afxdp/icmp_ptb_tests.rs:908:    insert_tunnel_endpoint(&mut fwd, "wireguard", libc::AF_INET, 0);
userspace-dp/src/afxdp/icmp_ptb_tests.rs:990:fn post_transform_wireguard_oversized_v6_emits_inner_ptb() {
userspace-dp/src/afxdp/icmp_ptb_tests.rs:997:    insert_tunnel_endpoint(&mut fwd, "wireguard", libc::AF_INET, 0);
userspace-dp/src/afxdp/poll_stages.rs:326:    let native_gre_packet = try_native_gre_decap_from_frame(raw_frame, meta, forwarding);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:861:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:893:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:929:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:958:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:993:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1005:/// "wireguard" — the GRE decap must return `None` (no match / drop),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1011:fn gre_decap_does_not_match_wireguard_row_with_same_outer_tuple() {
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1018:        ep.mode = "wireguard".to_string();
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1026:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1043:        ep.mode = "wireguard".to_string();
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1051:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1068:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1090:// `try_native_gre_decap_from_frame` directly so the assertion is on the
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1108:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1124:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1140:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1155:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1175:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1198:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1209:/// `try_native_gre_decap_from_frame` (gre.rs) makes this assertion fail
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1218:    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1238:        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1257:    assert_eq!(tunnel_mode_kind("wireguard"), TunnelKind::WireGuard);
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1259:    for bad in ["", "ipip", "vxlan", "GRE", "wireguard ", "gre6", "geneve"] {
userspace-dp/src/afxdp/mod.rs:141:// docs/pr/wireguard-clean/plan.md. Engine + tests only in this PR;
userspace-dp/src/afxdp/mod.rs:167:use self::gre::{encapsulate_native_gre_frame, try_native_gre_decap_from_frame};
userspace-dp/src/afxdp/forwarding_build/mod.rs:221:    // #1432 S2a: instantiate one WgEngine per mode=="wireguard" endpoint,
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:25:        let is_wireguard = endpoint.mode == "wireguard";
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:31:        let (source, destination) = if is_wireguard {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:83:        if is_wireguard {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:136:        if is_wireguard {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:152:    /// `wireguard` — WireGuard engine encap/decap.
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:166:        "wireguard" => TunnelKind::WireGuard,
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:216:/// must be "wireguard", listen_port must be nonzero, the local privkey
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:232:    if row.mode != "wireguard" {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:271:                        "xpf-userspace-dp: wireguard allowed-ips {:?} is not a valid CIDR; dropping this prefix (the peer keeps its other routes)",
userspace-dp/src/afxdp/wg/handshake.rs:6://! to what kernel WireGuard / wireguard-go / UniFi put on the wire:
userspace-dp/src/afxdp/wg/handshake.rs:99:    /// wireguard-go reject `len != MessageInitiationSize` / `MessageResponseSize`
userspace-dp/src/afxdp/wg/handshake.rs:212:    // (kernel WG / wireguard-go reject any other length).
userspace-dp/src/afxdp/wg/handshake.rs:218:    // reserved bytes = 0. wireguard-go / kernel WG read the full u32 and
userspace-dp/src/afxdp/test_fixtures.rs:268:            mode: "wireguard".to_string(),
userspace-dp/src/afxdp/wg/mod.rs:2://! dataplane. See `docs/pr/wireguard-clean/plan.md` for the design
userspace-dp/src/afxdp/wg/mod.rs:139:/// initial transcript hash matches the kernel WireGuard / wireguard-go
userspace-dp/src/afxdp/wg/mod.rs:141:/// (https://www.wireguard.com/protocol/) and the kernel source at
userspace-dp/src/afxdp/wg/mod.rs:142:/// `drivers/net/wireguard/noise.c` (search for "WireGuard v1 zx2c4").
userspace-dp/src/afxdp/wg/mod.rs:166:/// (WireGuard protocol page; wireguard-go `device/cookie.go` `Init`).
userspace-dp/src/afxdp/forwarding_build/tests.rs:4893:            mode: "wireguard".into(),
userspace-dp/src/afxdp/forwarding_build/tests.rs:4914:    assert_eq!(ep.mode, "wireguard");
userspace-dp/src/afxdp/forwarding_build/tests.rs:5065:                mode: "wireguard".into(),
userspace-dp/src/afxdp/wg/timers.rs:318:        // authenticated traversal in EITHER direction (wireguard-go
userspace-dp/src/afxdp/wg/cookie.rs:2://! (#4094 PR-A, WG whitepaper §5.4.7 / wireguard-go `device/cookie.go`).
userspace-dp/src/afxdp/wg/cookie.rs:40://! wireguard-go holds a single secret and re-challenges across a rotation
userspace-dp/src/afxdp/wg/cookie.rs:72:/// Responder cookie secret (`Rm`) rotation period. Mirrors wireguard-go
userspace-dp/src/afxdp/wg/cookie.rs:80:/// this grace period even if the rate falls back — mirrors wireguard-go's
userspace-dp/src/afxdp/wg/cookie.rs:87:/// cookie challenges. wireguard-go's analog is a handshake-queue depth of
userspace-dp/src/afxdp/wg/cookie.rs:115:/// wireguard-go `device/ratelimiter.go` (`packetsPerSecond` /
userspace-dp/src/afxdp/wg/cookie.rs:130:/// Run the per-source table GC at most this often (mirrors wireguard-go
userspace-dp/src/afxdp/wg/cookie.rs:417:    /// the initiation's source IP (mirrors wireguard-go `device/ratelimiter.go`)
userspace-dp/src/afxdp/wg/cookie.rs:716:/// the responder's [`CookieChecker`]. Mirrors wireguard-go
userspace-dp/src/afxdp/wg/cookie.rs:750:    /// MAC2. Two effects, mirroring wireguard-go `CookieGenerator::AddMacs`:
userspace-dp/src/afxdp/wg/session.rs:11://! (kernel `noise.c` `counter_validate` / wireguard-go `replay.go`
userspace-dp/src/afxdp/wg/session.rs:27:/// kernel/wireguard-go constants:
userspace-dp/src/afxdp/wg/session.rs:40:/// reference WireGuard `COUNTER_WINDOW_SIZE` (kernel/wireguard-go). A counter
userspace-dp/src/afxdp/wg/session.rs:255:/// the kernel `counter_validate` / wireguard-go `ValidateCounter`
userspace-dp/src/afxdp/wg/session.rs:270:    /// Highest counter accepted so far (wireguard-go `f.counter`).
userspace-dp/src/afxdp/wg/session.rs:310:    /// (kernel/wireguard-go). The test suite covers the in-order /
userspace-dp/src/afxdp/wg/session.rs:516:    fn reject_after_messages_constant_matches_wireguard_spec() {
userspace-dp/src/afxdp/wg/session.rs:522:    fn timer_constants_match_wireguard_spec() {
userspace-dp/src/afxdp/wg/tests.rs:840:/// matches kernel WireGuard and wireguard-go. We can't reach inside
userspace-dp/src/afxdp/wg/tests.rs:920:    // (`drivers/net/wireguard/noise.c`) uses the same byte string.
userspace-dp/src/afxdp/wg/tests.rs:1309:/// trailing padding bytes are non-zero (kernel WireGuard / wireguard-go
userspace-dp/src/afxdp/wg/peer.rs:107:/// current/previous/next keypair model (`drivers/net/wireguard/noise.c`,
userspace-dp/src/afxdp/wg/peer.rs:131:    /// the dead-peer detector — matching wireguard-go, where all
userspace-dp/src/afxdp/wg/peer.rs:182:    /// `memcmp(timestamp, last_timestamp) > 0` gate; wireguard-go's
userspace-dp/src/afxdp/wg/engine.rs:385:    /// WG and wireguard-go both do this. snow internally zeroizes
userspace-dp/src/afxdp/wg/engine.rs:571:    /// Ordering mirrors wireguard-go `device/receive.go`:
userspace-dp/src/afxdp/wg/engine.rs:804:    /// wireguard-go behaviour of retaining per-peer `last_timestamp`
userspace-dp/src/afxdp/wg/engine.rs:1300:        // kernel WG / wireguard-go. Compute the padded length and
userspace-dp/src/afxdp/wg/engine.rs:1531:        // wireguard-go fires its receive timers once the packet
userspace-dp/src/afxdp/wg/engine.rs:1647:        // interoperability with kernel WireGuard and wireguard-go. The
userspace-dp/src/afxdp/wg/engine.rs:1760:    // padding is not all-zero (kernel WireGuard / wireguard-go do not
userspace-dp/src/afxdp/frame/wg.rs:6://! `mode == "wireguard"` tunnel endpoint id directly (a route/connected
userspace-dp/src/afxdp/wg/tai64n.rs:5://! wireguard-go, UniFi) uses it for handshake anti-replay: it rejects an
userspace-dp/src/afxdp/wg/tai64n.rs:20://!   (`drivers/net/wireguard/noise.c`: `ktime_get_real_seconds() +
userspace-dp/src/afxdp/wg/tai64n.rs:21://!   0x400000000000000aULL`) and wireguard-go (`tai64n/tai64n.go`:
userspace-dp/src/afxdp/wg/tai64n.rs:33://! value equals numeric comparison — the same property wireguard-go relies
userspace-dp/src/afxdp/tunnel_tests.rs:169:        .mode = "wireguard".to_string();
userspace-dp/src/afxdp/tunnel_tests.rs:943:fn tunnel_tcp_mss_wireguard_uses_wg_overhead_not_gre() {
userspace-dp/src/afxdp/tunnel_tests.rs:946:    // under GRE mode, then flip the SAME endpoint to wireguard and
userspace-dp/src/afxdp/tunnel_tests.rs:965:        .mode = "wireguard".to_string();
userspace-dp/src/afxdp/coordinator/mod.rs:66:        .filter(|ep| ep.mode == "wireguard")
userspace-dp/src/afxdp/forwarding_build/wg.rs:2://! S2a). Builds one `Arc<WgEngine>` per `mode == "wireguard"` tunnel
userspace-dp/src/afxdp/forwarding_build/wg.rs:53:        if endpoint.mode != "wireguard" {
userspace-dp/src/afxdp/forwarding_build/wg.rs:110:                // different peer identity). Matches kernel / wireguard-go,

[35m[3mcodex[0m[0m
A repository-state warning: the checkout advanced during this read-only review from v6-r3 (`8b2ce31f`) to a newer plan revision. I’m pinning all conclusions to the requested v6-r3 snapshot and will use `git show` where necessary; I’ll also verify whether any cited production file changed before trusting current line numbers.
[35m[3mexec[0m[0m
[1m/bin/bash -lc 'git rev-parse HEAD
git status --short
git log -4 --oneline --decorate
git diff --name-only 8b2ce31fd4fc7ef6a30e6425c2dcc492cb500aa3..HEAD'[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
e4460612b479960eea3cb64ebeb516fc7874d5f6
e4460612b (HEAD -> research/2387-session-identity) research(#2387): plan v6-r4 — a reviewer refutation made the plan CHEAPER
8b2ce31fd research(#2387): v6-r3 follow-up — retire two stale no-version-bump claims
6ec5a057e research(#2387): plan v6-r3 — fold r2; two defects found in the FIX
8751d5a08 research(#2387): plan v6-r2 — fold Claude SMR + AGY r1
docs/research/2387-session-identity/agy-plan-r3.md
docs/research/2387-session-identity/claude-smr-plan-r3.md
docs/research/2387-session-identity/plan.md

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/coordinator/wg_control/dispatch.rs | sed -n '130,245p'
nl -ba userspace-dp/src/afxdp/coordinator/wg_control/mod.rs | sed -n '1,80p'
nl -ba userspace-dp/src/afxdp/forwarding_build/tunnels.rs | sed -n '135,175p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   130	                Err(_e) => {
   131	                    debug_log!("WG[{}]: drop initiation reason={:?}", tunnel_name, _e);
   132	                    InboundOutcome::Unauthenticated
   133	                }
   134	            }
   135	        }
   136	        crate::afxdp::wg::WG_TYPE_RESPONSE => match engine.consume_response(datagram) {
   137	            Ok((peer_pubkey, _idx)) => InboundOutcome::CompletedInitiator(peer_pubkey),
   138	            Err(_e) => {
   139	                debug_log!("WG[{}]: drop response reason={:?}", tunnel_name, _e);
   140	                InboundOutcome::Unauthenticated
   141	            }
   142	        },
   143	        crate::afxdp::wg::WG_TYPE_COOKIE => {
   144	            // #4094 PR-B: initiator-side cookie-reply consume. A responder
   145	            // under load answers our valid-MAC1 initiation with a type-3
   146	            // cookie-reply instead of a handshake response; decrypt it and
   147	            // store the cookie so our NEXT initiation to that peer carries a
   148	            // valid MAC2 (completing the handshake under load). NOT
   149	            // authenticated for endpoint-learning: a cookie-reply is
   150	            // XChaCha-sealed under our own public-key-derived key and proves
   151	            // nothing about whether the source holds the peer's keys.
   152	            // consume_cookie_reply counts internally (hs_rx_cookie_consumed
   153	            // on success, hs_rx_cookie_unsupported on a drop).
   154	            if !engine.consume_cookie_reply(datagram, engine.now_ns()) {
   155	                // Reply we could not attribute (no matching in-flight
   156	                // initiation) or could not decrypt (wrong key / bad AAD /
   157	                // tampered).
   158	                debug_log!("WG[{}]: drop cookie (unconsumable)", tunnel_name);
   159	            }
   160	            InboundOutcome::Unauthenticated
   161	        }
   162	        crate::afxdp::wg::WG_TYPE_DATA => {
   163	            match engine.try_decap(datagram, decap_buf) {
   164	                Ok(outcome) => {
   165	                    // #2317: RFC 6040 §4.2 decap-side ECN combine. The
   166	                    // outer ECN was captured out-of-band via recvmsg's
   167	                    // IP_RECVTOS / IPV6_RECVTCLASS cmsg (the kernel UDP
   168	                    // stack stripped the outer IP header before this WG
   169	                    // record reached userspace). Fold it into the
   170	                    // freshly-decrypted inner IP packet: an outer CE
   171	                    // upgrades an ECN-capable inner to CE (recomputing the
   172	                    // inner IPv4 header checksum), and the illegal
   173	                    // outer-CE / inner-Not-ECT combination is dropped
   174	                    // (counter bumped in apply_decap_ecn_combine). Reuses
   175	                    // the GRE decap combine body, with the WG-specific
   176	                    // illegal-drop counter. Skipped when no TOS cmsg
   177	                    // arrived (`outer_ecn` is None) or the inner family is
   178	                    // unrecognizable — never mutate on a malformed inner.
   179	                    if let Some(outer_ecn) = outer_ecn {
   180	                        let inner = &mut decap_buf[..outcome.len];
   181	                        let inner_family = match inner.first().map(|b| b >> 4) {
   182	                            Some(4) => Some(libc::AF_INET as u8),
   183	                            Some(6) => Some(libc::AF_INET6 as u8),
   184	                            _ => None,
   185	                        };
   186	                        if let Some(fam) = inner_family
   187	                            && !crate::afxdp::gre::apply_decap_ecn_combine(
   188	                                inner,
   189	                                fam,
   190	                                outer_ecn,
   191	                                &crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS,
   192	                            )
   193	                        {
   194	                            // Illegal RFC 6040 §4.2 combination — drop the
   195	                            // inner without writing it to the TUN. The
   196	                            // datagram still authenticated (the peer holds
   197	                            // the keys), so endpoint-learning proceeds.
   198	                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
   199	                        }
   200	                    }
   201	                    // Write the plaintext inner IP to the wgN TUN; the
   202	                    // kernel routes/firewalls it (NOT the AF_XDP policy
   203	                    // engine — the AllowedIPs gate inside try_decap is
   204	                    // S2a's inner-src control).
   205	                    //
   206	                    // #2438: the wgN TUN fd is O_NONBLOCK, so this uses
   207	                    // the single-write whole-packet seam
   208	                    // (`write_packet_nonblocking`) — never std
   209	                    // `Write::write_all`, whose short-count stream-resume
   210	                    // would re-write `buf[n..]` and inject the remainder
   211	                    // as a SECOND, malformed inner packet (the #2407
   212	                    // corruption class). The seam retries the WHOLE
   213	                    // packet on WouldBlock/EINTR and drops (counted) on a
   214	                    // genuine partial.
   215	                    if let Err(e) = crate::slowpath::write_packet_nonblocking(
   216	                        tun.as_raw_fd(),
   217	                        &decap_buf[..outcome.len],
   218	                    ) {
   219	                        WgCounters::bump(&engine.counters().tun_write_errors);
   220	                        record_local_tunnel_exception(
   221	                            recent_exceptions,
   222	                            tunnel_name,
   223	                            format!("wg_tun_write:{e}"),
   224	                        );
   225	                    }
   226	                    InboundOutcome::Authenticated(outcome.peer_pubkey)
   227	                }
   228	                Err(crate::afxdp::wg::DecapError::MalformedInner) => {
   229	                    // MalformedInner is only ever returned POST-AEAD:
   230	                    // the authenticated zero-length keepalive exits
   231	                    // decap through it by design (#1865), and a
   232	                    // malformed-but-authenticated inner also proves
   233	                    // the peer holds the session keys. Both count for
   234	                    // endpoint learning (this closes the #1865 plan §9
   235	                    // latent gap: a keepalive-only roaming peer now
   236	                    // updates our egress endpoint). #1434: try_decap's
   237	                    // MalformedInner/keepalive arm does not surface the
   238	                    // peer, so per-peer endpoint learning is only
   239	                    // unambiguous when the tunnel has exactly ONE peer
   240	                    // (the keepalive-roaming case the #1865 fix targets).
   241	                    // With multiple peers we cannot attribute a bare
   242	                    // keepalive to a specific peer here, so skip the
   243	                    // learn for THIS datagram (the next DATA record from
   244	                    // the peer learns it via the Authenticated(peer)
   245	                    // arm above). Return Unauthenticated so no wrong-peer
     1	//! WireGuard control thread (#1432 S2a).
     2	//!
     3	//! One supervised aux thread per `mode == "wireguard"` tunnel endpoint,
     4	//! modeled on `spawn_local_tunnel_sources` (the GRE local-origin
     5	//! template). The thread owns three handles:
     6	//!
     7	//!   - `Arc<WgEngine>` — the S1 wire-compliant engine (shared with the
     8	//!     dataplane workers via `ForwardingState.wg_engines`).
     9	//!   - a `UdpSocket` bound on `wg_listen_port` (outer transport, RX+TX).
    10	//!   - the persistent `wgN` **TUN** (inner). The kernel routes inner
    11	//!     traffic to/from it; xpf does not re-implement inner routing or
    12	//!     policy in S2a.
    13	//!
    14	//! ## RX model — kernel socket, ESP/IPsec precedent (plan §3.4)
    15	//!
    16	//! WG-to-firewall is local-destination UDP. The XDP shim passes
    17	//! local-destination UDP to the kernel via `cpumap_or_pass` (the same
    18	//! path ESP rides), and a dedicated shim early-return steers WG-port
    19	//! local-destination UDP to the kernel deterministically, so this kernel
    20	//! `UdpSocket` receives ALL inbound WG datagrams — handshake AND
    21	//! transport. There is no AF_XDP hot-path decap stage and no
    22	//! worker→control packet channel in S2a; the only worker→control
    23	//! coupling is the relaxed-atomic NoSession handshake-request edge that
    24	//! `WgEngine::request_handshake` records and this thread consumes.
    25	//!
    26	//! ## Directions
    27	//!
    28	//!   - **Inbound** (kernel socket → engine → TUN): dispatch on the WG
    29	//!     type byte. type 1 → `consume_initiation_create_response` + send
    30	//!     the response; type 2 → `consume_response`; type 3 (cookie) →
    31	//!     drop+count (S7); type 4 (transport) → `try_decap` (the engine
    32	//!     AllowedIPs-gates the inner src) → write the plaintext inner IP to
    33	//!     the `wgN` TUN, where the kernel routes/firewalls it.
    34	//!   - **Egress** (TUN → engine → kernel socket): inner IP packets the
    35	//!     kernel routes onto `wgN` are read, `try_encap`'d, and sent to the
    36	//!     peer endpoint. The transit AF_XDP egress is the other encap site
    37	//!     (frame/mod.rs).
    38	//!
    39	//! ## Timers + idle wait (#1888 S5 / #1889)
    40	//!
    41	//! The loop blocks in poll(2) over {socket, TUN} POLLIN when idle
    42	//! (timeout = min(next timer deadline, 100ms cap) — the cap bounds
    43	//! stop/join and worker-edge latency) and runs a 1s-granularity timer
    44	//! arm: session expiry (REJECT_AFTER_TIME teardown), the pure
    45	//! `WgEngine::timer_pass` (passive/persistent keepalives, no-reply
    46	//! reinit), and the handshake ATTEMPT machine (5s retransmit pacing,
    47	//! 90s give-up window, identity-based success). Per-use T1/T2/T3 age
    48	//! enforcement lives in the engine's encap/decap paths; this loop owns
    49	//! all sends. Design of record:
    50	//! `docs/research/1888-wg-timers/plan.md` (plan v9, 3/3 PLAN-READY).
    51	//!
    52	//! ## Layout (#6438)
    53	//!
    54	//! `mod.rs` keeps the thread entry (`wg_control_loop`) and the
    55	//! orchestrating `run_wg_control_loop` (RX bursts → TUN burst → timer
    56	//! arm → idle poll). The fused layers live in submodules:
    57	//!
    58	//!   - `mtu` — the pad-aware encapped-size formula + outer-MTU guard.
    59	//!   - `sock` — socket bind/options, the v4-mapped send shim, the #2317
    60	//!     outer-TOS cmsg codec, and the poll(2) wait layer.
    61	//!   - `attempt` — the #1888 S5 handshake attempt machine + keepalive
    62	//!     emit/pace helpers.
    63	//!   - `dispatch` — inbound type-byte dispatch (`InboundOutcome`
    64	//!     auth-before-roam contract) + the TUN-read encap-and-send.
    65	
    66	use super::*;
    67	use crate::afxdp::wg::counters::WgCounters;
    68	use std::io::Read;
    69	use std::net::{SocketAddr, UdpSocket};
    70	use std::os::fd::AsRawFd;
    71	
    72	mod attempt;
    73	mod dispatch;
    74	mod mtu;
    75	mod sock;
    76	
    77	use attempt::{
    78	    AttemptTrigger, HandshakeAttempt, drive_attempt_machine, pace_keepalive_skip, send_keepalive,
    79	    start_attempt,
    80	};
   135	        }
   136	        if is_wireguard {
   137	            state.has_wg_tunnels = true;
   138	        }
   139	    }
   140	    Ok(())
   141	}
   142	
   143	/// #2327: the typed kind of a tunnel-endpoint `mode` string. Centralizes
   144	/// the kind classification that the decap index, the egress encap
   145	/// dispatcher, and the GRE supervision paths all rely on, so a future
   146	/// tunnel kind is added in exactly one place and the egress dispatcher's
   147	/// fail-closed `_ =>` arm cannot silently treat it as GRE.
   148	#[derive(Clone, Copy, PartialEq, Eq, Debug)]
   149	pub(in crate::afxdp) enum TunnelKind {
   150	    /// `gre` / `ip6gre` — native GRE encapsulation/decapsulation.
   151	    Gre,
   152	    /// `wireguard` — WireGuard engine encap/decap.
   153	    WireGuard,
   154	    /// Any unrecognized / future / malformed mode string. The egress
   155	    /// dispatcher MUST fail closed (drop) on this rather than default to
   156	    /// GRE encap (the pre-#2327 fail-open behavior).
   157	    Unknown,
   158	}
   159	
   160	/// Classify a tunnel-endpoint `mode` string into a `TunnelKind`. Mirrors
   161	/// the canonical GRE-kind test used across the supervision paths
   162	/// (`mode == "gre" || mode == "ip6gre"`).
   163	pub(in crate::afxdp) fn tunnel_mode_kind(mode: &str) -> TunnelKind {
   164	    match mode {
   165	        "gre" | "ip6gre" => TunnelKind::Gre,
   166	        "wireguard" => TunnelKind::WireGuard,
   167	        _ => TunnelKind::Unknown,
   168	    }
   169	}
   170	
   171	/// #1866: the hydratable WG identity of one tunnel-endpoint snapshot
   172	/// row — the exact field set `wg_identity_unchanged`
   173	/// (`forwarding_build/wg.rs`) keys engine reuse on, hydrated with the
   174	/// exact gates `populate_tunnel_endpoints` applies. Single source of
   175	/// truth shared by the populate pass, the coordinator's

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'SessionInstall|insert_session|create_session|install_session|SessionEntry \\{|insert_forward|insert_reverse|upsert_synced_session|put_session' userspace-dp/src --glob '*.rs' | head -500"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
userspace-dp/src/protocol/control.rs:324:    /// aggregate admission bound (`upsert_synced_session`). Locally-created
userspace-dp/src/protocol/control.rs:1134:    /// (`build_synced_session_entry` -> `SessionInstall::session_id` ->
userspace-dp/src/afxdp/shared_ops.rs:212:pub(super) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
userspace-dp/src/afxdp/shared_ops.rs:428:/// index only covers sessions added via `upsert_synced_session` — locally
userspace-dp/src/afxdp/shared_ops.rs:774:    Some(SyncedSessionEntry {
userspace-dp/src/afxdp/shared_ops.rs:874:        let reverse_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:66:        SessionInstall {
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:88:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:676:fn n6472_install_sessions(sessions: &mut SessionTable, now_ns: u64) {
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:833:    n6472_install_sessions(&mut sessions, 123_000_000_000);
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:958:    n6472_install_sessions(&mut sessions, 123_000_000_000);
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:1071:    n6472_install_sessions(&mut sessions, 123_000_000_000);
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:2853:    let shared_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/mod.rs:809:                    SessionInstall {
userspace-dp/src/afxdp/session_glue/mod.rs:1131:            SessionInstall {
userspace-dp/src/session/ctx.rs:8://! - [`SessionInstall`] carries an owned [`SessionKey`]. Used by
userspace-dp/src/session/ctx.rs:31:pub(crate) struct SessionInstall {
userspace-dp/src/session/ctx.rs:54:/// [`SessionInstall`] would force an unnecessary owned copy at
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:779:    let shared_entry = SyncedSessionEntry {
userspace-dp/src/server/handlers/sync_session.rs:22:                guard.afxdp.upsert_synced_session(entry);
userspace-dp/src/session/install.rs:148:            entry: SessionEntry {
userspace-dp/src/session/install.rs:277:            SessionInstall {
userspace-dp/src/session/install.rs:297:        req: SessionInstall,
userspace-dp/src/session/install.rs:300:        let SessionInstall {
userspace-dp/src/session/install.rs:347:            entry: SessionEntry {
userspace-dp/src/afxdp/tunnel.rs:595:    let session_entry = SyncedSessionEntry {
userspace-dp/src/session/mod.rs:344:struct SessionEntry {
userspace-dp/src/afxdp/bpf_map/metrics.rs:253:/// that have no per-binding context (HA `upsert_synced_session`,
userspace-dp/src/afxdp/bpf_map/metrics.rs:264:/// coordinator's peer-synced install path (`upsert_synced_session`), which
userspace-dp/src/afxdp/session_glue/tests.rs:465:    let shared_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:553:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:629:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:728:    let shared_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:783:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:833:    let shared_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:903:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:943:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:995:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1044:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1137:    let mut entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1190:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1247:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1324:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1510:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1595:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1767:        .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:1833:        .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:2466:    let forward = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:2477:    let reverse = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:2545:    let mut entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:2598:    let mut entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3284:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3339:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3417:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3500:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3533:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3759:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3832:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3907:    let mut entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:3972:    let mut entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4077:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4181:        &SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4309:    let synced_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4575:fn test_synced_entry() -> SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4576:    SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4688:fn w3_forward_entry(src_host: u8, src_port: u16, snat_ip: Ipv4Addr) -> SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4691:    SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:4872:    let dnat = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:5024:    let forward = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/tests.rs:5281:    let shared_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/session_glue/promote.rs:116:        let promoted_entry = SyncedSessionEntry {
userspace-dp/src/server/helpers/session_sync.rs:168:    Ok(SyncedSessionEntry {
userspace-dp/src/afxdp/mod.rs:20:    SessionInstall, SessionKey, SessionLookup, SessionMetadata, SessionOrigin, SessionTable,
userspace-dp/src/session/tests.rs:421:// session id carried on the HA session-sync wire (SessionInstall.session_id)
userspace-dp/src/session/tests.rs:445:        SessionInstall {
userspace-dp/src/session/tests.rs:468:        SessionInstall {
userspace-dp/src/session/tests.rs:6013:        SessionInstall {
userspace-dp/src/session/tests.rs:6090:            SessionInstall {
userspace-dp/src/session/tests.rs:6143:            SessionInstall {
userspace-dp/src/session/tests.rs:6177:        SessionInstall {
userspace-dp/src/session/tests.rs:6352:        SessionInstall {
userspace-dp/src/session/tests.rs:6558:        SessionInstall {
userspace-dp/src/afxdp/coordinator/session_manager.rs:34:    /// a stale-generation install (`upsert_synced_session`, the
userspace-dp/src/afxdp/coordinator/session_manager.rs:45:    /// aggregate admission bound (`upsert_synced_session`). Locally-created
userspace-dp/src/afxdp/coordinator/session_manager.rs:52:    /// (the availability/DoS root of #5674). `upsert_synced_session` now bounds
userspace-dp/src/afxdp/coordinator/status.rs:185:    /// peer-synced install path (`upsert_synced_session`, #4393), which has no
userspace-dp/src/afxdp/coordinator/status.rs:218:    /// aggregate admission bound (`upsert_synced_session`). Locally-created
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:194:        |key: &SessionKey, resolution: ForwardingResolution, is_reverse: bool| SyncedSessionEntry {
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:305:        SyncedSessionEntry {
userspace-dp/src/afxdp/ha/session_import.rs:10:    /// import, and `upsert_synced_session` publishes both into `sessions.synced`
userspace-dp/src/afxdp/ha/session_import.rs:46:    pub fn upsert_synced_session(&self, entry: SyncedSessionEntry) {
userspace-dp/src/afxdp/ha/session_import.rs:311:            // this peer-synced forward SNAT session at `upsert_synced_session`
userspace-dp/src/afxdp/ha/session_import.rs:403:        self.upsert_synced_session(SyncedSessionEntry {
userspace-dp/src/afxdp/forwarding/tests.rs:2406:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/checksum.rs:295:// `upsert_synced_session` publishes the reverse-SNAT `dnat_table` entry for a
userspace-dp/src/afxdp/checksum.rs:297:// `upsert_synced_session` (the standby loses the embedded-ICMP steering entry
userspace-dp/src/afxdp/forwarding/local_delivery.rs:116:    let local_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:261:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:370:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:490:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:649:fn synced_entry_with_generation(generation: u64) -> SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:650:    SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:738:    busy.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:740:    busy.upsert_synced_session(synced_entry_with_generation(1));
userspace-dp/src/afxdp/ha_tests.rs:745:    busy.upsert_synced_session(synced_entry_port(2000, 0));
userspace-dp/src/afxdp/ha_tests.rs:790:fn upsert_synced_session_refuses_stale_generation_install() {
userspace-dp/src/afxdp/ha_tests.rs:795:    coordinator.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:799:    coordinator.upsert_synced_session(synced_entry_with_generation(1));
userspace-dp/src/afxdp/ha_tests.rs:816:    // `upsert_synced_session_applies_equal_and_newer_generation` being read
userspace-dp/src/afxdp/ha_tests.rs:818:    coordinator.upsert_synced_session(synced_entry_with_generation(3));
userspace-dp/src/afxdp/ha_tests.rs:838:// availability/DoS root of #5674). `upsert_synced_session` now bounds the
userspace-dp/src/afxdp/ha_tests.rs:857:// `upsert_synced_session` gate (`ha.rs`, the
userspace-dp/src/afxdp/ha_tests.rs:863:fn synced_entry_port(port: u16, generation: u64) -> SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:864:    SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:880:fn upsert_synced_session_rejects_over_ceiling_import_and_does_not_fan_out() {
userspace-dp/src/afxdp/ha_tests.rs:912:        coordinator.upsert_synced_session(entry);
userspace-dp/src/afxdp/ha_tests.rs:933:    coordinator.upsert_synced_session(rejected);
userspace-dp/src/afxdp/ha_tests.rs:974:    coordinator.upsert_synced_session(synced_entry_port(1000, 7));
userspace-dp/src/afxdp/ha_tests.rs:991:// `upsert_synced_session` read the map length with
userspace-dp/src/afxdp/ha_tests.rs:1020:        coordinator.upsert_synced_session(entry);
userspace-dp/src/afxdp/ha_tests.rs:1036:    coordinator.upsert_synced_session(rejected);
userspace-dp/src/afxdp/ha_tests.rs:1133:fn upsert_synced_session_applies_equal_and_newer_generation() {
userspace-dp/src/afxdp/ha_tests.rs:1137:    coordinator.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:1138:    coordinator.upsert_synced_session(synced_entry_with_generation(2)); // equal — applies
userspace-dp/src/afxdp/ha_tests.rs:1140:    coordinator.upsert_synced_session(synced_entry_with_generation(5)); // newer — applies
userspace-dp/src/afxdp/ha_tests.rs:1147:fn upsert_synced_session_legacy_zero_generation_applies() {
userspace-dp/src/afxdp/ha_tests.rs:1150:    coordinator.upsert_synced_session(synced_entry_with_generation(5));
userspace-dp/src/afxdp/ha_tests.rs:1151:    coordinator.upsert_synced_session(synced_entry_with_generation(0)); // legacy — applies
userspace-dp/src/afxdp/ha_tests.rs:1167:    coordinator.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:1204:    coordinator.upsert_synced_session(synced_entry_with_generation(9));
userspace-dp/src/afxdp/ha_tests.rs:1214:// `upsert_synced_session` read the stored entry with `.lock().ok()` and the
userspace-dp/src/afxdp/ha_tests.rs:1231:// in `upsert_synced_session`, or `.lock().ok().and_then(|s|
userspace-dp/src/afxdp/ha_tests.rs:1272:    coordinator.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:1281:    coordinator.upsert_synced_session(synced_entry_with_generation(1));
userspace-dp/src/afxdp/ha_tests.rs:1310:    coordinator.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:1354:    coordinator.upsert_synced_session(synced_entry_with_generation(2));
userspace-dp/src/afxdp/ha_tests.rs:1358:    coordinator.upsert_synced_session(synced_entry_with_generation(3));
userspace-dp/src/afxdp/ha_tests.rs:1409:    coordinator.upsert_synced_session(synced_entry_with_generation(9));
userspace-dp/src/afxdp/ha_tests.rs:1417:    coordinator.upsert_synced_session(synced_entry_with_generation(8));
userspace-dp/src/afxdp/ha_tests.rs:1470:fn synced_snat_entry() -> SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:1479:    SyncedSessionEntry {
userspace-dp/src/afxdp/ha_tests.rs:1504:/// counted). RED on revert: remove the publish from `upsert_synced_session` and
userspace-dp/src/afxdp/ha_tests.rs:1525:    coordinator.upsert_synced_session(synced_snat_entry());
userspace-dp/src/afxdp/ha_tests.rs:1550:    coordinator.upsert_synced_session(synced_entry_with_generation(0));
userspace-dp/src/afxdp/ha_tests.rs:1644:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/worker/mod.rs:376:pub(crate) struct SyncedSessionEntry {
userspace-dp/src/afxdp/tests_bind_forward.rs:1139:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tests_bind_forward.rs:1189:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tests_bind_forward.rs:1241:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tests_bind_forward.rs:1304:    let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560:                                        let forward_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2897:                                        let reverse_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/poll_descriptor/mod.rs:4812:                                        let entry = SyncedSessionEntry {
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:542:            .install_session(
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:564:            .install_session(&init_pub, resp_session)
userspace-dp/src/afxdp/wg/engine.rs:24://!     and installs the resulting session via `install_session`.
userspace-dp/src/afxdp/wg/engine.rs:422:    /// `reconcile_peers` and `install_session` both take it to
userspace-dp/src/afxdp/wg/engine.rs:1107:    pub(crate) fn install_session(
userspace-dp/src/afxdp/wg/engine.rs:1122:        self.install_session_locked(pubkey, session)
userspace-dp/src/afxdp/wg/engine.rs:1125:    /// Lock-free core of `install_session`: the caller MUST already hold
userspace-dp/src/afxdp/wg/engine.rs:1130:    pub(in crate::afxdp::wg) fn install_session_locked(
userspace-dp/src/afxdp/wg/engine.rs:1639:    /// `StatelessTransportState` that `install_session` wraps.
userspace-dp/src/afxdp/wg/handshake_session.rs:123:    /// `install_session` / `reconcile_peers`) so the reservation is atomic
userspace-dp/src/afxdp/wg/handshake_session.rs:203:        // concurrent handshake or `install_session` cannot claim this index
userspace-dp/src/afxdp/wg/handshake_session.rs:205:        // `install_session_locked`) or releases the reservation. decap never
userspace-dp/src/afxdp/wg/handshake_session.rs:207:        // by `install_session_locked` on completion.
userspace-dp/src/afxdp/wg/handshake_session.rs:498:        // the reconcile_lock we already hold (install_session_locked must NOT
userspace-dp/src/afxdp/wg/handshake_session.rs:500:        let result = match self.install_session_locked(&peer_pubkey, session) {
userspace-dp/src/afxdp/wg/handshake_session.rs:656:        let install = match self.install_session_locked(&peer_pubkey, session) {
userspace-dp/src/afxdp/frame/wg_tests.rs:389:        .install_session(
userspace-dp/src/afxdp/frame/wg_tests.rs:457:        .install_session(
userspace-dp/src/afxdp/frame/wg_tests.rs:470:        .install_session(
userspace-dp/src/afxdp/wg/engine_tests.rs:16:/// (`install_session_serializes_with_reconcile_removal`,
userspace-dp/src/afxdp/wg/engine_tests.rs:141:/// install_session unit tests below — going through snow is
userspace-dp/src/afxdp/wg/engine_tests.rs:172:fn install_session_same_peer_same_local_index_is_collision() {
userspace-dp/src/afxdp/wg/engine_tests.rs:199:    engine.install_session(&peer_pub, s1).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:203:    let err = engine.install_session(&peer_pub, s2).unwrap_err();
userspace-dp/src/afxdp/wg/engine_tests.rs:222:fn install_session_fresh_index_rekey_preserves_previous_demux() {
userspace-dp/src/afxdp/wg/engine_tests.rs:249:    engine.install_session(&peer_pub, s1).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:252:    engine.install_session(&peer_pub, s2).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:265:fn install_session_second_rekey_evicts_dropped_session() {
userspace-dp/src/afxdp/wg/engine_tests.rs:291:    engine.install_session(&peer_pub, s1).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:293:    engine.install_session(&peer_pub, s2).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:295:    engine.install_session(&peer_pub, s3).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:310:fn install_session_rejects_local_index_collision_across_peers() {
userspace-dp/src/afxdp/wg/engine_tests.rs:358:    engine.install_session(&peer_a_pub, sa).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:360:    let err = engine.install_session(&peer_b_pub, sb).unwrap_err();
userspace-dp/src/afxdp/wg/engine_tests.rs:415:    engine.install_session(&peer_pub, session).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:462:    engine.install_session(&peer_pub, s1).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:464:    engine.install_session(&peer_pub, s2).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:540:    engine.install_session(&peer_a_pub, s_a).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:542:    engine.install_session(&peer_b_pub, s_b).unwrap();
userspace-dp/src/afxdp/wg/engine_tests.rs:744:/// r6 regression: `install_session` and `reconcile_peers` must
userspace-dp/src/afxdp/wg/engine_tests.rs:749:///   1. install_session(P) loads `peer` via `peer_arc(P)` from
userspace-dp/src/afxdp/wg/engine_tests.rs:755:///   3. install_session continues against the orphan Arc<Peer>,
userspace-dp/src/afxdp/wg/engine_tests.rs:761:/// Fix: `install_session` takes `reconcile_lock` for the entire
userspace-dp/src/afxdp/wg/engine_tests.rs:774:fn install_session_serializes_with_reconcile_removal() {
userspace-dp/src/afxdp/wg/engine_tests.rs:827:    // Thread A: install_session in a tight loop, alternating
userspace-dp/src/afxdp/wg/engine_tests.rs:837:                match engine.install_session(&peer_pub, s) {
userspace-dp/src/afxdp/wg/engine_tests.rs:968:    engine.install_session(&peer_pub, session).unwrap();
userspace-dp/src/afxdp/wg/tests.rs:129:        .install_session(&resp_pub, init_session)
userspace-dp/src/afxdp/wg/tests.rs:132:        .install_session(&init_pub, resp_session.clone())
userspace-dp/src/afxdp/wg/tests.rs:308:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:314:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:332:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:338:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:607:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:613:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:979:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:1005:        .install_session(&init_pub, resp_session.clone())
userspace-dp/src/afxdp/wg/tests.rs:1608:        .install_session(
userspace-dp/src/afxdp/wg/tests.rs:1629:        .install_session(&init_pub, resp_session.clone())

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '430,500p;2500,2605p;2840,2935p;4750,4845p'
nl -ba userspace-dp/src/afxdp/forwarding/local_delivery.rs | sed -n '80,145p'
nl -ba userspace-dp/src/afxdp/tunnel.rs | sed -n '545,625p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   430	                let neighbor_epoch_snapshot = worker_ctx.dynamic_neighbors.snapshot_shard_epochs();
   431	                let mut decision = if let Some(flow) = flow.as_ref() {
   432	                    if let Some(resolved) = resolve_flow_session_decision(
   433	                        sessions,
   434	                        binding.bpf_maps.session_map_fd,
   435	                        worker_ctx.shared_sessions,
   436	                        worker_ctx.shared_nat_sessions,
   437	                        worker_ctx.shared_forward_wire_sessions,
   438	                        &worker_ctx.shared_owner_rg_indexes,
   439	                        worker_ctx.peer_worker_commands,
   440	                        worker_ctx.forwarding,
   441	                        worker_ctx.ha_state,
   442	                        worker_ctx.dynamic_neighbors,
   443	                        flow,
   444	                        now_ns,
   445	                        now_secs,
   446	                        meta.protocol,
   447	                        meta.tcp_flags,
   448	                        meta.ingress_ifindex as i32,
   449	                        packet_fabric_ingress,
   450	                        ha_startup_grace_until_secs,
   451	                    ) {
   452	                        telemetry.counters.session_hits += 1;
   453	                        telemetry.dbg.session_hit += 1;
   454	                        // #3073: re-count this established-session packet against
   455	                        // the admitting policy's hit counter. The cold path
   456	                        // counts the first packet in `try_match_rule`; this
   457	                        // covers every subsequent packet that hits the session
   458	                        // (and reply traffic on the reverse companion), so
   459	                        // `show security policies hit-count` reflects the real
   460	                        // load the rule carries — not just the first frame.
   461	                        // `resolve_flow_session_decision` never runs policy
   462	                        // evaluation, so a packet reaching here was never counted
   463	                        // by the cold path: exactly-once holds. The per-worker
   464	                        // coalescer keeps this off the shared counter cacheline.
   465	                        // #3322: prefer the session's reorder-stable bound
   466	                        // handle over the positional idx so a live policy
   467	                        // reorder cannot re-attribute this established flow's
   468	                        // packets to a different rule.
   469	                        //
   470	                        // #3706: EXCEPT on the LocalDelivery (host-bound) path.
   471	                        // A host-local session re-evaluates the `to-zone
   472	                        // junos-host` policy on EVERY hit (the mandatory teardown
   473	                        // re-check below), and that re-eval's `try_match_rule`
   474	                        // already counts this packet against the admitting rule's
   475	                        // hit counter — exactly as it did pre-#3706, when a
   476	                        // host-local session carried no bound counter and this
   477	                        // line was a no-op (`resolve_session_hit_counter(None, 0)`
   478	                        // -> None). Now that a junos-host permit stamps a bound
   479	                        // counter (#3706), counting HERE too would double-count
   480	                        // every established host-local permit packet. Transit has
   481	                        // no per-hit policy re-eval, so it counts solely here.
   482	                        // Gate on disposition so the count fires exactly once on
   483	                        // both paths (parity with transit) while the #3706 permit
   484	                        // attribution — policy_id / log flags / the bound counter
   485	                        // handle used for close-time re-resolution + HA sync —
   486	                        // stays stamped on the session.
   487	                        //
   488	                        // #5445: the bound hit-counter Arc is NO LONGER carried
   489	                        // on the per-packet established-hit `SessionLookup`
   490	                        // (cloning it there bumped the shared `Arc` refcount —
   491	                        // a `LOCK XADD` — on every established-session lookup,
   492	                        // the #919 hot-path atomic). Re-source it once here:
   493	                        // prefer the value the resolve threaded (the session-
   494	                        // MISS / forward-wire paths still carry it, an owner
   495	                        // handoff), else BORROW-and-clone it from THIS worker's
   496	                        // own session-table entry (the established-hit path,
   497	                        // whose lookup return is now counter-stripped). Both
   498	                        // sources are contention-free (owned local metadata /
   499	                        // per-worker table). `None` (idx-0 / peer-synced
   500	                        // transient not in the local table) falls back to the
  2500	                                        // bounce, max_sessions refusal,
  2501	                                        // install-partial), so a rolled-back
  2502	                                        // SNAT allocation is never counted.
  2503	                                        // DNAT/static-DNAT and SNAT/static-
  2504	                                        // SNAT counters are independent Arcs;
  2505	                                        // a DNAT+SNAT flow bumps both.
  2506	                                        let nat_hit_len = desc.len as u64;
  2507	                                        if let Some(c) = pre_routing_dnat_counter.as_ref() {
  2508	                                            c.add(nat_hit_len);
  2509	                                        }
  2510	                                        if let Some(c) = source_nat_counter.as_ref() {
  2511	                                            c.add(nat_hit_len);
  2512	                                        }
  2513	                                        // #5689: install the ordinary same-family
  2514	                                        // NAT / NPTv6 fragment association for a
  2515	                                        // FIRST fragment of this now-committed
  2516	                                        // flow, so its non-first fragments inherit
  2517	                                        // this translation on the flowless arm
  2518	                                        // (address-only L3 rewrite) instead of
  2519	                                        // being forwarded UNTRANSLATED. No-op
  2520	                                        // unless this packet is a first fragment
  2521	                                        // (offset 0, MF=1) carrying a same-family
  2522	                                        // rewrite; the cross-family NAT64 path
  2523	                                        // installs its own association (with
  2524	                                        // reverse info) earlier on the cold path.
  2525	                                        if let Some(l3_packet) =
  2526	                                            packet_frame.get(meta.l3_offset as usize..)
  2527	                                        {
  2528	                                            // #5146: publish the NAT64 (cross-
  2529	                                            // family) first-fragment association
  2530	                                            // ONLY now — the flow has COMMITTED
  2531	                                            // (past `can_admit` and a successful
  2532	                                            // forward session install). Publishing
  2533	                                            // it at source-allocation time left the
  2534	                                            // association live behind every
  2535	                                            // rollback arm (hop-limit ICMP-TE,
  2536	                                            // admission refusal, install-partial),
  2537	                                            // and the rollback releases only the
  2538	                                            // pool port — so a non-first fragment
  2539	                                            // of a rolled-back first fragment
  2540	                                            // inherited a rolled-back verdict AND a
  2541	                                            // now-reusable translation (#5146). Both
  2542	                                            // helpers self-gate (NAT64 vs ordinary
  2543	                                            // same-family), so exactly one fires for
  2544	                                            // a given committed first fragment.
  2545	                                            nat64_install_forward_fragment_assoc(
  2546	                                                worker_ctx.forwarding,
  2547	                                                l3_packet,
  2548	                                                meta.addr_family as i32,
  2549	                                                &decision,
  2550	                                                now_ns,
  2551	                                            );
  2552	                                            nat_install_forward_fragment_assoc(
  2553	                                                worker_ctx.forwarding,
  2554	                                                l3_packet,
  2555	                                                meta.addr_family as i32,
  2556	                                                &decision,
  2557	                                                now_ns,
  2558	                                            );
  2559	                                        }
  2560	                                        let forward_entry = SyncedSessionEntry {
  2561	                                            key: flow.forward_key.clone(),
  2562	                                            decision,
  2563	                                            metadata: forward_metadata,
  2564	                                            origin: SessionOrigin::ForwardFlow,
  2565	                                            protocol: meta.protocol,
  2566	                                            tcp_flags: meta.tcp_flags,
  2567	                                            // Local forward-flow learn (#2170): no peer gen.
  2568	                                            generation: 0,
  2569	                                            // #5212: local-origin shared publish; the id
  2570	                                            // rides the wire off the live entry via the
  2571	                                            // Open delta, not this replica (0 here).
  2572	                                            session_id: 0,
  2573	                                        };
  2574	                                        // #1789: count failed publishes so
  2575	                                        // map-at-capacity / stale-fd
  2576	                                        // failures are visible in release
  2577	                                        // builds (was `let _ =`).
  2578	                                        if publish_live_session_entry(
  2579	                                            binding.bpf_maps.session_map_fd,
  2580	                                            &flow.forward_key,
  2581	                                            decision.nat,
  2582	                                            false,
  2583	                                        )
  2584	                                        .is_err()
  2585	                                        {
  2586	                                            binding
  2587	                                                .live
  2588	                                                .session_publish_errors
  2589	                                                .fetch_add(1, Ordering::Relaxed);
  2590	                                        }
  2591	                                        publish_shared_session(
  2592	                                            worker_ctx.shared_sessions,
  2593	                                            worker_ctx.shared_nat_sessions,
  2594	                                            worker_ctx.shared_forward_wire_sessions,
  2595	                                            &worker_ctx.shared_owner_rg_indexes,
  2596	                                            &forward_entry,
  2597	                                        );
  2598	                                        // Populate BPF dnat_table for embedded ICMP NAT reversal.
  2599	                                        // Without this, mtr/traceroute intermediate hops are invisible.
  2600	                                        // #2244: a failed map publish silently loses the reverse
  2601	                                        // record — count it so map pressure is operator-visible.
  2602	                                        if !publish_dnat_table_entry(
  2603	                                            &worker_ctx.dnat_fds,
  2604	                                            &flow.forward_key,
  2605	                                            decision.nat,
  2840	                                                    reverse_key.src_ip,
  2841	                                                    reverse_key.src_port,
  2842	                                                    reverse_key.dst_ip,
  2843	                                                    reverse_key.dst_port,
  2844	                                                    binding.bpf_maps.session_map_fd,
  2845	                                                );
  2846	                                            }
  2847	                                            if !verify_session_key_in_bpf(
  2848	                                                binding.bpf_maps.session_map_fd,
  2849	                                                &flow.forward_key,
  2850	                                            ) {
  2851	                                                debug_log!(
  2852	                                                    "SESS_VERIFY_FAIL: forward key NOT found! \
  2853	                                                             af={} proto={} {}:{} -> {}:{}",
  2854	                                                    flow.forward_key.addr_family,
  2855	                                                    flow.forward_key.protocol,
  2856	                                                    flow.forward_key.src_ip,
  2857	                                                    flow.forward_key.src_port,
  2858	                                                    flow.forward_key.dst_ip,
  2859	                                                    flow.forward_key.dst_port,
  2860	                                                );
  2861	                                            }
  2862	                                            let logged = SESSION_CREATIONS_LOGGED
  2863	                                                .fetch_add(1, Ordering::Relaxed);
  2864	                                            if logged < 10 {
  2865	                                                debug_log!(
  2866	                                                    "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
  2867	                                                             | REV af={} proto={} {}:{} -> {}:{} \
  2868	                                                             | NAT src={:?} dst={:?} \
  2869	                                                             | map_fd={} bpf_entries={}",
  2870	                                                    logged,
  2871	                                                    flow.forward_key.addr_family,
  2872	                                                    flow.forward_key.protocol,
  2873	                                                    flow.forward_key.src_ip,
  2874	                                                    flow.forward_key.src_port,
  2875	                                                    flow.forward_key.dst_ip,
  2876	                                                    flow.forward_key.dst_port,
  2877	                                                    reverse_key.addr_family,
  2878	                                                    reverse_key.protocol,
  2879	                                                    reverse_key.src_ip,
  2880	                                                    reverse_key.src_port,
  2881	                                                    reverse_key.dst_ip,
  2882	                                                    reverse_key.dst_port,
  2883	                                                    decision.nat.rewrite_src,
  2884	                                                    decision.nat.rewrite_dst,
  2885	                                                    binding.bpf_maps.session_map_fd,
  2886	                                                    count_bpf_session_entries(
  2887	                                                        binding.bpf_maps.session_map_fd
  2888	                                                    ),
  2889	                                                );
  2890	                                                dump_bpf_session_entries(
  2891	                                                    binding.bpf_maps.session_map_fd,
  2892	                                                    20,
  2893	                                                );
  2894	                                            }
  2895	                                        }
  2896	                                        created += 1;
  2897	                                        let reverse_entry = SyncedSessionEntry {
  2898	                                            key: reverse_key,
  2899	                                            decision: reverse_decision,
  2900	                                            metadata: reverse_metadata,
  2901	                                            origin: SessionOrigin::ReverseFlow,
  2902	                                            protocol: meta.protocol,
  2903	                                            tcp_flags: meta.tcp_flags,
  2904	                                            // Local reverse-flow learn (#2170): no peer gen.
  2905	                                            generation: 0,
  2906	                                            // #5212: a reverse companion never emits
  2907	                                            // RT_FLOW (is_reverse skip) and gets its own
  2908	                                            // fresh id at install — no carried id.
  2909	                                            session_id: 0,
  2910	                                        };
  2911	                                        publish_shared_session(
  2912	                                            worker_ctx.shared_sessions,
  2913	                                            worker_ctx.shared_nat_sessions,
  2914	                                            worker_ctx.shared_forward_wire_sessions,
  2915	                                            &worker_ctx.shared_owner_rg_indexes,
  2916	                                            &reverse_entry,
  2917	                                        );
  2918	                                        replicate_session_upsert(
  2919	                                            worker_ctx.peer_worker_commands,
  2920	                                            &reverse_entry,
  2921	                                        );
  2922	                                    }
  2923	                                    if created > 0 {
  2924	                                        telemetry.counters.session_creates += created;
  2925	                                        telemetry.dbg.session_create += created;
  2926	                                    }
  2927	                                }
  2928	                            } else {
  2929	                                // #2089/#3071/#3615: enqueue the deny/reject
  2930	                                // reply FIRST, then emit the policy-deny RT_FLOW
  2931	                                // with the TRUTHFUL action. `reject` synthesizes
  2932	                                // a TCP RST / ICMP unreachable back toward the
  2933	                                // source; plain `deny` is a silent drop UNLESS
  2934	                                // the flow is TCP and the ingress (from) zone has
  2935	                                // Junos `tcp-rst`. When a `reject` reply
  4750	                                                &from_zone,
  4751	                                                &to_zone,
  4752	                                                pending_decision.resolution.egress_ifindex,
  4753	                                                &nat_match_flow,
  4754	                                                now_ns,
  4755	                                                snat_non_first_fragment,
  4756	                                                &mut snat_match_counter,
  4757	                                            ) {
  4758	                                                Ok(snat_decision) => {
  4759	                                                    pending_decision.nat =
  4760	                                                        pending_decision.nat.merge(snat_decision);
  4761	                                                    source_nat_release_key =
  4762	                                                        Some(nat_match_flow.forward_key.clone());
  4763	                                                    source_nat_counter = snat_match_counter;
  4764	                                                }
  4765	                                                Err(failure) => {
  4766	                                                    record_source_nat_failure(
  4767	                                                        telemetry,
  4768	                                                        worker_ctx,
  4769	                                                        meta,
  4770	                                                        flow,
  4771	                                                        from_zone_id,
  4772	                                                        to_zone_id,
  4773	                                                        desc.len,
  4774	                                                        &failure,
  4775	                                                    );
  4776	                                                    break 'missing_neighbor StageOutcome::RecycleAndContinue;
  4777	                                                }
  4778	                                            }
  4779	                                        }
  4780	                                    }
  4781	                                    let sess_meta = build_missing_neighbor_session_metadata(
  4782	                                        worker_ctx.forwarding,
  4783	                                        from_zone_id,
  4784	                                        to_zone_id,
  4785	                                        packet_fabric_ingress,
  4786	                                        pending_decision,
  4787	                                    );
  4788	                                    let pending_installed = sessions.install_with_protocol_with_origin(
  4789	                                        flow.forward_key.clone(),
  4790	                                        pending_decision,
  4791	                                        sess_meta.clone(),
  4792	                                        SessionOrigin::MissingNeighborSeed,
  4793	                                        now_ns,
  4794	                                        meta.protocol,
  4795	                                        meta.tcp_flags,
  4796	                                    );
  4797	                                    if pending_installed {
  4798	                                        // #2218: the seed install is the
  4799	                                        // committed translation for this
  4800	                                        // missing-neighbor flow (a refused seed
  4801	                                        // takes the else-arm below and rolls the
  4802	                                        // SNAT allocation back, so it is never
  4803	                                        // counted). Count the DNAT and SNAT
  4804	                                        // per-rule hits once each.
  4805	                                        let nat_hit_len = desc.len as u64;
  4806	                                        if let Some(c) = pre_routing_dnat_counter.as_ref() {
  4807	                                            c.add(nat_hit_len);
  4808	                                        }
  4809	                                        if let Some(c) = source_nat_counter.as_ref() {
  4810	                                            c.add(nat_hit_len);
  4811	                                        }
  4812	                                        let entry = SyncedSessionEntry {
  4813	                                            key: flow.forward_key.clone(),
  4814	                                            decision: pending_decision,
  4815	                                            metadata: sess_meta,
  4816	                                            origin: SessionOrigin::MissingNeighborSeed,
  4817	                                            protocol: meta.protocol,
  4818	                                            tcp_flags: meta.tcp_flags,
  4819	                                            // Local missing-neighbor seed (#2170): no peer gen.
  4820	                                            generation: 0,
  4821	                                            // #5212: local-origin seed; no carried id (0).
  4822	                                            session_id: 0,
  4823	                                        };
  4824	                                        publish_shared_session(
  4825	                                            worker_ctx.shared_sessions,
  4826	                                            worker_ctx.shared_nat_sessions,
  4827	                                            worker_ctx.shared_forward_wire_sessions,
  4828	                                            &worker_ctx.shared_owner_rg_indexes,
  4829	                                            &entry,
  4830	                                        );
  4831	                                        // #1789: count a failed publish
  4832	                                        // (shim misses the key -> NO_SESSION
  4833	                                        // degraded path for the seeded flow).
  4834	                                        if publish_session_map_entry_for_session(
  4835	                                            binding.bpf_maps.session_map_fd,
  4836	                                            &flow.forward_key,
  4837	                                            pending_decision,
  4838	                                            &entry.metadata,
  4839	                                        )
  4840	                                        .is_err()
  4841	                                        {
  4842	                                            binding
  4843	                                                .live
  4844	                                                .session_publish_errors
  4845	                                                .fetch_add(1, Ordering::Relaxed);
    80	    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    81	    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    82	    key: &SessionKey,
    83	    decision: SessionDecision,
    84	    metadata: SessionMetadata,
    85	    origin: SessionOrigin,
    86	    now_ns: u64,
    87	    protocol: u8,
    88	    tcp_flags: u8,
    89	) -> bool {
    90	    if let Some(previous) = sessions.take_synced_local(key) {
    91	        remove_shared_session(
    92	            shared_sessions,
    93	            shared_nat_sessions,
    94	            shared_forward_wire_sessions,
    95	            shared_owner_rg_indexes,
    96	            key,
    97	        );
    98	        delete_session_map_entry_for_removed_session(
    99	            session_map_fd,
   100	            key,
   101	            previous.decision,
   102	            &previous.metadata,
   103	        );
   104	    }
   105	    if !sessions.install_with_protocol_with_origin(
   106	        key.clone(),
   107	        decision,
   108	        metadata.clone(),
   109	        origin,
   110	        now_ns,
   111	        protocol,
   112	        tcp_flags,
   113	    ) {
   114	        return false;
   115	    }
   116	    let local_entry = SyncedSessionEntry {
   117	        key: key.clone(),
   118	        decision,
   119	        metadata,
   120	        origin,
   121	        protocol,
   122	        tcp_flags,
   123	        // Local forwarding-learn entry: no peer install generation (#2170).
   124	        generation: 0,
   125	        // #5212: a local-origin shared-map publish. The stable id is carried on
   126	        // the wire straight off the live entry by the incremental Open delta
   127	        // (`install_with_protocol_with_origin`) / the owner-RG cold-sync export
   128	        // (`emit_open_delta_with_origin`), not via this shared replica — so 0
   129	        // here (a cross-worker materialize of this entry re-allocs a local id).
   130	        session_id: 0,
   131	    };
   132	    // #1789: count a failed helper-local session publish (same
   133	    // shim-missing-key consequence as every other publish site).
   134	    if publish_session_map_entry_for_session(session_map_fd, key, decision, &local_entry.metadata)
   135	        .is_err()
   136	    {
   137	        crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
   138	            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
   139	    }
   140	    true
   141	}
   142	
   143	pub(in crate::afxdp) fn ingress_interface_local_resolution(
   144	    state: &ForwardingState,
   145	    ingress_ifindex: i32,
   545	    // the reverse-entry synthesis below must see the same HA map.
   546	    let resolution = enforce_ha_resolution_snapshot(
   547	        forwarding,
   548	        ha_runtime,
   549	        monotonic_nanos() / 1_000_000_000,
   550	        resolve_tunnel_forwarding_resolution(
   551	            forwarding,
   552	            Some(dynamic_neighbors),
   553	            tunnel_endpoint_id,
   554	            0,
   555	        ),
   556	    );
   557	    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
   558	        return Err(format!(
   559	            "local_tunnel_resolution:{}",
   560	            resolution.status(None, forwarding).disposition
   561	        ));
   562	    }
   563	    let decision = SessionDecision {
   564	        resolution,
   565	        nat: NatDecision::default(),
   566	    };
   567	    let flow = parse_session_flow_from_bytes(&inner_frame, meta)
   568	        .ok_or_else(|| "parse_local_origin_session_flow_failed".to_string())?;
   569	    // #6471: a firewall-INITIATED IKE exchange routed via this tunnel sees
   570	    // its replies arrive on the Stage-11 secondary path (GRE-inner local
   571	    // destination) with the Responder SPI set and NO inbound seed — without
   572	    // this outbound seed the reply would fail the live-exchange lookup and
   573	    // face the host-inbound `ike` gate as a forgery, breaking
   574	    // firewall-initiated tunnels on zones that omit `ike` (the primary path
   575	    // admits such replies via kernel conntrack-established). Only a genuine
   576	    // initiation (all-zero Responder SPI) seeds; the firewall's own later
   577	    // packets in the exchange are ignored here (they already match the seed
   578	    // direction-wise on the return lookup).
   579	    crate::afxdp::forwarding::maybe_seed_local_origin_ike(
   580	        ike_exchanges,
   581	        &inner_frame,
   582	        meta.l4_offset as usize,
   583	        &flow,
   584	        monotonic_nanos(),
   585	    );
   586	    // #921: zone_id is now a u16 field on EgressInterface — direct
   587	    // load, no name round-trip.
   588	    let zone_id = forwarding
   589	        .egress
   590	        .get(&decision.resolution.egress_ifindex)
   591	        .map(|iface| iface.zone_id)
   592	        .unwrap_or(0);
   593	    let bytes = encapsulate_native_gre_frame(&inner_frame, meta, &decision, forwarding)
   594	        .ok_or_else(|| "encapsulate_native_gre_frame_failed".to_string())?;
   595	    let session_entry = SyncedSessionEntry {
   596	        key: flow.forward_key,
   597	        decision,
   598	        metadata: SessionMetadata {
   599	            ingress_zone: zone_id,
   600	            egress_zone: zone_id,
   601	            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
   602	            fabric_ingress: false,
   603	            is_reverse: false,
   604	            nat64_reverse: None,
   605	            // #6224: this is the LOCAL-ORIGIN (host-outbound) GRE encapsulation
   606	            // path — the firewall's own kernel-routed traffic read off the TUN
   607	            // device (`local_tunnel_source_loop`), NOT a peer HA-sync import.
   608	            // `resolve_tunnel_forwarding_resolution` does route/next-hop/neighbor
   609	            // resolution ONLY; no security policy or application term is matched
   610	            // here (Junos runs no security policy on firewall-self-originated
   611	            // traffic). There is therefore no admitting policy/application to
   612	            // source the per-policy `then log` selection, the policy ID, the
   613	            // per-application idle timeout, or the hit-counter handle from.
   614	            // Zeroed policy fields and the global per-protocol idle timeout
   615	            // (`inactivity_timeout_ns: None` -> `session_timeout_ns` falls back
   616	            // to the per-protocol default) are the correct values for
   617	            // self-originated traffic; a per-app timeout would only differ if an
   618	            // admitting application existed, which it does not. The
   619	            // `origin: SessionOrigin::SyncImport` tag below is an install-path
   620	            // plumbing artifact (it reaches the uncapped coordinator-authoritative
   621	            // install path, see session_glue/mod.rs), NOT a peer wire import.
   622	            //
   623	            // (The earlier #2508/#3056/#3227/#3073 comments here mis-described
   624	            // this path as "peer-seeded import ... does not cross the HA wire
   625	            // yet". The real peer-import path — server/helpers.rs — DOES stamp

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tunnel.rs | sed -n '590,690p'
rg -n 'handle_local_tunnel|local_tunnel_source|SyncedSessionEntry \\{' userspace-dp/src/afxdp/tunnel.rs userspace-dp/src/afxdp/forwarding/local_delivery.rs --glob '*.rs'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   590	        .get(&decision.resolution.egress_ifindex)
   591	        .map(|iface| iface.zone_id)
   592	        .unwrap_or(0);
   593	    let bytes = encapsulate_native_gre_frame(&inner_frame, meta, &decision, forwarding)
   594	        .ok_or_else(|| "encapsulate_native_gre_frame_failed".to_string())?;
   595	    let session_entry = SyncedSessionEntry {
   596	        key: flow.forward_key,
   597	        decision,
   598	        metadata: SessionMetadata {
   599	            ingress_zone: zone_id,
   600	            egress_zone: zone_id,
   601	            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
   602	            fabric_ingress: false,
   603	            is_reverse: false,
   604	            nat64_reverse: None,
   605	            // #6224: this is the LOCAL-ORIGIN (host-outbound) GRE encapsulation
   606	            // path — the firewall's own kernel-routed traffic read off the TUN
   607	            // device (`local_tunnel_source_loop`), NOT a peer HA-sync import.
   608	            // `resolve_tunnel_forwarding_resolution` does route/next-hop/neighbor
   609	            // resolution ONLY; no security policy or application term is matched
   610	            // here (Junos runs no security policy on firewall-self-originated
   611	            // traffic). There is therefore no admitting policy/application to
   612	            // source the per-policy `then log` selection, the policy ID, the
   613	            // per-application idle timeout, or the hit-counter handle from.
   614	            // Zeroed policy fields and the global per-protocol idle timeout
   615	            // (`inactivity_timeout_ns: None` -> `session_timeout_ns` falls back
   616	            // to the per-protocol default) are the correct values for
   617	            // self-originated traffic; a per-app timeout would only differ if an
   618	            // admitting application existed, which it does not. The
   619	            // `origin: SessionOrigin::SyncImport` tag below is an install-path
   620	            // plumbing artifact (it reaches the uncapped coordinator-authoritative
   621	            // install path, see session_glue/mod.rs), NOT a peer wire import.
   622	            //
   623	            // (The earlier #2508/#3056/#3227/#3073 comments here mis-described
   624	            // this path as "peer-seeded import ... does not cross the HA wire
   625	            // yet". The real peer-import path — server/helpers.rs — DOES stamp
   626	            // all of these from `SessionSyncRequest` post-#3301; this path is
   627	            // simply not a wire path, so nothing crosses to read.)
   628	            log_session_init: false,
   629	            log_session_close: false,
   630	            policy_id: 0,
   631	            inactivity_timeout_ns: None,
   632	            policy_counter_idx: 0,
   633	            policy_counter: None,
   634	        },
   635	        origin: SessionOrigin::SyncImport,
   636	        protocol: meta.protocol,
   637	        tcp_flags: if meta.protocol == PROTO_TCP {
   638	            extract_tcp_flags_and_window(&inner_frame)
   639	                .map(|(flags, _)| flags)
   640	                .unwrap_or_default()
   641	        } else {
   642	            0
   643	        },
   644	        // Locally decapsulated tunnel session: no peer install generation (#2170).
   645	        generation: 0,
   646	        session_id: 0,
   647	    };
   648	    let reverse_session_entry = synthesized_synced_reverse_entry(
   649	        forwarding,
   650	        ha_runtime,
   651	        dynamic_neighbors,
   652	        &session_entry,
   653	        monotonic_nanos() / 1_000_000_000,
   654	    );
   655	    let now_ns = monotonic_nanos();
   656	    // #2362 fold B: local tunnel-origin path — the inner-frame L3/L4 offsets in
   657	    // `meta` describe the pre-encap packet, so use the meta-only extra
   658	    // (tcp_flags authoritative; is-fragment / icmp-type under-match on this rare
   659	    // local path rather than risk mis-parsing inner offsets).
   660	    let cos_extra = crate::afxdp::frame::term_match_extra_from_meta(meta.into());
   661	    let cos = resolve_cos_tx_selection_at(
   662	        forwarding,
   663	        decision.resolution.egress_ifindex,
   664	        meta,
   665	        Some(&session_entry.key),
   666	        cos_extra,
   667	        now_ns,
   668	    );
   669	    if cos.drop {
   670	        return Err("local_tunnel_packet_dropped_by_three_color_policer".to_string());
   671	    }
   672	    Ok(LocalTunnelTxPlan {
   673	        tx_ifindex: decision.resolution.tx_ifindex,
   674	        tx_request: TxRequest {
   675	            bytes,
   676	            expected_ports: None,
   677	            expected_addr_family: meta.addr_family,
   678	            expected_protocol: meta.protocol,
   679	            flow_key: Some(session_entry.key.clone()),
   680	            egress_ifindex: decision.resolution.egress_ifindex,
   681	            cos_queue_id: cos.queue_id,
   682	            dscp_rewrite: cos.dscp_rewrite,
   683	            mirror_clone: false,
   684	            enqueue_ns: 0,
   685	        },
   686	        session_entry,
   687	        reverse_session_entry,
   688	    })
   689	}
   690	
userspace-dp/src/afxdp/forwarding/local_delivery.rs:116:    let local_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tunnel.rs:157:/// `local_tunnel_source_loop` so the stop-latency contract is unit
userspace-dp/src/afxdp/tunnel.rs:234:pub(super) fn local_tunnel_source_loop(
userspace-dp/src/afxdp/tunnel.rs:595:    let session_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tunnel.rs:607:            // device (`local_tunnel_source_loop`), NOT a peer HA-sync import.

[35m[3mexec[0m[0m
[1m/bin/bash -lc "rg -n 'enum SessionOrigin|SessionOrigin::' userspace-dp/src --glob '*.rs' --glob '"'!**/tests.rs'"' --glob '"'!**/*_tests.rs'"' | head -400
nl -ba userspace-dp/src/session/mod.rs | sed -n '310,365p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
userspace-dp/src/server/helpers/session_sync.rs:271:        origin: crate::session::SessionOrigin::SyncImport,
userspace-dp/src/session/install.rs:99:            SessionOrigin::ForwardFlow,
userspace-dp/src/session/install.rs:281:                origin: SessionOrigin::SyncImport,
userspace-dp/src/session/install.rs:572:                entry.origin = SessionOrigin::SyncImport;
userspace-dp/src/session/mod.rs:1585:            .unwrap_or(SessionOrigin::ForwardFlow);
userspace-dp/src/session/mod.rs:1614:            .unwrap_or(SessionOrigin::ForwardFlow);
userspace-dp/src/afxdp/shared_ops.rs:124:        origin.is_peer_synced() || matches!(origin, SessionOrigin::SharedPromote)
userspace-dp/src/afxdp/shared_ops.rs:179:                entry.origin = SessionOrigin::SyncImport;
userspace-dp/src/afxdp/shared_ops.rs:197:                entry.origin = SessionOrigin::SyncImport;
userspace-dp/src/afxdp/shared_ops.rs:206:                entry.origin = SessionOrigin::SyncImport;
userspace-dp/src/afxdp/shared_ops.rs:316:                || matches!(entry.origin, SessionOrigin::SharedPromote);
userspace-dp/src/afxdp/shared_ops.rs:778:        origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/shared_ops.rs:861:        SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/shared_ops.rs:878:            origin: SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:132:        origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:2430:        SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:2848:        SessionOrigin::LocalMiss,
userspace-dp/src/afxdp/tests_embedded_poll_filter.rs:2857:        origin: SessionOrigin::LocalMiss,
userspace-dp/src/session/entry.rs:216:pub(crate) enum SessionOrigin {
userspace-dp/src/event_stream/tests/mod.rs:116:        origin: SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/tests_txn_flow_cache.rs:986:        SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/ha/session_import.rs:410:            origin: SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/session_glue/promote.rs:103:        origin: SessionOrigin::SharedPromote,
userspace-dp/src/afxdp/session_glue/promote.rs:120:            origin: SessionOrigin::SharedPromote,
userspace-dp/src/afxdp/session_glue/mod.rs:1354:        SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/session_glue/mod.rs:1364:        origin: SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/tunnel.rs:619:            // `origin: SessionOrigin::SyncImport` tag below is an install-path
userspace-dp/src/afxdp/tunnel.rs:635:        origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/tests_fabric_zone_stamp.rs:269:/// `SessionOrigin::ReverseFlow` seed. Before this PR the cluster-peer
userspace-dp/src/afxdp/tests_fabric_zone_stamp.rs:318:        Some(SessionOrigin::ReverseFlow),
userspace-dp/src/afxdp/tests_fabric_zone_stamp.rs:399:        Some(SessionOrigin::ReverseFlow),
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:211:            origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/tests_decap_dnat_table.rs:322:            origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:774:        SessionOrigin::LocalMiss,
userspace-dp/src/afxdp/tests_gre_local_delivery.rs:783:        origin: SessionOrigin::LocalMiss,
userspace-dp/src/afxdp/tests_bind_forward.rs:1172:        origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/tests_bind_forward.rs:1222:        origin: SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/tests_bind_forward.rs:1230:    assert_eq!(replica.origin, SessionOrigin::WorkerLocalImport);
userspace-dp/src/afxdp/tests_bind_forward.rs:1274:        origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/tests_bind_forward.rs:1337:        origin: SessionOrigin::SyncImport,
userspace-dp/src/afxdp/bpf_map/mod.rs:515:        SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/bpf_map/mod.rs:698:        SessionOrigin::SyncImport,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:944:                        // `SessionOrigin::ReverseFlow` seed gated only on the
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1960:                                SessionOrigin::LocalMiss,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2454:                                            SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2564:                                            origin: SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2783:                                            SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2901:                                            origin: SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:4792:                                        SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:4816:                                            origin: SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1744:            SessionOrigin::ForwardFlow
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1745:            | SessionOrigin::ReverseFlow
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1746:            | SessionOrigin::LocalMiss
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1747:            | SessionOrigin::MissingNeighborSeed => true,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1749:            SessionOrigin::SyncImport
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1750:            | SessionOrigin::SharedMaterialize
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1751:            | SessionOrigin::SharedPromote
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1752:            | SessionOrigin::WorkerLocalImport => false,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:1937:            origin: SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2155:            SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2156:            SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2157:            SessionOrigin::LocalMiss,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2158:            SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2171:            SessionOrigin::SyncImport,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2172:            SessionOrigin::SharedMaterialize,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2173:            SessionOrigin::WorkerLocalImport,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2174:            SessionOrigin::SharedPromote,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2194:            count_local_session_expiries([SessionOrigin::SharedPromote].into_iter()),
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2204:            SessionOrigin::ForwardFlow,       // local: +1
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2205:            SessionOrigin::SyncImport,        // synced: 0
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2206:            SessionOrigin::ReverseFlow,       // local: +1
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2207:            SessionOrigin::SharedMaterialize, // synced: 0
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2208:            SessionOrigin::WorkerLocalImport, // synced: 0
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2209:            SessionOrigin::SharedPromote,     // synced: 0
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2223:            SessionOrigin::ForwardFlow,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2224:            SessionOrigin::ReverseFlow,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2225:            SessionOrigin::LocalMiss,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2226:            SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2227:            SessionOrigin::SyncImport,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2228:            SessionOrigin::SharedMaterialize,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2229:            SessionOrigin::SharedPromote,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:2230:            SessionOrigin::WorkerLocalImport,
   310	    }
   311	}
   312	const MAX_SESSION_DELTAS: usize = 4096;
   313	use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
   314	// #2151: TCP flag bits from the shared crate::tcp_flags SSOT. Re-exported
   315	// so the conntrack submodules (install, lookup, expire) keep referencing
   316	// TCP_FIN/TCP_RST via `super::*`. The session-closing test is the shared
   317	// `is_closing` predicate.
   318	use crate::tcp_flags::{TCP_FIN, TCP_RST, has_rst, is_closing, is_initial_syn, is_syn_ack};
   319	
   320	#[allow(unused_macros)]
   321	macro_rules! debug_log {
   322	    ($($arg:tt)*) => {
   323	        #[cfg(feature = "debug-log")]
   324	        eprintln!($($arg)*);
   325	    };
   326	}
   327	
   328	// #2005 pure code-motion split: the conntrack fast path is split into
   329	// focused submodules that all attach `impl SessionTable` blocks. These
   330	// declarations sit AFTER `debug_log!` so the macro is in textual scope
   331	// for the child modules that call it (`expire`, `lookup`). The
   332	// coordinator/table definition and the #1752/#1855 in-place-refresh
   333	// contract (update_session / refresh_for_ha_transition + the
   334	// secondary-index re-assert + #964 eager cleanup helpers) stay in
   335	// mod.rs. Submodule methods keep their original visibility; the only
   336	// widening is `push_to_wheel` (module-private `fn` → `pub(in
   337	// crate::session)`) because callers in mod.rs / install / lookup cross
   338	// the module boundary into `expire`.
   339	mod expire;
   340	mod install;
   341	mod lookup;
   342	
   343	#[derive(Clone, Debug)]
   344	struct SessionEntry {
   345	    decision: SessionDecision,
   346	    metadata: SessionMetadata,
   347	    origin: SessionOrigin,
   348	    install_epoch: u64,
   349	    last_seen_ns: u64,
   350	    /// #2465: monotonic (`CLOCK_MONOTONIC`) nanosecond timestamp at which this
   351	    /// entry was first installed. Unlike `last_seen_ns` it is write-once: it is
   352	    /// NOT re-stamped by `touch`/`update_session`/`refresh_for_ha_transition`,
   353	    /// so it preserves the true session age across the lifetime of the entry.
   354	    /// Carried into the close `SessionDelta` so the RT_FLOW SESSION_CLOSE frame
   355	    /// reports a real flow StartTime (`#2465`) instead of the packet-count
   356	    /// heuristic. A re-import (`upsert_synced`) or a fresh install stamps it to
   357	    /// the install `now_ns`.
   358	    created_ns: u64,
   359	    expires_after_ns: u64,
   360	    closing: bool,
   361	    /// #3046: set once this TCP session has been seen carrying a RST. It is
   362	    /// sticky (never cleared back to false while the entry lives) so that a
   363	    /// stray reordered non-RST segment arriving after the RST cannot promote
   364	    /// the entry back to the 30s graceful-FIN `TCP_CLOSING_TIMEOUT_NS`. When
   365	    /// set together with `closing`, the timeout selection uses the short

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/session/entry.rs | sed -n '200,260p'
nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '900,970p;1915,1980p;2420,2470p;2750,2800p'
nl -ba userspace-dp/src/afxdp/worker/loop_body/mod.rs | sed -n '1900,1965p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   200	/// the `Arc` — those feed reverse-companion install, an owner handoff, not the
   201	/// per-packet fast path.)
   202	#[derive(Clone, Debug, PartialEq, Eq)]
   203	pub(crate) struct SessionLookup {
   204	    pub(crate) decision: SessionDecision,
   205	    pub(crate) metadata: SessionMetadata,
   206	}
   207	
   208	#[derive(Clone, Debug, PartialEq, Eq)]
   209	pub(crate) struct ForwardSessionMatch {
   210	    pub(crate) key: SessionKey,
   211	    pub(crate) decision: SessionDecision,
   212	    pub(crate) metadata: SessionMetadata,
   213	}
   214	
   215	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
   216	pub(crate) enum SessionOrigin {
   217	    ForwardFlow,
   218	    ReverseFlow,
   219	    LocalMiss,
   220	    MissingNeighborSeed,
   221	    SyncImport,
   222	    SharedMaterialize,
   223	    SharedPromote,
   224	    #[allow(dead_code)] // enum variant for completeness
   225	    WorkerLocalImport,
   226	}
   227	
   228	impl SessionOrigin {
   229	    pub(crate) fn as_str(self) -> &'static str {
   230	        match self {
   231	            Self::ForwardFlow => "forward_flow",
   232	            Self::ReverseFlow => "reverse_flow",
   233	            Self::LocalMiss => "local_miss",
   234	            Self::MissingNeighborSeed => "missing_neighbor_seed",
   235	            Self::SyncImport => "sync_import",
   236	            Self::SharedMaterialize => "shared_materialize",
   237	            Self::SharedPromote => "shared_promote",
   238	            Self::WorkerLocalImport => "worker_local_import",
   239	        }
   240	    }
   241	
   242	    /// Returns true for origins that represent peer-synced sessions.
   243	    /// These are sessions that arrived from the HA peer rather than
   244	    /// being created by local traffic.
   245	    pub(crate) fn is_peer_synced(self) -> bool {
   246	        matches!(
   247	            self,
   248	            Self::SyncImport | Self::SharedMaterialize | Self::WorkerLocalImport
   249	        )
   250	    }
   251	
   252	    pub(crate) fn is_promotable_synced(self) -> bool {
   253	        matches!(self, Self::SyncImport | Self::SharedMaterialize)
   254	    }
   255	
   256	    pub(crate) fn worker_replica_origin(self) -> Self {
   257	        if self.is_promotable_synced() {
   258	            Self::SyncImport
   259	        } else {
   260	            Self::WorkerLocalImport
   900	                                continue;
   901	                            }
   902	                        }
   903	                        resolved.decision
   904	                    } else {
   905	                        telemetry.counters.session_misses += 1;
   906	                        telemetry.dbg.session_miss += 1;
   907	                        match stage_screen_syn_cookie_ack_on_session_miss(
   908	                            Some(flow),
   909	                            packet_frame,
   910	                            meta,
   911	                            ingress_zone_override,
   912	                            now_ns,
   913	                            now_secs,
   914	                            screen,
   915	                            telemetry.counters,
   916	                            worker_ctx,
   917	                        ) {
   918	                            StageOutcome::RecycleAndContinue => {
   919	                                binding.scratch.scratch_recycle.push(desc.addr);
   920	                                continue;
   921	                            }
   922	                            StageOutcome::Continue(SynCookieAckOutcome::Pass) => {}
   923	                            StageOutcome::Continue(SynCookieAckOutcome::Validated) => {
   924	                                enqueue_syn_cookie_reply(
   925	                                    &mut binding.tx_pipeline,
   926	                                    worker_ctx.forwarding,
   927	                                    binding.ifindex,
   928	                                    packet_frame,
   929	                                    meta,
   930	                                    Some(flow),
   931	                                    SynCookieReply::AckRst,
   932	                                    telemetry.counters,
   933	                                );
   934	                                binding.scratch.scratch_recycle.push(desc.addr);
   935	                                continue;
   936	                            }
   937	                        }
   938	                        let resolution_target =
   939	                            parse_packet_destination_from_frame(packet_frame, meta)
   940	                                .unwrap_or(flow.dst_ip);
   941	                        // #6478: the cluster-peer return fast path was REMOVED.
   942	                        // It fast-pathed session-less fabric-ingress TCP
   943	                        // SYN-ACK / ACK / ICMP echo-reply forms into a NAT-less
   944	                        // `SessionOrigin::ReverseFlow` seed gated only on the
   945	                        // forgeable zone-encoded stamp — after #6458's stamp
   946	                        // validation a forged frame can still pass V1 on any
   947	                        // node whose claimed zone's RG is remote, so the seed
   948	                        // stayed forgeable. Session-less fabric-ingress
   949	                        // packets now take the normal miss path below: policy
   950	                        // under the #6458-validated zone, NAT applied, a
   951	                        // FORWARD session when permitted (the Junos
   952	                        // no-syn-check asymmetric pickup, #3152). The sync-race
   953	                        // sub-window the fast path covered (a peer-punted
   954	                        // return packet arriving before its synced session)
   955	                        // reverts to a bounded drop, which the #6478 verifier
   956	                        // explicitly prefers over unauthenticated seeding; a
   957	                        // genuine established flow's return is still served by
   958	                        // the synced session in `resolve_flow_session_decision`
   959	                        // before this point.
   960	
   961	                        // --- DNAT pre-routing ---
   962	                        // #6473: Junos evaluates static NAT BEFORE
   963	                        // destination NAT (Junos NAT overview, first-packet
   964	                        // order: static NAT → destination NAT → route →
   965	                        // policy → reverse static → source NAT; "static NAT
   966	                        // rules take precedence over destination NAT
   967	                        // rules"). The pre-#6473 code checked the DNAT pool
   968	                        // table first and only fell back to static-DNAT on
   969	                        // a miss, so an external address covered by BOTH a
   970	                        // static rule and a DNAT pool rule took the pool
  1915	                                .forwarding
  1916	                                .policy
  1917	                                .hit_counter_by_idx(host_policy_counter_idx)
  1918	                                .cloned();
  1919	                            let local_metadata = SessionMetadata {
  1920	                                ingress_zone: from_zone_id,
  1921	                                egress_zone: to_zone_id,
  1922	                                owner_rg_id: 0,
  1923	                                fabric_ingress: false,
  1924	                                is_reverse: false,
  1925	                                // Keep firewall-local sessions in the helper only for HA
  1926	                                // state. Publish only the exact observed key back into the
  1927	                                // BPF session map so subsequent established packets bypass
  1928	                                // userspace and return directly to the kernel.
  1929	                                nat64_reverse: None,
  1930	                                // #2508/#3706: a matching `to-zone junos-host then
  1931	                                // permit log` policy's per-policy RT_FLOW SYSLOG
  1932	                                // selection (a no-match host-local session carries
  1933	                                // none, so both stay false).
  1934	                                log_session_init: host_log_session_init,
  1935	                                log_session_close: host_log_session_close,
  1936	                                // #3056/#3706: the admitting junos-host policy's ID
  1937	                                // so the live-session BPF-compat publish and the
  1938	                                // SESSION_CREATE/CLOSE RT_FLOW records reference the
  1939	                                // policy that admitted the host-bound flow (0 only
  1940	                                // for a no-match host-local session).
  1941	                                policy_id: host_policy_id,
  1942	                                // #3227: host-local sessions are not policy-app-matched.
  1943	                                inactivity_timeout_ns: None,
  1944	                                // #3073/#3706: the admitting junos-host rule's
  1945	                                // hit-counter handle (0 / None for a no-match
  1946	                                // host-local session).
  1947	                                policy_counter_idx: host_policy_counter_idx,
  1948	                                policy_counter: host_policy_counter,
  1949	                            };
  1950	                            if install_helper_local_session_on_miss(
  1951	                                sessions,
  1952	                                binding.bpf_maps.session_map_fd,
  1953	                                worker_ctx.shared_sessions,
  1954	                                worker_ctx.shared_nat_sessions,
  1955	                                worker_ctx.shared_forward_wire_sessions,
  1956	                                &worker_ctx.shared_owner_rg_indexes,
  1957	                                &flow.forward_key,
  1958	                                decision,
  1959	                                local_metadata.clone(),
  1960	                                SessionOrigin::LocalMiss,
  1961	                                now_ns,
  1962	                                meta.protocol,
  1963	                                meta.tcp_flags,
  1964	                            ) {
  1965	                                telemetry.counters.session_creates += 1;
  1966	                                telemetry.dbg.session_create += 1;
  1967	                                // #2218: a DNAT/static-DNAT to a firewall-
  1968	                                // local service commits its translation
  1969	                                // here. No SNAT is applied on the local-
  1970	                                // delivery path, so only the pre-routing
  1971	                                // DNAT counter is bumped, once.
  1972	                                if let Some(c) = pre_routing_dnat_counter.as_ref() {
  1973	                                    c.add(desc.len as u64);
  1974	                                }
  1975	                                // #2008 M5: stamp the resolved application id.
  1976	                                // #3321: directional resolution (service = dst
  1977	                                // forward / src reverse).
  1978	                                // #3416: this is the DNAT-to-firewall-local
  1979	                                // delivery path — resolve the forward service
  1980	                                // port from the post-translation (rewritten)
  2420	                                        // SESSION_CREATE RT_FLOW record reference the
  2421	                                        // policy that admitted the flow (was the `0`
  2422	                                        // sentinel → first-configured-policy misattribution).
  2423	                                        policy_id: policy_result.policy_id,
  2424	                                        // #3227: stamp the matched application term's
  2425	                                        // per-application inactivity (idle) timeout
  2426	                                        // (seconds -> ns; None = use the global
  2427	                                        // per-protocol timeout) so the conntrack GC
  2428	                                        // ages this flow out on the app's value,
  2429	                                        // closing the legacy-eBPF appTimeout parity
  2430	                                        // regression.
  2431	                                        inactivity_timeout_ns:
  2432	                                            crate::session::app_inactivity_timeout_ns(
  2433	                                                policy_result.inactivity_timeout,
  2434	                                            ),
  2435	                                        // #3073: stamp the admitting rule's hit-counter
  2436	                                        // handle so the established fast path re-counts
  2437	                                        // every forward packet of this flow.
  2438	                                        policy_counter_idx: policy_result.policy_counter_idx,
  2439	                                        // #3322: the reorder-stable bound handle.
  2440	                                        policy_counter: bound_policy_counter.clone(),
  2441	                                    };
  2442	                                    // #3073: carry the admitting rule's handle so
  2443	                                    // the flow-cache entry populated for this new
  2444	                                    // flow re-counts its cached packets. #3322:
  2445	                                    // also carry the bound handle.
  2446	                                    flow_cache_policy_counter_idx =
  2447	                                        policy_result.policy_counter_idx;
  2448	                                    flow_cache_policy_counter = bound_policy_counter.clone();
  2449	                                    let forward_installed = track_in_userspace
  2450	                                        && sessions.install_with_protocol_with_origin(
  2451	                                            flow.forward_key.clone(),
  2452	                                            decision,
  2453	                                            forward_metadata.clone(),
  2454	                                            SessionOrigin::ForwardFlow,
  2455	                                            now_ns,
  2456	                                            meta.protocol,
  2457	                                            meta.tcp_flags,
  2458	                                        );
  2459	                                    if track_in_userspace && !forward_installed {
  2460	                                        // #1861 §5.2 residual: impossible by
  2461	                                        // construction after a passing
  2462	                                        // can_admit (cap is the only install
  2463	                                        // failure mode; nothing mutates the
  2464	                                        // table mid-iteration). Debug: loud.
  2465	                                        // Release (#1855 contract): count,
  2466	                                        // roll back, drop — never half-commit.
  2467	                                        debug_assert!(
  2468	                                            false,
  2469	                                            "forward install failed after can_admit preflight"
  2470	                                        );
  2750	                                        // reverse tuple attributes the same policy.
  2751	                                        policy_id: policy_result.policy_id,
  2752	                                        // #3227: mirror the matched application term's
  2753	                                        // per-application inactivity (idle) timeout onto
  2754	                                        // the reverse entry so whichever entry the GC
  2755	                                        // expires uses the app's idle window.
  2756	                                        inactivity_timeout_ns:
  2757	                                            crate::session::app_inactivity_timeout_ns(
  2758	                                                policy_result.inactivity_timeout,
  2759	                                            ),
  2760	                                        // #3073: mirror the admitting rule's hit-counter
  2761	                                        // handle onto the reverse companion so reply
  2762	                                        // traffic of the flow counts against the same
  2763	                                        // policy as the forward direction. #3322:
  2764	                                        // mirror the reorder-stable bound handle too.
  2765	                                        policy_counter_idx: policy_result.policy_counter_idx,
  2766	                                        policy_counter: bound_policy_counter.clone(),
  2767	                                    };
  2768	                                    // #1861 §5.2: the reverse install is gated on
  2769	                                    // forward_installed (was track_in_userspace —
  2770	                                    // a forward failure used to fall through and
  2771	                                    // still attempt the reverse, the latent
  2772	                                    // half-open-reverse hazard). At this point
  2773	                                    // track_in_userspace ⇒ forward_installed
  2774	                                    // (the residual arm above drops otherwise),
  2775	                                    // so this gate is explicit, not a behavior
  2776	                                    // fork.
  2777	                                    let reverse_installed = forward_installed
  2778	                                        && install_local_reverse
  2779	                                        && sessions.install_with_protocol_with_origin(
  2780	                                            reverse_key.clone(),
  2781	                                            reverse_decision,
  2782	                                            reverse_metadata.clone(),
  2783	                                            SessionOrigin::ReverseFlow,
  2784	                                            now_ns,
  2785	                                            meta.protocol,
  2786	                                            meta.tcp_flags,
  2787	                                        );
  2788	                                    if forward_installed
  2789	                                        && install_local_reverse
  2790	                                        && !reverse_installed
  2791	                                    {
  2792	                                        // #1861 §5.2 residual (reverse half):
  2793	                                        // impossible after a passing can_admit
  2794	                                        // for needed_sessions == 2. Release
  2795	                                        // (#1855 contract): keep the committed
  2796	                                        // forward (the reply repair services
  2797	                                        // inbound), count, and suppress the
  2798	                                        // flow-cache entry so the partially-
  2799	                                        // installed flow is re-evaluated per
  2800	                                        // packet instead of being persisted.
  1900	
  1901	    fn cache_hits(
  1902	        binding: &mut BindingWorker,
  1903	        key: &SessionKey,
  1904	        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
  1905	    ) -> bool {
  1906	        cache_hits_on_if(binding, key, rg_epochs, REAP_INGRESS_IF)
  1907	    }
  1908	
  1909	    fn cache_hits_on_if(
  1910	        binding: &mut BindingWorker,
  1911	        key: &SessionKey,
  1912	        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
  1913	        ingress_ifindex: i32,
  1914	    ) -> bool {
  1915	        binding
  1916	            .flow
  1917	            .flow_cache
  1918	            .lookup(
  1919	                key,
  1920	                FlowCacheLookup {
  1921	                    ingress_ifindex,
  1922	                    logical_ingress_ifindex: ingress_ifindex,
  1923	                    config_generation: 1,
  1924	                    fib_generation: 1,
  1925	                },
  1926	                0,
  1927	                rg_epochs,
  1928	            )
  1929	            .is_some()
  1930	    }
  1931	
  1932	    fn expired(key: SessionKey, snat_port: Option<u16>) -> ExpiredSession {
  1933	        ExpiredSession {
  1934	            key,
  1935	            decision: reap_decision(snat_port),
  1936	            metadata: reap_metadata(),
  1937	            origin: SessionOrigin::ForwardFlow,
  1938	        }
  1939	    }
  1940	
  1941	    // #3776 H1: a packet that resumes on a reaped flow's 5-tuple must MISS the
  1942	    // cache. Without the GC-path `invalidate_slot` the descriptor survives the
  1943	    // reap and the resumed packet is forwarded with no live session — the
  1944	    // stateful-firewall bypass. RED on revert (the entry survives, `cache_hits`
  1945	    // stays true after the reap).
  1946	    #[test]
  1947	    fn reaped_session_flow_cache_slot_is_invalidated() {
  1948	        let rg_epochs = reap_rg_epochs();
  1949	        let forwarding = ForwardingState::default();
  1950	        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
  1951	        let key = reap_key(12345);
  1952	        insert_cache_entry(&mut binding, &key, None);
  1953	        assert!(
  1954	            cache_hits(&mut binding, &key, &rg_epochs),
  1955	            "precondition: an active flow's descriptor is cached and hits"
  1956	        );
  1957	
  1958	        reap_expired_sessions(
  1959	            std::slice::from_mut(&mut binding),
  1960	            &[expired(key.clone(), None)],
  1961	            &forwarding,
  1962	            -1,
  1963	            -1,
  1964	            -1,
  1965	            1_000_000_000,

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tunnel.rs | sed -n '220,330p;500,550p'
rg -n 'session_entry' userspace-dp/src/afxdp/coordinator userspace-dp/src/afxdp/tunnel.rs --glob '*.rs' | head -100"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   220	    };
   221	    if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
   222	        return false;
   223	    }
   224	    endpoint.logical_ifindex == spawned_logical_ifindex
   225	        && forwarding
   226	            .ifindex_to_name
   227	            .get(&endpoint.logical_ifindex)
   228	            .is_some_and(|name| name == spawned_tunnel_name)
   229	}
   230	
   231	// Spawn plumbing: the shared state this thread reads is threaded in by
   232	// value/Arc at spawn (#1881). #2412 added the `wake` eventfd (16→17).
   233	#[allow(clippy::too_many_arguments)]
   234	pub(super) fn local_tunnel_source_loop(
   235	    tunnel_name: String,
   236	    tunnel_endpoint_id: u16,
   237	    spawned_logical_ifindex: i32,
   238	    shared_runtime: RuntimeViewReader,
   239	    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
   240	    dynamic_neighbors: Arc<ShardedNeighborMap>,
   241	    live: BTreeMap<u32, Arc<BindingLiveState>>,
   242	    identities: BTreeMap<u32, BindingIdentity>,
   243	    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
   244	    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
   245	    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
   246	    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
   247	    // #6471: node-shared live-IKE-exchange table — seeded when the firewall
   248	    // INITIATES IKE through this tunnel so the peer's replies are recognized
   249	    // as established at Stage 11 (see `build_local_origin_tunnel_tx_request`).
   250	    ike_exchanges: crate::afxdp::forwarding::SharedIkeExchangeTable,
   251	    worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
   252	    delivery_rx: Receiver<Vec<u8>>,
   253	    // #2412: the eventfd this thread blocks on in poll(2) alongside the
   254	    // TUN fd. Producers (worker slow path) and the stop path signal it
   255	    // to wake the loop, replacing the 1ms busy-poll.
   256	    wake: Arc<TunnelWake>,
   257	    recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
   258	    stop: Arc<AtomicBool>,
   259	) {
   260	    let mut tun = match open_tun(&tunnel_name) {
   261	        Ok((file, _actual_name)) => file,
   262	        Err(err) => {
   263	            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
   264	            return;
   265	        }
   266	    };
   267	    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
   268	        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
   269	        return;
   270	    }
   271	
   272	    let mut packet = vec![0u8; 65_536];
   273	    let mut next_slot = 0usize;
   274	    let mut local_sessions = FastMap::<SessionKey, u64>::default();
   275	    let mut local_sessions_last_prune_ns = 0u64;
   276	    let tun_fd = tun.as_raw_fd();
   277	    let wake_fd = wake.raw_fd();
   278	    // #1881 D.1: track the worker-visible forwarding ArcSwap instead
   279	    // of a spawn-time clone. ONE load point per outer iteration (the
   280	    // #1188 ptr_eq short-circuit); the same Arc is used for the WHOLE
   281	    // packet build below, so resolution, session synthesis, CoS, and
   282	    // encap are coherent by construction. Cost honesty: this loop is
   283	    // syscall-paced (read(2) drained per iteration, then a blocking
   284	    // poll(2) when idle — #2412 replaced the 1ms busy-poll, single-digit
   285	    // pps workload) — a drained read pass IS the batch, so the per-BATCH
   286	    // ArcSwap rule holds and the AF_XDP worker hot path is untouched.
   287	    //
   288	    // #6592: this thread needs only the forwarding half of the published
   289	    // `RuntimeView` (it builds and encapsulates local-origin packets; it does
   290	    // not match shim generation stamps), so it reads through
   291	    // `load_forwarding_if_changed`. A validation-only publish rotates the view
   292	    // but not the inner forwarding Arc, so it correctly sees no change here.
   293	    let mut forwarding: Arc<ForwardingState> = shared_runtime.load().forwarding().clone();
   294	    let mut endpoint_attached = endpoint_attachment_valid(
   295	        &forwarding,
   296	        tunnel_endpoint_id,
   297	        spawned_logical_ifindex,
   298	        &tunnel_name,
   299	    );
   300	    while !stop.load(Ordering::Relaxed) {
   301	        if let Some(new_forwarding) =
   302	            super::types::load_forwarding_if_changed(&forwarding, &shared_runtime)
   303	        {
   304	            forwarding = new_forwarding;
   305	            endpoint_attached = endpoint_attachment_valid(
   306	                &forwarding,
   307	                tunnel_endpoint_id,
   308	                spawned_logical_ifindex,
   309	                &tunnel_name,
   310	            );
   311	        }
   312	        // #1881 (AGY plan r1): ONE HA-state load per iteration, passed
   313	        // down so resolution enforcement and reverse-entry synthesis
   314	        // see the same map. Cross-source (forwarding↔HA) atomicity is
   315	        // not claimed — they are published independently by design,
   316	        // matching the worker path.
   317	        let ha_runtime = ha_state.load();
   318	        // #2438: deliver each queued packet with a single-write,
   319	        // whole-packet seam (non-blocking TUN fd) — never std
   320	        // `Write::write_all`, whose short-count resume would corrupt the
   321	        // device. `tun_fd` is a plain i32 copy, so this closure does not
   322	        // borrow `tun` (the read below still uses `tun`).
   323	        let mut write_packet = |buf: &[u8]| crate::slowpath::write_packet_nonblocking(tun_fd, buf);
   324	        match drain_local_tunnel_deliveries(
   325	            &mut write_packet,
   326	            &delivery_rx,
   327	            &stop,
   328	            &tunnel_name,
   329	            &recent_exceptions,
   330	        ) {
   500	            revents: 0,
   501	        },
   502	    ];
   503	    // SAFETY: two valid pollfds, count 2.
   504	    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
   505	    if rc < 0 {
   506	        let err = io::Error::last_os_error();
   507	        if err.kind() == io::ErrorKind::Interrupted {
   508	            return LocalTunnelPollOutcome::Ready; // spurious — re-run
   509	        }
   510	        return LocalTunnelPollOutcome::Fatal("poll_failed");
   511	    }
   512	    if rc == 0 {
   513	        return LocalTunnelPollOutcome::Idle;
   514	    }
   515	    if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
   516	        return LocalTunnelPollOutcome::Fatal("tun_revents");
   517	    }
   518	    // Coalesced eventfd signals: one drain clears the readable state; the
   519	    // caller drains the mpsc queue to completion regardless of the count.
   520	    if fds[1].revents & libc::POLLIN != 0 {
   521	        wake.drain();
   522	    }
   523	    LocalTunnelPollOutcome::Ready
   524	}
   525	
   526	pub(super) fn build_local_origin_tunnel_tx_request(
   527	    packet: &[u8],
   528	    tunnel_endpoint_id: u16,
   529	    forwarding: &ForwardingState,
   530	    ha_runtime: &BTreeMap<i32, HAGroupRuntime>,
   531	    dynamic_neighbors: &Arc<ShardedNeighborMap>,
   532	    // #6471: seeded for an outbound IKE initiation (see below). Production
   533	    // passes the node-shared table; tests pass a scratch one to assert the
   534	    // seed (or its absence).
   535	    ike_exchanges: &crate::afxdp::forwarding::IkeExchangeTable,
   536	) -> Result<LocalTunnelTxPlan, String> {
   537	    let mut meta = local_origin_packet_meta(packet)
   538	        .ok_or_else(|| "unsupported_local_origin_packet".to_string())?;
   539	    let inner_frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
   540	    meta.l3_offset = 14;
   541	    meta.l4_offset = meta.l4_offset.saturating_add(14);
   542	    meta.payload_offset = meta.payload_offset.saturating_add(14);
   543	    // #1881 (AGY plan r1): the caller loads HA state ONCE per loop
   544	    // iteration and passes the map down — resolution enforcement and
   545	    // the reverse-entry synthesis below must see the same HA map.
   546	    let resolution = enforce_ha_resolution_snapshot(
   547	        forwarding,
   548	        ha_runtime,
   549	        monotonic_nanos() / 1_000_000_000,
   550	        resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/tunnel.rs:595:    let session_entry = SyncedSessionEntry {
userspace-dp/src/afxdp/tunnel.rs:648:    let reverse_session_entry = synthesized_synced_reverse_entry(
userspace-dp/src/afxdp/tunnel.rs:652:        &session_entry,
userspace-dp/src/afxdp/tunnel.rs:665:        Some(&session_entry.key),
userspace-dp/src/afxdp/tunnel.rs:679:            flow_key: Some(session_entry.key.clone()),
userspace-dp/src/afxdp/tunnel.rs:686:        session_entry,
userspace-dp/src/afxdp/tunnel.rs:687:        reverse_session_entry,
userspace-dp/src/afxdp/tunnel.rs:735:    let entry = &plan.session_entry;
userspace-dp/src/afxdp/tunnel.rs:755:    if let Some(reverse) = &plan.reverse_session_entry {
userspace-dp/src/afxdp/tunnel.rs:772:            if let Some(reverse) = &plan.reverse_session_entry {
userspace-dp/src/afxdp/coordinator/mod.rs:505:    /// `build_synced_session_entry` to translate legacy
userspace-dp/src/afxdp/coordinator/mod.rs:824:            if publish_live_session_entry(

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tunnel.rs | sed -n '700,790p'
rg -n 'build_local_origin_tunnel_tx_request' userspace-dp/src/afxdp/tunnel.rs"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   700	        magic: USERSPACE_META_MAGIC,
   701	        version: USERSPACE_META_VERSION,
   702	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
   703	        l4_offset: l4_offset.min(u16::MAX as usize) as u16,
   704	        payload_offset: l4_offset.min(u16::MAX as usize) as u16,
   705	        pkt_len: packet.len().min(u16::MAX as usize) as u16,
   706	        addr_family,
   707	        protocol,
   708	        ..UserspaceDpMeta::default()
   709	    })
   710	}
   711	
   712	pub(super) fn wrap_raw_ip_packet_for_tunnel(packet: &[u8], addr_family: u8) -> Vec<u8> {
   713	    let mut frame = vec![0u8; 14 + packet.len()];
   714	    frame[12..14].copy_from_slice(if addr_family as i32 == libc::AF_INET {
   715	        &[0x08, 0x00]
   716	    } else {
   717	        &[0x86, 0xdd]
   718	    });
   719	    frame[14..].copy_from_slice(packet);
   720	    frame
   721	}
   722	
   723	pub(super) fn maybe_enqueue_local_tunnel_session(
   724	    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
   725	    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
   726	    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
   727	    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
   728	    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
   729	    local_sessions: &mut FastMap<SessionKey, u64>,
   730	    local_sessions_last_prune_ns: &mut u64,
   731	    plan: &LocalTunnelTxPlan,
   732	) {
   733	    let now_ns = monotonic_nanos();
   734	    prune_local_tunnel_sessions(local_sessions, local_sessions_last_prune_ns, now_ns);
   735	    let entry = &plan.session_entry;
   736	    let refresh_after_ns = if matches!(entry.protocol, PROTO_TCP) {
   737	        5_000_000_000
   738	    } else {
   739	        1_000_000_000
   740	    };
   741	    if matches!(
   742	        local_sessions.get(&entry.key),
   743	        Some(last) if now_ns.saturating_sub(*last) < refresh_after_ns
   744	    ) {
   745	        return;
   746	    }
   747	    local_sessions.insert(entry.key.clone(), now_ns);
   748	    publish_shared_session(
   749	        shared_sessions,
   750	        shared_nat_sessions,
   751	        shared_forward_wire_sessions,
   752	        shared_owner_rg_indexes,
   753	        entry,
   754	    );
   755	    if let Some(reverse) = &plan.reverse_session_entry {
   756	        publish_shared_session(
   757	            shared_sessions,
   758	            shared_nat_sessions,
   759	            shared_forward_wire_sessions,
   760	            shared_owner_rg_indexes,
   761	            reverse,
   762	        );
   763	    }
   764	    for pending in worker_commands {
   765	        // #1807: recover-and-push — `if let Ok` silently DROPPED the
   766	        // local-tunnel UpsertLocal pair for a poisoned worker queue. A
   767	        // panic between the forward and reverse pushes leaves the
   768	        // committed prefix (forward only); commands are self-contained.
   769	        {
   770	            let mut pending = worker_queue::lock_recover(pending);
   771	            pending.push_back(WorkerCommand::UpsertLocal(entry.clone()));
   772	            if let Some(reverse) = &plan.reverse_session_entry {
   773	                pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));
   774	            }
   775	        }
   776	    }
   777	    wait_for_local_tunnel_session_install(worker_commands, now_ns + 1_000_000);
   778	}
   779	
   780	fn prune_local_tunnel_sessions(
   781	    local_sessions: &mut FastMap<SessionKey, u64>,
   782	    last_prune_ns: &mut u64,
   783	    now_ns: u64,
   784	) {
   785	    if local_sessions.len() < LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD
   786	        || now_ns.saturating_sub(*last_prune_ns) < LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS
   787	    {
   788	        return;
   789	    }
   790	    let cutoff_ns = now_ns.saturating_sub(LOCAL_TUNNEL_SESSION_STALE_NS);
249:    // as established at Stage 11 (see `build_local_origin_tunnel_tx_request`).
363:                    match build_local_origin_tunnel_tx_request(
526:pub(super) fn build_local_origin_tunnel_tx_request(

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tunnel.rs | sed -n '338,405p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   338	        // idle wait point.
   339	        let mut wait = LocalTunnelWait::Block;
   340	        loop {
   341	            if stop.load(Ordering::Relaxed) {
   342	                return;
   343	            }
   344	            match tun.read(&mut packet) {
   345	                // EOF on a TUN fd does not occur in practice; treat it as
   346	                // "nothing more right now" and fall through to poll.
   347	                Ok(0) => break,
   348	                Ok(len) => {
   349	                    // #1881 D.1b: parked — the loaded state no longer
   350	                    // describes this thread's TUN attachment (endpoint
   351	                    // removed, mode flipped, or reattached). Drop without
   352	                    // building; the coordinator prune will join us. Keep
   353	                    // reading so the TUN never backs up.
   354	                    if !endpoint_attached {
   355	                        debug_log!(
   356	                            "LOCAL_TUNNEL[{}]: drop endpoint={} reason=local_tunnel_unattached",
   357	                            tunnel_name,
   358	                            tunnel_endpoint_id
   359	                        );
   360	                        continue;
   361	                    }
   362	                    let packet = &packet[..len];
   363	                    match build_local_origin_tunnel_tx_request(
   364	                        packet,
   365	                        tunnel_endpoint_id,
   366	                        &forwarding,
   367	                        ha_runtime.as_ref(),
   368	                        &dynamic_neighbors,
   369	                        &ike_exchanges,
   370	                    ) {
   371	                        Ok(plan) => {
   372	                            maybe_enqueue_local_tunnel_session(
   373	                                &shared_sessions,
   374	                                &shared_nat_sessions,
   375	                                &shared_forward_wire_sessions,
   376	                                &shared_owner_rg_indexes,
   377	                                &worker_commands,
   378	                                &mut local_sessions,
   379	                                &mut local_sessions_last_prune_ns,
   380	                                &plan,
   381	                            );
   382	                            if let Some(target_live) = select_live_binding_for_ifindex(
   383	                                &identities,
   384	                                &live,
   385	                                plan.tx_ifindex,
   386	                                next_slot,
   387	                            ) {
   388	                                next_slot = next_slot.wrapping_add(1);
   389	                                if let Err(err) = target_live.enqueue_tx(plan.tx_request) {
   390	                                    record_local_tunnel_exception(
   391	                                        &recent_exceptions,
   392	                                        &tunnel_name,
   393	                                        format!("enqueue_local_tunnel_tx:{err}"),
   394	                                    );
   395	                                }
   396	                            } else {
   397	                                record_local_tunnel_exception(
   398	                                    &recent_exceptions,
   399	                                    &tunnel_name,
   400	                                    format!("no_live_binding_for_tx_ifindex:{}", plan.tx_ifindex),
   401	                                );
   402	                            }
   403	                        }
   404	                        Err(err) => {
   405	                            #[cfg(not(feature = "debug-log"))]

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/forwarding_build/tunnels.rs | sed -n '1,95p;143,170p'
nl -ba userspace-dp/src/afxdp/gre.rs | sed -n '455,505p;615,690p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
     1	//! Tunnel-endpoint population for `build_forwarding_state`.
     2	//!
     3	//! Populates `state.tunnel_endpoints` and
     4	//! `state.tunnel_endpoint_by_ifindex`. Must run before the
     5	//! interfaces addresses pass, which reads
     6	//! `tunnel_endpoint_by_ifindex` when building
     7	//! `ConnectedRouteV4/V6.tunnel_endpoint_id`.
     8	
     9	use super::super::*;
    10	use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    11	
    12	pub(super) fn populate_tunnel_endpoints(
    13	    snapshot: &ConfigSnapshot,
    14	    state: &mut ForwardingState,
    15	) -> Result<(), crate::policy::SnapshotIntegrityError> {
    16	    for endpoint in &snapshot.tunnel_endpoints {
    17	        if endpoint.id == 0 || endpoint.ifindex <= 0 {
    18	            continue;
    19	        }
    20	        // #2410: validate the outer-IP TTL ONCE here instead of narrowing it
    21	        // with an unchecked `endpoint.ttl.max(0) as u8`. A value > 255 fails
    22	        // the snapshot closed rather than wrapping (256→0 blackholes the
    23	        // tunnel).
    24	        let ttl = super::validated::TunnelTtl::try_from_snapshot(endpoint.ttl, endpoint.id)?.get();
    25	        let is_wireguard = endpoint.mode == "wireguard";
    26	        // GRE/IPIP require concrete outer source/destination. WireGuard
    27	        // carries the peer in `wg_endpoint` and may have neither
    28	        // (responder-only), so skip the parse-or-drop gate for WG and
    29	        // default the unused outer source/destination to an unspecified
    30	        // address (#1432 S2a).
    31	        let (source, destination) = if is_wireguard {
    32	            (
    33	                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    34	                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    35	            )
    36	        } else {
    37	            let Ok(source) = endpoint.source.parse::<IpAddr>() else {
    38	                continue;
    39	            };
    40	            let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
    41	                continue;
    42	            };
    43	            // #5162: a non-WireGuard tunnel encapsulates in ONE outer IP
    44	            // family, so the outer source and destination MUST be the same
    45	            // family. The Go commit gate (validateTunnelOuterFamilyStrict)
    46	            // rejects a mixed pair, but a config synced from an older peer
    47	            // (pre-#5162) or a corrupt snapshot can still carry one — and the
    48	            // Go producer tags such a row `inet6` when EITHER endpoint is v6,
    49	            // which drives the GRE encoder into the AF_INET6 arm where the v4
    50	            // endpoint yields None → a SILENT per-packet drop. Skip the
    51	            // degenerate row loudly here instead so it installs nothing rather
    52	            // than a blackhole (fail-closed, mirroring the WG hydrate
    53	            // row-drop and the allowed-ips prefix-drop skip-and-continue
    54	            // posture in this file).
    55	            if source.is_ipv6() != destination.is_ipv6() {
    56	                eprintln!(
    57	                    "xpf-userspace-dp: tunnel endpoint {} outer source {} and destination {} are different address families; skipping this endpoint (a GRE/IPIP tunnel encapsulates in one outer family — #5162)",
    58	                    endpoint.id, source, destination
    59	                );
    60	                continue;
    61	            }
    62	            (source, destination)
    63	        };
    64	        let outer_family = match (endpoint.outer_family.as_str(), destination) {
    65	            ("inet6", _) => libc::AF_INET6,
    66	            ("inet", _) => libc::AF_INET,
    67	            (_, IpAddr::V6(_)) => libc::AF_INET6,
    68	            _ => libc::AF_INET,
    69	        };
    70	        let transport_table =
    71	            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);
    72	
    73	        // WireGuard field hydration (#1432 S2a, multi-peer #1434). On a
    74	        // malformed local privkey OR any malformed peer pubkey the
    75	        // endpoint is dropped — a WG tunnel with a bad key cannot
    76	        // function and must not silently install a half-configured
    77	        // engine. The hydration gates live in `hydrate_wg_identity`
    78	        // (#1866) so the coordinator's tombstone-respawn coherence check
    79	        // and the defer-branch prune can never drift from this path's
    80	        // semantics.
    81	        let mut wg_local_privkey = zeroize::Zeroizing::new([0u8; 32]);
    82	        let mut wg_peers: Vec<WgRuntimePeer> = Vec::new();
    83	        if is_wireguard {
    84	            let Some(identity) = hydrate_wg_identity(endpoint) else {
    85	                continue;
    86	            };
    87	            wg_local_privkey = identity.local_privkey;
    88	            wg_peers = identity.peers;
    89	        }
    90	
    91	        state.tunnel_endpoints.insert(
    92	            endpoint.id,
    93	            TunnelEndpoint {
    94	                id: endpoint.id,
    95	                logical_ifindex: endpoint.ifindex,
   143	/// #2327: the typed kind of a tunnel-endpoint `mode` string. Centralizes
   144	/// the kind classification that the decap index, the egress encap
   145	/// dispatcher, and the GRE supervision paths all rely on, so a future
   146	/// tunnel kind is added in exactly one place and the egress dispatcher's
   147	/// fail-closed `_ =>` arm cannot silently treat it as GRE.
   148	#[derive(Clone, Copy, PartialEq, Eq, Debug)]
   149	pub(in crate::afxdp) enum TunnelKind {
   150	    /// `gre` / `ip6gre` — native GRE encapsulation/decapsulation.
   151	    Gre,
   152	    /// `wireguard` — WireGuard engine encap/decap.
   153	    WireGuard,
   154	    /// Any unrecognized / future / malformed mode string. The egress
   155	    /// dispatcher MUST fail closed (drop) on this rather than default to
   156	    /// GRE encap (the pre-#2327 fail-open behavior).
   157	    Unknown,
   158	}
   159	
   160	/// Classify a tunnel-endpoint `mode` string into a `TunnelKind`. Mirrors
   161	/// the canonical GRE-kind test used across the supervision paths
   162	/// (`mode == "gre" || mode == "ip6gre"`).
   163	pub(in crate::afxdp) fn tunnel_mode_kind(mode: &str) -> TunnelKind {
   164	    match mode {
   165	        "gre" | "ip6gre" => TunnelKind::Gre,
   166	        "wireguard" => TunnelKind::WireGuard,
   167	        _ => TunnelKind::Unknown,
   168	    }
   169	}
   170	
   455	        GRE_PROTO_IPV4 => Some((libc::AF_INET as u8, 0x0800)),
   456	        GRE_PROTO_IPV6 => Some((libc::AF_INET6 as u8, 0x86dd)),
   457	        _ => None,
   458	    }
   459	}
   460	
   461	/// Match a received GRE (proto-47) outer tuple to a GRE-mode tunnel
   462	/// endpoint.
   463	///
   464	/// #2327 (kind-segregation + O(N) fix): the lookup goes through
   465	/// `gre_decap_index`, which only contains `mode == "gre"` / `"ip6gre"`
   466	/// endpoints — so a GRE frame is NEVER decapped against a WireGuard or
   467	/// any other non-GRE row even if the outer tuple/key happen to collide.
   468	/// The index is keyed by the endpoint's own
   469	/// `(outer_family, source, destination)`; a received frame mirrors it as
   470	/// `(addr_family, outer_dst, outer_src)`. Each bucket is a small
   471	/// candidate list so a duplicate outer tuple (a keyed and an unkeyed
   472	/// endpoint, or distinct logical ifindexes) is disambiguated by the GRE
   473	/// key here rather than resolved non-deterministically by a first-match
   474	/// scan over the entire table. Defense-in-depth: each candidate's
   475	/// `mode` is re-checked via `tunnel_mode_kind` so a future build-side
   476	/// indexing bug can never surface a non-GRE row on this path.
   477	fn match_tunnel_endpoint(
   478	    forwarding: &ForwardingState,
   479	    outer_family: i32,
   480	    outer_src: IpAddr,
   481	    outer_dst: IpAddr,
   482	    key: u32,
   483	    key_present: bool,
   484	) -> Option<&TunnelEndpoint> {
   485	    let candidates = forwarding
   486	        .gre_decap_index
   487	        .get(&(outer_family, outer_dst, outer_src))?;
   488	    for id in candidates {
   489	        let Some(endpoint) = forwarding.tunnel_endpoints.get(id) else {
   490	            continue;
   491	        };
   492	        // Kind re-check (defense in depth): only GRE-mode rows decap as
   493	        // GRE, regardless of what the index claims.
   494	        if tunnel_mode_kind(&endpoint.mode) != TunnelKind::Gre {
   495	            continue;
   496	        }
   497	        let key_ok = if endpoint.key == 0 {
   498	            !key_present || key == 0
   499	        } else {
   500	            key_present && endpoint.key == key
   501	        };
   502	        if key_ok {
   503	            return Some(endpoint);
   504	        }
   505	    }
   615	        return 0;
   616	    }
   617	    let l4 = rel_l4 as usize;
   618	    packet.get(l4 + 13).copied().unwrap_or_default()
   619	}
   620	
   621	pub(super) fn try_native_gre_decap_from_frame(
   622	    frame: &[u8],
   623	    meta: UserspaceDpMeta,
   624	    forwarding: &ForwardingState,
   625	) -> Option<NativeGrePacket> {
   626	    if meta.protocol != PROTO_GRE {
   627	        return None;
   628	    }
   629	    let gre_offset = meta.l4_offset as usize;
   630	    let base = frame.get(gre_offset..gre_offset + 4)?;
   631	    let flags_version = u16::from_be_bytes([base[0], base[1]]);
   632	    if (flags_version & GRE_VERSION_MASK) != 0 {
   633	        return None;
   634	    }
   635	    // Source Route Entries (the Routing-Present R bit) are not parsed —
   636	    // the variable SRE list has no fixed offset and is effectively dead
   637	    // on the modern Internet. A routed GRE frame stays a drop.
   638	    if (flags_version & GRE_FLAG_ROUTING) != 0 {
   639	        return None;
   640	    }
   641	    let checksum_present = (flags_version & GRE_FLAG_CHECKSUM) != 0;
   642	    let key_present = (flags_version & GRE_FLAG_KEY) != 0;
   643	    let sequence_present = (flags_version & GRE_FLAG_SEQUENCE) != 0;
   644	    let gre_proto = u16::from_be_bytes([base[2], base[3]]);
   645	    let (inner_family, inner_eth_proto) = gre_inner_family_and_proto(gre_proto)?;
   646	
   647	    let mut inner_offset = gre_offset + 4;
   648	    // #2782: RFC 2890 fixed field order is Checksum+Reserved1, then Key,
   649	    // then Sequence — the Checksum field (when present) is FIRST, right
   650	    // after the flags/protocol word. Skip its 4 bytes (2-byte Checksum +
   651	    // 2-byte Reserved1) to reach Key/Sequence and the inner payload, and
   652	    // validate the checksum so a corrupt frame is a counted drop rather
   653	    // than a silently-misforwarded one.
   654	    if checksum_present {
   655	        // The checksum covers the GRE header + payload. Bound that
   656	        // region by the OUTER IP length so we do not fold trailing L2
   657	        // padding (Ethernet min-frame pad) into the sum.
   658	        let gre_region = gre_checksum_region(frame, meta, gre_offset)?;
   659	        // IP one's-complement checksum of the whole GRE region (the
   660	        // Checksum field is included as-is); a valid frame folds to 0.
   661	        if checksum16(gre_region) != 0 {
   662	            GRE_DECAP_CHECKSUM_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
   663	            return None;
   664	        }
   665	        // Past the checksum/reserved field; bounds-check before advance.
   666	        frame.get(inner_offset..inner_offset + 4)?;
   667	        inner_offset += 4;
   668	    }
   669	    let mut key = 0u32;
   670	    if key_present {
   671	        key = u32::from_be_bytes(
   672	            <[u8; 4]>::try_from(frame.get(inner_offset..inner_offset + 4)?).ok()?,
   673	        );
   674	        inner_offset += 4;
   675	    }
   676	    if sequence_present {
   677	        frame.get(inner_offset..inner_offset + 4)?;
   678	        inner_offset += 4;
   679	    }
   680	    let inner_packet = frame.get(inner_offset..)?;
   681	    let inner_len = packet_trimmed_len(inner_packet, inner_family)?;
   682	    let inner_packet = &inner_packet[..inner_len];
   683	
   684	    let (outer_src, outer_dst) = parse_outer_addresses(frame, meta)?;
   685	    let endpoint = match_tunnel_endpoint(
   686	        forwarding,
   687	        meta.addr_family as i32,
   688	        outer_src,
   689	        outer_dst,
   690	        key,

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/daemon/daemon_ha_sync.go | sed -n '90,180p;750,805p'
nl -ba pkg/cluster/heartbeat_manager.go | sed -n '135,170p;314,330p;420,450p'
nl -ba pkg/cluster/heartbeat.go | sed -n '785,807p;860,885p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
    90	func (d *Daemon) onSessionSyncBulkReceived() {
    91		d.syncBulkPrimed.Store(true)
    92		slog.Info("cluster: session sync bulk received",
    93			"retry_gen", d.syncPrimeRetryGen.Load())
    94		d.stopSyncReadyTimer()
    95		if d.vrrpMgr != nil {
    96			d.vrrpMgr.ReleaseSyncHold()
    97		}
    98		if d.cluster != nil {
    99			d.cluster.SetSyncReady(true)
   100		}
   101	}
   102	
   103	func (d *Daemon) onSessionSyncBulkAckReceived() {
   104		d.syncPeerBulkPrimed.Store(true)
   105		slog.Info("cluster: session sync bulk ack received",
   106			"retry_gen", d.syncPrimeRetryGen.Load())
   107	}
   108	
   109	func (d *Daemon) onSessionSyncPeerDisconnected() {
   110		d.syncPeerConnected.Store(false)
   111		gen := d.syncPrimeRetryGen.Add(1)
   112	
   113		// On disconnect after a completed bulk exchange, preserve primed state
   114		// and sync readiness. The sessions are still in the BPF maps — a
   115		// subsequent reconnect will resume incremental sync without needing a
   116		// full bulk transfer (#466).
   117		ss := d.getSessionSync()
   118		wasEverPrimed := ss != nil && ss.BulkEverCompleted()
   119		if !wasEverPrimed {
   120			d.syncBulkPrimed.Store(false)
   121			d.syncPeerBulkPrimed.Store(false)
   122		}
   123	
   124		slog.Info("cluster: session sync peer disconnected",
   125			"retry_gen", gen,
   126			"was_ever_primed", wasEverPrimed,
   127			"bulk_primed", d.syncBulkPrimed.Load(),
   128			"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
   129			"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
   130		d.stopSyncReadyTimer()
   131	
   132		if !wasEverPrimed {
   133			if d.cluster != nil {
   134				d.cluster.SetSyncReady(false)
   135			}
   136		}
   137	}
   138	
   139	func (d *Daemon) shouldSuppressPeerHeartbeatTimeout() (bool, string) {
   140		ss := d.getSessionSync()
   141		if ss == nil || !ss.IsConnected() {
   142			d.hbSuppressStart.Store(0) // reset when sync disconnected
   143			return false, ""
   144		}
   145		const maxPeerSyncSilence = 2 * time.Second
   146		age, ok := ss.LastPeerReceiveAge()
   147		if !ok || age > maxPeerSyncSilence {
   148			d.hbSuppressStart.Store(0) // reset when sync goes quiet
   149			return false, ""
   150		}
   151	
   152		// Cap total suppression duration. During graceful shutdown the peer
   153		// may send a bulk sync that keeps LastPeerReceiveAge() fresh for tens
   154		// of seconds while heartbeats have already stopped. After 5s of
   155		// continuous suppression, stop suppressing so the heartbeat timeout
   156		// can fire and trigger failover.
   157		//
   158		// The window is measured in CLOCK_MONOTONIC nanos (#1792): with
   159		// wall-clock UnixNano a backward step left suppression stuck on
   160		// (blocking failover for the step duration) and a forward step cut
   161		// it short.
   162		const maxSuppressDuration = 5 * time.Second
   163		now := cluster.MonotonicNanos()
   164		start := d.hbSuppressStart.Load()
   165		if start == 0 {
   166			d.hbSuppressStart.Store(now)
   167			start = now
   168		}
   169		if hbSuppressCapExceeded(start, now, maxSuppressDuration) {
   170			return false, ""
   171		}
   172	
   173		return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
   174	}
   175	
   176	// hbSuppressCapExceeded reports whether continuous heartbeat-timeout
   177	// suppression that began at startMono has lasted longer than cap by nowMono.
   178	// Both timestamps are CLOCK_MONOTONIC nanos (cluster.MonotonicNanos), so the
   179	// cap is immune to wall-clock steps (#1792). Split out so tests can inject
   180	// timestamps and exercise step scenarios directly.
   750							if err := d.dp.HA().SetHAWatchdog(commsCtx, rg.ID, now); err != nil {
   751								slog.Warn("ha watchdog write failed", "rg", rg.ID, "err", err)
   752							}
   753						}
   754					}
   755				}
   756			}()
   757			slog.Info("HA watchdog heartbeat started", "rgs", len(cc.RedundancyGroups))
   758		}
   759	
   760		// In VRRP mode, make strict VIP ownership the runtime default so
   761		// rg_active follows VIP/MAC ownership rather than cluster-primary
   762		// intent. Direct/no-reth-vrrp mode and private-rg-election mode
   763		// still use cluster state because there are no VRRP instances to
   764		// gate on.
   765		d.syncRGStrictVIPOwnershipMode(cc)
   766	
   767		// Start heartbeat if control-interface and peer-address are configured.
   768		// Retry on bind failure: the control interface address and VRF device
   769		// may not be ready during daemon startup (networkd race).
   770		if cc.ControlInterface != "" && cc.PeerAddress != "" {
   771			go d.startHeartbeatWithRetry(commsCtx, cc.ControlInterface, cc.PeerAddress, vrfDevice)
   772		}
   773	
   774		// Start session/config sync on the control link (same interface as
   775		// heartbeat, port 4785). Consolidates all control-plane traffic onto
   776		// the dedicated control path. Falls back to fabric if no control
   777		// interface is configured (legacy compatibility).
   778		syncIface := cc.ControlInterface
   779		syncPeerAddr := cc.PeerAddress
   780		syncTransport := "control-link"
   781		if syncIface == "" || syncPeerAddr == "" {
   782			syncIface = cc.FabricInterface
   783			syncPeerAddr = cc.FabricPeerAddress
   784			syncTransport = "fabric"
   785		}
   786		if syncIface != "" && syncPeerAddr != "" {
   787			// Track the constructor goroutine so stopClusterComms can join it
   788			// before tearing the epoch down (#4958): a cancelled constructor must
   789			// finish (or drop its publish) before stop nils the shared state.
   790			d.clusterCommsWG.Add(1)
   791			go func() {
   792				defer d.clusterCommsWG.Done()
   793				var syncIP string
   794				for i := 0; i < 30; i++ {
   795					syncIP = resolveClusterInterfaceAddr(syncIface, syncPeerAddr, "")
   796					if syncIP != "" {
   797						break
   798					}
   799					if i == 0 {
   800						slog.Info("cluster: sync interface has no usable address yet, waiting",
   801							"interface", syncIface, "transport", syncTransport)
   802					}
   803					select {
   804					case <-commsCtx.Done():
   805						return
   135			},
   136		}
   137	}
   138	
   139	// HeartbeatRunning reports whether a heartbeat sender or receiver is currently
   140	// installed. Used by status reporting and to assert the idempotent
   141	// start/stop discipline (#4033).
   142	func (m *Manager) HeartbeatRunning() bool {
   143		m.mu.RLock()
   144		defer m.mu.RUnlock()
   145		return m.hbSender != nil || m.hbReceiver != nil
   146	}
   147	
   148	// StopHeartbeat halts heartbeat sender and receiver goroutines.
   149	func (m *Manager) StopHeartbeat() {
   150		m.mu.Lock()
   151		sender := m.hbSender
   152		receiver := m.hbReceiver
   153		m.hbSender = nil
   154		m.hbReceiver = nil
   155		m.mu.Unlock()
   156	
   157		if sender != nil {
   158			sender.stop()
   159		}
   160		if receiver != nil {
   161			receiver.stop()
   162		}
   163	}
   164	
   165	// RestartHeartbeat stops and restarts the heartbeat with the same parameters.
   166	// This is needed when the control interface's VRF binding changes (e.g. during
   167	// DHCP-triggered recompile) which invalidates the existing UDP sockets.
   168	// Retries up to 5 times with 1s delay if the bind fails (address may briefly
   169	// disappear during VRF rebind). Returns false if heartbeat was not running.
   170	//
   314	// handlePeerHeartbeat processes an incoming peer heartbeat.
   315	func (m *Manager) handlePeerHeartbeat(pkt *HeartbeatPacket) {
   316		m.mu.Lock()
   317		defer m.mu.Unlock()
   318		now := time.Now()
   319	
   320		wasAlive := m.peerAlive
   321		m.peerAlive = true
   322		m.peerEverSeen = true
   323		m.peerNodeID = int(pkt.NodeID)
   324		m.peerSoftwareVersion = pkt.SoftwareVersion
   325		m.peerHAProtocolVersion = normalizeHAProtocolVersion(pkt.HAProtocolVersion)
   326	
   327		// Rebuild peer group states from scratch — prunes stale RGs that
   328		// the peer no longer reports (fix #92).
   329		newPeerGroups := make(map[int]PeerGroupState, len(pkt.Groups))
   330		for _, g := range pkt.Groups {
   420		if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
   421			slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
   422			return
   423		}
   424	
   425		m.peerAlive = false
   426		m.peerGroups = make(map[int]PeerGroupState)
   427		m.peerMonitors = nil
   428		m.peerSoftwareVersion = ""
   429		m.peerHAProtocolVersion = 0
   430		slog.Warn("cluster: peer heartbeat timeout, marking peer lost")
   431		m.history.Record(EventHeartbeat, -1, "Peer heartbeat timeout")
   432	
   433		// Clear ManualFailover on all RGs: the peer is dead, so the surviving
   434		// node MUST be able to take over. Without this, a previous manual
   435		// transfer-out would keep the local node parked in secondary-hold even
   436		// though there is no longer a peer to hand ownership to.
   437		for _, rg := range m.groups {
   438			if rg.ManualFailover {
   439				slog.Info("cluster: clearing manual failover (peer lost)", "rg", rg.GroupID)
   440				rg.ManualFailover = false
   441				rg.ManualFailoverAt = time.Time{}
   442				m.recalcWeight(rg)
   443			}
   444		}
   445	
   446		// Peer lost: re-run single-node election.
   447		m.electSingleNode()
   448	
   449		// Attempt peer fencing if configured.
   450		if m.peerFencing == "disable-rg" {
   785			authSession: randomSessionID(),
   786		}
   787	}
   788	
   789	func (s *heartbeatSender) start() {
   790		s.wg.Add(1)
   791		go s.run()
   792	}
   793	
   794	func (s *heartbeatSender) run() {
   795		defer s.wg.Done()
   796		ticker := time.NewTicker(s.interval)
   797		defer ticker.Stop()
   798	
   799		for {
   800			select {
   801			case <-s.stopCh:
   802				return
   803			case <-ticker.C:
   804				s.send()
   805			}
   806		}
   807	}
   860		go r.readLoop()
   861		go r.timeoutLoop()
   862	}
   863	
   864	func (r *heartbeatReceiver) readLoop() {
   865		defer r.wg.Done()
   866		buf := make([]byte, maxHeartbeatSize)
   867	
   868		for {
   869			select {
   870			case <-r.stopCh:
   871				return
   872			default:
   873			}
   874	
   875			r.conn.SetReadDeadline(time.Now().Add(r.interval))
   876			n, _, err := r.conn.ReadFromUDP(buf)
   877			if err != nil {
   878				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
   879					continue
   880				}
   881				select {
   882				case <-r.stopCh:
   883					return
   884				default:
   885					slog.Debug("cluster: heartbeat read error", "err", err)

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/daemon/daemon_apply_commit.go | sed -n '700,740p'
nl -ba pkg/config/compiler_system.go | sed -n '1855,1880p'
rg -n 'config-synchronize|configuration-synchronize|ConfigSync' pkg/config/schema_chassis.go pkg/config/compiler_system.go"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   700		// #5578: this is a background timer callback with no return path, so mirror
   701		// the applyConfigLocked handling above — a PARTIAL session invalidation
   702		// (enumerate/delete failure) is surfaced via a loud slog.Error rather than
   703		// being lost. The helper now RETURNS the error so the two returning call
   704		// sites (commit + peer-sync) join it into their result; here the log is the
   705		// only available surface.
   706		if err := d.clearSessionsForPolicyChanges(oldActive, prevCfg); err != nil {
   707			slog.Error("commit confirmed auto-rollback: policy session invalidation was PARTIAL; "+
   708				"some rolled-back-policy sessions may keep forwarding under stale authorization", "err", err)
   709		}
   710		// #3868: RE-SYNC the rolled-back config (C1) to the cluster peer. The
   711		// standby already received the unconfirmed config (C2) via config-sync
   712		// SyncApply, which arms NO confirm timer, so it holds C2 as its PERMANENT
   713		// active. PromoteRollback above reverted only THIS node's store to C1;
   714		// without this push the nodes DIVERGE (primary=C1, standby=C2) and a
   715		// failover would serve the abandoned C2. syncConfigToPeer reads the
   716		// now-promoted active (C1) via ShowActive and queues it, exactly like a
   717		// normal commit's sync. It self-guards the peer-absent/disconnected case
   718		// (nil cluster/sessionSync, not RG0 primary, config-sync disabled, or no
   719		// active TCP conn all no-op); the existing reverse-sync-on-reconnect
   720		// retries when the peer comes back. Runs under d.applySem (held above),
   721		// after PromoteRollback, so the pushed text is always the rollback target.
   722		d.resyncRolledBackConfigToPeer()
   723		slog.Warn("commit confirmed timed out, configuration rolled back")
   724	}
   725	
   726	// resyncRolledBackConfigToPeer pushes the just-promoted rollback-target config
   727	// to the cluster peer after a commit-confirmed timeout (#3868). Delegates to
   728	// pushCommittedConfigToPeer so the confirm-timeout rollback path is unit-testable
   729	// without a live cluster transport: rollback_resync_test.go injects
   730	// d.syncPeerForTest to observe the call; production leaves it nil and the real
   731	// syncConfigToPeer runs. MUST be called with d.applySem held and AFTER
   732	// PromoteRollback so d.store.ShowActive() (read inside syncConfigToPeer ->
   733	// pushConfigToPeer) reflects the rolled-back config, not the abandoned
   734	// unconfirmed one.
   735	func (d *Daemon) resyncRolledBackConfigToPeer() {
   736		d.pushCommittedConfigToPeer()
   737	}
  1855			}
  1856		}
  1857		if n := clusterNode.FindChild("fabric-peer-address"); n != nil {
  1858			if v := nodeVal(n); v != "" {
  1859				ch.Cluster.FabricPeerAddress = v
  1860			}
  1861		}
  1862		if n := clusterNode.FindChild("fabric1-interface"); n != nil {
  1863			if v := nodeVal(n); v != "" {
  1864				ch.Cluster.Fabric1Interface = v
  1865			}
  1866		}
  1867		if n := clusterNode.FindChild("fabric1-peer-address"); n != nil {
  1868			if v := nodeVal(n); v != "" {
  1869				ch.Cluster.Fabric1PeerAddress = v
  1870			}
  1871		}
  1872		if clusterNode.FindChild("configuration-synchronize") != nil {
  1873			ch.Cluster.ConfigSync = true
  1874		}
  1875		if clusterNode.FindChild("nat-state-synchronization") != nil {
  1876			ch.Cluster.NATStateSync = true
  1877		}
  1878		if clusterNode.FindChild("ipsec-session-synchronization") != nil {
  1879			ch.Cluster.IPsecSASync = true
  1880		}
pkg/config/compiler_system.go:1872:	if clusterNode.FindChild("configuration-synchronize") != nil {
pkg/config/compiler_system.go:1873:		ch.Cluster.ConfigSync = true
pkg/config/schema_chassis.go:125:		"configuration-synchronize":     {desc: "Synchronize committed configuration from primary to secondary", children: nil},

[35m[3mcodex[0m[0m
The core safety gate is refuted, not merely underspecified. A v2 heartbeat can arrive before the reconnect bulk finishes and turn enforcement on while v1/domainless rows are retained; the reverse downgrade race exists because session-sync disconnect and heartbeat state have independent lifetimes. The v6-r3 test text is also internally impossible: “5-tuple-only, byte-identical to today” cannot simultaneously require a same-5-tuple default-domain packet not to match a legacy row.
[1mcollab:[0m Wait
[1mcollab:[0m Wait
[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba userspace-dp/src/afxdp/forwarding_build/tunnels.rs | sed -n '115,138p'
nl -ba userspace-dp/src/afxdp/poll_stages.rs | sed -n '285,340p'
nl -ba userspace-dp/src/afxdp/poll_descriptor/prerouting_scope.rs | sed -n '1,95p'
nl -ba pkg/daemon/daemon_ha_sync.go | sed -n '775,870p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   115	                wg_peers,
   116	            },
   117	        );
   118	        state
   119	            .tunnel_endpoint_by_ifindex
   120	            .insert(endpoint.ifindex, endpoint.id);
   121	        // #2327: kind-segregated decap index — only GRE-mode endpoints
   122	        // are indexed for the GRE (proto-47) decap fast path. A
   123	        // WireGuard or any non-GRE row is intentionally NOT indexed, so
   124	        // a received GRE frame can never be decapped against it even if
   125	        // the outer tuple/key collide. Keyed by the endpoint's own
   126	        // (outer_family, source, destination); the decap lookup queries
   127	        // with the received frame's mirrored (addr_family, outer_dst,
   128	        // outer_src).
   129	        if tunnel_mode_kind(&endpoint.mode) == TunnelKind::Gre {
   130	            state
   131	                .gre_decap_index
   132	                .entry((outer_family, source, destination))
   133	                .or_default()
   134	                .push(endpoint.id);
   135	        }
   136	        if is_wireguard {
   137	            state.has_wg_tunnels = true;
   138	        }
   285	        {
   286	            return;
   287	        }
   288	        let changed = worker_ctx
   289	            .dynamic_neighbors
   290	            .insert_if_changed((ifindex, na.target_ip), NeighborEntry { mac });
   291	        if neigh_limiter.should_program((ifindex, na.target_ip), mac, changed, now_ns) {
   292	            add_kernel_neighbor(ifindex, na.target_ip, mac);
   293	        }
   294	    }
   295	}
   296	
   297	/// Stage 6 — native GRE decapsulation.
   298	///
   299	/// Returns the (possibly-updated) `meta` and the optional owned
   300	/// decap frame. Caller binds the active slice locally:
   301	///
   302	/// ```text
   303	/// let (meta, owned) = stage_native_gre_decap(raw_frame, meta, ...);
   304	/// let packet_frame = owned.as_deref().unwrap_or(raw_frame);
   305	/// ```
   306	///
   307	/// `owned_packet_frame: Option<Vec<u8>>` MUST be a `mut` binding at
   308	/// the call site because the deferred stage-12+ code in
   309	/// `poll_descriptor.rs` calls `.take()` on it (grep
   310	/// `owned_packet_frame.take(` — the deferred flow-cache,
   311	/// session-hit reverse-NAT, and missing-neighbor side-queue paths
   312	/// each move the owned decap frame out before pushing the
   313	/// resulting forward request). Symbol references rather than line
   314	/// numbers because the line numbers drift any time a stage above
   315	/// is touched.
   316	///
   317	/// The helper does NOT return the active slice — that would be a
   318	/// self-referential return type (the slice would borrow from the
   319	/// returned `Vec`).
   320	#[inline]
   321	pub(super) fn stage_native_gre_decap(
   322	    raw_frame: &[u8],
   323	    meta: UserspaceDpMeta,
   324	    forwarding: &ForwardingState,
   325	) -> (UserspaceDpMeta, Option<Vec<u8>>) {
   326	    let native_gre_packet = try_native_gre_decap_from_frame(raw_frame, meta, forwarding);
   327	    let new_meta = native_gre_packet
   328	        .as_ref()
   329	        .map(|packet| packet.meta)
   330	        .unwrap_or(meta);
   331	    let owned_packet_frame = native_gre_packet.map(|packet| packet.frame);
   332	    (new_meta, owned_packet_frame)
   333	}
   334	
   335	/// Stage 7+8 — parse session flow and learn the source-side
   336	/// dynamic neighbor.
   337	///
   338	/// `learn_from_live_frame` MUST be `owned_packet_frame.is_none()`
   339	/// at the call site. Mirrors the GRE guard at
   340	/// poll_descriptor.rs:113 — neighbor learning uses the un-decapped
     1	// #6386 leaf extraction: the #5802 pre-routing NAT ingress-scope
     2	// resolver (`PreroutingIngressScope` + `prerouting_ingress_scope`),
     3	// lifted verbatim out of poll_descriptor/mod.rs. Both items were
     4	// already `pub(super)`; the ONLY non-motion change is the added
     5	// `#[inline]` on `prerouting_ingress_scope` — it restores same-CGU
     6	// inlining eligibility across the new module boundary (#6386 hot-path
     7	// preservation contract). Bodies byte-identical to their prior location.
     8	
     9	use super::*;
    10	
    11	/// #5802: the ingress identity the pre-routing DNAT / static-NAT / NPTv6
    12	/// scope matches `from zone` / `from interface` / `from routing-instance`
    13	/// against, resolved from the LOGICAL VLAN unit that received the frame.
    14	///
    15	/// The borrowed `&str` fields live for the `forwarding` borrow; `""` = no
    16	/// scope constraint (unscoped rule, matches every ingress).
    17	pub(super) struct PreroutingIngressScope<'a> {
    18	    /// The logical unit ingress ifindex (VLAN sub-interface), or the physical
    19	    /// bind ifindex for an untagged port. Threaded into the later zone-pair
    20	    /// policy so the pre-routing NAT scope and the zone policy share ONE
    21	    /// ingress identity.
    22	    pub logical_ifindex: i32,
    23	    /// Ingress zone name (a fabric-encoded override wins, else the logical
    24	    /// unit's zone).
    25	    pub zone_name: &'a str,
    26	    /// Ingress interface config name (e.g. `reth0.50`).
    27	    pub ifname: &'a str,
    28	    /// Ingress interface routing-instance (`""` = default VRF).
    29	    pub routing_instance: &'a str,
    30	}
    31	
    32	/// Resolve the pre-routing NAT scope identity for a received frame.
    33	///
    34	/// `ifindex_to_zone_id` / `ifindex_to_config_name` /
    35	/// `ifindex_to_routing_instance` are keyed by the LOGICAL unit ifindex
    36	/// (forwarding_build/interfaces.rs); a VLAN sub-interface's physical bind
    37	/// ifindex maps only to its parent's FIRST unit. #5802: scoping the
    38	/// pre-routing DNAT/static-NAT/NPTv6 lookups against the raw physical
    39	/// `meta.ingress_ifindex` on a trunk whose VLAN units sit in distinct zones /
    40	/// interfaces / routing-instances let a packet on one unit match another
    41	/// unit's scoped NAT rule (or miss its own) — a NAT scope-escape ahead of the
    42	/// correct logical zone policy. This resolves the logical unit first (the same
    43	/// identity the zone-policy / filter / CoS path uses, #3021) and reads the
    44	/// scope from it. An untagged port has no `(parent, vlan)` mapping, so it
    45	/// resolves logical == physical and the scope is byte-identical to pre-#5802.
    46	///
    47	/// The zone matches a fabric-ingress `zone_override` (peer-encoded) first,
    48	/// exactly as the pre-#5802 code did; only the physical→logical ifindex used
    49	/// for the local-unit fallback lookups changes.
    50	#[inline]
    51	pub(super) fn prerouting_ingress_scope(
    52	    forwarding: &ForwardingState,
    53	    physical_ifindex: i32,
    54	    ingress_vlan_id: u16,
    55	    zone_override: Option<u16>,
    56	) -> PreroutingIngressScope<'_> {
    57	    let logical_ifindex =
    58	        resolve_ingress_logical_ifindex(forwarding, physical_ifindex, ingress_vlan_id)
    59	            .unwrap_or(physical_ifindex);
    60	    // #919: ingress_zone_override is Option<u16>; DNAT/static NAT lookups take
    61	    // zone names, so resolve ID→name lazily on this miss path. A fabric-encoded
    62	    // override wins; else resolve the LOGICAL unit's zone (#5802).
    63	    let zone_name = zone_override
    64	        .and_then(|id| forwarding.zone_id_to_name.get(&id).map(|s| s.as_str()))
    65	        .or_else(|| {
    66	            forwarding
    67	                .ifindex_to_zone_id
    68	                .get(&logical_ifindex)
    69	                .and_then(|id| forwarding.zone_id_to_name.get(id))
    70	                .map(|s| s.as_str())
    71	        })
    72	        .unwrap_or("");
    73	    // #3096: ingress interface config-name + routing-instance for the DNAT
    74	    // `from interface` / `from routing-instance` scope. DNAT translates on
    75	    // inbound, so only the ingress identity matters. Empty = unscoped.
    76	    let ifname = forwarding
    77	        .ifindex_to_config_name
    78	        .get(&logical_ifindex)
    79	        .map(|s| s.as_str())
    80	        .unwrap_or("");
    81	    let routing_instance = forwarding
    82	        .ifindex_to_routing_instance
    83	        .get(&logical_ifindex)
    84	        .map(|s| s.as_str())
    85	        .unwrap_or("");
    86	    PreroutingIngressScope {
    87	        logical_ifindex,
    88	        zone_name,
    89	        ifname,
    90	        routing_instance,
    91	    }
    92	}
    93	
    94	#[cfg(test)]
    95	#[path = "prerouting_scope_tests.rs"]
   775		// heartbeat, port 4785). Consolidates all control-plane traffic onto
   776		// the dedicated control path. Falls back to fabric if no control
   777		// interface is configured (legacy compatibility).
   778		syncIface := cc.ControlInterface
   779		syncPeerAddr := cc.PeerAddress
   780		syncTransport := "control-link"
   781		if syncIface == "" || syncPeerAddr == "" {
   782			syncIface = cc.FabricInterface
   783			syncPeerAddr = cc.FabricPeerAddress
   784			syncTransport = "fabric"
   785		}
   786		if syncIface != "" && syncPeerAddr != "" {
   787			// Track the constructor goroutine so stopClusterComms can join it
   788			// before tearing the epoch down (#4958): a cancelled constructor must
   789			// finish (or drop its publish) before stop nils the shared state.
   790			d.clusterCommsWG.Add(1)
   791			go func() {
   792				defer d.clusterCommsWG.Done()
   793				var syncIP string
   794				for i := 0; i < 30; i++ {
   795					syncIP = resolveClusterInterfaceAddr(syncIface, syncPeerAddr, "")
   796					if syncIP != "" {
   797						break
   798					}
   799					if i == 0 {
   800						slog.Info("cluster: sync interface has no usable address yet, waiting",
   801							"interface", syncIface, "transport", syncTransport)
   802					}
   803					select {
   804					case <-commsCtx.Done():
   805						return
   806					case <-time.After(2 * time.Second):
   807					}
   808				}
   809				if syncIP == "" {
   810					slog.Error("cluster: sync interface address not available after retries",
   811						"interface", syncIface)
   812					return
   813				}
   814	
   815				syncLocal := net.JoinHostPort(syncIP, "4785")
   816				syncPeer := net.JoinHostPort(syncPeerAddr, "4785")
   817				slog.Info("cluster: session sync transport", "mode", syncTransport,
   818					"local", syncLocal, "peer", syncPeer)
   819	
   820				// Resolve secondary fabric (fab1) for dual transport failover.
   821				// Only applicable when using fabric transport (not control-link).
   822				var syncLocal1, syncPeer1 string
   823				if syncTransport == "fabric" && cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
   824					var fab1IP string
   825					for i := 0; i < 15; i++ {
   826						fab1IP = resolveClusterInterfaceAddr(cc.Fabric1Interface, cc.Fabric1PeerAddress, "")
   827						if fab1IP != "" {
   828							break
   829						}
   830						if i == 0 {
   831							slog.Info("cluster: fabric1 interface has no usable address yet, waiting",
   832								"interface", cc.Fabric1Interface)
   833						}
   834						select {
   835						case <-commsCtx.Done():
   836							return
   837						case <-time.After(2 * time.Second):
   838						}
   839					}
   840					if fab1IP != "" {
   841						syncLocal1 = net.JoinHostPort(fab1IP, "4785")
   842						syncPeer1 = net.JoinHostPort(cc.Fabric1PeerAddress, "4785")
   843						slog.Info("cluster: dual fabric transport configured",
   844							"fab0_local", syncLocal, "fab1_local", syncLocal1)
   845					} else {
   846						slog.Warn("cluster: fabric1 address not available, using single fabric only",
   847							"interface", cc.Fabric1Interface)
   848					}
   849				}
   850	
   851				// Build the session-sync object in a LOCAL variable and publish it
   852				// only if this constructor still owns the current comms epoch
   853				// (#4958). Everything below wires callbacks and cluster references
   854				// against this local `ss` — never re-reading d.sessionSync — so a
   855				// concurrent stopClusterComms that nils the field cannot turn a
   856				// re-dereference into a nil-deref panic, and a superseded epoch's
   857				// late publish is dropped rather than clobbering the live epoch.
   858				var ss *cluster.SessionSync
   859				if syncLocal1 != "" {
   860					ss = cluster.NewDualSessionSync(syncLocal, syncPeer, syncLocal1, syncPeer1, nil)
   861				} else {
   862					ss = cluster.NewSessionSync(syncLocal, syncPeer, nil)
   863				}
   864				if !d.publishSessionSyncIfCurrent(commsGen, ss) {
   865					// A restart superseded this epoch while we were resolving the
   866					// sync address; abort before wiring cluster state or binding.
   867					return
   868				}
   869				// #4107 F23: authenticate the session-sync stream with the same
   870				// control-link PSK the heartbeat + fabric-gRPC use (#4357). The

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/configstore/store_commit.go | sed -n '840,920p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   840	// returns (nil, false) and mutates nothing.
   841	//
   842	// IMPORTANT: ok=true means "store state was promoted", NOT "prevCfg is
   843	// non-nil". On a FIRST commit confirmed (fresh store) the rollback target
   844	// tree is the empty pre-config tree (confirmPrevTree != nil) but the
   845	// compiled config recorded at arm time is nil (a fresh store has
   846	// active=&ConfigTree{} but compiled=nil). PromoteRollback then promotes
   847	// the store back to the empty tree exactly as the prior performAutoRollback
   848	// did and returns (nil, true). The caller MUST nil-check prevCfg before
   849	// applying it to the dataplane — exactly as the old code's
   850	// `if fn != nil && prevCfg != nil` guard did. Re-applying that
   851	// first-commit-to-bootstrap case to the dataplane (and not persisting an
   852	// empty *committed* tree) is #1922 Item 1b, DEFERRED to PR-2; this PR
   853	// leaves that path's behavior unchanged (store reverts, dataplane is not
   854	// re-applied). The #1817 confirmGen guard and #1799 persist-failure
   855	// semantics are preserved verbatim.
   856	func (s *Store) PromoteRollback(gen uint64) (prevCfg *config.Config, ok bool) {
   857		s.mu.Lock()
   858		defer s.mu.Unlock()
   859	
   860		if gen != s.confirmGen {
   861			return nil, false
   862		}
   863		if s.confirmPrevTree == nil {
   864			return nil, false
   865		}
   866	
   867		s.active = s.confirmPrevTree
   868		s.compiled = s.confirmPrevCfg
   869		if s.candidate != nil {
   870			s.candidate = s.active.Clone()
   871			s.bumpCandidateGenLocked() // #5848: candidate reset on auto-rollback
   872		}
   873		s.dirty = false
   874	
   875		s.confirmTimer = nil
   876		s.confirmPrevTree = nil
   877		// #1922 Item 1b: first-commit rollback target. On a fresh-store FIRST
   878		// commit confirmed, confirmPrevCfg is nil here, so prevCfg below is nil
   879		// and ok is true — the store reverts to the empty tree. The caller
   880		// (the daemon executor) detects prevCfg==nil and rolls the dataplane
   881		// back via enterBootstrapMode rather than applying an empty config.
   882		prevCfg = s.confirmPrevCfg
   883		s.confirmPrevCfg = nil
   884		firstCommitRollback := prevCfg == nil
   885	
   886		// Persist reverted config to disk. Option B (#1799): the rollback
   887		// ALWAYS proceeds in memory — reverting the running config is the
   888		// safety property — but a persist failure here used to leave the
   889		// UNCONFIRMED candidate on disk, so a reboot would load the config
   890		// the operator never confirmed. The degraded flag + singleton
   891		// retry make the failure visible (/health 503, gauge, journal
   892		// ERROR) and heal the disk in the background.
   893		//
   894		// #1922 Item 1b: on a first-commit rollback the reverted tree is the
   895		// empty bootstrap tree. It MUST be persisted with the never-committed
   896		// marker (committed=0), NOT as an operator-committed-empty config —
   897		// otherwise a subsequent restart would classify committed-empty =>
   898		// normal (Item 2 case 5) and take over interfaces on an empty config.
   899		// everCommitted is cleared so the in-memory predicate also reads
   900		// never-committed without a restart.
   901		var perr error
   902		if firstCommitRollback {
   903			// Record the never-committed marker for BOTH the immediate write
   904			// and the degraded-retry loop, so a failed-then-healed write still
   905			// persists committed=0 (Codex r1 release-blocker).
   906			s.persistMarkerCommitted = false
   907			s.everCommitted = false
   908			perr = s.writeActiveMarker(s.active, false)
   909		} else {
   910			s.persistMarkerCommitted = true
   911			perr = s.writeActive(s.active)
   912		}
   913		// #5473: model confirm.json removal as a DURABLE transition. The record is
   914		// the crash-recovery intent that re-drives this rollback to the target
   915		// (confirmPrevTree). It may be removed ONLY once that target is durable on
   916		// disk — i.e. only when the writeActive above SUCCEEDED.
   917		if perr != nil {
   918			// The rollback to the target is NOT durable (disk still holds the
   919			// pre-rollback config). Removing confirm.json here would delete the only
   920			// record that would re-drive the rollback on the next boot: a crash

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/config/compiler_validate_vrf_overlap.go | sed -n '185,230p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   185		comparisons := 0
   186		truncated := false
   187	Scan:
   188		for i := 0; i < len(riNames); i++ {
   189			for j := i + 1; j < len(riNames); j++ {
   190				riA, riB := riNames[i], riNames[j]
   191				for _, a := range riPrefixes[riA] {
   192					for _, b := range riPrefixes[riB] {
   193						if comparisons >= vrfOverlapMaxComparisons {
   194							truncated = true
   195							break Scan
   196						}
   197						comparisons++
   198						// Family-separated: an IPv4 and an IPv6 prefix never overlap,
   199						// so skip the pair cheaply before the Overlaps() call.
   200						if a.prefix.Addr().Is4() != b.prefix.Addr().Is4() {
   201							continue
   202						}
   203						if !a.prefix.Overlaps(b.prefix) {
   204							continue
   205						}
   206						if len(warnings) >= vrfOverlapMaxWarnings {
   207							truncated = true
   208							break Scan
   209						}
   210						if a.prefix == b.prefix {
   211							warnings = append(warnings, fmt.Sprintf(
   212								"routing-instance %q (%s) and %q (%s) both carry %s: "+
   213									"overlapping L3 across routing-instances is forwarded via "+
   214									"PBR but is NOT session-isolated (#2387) — colliding "+
   215									"5-tuples may cross-forward until the session identity is "+
   216									"VRF-aware",
   217								riA, a.origin, riB, b.origin, a.prefix))
   218						} else {
   219							warnings = append(warnings, fmt.Sprintf(
   220								"routing-instance %q (%s, %s) and %q (%s, %s) carry "+
   221									"overlapping L3: overlapping L3 across routing-instances is "+
   222									"forwarded via PBR but is NOT session-isolated (#2387) — "+
   223									"colliding 5-tuples may cross-forward until the session "+
   224									"identity is VRF-aware",
   225								riA, a.origin, a.prefix, riB, b.origin, b.prefix))
   226						}
   227					}
   228				}
   229			}
   230		}

[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/cluster/heartbeat.go | sed -n '300,312p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/2387res
[32m succeeded in 0ms:[0m
   300		if data[4] != heartbeatVersion {
   301			return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
   302		}
   303	
   304		pkt := &HeartbeatPacket{
   305			NodeID:            data[5],
   306			ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
   307			HAProtocolVersion: LegacyHAProtocolVersion,
   308		}
   309	
   310		numGroups := int(data[8])
   311		need := heartbeatHeaderSize + numGroups*heartbeatGroupSize
   312		if len(data) < need {

[35m[3mcodex[0m[0m
v6-r3 fails hostile review. I pinned the review to `8b2ce31f`; the checkout advanced to a docs-only v6-r4 during review, while all cited production sources remained unchanged from `e80db2eae`.

### C1 — CONFIRMED, with a caveat

Current senders populate the version at `pkg/cluster/heartbeat_manager.go:266-270`, reserve trailer space at `pkg/cluster/heartbeat.go:239-263`, and encode it at `:279-287`. Unkeyed senders still call `MarshalHeartbeat` at `:809-819`; by contrast, `performSyncHandshake` returns immediately without a key at `pkg/cluster/sync_auth.go:329-334`.

Decoding occurs at `pkg/cluster/heartbeat.go:361-374`. Legacy packets may omit the trailer and default to protocol 1 at `:304-307`, so “every packet” means every current-generated heartbeat. On an unkeyed cluster the signal exists but is unauthenticated.

### C2 — CONFIRMED

`parseHAProtocolCompatible` fails when either version is absent and returns exactly `local == peer` at `pkg/upgrade/cluster_cli.go:247-274`. An N→N+1 bump therefore fails this particular rolling-upgrade predicate.

### C3 — REFUTED

`MinCompatHAProtocolVersion` has multiple production consumers:

- `xpfd protocol-versions` exports it at `cmd/xpfd/main.go:183-195`.
- Upgrade parsing requires it at `pkg/upgrade/imageversions.go:70-73,110-117`.
- `GateMixedBaseSwap` enforces its compatibility window at `pkg/upgrade/imageversions.go:153-160`.
- Deployment tooling mirrors that gate at `scripts/deploy/xpf-deploy.py:2121-2144`.

There is a second fatal omission: `SessionSyncWireVersion` currently tracks `CurrentHAProtocolVersion` at `pkg/cluster/sync.go:21-36`, while mixed-base deployment requires session-sync exact equality at `pkg/upgrade/imageversions.go:162-173`. Bumping `CurrentHAProtocolVersion` to 2 therefore still makes v1/v2 non-rolling unless those counters are explicitly decoupled.

### C4 — REFUTED

The heartbeat gate is not sufficient:

1. v1-imported/domainless sessions survive sync disconnect (`pkg/daemon/daemon_ha_sync.go:109-118`).
2. Heartbeat and session-sync start independently (`pkg/daemon/daemon_ha_sync.go:767-792`).
3. The first v2 heartbeat immediately overwrites the peer version (`pkg/cluster/heartbeat_manager.go:314-325`).
4. Authoritative session replacement finishes only at `BulkEnd` (`pkg/cluster/sync_conn_read.go:205-247`).

Thus enforcement can turn on while retained v1 sessions still carry domain 0. Default-VRF traffic can cross-match those rows until the v2 bulk completes—or indefinitely if it fails.

The reverse race also exists: `StopHeartbeat` leaves the cached version intact (`pkg/cluster/heartbeat_manager.go:148-163`), while a restarted sender emits nothing until its first ticker (`pkg/cluster/heartbeat.go:789-805`). A downgraded v1 peer can therefore import domainless sessions while the receiver still believes it is v2. Heartbeat timeout then clears the version and immediately enters single-node election (`pkg/cluster/heartbeat_manager.go:425-447`), so a global gate would disable isolation precisely during takeover.

The v6-r3 test at `plan.md@8b2ce31f:702-706` is internally impossible: “5-tuple-only, byte-identical to today” cannot also require a same-5-tuple default-domain packet not to match a legacy row.

### C5 — REFUTED

Config-carried allocation is not guaranteed as claimed:

- Config synchronization is optional (`pkg/config/types_chassis.go:113`) and sending returns early when disabled (`pkg/daemon/daemon_ha_sync.go:360-370`).
- Session sync is nevertheless started independently at `pkg/daemon/daemon_ha_sync.go:775-786,851-863`.
- When enabled, only formatted active configuration text is sent. A table added merely to compiled `Config` would not be persisted or synchronized.

Rollback also contradicts “never reissue.” `rollback N` restores a historical `ConfigTree` at `pkg/configstore/store_commit.go:997-1004`; committing promotes that exact tree at `:213-225`. Rolling back before an allocation erases its high-water mark and tombstone unless a separate non-rollbackable ledger or merge-forward rule exists.

The collision objection is fair only for an unchecked hash and is overstated as a categorical rejection. The repository already hashes RI names with FNV-1a (`pkg/config/routinginstanceid.go:26-55`), rejects simultaneous collisions on strict commit (`:119-181`), and quarantines them on tolerant load/config-sync (`:182-190`; `pkg/config/compiler_routing.go:485-514`). That existing mechanism must be evaluated before inventing a stateful allocator.

### C6 — REFUTED overall

The decapsulation absence subclaim is confirmed:

- VXLAN has no implementation; its only `userspace-dp/src` occurrence is an invalid-mode test vector at `userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1259`.
- Tunnel kinds are only GRE, WireGuard, and Unknown at `userspace-dp/src/afxdp/forwarding_build/tunnels.rs:143-168`; only GRE enters the decap index at `:121-134`, and the AF_XDP decap stage is native GRE at `userspace-dp/src/afxdp/poll_stages.rs:297-332`.
- `PROTO_IPIP` has matching/definition uses outside `policy.rs`, so that narrower wording is false, but there is no IP-in-IP decap path.

The inventory is incomplete. It misses local-origin GRE traffic read from the tunnel TUN (`userspace-dp/src/afxdp/tunnel.rs:344-381`), which creates forward and reverse session entries at `:595-654` and publishes them at `:723-777`.

Its native-ingress row is also technically wrong for VLAN trunks: routing-instance maps are keyed by logical-unit ifindex, not the raw physical ingress ifindex. The required physical+VLAN→logical resolution and subsequent RI lookup are documented at `userspace-dp/src/afxdp/poll_descriptor/prerouting_scope.rs:32-59,73-85`.

### Terminal assessment

v6-r3 is not safely implementable as written: C3/C4 invalidate its rolling-upgrade core, C5 invalidates its allocation invariant, and C6 misses a real producer while prescribing the wrong VLAN identity. These require architecture changes, not wording fixes. Given the niche trigger and existing explicit warning, the replacement must be re-costed against a hard commit rejection or abandoning the feature work.

1. Replace the global heartbeat gate with sync-incarnation/per-entry provenance and an atomic authoritative-bulk transition; explicitly choose fail-open continuity or fail-closed session loss for legacy rows.
2. Incorporate the existing compatibility-floor consumers, decouple `SessionSyncWireVersion` if appropriate, and preserve identical Go/Python bounded-window semantics.
3. Specify a rollback-safe allocator ledger or reuse the existing deterministic-ID plus collision-reject/quarantine pattern; prove delete/session-flush behavior.
4. Add local-origin GRE and logical VLAN-unit ingress to the producer design and tests.

VERDICT: PLAN-NEEDS-MAJOR-REVISION
[2mtokens used[0m
231,945
v6-r3 fails hostile review. I pinned the review to `8b2ce31f`; the checkout advanced to a docs-only v6-r4 during review, while all cited production sources remained unchanged from `e80db2eae`.

### C1 — CONFIRMED, with a caveat

Current senders populate the version at `pkg/cluster/heartbeat_manager.go:266-270`, reserve trailer space at `pkg/cluster/heartbeat.go:239-263`, and encode it at `:279-287`. Unkeyed senders still call `MarshalHeartbeat` at `:809-819`; by contrast, `performSyncHandshake` returns immediately without a key at `pkg/cluster/sync_auth.go:329-334`.

Decoding occurs at `pkg/cluster/heartbeat.go:361-374`. Legacy packets may omit the trailer and default to protocol 1 at `:304-307`, so “every packet” means every current-generated heartbeat. On an unkeyed cluster the signal exists but is unauthenticated.

### C2 — CONFIRMED

`parseHAProtocolCompatible` fails when either version is absent and returns exactly `local == peer` at `pkg/upgrade/cluster_cli.go:247-274`. An N→N+1 bump therefore fails this particular rolling-upgrade predicate.

### C3 — REFUTED

`MinCompatHAProtocolVersion` has multiple production consumers:

- `xpfd protocol-versions` exports it at `cmd/xpfd/main.go:183-195`.
- Upgrade parsing requires it at `pkg/upgrade/imageversions.go:70-73,110-117`.
- `GateMixedBaseSwap` enforces its compatibility window at `pkg/upgrade/imageversions.go:153-160`.
- Deployment tooling mirrors that gate at `scripts/deploy/xpf-deploy.py:2121-2144`.

There is a second fatal omission: `SessionSyncWireVersion` currently tracks `CurrentHAProtocolVersion` at `pkg/cluster/sync.go:21-36`, while mixed-base deployment requires session-sync exact equality at `pkg/upgrade/imageversions.go:162-173`. Bumping `CurrentHAProtocolVersion` to 2 therefore still makes v1/v2 non-rolling unless those counters are explicitly decoupled.

### C4 — REFUTED

The heartbeat gate is not sufficient:

1. v1-imported/domainless sessions survive sync disconnect (`pkg/daemon/daemon_ha_sync.go:109-118`).
2. Heartbeat and session-sync start independently (`pkg/daemon/daemon_ha_sync.go:767-792`).
3. The first v2 heartbeat immediately overwrites the peer version (`pkg/cluster/heartbeat_manager.go:314-325`).
4. Authoritative session replacement finishes only at `BulkEnd` (`pkg/cluster/sync_conn_read.go:205-247`).

Thus enforcement can turn on while retained v1 sessions still carry domain 0. Default-VRF traffic can cross-match those rows until the v2 bulk completes—or indefinitely if it fails.

The reverse race also exists: `StopHeartbeat` leaves the cached version intact (`pkg/cluster/heartbeat_manager.go:148-163`), while a restarted sender emits nothing until its first ticker (`pkg/cluster/heartbeat.go:789-805`). A downgraded v1 peer can therefore import domainless sessions while the receiver still believes it is v2. Heartbeat timeout then clears the version and immediately enters single-node election (`pkg/cluster/heartbeat_manager.go:425-447`), so a global gate would disable isolation precisely during takeover.

The v6-r3 test at `plan.md@8b2ce31f:702-706` is internally impossible: “5-tuple-only, byte-identical to today” cannot also require a same-5-tuple default-domain packet not to match a legacy row.

### C5 — REFUTED

Config-carried allocation is not guaranteed as claimed:

- Config synchronization is optional (`pkg/config/types_chassis.go:113`) and sending returns early when disabled (`pkg/daemon/daemon_ha_sync.go:360-370`).
- Session sync is nevertheless started independently at `pkg/daemon/daemon_ha_sync.go:775-786,851-863`.
- When enabled, only formatted active configuration text is sent. A table added merely to compiled `Config` would not be persisted or synchronized.

Rollback also contradicts “never reissue.” `rollback N` restores a historical `ConfigTree` at `pkg/configstore/store_commit.go:997-1004`; committing promotes that exact tree at `:213-225`. Rolling back before an allocation erases its high-water mark and tombstone unless a separate non-rollbackable ledger or merge-forward rule exists.

The collision objection is fair only for an unchecked hash and is overstated as a categorical rejection. The repository already hashes RI names with FNV-1a (`pkg/config/routinginstanceid.go:26-55`), rejects simultaneous collisions on strict commit (`:119-181`), and quarantines them on tolerant load/config-sync (`:182-190`; `pkg/config/compiler_routing.go:485-514`). That existing mechanism must be evaluated before inventing a stateful allocator.

### C6 — REFUTED overall

The decapsulation absence subclaim is confirmed:

- VXLAN has no implementation; its only `userspace-dp/src` occurrence is an invalid-mode test vector at `userspace-dp/src/afxdp/tests_gre_local_delivery.rs:1259`.
- Tunnel kinds are only GRE, WireGuard, and Unknown at `userspace-dp/src/afxdp/forwarding_build/tunnels.rs:143-168`; only GRE enters the decap index at `:121-134`, and the AF_XDP decap stage is native GRE at `userspace-dp/src/afxdp/poll_stages.rs:297-332`.
- `PROTO_IPIP` has matching/definition uses outside `policy.rs`, so that narrower wording is false, but there is no IP-in-IP decap path.

The inventory is incomplete. It misses local-origin GRE traffic read from the tunnel TUN (`userspace-dp/src/afxdp/tunnel.rs:344-381`), which creates forward and reverse session entries at `:595-654` and publishes them at `:723-777`.

Its native-ingress row is also technically wrong for VLAN trunks: routing-instance maps are keyed by logical-unit ifindex, not the raw physical ingress ifindex. The required physical+VLAN→logical resolution and subsequent RI lookup are documented at `userspace-dp/src/afxdp/poll_descriptor/prerouting_scope.rs:32-59,73-85`.

### Terminal assessment

v6-r3 is not safely implementable as written: C3/C4 invalidate its rolling-upgrade core, C5 invalidates its allocation invariant, and C6 misses a real producer while prescribing the wrong VLAN identity. These require architecture changes, not wording fixes. Given the niche trigger and existing explicit warning, the replacement must be re-costed against a hard commit rejection or abandoning the feature work.

1. Replace the global heartbeat gate with sync-incarnation/per-entry provenance and an atomic authoritative-bulk transition; explicitly choose fail-open continuity or fail-closed session loss for legacy rows.
2. Incorporate the existing compatibility-floor consumers, decouple `SessionSyncWireVersion` if appropriate, and preserve identical Go/Python bounded-window semantics.
3. Specify a rollback-safe allocator ledger or reuse the existing deterministic-ID plus collision-reject/quarantine pattern; prove delete/session-flush behavior.
4. Add local-origin GRE and logical VLAN-unit ingress to the producer design and tests.

VERDICT: PLAN-NEEDS-MAJOR-REVISION
