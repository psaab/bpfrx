# #7949 — the consumer enumeration for `snapshot.Interfaces`

**Verified at `origin/master` `8e3ae4665`** (i.e. after #8485 / #7509, which rewrote
`forwarding_build/interfaces.rs` and is directly adjacent — see §4).

This is the deliverable #7949's last comment asks for, and only that:

> the deliverable is not "make the row appear and check nothing broke". It is **the
> enumeration of every production consumer of `snapshot.Interfaces`, with what each
> does when handed a row that has a Zone but no explicit interface stanza**.

**No row is added by this document.** Whether it should exist is decided elsewhere
(#7167 §3), and R1/R2 of #7949 still bind.

---

## 1. The finding that reframes the issue: the hinge is one flag, and it explains the original error

#7949 records its own scoping mistake:

> I checked two consumers (`buildUserspaceIngressIfindexes` and
> `syncInterfaceAttachments`), found both unaffected, and generalised from two
> members to the set.

**The generalisation failed for a specific, checkable reason: those two are on the
same side of a single predicate, and it is the only thing that separates the
consumer set.**

`userspaceSkipsIngressInterface` (`ingress_exclusions.go:389`) →
`userspaceUnbindableNetdev` (`:79`) → `userspaceNetdevExclusionClass`, whose class
list includes `{name: "SecureTunnel", match: matchesSecureTunnelClass}` (`:145`),
and `matchesSecureTunnelClass` is `return iface.SecureTunnel` (`:385-386`).

So **`InterfaceSnapshot.SecureTunnel` is the hinge.** Every consumer either consults
that predicate — in which case a Shape B row with the flag set is skipped and the
consumer is genuinely unaffected — or it does not, in which case the row
participates. The author sampled two members of the filtered class and concluded
about the whole set.

Which value the flag takes is itself not free; see §3.

---

## 2. Level 1 — direct readers of `ConfigSnapshot.Interfaces` (Go)

Census method: `git grep -nE "\b(snap|snapshot|s|out|sn)\.Interfaces\b" origin/master -- pkg/`,
excluding `_test.go` and excluding `Interfaces.Interfaces` (the **config map**, a
different type — a `bind-interface`-only tunnel is absent from it either way, and
conflating the two inflates the set by ~90 irrelevant sites). Positive control:
the pattern must catch `maps_sync.go:1375`, the known `buildUserspaceIngressIfindexes`
read — it does.

**11 direct consumers. #7949's table names 5 of them, and two of those five are wrong.**

Every line number in #7949's table has also drifted — `buildLocalAddressEntries`
1393→1312, `resolveOwnerRGFromZone` 317→350, `buildNATTranslatedLocalAddressExclusions`
1684→1590, `snapshotBindingPlanKey` 1571→1490 — so the table is re-anchored here by
SYMBOL. Only `quarantineCollidingZones` (`zones_quarantine.go:96`) still matches its
original cite.

| # | consumer | file:line | filters via `userspaceSkipsIngressInterface`? | behaviour for a zoned Shape B row |
|---|---|---|---|---|
| 1 | `buildLocalAddressEntries` | `maps_sync.go:1312` | **no** | **participates structurally**; magnitude depends on §2.2 |
| 2 | `buildUserspaceIngressIfindexes` | `maps_sync.go:1375` | yes (`:1376`) | skipped |
| 3 | `snapshotBindingPlanKey` | `maps_sync.go:1490` | **yes (`:1491`)** | skipped — **#7949's table is wrong here** |
| 4 | `buildUserspaceIngressBindingAliases` | `maps_sync.go:1525` | yes (`:1526`) | skipped — not in #7949's table |
| 5 | `buildNATTranslatedLocalAddressExclusions` | `maps_sync.go:1590,1603` | **no** | NAT exclusions gain the addresses — **participates** |
| 6 | `resolveOwnerRGFromZone` | `manager_sessionsync_request.go:350` | **no**, but gated `RedundancyGroup > 0` | **does not participate** — see §2.1. **#7949's table is wrong here** |
| 7 | `findUserspaceEgressInterfaceSnapshot` | `manager_sessionsync_request.go:363,369,374` | **no** | matches on `Ifindex`/`ParentIfindex` — **participates** if the ifindex matches. Not in #7949's table |
| 8 | `snapshotNetdevVotes` | `ingress_exclusions.go:683,685` | records `unbindable` per row (`:697`) | contributes a vote carrying its exclusion state. Not in #7949's table |
| 9 | `UserspaceBoundLinuxInterfaces` | `interfaces.go:188` | yes (`:189`) | skipped. **NAME-keyed allowlist** — see §3.2. Not in #7949's table |
| 10 | `interfaceSNATEgressCandidatesFromSnapshot` | `nat_iface_pool_overlap.go:89,95` | **no** | **participates structurally**; keys on `iface.Addresses`, so §2.2 applies identically. Not in #7949's table |
| 11 | `quarantineCollidingZones` | `zones_quarantine.go:96` | **no** | **participates, and MUTATES** — `snap.Interfaces[i].Zone = ""` (`:98`). The only in-place writer |

### 2.2 `buildLocalAddressEntries` participates, but its effect may be empty — and that is measurable, not assumed

The loop (`:1312-1330`) has no per-interface exclusion: it walks every row and every
`iface.Addresses`, filtering only on CIDR parse failure, the NAT-exclusion set and
dedup. So a Shape B row is definitely admitted.

Whether it *yields* anything is a separate question this enumeration does not
settle. `Addresses` is populated from `buildLinkSnapshot(linuxName)`
(`interfaces.go:347`) — the **live kernel netdev**, not the config. A Shape B tunnel
by definition has no `set interfaces st0 unit 0 family inet address …` stanza, so it
has no AUTHORED address; the row would carry only whatever the kernel put on the
xfrmi.

This is worth stating precisely rather than asserting "the tunnel's addresses become
local-delivery entries", because the two claims differ: the consumer is unfiltered
(certain, read at the line), while the payload is empty-or-not depending on the live
device (unmeasured). #6955's `TestBareBindInterfaceGetsItsAuthoredAddress_6955` is
NOT evidence either way here — its fixture configures interface `st0` **with a unit**,
i.e. an interface stanza, which is Shape A.

**Owed measurement:** `ip -4 -6 addr show <xfrmi>` on a box running a
`bind-interface`-only route-based tunnel. One command, and it converts this row from
"participates structurally" to a magnitude.

The same caveat and the same one command settle consumer **10**
(`interfaceSNATEgressCandidatesFromSnapshot`), which also keys on `iface.Addresses`
(`nat_iface_pool_overlap.go:103`). Consumers 1 and 10 are the address-keyed pair;
consumers 7 and 11 key on ifindex and zone respectively and do not depend on this.

Note also that this function sorts its rows explicitly —
`sort.SliceStable(ifaces, ... Name < Name)` (`:95-96`) — which is a second, independent
place the codebase makes this iteration deterministic, alongside the `sort.Strings`
in the builder. The "unordered iteration" premise in §2.1 is contradicted at both
ends.

### 2.1 Correction: `resolveOwnerRGFromZone` is not a consumer for this shape

#7949 lists it as able to "change HA owner-RG resolution for that zone", and a later
comment escalates that to order-dependent nondeterminism. Both need correcting.

**It gates on `iface.RedundancyGroup > 0`.** A row's RG is
`rg := iface.RedundancyGroup; if rg <= 0 { rg = rethRG[name] }` (`interfaces.go:353-355`).
A `bind-interface`-only tunnel has **no interface stanza**, so it has neither an
authored `redundancy-group` nor a RETH parent — `rg` is 0 and the `> 0` condition
skips the row. It cannot win the first-wins race because it never enters it.

**And the iteration is not unordered.** `buildInterfaceSnapshotsFrom` collects the
config names into a slice and calls `sort.Strings(names)` (`interfaces.go:340-343`)
before building rows, so `snapshot.Interfaces` is deterministically ordered by
config interface name. First-wins over a sorted slice is *arbitrary with respect to
intent* — a name sort decides which RG wins — but it is **not nondeterministic**, and
the proposed acceptance-criteria line about "introducing nondeterminism" would pin a
property the code does not have.

The underlying complaint (this consumer cannot express a preference between two
zoned rows) survives; the mechanism stated for it does not.

---

## 2.3 Level 2 — helper-mediated consumers

These never name `.Interfaces`; they are affected because they call a level-1
function. `syncInterfaceAttachments` is the known example and the reason a
field-name grep is a syntactic proxy rather than the predicate.

| level-1 consumer | reached from |
|---|---|
| `buildLocalAddressEntries` (1) | `buildDesiredLocalAddressSets` (`maps_sync.go:987`) |
| `buildNATTranslatedLocalAddressExclusions` (5) | `buildLocalAddressEntries` (`:1308`) **and** `buildInterfaceNATAddressEntries` (`:1347`) |
| `findUserspaceEgressInterfaceSnapshot` (7) | `sessionSyncEgressLocked` (`manager_sessionsync_request.go:329`) |
| `interfaceSNATEgressCandidatesFromSnapshot` (10) | `detectInterfaceSNATPoolOverlaps` (`nat_iface_pool_overlap.go:183`) |
| `quarantineCollidingZones` (11) | `buildSnapshotWithSchedulerStateAndNATCounters` (`builder.go:161`) — i.e. snapshot construction itself |
| `buildUserspaceIngressIfindexes` (2) | `syncInterfaceAttachments` (`manager_compile.go:841`) — the issue's own second sample |

`buildInterfaceNATAddressEntries` is worth naming explicitly because it is the one
that looks like a level-1 consumer and is not: it reads the exclusion SETS returned
by (5), never the rows (`:1347-1365`). Checked directly rather than assumed from the
call.

Consumer 11's caller is the snapshot BUILDER, which means the zone-blanking mutation
happens during construction, before any of the other consumers see the slice —
relevant ordering if a Shape B row's zone ever collides.

## 3. The flag is not free: what decides `SecureTunnel` on a Shape B row

`snapshotSecureTunnel` (`interfaces.go:837`) is the union of a CONFIG oracle
(`secureTunnelOwned` → `cfg.SecureTunnelNetdevForRef`, `:700-704`) and a KERNEL one
(`liveXfrmNetdevs`). Two documented cases return **false**, and they behave
differently:

**3.1 The if_id collision.** `SecureTunnelNetdevForRef` returns false when two
distinct `bind-interface` strings derive one if_id, because routing then creates
NEITHER device (`interfaces.go:665-672`). The in-tree argument for why that is safe
is explicit: *"its ifindex stays 0 and every ifindex-keyed set skips it anyway."*
That argument holds only for **ifindex-keyed** consumers.

**3.2 The base row under the canonical spelling.** Also documented, at
`interfaces.go:694-698`: under `bind-interface st0.0` the BASE row `st0` reports
false, *"and being zoned it contributes its name to the name-keyed AF_XDP/RSS
allowlist even though no `st0` netdev exists"*. So the ifindex-0 argument does **not**
cover consumer 9, which is name-keyed by design.

**3.3 The row would not be caught by the sibling `Tunnel` class either.**
`netdevExclusionClasses` has TWO tunnel entries: `{name: "Tunnel", match: iface.Tunnel}`
(`ingress_exclusions.go:132`) and `{name: "SecureTunnel", ...}` (`:145`). A row's
`Tunnel` flag is `iface.Tunnel != nil || unit.Tunnel != nil` (`interfaces.go:371,446`)
— derived from the **interface stanza**, which a Shape B row by definition does not
have. So a synthesized Shape B row carries `Tunnel = false`, and `SecureTunnel` is
the ONLY class that can exclude it.

That makes §3.1 sharper than "the flag is false": in the if_id-collision case the row
escapes **both** exclusion classes and is held out of the ifindex-keyed consumers only
by the incidental fact that its ifindex is 0. Consumer 9 is name-keyed and admits it
regardless. The safety margin there is one accident wide, and it is not the flag.

**Consequence for the enumeration:** the per-consumer answer is not one column but
two — behaviour under `SecureTunnel = true` (the canonical case) and under
`SecureTunnel = false, Ifindex = 0`. A table with one column would report the
canonical case and miss the collision case, which is the same shape of error the
issue is trying to avoid.

---

## 4. The Rust half, which #7949 omits entirely — 12 consumers, and 3 are NOT no-ops

A snapshot row crosses the control socket into the helper
(`userspace-dp/src/protocol/snapshot.rs:39`, collection at `:443`). #7949's table is
Go-only. Census: 12 production consumers. Positive control: the `secure_tunnel`
production sweep returns exactly the two known gates (`planning.rs:422`,
`forwarding_build/interfaces.rs:262`), and both enclosing loops appear in the
`.interfaces` sweep, so both patterns reached the code.

**Five are ifindex-keyed** (`forwarding_build/interfaces.rs:121,221`, `:785`,
`cos.rs:1304`, `filter/compiler.rs:213`) and each opens with
`if iface.ifindex <= 0 { continue }`. For those, the Go comment's claim at
`interfaces.go:665-671` — *"its ifindex stays 0 and every ifindex-keyed set skips it
anyway"* — **holds exactly**. Two of them (`InterfaceUnknownZone`,
`MissingFilterRef`) fail the snapshot closed, and neither runs for such a row.

**But "every ifindex-keyed set" is not "every set". Seven of the twelve are not
ifindex-keyed**, and three of those are not no-ops for a zoned,
`secure_tunnel: false`, `ifindex == 0` row. All three are in `planning.rs` and route
through `include_userspace_binding_interface` (`:425`), which **never looks at
ifindex** — for this shape it returns `true`:

1. **`update_snapshot_binding_plan_key` (`:143`)** — the row is hashed into the plan
   key, so `same_binding_plan` returns false and the full binding-reconcile path runs
   on a commit that changes no binding. **This rescues #7949's plan-key claim**: §2
   correctly reports that the *Go* `snapshotBindingPlanKey` filters, so the mechanism
   the issue described does not fire there — but the Rust plan key is a second,
   unfiltered implementation of the same idea, and the churn the issue predicted is
   real in that plane. The issue mis-located a real consequence rather than inventing
   one, which is a different kind of error from the two in §2 and should be recorded
   as such.
2. **`snapshot_has_parent_candidate` (`:479`)** — the row votes that its netdev is a
   binding candidate, and `replan_queues:706-710` then **drops any zoned VLAN sibling**
   whose `parent_linux_name` is that name, while the parent contributes no candidate
   of its own (`rx_queues == 0`). Reachable shape: `bind-interface st10` plus
   `st10 unit 5 vlan-id 100` — the one #6691 round 8 already names in this file.
3. **`snapshot_refuses_parent_netdev` (`:561`)** — the unanimity tally has no
   `include_...` filter, so every row is an owner. A `secure_tunnel: false` row is an
   owner voting BINDABLE, which un-refuses the netdev (the exact inverse of the flag
   being true) and, by making `owners > 0`, suppresses the `FabricSnapshot.parent_unbindable`
   fallback voter added for the ownerless case.

**And this is the ordinary configuration, not an exotic one.** §3.2 already records
that under the canonical `bind-interface st0.0` the BASE row `st0` reports
`secure_tunnel: false`, is zoned by the fan-up, and has no netdev. That IS case (c).
The Go comment scopes its ifindex-0 reassurance to the rare if_id collision; its own
round-7 paragraph concedes the same row shape arises canonically. So findings 1-3
apply to the normal case, not an edge.

**Three further consumers are no-ops by VALUE, not by guard.** `slow_path_mtu`
(`snapshot.rs:620`, gated `mtu > 0`), `status.rs:48` (`addresses.len()`), and
`nat_translated_local_exclusions` (`rst.rs:29`, whose ONLY gate is `iface.zone`, so a
zoned row always enters the body) contribute nothing solely because
`buildLinkSnapshot` returns `ifindex=0, mtu=0, addresses=nil` together for an absent
netdev. Likewise `replan_queues` (`:666`) admits the row and is saved only by
`effective_rx_queues` re-reading `/sys/class/net/st0/queues` and getting 0. That
coupling is real but it is two independent lookups agreeing, not an invariant the
code states — and if a candidate ever WERE pushed with ifindex 0,
`planning.rs:1012-1017` leaves it `registered = armed = false` and
`status.rs:394-401` computes `status.enabled` as `.all(|b| b.registered && b.armed)`,
turning `enabled` false for the whole box.

## 5. What this enumeration concludes

1. The direct Go consumer set is **11**, not 5. Six were unlisted.
2. Two of #7949's five listed consumers are **wrong**: `snapshotBindingPlanKey`
   filters, and `resolveOwnerRGFromZone` cannot match a stanza-less row.
3. The genuinely-participating Go consumers are **1, 5, 7, 10, 11** — local address
   entries, NAT exclusions, egress-row lookup, interface-SNAT egress candidates, and
   zone quarantine (which also mutates).
4. The set splits on exactly one predicate, so the enumeration is **stable and
   checkable** rather than a list to re-derive: any future consumer either calls
   `userspaceSkipsIngressInterface` or does not.
5. The Rust side has **twelve** consumers, of which **three are not no-ops** for the
   canonical Shape B row — and they are name-keyed, so the ifindex-0 reassurance the
   Go comment offers does not reach them. Two more fail the snapshot closed, and
   `egress_zone_claim` (#8485, merged today) constrains *how* any future row must be
   built: it merges per ifindex and fails closed on disagreement.
6. The issue's three errors are of **two different kinds**, and the distinction is
   worth keeping. `resolveOwnerRGFromZone` and the nondeterminism escalation are
   simply false. The plan-key churn is **real but mis-located** — filtered in the Go
   implementation, unfiltered in the Rust one.

None of this decides whether the row should exist. It replaces "I checked two" with
a set that can be argued about.
