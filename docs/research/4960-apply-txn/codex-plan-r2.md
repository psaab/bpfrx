# Hostile adversarial plan review — round 2

This reviews v2 of `docs/research/4960-apply-txn/plan.md` on branch
`research/4960-apply-txn` at commit `9a60f235fd9e`, against the round-1 findings in
`docs/research/4960-apply-txn/codex-plan-r1.md` and the actual Go/Rust/XDP source at
that commit. The fence-first staged-commit direction is materially better than v1,
but v2 is not implementation-ready: its recommended hitless exception violates its
own invariant, and the daemon-wide fence, asynchronous debt, publication proof, and
HA/liveness ownership remain designs-to-be-written rather than a closed state
machine.

## 1. Does the fence-first model close the packet-observable mismatch?

**Sub-verdict: NOT YET. The ctrl map is a viable gate for packets that enter an
already-attached shim after a verified disable, but v2 does not establish a durable,
serialized fence and does not close pre-read/in-flight or local-pass gaps.**

### Evidence

The basic mechanism is sound in a narrower sense than v2 claims. The plan requires
`userspace_ctrl.enabled=0` before the first packet-observable mutation and retention
through every failed, ambiguous, or unproven result
(`docs/research/4960-apply-txn/plan.md:131-141,146-180`). An XDP invocation directly
reads `USERSPACE_CTRL[0]` at entry and immediately enters the degraded path when
`enabled==0`; no Rust control-socket round trip or one-second status propagation is
needed for a later-entering packet (`userspace-xdp/src/lib.rs:397-409`). That degraded
path drops transit while passing selected local/control traffic
(`userspace-xdp/src/lib.rs:992-1012`). Thus there is no inherent control-socket
propagation delay for a packet whose XDP invocation actually observes the disabled
row.

The plan does not, however, define how the gate is *established*. P0/FENCE says only
“write userspace_ctrl.enabled=0” (`plan.md:150-157`). Existing code already shows the
minimum safe primitive: `disableUserspaceCtrl` preserves the row, writes `Enabled=0`,
checks the update error, reads the row back, and verifies zero
(`pkg/dataplane/userspace/process_linkcycle.go:50-82`). Its teardown wrapper clears
all binding rows if disable cannot be verified (`process_linkcycle.go:87-99`). V2 has
no update-failure/readback-failure outcome, no rule prohibiting P1 after an
unverified write, and no corresponding failure-injection test in §9
(`plan.md:371-400`). A blind or partially failed fence write therefore remains a
pre-P1 race in the proposed design.

More seriously, a one-time map write is not durable ownership. The status loop takes
`m.mu` once per second, obtains helper status, and calls `applyHelperStatusLocked`
*before* attempting a deferred snapshot publish
(`pkg/dataplane/userspace/process_status.go:134-165`). That function derives
`ctrl.Enabled` from helper/readiness state without an apply-fence predicate
(`pkg/dataplane/userspace/maps_sync.go:337-381,418-538`) and writes `Enabled=1` at the
end (`maps_sync.go:793-798`). `Status`, forwarding/queue/binding setters, session
drains, HA updates, and link-cycle rebinds are additional callers of the same writer
(`pkg/dataplane/userspace/manager_status.go:31-52,78-157,180-230`;
`pkg/dataplane/userspace/manager_ha.go:26-66,631-718`;
`pkg/dataplane/userspace/process_linkcycle.go:184-224`). A daemon `BeginFence` that
returns and releases `m.mu` can therefore be undone before or during daemon-owned P1.
The plan itself concedes that the lock/liveness design is unresolved
(`plan.md:318-321,339-346`) while simultaneously depending on a daemon-level fence
(`plan.md:239-244`).

The race is broader than the enabled bit. Every successful
`applyHelperStatusLocked` pass rewrites binding aliases and the ingress, local, and
interface-NAT maps from `m.lastSnapshot`
(`pkg/dataplane/userspace/maps_sync.go:729-786`). V2 delays advancement of
`lastSnapshot`/published identity until P6 (`plan.md:172-175`). If a status call runs
between P3 and P4/P5, it can therefore rewrite P3 candidate maps toward the old
snapshot even if a new fence latch clamps `Enabled` to zero. The design needs one
transaction view and one serialization rule for *all* ctrl/classifier writers, not
just a debt checked by `syncSnapshotLocked`.

Nor is update-plus-readback a packet-drain barrier. One XDP invocation can read
`enabled=1` at entry and reach metadata construction/XSK redirect later
(`userspace-xdp/src/lib.rs:405-409,670-724`), and Rust workers can still consume
already queued RX batches (`userspace-dp/src/afxdp/worker/lifecycle.rs:91-125,209-225`).
The existing destructive link-cycle path explicitly
disables ctrl and then sends `stop_workers`, whose contract is to join all workers
before link mutation (`pkg/dataplane/userspace/process_linkcycle.go:136-164`). V2 P1
includes link/admin/MTU/address operations but specifies neither worker drain nor a
grace/epoch argument (`plan.md:158-162`). The source does not provide enough evidence
to prove that a readback has drained every enabled XDP invocation or queued XSK
packet; this is an open verification gap, not something the plan may assume away.

Finally, ctrl only governs an interface on which the shim is attached. V2 correctly
says new links must stay down or receive the disabled shim before going up
(`plan.md:158-162`), but daemon-owned fabric IPVLAN creation currently raises the
parent, adds addresses, and raises the child before Manager compilation
(`pkg/daemon/daemon_ha_fabric.go:19-96`; call ordering at
`pkg/daemon/daemon_apply.go:916-959`). The current daemon/dataplane interface has no
staged-attachment callback to enforce that partial order (`pkg/dataplane/apply.go:18-40,130-143`).

### Residual gap / required closure

V2 must specify a persistent transaction fence with at least
`establishing/active/uncertain/releasing` states, require update plus readback before
P1, and make every ctrl/classifier writer honor that state. It must choose and prove
a serialization model for status/HA/link-cycle calls, define the disposition of
already-enabled XDP/XSK work, and bring every daemon link creator into the
down-or-shim-first staging protocol. Until then §12 overclaims that r1 OQ-1 and
findings 1.1/1.2 are addressed (`plan.md:475-478`).

## 2. Is P2 post-actuation snapshot construction correct for live VLAN ifindexes?

**Sub-verdict: THE ORDERING DEFECT IS FIXED, BUT THE MATERIALIZATION PROOF IS NOT.
Finding 6.1 is only partially closed.**

### Evidence

The v2 order is the right order: P1 actuates host links and attachments, then P2
builds the final wire snapshot from post-actuation state
(`docs/research/4960-apply-txn/plan.md:158-166,289-299`). That matches the real
dependency. `compileZones` creates a VLAN child and obtains its live child ifindex
(`pkg/dataplane/compiler_iface.go:338-363`); `buildInterfaceSnapshots` later resolves
the live child and parent and stamps child/parent ifindexes, MTU, MAC, RX queues, and
addresses (`pkg/dataplane/userspace/interfaces.go:239-282`); and
`snapshotBindingPlanKey` includes both ifindexes
(`pkg/dataplane/userspace/maps_sync.go:1596-1628`). Current code already happens to
put `CompileUserspaceShim` before snapshot construction
(`pkg/dataplane/userspace/manager_compile.go:185-202`), so abandoning v1's
pre-actuation wire snapshot was correct.

P2 nevertheless does not prove successful live materialization. A VLAN creation
error is WARN-and-skip, not returned (`pkg/dataplane/compiler_iface.go:350-357`).
`buildLinkSnapshot` silently returns zero/empty fields on both interface and netlink
lookup failures (`pkg/dataplane/userspace/interfaces.go:430-449`). The proposed P2
can consequently produce a required, non-logical VLAN with `Ifindex=0` after a P1
failure that was never surfaced. Test 9 checks only successful resolution
(`plan.md:390-391`); it does not test failed creation, wrong parent, or a zero
ifindex.

The snapshot is also not literally “live addresses,” despite P2's wording
(`plan.md:163-166`). Address reconciliation swallows lookup, parse, list, delete, and
add failures (`pkg/dataplane/compiler_iface.go:184-247`), while snapshot construction
unions live addresses with configured addresses
(`pkg/dataplane/userspace/interfaces.go:264,452-513`). Connected routes are then
derived from those snapshot addresses (`pkg/dataplane/userspace/routes.go:191-205`).
A failed `AddrAdd` can therefore still be advertised to Rust as configured/present,
and a failed `AddrDel` can leave stale live state. P5 says only “prove” coherence and
does not define a required-link/address readback predicate (`plan.md:169-170`).

### Residual gap / required closure

P1 must either make required VLAN/link/address failures fatal or P2/P5 must perform
an authoritative post-actuation validator: required child exists, child/parent
ifindexes are nonzero and correctly related, required link identity/MTU is live, and
security-relevant desired/live addresses agree. Negative tests must cover failed
VLAN creation and failed address add/delete. Section 12's grouped statement that
6.1/6.2/6.3 are addressed (`plan.md:485-487`) is therefore too strong.

## 3. Are the five typed outcomes sufficient and distinguishable on NACK?

**Sub-verdict: PARTIALLY FIXED. The safe immediate rule is indeed “every non-Accept
stays fenced,” and v2 mostly states it, but the five entries are neither an
exhaustive outcome partition nor reliably distinguishable from the existing wire
status.**

### Evidence

V2 correctly identifies the present Go loss of information: after marshal/size/dial,
write, and response decode, `requestDetailedLocked` turns `OK:false` into an error
and discards the populated response (`pkg/dataplane/userspace/process_control.go:80-143`);
`requestLocked` can only copy status on success (`process_control.go:187-195`). Rust
does refresh and attach status after handler execution even for a NACK
(`userspace-dp/src/server/handlers/mod.rs:257-264`). Plan §4.3 is therefore right
that Go must stop discarding NACK status
(`docs/research/4960-apply-txn/plan.md:182-205`).

That status cannot reliably prove the causal pre/post-teardown class. Rust has an
internal `ReconcileError` enum that separates pre-teardown integrity/map setup from
post-teardown worker spawn, but the handler flattens it into free-form English error
strings (`userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:49-68`;
`userspace-dp/src/server/handlers/snapshot.rs:195-223,341-392`). The wire response has
only `ok`, `error`, and `status`, with no request-scoped stage/outcome code
(`userspace-dp/src/protocol/control.rs:881-893`;
`pkg/dataplane/userspace/protocol.go:60-65`). Both the pre-teardown restore and the
post-teardown-down branch restore the previous reported generation
(`snapshot.rs:195-201,356-365`). `status.enabled` is also not worker-liveness proof:
Rust derives it from forwarding armed/supported plus registered/armed bindings, not
from every binding being bound/ready with a live worker
(`userspace-dp/src/server/helpers.rs:245-259`). Parsing an error prefix or inferring a
request stage from a possibly already-degraded binding set would be a brittle
protocol. That contradicts v2's assertion that typed outcomes can be derived with no
wire change (`plan.md:334-337`).

The five labels also mix publication and whole-transaction states and omit necessary
states:

1. R1 required a **definite-not-dispatched** result. Marshal/size/configured-socket
   and dial failures occur before a write (`process_control.go:80-106`), while a
   write/read/decode failure after dispatch must remain ambiguous
   (`process_control.go:119-135`). V2's list at `plan.md:189-202` omits that partition.
2. “Accepted — new snapshot live” is too strong (`plan.md:189`). Rust can ACK and
   persist `defer_workers=true` while explicitly skipping worker spawn
   (`snapshot.rs:272-340`). ACK means accepted; P5 must separately prove live.
3. **ACK accepted but P5 failed/unproven** is absent. Under the invariant at
   `plan.md:169-180`, it must remain fenced and is not an accepted post-commit tail
   error.
4. “Accepted-with-post-commit-error” is not a P4 publication result. Worse, P6
   combines obsolete-hook removal with genuinely retryable HA/status tails
   (`plan.md:172-176,200-202`). A hook-removal failure is not automatically safe to
   classify “do not re-fence”; it is commit-critical attachment coherence.
5. The asynchronous branch needs a **Pending/Fenced, publish-not-yet-attempted**
   result, discussed under question 4. It currently returns ordinary success
   (`pkg/dataplane/userspace/manager_compile.go:257-298`).

The direct safety answer to OQ-D is less ambiguous: outcomes 2–4 each explicitly say
stay fenced, and every P1–P5 failure stays fenced
(`plan.md:179-180,190-199`). V2 does *not* quietly authorize an immediate unfence on
a NACK; even its old-live branch permits that only after maps/host are reconciled and
verified (`plan.md:190-194`). The pre/post distinction may remain diagnostic. The
normative rule must be: every non-ACK, every ACK with failed/unproven P5, and every
commit-critical cleanup failure retains the fence.

### Residual gap / required closure

Either collapse all explicit NACKs into one safety disposition and keep status/error
only as diagnostics, or add a machine-readable request-scoped Rust response enum.
Separate transport/publication results (not dispatched, explicit NACK, ambiguous
after dispatch, ACK) from transaction results (ACK-but-unverified, committed,
committed-with-retryable-tail-debt). OQ-D is still open at `plan.md:442-446`, so §12
cannot call r1 7.1 closed (`plan.md:488`).

## 4. Does the shared-debt proposal cover `pendingXSKStartup` and real status order?

**Sub-verdict: NO. Section 4.7 correctly traces the bug, but “persistent
transaction/debt state” is a placeholder, not a state machine, and its stated
behavior contradicts §4.6 and the daemon disposition.**

### Actual call trace

1. `pendingXSKStartup` means a helper and prior published snapshot exist while XSK
   liveness is neither proven nor failed
   (`pkg/dataplane/userspace/manager_compile.go:228-241`).
2. That branch programs candidate classifier maps (`manager_compile.go:257-265`),
   promotes the candidate into `m.lastSnapshot` and config/apply bookkeeping
   (`manager_compile.go:289-291`), and returns `nil` without calling
   `apply_snapshot` (`manager_compile.go:292-298`).
3. On the next status tick, while holding `m.mu`, the loop requests status and first
   calls `applyHelperStatusLocked` (`pkg/dataplane/userspace/process_status.go:143-160`).
   That method consumes the candidate `m.lastSnapshot`, rewrites aliases and all
   three classifier maps, and may write ctrl enabled
   (`pkg/dataplane/userspace/maps_sync.go:729-797`).
4. Only after that does the loop notice `publishedSnapshot < lastSnapshot.Generation`
   and call `syncSnapshotLocked` (`process_status.go:162-165`). Publication occurs at
   `process_status.go:101-104`; on failure it returns with no fence action. On ACK it
   advances published/applied identity before the fallible status application
   (`process_status.go:105-120`).

Section 4.7 accurately states this order and the missing fence
(`docs/research/4960-apply-txn/plan.md:270-280`). That recognition is useful, but no
transaction record, fields, transitions, or ownership are specified. At minimum the
record must distinguish committed snapshot, staged candidate, publish-not-attempted,
ambiguous-after-dispatch, accepted-but-unverified, committed, and superseded. A
boolean “debt” cannot safely use `m.lastSnapshot` for both old committed map repair
and candidate publication.

The fence predicate must be centralized in every `applyHelperStatusLocked` caller,
not only `statusLoop`/`syncSnapshotLocked`; the independent callers are shown at
`pkg/dataplane/userspace/manager_status.go:31-52,78-157,180-230`,
`manager_ha.go:26-66,631-718`, and `process_linkcycle.go:184-224`. Debt must be
created and a verified fence established *before* line 264's map writes, survive
NACK/timeout, and clear only after Accepted **and P5 verification**. Section 4.7 says
only “until Accepted” (`plan.md:279-280`), weaker than §4.2's verify-before-unfence
rule (`plan.md:169-176`). Superseding applies, helper restart/stop, content-hash
dedup, and the status-based ACK-loss catch-up path at
`process_status.go:19-38,73-81` also need explicit transitions and a guaranteed retry
consumer.

There is a direct external-state contradiction. Section 4.6 says the map-only path
fences only after non-Accept and says this covers the async leg
(`plan.md:259-268`), while §4.7 says the deferred leg stays fenced until acceptance
(`plan.md:274-280`). No publication has occurred when Manager returns success
(`manager_compile.go:289-298`); `Manager.ApplyConfig` propagates that as success
(`pkg/dataplane/userspace/manager.go:318-327`), so the daemon records success and
continues its new-config pipeline (`pkg/daemon/daemon_apply.go:1220-1248`). That is
the opposite of §4.5's “fenced or unknown stops local tail and suppresses peer push”
contract (`plan.md:229-237`).

### Residual gap / required closure

Either remove asynchronous success and block/return a typed fenced-pending result
until the first verified Accepted publication, or fully specify the candidate record,
central ctrl clamp, map view, retry startup, supersession, ACK-loss reconciliation,
promotion, daemon disposition, and release transitions. OQ-F explicitly leaves that
choice open (`plan.md:451-454`), so Section 12's claim that r1 7.2 “gets shared debt”
is not closure (`plan.md:489`).

## 5. Is the §4.6 map-only success window harmless?

**Sub-verdict: NO. The recommended option (ii) is a residual #4959-class mismatch,
is factually not bounded to “a few ms,” and misclassifies address-only changes as
map-only even though the current path mutates host addresses.**

### Evidence

The contradiction is textual and architectural. The absolute invariant says every
mutating apply is inside a fence and no candidate classifier/old-helper generation
may be ctrl-enabled (`docs/research/4960-apply-txn/plan.md:133-141`). The recommended
exception deliberately programs candidate maps, leaves old helper state live, and
fences only after non-Accept (`plan.md:252-268`). A later fence cannot retract a
packet already classified during that window.

The classifier set is not atomically replaced. Go synchronizes ingress, then local,
then interface-NAT (`pkg/dataplane/userspace/maps_sync.go:247-255`), and each map
independently adds candidate entries before pruning stale ones
(`maps_sync.go:945-1057,1124-1187`). XDP's session-miss path independently consults
the local map to pass a packet to the kernel and the interface-NAT map to redirect a
packet to Rust (`userspace-xdp/src/lib.rs:584-644,1363-1421`). Candidate local/NAT
classification can therefore select kernel versus an old helper that enforces the
opposite generation. This is not merely an internal bookkeeping skew.

Nor is it bounded to “a few ms” as claimed at `plan.md:263-265`. An apply request may
legitimately wait under a size-scaled deadline up to 67 seconds at the 64-MiB request
limit (`pkg/dataplane/userspace/process_control.go:33-56,59-77,103-123`). The window
may usually be shorter, but the source disproves the plan's bound.

The “pure classifier-map-only address change” premise is also false for the current
entry point. `Manager.Compile` calls `CompileUserspaceShim`, which runs the complete
`CompileConfig`, before `samePlanRefresh` is computed
(`pkg/dataplane/userspace/manager_compile.go:162-211,228-238`;
`pkg/dataplane/loader.go:169-208`). `compileZones` performs `AddrDel`/`AddrAdd`
reconciliation (`pkg/dataplane/compiler_iface.go:184-247,350-383,572-597`), while
`snapshotBindingPlanKey` excludes addresses, policy, and NAT
(`pkg/dataplane/userspace/maps_sync.go:1596-1628`). An address-only host mutation can
therefore still be `samePlanRefresh`. If option (ii) actually fences every host
mutation, it does not preserve the advertised address-only hitlessness. If it exempts
that path, it violates §4.1/P1.

There is a concrete security-plane residual. Candidate local-address entries cause
XDP to pass packets to the kernel (`userspace-xdp/src/lib.rs:621-632,1363-1377`), and
ctrl-disabled mode deliberately uses the same local classifier to pass local/control
traffic (`userspace-xdp/src/lib.rs:992-1012,1035-1056`). The kernel nft chain is the
*primary* host-inbound enforcement because ordinary firewall-local traffic bypasses
Rust (`pkg/daemon/daemon_nft.go:231-247`), and a retained old nft generation covers
only the destinations represented in that generation (`daemon_nft.go:249-259`). Yet
the daemon applies dataplane/address changes around `daemon_apply.go:1220-1245` and
does not install the new host-inbound nft generation until
`daemon_apply.go:2357-2370`. A newly local address can therefore become kernel
reachable under stale host-inbound authorization; even fence-always does not close
that gap because ctrl=0 intentionally passes local traffic. P3 includes only RST
suppression nft, not host-inbound nft (`plan.md:167,331-333`).

Even a successful same-plan publication is not literally hitless. XDP stamps packets
with the ctrl row's current config/FIB generation
(`userspace-xdp/src/lib.rs:681-710`). Rust's same-plan refresh swaps validation and
forwarding state to the new generation before returning ACK
(`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:278-355`), and its packet
classifier rejects metadata whose generation does not equal that state
(`userspace-dp/src/afxdp/forwarding/mod.rs:30-42`). Go updates ctrl from the returned
status only after `requestLocked` returns
(`pkg/dataplane/userspace/manager_compile.go:332-351`;
`pkg/dataplane/userspace/maps_sync.go:364-372,793-797`). That produces an
old-ctrl/new-helper fail-closed drop interval on success, further undermining the
claimed hitless benefit.

### Residual gap / required closure

The plan must withdraw option (ii) as currently described. The implementable safe
baseline is fence-always for every actual host/map/attachment mutation, unless a
separate design provides generation-banked maps plus dual-generation helper
acceptance. Host-inbound nft/local-pass authorization must be added to the staged
resource order (for example candidate/union protection before address/local-map
visibility and commit-time pruning), or the apply fence must drop non-lifeline local
traffic while staging.

## 6. New or residual gaps from fence ownership, locking, HA, and partial writes

**Sub-verdict: MAJOR DESIGN WORK REMAINS. The daemon/Manager split has no implementable
transaction boundary, and the proposed P7, lock, HA-readiness, attachment, and
fallible-tail rules conflict.**

### 6.1 P0, daemon fence ownership, and P7 cannot all occur in the stated order

The daemon mutates bootstrap naming/links, VRFs, tunnels/xfrmi/bonds, and fabric
IPVLAN before calling `d.dp.ApplyConfig`
(`pkg/daemon/daemon_apply.go:885-959,2227-2296`). Manager P0/Compile is reached only
at `daemon_apply.go:1220-1224`. The plan, however, requires Manager-style P0 before
FENCE (`plan.md:150-157`) and a daemon fence before daemon host reconciliation
(`plan.md:239-244`), while the runtime interface exposes only `ApplyConfig` and
link-cycle methods (`pkg/dataplane/apply.go:18-40,130-143`). There is no
`Validate/BeginFence/ApplyPrepared/CommitFence` protocol. Preserving existing method
signatures does not prohibit adding one, but §5 does not design it
(`plan.md:301-309`). As written, one must either mutate before P0/fence, fence before
P0 and turn deterministic validation errors into outages, or invent an unstated API.

P7 ownership is equally contradictory. The Manager state machine places obsolete
cleanup/identity at P6 and unfence at P7 (`plan.md:172-176`), while §4.5 says the
daemon fence spans daemon-owned work and is lifted after Manager reports a verified
commit (`plan.md:239-244`). Manager returns before networkd, RETH MAC/VIP/rebind,
proxy ARP, and management-VRF rebind
(`pkg/daemon/daemon_apply.go:1220-1248,1281-1520`). The daemon then changes routing
rules and explicitly republishes a route snapshot because the Manager-built snapshot
is stale (`daemon_apply.go:984-1005`), and applies host-inbound nft much later
(`daemon_apply.go:2357-2370`). A Manager P7 is too early; a daemon P7 requires a
later final snapshot/verification boundary that v2 does not define.

### 6.2 Locking either races or creates a liveness problem

Current host compilation and attachment removal occur before `m.mu`, and direct
`Manager.ApplyConfig` has no daemon `applySem`
(`pkg/dataplane/userspace/manager_compile.go:162-214,522-545`;
`pkg/dataplane/userspace/manager.go:318-327`). Releasing `m.mu` across daemon work
allows the status/HA/API writers described in question 1 to re-enable ctrl and
rewrite maps. Holding it across the entire daemon transaction blocks status and HA
control traffic and can already include an apply round trip with a legal 67-second
deadline (`pkg/dataplane/userspace/process_control.go:33-56`). V2 explicitly labels
this an unresolved design (`plan.md:318-321,345`), so §12's claim that 7.7 is
corrected is not a closure (`plan.md:494-495`). A separate apply-transaction mutex,
short `m.mu` critical sections, and persistent fence state checked at every map
writer are the plausible shape, but the plan must actually specify their ordering
and re-entrancy.

### 6.3 HA readiness needs synchronous revocation, not only a predicate edit

The current Manager predicate indeed ignores ctrl and checks helper/mode/liveness/
session/event state only (`pkg/dataplane/userspace/manager_ha.go:391-447`), so v2 is
right to require fenced nodes to be not-ready (`plan.md:246-250`). But
`ctrlWasEnabled` is bookkeeping changed by some writers, not an authoritative
transaction identity (`pkg/dataplane/userspace/manager.go:169-175`;
`pkg/dataplane/userspace/process_linkcycle.go:50-84`). A direct ctrl lookup failure
must fail readiness closed, and a persistent fence state is preferable to either
source alone.

There is a second HA edge: daemon readiness is periodically copied into cached
per-RG `Ready/ReadySince` via `SetRGReady`
(`pkg/daemon/daemon_ha.go:682-703`; `pkg/cluster/readiness.go:8-88`). Election/manual
failover uses that cached state (`pkg/cluster/manager.go:53-70`;
`pkg/cluster/failover.go:204-232`). A node that was ready immediately before fence
establishment remains takeover-eligible until the next readiness reconcile unless
fence begin synchronously revokes all relevant RGs and coordinates with an in-flight
handoff. Test 13 exercises only `takeoverReadyLocked` (`plan.md:397`); it does not
cover this cache window.

### 6.4 P6 mixes commit-critical attachments with retryable tail work

P5 claims host, attachments, maps, nft, and Rust snapshot are proven coherent before
the commit point (`plan.md:133-141,169-171`), yet obsolete hooks are intentionally
still present until P6 (`plan.md:158-175`). Those statements cannot both be true.
Current removal is warning-only (`pkg/dataplane/userspace/manager_compile.go:522-545`).
If an obsolete XDP hook remains after candidate ingress-map pruning, the shim passes
an ingress ifindex absent from `USERSPACE_INGRESS_IFACES` toward the kernel
(`userspace-xdp/src/lib.rs:426-429`). Therefore obsolete-hook removal and its
verification are release-critical; they cannot share outcome 5's blanket “do not
re-fence” rule with observability/HA debt (`plan.md:200-202`). Conversely, genuinely
retryable P6 tail errors must not cause an early return that accidentally skips P7.
The plan needs separate cleanup-critical and post-release/retryable phases.

### 6.5 Critical actuation contracts are still undefined

P1 says every actuation failure retains the fence (`plan.md:158-180`), but required
VLAN creation and address operations still warn/continue as shown under question 2,
and fabric parent/child MTU/address operations also swallow errors
(`pkg/daemon/daemon_ha_fabric.go:29-50,72-93`). Daemon pre-Manager reconcile errors
are accumulated and execution continues into Manager
(`pkg/daemon/daemon_apply.go:916-959,2227-2296`). Section 5 leaves the
critical-versus-best-effort choice open and merely recommends preserving warn-skip
for some cases (`plan.md:310-314`). P5 cannot prove coherence until every relevant
operation has a result/readback contract.

### Residual gap / required closure

The redesign needs one daemon-scoped transaction API and release owner, a pure P0
entry point before any daemon mutation, persistent/verified fence state independent
of `m.mu`, synchronous HA-readiness revocation, staged participation by daemon link
owners, and a final verification/release point after every packet/security-relevant
daemon operation. These are architecture, not implementation-detail, decisions.

## 7. Overall readiness and concrete blockers

**Sub-verdict: PLAN-NEEDS-MAJOR. The fence-first architecture is salvageable and is
still the right base, but v2 leaves multiple safety-defining choices open in §11 and
recommends one option that directly violates §4.1.**

The following concrete changes block PLAN-READY:

1. **Withdraw or redesign fence-on-non-Accept.** Choose fence-always for every actual
   host/map/attachment mutation, or provide a true multi-generation/banked-map
   protocol that proves the success window safe (`plan.md:252-268` versus
   `plan.md:131-141`; source evidence in question 5).
2. **Specify the daemon transaction API and final commit point.** P0, verified fence
   establishment, daemon pre-host stages, Manager stages, daemon post-host stages,
   final snapshot/route/nft verification, and exactly one release owner must be in
   one explicit order (`plan.md:146-180,239-244`; `daemon_apply.go:885-1005,1220-1520`).
3. **Make the fence durable and verified.** Define state transitions, update/readback
   failure behavior, all ctrl/classifier writers, direct Manager callers, and the
   in-flight XDP/XSK contract (`process_linkcycle.go:50-99`;
   `maps_sync.go:337-381,729-797`; `plan.md:156,318-321`).
4. **Include local-pass security and all link owners.** Stage host-inbound nft with
   local address/map visibility, or tighten the fence's local behavior; keep every
   daemon-created ingress surface down or shim-protected
   (`daemon_nft.go:231-259`; `daemon_ha_fabric.go:19-96`; `plan.md:158-167`).
5. **Define authoritative P1/P2/P5 predicates.** Required links, ifindexes,
   addresses, MTU, attachments, maps, nft, worker liveness, and incomplete kernel
   enumeration need critical/error/readback contracts, with negative tests
   (`compiler_iface.go:184-247,338-397`; `interfaces.go:430-513`;
   `plan.md:163-170,310-314`).
6. **Replace the five-label pseudo-partition.** Preserve definite-not-dispatched,
   NACK, ambiguous-after-dispatch, and ACK; add ACK-but-unverified and pending; use a
   wire outcome enum if causal NACK classification affects behavior
   (`process_control.go:80-143`; `snapshot.rs:195-223,341-392`;
   `plan.md:182-205,442-446`).
7. **Fully design or remove async deferred publication.** Candidate versus committed
   state, central fence clamp, retry ownership, supersession, daemon disposition,
   and P5-gated release cannot remain “shared debt” prose
   (`manager_compile.go:257-298`; `process_status.go:11-165`;
   `plan.md:270-280,451-454`).
8. **Close HA and cleanup races.** Fence begin must synchronously revoke cached RG
   readiness, and obsolete-hook removal must be commit/release-critical rather than
   a generic post-commit tail (`manager_ha.go:391-447`;
   `cluster/readiness.go:8-88`; `manager_compile.go:522-545`;
   `plan.md:172-176,246-250`).
9. **Resolve OQ-5 from r1.** V2's §12 omits the r1 judgment that a failed
   `BumpFIBGeneration` should not by itself create a late fatal/fence transition.
   Current `CompileConfig` ignores the returned error
   (`pkg/dataplane/compiler.go:298-304`), while the underlying operation can fail
   (`pkg/dataplane/maps_fabric.go:78-95`). The plan must explicitly preserve that
   non-fatal/retry contract or justify a new critical predicate before actuation.

This is not PLAN-KILL: a conservative daemon-scoped, verified fence-always design
with explicit local/nft protection can meet the fail-closed objective. It is a major
revision because the present recommendation, API boundary, and transaction states do
not yet define that design.

## Round-1 finding closure map and §12 cross-check

The states below judge whether v2 supplies enough design to implement safely, not
whether code already exists. Section 12 often says “→ section X”; several referenced
sections merely recognize or reopen the issue and therefore do not close it.

### CLOSED

| R1 item | Why closed in v2 |
|---|---|
| **2.1 / OQ-2 — reused `!samePlanRefresh` premise** | V2 no longer calls it an always-restart path and correctly relies on the existing bootstrap order, which writes ctrl disabled and clears bindings before candidate classifier maps (`plan.md:270-283`; `pkg/dataplane/userspace/maps_sync.go:121-195`). The separate async publisher remains 7.2, not a reason to keep this direct-branch finding open. |
| **5.1 / OQ-6 — old-snapshot re-sync is not rollback** | V2 deletes B1 and the host journal rather than claiming exact restoration (`plan.md:289-299`). That directly removes the unsound `old snapshot ∪ current kernel` rollback described by `maps_sync.go:986-1013,1080-1121`. |
| **5.2 — RST-suppression nft omitted from the resource set** | V2 explicitly includes RST-suppression in P3 and requires its current warning-only failure to trigger the fence or be proven before release (`plan.md:167,331-333`; current behavior at `maps_sync.go:1188-1213`). The newly found *host-inbound* nft omission is a different, broader resource gap. |
| **7.8 — #5680 mischaracterized as a fence precedent** | V2 corrects it to a pre-publish hybrid-identity guard, consistent with the actual refusal before publication (`plan.md:104-108,496`; `pkg/dataplane/userspace/manager_overlay.go:140-175,208-229`). |

### PARTIALLY CLOSED

| R1 item | What v2 fixed | What remains / §12 overclaim |
|---|---|---|
| **1.1/1.2 and OQ-1 — skew, incomplete journal, real staging fence** | The journal/B1 are gone and P1 states down-or-shim-first additions plus commit-gated obsolete removal (`plan.md:131-180,289-299`). | Recommended §4.6 still permits ctrl-enabled candidate maps with the old helper, and the fence has no durable owner/readback/quiescence design. Section 12's `plan.md:475-478` is therefore only partial. |
| **3.1 / OQ-3 — publish-last only behind a fence** | P1→P2→P3→P4 and the no-old-generation compensation rule are the correct high-level order (`plan.md:146-180,334-335`). | The operative fence/staging and daemon final commit point remain unresolved, so the high-level order is not yet an implementable single pipeline. |
| **4.1/4.2 / OQ-4 — independent daemon dispositions** | V2 explicitly separates local-tail and peer-push decisions and admits the daemon must change (`plan.md:223-250`). | It supplies no pending disposition, no actual daemon result/API, and leaves the peer reconvergence owner open in OQ-E (`plan.md:447-450`). Current daemon still continues after ordinary apply error (`daemon_apply.go:1220-1248`). |
| **6.1 — post-actuation VLAN/live dependency** | P2 is correctly after P1 (`plan.md:158-166,295-299`), matching the child/parent ifindex dependency at `interfaces.go:239-282`. | Warn-skipped materialization and silent zero/live-plus-config snapshot construction prevent proof (`compiler_iface.go:350-357`; `interfaces.go:430-513`). |
| **6.3 — smaller two-pass design** | V2 abandons the 925-line host IR and adopts P0 plus a final live P2 (`plan.md:150-166,289-299`). | It does not define a pure callable P0 before daemon work. Current `CompileUserspaceShim` performs pin cleanup and host compile before the snapshot (`pkg/dataplane/loader.go:169-208,267-334`), and `CompileConfig`'s recompile tail can call the inherited real FIB bump (`pkg/dataplane/compiler.go:298-304`; no override among `loader.go:352-454`). Section 4.4 also incorrectly calls phase 11 host-destructive even though `compilePortMirroring` itself ends at `compiler.go:1704-1748`; its cited later netlink helpers belong to other interface paths. |
| **7.1 — ACK loss and typed outcomes** | NACK status preservation and ambiguous-after-write fencing are recognized (`plan.md:182-205`). | Existing status cannot causally type pre/post teardown, definite-not-dispatched/Pending/ACK-but-unverified are missing, and OQ-D remains open (`plan.md:442-446`). Section 12's `plan.md:488` is partial. |
| **7.3 — attachments in the transaction** | P1/P6 now name add-before-publish and obsolete removal after acceptance (`plan.md:158-175`). | Daemon-created links cannot join the staging protocol, detach error semantics are warning-only, and P6 wrongly treats removal as non-refencing tail (`manager_compile.go:522-545`). |
| **7.5 — fallible work after publication** | V2 separates post-acceptance work and says true tail errors use retry/debt instead of rollback (`plan.md:172-175,200-202`). | It bundles release-critical obsolete-hook removal with that tail and does not enumerate the claimed retry owners. Section 12's `plan.md:492` is partial. |
| **7.6 — fence invisible to HA readiness** | The plan explicitly requires `takeoverReadyLocked` to reject a fenced node and adds a unit test (`plan.md:246-250,397`). | It leaves flag-versus-map authority and lookup failure unspecified and misses cached RG readiness between polls (`manager_ha.go:391-447`; `daemon_ha.go:682-703`; `cluster/readiness.go:8-88`). |
| **OQ-7 — atomicity/fence framing** | V2 adopts the fail-closed fence/stage framing requested in r1 (`plan.md:131-180,365-369`). | Its recommended hitless exception and unresolved transaction ownership fail that frame, so the question is only directionally closed. |

### STILL OPEN

| R1 item | Why it remains open / §12 disagreement |
|---|---|
| **6.2 — critical host failure contracts** | P1 promises fence-on-failure but VLAN/address/MTU/fabric operations still warn or return no error, and §5 explicitly leaves the compatibility choice open (`plan.md:158-180,310-314`; `compiler_iface.go:184-247,350-397`; `daemon_ha_fabric.go:29-50,72-93`). Section 12's `plan.md:485-487` does not close the missing contracts. |
| **7.2 — async `pendingXSKStartup` publisher** | Section 4.7 diagnoses the exact call order but defines no candidate/debt transitions and contradicts §4.6; OQ-F leaves the mechanism open (`plan.md:259-280,451-454`; `manager_compile.go:257-298`; `process_status.go:143-165`). Section 12's `plan.md:489` overclaims. |
| **7.4 — daemon is not the sole Manager orchestrator / candidate HA state** | V2 recognizes both facts (`plan.md:239-250,327-330`) but leaves daemon ownership as OQ-C and provides no transaction API or final post-daemon verification (`plan.md:438-441`; `daemon_apply.go:885-1005,1220-1520`). Section 12's `plan.md:491` is recognition, not resolution. |
| **7.7 — locking, zero-mutation, and test seam** | The plan explicitly says lock/liveness still needs design (`plan.md:318-321,345`) and only says tests “need” an injected seam (`plan.md:398-400`). P0 cannot precede current pin cleanup/daemon mutation without a new entry point (`manager_compile.go:162-175`; `loader.go:173-183,267-334`). Section 12's `plan.md:494-495` should say open. |
| **OQ-5 — `BumpFIBGeneration` failure disposition** | V2's Section 12 does not map this r1 answer at all. The source still ignores the returned error at `compiler.go:298-304`, and no plan section says whether P0/P1/P5 makes it fatal, retryable, or irrelevant; this must be explicit to avoid inventing a late fence point. |

## New findings introduced or exposed by the v2 redesign

### N2-1 — A ctrl fence is not a host-local authorization fence

Ctrl-disabled mode intentionally passes destinations selected by candidate local/NAT
maps (`userspace-xdp/src/lib.rs:992-1012,1035-1056`), while kernel nft is the primary
host-inbound owner (`pkg/daemon/daemon_nft.go:231-259`). V2 stages only RST nft and
does not order host-inbound nft with local address/map visibility
(`plan.md:163-168,331-333`; `daemon_apply.go:2357-2370`). “Fenced means no observable
mismatch” is therefore false for local traffic even if transit is perfectly fenced.

### N2-2 — The daemon-wide fence has no API or coherent release point

P0 is inside the later Manager apply, daemon mutations precede it, and material
daemon mutations plus route snapshot republish follow Manager return
(`daemon_apply.go:885-1005,1220-1520`; `pkg/dataplane/apply.go:18-40`). The plan puts
P7 in Manager while simultaneously assigning the span to the daemon
(`plan.md:172-176,239-244`). This is a new contradiction created by extending the
fence scope without redesigning orchestration.

### N2-3 — Begin-fence must synchronously revoke cached HA readiness

Changing only `takeoverReadyLocked` leaves the cluster's cached `Ready/ReadySince`
state valid until the next daemon reconcile (`manager_ha.go:391-447`;
`daemon_ha.go:682-703`; `cluster/readiness.go:8-88`). Election/manual failover reads
that cache (`cluster/manager.go:67-70`; `cluster/failover.go:204-232`). Fence begin
needs a synchronous readiness revocation and handoff interlock, not only test 13 at
`plan.md:397`.

### N2-4 — Successful same-plan publication has an old-ctrl/new-helper drop window

Rust swaps to the new validation generation before ACK
(`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:278-355`), while Go updates
the XDP ctrl generation only after the response
(`manager_compile.go:332-351`; `maps_sync.go:364-372,793-797`). Rust rejects old
metadata generation (`userspace-dp/src/afxdp/forwarding/mod.rs:30-42`). This does not
create a fail-open, but disproves §4.6's “hitless success” premise
(`plan.md:254-268`) and needs either fencing or a dual-generation handoff.

### N2-5 — P6's obsolete-hook removal is not generic post-commit tail work

The plan's commit proof includes attachments before the hooks are removed, then says
all P6 errors do not re-fence (`plan.md:133-141,169-176,200-202`). A retained shim on
an interface removed from candidate ingress classification takes the kernel-pass
branch (`userspace-xdp/src/lib.rs:426-429`), and current detach errors are warnings
(`manager_compile.go:522-545`). Cleanup must be release-critical or its residual path
must be separately proven safe.

### N2-6 — Status reconciliation can undo P3 without lifting the fence

Because P6 withholds `lastSnapshot` advancement (`plan.md:172-175`) while every
status application writes classifiers from `m.lastSnapshot`
(`maps_sync.go:729-786`), an interleaved status call can put old maps back after P3.
A ctrl clamp alone does not solve staged-map ownership; the transaction needs an
explicit candidate view or serialization.

VERDICT: PLAN-NEEDS-MAJOR
V2 replaces the unsound rollback model with the right fail-closed foundation, but its recommended hitless path, fence establishment/serialization, daemon release boundary, local nft coverage, async debt, and HA/cleanup transitions still do not satisfy the stated invariant. The plan is salvageable without a journal, but only after those safety-defining mechanisms are made concrete and the contradictory success-window exception is removed or fundamentally redesigned.
