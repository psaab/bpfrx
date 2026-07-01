# #2089 — Security-policy `reject` action: emit TCP RST / ICMP unreachable instead of silent drop

**Status:** v2 — revised after two hostile plan reviews (A: PLAN-NEEDS-MINOR,
B: PLAN-NEEDS-MAJOR). Both reviewers verified the dataplane-only premise,
the reuse of existing primitives, the type-agnostic v6 ICMP checksum, and
the "rejected flows are never cached/session-installed" claim as TRUE
against source. v2 resolves the three valid findings: (1) the reject
behavior is pinned to the project's OWN validated legacy-eBPF reject
prior art (commits `8400e23`, `3fc0a58` — "matching Junos reject
behavior") rather than to an ambiguous docs reading; (2) per-site inline
reject-enqueue instead of a shared deny/reject terminal (the two deny
sites are structurally asymmetric); (3) the RST seq/ack spec is stated
independently of the cookie path. See §11 for the review disposition.

## 0. Authoritative reference: the legacy eBPF reject (prior art)

xpf already shipped this exact feature on the retired eBPF dataplane
(`git show 8400e23`, `git show 3fc0a58`; `docs/session-history.md:56,206`).
That implementation is the canonical reference for the wire behavior —
its commit message states it generates "proper ICMP/ICMPv6 Destination
Unreachable (admin prohibited) responses for UDP, ICMP queries, and
other non-TCP traffic, **matching Junos reject behavior**." The exact
legacy dispatch (verbatim from `3fc0a58`, the post-#1476-deleted
`bpf/xdp` source) is:

```
if (rule->action == ACTION_REJECT) {
    if (meta->protocol == PROTO_TCP)        // TCP -> RST (v4/v6)
        return send_tcp_rst_v{4,6}(...);
    // RFC 792/4443: never send ICMP error about an ICMP error.
    // ICMPv4 error types: 3,4,5,11,12.  ICMPv6: all types < 128 are errors.
    if (meta->protocol == PROTO_ICMP &&
        (icmp_type == 3 || 4 || 5 || 11 || 12)) return XDP_DROP;
    if (meta->protocol == PROTO_ICMPV6 && icmp_type < 128) return XDP_DROP;
    // UDP, ICMP queries (echo/etc.), and other non-TCP -> ICMP unreachable
    return send_icmp_unreach_v{4,6}(...);   // v4 type 3 code 13; v6 type 1 code 1
}
return XDP_DROP;
```

This **settles** the parity question raised by review B-C1: xpf's intended
parity behavior is ICMPv4 type 3 **code 13** / ICMPv6 type 1 **code 1**
(administratively prohibited) for non-TCP, with replies generated for UDP
+ ICMP *query* types + other non-TCP, and suppressed only for inbound
ICMP/ICMPv6 *error* types. This plan reproduces that legacy behavior on
the userspace dataplane.

## 1. Issue framing

A Junos security policy `then reject` action is defined to **actively
reject** a blocked flow: for TCP it sends a **TCP RST** back to the
client; for every other protocol it sends an **ICMP destination
unreachable** (administratively prohibited). This is distinct from
`then deny`, which silently drops. vSRX parity requires:

- IPv4 non-TCP → **ICMP type 3, code 13** (communication administratively
  prohibited).
- IPv6 non-TCP → **ICMPv6 type 1, code 1** (communication with
  destination administratively prohibited).
- TCP (any family) → **TCP RST**.

Today xpf compiles `reject` all the way to `PolicyAction::Reject` in the
Rust dataplane, but the dataplane treats `Reject` **identically to
`Deny`**: the packet is dropped (frame recycled) with no reply. Clients
hang until timeout instead of getting an immediate connection-refused /
unreachable. Not a security hole (traffic is still blocked) but a real
parity + operator-experience gap.

## 2. Honest scope/value framing

This is a **functional parity** change, not a performance change. The
win is correctness: `reject` becomes a fast-fail instead of a hang.
Blast radius on the hot path is **zero for permit/deny** — the reject
synthesis only runs on the already-cold policy-deny exception arm, and
only when the matched action is `Reject` (a config-driven minority of
denied flows). There is no per-permit-packet cost.

The change is small and additive: it reuses three pre-existing,
already-tested dataplane primitives (the SYN-cookie TCP reply builder,
the local-ICMP-error builder, and the host-generated-frame TX enqueue
path) and wires them at the policy-deny sites. No new control-plane
wire fields are needed — `reject` already reaches the dataplane as a
distinct `PolicyAction`.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (Here the justification is parity,
not perf; the churn is genuinely small.)

## 3. What's already shipped / partially in place

The entire compile + wire path is intact and need **not** change:

- `pkg/config/compiler_security.go:275-276` — `"reject"` →
  `PolicyReject`.
- `pkg/dataplane/userspace/policies.go:587-596` — `PolicyReject` →
  wire string `"reject"`.
- `userspace-dp/src/policy.rs:1085-1089` — `parse_action("reject")` →
  `PolicyAction::Reject`.
- `userspace-dp/src/afxdp/event_emit.rs:8-10` — `RT_FLOW_ACTION_REJECT
  = 2` already defined and round-trips through the event codec
  (`event_stream/codec.rs:54`, decode test at `codec_tests.rs:289`).
- `pkg/logging/ringbuf.go:914` already renders action 2 as `"reject"`.

Pre-existing reply-synthesis primitives this plan reuses (no new
packet-crafting code from scratch):

1. **TCP reply builder** — `userspace-dp/src/afxdp/frame/tcp.rs`:
   `parse_tcp_reply_source`, `build_syn_cookie_tcp_reply_v4/v6`,
   `write_reply_eth_header`, `write_syn_cookie_tcp_header`. These swap
   L2/L3/L4 identity, set TCP flags/seq/ack, and recompute checksums
   from scratch. `build_syn_cookie_ack_rst_frame` already emits a
   `RST|ACK` — but only for ACK-bearing segments (the cookie path).
2. **ICMP error builder** — `userspace-dp/src/afxdp/icmp.rs`:
   `build_local_time_exceeded_v4/v6` reflect L2 (swap MAC, preserve
   ingress VLAN), build the outer IP header from
   `forwarding.egress.get(ingress_ifindex).primary_v4/v6`, embed the
   quoted original packet (IP header + 8 bytes for v4; up to 48 bytes
   for v6), and compute the ICMP/ICMPv6 checksum (v6 with pseudo-header).
   The type/code are the only thing specific to time-exceeded.
3. **Host-generated-frame TX enqueue** — `cookie_reply.rs`:
   `enqueue_syn_cookie_reply` pushes a `TxRequest` onto
   `binding.tx_pipeline.pending_tx_local` with TX-frame budget gating
   (`syn_cookie_reply_budget_available`). The reject path uses the same
   `TxRequest` shape (host-generated, `cos_queue_id: None`,
   `dscp_rewrite: None`, `flow_key: Some(...)`).

At every policy-deny site in `poll_descriptor/mod.rs`,
`binding.tx_pipeline`, `packet_frame`, `meta`, `flow`,
`worker_ctx.forwarding`, the ingress `BindingIdentity`, and
`binding.scratch.scratch_recycle` are all in scope (the SYN-cookie
enqueue is already called there at lines 213-214, 252, 474-475).

## 4. Concrete design

### 4.1 New reply builders

**`userspace-dp/src/afxdp/frame/tcp.rs` — general reject RST builder**

Add `build_reject_rst_frame(frame: &[u8]) -> Option<Vec<u8>>`:

- Parse via `parse_tcp_reply_source` (already returns
  `seq`, `ack`, `flags`, ports, family, l3).
- Compute RST fields per RFC 9293 §3.5.2 / RFC 793 §3.4 "Reset
  Generation" — stated here **independently of the cookie path** (review
  A-M1/B-M1: the existing `build_syn_cookie_ack_rst_frame` emits
  `RST|ACK` with `ack=seq+1`, which is the validated-cookie special
  case, NOT the general reset rule — do not copy it):
  - If the incoming segment carries **no ACK** (e.g. a bare SYN): the
    RST has `seq = 0`, `ack = incoming_seq + seg_len`, flags `RST|ACK`.
    `seg_len` counts the SYN (and FIN, if present) as 1 plus any payload
    bytes; for a bare SYN `ack = incoming_seq + 1`. (Computing the exact
    `seg_len` from the inbound frame — payload length from IP total-len
    minus headers, plus SYN/FIN — is part of the builder; the dominant
    bare-SYN case is `seq+1`.)
  - If the incoming segment **carries an ACK**: the RST has
    `seq = incoming_ack`, **no ACK flag**, flags `RST` only. This is the
    canonical RFC reset for an ACK-bearing segment to a closed port and
    is **deliberately different** from the cookie builder's `RST|ACK`.
- Reuse `build_syn_cookie_tcp_reply_v4/v6` for the L2/L3/L4 assembly
  (it already swaps identity + checksums). The RST window is already
  forced to 0 in `write_syn_cookie_tcp_header` when `TCP_FLAG_RST` is
  set, which is correct. (`write_syn_cookie_tcp_header` always writes
  the ack field; for the no-ACK-flag case the ack value is ignored by
  the receiver because the ACK bit is clear — confirm the data-offset
  byte and flags are written exactly, with the ACK bit cleared.)
- Do **not** reply to an incoming RST (`incoming flags & RST != 0` →
  return `None`); never RST-storm.

This is a thin wrapper that selects seq/ack/flags then delegates to the
existing assembly. `build_syn_cookie_ack_rst_frame` is left **untouched**
(cookie path stays byte-identical; the general builder does not subsume
it because the cookie case intentionally uses `RST|ACK`).

**`userspace-dp/src/afxdp/icmp.rs` — admin-prohibited builders**

Generalize the existing time-exceeded builders. The cleanest approach
that preserves the cookie/TE path byte-for-byte is to factor the
type/code out:

- Introduce `build_local_icmp_error_v4(frame, meta, ingress_ifindex,
  forwarding, icmp_type, icmp_code)` and the v6 analogue, containing
  the current body of `build_local_time_exceeded_v4/v6` with the
  hard-coded `[11,0,..]` / `[3,0,..]` replaced by `[icmp_type,
  icmp_code, ..]`.
- Re-express `build_local_time_exceeded_v4` as a call with `(11, 0)`
  and `build_local_time_exceeded_v6` with `(3, 0)` — preserving the
  existing wire bytes exactly (verified against the current
  hard-coded arrays).
- Add `build_reject_icmp_unreachable(frame, meta, ingress_ident,
  flow, forwarding) -> Option<Vec<u8>>` mirroring
  `build_local_time_exceeded_request`'s structure but calling the
  generalized builder with `(3, 13)` for v4 / `(1, 1)` for v6.
  **Note on the v6 type:** the current `_v6` builder hard-codes the
  ICMPv6 *time-exceeded* type 3; the reject path passes type **1**
  (dest-unreachable), code **1** (admin prohibited). The
  pseudo-header checksum (`checksum16_ipv6`) is type-agnostic, so the
  same builder is correct once the type byte is parameterized.

### 4.2 Reject-reply dispatch helper

Add a single cold helper, e.g. in a new
`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` (mirroring
`cookie_reply.rs`), `#[cold] #[inline(never)]`:

```
fn enqueue_policy_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
) -> bool
```

Behavior:

1. Budget-gate using the existing `syn_cookie_reply_budget_available`
   (or a sibling) so reject replies never starve the TX ring.
2. If `meta.protocol == PROTO_TCP`: build via `build_reject_rst_frame`.
   Else build via `build_reject_icmp_unreachable`.
   - **ICMP-error suppression must match the legacy prior art exactly**
     (§0) — do NOT reuse `is_icmp_error`, whose type sets differ
     (`is_icmp_error` is v4 `{3,11,12}` / v6 `{1,2,3,4}`, used for the
     embedded-ICMP-NAT path). The reject guard is:
     - `PROTO_ICMP` and `icmp_type ∈ {3,4,5,11,12}` → no reply (drop).
     - `PROTO_ICMPV6` and `icmp_type < 128` → no reply (drop).
     - all other non-TCP (UDP, ICMP *query* types like echo, GRE, …) →
       send the unreachable.
     `icmp_type` is read from `frame.get(meta.l4_offset)` (same parse as
     `poll_descriptor/mod.rs:850-853`), with bounds-check → fail-closed
     to silent drop if absent.
   - Never reply to a non-first fragment (no L4 header) — return without
     sending (the inbound has no transport header to quote/key).
3. On a successful build, push a `TxRequest` (host-generated frame
   shape, as the SYN-cookie path does) onto
   `tx_pipeline.pending_tx_local`, bump a new
   `counters.policy_reject_*` stat, and return `true`. On
   build/budget failure return `false` (caller still recycles + drops
   — fail-closed).

> **#3656 update (consumption ordering).** Steps 1-2 above are now
> **reordered**: reply-build FEASIBILITY (step 2) runs BEFORE the
> TX-frame budget gate and the #2472 `REJECT_BUCKET` token consumption
> (step 1). The reject/deny path is now:
>
>   build (`build_reject_rst_frame` / `build_reject_icmp_unreachable`)
>   → `Some(bytes)` proves an actual reply exists
>   → TX-frame budget gate (counts `*_reject_reply_budget_drops`)
>   → `allow_generated_error(Reject)` token consume
>   → #2238/#3035 output-filter classify → enqueue.
>
> Rationale: a frame that can never produce a reply — an inbound TCP
> RST, an inbound ICMP/ICMPv6 error, a non-first fragment, an L2
> group/broadcast frame, an unparseable frame, or an ingress without a
> primary of the inbound family — is a PLAIN drop. It must consume
> **neither** the shared per-reason rate-limit token (H11: a flood of
> unreplyable frames draining the shared `REJECT_BUCKET` would silently
> downgrade legitimate subsequent rejects to drops — a cheap DoS)
> **nor** a `*_reject_reply_budget_drops` counter (H12: mis-attributing
> an impossible reply as TX queue pressure hides the true attack shape).
> A budget drop / token consume / rate-limited count is now recorded
> only for a reply that could actually have been built. This is the
> residual of #3615 (which reordered the event emit + per-source counter
> split but left the bucket/budget consume ahead of the build) and is
> orthogonal to #3618 (per-zone bucket design) — the shared bucket is
> unchanged; only the consumption ORDERING moves. The extra build under
> budget/rate pressure is on the already-cold reject exception path.
> Enforced by `enqueue_reject_reply` in
> `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`; fail-on-revert
> tests: `unreplyable_reject_does_not_drain_bucket_3656`,
> `unreplyable_reject_does_not_count_budget_drop_3656`,
> `unreplyable_non_first_fragment_reject_untouched_3656`.

### 4.3 Trigger sites

There are three policy-deny code paths in
`poll_descriptor/mod.rs` (plus the cached/established path in
`flow_cache_hit.rs`):

- **A — early policy gate, MissingNeighbor arm** (`if let
  PolicyAction::Permit` at ~1161; the `else` deny at ~2374
  `if !matches!(.., Permit)`).
- **B — main new-flow policy deny** (`else` at ~1718-1750).
- **C — cached/established flow** (`flow_cache_hit.rs`): the
  cache only ever caches a **permit** decision (a deny/reject flow
  is not session-installed), so the reject reply fires on the
  first-packet decision in A/B, not on a cache hit. **To be
  re-confirmed at impl time** (open question Q4) — if a denied flow
  can re-enter via the cache, the reject must fire there too.

**Per-site inline insertion — NOT a shared deny/reject terminal**
(reviews A-finding-6 / B-M2). The two deny sites are structurally
**asymmetric** (verified against source):

- **Site A** (`~2374-2406`): handles the deny terminal *inline* — emits
  the deny event, sets `PolicyDenied`, calls `record_forwarding_disposition`,
  then `scratch_recycle.push(desc.addr); continue;`. `policy_result.action`,
  `flow`, `meta`, `packet_frame`, `binding.tx_pipeline`,
  `worker_ctx.forwarding`, and `worker_ctx.ident` are all in scope.
- **Site B** (`~1719-1750`): only emits the deny event, bumps debug
  counters, and sets `decision.resolution.disposition = PolicyDenied`,
  then **falls through** to the centralized disposition epilogue
  (`PolicyDenied` arm at `~3007`, `record_forwarding_disposition` at
  `~3011`, recycle in the shared epilogue). At that epilogue
  `policy_result.action` and the non-Option `flow` are **out of scope**.

A single "deny terminal" helper would therefore either double-record at
A or break B's fall-through, and cannot reach the reply state at B's
epilogue. So v2 inserts the reject-reply **inline at each site**,
gated `if matches!(policy_result.action, PolicyAction::Reject)`,
**before that site's existing recycle/disposition-set**, calling
`enqueue_policy_reject_reply(...)`. The existing `Deny` code at both
sites is left **byte-for-byte unchanged** — the reply is a pure
addition on the `Reject` sub-branch. (Site B's reply must be enqueued
at `~1719` where `action`/`flow`/`packet_frame` are live, before the
fall-through, not at the shared epilogue.)

### 4.4 Event / RT_FLOW correctness

Once the dataplane actually sends the reply, flip the two stale
mappings so logs no longer mis-report:

- `event_emit.rs:198` — `PolicyAction::Reject => RT_FLOW_ACTION_REJECT`
  (was `RT_FLOW_ACTION_DENY`). Update the stale comment.
- (Filter-reject at `event_emit.rs:210` is **out of scope** — see §10.
  Leave it reporting deny until filter-reject synthesis is wired, so it
  does not claim a reject that did not happen.)

### 4.5 Counters

Add `policy_reject_sent` / `policy_reject_budget_drops` /
`policy_reject_build_fail` to `BatchCounters` and surface via the
existing status snapshot (`protocol.go` / Prometheus) the same way
`syn_cookie_*` counters are surfaced. (Exact counter set finalized at
impl time; at minimum a sent counter so smoke can prove replies fire.)

## 5. Public API preservation

No Go control-plane API, gRPC, CLI grammar, or wire-snapshot field
changes. `policyActionString` and the wire `"reject"` string are
unchanged. No `SessionKey` change (reject is terminal, never
session-installed → no HA-sync / flow-cache key impact).

Existing Rust signatures preserved:
- `build_local_time_exceeded_v4/v6` — same signature, same output
  bytes (re-expressed over the generalized internal builder).
- `build_syn_cookie_ack_rst_frame` — untouched (cookie path
  byte-identical).
- `enqueue_syn_cookie_reply` / `syn_cookie_reply_budget_available` —
  untouched (reject reuses or siblings them).

## 6. Hidden invariants the change must preserve

1. **Permit/Deny hot path unchanged.** The reject branch must be gated
   behind `matches!(action, Reject)` so a permit or deny flow executes
   exactly the same instructions as today. The reject body is
   `#[cold]`.
2. **Fail-closed.** If the reply can't be built or the TX budget is
   exhausted, the packet is still dropped and **no** log claims a
   reject was sent. (Mirrors the `filter/mod.rs` `FilterAction::Reject`
   contract comment.)
3. **No reply amplification / loops.** Never reply to an inbound RST,
   never reply to an inbound ICMP/ICMPv6 error, never reply to a
   non-first fragment. The RST/ICMP reply is itself a host-generated
   frame that re-enters ingress on the peer side as ordinary traffic;
   it must not match a reject policy on the way back in a way that
   loops (it won't — the reply egresses toward the original *source*,
   which is on the *ingress* zone, not through the reject policy again;
   to be confirmed in Q2).
4. **TX-frame budget.** Reject replies are gated by the same reserve
   logic as SYN-cookie replies so a flood of rejected SYNs cannot
   starve transit TX frames.
5. **Side-effect ordering at deny sites.** The event emit + disposition
   set + counter bumps must keep their current order; the reply enqueue
   is inserted before the `scratch_recycle.push(...) / continue`.
6. **VLAN / L2 reflection correctness.** The reply must egress on the
   ingress interface with swapped MACs and the ingress VLAN tag
   preserved — both reused builders already do this
   (`write_reply_eth_header` / `ingress_reply_l2`).
7. **ICMP source address.** The unreachable's source IP is the firewall
   ingress interface address (`egress.primary_v4/v6`), matching the
   time-exceeded builder and Junos behavior (the RE/interface address,
   not a spoof of the original destination).
8. **Frame provenance — reflect the ORIGINAL, pre-NAT inbound packet**
   (review B-m2; verified). The policy decision precedes NAT apply (NAT
   is in the `Permit` arm at `~1161+`), and the deny sites use the
   ingress frame (`owned_packet_frame.as_deref().unwrap_or(raw_frame)`,
   `mod.rs:~280`). The RST/ICMP must therefore reflect the un-NAT'd
   client tuple — which it does, because the builders read
   `packet_frame` at the deny site (pre-NAT). Reflecting a mutated frame
   would be a silent correctness bug; the plan asserts this invariant
   explicitly so impl + tests guard it.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression (permit/deny) | **LOW** | Reject branch is gated + cold; permit/deny code path byte-unchanged. The only shared-path edit is parameterizing the ICMP builders, which is proven byte-identical by re-expressing TE over the generalized fn. |
| Lifetime / borrow-checker | **LOW** | Same borrow shape as the existing SYN-cookie enqueue (`&mut binding.tx_pipeline` + `&packet_frame`); reply is built into an owned `Vec<u8>` before enqueue. |
| Performance regression | **LOW** | No per-packet cost on permit/deny; reject body in `.text.unlikely`. TX-budget-gated so reject floods can't starve transit. |
| Architectural mismatch (#961/#946-P2) | **LOW** | Not a refactor of a data structure; an additive feature reusing established primitives at established extension points. No new architecture premise to fail. |
| Reply loop / amplification | **MED** | Mitigated by no-reply-to-RST / no-reply-to-ICMP-error / no-reply-to-fragment + budget gating; Q2 verifies the reply doesn't re-trigger the reject policy. |

## 8. Test plan

- `cargo build` clean (TMPDIR=/dev/shm).
- `cargo test --release` full suite green.
- New unit tests in `frame/tcp_tests.rs` and `afxdp/tests.rs`:
  - `build_reject_rst_frame` for v4 + v6, SYN (no-ACK → RST|ACK,
    ack=seq+1, seq=0) and non-SYN ACK-bearing (→ RST, seq=ack);
    verify MAC swap, IP swap, ports swapped, checksums valid, window 0.
  - `build_reject_icmp_unreachable` v4 (type 3 code 13) + v6 (type 1
    code 1): MAC/VLAN reflect, src = ingress primary, embedded quoted
    bytes, checksum valid.
  - No-reply guards: inbound RST → None; inbound ICMP error → None;
    non-first fragment → None.
  - Time-exceeded byte-identity regression: assert the generalized
    builder with (11,0)/(3,0) produces the same bytes as a golden
    vector captured from the current builder.
- 5/5 flake check on the most-affected named test.
- Go suite: `go test ./...` (no Go behavior change expected; confirms
  no regression).
- **Smoke on loss userspace cluster** (per skill, v4+v6 × push+reverse,
  Pass A CoS-disabled + Pass B per-class) to prove **no permit
  fast-path regression** — full 30-measurement matrix.
- **Reject directional matrix** (the issue's acceptance test; expanded
  per review B test-gaps):
  - **TCP v4 + v6**: connect through a `then reject` policy; `tcpdump`
    on the client for an inbound **RST** (both families — v6 explicitly,
    not implied).
  - **UDP v4 + v6**: probe through reject; capture an inbound **ICMP/
    ICMPv6 unreachable** (v4 type 3 **code 13** / v6 type 1 **code 1** —
    the prior-art admin-prohibited codes from §0).
  - **ICMP *query* (echo) through reject**: capture an inbound
    unreachable (a query is replied to, per §0).
  - **Inbound ICMP *error* through reject**: confirm **no** reply
    (silent drop — the §0 suppression guard).
  - **`then deny` control**: confirm **no** reply (silent drop
    preserved) — proves Deny is unchanged.
  - **Budget / flood fail-closed**: drive a rejected-SYN flood and
    confirm reject replies are budget-gated (drop to silent under
    pressure, `policy_reject_budget_drops` increments) without starving
    transit TX.
  - Confirm `show security flow` / Prometheus `policy_reject_sent`
    increments and the syslog RT_FLOW renders action `reject` (not
    `deny`).

## 9. Out of scope (explicitly)

- **Firewall-filter reject** (`FilterAction::Reject` in
  `filter/mod.rs`) — same gap, separate trigger path (input/lo0/output
  filter evaluation, not zone policy). It shares the new reply builders,
  so a follow-up is cheap, but it is **not** what #2089 asks for and
  expands the test surface (filter eval is on the per-packet hot path,
  not the cold deny arm). Deferred to a follow-up issue. The
  filter-reject RT_FLOW mapping (`event_emit.rs:210`) stays reporting
  deny so it never over-claims.
- **`reject` with explicit `reject-code` / TCP-reset tuning** (Junos
  lets you choose the ICMP code or force tcp-reset for non-TCP). xpf
  uses the Junos defaults (admin-prohibited / RST-for-TCP). Configurable
  reject codes are a separate enhancement.
- **Per-source rate-limiting of reject replies** beyond the existing
  TX-frame budget gate.

## 10. Open questions for adversarial review

1. **Centralize vs per-site.** Is factoring the deny/reject terminal
   into one helper called at sites A and B correct, or do the two
   sites have different in-scope state (e.g. `owner_rg_id`, NAT release
   keys) that makes a shared helper leak a subtle behavior difference
   for `Deny`? Should the reply instead be enqueued inline at each site
   to keep `Deny` provably untouched? (PLAN-KILL if a shared helper
   can't preserve `Deny` byte-for-byte.)
2. **Reply re-ingress loop.** The synthesized RST/ICMP egresses toward
   the original source via the ingress interface. Can that reply ever
   re-enter the dataplane and itself match a `reject` policy (e.g.
   asymmetric routing, hairpin, or the source being behind another
   reject zone), creating a reply storm? Is the no-reply-to-RST /
   no-reply-to-ICMP-error guard sufficient, or is an explicit
   host-origin marker needed?
3. **RST sequence semantics.** For a rejected bare SYN, is `seq=0,
   ack=seq+1, RST|ACK` the correct/most-compatible RST (matches Linux
   `tcp_v4_send_reset` for a SYN), or should we mirror the incoming
   seq differently? Are there segment-length edge cases (SYN+data,
   FIN) where `ack = seq + seg_len` matters for the client to accept
   the RST?
4. **Cached/established deny path.** Confirm a denied/rejected flow is
   never session-installed and therefore never re-enters via
   `flow_cache_hit.rs` — i.e. the reject reply only needs wiring at the
   first-packet A/B sites, not the cache-hit path. If a rejected flow
   *can* hit the cache, the reply must fire there too (and the plan
   must expand).
5. **TX budget starvation vs correctness.** Under a rejected-SYN flood,
   the budget gate will drop reject replies (fail-closed silent drop).
   Is that acceptable (it degrades gracefully to today's behavior under
   attack), or does reject need its own small dedicated reserve so a
   legitimate low-rate reject still fires while transit is busy?
6. **ICMPv6 builder generalization.** The current `_v6` builder is
   named/used only for time-exceeded (type 3) but parameterizing the
   type to 1 for dest-unreachable: any ICMPv6 quoting-length or
   pseudo-header subtlety that differs between type 1 and type 3 that
   the shared builder would get wrong? (RFC 4443: both are "as much of
   the invoking packet as fits without exceeding minimum MTU"; the
   current 48-byte cap should be fine, but confirm.)
7. **Source address selection for ICMP unreachable.** Using
   `egress.primary_v4/v6` of the **ingress** interface as the source —
   correct for vSRX parity? If the ingress interface has no primary of
   the right family (e.g. v6-only flow on a v4-only-addressed subif),
   the builder returns `None` and we fail-closed to a silent drop — is
   that the right fallback, or should we fall back to another interface
   address?

## 11. Disposition of round-1 hostile plan reviews

Two independent hostile reviewers (substituting for the infra-degraded
Codex/AGY companion lane) reviewed plan v1 against source.

**Reviewer A — VERDICT: PLAN-NEEDS-MINOR.** Verified the reuse premise,
ICMP/RST correctness, hot-path gating, and — most importantly — that
**rejected flows are never cached/session-installed** (`is_cacheable()`
returns true only for `ForwardCandidate|FabricRedirect`;
`flow_cache.rs:231/248`, `forwarding.rs:305-310`), so the cache-hit path
needs no reject wiring (plan Q4 confirmed TRUE). Findings adopted:
- *MAJOR (finding 6):* the two deny sites are structurally asymmetric;
  a shared deny terminal risks regressing `Deny`. → **Adopted:** §4.3
  rewritten to per-site inline insertion, `Deny` byte-unchanged.
- *MINOR (M1):* the v1 RST ACK-case "same as `build_syn_cookie_ack_rst_frame`"
  claim was false. → **Adopted:** §4.1 now specifies the RFC reset rule
  independently and leaves the cookie builder untouched.

**Reviewer B — VERDICT: PLAN-NEEDS-MAJOR.** Verified all internal
claims (reject reaches the dataplane as a distinct action; no
control-plane/wire change; `RT_FLOW_ACTION_REJECT=2` round-trips and
renders "reject"; v6 ICMP checksum is type-agnostic so parameterizing
the type byte is safe). Findings disposed:
- *CRITICAL (C1):* claimed vSRX default is UDP→type-3-**code-3**
  (port-unreachable) and **silent** for other non-TCP, so code 13 /
  reply-for-all is wrong. → **Resolved via the project's own validated
  prior art (§0):** the retired eBPF reject (`8400e23`/`3fc0a58`,
  explicitly "matching Junos reject behavior") used type 3 **code 13** /
  type 1 **code 1** and replied for UDP + ICMP queries + other non-TCP,
  suppressing only inbound ICMP *errors*. The plan reproduces that exact
  behavior. (The reviewer's docs reading is noted but the project's
  shipped-and-tested intent is authoritative for parity; configurable
  reject-code remains an explicit out-of-scope enhancement.) The
  precise suppression guard (v4 `{3,4,5,11,12}`, v6 `<128`) from the
  prior art is adopted in §4.2 in place of v1's vague `is_icmp_error`.
- *MAJOR (M1, M2):* same as A's M1/finding-6 — adopted (above).
- *MINOR (m2):* assert pre-NAT frame provenance. → **Adopted** as
  invariant 8 (§6).
- *Test gaps:* UDP reject, ICMP-query-vs-ICMP-error, v6 RST, budget
  flood. → **Adopted** in the §8 directional matrix.

**Net:** the architectural premise (dataplane-only, reuse existing
primitives, per-site insertion) is confirmed sound by both reviewers
and pinned to the project's own prior-art wire behavior. v2 is ready for
implementation.

## 12. Smoke status (loss userspace cluster, head c23b16ebe)

**Permit fast path — no regression (confirmed).** Post-deploy sustained
iperf3 through the cluster: 8.59 Gbit/s, 0 retransmits (v4 port 5201);
both nodes active, roles stable.

**Reject event/log/match — confirmed.** With a `then reject` policy
installed, sessions are tagged `Policy name: reject-test`, the
`Policy deny` counter increments, and the firewall event log emits
`action=reject` (the RT_FLOW_ACTION_REJECT mapping works end-to-end).

**Reject reply delivery — INCONCLUSIVE on this HA cluster (deferred to a
standalone DUT-isolated VM).** Repeated TCP/UDP probes through the
reject policy produced client-side timeouts with no captured reply.
Three lab-specific factors blocked a definitive result:
1. AF_XDP zero-copy TX on the mlx5 VF dataplane is invisible to kernel
   tcpdump, so the firewall side cannot observe a host-generated reply.
2. `policy_reject_sent` / `policy_reject_reply_budget_drops` are not
   surfaced via any CLI/HTTP/Prometheus (same as the sibling
   `syn_cookie_*` counters), so the build/enqueue/budget state can't be
   read from an operator surface.
3. Temporary stderr instrumentation showed `enqueue_policy_reject_reply`
   was not reached for the cluster's reject flows even though the deny
   counter moved and sessions were tagged `reject-test` — i.e. on this
   reth/VF + `ip_forward=1` HA path the reject decision appears to take
   a session-creating route that does not pass the two instrumented
   new-flow policy-deny sites (sites A/B). The unit tests prove the
   builders + enqueue are correct in isolation; the open question is
   which dataplane path the cluster's traffic actually takes.

Recommended follow-up: validate live on a **standalone DUT-isolated VM**
(`xpf-fwd`, virtio copy-mode AF_XDP = tcpdump-visible, `ip_forward`
disableable) — the environment where #2089 was originally found — and,
if the session-creating reject path is confirmed, wire the reject reply
there too (a third call site beyond A/B). Surfacing the
`policy_reject_*` counters via `show security flow statistics` would
also make this directly observable.
