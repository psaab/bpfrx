# #2089 — Security-policy `reject` action: emit TCP RST / ICMP unreachable instead of silent drop

**Status:** DRAFT v1 — pending adversarial plan review

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
- Compute RST fields per RFC 793 §3.4 ("Reset Generation"):
  - If the incoming segment has **no ACK** (e.g. a SYN): the RST
    carries `seq = 0`, `ack = incoming_seq + segment_len`, and flags
    `RST|ACK`. For a bare SYN, segment_len counts the SYN as 1, so
    `ack = incoming_seq + 1`. (We treat all reject-RST as 0-payload;
    SYN/FIN each consume one sequence number — see open question Q3 for
    the exact `seg_len` handling. For the common bare-SYN case
    `ack = seq + 1`.)
  - If the incoming segment **has an ACK**: the RST carries
    `seq = incoming_ack`, no ACK flag, flags `RST`. (Same as the
    existing `build_syn_cookie_ack_rst_frame`.)
- Reuse `build_syn_cookie_tcp_reply_v4/v6` for the L2/L3/L4 assembly
  (it already swaps identity + checksums). The RST window is already
  forced to 0 in `write_syn_cookie_tcp_header` when `TCP_FLAG_RST` is
  set, which is correct.
- Do **not** reply to an incoming RST (`flags & RST != 0` → return
  `None`); never RST-storm.

This is a thin wrapper that selects seq/ack/flags then delegates to the
existing assembly. `build_syn_cookie_ack_rst_frame` can optionally be
re-expressed in terms of the general builder (decided at impl time;
default is to leave it untouched to keep the cookie path byte-identical
and avoid expanding the diff).

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
   - **Never reply to an ICMP/ICMPv6 error message** (`is_icmp_error`)
     and never reply to a non-first fragment (no L4 header) — return
     without sending. (Junos likewise does not generate an unreachable
     for an inbound ICMP error or a fragment with no transport header.)
3. On a successful build, push a `TxRequest` (host-generated frame
   shape, as the SYN-cookie path does) onto
   `tx_pipeline.pending_tx_local`, bump a new
   `counters.policy_reject_*` stat, and return `true`. On
   build/budget failure return `false` (caller still recycles + drops
   — fail-closed).

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

At A and B, **before** recycling the frame, when
`matches!(action, PolicyAction::Reject)` call
`enqueue_policy_reject_reply(...)`. The drop/recycle (`scratch_recycle.push;
continue;`) is unchanged — the reply is an addition, the original
packet is still dropped. `Deny` is completely unchanged (still a silent
drop).

To avoid duplicating the gate at both A and B, factor the
"deny-or-reject terminal" handling into one helper that: emits the
deny/reject event, sets `ForwardingDisposition::PolicyDenied`, and (for
`Reject`) enqueues the reply. Both sites call it. This keeps A/B
behavior identical for `Deny` and centralizes the `Reject` branch.

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
- **Reject directional matrix** (the issue's acceptance test):
  configure a zone policy `then reject`; from the client side
  (`cluster-userspace-host`) attempt a TCP connection through it and
  `tcpdump` on the client for an inbound **RST**; send a UDP/ICMP
  probe and capture an inbound **ICMP/ICMPv6 unreachable** (v4 type 3
  code 13 / v6 type 1 code 1). Confirm `show security flow` /
  Prometheus `policy_reject_sent` increments. Confirm a `then deny`
  policy still produces **no** reply (silent drop preserved).

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
