# #850 allow_dns_reply: enforce policy on sessionless DNS admits

## Problem

`flow-config allow-dns-reply` is a Junos vSRX feature. Keep it.
The current implementation has a **policy bypass** bug: the
sessionless DNS reply (UDP sport=53) path tail-calls directly to
`xdp_forward` / `goto forward` / `ForwardCandidate`, skipping the
zone-pair policy check entirely on all three dataplanes. Attackers
can craft UDP with spoofed sport=53 and reach any FIB-resolved
egress without policy enforcement.

## Junos-aligned semantic (what this PR delivers)

The Junos `set security flow allow-dns-reply` knob admits a DNS
reply (sport=53) **without requiring an existing session** — useful
for asymmetric routing where the firewall doesn't see the query.
The reply is still evaluated against zone-pair policy; if a rule
permits the reply-direction flow, the packet passes. Unlike a
normal new-flow admit, allow-dns-reply admits **without creating a
session** (matches Junos's "no session required" intent).

This PR implements that: route the sessionless DNS reply through
policy, admit without session on Permit, drop on Deny.

## Design

### pkt_meta flag

Add `META_FLAG_DNS_REPLY_FASTPATH` to `bpf/headers/xpf_common.h`
(bit 6 — free per prior research, bits 0-5 in use, bit 7 reserved).

### XDP — `bpf/xdp/xdp_conntrack.c`

Change both v4 and v6 DNS-reply branches from:

```c
/* current: bypass policy */
if (fc && fc->allow_dns_reply) {
    bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
    return XDP_PASS;
}
```

to:

```c
/* fixed: still admit sessionlessly, but enforce policy first */
if (fc && fc->allow_dns_reply) {
    meta->meta_flags |= META_FLAG_DNS_REPLY_FASTPATH;
    meta->ct_state = SESS_STATE_NEW;
    meta->ct_direction = 0;
    TRACE_CT_MISS(meta);
    bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
    return XDP_PASS;
}
```

### XDP — `bpf/xdp/xdp_policy.c`

After a `Permit` action resolves, check for the fast-path flag.
If set AND `(meta->nat_flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT)) == 0`:
skip `create_session_v4/v6` AND skip the `SESSION_OPEN` event
emission (otherwise we'd log phantom RT_FLOW_SESSION_CREATE events).
Tail-call straight to `XDP_PROG_FORWARD`.

If the fast-path flag is set BUT NAT would be required: **fall
through to the normal admit path**. The reasoning: dynamic SNAT
inserts `dnat_table` entries and NAT64 inserts `nat64_state`;
both are garbage-collected by walking expired sessions
(`pkg/conntrack/gc.go:224-302`, `dpdk_worker/gc.c:41-187`). A
"permit + no session + stateful NAT" combo would leak map entries
permanently. Gating the skip on "no NAT flags" keeps the invariant
simple: fast-path admits are always NAT-free. When NAT is needed,
the knob behaves as a normal admit (session installed, NAT
properly anchored).

If `Deny`, normal deny handling (counter + drop/reject).

### DPDK — `dpdk_worker/conntrack.c`

Change the sessionless DNS carve-out to **not** return
`CT_DNS_REPLY`. Instead, set a meta field (e.g. add
`uint8_t dns_reply_fastpath : 1` to `pkt_meta`) and return
`CT_NEW` so the pipeline falls through to policy.

### DPDK — `dpdk_worker/pipeline.c`

In `process_packet`, after `policy_check()` returns `ACTION_PERMIT`:
if `meta.dns_reply_fastpath` is set AND `meta.nat_flags &
(SESS_FLAG_SNAT | SESS_FLAG_DNAT)` is zero, skip
`conntrack_create()` and jump to `forward:`. Otherwise (NAT needed
or fast-path flag not set), take the normal path.

The `CT_DNS_REPLY` constant can be removed (no remaining callers).

### Rust — `userspace-dp/src/afxdp.rs`

Inside the `ForwardCandidate` branch, change:

```rust
if allow_unsolicited_dns_reply(forwarding, flow) {
    /* empty: skip policy, forward */
} else if let PolicyAction::Permit = evaluate_policy(...) {
    /* normal flow */
}
```

to:

```rust
if let PolicyAction::Permit = evaluate_policy(...) {
    if allow_unsolicited_dns_reply(forwarding, flow) {
        /* Permit + fast-path: forward without session install */
        /* ... build forwarding resolution ... */
    } else {
        /* normal flow: install session, forward */
        /* ... normal path ... */
    }
}
```

Policy runs unconditionally; on Permit, the DNS-reply knob picks
the sessionless admit path instead of normal session-creating
admit — **only if the resolution doesn't require NAT**. If NAT is
needed (e.g. flow hits interface SNAT or a NAT pool), the normal
session-creating admit path runs so the NAT state has a session
anchor for GC.

## Files changed

- `bpf/headers/xpf_common.h` — add `META_FLAG_DNS_REPLY_FASTPATH`.
- `bpf/xdp/xdp_conntrack.c` — tail-call to POLICY not FORWARD, set flag.
- `bpf/xdp/xdp_policy.c` — skip `create_session_*` on fast-path Permit.
- `dpdk_worker/conntrack.c` — drop `CT_DNS_REPLY` return; set meta flag.
- `dpdk_worker/pipeline.c` — policy_check unconditionally; skip conntrack_create on fast-path Permit. Remove `CT_DNS_REPLY` constant.
- `pkg/dataplane/shared_mem.h` (DPDK meta) / `dpdk_worker/shared_mem.h` — add `dns_reply_fastpath` field.
- `userspace-dp/src/afxdp.rs` — reorder DNS check and `evaluate_policy` so policy runs first.
- `userspace-dp/src/afxdp/forwarding.rs` — `allow_unsolicited_dns_reply` helper retained; unit test retained (still tests the knob's predicate).
- Reference + test configs — **unchanged**. The feature stays.
- Docs (`README.md`, `feature-gaps.md`, `test_env.md`, architecture docs) — **unchanged** (feature behaves per Junos now).

## Risk

- **BPF verifier**: new tail-call slot change in xdp_conntrack is one branch; xdp_policy adds a conditional skip of session-create. Verify stack budget (combined stack 512 bytes across call frames). `create_session_v4/v6` use scratch maps already; skipping is just a branch-around.
- **Semantic change**: transit DNS replies that previously bypassed policy now go through policy. Deployments with asymmetric DNS + no matching zone-pair rule will see drops. That's the correct behavior — operators needed a policy anyway; the bypass was a bug. Document in commit.
- **Session-table growth**: no change (fast-path still doesn't create sessions).
- **Perf**: one extra conditional on the DNS-reply path. Non-hot-path.

## Test plan

1. `make generate && make build` (BPF verifier).
2. `cargo test -p xpf-userspace-dp --release`.
3. `make test`.
4. **Functional**:
   - `allow-dns-reply` on, policy permits DNS: `nslookup` from LAN via async DNS (sessionless) → reply passes.
   - `allow-dns-reply` on, policy denies DNS: `nslookup` reply from denied source → reply dropped.
   - `allow-dns-reply` off: normal path (query → session → reply matches).
   - Crafted UDP sport=53 from unpermitted source zone: drop.
5. `cluster-lan-host + cluster-userspace-host → WAN` ping + iperf3, no regression.
6. `iperf3 -P 16 -t 60` pre/post.
7. 10-min sustained.
8. Failover: `make test-failover`.

## Scope

- In: fix policy bypass while preserving Junos-aligned allow-dns-reply semantic.
- Out: same design for other sessionless carve-outs (`allow-embedded-icmp`, GRE/ESP, fabric_fwd) — those are trust-model
  carve-outs handled by PR B (#852/#863).
