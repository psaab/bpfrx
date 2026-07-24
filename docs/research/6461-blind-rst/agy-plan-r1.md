# AGY hostile plan review — round 1 (composite of runs 9/11/12/13; runs 1-8 lost to infra: companion flag derailment, headless command-permission denial, 5m print timeout — documented retries)

## Run A (Q1+Q2, timed out mid-Q3)

 lines 2150-2175}
Let's check lines 2150-2175 of userspace-dp/src/session/mod.rs first.
 lines 3590-3620 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see where flow cache hits or slow path execution happens.
 line 350-395 of `userspace-dp/src/afxdp/flow_cache.rs`.
 let's check `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` around lines 150-180 and 320-370.
 View lines 320-370 of `flow_cache_hit.rs`.
 let's check `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` around lines 1-140 to see what happens on flow cache hit regarding session entries or counters.
 Now let's analyze all 7 questions from the user and the plan's proposed code/design!

Let's carefully examine each question in detail and find empirical evidence from the repository files.

Question 1:
"Any TCP forwarding path bypassing both the session slow path and the flow-cache hit path, making baselines stale and breaking legitimate RST teardown."

Let's check if there are ANY TCP forwarding paths in `userspace-dp`.
Where do packets enter the dataplane?
In `poll_descriptor/mod.rs` (or other poll descriptor modules / forwarding modules):
Let's check how packets are processed in `userspace-dp`.
Is every packet reaching `poll_descriptor` processed via `stage_flow_cache_hit` or slow path `lookup_with_origin`?
What about:
1. `FabricRedirect` flows / fabric-ingress packets?
Let's check how fabric-ingress packets are handled!
In `poll_descriptor`:
Let's grep for `packet_fabric_ingress` or `fabric_ingress` in `poll_descriptor`.
 Let's check lines 3440-3490 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what happens when `packet_fabric_ingress` is true or other forwarding paths!
 Let's inspect `userspace-dp/src/afxdp/forwarding/fabric.rs` or Fabric return fast path!
Wait! Notice #4453 in plan §3:
"- #4453 — same predicate excludes bare RST/FIN from the fabric return fast path."
Let's view `userspace-dp/src/afxdp/forwarding/fabric.rs` around line 427!
 Let's also check LocalDelivery paths or any other forwarding path in `userspace-dp`.
What about `LocalDelivery`?
Where does `LocalDelivery` forward or deliver packets?
Let's check `userspace-dp/src/afxdp/disposition.rs` or `poll_descriptor/mod.rs` for `LocalDelivery`.
In `LocalDelivery` (host-inbound), packets are delivered to the local stack via TUN / slow-path reinjector or TAP.
Wait, do LocalDelivery packets update `seq_hi`/`ack_hi` on `SessionEntry`?
Let's check where `account_packet` is called or where `SessionEntry` sequence tracking would be updated.
Wait, let's check Question 1 carefully:
"1. Any TCP forwarding path bypassing both the session slow path and the flow-cache hit path, making baselines stale and breaking legitimate RST teardown."

Let's trace ALL TCP packet execution paths in `userspace-dp`:
When a packet enters `poll_descriptor` (XDP ring):
Stage 1: `stage_flow_cache_hit`
- If cache HIT:
  Option A plan proposes updating `FlowCacheEntry` with `tcp_seq_hi, tcp_ack_hi` in `lookup_counted` / `stage_flow_cache_hit`.
  Wait! Is every cacheable TCP packet a cache HIT or cache MISS?
  Cache HIT packets update the cache entry tracking state (`flow_cache`).
- If cache MISS:
  The packet falls through to the slow path (`resolve_flow_session_decision` -> `lookup_session_across_scopes` / `lookup_with_origin` -> `account_packet`).
  In the slow path, `lookup_with_origin` (or `account_packet` / `update_session`) is called. The plan proposes updating `SessionEntry`'s `TcpSeqTrack` here.

WAIT! Are there ANY TCP forwarding paths that forward TCP packets WITHOUT calling either `flow_cache.lookup_counted` (flow-cache hit path) OR `lookup_with_origin` / `account_packet` (session slow path)?

Let's search for all places where TCP packets are forwarded or handled!
Let's search for packet processing loops in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` and other poll/worker files.
Let's grep for `account_packet` or `lookup_with_origin` or `flow_cache.lookup_counted`.
 Let's check where `account_packet` is called!
 Look at `flow_cache_hit.rs:312`:
`sessions.account_packet` is called on flow cache hits!
Wait! Let's check `flow_cache_hit.rs` around lines 290-315!
 Look at line 312: `sessions.account_packet` runs on flow cache hit! But wait! What TCP packets land on flow cache hit?
`packet_eligible`: `is_ack_only(meta.tcp_flags)` (flags & 0x17 == 0x10). That means ACK or PSH+ACK segments (data transfer).
Wait, why does `account_packet` run on flow cache hit? `account_packet` updates `counters` and `observed_tcp_flags`, but does `account_packet` currently update sequence tracking? No, sequence state would need to be updated.
Wait! Let's check Question 1 again:
"1. Any TCP forwarding path bypassing both the session slow path and the flow-cache hit path, making baselines stale and breaking legitimate RST teardown."

Let's check if there are any paths where TCP packets are forwarded that DO NOT go through `stage_flow_cache_hit` AND DO NOT go through `lookup_with_origin` / `account_packet`.

Let's check:
Path A: LocalDelivery (host inbound).
Does LocalDelivery go through `stage_flow_cache_hit` or `account_packet`?
Let's search for `ForwardingDisposition::LocalDelivery` in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` or `flow_cache_hit.rs`.
Wait! Is `LocalDelivery` cached in flow_cache?
Let's check `should_cache`:
Line 394: `decision.resolution.disposition.is_cacheable()`.
Let's check `is_cacheable()` in `userspace-dp/src/afxdp/disposition.rs`.
 Let's view `userspace-dp/src/afxdp/types/forwarding.rs` at line 948.
 `is_cacheable` is ONLY `ForwardCandidate` and `FabricRedirect`!
So `LocalDelivery` is NOT cacheable in flow_cache!
What happens to `LocalDelivery` packets? Every `LocalDelivery` packet MUST go to the slow path!
Wait! In the slow path, what happens to `LocalDelivery` packets?
Let's check in `poll_descriptor/mod.rs` where slow path handles `LocalDelivery`.
Let's search for `LocalDelivery` in `poll_descriptor/mod.rs`.
 Let's grep for `ForwardingDisposition::LocalDelivery` in all of `userspace-dp/src/afxdp`.
 Let's check all 7 attack questions systematically:

1. **Question 1: Any TCP forwarding path bypassing both the session slow path and the flow-cache hit path, making baselines stale and breaking legitimate RST teardown.**
Let's check:
- Flow cache hit path: handles `ForwardCandidate` and `FabricRedirect` flows (when `is_ack_only` is true). It updates `FlowCacheEntry` (which the plan adds `tcp_seq_hi, tcp_ack_hi` to).
- Session slow path (`resolve_flow_session_decision` -> `lookup_session_across_scopes` / `lookup_with_origin`): handles all cache misses and non-cacheable segments (control segments, NAT64, NPTv6 miss, LocalDelivery, etc.).
Wait! Is there ANY TCP forwarding path in `userspace-dp` that bypasses BOTH?
Let's check:
- What about XDP BPF map / eBPF kernel fast path if any? Wait, does xpf have a kernel eBPF fast path or BPF map for session lookup?
Let's search for `bpf_map` or `xsks_map` or kernel fast path in `userspace-dp`.
Let's view `userspace-dp/src/afxdp/bpf_map/mod.rs`!
 What about `LocalDelivery` or BPF XDP redirect?
Wait! Look at `bpf_map_update_elem` above!
What does BPF map update do in kernel/XDP?
Let's search where `publish_session_map_key` or `session_map_fd` is used in `userspace-dp`.
 Let's check where `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` is used!
In `userspace-dp/src/afxdp/bpf_map/mod.rs`! What does `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` do?
When XDP receives a packet, XDP checks `bpf_map`. If the action is `PASS_TO_KERNEL` (`XDP_PASS`), the XDP program passes the packet directly to the Linux kernel stack without passing it to AF_XDP (userspace-dp)!
Wait! Let's check when `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` is set!
Look at line 3-12 of `bpf_map/mod.rs`:
`uses_kernel_local_session_map_entry`:
`origin.is_peer_synced() && !metadata.is_reverse && decision.resolution.disposition == ForwardingDisposition::LocalDelivery && decision.resolution.tunnel_endpoint_id == 0`
Wait! When an entry is peer-synced (HA standby node) and LocalDelivery, it gets published to the kernel BPF map as `PASS_TO_KERNEL` so kernel XDP passes it to Linux host network stack directly!
Wait, is there any OTHER forwarding path in userspace-dp?
What about fabric return fast path?
Wait! In `userspace-dp/src/afxdp/forwarding/fabric.rs`, what is the fabric return fast path?
Let's search for `forwarding/fabric.rs` or calls to `fabric` functions in `poll_descriptor`!
In `poll_descriptor/mod.rs`:
Let's grep `fabric` in `poll_descriptor/mod.rs`.
 Let's grep for `fabric.rs` or `fabric` functions called in `poll_descriptor/mod.rs`!
 Let's check where `forwarding::fabric` is called across `afxdp`.
 Let's search for functions in `forwarding/fabric.rs`. Let's view the top of `userspace-dp/src/afxdp/forwarding/fabric.rs`.
 Let's grep for `resolve_fabric_return` or look at lines 380-450 of `userspace-dp/src/afxdp/forwarding/fabric.rs`.
 Look at `cluster_peer_return_fast_path`!
What does `cluster_peer_return_fast_path` do?
When a packet arrives on a fabric interface (`ingress_is_fabric`), `cluster_peer_return_fast_path` runs BEFORE session lookup!
Wait! Look at lines 389-440 of `forwarding/fabric.rs`.
If `cluster_peer_return_fast_path` matches (e.g. established ACK data packet coming back over fabric), it returns `(SessionDecision, SessionMetadata)` WITHOUT doing a session lookup in `SessionTable`!
Wait! Let's check where `cluster_peer_return_fast_path` is called in `poll_descriptor` or `poll_stages.rs`!
Let's search for `cluster_peer_return_fast_path` in `userspace-dp/src/afxdp`!
 Let's view `userspace-dp/src/afxdp/poll_descriptor/mod.rs` around line 928 to see what `cluster_peer_return_fast_path` does in `poll_descriptor`.
 WOW! Look at lines 927-960 in `poll_descriptor/mod.rs`!
When `cluster_peer_return_fast_path` matches on fabric-ingress packets:
1. It builds a live forward request from frame and enqueues it.
2. It returns `continue` or falls through without calling `sessions.lookup_with_origin` or `sessions.account_packet`!
Wait! Let's check lines 955-970 of `poll_descriptor/mod.rs` to see what happens after `cluster_peer_return_fast_path`!
 Let's check lines 975 to 1010 of `poll_descriptor/mod.rs`!
 Look at lines 981-1010!
On `cluster_peer_return_fast_path`:
1. It calls `install_with_protocol_with_origin(..., SessionOrigin::ReverseFlow)` ONLY if there was no session. BUT if `install_with_protocol_with_origin` returns false (session already exists!), or for established flow, what happens?
Wait! Look at `install_with_protocol_with_origin`: if an entry already exists, `install_with_protocol_with_origin` returns `false` (does not update existing session sequence state!).
And `sessions.account_packet` or `sessions.touch_if_stale` or `sessions.lookup_with_origin` is NOT called on existing sessions on this path!
And `cluster_peer_return_fast_path` runs for established TCP data/ACK packets coming from fabric return!
Furthermore, `cluster_peer_return_fast_path` does NOT touch `flow_cache` or `SessionEntry.TcpSeqTrack` for established flows!
Wait! Let's check `cluster_peer_return_fast_path` again:
`meta.protocol == PROTO_TCP && !is_initial_syn && !is_closing`!
So established TCP data/ACK packets on the cluster peer return fast path bypass BOTH `flow_cache` (they don't look up or update `flow_cache`) AND `sessions.account_packet` / `lookup_with_origin` (they bypass `SessionTable` lookup and sequence tracking updates)!
Result: On the standby/inactive node receiving fabric-return data/ACK traffic, sequence progress (`seq_hi`, `ack_hi`) is NEVER UPDATED! The baseline on that node stays completely STALE!

Wait! Let's check if there are any other paths!
What about `PASS_TO_KERNEL` in BPF map (Question 1)?
When `bpf_map` has `PASS_TO_KERNEL` for a session on a node, packets hitting XDP in the kernel are passed directly to Linux network stack. They NEVER reach userspace-dp! Neither `flow_cache` nor `SessionTable` sees any of those packets! The userspace sequence tracking baseline on that node is 100% STALE!

Now let's check Question 2:
"2. The window rule seq_hi minus 64KiB to seq_hi plus clamp(wnd,64KiB,4MiB): RFC 1982 serial arithmetic correctness, wscale-blindness tradeoff, blind-guess spray cost vs endpoint RFC 5961 immunity."

Let's carefully evaluate Question 2:
- RFC 1982 serial arithmetic:
  The plan states in §5.3:
  `lo = seq_hi - BACK_SLACK` (64KiB)
  `hi = seq_hi + FWD_SLACK` (clamp(wnd, 64KiB, 4MiB))
  Window test: `seq.wrapping_sub(lo) <= hi.wrapping_sub(lo)`.
  Let's check RFC 1982 serial arithmetic:
  For 32-bit sequence numbers: `(s1 - s2) < 2^31` means s1 is after s2.
  Here `hi - lo = 64KiB + FWD_SLACK` which is at most `64KiB + 4MiB ≈ 4.06 MiB`.
  `4.06 MiB << 2^31 (2 GiB)`.
  So `seq.wrapping_sub(lo) <= (hi.wrapping_sub(lo))` is mathematically correct under RFC 1982 serial arithmetic, with no wrap-around ambiguity since `hi - lo < 2^31`.

- wscale-blindness tradeoff:
  The middlebox usually does not see the SYN options containing `wscale` (WS opt) because:
  a) The flow might be picked up mid-stream (asymmetric routing or mid-stream pickup, #3152), or
  b) SYN options are parsed only at handshake and not stored.
  So `wnd` in `TcpSeqTrack` is the unscaled 16-bit window (max 65535 = 64 KiB).
  With window scaling (RFC 7323), real TCP window can be up to 1 GiB (typically 1–16 MiB on modern Linux/Windows).
  By clamping `FWD_SLACK` to `[64 KiB, 4 MiB]`, the middlebox assumes a forward window up to 4 MiB even if `wnd` says 64 KiB.
  Tradeoff:
  - If real window > 4 MiB (e.g. high BDP 10Gbps links with 16 MiB window), a legitimate RST sent near `RCV.NXT + 8 MiB` will fall OUTSIDE `[seq_hi - 64K, seq_hi + 4M]`. The firewall will REFUSE the demote! (Soft-fail: session stays alive until normal timeout 300s).
  - On the attack side: total window width `W = 64 KiB + 4 MiB ≈ 4.125 MiB`.
    The sequence space is `2^32 = 4096 MiB`.
    Probability of a single blind RST guess hitting the window = `4.125 / 4096 ≈ 1 / 993` (or ~1 in 1000).
    Wait! In §2, the plan claimed:
    "a ≥32768× reduction per guess for a fresh baseline"
    Wait! Is `4.125 MiB / 4096 MiB` a 32768x reduction?!
    NO! `4.125 MiB / 4096 MiB = 1 / 993`!
    Wait! Why did the plan claim 32768x reduction in §2?!
    Let's read plan §2: "whose floor is 128 KiB (64 KiB back-slack + 64 KiB forward floor) out of 2^32 — a ≥32768× reduction per guess".
    The plan calculated 32768x using 128 KiB (`2^17 / 2^32 = 1 / 32768`), but then added `clamp(wnd, 64KiB, 4MiB)` where 4 MiB makes the window 4.125 MiB!
    `4.125 MiB / 4096 MiB` is ONLY ~1/1000 reduction (a 1000x reduction, NOT 32768x)!
    An off-path attacker only needs ~1,000 blind RST packets (spray cost) to hit the 4.125 MiB window!
    If the endpoint is RFC 5961 compliant, the endpoint will DROP the RST (unless exact `SEG.SEQ == RCV.NXT`, 1 in 2^32). But the FIREWALL demotes the session to 2s reaper window after ~1,000 packets!
    So an attacker spraying ~1,000 RST packets will demote the firewall session to 2s, causing session reap and SNAT port reassignment mid-connection!

Now let's check Question 3:
"3. HA edge: a blind RST demoting a non-owner node replica which reaps and emits a Close SessionDelta — trace whether the authoritative owner honors it (userspace-dp/src/expire.rs, pkg/dataplane/userspace/eventstream.go, pkg/cluster/sync_admission.go and the 2170 DeletesStaleIgnored install-generation guard). Real hole or gated?"

Let's trace Question 3 in the codebase!
Let's look at `userspace-dp/src/session/expire.rs` around lines 342-378 (viewed earlier):
Lines 342-345:
```rust
if !metadata.is_reverse
    && !removed.origin.is_peer_synced()
    && !removed.origin.is_transient_local_seed()
{
    self.push_delta(SessionDelta { kind: SessionDeltaKind::Close, ... });
}
```
LOOK AT LINE 343:
`&& !removed.origin.is_peer_synced()`!
A peer-synced entry (`is_peer_synced() == true`) NEVER emits a `SessionDeltaKind::Close`!
Let's verify this! Replicas / peer-synced entries on a non-owner node have `origin = SyncImport` (`is_peer_synced() == true`).
When a non-owner node reaps a peer-synced replica entry, line 343 checks `!removed.origin.is_peer_synced()`. Since it is peer-synced, `push_delta` IS NOT CALLED! No Close `SessionDelta` is EVER emitted by a standby/non-owner node for a peer-synced replica!

Wait, what if a non-owner node *materialized* a shared hit via `materialize_shared_session_hit`?
Let's check `materialize_shared_session_hit` in `userspace-dp/src/afxdp/session_glue/mod.rs:1105`:
`origin: shared.origin.materialized_shared_hit_origin()`.
Let's view `materialized_shared_hit_origin()` in `userspace-dp/src/session/mod.rs` or wherever `SessionOrigin` is defined!
 Let's view `userspace-dp/src/session/entry.rs` at line 264.
 Let's check `is_peer_synced()` in `userspace-dp/src/session/entry.rs` to see if `SharedMaterialize` is considered peer-synced!
Error: timeout waiting for response

## Run B (Q3+Q4)

### Question A Verdict: Hole

1. **`is_peer_synced()` Variants**:
   `is_peer_synced()` in [entry.rs:245-250](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L245-L250) returns `true` for:
   - `SessionOrigin::SyncImport`
   - `SessionOrigin::SharedMaterialize`
   - `SessionOrigin::WorkerLocalImport`

2. **Reap Behavior for `SharedMaterialize` / `SyncImport`**:
   In [expire.rs:342-345](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L342-L345), `!removed.origin.is_peer_synced()` evaluates to `false` for unpromoted `SharedMaterialize` or `SyncImport` sessions. Thus, their reap **cannot** emit a `Close` `SessionDelta`.

3. **Promotion Condition & Blind RST Trigger**:
   - In [promote.rs:71-120](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L71-L120) (`maybe_promote_synced_session`), a peer-synced entry flips to `SessionOrigin::SharedPromote` when:
     1. `origin.is_promotable_synced()` is `true` (`SyncImport` or `SharedMaterialize`), AND
     2. `decision.resolution.disposition == ForwardingDisposition::ForwardCandidate`.
   - `SharedPromote` is **not** included in `is_peer_synced()`, so `!is_peer_synced()` becomes `true` for promoted sessions, enabling future reaps to emit `Close` deltas.
   - **Yes**, a single blind RST packet ingressing the non-owner node will trigger a lookup hit in `lookup_session_across_scopes` ([session_glue/mod.rs:1157-1238](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1157-L1238)). If the disposition evaluates to `ForwardCandidate`, `maybe_promote_synced_session` executes without validating TCP flags, flipping the session origin to `SharedPromote`. Subsequent expiry on the non-owner node will then emit an authoritative `Close` delta.

---

### Question B Verdict: 3 Sites Confirmed

The claim is **CONFIRMED**. The search across `userspace-dp/src` reveals exactly three packet-driven marking sites for `closing`/`reset` state:

1. **[userspace-dp/src/session/lookup.rs:105-176](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L105-L176)** (Lookup hit path):
   - `L123`: `entry.closing = true;` (Triggered on lookup hit when `is_closing(tcp_flags)` is true).
   - `L127`: `entry.reset |= has_rst(tcp_flags);` (Triggered on lookup hit when `has_rst(tcp_flags)` is true).
   - `L176`: `reset: is_tcp && has_rst(tcp_flags)` (Triggered when propagating TCP closing/reset state to the companion flow via `TcpStatePropagation`).

2. **[userspace-dp/src/session/mod.rs:1261-1412](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1261-L1412)** (`update_session` / `upsert_synced_with_origin` & `promote_synced_with_origin`):
   - `L1261-1262`: `entry.closing = true; entry.reset |= reset;` (Triggered during synced session promotion updates).
   - `L1404`: `record.entry.reset |= matches!(protocol, PROTO_TCP) && has_rst(tcp_flags);` (Triggered when updating/upserting a synced session with incoming TCP flags).
   - `L1412`: `record.entry.closing |= matches!(protocol, PROTO_TCP) && is_closing(tcp_flags);` (Triggered when updating/upserting a synced session with incoming TCP flags).

3. **[userspace-dp/src/session/install.rs:179-400](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L179-L400)** (Install-time seeding):
   - `L179-180`: `closing: ..., reset: ...` (Triggered upon initial forward session installation).
   - `L399-400`: `closing: ..., reset: ...` (Triggered upon initial reverse session installation).

## Run C (Q5 meta-trust + Q6 OPENING)

### Question A: Meta Trust Verdicts

* **(a) VLAN-tagged frame:** **SAFE** — `userspace-xdp/src/lib.rs:1177-1185` ([parse_l2](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs#L1177-L1185)) parses 802.1Q/802.1ad tags and increments `l3_offset` by 4 or 8 bytes. `parse_ipv4` (line 1211) and `parse_ipv6` (line 1255) add IP header length relative to `l3_offset`, and [UserspaceDpMeta](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/mod.rs#L101-L130) is populated with `parsed.l4_offset` (line 694). `meta.l4_offset` points directly to the start of the TCP header, so `l4_offset+4..+12` lands on the real TCP seq/ack fields.
* **(b) IPv6 with extension headers:** **SAFE** — `userspace-xdp/src/lib.rs:1257-1289` ([parse_ipv6](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs#L1257-L1289)) loops over extension headers (`NEXTHDR_HOP`, `ROUTING`, `DEST`, `AUTH`, `FRAGMENT`), advancing `offset` past each extension header to the transport header. `meta.l4_offset` is stamped as `offset` (line 1304), pointing to the TCP header start.
* **(c) Non-first IP fragment:** **UNSAFE** — `userspace-xdp/src/lib.rs:1209-1225` (IPv4) and `1282-1304` (IPv6). The shim leaves `meta.protocol = 6` (`PROTO_TCP`), while `meta.l4_offset` is set to `l3_offset + ihl` (or `l3 + 40 + frag`), which points into arbitrary fragment payload. `parse_l4` (lines 1492–1504) does not check the fragment offset and can succeed if payload bytes coincidentally satisfy `data_offset >= 20`. If payload byte 13 satisfies `is_ack_only`, `packet_eligible` returns `true`, causing `meta.l4_offset+4..+12` to read raw fragment payload rather than TCP seq/ack.
* **(d) Short/truncated frame:** **SAFE** — `userspace-xdp/src/lib.rs:1492` ([parse_l4](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs#L1492)) enforces a strict 14-byte `read_bytes` check (`l4_offset + 14 <= data_end`). Short/truncated frames with `< 14` L4 bytes fail `parse_l4`/`parse_packet` and are dropped by XDP (`USERSPACE_FALLBACK_REASON_PARSE_FAIL`, lines 422–424), never reaching userspace or flow cache. If parsed, the 14-byte minimum check guarantees `l4_offset + 12` is in-bounds and lands on TCP seq/ack.

---

### Question B: OPENING Rule Verdict

**Verdict:** **SOUND**

* **Linux RST,ACK acceptance:** **YES.** Real Linux stacks (and RFC 793/9293 §3.5.2) responding to a SYN on a closed port send `RST,ACK` with `seq = 0`, `ack = syn_isn + 1`, and `ACK = 1`. The rule `(ACK set and ack == client_isn + 1)` evaluates to `true` and accepts Linux's RST,ACK.
* **Refused placements:** Non-standard middleboxes or buggy stacks that send a bare `RST` (`ACK = 0`) with `seq = 0` or `seq = client_isn` (violating RFC 793 requiring `ACK = 1` and `ack = seq + 1` when resetting an un-ACKed SYN) will be refused by the rule.
* **Impact of refusal:** **NONE.** A refusal only withholds the firewall session demote; the packet is still delivered to the destination endpoint. The destination host processes the RST and closes the TCP socket normally, while the firewall session cleanly expires via its short half-open session timer. Delivery and socket behavior are completely unaffected.

## Run D (Q7 option tradeoff)

### Design-Tradeoff Analysis: Issue 6461 (TCP RST/FIN Sequence Validation)

---

### 1. Comparative Analysis Matrix

| Metric / Dimension | Option A: State-Only Gate (Always On) | Option B: Active Drop & Challenge-ACK (Junos Parity) |
| :--- | :--- | :--- |
| **Packet Handling Policy** | **Always Forward** packet; refuse firewall session demotion if sequence is out-of-window / implausible. | **Drop** out-of-window RST/FIN at firewall; generate synthetic **Challenge-ACK** toward RST sender. |
| **Endpoint Protection** | Mitigates session-state table exhaustion / early reap at firewall level. *Does not shield non-RFC 5961 endpoints.* | Full protection: shields legacy/non-RFC 5961 endpoints from off-path teardown attacks. |
| **Dataplane Hot-Path Cost** | Negligible. Pure state inspection in userspace slow-path. | High. Requires UMEM buffer allocation, packet construction, checksum calculation, and rate-limiting on AF_XDP TX ring. |
| **Blast Radius of Stale State** | **Zero packet delivery impact.** Legitimate RST reaches endpoint; endpoint tears down even if firewall session lingers. | **High (Blackholing).** Legitimate RST dropped by firewall if tracking lags; connection hangs in half-open state. |
| **Asymmetric / HA Sensitivity** | Safe. Fail-open semantics prevent packet drop during asymmetric routing or HA sync lag. | Fragile. Dropping packets on sequence desync risks breaking valid traffic flows under asymmetric or fabric re-routes. |

---

### 2. Deep-Dive Evaluation Across 5 Dimensions

#### (1) Blast Radius of False Refuse & Stale Baselines
* **Option A**: If the firewall's sequence tracking window is stale or out-of-sync (e.g., due to pure-ACK fast-path bypass, HA sync latency, or restart), Option A refuses session demotion *inside the firewall table* but **still forwards the RST to the destination**.
  * **Result**: If the RST was legitimate, the receiver processes it and closes the TCP connection. The firewall session lingers until idle timeout. End-to-end communication and explicit connection teardowns are **never broken**.
* **Option B**: If sequence tracking drifts, Option B **drops** the legitimate RST packet and transmits a challenge-ACK.
  * **Result**: The initiating endpoint considers the connection closed, while the receiving endpoint stays open waiting for data. Firewall blackholes the explicit teardown, causing application hangs and broken connection cleanup.

#### (2) Challenge-ACK Generation Cost & Rate-Limiting (25Gbps AF_XDP Hot Path)
* **Option A**: Executes in the slow path as a light state check against session sequence bounds. Requires no frame allocation, header construction, or TX ring interactions.
* **Option B**: In an AF_XDP userspace architecture:
  * Emitting synthetic challenge-ACKs requires fetching free UMEM frames, building Eth/IP/TCP headers, computing L3/L4 checksums, and enqueueing to AF_XDP TX rings.
  * Under a high-rate off-path RST flood, unthrottled challenge-ACK generation can exhaust UMEM frame pools or saturate CPU cores handling TX rings. Implementing per-flow or global token-bucket rate limiters adds additional state lookup and lock/atomic contention overhead on the hot path.

#### (3) Interaction with Asymmetric Routing & HA Fabric
* **xpf Architecture Constraints**:
  1. **Flow Cache Fast Path**: Bulk pure-ACK traffic bypasses the session table. If the session table's sequence window is updated periodically or on slow-path hits, its sequence window can lag behind actual fast-path traffic.
  2. **HA Chassis Cluster & Fabric**: Cross-chassis forwarding and asymmetrical ingress/egress (Node 0 sees C$\rightarrow$S, Node 1 sees S$\rightarrow$C via fabric) make strict sequence window tracking prone to gaps during node failovers or asymmetric route changes.
* **Impact**: Option A's fail-open design tolerates asymmetric drift without packet loss. Option B risks dropping valid traffic whenever asymmetric routing or fast-path sequence lag occurs.

#### (4) Junos-Parity & Operator Expectations
* In Junos OS (SRX series):
  * **Default Behavior**: Junos demotes sessions on 5-tuple match without strict RST sequence validation (identical to `xpf` today).
  * **Knob**: `set security flow rst-sequence-check` enables Option B behavior, but it is **disabled by default** in standard Junos configurations due to false-drop risks in complex networks.
* Shipping Option A as an always-on default aligns with standard security firewall default behavior while avoiding unexpected packet drops.

#### (5) Staging Strategy: Option A as a Prerequisite for Option B
Option A provides the necessary foundational tracking mechanism without operational risk:
1. **Telemetry & Validation**: Deploys per-direction sequence/ACK window tracking into `xpf` session and flow-cache data structures safely.
2. **Real-World Calibration**: Allows monitoring of sequence validation metrics (false refusal rates vs valid demotions) across complex HA and asymmetric customer topologies **with zero risk of packet loss**.
3. **Paves the Way for Option B**: Once tracking accuracy across fast-path and HA failover is proven, Option B can be safely added as an opt-in CLI knob (`rst-sequence-check`).

---

### 3. Final Verdict & Top Risks

> **VERDICT: Implement Option A First.**
>
> Deliver Option A (state-only gate, always-on passthrough sequence check) for the first PR. Treat Option B (active drop + challenge-ACK) as a subsequent opt-in feature knob (`rst-sequence-check`).

#### Top Two Risks of Choice (Option A-First):

1. **Unshielded Non-RFC 5961 Endpoints**: 
   * *Risk*: Off-path attackers with a guessed 5-tuple sending an out-of-window RST will fail to demote the `xpf` firewall session, but because `xpf` still forwards the packet, endpoints lacking RFC 5961 validation will process the RST and tear down their TCP connection.
2. **Session Drift / Lingering Firewall State**:
   * *Risk*: If a valid endpoint RST falls outside the firewall's tracked sequence window (due to fast-path ACK sequence lag or HA sync delay), Option A refuses session demotion in the firewall while forwarding the packet. The endpoints tear down, but the `xpf` session remains active until idle timeout, taking up session table capacity.
