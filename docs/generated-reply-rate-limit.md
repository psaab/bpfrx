# Generated-reply rate limiting (userspace-dp)

SSOT for the token-bucket rate limiter on **locally-generated error/reset
replies** in the AF_XDP userspace dataplane
(`userspace-dp/src/afxdp/icmp_ratelimit.rs`). This is distinct from the screen
flood limiter (`userspace-dp/src/screen/rate.rs`, #3607), which detects inbound
floods; this one bounds the RATE at which the box AMPLIFIES a trigger into a
generated reply.

## What is limited

Three locally-originated reply generators run on cold exception paths, each
building + enqueuing a reply after the RFC-suppression and output-classification
gates:

| Reason | Generator | Rate-limit scope |
|--------|-----------|------------------|
| `TimeExceeded` | ICMPv4 Time Exceeded / ICMPv6 Hop-Limit Exceeded (`icmp::build_local_time_exceeded_request`) | Single global bucket |
| `PacketTooBig` | ICMPv4 Frag-Needed / ICMPv6 Packet Too Big (PMTUD, #2301/#2330) | Single global bucket |
| `Reject` | Policy `then reject`, firewall-filter / lo0 `then reject`, and a zone `tcp-rst` deny → TCP RST or ICMP/ICMPv6 admin-prohibited unreachable (`poll_descriptor::reject_reply`) | **Per ingress (from) zone (#3618)** |

Without a limiter, an attacker driving a flood of TTL-1 packets, oversized DF=1
packets, or rejected flows makes the box emit one generated reply per trigger
packet — a CPU / TX amplification sink and a reflection vector (the reply is
addressed to the trigger's spoofable source). The limiter is modelled on Linux's
`net.ipv4.icmp_msgs_per_sec` (default 1000/s): a bounded-state GCRA token bucket,
no per-source/per-destination map, so there is no attacker-driven map growth.

The `TokenBucket` is a single-atomic-word GCRA (theoretical-arrival-time); refill
and consume commit together in one CAS so concurrent workers can never
double-credit or over-admit (#2955). Default rate/burst are compile-time
constants `DEFAULT_RATE_PER_SEC = DEFAULT_BURST = 1000`; a zero rate disables the
limiter.

## #2472 → #3618: why the Reject reason is per-zone

`#2472` introduced a **single global** bucket per reason. For the Reject reason
that global bucket coupled all zones: a rejected-flow flood ingressing **one**
(e.g. untrusted WAN) zone drained the shared bucket, so a legitimate policy /
filter reject in a **different** (e.g. trusted/internal) zone fail-closed to a
silent drop even though that zone was not under attack. The aggregate cap was
being asked to also deliver per-zone fairness, and it could not — an operator
troubleshooting a policy misconfiguration in the quiet zone never saw that zone's
reject diagnostic while the busy zone stayed flooded.

`#3618` splits the Reject reason into **one bucket per configured zone**:

- `ForwardingState::reject_buckets: FastMap<u16, Arc<TokenBucket>>` — one GCRA
  bucket per configured zone id, built in `forwarding_build::zones::populate_zones`
  from the SAME validated zone set as `zone_id_to_name`. Cardinality = configured
  zones (the Go control plane caps distinct zones at `MaxUsableZoneID = 65533`),
  so it is config-bounded, never attacker-growable.
- At the reject call site (`poll_descriptor::reject_reply::enqueue_reject_reply`)
  the ingress **from-zone** is resolved from the LOGICAL ingress unit ifindex via
  `ifindex_to_zone_id` (the same SSOT the #3976 reply build and #3035 output
  classify key off, so a VLAN sub-interface keys its own zone's bucket, and a
  non-VLAN port resolves identically through the parent mapping).
- An unzoned (id 0) or otherwise-unknown from-zone falls back to the
  process-global `REJECT_FALLBACK_BUCKET` — a real bucket, so the gate is **never
  fail-open** and never panics on a missing key. Unzoned/unknown rejects share
  that one budget (the rare/degenerate case).

Zone ids are sparse `u16` stable name-hashes over `[0, 65533]` (NOT dense
`[0, 64)`), so the map is keyed by zone id, not a dense array.

### Why this does not weaken the anti-amplification cap

The realistic reflection attacker floods ONE ingress path (the WAN zone); each
zone's bucket still caps that path at 1000/s — **identical** to the pre-#3618
global cap for the single-ingress case. Per-zone buckets remove the cross-zone
starvation while preserving the per-ingress-zone cap. Reaching the `N × 1000/s`
aggregate requires an attacker already inside the trust boundary driving rejects
across many zones at once (a multi-VLAN trunk / compromised internal host), who
can emit far more damaging traffic than reflected RST/ICMP backscatter; each zone
is still individually capped. A global second-level ceiling for that east-west
amplifier is a filed optional follow-up, not built here.

### TimeExceeded / PacketTooBig stay global

TE/PTB keep their single global-per-reason bucket. Their generator sites
(`icmp.rs`, `tx/dispatch/mod.rs`) do not cleanly carry an ingress zone id (TE is
built deep in the ICMP builder, PTB in the TX dispatch path); scoping them
per-zone is a separate change with its own zone plumbing. Out of scope for #3618.

## Lifetime / sharing model (why `Arc<TokenBucket>`)

All workers gate against the SAME per-zone bucket: each worker holds an
`Arc<ForwardingState>` loaded from the shared `ArcSwap` (`load_full()`), so within
one forwarding generation they share the one `ForwardingState` instance and its
atomics — the cap is per-zone, not per-worker.

The buckets are held behind `Arc` (not plain values) because the coordinator
re-stores a CLONE of the forwarding state at runtime cadence (fabric refresh,
`snapshot_refresh.rs`), not only on config commit. A plain-value clone would
snapshot the coordinator-side (stale, worker-untouched) atomics on every refresh
and effectively RESET the limiter. `Arc<TokenBucket>` is shared by reference
across `ForwardingState::clone()`, so the limiter state persists across a refresh.
A genuine config rebuild re-runs `populate_zones` and installs fresh buckets —
**reset-on-commit**, which is accepted for a diagnostic limiter (a commit is rare,
operator-initiated, and a fresh burst allowance right after a commit is benign).

## Observability (metric unchanged)

The aggregate `reject_rate_limited_total` is a SINGLE process-global atomic
(`REJECT_RATE_LIMITED_TOTAL`) bumped on ANY per-zone (or fallback) deny — NOT a
sum over the per-zone buckets' fields — so `rate_limited_count(Reject)` stays an
O(1) atomic load and the coordinator status / Prometheus
`xpf_userspace_reject_rate_limited_total` wire contract is UNCHANGED by the
per-zone split. Each per-zone `TokenBucket` keeps its own `rate_limited` field
for OPTIONAL future per-zone attribution; the aggregate metric never reads it.

The per-source split (#3661) — `policy_reject_rate_limit_drops` /
`filter_reject_rate_limit_drops` — is orthogonal and still sums to the
source-neutral aggregate.

## Fail-closed invariants preserved

- Every failure leg (bucket-empty, budget-exhausted, unparseable, output-filter
  drop) still returns false and the caller silently drops the trigger packet —
  the reject reply is a courtesy; the trigger is dropped regardless, so this is a
  fairness/observability fix, never a good-traffic-drop or security bypass.
- A missing zone id maps to the fallback bucket, never a fail-open skip.
- #3656: a frame that can never produce a reply (inbound RST, inbound ICMP error,
  non-first fragment, ...) is proven unreplyable BEFORE the token is consumed, so
  a flood of unreplyable frames cannot drain a zone's bucket (H11).
