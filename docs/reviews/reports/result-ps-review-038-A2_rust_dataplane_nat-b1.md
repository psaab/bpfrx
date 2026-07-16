# Triage result — ps-review-038-A2_rust_dataplane_nat (batch 1/1)

- **Subsystem**: Rust userspace-dp NAT (nat/ pool+dest+static+source, nat64, nptv6)
- **Base in review**: d4506d4450e23f9a3fc572206b3c82f6b6c99029
- **Verified against**: origin/master @ **57d24d9aed4b64680831a1765a128921e79c00f7** (fetched); base is ~current master, minus a handful of merges — every cited symbol re-confirmed on 57d24d9.
- **Real bpfrx or avacado?** REAL bpfrx. All cited line numbers land exactly (reserve_flow:724, reserve_synced_source_nat_allocation:748, sticky_pool_index:905, expand_pool_address:425, ipv6_l4_offset_and_protocol:928). No agy/avacado tells (no redacted template, no /home/ps/git/xpf path, dedup index is accurate against this session's backlog).
- **Outcome counts**: 5 findings → **1 GENUINE-RESIDUAL (Low)**, 3 NEGATIVE (self-declared), 1 DELIBERATE. 0 confabulated, 0 dup, 0 already-fixed.

This is a high-quality, largely self-refuting audit: 4 of 5 "findings" are explicitly labelled negative-result / low-confidence by the author, and the module-by-module log is an honest read of hardened code. Only L-001 is a substantive residual.

---

## Per-finding disposition

### [L-001] HA-synced source-NAT reservation drops persistent-NAT lease on standby — **GENUINE-RESIDUAL (Low)**

**Verified real and accurate.** Traced the full path on 57d24d9:

- `allocator.rs:724 reserve_flow(...)` unconditionally inserts `LiveAllocation { translated, persistent_key: None }` (line 762). It marks `owner_by_translated` + `addr_index_by_translated` + `live_by_flow`, but never touches `persistent_by_source`.
- `source.rs:748 reserve_synced_source_nat_allocation(...)` builds only `TranslatedTuple{ip,port}` + `SourceNatFlowKey` and calls `reserve_flow`. It never derives `persistent_nat`, `persistent_nat_permit`, or a `PersistentSourceKey` — the synced NatDecision wire carries `rewrite_src`/`rewrite_src_port` only.
- The reuse gate that would be short-circuited on the promoted node lives in `allocator.rs:348-405`: `allocate_translation` computes `persistent_key = persistent_nat.then(|| flow.persistent_source_key(permit))` and reuses the lease's translated tuple ONLY if `persistent_by_source.contains_key(&key)`. Because the standby never inserted a lease, a post-failover second flow from the **same source (ip:port)** to a **different remote** in `permit-any-remote-host` mode (key `remote: None`) misses the lease and allocates a fresh translated port at `allocator.rs:446-467`.

**Reachability confirmed, not misread of a guarded path.** The `live_by_flow` fast-path (`allocate_translation`) only matches the identical 5-tuple, so it does NOT rescue the same-source/different-remote case — the flow key differs in `dst_ip`/`dst_port`. This is exactly the endpoint-independent-mapping (EIM) contract that persistent-NAT any-remote-host promises, and it degrades to endpoint-dependent for new flows on the promoted node.

**Not a dup.** Confirmed against the session backlog and git log:
- #4388 = SNAT HA **port reservation** (collision prevention) — that is precisely the non-persistent `reserve_flow` path; it deliberately reserves the port but not the lease.
- #4512 (`a1684d005`, merged #4564) = NAT64 HA cross-node **port** reservation — NAT64 fixes `persistent_nat=false` (see `allocate_nat64_pool_port` at source.rs:806), so it is orthogonal.
- #4565 = NAT64 **reverse-translation** info sync — different data.
- #4381/#4518 = NAT64 allocator plumbing.
- No open/merged issue in #4517-#4581 or the open set (#2387 #4455 #4478 #4498 #4549 #4555 #4559 #4565 #4566 #4569 #4573 #4576 #4577 #4578 #4579) covers persistent-NAT **lease** HA sync. `git log --grep=persistent` shows only WG/DDNS hits, no NAT-lease HA work.

**Severity = Low (agree with author), why not higher:**
- No memory-safety, no crash, no session hijack, no security bypass. The surviving synced flow keeps its reserved port (that is what #4388 already guarantees) — no reply mis-delivery.
- Blast radius is bounded to: (a) persistent-NAT-configured pools only, (b) post-failover window only, (c) a *second* flow that shares a source port with an already-synced flow but targets a different remote — realistically UDP SIP/STUN/P2P where source-port 5060 is reused across peers; TCP ephemeral ports are not reused while the connection is live, further narrowing this to UDP EIM consumers.
- In `target-host[-port]` mode the effect is only an extra pool port consumed (the lease key includes `remote`, so the new flow to a different remote correctly wants a distinct mapping anyway) — pure minor waste, no contract break.
**Why not lower (INFO):** it is a genuine, observable divergence from the Junos persistent-NAT EIM contract after failover, with a concrete crafted scenario, not a stylistic nit.

**Lane = needs-research.** The fix is a design decision, not a mechanical patch: either (a) extend the HA session-sync wire to carry `persistent_nat` + `persistent_nat_permit` + the derived `PersistentSourceKey` and add a `reserve_flow_persistent` variant that inserts into BOTH `live_by_flow` and `persistent_by_source` with correct `remote` scope and expiry, OR (b) explicitly accept "persistent-NAT EIM resets on failover" and document it as a known limitation next to the sticky-hash HA note. Choice (a) touches Go control-plane wire + Rust dataplane; choice (b) is a docs-only decision. Because the sync-vs-document tradeoff is unresolved and spans the wire format, this is needs-research rather than a clean go/rust lane.

---

### [L-002] NAT64 EH-overflow fail-closed parity — **NEGATIVE (self-declared)**

Author explicitly labels this a negative-result record. Verified independently: `ipv6_l4_offset_and_protocol` (nat64.rs:928) bounds its walk to `MAX_IPV6_EXT_HEADERS` and returns `None` (fail-closed) at the bound; `translate_embedded_v6_to_v4` reuses the same helper; `parse_embedded_v6_l4` in `afxdp/icmp_embed/parse.rs` uses the same constant and same fail-closed. This aligns with the #4435/#4533 EH-walk hardening already merged. No skew, no finding. Note the review's own reference to #4555 (userspace-**xdp** shim MAX_EXT_HDRS=6 vs userspace 8) is correctly excluded — that is the shim, a different file, and remains open separately.

### [L-003] expand_pool_address wrapping_add — **NEGATIVE (self-declared)**

Author self-refutes at Confidence: Low. Verified: `source.rs:444-457` guards `host_bits >= 64 || (1u128 << host_bits) > MAX_POOL_PREFIX_HOSTS` before enumerating, and `IpNet::network()` returns the masked base so low host bits are zero; `base.wrapping_add(i)` for `i < 2^host_bits` (≤65536) cannot wrap past u128 range even at the top of the address space. No bug.

### [L-004] sticky_pool_index uniformity for small pools — **DELIBERATE / NOT-MATERIAL**

The exact concern (FxHash correlating adjacent source IPs on tiny pools) is **explicitly addressed in-code** at `allocator.rs:908-914`: the fixed salt `b"xpf-userspace-snat-address-persistent-v2"` is seeded precisely because "FxHash of a small contiguous run can correlate adjacent addresses," and the doc comment (allocator.rs:886-904) states this is a **load-distribution hash, not a security primitive** — the only contract is determinism + cross-node identity, both of which hold. The SHA-256→FxHash swap was the deliberate #2349 perf change. The review itself rates it Low and its "fix" is *add a statistical uniformity test* — an observability/test-coverage nicety, not a correctness defect. No behavioral bug; classified DELIBERATE. (If ever driven, it is a test-only follow-up, not a code fix.)

### [L-005] nptv6 translate adjustment-word read — **NEGATIVE (self-declared, High confidence)**

Author labels this High-confidence negative result. Verified: `translate_inbound`/`translate_outbound` (nptv6.rs:321-344) rewrite prefix words `0..prefix_words` then apply the adjustment at `adj_word = if prefix_words >= 4 {4} else {3}` — the adjustment word is strictly beyond the rewritten prefix range for both /48 (words 0-2 rewritten, adj on 3) and /64 (words 0-3 rewritten, adj on 4), so the original interface-ID word is read, matching RFC 6296 §3.1. No off-by-one. Overlap/parse gates match Go #2240/#2241. No bug.

---

## Integer-truncation audit (review's requested focus)

The review's 20-row cast table was spot-checked on the two shift sites that matter (source.rs `1u64<<host_bits` v4 and `1u128<<host_bits` v6): both are guarded by an explicit `host_bits < 64/32` / `> MAX_POOL_PREFIX_HOSTS` check BEFORE the shift, so no shift-overflow and no count over-accept. i64→u64 persistent-timeout casts are all downstream of a `> 0 ? : 300` default → always positive. Confirmed no truncation residual; concur with the review's "no integer-truncation bug."

---

## Bottom line

1 genuine Low residual (L-001, persistent-NAT lease not HA-synced — novel, reachable, needs-research design decision). Everything else is a verified negative result or a documented deliberate design choice. No HIGH/MEDIUM survived; no confabulation; no dup.
