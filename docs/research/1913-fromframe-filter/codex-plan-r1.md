Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed431-6d42-7503-9772-905f442139d8
--------
user
HOSTILE PLAN REVIEW (round 1). You are an adversarial reviewer. Your job is to FAIL this plan if the architecture/diagnosis is wrong. Do NOT rubber-stamp. Do NOT KILL without a concrete counter-example with quoted file:line evidence.

Repo: /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter (branch research/1913-fromframe-filter, off origin/master d535f1f3e).
Plan: docs/research/1913-fromframe-filter/plan.md

Context: issue #1913. The trailing maybe_reinject_slow_path_from_frame at userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814 has NO disposition allow-list, unlike the desc-wrapper maybe_reinject_slow_path at userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90. The plan claims PolicyDenied/HAInactive/DiscardRoute frames are leaked to the kernel FIB, recommends Path A (call-site gate via shared predicate), and REJECTS Path B (filter inside _from_frame) because dispatch/mod.rs:225 deliberately passes FabricRedirect to bypass the filter.

Verify HOSTILELY, reading the actual source:
1. Is the §2.2 PolicyDenied -> kernel-FIB-forward trace CORRECT? Walk extract_l3_packet_with_nat (slow_path.rs:307), the tunnel gate (slow_path.rs:~196), and enqueue. Is there an EARLIER enforcement point that drops denied packets before mod.rs:2156? If yes, the bug is benign and the plan over-claims severity.
2. Is the §2.6 claim TRUE that dispatch/mod.rs:225 passes FabricRedirect through _from_frame on purpose (so Path B would break it)? Read dispatch/mod.rs:220-250.
3. Is Path C correctly rejected (does the desc-wrapper re-slice the original UMEM frame, re-introducing #1885)? Check the wrapper signature at slow_path.rs:80-113.
4. Any disposition reaching :2814 NOT accounted for in the plan's table (§2.1)? Are there early continue/return between :2156 and :2814 that I mis-tabulated?
5. Is the recommended call-site guard actually sufficient, or does leaving _from_frame unfiltered invite the next regression (altitude question)?

Output VERDICT: PLAN-READY or PLAN-NEEDS-REVISION or PLAN-KILL, with quoted file:line evidence for every finding. Be specific.
codex
I’ll read the plan and the exact call paths it cites, then I’ll verify the disposition flow against line-numbered source rather than trusting the summary.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '180,270p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   180	                if let Some(frame) = (unsafe { &*ingress_area })
   181	                    .slice(request.desc.addr as usize, request.desc.len as usize)
   182	                {
   183	                    frame
   184	                } else {
   185	                    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   186	                    continue;
   187	                }
   188	            }
   189	            PendingForwardFrame::Prebuilt(_) => unreachable!(),
   190	        };
   191	        if let Some(result) = enqueue_sampled_mirror_clone(
   192	            left,
   193	            ingress_index,
   194	            ingress_binding,
   195	            right,
   196	            binding_lookup,
   197	            mirror_targets,
   198	            forwarding,
   199	            request.meta.ingress_ifindex as i32,
   200	            request.meta.ingress_vlan_id,
   201	            request.ingress_queue_id,
   202	            source_frame,
   203	            request.meta,
   204	            request.flow_key.as_ref(),
   205	        ) {
   206	            record_mirror_clone_result(&ingress_binding.live, result, source_frame.len());
   207	        }
   208	        let expected_ports = request.expected_ports;
   209	        let ingress_umem_ptr = ingress_binding.umem.allocation_ptr();
   210	        let Some(target_binding) = resolve_pending_forward_target_binding(
   211	            left,
   212	            ingress_index,
   213	            ingress_binding,
   214	            request.ingress_queue_id,
   215	            right,
   216	            binding_lookup,
   217	            target_binding_index,
   218	            request.target_ifindex,
   219	        ) else {
   220	            // No XSK binding for the target interface.  Normally fabric
   221	            // parents have bindings; this is a safety-net fallback in case
   222	            // the binding is not yet ready or bind() failed.
   223	            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
   224	                if matches!(request.frame, PendingForwardFrame::Owned(_)) {
   225	                    maybe_reinject_slow_path_from_frame(
   226	                        ingress_ident,
   227	                        ingress_live,
   228	                        slow_path,
   229	                        local_tunnel_deliveries,
   230	                        source_frame,
   231	                        request.meta,
   232	                        request.decision,
   233	                        recent_exceptions,
   234	                        "slow_path",
   235	                        forwarding,
   236	                    );
   237	                } else {
   238	                    maybe_reinject_slow_path(
   239	                        ingress_ident,
   240	                        ingress_live,
   241	                        slow_path,
   242	                        local_tunnel_deliveries,
   243	                        unsafe { &*ingress_area },
   244	                        request.desc,
   245	                        request.meta,
   246	                        request.decision,
   247	                        recent_exceptions,
   248	                        forwarding,
   249	                    );
   250	                }
   251	                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   252	                continue;
   253	            }
   254	            dbg.no_egress_binding += 1;
   255	            if cfg!(feature = "debug-log") && dbg.no_egress_binding <= 3 {
   256	                debug_log!(
   257	                    "DBG NO_EGRESS_BINDING: target_ifindex={} ingress_if={} ingress_q={}",
   258	                    request.target_ifindex,
   259	                    ingress_ident.ifindex,
   260	                    request.ingress_queue_id,
   261	                );
   262	            }
   263	            record_exception(
   264	                recent_exceptions,
   265	                ingress_ident,
   266	                "missing_egress_binding",
   267	                request.desc.len,
   268	                None,
   269	                None,
   270	                forwarding,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2120,2845p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2120	                                        meta,
  2121	                                        ingress_zone_override,
  2122	                                    ),
  2123	                                    worker_ctx.forwarding,
  2124	                                    worker_ctx.ha_state,
  2125	                                    apply_nat_on_fabric,
  2126	                                    &worker_ctx.rg_epochs,
  2127	                                )
  2128	                            {
  2129	                                binding.flow.flow_cache.insert(entry);
  2130	                            }
  2131	                            // ── End flow cache population ────────────────
  2132	                        } else {
  2133	                            telemetry.dbg.build_fail += 1;
  2134	                            if cfg!(feature = "debug-log") {
  2135	                                if telemetry.dbg.build_fail <= 3 {
  2136	                                    eprintln!(
  2137	                                        "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
  2138	                                        decision.resolution.egress_ifindex,
  2139	                                        decision.resolution.tx_ifindex,
  2140	                                        decision.resolution.neighbor_mac.map(|m| format!(
  2141	                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2142	                                            m[0], m[1], m[2], m[3], m[4], m[5]
  2143	                                        )),
  2144	                                        decision.resolution.src_mac.map(|m| format!(
  2145	                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2146	                                            m[0], m[1], m[2], m[3], m[4], m[5]
  2147	                                        )),
  2148	                                        desc.len,
  2149	                                        meta.protocol,
  2150	                                    );
  2151	                                }
  2152	                            }
  2153	                        }
  2154	                    } else {
  2155	                        // Debug: count non-forward dispositions
  2156	                        match decision.resolution.disposition {
  2157	                            ForwardingDisposition::LocalDelivery => {
  2158	                                telemetry.dbg.local += 1;
  2159	                                // Host-bound traffic (NDP, ICMP echo, BGP,
  2160	                                // GRE-to-self inner packets, etc.) is
  2161	                                // delivered by the SINGLE decap-aware
  2162	                                // reinject chokepoint at the end of this
  2163	                                // leg (`maybe_reinject_slow_path_from_frame`
  2164	                                // over `packet_frame`). #1885: this arm used
  2165	                                // to ALSO call the desc-based
  2166	                                // `maybe_reinject_slow_path` here, pairing
  2167	                                // the ORIGINAL UMEM frame (the VLAN-tagged
  2168	                                // GRE OUTER frame on a tagged underlay) with
  2169	                                // the post-decap INNER meta
  2170	                                // (`stage_native_gre_decap` rebinds `meta`
  2171	                                // but `desc` still points at the un-decapped
  2172	                                // frame) — the slice landed 4 bytes early on
  2173	                                // tagged ingress (TUN write EINVAL: payload
  2174	                                // started with the dot1q TCI tail instead of
  2175	                                // the IP version nibble) and delivered the
  2176	                                // still-encapsulated OUTER packet on
  2177	                                // untagged ingress. It was ALSO a duplicate
  2178	                                // enqueue for non-decapped local packets
  2179	                                // (both calls pass the same disposition
  2180	                                // filter). The first delivered packet
  2181	                                // creates a BPF session map entry so
  2182	                                // subsequent packets bypass userspace
  2183	                                // entirely.
  2184	                                recycle_now = true;
  2185	                            }
  2186	                            ForwardingDisposition::NoRoute => {
  2187	                                telemetry.dbg.no_route += 1;
  2188	                                if cfg!(feature = "debug-log") {
  2189	                                    if telemetry.dbg.no_route <= 3 {
  2190	                                        if let Some(flow) = flow.as_ref() {
  2191	                                            eprintln!(
  2192	                                                "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
  2193	                                                flow.src_ip,
  2194	                                                flow.forward_key.src_port,
  2195	                                                flow.dst_ip,
  2196	                                                flow.forward_key.dst_port,
  2197	                                                meta.protocol,
  2198	                                                meta.ingress_ifindex,
  2199	                                            );
  2200	                                        }
  2201	                                    }
  2202	                                }
  2203	                            }
  2204	                            ForwardingDisposition::MissingNeighbor => {
  2205	                                telemetry.dbg.missing_neigh += 1;
  2206	                                // #1651 B3: dead-host fast-fail gate. Runs at
  2207	                                // the very top of the MissingNeighbor arm,
  2208	                                // BEFORE the kernel probe, session seed, and
  2209	                                // pending_neigh buffer, so a dead host never
  2210	                                // consumes a queue slot, fires a probe, or
  2211	                                // creates a MissingNeighborSeed session.
  2212	                                //
  2213	                                // Resolved-neighbor-wins (RTM_NEWNEIGH
  2214	                                // invalidation): check static then dynamic
  2215	                                // neighbors FIRST (same order as
  2216	                                // retry_pending_neigh / lookup_neighbor_entry).
  2217	                                // If the dst is now resolved, drop any stale
  2218	                                // negative entry and fall through to normal
  2219	                                // forwarding. Otherwise, if it is still
  2220	                                // negatively cached + un-expired, recycle the
  2221	                                // frame immediately.
  2222	                                if let Some(next_hop) = decision.resolution.next_hop {
  2223	                                    let neg_key =
  2224	                                        (decision.resolution.egress_ifindex, next_hop);
  2225	                                    // neg_neigh_gate runs the resolved-wins
  2226	                                    // probe (static neighbors THEN dynamic,
  2227	                                    // same order as retry_pending_neigh /
  2228	                                    // lookup_neighbor_entry) and the TTL check.
  2229	                                    // Returns true ⇒ fast-fail this packet.
  2230	                                    let fast_fail = neg_neigh_gate(
  2231	                                        &mut binding.neg_neigh_cache,
  2232	                                        &neg_key,
  2233	                                        now_ns,
  2234	                                        || {
  2235	                                            worker_ctx
  2236	                                                .forwarding
  2237	                                                .neighbors
  2238	                                                .contains_key(&neg_key)
  2239	                                                || worker_ctx
  2240	                                                    .dynamic_neighbors
  2241	                                                    .get(&neg_key)
  2242	                                                    .is_some()
  2243	                                        },
  2244	                                    );
  2245	                                    if fast_fail {
  2246	                                        telemetry.dbg.neg_neigh_fast_fail += 1;
  2247	                                        // #1782: promote the debug counter to a
  2248	                                        // real per-binding atomic so the
  2249	                                        // cold-start capture can read it from
  2250	                                        // Prometheus. Single Relaxed fetch_add
  2251	                                        // on the existing discard path — no new
  2252	                                        // hot-path work, no behavior change.
  2253	                                        binding
  2254	                                            .live
  2255	                                            .neg_neigh_fast_fail
  2256	                                            .fetch_add(1, Ordering::Relaxed);
  2257	                                        // #1769: the negative gate suppresses
  2258	                                        // the probe + buffer below, so a dst
  2259	                                        // that lost its dynamic entry (transient
  2260	                                        // FAILED/DELNEIGH or a dropped good
  2261	                                        // RTM_NEWNEIGH) would blackhole for the
  2262	                                        // full 3s TTL with nothing nudging it
  2263	                                        // back. Route it through the shared
  2264	                                        // resolver: a single-key RTM_GETNEIGH
  2265	                                        // off the hot path caches a confirmed
  2266	                                        // REACHABLE/PERMANENT lladdr (epoch-
  2267	                                        // guarded) or probes to force kernel
  2268	                                        // revalidation on a DELAY/STALE one.
  2269	                                        // Per-key rate-limited in the resolver
  2270	                                        // thread, so a SYN storm fires at most
  2271	                                        // one GET/probe per key per window. The
  2272	                                        // hot path only pays a non-blocking
  2273	                                        // try_send here (not per-packet — this
  2274	                                        // arm fires only on the negative fast-
  2275	                                        // fail).
  2276	                                        if let Some(resolver) =
  2277	                                            worker_ctx.neighbor_resolver
  2278	                                        {
  2279	                                            // Per-binding throttle: only
  2280	                                            // clone the iface name +
  2281	                                            // try_send once per key per
  2282	                                            // RESOLVER_ENQUEUE_THROTTLE_NS
  2283	                                            // so a dead-host SYN storm does
  2284	                                            // NOT allocate per fast-failed
  2285	                                            // packet (the resolver coalesces
  2286	                                            // per-key anyway). The cheap
  2287	                                            // (i32, IpAddr) map check runs
  2288	                                            // before any clone.
  2289	                                            let throttled = matches!(
  2290	                                                binding
  2291	                                                    .resolver_enqueue_throttle
  2292	                                                    .get(&neg_key),
  2293	                                                Some(&t) if now_ns.saturating_sub(t)
  2294	                                                    < RESOLVER_ENQUEUE_THROTTLE_NS
  2295	                                            );
  2296	                                            if !throttled {
  2297	                                                if let Some(name) = worker_ctx
  2298	                                                    .forwarding
  2299	                                                    .ifindex_to_name
  2300	                                                    .get(&neg_key.0)
  2301	                                                {
  2302	                                                    resolver.enqueue(
  2303	                                                        neg_key.0,
  2304	                                                        neg_key.1,
  2305	                                                        name.clone(),
  2306	                                                    );
  2307	                                                    // Bound the throttle
  2308	                                                    // map like the negative
  2309	                                                    // cache: a /24 scan
  2310	                                                    // touches <=254 keys, so
  2311	                                                    // clear wholesale past
  2312	                                                    // the cap (best-effort —
  2313	                                                    // losing throttle for a
  2314	                                                    // few keys only risks one
  2315	                                                    // extra clone).
  2316	                                                    if binding
  2317	                                                        .resolver_enqueue_throttle
  2318	                                                        .len()
  2319	                                                        >= MAX_NEG_NEIGH_CACHE
  2320	                                                        && !binding
  2321	                                                            .resolver_enqueue_throttle
  2322	                                                            .contains_key(&neg_key)
  2323	                                                    {
  2324	                                                        binding
  2325	                                                            .resolver_enqueue_throttle
  2326	                                                            .clear();
  2327	                                                    }
  2328	                                                    binding
  2329	                                                        .resolver_enqueue_throttle
  2330	                                                        .insert(neg_key, now_ns);
  2331	                                                }
  2332	                                            }
  2333	                                        }
  2334	                                        // Fresh RX descriptor → recycle via
  2335	                                        // scratch_recycle + continue, matching
  2336	                                        // the source-NAT-failure discard
  2337	                                        // pattern. The continue skips the
  2338	                                        // recycle_now epilogue and the
  2339	                                        // session-seed/buffer below.
  2340	                                        binding.scratch.scratch_recycle.push(desc.addr);
  2341	                                        continue;
  2342	                                    }
  2343	                                }
  2344	                                // #919/#922: zero-allocation ID-native resolution.
  2345	                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
  2346	                                    worker_ctx.forwarding,
  2347	                                    meta.ingress_ifindex as i32,
  2348	                                    ingress_zone_override,
  2349	                                    decision.resolution.egress_ifindex,
  2350	                                );
  2351	                                // Borrow zone names as &str (no clone) for the
  2352	                                // string-typed downstream NAT helpers.
  2353	                                let from_zone: &str = worker_ctx
  2354	                                    .forwarding
  2355	                                    .zone_id_to_name
  2356	                                    .get(&from_zone_id)
  2357	                                    .map(|s| s.as_str())
  2358	                                    .unwrap_or("");
  2359	                                let to_zone: &str = worker_ctx
  2360	                                    .forwarding
  2361	                                    .zone_id_to_name
  2362	                                    .get(&to_zone_id)
  2363	                                    .map(|s| s.as_str())
  2364	                                    .unwrap_or("");
  2365	                                // Send ARP/NDP solicitation via RAW socket (not XSK)
  2366	                                // so the reply goes through the kernel's normal RX
  2367	                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
  2368	                                // Also reinject original packet to slow-path for kernel
  2369	                                // to forward once the neighbor is resolved.
  2370	                                // Trigger ARP/NDP resolution via kernel netlink.
  2371	                                // Adding an INCOMPLETE neighbor entry makes the
  2372	                                // kernel send its own ARP/NDP solicitation through
  2373	                                // the normal stack, which correctly handles VLAN
  2374	                                // tagging and TX offload. The netlink monitor then
  2375	                                // picks up the resolved entry instantly.
  2376	                                if let Some(next_hop) = decision.resolution.next_hop {
  2377	                                    // Only spawn ping if we don't already have a
  2378	                                    // pending probe for this (ifindex, hop).
  2379	                                    // #1771 §2.2: pending_neigh is keyed by
  2380	                                    // (egress_ifindex, next_hop), so the
  2381	                                    // "already probing this hop" dedup is a
  2382	                                    // direct contains_key (was an O(n) iter scan).
  2383	                                    let already_probing = binding.pending_neigh.contains_key(&(
  2384	                                        decision.resolution.egress_ifindex,
  2385	                                        next_hop,
  2386	                                    ));
  2387	                                    if !already_probing {
  2388	                                        let iface_name = worker_ctx.forwarding
  2389	                                            .ifindex_to_name
  2390	                                            .get(&decision.resolution.egress_ifindex)
  2391	                                            .cloned();
  2392	                                        if let Some(name) = iface_name {
  2393	                                            // Fast path: ICMP socket triggers kernel ARP
  2394	                                            // in microseconds (no fork/exec).
  2395	                                            trigger_kernel_arp_probe(&name, next_hop);
  2396	                                        }
  2397	                                    }
  2398	                                }
  2399	                                // Create the session NOW so the SYN-ACK (reverse
  2400	                                // direction) finds the forward NAT match and creates
  2401	                                // a reverse session. Without this, the SYN-ACK hits
  2402	                                // session miss → policy deny (no rule for WAN→LAN).
  2403	                                let mut pending_decision = decision;
  2404	                                let mut source_nat_release_key = None;
  2405	                                // #1861 §5.3: true when the seed install was
  2406	                                // ATTEMPTED and refused (max_sessions). Gates
  2407	                                // the pending-neighbor buffering below: a
  2408	                                // refused seed's SNAT allocation was rolled
  2409	                                // back, so replaying the buffered frame after
  2410	                                // neighbor resolution would forward it on an
  2411	                                // unreserved NAT tuple with no session. Flow-
  2412	                                // less packets (no install attempted) keep
  2413	                                // buffering as before.
  2414	                                let mut seed_install_refused = false;
  2415	                                if let Some(flow) = flow.as_ref() {
  2416	                                    // #1620: cold-path histogram pre-eval gate
  2417	                                    // (session-install slow path). Per plan v4
  2418	                                    // §4.4: scoped &mut borrow ends before eval.
  2419	                                    let (cp_sample_tag, cp_t_in) = {
  2420	                                        let cp = &mut binding.cold_path;
  2421	                                        cp.sample_phase =
  2422	                                            cp.sample_phase.wrapping_add(1);
  2423	                                        let tag = (cp.sample_phase
  2424	                                            & worker_ctx.cold_path_sample_mask)
  2425	                                            == 0;
  2426	                                        let t = if tag {
  2427	                                            crate::afxdp::cold_path_hist::sample_tsc_start()
  2428	                                        } else {
  2429	                                            0
  2430	                                        };
  2431	                                        (tag, t)
  2432	                                    };
  2433	                                    let permit = matches!(
  2434	                                        evaluate_policy_with_len(
  2435	                                            &worker_ctx.forwarding.policy,
  2436	                                            from_zone_id,
  2437	                                            to_zone_id,
  2438	                                            flow.src_ip,
  2439	                                            flow.dst_ip,
  2440	                                            flow.forward_key.protocol,
  2441	                                            flow.forward_key.src_port,
  2442	                                            flow.forward_key.dst_port,
  2443	                                            desc.len as u64,
  2444	                                        ),
  2445	                                        PolicyAction::Permit
  2446	                                    );
  2447	                                    // #1620: cold-path histogram post-eval record.
  2448	                                    if cp_sample_tag {
  2449	                                        let t_out =
  2450	                                            crate::afxdp::cold_path_hist::sample_tsc_end();
  2451	                                        let q32 = binding.cold_path.ns_per_tsc_q32;
  2452	                                        if q32 != 0 {
  2453	                                            let delta_tsc =
  2454	                                                t_out.saturating_sub(cp_t_in);
  2455	                                            let raw_ns = ((delta_tsc as u128
  2456	                                                * q32 as u128)
  2457	                                                >> 32)
  2458	                                                as u64;
  2459	                                            let baseline =
  2460	                                                binding.cold_path.wrapper_ns_baseline;
  2461	                                            let delta_ns = if raw_ns < baseline {
  2462	                                                binding
  2463	                                                    .cold_path
  2464	                                                    .wrapper_underflow_count = binding
  2465	                                                    .cold_path
  2466	                                                    .wrapper_underflow_count
  2467	                                                    .saturating_add(1);
  2468	                                                0
  2469	                                            } else {
  2470	                                                raw_ns - baseline
  2471	                                            };
  2472	                                            // #1635: direct slot map lookup;
  2473	                                            // skip the sample on a miss.
  2474	                                            if let Some(slot) =
  2475	                                                crate::afxdp::cold_path_hist::lookup_slot(
  2476	                                                    &worker_ctx
  2477	                                                        .forwarding
  2478	                                                        .cold_path_slot_map,
  2479	                                                    from_zone_id,
  2480	                                                    to_zone_id,
  2481	                                                )
  2482	                                            {
  2483	                                                binding.cold_path.record_sample(
  2484	                                                    slot,
  2485	                                                    from_zone_id,
  2486	                                                    to_zone_id,
  2487	                                                    delta_ns,
  2488	                                                );
  2489	                                            }
  2490	                                        }
  2491	                                    }
  2492	                                    if permit {
  2493	                                        let nat_match_flow = flow.with_destination(
  2494	                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
  2495	                                        );
  2496	                                        // #1852: gate pool-mode SNAT allocation
  2497	                                        // for a non-first fragment (no L4 ports).
  2498	                                        let snat_non_first_fragment = {
  2499	                                            let l3 = meta.l3_offset as usize;
  2500	                                            l3 <= packet_frame.len()
  2501	                                                && is_non_first_fragment(
  2502	                                                    &packet_frame[l3..],
  2503	                                                    meta.addr_family,
  2504	                                                )
  2505	                                        };
  2506	                                        if pending_decision.nat.rewrite_dst.is_none() {
  2507	                                            match source_nat_decision_for_flow(
  2508	                                                worker_ctx.forwarding,
  2509	                                                &from_zone,
  2510	                                                &to_zone,
  2511	                                                pending_decision.resolution.egress_ifindex,
  2512	                                                &nat_match_flow,
  2513	                                                now_ns,
  2514	                                                snat_non_first_fragment,
  2515	                                            ) {
  2516	                                                Ok(snat_decision) => {
  2517	                                                    pending_decision.nat = snat_decision;
  2518	                                                    source_nat_release_key =
  2519	                                                        Some(nat_match_flow.forward_key.clone());
  2520	                                                }
  2521	                                                Err(failure) => {
  2522	                                                    record_source_nat_failure(
  2523	                                                        telemetry,
  2524	                                                        worker_ctx,
  2525	                                                        meta,
  2526	                                                        flow,
  2527	                                                        from_zone_id,
  2528	                                                        to_zone_id,
  2529	                                                        desc.len,
  2530	                                                        &failure,
  2531	                                                    );
  2532	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2533	                                                    continue;
  2534	                                                }
  2535	                                            }
  2536	                                        } else {
  2537	                                            match source_nat_decision_for_flow(
  2538	                                                worker_ctx.forwarding,
  2539	                                                &from_zone,
  2540	                                                &to_zone,
  2541	                                                pending_decision.resolution.egress_ifindex,
  2542	                                                &nat_match_flow,
  2543	                                                now_ns,
  2544	                                                snat_non_first_fragment,
  2545	                                            ) {
  2546	                                                Ok(snat_decision) => {
  2547	                                                    pending_decision.nat =
  2548	                                                        pending_decision.nat.merge(snat_decision);
  2549	                                                    source_nat_release_key =
  2550	                                                        Some(nat_match_flow.forward_key.clone());
  2551	                                                }
  2552	                                                Err(failure) => {
  2553	                                                    record_source_nat_failure(
  2554	                                                        telemetry,
  2555	                                                        worker_ctx,
  2556	                                                        meta,
  2557	                                                        flow,
  2558	                                                        from_zone_id,
  2559	                                                        to_zone_id,
  2560	                                                        desc.len,
  2561	                                                        &failure,
  2562	                                                    );
  2563	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2564	                                                    continue;
  2565	                                                }
  2566	                                            }
  2567	                                        }
  2568	                                    }
  2569	                                    let sess_meta = build_missing_neighbor_session_metadata(
  2570	                                        worker_ctx.forwarding,
  2571	                                        from_zone_id,
  2572	                                        to_zone_id,
  2573	                                        packet_fabric_ingress,
  2574	                                        pending_decision,
  2575	                                    );
  2576	                                    let pending_installed =
  2577	                                        sessions.install_with_protocol_with_origin(
  2578	                                            flow.forward_key.clone(),
  2579	                                            pending_decision,
  2580	                                            sess_meta.clone(),
  2581	                                            SessionOrigin::MissingNeighborSeed,
  2582	                                            now_ns,
  2583	                                            meta.protocol,
  2584	                                            meta.tcp_flags,
  2585	                                        );
  2586	                                    if pending_installed {
  2587	                                        let entry = SyncedSessionEntry {
  2588	                                            key: flow.forward_key.clone(),
  2589	                                            decision: pending_decision,
  2590	                                            metadata: sess_meta,
  2591	                                            origin: SessionOrigin::MissingNeighborSeed,
  2592	                                            protocol: meta.protocol,
  2593	                                            tcp_flags: meta.tcp_flags,
  2594	                                        };
  2595	                                        publish_shared_session(
  2596	                                            worker_ctx.shared_sessions,
  2597	                                            worker_ctx.shared_nat_sessions,
  2598	                                            worker_ctx.shared_forward_wire_sessions,
  2599	                                            &worker_ctx.shared_owner_rg_indexes,
  2600	                                            &entry,
  2601	                                        );
  2602	                                        // #1789: count a failed publish
  2603	                                        // (shim misses the key -> NO_SESSION
  2604	                                        // degraded path for the seeded flow).
  2605	                                        if publish_session_map_entry_for_session(
  2606	                                            binding.bpf_maps.session_map_fd,
  2607	                                            &flow.forward_key,
  2608	                                            pending_decision,
  2609	                                            &entry.metadata,
  2610	                                        )
  2611	                                        .is_err()
  2612	                                        {
  2613	                                            binding
  2614	                                                .live
  2615	                                                .session_publish_errors
  2616	                                                .fetch_add(1, Ordering::Relaxed);
  2617	                                        }
  2618	                                        publish_bpf_conntrack_entry(
  2619	                                            conntrack_v4_fd,
  2620	                                            conntrack_v6_fd,
  2621	                                            &flow.forward_key,
  2622	                                            pending_decision,
  2623	                                            &entry.metadata,
  2624	                                            &worker_ctx.forwarding.zone_name_to_id,
  2625	                                        );
  2626	                                        publish_dnat_table_entry(
  2627	                                            &worker_ctx.dnat_fds,
  2628	                                            &flow.forward_key,
  2629	                                            pending_decision.nat,
  2630	                                        );
  2631	                                        telemetry.counters.session_creates += 1;
  2632	                                    } else {
  2633	                                        // #1861 §5.3: at-cap seed refusal. The
  2634	                                        // single-entry install IS the
  2635	                                        // transaction here (no pair); the
  2636	                                        // refusal is counted by the table's
  2637	                                        // create_drops (exported since #1861 —
  2638	                                        // admission_refused stays preflight-
  2639	                                        // only). Roll back the SNAT allocation
  2640	                                        // and drop the frame instead of
  2641	                                        // buffering it for replay.
  2642	                                        seed_install_refused = true;
  2643	                                        rollback_source_nat_allocation(
  2644	                                            &worker_ctx.forwarding.source_nat_rules,
  2645	                                            source_nat_release_key
  2646	                                                .as_ref()
  2647	                                                .unwrap_or(&flow.forward_key),
  2648	                                            pending_decision.nat,
  2649	                                            false,
  2650	                                            now_ns,
  2651	                                        );
  2652	                                    }
  2653	                                }
  2654	                                // Buffer the packet. The ICMP probe resolves ARP
  2655	                                // in ~1ms. The retry loop below re-forwards the
  2656	                                // buffered packet once the neighbor resolves via the
  2657	                                // netlink monitor. The session was already created
  2658	                                // above so the SYN-ACK reverse path works too.
  2659	                                // Total latency: ~2ms (ARP + netlink + retry).
  2660	                                //
  2661	                                // NOTE: we do NOT reinject to slow-path here because
  2662	                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
  2663	                                // in zero-copy mode (mlx5). The ICMP probe + netlink
  2664	                                // monitor + buffer-retry path bypasses this issue.
  2665	                                // #1771 §2.2: buffer one representative packet
  2666	                                // per (egress_ifindex, next_hop). Keep the
  2667	                                // OLDEST (it drives the probe/dwell clock):
  2668	                                // a duplicate for an already-buffered hop is
  2669	                                // dropped+recycled (recycle_now stays true),
  2670	                                // pinning ≤1 UMEM frame per unresolved hop.
  2671	                                // A packet with no next_hop cannot be keyed or
  2672	                                // resolved (the retry sweep needs next_hop to
  2673	                                // look up a MAC), so it is not buffered —
  2674	                                // recycled instead of held until timeout.
  2675	                                // #1861 §5.3: a refused seed is recycled, not
  2676	                                // buffered (see seed_install_refused above) —
  2677	                                // the kernel ARP probe already fired, and the
  2678	                                // next packet retries the install once the
  2679	                                // table has room, converging with the #1771
  2680	                                // duplicate-drop semantics.
  2681	                                // #1873 R-E: tunnel-marked decisions are
  2682	                                // NEVER admitted to pending_neigh. The retry
  2683	                                // path TXes buffered frames via in-place
  2684	                                // MAC/VLAN rewrite with no encapsulation, so
  2685	                                // a buffered tunnel inner packet would go out
  2686	                                // PLAINTEXT on the physical wire when the
  2687	                                // outer neighbor resolves (AGY plan r2,
  2688	                                // verified). The kernel ARP/ICMP probe above
  2689	                                // already fired, and the post-match
  2690	                                // maybe_reinject_slow_path_from_frame call
  2691	                                // routes this frame into the R-C tunnel gate
  2692	                                // (counted drop) — the #1769 resolver keeps
  2693	                                // driving the outer next-hop, and the flow
  2694	                                // recovers via retransmission once resolved.
  2695	                                // #1902 (sibling of #1885): a GRE-DECAPPED
  2696	                                // packet is NEVER admitted to pending_neigh.
  2697	                                // `desc` still references the un-decapped
  2698	                                // OUTER UMEM frame while `meta`/the decision
  2699	                                // describe the synthetic INNER frame in
  2700	                                // `owned_packet_frame`; the retry path's
  2701	                                // rewrite_forwarded_frame_in_place(pkt.desc,
  2702	                                // pkt.meta, ..) would MAC/NAT/TTL-rewrite the
  2703	                                // still-encapsulated outer packet at inner
  2704	                                // offsets and TX it toward the inner next-hop
  2705	                                // — a corrupt transmit, not a drop. The
  2706	                                // kernel ARP/ICMP probe above already fired,
  2707	                                // the trailing decap-aware
  2708	                                // maybe_reinject_slow_path_from_frame
  2709	                                // chokepoint (#1901) still hands the
  2710	                                // correctly-paired INNER packet to the kernel
  2711	                                // slow path, and the #1769 resolver +
  2712	                                // retransmission recover the flow once the
  2713	                                // neighbor resolves. Counted per binding so
  2714	                                // the live gate is observable
  2715	                                // (xpf_userspace_pending_neigh_decap_drops_total).
  2716	                                if !seed_install_refused
  2717	                                    && pending_decision.resolution.tunnel_endpoint_id == 0
  2718	                                    && pending_decision.resolution.next_hop.is_some()
  2719	                                    && owned_packet_frame.is_some()
  2720	                                {
  2721	                                    binding
  2722	                                        .live
  2723	                                        .pending_neigh_decap_drops
  2724	                                        .fetch_add(1, Ordering::Relaxed);
  2725	                                } else if !seed_install_refused
  2726	                                    && pending_decision.resolution.tunnel_endpoint_id == 0
  2727	                                    && let Some(hop) = pending_decision.resolution.next_hop
  2728	                                {
  2729	                                    let pending_key =
  2730	                                        (pending_decision.resolution.egress_ifindex, hop);
  2731	                                    // #1782: split the buffer-admission test so
  2732	                                    // the capture can tell WHY a sibling was not
  2733	                                    // buffered. The DuplicateDrop branch is the
  2734	                                    // H5 sibling drop (key already pending — the
  2735	                                    // first packet drove the kernel probe); the
  2736	                                    // CapacityDrop branch is a distinct
  2737	                                    // condition, counted nowhere here. #1771
  2738	                                    // §2.4: the decision is the pure
  2739	                                    // `pending_neigh_admission` helper so
  2740	                                    // invariant N1's "at most one buffered
  2741	                                    // packet per key" half is unit-tested;
  2742	                                    // behavior is unchanged — an insert happens
  2743	                                    // iff the key is absent AND there is room,
  2744	                                    // otherwise `recycle_now` stays true and
  2745	                                    // the frame is recycled.
  2746	                                    match pending_neigh_admission(
  2747	                                        binding.pending_neigh.contains_key(&pending_key),
  2748	                                        binding.pending_neigh.len(),
  2749	                                    ) {
  2750	                                        PendingNeighAdmission::DuplicateDrop => {
  2751	                                            binding
  2752	                                                .live
  2753	                                                .pending_neigh_duplicate_drops
  2754	                                                .fetch_add(1, Ordering::Relaxed);
  2755	                                        }
  2756	                                        PendingNeighAdmission::Buffer => {
  2757	                                            let pending_flow_key = flow
  2758	                                                .as_ref()
  2759	                                                .map(|flow| flow.forward_key.clone())
  2760	                                                .or_else(|| {
  2761	                                                    parse_session_flow_from_meta(meta)
  2762	                                                        .map(|flow| flow.forward_key)
  2763	                                                });
  2764	                                            binding.pending_neigh.insert(
  2765	                                                pending_key,
  2766	                                                PendingNeighPacket {
  2767	                                                    addr: desc.addr,
  2768	                                                    desc,
  2769	                                                    meta,
  2770	                                                    decision: pending_decision,
  2771	                                                    flow_key: pending_flow_key,
  2772	                                                    queued_ns: now_ns,
  2773	                                                    probe_attempts: 0,
  2774	                                                },
  2775	                                            );
  2776	                                            recycle_now = false;
  2777	                                        }
  2778	                                        PendingNeighAdmission::CapacityDrop => {}
  2779	                                    }
  2780	                                }
  2781	                                if cfg!(feature = "debug-log") {
  2782	                                    if telemetry.dbg.missing_neigh <= 3 {
  2783	                                        if let Some(flow) = flow.as_ref() {
  2784	                                            eprintln!(
  2785	                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
  2786	                                                "SOLICIT+SLOW",
  2787	                                                flow.src_ip,
  2788	                                                flow.forward_key.src_port,
  2789	                                                flow.dst_ip,
  2790	                                                flow.forward_key.dst_port,
  2791	                                                meta.protocol,
  2792	                                                pending_decision.resolution.egress_ifindex,
  2793	                                                pending_decision.resolution.next_hop,
  2794	                                            );
  2795	                                        }
  2796	                                    }
  2797	                                }
  2798	                            }
  2799	                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
  2800	                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
  2801	                            _ => telemetry.dbg.disposition_other += 1,
  2802	                        }
  2803	                        record_forwarding_disposition(
  2804	                            &worker_ctx.ident,
  2805	                            DispositionCounters::Hot(telemetry.counters),
  2806	                            decision.resolution,
  2807	                            desc.len as u32,
  2808	                            Some(meta),
  2809	                            debug.as_ref(),
  2810	                            worker_ctx.recent_exceptions,
  2811	                            worker_ctx.last_resolution,
  2812	                            worker_ctx.forwarding,
  2813	                        );
  2814	                        maybe_reinject_slow_path_from_frame(
  2815	                            &worker_ctx.ident,
  2816	                            &binding.live,
  2817	                            worker_ctx.slow_path,
  2818	                            worker_ctx.local_tunnel_deliveries,
  2819	                            packet_frame,
  2820	                            meta,
  2821	                            decision,
  2822	                            worker_ctx.recent_exceptions,
  2823	                            "slow_path",
  2824	                            worker_ctx.forwarding,
  2825	                        );
  2826	                    }
  2827	                } else {
  2828	                    record_disposition(
  2829	                        &worker_ctx.ident,
  2830	                        &binding.live,
  2831	                        DispositionCounters::Hot(telemetry.counters),
  2832	                        disposition,
  2833	                        desc.len as u32,
  2834	                        Some(meta),
  2835	                        worker_ctx.recent_exceptions,
  2836	                        worker_ctx.forwarding,
  2837	                    );
  2838	                }
  2839	            } else {
  2840	                telemetry.dbg.metadata_err += 1;
  2841	                binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
  2842	                record_exception(
  2843	                    worker_ctx.recent_exceptions,
  2844	                    &worker_ctx.ident,
  2845	                    "metadata_parse",

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/slow_path.rs | sed -n '1,380p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
exec
/bin/bash -lc "nl -ba docs/research/1913-fromframe-filter/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
     1	// Slow-path / exception / build-failure routing for the dispatch
     2	// loop (#1443).
     3	//
     4	// Pure code motion from `dispatch/mod.rs`. Hot-path callers reach
     5	// these helpers only on exception branches (build failure, missing
     6	// egress binding, fabric-redirect fallback), so we tag the
     7	// reinjection family `#[cold] #[inline(never)]` per AGY round-2
     8	// finding D — `#[cold]` alone does not stop LLVM from inlining a
     9	// single-caller helper and bloating the hot i-cache footprint;
    10	// `#[inline(never)]` guarantees the cold body stays out-of-line.
    11	//
    12	// The dispatch `mod.rs` re-exports
    13	// - `handle_forward_build_failure`,
    14	// - `maybe_reinject_slow_path`,
    15	// - `maybe_reinject_slow_path_from_frame`,
    16	// - `extract_l3_packet_with_nat`
    17	// at `pub(in crate::afxdp)`; `extract_l3_packet` and
    18	// `extract_l3_packet_from_frame` keep their pre-split `pub(super)`
    19	// (visible to all of `tx/`) via `pub(in crate::afxdp::tx)`.
    20	
    21	use super::*;
    22	
    23	#[cold]
    24	#[inline(never)]
    25	pub(in crate::afxdp) fn handle_forward_build_failure(
    26	    binding: &BindingIdentity,
    27	    live: &BindingLiveState,
    28	    slow_path: Option<&Arc<SlowPathReinjector>>,
    29	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    30	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    31	    dbg: &mut DebugPollCounters,
    32	    _target_ifindex: i32,
    33	    packet_length: u32,
    34	    frame: &[u8],
    35	    meta: impl Into<UserspaceDpMeta>,
    36	    decision: SessionDecision,
    37	    fallback_to_slow_path: bool,
    38	    forwarding: &ForwardingState,
    39	) {
    40	    let meta = meta.into();
    41	    dbg.build_fail += 1;
    42	    #[cfg(feature = "debug-log")]
    43	    if dbg.build_fail <= 3 {
    44	        debug_log!(
    45	            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
    46	            _target_ifindex,
    47	            packet_length,
    48	            fallback_to_slow_path,
    49	        );
    50	    }
    51	    record_exception(
    52	        recent_exceptions,
    53	        binding,
    54	        "forward_build_failed",
    55	        packet_length,
    56	        Some(meta),
    57	        None,
    58	        forwarding,
    59	    );
    60	    if fallback_to_slow_path {
    61	        maybe_reinject_slow_path_from_frame(
    62	            binding,
    63	            live,
    64	            slow_path,
    65	            local_tunnel_deliveries,
    66	            frame,
    67	            meta,
    68	            decision,
    69	            recent_exceptions,
    70	            "forward_build_slow_path",
    71	            forwarding,
    72	        );
    73	    }
    74	}
    75	
    76	#[cold]
    77	#[inline(never)]
    78	pub(in crate::afxdp) fn maybe_reinject_slow_path(
    79	    binding: &BindingIdentity,
    80	    live: &BindingLiveState,
    81	    slow_path: Option<&Arc<SlowPathReinjector>>,
    82	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    83	    area: &MmapArea,
    84	    desc: XdpDesc,
    85	    meta: impl Into<UserspaceDpMeta>,
    86	    decision: SessionDecision,
    87	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    88	    forwarding: &ForwardingState,
    89	) {
    90	    let meta = meta.into();
    91	    if !matches!(
    92	        decision.resolution.disposition,
    93	        ForwardingDisposition::LocalDelivery
    94	            | ForwardingDisposition::NoRoute
    95	            | ForwardingDisposition::MissingNeighbor
    96	            | ForwardingDisposition::NextTableUnsupported
    97	    ) {
    98	        return;
    99	    }
   100	    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
   101	        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   102	        record_exception(
   103	            recent_exceptions,
   104	            binding,
   105	            "slow_path_extract_failed",
   106	            desc.len as u32,
   107	            Some(meta),
   108	            None,
   109	            forwarding,
   110	        );
   111	        return;
   112	    };
   113	    maybe_reinject_slow_path_from_frame(
   114	        binding,
   115	        live,
   116	        slow_path,
   117	        local_tunnel_deliveries,
   118	        frame,
   119	        meta,
   120	        decision,
   121	        recent_exceptions,
   122	        "slow_path",
   123	        forwarding,
   124	    );
   125	}
   126	
   127	#[cold]
   128	#[inline(never)]
   129	pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
   130	    binding: &BindingIdentity,
   131	    live: &BindingLiveState,
   132	    slow_path: Option<&Arc<SlowPathReinjector>>,
   133	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
   134	    frame: &[u8],
   135	    meta: impl Into<UserspaceDpMeta>,
   136	    decision: SessionDecision,
   137	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
   138	    reason: &str,
   139	    forwarding: &ForwardingState,
   140	) {
   141	    let meta = meta.into();
   142	    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
   143	        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   144	        record_exception(
   145	            recent_exceptions,
   146	            binding,
   147	            "slow_path_prepare_failed",
   148	            frame.len() as u32,
   149	            Some(meta),
   150	            None,
   151	            forwarding,
   152	        );
   153	        return;
   154	    };
   155	    let packet_len = packet.len() as u64;
   156	    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
   157	        && decision.resolution.local_ifindex > 0
   158	    {
   159	        local_tunnel_deliveries
   160	            .load()
   161	            .get(&decision.resolution.local_ifindex)
   162	            .cloned()
   163	    } else {
   164	        None
   165	    };
   166	    if let Some(delivery) = tunnel_delivery {
   167	        match delivery.try_send(packet) {
   168	            Ok(()) => {
   169	                live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
   170	            }
   171	            Err(std::sync::mpsc::TrySendError::Full(_)) => {
   172	                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   173	                record_exception(
   174	                    recent_exceptions,
   175	                    binding,
   176	                    "local_tunnel_delivery_queue_full",
   177	                    frame.len() as u32,
   178	                    Some(meta),
   179	                    None,
   180	                    forwarding,
   181	                );
   182	            }
   183	            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
   184	                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   185	                record_exception(
   186	                    recent_exceptions,
   187	                    binding,
   188	                    "local_tunnel_delivery_unavailable",
   189	                    frame.len() as u32,
   190	                    Some(meta),
   191	                    None,
   192	                    forwarding,
   193	                );
   194	            }
   195	        }
   196	        return;
   197	    }
   198	    // #1873 R-C (blanket gate, plan v4): a tunnel-marked inner packet
   199	    // is NEVER enqueued to the kernel slow-path TUN. Reinjection hands
   200	    // the UNENCAPSULATED inner packet to the kernel FIB; whenever the
   201	    // kernel's view diverges from the userspace FIB (tunnel removed,
   202	    // admin-down with the route withdrawn, VRF-table divergence) the
   203	    // kernel default-routes it — a plaintext leak (AGY plan r1/r3,
   204	    // verified). The gate is unconditional: the supposed WG cold-path
   205	    // benefit of reinjection is illusory (wg_control's TUN-read encap
   206	    // hits the same EncapError::NoSession and drops, and the worker
   207	    // already armed the handshake before the build returned None —
   208	    // frame/wg.rs), and GRE outer-neighbor cold start is recovered by
   209	    // the #1769 prober + retransmission. The local_tunnel_deliveries
   210	    // branch above stays open: that is GRE local-origin INBOUND
   211	    // delivery keyed by local_ifindex, never the generic TUN.
   212	    if decision.resolution.tunnel_endpoint_id != 0 {
   213	        live.tunnel_encap_unresolved_drops
   214	            .fetch_add(1, Ordering::Relaxed);
   215	        record_exception(
   216	            recent_exceptions,
   217	            binding,
   218	            "tunnel_encap_unresolved",
   219	            frame.len() as u32,
   220	            Some(meta),
   221	            None,
   222	            forwarding,
   223	        );
   224	        return;
   225	    }
   226	    let selected_path = slow_path.cloned();
   227	    let Some(slow_path) = selected_path else {
   228	        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   229	        record_exception(
   230	            recent_exceptions,
   231	            binding,
   232	            "slow_path_unavailable",
   233	            frame.len() as u32,
   234	            Some(meta),
   235	            None,
   236	            forwarding,
   237	        );
   238	        return;
   239	    };
   240	    match slow_path.enqueue(packet) {
   241	        Ok(EnqueueOutcome::Accepted) => {
   242	            live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
   243	        }
   244	        Ok(EnqueueOutcome::RateLimited) => {
   245	            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   246	            live.slow_path_rate_limited.fetch_add(1, Ordering::Relaxed);
   247	            record_exception(
   248	                recent_exceptions,
   249	                binding,
   250	                &format!("{reason}_rate_limited"),
   251	                frame.len() as u32,
   252	                Some(meta),
   253	                None,
   254	                forwarding,
   255	            );
   256	        }
   257	        Ok(EnqueueOutcome::QueueFull) => {
   258	            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   259	            record_exception(
   260	                recent_exceptions,
   261	                binding,
   262	                &format!("{reason}_queue_full"),
   263	                frame.len() as u32,
   264	                Some(meta),
   265	                None,
   266	                forwarding,
   267	            );
   268	        }
   269	        Err(err) => {
   270	            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   271	            live.set_error(err);
   272	            record_exception(
   273	                recent_exceptions,
   274	                binding,
   275	                &format!("{reason}_enqueue_failed"),
   276	                frame.len() as u32,
   277	                Some(meta),
   278	                None,
   279	                forwarding,
   280	            );
   281	        }
   282	    }
   283	}
   284	
   285	#[allow(dead_code)]
   286	pub(in crate::afxdp::tx) fn extract_l3_packet(
   287	    area: &MmapArea,
   288	    desc: XdpDesc,
   289	    meta: UserspaceDpMeta,
   290	) -> Option<Vec<u8>> {
   291	    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
   292	    extract_l3_packet_from_frame(frame, meta)
   293	}
   294	
   295	pub(in crate::afxdp::tx) fn extract_l3_packet_from_frame(
   296	    frame: &[u8],
   297	    meta: impl Into<ForwardPacketMeta>,
   298	) -> Option<Vec<u8>> {
   299	    let meta = meta.into();
   300	    let l3 = meta.l3_offset as usize;
   301	    if l3 >= frame.len() {
   302	        return None;
   303	    }
   304	    Some(frame[l3..].to_vec())
   305	}
   306	
   307	pub(in crate::afxdp) fn extract_l3_packet_with_nat(
   308	    frame: &[u8],
   309	    meta: impl Into<ForwardPacketMeta>,
   310	    nat: NatDecision,
   311	) -> Option<Vec<u8>> {
   312	    let meta = meta.into();
   313	    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
   314	    // #1852: non-first-fragment predicate, computed once and threaded.
   315	    let non_first_fragment = is_non_first_fragment(&packet, meta.addr_family);
   316	    match meta.addr_family as i32 {
   317	        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat, non_first_fragment)?,
   318	        libc::AF_INET6 => {
   319	            // Ext-aware L4 offset via the shared helper (#1838).
   320	            let rel_l4 =
   321	                v6_rel_l4_offset(&packet, meta.l3_offset, meta.l4_offset, meta.addr_family)?;
   322	            apply_nat_ipv6(&mut packet, rel_l4, meta.protocol, nat, non_first_fragment)?
   323	        }
   324	        _ => return None,
   325	    }
   326	    Some(packet)
   327	}

 succeeded in 0ms:
     1	# Plan of Action — #1913: trailing `maybe_reinject_slow_path_from_frame` runs for ALL non-forward dispositions (incl. PolicyDenied)
     2	
     3	- **Revision**: r1 (DRAFT — pre-review)
     4	- **Issue**: #1913 (bug)
     5	- **Branch**: `research/1913-fromframe-filter`
     6	- **Mode**: `/research` — STOP at PLAN-READY. No PR, no production source touched.
     7	- **Base**: origin/master @ `d535f1f3e`
     8	
     9	---
    10	
    11	## 1. Problem statement
    12	
    13	`poll_binding_process_descriptor`'s non-forward branch ends with an
    14	**unconditional** call to `maybe_reinject_slow_path_from_frame(.., packet_frame,
    15	meta, decision, ..)` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814`,
    16	immediately after the `match decision.resolution.disposition` block at
    17	`:2156`. That match has arms for `LocalDelivery`, `NoRoute`, `MissingNeighbor`,
    18	`PolicyDenied`, `HAInactive`, and a `_` catch-all (which covers `DiscardRoute`,
    19	`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).
    20	
    21	The disposition allow-list
    22	
    23	```rust
    24	LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported
    25	```
    26	
    27	exists ONLY in the desc-based wrapper `maybe_reinject_slow_path`
    28	(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90`). The `_from_frame`
    29	variant (`slow_path.rs:129+`) has **no disposition filter** — it goes
    30	straight to: `extract_l3_packet_with_nat` → LocalDelivery tunnel-delivery
    31	branch → #1873 R-C tunnel gate (`tunnel_endpoint_id != 0`) →
    32	`SlowPathReinjector::enqueue` → kernel slow-path TUN → kernel FIB.
    33	
    34	Because the trailing call at `:2814` uses the unfiltered `_from_frame`
    35	variant, **`PolicyDenied`, `HAInactive`, and `DiscardRoute` frames are
    36	handed to the kernel FIB** when the wrapper's allow-list says they should be
    37	dropped.
    38	
    39	## 2. Blast-radius walk (verified against source @ d535f1f3e)
    40	
    41	### 2.1 The trailing chokepoint (mod.rs:2156–2820)
    42	
    43	The `match` at `:2156` falls through to `record_forwarding_disposition(...)`
    44	(`:2802`) and then unconditionally `maybe_reinject_slow_path_from_frame(...,
    45	packet_frame, meta, decision, "slow_path", ...)` at `:2814`. Per-arm exit
    46	behavior verified end-to-end:
    47	
    48	| Arm | Early `continue`? | Reaches :2814 with disposition |
    49	|-----|-------------------|--------------------------------|
    50	| `LocalDelivery` (:2157) | no | `LocalDelivery` ✅ in allow-list |
    51	| `NoRoute` (:2186) | no | `NoRoute` ✅ in allow-list |
    52	| `MissingNeighbor` (:2204) | **sometimes** — `neg_neigh_gate` fast-fail and resolved-wins paths `continue` (recycle+skip); the buffered (`recycle_now=false`) and capacity-drop paths fall through | `MissingNeighbor` ✅ in allow-list |
    53	| `PolicyDenied` (:2799) | **no** | **`PolicyDenied` ✗ NOT in allow-list — LEAK** |
    54	| `HAInactive` (:2800) | no | **`HAInactive` ✗ NOT in allow-list — LEAK** |
    55	| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `ForwardCandidate`/`FabricRedirect`/`NextTableUnsupported` |
    56	
    57	So three dispositions reach the unfiltered enqueue that the wrapper would
    58	reject: **`PolicyDenied`, `HAInactive`, `DiscardRoute`**.
    59	
    60	### 2.2 What reinjecting a `PolicyDenied` frame actually does today
    61	
    62	`decision.resolution.disposition` is overwritten to `PolicyDenied` at
    63	`mod.rs:1694`, but the rest of `decision.resolution` (egress_ifindex,
    64	next_hop, tunnel_endpoint_id) and `decision.nat` retain whatever
    65	`resolve_forwarding` produced for the flow before the policy verdict.
    66	
    67	Tracing `maybe_reinject_slow_path_from_frame` (slow_path.rs:129+) for a
    68	typical denied transit flow:
    69	
    70	1. `extract_l3_packet_with_nat(frame, meta, decision.nat)` — depends ONLY on
    71	   a parseable L3 frame + addr_family, **not** on disposition. For a normal
    72	   IPv4/IPv6 transit packet this **succeeds** and returns the L3 bytes (NAT
    73	   default = no rewrite). → not the drop door.
    74	2. `tunnel_delivery` branch: requires `disposition == LocalDelivery`. False
    75	   for PolicyDenied. → skipped.
    76	3. #1873 R-C tunnel gate: `tunnel_endpoint_id != 0`. For a normal denied
    77	   transit flow this is **0**, so the gate does NOT fire. → not the drop door.
    78	4. `slow_path.cloned()` — present in production. → not the drop door.
    79	5. `slow_path.enqueue(packet)` → writes the raw L3 packet to the slow-path
    80	   TUN → **kernel FIB forwards it** (rate-limited only by the slow-path
    81	   reinjector's token bucket).
    82	
    83	**Conclusion: a policy-denied transit packet IS forwarded by the kernel**, a
    84	zone-policy bypass bounded only by the slow-path rate limiter. Telemetry:
    85	`record_slow_path_accept` (umem/mod.rs:941) bumps generic
    86	`slow_path_packets`/`slow_path_bytes` and hits the `_ => {}` arm (no
    87	disposition-specific counter), so the leak is invisible in
    88	per-disposition slow-path metrics. The `policy_deny` debug counter and
    89	`emit_policy_deny_event` still fire (deny is "logged"), masking the fact that
    90	the packet was also forwarded. **This is a correctness/security bug, not
    91	benign.**
    92	
    93	Caveats that bound (do NOT eliminate) the leak:
    94	- Only **first packets / cold-path packets** reach userspace at all; once a
    95	  session/flow-cache entry exists the BPF fast path handles it. A denied flow
    96	  never creates a session, so EVERY packet of a denied flow is a cold-path
    97	  packet → every packet is a leak candidate (not just the first).
    98	- The slow-path reinjector rate-limits, so the leak is a throttled trickle,
    99	  not line-rate. But "throttled" ≠ "blocked": a low-rate denied flow (e.g. a
   100	  port-scan probe, a single denied SSH attempt) is forwarded in full.
   101	- The kernel FIB must actually have a route to the dst for the forward to
   102	  land; for a denied **transit** flow it usually does (that is why policy,
   103	  not routing, was the gate).
   104	
   105	### 2.3 `HAInactive`
   106	
   107	By `:2814`, the safety-net conversions (`:1762`, `:1697`) have already turned
   108	`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
   109	**residual** `HAInactive` at the match means `egress_rg == 0` (unresolved
   110	ownership) or fabric-ingress anti-loop. Reinjecting it hands the packet to the
   111	standby node's kernel FIB — on a standby that does not own the RG this can
   112	produce duplicate/asymmetric forwarding or a plaintext send from the wrong
   113	node. Lower incidence than PolicyDenied (requires the residual-HAInactive
   114	corner) but still a should-drop disposition being reinjected.
   115	
   116	### 2.4 `DiscardRoute`
   117	
   118	A packet that matched a **discard/reject route** (`forwarding/mod.rs:1279`,
   119	`:1427`) lands in the `_` catch-all and is reinjected to the kernel FIB
   120	unfiltered. Discard routes exist precisely to drop traffic; reinjection
   121	re-routes it via the kernel (which may not have the same discard route or may
   122	default-route it). Another should-drop-but-forwarded leak. NOTE: `DiscardRoute`
   123	is ALSO absent from the wrapper allow-list, confirming the intended contract
   124	is "drop".
   125	
   126	### 2.5 Buffered-MissingNeighbor duplicate (issue Q3)
   127	
   128	For the `PendingNeighAdmission::Buffer` path the frame is inserted into
   129	`pending_neigh` and `recycle_now = false` (mod.rs:2776) — but execution still
   130	falls through to the trailing `:2814` call, which (since `MissingNeighbor` IS
   131	in the allow-list) **enqueues a copy to the kernel slow path**. On neighbor
   132	resolution `retry_pending_neigh` ALSO TXes the buffered frame via in-place
   133	rewrite. → potential **duplicate first-packet delivery** (one via kernel FIB
   134	now, one via the userspace rewrite later). The in-arm comment block
   135	(mod.rs:2690+) says "the trailing decap-aware ... chokepoint (#1901) still
   136	hands the correctly-paired INNER packet to the kernel slow path" — i.e. the
   137	duplicate is currently **intentional/known** for the recovery story, but the
   138	issue flags the contradiction with the buffer's "we buffer it for retry"
   139	intent. This is a SECONDARY concern; the primary bug is PolicyDenied/
   140	HAInactive/DiscardRoute. The plan addresses it explicitly (see §5 Path A
   141	sub-decision) but does not block on it.
   142	
   143	### 2.6 Why a fix inside `_from_frame` is WRONG (critical finding)
   144	
   145	`maybe_reinject_slow_path_from_frame` has **5 production call sites** (grep):
   146	- `slow_path.rs:61` (build-failure fallback, via `handle_forward_build_failure`)
   147	- `slow_path.rs:113` (the desc-wrapper's tail, AFTER its own allow-list filter)
   148	- `poll_stages.rs:452` (IPsec local-delivery — synthesizes `LocalDelivery`)
   149	- `tx/dispatch/mod.rs:225` (**"no XSK binding" fallback — passes
   150	  `FabricRedirect`, which is NOT in the allow-list, ON PURPOSE**)
   151	- `poll_descriptor/mod.rs:2814` (the buggy trailing call)
   152	
   153	The `dispatch/mod.rs:225` site deliberately uses the unfiltered `_from_frame`
   154	variant to reinject a `FabricRedirect` when the target binding is missing —
   155	the immediately-following `else` branch (`:238`) uses the FILTERED wrapper
   156	`maybe_reinject_slow_path` for the desc path, which would REJECT
   157	`FabricRedirect`. The `_from_frame` choice there is the bypass. So:
   158	
   159	> **Adding the allow-list inside `_from_frame` would break the
   160	> `dispatch/mod.rs:225` FabricRedirect fallback** (FabricRedirect is not in
   161	> the allow-list). This rules out the "filter inside `_from_frame`" option as
   162	> a drop-in. The fix belongs at the `mod.rs:2814` call site (or via a shared
   163	> predicate applied there), NOT inside the shared helper.
   164	
   165	## 3. Severity
   166	
   167	**Medium-High security/correctness bug.** A configured zone-policy DENY is
   168	silently bypassed for cold-path (sessionless) packets: every packet of a
   169	denied flow is reinjected to the kernel FIB and forwarded, rate-limited only
   170	by the slow-path token bucket, and invisible in per-disposition telemetry.
   171	Pre-existing since the #1054 extraction (`cc31ffb96`); untouched by #1911.
   172	
   173	## 4. Goals / non-goals
   174	
   175	**Goals**
   176	- The trailing reinject at `mod.rs:2814` must NOT enqueue `PolicyDenied`,
   177	  `HAInactive`, or `DiscardRoute` frames to the kernel slow path.
   178	- Preserve the existing intentional `_from_frame` bypass at
   179	  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
   180	  path at `poll_stages.rs:452`.
   181	- Document the contract: which dispositions are reinject-eligible, and where
   182	  the gate lives, at the call site and in `tx/dispatch/slow_path.rs`.
   183	- Decide the buffered-MissingNeighbor duplicate (§2.5): keep (document) or
   184	  suppress.
   185	
   186	**Non-goals**
   187	- No change to the policy-evaluation logic, the slow-path reinjector, NAT, or
   188	  the tunnel gate.
   189	- No change to the other 4 call sites' behavior.
   190	- No new Prometheus surface beyond what is needed to make the dropped-leak
   191	  observable (optional, see §5).
   192	
   193	## 5. Multiple Path Options
   194	
   195	### Path A — gate at the call site (mod.rs:2814) via a shared predicate (RECOMMENDED)
   196	
   197	Extract the allow-list into a single `pub(in crate::afxdp) const fn
   198	disposition_is_slow_path_eligible(d: ForwardingDisposition) -> bool` (or
   199	`ForwardingDisposition::is_slow_path_eligible(self)`) in
   200	`tx/dispatch/slow_path.rs` (or on the enum in `types/forwarding.rs`). Then:
   201	
   202	1. Replace the inline `matches!(...)` in the wrapper `maybe_reinject_slow_path`
   203	   (slow_path.rs:90) with a call to the shared predicate (no behavior change —
   204	   pure refactor, makes the two sites share one SSOT).
   205	2. At `mod.rs:2814`, wrap the trailing call:
   206	   ```rust
   207	   if disposition_is_slow_path_eligible(decision.resolution.disposition) {
   208	       maybe_reinject_slow_path_from_frame(...);
   209	   }
   210	   ```
   211	
   212	- **Pros**: minimal, surgical; fixes the exact leak; preserves the
   213	  intentional `dispatch/mod.rs:225` bypass (that site does NOT call the
   214	  predicate); one SSOT for the allow-list; trivially testable.
   215	- **Cons**: the predicate now lives at two call sites (wrapper + 2814) — a
   216	  third future caller could forget it. Mitigated by the shared `const fn`
   217	  name making the contract obvious + a doc comment.
   218	- **Buffered-MissingNeighbor (§2.5)**: `MissingNeighbor` stays in the
   219	  allow-list, so the §2.5 duplicate behavior is UNCHANGED by Path A. Sub-
   220	  decision: leave as-is (it is the documented #1901 recovery story) and
   221	  document it, OR additionally skip the trailing call when `recycle_now ==
   222	  false` (the frame is buffered for retry, no need to also kernel-reinject).
   223	  **Recommendation: leave MissingNeighbor behavior unchanged in this fix**
   224	  (it is a separate, lower-severity, already-documented concern) and note it
   225	  in the call-site comment; file a follow-up if the duplicate is undesirable.
   226	
   227	### Path B — filter inside `_from_frame` (REJECTED)
   228	
   229	Add the allow-list to `maybe_reinject_slow_path_from_frame` itself.
   230	
   231	- **Pros**: every `_from_frame` caller is covered automatically.
   232	- **Cons / FATAL**: breaks `dispatch/mod.rs:225`, which passes `FabricRedirect`
   233	  on purpose to bypass the filter. Would require simultaneously rewriting that
   234	  call site to a different mechanism. Larger blast radius, changes 5 call
   235	  sites' contract for one buggy site. **Rejected** per §2.6.
   236	
   237	### Path C — convert the trailing `_from_frame` call to the filtered wrapper `maybe_reinject_slow_path`
   238	
   239	At `mod.rs:2814`, call the desc-based wrapper (which already filters) instead
   240	of `_from_frame`.
   241	
   242	- **Cons / FATAL**: the wrapper takes `area: &MmapArea` + `desc: XdpDesc` and
   243	  re-slices the ORIGINAL UMEM frame. The trailing site MUST use `packet_frame`
   244	  (the post-decap `owned_packet_frame` when GRE decap rebound meta) — this is
   245	  the entire point of the #1885/#1901 fix (using `desc` here re-introduces the
   246	  4-byte-early VLAN slice / un-decapped-outer-packet bug the comments at
   247	  :2163+ describe). So switching to the desc wrapper RE-INTRODUCES #1885.
   248	  **Rejected.**
   249	
   250	### Path D — document-only ("intentional")
   251	
   252	Conclude the unfiltered behavior is intentional and just add comments.
   253	
   254	- **Cons / FATAL**: §2.2 proves a real policy bypass (denied packets
   255	  forwarded). Not intentional, not benign. **Rejected.**
   256	
   257	## 6. Recommended path
   258	
   259	**Path A.** Shared `const fn` predicate, gate at the `mod.rs:2814` call site,
   260	wrapper refactored to call the same predicate (SSOT). Leave the intentional

exec
/bin/bash -lc 'pwd && git rev-parse HEAD && git branch --show-current && git status --short' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
6db482ebad2fe958bced8cfbbff50e8b0e21e6d4
research/1913-fromframe-filter

codex
The initial read confirms the cited wrapper filter and the unfiltered frame helper. I’m narrowing the review now to the policy-deny path and the exact control flow between the disposition match and the reinjection call, because that’s where an earlier drop would invalidate the plan’s severity claim.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1775,2160p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1560,1775p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1560	                                                binding
  1561	                                                    .live
  1562	                                                    .session_publish_errors
  1563	                                                    .fetch_add(1, Ordering::Relaxed);
  1564	                                            }
  1565	                                            // Verify session keys and log creations (debug-only: BPF syscalls)
  1566	                                            if cfg!(feature = "debug-log") {
  1567	                                                if verify_session_key_in_bpf(
  1568	                                                    binding.bpf_maps.session_map_fd,
  1569	                                                    &reverse_key,
  1570	                                                ) {
  1571	                                                    SESSION_PUBLISH_VERIFY_OK
  1572	                                                        .fetch_add(1, Ordering::Relaxed);
  1573	                                                } else {
  1574	                                                    SESSION_PUBLISH_VERIFY_FAIL
  1575	                                                        .fetch_add(1, Ordering::Relaxed);
  1576	                                                    debug_log!(
  1577	                                                        "SESS_VERIFY_FAIL: reverse key NOT found after publish! \
  1578	                                                             af={} proto={} {}:{} -> {}:{} (map_fd={})",
  1579	                                                        reverse_key.addr_family,
  1580	                                                        reverse_key.protocol,
  1581	                                                        reverse_key.src_ip,
  1582	                                                        reverse_key.src_port,
  1583	                                                        reverse_key.dst_ip,
  1584	                                                        reverse_key.dst_port,
  1585	                                                        binding.bpf_maps.session_map_fd,
  1586	                                                    );
  1587	                                                }
  1588	                                                if !verify_session_key_in_bpf(
  1589	                                                    binding.bpf_maps.session_map_fd,
  1590	                                                    &flow.forward_key,
  1591	                                                ) {
  1592	                                                    debug_log!(
  1593	                                                        "SESS_VERIFY_FAIL: forward key NOT found! \
  1594	                                                             af={} proto={} {}:{} -> {}:{}",
  1595	                                                        flow.forward_key.addr_family,
  1596	                                                        flow.forward_key.protocol,
  1597	                                                        flow.forward_key.src_ip,
  1598	                                                        flow.forward_key.src_port,
  1599	                                                        flow.forward_key.dst_ip,
  1600	                                                        flow.forward_key.dst_port,
  1601	                                                    );
  1602	                                                }
  1603	                                                let logged = SESSION_CREATIONS_LOGGED
  1604	                                                    .fetch_add(1, Ordering::Relaxed);
  1605	                                                if logged < 10 {
  1606	                                                    debug_log!(
  1607	                                                        "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
  1608	                                                             | REV af={} proto={} {}:{} -> {}:{} \
  1609	                                                             | NAT src={:?} dst={:?} \
  1610	                                                             | map_fd={} bpf_entries={}",
  1611	                                                        logged,
  1612	                                                        flow.forward_key.addr_family,
  1613	                                                        flow.forward_key.protocol,
  1614	                                                        flow.forward_key.src_ip,
  1615	                                                        flow.forward_key.src_port,
  1616	                                                        flow.forward_key.dst_ip,
  1617	                                                        flow.forward_key.dst_port,
  1618	                                                        reverse_key.addr_family,
  1619	                                                        reverse_key.protocol,
  1620	                                                        reverse_key.src_ip,
  1621	                                                        reverse_key.src_port,
  1622	                                                        reverse_key.dst_ip,
  1623	                                                        reverse_key.dst_port,
  1624	                                                        decision.nat.rewrite_src,
  1625	                                                        decision.nat.rewrite_dst,
  1626	                                                        binding.bpf_maps.session_map_fd,
  1627	                                                        count_bpf_session_entries(
  1628	                                                            binding.bpf_maps.session_map_fd
  1629	                                                        ),
  1630	                                                    );
  1631	                                                    dump_bpf_session_entries(
  1632	                                                        binding.bpf_maps.session_map_fd,
  1633	                                                        20,
  1634	                                                    );
  1635	                                                }
  1636	                                            }
  1637	                                            created += 1;
  1638	                                            let reverse_entry = SyncedSessionEntry {
  1639	                                                key: reverse_key,
  1640	                                                decision: reverse_decision,
  1641	                                                metadata: reverse_metadata,
  1642	                                                origin: SessionOrigin::ReverseFlow,
  1643	                                                protocol: meta.protocol,
  1644	                                                tcp_flags: meta.tcp_flags,
  1645	                                            };
  1646	                                            publish_shared_session(
  1647	                                                worker_ctx.shared_sessions,
  1648	                                                worker_ctx.shared_nat_sessions,
  1649	                                                worker_ctx.shared_forward_wire_sessions,
  1650	                                                &worker_ctx.shared_owner_rg_indexes,
  1651	                                                &reverse_entry,
  1652	                                            );
  1653	                                            replicate_session_upsert(
  1654	                                                worker_ctx.peer_worker_commands,
  1655	                                                &reverse_entry,
  1656	                                            );
  1657	                                        }
  1658	                                        if created > 0 {
  1659	                                            telemetry.counters.session_creates += created;
  1660	                                            telemetry.dbg.session_create += created;
  1661	                                        }
  1662	                                    }
  1663	                                } else {
  1664	                                    emit_policy_deny_event(
  1665	                                        worker_ctx.event_stream,
  1666	                                        flow,
  1667	                                        meta,
  1668	                                        from_zone_id,
  1669	                                        to_zone_id,
  1670	                                        owner_rg_id,
  1671	                                        policy_result.policy_id,
  1672	                                        policy_result.action,
  1673	                                        now_ns,
  1674	                                    );
  1675	                                    telemetry.dbg.policy_deny += 1;
  1676	                                    if cfg!(feature = "debug-log")
  1677	                                        && (telemetry.dbg.policy_deny <= 3 || is_trust_flow)
  1678	                                    {
  1679	                                        debug_log!(
  1680	                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
  1681	                                            telemetry.dbg.policy_deny,
  1682	                                            flow.src_ip,
  1683	                                            flow.forward_key.src_port,
  1684	                                            flow.dst_ip,
  1685	                                            flow.forward_key.dst_port,
  1686	                                            meta.protocol,
  1687	                                            from_zone,
  1688	                                            to_zone,
  1689	                                            meta.ingress_ifindex,
  1690	                                            resolution.egress_ifindex,
  1691	                                        );
  1692	                                    }
  1693	                                    decision.resolution.disposition =
  1694	                                        ForwardingDisposition::PolicyDenied;
  1695	                                }
  1696	                            } else if decision.resolution.disposition
  1697	                                == ForwardingDisposition::HAInactive
  1698	                                && !packet_fabric_ingress
  1699	                            {
  1700	                                let owner_rg_id =
  1701	                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
  1702	                                if owner_rg_id > 0 {
  1703	                                    flow_cache_owner_rg_id = owner_rg_id;
  1704	                                }
  1705	                                // New flow to inactive RG: fabric-redirect to the peer
  1706	                                // that owns the egress RG.  Use from_zone_arc directly
  1707	                                // (always in scope) rather than going through the debug
  1708	                                // struct which may not have been populated.
  1709	                                // #919/#922: ID-keyed redirect — no name lookup.
  1710	                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
  1711	                                    worker_ctx.forwarding,
  1712	                                    from_zone_id,
  1713	                                )
  1714	                                .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
  1715	                                {
  1716	                                    decision.resolution = redirect;
  1717	                                }
  1718	                            }
  1719	                            decision
  1720	                        }
  1721	                    } else {
  1722	                        let non_flow_resolution = enforce_ha_resolution_snapshot(
  1723	                            worker_ctx.forwarding,
  1724	                            worker_ctx.ha_state,
  1725	                            now_secs,
  1726	                            resolve_forwarding(
  1727	                                // SAFETY: per the `area` contract in this
  1728	                                // function's header comment.
  1729	                                unsafe { &*area },
  1730	                                desc,
  1731	                                meta,
  1732	                                worker_ctx.forwarding,
  1733	                                worker_ctx.dynamic_neighbors,
  1734	                            ),
  1735	                        );
  1736	                        // For non-flow packets (no L4 ports), also attempt fabric
  1737	                        // redirect when the egress RG is inactive.
  1738	                        let final_resolution = if non_flow_resolution.disposition
  1739	                            == ForwardingDisposition::HAInactive
  1740	                            && !packet_fabric_ingress
  1741	                        {
  1742	                            resolve_fabric_redirect(worker_ctx.forwarding).unwrap_or(non_flow_resolution)
  1743	                        } else {
  1744	                            non_flow_resolution
  1745	                        };
  1746	                        SessionDecision {
  1747	                            resolution: final_resolution,
  1748	                            nat: NatDecision::default(),
  1749	                        }
  1750	                    };
  1751	                    // Safety net: convert any remaining HAInactive to fabric
  1752	                    // redirect. Session-hit and new-flow paths each attempt
  1753	                    // fabric redirect internally, but demoted sessions that
  1754	                    // arrive via DNAT/interface-NAT XDP shim paths can slip
  1755	                    // through with HAInactive when the inner conversion found
  1756	                    // no fabric link at the time. Anti-loop: never redirect
  1757	                    // packets that arrived on the fabric interface itself.
  1758	                    // Only redirect when the egress maps to a known RG.
  1759	                    // HAInactive with unknown ownership (rg=0) means unresolved
  1760	                    // — those should NOT be fabric-redirected.
  1761	                    let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
  1762	                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
  1763	                        && egress_rg > 0
  1764	                        && !packet_fabric_ingress
  1765	                    {
  1766	                        if flow_cache_owner_rg_id <= 0 {
  1767	                            flow_cache_owner_rg_id = egress_rg;
  1768	                        }
  1769	                        // #919: prefer the cached u16 zone ID; fall back to
  1770	                        // looking up the ifindex's zone name and translating
  1771	                        // to an ID. resolve_zone_encoded_fabric_redirect_by_id
  1772	                        // skips the name round-trip.
  1773	                        // #921: direct ifindex → u16 (was a two-hop
  1774	                        // name round-trip).
  1775	                        let zone_id = session_ingress_zone.or_else(|| {

 succeeded in 0ms:
  1775	                        let zone_id = session_ingress_zone.or_else(|| {
  1776	                            worker_ctx
  1777	                                .forwarding
  1778	                                .ifindex_to_zone_id
  1779	                                .get(&(meta.ingress_ifindex as i32))
  1780	                                .copied()
  1781	                        });
  1782	                        if let Some(redirect) = zone_id
  1783	                            .and_then(|id| {
  1784	                                resolve_zone_encoded_fabric_redirect_by_id(
  1785	                                    worker_ctx.forwarding,
  1786	                                    id,
  1787	                                )
  1788	                            })
  1789	                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
  1790	                        {
  1791	                            decision.resolution = redirect;
  1792	                        }
  1793	                    }
  1794	                    if matches!(
  1795	                        decision.resolution.disposition,
  1796	                        ForwardingDisposition::ForwardCandidate
  1797	                            | ForwardingDisposition::FabricRedirect
  1798	                    ) {
  1799	                        telemetry.dbg.forward += 1;
  1800	                        // Direction-specific tracking
  1801	                        let ingress_if = meta.ingress_ifindex as i32;
  1802	                        let egress_if = decision.resolution.egress_ifindex;
  1803	                        if ingress_if == 5 {
  1804	                            telemetry.dbg.rx_from_trust += 1;
  1805	                            telemetry.dbg.fwd_trust_to_wan += 1;
  1806	                        } else if ingress_if == 6 {
  1807	                            telemetry.dbg.rx_from_wan += 1;
  1808	                            telemetry.dbg.fwd_wan_to_trust += 1;
  1809	                        }
  1810	                        // NAT decision tracking
  1811	                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some()
  1812	                        {
  1813	                            telemetry.dbg.nat_applied_snat += 1;
  1814	                            telemetry.dbg.nat_applied_dnat += 1;
  1815	                        } else if decision.nat.rewrite_src.is_some() {
  1816	                            telemetry.dbg.nat_applied_snat += 1;
  1817	                        } else if decision.nat.rewrite_dst.is_some() {
  1818	                            telemetry.dbg.nat_applied_dnat += 1;
  1819	                        } else {
  1820	                            telemetry.dbg.nat_applied_none += 1;
  1821	                        }
  1822	                        // Log NAT details for first few forward-candidate packets
  1823	                        if cfg!(feature = "debug-log") {
  1824	                            if telemetry.dbg.forward <= 10 {
  1825	                                let flow_str = flow
  1826	                                    .as_ref()
  1827	                                    .map(|f| {
  1828	                                        format!(
  1829	                                            "{}:{} -> {}:{}",
  1830	                                            f.src_ip,
  1831	                                            f.forward_key.src_port,
  1832	                                            f.dst_ip,
  1833	                                            f.forward_key.dst_port
  1834	                                        )
  1835	                                    })
  1836	                                    .unwrap_or_else(|| "no-flow".into());
  1837	                                let nat_str = format!(
  1838	                                    "snat={:?} dnat={:?}",
  1839	                                    decision.nat.rewrite_src, decision.nat.rewrite_dst,
  1840	                                );
  1841	                                eprintln!(
  1842	                                    "DBG FWD_DECISION[{}]: ingress_if={} egress_if={} {} {} proto={}",
  1843	                                    telemetry.dbg.forward,
  1844	                                    ingress_if,
  1845	                                    egress_if,
  1846	                                    flow_str,
  1847	                                    nat_str,
  1848	                                    meta.protocol,
  1849	                                );
  1850	                            }
  1851	                        }
  1852	                        // TCP flag tracking on forwarded frames
  1853	                        if cfg!(feature = "debug-log") {
  1854	                            if meta.protocol == 6 {
  1855	                                // Compare meta.tcp_flags from BPF shim with raw frame TCP flags.
  1856	                                // #1145: reuse line-50 raw_frame bind instead of re-slicing.
  1857	                                let raw_tcp_info = extract_tcp_flags_and_window(raw_frame);
  1858	                                let raw_flags = raw_tcp_info.map(|(f, _)| f);
  1859	                                let raw_window = raw_tcp_info.map(|(_, w)| w);
  1860	                                // Log first 20 forwarded TCP packets: compare meta vs raw
  1861	                                if telemetry.dbg.forward <= 20 {
  1862	                                    let flow_str = flow
  1863	                                        .as_ref()
  1864	                                        .map(|f| {
  1865	                                            format!(
  1866	                                                "{}:{} -> {}:{}",
  1867	                                                f.src_ip,
  1868	                                                f.forward_key.src_port,
  1869	                                                f.dst_ip,
  1870	                                                f.forward_key.dst_port
  1871	                                            )
  1872	                                        })
  1873	                                        .unwrap_or_else(|| "no-flow".into());
  1874	                                    eprintln!(
  1875	                                        "FWD_TCP_CMP[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} l4_off={} {}",
  1876	                                        telemetry.dbg.forward,
  1877	                                        meta.tcp_flags,
  1878	                                        raw_flags
  1879	                                            .map(|f| format!("0x{:02x}", f))
  1880	                                            .unwrap_or_else(|| "NONE".into()),
  1881	                                        raw_window
  1882	                                            .map(|w| format!("{}", w))
  1883	                                            .unwrap_or_else(|| "NONE".into()),
  1884	                                        desc.len,
  1885	                                        meta.l4_offset,
  1886	                                        flow_str,
  1887	                                    );
  1888	                                    // Hex dump bytes around TCP flags position in raw frame.
  1889	                                    // #1145: reuse line-50 raw_frame bind (no Option wrapper).
  1890	                                    let l4 = meta.l4_offset as usize;
  1891	                                    if raw_frame.len() > l4 + 20 {
  1892	                                        let tcp_hdr: String = raw_frame[l4..l4 + 20]
  1893	                                            .iter()
  1894	                                            .map(|b| format!("{:02x}", b))
  1895	                                            .collect::<Vec<_>>()
  1896	                                            .join(" ");
  1897	                                        eprintln!(
  1898	                                            "FWD_TCP_HDR[{}]: offset={} {}",
  1899	                                            telemetry.dbg.forward, l4, tcp_hdr
  1900	                                        );
  1901	                                    }
  1902	                                }
  1903	                                if (meta.tcp_flags & 0x04) != 0 {
  1904	                                    // RST
  1905	                                    telemetry.dbg.fwd_tcp_rst += 1;
  1906	                                    if telemetry.dbg.fwd_tcp_rst <= 5 {
  1907	                                        let flow_str = flow
  1908	                                            .as_ref()
  1909	                                            .map(|f| {
  1910	                                                format!(
  1911	                                                    "{}:{} -> {}:{}",
  1912	                                                    f.src_ip,
  1913	                                                    f.forward_key.src_port,
  1914	                                                    f.dst_ip,
  1915	                                                    f.forward_key.dst_port
  1916	                                                )
  1917	                                            })
  1918	                                            .unwrap_or_else(|| "no-flow".into());
  1919	                                        eprintln!(
  1920	                                            "FWD_TCP_RST_DETECT[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} fwd#={} {}",
  1921	                                            telemetry.dbg.fwd_tcp_rst,
  1922	                                            meta.tcp_flags,
  1923	                                            raw_flags
  1924	                                                .map(|f| format!("0x{:02x}", f))
  1925	                                                .unwrap_or_else(|| "NONE".into()),
  1926	                                            raw_window
  1927	                                                .map(|w| format!("{}", w))
  1928	                                                .unwrap_or_else(|| "NONE".into()),
  1929	                                            desc.len,
  1930	                                            telemetry.dbg.forward,
  1931	                                            flow_str,
  1932	                                        );
  1933	                                        // Hex dump TCP header when RST detected.
  1934	                                        // #1145: reuse line-50 raw_frame bind.
  1935	                                        let l4 = meta.l4_offset as usize;
  1936	                                        if raw_frame.len() > l4 + 20 {
  1937	                                            let tcp_hdr: String = raw_frame[l4..l4 + 20]
  1938	                                                .iter()
  1939	                                                .map(|b| format!("{:02x}", b))
  1940	                                                .collect::<Vec<_>>()
  1941	                                                .join(" ");
  1942	                                            eprintln!(
  1943	                                                "FWD_TCP_RST_HDR[{}]: meta_off={} raw_off={} {}",
  1944	                                                telemetry.dbg.fwd_tcp_rst,
  1945	                                                l4,
  1946	                                                frame_l3_offset(raw_frame).unwrap_or(0),
  1947	                                                tcp_hdr
  1948	                                            );
  1949	                                        }
  1950	                                    }
  1951	                                }
  1952	                                if (meta.tcp_flags & 0x01) != 0 {
  1953	                                    // FIN
  1954	                                    telemetry.dbg.fwd_tcp_fin += 1;
  1955	                                    if telemetry.dbg.fwd_tcp_fin <= 5 {
  1956	                                        let flow_str = flow
  1957	                                            .as_ref()
  1958	                                            .map(|f| {
  1959	                                                format!(
  1960	                                                    "{}:{} -> {}:{}",
  1961	                                                    f.src_ip,
  1962	                                                    f.forward_key.src_port,
  1963	                                                    f.dst_ip,
  1964	                                                    f.forward_key.dst_port
  1965	                                                )
  1966	                                            })
  1967	                                            .unwrap_or_else(|| "no-flow".into());
  1968	                                        eprintln!(
  1969	                                            "FWD_TCP_FIN[{}]: ingress_if={} {} tcp_flags=0x{:02x}",
  1970	                                            telemetry.dbg.fwd_tcp_fin,
  1971	                                            meta.ingress_ifindex,
  1972	                                            flow_str,
  1973	                                            meta.tcp_flags,
  1974	                                        );
  1975	                                    }
  1976	                                }
  1977	                                // Detect zero-window in TCP frames by inspecting raw packet
  1978	                                if let Some(win) = raw_window {
  1979	                                    if win == 0 {
  1980	                                        telemetry.dbg.fwd_tcp_zero_window += 1;
  1981	                                        if telemetry.dbg.fwd_tcp_zero_window <= 10 {
  1982	                                            let flow_str = flow
  1983	                                                .as_ref()
  1984	                                                .map(|f| {
  1985	                                                    format!(
  1986	                                                        "{}:{} -> {}:{}",
  1987	                                                        f.src_ip,
  1988	                                                        f.forward_key.src_port,
  1989	                                                        f.dst_ip,
  1990	                                                        f.forward_key.dst_port
  1991	                                                    )
  1992	                                                })
  1993	                                                .unwrap_or_else(|| "no-flow".into());
  1994	                                            eprintln!(
  1995	                                                "FWD_TCP_ZERO_WIN[{}]: ingress_if={} {} meta_flags=0x{:02x} raw_flags={}",
  1996	                                                telemetry.dbg.fwd_tcp_zero_window,
  1997	                                                meta.ingress_ifindex,
  1998	                                                flow_str,
  1999	                                                meta.tcp_flags,
  2000	                                                raw_flags
  2001	                                                    .map(|f| format!("0x{:02x}", f))
  2002	                                                    .unwrap_or_else(|| "NONE".into()),
  2003	                                            );
  2004	                                        }
  2005	                                    }
  2006	                                }
  2007	                            }
  2008	                        }
  2009	                        if should_teardown_tcp_rst(meta, flow.as_ref())
  2010	                            && let Some(flow) = flow.as_ref()
  2011	                        {
  2012	                            binding
  2013	                                .scratch.scratch_rst_teardowns
  2014	                                .push((flow.forward_key.clone(), decision.nat));
  2015	                        }
  2016	                        telemetry.counters.forward_candidate_packets += 1;
  2017	                        if decision.nat.rewrite_src.is_some() {
  2018	                            telemetry.counters.snat_packets += 1;
  2019	                        }
  2020	                        if decision.nat.rewrite_dst.is_some() {
  2021	                            telemetry.counters.dnat_packets += 1;
  2022	                        }
  2023	                        if let Some(mut request) = build_live_forward_request_from_frame(
  2024	                            worker_ctx.binding_lookup,
  2025	                            binding_index,
  2026	                            &worker_ctx.ident,
  2027	                            desc,
  2028	                            packet_frame,
  2029	                            meta,
  2030	                            &decision,
  2031	                            worker_ctx.forwarding,
  2032	                            flow.as_ref(),
  2033	                            session_ingress_zone,
  2034	                            apply_nat_on_fabric,
  2035	                            now_ns,
  2036	                            worker_ctx.event_stream,
  2037	                            None,
  2038	                            None,
  2039	                        ) {
  2040	                            request.frame = owned_packet_frame
  2041	                                .take()
  2042	                                .map(PendingForwardFrame::Owned)
  2043	                                .unwrap_or(PendingForwardFrame::Live);
  2044	                            telemetry.dbg.tx += 1; // track forward requests queued
  2045	                            if cfg!(feature = "debug-log") {
  2046	                                if telemetry.dbg.tx <= 5 {
  2047	                                    let dst_mac_str = decision
  2048	                                        .resolution
  2049	                                        .neighbor_mac
  2050	                                        .map(|m| {
  2051	                                            format!(
  2052	                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2053	                                                m[0], m[1], m[2], m[3], m[4], m[5]
  2054	                                            )
  2055	                                        })
  2056	                                        .unwrap_or_else(|| "NONE".into());
  2057	                                    let src_mac_str = decision
  2058	                                        .resolution
  2059	                                        .src_mac
  2060	                                        .map(|m| {
  2061	                                            format!(
  2062	                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2063	                                                m[0], m[1], m[2], m[3], m[4], m[5]
  2064	                                            )
  2065	                                        })
  2066	                                        .unwrap_or_else(|| "NONE".into());
  2067	                                    let flow_str = flow
  2068	                                        .as_ref()
  2069	                                        .map(|f| {
  2070	                                            format!(
  2071	                                                "{}:{} -> {}:{}",
  2072	                                                f.src_ip,
  2073	                                                f.forward_key.src_port,
  2074	                                                f.dst_ip,
  2075	                                                f.forward_key.dst_port
  2076	                                            )
  2077	                                        })
  2078	                                        .unwrap_or_else(|| "no-flow".into());
  2079	                                    eprintln!(
  2080	                                        "DBG FWD_REQ: target_if={} egress_if={} tx_if={} len={} proto={} vlan={} dst_mac={} src_mac={} flow={}",
  2081	                                        request.target_ifindex,
  2082	                                        decision.resolution.egress_ifindex,
  2083	                                        decision.resolution.tx_ifindex,
  2084	                                        desc.len,
  2085	                                        meta.protocol,
  2086	                                        decision.resolution.tx_vlan_id,
  2087	                                        dst_mac_str,
  2088	                                        src_mac_str,
  2089	                                        flow_str,
  2090	                                    );
  2091	                                }
  2092	                            }
  2093	                            let request_target_binding_index = request.target_binding_index;
  2094	                            binding.scratch.scratch_forwards.push(request);
  2095	                            recycle_now = false;
  2096	                            // ── Flow cache population ────────────────────
  2097	                            // Cache ForwardCandidate decisions for established
  2098	                            // TCP/UDP flows. Skip NAT64/NPTv6 (non-cacheable).
  2099	                            // #1861 §5.4: never cache a decision whose backing
  2100	                            // session install was attempted and refused
  2101	                            // (flow_cache_install_failed) — a cached
  2102	                            // sessionless decision would suppress the
  2103	                            // per-packet reply repair until cache
  2104	                            // invalidation. "No install required" paths
  2105	                            // (DNS fast-path, fabric-return) keep the flag
  2106	                            // false and cache as before.
  2107	                            if !flow_cache_install_failed
  2108	                                && let Some(flow) = flow.as_ref()
  2109	                                && let Some(entry) = FlowCacheEntry::from_forward_decision(
  2110	                                    flow,
  2111	                                    meta,
  2112	                                    validation,
  2113	                                    decision,
  2114	                                    flow_cache_owner_rg_id,
  2115	                                    session_ingress_zone,
  2116	                                    request_target_binding_index,
  2117	                                    evaluate_non_pbr_input_filter_log_only(
  2118	                                        worker_ctx.forwarding,
  2119	                                        Some(flow),
  2120	                                        meta,
  2121	                                        ingress_zone_override,
  2122	                                    ),
  2123	                                    worker_ctx.forwarding,
  2124	                                    worker_ctx.ha_state,
  2125	                                    apply_nat_on_fabric,
  2126	                                    &worker_ctx.rg_epochs,
  2127	                                )
  2128	                            {
  2129	                                binding.flow.flow_cache.insert(entry);
  2130	                            }
  2131	                            // ── End flow cache population ────────────────
  2132	                        } else {
  2133	                            telemetry.dbg.build_fail += 1;
  2134	                            if cfg!(feature = "debug-log") {
  2135	                                if telemetry.dbg.build_fail <= 3 {
  2136	                                    eprintln!(
  2137	                                        "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
  2138	                                        decision.resolution.egress_ifindex,
  2139	                                        decision.resolution.tx_ifindex,
  2140	                                        decision.resolution.neighbor_mac.map(|m| format!(
  2141	                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2142	                                            m[0], m[1], m[2], m[3], m[4], m[5]
  2143	                                        )),
  2144	                                        decision.resolution.src_mac.map(|m| format!(
  2145	                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2146	                                            m[0], m[1], m[2], m[3], m[4], m[5]
  2147	                                        )),
  2148	                                        desc.len,
  2149	                                        meta.protocol,
  2150	                                    );
  2151	                                }
  2152	                            }
  2153	                        }
  2154	                    } else {
  2155	                        // Debug: count non-forward dispositions
  2156	                        match decision.resolution.disposition {
  2157	                            ForwardingDisposition::LocalDelivery => {
  2158	                                telemetry.dbg.local += 1;
  2159	                                // Host-bound traffic (NDP, ICMP echo, BGP,
  2160	                                // GRE-to-self inner packets, etc.) is

exec
/bin/bash -lc "rg -n \"PolicyDenied|policy_deny|emit_policy_deny|zone|resolution\\.disposition|maybe_reinject_slow_path_from_frame|ForwardingDisposition\" userspace-dp/src/afxdp/poll_descriptor/mod.rs" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
153:                        ingress_zone_override,
163:                        ingress_zone_override,
247:                    let mut session_ingress_zone: Option<u16> = None;
285:                                // `show security flow session` zone/interface display.
292:                                    &worker_ctx.forwarding.zone_name_to_id,
316:                                debug.from_zone = Some(resolved.metadata.ingress_zone);
317:                                debug.to_zone = Some(resolved.metadata.egress_zone);
319:                            session_ingress_zone = Some(resolved.metadata.ingress_zone);
327:                                    Some(resolved.metadata.ingress_zone),
346:                            if resolved.decision.resolution.disposition
347:                                == ForwardingDisposition::LocalDelivery
353:                                    Some(resolved.metadata.ingress_zone),
373:                                telemetry.dbg.policy_deny += 1;
384:                                resolved.decision.resolution.disposition,
385:                                ForwardingDisposition::ForwardCandidate
415:                                ingress_zone_override,
444:                            // a packet arriving from zone-encoded fabric ingress has already
446:                            // peer to hand it to the resolved local egress zone instead of
455:                                    ingress_zone_override,
524:                            // #919: ingress_zone_override is now Option<u16>;
525:                            // DNAT/static NAT lookups still take zone names,
527:                            let ingress_zone_name = ingress_zone_override
529:                                    worker_ctx.forwarding.zone_id_to_name.get(&id).map(|s| s.as_str())
535:                                        .ifindex_to_zone_id
537:                                        .and_then(|id| worker_ctx.forwarding.zone_id_to_name.get(id))
546:                                    ingress_zone_name,
554:                                    .match_dnat(resolution_target, ingress_zone_name)
614:                                ingress_zone_override,
633:                                ingress_zone_override,
694:                            // #919/#922: zero-allocation zone-pair resolution
697:                            let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
700:                                ingress_zone_override,
703:                            // Borrow zone names as &str for string-typed downstream
707:                            let from_zone: &str = worker_ctx
709:                                .zone_id_to_name
710:                                .get(&from_zone_id)
713:                            let to_zone: &str = worker_ctx
715:                                .zone_id_to_name
716:                                .get(&to_zone_id)
720:                                || from_zone == "lan"
729:                                from_zone_id,
736:                                        "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} ingress_if={} disp={:?} egress_if={} neigh={:?} zone={}->{}",
745:                                        resolution.disposition,
751:                                        from_zone,
752:                                        to_zone,
792:                                debug.from_zone = Some(from_zone_id);
793:                                debug.to_zone = Some(to_zone_id);
811:                            if resolution.disposition == ForwardingDisposition::LocalDelivery
817:                                    ingress_zone_override,
822:                                telemetry.dbg.policy_deny += 1;
826:                            if resolution.disposition == ForwardingDisposition::LocalDelivery
837:                                    ingress_zone: from_zone_id,
838:                                    egress_zone: to_zone_id,
871:                                        &worker_ctx.forwarding.zone_name_to_id,
900:                                            icmp_match.resolution.disposition,
979:                                                    icmp_decision.resolution.disposition,
990:                                                    icmp_resolution.disposition,
1010:                                            "ICMPV6_EMBED: no_match outer={}:{} -> {}:{} ingress_if={} from_zone={} to_zone={}",
1016:                                            from_zone,
1017:                                            to_zone,
1024:                            } else if decision.resolution.disposition
1025:                                == ForwardingDisposition::ForwardCandidate
1055:                                    from_zone_id,
1056:                                    to_zone_id,
1088:                                        // (capacity exhausted or zone-id
1093:                                                from_zone_id,
1094:                                                to_zone_id,
1099:                                                from_zone_id,
1100:                                                to_zone_id,
1169:                                                    &from_zone,
1170:                                                    &to_zone,
1188:                                                        from_zone_id,
1189:                                                        to_zone_id,
1200:                                                &from_zone,
1201:                                                &to_zone,
1218:                                                        from_zone_id,
1219:                                                        to_zone_id,
1266:                                        let track_in_userspace = decision.resolution.disposition
1267:                                            != ForwardingDisposition::LocalDelivery
1310:                                            ingress_zone: from_zone_id,
1311:                                            egress_zone: to_zone_id,
1431:                                            from_zone_id,
1502:                                            ingress_zone: to_zone_id,
1503:                                            egress_zone: from_zone_id,
1664:                                    emit_policy_deny_event(
1668:                                        from_zone_id,
1669:                                        to_zone_id,
1675:                                    telemetry.dbg.policy_deny += 1;
1677:                                        && (telemetry.dbg.policy_deny <= 3 || is_trust_flow)
1680:                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
1681:                                            telemetry.dbg.policy_deny,
1687:                                            from_zone,
1688:                                            to_zone,
1693:                                    decision.resolution.disposition =
1694:                                        ForwardingDisposition::PolicyDenied;
1696:                            } else if decision.resolution.disposition
1697:                                == ForwardingDisposition::HAInactive
1706:                                // that owns the egress RG.  Use from_zone_arc directly
1710:                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
1712:                                    from_zone_id,
1738:                        let final_resolution = if non_flow_resolution.disposition
1739:                            == ForwardingDisposition::HAInactive
1762:                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
1769:                        // #919: prefer the cached u16 zone ID; fall back to
1770:                        // looking up the ifindex's zone name and translating
1771:                        // to an ID. resolve_zone_encoded_fabric_redirect_by_id
1775:                        let zone_id = session_ingress_zone.or_else(|| {
1778:                                .ifindex_to_zone_id
1782:                        if let Some(redirect) = zone_id
1784:                                resolve_zone_encoded_fabric_redirect_by_id(
1795:                        decision.resolution.disposition,
1796:                        ForwardingDisposition::ForwardCandidate
1797:                            | ForwardingDisposition::FabricRedirect
2033:                            session_ingress_zone,
2115:                                    session_ingress_zone,
2121:                                        ingress_zone_override,
2156:                        match decision.resolution.disposition {
2157:                            ForwardingDisposition::LocalDelivery => {
2163:                                // leg (`maybe_reinject_slow_path_from_frame`
2186:                            ForwardingDisposition::NoRoute => {
2204:                            ForwardingDisposition::MissingNeighbor => {
2345:                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
2348:                                    ingress_zone_override,
2351:                                // Borrow zone names as &str (no clone) for the
2353:                                let from_zone: &str = worker_ctx
2355:                                    .zone_id_to_name
2356:                                    .get(&from_zone_id)
2359:                                let to_zone: &str = worker_ctx
2361:                                    .zone_id_to_name
2362:                                    .get(&to_zone_id)
2436:                                            from_zone_id,
2437:                                            to_zone_id,
2479:                                                    from_zone_id,
2480:                                                    to_zone_id,
2485:                                                    from_zone_id,
2486:                                                    to_zone_id,
2509:                                                &from_zone,
2510:                                                &to_zone,
2527:                                                        from_zone_id,
2528:                                                        to_zone_id,
2539:                                                &from_zone,
2540:                                                &to_zone,
2558:                                                        from_zone_id,
2559:                                                        to_zone_id,
2571:                                        from_zone_id,
2572:                                        to_zone_id,
2624:                                            &worker_ctx.forwarding.zone_name_to_id,
2690:                                // maybe_reinject_slow_path_from_frame call
2708:                                // maybe_reinject_slow_path_from_frame
2799:                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
2800:                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
2814:                        maybe_reinject_slow_path_from_frame(

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2200,2828p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2200	                                        }
  2201	                                    }
  2202	                                }
  2203	                            }
  2204	                            ForwardingDisposition::MissingNeighbor => {
  2205	                                telemetry.dbg.missing_neigh += 1;
  2206	                                // #1651 B3: dead-host fast-fail gate. Runs at
  2207	                                // the very top of the MissingNeighbor arm,
  2208	                                // BEFORE the kernel probe, session seed, and
  2209	                                // pending_neigh buffer, so a dead host never
  2210	                                // consumes a queue slot, fires a probe, or
  2211	                                // creates a MissingNeighborSeed session.
  2212	                                //
  2213	                                // Resolved-neighbor-wins (RTM_NEWNEIGH
  2214	                                // invalidation): check static then dynamic
  2215	                                // neighbors FIRST (same order as
  2216	                                // retry_pending_neigh / lookup_neighbor_entry).
  2217	                                // If the dst is now resolved, drop any stale
  2218	                                // negative entry and fall through to normal
  2219	                                // forwarding. Otherwise, if it is still
  2220	                                // negatively cached + un-expired, recycle the
  2221	                                // frame immediately.
  2222	                                if let Some(next_hop) = decision.resolution.next_hop {
  2223	                                    let neg_key =
  2224	                                        (decision.resolution.egress_ifindex, next_hop);
  2225	                                    // neg_neigh_gate runs the resolved-wins
  2226	                                    // probe (static neighbors THEN dynamic,
  2227	                                    // same order as retry_pending_neigh /
  2228	                                    // lookup_neighbor_entry) and the TTL check.
  2229	                                    // Returns true ⇒ fast-fail this packet.
  2230	                                    let fast_fail = neg_neigh_gate(
  2231	                                        &mut binding.neg_neigh_cache,
  2232	                                        &neg_key,
  2233	                                        now_ns,
  2234	                                        || {
  2235	                                            worker_ctx
  2236	                                                .forwarding
  2237	                                                .neighbors
  2238	                                                .contains_key(&neg_key)
  2239	                                                || worker_ctx
  2240	                                                    .dynamic_neighbors
  2241	                                                    .get(&neg_key)
  2242	                                                    .is_some()
  2243	                                        },
  2244	                                    );
  2245	                                    if fast_fail {
  2246	                                        telemetry.dbg.neg_neigh_fast_fail += 1;
  2247	                                        // #1782: promote the debug counter to a
  2248	                                        // real per-binding atomic so the
  2249	                                        // cold-start capture can read it from
  2250	                                        // Prometheus. Single Relaxed fetch_add
  2251	                                        // on the existing discard path — no new
  2252	                                        // hot-path work, no behavior change.
  2253	                                        binding
  2254	                                            .live
  2255	                                            .neg_neigh_fast_fail
  2256	                                            .fetch_add(1, Ordering::Relaxed);
  2257	                                        // #1769: the negative gate suppresses
  2258	                                        // the probe + buffer below, so a dst
  2259	                                        // that lost its dynamic entry (transient
  2260	                                        // FAILED/DELNEIGH or a dropped good
  2261	                                        // RTM_NEWNEIGH) would blackhole for the
  2262	                                        // full 3s TTL with nothing nudging it
  2263	                                        // back. Route it through the shared
  2264	                                        // resolver: a single-key RTM_GETNEIGH
  2265	                                        // off the hot path caches a confirmed
  2266	                                        // REACHABLE/PERMANENT lladdr (epoch-
  2267	                                        // guarded) or probes to force kernel
  2268	                                        // revalidation on a DELAY/STALE one.
  2269	                                        // Per-key rate-limited in the resolver
  2270	                                        // thread, so a SYN storm fires at most
  2271	                                        // one GET/probe per key per window. The
  2272	                                        // hot path only pays a non-blocking
  2273	                                        // try_send here (not per-packet — this
  2274	                                        // arm fires only on the negative fast-
  2275	                                        // fail).
  2276	                                        if let Some(resolver) =
  2277	                                            worker_ctx.neighbor_resolver
  2278	                                        {
  2279	                                            // Per-binding throttle: only
  2280	                                            // clone the iface name +
  2281	                                            // try_send once per key per
  2282	                                            // RESOLVER_ENQUEUE_THROTTLE_NS
  2283	                                            // so a dead-host SYN storm does
  2284	                                            // NOT allocate per fast-failed
  2285	                                            // packet (the resolver coalesces
  2286	                                            // per-key anyway). The cheap
  2287	                                            // (i32, IpAddr) map check runs
  2288	                                            // before any clone.
  2289	                                            let throttled = matches!(
  2290	                                                binding
  2291	                                                    .resolver_enqueue_throttle
  2292	                                                    .get(&neg_key),
  2293	                                                Some(&t) if now_ns.saturating_sub(t)
  2294	                                                    < RESOLVER_ENQUEUE_THROTTLE_NS
  2295	                                            );
  2296	                                            if !throttled {
  2297	                                                if let Some(name) = worker_ctx
  2298	                                                    .forwarding
  2299	                                                    .ifindex_to_name
  2300	                                                    .get(&neg_key.0)
  2301	                                                {
  2302	                                                    resolver.enqueue(
  2303	                                                        neg_key.0,
  2304	                                                        neg_key.1,
  2305	                                                        name.clone(),
  2306	                                                    );
  2307	                                                    // Bound the throttle
  2308	                                                    // map like the negative
  2309	                                                    // cache: a /24 scan
  2310	                                                    // touches <=254 keys, so
  2311	                                                    // clear wholesale past
  2312	                                                    // the cap (best-effort —
  2313	                                                    // losing throttle for a
  2314	                                                    // few keys only risks one
  2315	                                                    // extra clone).
  2316	                                                    if binding
  2317	                                                        .resolver_enqueue_throttle
  2318	                                                        .len()
  2319	                                                        >= MAX_NEG_NEIGH_CACHE
  2320	                                                        && !binding
  2321	                                                            .resolver_enqueue_throttle
  2322	                                                            .contains_key(&neg_key)
  2323	                                                    {
  2324	                                                        binding
  2325	                                                            .resolver_enqueue_throttle
  2326	                                                            .clear();
  2327	                                                    }
  2328	                                                    binding
  2329	                                                        .resolver_enqueue_throttle
  2330	                                                        .insert(neg_key, now_ns);
  2331	                                                }
  2332	                                            }
  2333	                                        }
  2334	                                        // Fresh RX descriptor → recycle via
  2335	                                        // scratch_recycle + continue, matching
  2336	                                        // the source-NAT-failure discard
  2337	                                        // pattern. The continue skips the
  2338	                                        // recycle_now epilogue and the
  2339	                                        // session-seed/buffer below.
  2340	                                        binding.scratch.scratch_recycle.push(desc.addr);
  2341	                                        continue;
  2342	                                    }
  2343	                                }
  2344	                                // #919/#922: zero-allocation ID-native resolution.
  2345	                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
  2346	                                    worker_ctx.forwarding,
  2347	                                    meta.ingress_ifindex as i32,
  2348	                                    ingress_zone_override,
  2349	                                    decision.resolution.egress_ifindex,
  2350	                                );
  2351	                                // Borrow zone names as &str (no clone) for the
  2352	                                // string-typed downstream NAT helpers.
  2353	                                let from_zone: &str = worker_ctx
  2354	                                    .forwarding
  2355	                                    .zone_id_to_name
  2356	                                    .get(&from_zone_id)
  2357	                                    .map(|s| s.as_str())
  2358	                                    .unwrap_or("");
  2359	                                let to_zone: &str = worker_ctx
  2360	                                    .forwarding
  2361	                                    .zone_id_to_name
  2362	                                    .get(&to_zone_id)
  2363	                                    .map(|s| s.as_str())
  2364	                                    .unwrap_or("");
  2365	                                // Send ARP/NDP solicitation via RAW socket (not XSK)
  2366	                                // so the reply goes through the kernel's normal RX
  2367	                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
  2368	                                // Also reinject original packet to slow-path for kernel
  2369	                                // to forward once the neighbor is resolved.
  2370	                                // Trigger ARP/NDP resolution via kernel netlink.
  2371	                                // Adding an INCOMPLETE neighbor entry makes the
  2372	                                // kernel send its own ARP/NDP solicitation through
  2373	                                // the normal stack, which correctly handles VLAN
  2374	                                // tagging and TX offload. The netlink monitor then
  2375	                                // picks up the resolved entry instantly.
  2376	                                if let Some(next_hop) = decision.resolution.next_hop {
  2377	                                    // Only spawn ping if we don't already have a
  2378	                                    // pending probe for this (ifindex, hop).
  2379	                                    // #1771 §2.2: pending_neigh is keyed by
  2380	                                    // (egress_ifindex, next_hop), so the
  2381	                                    // "already probing this hop" dedup is a
  2382	                                    // direct contains_key (was an O(n) iter scan).
  2383	                                    let already_probing = binding.pending_neigh.contains_key(&(
  2384	                                        decision.resolution.egress_ifindex,
  2385	                                        next_hop,
  2386	                                    ));
  2387	                                    if !already_probing {
  2388	                                        let iface_name = worker_ctx.forwarding
  2389	                                            .ifindex_to_name
  2390	                                            .get(&decision.resolution.egress_ifindex)
  2391	                                            .cloned();
  2392	                                        if let Some(name) = iface_name {
  2393	                                            // Fast path: ICMP socket triggers kernel ARP
  2394	                                            // in microseconds (no fork/exec).
  2395	                                            trigger_kernel_arp_probe(&name, next_hop);
  2396	                                        }
  2397	                                    }
  2398	                                }
  2399	                                // Create the session NOW so the SYN-ACK (reverse
  2400	                                // direction) finds the forward NAT match and creates
  2401	                                // a reverse session. Without this, the SYN-ACK hits
  2402	                                // session miss → policy deny (no rule for WAN→LAN).
  2403	                                let mut pending_decision = decision;
  2404	                                let mut source_nat_release_key = None;
  2405	                                // #1861 §5.3: true when the seed install was
  2406	                                // ATTEMPTED and refused (max_sessions). Gates
  2407	                                // the pending-neighbor buffering below: a
  2408	                                // refused seed's SNAT allocation was rolled
  2409	                                // back, so replaying the buffered frame after
  2410	                                // neighbor resolution would forward it on an
  2411	                                // unreserved NAT tuple with no session. Flow-
  2412	                                // less packets (no install attempted) keep
  2413	                                // buffering as before.
  2414	                                let mut seed_install_refused = false;
  2415	                                if let Some(flow) = flow.as_ref() {
  2416	                                    // #1620: cold-path histogram pre-eval gate
  2417	                                    // (session-install slow path). Per plan v4
  2418	                                    // §4.4: scoped &mut borrow ends before eval.
  2419	                                    let (cp_sample_tag, cp_t_in) = {
  2420	                                        let cp = &mut binding.cold_path;
  2421	                                        cp.sample_phase =
  2422	                                            cp.sample_phase.wrapping_add(1);
  2423	                                        let tag = (cp.sample_phase
  2424	                                            & worker_ctx.cold_path_sample_mask)
  2425	                                            == 0;
  2426	                                        let t = if tag {
  2427	                                            crate::afxdp::cold_path_hist::sample_tsc_start()
  2428	                                        } else {
  2429	                                            0
  2430	                                        };
  2431	                                        (tag, t)
  2432	                                    };
  2433	                                    let permit = matches!(
  2434	                                        evaluate_policy_with_len(
  2435	                                            &worker_ctx.forwarding.policy,
  2436	                                            from_zone_id,
  2437	                                            to_zone_id,
  2438	                                            flow.src_ip,
  2439	                                            flow.dst_ip,
  2440	                                            flow.forward_key.protocol,
  2441	                                            flow.forward_key.src_port,
  2442	                                            flow.forward_key.dst_port,
  2443	                                            desc.len as u64,
  2444	                                        ),
  2445	                                        PolicyAction::Permit
  2446	                                    );
  2447	                                    // #1620: cold-path histogram post-eval record.
  2448	                                    if cp_sample_tag {
  2449	                                        let t_out =
  2450	                                            crate::afxdp::cold_path_hist::sample_tsc_end();
  2451	                                        let q32 = binding.cold_path.ns_per_tsc_q32;
  2452	                                        if q32 != 0 {
  2453	                                            let delta_tsc =
  2454	                                                t_out.saturating_sub(cp_t_in);
  2455	                                            let raw_ns = ((delta_tsc as u128
  2456	                                                * q32 as u128)
  2457	                                                >> 32)
  2458	                                                as u64;
  2459	                                            let baseline =
  2460	                                                binding.cold_path.wrapper_ns_baseline;
  2461	                                            let delta_ns = if raw_ns < baseline {
  2462	                                                binding
  2463	                                                    .cold_path
  2464	                                                    .wrapper_underflow_count = binding
  2465	                                                    .cold_path
  2466	                                                    .wrapper_underflow_count
  2467	                                                    .saturating_add(1);
  2468	                                                0
  2469	                                            } else {
  2470	                                                raw_ns - baseline
  2471	                                            };
  2472	                                            // #1635: direct slot map lookup;
  2473	                                            // skip the sample on a miss.
  2474	                                            if let Some(slot) =
  2475	                                                crate::afxdp::cold_path_hist::lookup_slot(
  2476	                                                    &worker_ctx
  2477	                                                        .forwarding
  2478	                                                        .cold_path_slot_map,
  2479	                                                    from_zone_id,
  2480	                                                    to_zone_id,
  2481	                                                )
  2482	                                            {
  2483	                                                binding.cold_path.record_sample(
  2484	                                                    slot,
  2485	                                                    from_zone_id,
  2486	                                                    to_zone_id,
  2487	                                                    delta_ns,
  2488	                                                );
  2489	                                            }
  2490	                                        }
  2491	                                    }
  2492	                                    if permit {
  2493	                                        let nat_match_flow = flow.with_destination(
  2494	                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
  2495	                                        );
  2496	                                        // #1852: gate pool-mode SNAT allocation
  2497	                                        // for a non-first fragment (no L4 ports).
  2498	                                        let snat_non_first_fragment = {
  2499	                                            let l3 = meta.l3_offset as usize;
  2500	                                            l3 <= packet_frame.len()
  2501	                                                && is_non_first_fragment(
  2502	                                                    &packet_frame[l3..],
  2503	                                                    meta.addr_family,
  2504	                                                )
  2505	                                        };
  2506	                                        if pending_decision.nat.rewrite_dst.is_none() {
  2507	                                            match source_nat_decision_for_flow(
  2508	                                                worker_ctx.forwarding,
  2509	                                                &from_zone,
  2510	                                                &to_zone,
  2511	                                                pending_decision.resolution.egress_ifindex,
  2512	                                                &nat_match_flow,
  2513	                                                now_ns,
  2514	                                                snat_non_first_fragment,
  2515	                                            ) {
  2516	                                                Ok(snat_decision) => {
  2517	                                                    pending_decision.nat = snat_decision;
  2518	                                                    source_nat_release_key =
  2519	                                                        Some(nat_match_flow.forward_key.clone());
  2520	                                                }
  2521	                                                Err(failure) => {
  2522	                                                    record_source_nat_failure(
  2523	                                                        telemetry,
  2524	                                                        worker_ctx,
  2525	                                                        meta,
  2526	                                                        flow,
  2527	                                                        from_zone_id,
  2528	                                                        to_zone_id,
  2529	                                                        desc.len,
  2530	                                                        &failure,
  2531	                                                    );
  2532	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2533	                                                    continue;
  2534	                                                }
  2535	                                            }
  2536	                                        } else {
  2537	                                            match source_nat_decision_for_flow(
  2538	                                                worker_ctx.forwarding,
  2539	                                                &from_zone,
  2540	                                                &to_zone,
  2541	                                                pending_decision.resolution.egress_ifindex,
  2542	                                                &nat_match_flow,
  2543	                                                now_ns,
  2544	                                                snat_non_first_fragment,
  2545	                                            ) {
  2546	                                                Ok(snat_decision) => {
  2547	                                                    pending_decision.nat =
  2548	                                                        pending_decision.nat.merge(snat_decision);
  2549	                                                    source_nat_release_key =
  2550	                                                        Some(nat_match_flow.forward_key.clone());
  2551	                                                }
  2552	                                                Err(failure) => {
  2553	                                                    record_source_nat_failure(
  2554	                                                        telemetry,
  2555	                                                        worker_ctx,
  2556	                                                        meta,
  2557	                                                        flow,
  2558	                                                        from_zone_id,
  2559	                                                        to_zone_id,
  2560	                                                        desc.len,
  2561	                                                        &failure,
  2562	                                                    );
  2563	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2564	                                                    continue;
  2565	                                                }
  2566	                                            }
  2567	                                        }
  2568	                                    }
  2569	                                    let sess_meta = build_missing_neighbor_session_metadata(
  2570	                                        worker_ctx.forwarding,
  2571	                                        from_zone_id,
  2572	                                        to_zone_id,
  2573	                                        packet_fabric_ingress,
  2574	                                        pending_decision,
  2575	                                    );
  2576	                                    let pending_installed =
  2577	                                        sessions.install_with_protocol_with_origin(
  2578	                                            flow.forward_key.clone(),
  2579	                                            pending_decision,
  2580	                                            sess_meta.clone(),
  2581	                                            SessionOrigin::MissingNeighborSeed,
  2582	                                            now_ns,
  2583	                                            meta.protocol,
  2584	                                            meta.tcp_flags,
  2585	                                        );
  2586	                                    if pending_installed {
  2587	                                        let entry = SyncedSessionEntry {
  2588	                                            key: flow.forward_key.clone(),
  2589	                                            decision: pending_decision,
  2590	                                            metadata: sess_meta,
  2591	                                            origin: SessionOrigin::MissingNeighborSeed,
  2592	                                            protocol: meta.protocol,
  2593	                                            tcp_flags: meta.tcp_flags,
  2594	                                        };
  2595	                                        publish_shared_session(
  2596	                                            worker_ctx.shared_sessions,
  2597	                                            worker_ctx.shared_nat_sessions,
  2598	                                            worker_ctx.shared_forward_wire_sessions,
  2599	                                            &worker_ctx.shared_owner_rg_indexes,
  2600	                                            &entry,
  2601	                                        );
  2602	                                        // #1789: count a failed publish
  2603	                                        // (shim misses the key -> NO_SESSION
  2604	                                        // degraded path for the seeded flow).
  2605	                                        if publish_session_map_entry_for_session(
  2606	                                            binding.bpf_maps.session_map_fd,
  2607	                                            &flow.forward_key,
  2608	                                            pending_decision,
  2609	                                            &entry.metadata,
  2610	                                        )
  2611	                                        .is_err()
  2612	                                        {
  2613	                                            binding
  2614	                                                .live
  2615	                                                .session_publish_errors
  2616	                                                .fetch_add(1, Ordering::Relaxed);
  2617	                                        }
  2618	                                        publish_bpf_conntrack_entry(
  2619	                                            conntrack_v4_fd,
  2620	                                            conntrack_v6_fd,
  2621	                                            &flow.forward_key,
  2622	                                            pending_decision,
  2623	                                            &entry.metadata,
  2624	                                            &worker_ctx.forwarding.zone_name_to_id,
  2625	                                        );
  2626	                                        publish_dnat_table_entry(
  2627	                                            &worker_ctx.dnat_fds,
  2628	                                            &flow.forward_key,
  2629	                                            pending_decision.nat,
  2630	                                        );
  2631	                                        telemetry.counters.session_creates += 1;
  2632	                                    } else {
  2633	                                        // #1861 §5.3: at-cap seed refusal. The
  2634	                                        // single-entry install IS the
  2635	                                        // transaction here (no pair); the
  2636	                                        // refusal is counted by the table's
  2637	                                        // create_drops (exported since #1861 —
  2638	                                        // admission_refused stays preflight-
  2639	                                        // only). Roll back the SNAT allocation
  2640	                                        // and drop the frame instead of
  2641	                                        // buffering it for replay.
  2642	                                        seed_install_refused = true;
  2643	                                        rollback_source_nat_allocation(
  2644	                                            &worker_ctx.forwarding.source_nat_rules,
  2645	                                            source_nat_release_key
  2646	                                                .as_ref()
  2647	                                                .unwrap_or(&flow.forward_key),
  2648	                                            pending_decision.nat,
  2649	                                            false,
  2650	                                            now_ns,
  2651	                                        );
  2652	                                    }
  2653	                                }
  2654	                                // Buffer the packet. The ICMP probe resolves ARP
  2655	                                // in ~1ms. The retry loop below re-forwards the
  2656	                                // buffered packet once the neighbor resolves via the
  2657	                                // netlink monitor. The session was already created
  2658	                                // above so the SYN-ACK reverse path works too.
  2659	                                // Total latency: ~2ms (ARP + netlink + retry).
  2660	                                //
  2661	                                // NOTE: we do NOT reinject to slow-path here because
  2662	                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
  2663	                                // in zero-copy mode (mlx5). The ICMP probe + netlink
  2664	                                // monitor + buffer-retry path bypasses this issue.
  2665	                                // #1771 §2.2: buffer one representative packet
  2666	                                // per (egress_ifindex, next_hop). Keep the
  2667	                                // OLDEST (it drives the probe/dwell clock):
  2668	                                // a duplicate for an already-buffered hop is
  2669	                                // dropped+recycled (recycle_now stays true),
  2670	                                // pinning ≤1 UMEM frame per unresolved hop.
  2671	                                // A packet with no next_hop cannot be keyed or
  2672	                                // resolved (the retry sweep needs next_hop to
  2673	                                // look up a MAC), so it is not buffered —
  2674	                                // recycled instead of held until timeout.
  2675	                                // #1861 §5.3: a refused seed is recycled, not
  2676	                                // buffered (see seed_install_refused above) —
  2677	                                // the kernel ARP probe already fired, and the
  2678	                                // next packet retries the install once the
  2679	                                // table has room, converging with the #1771
  2680	                                // duplicate-drop semantics.
  2681	                                // #1873 R-E: tunnel-marked decisions are
  2682	                                // NEVER admitted to pending_neigh. The retry
  2683	                                // path TXes buffered frames via in-place
  2684	                                // MAC/VLAN rewrite with no encapsulation, so
  2685	                                // a buffered tunnel inner packet would go out
  2686	                                // PLAINTEXT on the physical wire when the
  2687	                                // outer neighbor resolves (AGY plan r2,
  2688	                                // verified). The kernel ARP/ICMP probe above
  2689	                                // already fired, and the post-match
  2690	                                // maybe_reinject_slow_path_from_frame call
  2691	                                // routes this frame into the R-C tunnel gate
  2692	                                // (counted drop) — the #1769 resolver keeps
  2693	                                // driving the outer next-hop, and the flow
  2694	                                // recovers via retransmission once resolved.
  2695	                                // #1902 (sibling of #1885): a GRE-DECAPPED
  2696	                                // packet is NEVER admitted to pending_neigh.
  2697	                                // `desc` still references the un-decapped
  2698	                                // OUTER UMEM frame while `meta`/the decision
  2699	                                // describe the synthetic INNER frame in
  2700	                                // `owned_packet_frame`; the retry path's
  2701	                                // rewrite_forwarded_frame_in_place(pkt.desc,
  2702	                                // pkt.meta, ..) would MAC/NAT/TTL-rewrite the
  2703	                                // still-encapsulated outer packet at inner
  2704	                                // offsets and TX it toward the inner next-hop
  2705	                                // — a corrupt transmit, not a drop. The
  2706	                                // kernel ARP/ICMP probe above already fired,
  2707	                                // the trailing decap-aware
  2708	                                // maybe_reinject_slow_path_from_frame
  2709	                                // chokepoint (#1901) still hands the
  2710	                                // correctly-paired INNER packet to the kernel
  2711	                                // slow path, and the #1769 resolver +
  2712	                                // retransmission recover the flow once the
  2713	                                // neighbor resolves. Counted per binding so
  2714	                                // the live gate is observable
  2715	                                // (xpf_userspace_pending_neigh_decap_drops_total).
  2716	                                if !seed_install_refused
  2717	                                    && pending_decision.resolution.tunnel_endpoint_id == 0
  2718	                                    && pending_decision.resolution.next_hop.is_some()
  2719	                                    && owned_packet_frame.is_some()
  2720	                                {
  2721	                                    binding
  2722	                                        .live
  2723	                                        .pending_neigh_decap_drops
  2724	                                        .fetch_add(1, Ordering::Relaxed);
  2725	                                } else if !seed_install_refused
  2726	                                    && pending_decision.resolution.tunnel_endpoint_id == 0
  2727	                                    && let Some(hop) = pending_decision.resolution.next_hop
  2728	                                {
  2729	                                    let pending_key =
  2730	                                        (pending_decision.resolution.egress_ifindex, hop);
  2731	                                    // #1782: split the buffer-admission test so
  2732	                                    // the capture can tell WHY a sibling was not
  2733	                                    // buffered. The DuplicateDrop branch is the
  2734	                                    // H5 sibling drop (key already pending — the
  2735	                                    // first packet drove the kernel probe); the
  2736	                                    // CapacityDrop branch is a distinct
  2737	                                    // condition, counted nowhere here. #1771
  2738	                                    // §2.4: the decision is the pure
  2739	                                    // `pending_neigh_admission` helper so
  2740	                                    // invariant N1's "at most one buffered
  2741	                                    // packet per key" half is unit-tested;
  2742	                                    // behavior is unchanged — an insert happens
  2743	                                    // iff the key is absent AND there is room,
  2744	                                    // otherwise `recycle_now` stays true and
  2745	                                    // the frame is recycled.
  2746	                                    match pending_neigh_admission(
  2747	                                        binding.pending_neigh.contains_key(&pending_key),
  2748	                                        binding.pending_neigh.len(),
  2749	                                    ) {
  2750	                                        PendingNeighAdmission::DuplicateDrop => {
  2751	                                            binding
  2752	                                                .live
  2753	                                                .pending_neigh_duplicate_drops
  2754	                                                .fetch_add(1, Ordering::Relaxed);
  2755	                                        }
  2756	                                        PendingNeighAdmission::Buffer => {
  2757	                                            let pending_flow_key = flow
  2758	                                                .as_ref()
  2759	                                                .map(|flow| flow.forward_key.clone())
  2760	                                                .or_else(|| {
  2761	                                                    parse_session_flow_from_meta(meta)
  2762	                                                        .map(|flow| flow.forward_key)
  2763	                                                });
  2764	                                            binding.pending_neigh.insert(
  2765	                                                pending_key,
  2766	                                                PendingNeighPacket {
  2767	                                                    addr: desc.addr,
  2768	                                                    desc,
  2769	                                                    meta,
  2770	                                                    decision: pending_decision,
  2771	                                                    flow_key: pending_flow_key,
  2772	                                                    queued_ns: now_ns,
  2773	                                                    probe_attempts: 0,
  2774	                                                },
  2775	                                            );
  2776	                                            recycle_now = false;
  2777	                                        }
  2778	                                        PendingNeighAdmission::CapacityDrop => {}
  2779	                                    }
  2780	                                }
  2781	                                if cfg!(feature = "debug-log") {
  2782	                                    if telemetry.dbg.missing_neigh <= 3 {
  2783	                                        if let Some(flow) = flow.as_ref() {
  2784	                                            eprintln!(
  2785	                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
  2786	                                                "SOLICIT+SLOW",
  2787	                                                flow.src_ip,
  2788	                                                flow.forward_key.src_port,
  2789	                                                flow.dst_ip,
  2790	                                                flow.forward_key.dst_port,
  2791	                                                meta.protocol,
  2792	                                                pending_decision.resolution.egress_ifindex,
  2793	                                                pending_decision.resolution.next_hop,
  2794	                                            );
  2795	                                        }
  2796	                                    }
  2797	                                }
  2798	                            }
  2799	                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
  2800	                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
  2801	                            _ => telemetry.dbg.disposition_other += 1,
  2802	                        }
  2803	                        record_forwarding_disposition(
  2804	                            &worker_ctx.ident,
  2805	                            DispositionCounters::Hot(telemetry.counters),
  2806	                            decision.resolution,
  2807	                            desc.len as u32,
  2808	                            Some(meta),
  2809	                            debug.as_ref(),
  2810	                            worker_ctx.recent_exceptions,
  2811	                            worker_ctx.last_resolution,
  2812	                            worker_ctx.forwarding,
  2813	                        );
  2814	                        maybe_reinject_slow_path_from_frame(
  2815	                            &worker_ctx.ident,
  2816	                            &binding.live,
  2817	                            worker_ctx.slow_path,
  2818	                            worker_ctx.local_tunnel_deliveries,
  2819	                            packet_frame,
  2820	                            meta,
  2821	                            decision,
  2822	                            worker_ctx.recent_exceptions,
  2823	                            "slow_path",
  2824	                            worker_ctx.forwarding,
  2825	                        );
  2826	                    }
  2827	                } else {
  2828	                    record_disposition(

exec
/bin/bash -lc "rg -n \"maybe_reinject_slow_path_from_frame\\(|maybe_reinject_slow_path\\(\" userspace-dp/src/afxdp" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/poll_stages.rs:452:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814:                        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:4163:    maybe_reinject_slow_path(
userspace-dp/src/afxdp/tests.rs:4224:    maybe_reinject_slow_path(
userspace-dp/src/afxdp/tests.rs:4287:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:5371:        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:5441:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:61:        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:78:pub(in crate::afxdp) fn maybe_reinject_slow_path(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:113:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:129:pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:225:                    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:238:                    maybe_reinject_slow_path(

codex
So far I do not see a separate drop after `PolicyDenied` is assigned: the next structural gate is the forward/non-forward split, and non-forward falls into the disposition match. I’m checking the long `MissingNeighbor` arm separately because it contains the only `continue` statements in the reviewed range.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1300,1565p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1300	                                                    .as_ref()
  1301	                                                    .unwrap_or(&flow.forward_key),
  1302	                                                decision.nat,
  1303	                                                false,
  1304	                                                now_ns,
  1305	                                            );
  1306	                                            binding.scratch.scratch_recycle.push(desc.addr);
  1307	                                            continue;
  1308	                                        }
  1309	                                        let forward_metadata = SessionMetadata {
  1310	                                            ingress_zone: from_zone_id,
  1311	                                            egress_zone: to_zone_id,
  1312	                                            owner_rg_id,
  1313	                                            fabric_ingress,
  1314	                                            is_reverse: false,
  1315	                                            nat64_reverse: nat64_info,
  1316	                                        };
  1317	                                        let forward_installed = track_in_userspace
  1318	                                            && sessions.install_with_protocol_with_origin(
  1319	                                                flow.forward_key.clone(),
  1320	                                                decision,
  1321	                                                forward_metadata.clone(),
  1322	                                                SessionOrigin::ForwardFlow,
  1323	                                                now_ns,
  1324	                                                meta.protocol,
  1325	                                                meta.tcp_flags,
  1326	                                            );
  1327	                                        if track_in_userspace && !forward_installed {
  1328	                                            // #1861 §5.2 residual: impossible by
  1329	                                            // construction after a passing
  1330	                                            // can_admit (cap is the only install
  1331	                                            // failure mode; nothing mutates the
  1332	                                            // table mid-iteration). Debug: loud.
  1333	                                            // Release (#1855 contract): count,
  1334	                                            // roll back, drop — never half-commit.
  1335	                                            debug_assert!(
  1336	                                                false,
  1337	                                                "forward install failed after can_admit preflight"
  1338	                                            );
  1339	                                            sessions.note_install_partial();
  1340	                                            rollback_source_nat_allocation(
  1341	                                                &worker_ctx.forwarding.source_nat_rules,
  1342	                                                source_nat_release_key
  1343	                                                    .as_ref()
  1344	                                                    .unwrap_or(&flow.forward_key),
  1345	                                                decision.nat,
  1346	                                                false,
  1347	                                                now_ns,
  1348	                                            );
  1349	                                            binding.scratch.scratch_recycle.push(desc.addr);
  1350	                                            continue;
  1351	                                        }
  1352	                                        if forward_installed {
  1353	                                            created += 1;
  1354	                                            let forward_entry = SyncedSessionEntry {
  1355	                                                key: flow.forward_key.clone(),
  1356	                                                decision,
  1357	                                                metadata: forward_metadata,
  1358	                                                origin: SessionOrigin::ForwardFlow,
  1359	                                                protocol: meta.protocol,
  1360	                                                tcp_flags: meta.tcp_flags,
  1361	                                            };
  1362	                                            // #1789: count failed publishes so
  1363	                                            // map-at-capacity / stale-fd
  1364	                                            // failures are visible in release
  1365	                                            // builds (was `let _ =`).
  1366	                                            if publish_live_session_entry(
  1367	                                                binding.bpf_maps.session_map_fd,
  1368	                                                &flow.forward_key,
  1369	                                                decision.nat,
  1370	                                                false,
  1371	                                            )
  1372	                                            .is_err()
  1373	                                            {
  1374	                                                binding
  1375	                                                    .live
  1376	                                                    .session_publish_errors
  1377	                                                    .fetch_add(1, Ordering::Relaxed);
  1378	                                            }
  1379	                                            publish_shared_session(
  1380	                                                worker_ctx.shared_sessions,
  1381	                                                worker_ctx.shared_nat_sessions,
  1382	                                                worker_ctx.shared_forward_wire_sessions,
  1383	                                                &worker_ctx.shared_owner_rg_indexes,
  1384	                                                &forward_entry,
  1385	                                            );
  1386	                                            // Populate BPF dnat_table for embedded ICMP NAT reversal.
  1387	                                            // Without this, mtr/traceroute intermediate hops are invisible.
  1388	                                            publish_dnat_table_entry(
  1389	                                                &worker_ctx.dnat_fds,
  1390	                                                &flow.forward_key,
  1391	                                                decision.nat,
  1392	                                            );
  1393	                                            replicate_session_upsert(
  1394	                                                worker_ctx.peer_worker_commands,
  1395	                                                &forward_entry,
  1396	                                            );
  1397	                                            if let Some(cached_log) =
  1398	                                                input_filter_eval.cached_log
  1399	                                            {
  1400	                                                emit_input_filter_log_match(
  1401	                                                    worker_ctx.event_stream,
  1402	                                                    flow,
  1403	                                                    meta,
  1404	                                                    cached_log,
  1405	                                                    now_ns,
  1406	                                                );
  1407	                                            }
  1408	                                        } else {
  1409	                                            // #1861: only reachable when
  1410	                                            // track_in_userspace == false (a true
  1411	                                            // install failure now drops above) —
  1412	                                            // no session anchors the NAT state, so
  1413	                                            // release any allocation. No-op for the
  1414	                                            // DNS fast-path (its guard requires no
  1415	                                            // NAT).
  1416	                                            rollback_source_nat_allocation(
  1417	                                                &worker_ctx.forwarding.source_nat_rules,
  1418	                                                source_nat_release_key
  1419	                                                    .as_ref()
  1420	                                                    .unwrap_or(&flow.forward_key),
  1421	                                                decision.nat,
  1422	                                                false,
  1423	                                                now_ns,
  1424	                                            );
  1425	                                        }
  1426	                                        let reverse_resolution = reverse_resolution_for_session(
  1427	                                            worker_ctx.forwarding,
  1428	                                            worker_ctx.ha_state,
  1429	                                            worker_ctx.dynamic_neighbors,
  1430	                                            flow.src_ip,
  1431	                                            from_zone_id,
  1432	                                            fabric_ingress,
  1433	                                            now_secs,
  1434	                                            false,
  1435	                                        );
  1436	                                        // Install the reverse entry even if the initial reply-side
  1437	                                        // resolution is not immediately usable. On live traffic the
  1438	                                        // first server reply can arrive before the reverse neighbor
  1439	                                        // state has converged on every worker, and dropping the reverse
  1440	                                        // entry creation turns that race into a hard policy miss. The
  1441	                                        // hit path re-resolves on demand and can fall back to the
  1442	                                        // cached decision when neighbor convergence is still in flight.
  1443	                                        let reverse_decision = SessionDecision {
  1444	                                            resolution: reverse_resolution,
  1445	                                            nat: decision.nat.reverse(
  1446	                                                flow.src_ip,
  1447	                                                flow.dst_ip,
  1448	                                                flow.forward_key.src_port,
  1449	                                                flow.forward_key.dst_port,
  1450	                                            ),
  1451	                                        };
  1452	                                        // For NAT64: the reverse key is IPv4 (different AF
  1453	                                        // from the forward IPv6 key). The reply arrives as
  1454	                                        // IPv4: src=dst_v4, dst=snat_v4.
  1455	                                        let (reverse_key, reverse_protocol) = if nat64_info
  1456	                                            .is_some()
  1457	                                        {
  1458	                                            let nat = decision.nat;
  1459	                                            let dst_v4 = match nat.rewrite_dst {
  1460	                                                Some(IpAddr::V4(v4)) => v4,
  1461	                                                _ => Ipv4Addr::UNSPECIFIED,
  1462	                                            };
  1463	                                            let snat_v4 = match nat.rewrite_src {
  1464	                                                Some(IpAddr::V4(v4)) => v4,
  1465	                                                _ => Ipv4Addr::UNSPECIFIED,
  1466	                                            };
  1467	                                            // Map protocol: ICMPv6→ICMP for the reverse key.
  1468	                                            let rev_proto = match meta.protocol {
  1469	                                                PROTO_ICMPV6 => PROTO_ICMP,
  1470	                                                p => p,
  1471	                                            };
  1472	                                            let (src_port, dst_port) = if matches!(
  1473	                                                meta.protocol,
  1474	                                                PROTO_ICMP | PROTO_ICMPV6
  1475	                                            ) {
  1476	                                                (
  1477	                                                    flow.forward_key.src_port,
  1478	                                                    flow.forward_key.dst_port,
  1479	                                                )
  1480	                                            } else {
  1481	                                                (
  1482	                                                    flow.forward_key.dst_port,
  1483	                                                    flow.forward_key.src_port,
  1484	                                                )
  1485	                                            };
  1486	                                            (
  1487	                                                SessionKey {
  1488	                                                    addr_family: libc::AF_INET as u8,
  1489	                                                    protocol: rev_proto,
  1490	                                                    src_ip: IpAddr::V4(dst_v4),
  1491	                                                    dst_ip: IpAddr::V4(snat_v4),
  1492	                                                    src_port,
  1493	                                                    dst_port,
  1494	                                                },
  1495	                                                rev_proto,
  1496	                                            )
  1497	                                        } else {
  1498	                                            (flow.reverse_key_with_nat(decision.nat), meta.protocol)
  1499	                                        };
  1500	                                        let _ = reverse_protocol; // used below for install
  1501	                                        let reverse_metadata = SessionMetadata {
  1502	                                            ingress_zone: to_zone_id,
  1503	                                            egress_zone: from_zone_id,
  1504	                                            owner_rg_id,
  1505	                                            fabric_ingress,
  1506	                                            is_reverse: true,
  1507	                                            nat64_reverse: nat64_info,
  1508	                                        };
  1509	                                        // #1861 §5.2: the reverse install is gated on
  1510	                                        // forward_installed (was track_in_userspace —
  1511	                                        // a forward failure used to fall through and
  1512	                                        // still attempt the reverse, the latent
  1513	                                        // half-open-reverse hazard). At this point
  1514	                                        // track_in_userspace ⇒ forward_installed
  1515	                                        // (the residual arm above drops otherwise),
  1516	                                        // so this gate is explicit, not a behavior
  1517	                                        // fork.
  1518	                                        let reverse_installed = forward_installed
  1519	                                            && install_local_reverse
  1520	                                            && sessions.install_with_protocol_with_origin(
  1521	                                                reverse_key.clone(),
  1522	                                                reverse_decision,
  1523	                                                reverse_metadata.clone(),
  1524	                                                SessionOrigin::ReverseFlow,
  1525	                                                now_ns,
  1526	                                                meta.protocol,
  1527	                                                meta.tcp_flags,
  1528	                                            );
  1529	                                        if forward_installed
  1530	                                            && install_local_reverse
  1531	                                            && !reverse_installed
  1532	                                        {
  1533	                                            // #1861 §5.2 residual (reverse half):
  1534	                                            // impossible after a passing can_admit
  1535	                                            // for needed_sessions == 2. Release
  1536	                                            // (#1855 contract): keep the committed
  1537	                                            // forward (the reply repair services
  1538	                                            // inbound), count, and suppress the
  1539	                                            // flow-cache entry so the partially-
  1540	                                            // installed flow is re-evaluated per
  1541	                                            // packet instead of being persisted.
  1542	                                            debug_assert!(
  1543	                                                false,
  1544	                                                "reverse install failed after can_admit preflight"
  1545	                                            );
  1546	                                            sessions.note_install_partial();
  1547	                                            flow_cache_install_failed = true;
  1548	                                        }
  1549	                                        if reverse_installed {
  1550	                                            // #1789: count failed reverse-key
  1551	                                            // publishes (was `let _ =`; the
  1552	                                            // debug-only verify below re-reads
  1553	                                            // the map and cannot see the Err).
  1554	                                            if publish_live_session_key(
  1555	                                                binding.bpf_maps.session_map_fd,
  1556	                                                &reverse_key,
  1557	                                            )
  1558	                                            .is_err()
  1559	                                            {
  1560	                                                binding
  1561	                                                    .live
  1562	                                                    .session_publish_errors
  1563	                                                    .fetch_add(1, Ordering::Relaxed);
  1564	                                            }
  1565	                                            // Verify session keys and log creations (debug-only: BPF syscalls)

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2400,2570p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2400	                                // direction) finds the forward NAT match and creates
  2401	                                // a reverse session. Without this, the SYN-ACK hits
  2402	                                // session miss → policy deny (no rule for WAN→LAN).
  2403	                                let mut pending_decision = decision;
  2404	                                let mut source_nat_release_key = None;
  2405	                                // #1861 §5.3: true when the seed install was
  2406	                                // ATTEMPTED and refused (max_sessions). Gates
  2407	                                // the pending-neighbor buffering below: a
  2408	                                // refused seed's SNAT allocation was rolled
  2409	                                // back, so replaying the buffered frame after
  2410	                                // neighbor resolution would forward it on an
  2411	                                // unreserved NAT tuple with no session. Flow-
  2412	                                // less packets (no install attempted) keep
  2413	                                // buffering as before.
  2414	                                let mut seed_install_refused = false;
  2415	                                if let Some(flow) = flow.as_ref() {
  2416	                                    // #1620: cold-path histogram pre-eval gate
  2417	                                    // (session-install slow path). Per plan v4
  2418	                                    // §4.4: scoped &mut borrow ends before eval.
  2419	                                    let (cp_sample_tag, cp_t_in) = {
  2420	                                        let cp = &mut binding.cold_path;
  2421	                                        cp.sample_phase =
  2422	                                            cp.sample_phase.wrapping_add(1);
  2423	                                        let tag = (cp.sample_phase
  2424	                                            & worker_ctx.cold_path_sample_mask)
  2425	                                            == 0;
  2426	                                        let t = if tag {
  2427	                                            crate::afxdp::cold_path_hist::sample_tsc_start()
  2428	                                        } else {
  2429	                                            0
  2430	                                        };
  2431	                                        (tag, t)
  2432	                                    };
  2433	                                    let permit = matches!(
  2434	                                        evaluate_policy_with_len(
  2435	                                            &worker_ctx.forwarding.policy,
  2436	                                            from_zone_id,
  2437	                                            to_zone_id,
  2438	                                            flow.src_ip,
  2439	                                            flow.dst_ip,
  2440	                                            flow.forward_key.protocol,
  2441	                                            flow.forward_key.src_port,
  2442	                                            flow.forward_key.dst_port,
  2443	                                            desc.len as u64,
  2444	                                        ),
  2445	                                        PolicyAction::Permit
  2446	                                    );
  2447	                                    // #1620: cold-path histogram post-eval record.
  2448	                                    if cp_sample_tag {
  2449	                                        let t_out =
  2450	                                            crate::afxdp::cold_path_hist::sample_tsc_end();
  2451	                                        let q32 = binding.cold_path.ns_per_tsc_q32;
  2452	                                        if q32 != 0 {
  2453	                                            let delta_tsc =
  2454	                                                t_out.saturating_sub(cp_t_in);
  2455	                                            let raw_ns = ((delta_tsc as u128
  2456	                                                * q32 as u128)
  2457	                                                >> 32)
  2458	                                                as u64;
  2459	                                            let baseline =
  2460	                                                binding.cold_path.wrapper_ns_baseline;
  2461	                                            let delta_ns = if raw_ns < baseline {
  2462	                                                binding
  2463	                                                    .cold_path
  2464	                                                    .wrapper_underflow_count = binding
  2465	                                                    .cold_path
  2466	                                                    .wrapper_underflow_count
  2467	                                                    .saturating_add(1);
  2468	                                                0
  2469	                                            } else {
  2470	                                                raw_ns - baseline
  2471	                                            };
  2472	                                            // #1635: direct slot map lookup;
  2473	                                            // skip the sample on a miss.
  2474	                                            if let Some(slot) =
  2475	                                                crate::afxdp::cold_path_hist::lookup_slot(
  2476	                                                    &worker_ctx
  2477	                                                        .forwarding
  2478	                                                        .cold_path_slot_map,
  2479	                                                    from_zone_id,
  2480	                                                    to_zone_id,
  2481	                                                )
  2482	                                            {
  2483	                                                binding.cold_path.record_sample(
  2484	                                                    slot,
  2485	                                                    from_zone_id,
  2486	                                                    to_zone_id,
  2487	                                                    delta_ns,
  2488	                                                );
  2489	                                            }
  2490	                                        }
  2491	                                    }
  2492	                                    if permit {
  2493	                                        let nat_match_flow = flow.with_destination(
  2494	                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
  2495	                                        );
  2496	                                        // #1852: gate pool-mode SNAT allocation
  2497	                                        // for a non-first fragment (no L4 ports).
  2498	                                        let snat_non_first_fragment = {
  2499	                                            let l3 = meta.l3_offset as usize;
  2500	                                            l3 <= packet_frame.len()
  2501	                                                && is_non_first_fragment(
  2502	                                                    &packet_frame[l3..],
  2503	                                                    meta.addr_family,
  2504	                                                )
  2505	                                        };
  2506	                                        if pending_decision.nat.rewrite_dst.is_none() {
  2507	                                            match source_nat_decision_for_flow(
  2508	                                                worker_ctx.forwarding,
  2509	                                                &from_zone,
  2510	                                                &to_zone,
  2511	                                                pending_decision.resolution.egress_ifindex,
  2512	                                                &nat_match_flow,
  2513	                                                now_ns,
  2514	                                                snat_non_first_fragment,
  2515	                                            ) {
  2516	                                                Ok(snat_decision) => {
  2517	                                                    pending_decision.nat = snat_decision;
  2518	                                                    source_nat_release_key =
  2519	                                                        Some(nat_match_flow.forward_key.clone());
  2520	                                                }
  2521	                                                Err(failure) => {
  2522	                                                    record_source_nat_failure(
  2523	                                                        telemetry,
  2524	                                                        worker_ctx,
  2525	                                                        meta,
  2526	                                                        flow,
  2527	                                                        from_zone_id,
  2528	                                                        to_zone_id,
  2529	                                                        desc.len,
  2530	                                                        &failure,
  2531	                                                    );
  2532	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2533	                                                    continue;
  2534	                                                }
  2535	                                            }
  2536	                                        } else {
  2537	                                            match source_nat_decision_for_flow(
  2538	                                                worker_ctx.forwarding,
  2539	                                                &from_zone,
  2540	                                                &to_zone,
  2541	                                                pending_decision.resolution.egress_ifindex,
  2542	                                                &nat_match_flow,
  2543	                                                now_ns,
  2544	                                                snat_non_first_fragment,
  2545	                                            ) {
  2546	                                                Ok(snat_decision) => {
  2547	                                                    pending_decision.nat =
  2548	                                                        pending_decision.nat.merge(snat_decision);
  2549	                                                    source_nat_release_key =
  2550	                                                        Some(nat_match_flow.forward_key.clone());
  2551	                                                }
  2552	                                                Err(failure) => {
  2553	                                                    record_source_nat_failure(
  2554	                                                        telemetry,
  2555	                                                        worker_ctx,
  2556	                                                        meta,
  2557	                                                        flow,
  2558	                                                        from_zone_id,
  2559	                                                        to_zone_id,
  2560	                                                        desc.len,
  2561	                                                        &failure,
  2562	                                                    );
  2563	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2564	                                                    continue;
  2565	                                                }
  2566	                                            }
  2567	                                        }
  2568	                                    }
  2569	                                    let sess_meta = build_missing_neighbor_session_metadata(
  2570	                                        worker_ctx.forwarding,

exec
/bin/bash -lc 'rg -n "enum ForwardingDisposition|ForwardingDisposition" userspace-dp/src | head -100' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/session/mod.rs:1:use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
userspace-dp/src/session/mod.rs:1232:            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
userspace-dp/src/session/tests.rs:35:        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
userspace-dp/src/session/tests.rs:706:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/session/tests.rs:738:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/server/helpers.rs:357:                    afxdp::ForwardingDisposition::ForwardCandidate
userspace-dp/src/server/helpers.rs:359:                    afxdp::ForwardingDisposition::NoRoute
userspace-dp/src/filter/README.md:245:`ForwardingDisposition::LocalDelivery`, which
userspace-dp/src/main_tests.rs:401:        afxdp::ForwardingDisposition::ForwardCandidate
userspace-dp/src/event_stream/codec.rs:6:use crate::afxdp::ForwardingDisposition;
userspace-dp/src/event_stream/codec.rs:219:            || decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/event_stream/codec.rs:612:fn encode_disposition(d: ForwardingDisposition) -> u8 {
userspace-dp/src/event_stream/codec.rs:614:        ForwardingDisposition::ForwardCandidate => DISP_FORWARD_CANDIDATE,
userspace-dp/src/event_stream/codec.rs:615:        ForwardingDisposition::LocalDelivery => DISP_LOCAL_DELIVERY,
userspace-dp/src/event_stream/codec.rs:616:        ForwardingDisposition::FabricRedirect => DISP_FABRIC_REDIRECT,
userspace-dp/src/event_stream/codec.rs:617:        ForwardingDisposition::PolicyDenied => DISP_POLICY_DENIED,
userspace-dp/src/event_stream/codec.rs:618:        ForwardingDisposition::NoRoute => DISP_NO_ROUTE,
userspace-dp/src/event_stream/codec.rs:619:        ForwardingDisposition::MissingNeighbor => DISP_MISSING_NEIGHBOR,
userspace-dp/src/event_stream/codec.rs:620:        ForwardingDisposition::HAInactive => DISP_HA_INACTIVE,
userspace-dp/src/event_stream/codec.rs:621:        ForwardingDisposition::DiscardRoute => DISP_DISCARD_ROUTE,
userspace-dp/src/event_stream/codec.rs:622:        ForwardingDisposition::NextTableUnsupported => DISP_NEXT_TABLE_UNSUPPORTED,
userspace-dp/src/event_stream/codec.rs:630:        || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/event_stream/codec_tests.rs:45:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/event_stream/codec_tests.rs:435:        encode_disposition(ForwardingDisposition::ForwardCandidate),
userspace-dp/src/event_stream/codec_tests.rs:438:    assert_eq!(encode_disposition(ForwardingDisposition::LocalDelivery), 1);
userspace-dp/src/event_stream/codec_tests.rs:439:    assert_eq!(encode_disposition(ForwardingDisposition::FabricRedirect), 2);
userspace-dp/src/event_stream/codec_tests.rs:440:    assert_eq!(encode_disposition(ForwardingDisposition::PolicyDenied), 3);
userspace-dp/src/event_stream/codec_tests.rs:441:    assert_eq!(encode_disposition(ForwardingDisposition::NoRoute), 4);
userspace-dp/src/event_stream/codec_tests.rs:443:        encode_disposition(ForwardingDisposition::MissingNeighbor),
userspace-dp/src/event_stream/codec_tests.rs:446:    assert_eq!(encode_disposition(ForwardingDisposition::HAInactive), 6);
userspace-dp/src/event_stream/codec_tests.rs:447:    assert_eq!(encode_disposition(ForwardingDisposition::DiscardRoute), 7);
userspace-dp/src/event_stream/codec_tests.rs:449:        encode_disposition(ForwardingDisposition::NextTableUnsupported),
userspace-dp/src/afxdp/disposition.rs:331:        ForwardingDisposition::LocalDelivery => {
userspace-dp/src/afxdp/disposition.rs:334:        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
userspace-dp/src/afxdp/disposition.rs:337:        ForwardingDisposition::HAInactive => {
userspace-dp/src/afxdp/disposition.rs:350:        ForwardingDisposition::PolicyDenied => {
userspace-dp/src/afxdp/disposition.rs:363:        ForwardingDisposition::NoRoute => {
userspace-dp/src/afxdp/disposition.rs:376:        ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/disposition.rs:389:        ForwardingDisposition::DiscardRoute => {
userspace-dp/src/afxdp/disposition.rs:402:        ForwardingDisposition::NextTableUnsupported => {
userspace-dp/src/afxdp/coordinator/inject.rs:178:                        if resolution.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs:67:                != ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/coordinator/tests.rs:164:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:55:        if re_resolved.disposition != ForwardingDisposition::HAInactive {
userspace-dp/src/afxdp/session_glue/promote.rs:87:        || decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/ha.rs:516:                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/shared_ops.rs:603:        || forward_match.decision.resolution.disposition == ForwardingDisposition::FabricRedirect;
userspace-dp/src/afxdp/shared_ops.rs:702:        && enforced.disposition == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/session_delta.rs:90:                ForwardingDisposition::ForwardCandidate => "forward_candidate",
userspace-dp/src/afxdp/session_delta.rs:91:                ForwardingDisposition::LocalDelivery => "local_delivery",
userspace-dp/src/afxdp/session_delta.rs:92:                ForwardingDisposition::NoRoute => "no_route",
userspace-dp/src/afxdp/session_delta.rs:93:                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
userspace-dp/src/afxdp/session_delta.rs:94:                ForwardingDisposition::PolicyDenied => "policy_denied",
userspace-dp/src/afxdp/session_delta.rs:95:                ForwardingDisposition::FabricRedirect => "fabric_redirect",
userspace-dp/src/afxdp/session_delta.rs:96:                ForwardingDisposition::HAInactive => "ha_inactive",
userspace-dp/src/afxdp/session_delta.rs:97:                ForwardingDisposition::DiscardRoute => "discard_route",
userspace-dp/src/afxdp/session_delta.rs:98:                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
userspace-dp/src/afxdp/session_delta.rs:139:                || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/mod.rs:22:    if cached.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/session_glue/mod.rs:29:    fallback.disposition = ForwardingDisposition::ForwardCandidate;
userspace-dp/src/afxdp/session_glue/mod.rs:87:    if decision.resolution.disposition == ForwardingDisposition::LocalDelivery {
userspace-dp/src/afxdp/session_glue/mod.rs:128:            ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/session_glue/mod.rs:145:        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/session_glue/mod.rs:199:    if resolution.disposition != ForwardingDisposition::HAInactive || metadata.fabric_ingress {
userspace-dp/src/afxdp/session_glue/mod.rs:232:    resolution.disposition == ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/mod.rs:281:            || decision.resolution.disposition != ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/session_glue/mod.rs:478:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/mod.rs:1173:    if resolution.disposition != ForwardingDisposition::HAInactive {
userspace-dp/src/afxdp/session_glue/mod.rs:1193:    if enforced.disposition == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/tunnel.rs:313:    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/mod.rs:183:pub(crate) use self::types::{ForwardingDisposition, ForwardingResolution, NeighborEntry};
userspace-dp/src/afxdp/session_glue/tests.rs:34:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:254:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/session_glue/tests.rs:511:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:522:        disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:1344:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:1436:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2137:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2503:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:2522:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:2572:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:2593:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:2643:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2669:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:2722:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2748:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:2801:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2827:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:2880:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:2901:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:2954:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3063:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:3094:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3111:            disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/session_glue/tests.rs:3126:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3142:            disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/session_glue/tests.rs:3155:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/session_glue/tests.rs:3167:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:3180:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/session_glue/tests.rs:3193:            disposition: ForwardingDisposition::ForwardCandidate,

exec
/bin/bash -lc "rg -n \"DiscardRoute|NextTableUnsupported|HAInactive|FabricRedirect|ForwardCandidate|MissingNeighbor|NoRoute|LocalDelivery|PolicyDenied\" userspace-dp/src --glob '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/main_tests.rs:401:        afxdp::ForwardingDisposition::ForwardCandidate
userspace-dp/src/protocol/control.rs:185:    /// #1902: GRE-decapped MissingNeighbor packets refused
userspace-dp/src/protocol/control.rs:207:    /// including `MissingNeighborSeed` installs the per-worker
userspace-dp/src/protocol/control.rs:241:    /// when a `MissingNeighbor` negative-cache fast-fail nudges a wedged
userspace-dp/src/session/mod.rs:1232:            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
userspace-dp/src/server/helpers.rs:73:    // authoritative collision watch (covers MissingNeighborSeed installs
userspace-dp/src/server/helpers.rs:357:                    afxdp::ForwardingDisposition::ForwardCandidate
userspace-dp/src/server/helpers.rs:359:                    afxdp::ForwardingDisposition::NoRoute
userspace-dp/src/session/tests.rs:35:        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
userspace-dp/src/session/tests.rs:100:        SessionOrigin::MissingNeighborSeed,
userspace-dp/src/session/tests.rs:120:        SessionOrigin::MissingNeighborSeed,
userspace-dp/src/session/tests.rs:706:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/session/tests.rs:738:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/session/entry.rs:53:    MissingNeighborSeed,
userspace-dp/src/session/entry.rs:67:            Self::MissingNeighborSeed => "missing_neighbor_seed",
userspace-dp/src/session/entry.rs:106:        matches!(self, Self::MissingNeighborSeed)
userspace-dp/src/afxdp/shared_ops.rs:10:/// NAT session passes through — normal installs, `MissingNeighborSeed`
userspace-dp/src/afxdp/shared_ops.rs:34:/// queued under `delta.FabricRedirect && !delta.FabricIngress`). Both
userspace-dp/src/afxdp/shared_ops.rs:274:    // session misses and can resolve to HAInactive if the worker hasn't
userspace-dp/src/afxdp/shared_ops.rs:603:        || forward_match.decision.resolution.disposition == ForwardingDisposition::FabricRedirect;
userspace-dp/src/afxdp/shared_ops.rs:622:        // from prior FabricRedirect results.
userspace-dp/src/afxdp/shared_ops.rs:702:        && enforced.disposition == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/coordinator/inject.rs:178:                        if resolution.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/types/forwarding.rs:243:    LocalDelivery,
userspace-dp/src/afxdp/types/forwarding.rs:244:    ForwardCandidate,
userspace-dp/src/afxdp/types/forwarding.rs:245:    FabricRedirect,
userspace-dp/src/afxdp/types/forwarding.rs:246:    HAInactive,
userspace-dp/src/afxdp/types/forwarding.rs:247:    PolicyDenied,
userspace-dp/src/afxdp/types/forwarding.rs:248:    NoRoute,
userspace-dp/src/afxdp/types/forwarding.rs:249:    MissingNeighbor,
userspace-dp/src/afxdp/types/forwarding.rs:250:    DiscardRoute,
userspace-dp/src/afxdp/types/forwarding.rs:251:    NextTableUnsupported,
userspace-dp/src/afxdp/types/forwarding.rs:259:    ///   - `ForwardCandidate`: Normal forwarded traffic with a resolved
userspace-dp/src/afxdp/types/forwarding.rs:261:    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
userspace-dp/src/afxdp/types/forwarding.rs:268:    ///     in which a cached `FabricRedirect` could point at a stale
userspace-dp/src/afxdp/types/forwarding.rs:272:    ///   - `LocalDelivery`: Delivered to the kernel stack, not forwarded
userspace-dp/src/afxdp/types/forwarding.rs:274:    ///   - `HAInactive`: The owning RG is not active on this node. Transient
userspace-dp/src/afxdp/types/forwarding.rs:276:    ///   - `PolicyDenied`: Packet was denied by policy. Drop decisions are
userspace-dp/src/afxdp/types/forwarding.rs:278:    ///   - `NoRoute`: No route to destination. Transient — may resolve when
userspace-dp/src/afxdp/types/forwarding.rs:280:    ///   - `MissingNeighbor`: Route exists but ARP/NDP is unresolved.
userspace-dp/src/afxdp/types/forwarding.rs:282:    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
userspace-dp/src/afxdp/types/forwarding.rs:283:    ///     the same reason as PolicyDenied.
userspace-dp/src/afxdp/types/forwarding.rs:284:    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
userspace-dp/src/afxdp/types/forwarding.rs:289:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/types/forwarding.rs:315:                ForwardingDisposition::LocalDelivery => "local_delivery",
userspace-dp/src/afxdp/types/forwarding.rs:316:                ForwardingDisposition::ForwardCandidate => "forward_candidate",
userspace-dp/src/afxdp/types/forwarding.rs:317:                ForwardingDisposition::FabricRedirect => "fabric_redirect",
userspace-dp/src/afxdp/types/forwarding.rs:318:                ForwardingDisposition::HAInactive => "ha_inactive",
userspace-dp/src/afxdp/types/forwarding.rs:319:                ForwardingDisposition::PolicyDenied => "policy_denied",
userspace-dp/src/afxdp/types/forwarding.rs:320:                ForwardingDisposition::NoRoute => "no_route",
userspace-dp/src/afxdp/types/forwarding.rs:321:                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
userspace-dp/src/afxdp/types/forwarding.rs:322:                ForwardingDisposition::DiscardRoute => "discard_route",
userspace-dp/src/afxdp/types/forwarding.rs:323:                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
userspace-dp/src/afxdp/disposition.rs:11:// the forwarding outcome itself (ForwardCandidate / FabricRedirect /
userspace-dp/src/afxdp/disposition.rs:12:// LocalDelivery / etc.) is the dimension being recorded.
userspace-dp/src/afxdp/disposition.rs:331:        ForwardingDisposition::LocalDelivery => {
userspace-dp/src/afxdp/disposition.rs:334:        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
userspace-dp/src/afxdp/disposition.rs:337:        ForwardingDisposition::HAInactive => {
userspace-dp/src/afxdp/disposition.rs:350:        ForwardingDisposition::PolicyDenied => {
userspace-dp/src/afxdp/disposition.rs:363:        ForwardingDisposition::NoRoute => {
userspace-dp/src/afxdp/disposition.rs:376:        ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/disposition.rs:389:        ForwardingDisposition::DiscardRoute => {
userspace-dp/src/afxdp/disposition.rs:402:        ForwardingDisposition::NextTableUnsupported => {
userspace-dp/src/event_stream/codec_tests.rs:45:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/event_stream/codec_tests.rs:435:        encode_disposition(ForwardingDisposition::ForwardCandidate),
userspace-dp/src/event_stream/codec_tests.rs:438:    assert_eq!(encode_disposition(ForwardingDisposition::LocalDelivery), 1);
userspace-dp/src/event_stream/codec_tests.rs:439:    assert_eq!(encode_disposition(ForwardingDisposition::FabricRedirect), 2);
userspace-dp/src/event_stream/codec_tests.rs:440:    assert_eq!(encode_disposition(ForwardingDisposition::PolicyDenied), 3);
userspace-dp/src/event_stream/codec_tests.rs:441:    assert_eq!(encode_disposition(ForwardingDisposition::NoRoute), 4);
userspace-dp/src/event_stream/codec_tests.rs:443:        encode_disposition(ForwardingDisposition::MissingNeighbor),
userspace-dp/src/event_stream/codec_tests.rs:446:    assert_eq!(encode_disposition(ForwardingDisposition::HAInactive), 6);
userspace-dp/src/event_stream/codec_tests.rs:447:    assert_eq!(encode_disposition(ForwardingDisposition::DiscardRoute), 7);
userspace-dp/src/event_stream/codec_tests.rs:449:        encode_disposition(ForwardingDisposition::NextTableUnsupported),
userspace-dp/src/afxdp/ha_tests.rs:119:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_delta.rs:90:                ForwardingDisposition::ForwardCandidate => "forward_candidate",
userspace-dp/src/afxdp/session_delta.rs:91:                ForwardingDisposition::LocalDelivery => "local_delivery",
userspace-dp/src/afxdp/session_delta.rs:92:                ForwardingDisposition::NoRoute => "no_route",
userspace-dp/src/afxdp/session_delta.rs:93:                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
userspace-dp/src/afxdp/session_delta.rs:94:                ForwardingDisposition::PolicyDenied => "policy_denied",
userspace-dp/src/afxdp/session_delta.rs:95:                ForwardingDisposition::FabricRedirect => "fabric_redirect",
userspace-dp/src/afxdp/session_delta.rs:96:                ForwardingDisposition::HAInactive => "ha_inactive",
userspace-dp/src/afxdp/session_delta.rs:97:                ForwardingDisposition::DiscardRoute => "discard_route",
userspace-dp/src/afxdp/session_delta.rs:98:                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
userspace-dp/src/afxdp/session_delta.rs:139:                || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/umem/mod.rs:469:    /// drop. The first MissingNeighbor packet for a `(egress_ifindex,
userspace-dp/src/afxdp/umem/mod.rs:477:    /// #1902: per-binding count of GRE-decapped MissingNeighbor packets
userspace-dp/src/afxdp/umem/mod.rs:956:            ForwardingDisposition::LocalDelivery => {
userspace-dp/src/afxdp/umem/mod.rs:960:            ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/umem/mod.rs:964:            ForwardingDisposition::NoRoute => {
userspace-dp/src/afxdp/umem/mod.rs:968:            ForwardingDisposition::NextTableUnsupported => {
userspace-dp/src/afxdp/neighbor_resolver.rs:6://! The `MissingNeighbor` negative-cache gate
userspace-dp/src/afxdp/ha.rs:516:                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/neg_neigh.rs:5://! un-expired, and still-unresolved, new `MissingNeighbor` packets to it
userspace-dp/src/afxdp/neg_neigh.rs:79:/// The full dead-host gate decision used at the `MissingNeighbor` handler.
userspace-dp/src/afxdp/umem/tests.rs:1510:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/event_stream/codec.rs:219:            || decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/event_stream/codec.rs:614:        ForwardingDisposition::ForwardCandidate => DISP_FORWARD_CANDIDATE,
userspace-dp/src/event_stream/codec.rs:615:        ForwardingDisposition::LocalDelivery => DISP_LOCAL_DELIVERY,
userspace-dp/src/event_stream/codec.rs:616:        ForwardingDisposition::FabricRedirect => DISP_FABRIC_REDIRECT,
userspace-dp/src/event_stream/codec.rs:617:        ForwardingDisposition::PolicyDenied => DISP_POLICY_DENIED,
userspace-dp/src/event_stream/codec.rs:618:        ForwardingDisposition::NoRoute => DISP_NO_ROUTE,
userspace-dp/src/event_stream/codec.rs:619:        ForwardingDisposition::MissingNeighbor => DISP_MISSING_NEIGHBOR,
userspace-dp/src/event_stream/codec.rs:620:        ForwardingDisposition::HAInactive => DISP_HA_INACTIVE,
userspace-dp/src/event_stream/codec.rs:621:        ForwardingDisposition::DiscardRoute => DISP_DISCARD_ROUTE,
userspace-dp/src/event_stream/codec.rs:622:        ForwardingDisposition::NextTableUnsupported => DISP_NEXT_TABLE_UNSUPPORTED,
userspace-dp/src/event_stream/codec.rs:630:        || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/types/runtime.rs:317:    /// MissingNeighbor packet to a negatively-cached (un-expired,
userspace-dp/src/afxdp/types/runtime.rs:387:    /// not exercise the resolver path. The `MissingNeighbor`
userspace-dp/src/afxdp/session_glue/mod.rs:22:    if cached.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/session_glue/mod.rs:29:    fallback.disposition = ForwardingDisposition::ForwardCandidate;
userspace-dp/src/afxdp/session_glue/mod.rs:87:    if decision.resolution.disposition == ForwardingDisposition::LocalDelivery {
userspace-dp/src/afxdp/session_glue/mod.rs:99:        // a boot, so inequality is authoritative. Tunnel-marked NoRoute
userspace-dp/src/afxdp/session_glue/mod.rs:128:            ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/session_glue/mod.rs:145:        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/session_glue/mod.rs:199:    if resolution.disposition != ForwardingDisposition::HAInactive || metadata.fabric_ingress {
userspace-dp/src/afxdp/session_glue/mod.rs:232:    resolution.disposition == ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/mod.rs:281:            || decision.resolution.disposition != ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/session_glue/mod.rs:478:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/mod.rs:606:                // tunnel resolution is ForwardCandidate
userspace-dp/src/afxdp/session_glue/mod.rs:1173:    if resolution.disposition != ForwardingDisposition::HAInactive {
userspace-dp/src/afxdp/session_glue/mod.rs:1193:    if enforced.disposition == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/coordinator/tests.rs:164:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs:67:                != ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:47:        // the resolved ForwardCandidate so the session is ready when
userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:55:        if re_resolved.disposition != ForwardingDisposition::HAInactive {
userspace-dp/src/afxdp/poll_stages.rs:20://!   policy/NAT/forwarding, reverse-NAT/ICMP, MissingNeighbor
userspace-dp/src/afxdp/poll_stages.rs:419:/// `SessionDecision` with `LocalDelivery` disposition and
userspace-dp/src/afxdp/poll_stages.rs:440:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/session_glue/tests.rs:34:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:254:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/session_glue/tests.rs:511:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:522:        disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:1344:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:1436:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2137:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2158:        SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/session_glue/tests.rs:2503:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:2522:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:2572:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:2593:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:2643:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2669:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:2722:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2748:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:2801:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:2827:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:2880:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:2901:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:2954:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3063:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:3094:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3111:            disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/session_glue/tests.rs:3126:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3142:            disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/session_glue/tests.rs:3155:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/session_glue/tests.rs:3167:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:3180:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/session_glue/tests.rs:3193:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:3208:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:3233:                    disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/session_glue/tests.rs:3262:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/session_glue/tests.rs:3533:                    disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:3562:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/session_glue/tests.rs:3659:            disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/tests.rs:3731:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/coordinator/status.rs:63:    /// every `BindingLiveState`. Counts GRE-decapped MissingNeighbor
userspace-dp/src/afxdp/coordinator/status.rs:127:    /// `MissingNeighborSeed` installs, which never replicate to sibling
userspace-dp/src/afxdp/flow_cache_tests.rs:100:        decision: make_decision(ForwardingDisposition::ForwardCandidate),
userspace-dp/src/afxdp/flow_cache_tests.rs:349:        ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/flow_cache_tests.rs:350:        ForwardingDisposition::MissingNeighbor,
userspace-dp/src/afxdp/flow_cache_tests.rs:351:        ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/flow_cache_tests.rs:352:        ForwardingDisposition::PolicyDenied,
userspace-dp/src/afxdp/flow_cache_tests.rs:353:        ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/flow_cache_tests.rs:366:// (g) ForwardCandidate is cacheable
userspace-dp/src/afxdp/flow_cache_tests.rs:372:    let decision = make_decision(ForwardingDisposition::ForwardCandidate);
userspace-dp/src/afxdp/flow_cache_tests.rs:376:        "TCP ForwardCandidate should be cacheable",
userspace-dp/src/afxdp/flow_cache_tests.rs:380:        "UDP ForwardCandidate should be cacheable",
userspace-dp/src/afxdp/flow_cache_tests.rs:391:    let mut nat64_decision = make_decision(ForwardingDisposition::ForwardCandidate);
userspace-dp/src/afxdp/flow_cache_tests.rs:398:    let mut nptv6_decision = make_decision(ForwardingDisposition::ForwardCandidate);
userspace-dp/src/afxdp/flow_cache_tests.rs:434:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/flow_cache_tests.rs:493:    let entry = entry.expect("should produce a cache entry for ForwardCandidate");
userspace-dp/src/afxdp/flow_cache_tests.rs:518:        decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/flow_cache_tests.rs:598:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/flow_cache_tests.rs:948:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/flow_cache_tests.rs:1235:    // NoRoute is not cacheable.
userspace-dp/src/afxdp/flow_cache_tests.rs:1236:    let decision = make_decision(ForwardingDisposition::NoRoute);
userspace-dp/src/afxdp/flow_cache_tests.rs:1253:    assert!(entry.is_none(), "NoRoute should not produce a cache entry");
userspace-dp/src/afxdp/flow_cache_tests.rs:1273:            disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/session_glue/promote.rs:63:/// not promotable or not currently in a `ForwardCandidate` state.
userspace-dp/src/afxdp/session_glue/promote.rs:87:        || decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/icmp.rs:71:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/forward_request.rs:22:    decision.resolution.disposition != ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forward_request.rs:91:        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/forward_request.rs:107:    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/neighbor_dispatch.rs:51:/// used at the `MissingNeighbor` handler in `poll_descriptor`. Extracted
userspace-dp/src/afxdp/neighbor_dispatch.rs:146:            // MissingNeighbor buffer site instead of re-buffering for
userspace-dp/src/afxdp/neighbor_dispatch.rs:221:        decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
userspace-dp/src/afxdp/neighbor_dispatch.rs:496:                disposition: ForwardingDisposition::MissingNeighbor,
userspace-dp/src/afxdp/bpf_map_tests.rs:15:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/bpf_map_tests.rs:62:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/bpf_map_tests.rs:120:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/bpf_map_tests.rs:169:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/icmp_embed/builders.rs:247:/// local resolution turned into HAInactive/NoRoute/DiscardRoute.
userspace-dp/src/afxdp/icmp_embed/builders.rs:261:            ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/icmp_embed/builders.rs:262:                | ForwardingDisposition::NoRoute
userspace-dp/src/afxdp/icmp_embed/builders.rs:263:                | ForwardingDisposition::DiscardRoute
userspace-dp/src/afxdp/tunnel.rs:313:    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/worker/mod.rs:146:    /// while present + un-expired + still-unresolved, new `MissingNeighbor`
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:35:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:52:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:93:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:94:            | ForwardingDisposition::NoRoute
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:95:            | ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:96:            | ForwardingDisposition::NextTableUnsupported
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156:    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/tx/tcp_segmentation.rs:102:        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:161:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:206:                if cached_decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:223:            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/forwarding/mod.rs:92:            disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/forwarding/mod.rs:357:        disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/forwarding/mod.rs:397:    if resolution.disposition != ForwardingDisposition::HAInactive {
userspace-dp/src/afxdp/forwarding/mod.rs:415:    if !fabric_ingress || matches!(resolution.disposition, ForwardingDisposition::LocalDelivery) {
userspace-dp/src/afxdp/forwarding/mod.rs:424:        && resolution.disposition != ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forwarding/mod.rs:440:        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:474:    if fabric_return_resolution.disposition != ForwardingDisposition::ForwardCandidate {
userspace-dp/src/afxdp/forwarding/mod.rs:557:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/mod.rs:558:            | ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:559:            | ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/mod.rs:563:    if resolution.disposition == ForwardingDisposition::LocalDelivery && ha_state.is_empty() {
userspace-dp/src/afxdp/forwarding/mod.rs:568:        // In cluster mode, rg=0 on a ForwardCandidate to an egress interface
userspace-dp/src/afxdp/forwarding/mod.rs:573:        if resolution.disposition != ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/mod.rs:578:                disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/forwarding/mod.rs:586:            disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/forwarding/mod.rs:592:            disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/forwarding/mod.rs:620:        && (resolution.disposition == ForwardingDisposition::FabricRedirect || fabric_ingress)
userspace-dp/src/afxdp/forwarding/mod.rs:624:    if resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/forwarding/mod.rs:636:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:677:    if fabric_ingress && enforced.disposition == ForwardingDisposition::HAInactive {
userspace-dp/src/afxdp/forwarding/mod.rs:895:                    disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/forwarding/mod.rs:920:                    disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/forwarding/mod.rs:1015:                disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/forwarding/mod.rs:1034:                disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/forwarding/mod.rs:1066:    if resolution.disposition != ForwardingDisposition::LocalDelivery {
userspace-dp/src/afxdp/forwarding/mod.rs:1179:        disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/forwarding/mod.rs:1215:            disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1254:                    ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/mod.rs:1256:                    ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:1279:                    disposition: ForwardingDisposition::DiscardRoute,
userspace-dp/src/afxdp/forwarding/mod.rs:1293:                        disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1333:                    ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/mod.rs:1335:                    ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:1363:            disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1402:                    ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/mod.rs:1404:                    ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:1427:                    disposition: ForwardingDisposition::DiscardRoute,
userspace-dp/src/afxdp/forwarding/mod.rs:1441:                        disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1481:                    ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/mod.rs:1483:                    ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/forwarding/mod.rs:1503:        disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/forwarding/mod.rs:1542:    if outer.disposition == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/flow_cache.rs:319:        // temporarily resolve to FabricRedirect, but failback must still evict
userspace-dp/src/afxdp/flow_cache.rs:333:                    == ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/bpf_map/mod.rs:10:        && decision.resolution.disposition == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/poll_descriptor/mod.rs:347:                                == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/poll_descriptor/mod.rs:385:                                ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/poll_descriptor/mod.rs:811:                            if resolution.disposition == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/poll_descriptor/mod.rs:826:                            if resolution.disposition == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1025:                                == ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1267:                                            != ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1287:                                        // case (DNS fast-path, LocalDelivery): no
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1694:                                        ForwardingDisposition::PolicyDenied;
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1697:                                == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1739:                            == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1751:                    // Safety net: convert any remaining HAInactive to fabric
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1755:                    // through with HAInactive when the inner conversion found
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1759:                    // HAInactive with unknown ownership (rg=0) means unresolved
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1762:                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1796:                        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/poll_descriptor/mod.rs:1797:                            | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2097:                            // Cache ForwardCandidate decisions for established
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2157:                            ForwardingDisposition::LocalDelivery => {
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2186:                            ForwardingDisposition::NoRoute => {
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2204:                            ForwardingDisposition::MissingNeighbor => {
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2207:                                // the very top of the MissingNeighbor arm,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2211:                                // creates a MissingNeighborSeed session.
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2581:                                            SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2591:                                            origin: SessionOrigin::MissingNeighborSeed,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2799:                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2800:                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
userspace-dp/src/afxdp/forwarding/tests.rs:87:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/forwarding/tests.rs:104:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:264:    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/forwarding/tests.rs:268:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forwarding/tests.rs:302:    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/forwarding/tests.rs:306:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forwarding/tests.rs:333:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:372:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forwarding/tests.rs:616:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forwarding/tests.rs:634:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:664:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:687:    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
userspace-dp/src/afxdp/forwarding/tests.rs:733:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:849:            disposition: ForwardingDisposition::MissingNeighbor,
userspace-dp/src/afxdp/forwarding/tests.rs:895:    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/forwarding/tests.rs:918:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/forwarding/tests.rs:940:    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/forwarding/tests.rs:971:    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/forwarding/tests.rs:1008:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/forwarding/tests.rs:1039:    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/forwarding/tests.rs:1056:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/forwarding/tests.rs:1083:    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
userspace-dp/src/afxdp/forwarding/tests.rs:1105:            disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/forwarding/tests.rs:1132:    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
userspace-dp/src/afxdp/forwarding/tests.rs:1154:            disposition: ForwardingDisposition::DiscardRoute,
userspace-dp/src/afxdp/forwarding/tests.rs:1181:    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
userspace-dp/src/afxdp/forwarding/tests.rs:1199:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/forwarding/tests.rs:1226:    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
userspace-dp/src/afxdp/forwarding/tests.rs:1233:        disposition: ForwardingDisposition::HAInactive,
userspace-dp/src/afxdp/forwarding/tests.rs:1245:        ForwardingDisposition::HAInactive
userspace-dp/src/afxdp/forwarding/tests.rs:1384:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1390:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1401:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1410:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1457:    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/forwarding/tests.rs:1472:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1484:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1561:    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/forwarding/tests.rs:1578:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1592:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/forwarding/tests.rs:1968:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:1987:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:2001:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:2022:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:2048:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:2090:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:2118:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/forwarding/tests.rs:2245:        ForwardingDisposition::NextTableUnsupported
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:99:        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/tests.rs:92:            disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/tests.rs:116:            disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/tests.rs:218:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:281:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:604:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:646:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:671:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/tests.rs:686:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/tests.rs:836:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/tests.rs:1740:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:1862:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:1977:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:2109:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:2288:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:2542:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:2658:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:2688:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:2754:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/tests.rs:2839:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:3633:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:4017:            disposition: ForwardingDisposition::LocalDelivery,
userspace-dp/src/afxdp/tests.rs:4150:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:4210:            disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/tests.rs:4274:            disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/tests.rs:4333:            disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/tests.rs:4404:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/tests.rs:4451:    live.record_slow_path_accept(ForwardingDisposition::MissingNeighbor, "slow_path", 128);
userspace-dp/src/afxdp/tests.rs:4453:        ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/tests.rs:4493:            disposition: ForwardingDisposition::PolicyDenied,
userspace-dp/src/afxdp/tests.rs:4556:            disposition: ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/tests.rs:5041:    // neighbor so the rebuilt reverse decision is a ForwardCandidate.
userspace-dp/src/afxdp/tests.rs:5147:// I6: a MissingNeighborSeed install refused at cap must NOT buffer the
userspace-dp/src/afxdp/tests.rs:5155:    // MAC is now unknown -> MissingNeighbor seed path.
userspace-dp/src/afxdp/tests.rs:5354:/// fallback, NoRoute, MissingNeighbor non-forward dispositions). It is
userspace-dp/src/afxdp/tests.rs:5362:        ForwardingDisposition::ForwardCandidate, // build-failure door
userspace-dp/src/afxdp/tests.rs:5363:        ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/tests.rs:5364:        ForwardingDisposition::MissingNeighbor,
userspace-dp/src/afxdp/tests.rs:5421:        tunnel_marked_decision(ForwardingDisposition::ForwardCandidate),
userspace-dp/src/afxdp/tests.rs:5439:    let mut decision = tunnel_marked_decision(ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/tests.rs:5459:/// unresolved (MissingNeighbor) must NOT be buffered in pending_neigh
userspace-dp/src/afxdp/tests.rs:5497:    // 172.16.80.1 default gateway) is unresolved -> MissingNeighbor
userspace-dp/src/afxdp/tests.rs:5522:    // First packet: the decision is tunnel-marked ForwardCandidate; the
userspace-dp/src/afxdp/tests.rs:5569:/// packet to 10.255.0.1 resolves LocalDelivery with
userspace-dp/src/afxdp/tests.rs:5725:        "exactly ONE delivery per packet — the LocalDelivery arm must \
userspace-dp/src/afxdp/tests.rs:5777:/// the LocalDelivery arm sliced the ORIGINAL tagged outer frame at the
userspace-dp/src/afxdp/tests.rs:5835:    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
userspace-dp/src/afxdp/tests.rs:5843:        "exactly ONE slow-path enqueue attempt per LocalDelivery packet \
userspace-dp/src/afxdp/tests.rs:5874:/// not LocalDelivery, not a tunnel-marked encap — so a cold neighbor
userspace-dp/src/afxdp/tests.rs:5875:/// reaches the MissingNeighbor pending_neigh admission site.
userspace-dp/src/afxdp/tests.rs:5897:/// `retry_pending_neigh`. Pre-#1902 the MissingNeighbor arm buffered
userspace-dp/src/afxdp/tests.rs:5935:        "inner dst neighbor is cold -> the packet must take the MissingNeighbor arm"
userspace-dp/src/afxdp/tests.rs:6051:    assert_eq!(dbg.missing_neigh, 1, "cold neighbor -> MissingNeighbor arm");
userspace-dp/src/afxdp/tests.rs:6159:        disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/mod.rs:473:        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/frame/prop_tests/segment.rs:49:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2306:            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2328:        crate::afxdp::ForwardingDisposition::NoRoute,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2342:    // normally (the cached ForwardCandidate fallback applies when the
userspace-dp/src/afxdp/forwarding_build/tests.rs:2354:        (crate::afxdp::ForwardingDisposition::NoRoute, 0),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2376:        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/build/mod.rs:50:        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs:152:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:384:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/frame/tests.rs:391:        ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/frame/tests.rs:400:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/frame/tests.rs:407:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/frame/tests.rs:413:        ForwardingDisposition::MissingNeighbor
userspace-dp/src/afxdp/frame/tests.rs:430:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/frame/tests.rs:458:    assert_eq!(resolved.disposition, ForwardingDisposition::MissingNeighbor);
userspace-dp/src/afxdp/frame/tests.rs:516:        ForwardingDisposition::ForwardCandidate
userspace-dp/src/afxdp/frame/tests.rs:1378:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:1440:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:1482:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:1721:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:1895:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:1979:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2067:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2160:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2263:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2406:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2515:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2630:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2726:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:2840:        ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/frame/tests.rs:2870:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3032:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3110:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3191:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3274:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3372:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3490:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3594:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:3701:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4031:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4272:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4347:                disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4414:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/frame/tests.rs:4445:/// `disposition = FabricRedirect`, `apply_nat_on_fabric = false`,
userspace-dp/src/afxdp/frame/tests.rs:4488:                disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/frame/tests.rs:4615:                    disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4656:            == ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/frame/tests.rs:4714:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4802:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:4894:            disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/frame/tests.rs:4980:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:5076:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:5161:            disposition: ForwardingDisposition::ForwardCandidate,
userspace-dp/src/afxdp/frame/tests.rs:5546:            disposition: ForwardingDisposition::ForwardCandidate,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_stages.rs | sed -n '420,470p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   420	/// reinjects the packet via the slow-path TUN device, then signals
   421	/// `RecycleAndContinue` so the caller drops the UMEM frame.
   422	///
   423	/// Non-IPsec packets fall through unchanged.
   424	#[inline]
   425	pub(super) fn stage_ipsec_passthrough_check(
   426	    flow: Option<&SessionFlow>,
   427	    packet_frame: &[u8],
   428	    meta: UserspaceDpMeta,
   429	    binding_live: &BindingLiveState,
   430	    worker_ctx: &WorkerContext,
   431	) -> StageOutcome<()> {
   432	    let Some(flow) = flow else {
   433	        return StageOutcome::Continue(());
   434	    };
   435	    if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
   436	        return StageOutcome::Continue(());
   437	    }
   438	    let ipsec_decision = SessionDecision {
   439	        resolution: ForwardingResolution {
   440	            disposition: ForwardingDisposition::LocalDelivery,
   441	            local_ifindex: 0,
   442	            egress_ifindex: 0,
   443	            tx_ifindex: 0,
   444	            tunnel_endpoint_id: 0,
   445	            next_hop: None,
   446	            neighbor_mac: None,
   447	            src_mac: None,
   448	            tx_vlan_id: 0,
   449	        },
   450	        nat: NatDecision::default(),
   451	    };
   452	    maybe_reinject_slow_path_from_frame(
   453	        &worker_ctx.ident,
   454	        binding_live,
   455	        worker_ctx.slow_path,
   456	        worker_ctx.local_tunnel_deliveries,
   457	        packet_frame,
   458	        meta,
   459	        ipsec_decision,
   460	        worker_ctx.recent_exceptions,
   461	        "slow_path",
   462	        worker_ctx.forwarding,
   463	    );
   464	    StageOutcome::RecycleAndContinue
   465	}
   466	
   467	#[cfg(test)]
   468	mod tests {
   469	    use super::*;
   470	    use crate::event_stream::DataplaneEventRateLimitConfig;

codex
The `MissingNeighbor` arm does have additional `continue` exits on source-NAT failure and negative-neighbor fast-fail, so the plan’s table needs to be exact there. For `PolicyDenied`/`HAInactive`, the source so far still shows only counter increments before the common reinject tail.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/umem/mod.rs | sed -n '930,980p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/types/forwarding.rs | sed -n '235,325p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   930	        if let Ok(mut err) = self.last_error.lock() {
   931	            err.clear();
   932	        }
   933	    }
   934	
   935	    pub(super) fn set_error(&self, msg: String) {
   936	        if let Ok(mut err) = self.last_error.lock() {
   937	            *err = msg;
   938	        }
   939	    }
   940	
   941	    pub(super) fn record_slow_path_accept(
   942	        &self,
   943	        disposition: ForwardingDisposition,
   944	        reason: &str,
   945	        packet_len: u64,
   946	    ) {
   947	        self.slow_path_packets.fetch_add(1, Ordering::Relaxed);
   948	        self.slow_path_bytes
   949	            .fetch_add(packet_len, Ordering::Relaxed);
   950	        if reason == "forward_build_slow_path" {
   951	            self.slow_path_forward_build_packets
   952	                .fetch_add(1, Ordering::Relaxed);
   953	            return;
   954	        }
   955	        match disposition {
   956	            ForwardingDisposition::LocalDelivery => {
   957	                self.slow_path_local_delivery_packets
   958	                    .fetch_add(1, Ordering::Relaxed);
   959	            }
   960	            ForwardingDisposition::MissingNeighbor => {
   961	                self.slow_path_missing_neighbor_packets
   962	                    .fetch_add(1, Ordering::Relaxed);
   963	            }
   964	            ForwardingDisposition::NoRoute => {
   965	                self.slow_path_no_route_packets
   966	                    .fetch_add(1, Ordering::Relaxed);
   967	            }
   968	            ForwardingDisposition::NextTableUnsupported => {
   969	                self.slow_path_next_table_packets
   970	                    .fetch_add(1, Ordering::Relaxed);
   971	            }
   972	            _ => {}
   973	        }
   974	    }
   975	
   976	
   977	    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
   978	        self.push_redirect_inbox(req);
   979	        Ok(())
   980	    }

 succeeded in 0ms:
   235	    pub(in crate::afxdp) overlay_ifindex: i32,
   236	    pub(in crate::afxdp) peer_addr: IpAddr,
   237	    pub(in crate::afxdp) peer_mac: [u8; 6],
   238	    pub(in crate::afxdp) local_mac: [u8; 6],
   239	}
   240	
   241	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
   242	pub(crate) enum ForwardingDisposition {
   243	    LocalDelivery,
   244	    ForwardCandidate,
   245	    FabricRedirect,
   246	    HAInactive,
   247	    PolicyDenied,
   248	    NoRoute,
   249	    MissingNeighbor,
   250	    DiscardRoute,
   251	    NextTableUnsupported,
   252	}
   253	
   254	impl ForwardingDisposition {
   255	    /// Whether this disposition produces a stable forwarding decision that can
   256	    /// be stored in the per-worker flow cache.
   257	    ///
   258	    /// Cacheable:
   259	    ///   - `ForwardCandidate`: Normal forwarded traffic with a resolved
   260	    ///     neighbor and egress interface. The common fast path.
   261	    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
   262	    ///     because each cache entry captures the owning RG epoch into
   263	    ///     `FlowCacheStamp::owner_rg_epoch` at insert time
   264	    ///     (`flow_cache.rs:60-83`), and `FlowCache::lookup`
   265	    ///     (`flow_cache.rs:314-347`) treats the entry as a miss when
   266	    ///     `current_epoch != entry.stamp.owner_rg_epoch`. The owning RG
   267	    ///     bumps its epoch on every active/standby flip, so the window
   268	    ///     in which a cached `FabricRedirect` could point at a stale
   269	    ///     fabric peer is bounded by the next RG epoch bump (#1065).
   270	    ///
   271	    /// Not cacheable:
   272	    ///   - `LocalDelivery`: Delivered to the kernel stack, not forwarded
   273	    ///     through XSK bindings. No rewrite descriptor to cache.
   274	    ///   - `HAInactive`: The owning RG is not active on this node. Transient
   275	    ///     state that changes on failover — must never be cached.
   276	    ///   - `PolicyDenied`: Packet was denied by policy. Drop decisions are
   277	    ///     not cached to allow policy changes to take effect immediately.
   278	    ///   - `NoRoute`: No route to destination. Transient — may resolve when
   279	    ///     FIB is updated.
   280	    ///   - `MissingNeighbor`: Route exists but ARP/NDP is unresolved.
   281	    ///     Transient — resolves when the neighbor entry appears.
   282	    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
   283	    ///     the same reason as PolicyDenied.
   284	    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
   285	    ///     unsupported next-table. Permanent miss, not worth caching.
   286	    pub(in crate::afxdp) fn is_cacheable(self) -> bool {
   287	        matches!(
   288	            self,
   289	            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
   290	        )
   291	    }
   292	}
   293	
   294	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
   295	pub(crate) struct ForwardingResolution {
   296	    pub(crate) disposition: ForwardingDisposition,
   297	    pub(crate) local_ifindex: i32,
   298	    pub(crate) egress_ifindex: i32,
   299	    pub(crate) tx_ifindex: i32,
   300	    pub(crate) tunnel_endpoint_id: u16,
   301	    pub(crate) next_hop: Option<IpAddr>,
   302	    pub(crate) neighbor_mac: Option<[u8; 6]>,
   303	    pub(crate) src_mac: Option<[u8; 6]>,
   304	    pub(crate) tx_vlan_id: u16,
   305	}
   306	
   307	impl ForwardingResolution {
   308	    pub(in crate::afxdp) fn status(
   309	        self,
   310	        debug: Option<&ResolutionDebug>,
   311	        forwarding: &ForwardingState,
   312	    ) -> PacketResolution {
   313	        PacketResolution {
   314	            disposition: match self.disposition {
   315	                ForwardingDisposition::LocalDelivery => "local_delivery",
   316	                ForwardingDisposition::ForwardCandidate => "forward_candidate",
   317	                ForwardingDisposition::FabricRedirect => "fabric_redirect",
   318	                ForwardingDisposition::HAInactive => "ha_inactive",
   319	                ForwardingDisposition::PolicyDenied => "policy_denied",
   320	                ForwardingDisposition::NoRoute => "no_route",
   321	                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
   322	                ForwardingDisposition::DiscardRoute => "discard_route",
   323	                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
   324	            }
   325	            .to_string(),

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/disposition.rs | sed -n '320,410p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   320	    binding: &BindingIdentity,
   321	    mut counters: DispositionCounters<'_>,
   322	    resolution: ForwardingResolution,
   323	    packet_length: u32,
   324	    meta: Option<UserspaceDpMeta>,
   325	    debug: Option<&ResolutionDebug>,
   326	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
   327	    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
   328	    forwarding: &ForwardingState,
   329	) {
   330	    match resolution.disposition {
   331	        ForwardingDisposition::LocalDelivery => {
   332	            counters.bump_local_delivery();
   333	        }
   334	        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
   335	            counters.bump_forward_candidate();
   336	        }
   337	        ForwardingDisposition::HAInactive => {
   338	            update_last_resolution(last_resolution, resolution, debug, forwarding);
   339	            counters.bump_exception();
   340	            record_exception(
   341	                recent_exceptions,
   342	                binding,
   343	                "ha_inactive",
   344	                packet_length,
   345	                meta,
   346	                debug,
   347	                forwarding,
   348	            );
   349	        }
   350	        ForwardingDisposition::PolicyDenied => {
   351	            update_last_resolution(last_resolution, resolution, debug, forwarding);
   352	            counters.bump_policy_denied();
   353	            record_exception(
   354	                recent_exceptions,
   355	                binding,
   356	                "policy_denied",
   357	                packet_length,
   358	                meta,
   359	                debug,
   360	                forwarding,
   361	            );
   362	        }
   363	        ForwardingDisposition::NoRoute => {
   364	            update_last_resolution(last_resolution, resolution, debug, forwarding);
   365	            counters.bump_route_miss();
   366	            record_exception(
   367	                recent_exceptions,
   368	                binding,
   369	                "no_route",
   370	                packet_length,
   371	                meta,
   372	                debug,
   373	                forwarding,
   374	            );
   375	        }
   376	        ForwardingDisposition::MissingNeighbor => {
   377	            update_last_resolution(last_resolution, resolution, debug, forwarding);
   378	            counters.bump_neighbor_miss();
   379	            record_exception(
   380	                recent_exceptions,
   381	                binding,
   382	                "missing_neighbor",
   383	                packet_length,
   384	                meta,
   385	                debug,
   386	                forwarding,
   387	            );
   388	        }
   389	        ForwardingDisposition::DiscardRoute => {
   390	            update_last_resolution(last_resolution, resolution, debug, forwarding);
   391	            counters.bump_discard_route();
   392	            record_exception(
   393	                recent_exceptions,
   394	                binding,
   395	                "discard_route",
   396	                packet_length,
   397	                meta,
   398	                debug,
   399	                forwarding,
   400	            );
   401	        }
   402	        ForwardingDisposition::NextTableUnsupported => {
   403	            update_last_resolution(last_resolution, resolution, debug, forwarding);
   404	            counters.bump_next_table();
   405	            record_exception(
   406	                recent_exceptions,
   407	                binding,
   408	                "next_table_unsupported",
   409	                packet_length,
   410	                meta,

exec
/bin/bash -lc "rg -n \"struct SlowPathReinjector|fn enqueue|EnqueueOutcome|slow_path.*TUN|tun\" userspace-dp/src -g '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/nat64_tests.rs:560:// ECN copied verbatim) — NAT64 is stateless translation, not RFC 6040 tunnel
userspace-dp/src/protocol/control.rs:320:    /// #1865: per-WG-tunnel operator telemetry rows. Keyed by tunnel
userspace-dp/src/protocol/control.rs:321:    /// NAME (`tunnel`) — `tunnel_endpoint_id` is informational only
userspace-dp/src/protocol/control.rs:323:    /// (and omitted — `skip_serializing_if`) when no WG tunnel is
userspace-dp/src/protocol/control.rs:326:    #[serde(rename = "wg_tunnels", default, skip_serializing_if = "Vec::is_empty")]
userspace-dp/src/protocol/control.rs:327:    pub wg_tunnels: Vec<WgTunnelStatus>,
userspace-dp/src/protocol/control.rs:448:/// #1865: one WG tunnel's telemetry row inside `ProcessStatus`.
userspace-dp/src/protocol/control.rs:461:    pub tunnel: String,
userspace-dp/src/protocol/control.rs:463:    /// renumbers when tunnels are added/removed; never a join key).
userspace-dp/src/protocol/control.rs:464:    #[serde(rename = "tunnel_endpoint_id", default)]
userspace-dp/src/protocol/control.rs:465:    pub tunnel_endpoint_id: u16,
userspace-dp/src/protocol/control.rs:560:    #[serde(rename = "tun_write_errors", default)]
userspace-dp/src/protocol/control.rs:561:    pub tun_write_errors: u64,
userspace-dp/src/protocol/control.rs:562:    #[serde(rename = "tun_rx_drops_no_endpoint", default)]
userspace-dp/src/protocol/control.rs:563:    pub tun_rx_drops_no_endpoint: u64,
userspace-dp/src/protocol/control.rs:696:    #[serde(rename = "tunnel_endpoint_id", default)]
userspace-dp/src/protocol/control.rs:697:    pub tunnel_endpoint_id: u16,
userspace-dp/src/protocol/mod.rs:13://!     fabric/tunnel/neighbor/mirror snapshots, MapPins, capabilities)
userspace-dp/src/protocol/binding.rs:454:    /// #1873 R-C/R-E: tunnel-marked inner packets dropped instead of
userspace-dp/src/protocol/binding.rs:457:    #[serde(rename = "tunnel_encap_unresolved_drops", default)]
userspace-dp/src/protocol/binding.rs:458:    pub tunnel_encap_unresolved_drops: u64,
userspace-dp/src/protocol/binding.rs:1022:    #[serde(rename = "tunnel_endpoint_id", default)]
userspace-dp/src/protocol/binding.rs:1023:    pub tunnel_endpoint_id: u16,
userspace-dp/src/protocol/tests.rs:1157:    s.insert("tunnel_endpoint_snapshot".into(), dump(&TunnelEndpointSnapshot::default()));
userspace-dp/src/protocol/tests.rs:1414:// per-WG-tunnel telemetry rows. The wire keys feed
userspace-dp/src/protocol/tests.rs:1418:fn process_status_wg_tunnels_roundtrip_and_compat() {
userspace-dp/src/protocol/tests.rs:1423:        tunnel: "wg0".to_string(),
userspace-dp/src/protocol/tests.rs:1424:        tunnel_endpoint_id: 7,
userspace-dp/src/protocol/tests.rs:1463:        tun_write_errors: 34,
userspace-dp/src/protocol/tests.rs:1464:        tun_rx_drops_no_endpoint: 35,
userspace-dp/src/protocol/tests.rs:1478:        wg_tunnels: vec![row],
userspace-dp/src/protocol/tests.rs:1483:    let wire_row = &value["wg_tunnels"][0];
userspace-dp/src/protocol/tests.rs:1484:    assert_eq!(wire_row["tunnel"], "wg0");
userspace-dp/src/protocol/tests.rs:1485:    assert_eq!(wire_row["tunnel_endpoint_id"], 7);
userspace-dp/src/protocol/tests.rs:1499:    assert_eq!(back.wg_tunnels.len(), 1);
userspace-dp/src/protocol/tests.rs:1500:    let b = &back.wg_tunnels[0];
userspace-dp/src/protocol/tests.rs:1501:    assert_eq!(b.tunnel, "wg0");
userspace-dp/src/protocol/tests.rs:1504:    assert_eq!(b.tun_rx_drops_no_endpoint, 35);
userspace-dp/src/protocol/tests.rs:1511:    // EMPTY-INVARIANT: a ProcessStatus with no WG tunnels serializes
userspace-dp/src/protocol/tests.rs:1512:    // with NO `wg_tunnels` key at all — non-WG deployments stay
userspace-dp/src/protocol/tests.rs:1517:        empty_value.get("wg_tunnels").is_none(),
userspace-dp/src/protocol/tests.rs:1518:        "empty wg_tunnels must be omitted from the wire entirely"
userspace-dp/src/protocol/tests.rs:1524:    assert!(legacy.wg_tunnels.is_empty());
userspace-dp/src/protocol/tests.rs:1530:        r#"{"tunnel":"wg9","future_field_from_s6":42}"#,
userspace-dp/src/protocol/tests.rs:1533:    assert_eq!(future_row.tunnel, "wg9");
userspace-dp/src/protocol/snapshot.rs:61:    pub tunnel: bool,
userspace-dp/src/protocol/snapshot.rs:201:    #[serde(rename = "tunnel_endpoints", default)]
userspace-dp/src/protocol/snapshot.rs:202:    pub tunnel_endpoints: Vec<TunnelEndpointSnapshot>,
userspace-dp/src/prefix_set.rs:26:/// 16 is a starting tunable; the companion bench
userspace-dp/src/prefix_set.rs:31:/// the constant turns out to be poorly tuned in production traces.
userspace-dp/src/session/tests.rs:39:        tunnel_endpoint_id: 0,
userspace-dp/src/slowpath.rs:37:pub enum EnqueueOutcome {
userspace-dp/src/slowpath.rs:166:pub struct SlowPathReinjector {
userspace-dp/src/slowpath.rs:192:    pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
userspace-dp/src/slowpath.rs:207:            return Ok(EnqueueOutcome::RateLimited);
userspace-dp/src/slowpath.rs:211:            Ok(()) => Ok(EnqueueOutcome::Accepted),
userspace-dp/src/slowpath.rs:221:                Ok(EnqueueOutcome::QueueFull)
userspace-dp/src/slowpath.rs:242:    let (tun, actual_name) = match open_tun(name) {
userspace-dp/src/slowpath.rs:268:            WriteMode::IoUring(ring) => write_packet_io_uring(ring, tun.as_raw_fd(), &req.bytes)
userspace-dp/src/slowpath.rs:269:                .or_else(|_| write_packet_sync(tun.as_raw_fd(), &req.bytes)),
userspace-dp/src/slowpath.rs:270:            WriteMode::SyncFallback => write_packet_sync(tun.as_raw_fd(), &req.bytes),
userspace-dp/src/slowpath.rs:349:pub(crate) fn open_tun(name: &str) -> Result<(std::fs::File, String), String> {
userspace-dp/src/slowpath.rs:350:    let tun = OpenOptions::new()
userspace-dp/src/slowpath.rs:353:        .open("/dev/net/tun")
userspace-dp/src/slowpath.rs:354:        .map_err(|e| format!("open /dev/net/tun: {e}"))?;
userspace-dp/src/slowpath.rs:356:    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &mut ifr) };
userspace-dp/src/slowpath.rs:370:    Ok((tun, actual_name))
userspace-dp/src/main_tests.rs:52:                tunnel: true,
userspace-dp/src/main_tests.rs:380:fn build_synced_session_entry_preserves_tunnel_endpoint_id() {
userspace-dp/src/main_tests.rs:391:        tunnel_endpoint_id: 3,
userspace-dp/src/main_tests.rs:397:    assert_eq!(entry.decision.resolution.tunnel_endpoint_id, 3);
userspace-dp/src/main_tests.rs:518:fn queue_planner_ignores_tunnel_netdevices_for_transit() {
userspace-dp/src/main_tests.rs:526:                tunnel: true,
userspace-dp/src/event_stream/codec_tests.rs:49:            tunnel_endpoint_id: 0,
userspace-dp/src/nat64.rs:149:    // stateless translation, not RFC 6040 tunnel encapsulation).
userspace-dp/src/event_stream/codec.rs:209:        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tunnel_endpoint_id.to_le_bytes());
userspace-dp/src/server/helpers.rs:33:            .reconcile_local_tunnel_liveness(state.snapshot.as_ref());
userspace-dp/src/server/helpers.rs:134:    // #1865: per-WG-tunnel telemetry rows (empty — and omitted from
userspace-dp/src/server/helpers.rs:135:    // the wire — when no WG tunnel is configured).
userspace-dp/src/server/helpers.rs:136:    state.status.wg_tunnels = state.afxdp.wg_tunnel_statuses();
userspace-dp/src/server/helpers.rs:312:    let tx_ifindex = if req.tunnel_endpoint_id != 0 {
userspace-dp/src/server/helpers.rs:355:                    || req.tunnel_endpoint_id != 0
userspace-dp/src/server/helpers.rs:364:                tunnel_endpoint_id: req.tunnel_endpoint_id,
userspace-dp/src/server/helpers.rs:555:                iface.tunnel
userspace-dp/src/server/helpers.rs:666:    if iface.tunnel {
userspace-dp/src/server/handlers/rebind.rs:28:    // captures tunnel_owners/snapshot_was_installed (which blinds the
userspace-dp/src/server/handlers/rebind.rs:29:    // tunnel-owner remap purge in apply_snapshot). The RETH-MAC link-cycle
userspace-dp/src/server/tests.rs:825:            tunnel: true,
userspace-dp/src/server/tests.rs:828:        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/server/tests.rs:855:    // opportunistically (it fails AddrInUse on dual-stack hosts, which
userspace-dp/src/server/lifecycle.rs:142:            wg_tunnels: Vec::new(),
userspace-dp/src/afxdp/icmp.rs:75:                tunnel_endpoint_id: 0,
userspace-dp/src/server/handlers/snapshot.rs:124:            // threads — a removed/mode-flipped tunnel's thread must
userspace-dp/src/server/handlers/snapshot.rs:129:                .prune_local_tunnel_sources_for_snapshot(&snapshot);
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:4://! validation, manager-neighbor key rotation, the #1873 tunnel-remap
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:9://! calls (`tunnel_remap_purge_ids`, `log_wg_endpoint_set_transition`)
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:173:        let tunnel_purge_ids = tunnel_remap_purge_ids(
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:178:        self.purge_remapped_tunnel_sessions(&tunnel_purge_ids);
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:208:            // runtime-snapshot refresh — tunnel interfaces are excluded
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:209:            // from the binding plan, so tunnel add/remove/reattach
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:215:            // (tunnel.rs endpoint_attachment_valid, plan D.1b).
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:216:            self.reconcile_local_tunnel_sources();
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:222:            self.stop_all_local_tunnel_sources("disarmed");
userspace-dp/src/afxdp/session_delta.rs:104:            tunnel_endpoint_id: delta.decision.resolution.tunnel_endpoint_id,
userspace-dp/src/afxdp/shared_ops.rs:13:/// promotes, HA sync imports, and tunnel-local installs — so zero here is
userspace-dp/src/afxdp/shared_ops.rs:612:        forward_match.decision.resolution.tunnel_endpoint_id != 0
userspace-dp/src/afxdp/shared_ops.rs:682:    allow_unseeded_tunnel_local: bool,
userspace-dp/src/afxdp/shared_ops.rs:701:    if allow_unseeded_tunnel_local
userspace-dp/src/afxdp/coordinator/supervisor.rs:42:/// - `xpf-native-gre-origin-*` death: that tunnel's local-origin
userspace-dp/src/afxdp/coordinator/supervisor.rs:43:///   packet stream stops; transit packets through the tunnel are
userspace-dp/src/afxdp/ha.rs:395:    /// #1873 R-D: purge every session whose stored tunnel_endpoint_id
userspace-dp/src/afxdp/ha.rs:398:    /// tunnel name (temporal hash reuse, or the one-time
userspace-dp/src/afxdp/ha.rs:400:    /// session would re-resolve its stored id into the WRONG tunnel
userspace-dp/src/afxdp/ha.rs:401:    /// (cross-tunnel encap) or permanently dead-end on the R-C gate.
userspace-dp/src/afxdp/ha.rs:409:    pub(crate) fn purge_remapped_tunnel_sessions(&self, purge_ids: &[u16]) -> usize {
userspace-dp/src/afxdp/ha.rs:420:                let id = entry.decision.resolution.tunnel_endpoint_id;
userspace-dp/src/afxdp/ha.rs:426:                // tunnel-marked one while the forward entry is not in
userspace-dp/src/afxdp/ha.rs:460:                "xpf-userspace-dp: purged {} session(s) on tunnel-endpoint id remap (ids {:?}) (#1873)",
userspace-dp/src/afxdp/neighbor_resolver.rs:263:    pub(crate) fn enqueue(&self, ifindex: i32, hop: IpAddr, iface_name: String) {
userspace-dp/src/afxdp/neighbor_resolver.rs:926:    fn enqueue_full_queue_counts_drop_not_block() {
userspace-dp/src/afxdp/neighbor_resolver.rs:947:    fn enqueue_snapshots_current_epoch() {
userspace-dp/src/afxdp/neighbor_resolver.rs:973:    fn enqueue_disconnected_counts_disconnected() {
userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:128:    binding.tunnel_encap_unresolved_drops = snap.tunnel_encap_unresolved_drops;
userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:302:    binding.tunnel_encap_unresolved_drops = 0;
userspace-dp/src/afxdp/cos/ecn.rs:4:// admission tuning).
userspace-dp/src/afxdp/cos/ecn.rs:183:    // rewritten (e.g. NAT64, tunnel transit). Trusting the parse keeps
userspace-dp/src/afxdp/cos/admission.rs:69:/// This is a tuning knob against live counter telemetry, not a
userspace-dp/src/afxdp/cos/admission.rs:266:/// the fraction tuned it must move in lockstep across both arms —
userspace-dp/src/afxdp/session_glue/mod.rs:90:    if decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/session_glue/mod.rs:91:        // #1873 (Codex code r2): the session's stored tunnel resolution
userspace-dp/src/afxdp/session_glue/mod.rs:95:        // reuse: remove tunnel A, add tunnel B whose name folds to the
userspace-dp/src/afxdp/session_glue/mod.rs:104:                .tunnel_endpoints
userspace-dp/src/afxdp/session_glue/mod.rs:105:                .get(&decision.resolution.tunnel_endpoint_id)
userspace-dp/src/afxdp/session_glue/mod.rs:115:                    gated.tunnel_endpoint_id = decision.resolution.tunnel_endpoint_id;
userspace-dp/src/afxdp/session_glue/mod.rs:121:        let resolved = super::resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/session_glue/mod.rs:124:            decision.resolution.tunnel_endpoint_id,
userspace-dp/src/afxdp/session_glue/mod.rs:224:fn should_bypass_unseeded_tunnel_ha(
userspace-dp/src/afxdp/session_glue/mod.rs:235:            .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/session_glue/mod.rs:590:                // #1870: local-tunnel pair entries are coordinator-
userspace-dp/src/afxdp/session_glue/mod.rs:592:                // the shared maps (the tunnel.rs publish precedes the
userspace-dp/src/afxdp/session_glue/mod.rs:606:                // tunnel resolution is ForwardCandidate
userspace-dp/src/afxdp/session_glue/mod.rs:607:                // (build_local_origin_tunnel_tx_request) — so the
userspace-dp/src/afxdp/session_glue/mod.rs:1194:        && should_bypass_unseeded_tunnel_ha(
userspace-dp/src/afxdp/types/forwarding.rs:3:// route entries, egress and tunnel-endpoint descriptors, fabric-link
userspace-dp/src/afxdp/types/forwarding.rs:23:    pub(in crate::afxdp) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
userspace-dp/src/afxdp/types/forwarding.rs:24:    pub(in crate::afxdp) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
userspace-dp/src/afxdp/types/forwarding.rs:25:    /// WireGuard engines keyed by tunnel_endpoint_id (#1432 S2a). One
userspace-dp/src/afxdp/types/forwarding.rs:30:    /// live sessions survive a commit that does not touch the tunnel.
userspace-dp/src/afxdp/types/forwarding.rs:34:    pub(in crate::afxdp) has_wg_tunnels: bool,
userspace-dp/src/afxdp/types/forwarding.rs:60:    pub(in crate::afxdp) tunnel_interfaces: FastSet<i32>,
userspace-dp/src/afxdp/types/forwarding.rs:112:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:119:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:126:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:136:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:300:    pub(crate) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/session_glue/tests.rs:38:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:85:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:258:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:307:fn test_forwarding_state_split_rgs_with_tunnel() -> ForwardingState {
userspace-dp/src/afxdp/session_glue/tests.rs:309:    forwarding.tunnel_endpoint_by_ifindex.insert(586, 1);
userspace-dp/src/afxdp/session_glue/tests.rs:438:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:526:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:1291:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:1390:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:1473:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:1554:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:1636:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:2526:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:2597:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:2673:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:2752:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:2831:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:2905:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3115:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3146:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3171:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3185:fn tunnel_ingress_session_hit_bypasses_unseeded_ha_during_startup_grace() {
userspace-dp/src/afxdp/session_glue/tests.rs:3186:    let forwarding = test_forwarding_state_split_rgs_with_tunnel();
userspace-dp/src/afxdp/session_glue/tests.rs:3197:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3214:fn reverse_session_from_tunnel_forward_bypasses_unseeded_ha_during_startup_grace() {
userspace-dp/src/afxdp/session_glue/tests.rs:3215:    let forwarding = test_forwarding_state_split_rgs_with_tunnel();
userspace-dp/src/afxdp/session_glue/tests.rs:3237:                    tunnel_endpoint_id: 1,
userspace-dp/src/afxdp/session_glue/tests.rs:3537:                    tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3649:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:3663:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/session_glue/tests.rs:4379:// Deterministic at-cap pins for the local-tunnel prewarm pair. The
userspace-dp/src/afxdp/session_glue/tests.rs:4388:/// Mirror the producer's pair shape (`build_local_origin_tunnel_tx_request`
userspace-dp/src/afxdp/session_glue/tests.rs:4391:fn local_tunnel_pair() -> (SyncedSessionEntry, SyncedSessionEntry) {
userspace-dp/src/afxdp/session_glue/tests.rs:4414:/// whose keys cannot collide with the local-tunnel pair (filler src
userspace-dp/src/afxdp/session_glue/tests.rs:4473:    let (forward, reverse) = local_tunnel_pair();
userspace-dp/src/afxdp/session_glue/tests.rs:4503:    let (forward, reverse) = local_tunnel_pair();
userspace-dp/src/afxdp/session_glue/tests.rs:4524:    let (forward, reverse) = local_tunnel_pair();
userspace-dp/src/afxdp/session_glue/tests.rs:4544:    let (forward, reverse) = local_tunnel_pair();
userspace-dp/src/afxdp/session_glue/tests.rs:4563:        "local same-key entry must be replaced by the tunnel decision"
userspace-dp/src/afxdp/session_glue/tests.rs:4579:    let (forward, reverse) = local_tunnel_pair();
userspace-dp/src/afxdp/session_glue/tests.rs:4606:/// local-tunnel entries carry SyncImport and are skipped by
userspace-dp/src/afxdp/session_glue/tests.rs:4613:    let (forward, reverse) = local_tunnel_pair();
userspace-dp/src/afxdp/session_glue/tests.rs:4622:        "peer-synced-origin local-tunnel entries must not bulk-export"
userspace-dp/src/afxdp/cos/admission_tests.rs:293:    // Written against the constants so retuning NUM/DEN doesn't
userspace-dp/src/afxdp/cos/admission_tests.rs:391:    // per-flow = 24000 / 3 = 8_000. If NUM/DEN is retuned, both
userspace-dp/src/afxdp/cos/admission_tests.rs:394:    // retune fails the pin loudly, which is the whole point.
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:3://! thread families are keyed by tunnel_endpoint_id and share the
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:6://! "Aux tunnel threads" section of this directory's README.md for
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:8://! elsewhere (`wg_control.rs` for WG, `afxdp/tunnel.rs` for GRE);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:10://! maps themselves (`tunnel_sources`, `wg_control_threads`) stay on
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:23:    /// `forwarding.tunnel_endpoints`. Called from initial worker
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:24:    /// bring-up AND every armed `refresh_runtime_snapshot` — tunnel
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:26:    /// (`include_userspace_binding_interface`), so tunnel-only commits
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:54:    pub(super) fn reconcile_local_tunnel_sources(&mut self) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:55:        let swept = self.sweep_finished_local_tunnel_sources();
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:59:        for (id, entry) in self.tunnel_sources.iter() {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:60:            let reason = match self.forwarding.tunnel_endpoints.get(id) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:69:                            .is_some_and(|name| *name == entry.spawned_tunnel_name);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:86:            self.publish_local_tunnel_deliveries_excluding(&stale_ids);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:89:            self.stop_remove_local_tunnel_entry(*id, reason);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:99:                .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:105:                match self.tunnel_sources.get(&id) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:115:                spawned |= self.spawn_one_local_tunnel_source(id);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:120:            self.publish_local_tunnel_deliveries_excluding(&[]);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:127:    fn sweep_finished_local_tunnel_sources(&mut self) -> usize {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:129:            .tunnel_sources
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:141:            if let Some(entry) = self.tunnel_sources.get_mut(&id) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:150:                    "xpf-userspace-dp: GRE local-origin thread exited endpoint={id} tun={} — tombstoned (respawn if still configured)",
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:151:                    entry.spawned_tunnel_name
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:161:    fn stop_remove_local_tunnel_entry(&mut self, id: u16, reason: &str) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:162:        if let Some(mut entry) = self.tunnel_sources.remove(&id) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:170:                "xpf-userspace-dp: stopped GRE local-origin thread endpoint={id} tun={} reason={reason}",
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:171:                entry.spawned_tunnel_name
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:176:    /// #1881: publish `local_tunnel_deliveries` from the entry map —
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:180:    fn publish_local_tunnel_deliveries_excluding(&self, exclude: &[u16]) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:182:        for (id, entry) in self.tunnel_sources.iter() {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:190:        self.local_tunnel_deliveries.store(Arc::new(map));
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:199:    fn spawn_one_local_tunnel_source(&mut self, id: u16) -> bool {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:200:        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:206:        let Some(tunnel_name) = self
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:237:        let thread_tunnel_name = tunnel_name.clone();
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:240:            "xpf-userspace-dp: spawning GRE local-origin thread endpoint={id} tun={tunnel_name}"
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:242:        // #925-A: wrap aux tunnel-origin thread in catch_unwind.
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:244:        // generated GRE traffic on this tunnel; transit packets
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:247:            format!("xpf-native-gre-origin-{}", tunnel_name),
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:249:                local_tunnel_source_loop(
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:250:                    thread_tunnel_name,
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:284:                            interface: tunnel_name.clone(),
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:285:                            reason: format!("spawn_local_tunnel_source_failed:{id}:{err}"),
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:296:        self.tunnel_sources.insert(
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:301:                spawned_tunnel_name: tunnel_name,
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:315:    pub(crate) fn stop_all_local_tunnel_sources(&mut self, reason: &str) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:316:        let ids: Vec<u16> = self.tunnel_sources.keys().copied().collect();
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:320:        self.local_tunnel_deliveries
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:323:            self.stop_remove_local_tunnel_entry(id, reason);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:330:    /// GRE tunnel's thread would keep its TUN reader fd (on a netdev
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:341:    pub(crate) fn prune_local_tunnel_sources_for_snapshot(
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:346:            .tunnel_sources
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:350:                    .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:366:                    || row_label != entry.spawned_tunnel_name
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:377:        self.publish_local_tunnel_deliveries_excluding(&stale_ids);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:379:            self.stop_remove_local_tunnel_entry(id, reason);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:395:    pub(crate) fn reconcile_local_tunnel_liveness(
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:399:        let swept = self.sweep_finished_local_tunnel_sources();
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:405:                    .tunnel_sources
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:411:                    let Some(entry) = self.tunnel_sources.get(&id) else {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:417:                    if !self.local_tunnel_tombstone_respawn_coherent(id, snapshot) {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:420:                    spawned = self.spawn_one_local_tunnel_source(id);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:426:            self.publish_local_tunnel_deliveries_excluding(&[]);
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:435:    fn local_tunnel_tombstone_respawn_coherent(
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:440:        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:454:            .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:503:        for endpoint in self.forwarding.tunnel_endpoints.values() {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:521:                        .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:529:                                    .is_some_and(|name| *name == entry.spawned_tunnel_name)
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:586:                    "xpf-userspace-dp: WG control thread exited endpoint={id} tun={} — tombstoned (respawn if still configured)",
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:587:                    entry.spawned_tunnel_name
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:604:                let name = entry.spawned_tunnel_name.clone();
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:610:                        "xpf-userspace-dp: stopped WG control thread endpoint={id} tun={name} reason={reason}"
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:620:                "xpf-userspace-dp: stopped WG control thread endpoint={id} tun={name} reason={reason}"
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:639:                "xpf-userspace-dp: stopped WG control thread endpoint={id} tun={} reason={reason}",
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:640:                entry.spawned_tunnel_name
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:652:        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:662:        let Some(tunnel_name) = self
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:676:        let thread_tunnel_name = tunnel_name.clone();
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:678:            "xpf-userspace-dp: spawning WG control thread endpoint={id} tun={tunnel_name} port={listen_port}"
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:681:            format!("xpf-wg-control-{tunnel_name}"),
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:684:                    thread_tunnel_name,
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:705:                            interface: tunnel_name.clone(),
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:723:                spawned_tunnel_name: tunnel_name,
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:783:        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:797:            .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:850:            .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/status.rs:139:    /// session replication, activation prewarm, tunnel install/drain-wait,
userspace-dp/src/afxdp/coordinator/status.rs:645:    /// #1865: per-WG-tunnel telemetry rows for `ProcessStatus.wg_tunnels`.
userspace-dp/src/afxdp/coordinator/status.rs:646:    /// One row per `mode == "wireguard"` tunnel endpoint with a live
userspace-dp/src/afxdp/coordinator/status.rs:648:    /// KEYED by tunnel name (`ifindex_to_name`; positional ids renumber
userspace-dp/src/afxdp/coordinator/status.rs:655:    pub fn wg_tunnel_statuses(&self) -> Vec<crate::protocol::WgTunnelStatus> {
userspace-dp/src/afxdp/coordinator/status.rs:658:            .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/status.rs:671:            let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
userspace-dp/src/afxdp/coordinator/status.rs:683:            let tunnel = self
userspace-dp/src/afxdp/coordinator/status.rs:708:                tunnel,
userspace-dp/src/afxdp/coordinator/status.rs:709:                tunnel_endpoint_id: id,
userspace-dp/src/afxdp/coordinator/status.rs:768:                tun_write_errors: c.tun_write_errors.load(Ordering::Relaxed),
userspace-dp/src/afxdp/coordinator/status.rs:769:                tun_rx_drops_no_endpoint: c.tun_rx_drops_no_endpoint.load(Ordering::Relaxed),
userspace-dp/src/afxdp/coordinator/mod.rs:14:mod tunnel_supervision;
userspace-dp/src/afxdp/coordinator/mod.rs:55:        .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/mod.rs:79:pub(in crate::afxdp) fn tunnel_remap_purge_ids(
userspace-dp/src/afxdp/coordinator/mod.rs:85:        .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/mod.rs:89:    tunnel_remap_purge_ids_from_owners(&owners, next, include_new_appearances)
userspace-dp/src/afxdp/coordinator/mod.rs:96:pub(in crate::afxdp) fn tunnel_remap_purge_ids_from_owners(
userspace-dp/src/afxdp/coordinator/mod.rs:103:        match next.tunnel_endpoints.get(id) {
userspace-dp/src/afxdp/coordinator/mod.rs:110:        for id in next.tunnel_endpoints.keys() {
userspace-dp/src/afxdp/coordinator/mod.rs:124:/// itself carries tunnel_endpoint_id == 0 in asymmetric topologies and
userspace-dp/src/afxdp/coordinator/mod.rs:127:/// forward keeps forwarding without the tunnel), matching the live
userspace-dp/src/afxdp/coordinator/mod.rs:138:        let id = entry.decision.resolution.tunnel_endpoint_id;
userspace-dp/src/afxdp/coordinator/mod.rs:175:    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/coordinator/mod.rs:177:    /// tunnel_endpoint_id. Reconciled by the same three-pass shape as
userspace-dp/src/afxdp/coordinator/mod.rs:181:    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceEntry>,
userspace-dp/src/afxdp/coordinator/mod.rs:183:    /// tunnel_endpoint_id. Each entry records the engine Arc address +
userspace-dp/src/afxdp/coordinator/mod.rs:225:            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
userspace-dp/src/afxdp/coordinator/mod.rs:226:            tunnel_sources: BTreeMap::new(),
userspace-dp/src/afxdp/coordinator/mod.rs:394:        for entry in self.tunnel_sources.values_mut() {
userspace-dp/src/afxdp/coordinator/mod.rs:399:        for entry in self.tunnel_sources.values_mut() {
userspace-dp/src/afxdp/coordinator/mod.rs:406:        self.tunnel_sources.clear();
userspace-dp/src/afxdp/coordinator/mod.rs:407:        self.local_tunnel_deliveries
userspace-dp/src/afxdp/coordinator/mod.rs:690:        // Tunnel routes (tunnel_endpoint_id != 0) are skipped: their HA
userspace-dp/src/afxdp/coordinator/mod.rs:691:        // ownership is the tunnel endpoint's RG, not the underlay egress
userspace-dp/src/afxdp/coordinator/mod.rs:693:        // tunnel_endpoint_id) — gating them via owner_rg_for_flow(egress)
userspace-dp/src/afxdp/coordinator/mod.rs:697:        // as ordinary (tunnel_endpoint_id == 0) routes.
userspace-dp/src/afxdp/coordinator/mod.rs:700:                if route.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/coordinator/mod.rs:710:                if route.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/coordinator/wg_control.rs:3://! One supervised aux thread per `mode == "wireguard"` tunnel endpoint,
userspace-dp/src/afxdp/coordinator/wg_control.rs:4://! modeled on `spawn_local_tunnel_sources` (the GRE local-origin
userspace-dp/src/afxdp/coordinator/wg_control.rs:59:/// Outer MTU assumed for the WG transport path (S2a single-tunnel;
userspace-dp/src/afxdp/coordinator/wg_control.rs:60:/// matches the Go-side wgN MTU cap in pkg/routing/tunnel.go). The exact
userspace-dp/src/afxdp/coordinator/wg_control.rs:88:/// ~10/s per tunnel. With every timer deadline >= 1s out the idle
userspace-dp/src/afxdp/coordinator/wg_control.rs:107:    tunnel_name: String,
userspace-dp/src/afxdp/coordinator/wg_control.rs:108:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/coordinator/wg_control.rs:122:            record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:124:                &tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:128:                "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: bind :{listen_port} failed: {err}"
userspace-dp/src/afxdp/coordinator/wg_control.rs:134:        record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:136:            &tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:140:            "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: set_nonblocking failed: {err}"
userspace-dp/src/afxdp/coordinator/wg_control.rs:145:    // Attach to the persistent wgN TUN (Go pre-created it; open_tun
userspace-dp/src/afxdp/coordinator/wg_control.rs:147:    let mut tun = match open_tun(&tunnel_name) {
userspace-dp/src/afxdp/coordinator/wg_control.rs:151:                "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: open_tun failed: {err}"
userspace-dp/src/afxdp/coordinator/wg_control.rs:153:            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
userspace-dp/src/afxdp/coordinator/wg_control.rs:157:    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
userspace-dp/src/afxdp/coordinator/wg_control.rs:159:            "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: tun set_nonblocking failed: {err}"
userspace-dp/src/afxdp/coordinator/wg_control.rs:161:        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
userspace-dp/src/afxdp/coordinator/wg_control.rs:166:        &tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:170:        tun,
userspace-dp/src/afxdp/coordinator/wg_control.rs:176:    eprintln!("xpf-userspace-dp: WG control thread stopped tun={tunnel_name}");
userspace-dp/src/afxdp/coordinator/wg_control.rs:177:    let _ = tunnel_endpoint_id;
userspace-dp/src/afxdp/coordinator/wg_control.rs:244:/// Block in poll(2) on {socket, tun} POLLIN with `timeout_ms`.
userspace-dp/src/afxdp/coordinator/wg_control.rs:250:fn wg_poll_wait(socket_fd: i32, tun_fd: i32, timeout_ms: i32) -> PollWait {
userspace-dp/src/afxdp/coordinator/wg_control.rs:258:            fd: tun_fd,
userspace-dp/src/afxdp/coordinator/wg_control.rs:275:        return PollWait::Fatal("tun_revents");
userspace-dp/src/afxdp/coordinator/wg_control.rs:289:/// The per-tunnel control loop proper, on pre-opened fds so the loop
userspace-dp/src/afxdp/coordinator/wg_control.rs:294:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:298:    mut tun: std::fs::File,
userspace-dp/src/afxdp/coordinator/wg_control.rs:309:    // and the tunnel would black-hole the reply path). This is the WG
userspace-dp/src/afxdp/coordinator/wg_control.rs:315:    let mut tun_buf = vec![0u8; 65_535];
userspace-dp/src/afxdp/coordinator/wg_control.rs:320:    let tun_fd = tun.as_raw_fd();
userspace-dp/src/afxdp/coordinator/wg_control.rs:328:    let mut tun_fatal_reads: u32 = 0;
userspace-dp/src/afxdp/coordinator/wg_control.rs:344:            tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:366:                        &mut tun,
userspace-dp/src/afxdp/coordinator/wg_control.rs:371:                        tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:408:                                    tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:423:                    record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:425:                        tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:436:                match tun.read(&mut tun_buf) {
userspace-dp/src/afxdp/coordinator/wg_control.rs:439:                        tun_fatal_reads = 0;
userspace-dp/src/afxdp/coordinator/wg_control.rs:446:                            &tun_buf[..len],
userspace-dp/src/afxdp/coordinator/wg_control.rs:448:                            tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:455:                        tun_fatal_reads += 1;
userspace-dp/src/afxdp/coordinator/wg_control.rs:456:                        record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:458:                            tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:459:                            format!("wg_tun_read:{e}"),
userspace-dp/src/afxdp/coordinator/wg_control.rs:473:                match tun.read(&mut tun_buf) {
userspace-dp/src/afxdp/coordinator/wg_control.rs:477:                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
userspace-dp/src/afxdp/coordinator/wg_control.rs:479:                        tun_fatal_reads = 0;
userspace-dp/src/afxdp/coordinator/wg_control.rs:484:                        tun_fatal_reads += 1;
userspace-dp/src/afxdp/coordinator/wg_control.rs:490:        if tun_fatal_reads >= WG_TUN_FATAL_READ_LIMIT {
userspace-dp/src/afxdp/coordinator/wg_control.rs:494:            record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:496:                tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:497:                "wg_tun_fatal_reads:exiting".to_string(),
userspace-dp/src/afxdp/coordinator/wg_control.rs:518:                            &mut encap_buf, tunnel_name, recent_exceptions,
userspace-dp/src/afxdp/coordinator/wg_control.rs:534:                    tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:548:            match wg_poll_wait(socket_fd, tun_fd, poll_timeout_ms(next_deadline, now)) {
userspace-dp/src/afxdp/coordinator/wg_control.rs:551:                    record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:553:                        tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:578:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:600:        tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:624:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:676:                    tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:717:            tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:739:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:760:                    record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:762:                        tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:806:/// tunnel placed inside a routing-instance whose peer route lives only in
userspace-dp/src/afxdp/coordinator/wg_control.rs:808:/// owned by the S6 multi-instance work (#1434). S2a single-tunnel scope
userspace-dp/src/afxdp/coordinator/wg_control.rs:929:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:946:                record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:948:                    tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:969:    tun: &mut std::fs::File,
userspace-dp/src/afxdp/coordinator/wg_control.rs:974:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:996:                            record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:998:                                tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1006:                    debug_log!("WG[{}]: drop initiation reason={:?}", tunnel_name, _e);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1014:                debug_log!("WG[{}]: drop response reason={:?}", tunnel_name, _e);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1022:            debug_log!("WG[{}]: drop cookie (S7)", tunnel_name);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1032:                    if let Err(e) = tun.write_all(&decap_buf[..outcome.len]) {
userspace-dp/src/afxdp/coordinator/wg_control.rs:1033:                        WgCounters::bump(&engine.counters().tun_write_errors);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1034:                        record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:1036:                            tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1037:                            format!("wg_tun_write:{e}"),
userspace-dp/src/afxdp/coordinator/wg_control.rs:1054:                    debug_log!("WG[{}]: drop transport reason={:?}", tunnel_name, _e);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1065:            debug_log!("WG[{}]: drop unknown type {}", tunnel_name, wg_type);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1084:    tunnel_name: &str,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1099:            tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1109:                record_local_tunnel_exception(
userspace-dp/src/afxdp/coordinator/wg_control.rs:1111:                    tunnel_name,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1122:            debug_log!("WG[{}]: encap drop reason={:?}", tunnel_name, _e);
userspace-dp/src/afxdp/coordinator/wg_control.rs:1211:        std::fs::File,             // tun stand-in (pipe read end)
userspace-dp/src/afxdp/coordinator/wg_control.rs:1236:        let tun = unsafe { std::fs::File::from_raw_fd(read_fd) };
userspace-dp/src/afxdp/coordinator/wg_control.rs:1240:        (engine, socket, tun, pipe_w, exceptions, stop)
userspace-dp/src/afxdp/coordinator/wg_control.rs:1246:        tun: std::fs::File,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1256:                tun,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1268:        let (engine, socket, tun, _pipe_w, exceptions, stop) = poll_loop_fixture();
userspace-dp/src/afxdp/coordinator/wg_control.rs:1269:        let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
userspace-dp/src/afxdp/coordinator/wg_control.rs:1287:        let (engine, socket, tun, _pipe_w, exceptions, stop) = poll_loop_fixture();
userspace-dp/src/afxdp/coordinator/wg_control.rs:1290:        let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
userspace-dp/src/afxdp/coordinator/wg_control.rs:1317:    fn poll_loop_exits_on_tun_teardown() {
userspace-dp/src/afxdp/coordinator/wg_control.rs:1318:        let (engine, socket, tun, pipe_w, exceptions, stop) = poll_loop_fixture();
userspace-dp/src/afxdp/coordinator/wg_control.rs:1319:        let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
userspace-dp/src/afxdp/coordinator/wg_control.rs:1341:        let (engine, socket, _tun, _pipe_w, exceptions, _stop) = poll_loop_fixture();
userspace-dp/src/afxdp/tx/tcp_segmentation.rs:21:    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/types/runtime.rs:45:/// tunnel_endpoint_id in `Coordinator::tunnel_sources`. Mirrors
userspace-dp/src/afxdp/types/runtime.rs:59:    /// tunnel name. Attachment drift is the ONLY restart condition.
userspace-dp/src/afxdp/types/runtime.rs:61:    pub(in crate::afxdp) spawned_tunnel_name: String,
userspace-dp/src/afxdp/types/runtime.rs:65:    /// `local_tunnel_deliveries` is restricted to entries with a live
userspace-dp/src/afxdp/types/runtime.rs:73:/// tunnel_endpoint_id in `Coordinator::wg_control_threads`.
userspace-dp/src/afxdp/types/runtime.rs:93:    /// resolved tunnel name. Attachment drift is a stale condition —
userspace-dp/src/afxdp/types/runtime.rs:97:    pub(in crate::afxdp) spawned_tunnel_name: String,
userspace-dp/src/afxdp/types/runtime.rs:400:    pub(in crate::afxdp) local_tunnel_deliveries:
userspace-dp/src/afxdp/tx/dispatch/mod.rs:74:pub(in crate::afxdp) fn enqueue_pending_forwards(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:88:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:229:                        local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:242:                        local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:418:                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:445:                    && !uses_native_tunnel
userspace-dp/src/afxdp/tx/dispatch/mod.rs:610:                    let direct_built = if is_nat64 || uses_native_tunnel {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:891:                local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:1032:    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/cos/queue_service/mod.rs:762:// > 0`. Implements an operator-tunable budget split between Phase 1
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:39:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:56:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:509:fn enqueue_pending_forwards_mirrors_live_frame_and_records_counter() {
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:542:    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:564:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/cos.rs:80:pub(super) fn enqueue_local_request_to_target_or_owner(
userspace-dp/src/afxdp/coordinator/tests.rs:168:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/coordinator/tests.rs:644:    // COS_ROOT_LEASE_TARGET_US, both of which are tuning knobs, so
userspace-dp/src/afxdp/coordinator/tests.rs:646:    // against legitimate scheduler tuning.
userspace-dp/src/afxdp/coordinator/tests.rs:1706:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/coordinator/tests.rs:1761:fn queue_warm_pass_skips_tunnel_routes() {
userspace-dp/src/afxdp/coordinator/tests.rs:1762:    // Codex r1 High #1: a route with tunnel_endpoint_id != 0 is HA-owned
userspace-dp/src/afxdp/coordinator/tests.rs:1763:    // by the tunnel endpoint's RG, not the underlay egress RG, and is out
userspace-dp/src/afxdp/coordinator/tests.rs:1767:    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].tunnel_endpoint_id = 7;
userspace-dp/src/afxdp/coordinator/tests.rs:1769:    assert!(rx.try_recv().is_err(), "tunnel route must not be warmed");
userspace-dp/src/afxdp/coordinator/tests.rs:1791:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/coordinator/tests.rs:1852:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/coordinator/tests.rs:2129:// then fails open_tun (no TUN device in the test environment) and
userspace-dp/src/afxdp/coordinator/tests.rs:2148:            tunnel: true,
userspace-dp/src/afxdp/coordinator/tests.rs:2151:        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/afxdp/coordinator/tests.rs:2323:        coordinator.forwarding.tunnel_endpoints.contains_key(&1),
userspace-dp/src/afxdp/coordinator/tests.rs:2348:    assert!(wg1866_wait_tombstone(&mut coordinator, 1, 2_000), "open_tun failure tombstones");
userspace-dp/src/afxdp/coordinator/tests.rs:2379:    assert!(wg1866_wait_tombstone(&mut coordinator, 1, 2_000), "open_tun failure tombstones");
userspace-dp/src/afxdp/coordinator/tests.rs:2405:    assert_eq!(entry.spawned_tunnel_name, "wgt1866i");
userspace-dp/src/afxdp/coordinator/tests.rs:2411:        entry.spawned_tunnel_name, "wgt1866j",
userspace-dp/src/afxdp/coordinator/tests.rs:2428:    snap.tunnel_endpoints[0].linux_name = String::new();
userspace-dp/src/afxdp/coordinator/tests.rs:2432:        "open_tun failure tombstones"
userspace-dp/src/afxdp/coordinator/tests.rs:2451:// path; the spawned thread fails open_tun (no TUN privilege in the
userspace-dp/src/afxdp/coordinator/tests.rs:2455:// touched tunnel_sources (threads were spawned at bring-up only).
userspace-dp/src/afxdp/coordinator/tests.rs:2464:            tunnel: true,
userspace-dp/src/afxdp/coordinator/tests.rs:2467:        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/afxdp/coordinator/tests.rs:2513:        coordinator.reconcile_local_tunnel_liveness(None);
userspace-dp/src/afxdp/coordinator/tests.rs:2514:        match coordinator.tunnel_sources.get(&id) {
userspace-dp/src/afxdp/coordinator/tests.rs:2525:/// THE bug pin (#1881 F3): a same-plan refresh that adds a GRE tunnel
userspace-dp/src/afxdp/coordinator/tests.rs:2527:/// Fails on master, where refresh never reconciled tunnel_sources.
userspace-dp/src/afxdp/coordinator/tests.rs:2533:        .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2537:    assert_eq!(entry.spawned_tunnel_name, "gre1881a");
userspace-dp/src/afxdp/coordinator/tests.rs:2541:            .local_tunnel_deliveries
userspace-dp/src/afxdp/coordinator/tests.rs:2548:/// #1881 F4: a refresh that REMOVES the tunnel stops + joins the
userspace-dp/src/afxdp/coordinator/tests.rs:2554:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2557:        coordinator.tunnel_sources.is_empty(),
userspace-dp/src/afxdp/coordinator/tests.rs:2561:        coordinator.local_tunnel_deliveries.load().is_empty(),
userspace-dp/src/afxdp/coordinator/tests.rs:2573:        coordinator.tunnel_sources.is_empty(),
userspace-dp/src/afxdp/coordinator/tests.rs:2576:    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2588:        .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2594:        .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2610:        .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2616:        .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2624:    let deliveries = coordinator.local_tunnel_deliveries.load();
userspace-dp/src/afxdp/coordinator/tests.rs:2639:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2643:        !coordinator.tunnel_sources.contains_key(&1),
userspace-dp/src/afxdp/coordinator/tests.rs:2650:    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2661:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2664:        coordinator.tunnel_sources.is_empty(),
userspace-dp/src/afxdp/coordinator/tests.rs:2667:    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2678:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2680:    coordinator.prune_local_tunnel_sources_for_snapshot(&snap);
userspace-dp/src/afxdp/coordinator/tests.rs:2681:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2686:    coordinator.prune_local_tunnel_sources_for_snapshot(&moved);
userspace-dp/src/afxdp/coordinator/tests.rs:2688:        coordinator.tunnel_sources.is_empty(),
userspace-dp/src/afxdp/coordinator/tests.rs:2691:    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2695:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2696:    coordinator.prune_local_tunnel_sources_for_snapshot(&ConfigSnapshot::default());
userspace-dp/src/afxdp/coordinator/tests.rs:2697:    assert!(coordinator.tunnel_sources.is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2698:    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2701:/// #1881 F6: a thread that exits (open_tun failure here) is
userspace-dp/src/afxdp/coordinator/tests.rs:2713:        "open_tun failure tombstones the entry"
userspace-dp/src/afxdp/coordinator/tests.rs:2716:        coordinator.local_tunnel_deliveries.load().is_empty(),
userspace-dp/src/afxdp/coordinator/tests.rs:2722:        .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2727:    coordinator.reconcile_local_tunnel_liveness(Some(&mismatched));
userspace-dp/src/afxdp/coordinator/tests.rs:2730:            .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2738:    coordinator.reconcile_local_tunnel_liveness(Some(&snap));
userspace-dp/src/afxdp/coordinator/tests.rs:2741:            .tunnel_sources
userspace-dp/src/afxdp/coordinator/tests.rs:2758:    assert!(coordinator.tunnel_sources.contains_key(&1));
userspace-dp/src/afxdp/coordinator/tests.rs:2760:    assert!(coordinator.tunnel_sources.is_empty(), "stop clears entries");
userspace-dp/src/afxdp/coordinator/tests.rs:2761:    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
userspace-dp/src/afxdp/coordinator/tests.rs:2763:        coordinator.reconcile_local_tunnel_liveness(Some(&snap));
userspace-dp/src/afxdp/coordinator/tests.rs:2765:            coordinator.tunnel_sources.is_empty(),
userspace-dp/src/afxdp/bpf_map_tests.rs:12:fn local_delivery_decision(tunnel_endpoint_id: u16) -> SessionDecision {
userspace-dp/src/afxdp/bpf_map_tests.rs:19:            tunnel_endpoint_id,
userspace-dp/src/afxdp/bpf_map_tests.rs:41:fn kernel_local_session_map_entry_requires_zero_tunnel_endpoint() {
userspace-dp/src/afxdp/bpf_map_tests.rs:124:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/bpf_map_tests.rs:173:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/neighbor_dispatch.rs:206:        // #1873 R-E defense-in-depth: tunnel-marked entries are excluded
userspace-dp/src/afxdp/neighbor_dispatch.rs:208:        // but an in-place rewrite of a tunnel inner packet transmits it
userspace-dp/src/afxdp/neighbor_dispatch.rs:212:        if decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/neighbor_dispatch.rs:215:                .tunnel_encap_unresolved_drops
userspace-dp/src/afxdp/neighbor_dispatch.rs:500:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:29:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:65:            local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:82:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:117:        local_tunnel_deliveries,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:133:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156:    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159:        local_tunnel_deliveries
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:166:    if let Some(delivery) = tunnel_delivery {
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:176:                    "local_tunnel_delivery_queue_full",
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:188:                    "local_tunnel_delivery_unavailable",
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:198:    // #1873 R-C (blanket gate, plan v4): a tunnel-marked inner packet
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:201:    // kernel's view diverges from the userspace FIB (tunnel removed,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:209:    // the #1769 prober + retransmission. The local_tunnel_deliveries
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:212:    if decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:213:        live.tunnel_encap_unresolved_drops
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:218:            "tunnel_encap_unresolved",
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:241:        Ok(EnqueueOutcome::Accepted) => {
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:244:        Ok(EnqueueOutcome::RateLimited) => {
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:257:        Ok(EnqueueOutcome::QueueFull) => {
userspace-dp/src/afxdp/tx/cos_classify_tests.rs:42:fn enqueue_exact_queue_publishes_shared_backlog_slot() {
userspace-dp/src/afxdp/tx/cos_classify_tests.rs:2398:fn enqueue_cos_item_stamps_enqueue_ns_at_admission() {
userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:10://! monitor, and spawn the local tunnel sources. Final
userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:255:        let local_tunnel_deliveries = coord.local_tunnel_deliveries.clone();
userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:320:                    local_tunnel_deliveries,
userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:449:    coord.reconcile_local_tunnel_sources();
userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:16:    // #1873 R-D (AGY code r3): capture the tunnel-owner map and the
userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:20:    let tunnel_owners: Vec<(u16, String)> = coord
userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:22:        .tunnel_endpoints
userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:50:        tunnel_owners,
userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:31:    /// #1873 R-D (AGY code r3): the tunnel-owner map (id -> logical
userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:37:    pub(super) tunnel_owners: Vec<(u16, String)>,
userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:72:    ///    start neighbor monitor + local tunnel sources.
userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:121:            &preserved.tunnel_owners,
userspace-dp/src/afxdp/flow_cache_tests.rs:55:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:438:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:602:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:952:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:1277:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:26:    prior_tunnel_owners: &[(u16, String)],
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:63:    // #1873 R-D: the purge diff runs against the tunnel-owner map
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:74:    let tunnel_purge_ids = super::super::tunnel_remap_purge_ids_from_owners(
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:75:        prior_tunnel_owners,
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:79:    coord.purge_remapped_tunnel_sessions(&tunnel_purge_ids);
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:87:        &tunnel_purge_ids,
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:114:        .local_tunnel_deliveries
userspace-dp/src/afxdp/tunnel.rs:7:fn local_tunnel_io_error_is_fatal(err: &io::Error) -> bool {
userspace-dp/src/afxdp/tunnel.rs:30:fn local_tunnel_write_error_is_fatal(err: &io::Error) -> bool {
userspace-dp/src/afxdp/tunnel.rs:57:/// `local_tunnel_source_loop` so the stop-latency contract is unit
userspace-dp/src/afxdp/tunnel.rs:59:pub(super) fn drain_local_tunnel_deliveries(
userspace-dp/src/afxdp/tunnel.rs:60:    tun: &mut impl Write,
userspace-dp/src/afxdp/tunnel.rs:63:    tunnel_name: &str,
userspace-dp/src/afxdp/tunnel.rs:72:                if let Err(err) = tun.write_all(&packet) {
userspace-dp/src/afxdp/tunnel.rs:73:                    record_local_tunnel_exception(
userspace-dp/src/afxdp/tunnel.rs:75:                        tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:76:                        format!("write_local_tunnel_delivery:{err}"),
userspace-dp/src/afxdp/tunnel.rs:78:                    if local_tunnel_write_error_is_fatal(&err) {
userspace-dp/src/afxdp/tunnel.rs:92:/// the tunnel this thread is attached to. The TUN fd is bound to the
userspace-dp/src/afxdp/tunnel.rs:104:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tunnel.rs:106:    spawned_tunnel_name: &str,
userspace-dp/src/afxdp/tunnel.rs:108:    let Some(endpoint) = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id) else {
userspace-dp/src/afxdp/tunnel.rs:118:            .is_some_and(|name| name == spawned_tunnel_name)
userspace-dp/src/afxdp/tunnel.rs:121:pub(super) fn local_tunnel_source_loop(
userspace-dp/src/afxdp/tunnel.rs:122:    tunnel_name: String,
userspace-dp/src/afxdp/tunnel.rs:123:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tunnel.rs:139:    let mut tun = match open_tun(&tunnel_name) {
userspace-dp/src/afxdp/tunnel.rs:142:            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
userspace-dp/src/afxdp/tunnel.rs:146:    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
userspace-dp/src/afxdp/tunnel.rs:147:        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
userspace-dp/src/afxdp/tunnel.rs:167:        tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:169:        &tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:178:                tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:180:                &tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:189:        match drain_local_tunnel_deliveries(
userspace-dp/src/afxdp/tunnel.rs:190:            &mut tun,
userspace-dp/src/afxdp/tunnel.rs:193:            &tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:199:        match tun.read(&mut packet) {
userspace-dp/src/afxdp/tunnel.rs:209:                        "LOCAL_TUNNEL[{}]: drop endpoint={} reason=local_tunnel_unattached",
userspace-dp/src/afxdp/tunnel.rs:210:                        tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:211:                        tunnel_endpoint_id
userspace-dp/src/afxdp/tunnel.rs:216:                match build_local_origin_tunnel_tx_request(
userspace-dp/src/afxdp/tunnel.rs:218:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:224:                        maybe_enqueue_local_tunnel_session(
userspace-dp/src/afxdp/tunnel.rs:242:                                record_local_tunnel_exception(
userspace-dp/src/afxdp/tunnel.rs:244:                                    &tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:245:                                    format!("enqueue_local_tunnel_tx:{err}"),
userspace-dp/src/afxdp/tunnel.rs:249:                            record_local_tunnel_exception(
userspace-dp/src/afxdp/tunnel.rs:251:                                &tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:261:                            tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:262:                            tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:272:                record_local_tunnel_exception(
userspace-dp/src/afxdp/tunnel.rs:274:                    &tunnel_name,
userspace-dp/src/afxdp/tunnel.rs:275:                    format!("read_local_tunnel:{err}"),
userspace-dp/src/afxdp/tunnel.rs:277:                if local_tunnel_io_error_is_fatal(&err) {
userspace-dp/src/afxdp/tunnel.rs:286:pub(super) fn build_local_origin_tunnel_tx_request(
userspace-dp/src/afxdp/tunnel.rs:288:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tunnel.rs:295:    let inner_frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
userspace-dp/src/afxdp/tunnel.rs:306:        resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/tunnel.rs:309:            tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:315:            "local_tunnel_resolution:{}",
userspace-dp/src/afxdp/tunnel.rs:371:        return Err("local_tunnel_packet_dropped_by_three_color_policer".to_string());
userspace-dp/src/afxdp/tunnel.rs:413:pub(super) fn wrap_raw_ip_packet_for_tunnel(packet: &[u8], addr_family: u8) -> Vec<u8> {
userspace-dp/src/afxdp/tunnel.rs:424:pub(super) fn maybe_enqueue_local_tunnel_session(
userspace-dp/src/afxdp/tunnel.rs:435:    prune_local_tunnel_sessions(local_sessions, local_sessions_last_prune_ns, now_ns);
userspace-dp/src/afxdp/tunnel.rs:467:        // local-tunnel UpsertLocal pair for a poisoned worker queue. A
userspace-dp/src/afxdp/tunnel.rs:478:    wait_for_local_tunnel_session_install(worker_commands, now_ns + 1_000_000);
userspace-dp/src/afxdp/tunnel.rs:481:fn prune_local_tunnel_sessions(
userspace-dp/src/afxdp/tunnel.rs:496:pub(super) fn wait_for_local_tunnel_session_install(
userspace-dp/src/afxdp/tunnel.rs:572:#[path = "tunnel_tests.rs"]
userspace-dp/src/afxdp/tunnel.rs:575:pub(super) fn record_local_tunnel_exception(
userspace-dp/src/afxdp/tunnel.rs:577:    tunnel_name: &str,
userspace-dp/src/afxdp/tunnel.rs:585:                interface: tunnel_name.to_string(),
userspace-dp/src/afxdp/coordinator/reconcile/reset.rs:58:        binding.tunnel_encap_unresolved_drops = 0;
userspace-dp/src/afxdp/tx/cos_classify.rs:435:pub(in crate::afxdp) fn enqueue_local_into_cos(
userspace-dp/src/afxdp/tx/cos_classify.rs:575:pub(super) fn enqueue_prepared_into_cos(
userspace-dp/src/afxdp/tx/cos_classify.rs:815:fn enqueue_cos_item(
userspace-dp/src/afxdp/gre.rs:93:fn match_tunnel_endpoint(
userspace-dp/src/afxdp/gre.rs:101:    forwarding.tunnel_endpoints.values().find(|endpoint| {
userspace-dp/src/afxdp/gre.rs:220:    let endpoint = match_tunnel_endpoint(
userspace-dp/src/afxdp/gre.rs:261:    // is the per-packet path on GRE-tunnel workloads. Direct ID
userspace-dp/src/afxdp/gre.rs:307:        .tunnel_endpoints
userspace-dp/src/afxdp/gre.rs:308:        .get(&decision.resolution.tunnel_endpoint_id)?;
userspace-dp/src/afxdp/cos/queue_service/tests.rs:3114:    // 37,500 B); fraction tuned so the Phase-1 budget == q0's quantum exactly
userspace-dp/src/afxdp/forwarding_build/fib.rs:44:            let (next_hop, ifindex, tunnel_endpoint_id) = resolve_route_target_v4(
userspace-dp/src/afxdp/forwarding_build/fib.rs:58:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/fib.rs:66:            let (next_hop, ifindex, tunnel_endpoint_id) = resolve_route_target_v6(
userspace-dp/src/afxdp/forwarding_build/fib.rs:80:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/fib.rs:175:                    .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding_build/fib.rs:182:    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
userspace-dp/src/afxdp/forwarding_build/fib.rs:183:    (next_hop, ifindex, tunnel_endpoint_id)
userspace-dp/src/afxdp/forwarding_build/fib.rs:209:                    .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding_build/fib.rs:216:    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
userspace-dp/src/afxdp/forwarding_build/fib.rs:217:    (next_hop, ifindex, tunnel_endpoint_id)
userspace-dp/src/afxdp/forwarding_build/fib.rs:277:        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
userspace-dp/src/afxdp/forwarding_build/fib.rs:288:        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
userspace-dp/src/afxdp/mod.rs:23:use crate::slowpath::{EnqueueOutcome, SlowPathReinjector, SlowPathStatus, open_tun};
userspace-dp/src/afxdp/mod.rs:108:#[path = "tunnel.rs"]
userspace-dp/src/afxdp/mod.rs:109:mod tunnel;
userspace-dp/src/afxdp/mod.rs:128:// Clean-room WireGuard tunnel termination — see
userspace-dp/src/afxdp/mod.rs:179:use self::tunnel::*;
userspace-dp/src/afxdp/worker_queue.rs:12://   forward + reverse UpsertLocal pair in tunnel.rs) leaves exactly
userspace-dp/src/afxdp/worker_queue.rs:31:/// session replication, activation prewarm, tunnel install/drain-wait,
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:3://! Populates `state.tunnel_endpoints` and
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:4://! `state.tunnel_endpoint_by_ifindex`. Must run before the
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:6://! `tunnel_endpoint_by_ifindex` when building
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:7://! `ConnectedRouteV4/V6.tunnel_endpoint_id`.
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:12:pub(super) fn populate_tunnel_endpoints(
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:16:    for endpoint in &snapshot.tunnel_endpoints {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:50:        // endpoint is dropped — a WG tunnel with a bad local privkey or
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:72:        state.tunnel_endpoints.insert(
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:103:            .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:106:            state.has_wg_tunnels = true;
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:111:/// #1866: the hydratable WG identity of one tunnel-endpoint snapshot
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:114:/// exact gates `populate_tunnel_endpoints` applies. Single source of
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:141:/// gates as `populate_tunnel_endpoints`' WireGuard arm: mode must be
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:156:    // A WG tunnel with no listen port cannot bind a socket and is
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:158:    // "no WG"). Drop it rather than install a half-dead tunnel
userspace-dp/src/afxdp/poll_stages.rs:164:/// frame would record the GRE tunnel's egress MAC instead of the
userspace-dp/src/afxdp/poll_stages.rs:444:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/poll_stages.rs:456:        worker_ctx.local_tunnel_deliveries,
userspace-dp/src/afxdp/poll_stages.rs:562:        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/poll_stages.rs:589:            local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/forwarding_build/mod.rs:14://! - [`tunnels`] — `populate_tunnel_endpoints`
userspace-dp/src/afxdp/forwarding_build/mod.rs:30:mod tunnels;
userspace-dp/src/afxdp/forwarding_build/mod.rs:46:// `WgRowIdentity` type itself is only named inside `tunnels`.)
userspace-dp/src/afxdp/forwarding_build/mod.rs:47:pub(in crate::afxdp) use tunnels::hydrate_wg_identity;
userspace-dp/src/afxdp/forwarding_build/mod.rs:145:    tunnels::populate_tunnel_endpoints(snapshot, &mut state);
userspace-dp/src/afxdp/forwarding_build/mod.rs:430:/// (neighRetransTargetMs in pkg/daemon/host_tunables.go) but the kernel
userspace-dp/src/afxdp/cos/fairness.rs:29:/// starting point; tunable.
userspace-dp/src/afxdp/mirror.rs:61:pub(in crate::afxdp) fn enqueue_mirror_clone(
userspace-dp/src/afxdp/mirror.rs:102:pub(in crate::afxdp) fn enqueue_sampled_mirror_clone(
userspace-dp/src/afxdp/mirror.rs:172:fn enqueue_mirror_clone_to_binding(
userspace-dp/src/afxdp/mirror.rs:251:pub(in crate::afxdp) fn enqueue_mirror_clone_to_live(
userspace-dp/src/afxdp/mirror.rs:296:pub(in crate::afxdp) fn enqueue_admitted_mirror_clone_to_live(
userspace-dp/src/afxdp/mirror.rs:326:pub(in crate::afxdp) fn enqueue_sampled_mirror_clone_to_live(
userspace-dp/src/afxdp/test_fixtures.rs:128:                tunnel: true,
userspace-dp/src/afxdp/test_fixtures.rs:137:        tunnel_endpoints: vec![TunnelEndpointSnapshot {
userspace-dp/src/afxdp/umem/tests.rs:35:fn enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer() {
userspace-dp/src/afxdp/umem/tests.rs:109:fn enqueue_tx_owned_below_cap_does_not_touch_overflow_counter() {
userspace-dp/src/afxdp/umem/tests.rs:1514:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/ha_tests.rs:123:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/ha_tests.rs:165:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/umem/snapshot.rs:112:            tunnel_encap_unresolved_drops: self
userspace-dp/src/afxdp/umem/snapshot.rs:113:                .tunnel_encap_unresolved_drops
userspace-dp/src/afxdp/umem/mod.rs:384:    /// #1873 R-C: tunnel-marked inner packets dropped at the slow-path
userspace-dp/src/afxdp/umem/mod.rs:387:    /// bumped by the R-E pending-neigh tunnel exclusion.
userspace-dp/src/afxdp/umem/mod.rs:388:    pub(in crate::afxdp) tunnel_encap_unresolved_drops: AtomicU64,
userspace-dp/src/afxdp/umem/mod.rs:485:    /// admission candidate (non-tunnel decision with a next_hop, seed
userspace-dp/src/afxdp/umem/mod.rs:651:    pub(in crate::afxdp) fn enqueue_owned(mut self, req: TxRequest) -> Result<(), TxRequest> {
userspace-dp/src/afxdp/umem/mod.rs:738:            tunnel_encap_unresolved_drops: AtomicU64::new(0),
userspace-dp/src/afxdp/umem/mod.rs:977:    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
userspace-dp/src/afxdp/umem/mod.rs:982:    pub(super) fn enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
userspace-dp/src/afxdp/neighbor.rs:518:/// self-contained instead of depending on the Go-side `tuneSocketBuffers`
userspace-dp/src/afxdp/neighbor.rs:526:/// tuning failure is logged and tolerated (the monitor still works with
userspace-dp/src/afxdp/neighbor.rs:860:/// empty mask. Pinning is a tuning hint, not a correctness requirement.
userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs:47:pub(super) fn enqueue_syn_cookie_reply(
userspace-dp/src/afxdp/worker/mod.rs:1055:// (afxdp/tunnel.rs) shares the same per-tick refresh helper.
userspace-dp/src/afxdp/worker/mod.rs:1274:    /// #1873 R-C/R-E tunnel-marked drop counter (see umem/mod.rs).
userspace-dp/src/afxdp/worker/mod.rs:1275:    pub(crate) tunnel_encap_unresolved_drops: u64,
userspace-dp/src/afxdp/forwarding_build/wg.rs:2://! S2a). Builds one `Arc<WgEngine>` per `mode == "wireguard"` tunnel
userspace-dp/src/afxdp/forwarding_build/wg.rs:4://! tunnel_endpoint_id.
userspace-dp/src/afxdp/forwarding_build/wg.rs:12://! black-hole a tunnel.
userspace-dp/src/afxdp/forwarding_build/wg.rs:41:    if !state.has_wg_tunnels {
userspace-dp/src/afxdp/forwarding_build/wg.rs:44:    for (&id, endpoint) in state.tunnel_endpoints.iter() {
userspace-dp/src/afxdp/forwarding_build/wg.rs:59:                prev_state.tunnel_endpoints.get(&id),
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:7://!    `state.tunnel_interfaces`, `state.local_v[46]`,
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:75:        if iface.tunnel {
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:76:            state.tunnel_interfaces.insert(iface.ifindex);
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:81:        let tunnel_endpoint_id = state
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:82:            .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:100:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:112:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:153:            .or_else(|| iface.tunnel.then_some([0; 6]))
userspace-dp/src/afxdp/forwarding_build/tests.rs:2016:        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2034:fn wg_endpoint_hydrates_runtime_tunnel_endpoint() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2037:    assert!(state.has_wg_tunnels, "WG endpoint sets has_wg_tunnels");
userspace-dp/src/afxdp/forwarding_build/tests.rs:2038:    let ep = state.tunnel_endpoints.get(&7).expect("WG endpoint present");
userspace-dp/src/afxdp/forwarding_build/tests.rs:2054:    snap.tunnel_endpoints[0].wg_local_privkey_hex = "deadbeef".into(); // wrong length
userspace-dp/src/afxdp/forwarding_build/tests.rs:2057:        !state.tunnel_endpoints.contains_key(&7),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2060:    assert!(!state.has_wg_tunnels);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2116:    // A WG tunnel with no listen port cannot bind a socket and is
userspace-dp/src/afxdp/forwarding_build/tests.rs:2118:    // half-dead tunnel binding port 0 (Codex MAJOR).
userspace-dp/src/afxdp/forwarding_build/tests.rs:2122:        !state.tunnel_endpoints.contains_key(&7),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2125:    assert!(!state.has_wg_tunnels);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2130:// #1873 — stable-id contract: removing one tunnel preserves the OTHER
userspace-dp/src/afxdp/forwarding_build/tests.rs:2131:// tunnels' engines + remap purge-set computation.
userspace-dp/src/afxdp/forwarding_build/tests.rs:2134:fn two_tunnel_snapshot() -> ConfigSnapshot {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2136:        tunnel_endpoints: vec![
userspace-dp/src/afxdp/forwarding_build/tests.rs:2168:/// snapshot that removes one tunnel keeps the OTHER tunnel's id, so
userspace-dp/src/afxdp/forwarding_build/tests.rs:2174:fn wg_engine_survives_unrelated_tunnel_removal() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2175:    let snap = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2179:    // Remove the GRE tunnel; the WG row is byte-identical (same id —
userspace-dp/src/afxdp/forwarding_build/tests.rs:2181:    let mut snap2 = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2182:    snap2.tunnel_endpoints.retain(|ep| ep.id == 7);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2192:        "removing an unrelated tunnel must not rebuild the WG engine (#1873)"
userspace-dp/src/afxdp/forwarding_build/tests.rs:2200:fn tunnel_remap_purge_ids_owner_change_semantics() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2201:    use crate::afxdp::coordinator::tunnel_remap_purge_ids;
userspace-dp/src/afxdp/forwarding_build/tests.rs:2202:    let prev = build_forwarding_state(&two_tunnel_snapshot());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2205:    let mut snap_removed = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2206:    snap_removed.tunnel_endpoints.retain(|ep| ep.id == 7);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2208:    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2212:    let mut snap_reused = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2213:    snap_reused.tunnel_endpoints[0].interface = "gr-9/9/9.0".into();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2215:    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2218:    let mut snap_renamed = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2219:    snap_renamed.tunnel_endpoints[0].linux_name = "gre-renamed".into();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2221:    assert!(tunnel_remap_purge_ids(&prev, &next, true).is_empty());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2224:    let next = build_forwarding_state(&two_tunnel_snapshot());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2225:    assert!(tunnel_remap_purge_ids(&prev, &next, true).is_empty());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2234:fn reowned_tunnel_id_installs_immediately_with_engine_reuse() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2235:    let prev = build_forwarding_state(&two_tunnel_snapshot());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2238:    let mut snap_reused = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2239:    snap_reused.tunnel_endpoints[0].interface = "gr-9/9/9.0".into();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2246:    let ep = next.tunnel_endpoints.get(&824).expect("new owner installed");
userspace-dp/src/afxdp/forwarding_build/tests.rs:2249:    assert!(next.tunnel_endpoints.contains_key(&7));
userspace-dp/src/afxdp/forwarding_build/tests.rs:2264:fn newly_appearing_tunnel_id_is_purged_after_first_apply() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2265:    use crate::afxdp::coordinator::tunnel_remap_purge_ids;
userspace-dp/src/afxdp/forwarding_build/tests.rs:2267:    let mut snap_wg_only = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2268:    snap_wg_only.tunnel_endpoints.retain(|ep| ep.id == 7);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2270:    let next = build_forwarding_state(&two_tunnel_snapshot());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2271:    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2272:    assert!(tunnel_remap_purge_ids(&prev, &next, false).is_empty());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2276:/// tunnel resolution was created against a DIFFERENT owning netdev of
userspace-dp/src/afxdp/forwarding_build/tests.rs:2282:fn stale_session_never_adopts_reowned_tunnel_id() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2286:    let state = build_forwarding_state(&two_tunnel_snapshot());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2288:        .tunnel_endpoints
userspace-dp/src/afxdp/forwarding_build/tests.rs:2312:            tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2332:        resolved.tunnel_endpoint_id, 824,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2333:        "the gated resolution stays tunnel-marked so the R-C gate drops it"
userspace-dp/src/afxdp/forwarding_build/tests.rs:2360:/// tunnel resolution (stored egress_ifindex != the current row's
userspace-dp/src/afxdp/forwarding_build/tests.rs:2367:    let mut snap = two_tunnel_snapshot();
userspace-dp/src/afxdp/forwarding_build/tests.rs:2368:    snap.tunnel_endpoints[0].redundancy_group = 2;
userspace-dp/src/afxdp/forwarding_build/tests.rs:2371:        .tunnel_endpoints
userspace-dp/src/afxdp/forwarding_build/tests.rs:2380:        tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2398:/// the reconcile path diffs against the tunnel-owner map captured
userspace-dp/src/afxdp/forwarding_build/tests.rs:2403:fn tunnel_remap_purge_ids_from_owners_semantics() {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2404:    use crate::afxdp::coordinator::tunnel_remap_purge_ids_from_owners;
userspace-dp/src/afxdp/forwarding_build/tests.rs:2405:    let next = build_forwarding_state(&two_tunnel_snapshot());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2414:        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2421:        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2428:        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2431:    assert!(tunnel_remap_purge_ids_from_owners(&owners, &next, false).is_empty());
userspace-dp/src/afxdp/forwarding_build/tests.rs:2434:    assert!(tunnel_remap_purge_ids_from_owners(&[], &next, false).is_empty());
userspace-dp/src/afxdp/worker/lifecycle.rs:38:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/worker/lifecycle.rs:197:            local_tunnel_deliveries,
userspace-dp/src/afxdp/worker/lifecycle.rs:275:                local_tunnel_deliveries,
userspace-dp/src/afxdp/tunnel_tests.rs:1:// Tests for afxdp/tunnel.rs — relocated from inline
userspace-dp/src/afxdp/tunnel_tests.rs:2:// `#[cfg(test)] mod tests` to keep tunnel.rs under the modularity-discipline
userspace-dp/src/afxdp/tunnel_tests.rs:4:// `#[path = "tunnel_tests.rs"]` from tunnel.rs.
userspace-dp/src/afxdp/tunnel_tests.rs:20:fn prune_local_tunnel_sessions_drops_old_entries_when_threshold_exceeded() {
userspace-dp/src/afxdp/tunnel_tests.rs:32:    prune_local_tunnel_sessions(&mut sessions, &mut last_prune_ns, now_ns);
userspace-dp/src/afxdp/tunnel_tests.rs:40:fn local_tunnel_io_error_is_fatal_for_permanent_tunnel_fd_errors() {
userspace-dp/src/afxdp/tunnel_tests.rs:41:    assert!(local_tunnel_io_error_is_fatal(
userspace-dp/src/afxdp/tunnel_tests.rs:44:    assert!(local_tunnel_io_error_is_fatal(
userspace-dp/src/afxdp/tunnel_tests.rs:47:    assert!(local_tunnel_io_error_is_fatal(
userspace-dp/src/afxdp/tunnel_tests.rs:50:    assert!(local_tunnel_io_error_is_fatal(
userspace-dp/src/afxdp/tunnel_tests.rs:53:    assert!(local_tunnel_io_error_is_fatal(
userspace-dp/src/afxdp/tunnel_tests.rs:59:fn local_tunnel_io_error_is_not_fatal_for_retryable_io() {
userspace-dp/src/afxdp/tunnel_tests.rs:60:    assert!(!local_tunnel_io_error_is_fatal(&io::Error::from(
userspace-dp/src/afxdp/tunnel_tests.rs:63:    assert!(!local_tunnel_io_error_is_fatal(&io::Error::from(
userspace-dp/src/afxdp/tunnel_tests.rs:66:    assert!(!local_tunnel_io_error_is_fatal(
userspace-dp/src/afxdp/tunnel_tests.rs:166:        .tunnel_endpoints
userspace-dp/src/afxdp/tunnel_tests.rs:180:fn drain_local_tunnel_deliveries_observes_stop_under_busy_producer() {
userspace-dp/src/afxdp/tunnel_tests.rs:195:        drain_local_tunnel_deliveries(&mut sink, &rx, &stop, "gre1881drain", &recent);
userspace-dp/src/afxdp/tunnel_tests.rs:212:fn drain_local_tunnel_deliveries_drains_then_returns_when_not_stopped() {
userspace-dp/src/afxdp/tunnel_tests.rs:220:        drain_local_tunnel_deliveries(&mut sink, &rx, &stop, "gre1881drain2", &recent);
userspace-dp/src/afxdp/tunnel_tests.rs:228:fn local_tunnel_write_error_einval_is_not_fatal() {
userspace-dp/src/afxdp/tunnel_tests.rs:235:    assert!(!local_tunnel_write_error_is_fatal(&einval));
userspace-dp/src/afxdp/tunnel_tests.rs:237:        local_tunnel_io_error_is_fatal(&einval),
userspace-dp/src/afxdp/tunnel_tests.rs:243:            local_tunnel_write_error_is_fatal(&err),
userspace-dp/src/afxdp/tunnel_tests.rs:264:    let outcome = drain_local_tunnel_deliveries(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:136:                    // GRE tunnel egress).
userspace-dp/src/afxdp/poll_descriptor/mod.rs:638:                            let resolution = if should_block_tunnel_interface_nat_session_miss(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2681:                                // #1873 R-E: tunnel-marked decisions are
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2685:                                // a buffered tunnel inner packet would go out
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2691:                                // routes this frame into the R-C tunnel gate
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2717:                                    && pending_decision.resolution.tunnel_endpoint_id == 0
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2726:                                    && pending_decision.resolution.tunnel_endpoint_id == 0
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2818:                            worker_ctx.local_tunnel_deliveries,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:49:    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:658:                &local_tunnel_deliveries,
userspace-dp/src/afxdp/wg/mss.rs:32://! tunnel carrying an IPv4 inner TCP segment, accounting for the
userspace-dp/src/afxdp/bpf_map/mod.rs:11:        && decision.resolution.tunnel_endpoint_id == 0
userspace-dp/src/afxdp/wg/mod.rs:1://! Clean-room WireGuard tunnel termination for the userspace AF_XDP
userspace-dp/src/afxdp/wg/mod.rs:71:// timer decision pass (T6/T7/T8) the per-tunnel control thread runs.
userspace-dp/src/afxdp/wg/mod.rs:87:/// `forwarding_build::tunnels::decode_wg_key_hex`. PUBLIC keys only —
userspace-dp/src/afxdp/wg/session.rs:45:/// control-thread tick, single-digit tunnel counts.)
userspace-dp/src/afxdp/wg/counters.rs:3://! One `WgCounters` per `WgEngine` (== per tunnel in S2a). All fields
userspace-dp/src/afxdp/wg/counters.rs:4://! are relaxed `AtomicU64`s: increment sites are either the per-tunnel
userspace-dp/src/afxdp/wg/counters.rs:19://!     tunnel's history to this one. Prometheus `rate()` tolerates
userspace-dp/src/afxdp/wg/counters.rs:81:    /// are logical tunnel payload bytes — they will NOT match a kernel
userspace-dp/src/afxdp/wg/counters.rs:123:    /// `tun.write_all` failures delivering decap'd inner packets.
userspace-dp/src/afxdp/wg/counters.rs:124:    pub(crate) tun_write_errors: AtomicU64,
userspace-dp/src/afxdp/wg/counters.rs:127:    pub(crate) tun_rx_drops_no_endpoint: AtomicU64,
userspace-dp/src/afxdp/forwarding/tests.rs:853:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/tests.rs:1060:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/tests.rs:1109:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/tests.rs:1158:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/tests.rs:1203:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/tests.rs:1237:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/tests.rs:1526:fn tunnel_session_miss_blocks_interface_nat_local_delivery() {
userspace-dp/src/afxdp/forwarding/tests.rs:1537:    let tunnel_snat_ip = "10.255.192.42".parse().expect("tunnel snat");
userspace-dp/src/afxdp/forwarding/tests.rs:1538:    assert!(should_block_tunnel_interface_nat_session_miss(
userspace-dp/src/afxdp/forwarding/tests.rs:1540:        tunnel_snat_ip,
userspace-dp/src/afxdp/forwarding/tests.rs:1543:    assert!(should_block_tunnel_interface_nat_session_miss(
userspace-dp/src/afxdp/forwarding/tests.rs:1545:        tunnel_snat_ip,
userspace-dp/src/afxdp/forwarding/tests.rs:1548:    assert!(should_block_tunnel_interface_nat_session_miss(
userspace-dp/src/afxdp/forwarding/tests.rs:1550:        tunnel_snat_ip,
userspace-dp/src/afxdp/forwarding/mod.rs:96:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:270:    if resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:272:            .tunnel_endpoints
userspace-dp/src/afxdp/forwarding/mod.rs:273:            .get(&resolution.tunnel_endpoint_id)
userspace-dp/src/afxdp/forwarding/mod.rs:274:            // #1873 (Codex code r3): a stored tunnel resolution whose
userspace-dp/src/afxdp/forwarding/mod.rs:278:            // re-home a stale, drop-only session under the new tunnel
userspace-dp/src/afxdp/forwarding/mod.rs:361:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:728:    // the caller is responsible for checking the tunnel context.
userspace-dp/src/afxdp/forwarding/mod.rs:739:    if decision.resolution.tunnel_endpoint_id == 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:743:        .tunnel_endpoints
userspace-dp/src/afxdp/forwarding/mod.rs:744:        .get(&decision.resolution.tunnel_endpoint_id)
userspace-dp/src/afxdp/forwarding/mod.rs:781:    if decision.resolution.tunnel_endpoint_id == 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:899:                    tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:924:                    tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1019:                tunnel_endpoint_id: state
userspace-dp/src/afxdp/forwarding/mod.rs:1020:                    .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding/mod.rs:1038:                tunnel_endpoint_id: state
userspace-dp/src/afxdp/forwarding/mod.rs:1039:                    .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding/mod.rs:1142:pub(super) fn should_block_tunnel_interface_nat_session_miss(
userspace-dp/src/afxdp/forwarding/mod.rs:1150:            Some(local) if local.tunnel_endpoint_id != 0
userspace-dp/src/afxdp/forwarding/mod.rs:1183:        tunnel_endpoint_id: state
userspace-dp/src/afxdp/forwarding/mod.rs:1184:            .tunnel_endpoint_by_ifindex
userspace-dp/src/afxdp/forwarding/mod.rs:1211:    allow_tunnels: bool,
userspace-dp/src/afxdp/forwarding/mod.rs:1219:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1237:            tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1239:            if tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:1240:                return if allow_tunnels {
userspace-dp/src/afxdp/forwarding/mod.rs:1241:                    resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/forwarding/mod.rs:1244:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1261:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1272:            tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1283:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1297:                        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1310:                    allow_tunnels,
userspace-dp/src/afxdp/forwarding/mod.rs:1313:            if tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:1314:                return if allow_tunnels {
userspace-dp/src/afxdp/forwarding/mod.rs:1315:                    resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/forwarding/mod.rs:1318:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1340:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1359:    allow_tunnels: bool,
userspace-dp/src/afxdp/forwarding/mod.rs:1367:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1385:            tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1387:            if tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:1388:                return if allow_tunnels {
userspace-dp/src/afxdp/forwarding/mod.rs:1389:                    resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/forwarding/mod.rs:1392:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1409:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1420:            tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1431:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1445:                        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1458:                    allow_tunnels,
userspace-dp/src/afxdp/forwarding/mod.rs:1461:            if tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/forwarding/mod.rs:1462:                return if allow_tunnels {
userspace-dp/src/afxdp/forwarding/mod.rs:1463:                    resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/forwarding/mod.rs:1466:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1488:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1507:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/forwarding/mod.rs:1515:pub(super) fn resolve_tunnel_forwarding_resolution(
userspace-dp/src/afxdp/forwarding/mod.rs:1518:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/forwarding/mod.rs:1521:    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
userspace-dp/src/afxdp/forwarding/mod.rs:1543:        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
userspace-dp/src/afxdp/forwarding/mod.rs:1552:        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1612:        tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/forwarding/mod.rs:1616:        tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/forwarding/mod.rs:1626:        tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/forwarding/mod.rs:1630:        tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/forwarding/mod.rs:1645:                tunnel_endpoint_id: conn.tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1650:            tunnel_endpoint_id: route.tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1661:            tunnel_endpoint_id: conn.tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1675:                tunnel_endpoint_id: conn.tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1680:            tunnel_endpoint_id: route.tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding/mod.rs:1691:            tunnel_endpoint_id: conn.tunnel_endpoint_id,
userspace-dp/src/afxdp/wg/dscp.rs:9://! 6040 (ECN propagation across tunnels) is a tracked follow-up.
userspace-dp/src/afxdp/frame/wg.rs:6://! `mode == "wireguard"` tunnel endpoint id directly (a route/connected
userspace-dp/src/afxdp/frame/wg.rs:15://! only calls into the tunnel-encap branch when
userspace-dp/src/afxdp/frame/wg.rs:16://! `tunnel_endpoint_id != 0`, and a plain forward short-circuits long
userspace-dp/src/afxdp/frame/wg.rs:51:    let id = decision.resolution.tunnel_endpoint_id;
userspace-dp/src/afxdp/frame/wg.rs:52:    let endpoint = forwarding.tunnel_endpoints.get(&id)?;
userspace-dp/src/afxdp/frame/tcp.rs:204:    // fragment-aware: that helper is read by GRE decap / tunnel
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:24:    let mtu = if decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/frame/tcp_segmentation.rs:326:        if decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/wg/timers.rs:4://! pass the per-tunnel control thread runs at 1s granularity.
userspace-dp/src/afxdp/frame/inspect.rs:225:/// `packet_rel_l4_offset_and_protocol` (read by GRE decap / tunnel
userspace-dp/src/afxdp/frame/mod.rs:264:    if decision.resolution.tunnel_endpoint_id != 0 {
userspace-dp/src/afxdp/frame/mod.rs:269:            .tunnel_endpoints
userspace-dp/src/afxdp/frame/mod.rs:270:            .get(&decision.resolution.tunnel_endpoint_id)
userspace-dp/src/afxdp/frame/headers.rs:31://     tunnel packet. (Codex code-review wording fix: the
userspace-dp/src/afxdp/frame/headers.rs:34://     requires DF=1 for tunnel packets".)
userspace-dp/src/afxdp/tests.rs:96:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:120:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:222:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:285:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:608:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:650:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:840:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:1744:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:1866:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:1981:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:2113:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:2292:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:2546:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:2662:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:2692:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:2843:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:3061:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:3088:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:3248:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:3275:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:3417:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:3444:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:3587:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:3614:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:3637:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:3796:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:3823:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:3971:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:3998:        local_tunnel_deliveries: &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:4021:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4127:    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:4154:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4167:        &local_tunnel_reinjectors,
userspace-dp/src/afxdp/tests.rs:4188:    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:4214:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4228:        &local_tunnel_reinjectors,
userspace-dp/src/afxdp/tests.rs:4252:    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:4278:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4291:        &local_tunnel_reinjectors,
userspace-dp/src/afxdp/tests.rs:4337:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4346:    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:4352:        &local_tunnel_reinjectors,
userspace-dp/src/afxdp/tests.rs:4408:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4417:    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:4423:        &local_tunnel_reinjectors,
userspace-dp/src/afxdp/tests.rs:4497:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4560:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:4737:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:4745:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:4749:/// `txn_run_descriptor` with a caller-provided `local_tunnel_deliveries`
userspace-dp/src/afxdp/tests.rs:4759:    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
userspace-dp/src/afxdp/tests.rs:4814:        local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5302:// === #1873 R-C: blanket tunnel gate at the slow-path chokepoint ===
userspace-dp/src/afxdp/tests.rs:5304:fn tunnel_gate_test_fixture() -> (
userspace-dp/src/afxdp/tests.rs:5335:fn tunnel_marked_decision(disposition: ForwardingDisposition) -> SessionDecision {
userspace-dp/src/afxdp/tests.rs:5342:            tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/tests.rs:5352:/// #1873 R-C: a tunnel-marked inner packet must NEVER be enqueued to
userspace-dp/src/afxdp/tests.rs:5360:fn tunnel_marked_frame_never_reaches_slow_path() {
userspace-dp/src/afxdp/tests.rs:5369:        let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
userspace-dp/src/afxdp/tests.rs:5370:        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:5375:            &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5378:            tunnel_marked_decision(disposition),
userspace-dp/src/afxdp/tests.rs:5384:            live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
userspace-dp/src/afxdp/tests.rs:5386:            "case {i}: tunnel gate did not fire"
userspace-dp/src/afxdp/tests.rs:5397:            "tunnel_encap_unresolved",
userspace-dp/src/afxdp/tests.rs:5406:fn tunnel_marked_build_failure_drops_instead_of_slow_path() {
userspace-dp/src/afxdp/tests.rs:5407:    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
userspace-dp/src/afxdp/tests.rs:5408:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
userspace-dp/src/afxdp/tests.rs:5414:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5421:        tunnel_marked_decision(ForwardingDisposition::ForwardCandidate),
userspace-dp/src/afxdp/tests.rs:5425:    assert_eq!(live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed), 1);
userspace-dp/src/afxdp/tests.rs:5429:/// #1873 R-C: the local_tunnel_deliveries branch (GRE local-origin
userspace-dp/src/afxdp/tests.rs:5433:fn tunnel_gate_keeps_local_tunnel_delivery_open() {
userspace-dp/src/afxdp/tests.rs:5434:    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
userspace-dp/src/afxdp/tests.rs:5438:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests.rs:5439:    let mut decision = tunnel_marked_decision(ForwardingDisposition::LocalDelivery);
userspace-dp/src/afxdp/tests.rs:5445:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5453:    assert_eq!(live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed), 0);
userspace-dp/src/afxdp/tests.rs:5454:    let delivered = rx.try_recv().expect("local tunnel delivery still open");
userspace-dp/src/afxdp/tests.rs:5458:/// #1873 R-E: a tunnel-marked decision whose OUTER next-hop is
userspace-dp/src/afxdp/tests.rs:5461:/// buffered tunnel inner packet would later TX PLAINTEXT. The frame
userspace-dp/src/afxdp/tests.rs:5465:fn txn_tunnel_marked_missing_neighbor_not_buffered() {
userspace-dp/src/afxdp/tests.rs:5474:    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/afxdp/tests.rs:5496:    // No neighbors: the tunnel's OUTER destination (203.0.113.9 via the
userspace-dp/src/afxdp/tests.rs:5498:    // with tunnel_endpoint_id preserved.
userspace-dp/src/afxdp/tests.rs:5522:    // First packet: the decision is tunnel-marked ForwardCandidate; the
userspace-dp/src/afxdp/tests.rs:5527:        "tunnel-marked frame must never be admitted to pending_neigh (#1873 R-E)"
userspace-dp/src/afxdp/tests.rs:5531:        .tunnel_encap_unresolved_drops
userspace-dp/src/afxdp/tests.rs:5535:        "tunnel-marked frame must be dropped+counted at the R-C gate"
userspace-dp/src/afxdp/tests.rs:5539:    // re-resolves the stored tunnel id. Whatever door the failure
userspace-dp/src/afxdp/tests.rs:5554:        "tunnel-marked frame must skip pending_neigh admission on the session path too (#1873 R-E)"
userspace-dp/src/afxdp/tests.rs:5559:            .tunnel_encap_unresolved_drops
userspace-dp/src/afxdp/tests.rs:5570:/// `local_ifindex == 77` — the `local_tunnel_deliveries` key.
userspace-dp/src/afxdp/tests.rs:5582:        tunnel: true,
userspace-dp/src/afxdp/tests.rs:5590:    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
userspace-dp/src/afxdp/tests.rs:5696:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests.rs:5705:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5749:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests.rs:5760:            &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5799:/// tunnel channel funnels to the kernel slow-path TUN; with no
userspace-dp/src/afxdp/tests.rs:5823:    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
userspace-dp/src/afxdp/tests.rs:5832:        &local_tunnel_deliveries,
userspace-dp/src/afxdp/tests.rs:5838:        "a non-tunnel-ingress local packet must NOT hit the gr- channel"
userspace-dp/src/afxdp/tests.rs:5873:/// decision egresses a PLAIN interface (`tunnel_endpoint_id == 0`) —
userspace-dp/src/afxdp/tests.rs:5874:/// not LocalDelivery, not a tunnel-marked encap — so a cold neighbor
userspace-dp/src/afxdp/tests.rs:6136:/// preserved synced-session replay list by purged tunnel ids must
userspace-dp/src/afxdp/tests.rs:6138:/// reverse companion (tunnel_endpoint_id == 0) of a dropped forward
userspace-dp/src/afxdp/tests.rs:6158:    let tunnel_resolution = ForwardingResolution {
userspace-dp/src/afxdp/tests.rs:6163:        tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/tests.rs:6170:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tests.rs:6171:        ..tunnel_resolution
userspace-dp/src/afxdp/tests.rs:6195:    // Case 1: tunnel-marked forward + unmarked derived reverse
userspace-dp/src/afxdp/tests.rs:6198:        make(&forward_key, tunnel_resolution, false),
userspace-dp/src/afxdp/tests.rs:6206:    // Case 2: reverse-marked tunnel entry drops standalone; its
userspace-dp/src/afxdp/tests.rs:6212:        make(&reverse_key, tunnel_resolution, true),
userspace-dp/src/afxdp/tests.rs:6219:    let mut entries = vec![make(&forward_key, tunnel_resolution, false)];
userspace-dp/src/afxdp/wg/tests.rs:1164:fn tunnel_endpoint_snapshot_private_key_is_skipped_and_redacted() {
userspace-dp/src/afxdp/frame/prop_tests/segment.rs:53:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/build/ipv4.rs:6://! memcpy, ip_start, tunnel_tcp_mss, apply_nat) and dispatches here.
userspace-dp/src/afxdp/frame/build/ipv4.rs:24:    tunnel_tcp_mss: u16,
userspace-dp/src/afxdp/frame/build/ipv4.rs:25:    force_tunnel_l4_recompute: bool,
userspace-dp/src/afxdp/frame/build/ipv4.rs:86:    if tunnel_tcp_mss > 0 {
userspace-dp/src/afxdp/frame/build/ipv4.rs:87:        let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
userspace-dp/src/afxdp/frame/build/ipv4.rs:91:    // tunnel-egress recompute (tunnel_endpoint_id != 0) would otherwise
userspace-dp/src/afxdp/frame/build/ipv4.rs:94:    // restore is gated — so only the forced-tunnel term can fire.)
userspace-dp/src/afxdp/frame/build/ipv4.rs:95:    if !non_first_fragment && (force_tunnel_l4_recompute || (repaired_ports && !enforced)) {
userspace-dp/src/afxdp/frame/build/ipv6.rs:6://! memcpy, ip_start, tunnel_tcp_mss, apply_nat) and dispatches here.
userspace-dp/src/afxdp/frame/build/ipv6.rs:23:    tunnel_tcp_mss: u16,
userspace-dp/src/afxdp/frame/build/ipv6.rs:24:    force_tunnel_l4_recompute: bool,
userspace-dp/src/afxdp/frame/build/ipv6.rs:69:    if tunnel_tcp_mss > 0 {
userspace-dp/src/afxdp/frame/build/ipv6.rs:70:        let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
userspace-dp/src/afxdp/frame/build/ipv6.rs:74:    // forced tunnel-egress recompute would otherwise re-corrupt the bytes
userspace-dp/src/afxdp/frame/build/ipv6.rs:76:    if !non_first_fragment && (force_tunnel_l4_recompute || (repaired_ports && !enforced)) {
userspace-dp/src/afxdp/frame/build/mod.rs:4://! resolution of `apply_nat` / `tunnel_tcp_mss` / `force_tunnel_l4_recompute`)
userspace-dp/src/afxdp/frame/build/mod.rs:89:    let force_tunnel_l4_recompute = decision.resolution.tunnel_endpoint_id != 0;
userspace-dp/src/afxdp/frame/build/mod.rs:90:    let tunnel_tcp_mss = native_gre_tcp_mss(forwarding, decision, meta.addr_family);
userspace-dp/src/afxdp/frame/build/mod.rs:100:            tunnel_tcp_mss,
userspace-dp/src/afxdp/frame/build/mod.rs:101:            force_tunnel_l4_recompute,
userspace-dp/src/afxdp/frame/build/mod.rs:110:            tunnel_tcp_mss,
userspace-dp/src/afxdp/frame/build/mod.rs:111:            force_tunnel_l4_recompute,
userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs:156:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:418:fn tunnel_route_resolves_to_logical_tunnel_and_physical_tx() {
userspace-dp/src/afxdp/frame/tests.rs:434:    assert_eq!(resolved.tunnel_endpoint_id, 1);
userspace-dp/src/afxdp/frame/tests.rs:448:fn tunnel_route_preserves_logical_egress_on_outer_neighbor_miss() {
userspace-dp/src/afxdp/frame/tests.rs:461:    assert_eq!(resolved.tunnel_endpoint_id, 1);
userspace-dp/src/afxdp/frame/tests.rs:520:    assert_eq!(resolved.tunnel_endpoint_id, 1);
userspace-dp/src/afxdp/frame/tests.rs:526:    let egress = state.egress.get(&362).expect("logical tunnel egress");
userspace-dp/src/afxdp/frame/tests.rs:539:    assert_eq!(resolved.tunnel_endpoint_id, 1);
userspace-dp/src/afxdp/frame/tests.rs:544:fn native_gre_decap_maps_inner_packet_to_logical_tunnel_ingress() {
userspace-dp/src/afxdp/frame/tests.rs:629:fn local_origin_tunnel_tx_request_encapsulates_raw_ip_for_active_owner() {
userspace-dp/src/afxdp/frame/tests.rs:643:    let plan = build_local_origin_tunnel_tx_request(
userspace-dp/src/afxdp/frame/tests.rs:650:    .expect("local-origin tunnel tx request");
userspace-dp/src/afxdp/frame/tests.rs:662:fn local_origin_tunnel_tx_request_rejects_inactive_owner() {
userspace-dp/src/afxdp/frame/tests.rs:674:    let err = build_local_origin_tunnel_tx_request(
userspace-dp/src/afxdp/frame/tests.rs:681:    .expect_err("inactive owner should not originate tunnel traffic");
userspace-dp/src/afxdp/frame/tests.rs:1382:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:1444:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:1486:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:1725:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:1899:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:1983:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2071:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2164:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2267:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2410:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2519:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2634:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2730:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:2874:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3036:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3114:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3195:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3278:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3376:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3494:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3598:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:3705:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4035:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4276:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4351:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4418:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4492:                tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4619:                    tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4721:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4809:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4901:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:4987:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:5083:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:5168:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/frame/tests.rs:5502:fn build_tunnel_egress_non_first_fragment_skips_forced_l4_recompute() {
userspace-dp/src/afxdp/frame/tests.rs:5503:    // #1852 (Codex impl review): the copy builder's forced tunnel L4
userspace-dp/src/afxdp/frame/tests.rs:5504:    // recompute (tunnel_endpoint_id != 0 -> force_tunnel_l4_recompute)
userspace-dp/src/afxdp/frame/tests.rs:5550:            tunnel_endpoint_id: 7, // tunnel egress -> force_tunnel_l4_recompute
userspace-dp/src/afxdp/frame/tests.rs:5574:        "forced tunnel L4 recompute must not touch non-first fragment payload"
userspace-dp/src/afxdp/frame/tests.rs:5585:fn local_origin_tunnel_tx_request_follows_supplied_state_destination() {
userspace-dp/src/afxdp/frame/tests.rs:5588:    snapshot_new.tunnel_endpoints[0].destination = "2602:ffd3:0:2::9".to_string();
userspace-dp/src/afxdp/frame/tests.rs:5602:        build_local_origin_tunnel_tx_request(&packet[14..], 1, &state_old, &ha_state, &dynamic_neighbors)
userspace-dp/src/afxdp/frame/tests.rs:5606:        build_local_origin_tunnel_tx_request(&packet[14..], 1, &state_new, &ha_state, &dynamic_neighbors)

exec
/bin/bash -lc 'rg -n "pub struct SlowPathReinjector|impl SlowPathReinjector|fn enqueue" -S .' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
./docs/userspace-capture-plan.md:221:    fn enqueue(&mut self, point: CapturePoint, ifindex: i32, frame: &[u8]) {
./userspace-dp/src/afxdp/neighbor_resolver.rs:263:    pub(crate) fn enqueue(&self, ifindex: i32, hop: IpAddr, iface_name: String) {
./userspace-dp/src/afxdp/neighbor_resolver.rs:926:    fn enqueue_full_queue_counts_drop_not_block() {
./userspace-dp/src/afxdp/neighbor_resolver.rs:947:    fn enqueue_snapshots_current_epoch() {
./userspace-dp/src/afxdp/neighbor_resolver.rs:973:    fn enqueue_disconnected_counts_disconnected() {
./userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs:47:pub(super) fn enqueue_syn_cookie_reply(
./userspace-dp/src/afxdp/umem/mod.rs:651:    pub(in crate::afxdp) fn enqueue_owned(mut self, req: TxRequest) -> Result<(), TxRequest> {
./userspace-dp/src/afxdp/umem/mod.rs:977:    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
./userspace-dp/src/afxdp/umem/mod.rs:982:    pub(super) fn enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
./userspace-dp/src/afxdp/umem/tests.rs:35:fn enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer() {
./userspace-dp/src/afxdp/umem/tests.rs:109:fn enqueue_tx_owned_below_cap_does_not_touch_overflow_counter() {
./userspace-dp/src/slowpath.rs:166:pub struct SlowPathReinjector {
./userspace-dp/src/slowpath.rs:172:impl SlowPathReinjector {
./userspace-dp/src/slowpath.rs:192:    pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
./userspace-dp/src/afxdp/mirror.rs:61:pub(in crate::afxdp) fn enqueue_mirror_clone(
./userspace-dp/src/afxdp/mirror.rs:102:pub(in crate::afxdp) fn enqueue_sampled_mirror_clone(
./userspace-dp/src/afxdp/mirror.rs:172:fn enqueue_mirror_clone_to_binding(
./userspace-dp/src/afxdp/mirror.rs:251:pub(in crate::afxdp) fn enqueue_mirror_clone_to_live(
./userspace-dp/src/afxdp/mirror.rs:296:pub(in crate::afxdp) fn enqueue_admitted_mirror_clone_to_live(
./userspace-dp/src/afxdp/mirror.rs:326:pub(in crate::afxdp) fn enqueue_sampled_mirror_clone_to_live(
./userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:509:fn enqueue_pending_forwards_mirrors_live_frame_and_records_counter() {
./userspace-dp/src/afxdp/tx/dispatch/cos.rs:80:pub(super) fn enqueue_local_request_to_target_or_owner(
./userspace-dp/src/afxdp/tx/dispatch/mod.rs:74:pub(in crate::afxdp) fn enqueue_pending_forwards(
./userspace-dp/src/afxdp/tx/cos_classify_tests.rs:42:fn enqueue_exact_queue_publishes_shared_backlog_slot() {
./userspace-dp/src/afxdp/tx/cos_classify_tests.rs:2398:fn enqueue_cos_item_stamps_enqueue_ns_at_admission() {
./userspace-dp/src/afxdp/tx/cos_classify.rs:435:pub(in crate::afxdp) fn enqueue_local_into_cos(
./userspace-dp/src/afxdp/tx/cos_classify.rs:575:pub(super) fn enqueue_prepared_into_cos(
./userspace-dp/src/afxdp/tx/cos_classify.rs:815:fn enqueue_cos_item(
./docs/pr/1697-poll-descriptor-cold-path-split/plan.md:257:   - `fn enqueue_syn_cookie_reply` — `#[cold] #[inline(never)]`

codex
The helper’s telemetry also supports the plan’s invisibility claim: only LocalDelivery/MissingNeighbor/NoRoute/NextTableUnsupported get disposition-specific slow-path counters; everything else falls into `_ => {}`. I’m checking the reinjector implementation now only to anchor the “enqueue writes to TUN” part.
exec
/bin/bash -lc "nl -ba userspace-dp/src/slowpath.rs | sed -n '160,275p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   160	            queue_full_packets: self.queue_full_packets.load(Ordering::Relaxed),
   161	            write_errors: self.write_errors.load(Ordering::Relaxed),
   162	        }
   163	    }
   164	}
   165	
   166	pub struct SlowPathReinjector {
   167	    tx: SyncSender<PacketRequest>,
   168	    limiter: Mutex<RateLimiter>,
   169	    status: Arc<SharedStatus>,
   170	}
   171	
   172	impl SlowPathReinjector {
   173	    pub fn new(name: &str) -> Result<Self, String> {
   174	        let status = Arc::new(SharedStatus::new());
   175	        let (tx, rx) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
   176	        let thread_status = status.clone();
   177	        let name = name.to_string();
   178	        thread::Builder::new()
   179	            .name("xpf-slowpath".to_string())
   180	            .spawn(move || slow_path_worker(&name, rx, thread_status))
   181	            .map_err(|e| format!("spawn slow-path worker: {e}"))?;
   182	        Ok(Self {
   183	            tx,
   184	            limiter: Mutex::new(RateLimiter::new(
   185	                DEFAULT_RATE_LIMIT_PACKETS_PER_SEC,
   186	                DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
   187	            )),
   188	            status,
   189	        })
   190	    }
   191	
   192	    pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
   193	        let packet_len = bytes.len() as u64;
   194	        let allowed = self
   195	            .limiter
   196	            .lock()
   197	            .map_err(|_| "slow-path limiter lock poisoned".to_string())?
   198	            .allow(bytes.len());
   199	        if !allowed {
   200	            self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
   201	            self.status
   202	                .dropped_bytes
   203	                .fetch_add(packet_len, Ordering::Relaxed);
   204	            self.status
   205	                .rate_limited_packets
   206	                .fetch_add(1, Ordering::Relaxed);
   207	            return Ok(EnqueueOutcome::RateLimited);
   208	        }
   209	        self.status.queued_packets.fetch_add(1, Ordering::Relaxed);
   210	        match self.tx.try_send(PacketRequest { bytes }) {
   211	            Ok(()) => Ok(EnqueueOutcome::Accepted),
   212	            Err(TrySendError::Full(req)) => {
   213	                self.status.queued_packets.fetch_sub(1, Ordering::Relaxed);
   214	                self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
   215	                self.status
   216	                    .dropped_bytes
   217	                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
   218	                self.status
   219	                    .queue_full_packets
   220	                    .fetch_add(1, Ordering::Relaxed);
   221	                Ok(EnqueueOutcome::QueueFull)
   222	            }
   223	            Err(TrySendError::Disconnected(req)) => {
   224	                self.status.queued_packets.fetch_sub(1, Ordering::Relaxed);
   225	                self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
   226	                self.status
   227	                    .dropped_bytes
   228	                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
   229	                let err = "slow-path worker is not running".to_string();
   230	                self.status.set_last_error(err.clone());
   231	                Err(err)
   232	            }
   233	        }
   234	    }
   235	
   236	    pub fn status(&self) -> SlowPathStatus {
   237	        self.status.snapshot()
   238	    }
   239	}
   240	
   241	fn slow_path_worker(name: &str, rx: Receiver<PacketRequest>, status: Arc<SharedStatus>) {
   242	    let (tun, actual_name) = match open_tun(name) {
   243	        Ok(v) => v,
   244	        Err(err) => {
   245	            status.set_last_error(err);
   246	            status.active.store(false, Ordering::Relaxed);
   247	            return;
   248	        }
   249	    };
   250	    status.set_device_name(&actual_name);
   251	    status.active.store(true, Ordering::Relaxed);
   252	
   253	    let mut mode = match IoUring::new(256) {
   254	        Ok(ring) => {
   255	            status.set_mode("io_uring");
   256	            WriteMode::IoUring(ring)
   257	        }
   258	        Err(err) => {
   259	            status.set_mode("sync");
   260	            status.set_last_error(format!("slow-path io_uring unavailable: {err}"));
   261	            WriteMode::SyncFallback
   262	        }
   263	    };
   264	
   265	    while let Ok(req) = rx.recv() {
   266	        status.queued_packets.fetch_sub(1, Ordering::Relaxed);
   267	        let result = match &mut mode {
   268	            WriteMode::IoUring(ring) => write_packet_io_uring(ring, tun.as_raw_fd(), &req.bytes)
   269	                .or_else(|_| write_packet_sync(tun.as_raw_fd(), &req.bytes)),
   270	            WriteMode::SyncFallback => write_packet_sync(tun.as_raw_fd(), &req.bytes),
   271	        };
   272	        match result {
   273	            Ok(()) => {
   274	                status.injected_packets.fetch_add(1, Ordering::Relaxed);
   275	                status

exec
/bin/bash -lc "nl -ba userspace-dp/src/slowpath.rs | sed -n '30,60p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
    30	    pub dropped_packets: u64,
    31	    pub dropped_bytes: u64,
    32	    pub rate_limited_packets: u64,
    33	    pub queue_full_packets: u64,
    34	    pub write_errors: u64,
    35	}
    36	
    37	pub enum EnqueueOutcome {
    38	    Accepted,
    39	    RateLimited,
    40	    QueueFull,
    41	}
    42	
    43	struct PacketRequest {
    44	    bytes: Vec<u8>,
    45	}
    46	
    47	struct RateLimiter {
    48	    window_started: Instant,
    49	    packets: u64,
    50	    bytes: u64,
    51	    max_packets_per_sec: u64,
    52	    max_bytes_per_sec: u64,
    53	}
    54	
    55	impl RateLimiter {
    56	    fn new(max_packets_per_sec: u64, max_bytes_per_sec: u64) -> Self {
    57	        Self {
    58	            window_started: Instant::now(),
    59	            packets: 0,
    60	            bytes: 0,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tests.rs | sed -n '4140,4310p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  4140	        version: USERSPACE_META_VERSION,
  4141	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  4142	        l3_offset: 14,
  4143	        l4_offset: 34,
  4144	        addr_family: libc::AF_INET as u8,
  4145	        protocol: PROTO_ICMP,
  4146	        ..UserspaceDpMeta::default()
  4147	    };
  4148	    let decision = SessionDecision {
  4149	        resolution: ForwardingResolution {
  4150	            disposition: ForwardingDisposition::ForwardCandidate,
  4151	            local_ifindex: 0,
  4152	            egress_ifindex: 6,
  4153	            tx_ifindex: 6,
  4154	            tunnel_endpoint_id: 0,
  4155	            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
  4156	            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
  4157	            src_mac: Some([6, 7, 8, 9, 10, 11]),
  4158	            tx_vlan_id: 0,
  4159	        },
  4160	        nat: NatDecision::default(),
  4161	    };
  4162	
  4163	    maybe_reinject_slow_path(
  4164	        &binding,
  4165	        &live,
  4166	        None,
  4167	        &local_tunnel_reinjectors,
  4168	        &area,
  4169	        XdpDesc {
  4170	            addr: 0,
  4171	            len: frame.len() as u32,
  4172	            options: 0,
  4173	        },
  4174	        meta,
  4175	        decision,
  4176	        &recent_exceptions,
  4177	        &ForwardingState::default(),
  4178	    );
  4179	
  4180	    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
  4181	    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
  4182	    assert!(recent_exceptions.lock().expect("exceptions").is_empty());
  4183	}
  4184	
  4185	#[test]
  4186	fn maybe_reinject_slow_path_records_extract_failure_for_invalid_desc() {
  4187	    let area = MmapArea::new(128).expect("mmap");
  4188	    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  4189	    let binding = BindingIdentity {
  4190	        slot: 3,
  4191	        queue_id: 2,
  4192	        worker_id: 1,
  4193	        interface: Arc::<str>::from("ge-0-0-1"),
  4194	        ifindex: 5,
  4195	    };
  4196	    let live = BindingLiveState::new();
  4197	    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
  4198	    let meta = UserspaceDpMeta {
  4199	        magic: USERSPACE_META_MAGIC,
  4200	        version: USERSPACE_META_VERSION,
  4201	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  4202	        l3_offset: 14,
  4203	        l4_offset: 34,
  4204	        addr_family: libc::AF_INET as u8,
  4205	        protocol: PROTO_ICMP,
  4206	        ..UserspaceDpMeta::default()
  4207	    };
  4208	    let decision = SessionDecision {
  4209	        resolution: ForwardingResolution {
  4210	            disposition: ForwardingDisposition::NoRoute,
  4211	            local_ifindex: 0,
  4212	            egress_ifindex: 0,
  4213	            tx_ifindex: 0,
  4214	            tunnel_endpoint_id: 0,
  4215	            next_hop: None,
  4216	            neighbor_mac: None,
  4217	            src_mac: None,
  4218	            tx_vlan_id: 0,
  4219	        },
  4220	        nat: NatDecision::default(),
  4221	    };
  4222	
  4223	    // Addr beyond the registered UMEM length forces an extract failure.
  4224	    maybe_reinject_slow_path(
  4225	        &binding,
  4226	        &live,
  4227	        None,
  4228	        &local_tunnel_reinjectors,
  4229	        &area,
  4230	        XdpDesc {
  4231	            addr: 512,
  4232	            len: 96,
  4233	            options: 0,
  4234	        },
  4235	        meta,
  4236	        decision,
  4237	        &recent_exceptions,
  4238	        &ForwardingState::default(),
  4239	    );
  4240	
  4241	    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
  4242	    let exceptions = recent_exceptions.lock().expect("exceptions");
  4243	    let last = exceptions.back().expect("exception recorded");
  4244	    assert_eq!(last.reason, "slow_path_extract_failed");
  4245	    assert_eq!(last.packet_length, 96);
  4246	}
  4247	
  4248	#[test]
  4249	fn maybe_reinject_slow_path_from_frame_records_unavailable() {
  4250	    let frame =
  4251	        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
  4252	    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  4253	    let binding = BindingIdentity {
  4254	        slot: 7,
  4255	        queue_id: 0,
  4256	        worker_id: 0,
  4257	        interface: Arc::<str>::from("ge-0-0-2"),
  4258	        ifindex: 6,
  4259	    };
  4260	    let live = BindingLiveState::new();
  4261	    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
  4262	    let meta = UserspaceDpMeta {
  4263	        magic: USERSPACE_META_MAGIC,
  4264	        version: USERSPACE_META_VERSION,
  4265	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  4266	        l3_offset: 14,
  4267	        l4_offset: 34,
  4268	        addr_family: libc::AF_INET as u8,
  4269	        protocol: PROTO_ICMP,
  4270	        ..UserspaceDpMeta::default()
  4271	    };
  4272	    let decision = SessionDecision {
  4273	        resolution: ForwardingResolution {
  4274	            disposition: ForwardingDisposition::NoRoute,
  4275	            local_ifindex: 0,
  4276	            egress_ifindex: 0,
  4277	            tx_ifindex: 0,
  4278	            tunnel_endpoint_id: 0,
  4279	            next_hop: None,
  4280	            neighbor_mac: None,
  4281	            src_mac: None,
  4282	            tx_vlan_id: 0,
  4283	        },
  4284	        nat: NatDecision::default(),
  4285	    };
  4286	
  4287	    maybe_reinject_slow_path_from_frame(
  4288	        &binding,
  4289	        &live,
  4290	        None,
  4291	        &local_tunnel_reinjectors,
  4292	        &frame,
  4293	        meta,
  4294	        decision,
  4295	        &recent_exceptions,
  4296	        "forward_build_slow_path",
  4297	        &ForwardingState::default(),
  4298	    );
  4299	
  4300	    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
  4301	    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
  4302	    let exceptions = recent_exceptions.lock().expect("exceptions");
  4303	    let last = exceptions.back().expect("exception recorded");
  4304	    assert_eq!(last.reason, "slow_path_unavailable");
  4305	    assert_eq!(last.ifindex, 6);
  4306	}
  4307	
  4308	#[test]
  4309	fn handle_forward_build_failure_records_build_and_slow_path_failures() {
  4310	    let frame =

exec
/bin/bash -lc "nl -ba userspace-dp/src/slowpath.rs | sed -n '275,375p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   275	                status
   276	                    .injected_bytes
   277	                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
   278	            }
   279	            Err(err) => {
   280	                status.write_errors.fetch_add(1, Ordering::Relaxed);
   281	                status.dropped_packets.fetch_add(1, Ordering::Relaxed);
   282	                status
   283	                    .dropped_bytes
   284	                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
   285	                status.set_last_error(err);
   286	            }
   287	        }
   288	    }
   289	    status.active.store(false, Ordering::Relaxed);
   290	}
   291	
   292	fn write_packet_sync(fd: i32, bytes: &[u8]) -> Result<(), String> {
   293	    let mut written = 0usize;
   294	    while written < bytes.len() {
   295	        let rc = unsafe {
   296	            libc::write(
   297	                fd,
   298	                bytes.as_ptr().add(written).cast::<libc::c_void>(),
   299	                bytes.len() - written,
   300	            )
   301	        };
   302	        if rc < 0 {
   303	            return Err(format!("slow-path write: {}", io::Error::last_os_error()));
   304	        }
   305	        if rc == 0 {
   306	            return Err("slow-path write returned 0".to_string());
   307	        }
   308	        written += rc as usize;
   309	    }
   310	    Ok(())
   311	}
   312	
   313	fn write_packet_io_uring(ring: &mut IoUring, fd: i32, bytes: &[u8]) -> Result<(), String> {
   314	    let mut offset = 0usize;
   315	    while offset < bytes.len() {
   316	        let entry = opcode::Write::new(
   317	            types::Fd(fd),
   318	            unsafe { bytes.as_ptr().add(offset) },
   319	            (bytes.len() - offset) as _,
   320	        )
   321	        .build()
   322	        .user_data(1);
   323	        unsafe {
   324	            ring.submission()
   325	                .push(&entry)
   326	                .map_err(|_| "slow-path submit queue full".to_string())?;
   327	        }
   328	        ring.submit_and_wait(1)
   329	            .map_err(|e| format!("submit slow-path write: {e}"))?;
   330	        let mut completion = ring.completion();
   331	        let cqe = completion
   332	            .next()
   333	            .ok_or_else(|| "missing slow-path completion".to_string())?;
   334	        let res = cqe.result();
   335	        if res < 0 {
   336	            return Err(format!(
   337	                "slow-path io_uring write failed: {}",
   338	                io::Error::from_raw_os_error(-res)
   339	            ));
   340	        }
   341	        if res == 0 {
   342	            return Err("slow-path io_uring short write: 0".to_string());
   343	        }
   344	        offset += res as usize;
   345	    }
   346	    Ok(())
   347	}
   348	
   349	pub(crate) fn open_tun(name: &str) -> Result<(std::fs::File, String), String> {
   350	    let tun = OpenOptions::new()
   351	        .read(true)
   352	        .write(true)
   353	        .open("/dev/net/tun")
   354	        .map_err(|e| format!("open /dev/net/tun: {e}"))?;
   355	    let mut ifr = IfReq::new(name, IFF_TUN | IFF_NO_PI)?;
   356	    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &mut ifr) };
   357	    if rc < 0 {
   358	        return Err(format!(
   359	            "TUNSETIFF {}: {}",
   360	            name,
   361	            io::Error::last_os_error()
   362	        ));
   363	    }
   364	    let actual_name = ifr.name_string();
   365	    set_if_up(&actual_name)?;
   366	    // Slow-path injected IPv4 replies arrive on the TUN device, but their
   367	    // reverse route still points at the real egress interface. Disable
   368	    // per-device rp_filter so the kernel accepts those packets.
   369	    set_ipv4_sysctl(&actual_name, "rp_filter", "0")?;
   370	    Ok((tun, actual_name))
   371	}
   372	
   373	fn set_if_up(name: &str) -> Result<(), String> {
   374	    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
   375	    if sock < 0 {

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tests.rs | sed -n '4480,4515p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  4480	        ifindex: 3,
  4481	    };
  4482	    let mut counters = BatchCounters::default();
  4483	
  4484	    // Before any calls: live counter must be 0, batch must be clean.
  4485	    assert_eq!(live.policy_denied_packets.load(Ordering::Relaxed), 0);
  4486	    assert!(!counters.touched);
  4487	
  4488	    // Hot call — should land in batch, not in live.
  4489	    record_forwarding_disposition(
  4490	        &binding,
  4491	        DispositionCounters::Hot(&mut counters),
  4492	        ForwardingResolution {
  4493	            disposition: ForwardingDisposition::PolicyDenied,
  4494	            local_ifindex: 0,
  4495	            egress_ifindex: 0,
  4496	            tx_ifindex: 0,
  4497	            tunnel_endpoint_id: 0,
  4498	            next_hop: None,
  4499	            neighbor_mac: None,
  4500	            src_mac: None,
  4501	            tx_vlan_id: 0,
  4502	        },
  4503	        64,
  4504	        None,
  4505	        None,
  4506	        &recent_exceptions,
  4507	        &Arc::new(Mutex::new(None)),
  4508	        &ForwardingState::default(),
  4509	    );
  4510	
  4511	    assert_eq!(
  4512	        counters.policy_denied_packets, 1,
  4513	        "batch should hold the count"
  4514	    );
  4515	    assert_eq!(

codex
One important nuance for the verdict: `ForwardCandidate` can only reach the tail via the `_` arm if control is already in the non-forward `else`, which is structurally excluded by the earlier `matches!(ForwardCandidate | FabricRedirect)` branch. I’ll call that out as an over-broad table row rather than a functional blocker.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tests.rs | sed -n '4310,4435p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  4310	    let frame =
  4311	        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
  4312	    let binding = BindingIdentity {
  4313	        slot: 7,
  4314	        queue_id: 0,
  4315	        worker_id: 0,
  4316	        interface: Arc::<str>::from("ge-0-0-2"),
  4317	        ifindex: 6,
  4318	    };
  4319	    let live = BindingLiveState::new();
  4320	    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
  4321	    let meta = UserspaceDpMeta {
  4322	        magic: USERSPACE_META_MAGIC,
  4323	        version: USERSPACE_META_VERSION,
  4324	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  4325	        l3_offset: 14,
  4326	        l4_offset: 34,
  4327	        addr_family: libc::AF_INET as u8,
  4328	        protocol: PROTO_ICMP,
  4329	        ..UserspaceDpMeta::default()
  4330	    };
  4331	    let decision = SessionDecision {
  4332	        resolution: ForwardingResolution {
  4333	            disposition: ForwardingDisposition::NoRoute,
  4334	            local_ifindex: 0,
  4335	            egress_ifindex: 0,
  4336	            tx_ifindex: 0,
  4337	            tunnel_endpoint_id: 0,
  4338	            next_hop: None,
  4339	            neighbor_mac: None,
  4340	            src_mac: None,
  4341	            tx_vlan_id: 0,
  4342	        },
  4343	        nat: NatDecision::default(),
  4344	    };
  4345	    let mut dbg = DebugPollCounters::default();
  4346	    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  4347	
  4348	    handle_forward_build_failure(
  4349	        &binding,
  4350	        &live,
  4351	        None,
  4352	        &local_tunnel_reinjectors,
  4353	        &recent_exceptions,
  4354	        &mut dbg,
  4355	        6,
  4356	        frame.len() as u32,
  4357	        &frame,
  4358	        meta,
  4359	        decision,
  4360	        true,
  4361	        &ForwardingState::default(),
  4362	    );
  4363	
  4364	    assert_eq!(dbg.build_fail, 1);
  4365	    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
  4366	    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
  4367	    let reasons: Vec<String> = recent_exceptions
  4368	        .lock()
  4369	        .expect("exceptions")
  4370	        .iter()
  4371	        .map(|entry| entry.reason.clone())
  4372	        .collect();
  4373	    assert_eq!(
  4374	        reasons,
  4375	        vec!["forward_build_failed", "slow_path_unavailable"]
  4376	    );
  4377	}
  4378	
  4379	#[test]
  4380	fn handle_forward_build_failure_without_fallback_only_records_build_failure() {
  4381	    let frame =
  4382	        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
  4383	    let binding = BindingIdentity {
  4384	        slot: 7,
  4385	        queue_id: 0,
  4386	        worker_id: 0,
  4387	        interface: Arc::<str>::from("ge-0-0-2"),
  4388	        ifindex: 6,
  4389	    };
  4390	    let live = BindingLiveState::new();
  4391	    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
  4392	    let meta = UserspaceDpMeta {
  4393	        magic: USERSPACE_META_MAGIC,
  4394	        version: USERSPACE_META_VERSION,
  4395	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  4396	        l3_offset: 14,
  4397	        l4_offset: 34,
  4398	        addr_family: libc::AF_INET as u8,
  4399	        protocol: PROTO_ICMP,
  4400	        ..UserspaceDpMeta::default()
  4401	    };
  4402	    let decision = SessionDecision {
  4403	        resolution: ForwardingResolution {
  4404	            disposition: ForwardingDisposition::ForwardCandidate,
  4405	            local_ifindex: 0,
  4406	            egress_ifindex: 12,
  4407	            tx_ifindex: 12,
  4408	            tunnel_endpoint_id: 0,
  4409	            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
  4410	            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
  4411	            src_mac: Some([6, 7, 8, 9, 10, 11]),
  4412	            tx_vlan_id: 0,
  4413	        },
  4414	        nat: NatDecision::default(),
  4415	    };
  4416	    let mut dbg = DebugPollCounters::default();
  4417	    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  4418	
  4419	    handle_forward_build_failure(
  4420	        &binding,
  4421	        &live,
  4422	        None,
  4423	        &local_tunnel_reinjectors,
  4424	        &recent_exceptions,
  4425	        &mut dbg,
  4426	        12,
  4427	        frame.len() as u32,
  4428	        &frame,
  4429	        meta,
  4430	        decision,
  4431	        false,
  4432	        &ForwardingState::default(),
  4433	    );
  4434	
  4435	    assert_eq!(dbg.build_fail, 1);

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tests.rs | sed -n '4100,4185p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  4100	    assert!(binding.scratch.scratch_forwards.is_empty());
  4101	    assert_eq!(sessions.len(), 0);
  4102	    assert!(shared_sessions.lock().expect("shared sessions").is_empty());
  4103	    assert!(shared_nat_sessions.lock().expect("shared nat").is_empty());
  4104	    assert!(
  4105	        shared_forward_wire_sessions
  4106	            .lock()
  4107	            .expect("shared forward wire")
  4108	            .is_empty()
  4109	    );
  4110	    let deltas = sessions.drain_deltas(16);
  4111	    assert_eq!(deltas.len(), 1);
  4112	    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
  4113	    assert_eq!(deltas[0].key, flow_key);
  4114	    assert_eq!(binding.live.slow_path_drops.load(Ordering::Relaxed), 0);
  4115	    assert!(recent_exceptions.lock().unwrap().is_empty());
  4116	    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
  4117	}
  4118	
  4119	#[test]
  4120	fn maybe_reinject_slow_path_ignores_forward_candidate_disposition() {
  4121	    let frame =
  4122	        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
  4123	    let mut area = MmapArea::new(4096).expect("mmap");
  4124	    area.slice_mut(0, frame.len())
  4125	        .expect("slice")
  4126	        .copy_from_slice(&frame);
  4127	    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  4128	
  4129	    let binding = BindingIdentity {
  4130	        slot: 3,
  4131	        queue_id: 2,
  4132	        worker_id: 1,
  4133	        interface: Arc::<str>::from("ge-0-0-1"),
  4134	        ifindex: 5,
  4135	    };
  4136	    let live = BindingLiveState::new();
  4137	    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
  4138	    let meta = UserspaceDpMeta {
  4139	        magic: USERSPACE_META_MAGIC,
  4140	        version: USERSPACE_META_VERSION,
  4141	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  4142	        l3_offset: 14,
  4143	        l4_offset: 34,
  4144	        addr_family: libc::AF_INET as u8,
  4145	        protocol: PROTO_ICMP,
  4146	        ..UserspaceDpMeta::default()
  4147	    };
  4148	    let decision = SessionDecision {
  4149	        resolution: ForwardingResolution {
  4150	            disposition: ForwardingDisposition::ForwardCandidate,
  4151	            local_ifindex: 0,
  4152	            egress_ifindex: 6,
  4153	            tx_ifindex: 6,
  4154	            tunnel_endpoint_id: 0,
  4155	            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
  4156	            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
  4157	            src_mac: Some([6, 7, 8, 9, 10, 11]),
  4158	            tx_vlan_id: 0,
  4159	        },
  4160	        nat: NatDecision::default(),
  4161	    };
  4162	
  4163	    maybe_reinject_slow_path(
  4164	        &binding,
  4165	        &live,
  4166	        None,
  4167	        &local_tunnel_reinjectors,
  4168	        &area,
  4169	        XdpDesc {
  4170	            addr: 0,
  4171	            len: frame.len() as u32,
  4172	            options: 0,
  4173	        },
  4174	        meta,
  4175	        decision,
  4176	        &recent_exceptions,
  4177	        &ForwardingState::default(),
  4178	    );
  4179	
  4180	    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
  4181	    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
  4182	    assert!(recent_exceptions.lock().expect("exceptions").is_empty());
  4183	}
  4184	
  4185	#[test]

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tests.rs | sed -n '5350,5465p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  5350	}
  5351	
  5352	/// #1873 R-C: a tunnel-marked inner packet must NEVER be enqueued to
  5353	/// the kernel slow-path TUN — through ANY door (build-failure
  5354	/// fallback, NoRoute, MissingNeighbor non-forward dispositions). It is
  5355	/// dropped with the dedicated counter + exception, and the generic
  5356	/// slow_path_drops counter stays untouched (proving the gate fires
  5357	/// BEFORE the enqueue/unavailable handling, not as a side effect of
  5358	/// slow_path being absent).
  5359	#[test]
  5360	fn tunnel_marked_frame_never_reaches_slow_path() {
  5361	    for (i, disposition) in [
  5362	        ForwardingDisposition::ForwardCandidate, // build-failure door
  5363	        ForwardingDisposition::NoRoute,
  5364	        ForwardingDisposition::MissingNeighbor,
  5365	    ]
  5366	    .into_iter()
  5367	    .enumerate()
  5368	    {
  5369	        let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
  5370	        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  5371	        maybe_reinject_slow_path_from_frame(
  5372	            &binding,
  5373	            &live,
  5374	            None,
  5375	            &local_tunnel_deliveries,
  5376	            &frame,
  5377	            meta,
  5378	            tunnel_marked_decision(disposition),
  5379	            &recent_exceptions,
  5380	            "forward_build_slow_path",
  5381	            &ForwardingState::default(),
  5382	        );
  5383	        assert_eq!(
  5384	            live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
  5385	            1,
  5386	            "case {i}: tunnel gate did not fire"
  5387	        );
  5388	        assert_eq!(
  5389	            live.slow_path_drops.load(Ordering::Relaxed),
  5390	            0,
  5391	            "case {i}: generic slow-path drop counted — gate fired too late"
  5392	        );
  5393	        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
  5394	        let exceptions = recent_exceptions.lock().expect("exceptions");
  5395	        assert_eq!(
  5396	            exceptions.back().expect("exception").reason,
  5397	            "tunnel_encap_unresolved",
  5398	            "case {i}"
  5399	        );
  5400	    }
  5401	}
  5402	
  5403	/// #1873 R-C: the build-failure entry point (`handle_forward_build_failure`
  5404	/// with fallback_to_slow_path = true) funnels through the same gate.
  5405	#[test]
  5406	fn tunnel_marked_build_failure_drops_instead_of_slow_path() {
  5407	    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
  5408	    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
  5409	    let mut dbg = DebugPollCounters::default();
  5410	    handle_forward_build_failure(
  5411	        &binding,
  5412	        &live,
  5413	        None,
  5414	        &local_tunnel_deliveries,
  5415	        &recent_exceptions,
  5416	        &mut dbg,
  5417	        6,
  5418	        frame.len() as u32,
  5419	        &frame,
  5420	        meta,
  5421	        tunnel_marked_decision(ForwardingDisposition::ForwardCandidate),
  5422	        true,
  5423	        &ForwardingState::default(),
  5424	    );
  5425	    assert_eq!(live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed), 1);
  5426	    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
  5427	}
  5428	
  5429	/// #1873 R-C: the local_tunnel_deliveries branch (GRE local-origin
  5430	/// INBOUND delivery, keyed by local_ifindex) must stay OPEN — the gate
  5431	/// sits after it.
  5432	#[test]
  5433	fn tunnel_gate_keeps_local_tunnel_delivery_open() {
  5434	    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
  5435	    let (tx, rx) = mpsc::sync_channel(4);
  5436	    let mut deliveries = BTreeMap::new();
  5437	    deliveries.insert(9, tx);
  5438	    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
  5439	    let mut decision = tunnel_marked_decision(ForwardingDisposition::LocalDelivery);
  5440	    decision.resolution.local_ifindex = 9;
  5441	    maybe_reinject_slow_path_from_frame(
  5442	        &binding,
  5443	        &live,
  5444	        None,
  5445	        &local_tunnel_deliveries,
  5446	        &frame,
  5447	        meta,
  5448	        decision,
  5449	        &recent_exceptions,
  5450	        "forward_build_slow_path",
  5451	        &ForwardingState::default(),
  5452	    );
  5453	    assert_eq!(live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed), 0);
  5454	    let delivered = rx.try_recv().expect("local tunnel delivery still open");
  5455	    assert!(!delivered.is_empty());
  5456	}
  5457	
  5458	/// #1873 R-E: a tunnel-marked decision whose OUTER next-hop is
  5459	/// unresolved (MissingNeighbor) must NOT be buffered in pending_neigh
  5460	/// — the retry path's in-place rewrite cannot encapsulate, so a
  5461	/// buffered tunnel inner packet would later TX PLAINTEXT. The frame
  5462	/// instead flows to the slow-path chokepoint where the R-C blanket
  5463	/// gate drops + counts it.
  5464	#[test]
  5465	fn txn_tunnel_marked_missing_neighbor_not_buffered() {

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '60,255p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
    60	// pre-split sibling-tx/ visibility verbatim.
    61	pub(in crate::afxdp::tx) use slow_path::{extract_l3_packet, extract_l3_packet_from_frame};
    62	
    63	#[inline]
    64	fn recycle_ingress_frame(ingress_binding: &mut BindingWorker, source_offset: u64, now_ns: u64) {
    65	    ingress_binding
    66	        .tx_pipeline
    67	        .pending_fill_frames
    68	        .push_back(source_offset);
    69	    if ingress_binding.tx_pipeline.pending_fill_frames.len() >= FILL_BATCH_SIZE {
    70	        let _ = drain_pending_fill(ingress_binding, now_ns);
    71	    }
    72	}
    73	
    74	pub(in crate::afxdp) fn enqueue_pending_forwards(
    75	    left: &mut [BindingWorker],
    76	    ingress_index: usize,
    77	    ingress_binding: &mut BindingWorker,
    78	    right: &mut [BindingWorker],
    79	    binding_lookup: &WorkerBindingLookup,
    80	    mirror_targets: &MirrorTargetMap,
    81	    pending_forwards: &mut Vec<PendingForwardRequest>,
    82	    post_recycles: &mut Vec<(u32, u64)>,
    83	    now_ns: u64,
    84	    forwarding: &ForwardingState,
    85	    ingress_ident: &BindingIdentity,
    86	    ingress_live: &BindingLiveState,
    87	    slow_path: Option<&Arc<SlowPathReinjector>>,
    88	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    89	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    90	    dbg: &mut DebugPollCounters,
    91	    worker_id: u32,
    92	    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    93	) {
    94	    if pending_forwards.is_empty() {
    95	        return;
    96	    }
    97	    let ingress_area = ingress_binding.umem.area() as *const MmapArea;
    98	    let tx_selection_enabled_v4 = forwarding.tx_selection_enabled_v4;
    99	    let tx_selection_enabled_v6 = forwarding.tx_selection_enabled_v6;
   100	    post_recycles.clear();
   101	    // Walk the scratch vector in place. Moving large PendingForwardRequest
   102	    // values through the iterator path was still forcing per-request memcpy
   103	    // traffic before any forwarding work started.
   104	    for request in pending_forwards.iter_mut() {
   105	        let source_offset = request.desc.addr;
   106	        let ingress_slot = ingress_binding.slot;
   107	        if pending_forward_needs_cos_tx_selection(
   108	            request,
   109	            tx_selection_enabled_v4,
   110	            tx_selection_enabled_v6,
   111	        ) {
   112	            let cos = resolve_pending_forward_cos_tx_selection(forwarding, &request, now_ns);
   113	            if cos.drop {
   114	                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   115	                continue;
   116	            }
   117	            request.cos_queue_id = cos.queue_id;
   118	            request.dscp_rewrite = cos.dscp_rewrite;
   119	            request.cos_tx_selection_resolved = true;
   120	        }
   121	        let target_binding_index = request.target_binding_index.or_else(|| {
   122	            binding_lookup.target_index(
   123	                ingress_index,
   124	                ingress_binding.ifindex,
   125	                request.ingress_queue_id,
   126	                request.target_ifindex,
   127	            )
   128	        });
   129	
   130	        // Fast path: prebuilt frame (e.g. ICMP error NAT reversal).
   131	        // The frame is already fully rewritten — just enqueue for TX.
   132	        if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
   133	            let Some(target_binding) = resolve_pending_forward_target_binding(
   134	                left,
   135	                ingress_index,
   136	                ingress_binding,
   137	                request.ingress_queue_id,
   138	                right,
   139	                binding_lookup,
   140	                target_binding_index,
   141	                request.target_ifindex,
   142	            ) else {
   143	                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   144	                continue;
   145	            };
   146	            let frame_len = prebuilt.len();
   147	            let req = TxRequest {
   148	                bytes: core::mem::take(prebuilt),
   149	                expected_ports: None,
   150	                expected_addr_family: request.meta.addr_family,
   151	                expected_protocol: request.meta.protocol,
   152	                flow_key: request.flow_key.clone(),
   153	                egress_ifindex: request.decision.resolution.egress_ifindex,
   154	                cos_queue_id: request.cos_queue_id,
   155	                dscp_rewrite: request.dscp_rewrite,
   156	                mirror_clone: false,
   157	                enqueue_ns: 0,
   158	            };
   159	            if enqueue_local_request_to_target_or_owner(target_binding, req).is_err() {
   160	                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   161	                continue;
   162	            }
   163	            dbg.enqueue_ok += 1;
   164	            dbg.enqueue_copy += 1;
   165	            target_binding.tx_counters.pending_copy_tx_packets += 1;
   166	            dbg.tx_bytes_total += frame_len as u64;
   167	            if (frame_len as u32) > dbg.tx_max_frame {
   168	                dbg.tx_max_frame = frame_len as u32;
   169	            }
   170	            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   171	            continue;
   172	        }
   173	
   174	        // Read source frame directly from ingress UMEM — no heap copy needed.
   175	        // The frame is safe to read: RX ring released but frame not yet returned
   176	        // to fill ring (that happens after this function completes).
   177	        let source_frame = match &request.frame {
   178	            PendingForwardFrame::Owned(frame) => frame.as_slice(),
   179	            PendingForwardFrame::Live => {
   180	                if let Some(frame) = (unsafe { &*ingress_area })
   181	                    .slice(request.desc.addr as usize, request.desc.len as usize)
   182	                {
   183	                    frame
   184	                } else {
   185	                    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   186	                    continue;
   187	                }
   188	            }
   189	            PendingForwardFrame::Prebuilt(_) => unreachable!(),
   190	        };
   191	        if let Some(result) = enqueue_sampled_mirror_clone(
   192	            left,
   193	            ingress_index,
   194	            ingress_binding,
   195	            right,
   196	            binding_lookup,
   197	            mirror_targets,
   198	            forwarding,
   199	            request.meta.ingress_ifindex as i32,
   200	            request.meta.ingress_vlan_id,
   201	            request.ingress_queue_id,
   202	            source_frame,
   203	            request.meta,
   204	            request.flow_key.as_ref(),
   205	        ) {
   206	            record_mirror_clone_result(&ingress_binding.live, result, source_frame.len());
   207	        }
   208	        let expected_ports = request.expected_ports;
   209	        let ingress_umem_ptr = ingress_binding.umem.allocation_ptr();
   210	        let Some(target_binding) = resolve_pending_forward_target_binding(
   211	            left,
   212	            ingress_index,
   213	            ingress_binding,
   214	            request.ingress_queue_id,
   215	            right,
   216	            binding_lookup,
   217	            target_binding_index,
   218	            request.target_ifindex,
   219	        ) else {
   220	            // No XSK binding for the target interface.  Normally fabric
   221	            // parents have bindings; this is a safety-net fallback in case
   222	            // the binding is not yet ready or bind() failed.
   223	            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
   224	                if matches!(request.frame, PendingForwardFrame::Owned(_)) {
   225	                    maybe_reinject_slow_path_from_frame(
   226	                        ingress_ident,
   227	                        ingress_live,
   228	                        slow_path,
   229	                        local_tunnel_deliveries,
   230	                        source_frame,
   231	                        request.meta,
   232	                        request.decision,
   233	                        recent_exceptions,
   234	                        "slow_path",
   235	                        forwarding,
   236	                    );
   237	                } else {
   238	                    maybe_reinject_slow_path(
   239	                        ingress_ident,
   240	                        ingress_live,
   241	                        slow_path,
   242	                        local_tunnel_deliveries,
   243	                        unsafe { &*ingress_area },
   244	                        request.desc,
   245	                        request.meta,
   246	                        request.decision,
   247	                        recent_exceptions,
   248	                        forwarding,
   249	                    );
   250	                }
   251	                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   252	                continue;
   253	            }
   254	            dbg.no_egress_binding += 1;
   255	            if cfg!(feature = "debug-log") && dbg.no_egress_binding <= 3 {

codex
The dispatch fallback is weaker than the plan states. The code uses `_from_frame` only for `PendingForwardFrame::Owned`; the live-frame `FabricRedirect` fallback goes through the filtered wrapper and would be rejected today. I’m tracing whether `FabricRedirect` can be live, because that determines whether §2.6 is proven or over-asserted.
exec
/bin/bash -lc "rg -n \"enum PendingForwardFrame|PendingForwardFrame::Owned|PendingForwardFrame::Live|PendingForwardFrame::Prebuilt|struct PendingForwardRequest|build_live_forward_request_from_frame|request\\.frame\" userspace-dp/src/afxdp -g '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/types/tx.rs:61:pub(in crate::afxdp) enum PendingForwardFrame {
userspace-dp/src/afxdp/types/tx.rs:73:pub(in crate::afxdp) struct PendingForwardRequest {
userspace-dp/src/afxdp/tests.rs:194:fn build_live_forward_request_from_frame_uses_precomputed_hints() {
userspace-dp/src/afxdp/tests.rs:235:    let req = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/tests.rs:260:fn build_live_forward_request_from_frame_drops_logged_output_filter_discard() {
userspace-dp/src/afxdp/tests.rs:335:    let req = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/tests.rs:1310:    assert!(matches!(request.frame, PendingForwardFrame::Prebuilt(_)));
userspace-dp/src/afxdp/mod.rs:654:    build_live_forward_request_from_frame, should_install_local_reverse_session,
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:344:                if let Some(mut request) = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:364:                    request.frame = owned_packet_frame
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:366:                        .map(PendingForwardFrame::Owned)
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:367:                        .unwrap_or(PendingForwardFrame::Live);
userspace-dp/src/afxdp/icmp.rs:67:        frame: PendingForwardFrame::Prebuilt(prebuilt_frame),
userspace-dp/src/afxdp/poll_descriptor/mod.rs:466:                                if let Some(mut request) = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:483:                                    request.frame = owned_packet_frame
userspace-dp/src/afxdp/poll_descriptor/mod.rs:485:                                        .map(PendingForwardFrame::Owned)
userspace-dp/src/afxdp/poll_descriptor/mod.rs:486:                                        .unwrap_or(PendingForwardFrame::Live);
userspace-dp/src/afxdp/poll_descriptor/mod.rs:960:                                                    frame: PendingForwardFrame::Prebuilt(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2023:                        if let Some(mut request) = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2040:                            request.frame = owned_packet_frame
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2042:                                .map(PendingForwardFrame::Owned)
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2043:                                .unwrap_or(PendingForwardFrame::Live);
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:79:        frame: PendingForwardFrame::Live,
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs:108:        frame: PendingForwardFrame::Live,
userspace-dp/src/afxdp/frame/tests.rs:2657:    let req = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:132:        if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:177:        let source_frame = match &request.frame {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:178:            PendingForwardFrame::Owned(frame) => frame.as_slice(),
userspace-dp/src/afxdp/tx/dispatch/mod.rs:179:            PendingForwardFrame::Live => {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:189:            PendingForwardFrame::Prebuilt(_) => unreachable!(),
userspace-dp/src/afxdp/tx/dispatch/mod.rs:224:                if matches!(request.frame, PendingForwardFrame::Owned(_)) {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:447:                    && matches!(request.frame, PendingForwardFrame::Live);
userspace-dp/src/afxdp/forward_request.rs:3:// `build_live_forward_request` and `build_live_forward_request_from_frame`
userspace-dp/src/afxdp/forward_request.rs:42:    build_live_forward_request_from_frame(
userspace-dp/src/afxdp/forward_request.rs:61:pub(super) fn build_live_forward_request_from_frame(
userspace-dp/src/afxdp/forward_request.rs:173:        frame: PendingForwardFrame::Live,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/types.rs | sed -n '1,160p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
nl: userspace-dp/src/afxdp/tx/types.rs: No such file or directory

exec
/bin/bash -lc "rg -n \"pub\\(in crate::afxdp\\) fn build_live_forward_request_from_frame|fn build_live_forward_request_from_frame|build_live_forward_request\" userspace-dp/src/afxdp -g '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/mod.rs:654:    build_live_forward_request_from_frame, should_install_local_reverse_session,
userspace-dp/src/afxdp/mod.rs:656:// `build_live_forward_request` is only referenced by tests in
userspace-dp/src/afxdp/mod.rs:659:use forward_request::build_live_forward_request;
userspace-dp/src/afxdp/mod.rs:667:// Superseded by inline logic in build_live_forward_request() that reads ports
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:344:                if let Some(mut request) = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:466:                                if let Some(mut request) = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2023:                        if let Some(mut request) = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/tests.rs:194:fn build_live_forward_request_from_frame_uses_precomputed_hints() {
userspace-dp/src/afxdp/tests.rs:235:    let req = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/tests.rs:260:fn build_live_forward_request_from_frame_drops_logged_output_filter_discard() {
userspace-dp/src/afxdp/tests.rs:335:    let req = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/frame/tests.rs:2103:fn build_live_forward_request_prefers_session_flow_ports_over_frame() {
userspace-dp/src/afxdp/frame/tests.rs:2197:    let req = build_live_forward_request(
userspace-dp/src/afxdp/frame/tests.rs:2221:fn build_live_forward_request_uses_live_frame_ports_when_no_session_flow() {
userspace-dp/src/afxdp/frame/tests.rs:2301:    let req = build_live_forward_request(
userspace-dp/src/afxdp/frame/tests.rs:2324:fn build_live_forward_request_meters_non_l4_metadata_flow() {
userspace-dp/src/afxdp/frame/tests.rs:2426:    let req = build_live_forward_request(
userspace-dp/src/afxdp/frame/tests.rs:2452:fn build_live_forward_request_marks_empty_cos_selection_resolved() {
userspace-dp/src/afxdp/frame/tests.rs:2535:    let req = build_live_forward_request(
userspace-dp/src/afxdp/frame/tests.rs:2563:fn build_live_forward_request_emits_output_filter_log_event() {
userspace-dp/src/afxdp/frame/tests.rs:2657:    let req = build_live_forward_request_from_frame(
userspace-dp/src/afxdp/frame/tests.rs:2696:fn build_live_forward_request_uses_flow_or_metadata_ports_when_frame_ports_unavailable() {
userspace-dp/src/afxdp/frame/tests.rs:2748:    let req = build_live_forward_request(
userspace-dp/src/afxdp/frame/tests.rs:2771:fn build_live_forward_request_marks_session_fabric_redirect_for_nat_and_zone() {
userspace-dp/src/afxdp/frame/tests.rs:2817:    let req = build_live_forward_request(
userspace-dp/src/afxdp/frame/tests.rs:2846:fn build_live_forward_request_caches_target_binding_index() {
userspace-dp/src/afxdp/frame/tests.rs:2900:    let req = build_live_forward_request(
userspace-dp/src/afxdp/forward_request.rs:3:// `build_live_forward_request` and `build_live_forward_request_from_frame`
userspace-dp/src/afxdp/forward_request.rs:27:pub(super) fn build_live_forward_request(
userspace-dp/src/afxdp/forward_request.rs:42:    build_live_forward_request_from_frame(
userspace-dp/src/afxdp/forward_request.rs:61:pub(super) fn build_live_forward_request_from_frame(

exec
/bin/bash -lc 'rg -n "owned_packet_frame|packet_frame|stage_native_gre_decap|FabricRedirect" userspace-dp/src/afxdp/poll_descriptor/mod.rs' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
30:    stage_native_gre_decap, stage_parse_flow_and_learn, stage_screen_check,
124:                    // `owned_packet_frame` MUST be `mut` — deferred
126:                    let (mut meta, mut owned_packet_frame) =
127:                        stage_native_gre_decap(raw_frame, meta, worker_ctx.forwarding);
128:                    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
132:                    // `owned_packet_frame.is_none()` — preserves the
142:                        packet_frame,
144:                        owned_packet_frame.is_none(),
155:                    } = stage_classify_fabric_ingress(packet_frame, &mut meta, worker_ctx);
161:                        packet_frame,
178:                                packet_frame,
193:                        packet_frame,
205:                    // The original L477 `packet_frame` binding's NLL
224:                            &mut owned_packet_frame,
239:                    // Re-bind packet_frame for slow-path code below
242:                    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
413:                                packet_frame,
430:                                        packet_frame,
441:                                parse_packet_destination_from_frame(packet_frame, meta)
453:                                    packet_frame,
471:                                    packet_frame,
483:                                    request.frame = owned_packet_frame
1117:                                        l3 <= packet_frame.len()
1119:                                                &packet_frame[l3..],
1797:                            | ForwardingDisposition::FabricRedirect
2028:                            packet_frame,
2040:                            request.frame = owned_packet_frame
2164:                                // over `packet_frame`). #1885: this arm used
2170:                                // (`stage_native_gre_decap` rebinds `meta`
2500:                                            l3 <= packet_frame.len()
2502:                                                    &packet_frame[l3..],
2700:                                // `owned_packet_frame`; the retry path's
2719:                                    && owned_packet_frame.is_some()
2819:                            packet_frame,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '100,250p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   100	                let disposition = classify_metadata(meta, validation);
   101	                if disposition == PacketDisposition::Valid {
   102	                    telemetry.counters.validated_packets += 1;
   103	                    telemetry.counters.validated_bytes += desc.len as u64;
   104	                    // SAFETY: per the `area` contract in this function's
   105	                    // header comment.
   106	                    let Some(raw_frame) =
   107	                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
   108	                    else {
   109	                        binding.scratch.scratch_recycle.push(desc.addr);
   110	                        continue;
   111	                    };
   112	                    // #946 Phase 1 stage 5: ARP / NDP link-layer
   113	                    // classification. ARP frames recycle without
   114	                    // transiting; NDP NA learns and falls through.
   115	                    if let StageOutcome::RecycleAndContinue =
   116	                        stage_link_layer_classify(raw_frame, meta, worker_ctx)
   117	                    {
   118	                        binding.scratch.scratch_recycle.push(desc.addr);
   119	                        continue;
   120	                    }
   121	                    // #946 Phase 1 stage 6: native GRE decap. Caller
   122	                    // binds the active slice locally; helper does NOT
   123	                    // return the slice (would be self-referential).
   124	                    // `owned_packet_frame` MUST be `mut` — deferred
   125	                    // stage-12+ code at lines below calls `.take()`.
   126	                    let (mut meta, mut owned_packet_frame) =
   127	                        stage_native_gre_decap(raw_frame, meta, worker_ctx.forwarding);
   128	                    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
   129	                    // #946 Phase 1 stage 7+8: parse session flow and
   130	                    // learn the source-side dynamic neighbor.
   131	                    // `learn_from_live_frame` MUST be
   132	                    // `owned_packet_frame.is_none()` — preserves the
   133	                    // GRE guard at the original line 113 (neighbor
   134	                    // learning uses the live UMEM Ethernet frame so
   135	                    // the source MAC is the outer host's, not the
   136	                    // GRE tunnel egress).
   137	                    let flow = stage_parse_flow_and_learn(
   138	                        // SAFETY: per the `area` contract in this
   139	                        // function's header comment.
   140	                        unsafe { &*area },
   141	                        desc,
   142	                        packet_frame,
   143	                        meta,
   144	                        owned_packet_frame.is_none(),
   145	                        &mut binding.last_learned_neighbor,
   146	                        worker_ctx,
   147	                    );
   148	                    // #946 Phase 1 stage 9: fabric-ingress
   149	                    // classification. Mutates meta.meta_flags. MUST
   150	                    // run before screen/IPsec/flow-cache because they
   151	                    // read meta.meta_flags downstream.
   152	                    let FabricIngressOutcome {
   153	                        ingress_zone_override,
   154	                        packet_fabric_ingress,
   155	                    } = stage_classify_fabric_ingress(packet_frame, &mut meta, worker_ctx);
   156	                    // #946 Phase 1 stage 10: screen / IDS slow-path.
   157	                    // Caller still owns the recycle push (matches
   158	                    // original code's pattern).
   159	                    match stage_screen_check(
   160	                        flow.as_ref(),
   161	                        packet_frame,
   162	                        meta,
   163	                        ingress_zone_override,
   164	                        now_secs,
   165	                        screen,
   166	                        telemetry.counters,
   167	                        worker_ctx,
   168	                    ) {
   169	                        StageOutcome::RecycleAndContinue => {
   170	                            binding.scratch.scratch_recycle.push(desc.addr);
   171	                            continue;
   172	                        }
   173	                        StageOutcome::Continue(ScreenCheckOutcome::Pass) => {}
   174	                        StageOutcome::Continue(ScreenCheckOutcome::SynCookieChallenge(challenge)) => {
   175	                            enqueue_syn_cookie_reply(
   176	                                &mut binding.tx_pipeline,
   177	                                binding.ifindex,
   178	                                packet_frame,
   179	                                meta,
   180	                                flow.as_ref(),
   181	                                SynCookieReply::SynAck(challenge),
   182	                                telemetry.counters,
   183	                            );
   184	                            binding.scratch.scratch_recycle.push(desc.addr);
   185	                            continue;
   186	                        }
   187	                    }
   188	                    // #946 Phase 1 stage 11: IPsec passthrough. ESP
   189	                    // (proto 50) and IKE (UDP 500/4500) reinject via
   190	                    // the slow-path TUN; recycle the UMEM frame.
   191	                    if let StageOutcome::RecycleAndContinue = stage_ipsec_passthrough_check(
   192	                        flow.as_ref(),
   193	                        packet_frame,
   194	                        meta,
   195	                        &binding.live,
   196	                        worker_ctx,
   197	                    ) {
   198	                        binding.scratch.scratch_recycle.push(desc.addr);
   199	                        continue;
   200	                    }
   201	                    // ── Flow cache fast path (#1327 Step 1) ────────────────
   202	                    // Extracted to poll_descriptor/flow_cache_hit.rs. The
   203	                    // helper owns ALL recycle/forward pushes on Consumed;
   204	                    // caller MUST `continue` without touching desc.addr.
   205	                    // The original L477 `packet_frame` binding's NLL
   206	                    // lifetime ends at the previous line (last use was
   207	                    // inside stage_ipsec_passthrough_check); it is rebound
   208	                    // below the helper call for the slow-path code.
   209	                    if FlowCacheEntry::packet_eligible(meta)
   210	                        && let Some(flow) = flow.as_ref()
   211	                    {
   212	                        match stage_flow_cache_hit(
   213	                            &mut binding.flow,
   214	                            &mut binding.tx_pipeline,
   215	                            &mut binding.tx_counters,
   216	                            &mut binding.scratch,
   217	                            &mut binding.mirror_sample_counter,
   218	                            &binding.live,
   219	                            binding.slot,
   220	                            binding_index,
   221	                            desc,
   222	                            area,
   223	                            raw_frame,
   224	                            &mut owned_packet_frame,
   225	                            meta,
   226	                            flow,
   227	                            packet_fabric_ingress,
   228	                            validation,
   229	                            sessions,
   230	                            now_ns,
   231	                            now_secs,
   232	                            worker_ctx,
   233	                            telemetry,
   234	                        ) {
   235	                            FlowCacheOutcome::Consumed => continue,
   236	                            FlowCacheOutcome::FallThrough => {}
   237	                        }
   238	                    }
   239	                    // Re-bind packet_frame for slow-path code below
   240	                    // (original L477 binding's NLL lifetime ended before
   241	                    // the helper call above).
   242	                    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
   243	                    // ── End flow cache fast path ─────────────────────────
   244	                    let mut debug = flow
   245	                        .as_ref()
   246	                        .map(|flow| ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow));
   247	                    let mut session_ingress_zone: Option<u16> = None;
   248	                    let mut flow_cache_owner_rg_id = 0i32;
   249	                    let mut apply_nat_on_fabric = false;
   250	                    // #1861 §5.4: true when a session install was attempted

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/types/tx.rs | sed -n '50,115p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
    50	            expected_protocol: self.expected_protocol,
    51	            flow_key: self.flow_key,
    52	            egress_ifindex: self.egress_ifindex,
    53	            cos_queue_id: self.cos_queue_id,
    54	            dscp_rewrite: self.dscp_rewrite,
    55	            mirror_clone: self.mirror_clone,
    56	            enqueue_ns: self.enqueue_ns,
    57	        }
    58	    }
    59	}
    60	
    61	pub(in crate::afxdp) enum PendingForwardFrame {
    62	    Live,
    63	    Owned(Vec<u8>),
    64	    Prebuilt(Vec<u8>),
    65	}
    66	
    67	impl Default for PendingForwardFrame {
    68	    fn default() -> Self {
    69	        Self::Live
    70	    }
    71	}
    72	
    73	pub(in crate::afxdp) struct PendingForwardRequest {
    74	    pub(in crate::afxdp) target_ifindex: i32,
    75	    pub(in crate::afxdp) target_binding_index: Option<usize>,
    76	    pub(in crate::afxdp) ingress_queue_id: u32,
    77	    pub(in crate::afxdp) desc: XdpDesc,
    78	    pub(in crate::afxdp) frame: PendingForwardFrame,
    79	    pub(in crate::afxdp) meta: ForwardPacketMeta,
    80	    pub(in crate::afxdp) decision: SessionDecision,
    81	    pub(in crate::afxdp) apply_nat_on_fabric: bool,
    82	    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    83	    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    84	    pub(in crate::afxdp) nat64_reverse: Option<Nat64ReverseInfo>,
    85	    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    86	    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    87	    pub(in crate::afxdp) cos_tx_selection_resolved: bool,
    88	}
    89	
    90	pub(in crate::afxdp) struct PreparedTxRequest {
    91	    pub(in crate::afxdp) offset: u64,
    92	    pub(in crate::afxdp) len: u32,
    93	    pub(in crate::afxdp) recycle: PreparedTxRecycle,
    94	    #[allow(dead_code)]
    95	    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    96	    #[allow(dead_code)]
    97	    pub(in crate::afxdp) expected_addr_family: u8,
    98	    #[allow(dead_code)]
    99	    pub(in crate::afxdp) expected_protocol: u8,
   100	    pub(in crate::afxdp) flow_key: Option<SessionKey>,
   101	    pub(in crate::afxdp) egress_ifindex: i32,
   102	    pub(in crate::afxdp) cos_queue_id: Option<u8>,
   103	    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
   104	    pub(in crate::afxdp) mirror_clone: bool,
   105	    /// #1829 Phase 1: CoS enqueue timestamp. Same contract as
   106	    /// `TxRequest::enqueue_ns` (0 = never CoS-enqueued / no data);
   107	    /// see the field doc there.
   108	    pub(in crate::afxdp) enqueue_ns: u64,
   109	}
   110	
   111	impl PreparedTxRequest {
   112	    #[inline]
   113	    pub(in crate::afxdp) fn to_local_request(&self, bytes: Vec<u8>) -> TxRequest {
   114	        TxRequest {
   115	            bytes,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '400,470p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/forward_request.rs | sed -n '1,190p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   400	                thread_local! {
   401	                    static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
   402	                }
   403	                SEG_MISS_LOG.with(|cap| {
   404	                    record_forwarded_tcp_segmentation_miss(
   405	                        cap,
   406	                        recent_exceptions,
   407	                        ingress_ident,
   408	                        source_frame,
   409	                        request,
   410	                        forwarding,
   411	                    );
   412	                });
   413	            }
   414	            if !copied_source_frame {
   415	                // NAT64: header size changes prevent in-place rewrite.
   416	                // Always use copy path with NAT64-specific frame builder.
   417	                let is_nat64 = request.decision.nat.nat64;
   418	                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;
   419	                // #1598 secondary fix: gate on `shared_exact` policy
   420	                // (not on `shared_queue_lease.is_some()`), see the
   421	                // doc comment on `request_runs_under_shared_exact_policy`
   422	                // in dispatch/cos.rs. Non-exact uncapped queues now
   423	                // qualify for the local in-place rewrite path.
   424	                let owner_matches_target = request_runs_under_shared_exact_policy(
   425	                    &target_binding.cos.cos_fast_interfaces,
   426	                    request.decision.resolution.egress_ifindex,
   427	                    request.cos_queue_id,
   428	                ) || cos_owner_live_for_request(
   429	                    &target_binding.cos.cos_fast_interfaces,
   430	                    request.decision.resolution.egress_ifindex,
   431	                    request.cos_queue_id,
   432	                )
   433	                .as_ref()
   434	                .is_none_or(|live| Arc::ptr_eq(live, &target_binding.live));
   435	
   436	                /*
   437	                 * In-place TX optimization: rewrite the ingress frame directly in UMEM
   438	                 * and submit it to the target binding's TX ring without copying.
   439	                 * This is valid whenever ingress and egress bindings share the same
   440	                 * UMEM allocation. That includes same-binding hairpin and the narrow
   441	                 * shared-UMEM groups.
   442	                 */
   443	                let can_rewrite_in_place = target_binding.umem.allocation_ptr() == ingress_umem_ptr
   444	                    && !is_nat64
   445	                    && !uses_native_tunnel
   446	                    && owner_matches_target
   447	                    && matches!(request.frame, PendingForwardFrame::Live);
   448	                if can_rewrite_in_place {
   449	                    match rewrite_forwarded_frame_in_place(
   450	                        unsafe { &*ingress_area },
   451	                        request.desc,
   452	                        request.meta,
   453	                        &request.decision,
   454	                        request.apply_nat_on_fabric,
   455	                        expected_ports,
   456	                    ) {
   457	                        Some(rewrite_result) => {
   458	                            target_binding.tx_pipeline.pending_tx_prepared.push_back(
   459	                                PreparedTxRequest {
   460	                                    offset: rewrite_result.offset,
   461	                                    len: rewrite_result.len,
   462	                                    recycle: PreparedTxRecycle::fill_on_slot(
   463	                                        ingress_slot,
   464	                                        rewrite_result.offset,
   465	                                        source_offset,
   466	                                    ),
   467	                                    expected_ports,
   468	                                    expected_addr_family: request.meta.addr_family,
   469	                                    expected_protocol: request.meta.protocol,
   470	                                    flow_key: flow_key.take(),

 succeeded in 0ms:
     1	// Forward-request builders extracted from afxdp.rs (Issue 67.4).
     2	//
     3	// `build_live_forward_request` and `build_live_forward_request_from_frame`
     4	// pack a per-packet ForwardingResolution + SessionMetadata into the
     5	// LiveForwardRequest descriptor that the dispatch path enqueues.
     6	//
     7	// `should_install_local_reverse_session` is the small predicate that
     8	// decides whether the reverse-direction session entry should be
     9	// pre-installed locally vs lazily on first reverse-direction packet.
    10	//
    11	// Pure relocation. `use super::*;` brings every type and helper from
    12	// afxdp.rs into scope.
    13	
    14	use super::*;
    15	
    16	pub(super) fn should_install_local_reverse_session(
    17	    decision: SessionDecision,
    18	    fabric_ingress: bool,
    19	) -> bool {
    20	    let fabric_wire_placeholder =
    21	        shared_ops::is_fabric_wire_placeholder(fabric_ingress, false, decision);
    22	    decision.resolution.disposition != ForwardingDisposition::FabricRedirect
    23	        || (fabric_ingress && !fabric_wire_placeholder)
    24	}
    25	
    26	#[cfg_attr(not(test), allow(dead_code))]
    27	pub(super) fn build_live_forward_request(
    28	    area: &MmapArea,
    29	    binding_lookup: &WorkerBindingLookup,
    30	    current_binding_index: usize,
    31	    ingress_ident: &BindingIdentity,
    32	    desc: XdpDesc,
    33	    meta: UserspaceDpMeta,
    34	    decision: &SessionDecision,
    35	    forwarding: &ForwardingState,
    36	    flow: Option<&SessionFlow>,
    37	    fabric_ingress_zone: Option<u16>,
    38	    apply_nat_on_fabric: bool,
    39	    now_ns: u64,
    40	) -> Option<PendingForwardRequest> {
    41	    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    42	    build_live_forward_request_from_frame(
    43	        binding_lookup,
    44	        current_binding_index,
    45	        ingress_ident,
    46	        desc,
    47	        frame,
    48	        meta,
    49	        decision,
    50	        forwarding,
    51	        flow,
    52	        fabric_ingress_zone,
    53	        apply_nat_on_fabric,
    54	        now_ns,
    55	        None,
    56	        None,
    57	        None,
    58	    )
    59	}
    60	
    61	pub(super) fn build_live_forward_request_from_frame(
    62	    binding_lookup: &WorkerBindingLookup,
    63	    current_binding_index: usize,
    64	    ingress_ident: &BindingIdentity,
    65	    desc: XdpDesc,
    66	    frame: &[u8],
    67	    meta: UserspaceDpMeta,
    68	    decision: &SessionDecision,
    69	    forwarding: &ForwardingState,
    70	    flow: Option<&SessionFlow>,
    71	    fabric_ingress_zone: Option<u16>,
    72	    apply_nat_on_fabric: bool,
    73	    now_ns: u64,
    74	    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    75	    hints: Option<PendingForwardHints>,
    76	    precomputed_tx_selection: Option<&CachedTxSelectionDescriptor>,
    77	) -> Option<PendingForwardRequest> {
    78	    let hints = hints.unwrap_or_default();
    79	    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
    80	        decision.resolution.tx_ifindex
    81	    } else {
    82	        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
    83	    };
    84	    // Prefer session flow ports (set by conntrack, immune to DMA races),
    85	    // then live frame ports (lazy — only parsed if session ports unavailable),
    86	    // then metadata as last resort.
    87	    let expected_ports = hints
    88	        .expected_ports
    89	        .or_else(|| authoritative_forward_ports(frame, meta, flow));
    90	    let target_binding_index = hints.target_binding_index.or_else(|| {
    91	        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
    92	            binding_lookup.fabric_target_index(
    93	                target_ifindex,
    94	                fabric_queue_hash(flow, expected_ports, meta),
    95	            )
    96	        } else {
    97	            binding_lookup.target_index(
    98	                current_binding_index,
    99	                ingress_ident.ifindex,
   100	                ingress_ident.queue_id,
   101	                target_ifindex,
   102	            )
   103	        }
   104	    });
   105	    let mut decision = *decision;
   106	    // #919/#922: ID-keyed redirect — no `zone_id_to_name` round-trip.
   107	    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect
   108	        && let Some(ingress_zone_id) = fabric_ingress_zone
   109	        && let Some(zone_redirect) =
   110	            resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone_id)
   111	    {
   112	        decision.resolution.src_mac = zone_redirect.src_mac;
   113	    }
   114	    let fallback_flow;
   115	    let tx_selection_flow = if flow.is_some() {
   116	        flow
   117	    } else {
   118	        fallback_flow = parse_session_flow_from_meta(meta);
   119	        fallback_flow.as_ref()
   120	    };
   121	    let cos = precomputed_tx_selection
   122	        .map(|selection| CoSTxSelection {
   123	            queue_id: selection.queue_id,
   124	            dscp_rewrite: selection.dscp_rewrite,
   125	            drop: selection.drop,
   126	            filter_log: selection.filter_log,
   127	        })
   128	        .unwrap_or_else(|| {
   129	            resolve_cos_tx_selection_at(
   130	                forwarding,
   131	                decision.resolution.egress_ifindex,
   132	                meta,
   133	                tx_selection_flow.map(|flow| &flow.forward_key),
   134	                now_ns,
   135	            )
   136	        });
   137	    if let (Some(filter_log), Some(flow)) = (cos.filter_log, tx_selection_flow) {
   138	        let ingress_zone_id = fabric_ingress_zone
   139	            .filter(|id| forwarding.zone_id_to_name.contains_key(id))
   140	            .or_else(|| {
   141	                forwarding
   142	                    .ifindex_to_zone_id
   143	                    .get(&(meta.ingress_ifindex as i32))
   144	                    .copied()
   145	            })
   146	            .unwrap_or(0);
   147	        let egress_zone_id = forwarding
   148	            .egress
   149	            .get(&decision.resolution.egress_ifindex)
   150	            .map(|egress| egress.zone_id)
   151	            .unwrap_or(0);
   152	        emit_filter_log_event(
   153	            event_stream,
   154	            flow,
   155	            meta,
   156	            ingress_zone_id,
   157	            egress_zone_id,
   158	            filter_log.filter_id,
   159	            filter_log.term_id,
   160	            filter_log.action,
   161	            FilterLogSource::Output,
   162	            now_ns,
   163	        );
   164	    }
   165	    if cos.drop {
   166	        return None;
   167	    }
   168	    Some(PendingForwardRequest {
   169	        target_ifindex,
   170	        target_binding_index,
   171	        ingress_queue_id: ingress_ident.queue_id,
   172	        desc,
   173	        frame: PendingForwardFrame::Live,
   174	        meta: meta.into(),
   175	        decision,
   176	        apply_nat_on_fabric,
   177	        expected_ports,
   178	        flow_key: tx_selection_flow.map(|flow| flow.forward_key.clone()),
   179	        nat64_reverse: None,
   180	        cos_queue_id: cos.queue_id,
   181	        dscp_rewrite: cos.dscp_rewrite,
   182	        cos_tx_selection_resolved: true,
   183	    })
   184	}

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '430,500p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   430	                                        packet_frame,
   431	                                        meta,
   432	                                        Some(flow),
   433	                                        SynCookieReply::AckRst,
   434	                                        telemetry.counters,
   435	                                    );
   436	                                    binding.scratch.scratch_recycle.push(desc.addr);
   437	                                    continue;
   438	                                }
   439	                            }
   440	                            let resolution_target =
   441	                                parse_packet_destination_from_frame(packet_frame, meta)
   442	                                    .unwrap_or(flow.dst_ip);
   443	                            // Cluster peer return fast path:
   444	                            // a packet arriving from zone-encoded fabric ingress has already
   445	                            // been policy/NAT-validated by the active owner. Allow the inactive
   446	                            // peer to hand it to the resolved local egress zone instead of
   447	                            // treating it as a brand-new flow. Keep pure TCP SYN excluded so
   448	                            // brand-new connects still require local session ownership.
   449	                            if let Some((fabric_return_decision, fabric_return_metadata)) =
   450	                                cluster_peer_return_fast_path(
   451	                                    worker_ctx.forwarding,
   452	                                    worker_ctx.dynamic_neighbors,
   453	                                    packet_frame,
   454	                                    meta,
   455	                                    ingress_zone_override,
   456	                                    resolution_target,
   457	                                )
   458	                            {
   459	                                let ingress_ident = BindingIdentity {
   460	                                    slot: binding.slot,
   461	                                    queue_id: binding.queue_id,
   462	                                    worker_id: binding.worker_id,
   463	                                    interface: binding.interface.clone(),
   464	                                    ifindex: binding.ifindex,
   465	                                };
   466	                                if let Some(mut request) = build_live_forward_request_from_frame(
   467	                                    worker_ctx.binding_lookup,
   468	                                    binding_index,
   469	                                    &ingress_ident,
   470	                                    desc,
   471	                                    packet_frame,
   472	                                    meta,
   473	                                    &fabric_return_decision,
   474	                                    worker_ctx.forwarding,
   475	                                    Some(flow),
   476	                                    None,
   477	                                    false,
   478	                                    now_ns,
   479	                                    worker_ctx.event_stream,
   480	                                    None,
   481	                                    None,
   482	                                ) {
   483	                                    request.frame = owned_packet_frame
   484	                                        .take()
   485	                                        .map(PendingForwardFrame::Owned)
   486	                                        .unwrap_or(PendingForwardFrame::Live);
   487	                                    if sessions.install_with_protocol_with_origin(
   488	                                        flow.forward_key.clone(),
   489	                                        fabric_return_decision,
   490	                                        fabric_return_metadata,
   491	                                        SessionOrigin::ReverseFlow,
   492	                                        now_ns,
   493	                                        meta.protocol,
   494	                                        meta.tcp_flags,
   495	                                    ) {
   496	                                        // #1789: a failed publish leaves the
   497	                                        // shim without this key (NO_SESSION
   498	                                        // degraded path). Count it; one
   499	                                        // Relaxed fetch_add on the rare error
   500	                                        // branch only.

codex
`PendingForwardRequest` defaults to `Live`; `Owned` is only assigned when GRE decap produced an owned inner packet. That makes the dispatch fallback a frame-source distinction, not clean evidence of a disposition-policy bypass by design. I’m checking whether any tests or comments assert the `FabricRedirect`/`_from_frame` fallback contract directly.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs | sed -n '320,375p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   320	                        expected_addr_family: meta.addr_family,
   321	                        expected_protocol: meta.protocol,
   322	                        flow_key: Some(flow_key),
   323	                        egress_ifindex: cached_decision.resolution.egress_ifindex,
   324	                        cos_queue_id: cached_queue_id,
   325	                        dscp_rewrite: cached_dscp_rewrite,
   326	                        mirror_clone: false,
   327	                        enqueue_ns: 0,
   328	                    });
   329	                    tx_counters.pending_in_place_tx_packets += 1;
   330	                    tx_counters.record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
   331	                    telemetry.dbg.forward += 1;
   332	                    telemetry.dbg.tx += 1;
   333	                    recycle_now = false;
   334	                }
   335	            }
   336	            // Fallback: use PendingForwardRequest path for cross-binding or failure.
   337	            if recycle_now {
   338	                let cached_precomputed_tx_selection = CachedTxSelectionDescriptor {
   339	                    queue_id: cached_queue_id,
   340	                    dscp_rewrite: cached_dscp_rewrite,
   341	                    drop: cached_descriptor.tx_selection.drop,
   342	                    ..CachedTxSelectionDescriptor::default()
   343	                };
   344	                if let Some(mut request) = build_live_forward_request_from_frame(
   345	                    worker_ctx.binding_lookup,
   346	                    binding_index,
   347	                    worker_ctx.ident,
   348	                    desc,
   349	                    packet_frame,
   350	                    meta,
   351	                    &cached_decision,
   352	                    worker_ctx.forwarding,
   353	                    Some(flow),
   354	                    Some(cached_metadata.ingress_zone),
   355	                    cached_descriptor.apply_nat_on_fabric,
   356	                    now_ns,
   357	                    worker_ctx.event_stream,
   358	                    Some(PendingForwardHints {
   359	                        expected_ports,
   360	                        target_binding_index: target_bi,
   361	                    }),
   362	                    Some(&cached_precomputed_tx_selection),
   363	                ) {
   364	                    request.frame = owned_packet_frame
   365	                        .take()
   366	                        .map(PendingForwardFrame::Owned)
   367	                        .unwrap_or(PendingForwardFrame::Live);
   368	                    telemetry.dbg.forward += 1;
   369	                    telemetry.dbg.tx += 1;
   370	                    scratch.scratch_forwards.push(request);
   371	                    recycle_now = false;
   372	                }
   373	            }
   374	        }
   375	        if recycle_now {

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs | sed -n '1,160p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
     1	// Tests for afxdp/tx/dispatch.rs — relocated from inline
     2	// `#[cfg(test)] mod tests` to keep dispatch.rs under the modularity-discipline
     3	// LOC threshold. Loaded as a sibling submodule via
     4	// `#[path = "dispatch_tests.rs"]` from dispatch.rs.
     5	
     6	use super::*;
     7	use crate::afxdp::tx::test_support::{build_ipv4_test_packet, test_session_key};
     8	use crate::test_zone_ids::*;
     9	use arc_swap::ArcSwap;
    10	use std::collections::{BTreeMap, VecDeque};
    11	use std::sync::atomic::Ordering;
    12	use std::sync::mpsc::SyncSender;
    13	use std::sync::{Arc, Mutex};
    14	
    15	fn test_forwarding_with_egress_mtu(mtu: usize) -> ForwardingState {
    16	    let mut forwarding = ForwardingState::default();
    17	    forwarding.egress.insert(
    18	        80,
    19	        EgressInterface {
    20	            bind_ifindex: 11,
    21	            vlan_id: 80,
    22	            mtu,
    23	            src_mac: [0; 6],
    24	            zone_id: TEST_WAN_ZONE_ID,
    25	            redundancy_group: 0,
    26	            primary_v4: None,
    27	            primary_v6: None,
    28	        },
    29	    );
    30	    forwarding
    31	}
    32	fn test_decision() -> SessionDecision {
    33	    SessionDecision {
    34	        resolution: ForwardingResolution {
    35	            disposition: ForwardingDisposition::ForwardCandidate,
    36	            local_ifindex: 0,
    37	            egress_ifindex: 80,
    38	            tx_ifindex: 11,
    39	            tunnel_endpoint_id: 0,
    40	            next_hop: None,
    41	            neighbor_mac: None,
    42	            src_mac: None,
    43	            tx_vlan_id: 80,
    44	        },
    45	        nat: NatDecision::default(),
    46	    }
    47	}
    48	
    49	fn test_forwarding_decision_to_bound_ifindex(tx_ifindex: i32) -> SessionDecision {
    50	    SessionDecision {
    51	        resolution: ForwardingResolution {
    52	            disposition: ForwardingDisposition::ForwardCandidate,
    53	            local_ifindex: 0,
    54	            egress_ifindex: 80,
    55	            tx_ifindex,
    56	            tunnel_endpoint_id: 0,
    57	            next_hop: None,
    58	            neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    59	            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
    60	            tx_vlan_id: 0,
    61	        },
    62	        nat: NatDecision::default(),
    63	    }
    64	}
    65	
    66	fn test_pending_forward_request(
    67	    addr_family: u8,
    68	    cos_tx_selection_resolved: bool,
    69	) -> PendingForwardRequest {
    70	    PendingForwardRequest {
    71	        target_ifindex: 11,
    72	        target_binding_index: None,
    73	        ingress_queue_id: 0,
    74	        desc: XdpDesc {
    75	            addr: 0,
    76	            len: 64,
    77	            options: 0,
    78	        },
    79	        frame: PendingForwardFrame::Live,
    80	        meta: ForwardPacketMeta {
    81	            addr_family,
    82	            ..ForwardPacketMeta::default()
    83	        },
    84	        decision: test_decision(),
    85	        apply_nat_on_fabric: false,
    86	        expected_ports: None,
    87	        flow_key: None,
    88	        nat64_reverse: None,
    89	        cos_queue_id: None,
    90	        dscp_rewrite: None,
    91	        cos_tx_selection_resolved,
    92	    }
    93	}
    94	
    95	fn test_live_forward_request_for_frame(
    96	    frame_len: usize,
    97	    decision: SessionDecision,
    98	) -> PendingForwardRequest {
    99	    PendingForwardRequest {
   100	        target_ifindex: decision.resolution.tx_ifindex,
   101	        target_binding_index: None,
   102	        ingress_queue_id: 0,
   103	        desc: XdpDesc {
   104	            addr: 0,
   105	            len: frame_len as u32,
   106	            options: 0,
   107	        },
   108	        frame: PendingForwardFrame::Live,
   109	        meta: ForwardPacketMeta {
   110	            ingress_ifindex: 11,
   111	            l3_offset: 14,
   112	            l4_offset: 34,
   113	            pkt_len: frame_len as u16,
   114	            addr_family: libc::AF_INET as u8,
   115	            protocol: PROTO_TCP,
   116	            ..ForwardPacketMeta::default()
   117	        },
   118	        decision,
   119	        apply_nat_on_fabric: false,
   120	        expected_ports: None,
   121	        flow_key: Some(test_session_key(12345, 443)),
   122	        nat64_reverse: None,
   123	        cos_queue_id: None,
   124	        dscp_rewrite: None,
   125	        cos_tx_selection_resolved: true,
   126	    }
   127	}
   128	
   129	fn test_cos_fast_interfaces(
   130	    egress_ifindex: i32,
   131	    default_queue: u8,
   132	    shared_exact_queues: &[(u8, bool)],
   133	) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
   134	    // Legacy fixture: shared_exact AND shared_queue_lease set together.
   135	    // For the post-#1598 decoupled case where a queue can be
   136	    // shared_exact=true with NO lease (non-exact uncapped class), use
   137	    // `test_cos_fast_interfaces_decoupled` below.
   138	    let decoupled: Vec<(u8, bool, bool)> = shared_exact_queues
   139	        .iter()
   140	        .copied()
   141	        .map(|(queue_id, shared_exact)| (queue_id, shared_exact, shared_exact))
   142	        .collect();
   143	    test_cos_fast_interfaces_decoupled(egress_ifindex, default_queue, &decoupled)
   144	}
   145	
   146	fn test_cos_fast_interfaces_decoupled(
   147	    egress_ifindex: i32,
   148	    default_queue: u8,
   149	    queues: &[(u8, bool, bool)],
   150	) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
   151	    // Each tuple: (queue_id, shared_exact, has_lease).
   152	    // The pair (true, false) models the #1598 non-exact uncapped case:
   153	    // the routing-level shared_exact flag is set, but the
   154	    // exact-only `shared_queue_lease` is absent.
   155	    let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
   156	    let mut queue_fast_path = Vec::new();
   157	    for (idx, (queue_id, shared_exact, has_lease)) in queues.iter().copied().enumerate() {
   158	        queue_index_by_id[usize::from(queue_id)] = idx as u16;
   159	        queue_fast_path.push(WorkerCoSQueueFastPath {
   160	            shared_exact,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/frame/tests.rs | sed -n '2760,2860p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2760	        &ForwardingState::default(),
  2761	        Some(&flow),
  2762	        None,
  2763	        false,
  2764	        0,
  2765	    )
  2766	    .expect("request");
  2767	    assert_eq!(req.expected_ports, Some((54688, 5201)));
  2768	}
  2769	
  2770	#[test]
  2771	fn build_live_forward_request_marks_session_fabric_redirect_for_nat_and_zone() {
  2772	    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
  2773	    let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
  2774	    let zone_redirect =
  2775	        resolve_zone_encoded_fabric_redirect(&forwarding, "wan").expect("zone redirect");
  2776	    let mut area = MmapArea::new(256).expect("mmap");
  2777	    area.slice_mut(0, 64).expect("slice").fill(0xaa);
  2778	    let ingress_ident = BindingIdentity {
  2779	        slot: 0,
  2780	        queue_id: 0,
  2781	        worker_id: 0,
  2782	        interface: Arc::<str>::from("fab0"),
  2783	        ifindex: 21,
  2784	    };
  2785	    let meta = UserspaceDpMeta {
  2786	        magic: USERSPACE_META_MAGIC,
  2787	        version: USERSPACE_META_VERSION,
  2788	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  2789	        l3_offset: 14,
  2790	        l4_offset: 34,
  2791	        addr_family: libc::AF_INET as u8,
  2792	        protocol: PROTO_TCP,
  2793	        flow_src_port: 5201,
  2794	        flow_dst_port: 44278,
  2795	        ..UserspaceDpMeta::default()
  2796	    };
  2797	    let decision = SessionDecision {
  2798	        resolution: fabric_redirect,
  2799	        nat: NatDecision {
  2800	            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
  2801	            ..NatDecision::default()
  2802	        },
  2803	    };
  2804	    let flow = SessionFlow {
  2805	        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
  2806	        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
  2807	        forward_key: SessionKey {
  2808	            addr_family: libc::AF_INET as u8,
  2809	            protocol: PROTO_TCP,
  2810	            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
  2811	            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
  2812	            src_port: 5201,
  2813	            dst_port: 44278,
  2814	        },
  2815	    };
  2816	
  2817	    let req = build_live_forward_request(
  2818	        &area,
  2819	        &WorkerBindingLookup::default(),
  2820	        0,
  2821	        &ingress_ident,
  2822	        XdpDesc {
  2823	            addr: 0,
  2824	            len: 64,
  2825	            options: 0,
  2826	        },
  2827	        meta,
  2828	        &decision,
  2829	        &forwarding,
  2830	        Some(&flow),
  2831	        Some(TEST_WAN_ZONE_ID),
  2832	        true,
  2833	        0,
  2834	    )
  2835	    .expect("request");
  2836	
  2837	    assert!(req.apply_nat_on_fabric);
  2838	    assert_eq!(
  2839	        req.decision.resolution.disposition,
  2840	        ForwardingDisposition::FabricRedirect
  2841	    );
  2842	    assert_eq!(req.decision.resolution.src_mac, zone_redirect.src_mac);
  2843	}
  2844	
  2845	#[test]
  2846	fn build_live_forward_request_caches_target_binding_index() {
  2847	    let mut area = MmapArea::new(256).expect("mmap");
  2848	    area.slice_mut(0, 64).expect("slice").fill(0xaa);
  2849	    let ingress_ident = BindingIdentity {
  2850	        slot: 7,
  2851	        queue_id: 3,
  2852	        worker_id: 0,
  2853	        interface: Arc::<str>::from("ge-0-0-1"),
  2854	        ifindex: 10,
  2855	    };
  2856	    let meta = UserspaceDpMeta {
  2857	        magic: USERSPACE_META_MAGIC,
  2858	        version: USERSPACE_META_VERSION,
  2859	        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
  2860	        l3_offset: 14,

exec
/bin/bash -lc "rg -n \"FabricRedirect|maybe_reinject|no XSK|missing.*egress|slow_path\" docs/research/1913-fromframe-filter docs -g '*.md'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:7:1. **Allow-list divergence is real.** `tx/dispatch/slow_path.rs:90` filters
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:9:   `_from_frame` variant (slow_path.rs:129+) has NO such filter. CONFIRMED.
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:18:   `maybe_reinject_slow_path_from_frame`: `extract_l3_packet_with_nat`
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:22:   flow → does NOT fire; `slow_path.enqueue(packet)` → kernel TUN → kernel
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:32:   with `request.decision` whose disposition is `FabricRedirect` (guarded by
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:33:   `if request.decision.resolution.disposition == FabricRedirect` at :223),
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:34:   and the sibling `else` at :238 uses the FILTERED wrapper. FabricRedirect is
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:39:6. **Path C is correctly fatal.** The wrapper `maybe_reinject_slow_path` takes
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:66:`ForwardingDisposition::is_slow_path_eligible` on `types/forwarding.rs`
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:69:(:264-283). Free-fn in slow_path.rs is fine too; this is a nit.
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:75:`record_slow_path_accept` to fire for these dispositions — there is not (the
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:76:`_ => {}` arm in `record_slow_path_accept` means PolicyDenied/HAInactive/
docs/session-sync-architecture.md:275:- `FabricRedirect` with `!FabricIngress`: always synced even if the local node
docs/session-sync-architecture.md:283:The filtering fields on `SessionDeltaInfo` are `FabricRedirect` and
docs/session-sync-architecture.md:406:- v3 (current): Corrected delta filtering field names (`FabricRedirect` +
docs/research/1913-fromframe-filter/plan.md:1:# Plan of Action — #1913: trailing `maybe_reinject_slow_path_from_frame` runs for ALL non-forward dispositions (incl. PolicyDenied)
docs/research/1913-fromframe-filter/plan.md:14:**unconditional** call to `maybe_reinject_slow_path_from_frame(.., packet_frame,
docs/research/1913-fromframe-filter/plan.md:19:`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).
docs/research/1913-fromframe-filter/plan.md:27:exists ONLY in the desc-based wrapper `maybe_reinject_slow_path`
docs/research/1913-fromframe-filter/plan.md:28:(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90`). The `_from_frame`
docs/research/1913-fromframe-filter/plan.md:29:variant (`slow_path.rs:129+`) has **no disposition filter** — it goes
docs/research/1913-fromframe-filter/plan.md:44:(`:2802`) and then unconditionally `maybe_reinject_slow_path_from_frame(...,
docs/research/1913-fromframe-filter/plan.md:45:packet_frame, meta, decision, "slow_path", ...)` at `:2814`. Per-arm exit
docs/research/1913-fromframe-filter/plan.md:55:| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `ForwardCandidate`/`FabricRedirect`/`NextTableUnsupported` |
docs/research/1913-fromframe-filter/plan.md:67:Tracing `maybe_reinject_slow_path_from_frame` (slow_path.rs:129+) for a
docs/research/1913-fromframe-filter/plan.md:78:4. `slow_path.cloned()` — present in production. → not the drop door.
docs/research/1913-fromframe-filter/plan.md:79:5. `slow_path.enqueue(packet)` → writes the raw L3 packet to the slow-path
docs/research/1913-fromframe-filter/plan.md:85:`record_slow_path_accept` (umem/mod.rs:941) bumps generic
docs/research/1913-fromframe-filter/plan.md:86:`slow_path_packets`/`slow_path_bytes` and hits the `_ => {}` arm (no
docs/research/1913-fromframe-filter/plan.md:108:`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
docs/research/1913-fromframe-filter/plan.md:145:`maybe_reinject_slow_path_from_frame` has **5 production call sites** (grep):
docs/research/1913-fromframe-filter/plan.md:146:- `slow_path.rs:61` (build-failure fallback, via `handle_forward_build_failure`)
docs/research/1913-fromframe-filter/plan.md:147:- `slow_path.rs:113` (the desc-wrapper's tail, AFTER its own allow-list filter)
docs/research/1913-fromframe-filter/plan.md:149:- `tx/dispatch/mod.rs:225` (**"no XSK binding" fallback — passes
docs/research/1913-fromframe-filter/plan.md:150:  `FabricRedirect`, which is NOT in the allow-list, ON PURPOSE**)
docs/research/1913-fromframe-filter/plan.md:154:variant to reinject a `FabricRedirect` when the target binding is missing —
docs/research/1913-fromframe-filter/plan.md:156:`maybe_reinject_slow_path` for the desc path, which would REJECT
docs/research/1913-fromframe-filter/plan.md:157:`FabricRedirect`. The `_from_frame` choice there is the bypass. So:
docs/research/1913-fromframe-filter/plan.md:160:> `dispatch/mod.rs:225` FabricRedirect fallback** (FabricRedirect is not in
docs/research/1913-fromframe-filter/plan.md:179:  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
docs/research/1913-fromframe-filter/plan.md:182:  the gate lives, at the call site and in `tx/dispatch/slow_path.rs`.
docs/research/1913-fromframe-filter/plan.md:198:disposition_is_slow_path_eligible(d: ForwardingDisposition) -> bool` (or
docs/research/1913-fromframe-filter/plan.md:199:`ForwardingDisposition::is_slow_path_eligible(self)`) in
docs/research/1913-fromframe-filter/plan.md:200:`tx/dispatch/slow_path.rs` (or on the enum in `types/forwarding.rs`). Then:
docs/research/1913-fromframe-filter/plan.md:202:1. Replace the inline `matches!(...)` in the wrapper `maybe_reinject_slow_path`
docs/research/1913-fromframe-filter/plan.md:203:   (slow_path.rs:90) with a call to the shared predicate (no behavior change —
docs/research/1913-fromframe-filter/plan.md:207:   if disposition_is_slow_path_eligible(decision.resolution.disposition) {
docs/research/1913-fromframe-filter/plan.md:208:       maybe_reinject_slow_path_from_frame(...);
docs/research/1913-fromframe-filter/plan.md:229:Add the allow-list to `maybe_reinject_slow_path_from_frame` itself.
docs/research/1913-fromframe-filter/plan.md:232:- **Cons / FATAL**: breaks `dispatch/mod.rs:225`, which passes `FabricRedirect`
docs/research/1913-fromframe-filter/plan.md:237:### Path C — convert the trailing `_from_frame` call to the filtered wrapper `maybe_reinject_slow_path`
docs/research/1913-fromframe-filter/plan.md:261:`dispatch/mod.rs:225` FabricRedirect bypass untouched. Leave the
docs/research/1913-fromframe-filter/plan.md:268:1. `types/forwarding.rs` (or `tx/dispatch/slow_path.rs`): add
docs/research/1913-fromframe-filter/plan.md:269:   `pub(in crate::afxdp) const fn is_slow_path_eligible` over the allow-list
docs/research/1913-fromframe-filter/plan.md:272:   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
docs/research/1913-fromframe-filter/plan.md:273:2. `slow_path.rs:90`: replace the inline `matches!` with the predicate (pure
docs/research/1913-fromframe-filter/plan.md:285:- Today the leak is invisible (generic `slow_path_packets` only). After the
docs/research/1913-fromframe-filter/plan.md:290:- Optional: a `slow_path_disposition_filtered` counter to make the
docs/research/1913-fromframe-filter/plan.md:298:- **T1 (the bug)**: `maybe_reinject_slow_path_from_frame` direct call is NOT
docs/research/1913-fromframe-filter/plan.md:300:  the predicate: `is_slow_path_eligible(PolicyDenied) == false`,
docs/research/1913-fromframe-filter/plan.md:303:  `(FabricRedirect|ForwardCandidate) == false`.
docs/research/1913-fromframe-filter/plan.md:304:- **T2 (wrapper SSOT)**: the wrapper `maybe_reinject_slow_path` with a
docs/research/1913-fromframe-filter/plan.md:310:  fixture. If feasible, assert `slow_path_packets == 0` and the policy_deny
docs/research/1913-fromframe-filter/plan.md:314:- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
docs/multi-wan.md:63:  programming fails (missing egress link at boot, rule/route add
docs/userspace-cold-start-resolution.md:55:did `XDP_PASS` (kernel forwarding), so no XSK packets ever arrived —
docs/session-sync-design.md:18:filtering by `FabricRedirect`/`FabricIngress`/`local_delivery`, and readiness
docs/session-sync-design.md:83:- stale-owner `FabricRedirect` exceptions
docs/session-sync-design.md:508:  [20]    Flags (bit0=FabricRedirect, bit1=FabricIngress, bit2=IsReverse)
docs/session-sync-design.md:533:  [N+2]   Flags (bit0=FabricRedirect, bit1=FabricIngress)
docs/phases.md:1713:| `pkg/api/types.go` | `FabricRedirects` field in GlobalStats |
docs/research/1881-gre-frozen-state/codex-plan-r2.md:12:   Current loop checks `stop` only outside the delivery-drain loop: [userspace-dp/src/afxdp/tunnel.rs:52](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs:52), then drains until `Empty`/`Disconnected`: [userspace-dp/src/afxdp/tunnel.rs:53](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs:53). Producers load and clone senders per packet: [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159), [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:167](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:167), and the queue is large: [userspace-dp/src/afxdp/mod.rs:313](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/mod.rs:313).  
docs/research/1881-gre-frozen-state/codex-plan-r2.md:13:   Store #1 removes stale senders before stop, so new producers cannot enqueue; old cloned senders are bounded by the new inner-loop stop check. `Disconnected` is already tolerated: [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:183](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:183).
docs/research/1881-gre-frozen-state/codex-plan-r2.md:23:1. **Parked delivery writes:** ratified. I did not find a harmful trace beyond bounded stale/in-flight delivery. The delivery path is local-delivery only: [slow_path.rs:156](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156), and the generic tunnel-marked slow-path leak gate remains after it: [slow_path.rs:198](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:198). Removed/mode-flipped endpoints stop matching new GRE decap state, and residual cloned-sender races are bounded by store #1 plus the drain stop check.
docs/research/1881-gre-frozen-state/codex-plan-r2.md:25:2. **Two-store reconcile:** acceptable. Workers load the delivery map at the slow-path point, not once for a long batch: [slow_path.rs:159](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159). Between stores, fail-closed drops/unavailable delivery are acceptable.
docs/archived/failover-hardening-progress.md:282:  - `disposition=FabricRedirect`
docs/archived/failover-hardening-progress.md:401:  - `missing_neighbor ingress-ifindex=4 egress-ifindex=13 next-hop=172.16.80.200 flow=172.16.80.8:58574->172.16.80.200:5201 zones=lan->wan`
docs/research/1881-gre-frozen-state/claude-smr-plan-r1.md:24:- F3 inbound half: `tx/dispatch/slow_path.rs:157-198` — LocalDelivery
docs/research/1881-gre-frozen-state/claude-smr-plan-r1.md:29:- Q5 (delivery swap race): `slow_path.rs:184-196` already tolerates
docs/research/1881-gre-frozen-state/agy-plan-r1.md:16:    Adding a tunnel does not trigger a full binding plan reconcile. The same-plan snapshot refresh ignores `self.tunnel_sources`, so no reader thread is spawned for the new TUN device. Because the coordinator does not publish a `SyncSender` for the new interface index to `local_tunnel_deliveries` ([userspace-dp/src/afxdp/coordinator/mod.rs:614](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs#L614)), any incoming decapsulated tunnel packet hits a lookup miss at [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:161](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L161) and is dropped.
docs/research/1881-gre-frozen-state/agy-plan-r1.md:43:    Rebuild-after-join + single store is fully sufficient. Workers retrieve the `SyncSender` dynamically *for each packet* via [local_tunnel_deliveries.load()](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L159-L162). If a thread is stopped and joined during a reconcile, its receiver is dropped. Any worker trying to send to a cloned sender during this transition will get `Err(TrySendError::Disconnected)` ([userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:183](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L183)), which is handled safely by logging a `local_tunnel_delivery_unavailable` exception. Once the map is swapped, workers retrieve the new sender.
docs/archived/userspace-failover-hardening-plan.md:101:  - `session_miss -> missing_neighbor -> slow_path`
docs/archived/userspace-failover-hardening-plan.md:875:   `FabricRedirect`.
docs/archived/userspace-failover-hardening-plan.md:887:  `session_miss -> slow_path`
docs/archived/userspace-failover-hardening-plan.md:893:- The next failure is no longer `session_miss -> slow_path`; it is
docs/research/1881-gre-frozen-state/codex-plan-r1.md:7:   The plan claims stop+join is bounded by one loop iteration, but the loop checks `stop` only at the outer loop: `userspace-dp/src/afxdp/tunnel.rs:52`. Before the read path, it drains `delivery_rx` until `Empty` or `Disconnected`: `tunnel.rs:53-70`. Workers can keep obtaining the old sender while it remains published: `tx/dispatch/slow_path.rs:156-167`; send failures are only handled for full/disconnected channels: `slow_path.rs:171-183`. The queue is large enough to sustain the race: `userspace-dp/src/afxdp/mod.rs:313`. Because the plan republishes the delivery map after join, a busy inbound local-delivery stream can keep the receiver non-empty and invalidate the control-thread join budget.
docs/archived/userspace-failover-next-steps.md:57:- cached `FabricRedirect` flow-cache hits now use the same per-flow fabric queue hash as the slow path instead of inheriting ingress queue affinity
docs/archived/userspace-failover-next-steps.md:74:- after switching cached `FabricRedirect` hits to the flow-hash queue selector, the same hardened one-cycle failover gate passed without collapse
docs/archived/userspace-failover-next-steps.md:278:  - `disposition=FabricRedirect`
docs/research/1881-gre-frozen-state/agy-plan-r2.md:37:I will search for `local_tunnel_deliveries` in `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` to examine how workers access the delivery channels and handle disconnected senders.
docs/research/1881-gre-frozen-state/agy-plan-r2.md:38:I will view `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` around line 150 to check how `local_tunnel_deliveries` is accessed and how send failures are handled.
docs/research/1881-gre-frozen-state/agy-plan-r2.md:78:1. **Workers Egress**: Workers lookup and clone delivery channels *per-packet* at [slow_path.rs:159-162](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L159-L162).
docs/research/1881-gre-frozen-state/agy-plan-r2.md:83:6. **Cleanup**: The thread exits and drops its `Receiver`, disconnecting the channel. Any remaining worker holding the old map from before Store #1 gets `Disconnected` on `try_send` and handles it gracefully via exception logging at [slow_path.rs:183-195](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L183-L195).
docs/research/1881-gre-frozen-state/agy-plan-r2.md:111:Workers load `local_tunnel_deliveries` fresh *per packet* at [slow_path.rs:159-160](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L159-L160).
docs/research/1881-gre-frozen-state/agy-plan-r2.md:113:- If a worker holds the sender of a pruned thread during the transition, `try_send` returns `Disconnected` which is safely caught and recorded at [slow_path.rs:183](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L183). No stronger synchronization is required.
docs/pr/963-frame-builder/plan.md:59:- FabricRedirect vs ForwardCandidate disposition (1581–1593).
docs/pr/963-frame-builder/plan.md:271:   `disposition = FabricRedirect`, `apply_nat_on_fabric = false`,
docs/research/1881-gre-frozen-state/plan.md:128:| F3 | ADD a GRE tunnel at runtime | Go creates the persistent TUN anchor (`tunnel.go:124`), routes point at it, but no reader thread exists and `local_tunnel_deliveries` has no entry → local-origin blackhole AND inbound decapped-to-local delivery drop (`tx/dispatch/slow_path.rs:157-198` lookup miss falls to the #1873 R-C blanket gate → DROP). |
docs/research/1881-gre-frozen-state/plan.md:481:   (`slow_path.rs:184-196`) covers the residual race of a map Arc
docs/research/1881-gre-frozen-state/plan.md:616:   packet at `slow_path.rs:159-162`.)
docs/research/1881-gre-frozen-state/claude-smr-plan-r2.md:18:   to the channel's map key (`tx/dispatch/slow_path.rs:156-162`).
docs/research/1881-gre-frozen-state/claude-smr-plan-r2.md:51:(`slow_path.rs:159-162`) cannot obtain the stale sender; residual
docs/research/1921-virtio-mq-bind/plan.md:215:  channels only when no XSK is bound (fresh start, or post-`stop_workers`).
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:7:1. **Allow-list divergence is real.** `tx/dispatch/slow_path.rs:90` filters
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:9:   `_from_frame` variant (slow_path.rs:129+) has NO such filter. CONFIRMED.
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:18:   `maybe_reinject_slow_path_from_frame`: `extract_l3_packet_with_nat`
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:22:   flow → does NOT fire; `slow_path.enqueue(packet)` → kernel TUN → kernel
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:32:   with `request.decision` whose disposition is `FabricRedirect` (guarded by
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:33:   `if request.decision.resolution.disposition == FabricRedirect` at :223),
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:34:   and the sibling `else` at :238 uses the FILTERED wrapper. FabricRedirect is
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:39:6. **Path C is correctly fatal.** The wrapper `maybe_reinject_slow_path` takes
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:66:`ForwardingDisposition::is_slow_path_eligible` on `types/forwarding.rs`
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:69:(:264-283). Free-fn in slow_path.rs is fine too; this is a nit.
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:75:`record_slow_path_accept` to fire for these dispositions — there is not (the
docs/research/1913-fromframe-filter/claude-smr-plan-r1.md:76:`_ => {}` arm in `record_slow_path_accept` means PolicyDenied/HAInactive/
docs/research/1913-fromframe-filter/plan.md:1:# Plan of Action — #1913: trailing `maybe_reinject_slow_path_from_frame` runs for ALL non-forward dispositions (incl. PolicyDenied)
docs/research/1913-fromframe-filter/plan.md:14:**unconditional** call to `maybe_reinject_slow_path_from_frame(.., packet_frame,
docs/research/1913-fromframe-filter/plan.md:19:`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).
docs/research/1913-fromframe-filter/plan.md:27:exists ONLY in the desc-based wrapper `maybe_reinject_slow_path`
docs/research/1913-fromframe-filter/plan.md:28:(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90`). The `_from_frame`
docs/research/1913-fromframe-filter/plan.md:29:variant (`slow_path.rs:129+`) has **no disposition filter** — it goes
docs/research/1913-fromframe-filter/plan.md:44:(`:2802`) and then unconditionally `maybe_reinject_slow_path_from_frame(...,
docs/research/1913-fromframe-filter/plan.md:45:packet_frame, meta, decision, "slow_path", ...)` at `:2814`. Per-arm exit
docs/research/1913-fromframe-filter/plan.md:55:| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `ForwardCandidate`/`FabricRedirect`/`NextTableUnsupported` |
docs/research/1913-fromframe-filter/plan.md:67:Tracing `maybe_reinject_slow_path_from_frame` (slow_path.rs:129+) for a
docs/research/1913-fromframe-filter/plan.md:78:4. `slow_path.cloned()` — present in production. → not the drop door.
docs/research/1913-fromframe-filter/plan.md:79:5. `slow_path.enqueue(packet)` → writes the raw L3 packet to the slow-path
docs/research/1913-fromframe-filter/plan.md:85:`record_slow_path_accept` (umem/mod.rs:941) bumps generic
docs/research/1913-fromframe-filter/plan.md:86:`slow_path_packets`/`slow_path_bytes` and hits the `_ => {}` arm (no
docs/research/1913-fromframe-filter/plan.md:108:`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
docs/research/1913-fromframe-filter/plan.md:145:`maybe_reinject_slow_path_from_frame` has **5 production call sites** (grep):
docs/research/1913-fromframe-filter/plan.md:146:- `slow_path.rs:61` (build-failure fallback, via `handle_forward_build_failure`)
docs/research/1913-fromframe-filter/plan.md:147:- `slow_path.rs:113` (the desc-wrapper's tail, AFTER its own allow-list filter)
docs/research/1913-fromframe-filter/plan.md:149:- `tx/dispatch/mod.rs:225` (**"no XSK binding" fallback — passes
docs/research/1913-fromframe-filter/plan.md:150:  `FabricRedirect`, which is NOT in the allow-list, ON PURPOSE**)
docs/research/1913-fromframe-filter/plan.md:154:variant to reinject a `FabricRedirect` when the target binding is missing —
docs/research/1913-fromframe-filter/plan.md:156:`maybe_reinject_slow_path` for the desc path, which would REJECT
docs/research/1913-fromframe-filter/plan.md:157:`FabricRedirect`. The `_from_frame` choice there is the bypass. So:
docs/research/1913-fromframe-filter/plan.md:160:> `dispatch/mod.rs:225` FabricRedirect fallback** (FabricRedirect is not in
docs/research/1913-fromframe-filter/plan.md:179:  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
docs/research/1913-fromframe-filter/plan.md:182:  the gate lives, at the call site and in `tx/dispatch/slow_path.rs`.
docs/research/1913-fromframe-filter/plan.md:198:disposition_is_slow_path_eligible(d: ForwardingDisposition) -> bool` (or
docs/research/1913-fromframe-filter/plan.md:199:`ForwardingDisposition::is_slow_path_eligible(self)`) in
docs/research/1913-fromframe-filter/plan.md:200:`tx/dispatch/slow_path.rs` (or on the enum in `types/forwarding.rs`). Then:
docs/research/1913-fromframe-filter/plan.md:202:1. Replace the inline `matches!(...)` in the wrapper `maybe_reinject_slow_path`
docs/research/1913-fromframe-filter/plan.md:203:   (slow_path.rs:90) with a call to the shared predicate (no behavior change —
docs/research/1913-fromframe-filter/plan.md:207:   if disposition_is_slow_path_eligible(decision.resolution.disposition) {
docs/research/1913-fromframe-filter/plan.md:208:       maybe_reinject_slow_path_from_frame(...);
docs/research/1913-fromframe-filter/plan.md:229:Add the allow-list to `maybe_reinject_slow_path_from_frame` itself.
docs/research/1913-fromframe-filter/plan.md:232:- **Cons / FATAL**: breaks `dispatch/mod.rs:225`, which passes `FabricRedirect`
docs/research/1913-fromframe-filter/plan.md:237:### Path C — convert the trailing `_from_frame` call to the filtered wrapper `maybe_reinject_slow_path`
docs/research/1913-fromframe-filter/plan.md:261:`dispatch/mod.rs:225` FabricRedirect bypass untouched. Leave the
docs/research/1913-fromframe-filter/plan.md:268:1. `types/forwarding.rs` (or `tx/dispatch/slow_path.rs`): add
docs/research/1913-fromframe-filter/plan.md:269:   `pub(in crate::afxdp) const fn is_slow_path_eligible` over the allow-list
docs/research/1913-fromframe-filter/plan.md:272:   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
docs/research/1913-fromframe-filter/plan.md:273:2. `slow_path.rs:90`: replace the inline `matches!` with the predicate (pure
docs/research/1913-fromframe-filter/plan.md:285:- Today the leak is invisible (generic `slow_path_packets` only). After the
docs/research/1913-fromframe-filter/plan.md:290:- Optional: a `slow_path_disposition_filtered` counter to make the
docs/research/1913-fromframe-filter/plan.md:298:- **T1 (the bug)**: `maybe_reinject_slow_path_from_frame` direct call is NOT
docs/research/1913-fromframe-filter/plan.md:300:  the predicate: `is_slow_path_eligible(PolicyDenied) == false`,
docs/research/1913-fromframe-filter/plan.md:303:  `(FabricRedirect|ForwardCandidate) == false`.
docs/research/1913-fromframe-filter/plan.md:304:- **T2 (wrapper SSOT)**: the wrapper `maybe_reinject_slow_path` with a
docs/research/1913-fromframe-filter/plan.md:310:  fixture. If feasible, assert `slow_path_packets == 0` and the policy_deny
docs/research/1913-fromframe-filter/plan.md:314:- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
docs/issues/issue-history.md:38:- In interface mode, treat missing `snat_egress_ips` entry as allocation failure (drop/counter), not pool fallback.
docs/issues/issue-history.md:4428:When a reverse-NAT reply packet (server → SNAT address) can't be forwarded directly due to a missing neighbor MAC, `maybe_reinject_slow_path` injects the packet into the TUN device **without reversing the NAT**. The kernel sees `dst=firewall's own SNAT IP`, delivers it locally, and the reply never reaches the original client.
docs/issues/issue-history.md:4435:4. `maybe_reinject_slow_path` sends raw `{src=172.16.80.200, dst=172.16.80.8}` to TUN
docs/issues/issue-history.md:4452:- `userspace-dp/src/afxdp.rs` — `maybe_reinject_slow_path`, `extract_l3_packet`
docs/issues/issue-history.md:5481:This is exactly the kind of split-RG failback case the comment describes: a reverse companion previously synthesized as `FabricRedirect` can need to flip back to local forwarding when another RG becomes active.
docs/issues/issue-history.md:5493:This can leave reverse companions pinned to stale `FabricRedirect` or remote-owner behavior across split-RG activation/failback, which is directly relevant to the forwarding fragility still being debugged.
docs/issues/issue-history.md:6004:- The same function only syncs stale-owner `FabricRedirect` deltas under a special case.
docs/issues/issue-history.md:7706:Cached entries on the hot path can continue forwarding with a stale `ForwardCandidate`/`FabricRedirect` decision after `HAGroupRuntime::is_forwarding_active()` would already return false. That means established cached flows can keep using the local fast path after watchdog lease expiry instead of falling back to `HAInactive` and fabric redirect/slow-path re-resolution.
docs/issues/issue-history.md:7770:   resolve to FabricRedirect disposition
docs/issues/issue-history.md:7792:## #434 — Cached FabricRedirect flow-cache hits ignore apply_nat_on_fabric [CLOSED] (closed 2026-04-04)
docs/issues/issue-history.md:7795:Cached userspace flow-cache hits for `FabricRedirect` sessions do not consistently honor the cached `apply_nat_on_fabric` decision.
docs/issues/issue-history.md:7805:- preserve whether a cached descriptor represents a `FabricRedirect`
docs/issues/issue-history.md:8336:The failback path (node1→node0) still has a gap where the stream dies. The session on node0 needs to re-resolve from FabricRedirect back to ForwardCandidate (direct forward), but during this transition packets are dropped.
docs/issues/issue-history.md:9348:On a non-fabric ingress packet whose egress owner RG is inactive locally, new flow installation must use the same HA-enforced resolution as session hits: `HAInactive` should convert to zone-encoded `FabricRedirect`, not local WAN forwarding.
docs/issues/issue-history.md:9471:After the restart/deploy cycle on `loss`, standby `fw0` can get stuck with userspace forwarding armed but no XSK bindings ever becoming ready, which blocks explicit failover back to that node.
docs/issues/issue-history.md:9612:- `Last resolution: missing_neighbor ingress-ifindex=4 egress-ifindex=14 next-hop=172.16.80.200 flow=172.16.80.8:55280->172.16.80.200:5201 zones=lan->wan`
docs/issues/issue-history.md:10101:- `cargo test --manifest-path userspace-dp/Cargo.toml maybe_reinject_slow_path_records_extract_failure_for_invalid_desc -- --nocapture`
docs/issues/issue-history.md:17320:## #1065 — Bug: ForwardingDisposition::is_cacheable doc/code mismatch on FabricRedirect [CLOSED] (closed 2026-05-02)
docs/issues/issue-history.md:17324:In `afxdp/types/forwarding.rs` (was `afxdp/types/mod.rs` before #1064), `ForwardingDisposition::is_cacheable()` returns `true` for both `ForwardCandidate` and `FabricRedirect`:
docs/issues/issue-history.md:17330:        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
docs/issues/issue-history.md:17335:But the doc comment lists `FabricRedirect` under **Not cacheable** with this rationale:
docs/issues/issue-history.md:17337:> `FabricRedirect`: Targets a fabric overlay binding that differs from the normal egress binding. Fabric target selection depends on per-packet queue hashing and binding availability, which the cache entry cannot capture. Also, fabric sessions may flip back to `ForwardCandidate` after failback, making cached fabric entries stale.
docs/issues/issue-history.md:17340:- The code is wrong — `FabricRedirect` should NOT be cacheable per the doc reasoning. Remove it from the matches!() set.
docs/issues/issue-history.md:17341:- The doc is wrong — `FabricRedirect` IS cacheable. Move it to the "Cacheable" section and replace the rationale.
docs/issues/issue-history.md:17347:Which is correct? If `FabricRedirect` truly can't capture per-packet queue hashing, it shouldn't cache. If failback semantics are tolerated, it can.
docs/issues/issue-history.md:23423:That means authors can submit honest smoke evidence from the standard harness while still missing reverse-path and CoS-classification regressions.
docs/pr/1444-cli-presenters/plan.md:30:- **Codex r1**: `readFabricRedirectCounters` + `fabricRedirectCounters` type
docs/pr/1444-cli-presenters/plan.md:131:| `cli_show_cluster.go` (extend) | `fabricRedirectCounters` type (146), `readFabricRedirectCounters` (154) | Move (consumed at `:168`) |
docs/pr/1431-filter-cache-invariants/claude-smr-code-r1.md:172:`FabricRedirect`. `LocalDelivery` returns `false`. lo0 filter
docs/pr/1431-filter-cache-invariants/plan.md:270:`FabricRedirect`. `LocalDelivery`-disposition packets do not enter
docs/pr/1326-worker-loop-extract/plan.md:567:            slow_path.as_ref(),
docs/issues/pr-history.md:3386:- honor cached `apply_nat_on_fabric` decisions on `FabricRedirect` flow-cache hits
docs/issues/pr-history.md:4030:Before VRRP demotes an RG, send `preflight_demote_rg` to the Rust helper. This marks the RG as inactive in the flow cache and bumps the epoch, causing sessions to re-resolve from ForwardCandidate (direct) to FabricRedirect (fabric). Traffic shifts to the fabric path **before** the VIP moves, eliminating the forwarding gap.
docs/issues/pr-history.md:4083:- **Reorder cluster Secondary handler**: run userspace preflight (flow cache flush to `FabricRedirect`) BEFORE `ResignRG`. Previously VRRP resigned first, removing VIPs before traffic could shift to the fabric path.
docs/issues/pr-history.md:4907:- `go test ./pkg/daemon -run 'TestShouldSyncUserspaceDelta(SkipsMissingNeighborSeed|SkipsLocalDelivery|PrefersOwnerRG|FallsBackToZone|AllowsStaleOwnerFabricRedirect|DoesNotBypassFabricIngress)$' -count=1`
docs/issues/pr-history.md:5569:- cargo test --manifest-path userspace-dp/Cargo.toml maybe_reinject_slow_path_records_extract_failure_for_invalid_desc -- --nocapture
docs/issues/pr-history.md:6820:What was missing was explicit regression coverage for the predicate itself. The only existing asserts are inside `build_worker_cos_fast_interfaces_flattens_owner_and_lease_state`, which tests the whole flat-path assembly. A future perf or refactor slice that tweaks the threshold could flip classification for `5201` or `5202` without a single focused test firing.
docs/issues/pr-history.md:13851:\`dynamic_neighbor_status\`, \`cos_no_owner_binding_drops_total\`, \`recent_exceptions\`, \`recent_session_deltas\`, \`last_resolution\`, \`slow_path_status\`, \`drain_session_deltas\`, \`cos_statuses\`, \`filter_term_counters\`, \`worker_heartbeats\`, \`worker_count\`, \`worker_runtime_snapshots\`, \`identity_count\`, \`live_count\`, \`planned_counts\`, \`reconcile_debug\`.
docs/issues/pr-history.md:16423:## PR #1132 — #1065: doc fix — FabricRedirect IS cacheable (matches code) [MERGED] (merged 2026-05-02)
docs/issues/pr-history.md:16427:Closes #1065. Doc-only fix. The is_cacheable() match block has always included FabricRedirect; the doc rationale was stale (claimed it was 'not cacheable' due to per-packet hashing + failback staleness). The flow_cache RG-epoch invalidation handles staleness, so the code is correct — only the doc lagged.
docs/issues/pr-history.md:25464:- `cli_show_cluster.go` — `fabricRedirectCounters` type + `readFabricRedirectCounters` (single consumer at `:168`).
docs/issues/pr-history.md:25475:- Codex round-1: **PLAN-NEEDS-MAJOR** (`task-mpmuqaqp-wdbuti`) — 8 findings: redundant `cli_completion.go`, naming convention, misplaced `readFabricRedirectCounters`/`topTalkerEntry`, misplaced security helpers, 2k-file discipline violation on `cli_show_security.go`, dead-code accounting, build+test gates.
docs/issues/pr-history.md:25712:- `PreservedReconcileState` has exactly 2 fields (`synced_sessions` + `slow_path`); `had_live_workers` is local to teardown.
docs/issues/pr-history.md:27060:- `tx/dispatch/slow_path.rs` (292 LOC) — `handle_forward_build_failure`, `maybe_reinject_slow_path[_from_frame]`, `extract_l3_packet[_from_frame][_with_nat]`. Marked `#[cold] #[inline(never)]` per AGY round-2 finding D — `#[cold]` alone does not stop LLVM from inlining a single-caller helper and bloating the hot i-cache footprint; `#[inline(never)]` guarantees the cold body stays out-of-line.
docs/issues/pr-history.md:27080:Plan v3 specified a 5-submodule layout including `inplace_dispatch.rs` housing the 845-LOC Phase 8 body. This implementation lands the 3-submodule split only (`cos.rs`, `shared_recycle.rs`, `slow_path.rs`) and leaves the Phase 8 body in `mod.rs`. Justification:
docs/shared-umem-plan.md:319:- register no XSKMAP entries for the group until every socket is bound and
docs/shared-umem-plan.md:393:  group and registers no XSKMAP entries
docs/fabric-performance-optimizations.md:22:   result is `FabricRedirect`, the helper builds the fabric frame itself and
docs/fabric-performance-optimizations.md:48:3. Session lookup -> FabricRedirect (RG1/WAN owned by fw1)
docs/fabric-performance-optimizations.md:66:3. Session lookup -> FabricRedirect (RG2/LAN owned by fw0)
docs/fabric-performance-optimizations.md:126:1. Honor cached `apply_nat_on_fabric` decisions on `FabricRedirect` hits.
docs/fabric-performance-optimizations.md:198:- [x] FabricRedirect flow cache cacheable
docs/userspace-dataplane-cleanup-plan.md:459:   - `forward_build_slow_path`
docs/pr/678-hotpath-cuts/plan.md:169:       `shared_owner_rg_indexes`, `slow_path`,
docs/pr/678-hotpath-cuts/plan.md:273:  `screen_drops`, `slow_path_drops`, `flow_cache_*` all bump the same
docs/pr/1902-pending-neigh/reviewer-ids.md:35:(mod.rs:2853) → trailing `maybe_reinject_slow_path_from_frame`
docs/pr/1902-pending-neigh/reviewer-ids.md:52:`maybe_reinject_slow_path_from_frame` call at mod.rs:2814 runs for ALL
docs/pr/1902-pending-neigh/reviewer-ids.md:56:lives only in the desc-based `maybe_reinject_slow_path` wrapper
docs/pr/1902-pending-neigh/reviewer-ids.md:57:(slow_path.rs:90). Flagged to the parent for separate triage.
docs/pr/1902-pending-neigh/reviewer-ids.md:124:- #1913 — trailing `maybe_reinject_slow_path_from_frame` runs for ALL
docs/pr/1902-pending-neigh/plan.md:60:`maybe_reinject_slow_path_from_frame(packet_frame, meta, ..)`
docs/pr/1861-install-txn/claude-smr-code-r1.md:73:   `install_local_reverse == false` (FabricRedirect, non-fabric-ingress)
docs/pr/1443-tx-dispatch-modularize/plan.md:26:    fallback_to_slow_path = true;
docs/pr/1443-tx-dispatch-modularize/plan.md:34:`fallback_to_slow_path` are loop-local variables declared at
docs/pr/1443-tx-dispatch-modularize/plan.md:89:slow_path, shared_recycle).
docs/pr/1443-tx-dispatch-modularize/plan.md:162:   `slow_path.rs`, `shared_recycle.rs`. See §"Layout v2".
docs/pr/1443-tx-dispatch-modularize/plan.md:186:    `dispatch/slow_path.rs`.** Accepted. They were `pub(super)`
docs/pr/1443-tx-dispatch-modularize/plan.md:327:├── slow_path.rs                 — exception / reinjection / build-fail
docs/pr/1443-tx-dispatch-modularize/plan.md:329:│                                  maybe_reinject_slow_path,
docs/pr/1443-tx-dispatch-modularize/plan.md:330:│                                  maybe_reinject_slow_path_from_frame,
docs/pr/1443-tx-dispatch-modularize/plan.md:367:- `handle_forward_build_failure` (re-export from `slow_path.rs`)
docs/pr/1443-tx-dispatch-modularize/plan.md:372:- `maybe_reinject_slow_path` (re-export from `slow_path.rs`)
docs/pr/1443-tx-dispatch-modularize/plan.md:373:- `maybe_reinject_slow_path_from_frame` (re-export from
docs/pr/1443-tx-dispatch-modularize/plan.md:374:  `slow_path.rs`)
docs/pr/1443-tx-dispatch-modularize/plan.md:375:- `extract_l3_packet_with_nat` (re-export from `slow_path.rs`)
docs/pr/1443-tx-dispatch-modularize/plan.md:388:mod slow_path;
docs/pr/1443-tx-dispatch-modularize/plan.md:395:pub(in crate::afxdp) use slow_path::{
docs/pr/1443-tx-dispatch-modularize/plan.md:397:    maybe_reinject_slow_path,
docs/pr/1443-tx-dispatch-modularize/plan.md:398:    maybe_reinject_slow_path_from_frame,
docs/pr/1443-tx-dispatch-modularize/plan.md:401:pub(in crate::afxdp::tx) use slow_path::{
docs/pr/1443-tx-dispatch-modularize/plan.md:476:    /// loop-local `build_failed = true` and `fallback_to_slow_path
docs/pr/1443-tx-dispatch-modularize/plan.md:486:    /// 850-853 sets build_failed + fallback_to_slow_path (no
docs/pr/1443-tx-dispatch-modularize/plan.md:512:        fallback_to_slow_path = true;
docs/pr/1443-tx-dispatch-modularize/plan.md:526:Every helper in `cos.rs`, `frame.rs`, `slow_path.rs`,
docs/pr/1443-tx-dispatch-modularize/plan.md:546:| `slow_path.rs::handle_forward_build_failure` | `#[cold]` + `#[inline(never)]` | Build-failure path. v3 adds `#[inline(never)]` per AGY round-2 D: `#[cold]` alone does not prevent inlining |
docs/pr/1443-tx-dispatch-modularize/plan.md:547:| `slow_path.rs::maybe_reinject_slow_path` | `#[cold]` + `#[inline(never)]` | Reinjection path |
docs/pr/1443-tx-dispatch-modularize/plan.md:548:| `slow_path.rs::maybe_reinject_slow_path_from_frame` | `#[cold]` + `#[inline(never)]` | Reinjection path |
docs/pr/1443-tx-dispatch-modularize/plan.md:549:| `slow_path.rs::extract_l3_packet*` | (no marker) | Called by both hot and cold paths; let LLVM decide |
docs/pr/1328-coordinator-reconcile-split/plan.md:46:   `workers.live` empty, `slow_path == None`. (`last_reconcile_stage`
docs/pr/1328-coordinator-reconcile-split/plan.md:54:   `slow_path: Option<Arc<SlowPathReinjector>>`.
docs/pr/1328-coordinator-reconcile-split/plan.md:156:                               //  - rebuild_slow_path
docs/pr/1328-coordinator-reconcile-split/plan.md:191:    pub slow_path: Option<Arc<SlowPathReinjector>>,
docs/pr/1328-coordinator-reconcile-split/plan.md:214:            self, snapshot, bindings, preserved.slow_path,
docs/pr/1328-coordinator-reconcile-split/plan.md:310:   needed for the `preserve_healthy_slow_path` flow that follows),
docs/pr/1328-coordinator-reconcile-split/plan.md:382:     ArcSwap fields reset + slow_path = None + bpf_maps cleared +
docs/pr/1328-coordinator-reconcile-split/plan.md:390:     slow_path re-armed + ha.fabrics published + xsk/heartbeat/session
docs/pr/1328-coordinator-reconcile-split/plan.md:452:5. **`preserved_slow_path` lifetime.** Identical pattern — second
docs/pr/1328-coordinator-reconcile-split/plan.md:478:| Lifetime / borrow-checker | MEDIUM | `&mut self` plus `&mut [BindingStatus]` across phase boundaries means each new helper takes both. The two `Vec<…>` preserved fields (`synced_sessions`, `slow_path`) are passed by value through the `PreservedReconcileState`, so no lifetime extension is needed. Smoke: `cargo build --release` clean. |
docs/pr/1328-coordinator-reconcile-split/plan.md:494:   - `slow_path` is `None`.
docs/pr/1328-coordinator-reconcile-split/plan.md:545:   the struct (two fields: `synced_sessions` + `slow_path`) as a
docs/pr/963-frame-editor-redux/design.md:143:`MissingNeighbor` resolutions are non-cacheable; cached `FabricRedirect`
docs/pr/1885-vlan-slice/reviewer-ids.md:10:- Claude SMR (in-conversation): MERGE-READY. Hand-traced tagged offsets (TPID@12, TCI@14, ethertype@16, L3@18; old slice = outer[14..] = TCI tail — matches live strace 00 50 86 dd); structural proof that packet_frame can never be raw-with-inner-meta at the trailing chokepoint: packet_frame borrows owned_packet_frame, so any .take() on a CFG path reaching the 2778 use would be rejected by the borrow checker (NLL) — compilation is the proof. Removal loses only the redundant desc re-validation (desc already sliced at loop head) and corrects the double record_slow_path_accept.
docs/pr/1352-frame-build-rewrite-split/plan.md:1049:   == ForwardingDisposition::FabricRedirect ? apply_nat_on_fabric
docs/pr/945-context-object/plan.md:35:  `slow_path`, `local_tunnel_deliveries`, `recent_exceptions`,
docs/pr/945-context-object/plan.md:105:    pub slow_path: Option<&'a Arc<SlowPathReinjector>>,
docs/pr/1885-vlan-slice/plan.md:8:(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`).
docs/pr/1885-vlan-slice/plan.md:29:  -> maybe_reinject_slow_path(area, desc, meta, ...)
docs/pr/1885-vlan-slice/plan.md:51:   The arm's in-line `maybe_reinject_slow_path` call is fully redundant:
docs/pr/1885-vlan-slice/plan.md:53:   (`maybe_reinject_slow_path_from_frame(packet_frame, meta, ...)`,
docs/pr/1885-vlan-slice/plan.md:82:Delete the in-arm `maybe_reinject_slow_path(area, desc, …)` call from
docs/pr/1885-vlan-slice/plan.md:85:`maybe_reinject_slow_path_from_frame(packet_frame, meta, …)` chokepoint
docs/pr/1885-vlan-slice/plan.md:112:- `unencapsulated_local_delivery_reinjects_slow_path_exactly_once` —
docs/pr/1885-vlan-slice/plan.md:117:  `slow_path_drops` counter — pre-fix 2 attempts, fixed exactly 1.
docs/pr/1697-poll-descriptor-cold-path-split/plan.md:147:`ForwardCandidate | FabricRedirect`), so it can run per-packet on
docs/pr/1697-poll-descriptor-cold-path-split/plan.md:201:the repo's existing pattern at `tx/dispatch/slow_path.rs:23`).
docs/pr/1697-poll-descriptor-cold-path-split/plan.md:240:     FabricRedirect`. Host-bound traffic is low-rate vs transit, so
docs/pr/1881-gre-frozen-state/agy-code-r1.md:72:Workers load `local_tunnel_deliveries` into an `Arc` snapshot. A lookup returning `None` or a send returning `Disconnected` (e.g., if loaded before Store #1 but sent after the channel closed) is gracefully handled in `slow_path.rs:183-196` without panic or block.
docs/pr/1760-reverse-key-watch/claude-smr-code-r1.md:10:   same value under `FabricRedirect && !FabricIngress`; `reverse_wire_key`
docs/pr/1678-debuglog/plan.md:147:  build (`tx/dispatch/mod.rs` `build_failed` / `fallback_to_slow_path`).
docs/pr/1373-retire-ebpf-dataplane/README.md:266:| `pkg/cli/cli_show_cluster.go` | #1444 — `fabricRedirectCounters` type and `readFabricRedirectCounters` relocated from `cli.go`; still reads legacy `GlobalCtrFabric*` counter indices via `dataplane.Telemetry`. |
docs/pr/1873-tunnel-ids/claude-smr-code-r1.md:67:  `maybe_reinject_slow_path_from_frame`; no caller invokes
docs/pr/1873-tunnel-ids/claude-smr-code-r1.md:68:  `slow_path.enqueue` directly outside it (grep-verified across
docs/pr/1873-tunnel-ids/claude-smr-code-r1.md:71:  pins assert generic `slow_path_drops` stays 0, proving order.
docs/pr/1873-tunnel-ids/claude-smr-code-r1.md:82:  mirror — byte-for-byte parallel to `slow_path_rate_limited`'s
docs/pr/1873-tunnel-ids/plan.md:66:  them all (build failure `tx/dispatch/mod.rs:575,855`; FabricRedirect
docs/pr/1873-tunnel-ids/plan.md:72:  invariant at the `maybe_reinject_slow_path_from_frame` chokepoint.
docs/pr/1873-tunnel-ids/plan.md:113:  build sets `fallback_to_slow_path = true`
docs/pr/1873-tunnel-ids/plan.md:115:  `maybe_reinject_slow_path_from_frame` (`slow_path.rs:129`) has no
docs/pr/1873-tunnel-ids/plan.md:286:(`tx/dispatch/mod.rs:575,855` → `slow_path.rs:60-73`), FabricRedirect
docs/pr/1873-tunnel-ids/plan.md:298:`maybe_reinject_slow_path_from_frame` (every door above funnels
docs/pr/1873-tunnel-ids/plan.md:301:`local_ifindex`, never the generic TUN), before `slow_path.enqueue`
docs/pr/1873-tunnel-ids/plan.md:302:(`slow_path.rs:198`):
docs/pr/1873-tunnel-ids/plan.md:572:    (c) MissingNeighbor disposition, (d) FabricRedirect
docs/pr/1873-tunnel-ids/plan.md:671:   tunnel-marked frames)? `record_slow_path_accept` simply sees fewer

exec
/bin/bash -lc "rg -n \"FabricRedirect.*slow_path|slow_path.*FabricRedirect|no XSK binding|missing.*binding|from_frame.*FabricRedirect|maybe_reinject_slow_path_from_frame\" userspace-dp/src/afxdp/tests.rs userspace-dp/src/afxdp/tx/dispatch -g '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/tests.rs:4249:fn maybe_reinject_slow_path_from_frame_records_unavailable() {
userspace-dp/src/afxdp/tests.rs:4287:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:5371:        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:5441:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:56:    maybe_reinject_slow_path_from_frame,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:225:                    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:266:                "missing_egress_binding",
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:15:// - `maybe_reinject_slow_path_from_frame`,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:61:        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:113:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:129:pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(

codex
There is an additional Path B problem beyond the plan’s FabricRedirect example: `handle_forward_build_failure` funnels `ForwardCandidate` build failures through `_from_frame`, and the wrapper allow-list would reject `ForwardCandidate`. I’m verifying the call sites before I decide whether this is a required revision or just supporting evidence.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1020,1085p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1020	                                }
  1021	                                // Permit without policy check or session install.
  1022	                                // If NAT reversal was applied, the prebuilt frame
  1023	                                // is already queued. If not, fall through to slow-path.
  1024	                            } else if decision.resolution.disposition
  1025	                                == ForwardingDisposition::ForwardCandidate
  1026	                            {
  1027	                                let owner_rg_id =
  1028	                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
  1029	                                flow_cache_owner_rg_id = owner_rg_id;
  1030	                                // #850: allow-dns-reply admits sessionless DNS replies
  1031	                                // through policy (not around it). Always evaluate policy;
  1032	                                // the session-install step below is skipped only when
  1033	                                // the knob matches AND no NAT is required (to avoid
  1034	                                // orphan NAT state without a session anchor).
  1035	                                //
  1036	                                // #1620: cold-path latency histogram pre-eval gate.
  1037	                                // Per plan v4 §4.4: open a scoped &mut binding.cold_path
  1038	                                // borrow that ENDS before evaluate_policy_*, so no
  1039	                                // mutable cold_path borrow overlaps the policy call.
  1040	                                let (cp_sample_tag, cp_t_in) = {
  1041	                                    let cp = &mut binding.cold_path;
  1042	                                    cp.sample_phase = cp.sample_phase.wrapping_add(1);
  1043	                                    let tag = (cp.sample_phase
  1044	                                        & worker_ctx.cold_path_sample_mask)
  1045	                                        == 0;
  1046	                                    let t = if tag {
  1047	                                        crate::afxdp::cold_path_hist::sample_tsc_start()
  1048	                                    } else {
  1049	                                        0
  1050	                                    };
  1051	                                    (tag, t)
  1052	                                };
  1053	                                let policy_result = evaluate_policy_result_with_len(
  1054	                                    &worker_ctx.forwarding.policy,
  1055	                                    from_zone_id,
  1056	                                    to_zone_id,
  1057	                                    flow.src_ip,
  1058	                                    flow.dst_ip,
  1059	                                    flow.forward_key.protocol,
  1060	                                    flow.forward_key.src_port,
  1061	                                    flow.forward_key.dst_port,
  1062	                                    desc.len as u64,
  1063	                                );
  1064	                                // #1620: cold-path latency histogram post-eval record.
  1065	                                // q32-skip + wrapper_underflow_count per plan v4 §4.4.
  1066	                                if cp_sample_tag {
  1067	                                    let t_out =
  1068	                                        crate::afxdp::cold_path_hist::sample_tsc_end();
  1069	                                    let q32 = binding.cold_path.ns_per_tsc_q32;
  1070	                                    if q32 != 0 {
  1071	                                        let delta_tsc = t_out.saturating_sub(cp_t_in);
  1072	                                        let raw_ns =
  1073	                                            ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
  1074	                                        let baseline =
  1075	                                            binding.cold_path.wrapper_ns_baseline;
  1076	                                        let delta_ns = if raw_ns < baseline {
  1077	                                            binding.cold_path.wrapper_underflow_count =
  1078	                                                binding
  1079	                                                    .cold_path
  1080	                                                    .wrapper_underflow_count
  1081	                                                    .saturating_add(1);
  1082	                                            0
  1083	                                        } else {
  1084	                                            raw_ns - baseline
  1085	                                        };

exec
/bin/bash -lc "rg -n \"handle_forward_build_failure\\(|fallback_to_slow_path|build_failed|forward_build_slow_path\" userspace-dp/src/afxdp -g '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/umem/mod.rs:950:        if reason == "forward_build_slow_path" {
userspace-dp/src/afxdp/tests.rs:4296:        "forward_build_slow_path",
userspace-dp/src/afxdp/tests.rs:4348:    handle_forward_build_failure(
userspace-dp/src/afxdp/tests.rs:4375:        vec!["forward_build_failed", "slow_path_unavailable"]
userspace-dp/src/afxdp/tests.rs:4419:    handle_forward_build_failure(
userspace-dp/src/afxdp/tests.rs:4444:    assert_eq!(reasons, vec!["forward_build_failed"]);
userspace-dp/src/afxdp/tests.rs:4454:        "forward_build_slow_path",
userspace-dp/src/afxdp/tests.rs:5380:            "forward_build_slow_path",
userspace-dp/src/afxdp/tests.rs:5404:/// with fallback_to_slow_path = true) funnels through the same gate.
userspace-dp/src/afxdp/tests.rs:5410:    handle_forward_build_failure(
userspace-dp/src/afxdp/tests.rs:5450:        "forward_build_slow_path",
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:25:pub(in crate::afxdp) fn handle_forward_build_failure(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:37:    fallback_to_slow_path: bool,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:48:            fallback_to_slow_path,
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:54:        "forward_build_failed",
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:60:    if fallback_to_slow_path {
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:70:            "forward_build_slow_path",
userspace-dp/src/afxdp/tx/dispatch/mod.rs:275:        let mut build_failed = false;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:276:        let mut fallback_to_slow_path = false;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:352:                                build_failed = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:563:                                    build_failed = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:564:                                    fallback_to_slow_path = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:576:                                build_failed = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:577:                                fallback_to_slow_path = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:687:                                    build_failed = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:690:                            if build_failed {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:843:                                    build_failed = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:844:                                    fallback_to_slow_path = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:856:                                build_failed = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:857:                                fallback_to_slow_path = true;
userspace-dp/src/afxdp/tx/dispatch/mod.rs:886:        if build_failed {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:887:            handle_forward_build_failure(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:899:                fallback_to_slow_path,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '760,865p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
exec
/bin/bash -lc "nl -ba docs/research/1913-fromframe-filter/plan.md | sed -n '257,330p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   257	## 6. Recommended path
   258	
   259	**Path A.** Shared `const fn` predicate, gate at the `mod.rs:2814` call site,
   260	wrapper refactored to call the same predicate (SSOT). Leave the intentional
   261	`dispatch/mod.rs:225` FabricRedirect bypass untouched. Leave the
   262	MissingNeighbor buffered-duplicate behavior unchanged (document it; optional
   263	follow-up). Add an observability counter for the now-dropped
   264	PolicyDenied/HAInactive/DiscardRoute case if cheap (see §8).
   265	
   266	## 7. Implementation sketch (for the eventual /engineer pass — NOT executed here)
   267	
   268	1. `types/forwarding.rs` (or `tx/dispatch/slow_path.rs`): add
   269	   `pub(in crate::afxdp) const fn is_slow_path_eligible` over the allow-list
   270	   `LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported`, with a
   271	   doc comment stating the drop set (`PolicyDenied | HAInactive | DiscardRoute
   272	   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
   273	2. `slow_path.rs:90`: replace the inline `matches!` with the predicate (pure
   274	   refactor; no behavior change).
   275	3. `poll_descriptor/mod.rs:2814`: guard the trailing call with the predicate.
   276	   When the predicate is false, the frame is already counted by
   277	   `record_forwarding_disposition` (:2802) and recycled by the
   278	   `recycle_now` epilogue (:2852) — no leak, no double-count. Add a short
   279	   comment referencing #1913 + the eligibility predicate.
   280	4. (optional) bump a dedicated drop counter when the gate suppresses a
   281	   reinject, so the bypass-that-was is observable.
   282	
   283	## 8. Observability / telemetry
   284	
   285	- Today the leak is invisible (generic `slow_path_packets` only). After the
   286	  fix, the suppressed frames are counted via the existing
   287	  `record_forwarding_disposition` per-disposition counters
   288	  (`bump_discard_route`, `policy_deny`, `ha_inactive`) — already wired at
   289	  `:2802`. No NEW metric strictly required.
   290	- Optional: a `slow_path_disposition_filtered` counter to make the
   291	  "would-have-reinjected-but-gated" path explicit. Low value (the disposition
   292	  counters already tell the story); include only if a reviewer wants it.
   293	
   294	## 9. Test plan (for /engineer; describe only)
   295	
   296	Unit (in `userspace-dp/src/afxdp/tests.rs`, alongside the existing
   297	`tunnel_marked_*` tests):
   298	- **T1 (the bug)**: `maybe_reinject_slow_path_from_frame` direct call is NOT
   299	  the unit under test — the gate is at the call site, so add a test exercising
   300	  the predicate: `is_slow_path_eligible(PolicyDenied) == false`,
   301	  `(HAInactive) == false`, `(DiscardRoute) == false`,
   302	  `(LocalDelivery|NoRoute|MissingNeighbor|NextTableUnsupported) == true`,
   303	  `(FabricRedirect|ForwardCandidate) == false`.
   304	- **T2 (wrapper SSOT)**: the wrapper `maybe_reinject_slow_path` with a
   305	  `PolicyDenied` decision still early-returns with no enqueue (regression on
   306	  the existing wrapper filter, now via the shared predicate). Reuse the
   307	  existing wrapper test fixture.
   308	- **T3 (call-site integration)**: harder — exercising the full
   309	  `poll_binding_process_descriptor` PolicyDenied path requires the worker-ctx
   310	  fixture. If feasible, assert `slow_path_packets == 0` and the policy_deny
   311	  disposition counter == 1 for a denied transit frame. If the fixture is too
   312	  heavy, T1+T2 + a focused call-site assertion suffice (the call-site guard is
   313	  a one-line `if`, trivially reviewable).
   314	- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
   315	  reinjects (its `_from_frame` path is NOT gated by the predicate). Confirm via
   316	  the existing dispatch tests / add one if absent.
   317	
   318	Build/lint: `make build-userspace-dp`, `cargo test -p` the userspace-dp crate.
   319	
   320	## 10. Smoke / validation (for /engineer)
   321	
   322	- Deploy to `loss:xpf-userspace-fw0/fw1`, install a config with an explicit
   323	  zone-policy DENY for a transit flow, send cold-path packets matching the
   324	  denied flow, and confirm they are NOT forwarded (kernel-side capture on the
   325	  far side shows zero). Before the fix: a trickle leaks. After: zero.
   326	- Standard fast smoke (P12R iperf3 v4/v6 line-rate) to confirm no regression on
   327	  the permitted/forwarded path.
   328	- `make test-failover` is advisable since HAInactive is in scope (the residual-
   329	  HAInactive reinject change could affect standby behavior). Confirm zero-drop
   330	  failover unchanged.

 succeeded in 0ms:
   760	                                            flow.forward_key.src_ip,
   761	                                            flow.forward_key.src_port,
   762	                                            flow.forward_key.dst_ip,
   763	                                            flow.forward_key.dst_port,
   764	                                            count_bpf_session_entries(binding.bpf_maps.session_map_fd),
   765	                                            sessions.len(),
   766	                                        );
   767	                                        // Dump all local sessions to compare
   768	                                        if telemetry.dbg.session_miss <= 3 {
   769	                                            let mut sess_dump = String::new();
   770	                                            let mut count = 0;
   771	                                            sessions.iter_with_origin(|key, decision, metadata, origin| {
   772	                                                if count < 30 {
   773	                                                    use std::fmt::Write;
   774	                                                    let _ = write!(sess_dump,
   775	                                                        "\n  LOCAL_SESS: af={} proto={} {}:{}->{}:{} nat=({:?},{:?}) rev={} synced={} origin={}",
   776	                                                        key.addr_family, key.protocol,
   777	                                                        key.src_ip, key.src_port, key.dst_ip, key.dst_port,
   778	                                                        decision.nat.rewrite_src, decision.nat.rewrite_dst,
   779	                                                        metadata.is_reverse, origin.is_peer_synced(), origin.as_str(),
   780	                                                    );
   781	                                                    count += 1;
   782	                                                }
   783	                                            });
   784	                                            if !sess_dump.is_empty() {
   785	                                                eprintln!("DBG SESS_MISS_DUMP:{sess_dump}");
   786	                                            }
   787	                                        }
   788	                                    }
   789	                                }
   790	                            }
   791	                            if let Some(debug) = debug.as_mut() {
   792	                                debug.from_zone = Some(from_zone_id);
   793	                                debug.to_zone = Some(to_zone_id);
   794	                            }
   795	                            // Compute embedded ICMP error flag early so we can skip
   796	                            // the BPF session map publish for ICMP errors. Publishing
   797	                            // them as PASS_TO_KERNEL causes subsequent ICMP errors to
   798	                            // bypass the userspace embedded ICMP NAT reversal.
   799	                            let is_embedded_icmp_error = if worker_ctx.forwarding.allow_embedded_icmp
   800	                                && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
   801	                            {
   802	                                // #1145: reuse line-50 raw_frame bind.
   803	                                raw_frame
   804	                                    .get(meta.l4_offset as usize)
   805	                                    .copied()
   806	                                    .map(|icmp_type| is_icmp_error(meta.protocol, icmp_type))
   807	                                    .unwrap_or(false)
   808	                            } else {
   809	                                false
   810	                            };
   811	                            if resolution.disposition == ForwardingDisposition::LocalDelivery
   812	                                && apply_lo0_filter_action(
   813	                                    worker_ctx.forwarding,
   814	                                    worker_ctx.event_stream,
   815	                                    Some(flow),
   816	                                    meta,
   817	                                    ingress_zone_override,
   818	                                    now_ns,
   819	                                )
   820	                            {
   821	                                telemetry.dbg.local += 1;
   822	                                telemetry.dbg.policy_deny += 1;
   823	                                binding.scratch.scratch_recycle.push(desc.addr);
   824	                                continue;
   825	                            }
   826	                            if resolution.disposition == ForwardingDisposition::LocalDelivery
   827	                                && !is_embedded_icmp_error
   828	                                && should_cache_local_delivery_session_on_miss(
   829	                                    worker_ctx.forwarding,
   830	                                    effective_resolution_target,
   831	                                    resolution,
   832	                                    meta.protocol,
   833	                                    meta.tcp_flags,
   834	                                )
   835	                            {
   836	                                let local_metadata = SessionMetadata {
   837	                                    ingress_zone: from_zone_id,
   838	                                    egress_zone: to_zone_id,
   839	                                    owner_rg_id: 0,
   840	                                    fabric_ingress: false,
   841	                                    is_reverse: false,
   842	                                    // Keep firewall-local sessions in the helper only for HA
   843	                                    // state. Publish only the exact observed key back into the
   844	                                    // BPF session map so subsequent established packets bypass
   845	                                    // userspace and return directly to the kernel.
   846	                                    nat64_reverse: None,
   847	                                };
   848	                                if install_helper_local_session_on_miss(
   849	                                    sessions,
   850	                                    binding.bpf_maps.session_map_fd,
   851	                                    worker_ctx.shared_sessions,
   852	                                    worker_ctx.shared_nat_sessions,
   853	                                    worker_ctx.shared_forward_wire_sessions,
   854	                                    &worker_ctx.shared_owner_rg_indexes,
   855	                                    &flow.forward_key,
   856	                                    decision,
   857	                                    local_metadata.clone(),
   858	                                    SessionOrigin::LocalMiss,
   859	                                    now_ns,
   860	                                    meta.protocol,
   861	                                    meta.tcp_flags,
   862	                                ) {
   863	                                    telemetry.counters.session_creates += 1;
   864	                                    telemetry.dbg.session_create += 1;
   865	                                    publish_bpf_conntrack_entry(

exec
/bin/bash -lc "nl -ba docs/research/1913-fromframe-filter/claude-smr-plan-r1.md | sed -n '1,90p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
     1	# Claude SMR hostile plan review — #1913 r1
     2	
     3	Reviewer: Claude (domain SMR + CPU-arch/design + SW-design-patterns), HOSTILE pass.
     4	
     5	## Independently re-verified claims (read source @ d535f1f3e)
     6	
     7	1. **Allow-list divergence is real.** `tx/dispatch/slow_path.rs:90` filters
     8	   `LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported`; the
     9	   `_from_frame` variant (slow_path.rs:129+) has NO such filter. CONFIRMED.
    10	
    11	2. **PolicyDenied reaches :2814 with no early exit.** The arm at mod.rs:2799 is
    12	   `ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,` —
    13	   a single statement, no `continue`/`return`. Falls through to
    14	   `record_forwarding_disposition` (:2802) then the unconditional reinject
    15	   (:2814). CONFIRMED.
    16	
    17	3. **The reinject forwards a denied packet.** Walked
    18	   `maybe_reinject_slow_path_from_frame`: `extract_l3_packet_with_nat`
    19	   (depends on frame parseability + addr_family, NOT disposition) → succeeds;
    20	   `tunnel_delivery` requires LocalDelivery → skipped for PolicyDenied; #1873
    21	   gate requires `tunnel_endpoint_id != 0` → 0 for a normal denied transit
    22	   flow → does NOT fire; `slow_path.enqueue(packet)` → kernel TUN → kernel
    23	   FIB. CONFIRMED — this is a real zone-policy bypass.
    24	
    25	4. **No use-after-recycle.** PolicyDenied/HAInactive keep `recycle_now = true`
    26	   (default). The reinject extracts/copies the L3 bytes into an owned `Vec`
    27	   BEFORE the `if recycle_now { scratch_recycle.push(desc.addr); }` epilogue
    28	   at :2852. So the leak is a clean copy-out, not a buffer hazard. Severity is
    29	   purely the policy bypass, not memory unsafety. CONFIRMED.
    30	
    31	5. **Path B is correctly fatal.** `tx/dispatch/mod.rs:225` calls `_from_frame`
    32	   with `request.decision` whose disposition is `FabricRedirect` (guarded by
    33	   `if request.decision.resolution.disposition == FabricRedirect` at :223),
    34	   and the sibling `else` at :238 uses the FILTERED wrapper. FabricRedirect is
    35	   NOT in the allow-list, so the `_from_frame` choice is the deliberate
    36	   bypass. Adding the filter inside `_from_frame` WOULD break this site.
    37	   CONFIRMED — Path B rejection is sound.
    38	
    39	6. **Path C is correctly fatal.** The wrapper `maybe_reinject_slow_path` takes
    40	   `area: &MmapArea` + `desc: XdpDesc` and re-slices `area.slice(desc.addr,
    41	   desc.len)`. The trailing site needs `packet_frame` (post-decap
    42	   `owned_packet_frame`); using `desc` re-introduces the #1885 4-byte VLAN /
    43	   un-decapped-outer bug documented at mod.rs:2163+. CONFIRMED.
    44	
    45	## Hostile findings
    46	
    47	### F1 (MINOR, plan-improving) — DiscardRoute is the clearest-cut leak; lead with it
    48	The plan correctly flags DiscardRoute (§2.4) but buries it after PolicyDenied.
    49	DiscardRoute has the LEAST ambiguous contract: a discard/reject route exists
    50	SOLELY to drop, the wrapper allow-list explicitly excludes it, and there is no
    51	"deny is logged" mitigation. The plan's severity framing should note
    52	DiscardRoute is the cleanest proof the unfiltered reinject is a bug (no
    53	plausible "intentional" reading). Not a blocker — Path A fixes all three
    54	identically.
    55	
    56	### F2 (MINOR) — §2.5 buffered-MissingNeighbor: the plan should be explicit that Path A does NOT touch it
    57	The plan says "leave unchanged" but the recommended fix keeps MissingNeighbor
    58	in the allow-list, so the duplicate-delivery the issue's Q3 flags is NOT fixed.
    59	That is defensible (it is the documented #1901 recovery story), but the
    60	converged plan + issue comment must say plainly: "Q3 is acknowledged and
    61	DEFERRED; Path A does not change it." Otherwise a reader thinks #1913 closes
    62	Q3. Recommend an explicit follow-up issue reference.
    63	
    64	### F3 (NIT) — predicate location SSOT
    65	Plan offers enum-method vs free-fn. Prefer the enum method
    66	`ForwardingDisposition::is_slow_path_eligible` on `types/forwarding.rs`
    67	alongside the existing `is_cacheable` — same pattern, discoverable, and the
    68	doc comment lives with the enum that already documents each variant's intent
    69	(:264-283). Free-fn in slow_path.rs is fine too; this is a nit.
    70	
    71	### F4 (verify-at-/engineer) — telemetry double-count check
    72	After the fix, suppressed frames are counted by `record_forwarding_disposition`
    73	(:2802) which runs BEFORE the (now-gated) reinject. Confirm that with the
    74	reinject suppressed there is no path that ALSO expected the reinject's
    75	`record_slow_path_accept` to fire for these dispositions — there is not (the
    76	`_ => {}` arm in `record_slow_path_accept` means PolicyDenied/HAInactive/
    77	DiscardRoute never had a slow-path-specific counter anyway), so no counter goes
    78	missing. Just pin this in a test.
    79	
    80	## Verdict
    81	
    82	**PLAN-READY-WITH-NITS.** The diagnosis is correct and independently
    83	re-verified at every load-bearing step (policy bypass is real, not benign;
    84	Path B and Path C rejections are both fatal-for-the-right-reason). Path A is
    85	the right altitude: it aligns the trailing call with the contract the wrapper
    86	has shipped since introduction, touches one call site + one pure refactor, and
    87	preserves the one intentional unfiltered site. F1/F2 are wording/scope-clarity
    88	improvements for the converged doc; F3 a nit; F4 a test pin. None block
    89	PLAN-READY. Fold F1/F2 into r2 and I am at clean PLAN-READY.
    90	

codex
The plan’s test section already asks for a dispatch regression test, which is good. But the written rationale should name both exceptions to a helper-level filter: `ForwardCandidate` build-failure fallback and owned-frame `FabricRedirect` fallback. That is a revision-quality documentation gap, not a reason to abandon Path A.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '260,365p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   260	                    request.ingress_queue_id,
   261	                );
   262	            }
   263	            record_exception(
   264	                recent_exceptions,
   265	                ingress_ident,
   266	                "missing_egress_binding",
   267	                request.desc.len,
   268	                None,
   269	                None,
   270	                forwarding,
   271	            );
   272	            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   273	            continue;
   274	        };
   275	        let mut build_failed = false;
   276	        let mut fallback_to_slow_path = false;
   277	        let mut copied_source_frame = false;
   278	        let mut retained_source_frame = false;
   279	        let mut flow_key = request.flow_key.take();
   280	        {
   281	            let tcp_segmentation_needed = forwarded_tcp_may_need_segmentation(
   282	                source_frame,
   283	                request.meta,
   284	                &request.decision,
   285	                forwarding,
   286	            );
   287	            if tcp_segmentation_needed {
   288	                if let Some((segments, bytes, max_frame)) =
   289	                    segment_forwarded_tcp_frames_into_prepared(
   290	                        target_binding,
   291	                        source_frame,
   292	                        request.meta,
   293	                        &request.decision,
   294	                        forwarding,
   295	                        request.apply_nat_on_fabric,
   296	                        expected_ports,
   297	                        flow_key.clone(),
   298	                        request.cos_queue_id,
   299	                        request.dscp_rewrite,
   300	                        now_ns,
   301	                        post_recycles,
   302	                        worker_id,
   303	                        worker_commands_by_id,
   304	                    )
   305	                {
   306	                    dbg.enqueue_ok += segments as u64;
   307	                    dbg.enqueue_direct += segments as u64;
   308	                    target_binding.tx_counters.pending_direct_tx_packets += segments as u64;
   309	                    dbg.tx_bytes_total += bytes;
   310	                    if max_frame > dbg.tx_max_frame {
   311	                        dbg.tx_max_frame = max_frame;
   312	                    }
   313	                    copied_source_frame = true;
   314	                    if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE {
   315	                        let _ = drain_pending_tx_local_owner(
   316	                            target_binding,
   317	                            now_ns,
   318	                            post_recycles,
   319	                            forwarding,
   320	                            worker_id,
   321	                            worker_commands_by_id,
   322	                        );
   323	                    }
   324	                } else if let Some(segmented) = segment_forwarded_tcp_frames_from_frame(
   325	                    source_frame,
   326	                    request.meta,
   327	                    &request.decision,
   328	                    forwarding,
   329	                    request.apply_nat_on_fabric,
   330	                    expected_ports,
   331	                ) {
   332	                    for frame in segmented {
   333	                        if cfg!(feature = "debug-log") {
   334	                            if let Some(reason) = forward_tuple_mismatch_reason(
   335	                                live_frame_ports_from_meta_bytes(source_frame, request.meta),
   336	                                expected_ports,
   337	                                live_frame_ports_bytes(
   338	                                    &frame,
   339	                                    request.meta.addr_family,
   340	                                    request.meta.protocol,
   341	                                ),
   342	                            ) {
   343	                                record_exception(
   344	                                    recent_exceptions,
   345	                                    ingress_ident,
   346	                                    &reason,
   347	                                    frame.len() as u32,
   348	                                    Some(request.meta.into()),
   349	                                    None,
   350	                                    forwarding,
   351	                                );
   352	                                build_failed = true;
   353	                                break;
   354	                            }
   355	                        }
   356	                        let seg_frame_len = frame.len();
   357	                        target_binding
   358	                            .tx_pipeline
   359	                            .pending_tx_local
   360	                            .push_back(TxRequest {
   361	                                bytes: frame,
   362	                                expected_ports,
   363	                                expected_addr_family: request.meta.addr_family,
   364	                                expected_protocol: request.meta.protocol,
   365	                                flow_key: flow_key.clone(),

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '540,590p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   540	                                        "oversized_forward_frame",
   541	                                        cp1_len as u32,
   542	                                        Some(request.meta.into()),
   543	                                        None,
   544	                                        forwarding,
   545	                                    );
   546	                                    continue;
   547	                                }
   548	                                let req = TxRequest {
   549	                                    bytes: frame,
   550	                                    expected_ports,
   551	                                    expected_addr_family: request.meta.addr_family,
   552	                                    expected_protocol: request.meta.protocol,
   553	                                    flow_key: flow_key.take(),
   554	                                    egress_ifindex: request.decision.resolution.egress_ifindex,
   555	                                    cos_queue_id: request.cos_queue_id,
   556	                                    dscp_rewrite: request.dscp_rewrite,
   557	                                    mirror_clone: false,
   558	                                    enqueue_ns: 0,
   559	                                };
   560	                                if enqueue_local_request_to_target_or_owner(target_binding, req)
   561	                                    .is_err()
   562	                                {
   563	                                    build_failed = true;
   564	                                    fallback_to_slow_path = true;
   565	                                    continue;
   566	                                }
   567	                                dbg.enqueue_ok += 1;
   568	                                dbg.enqueue_copy += 1;
   569	                                target_binding.tx_counters.pending_copy_tx_packets += 1;
   570	                                dbg.tx_bytes_total += cp1_len as u64;
   571	                                if (cp1_len as u32) > dbg.tx_max_frame {
   572	                                    dbg.tx_max_frame = cp1_len as u32;
   573	                                }
   574	                            }
   575	                            None => {
   576	                                build_failed = true;
   577	                                fallback_to_slow_path = true;
   578	                            }
   579	                        },
   580	                    }
   581	                } else {
   582	                    enum DirectTxFallbackReason {
   583	                        NoFreeTxFrame,
   584	                        BuildReturnedNone,
   585	                        DisallowedByRewriteMode,
   586	                    }
   587	                    // Direct TX build: write the forwarded frame directly into
   588	                    // the target binding's UMEM TX frame, eliminating the
   589	                    // intermediate Vec allocation and one memcpy.
   590	                    // NAT64 cannot use direct TX (header size changes), so

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '830,905p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   830	                                    expected_ports,
   831	                                    expected_addr_family: request.meta.addr_family,
   832	                                    expected_protocol: request.meta.protocol,
   833	                                    flow_key: flow_key.take(),
   834	                                    egress_ifindex: request.decision.resolution.egress_ifindex,
   835	                                    cos_queue_id: request.cos_queue_id,
   836	                                    dscp_rewrite: request.dscp_rewrite,
   837	                                    mirror_clone: false,
   838	                                    enqueue_ns: 0,
   839	                                };
   840	                                if enqueue_local_request_to_target_or_owner(target_binding, req)
   841	                                    .is_err()
   842	                                {
   843	                                    build_failed = true;
   844	                                    fallback_to_slow_path = true;
   845	                                    continue;
   846	                                }
   847	                                dbg.enqueue_ok += 1;
   848	                                dbg.enqueue_copy += 1;
   849	                                target_binding.tx_counters.pending_copy_tx_packets += 1;
   850	                                dbg.tx_bytes_total += cp2_len as u64;
   851	                                if (cp2_len as u32) > dbg.tx_max_frame {
   852	                                    dbg.tx_max_frame = cp2_len as u32;
   853	                                }
   854	                            }
   855	                            None => {
   856	                                build_failed = true;
   857	                                fallback_to_slow_path = true;
   858	                            }
   859	                        }
   860	                    }
   861	                }
   862	            }
   863	            if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE
   864	                || target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE
   865	            {
   866	                let _ = drain_pending_tx_local_owner(
   867	                    target_binding,
   868	                    now_ns,
   869	                    post_recycles,
   870	                    forwarding,
   871	                    worker_id,
   872	                    worker_commands_by_id,
   873	                );
   874	            }
   875	        }
   876	        if !post_recycles.is_empty() {
   877	            apply_shared_recycles(
   878	                left,
   879	                ingress_index,
   880	                ingress_binding,
   881	                right,
   882	                binding_lookup,
   883	                post_recycles,
   884	            );
   885	        }
   886	        if build_failed {
   887	            handle_forward_build_failure(
   888	                ingress_ident,
   889	                ingress_live,
   890	                slow_path,
   891	                local_tunnel_deliveries,
   892	                recent_exceptions,
   893	                dbg,
   894	                request.target_ifindex,
   895	                request.desc.len,
   896	                source_frame,
   897	                request.meta,
   898	                request.decision,
   899	                fallback_to_slow_path,
   900	                forwarding,
   901	            );
   902	            if !retained_source_frame {
   903	                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
   904	            }
   905	            continue;

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/slow_path.rs | sed -n '23,73p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
    23	#[cold]
    24	#[inline(never)]
    25	pub(in crate::afxdp) fn handle_forward_build_failure(
    26	    binding: &BindingIdentity,
    27	    live: &BindingLiveState,
    28	    slow_path: Option<&Arc<SlowPathReinjector>>,
    29	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    30	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    31	    dbg: &mut DebugPollCounters,
    32	    _target_ifindex: i32,
    33	    packet_length: u32,
    34	    frame: &[u8],
    35	    meta: impl Into<UserspaceDpMeta>,
    36	    decision: SessionDecision,
    37	    fallback_to_slow_path: bool,
    38	    forwarding: &ForwardingState,
    39	) {
    40	    let meta = meta.into();
    41	    dbg.build_fail += 1;
    42	    #[cfg(feature = "debug-log")]
    43	    if dbg.build_fail <= 3 {
    44	        debug_log!(
    45	            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
    46	            _target_ifindex,
    47	            packet_length,
    48	            fallback_to_slow_path,
    49	        );
    50	    }
    51	    record_exception(
    52	        recent_exceptions,
    53	        binding,
    54	        "forward_build_failed",
    55	        packet_length,
    56	        Some(meta),
    57	        None,
    58	        forwarding,
    59	    );
    60	    if fallback_to_slow_path {
    61	        maybe_reinject_slow_path_from_frame(
    62	            binding,
    63	            live,
    64	            slow_path,
    65	            local_tunnel_deliveries,
    66	            frame,
    67	            meta,
    68	            decision,
    69	            recent_exceptions,
    70	            "forward_build_slow_path",
    71	            forwarding,
    72	        );
    73	    }

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/slow_path.rs | sed -n '76,125p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
    76	#[cold]
    77	#[inline(never)]
    78	pub(in crate::afxdp) fn maybe_reinject_slow_path(
    79	    binding: &BindingIdentity,
    80	    live: &BindingLiveState,
    81	    slow_path: Option<&Arc<SlowPathReinjector>>,
    82	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    83	    area: &MmapArea,
    84	    desc: XdpDesc,
    85	    meta: impl Into<UserspaceDpMeta>,
    86	    decision: SessionDecision,
    87	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    88	    forwarding: &ForwardingState,
    89	) {
    90	    let meta = meta.into();
    91	    if !matches!(
    92	        decision.resolution.disposition,
    93	        ForwardingDisposition::LocalDelivery
    94	            | ForwardingDisposition::NoRoute
    95	            | ForwardingDisposition::MissingNeighbor
    96	            | ForwardingDisposition::NextTableUnsupported
    97	    ) {
    98	        return;
    99	    }
   100	    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
   101	        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   102	        record_exception(
   103	            recent_exceptions,
   104	            binding,
   105	            "slow_path_extract_failed",
   106	            desc.len as u32,
   107	            Some(meta),
   108	            None,
   109	            forwarding,
   110	        );
   111	        return;
   112	    };
   113	    maybe_reinject_slow_path_from_frame(
   114	        binding,
   115	        live,
   116	        slow_path,
   117	        local_tunnel_deliveries,
   118	        frame,
   119	        meta,
   120	        decision,
   121	        recent_exceptions,
   122	        "slow_path",
   123	        forwarding,
   124	    );
   125	}

codex
For the disposition table, I found two concrete corrections: the `_` arm cannot see `ForwardCandidate`/`FabricRedirect` on the normal path because the enclosing branch consumes them earlier, and `MissingNeighbor` has source-NAT-failure `continue`s that the table did not list. That pushes the plan to revision, even though the core bug still stands.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1788,1802p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1788	                            })
  1789	                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
  1790	                        {
  1791	                            decision.resolution = redirect;
  1792	                        }
  1793	                    }
  1794	                    if matches!(
  1795	                        decision.resolution.disposition,
  1796	                        ForwardingDisposition::ForwardCandidate
  1797	                            | ForwardingDisposition::FabricRedirect
  1798	                    ) {
  1799	                        telemetry.dbg.forward += 1;
  1800	                        // Direction-specific tracking
  1801	                        let ingress_if = meta.ingress_ifindex as i32;
  1802	                        let egress_if = decision.resolution.egress_ifindex;

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2516,2568p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2516	                                                Ok(snat_decision) => {
  2517	                                                    pending_decision.nat = snat_decision;
  2518	                                                    source_nat_release_key =
  2519	                                                        Some(nat_match_flow.forward_key.clone());
  2520	                                                }
  2521	                                                Err(failure) => {
  2522	                                                    record_source_nat_failure(
  2523	                                                        telemetry,
  2524	                                                        worker_ctx,
  2525	                                                        meta,
  2526	                                                        flow,
  2527	                                                        from_zone_id,
  2528	                                                        to_zone_id,
  2529	                                                        desc.len,
  2530	                                                        &failure,
  2531	                                                    );
  2532	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2533	                                                    continue;
  2534	                                                }
  2535	                                            }
  2536	                                        } else {
  2537	                                            match source_nat_decision_for_flow(
  2538	                                                worker_ctx.forwarding,
  2539	                                                &from_zone,
  2540	                                                &to_zone,
  2541	                                                pending_decision.resolution.egress_ifindex,
  2542	                                                &nat_match_flow,
  2543	                                                now_ns,
  2544	                                                snat_non_first_fragment,
  2545	                                            ) {
  2546	                                                Ok(snat_decision) => {
  2547	                                                    pending_decision.nat =
  2548	                                                        pending_decision.nat.merge(snat_decision);
  2549	                                                    source_nat_release_key =
  2550	                                                        Some(nat_match_flow.forward_key.clone());
  2551	                                                }
  2552	                                                Err(failure) => {
  2553	                                                    record_source_nat_failure(
  2554	                                                        telemetry,
  2555	                                                        worker_ctx,
  2556	                                                        meta,
  2557	                                                        flow,
  2558	                                                        from_zone_id,
  2559	                                                        to_zone_id,
  2560	                                                        desc.len,
  2561	                                                        &failure,
  2562	                                                    );
  2563	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2564	                                                    continue;
  2565	                                                }
  2566	                                            }
  2567	                                        }
  2568	                                    }

exec
/bin/bash -lc "sed -n '2156,2814p' userspace-dp/src/afxdp/poll_descriptor/mod.rs | nl -ba -v 2156 | rg -n \"continue|return|break|maybe_reinject|match decision|ForwardingDisposition|record_forwarding_disposition\"" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
1:  2156	                        match decision.resolution.disposition {
2:  2157	                            ForwardingDisposition::LocalDelivery => {
8:  2163	                                // leg (`maybe_reinject_slow_path_from_frame`
11:  2166	                                // `maybe_reinject_slow_path` here, pairing
31:  2186	                            ForwardingDisposition::NoRoute => {
49:  2204	                            ForwardingDisposition::MissingNeighbor => {
180:  2335	                                        // scratch_recycle + continue, matching
182:  2337	                                        // pattern. The continue skips the
186:  2341	                                        continue;
378:  2533	                                                    continue;
409:  2564	                                                    continue;
507:  2662	                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
535:  2690	                                // maybe_reinject_slow_path_from_frame call
553:  2708	                                // maybe_reinject_slow_path_from_frame
644:  2799	                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
645:  2800	                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
648:  2803	                        record_forwarding_disposition(
659:  2814	                        maybe_reinject_slow_path_from_frame(

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2848,2865p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2848	                    None,
  2849	                    worker_ctx.forwarding,
  2850	                );
  2851	            }
  2852	            if recycle_now {
  2853	                binding.scratch.scratch_recycle.push(desc.addr);
  2854	            }
  2855	        }
  2856	        received.release();
  2857	        drop(received);
  2858	}

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2154,2185p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2154	                    } else {
  2155	                        // Debug: count non-forward dispositions
  2156	                        match decision.resolution.disposition {
  2157	                            ForwardingDisposition::LocalDelivery => {
  2158	                                telemetry.dbg.local += 1;
  2159	                                // Host-bound traffic (NDP, ICMP echo, BGP,
  2160	                                // GRE-to-self inner packets, etc.) is
  2161	                                // delivered by the SINGLE decap-aware
  2162	                                // reinject chokepoint at the end of this
  2163	                                // leg (`maybe_reinject_slow_path_from_frame`
  2164	                                // over `packet_frame`). #1885: this arm used
  2165	                                // to ALSO call the desc-based
  2166	                                // `maybe_reinject_slow_path` here, pairing
  2167	                                // the ORIGINAL UMEM frame (the VLAN-tagged
  2168	                                // GRE OUTER frame on a tagged underlay) with
  2169	                                // the post-decap INNER meta
  2170	                                // (`stage_native_gre_decap` rebinds `meta`
  2171	                                // but `desc` still points at the un-decapped
  2172	                                // frame) — the slice landed 4 bytes early on
  2173	                                // tagged ingress (TUN write EINVAL: payload
  2174	                                // started with the dot1q TCI tail instead of
  2175	                                // the IP version nibble) and delivered the
  2176	                                // still-encapsulated OUTER packet on
  2177	                                // untagged ingress. It was ALSO a duplicate
  2178	                                // enqueue for non-decapped local packets
  2179	                                // (both calls pass the same disposition
  2180	                                // filter). The first delivered packet
  2181	                                // creates a BPF session map entry so
  2182	                                // subsequent packets bypass userspace
  2183	                                // entirely.
  2184	                                recycle_now = true;
  2185	                            }

codex
VERDICT: **PLAN-NEEDS-REVISION**

Core diagnosis is correct: this is not benign. But the plan needs source-accurate revisions in §2.1 and §2.6 before I’d call it ready.

1. **PolicyDenied -> slow-path TUN trace is correct. No earlier drop found.**

Evidence:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1693`: `decision.resolution.disposition =`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1694`: `ForwardingDisposition::PolicyDenied;`

That decision then misses the forward branch:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1794`: `if matches!(`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1796`: `ForwardingDisposition::ForwardCandidate`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1797`: `| ForwardingDisposition::FabricRedirect`

In the non-forward match, PolicyDenied only increments a counter:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2799`: `ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,`

Then it records disposition and unconditionally reinjects:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2803`: `record_forwarding_disposition(`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814`: `maybe_reinject_slow_path_from_frame(`

The helper has no disposition filter:
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:142`: `let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156`: `decision.resolution.disposition == ForwardingDisposition::LocalDelivery`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:212`: `if decision.resolution.tunnel_endpoint_id != 0 {`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:240`: `match slow_path.enqueue(packet) {`

So a normal non-tunnel denied transit packet reaches the slow-path TUN write path. Kernel forwarding still depends on kernel routes, but there is no userspace policy drop after `PolicyDenied`.

2. **§2.6 is only partly true and over-argued.**

Yes, `dispatch/mod.rs:225` can pass `FabricRedirect` into `_from_frame`, but only for owned frames:
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:223`: `if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:224`: `if matches!(request.frame, PendingForwardFrame::Owned(_)) {`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:225`: `maybe_reinject_slow_path_from_frame(`

Counterexample to the plan’s “the immediately-following else is the bypass proof”: the live-frame branch uses the filtered wrapper and therefore rejects `FabricRedirect` today:
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:238`: `maybe_reinject_slow_path(`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:91`: `if !matches!(`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:93`: `ForwardingDisposition::LocalDelivery`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:96`: `| ForwardingDisposition::NextTableUnsupported`

Also, Path B would break more than this: `ForwardCandidate` build-failure fallback also relies on unfiltered `_from_frame`.
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:855`: `None => {`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:856`: `build_failed = true;`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:857`: `fallback_to_slow_path = true;`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:887`: `handle_forward_build_failure(`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:60`: `if fallback_to_slow_path {`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:61`: `maybe_reinject_slow_path_from_frame(`

Revise §2.6: Path B is still bad, but the stated proof is too broad and misses the build-failure caller.

3. **Path C is correctly rejected.**

The wrapper re-slices the original UMEM descriptor:
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:83`: `area: &MmapArea,`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:84`: `desc: XdpDesc,`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:100`: `let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {`

The trailing site correctly uses `packet_frame`:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2819`: `packet_frame,`

And the source explicitly documents the #1885 failure mode:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2167`: `the ORIGINAL UMEM frame`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2169`: `the post-decap INNER meta`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2172`: `the slice landed 4 bytes early`

4. **§2.1 table needs correction.**

The enum variants are all accounted for:
`userspace-dp/src/afxdp/types/forwarding.rs:242`: `pub(crate) enum ForwardingDisposition {`
through
`userspace-dp/src/afxdp/types/forwarding.rs:251`: `NextTableUnsupported,`

But `ForwardCandidate` and `FabricRedirect` should not be listed as reaching `:2814`; the enclosing branch consumes them at `poll_descriptor/mod.rs:1794-1798`.

The table also misses two `MissingNeighbor` early continues on SNAT failure:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2533`: `continue;`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2564`: `continue;`

5. **Path A is sufficient for this bug, but the altitude is weak.**

A call-site guard at `:2814` fixes the leak. But leaving `_from_frame` unfiltered is a future footgun unless the contract is made explicit. Revise Path A to either add an `eligible_from_frame` wrapper for generic non-forward reinjection, or clearly mark the current helper as unchecked/raw and require special callers to justify bypassing the predicate.
tokens used
146,005
VERDICT: **PLAN-NEEDS-REVISION**

Core diagnosis is correct: this is not benign. But the plan needs source-accurate revisions in §2.1 and §2.6 before I’d call it ready.

1. **PolicyDenied -> slow-path TUN trace is correct. No earlier drop found.**

Evidence:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1693`: `decision.resolution.disposition =`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1694`: `ForwardingDisposition::PolicyDenied;`

That decision then misses the forward branch:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1794`: `if matches!(`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1796`: `ForwardingDisposition::ForwardCandidate`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1797`: `| ForwardingDisposition::FabricRedirect`

In the non-forward match, PolicyDenied only increments a counter:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2799`: `ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,`

Then it records disposition and unconditionally reinjects:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2803`: `record_forwarding_disposition(`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814`: `maybe_reinject_slow_path_from_frame(`

The helper has no disposition filter:
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:142`: `let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156`: `decision.resolution.disposition == ForwardingDisposition::LocalDelivery`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:212`: `if decision.resolution.tunnel_endpoint_id != 0 {`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:240`: `match slow_path.enqueue(packet) {`

So a normal non-tunnel denied transit packet reaches the slow-path TUN write path. Kernel forwarding still depends on kernel routes, but there is no userspace policy drop after `PolicyDenied`.

2. **§2.6 is only partly true and over-argued.**

Yes, `dispatch/mod.rs:225` can pass `FabricRedirect` into `_from_frame`, but only for owned frames:
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:223`: `if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:224`: `if matches!(request.frame, PendingForwardFrame::Owned(_)) {`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:225`: `maybe_reinject_slow_path_from_frame(`

Counterexample to the plan’s “the immediately-following else is the bypass proof”: the live-frame branch uses the filtered wrapper and therefore rejects `FabricRedirect` today:
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:238`: `maybe_reinject_slow_path(`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:91`: `if !matches!(`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:93`: `ForwardingDisposition::LocalDelivery`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:96`: `| ForwardingDisposition::NextTableUnsupported`

Also, Path B would break more than this: `ForwardCandidate` build-failure fallback also relies on unfiltered `_from_frame`.
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:855`: `None => {`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:856`: `build_failed = true;`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:857`: `fallback_to_slow_path = true;`
`userspace-dp/src/afxdp/tx/dispatch/mod.rs:887`: `handle_forward_build_failure(`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:60`: `if fallback_to_slow_path {`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:61`: `maybe_reinject_slow_path_from_frame(`

Revise §2.6: Path B is still bad, but the stated proof is too broad and misses the build-failure caller.

3. **Path C is correctly rejected.**

The wrapper re-slices the original UMEM descriptor:
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:83`: `area: &MmapArea,`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:84`: `desc: XdpDesc,`
`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:100`: `let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {`

The trailing site correctly uses `packet_frame`:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2819`: `packet_frame,`

And the source explicitly documents the #1885 failure mode:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2167`: `the ORIGINAL UMEM frame`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2169`: `the post-decap INNER meta`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2172`: `the slice landed 4 bytes early`

4. **§2.1 table needs correction.**

The enum variants are all accounted for:
`userspace-dp/src/afxdp/types/forwarding.rs:242`: `pub(crate) enum ForwardingDisposition {`
through
`userspace-dp/src/afxdp/types/forwarding.rs:251`: `NextTableUnsupported,`

But `ForwardCandidate` and `FabricRedirect` should not be listed as reaching `:2814`; the enclosing branch consumes them at `poll_descriptor/mod.rs:1794-1798`.

The table also misses two `MissingNeighbor` early continues on SNAT failure:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2533`: `continue;`
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2564`: `continue;`

5. **Path A is sufficient for this bug, but the altitude is weak.**

A call-site guard at `:2814` fixes the leak. But leaving `_from_frame` unfiltered is a future footgun unless the contract is made explicit. Revise Path A to either add an `eligible_from_frame` wrapper for generic non-forward reinjection, or clearly mark the current helper as unchecked/raw and require special callers to justify bypassing the predicate.
