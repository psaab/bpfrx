I will first list the files in `docs/research/1760-reverse-key-v2` to locate the plan document and past round feedback.
I will list the contents of the research directory in the specified worktree path.
I will view the plan document in the worktree to examine the plan for the stage-2 revisit.
I will search the codebase to locate files mentioning `install_helper_local_session_on_miss` and check the file paths.
I will view `install_helper_local_session_on_miss` in `forwarding/mod.rs` to see what it does.
I will view the rest of the `install_helper_local_session_on_miss` function.
I will view the caller of `install_helper_local_session_on_miss` in `poll_descriptor/mod.rs`.
I will grep for `install_with_protocol_with_origin` to locate where it is defined.
I will view `install_with_protocol_with_origin` in `session/mod.rs` to see its parameters and how it indexes sessions.
I will search for the definition of `index_forward_nat_key` in `session/mod.rs`.
I will view `index_forward_nat_key` in `session/mod.rs` to see what index structures are updated.
I will search for the definition or assignment of `decision` in `poll_descriptor/mod.rs` around lines 750-810.
I will view lines 650 to 720 of `poll_descriptor/mod.rs` to find how `decision` is computed.
I will search for `should_cache_local_delivery_session_on_miss` to see its definition.
I will view the `should_cache_local_delivery_session_on_miss` function in `forwarding/mod.rs`.
I will grep for `fn reverse_wire_key` in the codebase.
I will view `reverse_wire_key` in `session/key.rs` to see how it constructs the reverse key.
I will search the codebase for all calls to `publish_shared_session` to see where forward NAT sessions can be created/published.
I will view `poll_descriptor/mod.rs` around line 1253 to see where it calls `publish_shared_session`.
I will view lines 1450 to 1485 of `poll_descriptor/mod.rs`.
I will view lines 2280 to 2320 of `poll_descriptor/mod.rs`.
I will search the codebase for files containing `upsert_synced` to see how synced sessions are processed.
I will view `upsert_synced_session` in `ha.rs`.
I will view `handle_upsert_synced` in `upsert_synced.rs`.
I will grep for `fn upsert_synced_with_origin` in `session/mod.rs`.
I will view `upsert_synced_with_origin` in `session/mod.rs`.
I will search `poll_descriptor/mod.rs` for `install_with_protocol_with_origin` calls.
I will view `poll_descriptor/mod.rs` around line 461.
I will view lines 400 to 440 of `poll_descriptor/mod.rs`.
I will view lines 1210 to 1235 of `poll_descriptor/mod.rs`.
I will view lines 1365 to 1390 of `poll_descriptor/mod.rs`.
I will grep for `publish_shared_session` in `tunnel.rs` to see what kind of sessions are published there.
I will view the `publish_shared_session` function in `shared_ops.rs`.
I will view the rest of the `publish_shared_session` function in `shared_ops.rs`.
I will search the codebase for `SharedPromote` to see when and how it is used.
I will view `promote.rs` around line 103 to see how `SharedPromote` sessions are published.
I will view `reverse_canonical_key` and surrounding functions in `session/key.rs`.
I will search for `lookup_forwarding_resolution_for_session` to see if it changes the NAT decision.
I will view `lookup_forwarding_resolution_for_session` in `session_glue/mod.rs`.
I will view the `remove_shared_session` function in `shared_ops.rs` around line 685.
I will check the git status and diff inside the worktree to see what code changes have been drafted there.
Here is the adversarial plan review for the **#1760 Stage-2 Revisit**. 

---

### **Final Verdict**
**`PLAN-READY`**

The Plan v3, including its operator conditional between **Path W-lite** (measure and watch) and **Path K** (close as accepted-risk for lab-only environments), is converged, technically sound, and fully honest. The W3′ displacement detector is robust, has zero per-packet overhead, and successfully closes the coverage holes identified in Round 2.

---

### **Detailed Adjudication of Round-3 Questions**

#### **1. Coverage Map Completeness & Local-Delivery Adjudication**
* **Local-Delivery Adjudication:** A local-delivery session is **completely outside the collision domain** of transit NAT sessions.
  * **Reverse Wire Keys (`reverse_wire_key`):** For a transit NAT session (e.g., DNAT to backend `B`), the reverse wire key has `src_ip = B` ([key.rs:117](file:///home/ps/git/bpfrx/userspace-dp/src/session/key.rs#L117)). A local-delivery session always has `src_ip = I` (the local interface IP, [key.rs:133](file:///home/ps/git/bpfrx/userspace-dp/src/session/key.rs#L133)). Since `B != I` (a local interface IP is never an active forwarding backend's subnet IP), their wire keys never collide.
  * **Reverse Canonical Keys (`reverse_canonical_key`):** These could only overlap if the client IP `C` is the same, client port `c_port` is the same, and the destination port of the DNAT flow equals the local-delivery service port. However, a client TCP stack cannot open two concurrent connections using the same source port to the identical destination IP and port; thus, duplicate 4-tuples are impossible on the wire. For UDP or different destination IPs (e.g., multi-IP interfaces), either different port values or distinct destination IPs prevent any key collision.
* **Other Bypassing Creation Paths:** There are **no other production forward-NAT creation paths** that bypass `publish_shared_session` ([shared_ops.rs:623](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs#L623)). 
  * The only other path using `install_with_protocol_with_origin` without publishing to the shared maps is `cluster_peer_return_fast_path` ([poll_descriptor/mod.rs:461](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L461)). However, this path installs return flows (`SessionOrigin::ReverseFlow` with `is_reverse: true`), which write to `reverse_translated_index` instead of `nat_reverse_index` ([session/mod.rs:1211-1215](file:///home/ps/git/bpfrx/userspace-dp/src/session/mod.rs#L1211-L1215)) and do not participate in the `#1760` forward-NAT collision domain.

#### **2. W3′ False Positives**
The predicate `displaced.key != entry.key` (with canonical-alias exclusion) is **completely clean and free of false positives** across all listed scenarios:
* **RG Migration & HA Re-Sync:** Re-resolution and sync commands only update the egress resolution parameters and owners in the `SyncedSessionEntry` ([upsert_synced.rs:55-61](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L55-L61)). The forward key (`entry.key`) and the NAT decision (`entry.decision.nat`) remain strictly immutable. Consequently, republishing the entry will always find `displaced.key == entry.key`, resulting in a negative displacement signal.
* **SharedPromote / Promote:** Promotion updates the origin field to `SessionOrigin::SharedPromote` but retains the original forward key ([promote.rs:109-116](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/session_glue/promote.rs#L109-L116)). Its publish to `shared_nat_sessions` displaces the existing standby entry of the same session, yielding `displaced.key == entry.key` (no false positive).
* **NAT64 Alias Shapes:** The addresses and address families calculated by `reverse_wire_key` ([key.rs:97-113](file:///home/ps/git/bpfrx/userspace-dp/src/session/key.rs#L97-L113)) are fully determined by the immutable forward key and NAT decision, meaning the alias shapes remain constant for the session's lifetime.

#### **3. W-lite vs. W5 (Incremental Live-Pair Audit)**
**W-lite is an acceptable and preferred reduced ship.**
* The watch serves as an **event detector** to verify if collisions occur in production, not a census. The first collision event between a pair of flows (S1 and S2) is guaranteed to be caught and counted by W3′. 
* Missing subsequent collisions against the unindexed loser (S3 colliding with S1's key after the winning S2's teardown removes K) does not change the operator's diagnostic conclusion. 
* The operational cost and code complexity of a periodic background worker sweep (W5) are not justified for diagnostic telemetry.

#### **4. Plan Framing and Conditional**
* The framing is correct. The lab environment represents a degenerate population where collisions cannot organically occur (due to a single LAN client's ephemeral port uniqueness). 
* The watch is the logical prerequisite to justify the engineering complexity of A1 (install-time refusal with commit-order inversion). Therefore, the plan's operator conditional is appropriate and honest.

#### **5. PLAN-KILL Adjudication**
* **Invitation Declined:** W3′ is resilient. Even cross-node collisions are eventually detected because regular sessions are replicated via `replicate_session_upsert` ([promote.rs:124](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/session_glue/promote.rs#L124)), which triggers `publish_shared_session` on the peer nodes. Cross-worker seeds on the same node are caught immediately as they share the process-global `shared_nat_sessions` lock.
* The implementation cost of Path W is minimal (slow path counters and a process-global 60s CAS warning throttle), offering excellent value for a future production deployment.
