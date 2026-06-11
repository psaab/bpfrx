PLAN-NEEDS-MAJOR

1. HIGH — I5 / §2 face(ii) is factually wrong about replies staying cold-path.

`userspace-dp/src/afxdp/shared_ops.rs:720` quotes `) -> SessionLookup {`; `userspace-dp/src/afxdp/shared_ops.rs:729` quotes `if sessions.install_with_protocol_with_origin(`; `userspace-dp/src/afxdp/shared_ops.rs:762` quotes `reverse`. The repair helper returns the synthesized decision regardless of install success.

Then `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1995` quotes `if let Some(flow) = flow.as_ref()` and `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2016` quotes `binding.flow.flow_cache.insert(entry);`. There is no install-success gate on reply-repair cache population. `userspace-dp/src/afxdp/flow_cache.rs:227` quotes `pub(super) fn should_cache` and `userspace-dp/src/afxdp/flow_cache.rs:228-231` gates only protocol, NAT64/NPTv6, and disposition.

So the plan’s claim that every reply “rides the cold path” and retries repair until capacity frees is false. The proposed `(SessionLookup, bool)` ride-along fixes `created`, but not the flow-cache side effect unless the plan explicitly gates cache insertion for failed repair installs or deliberately accepts sessionless reply-direction cache entries.

2. MEDIUM — NAT64 is missing from the interleaving map.

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:574` quotes `let nat64_match =`; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:580` quotes `worker_ctx.forwarding.nat64.allocate_v4_source(idx)?;`; `userspace-dp/src/nat64.rs:102` quotes `prefix.pool_index.fetch_add(1, Ordering::Relaxed)`. This is allocated before session admission, policy completion, and install.

It is not a pool-port leak: `userspace-dp/src/nat64.rs:109-116` builds a NAT64 decision with no port allocation, and `userspace-dp/src/afxdp/flow_cache.rs:229` quotes `&& !decision.nat.nat64`, so I2 cache persistence is excluded. But today a refused NAT64 flow can still forward one translated packet with no session/reverse repair anchor. Path A drops it, but §4/tests need an explicit NAT64 row/pin.

3. MEDIUM — I13 is a real same-class transaction failure, and “document + optional counter” is under-justified for broad #1861 scope.

`userspace-dp/src/afxdp/tunnel.rs:306` quotes `publish_shared_session(`; `userspace-dp/src/afxdp/tunnel.rs:329` quotes `pending.push_back(WorkerCommand::UpsertLocal(entry.clone()));`; `userspace-dp/src/afxdp/tunnel.rs:331` quotes `pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));`.

The worker then discards the install result: `userspace-dp/src/afxdp/session_glue/mod.rs:560` quotes `sessions.install_with_protocol_with_origin(` as a bare statement, while `userspace-dp/src/session/mod.rs:690-692` quotes `if self.len() >= self.max_sessions` / `return false;`. If #1861 means “failed session install is transactional” across the Rust dataplane, I13 cannot stay optional without explicit user signoff.

4. LOW — I2’s operator symptoms omit embedded ICMP failure.

`userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs:41-43` quotes `lookup_forward_nat_across_scopes(ctx.sessions, ctx.shared_nat_sessions, &reverse_key)`; `userspace-dp/src/afxdp/icmp_embed/session_match.rs:77-83` quotes `sessions.lookup(...).or_else(...find_forward_nat_match...)`. The embedded ICMP path does not consult flow cache.

For the I2 leaked pool-SNAT flow, there is no local/shared session index, only a flow-cache entry, so ICMP errors for that stateless cached flow will not NAT-reverse. Path A still fixes this by refusing/cache-skipping, but the table understates the current failure surface.

5. INFO — I did not find a Path A atomicity kill; I2 reachability and pool-mode scope check out.

`userspace-dp/src/afxdp/worker/loop_body/mod.rs:495` quotes `apply_worker_commands(`, `:567` quotes `sessions.expire_stale_entries(loop_now_ns)`, and `:631` quotes `if poll_binding(`; command handling and GC happen before polling, not between the proposed preflight and installs. The two installs use the same mutable table: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1274` quotes `let forward_installed = track_in_userspace` and `:1434-1436` quotes `if track_in_userspace && install_local_reverse && sessions.install_with_protocol_with_origin(`.

I2 is real: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1341` quotes `rollback_source_nat_allocation(` and `:2016` quotes `binding.flow.flow_cache.insert(entry);`. It is pool-mode scoped: `userspace-dp/src/nat/source.rs:442-451` returns interface-mode SNAT with no `rewrite_src_port`, while `userspace-dp/src/nat/source.rs:350-351` returns unless a rewritten source port exists.

Codex session ID: 019eb640-4d63-7851-ae8d-0300473ef944
Resume in Codex: codex resume 019eb640-4d63-7851-ae8d-0300473ef944
