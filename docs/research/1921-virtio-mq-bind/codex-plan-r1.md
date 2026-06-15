# Codex plan-review r1 (task-mqfnykhy-2jfzzu) — plan @ 96eee9025

**Verdict: PLAN-KILL**

Fatal: the plan's central failure chain is wrong.

1. `armed` is NOT bind success. `set_bindings_forwarding_armed`
   (helpers.rs:487) sets `binding.armed = armed && binding.registered` — a
   control-plane forwarding-armed REQUEST flag applied to all registered
   bindings, independent of whether the XSK bind succeeded. Bind success is
   `bound`/`xsk_registered`/`ready` (refresh_bindings.rs:226). So a failed bind
   can be `registered=true, armed=true, ready=false`; the all-or-nothing
   `enabled` gate (helpers.rs:210, `all(registered && armed)`) and Go
   `probeBindingsReady` (maps_sync.go:411) do NOT necessarily trip. The BPF
   binding map withholds READY instead (maps_sync.go:97 `Registered && Armed &&
   Ready`), so the likely live failure is PER-QUEUE `binding_not_ready` transit
   drop (lib.rs:427), not "ctrl flag 0 → XDP_PASS → no SNAT".
2. Ring-mismatch refuted for current code, but `queueCountFromBindings`
   (maps_sync.go:1649) tracks max REGISTERED queue id, not the bound set — and
   a Path-A shrink that reduces registered bindings to `workers` WITHOUT
   shrinking the NIC's real RX queues reintroduces ring mismatch.
3. Path A ordering dangerous: Rust prefers snapshot `rx_queues`
   (helpers.rs:698), stamped by Go from sysfs (interfaces.go:173). `ethtool -L`
   must run BEFORE Go builds the snapshot, or the snapshot must carry the
   reconciled count. Helper-side pin after snapshot receipt is too late.
4. mlx5/i40e "no-op" is not an invariant: rss_indirection.go:164 skips mlx5 RSS
   reshape for workers==1; a broad combined=workers reduces HW queues whenever
   workers<queues → throughput regression. Must be driver-scoped/operator-gated
   with explicit "workers == desired fanout" semantics.
5. Fabric/IPVLAN parent not proven safe — needs explicit exclusion or validation.
6. Go should own channel pinning (owns ethtool + bind sequencing) but it must run
   before snapshot construction / before rebind, not at the late RSS reapply site.
