# Path B evidence — "crypto DEK churn" is misattributed TX-wakeup syscall cost

All on loss:xpf-userspace-fw0, `-P48 -p5210`, flow-rebalance OFF, CoS ON.

## perf flat self-time (4 consecutive 6s windows) — reproducible ~5.5%
mlx5_crypto_modify_dek_key ~3.5% + dek_fill_key ~0.8 + __pfx_create_dek_bulk ~0.8
+ dek_pool_remove_bulk ~0.3 + create_dek_key ~0.15 + dek_bulk_reset_synced ~0.08.

## bpftrace kprobe call counts (the metric validation)
- 8s: mlx5e_napi_poll = 3,579,581 ; mlx5_crypto_modify_dek_key = 0
- 10s: modify_dek_key = 0 ; dek_pool_remove_bulk = 0 ; create_dek_bulk = 0
=> the DEK functions are NEVER CALLED. The perf % is a symbolization artifact:
mlx5_core ships as mlx5_core.ko.xz (compressed); perf rounds sampled PCs in
unexported static functions to the nearest EXPORTED symbol (the crypto DEK
family at kallsyms 0xc0a801xx). `perf annotate mlx5_crypto_modify_dek_key`
disassembles to code referencing mlx5e_port_linkspeed — wrong function — confirming
broken compressed-module resolution.

## The REAL cost (AGY hypothesis, verified): AF_XDP TX/RX wake sendto kicks
8s under load:
- xsk_sendmsg          = 885,309  (~110K/s)
- sys_enter_sendto (worker) = 865,011 (~108K/s)
- mlx5e_xsk_wakeup     = 124,259  (~15.5K/s)
The workers kick the TX/RX rings via sendto(). mlx5e_xsk_wakeup is static/
unexported → its samples misattribute to the crypto symbols. Already gated by
needs_wakeup() (rings.rs:142-145) + TX_WAKE_MIN_INTERVAL_NS=50_000 (mod.rs:302).
RX-wake also uses sendto (rings.rs:182-198). Reducible by widening the wake
interval / batching kicks — at a TX-latency / ring-backpressure tradeoff.
