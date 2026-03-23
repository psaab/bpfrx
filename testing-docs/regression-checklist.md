# Regression Checklist

Pre-commit validation checklist. Check the boxes that apply to your change.

## Always Required

- [ ] `make test` — all Go tests pass (880+ tests, 26 packages)
- [ ] `cd userspace-dp && cargo test` — all Rust tests pass (356 tests)
- [ ] `make build` — Go daemon compiles
- [ ] `make build-ctl` — CLI client compiles

## If You Changed Rust Userspace Code (`userspace-dp/`)

- [ ] `cargo build --release` — release build succeeds
- [ ] Deploy to loss userspace cluster: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy all`
- [ ] Restart BOTH nodes: `incus exec loss:bpfrx-userspace-fw{0,1} -- systemctl restart bpfrxd`
- [ ] Wait 40s, then: `ping -c 10 172.16.80.200` — 0% loss, all TTL=63
- [ ] Wait 40s, then: `ping6 -c 10 2001:559:8585:80::200` — 0% loss, all TTL=63
- [ ] `iperf3 -c 172.16.80.200 -P 8 -t 5` — > 18 Gbps
- [ ] `mtr -n --report --report-cycles=5 -4 142.251.32.46` — intermediate hops visible

## If You Changed XDP Shim (`userspace-xdp/`)

- [ ] `cd userspace-xdp && cargo +nightly build --release` — BPF object compiles
- [ ] Copy to embed: `cp target/bpfel-unknown-none/release/libbpfrx_userspace_xdp.so ../pkg/dataplane/userspace_xdp_bpfel.o`
- [ ] `make build` — Go daemon embeds new XDP object
- [ ] Deploy and check: `journalctl -u bpfrxd | grep "stack.*too large"` — NO stack overflow
- [ ] Cluster comes up: `show chassis cluster status` — both nodes have primary/secondary

## If You Changed Cluster / VRRP / Session Sync

- [ ] `make cluster-deploy` — deploy to eBPF cluster
- [ ] `make test-failover` — **MANDATORY** per CLAUDE.md
- [ ] `make test-ha-crash` — crash recovery works
- [ ] Session sync: `show security flow session` on secondary shows synced sessions

## If You Changed Forwarding / NAT / Policy

- [ ] `make test-deploy` — deploy to standalone VM
- [ ] `./test/incus/test-connectivity.sh` — all zones can communicate per policy
- [ ] SNAT flows show correct translated source
- [ ] DNAT flows reach internal server

## If You Changed Config Parser

- [ ] Run flat `set` syntax tests: `go test -run TestSet ./pkg/config/...`
- [ ] Run hierarchical tests: `go test -run TestParse ./pkg/config/...`
- [ ] Test both `load override` and `load merge` paths
- [ ] Verify `show | display set` round-trips correctly

## If You Changed FRR / Routing

- [ ] `vtysh -c "show ip route"` — routes correct
- [ ] VRF isolation: traffic in one VRF doesn't leak to another
- [ ] Default route via DHCP: admin distance 200

## If You Changed RA / IPv6

- [ ] After restart: host gets IPv6 default route via RA within 30s
- [ ] `ip -6 route show default` on host — exists via stable link-local
- [ ] Ping firewall VIP: `ping6 2001:559:8585:ef00::1` — works

## Performance Regression Check

Run before and after:
```bash
scripts/userspace-perf-compare.sh --runs 3 --duration 10
```

**Red flag**: > 5% sustained throughput drop.

## Commit Message Convention

```
type(scope): short description

Longer description if needed.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`
Scopes: `afxdp`, `xdp-shim`, `cluster`, `vrrp`, `config`, `daemon`, `ra`
