# PR #797 — adversarial networking-OS review

## 1. mlx5 detection correctness

HIGH — D3 is applied to every `mlx5_core` netdev, not just interfaces bound to the userspace dataplane.

`applyRSSIndirection()` scans all of `/sys/class/net` and touches any interface whose driver basename is `mlx5_core`, with no check against the userspace binding plan (`pkg/daemon/rss_indirection.go:111-125`). That is broader than the doc claim that D3 affects interfaces “bound to `xpf-userspace-dp`” (`docs/785-d3-validation.md:5-14`). On a host with two mlx5 ports, or a PF/VF split where only one netdev is used by AF_XDP, the other interface would still get queues `workers..N-1` weighted to zero.

Mitigation: derive an explicit allowlist from the userspace binding plan or the compiled config and only touch mlx5 interfaces that will actually receive AF_XDP bindings.

## 2. ethtool invocation

LOW — The shell-out is safe from command injection, but feature compatibility is only discovered at runtime.

The implementation uses `exec.Command("ethtool", args...)`, so interface names are passed as argv rather than through a shell (`pkg/daemon/rss_indirection.go:60-62`); the netlink `ETHTOOL_MSG_RSS_SET` concern does not apply because this PR does not use netlink. Missing `ethtool` and other failures degrade safely via WARN logs (`pkg/daemon/rss_indirection.go:143-175`), but there is no preflight for whether this userland supports `-X ... weight ...`.

Mitigation: add a startup capability probe and a health bit when D3 cannot be applied.

## 3. workers count derivation

HIGH — Worker count is sampled once at daemon startup even though the userspace binding plan can change later.

`Daemon.Run()` reads `cfg.System.UserspaceDataplane.Workers` once and passes it into `enumerateAndRenameInterfaces()` once (`pkg/daemon/daemon.go:453-467`). Separately, the userspace helper treats `workers` as part of the binding-plan key and restarts itself when that plan changes (`pkg/dataplane/userspace/maps_sync.go:1173-1179`, `pkg/dataplane/userspace/process.go:285-295`). If workers change from 4 to 6, the helper can restart for six workers while a stale `[1 1 1 1 0 0]` table still starves queues 4 and 5.

Mitigation: recompute and apply or restore RSS whenever the userspace binding plan changes, not only during the initial startup path.

## 4. timing

No grounded timing bug found in the reviewed code.

`Daemon.Run()` performs interface enumeration and D3 before routing, FRR, or dataplane startup (`pkg/daemon/daemon.go:448-470`), and `linksetup.go` invokes D3 before returning from that phase (`pkg/daemon/linksetup.go:100-105`). That ordering avoids mid-traffic rehash during an active XSK lifetime.

## 5. idempotency

LOW — The idempotency check accepts any constrained table, not necessarily the intended equal-weight table.

`indirectionTableMatches()` returns true whenever all parsed queue IDs are `< activeCount`, without checking distribution (`pkg/daemon/rss_indirection.go:213-267`). A table like `0 0 0 0 1 2 3 3` would be treated as “unchanged” for four active workers even though the write path intends equal weights `1 1 1 1 0 0` (`pkg/daemon/rss_indirection.go:161-165`). The “reconciliation may reapply” concern does not apply today because the only call path is startup (`pkg/daemon/linksetup.go:100-104`).

Mitigation: compare the live table against the exact expected bucket distribution, or always rewrite when the table is not provably the target layout.

## 6. shutdown behavior

HIGH — There is no restore path, so D3 state can survive exit or config rollback in a way that contradicts the PR’s own invariants.

The code applies weights on startup (`pkg/daemon/rss_indirection.go:161-178`) but skips for `workers == 1` and `workers >= queues` (`pkg/daemon/rss_indirection.go:106-109`, `193-205`), and the only call site is the startup path (`pkg/daemon/linksetup.go:100-104`). A concrete failure mode is: start once with 4 workers on a 6-queue mlx5 and apply `[1 1 1 1 0 0]`; then restart with 1 worker or 6 workers and the code now skips, leaving the old restricted table in place. That contradicts the file’s own “single worker — keep default RSS” rationale (`pkg/daemon/rss_indirection.go:92-96`).

Mitigation: snapshot the pre-D3 table and restore it on shutdown or on D3 disable, or explicitly install a default/equal table whenever D3 is skipped after having been active before.

## 7. standalone vs cluster deploy

No separate cluster-role bug is proven beyond the interface-selection problem already noted in section 1.

D3 is gated by userspace dataplane config and worker count, not by RG ownership or HA role (`pkg/daemon/daemon.go:453-467`). That means it runs on standalone nodes and HA secondaries alike, but the reviewed code does not show that as inconsistent with how the userspace dataplane itself starts. The real risk is still wrong-interface selection, not secondary-role execution by itself.

## 8. thread safety

No grounded thread-safety issue found.

The only call path is `Daemon.Run()` during early startup (`pkg/daemon/daemon.go:448-470`), before cluster event goroutines are started (`pkg/daemon/daemon.go:487-502`). `applyRSSIndirection()` itself uses no shared mutable package state (`pkg/daemon/rss_indirection.go:101-179`), so concurrent `ethtool -X` on the same interface is not reachable from this diff.

## 9. test coverage

LOW — The arithmetic edge cases are covered, but the integration risks are not.

The tests do cover `workers == 1`, `workers == queues`, `workers > queues`, `workers < queues`, missing `ethtool`, and one matching-table case (`pkg/daemon/rss_indirection_test.go:61-129`, `131-219`, `245-265`). But the non-mlx5 test never exercises the real top-level scan path (`pkg/daemon/rss_indirection_test.go:187-205`), and nothing tests interface allowlisting, stale-state restoration, or runtime worker-count changes.

Mitigation: inject interface enumeration into the executor and add tests for interface selection, worker-count transitions, and restore behavior.

## 10. measurement methodology in `docs/785-d3-validation.md`

MEDIUM — The validation doc does not establish that the retransmit spike is only “cluster state noise.”

The fresh D3 run shows retransmits on every run, including 813 on run 1 (`docs/785-d3-validation.md:30-36`), while the “earlier D3 run” reports mean retransmits of 0 and better throughput (`docs/785-d3-validation.md:47-58`). The doc attributes that gap to a “quiet cluster” versus a “noisier” one (`docs/785-d3-validation.md:55-58`), but it records no cluster-state snapshot, NIC counters, queue stats, or `ethtool -x` dumps to prove that external noise, rather than D3 itself, explains the delta.

Mitigation: rerun matched A/B on the same deploy state, capture NIC and host retransmit/drop counters, and archive the live indirection table with each run.

## 11. observability

LOW — Operators only get one startup log line; there is no persistent status surface for what D3 did.

Successful application is logged once with `iface`, `workers`, `queues`, and `weights`, and skips/failures are also only logs (`pkg/daemon/rss_indirection.go:135-178`). If section 1’s wrong-interface case happens, the only clue is a boot-time journal entry. There is no metric, RPC field, or health output exposing the currently constrained interfaces or whether D3 fell back.

Mitigation: export D3 state in health/status output, including the target interface list and last apply result.

## 12. rollback story

MEDIUM — There is no first-class kill switch for D3.

D3 is wired directly into daemon startup when userspace dataplane config is present (`pkg/daemon/daemon.go:459-465`, `pkg/daemon/linksetup.go:100-104`). The reviewed `UserspaceConfig` surface contains `binary`, sockets, `workers`, `ring_entries`, and `poll_mode`, but no RSS/D3 toggle (`pkg/config/types.go:450-459`). If D3 causes a production regression, rollback is a manual `ethtool` or reboot procedure rather than a safe config change, and section 6 shows that merely lowering workers does not restore the table.

Mitigation: add an explicit global D3 enable/disable flag and define the operational rollback path as part of the feature, including table restoration.

## Where the PR holds up

D3 does run before dataplane bring-up and before any AF_XDP bind path (`pkg/daemon/daemon.go:448-470`, `pkg/daemon/linksetup.go:100-105`). The `ethtool` shell-out is not injection-prone and D3 failures are deliberately best-effort (`pkg/daemon/rss_indirection.go:60-62`, `143-175`). The unit tests cover the core weight-vector edge cases (`pkg/daemon/rss_indirection_test.go:61-129`); the gaps are in scope selection and lifecycle.
