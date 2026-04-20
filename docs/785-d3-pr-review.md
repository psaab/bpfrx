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

## Round 2 verification

ROUND 2: NOT READY — H1 and H2 are only partially fixed, and the rollback/kill-switch work is improved but still incomplete.

### H1

PARTIAL — there is now an explicit call-site mlx5 guard, so a mixed-NIC startup that enumerates `virtio_net` does avoid `ethtool`: `applyRSSIndirection()` reads `drv := execer.readDriver(iface)` and skips unless `drv == mlx5_core` before calling `applyRSSIndirectionOne()` (`pkg/daemon/rss_indirection.go:160-173`, exact guard at `pkg/daemon/rss_indirection.go:165`). The mixed-driver tests exercise that path and assert zero `ethtool` calls on non-mlx5 interfaces (`pkg/daemon/rss_indirection_test.go:193-243`).

The original overbreadth is still not fully fixed. The top-level scan still iterates every interface returned by sysfs and applies to every `mlx5_core` netdev, with no allowlist derived from the userspace binding plan or compiled config (`pkg/daemon/rss_indirection.go:154-173`). The new disable/restore path inherits the same all-mlx5 scope (`pkg/daemon/rss_indirection.go:182-206`). That still conflicts with the validation doc claim that D3 targets interfaces "bound to `xpf-userspace-dp`" (`docs/785-d3-validation.md:5-15`).

### H2

PARTIAL — the daemon reconcile path is now wired correctly, but not every live commit path uses it.

For daemon-managed API commits, the wiring is real: the daemon injects `d.applyConfig` as the server `ApplyFn` (`pkg/grpcapi/server.go:36-55`), and both gRPC and HTTP commit handlers call that callback after `store.Commit()` / `store.CommitConfirmed()` (`pkg/grpcapi/server_config.go:155-186`, `pkg/api/handlers.go:1518-1536`). Inside `applyConfig`, step 21 now recomputes `rssEnabled`/`workers` and calls `reapplyRSSIndirection()` unconditionally when dataplane is enabled, so a dataplane-only commit still triggers the D3 path even if linksetup itself did not change (`pkg/daemon/daemon.go:2283-2298`).

But daemon interactive mode still bypasses that path. In interactive mode the daemon creates a local CLI (`pkg/daemon/daemon.go:1076-1079`); CLI commits call `c.applyToDataplane(compiled)` directly (`pkg/cli/cli_config.go:170-239`), and `applyToDataplane()` compiles the dataplane but never calls `d.applyConfig()` or `reapplyRSSIndirection()` (`pkg/cli/cli.go:1407-1434`; `reapplyRSSIndirection` not found under `pkg/cli`). Worker-count changes are still real dataplane changes on that path because the userspace helper restart key includes `Workers` (`pkg/dataplane/userspace/process.go:24-35`, `957-964`) and the binding-plan key includes `workers=%d` (`pkg/dataplane/userspace/maps_sync.go:1173-1204`). So a live `set system dataplane workers N` committed from the in-process CLI still skips the D3 reapply.

I did not find a grounded "4 -> 2 retires queues and drops packets" race in the current helper. The queue planner keeps one binding per queue and only remaps `worker_id` modulo the new worker count (`userspace-dp/src/main.rs:1122-1154`), so the concrete remaining bug here is the missing commit-path wiring, not steering to unbound retired queues.

### M

PARTIAL — the new knob exists and works on the daemon reconcile path, but it is not fully documented and still does not restore on daemon stop.

`rss-indirection` is now a first-class `system dataplane` schema entry with the expected `enable|disable` surface (`pkg/config/ast.go:1374-1380`). Default is enabled because `RSSIndirectionDisabled` is false by default and the compiler only flips it on for the literal string `disable` (`pkg/config/types.go:460-465`, `pkg/config/compiler_system.go:448-453`); the parser tests pin both the default and the `enable`/`disable` cases (`pkg/config/parser_ast_test.go:2682-2735`). This follows the local `poll-mode` convention of schema-desc + compiler-side accepted values (`pkg/config/compiler_system.go:444-453`).

On the daemon reconcile path, toggling the knob does rerun the D3 code: startup passes `rssEnabled` into `enumerateAndRenameInterfaces()` (`pkg/daemon/daemon.go:453-473`, `pkg/daemon/linksetup.go:45-107`), commit-time reconcile calls `reapplyRSSIndirection()` (`pkg/daemon/daemon.go:2283-2298`), and `enabled=false` actively restores the default table with `ethtool -X <iface> default` (`pkg/daemon/rss_indirection.go:131-141`, `177-207`). But the interactive CLI commit path above still bypasses that logic (`pkg/daemon/daemon.go:1076-1079`, `pkg/cli/cli_config.go:170-239`, `pkg/cli/cli.go:1407-1434`).

The knob is not fully documented. The only user-facing description I found is the schema string in `pkg/config/ast.go:1379`; the validation doc still describes D3 as a startup-only feature and does not mention `rss-indirection enable|disable` at all (`docs/785-d3-validation.md:12-16`). On daemon stop, the table still persists rather than restoring: the shutdown path never calls `restoreDefaultRSSIndirection()` or any equivalent restore (`pkg/daemon/daemon.go:1167-1259`), and that restore helper is only reachable from `applyRSSIndirection(enabled=false, ...)` (`pkg/daemon/rss_indirection.go:131-141`, `182-206`).

### New findings

LOW — No test covers the new commit-time wiring end to end. The added tests prove config compilation of the knob (`pkg/config/parser_ast_test.go:2690-2735`) and the direct helper behavior of `applyRSSIndirection(false, ...)` (`pkg/daemon/rss_indirection_test.go:289-318`), but I found no test for `applyConfig()` step 21 or for the interactive CLI commit path (`reapplyRSSIndirection` / `applyToDataplane` test coverage not found). Mitigation: add a daemon/CLI-level test with an injectable RSS executor that proves gRPC, HTTP, and in-process CLI commits all re-run apply/restore.

PR readiness: NOT READY — the daemon API paths now reapply D3 on commit, but the in-process CLI commit path still bypasses that logic, H1 still touches every mlx5 interface instead of only the userspace allowlist, and shutdown still leaves the RSS table behind.
