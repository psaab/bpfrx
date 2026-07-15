# Triage result — codex-review-177 slice A8 / A9 / A10

- Triager: triage-177-C
- Review base: d22789fa6 (STALE)
- Verified against CURRENT origin/master: **812bf30c1** (`git fetch origin master` first)
- Total findings in slice: **52** (A8 ×16, A9 ×10, A10 ×26)
- Method: 5 verification helpers re-checked every finding against current origin/master via
  `git show origin/master:<path>` (3 gates: symbol-exists / already-fixed / real+material)
  + dedup vs 76 open issues. Every symbol was read on current origin/master.

## Tally
- **Filed 45 new issues** (#5031–#5077) covering **46 findings** (A8-b1-F14 + A8-b2-F7 cohorted into one, #5046).
- **DUP: 3** — A8-b1-F5 → #4883, A10-b1-F6 → #4908, A10-b2-F5 → #4883.
- **NOT-REAL: 3** — A8-b2-F8, A8-b1-F8, A10-b1-F2.
- **ALREADY-FIXED: 0**, **RETIRED-PATH: 0**. (The 33 recent merges touched adjacent
  api/config/snmp/logging/nat code — including the #4883/#4886/#4908 cohorts we deduped
  against — but none remediated these specific defects; all cited symbols are live.)

Verdict legend: FILE-#N · DUP-#N · NOT-REAL · ALREADY-FIXED · RETIRED-PATH

---

## Per-finding verdicts

### High-confidence block (all GENUINE, filed)
| Finding | Verdict | origin/master anchor |
|---|---|---|
| A8-b2-F1 | FILE-#5035 | grpcapi/server.go:260-271 — Run binds any --grpc-addr, no loopback guard (unauth zeroize/commit). security |
| A9-b1-F1 | FILE-#5036 | daemon_run.go:463-470 / daemon_feeds.go:22-29 — feed mgr boot-only, no day-2 reconcile → deny fail-open. security |
| A10-b2-F1 | FILE-#5037 | cli_dispatch.go:132-146 — `\| last N` make([]string,N) from unbounded operand, view-only OOM. security; xref #4886 |
| A10-b2-F2 | FILE-#5038 | monitor.go:23,47-124 — view-level flow-trace opens/rotates any /var/log inode as root. security |
| A10-b2-F3 | FILE-#5039 | cli_request_system.go:177-184 — ISSU prints drain-complete+stop from desired state only |
| A10-b3-F1 | FILE-#5040 | dhcpserver/lease_sync.go:631-637 — active-active takeover pre-seed wipes still-mastered RG leases |
| A10-b3-F2 | FILE-#5041 | dhcpserver/dhcpserver.go:860-875,983-994 — Kea subnet-id positional over HA-filtered subset → misbind |
| A10-b4-F1 | FILE-#5042 | image/bake.py:667 + deploy/xpf-deploy.py:1390-1417 — mixed-base gate reads unsigned .manifest. security |
| A10-b4-F2 | FILE-#5043 | deploy/xpf-deploy.py:567-577 — fetch --install-libvirt overwrites golden in place → overlay corruption |
| A10-b4-F9 | FILE-#5044 | upgrade/cluster_cli.go:524-533 — configuredRGs {0,1,2} fallback leaves RG>=3 demoted at rejoin |

### Medium-confidence block (A8/A9 REST/grpc/eventengine/rpm)
| Finding | Verdict | origin/master anchor |
|---|---|---|
| A8-b1-F2 | FILE-#5054 | daemon_run.go:1119-1120 — REST/local-shell commit skips peer config-sync (HA stale-intent) |
| A8-b1-F4 | FILE-#5055 | api/auth.go:66-84 / api.go:103-116 — no CSRF/cross-site defense on mutation routes. security |
| A8-b1-F5 | DUP-#4883 | api/dhcp.go:83-107 — zero-value Interface → ClearAllDUIDs; malformed-clear→clear-all already tracked |
| A8-b1-F6 | FILE-#5056 | api/routing.go:88 / frr/vtysh.go:85-97 — BGP endpoint materializes full RIB, ignores cancel |
| A8-b1-F7 | FILE-#5057 | api/system.go:113-155 — ping/traceroute no aggregate concurrency bound (mgmt DoS). security |
| A8-b1-F8 | NOT-REAL | api/server.go:390-399 — promhttp Timeout≠gather-cancel; no blocking collector on live path (defensive) |
| A8-b1-F9 | FILE-#5058 | api/server.go:546-576 — Run leaks surviving HTTP/HTTPS listener on sibling failure |
| A8-b2-F2 | FILE-#5059 | grpcapi/server_config.go:50 / configstore/store_command.go:11-27 — mutators ignore lock holder. security |
| A8-b2-F4 | FILE-#5060 | grpcapi/server_diag_ping.go:108,127 — Scanner ErrTooLong leaks RPC/goroutine. security |
| A9-b1-F2 | FILE-#5061 | rpm/icmp.go:339-349 vs rpm.go:60-80 — VRF resolver setup fail counted as loss → route action. security |
| A9-b1-F3 | FILE-#5062 | eventengine/engine.go:565-635 — supersede races producers, drops unrelated accepted action |
| A9-b1-F4 | FILE-#5063 | eventengine/engine.go:813-818 — armed nonfatal commit counted rejected, no cooldown, re-commits |

### Medium-confidence block (A9/A10 snmp/cli/dhcp/upgrade)
| Finding | Verdict | origin/master anchor |
|---|---|---|
| A9-b1-F5 | FILE-#5064 | logging/eventbuf.go:148 — drops security records to slow subs, no seq/overrun/metric. audit |
| A9-b1-F7 | FILE-#5065 | snmp/agent.go:841-854 + v3.go:457-469 — GETBULK column-major, violates RFC 3416 §4.2.3 |
| A10-b1-F2 | NOT-REAL | build-userspace-xdp.sh:156 — verify/install TOCTOU only under concurrent manual generate; repro gate catches |
| A10-b2-F4 | FILE-#5066 | cli/session_filter.go:185-191,298 — clear ... summary/brief/sort-by parses clean → clears all |
| A10-b2-F5 | DUP-#4883 | cli/monitor.go:658-662 — flow-trace writer error leaves monitor Active (verbatim in #4883) |
| A10-b2-F6 | FILE-#5067 | cli_show_security_filters.go:348-377 — `firewall ... effective` misreports after disarmed apply |
| A10-b2-F7 | FILE-#5068 | cli/completion.go:473 + cli_show_interfaces_terse.go:33-44 — nil iface/unit map value panics CLI |
| A10-b2-F8 | FILE-#5069 | cli_show_system.go:785-816 — show log N unbounded, CombinedOutput buffered (PermView DoS); xref #4886 |
| A10-b3-F5 | FILE-#5070 | ddns/backend_bind.go:70-75,132 — SO_BINDTODEVICE uses raw RI/Junos names, not kernel devs. vsrx-parity |
| A10-b3-F7 | FILE-#5071 | dhcprelay/relay.go:1141,1516 — second-hop relay overwrites giaddr+Opt82 (RFC 1542 §4.1.1). vsrx-parity |
| A10-b3-F9 | FILE-#5072 | dhcpserver/ddns.go:59-65 — IA_PD discriminator dropped → prefix base published as AAAA/PTR. security |
| A10-b3-F10 | FILE-#5073 | dhcpserver/lease_sync.go:85-94,709 — DHCPv6 preferred lifetime dropped → deprecated revived; xref #4871 |
| A10-b4-F4 | FILE-#5074 | upgrade/cutover.go:648-664 — rollback preflight treats any stat error as DB-absent, no snapshot |
| A10-b4-F6 | FILE-#5075 | deploy/xpf-deploy.py:1595-1602 — image-roll accepts any responding xpfd, no version match |
| A10-b4-F8 | FILE-#5076 | upgrade/kernel_linux.go:549-560 — failed purge then unconditional delete of pkg-owned files |
| A10-b4-F12 | FILE-#5077 | test/incus/step1-histogram-classify.py:258-266 — submit classifier negative deltas; xref #4907. audit |

### Low-confidence tail
| Finding | Verdict | origin/master anchor |
|---|---|---|
| A8-b1-F12 | FILE-#5045 | api/metrics.go:1039 vs :1056 — counter-read error series lost to IsLoaded early return |
| A8-b1-F14 | FILE-#5046 | api/nat.go:29-31,285-288 — NAT stats REST fail-open to zero (cohorted with A8-b2-F7). nat |
| A8-b2-F6 | FILE-#5047 | grpcapi/server.go:316-349 — fabric listener listen/Serve failure terminal + unsupervised |
| A8-b2-F7 | FILE-#5046 | grpcapi/server_nat.go:133-135,224-227 — NAT stats gRPC fail-open to zero (cohorted with A8-b1-F14) |
| A8-b2-F8 | NOT-REAL | grpcapi/server_config.go:288-307 — unknown enum → candidate default; needs hand-crafted client, redaction holds |
| A8-b1-F13 | FILE-#5031 | api/health.go:23-51 + auth.go:26-32 — unauth /health leaks raw compile/bootstrap errors. security |
| A9-b1-F9 | FILE-#5048 | flowexport/transport.go:475-479 — max-depth high-water RMW outside mutex, can regress |
| A9-b1-F10 | FILE-#5032 | snmp/v3.go:798-820,824-840 — priv params random, not RFC-unique salts. security |
| A9-b1-F11 | FILE-#5049 | snmp/agent.go:605-618 — v1 traps supported but v1 GET/GETNEXT dropped. vsrx-parity |
| A9-b1-F12 | FILE-#5050 | daemon_snmp_reconcile.go:166-169 — IF-MIB HC unicast = Linux totals, mcast/bcast double-count |
| A10-b1-F4 | FILE-#5051 | cmd/cli/monitor.go:368-410 — monitor security packet-drop drops malformed selectors (fail-open); xref #4883 |
| A10-b1-F5 | FILE-#5052 | cmd/cli/show_system.go:28-58, show.go:398 — rollback display selectors int32-truncate to wrong slot |
| A10-b1-F6 | DUP-#4908 | cmd/cli/show_nat.go:207-226 — DNAT summary shows zero on stats-RPC failure (in #4908 cohort) |
| A10-b1-F7 | FILE-#5053 | cmd/cli/shared.go:42 / main.go:150 — configMode bool data race SIGINT vs dispatch |

---

## Notes
- Cohort: A8-b1-F14 (REST) + A8-b2-F7 (gRPC) are the same NAT-stats-fail-open-to-zero defect on
  two surfaces → filed once as #5046. Their CLI sibling A10-b1-F6 was already tracked (#4908).
- 3 cross-references embedded in issue bodies (not dups, distinct roots): #5037/#5069→#4886,
  #5073→#4871, #5077→#4907, #5051→#4883.
- Security label applied to: #5031, #5032, #5035, #5036, #5037, #5038, #5042, #5055, #5057,
  #5059, #5060, #5061, #5072 (auth / info-disclosure / fail-open / privilege / DoS-by-untrusted).
- No code changed, no PRs, no git-mutation. Only `gh issue create` + this ledger.
