# Triage result — ps-review-044 (Paladin Defensive-Coverage Campaign, 23 batches, ~11.7k lines)

**Review base:** `f1ef0eec8` · **Verified against origin/master:** `a6fcd463b` (7 PRs #5651–#5657 merged since base).
**Method:** parent + 4 read+verify subagents on the material-heavy batches (A1 Rust, A3 config, A4/A5 HA, A7 daemon); parent handled A2 NAT and the A6/A8/A9/A10 modularity batches directly. Every FILE candidate re-verified by the parent on origin/master before filing (symbol grep, whole-function-body read, dedup vs 204 open issues).

## Headline
This review is **overwhelmingly a modularity/refactor audit** with a thin layer of material defensive-coverage findings. The security surface (zone/global policy fail-open, VRRP/HA int-truncation, host-inbound, screen thresholds, default-deny) has already been hardened across 310 prior reviews — nearly every "HIGH/CRITICAL"-labeled finding is **confirmatory** ("Fix direction: Fixed (#NNNN)") or a **negative result**. Only 5 findings (across 3 issues) survived all 3 gates as genuinely new + material + not-already-tracked.

## Summary line
**3 filed (#5658, #5659, #5660 — covering 5 findings) / ~15 already-fixed-or-confirmatory / 6 dup-of-open-issue / ~60 cohort (existing #4421/#4422/#5190) / ~55 dropped (negatives/self-refuted/test-only/info).**

---

## FILED

### #5658 — nat: static block-to-block & DNAT install lack a minimum-prefix floor (A2 F7+F8)
- **Root:** `static_nat.rs from_snapshots` (origin/master:387-410) rejects family/length-mismatch + port-bearing blocks but has **no `len==0` floor**; a `/0↔/0` equal-length pair installs a whole-internet 1:1 static NAT (`host_mask_v4(0)=u32::MAX` → `contains()` true for all IPv4). Go `validateNATHostMaskStrict` (compiler_validate_strict_nat.go:947-989) also accepts it (commit-reachable). F8: `destination.rs:1049` pushes `slot.network()` unconditionally → `/0` registers `0.0.0.0` local.
- **Gate outcome:** FILE. symbol-exists ✓ (both paths live), not-already-fixed ✓ (no floor on either side), real+material ✓ (commit-reachable fail-open; sibling reject branches in the same fns establish the fail-closed contract this escapes). No open-issue dup. Severity Low–Med.

### #5659 — host-inbound: empty-zone ingress interface (zone_id 0) admit-all — #2391 backstop symmetry gap (A1 FH-001)
- **Root:** `interfaces.rs:62-92` zone→zone_id insert (+#2391 fail-closed) is guarded by `!iface.zone.is_empty()`, but `local_v4`/`local_v6` (149-179) are populated unconditionally; `host_inbound.rs:493-501` `host_inbound_admits(0)` → `None => true` (admit). Contradicts zoneid.go:172-175 quarantine "traffic denied" promise for host-inbound.
- **Gate outcome:** FILE (with honest reachability caveat). symbol-exists ✓, not-already-fixed ✓ (#2391 covers only *non-empty* unknown zone), real ✓ (asymmetry confirmed). **Reachability is gated** — unzoned interfaces are skipped by the AF_XDP bind gate (interfaces.go:147) and `host_inbound_configured` empty-override fails closed — so I filed it as a **fail-closed-symmetry / defense-in-depth** gap, not a confirmed Medium bypass, with the full adversarial analysis in the body so the maintainer makes the final call. Downgraded from the subagent's "Medium" to Low+caveat. No dup (distinct from #5566/#3226/#5568).

### #5660 — nat/allocator: deterministic-reverse O(N) scan + unchecked port_of cast (A2 F9+F10 cohort)
- **Root:** `allocator.rs:251/391` `pool_v4.iter().position(...)` O(N)≤64k linear scan on reverse cold path; `:503` `port_of` u32→u16 cast safe-today-but-undocumented. Both live, Low/Info. Cohorted per campaign convention (the team-lead's "one cohort issue" for bounded-hardening survivors). Note: `reverse_deterministic_v6` taking `pool_v4` is **correct** (NAPT64 external side is IPv4) — not the copy-paste bug it first appeared to be.

---

## DUP of existing open issue (NOT refiled)

| Finding | Verdict | Reasoning |
|---|---|---|
| A2 F1 — address-only SNAT HA reservation missing | **dup #5338** | Exact same root: `reserve_synced_source_nat_allocation` early-returns when `rewrite_src_port` is None (skips address-only/no-port). #5338 title is verbatim this. Review's "not in dedup-index" was stale (base predates #5338). |
| A2 F2 — reserve_flow frees deterministic port with recycle=true | **dup #5446** (sibling #5178) | Same fn (`reserve_flow`), same bug (deterministic port hits recycle FIFO). #5446 = "HA reserve_flow marks deterministic-CGNAT/NAT64 synced flows as non-deterministic → recycle-queue leak". Both open. |
| A2 F3 — NAT64 Pref64 hairpin missing RFC 6146 §5 drop | **dup #5623** | Review self-marks "(confirmed dedup)"; #5623 = "no Pref64 source-eligibility rejection". |
| A2 F4 — NAT64 strips AH / translates active RH | **dup #5625** | Review self-marks confirmed-dedup; #5625 = "EH walker strips/translates AH". |
| A2 F5 — NAT64 BIB endpoint-dependent (EIM violation) | **confirmed-dedup (prior)** | Review self-marks "(confirmed dedup)" vs a prior campaign issue; not in current open set (filed+closed earlier). Not refiled per review's own dedup. |
| A2 F6 — NAT64 frag cache serializes workers on public FNV | **confirmed-dedup** (adjacent #5447/#2562) | Review self-marks confirmed-dedup; frag-cache DoS surface tracked by #5447 (evict) + #2562 (stateful frag cache). |

---

## ALREADY-FIXED / CONFIRMATORY (verified present on origin/master — NOT refiled)

**A3 config (b2/b3/b4) — entire slice is a negative/confirmatory sweep.** Spot-verified the 4 highest-severity "already-fixed" claims live on origin/master:
- Syslog log-file path-traversal + PermView authz → **#4860** present (`syslog_logfile.go:41`).
- SNMP `restrict` typo fail-open → **#4834** present (`snmp_clients.go:187`).
- Secret JSON/YAML redaction + REST sentinel-refuse → **#2053** present (`secret.go:141/160/194`).
- System string injection into root service configs → **#4902** present (`schema_validators_system.go:276-338`).
- Multi-zone scoped-global policy (parent watch #4626) → **already-fixed** (`schema_security.go` firewallMatchValues multi-list + `scoped_global_zoneset_4626_test.go`).
- A3-b2 VRRP/policy Findings 1-13 (VRID/priority uint8 truncation, screen u32 wrap, default-policy fail-open, match-ANY, unsupported-leaf drop, zone bracket collapse, host-inbound split-brain, filter symbolic drop, interface-range MaxInt64 loop) — **all end "Fix direction: Fixed (#3065/#3044/#3113/#3200/#3205/#3317/#4434/#4573/#4826/#5184/#5248/#5373…)"**; confirmatory, no new work.

**A7 daemon:** D-06 scp archive argv-injection → **already-fixed** (`daemon_flow.go:529` `--` separator + commit-time leading-dash reject). F7 IPsec endpoint-validation gap → **already-fixed by #5657**.

**A4 configstore:** clean security audit, author verdict "No blocking persistence or crypto defects" — all durability/crypto/redaction seams PASS with RED-on-revert tests.

---

## COHORT (route to existing cohort issues — NOT filed individually per "don't file 20 trivial ones")

- **→ #4421 (Refactor/modularity backlog):** the bulk of the review. All god-file/monolith/decomposition findings:
  - A1-b2 (9): poll_descriptor 4840, types/cos.rs, neighbor.rs, umem, tx/dispatch, shared_ops, session_glue, wg/engine.
  - A5 (8): sync_conn.go 1858, vrrp/instance.go 2417, vrrp/manager.go, sync_protocol.go, heartbeat.go, sync.go, ra.go+sender.go, cluster lock-domain. (LOC all verified exact on origin/master.)
  - A6 (M1-M12): protocol.go 3064, maps_sync.go, manager_ha.go, Manager god-struct, NAT/policy/zones/process compile fusion.
  - A7 (34): daemon_run.go 2492 (also #4662), daemon_apply.go 2265 (#4407), daemon_nft/system, frr/policy_render 2309, networkd, linksetup, ipsec policy/ike, routing/tunnel.go 2016, routing/rules.go, upgrade orchestrators.
  - A8 (all): metrics_descriptors, NewServer route-reg, sessions.go, security.go matchPoliciesHandler, SystemAction switch, server_diag_zeroize.
  - A9 (all): snmp/agent.go 2143, logging/ringbuf, eventengine, feeds, flowexport, snmp/v3, syslog.
  - A10 (all): cli_show_flow.go 1262, cli_show_routing 1156, ddns/dhcp god-managers, xpf-deploy.py 2243.
  - **Scope note:** #4421's title names Rust-dataplane + rules.go. The Go HA/cluster/daemon/frr/routing/upgrade god-files are an adjacent scope not individually enumerated there; recorded here as belonging to the modularity umbrella. If scope hygiene is wanted, a single new "Go control-plane modularity" cohort could seed from this list — deferred to the lead (did not file to avoid a redundant modularity tracker).
- **→ #4422 (test-coverage/observability backlog):** A3 IsIdentRune parity test, tcp_flags fuzz; A7 host_tunables test-seam.
- **→ #5190 (userspace-dp observability LOW cohort):** A1-b3 CoS status queued_bytes speculation, slowpath WriteError taxonomy, empty concrete-zone histogram-dark.

---

## DROPPED (negatives / self-refuted / test-only / info)

- **A5 Finding 8 (dual-GARP divergence):** REFUTED by code — `vrrp/instance.go:2303` calls `cluster.SendGratuitousARPBurstGated`; vrrp's `sendGARP` applies the epoch/dampener gate then delegates (layered, not duplicated). daemon_proxyarp.go is a separate feature. No divergence.
- **A1 I-001 (TCP-seg u16 wrap):** cited `tcp_segmentation.rs:608` is a `#[cfg(test)]` helper; production casts bounded by netlink MTU (≤65535). Symbol-misidentified + not reachable.
- **A1 b3 F6-F11:** self-labeled negative confirmations (DSCP >63 reject, L4 flow-cache gate, screen truncation fail-closed, session_id wrap-guard #4915, snapshot monotonicity #5169/#3767, SYN-cookie SipHash domain separation).
- **A7 D-04 (SNMP teardown deadlock):** refuted (ctx-cancel unblocks ReadFromUDP; idempotent Stop). D-05 neighbor probe-max env: deliberate root-gated bound.
- **A3 b1/b3:** lexer isIdentChar (intentional Junos parity, 3-layer defense), junos_host_deny Atoi casts (range-checked), parser depth-cap 256 (correct DoS guard), all L-01..L-08 confirmatory.
- **A2 F10 → folded into #5660** (port_of, Info). A2 I-002 LOCAL_DELIVERY_IFINDEX0 (diagnostic, self-refuted).
- Numerous A5/A7 "NOT MONOLITHIC / DO-NOT-SPLIT" negatives and A9 cohesive-small negatives.

---

*Marker: `/tmp/.researched-ps-review-044.md`. All ground truth verified via `git show origin/master:<path>`, never the stale main checkout.*
