OpenAI Codex v0.153.1
--------
workdir: /var/tmp/RES8865
model: gpt-6-astra
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 01a07150-c2ee-72b1-ad23-a3b8f60ac6be
--------
user
You are performing a HOSTILE plan review. Your job is to FAIL this plan if its architecture or reasoning is wrong. Do not synthesize, do not be agreeable, do not produce "READY with nits" as a default.

Read the plan at docs/research/8865-muse-spark-008-009/plan.md in this worktree.

Context you must verify rather than accept:
- It plans work against two external review reports (113 findings total) that are 128+ commits stale.
- It recommends CLASS-FIRST triage over FINDING-FIRST.
- Its central evidence is a 5-member "wire-count allocation" class in pkg/cluster that it claims enumerates completely in four commands.

Attack these specifically:
1. Is the class-first recommendation generalised from ONE well-behaved class? Check whether the OTHER named classes (multi-statement packed fold, reserved-name, commit/load asymmetry) actually enumerate as cheaply. If they do not, the recommendation is built on the easiest case.
2. The plan examined roughly 8 of 113 findings. Is its 4-class map a plan for 113 findings or a plan for 8, presented as the former?
3. It sequences 008 H4 (an accepted commit that bricks the next boot) SECOND, and admits H4 is unverified. If H4 is real, is that sequencing defensible?
4. It claims class-first lets "one change close many findings" but the wire-count fix closes 2. Is the claim supported at the strength stated?
5. It dismisses instrument-first using #8830's 1-defect-from-32-rows ratio - but that instrument found a live IPsec security defect that enumeration had missed. Is the cost being used to argue against a method that worked?

Verify claims against the actual code in this worktree where you can. pkg/cluster/sync_protocol.go:806 and :1231 are the two live sites; pkg/cluster/sync_persistent_nat_lease_8121.go:152 is the fixed sibling.

Output verdict as exactly one of: PLAN-READY / PLAN-READY-WITH-NITS / PLAN-REVISE / PLAN-KILL, followed by numbered findings, each with the evidence you checked. Be specific about what you verified versus what you reasoned about.

codex
I’ll check the plan, the reports, and the cited code, then separate verified defects in the plan from unresolved claims.

exec
/bin/bash -lc "pwd && rg --files -g 'AGENTS.md' -g 'plan.md' -g '*008*' -g '*009*' -g '*8830*' docs .codex pkg/cluster 2>/dev/null" in /var/tmp/RES8865
 succeeded in 0ms:
/var/tmp/RES8865
docs/pr/1527-dpdk-boot-decouple/plan.md
docs/pr/1772-neighbor-latency-metrics/plan.md
docs/pr/1611-flooder-runner-body/plan.md
docs/pr/1520-userspace-boot-extraction/plan.md
docs/research/1928-virtio-copy-xsk-rx/plan.md
docs/pr/1732-waterfill-persistent-honored/plan.md
docs/research/2170-ha-deferred-delete/plan.md
docs/pr/1189-coordinator-decompose/plan.md
docs/research/5275-arm-failclosed/plan.md
docs/research/1921-virtio-mq-bind/plan.md
docs/pr/1205-cos-drift-check/plan.md
docs/pr/1623-path-b-narrow/plan.md
docs/pr/1673-readme-refresh/plan.md
docs/pr/p2c-tx-transmit/plan.md
docs/pr/1865-wg-telemetry/plan.md
docs/research/8865-muse-spark-008-009/plan.md
docs/pr/881-cpu-windows/plan.md
docs/pr/1628-cos-instr/plan.md
docs/research/3616-ipsec-host-inbound/plan.md
docs/pr/1476-mechanical-bpf-removal/plan.md
docs/pr/1755-cos-probestack/plan.md
docs/pr/2315-wg-gre-decap-ecn/plan.md
docs/research/1982-upgrade-manifest-ssot/plan.md
docs/pr/916-cos-deadlock/plan.md
docs/pr/963-frame-builder/plan.md
docs/research/1855-inplace-contract/plan.md
docs/pr/7209-syncsession-off-lock/plan.md
docs/pr/814-max-interfaces/plan.md
docs/pr/1743-cos-waterfill-shaped-budget/plan.md
docs/research/ddns-world-class/plan.md
docs/pr/1712-ospf-per-interface-area/plan.md
docs/pr/1043-server-show-split/plan.md
docs/pr/screen-correctness-narrow/plan.md
docs/research/2197-proxyarp-followups/plan.md
docs/pr/screen-correctness/plan.md
docs/pr/p2b-tx-rings/plan.md
docs/research/2150-parser-consolidation/plan.md
docs/pr/1319-typed-leaf-pr1/plan.md
docs/pr/2074-remote-addrs-name-leak/plan.md
docs/research/1919-wg-addr-route-prune/plan.md
docs/pr/915-exact-surplus-sharing/plan.md
docs/pr/2120-standby-wheel-expiry/plan.md
docs/pr/835-slice-d-rss/plan.md
docs/pr/900-100e100m-harness/plan.md
docs/research/1881-gre-frozen-state/plan.md
docs/pr/7494-non-first-fragment/plan.md
docs/pr/1304-equal-flow-estimator/plan.md
docs/pr/1330-fairness-eval-library/plan.md
docs/pr/2072-route-filter-upto/plan.md
docs/pr/1893-configstore-durability/plan.md
docs/pr/821-p1-sched-switch-capture/plan.md
docs/pr/959-phase6-timers/plan.md
docs/research/6744-kimi-review-003/plan.md
docs/pr/1546-filter-engine-split/plan.md
docs/pr/1699-config-ast-schema-split/plan.md
docs/pr/2138-snat-protocol-abort/plan.md
docs/pr/1706-routing-latent-defects/plan.md
docs/pr/956-phase4-token-bucket/plan.md
docs/pr/1325-protocol-split/plan.md
docs/pr/1531-dpdk-docs-retire/plan.md
docs/pr/1538-multierror-validation/plan.md
docs/research/1888-wg-timers/plan.md
docs/pr/2128-session-limit-leak/plan.md
docs/pr/914-rate-aware-admission/plan.md
docs/pr/1606-wire-protocol-address-book/plan.md
docs/research/2155-vrrp-cluster/plan.md
docs/pr/959-phase3-cos/plan.md
docs/pr/1547-frr-split/plan.md
docs/pr/5800-iouring-inflight-registry/plan.md
docs/pr/2071-ipv6-prefix-list/plan.md
docs/pr/805-rss-refresh/plan.md
docs/pr/1432-wg-s2a-datapath-socket-config/plan.md
docs/pr/1760-collision-counter/plan.md
docs/pr/1282-segmiss/plan.md
docs/pr/7487-fabric-auth-skew-independent/plan.md
docs/pr/2089-reject-action/plan.md
docs/pr/956-phase5-queue-ops/plan.md
docs/pr/p2c2-tx-drain/plan.md
docs/pr/879-cluster-peer-rendering/plan.md
docs/research/1880-boot-budget/plan.md
docs/pr/1714-stale-not-implemented-notes/plan.md
docs/pr/1694-getmapstats-name-count-fix/plan.md
docs/pr/1667-snat-docguard/plan.md
docs/pr/547-rss-skew-fixture/plan.md
docs/pr/1540-rest-api-split/plan.md
docs/pr/1866-wg-teardown/plan.md
docs/research/7409-learned-route-fib/plan.md
docs/pr/1210-stale-cos-comments/plan.md
docs/pr/1896-journal/plan.md
docs/pr/1686-maps-domain-split/plan.md
docs/pr/1188-runtime-snapshot/plan.md
docs/research/2139-eventoptions-cluster/plan.md
docs/pr/5630-ipsec-endpoint-validate/plan.md
docs/pr/6458-fabric-zone-stamp/plan.md
docs/pr/1691-cos-push-ceiling-gate-rescope/plan.md
docs/pr/959-phase8-bindmeta/plan.md
docs/pr/869-worker-runtime/plan.md
docs/pr/921-zone-id-maps/plan.md
docs/research/1946-fabric-redirect-asymmetry/plan.md
docs/pr/vlan-hwaccel/plan.md
docs/pr/946-pipeline-phase1/plan.md
docs/pr/1598-cos-uncapped-fix/plan.md
docs/research/3607-screen-rate/plan.md
docs/research/1961-wire-type-dscp/plan.md
docs/pr/1431-filter-cache-invariants/plan.md
docs/research/3643-dead-counters/plan.md
docs/research/1884-tunnel-flap/plan.md
docs/pr/1326-worker-loop-extract/plan.md
docs/research/2239-dhcp-ha-lease-sync/plan.md
docs/research/2387-vrf-flow-identity/plan.md
docs/pr/2008-h7-log-default-profile/plan.md
docs/pr/1630-cause1-credit-carry/plan.md
docs/pr/2118-policy-hit-count/plan.md
docs/research/4408-hotpath-split/plan.md
docs/pr/2154-parseleasecsv/plan.md
docs/pr/1565-iface-name-translate/plan.md
docs/pr/p2d-tx-classify/plan.md
docs/pr/913-mqfq-vtime/plan.md
docs/pr/1354-transmit-phase-split/plan.md
docs/pr/1501-a2-outer-udp-cs/plan.md
docs/pr/1863-realization-gap/plan.md
docs/pr/line-rate-investigation/plan.md
docs/pr/2491-static-nat-port-fwd/plan.md
docs/pr/1539-ast-leakage-guard/plan.md
docs/pr/1515-conntrack-gc-canary/plan.md
docs/pr/2125-2126-ipsec-swanctl-render/plan.md
docs/pr/1229-cross-worker-vtime/plan.md
docs/pr/1711-policy-sim-ip-validation/plan.md
docs/pr/918-flow-cache-associative/plan.md
docs/reviews/archive/ps-review-009.md
docs/pr/816-step1-rerun/plan.md
docs/pr/6979-f6-pool-address-overlap/plan.md
docs/pr/917-vmin-trio-closeout/plan.md
docs/pr/1620-binding-worker-hist-integration/plan.md
docs/pr/1518-cluster-session-sync-migration/plan.md
docs/pr/1904-routing-followups/plan.md
docs/pr/959-phase9-flowcache/plan.md
docs/pr/1197-neighbor-snapshot/plan.md
docs/pr/959-phase2-scratch/plan.md
docs/pr/905-mouse-latency/plan.md
docs/reviews/archive/ps-review-008.md
docs/pr/2090-checkvipreadiness-carrier/plan.md
docs/pr/1607-hw-ceiling-microbench/plan.md
docs/pr/2075-flowexport-reconcile/plan.md
docs/pr/6812-snat-aggregate-bitmap-cap/plan.md
docs/pr/1713-resolved-dns-renderer/plan.md
docs/pr/1651-b3-negcache/plan.md
docs/pr/1187-telemetry-double-buffer/plan.md
docs/pr/1528-dpdk-mechanical-removal/plan.md
docs/pr/678-hotpath-cuts/plan.md
docs/pr/1444-cli-presenters/plan.md
docs/pr/1473-xdp-shim-decouple/plan.md
docs/pr/927-mqfq-orphan-vtime/plan.md
docs/pr/1145-packet-scratchpad/plan.md
docs/pr/6436-binding-state-extract/plan.md
docs/pr/1724-checksum-offset-helper/plan.md
docs/pr/2145-vlan-present-l3-offset/plan.md
docs/pr/1666-ready-gate/plan.md
docs/pr/708-enqueue-pacing/plan.md
docs/pr/838-afd-lite/plan.md
docs/pr/1357-session-ctx-structs/plan.md
docs/pr/1521-maps-sync-decouple/plan.md
docs/pr/1614-multi-rss-cos/plan.md
docs/pr/1351-umem-snapshot-debug-split/plan.md
docs/pr/1875-cluster-ownership/plan.md
docs/pr/1350-drain-phase-split/plan.md
docs/pr/1342-forwarding-build-split/plan.md
docs/pr/956-phase8-cross-binding/plan.md
docs/pr/1612-scale-target-measurement/plan.md
docs/pr/1658-rcvbuf/plan.md
docs/pr/1726-prometheus-descriptor-coverage-canary/plan.md
docs/pr/1609-multistage-policy-dag/plan.md
docs/pr/wireguard-clean/plan.md
docs/pr/1439-snapshot-builders/plan.md
docs/pr/1355-cos-push-split/plan.md
docs/pr/1206-cosqueueruntime-split/plan.md
docs/pr/949-sharded-locks/plan.md
docs/pr/846-apply-config-serialize/plan.md
docs/pr/1044c-cli-split/plan.md
docs/pr/1559-canary-harden/plan.md
docs/pr/1352-frame-build-rewrite-split/plan.md
docs/pr/1541-cluster-mgr-split/plan.md
docs/pr/infra-fixes/plan.md
docs/pr/1885-vlan-slice/plan.md
docs/pr/1710-snmpv3-authparams-position/plan.md
docs/pr/1736-wg-interop/plan.md
docs/pr/1219-fairness-harness/plan.md
docs/pr/2121-flushdeletejournal-requeue/plan.md
docs/pr/1662-nat64-dscp/plan.md
docs/pr/5146-nat64-frag-rollback/plan.md
docs/pr/925-phase2/plan.md
docs/pr/940-942-vmin-correctness/plan.md
docs/pr/956-tx-decomposition/plan.md
docs/pr/1516-grpcapi-migration/plan.md
docs/pr/1902-pending-neigh/plan.md
docs/pr/1526-dpdk-reject/plan.md
docs/pr/1328-coordinator-reconcile-split/plan.md
docs/pr/2103-2105-route-filter-frr-validity/plan.md
docs/pr/1443-tx-dispatch-modularize/plan.md
docs/pr/1346-session-glue-split/plan.md
docs/pr/1166-tso-extract/plan.md
docs/pr/1745-equal-flow-failopen-sample/plan.md
docs/pr/920-batch-size-l1d/plan.md
docs/pr/1895-probe-pin/plan.md
docs/pr/p2a-tx-stats/plan.md
docs/pr/1638-rm-scaffold/plan.md
docs/pr/959-phase5-bpfmaps/plan.md
docs/pr/1356-bpf-map-split/plan.md
docs/pr/877-chassis-forwarding/plan.md
docs/pr/1331-submit-cos-batch-per-variant/plan.md
docs/pr/925-worker-supervisor/plan.md
docs/pr/827-p3-captures/plan.md
docs/pr/945-context-object/plan.md
docs/pr/1349-worker-cos-status-split/plan.md
docs/pr/1543-screen-syn-cookie-split/plan.md
docs/pr/6438-wg-control-split/plan.md
docs/pr/1735-mqfq-generalize-shaped/plan.md
docs/pr/1440-header-serialization-consolidate/plan.md
docs/pr/819-step2-discriminator-design/plan.md
docs/pr/926-demote-vtime-inflation/plan.md
docs/pr/1977-numwidth-wire/plan.md
docs/pr/956-phase7-queue-service/plan.md
docs/pr/959-phase4-tx-counters/plan.md
docs/pr/844-vrf-idempotent/plan.md
docs/pr/929-same-class-harness/plan.md
docs/pr/812-tx-latency-histogram/plan.md
docs/pr/1321-validation-contract/plan.md
docs/pr/956-phase2-flow-hash/plan.md
docs/pr/p1-tx-completion/plan.md
docs/pr/1542-nat-runtime-split/plan.md
docs/pr/1373-retire-ebpf-dataplane/plan.md
docs/pr/964-session-multi-index/plan.md
docs/pr/1678-debuglog/plan.md
docs/pr/1700-server-show-split/plan.md
docs/pr/867-ack-ip-sweep/plan.md
docs/pr/2122-2123-nat-cidr-parse/plan.md
docs/pr/6765-snat-pool-carryover/plan.md
docs/pr/965-session-gc-timer-wheel/plan.md
docs/pr/1381-dataplane-interface-split/plan.md
docs/pr/2085-kea-lease-parser/plan.md
docs/pr/1635-cold-path-hist-redesign/plan.md
docs/pr/1827-pr3-nat/plan.md
docs/pr/1529-dpdk-docs-sweep/plan.md
docs/pr/1517-cli-migration/plan.md
docs/pr/1725-filter-engine-tests/plan.md
docs/pr/7212-static-input-filter-revalidation/plan.md
docs/pr/6386-poll-descriptor-extract/plan.md
docs/pr/1636-cold-connect-mitigation/plan.md
docs/pr/850-allow-dns-reply/plan.md
docs/pr/941-vacate-hard-cap/plan.md
docs/pr/825-p3-tx-kick-latency/plan.md
docs/pr/709-owner-hotspot/plan.md
docs/pr/909-meta-prefetch/plan.md
docs/pr/1231-iperf-c-fix/plan.md
docs/pr/1329-shared-cos-lease-extract/plan.md
docs/pr/919-922-zone-ids/plan.md
docs/pr/2073-ipsec-pfs/plan.md
docs/pr/2124-protocol-failopen/plan.md
docs/pr/1769-neighbor-resolver/plan.md
docs/pr/1621-cold-path-wire-prometheus/plan.md
docs/pr/2084-ping-traceroute-separator/plan.md
docs/pr/2083-rename-iface-down/plan.md
docs/pr/1208-refactoring-audit-refresh/plan.md
docs/pr/1752-session-inplace-refresh/plan.md
docs/pr/871-reject-vlan-stack/plan.md
docs/pr/1626-smoke-fixture-guarantee-rate/plan.md
docs/pr/1763-fused-minfinish/plan.md
docs/pr/2008-h9-h10-m1-commit-validation/plan.md
docs/pr/917-mqfq-phase4/plan.md
docs/pr/nat-correctness/plan.md
docs/pr/1348-icmp-embed-split/plan.md
docs/pr/959-phase7-tx-pipeline/plan.md
docs/pr/6766-inline-icmp-dup/plan.md
docs/pr/1733-equal-flow-worker-cap-reject/plan.md
docs/pr/2114-natpoolalarm-bootstrap-race/plan.md
docs/pr/2127-rtproto-name-mapping/plan.md
docs/pr/1327-poll-descriptor-stages/plan.md
docs/pr/1522-readme-doc-drift/plan.md
docs/pr/2152-vrrp-arp-probe-vip-sender/plan.md
docs/pr/1661-audit-drift/plan.md
docs/pr/1697-poll-descriptor-cold-path-split/plan.md
docs/pr/956-phase6-builders/plan.md
docs/pr/4662-daemon-run-decompose/plan.md
docs/pr/923-policy-prefix-set/plan.md
docs/pr/2299-2300-2303-wg-mtu-ecn/plan.md
docs/pr/956-phase3-admission/plan.md
docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md
docs/pr/1303-mtr-smoke/plan.md
docs/pr/1615-flooder-multithread-virtio/plan.md
docs/pr/1687-shared-presentation/plan.md
docs/pr/1698-routing-domain-managers/plan.md
docs/pr/959-phase1-telemetry/plan.md
docs/pr/1563-cli-c-nontty-fix/plan.md
docs/pr/1701-config-types-split/plan.md
docs/pr/1873-tunnel-ids/plan.md
docs/pr/1345-server-handlers-split/plan.md

exec
/bin/bash -lc 'nl -ba docs/research/8865-muse-spark-008-009/plan.md' in /var/tmp/RES8865
 succeeded in 0ms:
     1	# Plan of action — muse-spark reviews 008 + 009 (#8865)
     2	
     3	- **Revision:** r1
     4	- **Base:** `b24e26d3b` (master at drafting)
     5	- **Reports:** `muse-spark-review-008` (109 findings across 5 rounds), `muse-spark-review-009` (4 High). 009 excludes 007 and 008, so the three are disjoint.
     6	- **Status:** DRAFT — awaiting 3-way hostile review.
     7	
     8	## 1. Problem statement
     9	
    10	113 findings arrive against a tree that has moved **128+ commits** since either
    11	report's tip, during a campaign that closed **41 issues** concentrated in exactly
    12	the areas both reports target. The question is not "how do we work 113 findings"
    13	but **"which of them still describe this tree, and what is the smallest set of
    14	changes that closes them."**
    15	
    16	## 2. What has been established before planning
    17	
    18	**Verified LIVE at `b24e26d3b`:**
    19	
    20	| finding | evidence |
    21	|---|---|
    22	| 008 H1 | elided `security-zone z1 description hi screen s1;` -> `screen=""`, strict clean |
    23	| 008 H2 | elided form **evades** the strict undefined-interface gate the braced form fails |
    24	| 008 H3 | `packedStatements` opt-ins 3 -> 8, `security-zone` still not among them |
    25	| 008 M17 | `decodeIPsecSAPayload` does an **unbounded** `strings.Split` on wire payload |
    26	| 009 PHA-001 | DHCP `SyncLease` decoder **clamps** a wire count and allocates it |
    27	| 008 H5 (mech) | `mgmtVRFName = "mgmt"` hardcoded, no reserved-name check in `pkg/config` |
    28	
    29	**Not established:** 008 H4 (self-brick) is consistent with the code — the 16 MiB
    30	ceiling lives in `bounded_read.go` on the *read* side and no size gate is visible
    31	in `commitWithDescriptionLocked` — but has not been reproduced end-to-end here.
    32	
    33	## 3. The finding that reframes the work: both reports found ONE member each of ONE class
    34	
    35	Enumerating every wire-count-driven allocation in `pkg/cluster` — four commands —
    36	partitions completely:
    37	
    38	```
    39	sync.go:1365, :1397                    SAFE   length check -> REJECT, count <= 255
    40	sync_persistent_nat_lease_8121.go:152  FIXED  -> REJECT            (#8792/#8805, from report 007)
    41	sync_protocol.go:1231   SyncLease      LIVE   -> CLAMP then allocate   (009 PHA-001)
    42	sync_protocol.go:806    decodeIPsecSA  LIVE   -> unbounded Split       (008 M17)
    43	```
    44	
    45	**The discriminator is reject-versus-clamp.** The fixed site rejects; both live
    46	sites bound the count by a *cheaper unit than the thing allocated* and proceed.
    47	`len(payload)/4` prefixes vs a 168-byte `SyncLease` is a **42x** amplification
    48	inside a bound that looks like a bound.
    49	
    50	Three independent facts follow:
    51	
    52	1. **Report 007's fix landed on one member of a class nobody enumerated.** Its
    53	   own comment cites the "#7175 discipline"; so does the still-live `SyncLease`
    54	   site. The discipline was cited and not applied.
    55	2. **Two separate reviewers each found one different live member.** Neither found
    56	   both. An enumeration finds all of them in minutes.
    57	3. **The safe sites show the correct pattern already exists in the same file
    58	   family** — this is not a design question, it is an application question.
    59	
    60	## 4. Path options
    61	
    62	### Path A — finding-first triage (the default, NOT recommended)
    63	
    64	Adjudicate all 113 in severity order, file per finding.
    65	
    66	- **Cost:** the 007 triage is running ~3 findings/hour with genuine measurement.
    67	  113 findings is weeks, and the board goes to ~100 rows.
    68	- **Against:** it re-derives per finding what a class enumeration establishes
    69	  once. It also **repeats the exact failure that produced these reports** — 007's
    70	  finding 03 was fixed as one instance, and its siblings are 008 M17 and 009
    71	  PHA-001.
    72	
    73	### Path B — class-first (RECOMMENDED)
    74	
    75	Group findings into **mechanism classes**, enumerate each class completely, fix
    76	the class, and let one change close many findings.
    77	
    78	Known classes, with today's evidence:
    79	
    80	| class | members | status |
    81	|---|---|---|
    82	| wire-count allocation | 5 enumerated | 3 safe/fixed, 2 live — *fix is one shape* |
    83	| multi-statement packed fold | H1, H2, H3, + M-rows | mechanism understood; `packedStatements` opt-in per container |
    84	| reserved-name collision | H5 | single instance; enumerate other hardcoded names |
    85	| commit/load asymmetry | H4 | single instance; enumerate other accept-then-refuse gates |
    86	
    87	- **For:** the wire-count class is already enumerated and partitioned. The
    88	  brace-elision class produced 6 defects and 2 instruments today, and the
    89	  instruments found what enumeration missed.
    90	- **Against:** classing is a judgement, and a wrong class boundary hides members.
    91	  Mitigated by requiring an **enumeration with a published ratio** per class, the
    92	  discipline this board used on #8859 (64 swept, 43 silent, 18 SAME as negative
    93	  control).
    94	
    95	### Path C — instrument-first
    96	
    97	Build a detector per class before fixing anything.
    98	
    99	- **For:** today's two instruments (positional predicate, blind-pair guard) each
   100	  caught live defects, and the blind-pair guard caught one within an hour on
   101	  another lane's change.
   102	- **Against:** #8830 showed an instrument can cost two corrections and return
   103	  1 defect from 32 candidate rows. **An instrument is worth building when the
   104	  class is large and the members are not enumerable by grep.** The wire-count
   105	  class was enumerable in four commands; a detector for it would be ceremony.
   106	
   107	**Recommendation: Path B, with Path C reserved for classes that resist
   108	enumeration.** Apply the #8859 gate column — *does an existing gate already
   109	handle this?* — to every candidate before calling it a defect. That column found
   110	two already-handled rows in a 45-row set today.
   111	
   112	## 5. Proposed sequencing
   113	
   114	1. **Wire-count allocation class** — fix `sync_protocol.go:1231` and `:806`
   115	   to the reject-shape the sibling already uses. Closes 009 PHA-001 and 008 M17.
   116	   Guard: assert **rejection**, not clamping, with the payload/element size ratio
   117	   in the failure text.
   118	2. **008 H4** — reproduce the self-brick end to end first; it is the only
   119	   unverified High and it is the highest consequence (a node that will not boot).
   120	3. **Multi-statement packed fold (H1/H2/H3)** — this is live work already
   121	   understood by the lane that landed #8856; the remaining question is which
   122	   containers need `packedStatements` and whether the opt-in is the right shape
   123	   or the fold should refuse.
   124	4. **H5 reserved names** — enumerate hardcoded infrastructure names before fixing
   125	   `mgmt` alone.
   126	5. **The remaining ~104** — staleness-partition in batches, publishing the ratio,
   127	   per the #8791 method: measure at the report's base AND at master, because a
   128	   current quote settles nothing.
   129	
   130	## 6. Acceptance criteria (per class)
   131	
   132	- Enumeration published with its **ratio** and its **negative control**.
   133	- A **gate column**: does the strict path refuse, or the lenient path warn?
   134	- Fixes asserted on **contents**, never on "commit succeeded".
   135	- **Liveness** beside every equality assertion.
   136	- Both elision depths where the class is elision-shaped; two instances where the
   137	  leaf is `multi:true`.
   138	- `Store.Load` must still accept everything it accepts today.
   139	
   140	## 7. Risks
   141	
   142	- **Class boundaries drawn wrong** — mitigated by published enumerations.
   143	- **Board inflation** — 113 findings must not become 113 issues; adjudications go
   144	  in one comment per class, issues only for confirmed defects.
   145	- **Report numbers inherited** — 008's own header says "109 findings, 11 High"
   146	  while its method header says "why the count is 37 and not 100" and its HIGH
   147	  section is headed "(5)". **Derive counts; do not quote them.**
   148	
   149	## 8. What this plan does NOT propose
   150	
   151	- No `Format()` canonicalisation (open decision on #8850, user's call).
   152	- No work on the 39 Low findings until the Highs and the classes are closed.
   153	- No new instrument unless a class resists enumeration.

exec
/bin/bash -lc "rg --files docs | rg '8865|8830|muse|spark'; rg -n '"'^#{1,5} |H4|hash|commit|[0-9]{2} findings'"' docs/reviews/archive/ps-review-008.md docs/reviews/archive/ps-review-009.md" in /var/tmp/RES8865
 succeeded in 0ms:
docs/research/8865-muse-spark-008-009/claude-smr-plan-r1.md
docs/research/8865-muse-spark-008-009/codex-plan-r1.md
docs/research/8865-muse-spark-008-009/plan.md
docs/reviews/reports/result-claude-spark-review-001.md
docs/reviews/archive/result-claude-spark-review-001.md
docs/reviews/reports/result-claude-spark-review-002.md
docs/reviews/archive/claude-spark-review-002.md
docs/reviews/archive/claude-spark-review-001.md
docs/reviews/archive/result-claude-spark-review-002.md
docs/reviews/archive/ps-review-009.md:1:# xpf firewall core policy audit â€” ps-review-009
docs/reviews/archive/ps-review-009.md:3:## 1. Base commit reviewed
docs/reviews/archive/ps-review-009.md:12:## 2. Output path
docs/reviews/archive/ps-review-009.md:16:## 3. Duplicate suppression summary
docs/reviews/archive/ps-review-009.md:34:## 4. Explicit module checklist â€“ parallel agent deep dives
docs/reviews/archive/ps-review-009.md:62:## 6. Findings â€“ HIGH IMPACT ONLY
docs/reviews/archive/ps-review-009.md:64:### P1 â€“ CRITICAL
docs/reviews/archive/ps-review-009.md:104:### P2 â€“ HIGH
docs/reviews/archive/ps-review-009.md:142:### P3 â€“ CRITICAL
docs/reviews/archive/ps-review-009.md:209:### P4 â€“ HIGH
docs/reviews/archive/ps-review-009.md:225:  1. Operator commits lenient config with protocol-less application, or typo in protocol, or malformed port, or undefined app name, or unresolvable address.
docs/reviews/archive/ps-review-009.md:253:### P5 â€“ HIGH
docs/reviews/archive/ps-review-009.md:289:  - Option 1 (strict): Disallow 1:N NAT configurations that cause reverse-key collisions at config commit. Reject interface-mode SNAT without port translation if multiple hosts could share, DNAT to same backend without proper SNAT, etc. Complex to detect all cases.
docs/reviews/archive/ps-review-009.md:299:### P6 â€“ HIGH
docs/reviews/archive/ps-review-009.md:364:## 7. Suggested issue split
docs/reviews/archive/ps-review-008.md:1:# xpf firewall core policy audit â€” ps-review-008
docs/reviews/archive/ps-review-008.md:3:## 1. Base commit reviewed
docs/reviews/archive/ps-review-008.md:12:## 2. Output path
docs/reviews/archive/ps-review-008.md:16:## 3. Duplicate suppression summary
docs/reviews/archive/ps-review-008.md:30:- Findings below are **not** restatements of prior 64 findings. Where a prior finding mentioned a related area (e.g., P1 HA NAT pool), this report provides deeper technical analysis and confirms the critical bug with full trace.
docs/reviews/archive/ps-review-008.md:33:## 4. Explicit module checklist
docs/reviews/archive/ps-review-008.md:45:## 5. Parallel agent results summary
docs/reviews/archive/ps-review-008.md:47:### Agent 1: pkg/policymatch/ â€“ HIGH IMPACT SIMULATOR ACCURACY GAP
docs/reviews/archive/ps-review-008.md:51:### Agent 2: userspace-dp/src/policy.rs â€“ NO HIGH IMPACT ISSUES
docs/reviews/archive/ps-review-008.md:54:### Agent 3: NAT + HA â€“ CRITICAL NAT POOL CONFLICT + HIGH DNAT_TABLE GAP
docs/reviews/archive/ps-review-008.md:59:### Agent 4: Filter & PBR â€“ CRITICAL PBR BYPASS WITH NON-ACCEPT ACTION
docs/reviews/archive/ps-review-008.md:64:### Agent 5: Session & HA â€“ NO HIGH IMPACT ISSUES (beyond NAT pool conflict)
docs/reviews/archive/ps-review-008.md:76:## 6. Findings â€“ HIGH IMPACT ONLY
docs/reviews/archive/ps-review-008.md:78:### P1 â€“ CRITICAL
docs/reviews/archive/ps-review-008.md:115:### P2 â€“ HIGH
docs/reviews/archive/ps-review-008.md:145:### P3 â€“ CRITICAL
docs/reviews/archive/ps-review-008.md:206:### P4 â€“ HIGH
docs/reviews/archive/ps-review-008.md:222:  1. Operator commits lenient config with protocol-less application, or typo in protocol, or malformed port, or undefined app name, or unresolvable address.
docs/reviews/archive/ps-review-008.md:250:## 7. Suggested issue split

exec
/bin/bash -lc "rg --files -g 'AGENTS.md' -g '"'!vendor'"' -g '"'!node_modules'"' . /var/tmp 2>/dev/null | head -70; git status --short; git log -1 --format='%H %s'" in /var/tmp/RES8865
 succeeded in 0ms:
./AGENTS.md
/var/tmp/RES8865/AGENTS.md
/var/tmp/L8388-cmp/AGENTS.md
/var/tmp/L8858/AGENTS.md
/var/tmp/L8791base/AGENTS.md
/var/tmp/GE/AGENTS.md
/var/tmp/L8791/AGENTS.md
/var/tmp/L8859/AGENTS.md
/var/tmp/K8862b/AGENTS.md
/var/tmp/Lsweep/AGENTS.md
/var/tmp/L8388-pos/AGENTS.md
?? docs/research/8865-muse-spark-008-009/claude-smr-plan-r1.md
?? docs/research/8865-muse-spark-008-009/codex-plan-r1.md
958de0c92625b2ee82339860e9bc47510d56817d docs: #8865 research plan r1 for muse-spark 008+009

exec
/bin/bash -lc "nl -ba pkg/cluster/sync_protocol.go | sed -n '715,875p;1150,1300p'; nl -ba pkg/cluster/sync_persistent_nat_lease_8121.go | sed -n '100,210p'; nl -ba pkg/cluster/sync.go | sed -n '1300,1450p'" in /var/tmp/RES8865
 succeeded in 0ms:
   715			val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
   716			off += 4
   717			val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
   718			off += 2
   719			copy(val.FibDmac[:], payload[off:off+6])
   720			off += 6
   721			copy(val.FibSmac[:], payload[off:off+6])
   722			off += 6
   723			val.FibGen = binary.LittleEndian.Uint16(payload[off:])
   724			off += 2
   725		}
   726		// #2170: install generation (length-gated; absent → 0 = legacy peer).
   727		if off+8 <= len(payload) {
   728			val.Generation = binary.LittleEndian.Uint64(payload[off:])
   729			off += 8
   730		}
   731		// #3301: per-application idle timeout + per-rule hit-counter handle
   732		// (length-gated; absent → 0 = legacy peer / global timeout / no counter).
   733		if off+4 <= len(payload) {
   734			val.AppTimeout = binary.LittleEndian.Uint32(payload[off:])
   735			off += 4
   736		}
   737		if off+4 <= len(payload) {
   738			val.PolicyCounterIdx = binary.LittleEndian.Uint32(payload[off:])
   739			off += 4
   740		}
   741		// #4565: NAT64 translated pool SOURCE (length-gated; absent => all-zero =
   742		// not NAT64, the rolling-upgrade-safe default from a legacy peer).
   743		if off+4 <= len(payload) {
   744			copy(val.Nat64SnatV4[:], payload[off:off+4])
   745			off += 4
   746		}
   747		// #5274: admitting config epoch (length-gated; absent → 0 = legacy peer /
   748		// config-epoch check disabled).
   749		if off+8 <= len(payload) {
   750			val.ConfigEpoch = binary.LittleEndian.Uint64(payload[off:])
   751			off += 8
   752		}
   753		// #5212: originating node's stable RT_FLOW session id (length-gated; absent →
   754		// 0 = legacy peer, receiver allocs a fresh local id on import).
   755		if off+8 <= len(payload) {
   756			val.RTFlowSessionID = binary.LittleEndian.Uint64(payload[off:])
   757			off += 8
   758		}
   759		// #7095: cluster-stable ingress-interface fold (length-gated; absent → 0 =
   760		// legacy peer / no stable name / fabric-redirected, all of which fall back
   761		// to the zone approximation).
   762		if off+4 <= len(payload) {
   763			val.IngressIfaceFold = binary.LittleEndian.Uint32(payload[off:])
   764			off += 4
   765		}
   766		// #7188: tunnel session-identity discriminator (length-gated; absent → 0 =
   767		// the RESERVED "not carried" tag, on which the peer helper withholds a
   768		// protocol-47 session rather than importing it aliased onto another RFC 2890
   769		// tunnel's key).
   770		if off+8 <= len(payload) {
   771			val.TunnelDiscriminator = binary.LittleEndian.Uint64(payload[off:])
   772			off += 8
   773		}
   774		// #7239: length-gated trailing routing domain. Absent => 0 (the default
   775		// routing instance), which is what a peer predating this field sends and
   776		// what every deployment with no routing-instance interface membership
   777		// carries.
   778		if off+4 <= len(payload) {
   779			val.RoutingDomain = binary.LittleEndian.Uint32(payload[off:])
   780			off += 4
   781		}
   782		return key, val, true
   783	}
   784	
   785	// encodeIPsecSAPayload encodes a list of IPsec connection names as
   786	// newline-separated bytes.
   787	func encodeIPsecSAPayload(names []string) []byte {
   788		if len(names) == 0 {
   789			return nil
   790		}
   791		joined := ""
   792		for i, name := range names {
   793			if i > 0 {
   794				joined += "\n"
   795			}
   796			joined += name
   797		}
   798		return []byte(joined)
   799	}
   800	
   801	// decodeIPsecSAPayload decodes a newline-separated list of IPsec connection names.
   802	func decodeIPsecSAPayload(payload []byte) []string {
   803		if len(payload) == 0 {
   804			return nil
   805		}
   806		parts := strings.Split(string(payload), "\n")
   807		var names []string
   808		for _, p := range parts {
   809			if p != "" {
   810				names = append(names, p)
   811			}
   812		}
   813		return names
   814	}
   815	
   816	// --- #3931 config-sync generation wire codec ------------------------------
   817	//
   818	// The config-sync payload historically was the raw UTF-8 config text with no
   819	// framing. #3931 appends a monotonic config generation so the receiver can
   820	// order a rapid commit pair (C1 then C2) and refuse a reordered older config.
   821	// Because the config text is arbitrary bytes (no fixed layout to length-gate a
   822	// leading field against), the generation is carried as a TRAILING framing:
   823	//
   824	//	[config text bytes][configGenMagic (8)][gen (uint64 LE, 8)]
   825	//
   826	// A NEW receiver (decodeConfigPayload) detects the magic at the tail and peels
   827	// off the trailing 16 bytes; a payload without the magic is a LEGACY sender's
   828	// raw config text and decodes with gen=0 (applied unconditionally, preserving
   829	// the pre-#3931 behavior). The magic bytes are deliberately non-printable so
   830	// they cannot collide with real Junos config text. NOTE the one asymmetric
   831	// direction: a NEW sender's framed payload reaching a LEGACY receiver (only
   832	// possible in the brief mixed-version ISSU window) is treated by that old
   833	// receiver as config text with 16 trailing binary bytes, which its Junos
   834	// parser rejects — the config-sync apply fails and the old node retains its
   835	// current config (fail-safe, no crash, no divergence worse than today). This
   836	// is why #3931 does NOT bump SessionSyncWireVersion: that gate governs whether
   837	// SESSIONS sync at all across a mixed pair, and bumping it would break session
   838	// sync for the whole mixed-base window (the #2239 lesson). Config-gen is
   839	// additive and self-detecting via the magic.
   840	var configGenMagic = [8]byte{0x00, 0xff, 'x', 'p', 'f', 'C', 'G', 0x00}
   841	
   842	// encodeConfigPayload builds a config-sync payload carrying the config text
   843	// and a trailing generation (see the codec note above).
   844	func encodeConfigPayload(configText string, gen uint64) []byte {
   845		buf := make([]byte, 0, len(configText)+16)
   846		buf = append(buf, configText...)
   847		buf = append(buf, configGenMagic[:]...)
   848		buf = binary.LittleEndian.AppendUint64(buf, gen)
   849		return buf
   850	}
   851	
   852	// decodeConfigPayload splits a config-sync payload into its config text and
   853	// generation. A payload without the trailing configGenMagic is a legacy
   854	// sender's raw config text and yields gen=0.
   855	func decodeConfigPayload(payload []byte) (configText string, gen uint64) {
   856		if len(payload) >= 16 && bytes.Equal(payload[len(payload)-16:len(payload)-8], configGenMagic[:]) {
   857			gen = binary.LittleEndian.Uint64(payload[len(payload)-8:])
   858			return string(payload[:len(payload)-16]), gen
   859		}
   860		return string(payload), 0
   861	}
   862	
   863	// --- #5706 full-set state-sync ordering wire codec ------------------------
   864	//
   865	// IPsec SA and DHCP-server lease sync are FULL-SET pushes: each message
   866	// REPLACES the peer's held set wholesale. Two fabric receiveLoops
   867	// (conn0/conn1) process a peer's frames concurrently, so a full-set can be
   868	// delivered OUT OF ORDER across the redundant streams — a stale older set
   869	// could then overwrite a newer one (a state REGRESSION). To order them, each
   870	// full-set carries a trailing (incarnation, seq) framing analogous to the
   871	// #3931 config-generation trailer:
   872	//
   873	//	[ base payload ][ fullSetSeqMagic (8) ][ incarnation (8 LE) ][ seq (8 LE) ]
   874	//
   875	// incarnation is the SENDER's process epoch (constant for a boot; a restart
  1150		if l.Hostname, off, ok = getLeaseString(buf, off); !ok {
  1151			return l
  1152		}
  1153		if off < len(buf) {
  1154			flags := buf[off]
  1155			l.FQDNFwd = flags&0x01 != 0
  1156			l.FQDNRev = flags&0x02 != 0
  1157			off++ // advance past flags so the #5073 trailing field can follow
  1158		}
  1159		// #5073 append-only trailing field. PRESENT (a newer peer) → read it;
  1160		// ABSENT (an older peer whose record stopped at the FQDN flags byte) → leave
  1161		// the preferred==valid default set above. Guarded by remaining length so a
  1162		// truncated tail never over-reads.
  1163		if off+4 <= len(buf) {
  1164			l.PreferredRemaining = int(binary.LittleEndian.Uint32(buf[off:]))
  1165			off += 4
  1166		}
  1167		return l
  1168	}
  1169	
  1170	// encodeDHCPLeasePayload serializes a full-set lease push: a 4-byte count
  1171	// followed by length-prefixed lease records. An empty set encodes as a 4-byte
  1172	// zero count (a legitimate "I serve no leases" message, distinct from a legacy
  1173	// peer that never sends this type at all).
  1174	func encodeDHCPLeasePayload(leases []dhcpserver.SyncLease) []byte {
  1175		// Encode records first so an oversized field (which encodeOneLease rejects,
  1176		// #4892) DROPS just that lease — fail-closed — while the count prefix stays
  1177		// consistent with the records actually emitted. Dropping one unencodable
  1178		// lease is strictly safer than either misframing the peer's decode or
  1179		// blocking the entire push; the standby simply lacks that one lease (the
  1180		// client re-DHCPs on takeover) instead of seeding a corrupted identity.
  1181		recs := make([][]byte, 0, len(leases))
  1182		for _, l := range leases {
  1183			rec, err := encodeOneLease(l)
  1184			if err != nil {
  1185				slog.Warn("cluster sync: dropping unencodable DHCP lease from sync push",
  1186					"family", l.Family, "address", l.Address, "err", err)
  1187				continue
  1188			}
  1189			recs = append(recs, rec)
  1190		}
  1191		b := make([]byte, 0, 8+len(recs)*64)
  1192		b = binary.LittleEndian.AppendUint32(b, uint32(len(recs)))
  1193		for _, rec := range recs {
  1194			b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
  1195			b = append(b, rec...)
  1196		}
  1197		return b
  1198	}
  1199	
  1200	// decodeDHCPLeasePayload parses a full-set lease push. A truncated payload
  1201	// stops decoding at the last complete record (fail-safe: a partial message
  1202	// yields the leases that fully arrived rather than erroring the whole push).
  1203	// #7175 (C179-075): the bool reports whether the payload decoded COMPLETELY.
  1204	// A full-set push REPLACES the peer lease set, so returning a truncated prefix
  1205	// silently deleted every lease past the truncation point on the standby. The
  1206	// caller must retain its prior set when this is false rather than storing a
  1207	// partial one — the same disposition the stale-sequence guard already applies
  1208	// one branch above ("standby retains newer set").
  1209	func decodeDHCPLeasePayload(payload []byte) ([]dhcpserver.SyncLease, bool) {
  1210		if len(payload) < 4 {
  1211			return nil, false
  1212		}
  1213		count := int(binary.LittleEndian.Uint32(payload[:4]))
  1214		off := 4
  1215		malformed := false
  1216		// Clamp the preallocation to what the payload can physically hold: count
  1217		// is untrusted on-wire data, and each record consumes at least its 4-byte
  1218		// length prefix, so there can be at most len(payload)/4 records. Without
  1219		// this, a corrupt/malicious frame claiming count=0xFFFFFFFF would attempt
  1220		// a ~hundreds-of-GB make() (SyncLease is ~160 bytes) and panic before the
  1221		// loop's truncation guard fires. Valid payloads are unaffected (a real
  1222		// count is always <= len(payload)/4). Clamping count also bounds the loop.
  1223		// #7175: a count exceeding what the payload can physically hold is not a
  1224		// short valid set — no encoder produces it. The clamp still bounds the
  1225		// allocation, and the frame is now reported as malformed rather than
  1226		// silently reduced to whatever fit.
  1227		if maxRecords := len(payload) / 4; count > maxRecords {
  1228			count = maxRecords
  1229			malformed = true
  1230		}
  1231		out := make([]dhcpserver.SyncLease, 0, count)
  1232		for i := 0; i < count; i++ {
  1233			if off+4 > len(payload) {
  1234				// The buffer ended while the count still expected records. Every
  1235				// record that DID arrive is whole — only the sender's count was
  1236				// wrong — so this stays recoverable, which is the contract
  1237				// TestDHCPLeasePayload_TruncatedStream pins. Deliberately NOT
  1238				// promoted to malformed: nothing was lost mid-record.
  1239				break
  1240			}
  1241			recLen := int(binary.LittleEndian.Uint32(payload[off:]))
  1242			off += 4
  1243			if recLen < 0 || off+recLen > len(payload) {
  1244				// A record is CUT: its declared length runs past the buffer, so
  1245				// part of a lease is gone. This is the C179-075 case — the full-set
  1246				// push REPLACES the peer set, so returning the prefix would delete
  1247				// every lease after the cut on the standby.
  1248				malformed = true
  1249				break
  1250			}
  1251			out = append(out, decodeOneLease(payload[off:off+recLen]))
  1252			off += recLen
  1253		}
  1254		// NOTE: trailing bytes after the last record are NOT malformed. The #5073
  1255		// full-set seq trailer is appended exactly so an old decoder walks its
  1256		// records and ignores the remainder (TestFullSetSeqDHCPTrailerIgnoredByOldDecoder).
  1257		if malformed {
  1258			return nil, false
  1259		}
  1260		return out, true
  1261	}
   100			addressOnly = 1
   101		}
   102		b = append(b, addressOnly)
   103		b = binary.LittleEndian.AppendUint64(b, l.RemainingNs)
   104		b = binary.LittleEndian.AppendUint64(b, l.TimeoutNs)
   105		return b, nil
   106	}
   107	
   108	// decodePersistentNatLeasePayload parses a full-set push. The bool reports
   109	// whether the payload decoded COMPLETELY: a full-set push REPLACES the peer set,
   110	// so a truncated prefix must not be installed as if it were the whole thing —
   111	// the #7175 discipline. The caller retains its previous set when this is false.
   112	func decodePersistentNatLeasePayload(buf []byte) ([]userspace.IdleLeaseWire, bool) {
   113		if len(buf) < 4 {
   114			return nil, false
   115		}
   116		count := int(binary.LittleEndian.Uint32(buf))
   117		off := 4
   118		// #8792: SIZE THE ALLOCATION FROM THE BUFFER, NOT FROM THE WIRE.
   119		//
   120		// `count` is untrusted on-wire data and the make() below sizes its
   121		// preallocation from it, so the loop's bounds check — one line further down
   122		// — fires only AFTER the allocation it was meant to protect. A four-byte
   123		// frame of `ff ff ff ff` asks for 2^32-1 records of 112 bytes each, roughly
   124		// 448 GiB, before a single length prefix has been read.
   125		//
   126		// Every record costs at least its own 4-byte length prefix, so the body
   127		// after the count can hold at most (len(buf)-4)/4 of them. A count above
   128		// that cannot describe THIS frame under any encoding, so it is refused
   129		// rather than clamped: a full-set push REPLACES the peer set, and this
   130		// decoder's bool means "decoded COMPLETELY". Installing whatever fit would
   131		// delete every lease past the point the sender's count went wrong.
   132		//
   133		// The DHCP sibling in sync_protocol.go CLAMPS and continues on the same
   134		// input, and that divergence is deliberate: #7175 fixed it under a contract
   135		// that separates a wrong COUNT from lost DATA, and
   136		// TestDHCPFullSetStillToleratesAnOverDeclaredCount7175 pins the tolerance.
   137		// This decoder has no such separation to make.
   138		//
   139		// What this is NOT: a claim about crashing. Whether the oversized make()
   140		// is fatal depends on the host — 112 * (2^32-1) stays under the runtime's
   141		// maxAlloc, so no makeslice panic is inherent, and under
   142		// overcommit_memory=1 the mapping can succeed unbacked and the process
   143		// survives to discard the frame. The invariant repaired here holds in every
   144		// environment: a count the body cannot physically hold is rejected BEFORE
   145		// the allocation. Note also that the receive loop's defer only disconnects;
   146		// it is not a recovery boundary, so wrapping the decoder in recover() would
   147		// not be a fix where the allocation IS fatal — a Go runtime OOM is a fatal
   148		// error, not a panic.
   149		if maxRecords := (len(buf) - 4) / 4; count < 0 || count > maxRecords {
   150			return nil, false
   151		}
   152		out := make([]userspace.IdleLeaseWire, 0, count)
   153		for i := 0; i < count; i++ {
   154			// Checked SUBTRACTION rather than `off+4 > len(buf)`. NOT LOAD-BEARING,
   155			// and said so rather than left to look like part of the fix: with the
   156			// count now bounded above, `off` and `n` are both bounded and the
   157			// additive form cannot overflow on any reachable input — mutating this
   158			// back to `off+n > len(buf)` does NOT red the #8792 cell. It is kept as
   159			// shape hygiene, because the additive form is what overflows when one
   160			// operand comes off the wire, and a future change that loosens the
   161			// bound above would silently re-arm it.
   162			if len(buf)-off < 4 {
   163				return out, false
   164			}
   165			n := int(binary.LittleEndian.Uint32(buf[off:]))
   166			off += 4
   167			if n < 0 || n > len(buf)-off {
   168				return out, false
   169			}
   170			rec, ok := decodeOnePersistentNatLease(buf[off : off+n])
   171			if !ok {
   172				return out, false
   173			}
   174			out = append(out, rec)
   175			off += n
   176		}
   177		return out, true
   178	}
   179	
   180	func decodeOnePersistentNatLease(buf []byte) (userspace.IdleLeaseWire, bool) {
   181		var l userspace.IdleLeaseWire
   182		off := 0
   183		var ok bool
   184		if l.Pool, off, ok = getLeaseString(buf, off); !ok {
   185			return l, false
   186		}
   187		if off >= len(buf) {
   188			return l, false
   189		}
   190		l.Protocol = buf[off]
   191		off++
   192		if l.SrcIP, off, ok = getLeaseString(buf, off); !ok {
   193			return l, false
   194		}
   195		if off+2 > len(buf) {
   196			return l, false
   197		}
   198		l.SrcPort = binary.LittleEndian.Uint16(buf[off:])
   199		off += 2
   200		if l.RemoteIP, off, ok = getLeaseString(buf, off); !ok {
   201			return l, false
   202		}
   203		if off+2 > len(buf) {
   204			return l, false
   205		}
   206		l.RemotePort = binary.LittleEndian.Uint16(buf[off:])
   207		off += 2
   208		if l.TranslatedIP, off, ok = getLeaseString(buf, off); !ok {
   209			return l, false
   210		}
  1300		persistentNatLeaseSeqCounter atomic.Uint64
  1301	
  1302		recvSeqMu                 sync.Mutex
  1303		ipsecRecvSeq              fullSetSeqGuard
  1304		dhcpV4RecvSeq             fullSetSeqGuard
  1305		dhcpV6RecvSeq             fullSetSeqGuard
  1306		persistentNatLeaseRecvSeq fullSetSeqGuard
  1307	}
  1308	
  1309	// configApplyItem is one config-sync payload queued for ordered apply by the
  1310	// single-consumer configApplyLoop (#3931).
  1311	type configApplyItem struct {
  1312		gen  uint64
  1313		text string
  1314		// incarnation is the peer boot the payload arrived under (#5084), taken
  1315		// from the connection that carried it. Zero = un-incarnated: the payload
  1316		// is never dropped on incarnation grounds (plan §6 rule 4).
  1317		//
  1318		// This field is the whole fix. Without it a payload queued from a peer's
  1319		// PRIOR boot can apply after resetRecvGen has zeroed the high-water, record
  1320		// a high mark, and then refuse the rebooted peer's lower-generation current
  1321		// config permanently.
  1322		incarnation bootIncarnation
  1323	}
  1324	type failoverAck struct {
  1325		status uint8
  1326		detail string
  1327	}
  1328	type failoverWaiter struct {
  1329		reqID uint64
  1330		ch    chan failoverAck
  1331		rgIDs []int
  1332	}
  1333	
  1334	const (
  1335		failoverAckApplied uint8 = iota
  1336		failoverAckRejected
  1337		failoverAckFailed
  1338		failoverAckDisconnected
  1339	)
  1340	
  1341	var ErrRemoteFailoverRejected = errors.New("remote failover rejected")
  1342	
  1343	const maxFailoverBatchRGCount = 255
  1344	
  1345	func encodeFailoverBatchRequestPayload(rgIDs []int, reqID uint64) []byte {
  1346		payload := make([]byte, 1+len(rgIDs)+8)
  1347		payload[0] = byte(len(rgIDs))
  1348		for i, rgID := range rgIDs {
  1349			payload[1+i] = byte(rgID)
  1350		}
  1351		binary.LittleEndian.PutUint64(payload[1+len(rgIDs):], reqID)
  1352		return payload
  1353	}
  1354	func decodeFailoverBatchRequestPayload(payload []byte) ([]int, uint64, error) {
  1355		if len(payload) < 1 {
  1356			return nil, 0, fmt.Errorf("message too short")
  1357		}
  1358		count := int(payload[0])
  1359		if count == 0 {
  1360			return nil, 0, fmt.Errorf("batch has no redundancy groups")
  1361		}
  1362		if len(payload) < 1+count+8 {
  1363			return nil, 0, fmt.Errorf("message too short")
  1364		}
  1365		rgIDs := make([]int, 0, count)
  1366		for _, rgID := range payload[1 : 1+count] {
  1367			rgIDs = append(rgIDs, int(rgID))
  1368		}
  1369		ids, err := normalizeFailoverRGIDs(rgIDs)
  1370		if err != nil {
  1371			return nil, 0, err
  1372		}
  1373		return ids, binary.LittleEndian.Uint64(payload[1+count : 1+count+8]), nil
  1374	}
  1375	func encodeFailoverBatchAckPayload(rgIDs []int, status uint8, reqID uint64, detail string) []byte {
  1376		payload := make([]byte, 1+len(rgIDs)+1+8+len(detail))
  1377		payload[0] = byte(len(rgIDs))
  1378		for i, rgID := range rgIDs {
  1379			payload[1+i] = byte(rgID)
  1380		}
  1381		payload[1+len(rgIDs)] = status
  1382		binary.LittleEndian.PutUint64(payload[1+len(rgIDs)+1:], reqID)
  1383		copy(payload[1+len(rgIDs)+1+8:], detail)
  1384		return payload
  1385	}
  1386	func decodeFailoverBatchAckPayload(payload []byte) ([]int, uint8, uint64, string, error) {
  1387		if len(payload) < 1 {
  1388			return nil, 0, 0, "", fmt.Errorf("message too short")
  1389		}
  1390		count := int(payload[0])
  1391		if count == 0 {
  1392			return nil, 0, 0, "", fmt.Errorf("batch has no redundancy groups")
  1393		}
  1394		if len(payload) < 1+count+1+8 {
  1395			return nil, 0, 0, "", fmt.Errorf("message too short")
  1396		}
  1397		rgIDs := make([]int, 0, count)
  1398		for _, rgID := range payload[1 : 1+count] {
  1399			rgIDs = append(rgIDs, int(rgID))
  1400		}
  1401		ids, err := normalizeFailoverRGIDs(rgIDs)
  1402		if err != nil {
  1403			return nil, 0, 0, "", err
  1404		}
  1405		status := payload[1+count]
  1406		reqID := binary.LittleEndian.Uint64(payload[1+count+1 : 1+count+1+8])
  1407		detail := string(payload[1+count+1+8:])
  1408		return ids, status, reqID, detail, nil
  1409	}
  1410	
  1411	type sessionSyncSweepProfiler interface {
  1412		SessionSyncSweepProfile() (enabled bool, activeInterval, idleInterval time.Duration)
  1413	}
  1414	type clusterSyncedSessionInstaller interface {
  1415		SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error
  1416		SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error
  1417	}
  1418	
  1419	const deleteJournalDefaultCap = 10000
  1420	
  1421	// NewSessionSync creates a new single-fabric session synchronization manager.
  1422	//
  1423	// The runtime parameter is backend-neutral (see clusterRuntime in runtime.go).
  1424	// In-tree callers either pass nil at construction time and wire the runtime
  1425	// later via SetRuntime (the daemon's pattern, see daemon_ha_sync.go) or pass a
  1426	// runtime that already implements Sessions()/Telemetry() — both
  1427	// *dataplane.Manager and *dataplane/userspace.LegacyDataPlaneAdapter satisfy
  1428	// that contract. Callers that hold only a value typed as dataplane.DataPlane
  1429	// (the legacy bridge does NOT expose Sessions()/Telemetry() directly) can
  1430	// either: (a) wrap it in a small local type that adds Sessions() and
  1431	// Telemetry() returning dataplane.SessionStoreOf(dp) /
  1432	// dataplane.TelemetryOf(dp) and
  1433	// pass that wrapper here — Go structural typing accepts any value with the
  1434	// right method set even though clusterRuntime is package-private — or (b)
  1435	// pass nil and use the deprecated SetDataPlane alias, which performs the
  1436	// same adaptation internally.
  1437	func NewSessionSync(localAddr, peerAddr string, rt clusterRuntime) *SessionSync {
  1438		s := &SessionSync{
  1439			localAddr:                  localAddr,
  1440			peerAddr:                   peerAddr,
  1441			sendCh:                     make(chan []byte, 4096),
  1442			deleteJournalCap:           deleteJournalDefaultCap,
  1443			failoverWaiters:            make(map[int]failoverWaiter),
  1444			failoverCommitWaiters:      make(map[int]failoverWaiter),
  1445			failoverBatchWaiters:       make(map[string]failoverWaiter),
  1446			failoverBatchCommitWaiters: make(map[string]failoverWaiter),
  1447		}
  1448		s.initGenState()
  1449		s.SetRuntime(rt)
  1450		return s

exec
/bin/bash -lc "cat AGENTS.md; rg -n 'muse-spark-review-00[789]|8830|8859|8791' docs/research docs/reviews .codex --glob '"'!**/8865-muse-spark-008-009/*'"'" in /var/tmp/RES8865
 exited 1 in 0ms:
## Agent Roles

Use these roles whenever work is split across multiple Codex agents.

### Orchestrator

- Owns the overall plan, sequencing, and user communication.
- Decides agent boundaries, assigns worktrees, and prevents overlap.
- Reviews architect and implementor outputs before considering a workstream done.
- Keeps agents running until the code, docs, and validation are at a production-quality bar.
- Must keep agents working until they reach a real stopping point that requires user interaction or they have genuinely run out of assigned work.

### Architect

- Owns the design for one workstream.
- Keeps the plan, invariants, architecture, `README.md` updates, and system fit in sync with the implementation.
- Defines the intended write scope for implementors and checks that the resulting code matches the documented invariants exactly.
- Surfaces ambiguity, design risk, and missing validation quickly; does not stop at a rough plan if the implementation still needs direction.
- May refine or clarify invariants, but any material invariant change must be signed off on by the user before it is treated as approved design.

### Design Reviewer

- Reviews the architect's design output after every proposal and every revision, not just at the end.
- Holds a deliberately high bar and is expected to be somewhat antagonistic in service of quality.
- Challenges assumptions, proposes alternatives, asks clarifying questions, and looks for weak invariants, hidden coupling, operational risk, and missing test strategy.
- Gives concrete feedback to the architect until the design is crisp enough that implementation can proceed without ambiguity.
- Does not silently accept hand-wavy plans. If a design is underspecified, inconsistent, or too risky, sends it back with explicit objections.

### Implementor

- Owns concrete code changes for a bounded slice inside one workstream.
- Works only within the assigned file and worktree scope.
- Carries changes through code, tests, formatting, and validation; does not stop after partial implementation.
- Reports exact files changed, exact commands run, and any remaining gaps blocking production readiness.

### Reviewer

- Reviews implementor output after the architect has validated that it matches the intended design.
- Focuses on correctness, regressions, missing validation, unclear invariants, and production risks.
- Treats architect validation as necessary but not sufficient; the reviewer performs an independent check before the workstream is considered ready.
- Does not broaden scope casually; either approves the validated slice or returns concrete findings that must be resolved.

## Multi-Agent Rules

- The main checkout is the control checkout. Use it for orchestration, stack inspection, final audits, amend/restack/publish work, and shared documentation updates unless the orchestrator assigns docs to a dedicated worker.
- Before an implementor edits code, create a dedicated worktree for that agent from the main checkout and tell the agent its exact worktree path.
- Name worktrees so ownership is obvious, for example by role or agent name, and keep one active workstream per worktree.
- Create worktrees from the main checkout with a clear branch or bookmark context, and verify the starting commit before handing them to workers.
- After creating a worktree, confirm the agent can report `pwd`, current commit, and assigned write scope before implementation begins.
- Use these commands from the main checkout:
  - list worktrees: `git worktree list`
  - create a worker worktree: `git worktree add <path> --label <agent-or-role>`
  - create a worker worktree with the current dirty snapshot copied in: `git worktree add <path> --label <agent-or-role> --snapshot`
  - relabel a worktree: `git worktree label <path> <label>`

exec
/bin/bash -lc "rg -n 'packedStatements|mgmtVRFName|bounded_read|commitWithDescriptionLocked|maxConfigFileSize' pkg; rg --files /var/tmp /home/ps 2>/dev/null | rg 'muse.spark.review.00[789]|8830' | head -90; git log -8 --oneline" in /var/tmp/RES8865
 succeeded in 654ms:
/home/ps/git/linux/Documentation/devicetree/bindings/usb/parade,ps8830.yaml
/home/ps/git/linux/sound/pci/au88x0/au8830.h
/home/ps/git/linux/sound/pci/au88x0/au8830.c
/home/ps/git/linux/drivers/media/dvb-frontends/atbm8830_priv.h
/home/ps/git/linux/drivers/media/dvb-frontends/atbm8830.c
/home/ps/git/linux/drivers/media/dvb-frontends/atbm8830.h
/home/ps/git/bpfrx/cache/gc3476/40/4057f8830b52ec3a3312375cf4aa23c61d9f8ebe37fd53dd6975b3f4feedc1ca-a
/home/ps/git/bpfrx/cache/gc3476/72/72128f6e2432ee93fda624886f1a288830a886fdaa99f6d59ef62aa00789e147-d
/home/ps/git/bpfrx/cache/gc3476/51/513061f8451374399a098baab838efbbb0893c8f0b0596b43803d790988308ca-a
/home/ps/git/bpfrx/cache/gc3476/11/110acb220776b2ae28288309d790bb31aee2c562c125fdf4fd2e2c80d25bcb39-a
/home/ps/git/bpfrx/cache/gc3476/2d/2d8a158208830a5c48a47cad7d272d6aee0a60e424536aa683c9939f00e6aea4-a
958de0c92 docs: #8865 research plan r1 for muse-spark 008+009
0ab441553 Merge pull request #8864 from psaab/fix/8852-depth-correction
638bf81ea test: separate the blind-pair list's durable claim from its volatile one
b24e26d3b Merge pull request #8861 from psaab/fix/8854-hoist-hostinbound
9f44de908 config: hoist the loop-invariant host-inbound resolver out of the zone loop
c6c5a8b3c Merge pull request #8856 from psaab/fix/8850-elided-security-containers
df2b04c11 Merge pull request #8857 from psaab/work/8852-annotate
9a33a3221 test: record which blind scope pairs are confirmed defects

exec
/bin/bash -lc "rg -n '7175|decodeIPsecSAPayload|SyncLease struct|maxSyncMessage|MaxSync|msgIPsecSA|IPsecSA' pkg/cluster/sync* pkg/dhcpserver --glob '*.go' | head -145; rg -n 'make\\(|strings\\.(Split|Fields)|bytes\\.(Split|Fields)|binary\\.(Little|Big)Endian\\.(Uint16|Uint32|Uint64)' pkg/cluster --glob '*.go' --glob '"'!**/*test.go'"' | head -180" in /var/tmp/RES8865
 succeeded in 0ms:
pkg/cluster/sync_protocol.go:469:	// #7175: a payload that stops here is MALFORMED, not a legacy peer. This
pkg/cluster/sync_protocol.go:478:	// CORRECTION (was wrong in the original #7175 comment): this used to cite
pkg/cluster/sync_protocol.go:481:	// predate #7175: #3110 fenced every rule tier against zone 0, so a wildcard
pkg/cluster/sync_protocol.go:650:	// #7175: mandatory — see decodeSessionV4Payload for the reasoning. SessionID,
pkg/cluster/sync_protocol.go:670:	// #7175: mandatory. v6 gives NAT its own block because the addresses are 16
pkg/cluster/sync_protocol.go:785:// encodeIPsecSAPayload encodes a list of IPsec connection names as
pkg/cluster/sync_protocol.go:787:func encodeIPsecSAPayload(names []string) []byte {
pkg/cluster/sync_protocol.go:801:// decodeIPsecSAPayload decodes a newline-separated list of IPsec connection names.
pkg/cluster/sync_protocol.go:802:func decodeIPsecSAPayload(payload []byte) []string {
pkg/cluster/sync_protocol.go:935:// trailing (incarnation, seq) full-set trailer. encodeIPsecSAPayload joins
pkg/cluster/sync_protocol.go:1203:// #7175 (C179-075): the bool reports whether the payload decoded COMPLETELY.
pkg/cluster/sync_protocol.go:1223:	// #7175: a count exceeding what the payload can physically hold is not a
pkg/cluster/sync_persistent_nat_lease_8121_test.go:96:// #7175 discipline: a full-set push REPLACES the peer's set, so a truncated
pkg/cluster/sync_persistent_nat_lease_8121.go:111:// the #7175 discipline. The caller retains its previous set when this is false.
pkg/cluster/sync_persistent_nat_lease_8121.go:134:	// input, and that divergence is deliberate: #7175 fixed it under a contract
pkg/cluster/sync_persistent_nat_lease_8121.go:136:	// TestDHCPFullSetStillToleratesAnOverDeclaredCount7175 pins the tolerance.
pkg/cluster/sync_capabilities_6650_test.go:251:		{syncMsgIPsecSA, "IPsecSA"}, {syncMsgFailover, "Failover"},
pkg/cluster/sync_truncated_record_7175_test.go:11:// #7175: a truncated-but-framed session-sync record must not decode ok=true
pkg/cluster/sync_truncated_record_7175_test.go:18:// CORRECTION to the original #7175 rationale: this said zone id 0 against zone
pkg/cluster/sync_truncated_record_7175_test.go:70:func TestTruncatedV4RecordNeverDecodesWithZeroedForwardingFields7175(t *testing.T) {
pkg/cluster/sync_truncated_record_7175_test.go:84:				"record must not be accepted with a zeroed policy id (#7175)", n, got.PolicyID, val.PolicyID)
pkg/cluster/sync_truncated_record_7175_test.go:94:				"a session installed with no translation misforwards (#7175)",
pkg/cluster/sync_truncated_record_7175_test.go:112:func TestCompleteV4RecordStillRoundTrips7175(t *testing.T) {
pkg/cluster/sync_truncated_record_7175_test.go:128:func TestTruncatedV6RecordNeverDecodesWithZeroedForwardingFields7175(t *testing.T) {
pkg/cluster/sync_truncated_record_7175_test.go:149:			t.Fatalf("v6 prefix of %d bytes decoded ok=true with policy=%d zones=(%d,%d) (#7175)",
pkg/cluster/sync_truncated_record_7175_test.go:155:				"in its own 36-byte block, which was separately fail-open (#7175)", n)
pkg/cluster/sync_truncated_record_7175_test.go:166:func TestDHCPFullSetRejectsARecordCutMidStream7175(t *testing.T) {
pkg/cluster/sync_truncated_record_7175_test.go:198:func TestDHCPFullSetStillToleratesAnOverDeclaredCount7175(t *testing.T) {
pkg/cluster/sync_truncated_record_7175_test.go:208:			"(ok=%v, %d leases, want true/2). #7175 rejects data LOSS, not a wrong count", ok, len(out))
pkg/cluster/sync_test.go:464:func TestIPsecSAPayloadRoundTrip(t *testing.T) {
pkg/cluster/sync_test.go:466:	payload := encodeIPsecSAPayload(names)
pkg/cluster/sync_test.go:467:	decoded := decodeIPsecSAPayload(payload)
pkg/cluster/sync_test.go:479:func TestIPsecSAPayloadEmpty(t *testing.T) {
pkg/cluster/sync_test.go:480:	payload := encodeIPsecSAPayload(nil)
pkg/cluster/sync_test.go:481:	decoded := decodeIPsecSAPayload(payload)
pkg/cluster/sync_test.go:487:func TestPeerIPsecSAs(t *testing.T) {
pkg/cluster/sync_test.go:491:	if names := ss.PeerIPsecSAs(); len(names) != 0 {
pkg/cluster/sync_test.go:496:	ss.handleMessage(nil, syncMsgIPsecSA, encodeIPsecSAPayload([]string{"vpn-a", "vpn-b"}))
pkg/cluster/sync_test.go:498:	names := ss.PeerIPsecSAs()
pkg/cluster/sync_test.go:507:// TestIPsecSAEmptyPushClearsPeer proves the receiver side of the #4385 fix: an
pkg/cluster/sync_test.go:510:// reinitiateIPsecSAs finds nothing to resurrect. The receiver overwrites the
pkg/cluster/sync_test.go:512:// empty set (the syncIPsecSAPeriodic decision, tested in pkg/daemon).
pkg/cluster/sync_test.go:513:func TestIPsecSAEmptyPushClearsPeer(t *testing.T) {
pkg/cluster/sync_test.go:517:	ss.OnIPsecSAReceived = func(names []string) { lastReceived = names }
pkg/cluster/sync_test.go:520:	ss.handleMessage(nil, syncMsgIPsecSA, encodeIPsecSAPayload([]string{"vpn-a"}))
pkg/cluster/sync_test.go:521:	if names := ss.PeerIPsecSAs(); len(names) != 1 || names[0] != "vpn-a" {
pkg/cluster/sync_test.go:525:		t.Fatalf("setup: OnIPsecSAReceived want 1 name, got %v", lastReceived)
pkg/cluster/sync_test.go:530:	ss.handleMessage(nil, syncMsgIPsecSA, encodeIPsecSAPayload(nil))
pkg/cluster/sync_test.go:531:	if names := ss.PeerIPsecSAs(); len(names) != 0 {
pkg/cluster/sync_test.go:535:		t.Fatalf("empty push: OnIPsecSAReceived want 0 names, got %v", lastReceived)
pkg/cluster/sync_test.go:539:// TestQueueIPsecSAConfirmedSend pins the #4385 confirmed-send report:
pkg/cluster/sync_test.go:540:// QueueIPsecSA returns false when there is no active conn (nothing sent) and
pkg/cluster/sync_test.go:544:func TestQueueIPsecSAConfirmedSend(t *testing.T) {
pkg/cluster/sync_test.go:549:	if ss.QueueIPsecSA([]string{"vpn-a"}) {
pkg/cluster/sync_test.go:550:		t.Fatal("QueueIPsecSA with no active conn must report an unconfirmed send")
pkg/cluster/sync_test.go:552:	if ss.QueueIPsecSA(nil) {
pkg/cluster/sync_test.go:553:		t.Fatal("QueueIPsecSA(empty) with no active conn must report an unconfirmed send")
pkg/cluster/sync_test.go:562:	if !ss.QueueIPsecSA([]string{"vpn-a"}) {
pkg/cluster/sync_test.go:563:		t.Fatal("QueueIPsecSA with an active conn must report a confirmed send")
pkg/cluster/sync_test.go:565:	if !ss.QueueIPsecSA(nil) {
pkg/cluster/sync_test.go:566:		t.Fatal("QueueIPsecSA(empty) with an active conn must report a confirmed send")
pkg/cluster/sync_conn_read.go:112:				// #7175: a truncated record used to decode ok=true with PolicyID,
pkg/cluster/sync_conn_read.go:147:				// #7175: a truncated record used to decode ok=true with PolicyID,
pkg/cluster/sync_conn_read.go:464:	case syncMsgIPsecSA:
pkg/cluster/sync_conn_read.go:465:		s.stats.IPsecSAReceived.Add(1)
pkg/cluster/sync_conn_read.go:475:			s.stats.IPsecSAStaleIgnored.Add(1)
pkg/cluster/sync_conn_read.go:484:		names := decodeIPsecSAPayload(stripIPsecFullSetDelim(base))
pkg/cluster/sync_conn_read.go:485:		s.peerIPsecSAsMu.Lock()
pkg/cluster/sync_conn_read.go:486:		s.peerIPsecSAs = names
pkg/cluster/sync_conn_read.go:487:		s.peerIPsecSAsMu.Unlock()
pkg/cluster/sync_conn_read.go:489:		if s.OnIPsecSAReceived != nil {
pkg/cluster/sync_conn_read.go:490:			s.OnIPsecSAReceived(names)
pkg/cluster/sync_conn_read.go:533:			// #7175: a full-set push REPLACES the set, so storing a truncated
pkg/cluster/sync_conn_read.go:560:			// #7175: a full-set push REPLACES the set, so storing a truncated
pkg/cluster/sync.go:79:	syncMsgIPsecSA                = 9
pkg/cluster/sync.go:269:	// MalformedRecordsDropped counts sync records REJECTED by the #7175 decode
pkg/cluster/sync.go:271:	// a DHCP full-set push that did not decode completely. Before #7175 these
pkg/cluster/sync.go:353:	IPsecSASent              atomic.Uint64
pkg/cluster/sync.go:354:	IPsecSAReceived          atomic.Uint64
pkg/cluster/sync.go:355:	// IPsecSAStaleIgnored counts IPsec SA full-sets dropped by the #5706
pkg/cluster/sync.go:360:	IPsecSAStaleIgnored atomic.Uint64
pkg/cluster/sync.go:368:	// ordering guard (per family), the DHCP analog of IPsecSAStaleIgnored: a
pkg/cluster/sync.go:485:	IPsecSASent                uint64
pkg/cluster/sync.go:486:	IPsecSAReceived            uint64
pkg/cluster/sync.go:487:	IPsecSAStaleIgnored        uint64
pkg/cluster/sync.go:765:	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
pkg/cluster/sync.go:766:	OnIPsecSAReceived func(connectionNames []string)
pkg/cluster/sync.go:873:	peerIPsecSAs       []string
pkg/cluster/sync.go:874:	peerIPsecSAsMu     sync.Mutex
pkg/cluster/sync.go:876:	// family (the peerIPsecSAs precedent). On takeover the daemon reads these
pkg/cluster/sync.go:1619:	return SyncStatsSnapshot{SessionsSent: s.stats.SessionsSent.Load(), SweepSessionsSent: s.stats.SweepSessionsSent.Load(), SessionsReceived: s.stats.SessionsReceived.Load(), SessionsInstalled: s.stats.SessionsInstalled.Load(), DeletesSent: s.stats.DeletesSent.Load(), DeletesReceived: s.stats.DeletesReceived.Load(), BulkSyncs: s.stats.BulkSyncs.Load(), ConfigsSent: s.stats.ConfigsSent.Load(), ConfigsReceived: s.stats.ConfigsReceived.Load(), ConfigsStaleIgnored: s.stats.ConfigsStaleIgnored.Load(), BulkPrimesWithoutIncarnation: s.stats.BulkPrimesWithoutIncarnation.Load(), PeerBootIncarnation: s.PeerBootIncarnation().String(), ConfigsDeadIncarnationDropped: s.stats.ConfigsDeadIncarnationDropped.Load(), ConfigsApplyFailed: s.stats.ConfigsApplyFailed.Load(), ImportsRefusedByHelper: s.stats.ImportsRefusedByHelper.Load(), ConfigsQueueFullDropped: s.stats.ConfigsQueueFullDropped.Load(), ConfigApplyNacksReceived: s.stats.ConfigApplyNacksReceived.Load(), IPsecSASent: s.stats.IPsecSASent.Load(), IPsecSAReceived: s.stats.IPsecSAReceived.Load(), IPsecSAStaleIgnored: s.stats.IPsecSAStaleIgnored.Load(), DHCPLeasesSent: s.stats.DHCPLeasesSent.Load(), DHCPLeasesReceived: s.stats.DHCPLeasesReceived.Load(), DHCPLeasesStaleIgnored: s.stats.DHCPLeasesStaleIgnored.Load(), DHCPLeasesSeeded: s.stats.DHCPLeasesSeeded.Load(), FencesSent: s.stats.FencesSent.Load(), FencesReceived: s.stats.FencesReceived.Load(), FenceAcksSent: s.stats.FenceAcksSent.Load(), FenceAcksReceived: s.stats.FenceAcksReceived.Load(), FenceAcksTimedOut: s.stats.FenceAcksTimedOut.Load(), Errors: s.stats.Errors.Load(), DeletesDropped: s.stats.DeletesDropped.Load(), DeletesStaleIgnored: s.stats.DeletesStaleIgnored.Load(), InstallsStaleIgnored: s.stats.InstallsStaleIgnored.Load(), SessionsStaleConfigIgnored: s.stats.SessionsStaleConfigIgnored.Load(), GenMapOverflow: s.stats.GenMapOverflow.Load(), PreAuthRejected: s.stats.PreAuthRejected.Load(), Connected: s.stats.Connected.Load(), ActiveFabric: activeFabric, BulkSyncStartTime: s.stats.BulkSyncStartTime.Load(), BulkSyncEndTime: s.stats.BulkSyncEndTime.Load(), BulkSyncSessions: s.stats.BulkSyncSessions.Load(), LastConfigSyncTime: s.stats.LastConfigSyncTime.Load(), LastConfigSyncSize: s.stats.LastConfigSyncSize.Load(), LastFenceSeq: s.stats.LastFenceSeq.Load(), LastFenceAckAt: s.stats.LastFenceAckAt.Load()}
pkg/cluster/sync.go:1818:	return fmt.Sprintf("Session sync statistics:\n"+"  Connected:          %v\n"+"  Active fabric:      %s\n"+"  Sessions sent:      %d\n"+"  Sessions received:  %d\n"+"  Sessions installed: %d\n"+"  Deletes sent:       %d\n"+"  Deletes received:   %d\n"+"  Bulk syncs:         %d\n"+"  Configs sent:       %d\n"+"  Configs received:   %d\n"+"  IPsec SAs sent:     %d\n"+"  IPsec SAs received: %d\n"+"  Fences sent:        %d\n"+"  Fences received:    %d\n"+"  Install fence seq:  %d\n"+"  Last fence ack:     %s\n"+"  Errors:             %d\n", s.stats.Connected.Load(), fabricStr, s.stats.SessionsSent.Load(), s.stats.SessionsReceived.Load(), s.stats.SessionsInstalled.Load(), s.stats.DeletesSent.Load(), s.stats.DeletesReceived.Load(), s.stats.BulkSyncs.Load(), s.stats.ConfigsSent.Load(), s.stats.ConfigsReceived.Load(), s.stats.IPsecSASent.Load(), s.stats.IPsecSAReceived.Load(), s.stats.FencesSent.Load(), s.stats.FencesReceived.Load(), fenceSeq, fenceAckStr, s.stats.Errors.Load())
pkg/cluster/sync.go:1821:func (s *SessionSync) PeerIPsecSAs() []string {
pkg/cluster/sync.go:1822:	s.peerIPsecSAsMu.Lock()
pkg/cluster/sync.go:1823:	defer s.peerIPsecSAsMu.Unlock()
pkg/cluster/sync.go:1824:	cp := make([]string, len(s.peerIPsecSAs))
pkg/cluster/sync.go:1825:	copy(cp, s.peerIPsecSAs)
pkg/cluster/sync.go:1829:// QueueIPsecSA advertises the active IPsec connection-name set to the peer over
pkg/cluster/sync.go:1837:func (s *SessionSync) QueueIPsecSA(connectionNames []string) bool {
pkg/cluster/sync.go:1851:	payload := appendIPsecFullSetSeq(encodeIPsecSAPayload(connectionNames), s.syncEpoch, seq)
pkg/cluster/sync.go:1853:	err := writeMsg(conn, syncMsgIPsecSA, payload)
pkg/cluster/sync.go:1861:	s.stats.IPsecSASent.Add(1)
pkg/cluster/sync.go:1966:// re-pushes), it NEVER blocks lease granting on this node. Mirrors QueueIPsecSA.
pkg/dhcpserver/lease_sync.go:32://     reinitiateIPsecSAs precedent).
pkg/dhcpserver/lease_sync.go:60:// reinitiateIPsecSAs, so a slow Kea only delays the seed, never the takeover.
pkg/dhcpserver/lease_sync.go:66:// the standby's process memory exactly like peerIPsecSAs.
pkg/dhcpserver/lease_sync.go:71:type SyncLease struct {
pkg/cluster/sync_auth.go:254:	out := make([]byte, len(frame)+syncAuthFrameTrailerSize)
pkg/cluster/sync_auth.go:274:	seq := binary.LittleEndian.Uint64(trailer[:8])
pkg/cluster/sync_auth.go:403:	hdr := make([]byte, syncHeaderSize)
pkg/cluster/sync_auth.go:411:	length := binary.LittleEndian.Uint32(hdr[8:12])
pkg/cluster/sync_auth.go:416:		payload = make([]byte, length)
pkg/cluster/sync_config_crypto.go:177:		ready: make(chan struct{}),
pkg/cluster/sync_config_crypto.go:203:	salt := make([]byte, 0, len(lo)+len(hi))
pkg/cluster/sync_config_crypto.go:225:	nonce := make([]byte, syncConfigNonceSize)
pkg/cluster/sync_config_crypto.go:229:	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
pkg/cluster/sync_config_crypto.go:316:	payload := make([]byte, 0, 1+syncConfigECDHPubSize)
pkg/cluster/sync_failover.go:22:	set := make(map[int]struct{}, len(a))
pkg/cluster/sync_failover.go:79:	waitCh := make(chan failoverAck, 1)
pkg/cluster/sync_failover.go:92:	payload := make([]byte, 9)
pkg/cluster/sync_failover.go:146:	waitCh := make(chan failoverAck, 1)
pkg/cluster/sync_failover.go:229:	waitCh := make(chan failoverAck, 1)
pkg/cluster/sync_failover.go:241:	payload := make([]byte, 9)
pkg/cluster/sync_failover.go:295:	waitCh := make(chan failoverAck, 1)
pkg/cluster/sync_failover.go:515:	payload := make([]byte, 10+len(detail))
pkg/cluster/sync_auth_noise_7163.go:158:	buf := make([]byte, 0, 2+4*4)
pkg/cluster/heartbeat_epoch_owner_7501.go:87:	f := strings.Fields(strings.TrimSpace(s))
pkg/cluster/heartbeat_epoch_owner_7501.go:155:	rest := strings.Fields(s[close+1:])
pkg/cluster/heartbeat_manager.go:558:	newPeerGroups := make(map[int]PeerGroupState, len(pkt.Groups))
pkg/cluster/heartbeat_manager.go:582:		m.peerMonitors = make([]InterfaceMonitorInfo, len(pkt.Monitors))
pkg/cluster/heartbeat_manager.go:658:	m.peerGroups = make(map[int]PeerGroupState)
pkg/cluster/kernel_selfrecover.go:167:	ids := make([]int, 0, len(m.groups))
pkg/cluster/sync_conn_write.go:200:		merged := make([][]byte, 0, total)
pkg/cluster/sync_conn_write.go:216:	merged := make([][]byte, 0, capN)
pkg/cluster/garp.go:95:	pkt := make([]byte, 42) // 14 ethernet + 28 ARP
pkg/cluster/garp.go:394:	pkt := make([]byte, 42) // 14 ethernet + 28 ARP
pkg/cluster/garp.go:587:	pkt := make([]byte, 86)
pkg/cluster/garp.go:710:	pkt := make([]byte, 86)
pkg/cluster/garp.go:752:	b := make([]byte, 2)
pkg/cluster/election.go:749:	desired := make(map[monitorKey]int)
pkg/cluster/election.go:768:	affected := make(map[int]struct{})
pkg/cluster/events.go:61:		events:  make(map[EventCategory][]HistoryEvent),
pkg/cluster/events.go:98:	cp := make([]HistoryEvent, len(ring))
pkg/cluster/heartbeat_epoch.go:526:	return binary.LittleEndian.Uint64(data[markerAt+heartbeatEpochMarkerSize : bodyEnd]), true
pkg/cluster/heartbeat_epoch.go:965:		worker = &bootEpochRefineWorker{done: make(chan struct{})}
pkg/cluster/sync_conn.go:914:	done := make(chan struct{})
pkg/cluster/sync_conn.go:1078:		s.failoverWaiters = make(map[int]failoverWaiter)
pkg/cluster/sync_conn.go:1079:		s.failoverCommitWaiters = make(map[int]failoverWaiter)
pkg/cluster/sync_conn.go:1080:		s.failoverBatchWaiters = make(map[string]failoverWaiter)
pkg/cluster/sync_conn.go:1081:		s.failoverBatchCommitWaiters = make(map[string]failoverWaiter)
pkg/cluster/monitor.go:221:		ifaceState:       make(map[monitorKey]*monitorState),
pkg/cluster/monitor.go:222:		ipState:          make(map[ipMonitorKey]*monitorState),
pkg/cluster/monitor.go:223:		ipDebts:          make(map[int]map[string]int),
pkg/cluster/monitor.go:224:		ipThresholdState: make(map[int]bool),
pkg/cluster/monitor.go:342:	desired := make(map[monitorKey]bool)
pkg/cluster/monitor.go:343:	desiredRGs := make(map[int]bool)
pkg/cluster/monitor.go:482:	cp := make([]InterfaceMonitorInfo, len(mon.localStatuses))
pkg/cluster/monitor.go:618:	results := make([]ipProbeResult, len(addrs))
pkg/cluster/monitor.go:630:	sem := make(chan struct{}, conc)
pkg/cluster/monitor.go:979:		installed = make(map[string]int)
pkg/cluster/monitor.go:1105:	probeDone := make(chan struct{})
pkg/cluster/monitor.go:1164:	reply := make([]byte, 1500)
pkg/cluster/sync_auth_upgrade.go:491:	payload := make([]byte, 0, 1+len(msg1))
pkg/cluster/sync_auth_upgrade.go:688:	payloadOut := make([]byte, 0, 1+len(msg2))
pkg/cluster/sync_auth_upgrade.go:777:	confirm := make([]byte, 0, 1+syncAuthUpgradeConfirmLen)
pkg/cluster/group_state.go:20:	seen := make(map[int]bool)
pkg/cluster/group_state.go:206:	states := make([]RedundancyGroupState, 0, len(m.groups))
pkg/cluster/group_state.go:210:			cp.MonitorFails = make([]string, len(rg.MonitorFails))
pkg/cluster/group_state.go:214:			cp.ReadinessReasons = make([]string, len(rg.ReadinessReasons))
pkg/cluster/group_state.go:246:	ids := make([]int, 0, len(m.groups))
pkg/cluster/group_state.go:268:		cp.MonitorFails = make([]string, len(rg.MonitorFails))
pkg/cluster/group_state.go:272:		cp.ReadinessReasons = make([]string, len(rg.ReadinessReasons))
pkg/cluster/group_state.go:380:	result := make(map[int]int, len(m.groups))
pkg/cluster/arp_responder_8621.go:104:	if binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_ARP {
pkg/cluster/arp_responder_8621.go:107:	if binary.BigEndian.Uint16(frame[14:16]) != arpHTypeEther ||
pkg/cluster/arp_responder_8621.go:108:		binary.BigEndian.Uint16(frame[16:18]) != arpPTypeIPv4 ||
pkg/cluster/arp_responder_8621.go:113:	if binary.BigEndian.Uint16(frame[arpOpcodeOffset:arpOpcodeOffset+2]) != arpOpcodeReq {
pkg/cluster/arp_responder_8621.go:143:	pkt := make([]byte, arpFrameLen)
pkg/cluster/sync_admission.go:92:		s.setupConns = make(map[net.Conn]bool)
pkg/cluster/sync_admission.go:125:	conns := make([]net.Conn, 0, len(s.setupConns))
pkg/cluster/heartbeat.go:266:	buf := make([]byte, maxHeartbeatSize)
pkg/cluster/heartbeat.go:366:		ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
pkg/cluster/heartbeat.go:376:	pkt.Groups = make([]HeartbeatGroup, numGroups)
pkg/cluster/heartbeat.go:381:			Priority: binary.LittleEndian.Uint16(data[off+1 : off+3]),
pkg/cluster/heartbeat.go:434:		pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
pkg/cluster/heartbeat.go:534:	trailer := make([]byte, heartbeatAuthTrailerSize)
pkg/cluster/heartbeat.go:539:	out := make([]byte, 0, len(body)+tailReserve)
pkg/cluster/heartbeat.go:567:	session = binary.LittleEndian.Uint64(data[start+4 : start+12])
pkg/cluster/heartbeat.go:568:	counter = binary.LittleEndian.Uint64(data[start+12 : start+20])
pkg/cluster/heartbeat.go:1285:	return binary.LittleEndian.Uint64(b[:])
pkg/cluster/heartbeat.go:1389:		stopCh:   make(chan struct{}),
pkg/cluster/heartbeat.go:1528:		stopCh:    make(chan struct{}),
pkg/cluster/heartbeat.go:1550:	buf := make([]byte, maxHeartbeatSize)
pkg/cluster/sync_bulk.go:431:	seq := binary.LittleEndian.Uint64(payload)
pkg/cluster/sync_bulk.go:446:	waiter := make(chan struct{})
pkg/cluster/sync_bulk.go:449:		s.barrierWaiters = make(map[uint64]chan struct{})
pkg/cluster/sync_conn_read.go:18:	hdrBuf := make([]byte, syncHeaderSize)
pkg/cluster/sync_conn_read.go:54:		hdr.Length = binary.LittleEndian.Uint32(hdrBuf[8:12])
pkg/cluster/sync_conn_read.go:66:			payload = make([]byte, hdr.Length)
pkg/cluster/sync_conn_read.go:76:			trailer := make([]byte, syncAuthFrameTrailerSize)
pkg/cluster/sync_conn_read.go:174:			key.SrcPort = binary.LittleEndian.Uint16(payload[8:10])
pkg/cluster/sync_conn_read.go:175:			key.DstPort = binary.LittleEndian.Uint16(payload[10:12])
pkg/cluster/sync_conn_read.go:181:				gen = binary.LittleEndian.Uint64(payload[16:24])
pkg/cluster/sync_conn_read.go:191:			key.SrcPort = binary.LittleEndian.Uint16(payload[32:34])
pkg/cluster/sync_conn_read.go:192:			key.DstPort = binary.LittleEndian.Uint16(payload[34:36])
pkg/cluster/sync_conn_read.go:197:				gen = binary.LittleEndian.Uint64(payload[40:48])
pkg/cluster/sync_conn_read.go:204:			epoch = binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:243:		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
pkg/cluster/sync_conn_read.go:244:		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
pkg/cluster/sync_conn_read.go:294:			epoch = binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:340:		epoch := binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:378:		nackedGen := binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:579:		reqID := binary.LittleEndian.Uint64(payload[1:9])
pkg/cluster/sync_conn_read.go:589:		reqID := binary.LittleEndian.Uint64(payload[2:10])
pkg/cluster/sync_conn_read.go:599:		reqID := binary.LittleEndian.Uint64(payload[1:9])
pkg/cluster/sync_conn_read.go:609:		reqID := binary.LittleEndian.Uint64(payload[2:10])
pkg/cluster/sync_conn_read.go:654:			fenceSeq = binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:687:		peerProto := binary.LittleEndian.Uint16(payload[:2])
pkg/cluster/sync_conn_read.go:703:			peerWire = binary.LittleEndian.Uint16(payload[3:5])
pkg/cluster/sync_conn_read.go:713:		peerMono := binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:734:		seq := binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:743:		seq := binary.LittleEndian.Uint64(payload[:8])
pkg/cluster/sync_conn_read.go:748:			peerSessionsReceived = binary.LittleEndian.Uint64(payload[8:16])
pkg/cluster/sync_conn_read.go:749:			peerSessionsInstalled = binary.LittleEndian.Uint64(payload[16:24])
pkg/cluster/readiness.go:46:	reason = strings.Join(strings.Fields(reason), " ")
pkg/cluster/manager.go:654:		groups:                         make(map[int]*RedundancyGroupState),
pkg/cluster/manager.go:655:		monitorWeights:                 make(map[monitorKey]int),
pkg/cluster/manager.go:656:		eventCh:                        make(chan ClusterEvent, 64),
pkg/cluster/manager.go:657:		garpCounts:                     make(map[int]int),
pkg/cluster/manager.go:658:		peerGroups:                     make(map[int]PeerGroupState),
pkg/cluster/manager.go:659:		peerTransferOutOverride:        make(map[int]uint64),
pkg/cluster/manager.go:660:		peerTransferCommitGraceUntil:   make(map[int]time.Time),
pkg/cluster/manager.go:661:		localTransferOutHoldUntil:      make(map[int]time.Time),
pkg/cluster/manager.go:662:		peerTransferOutPrevious:        make(map[int]peerGroupSnapshot),
pkg/cluster/manager.go:663:		remoteTransferOutLeaseUntil:    make(map[int]time.Time),
pkg/cluster/manager.go:664:		remoteTransferOutLeaseReqID:    make(map[int]uint64),
pkg/cluster/manager.go:674:		failoverInProgress:             make(map[int]bool),
pkg/cluster/manager.go:675:		failoverGen:                    make(map[int]uint64),
pkg/cluster/manager.go:676:		bootEpochReady:                 make(chan struct{}),
pkg/cluster/manager.go:744:	out := make([][]byte, 0, 2)
pkg/cluster/sync_fence_ack_7147.go:185:	buf := make([]byte, fenceAckPayloadLen)
pkg/cluster/sync_fence_ack_7147.go:212:		Seq:       binary.LittleEndian.Uint64(payload[0:8]),
pkg/cluster/sync_fence_ack_7147.go:214:		RGsFenced: int(binary.LittleEndian.Uint16(payload[9:11])),
pkg/cluster/sync_fence_ack_7147.go:215:		RGsTotal:  int(binary.LittleEndian.Uint16(payload[11:13])),
pkg/cluster/sync_fence_ack_7147.go:339:	waiter := make(chan FenceAck, 1)
pkg/cluster/sync_fence_ack_7147.go:342:		s.fenceAckWaiters = make(map[uint64]chan FenceAck)
pkg/cluster/sync_persistent_nat_lease_8121.go:60:	recs := make([][]byte, 0, len(leases))
pkg/cluster/sync_persistent_nat_lease_8121.go:70:	b := make([]byte, 0, 8+len(recs)*96)
pkg/cluster/sync_persistent_nat_lease_8121.go:80:	b := make([]byte, 0, 96)
pkg/cluster/sync_persistent_nat_lease_8121.go:116:	count := int(binary.LittleEndian.Uint32(buf))
pkg/cluster/sync_persistent_nat_lease_8121.go:120:	// `count` is untrusted on-wire data and the make() below sizes its
pkg/cluster/sync_persistent_nat_lease_8121.go:139:	// What this is NOT: a claim about crashing. Whether the oversized make()
pkg/cluster/sync_persistent_nat_lease_8121.go:152:	out := make([]userspace.IdleLeaseWire, 0, count)
pkg/cluster/sync_persistent_nat_lease_8121.go:165:		n := int(binary.LittleEndian.Uint32(buf[off:]))
pkg/cluster/sync_persistent_nat_lease_8121.go:198:	l.SrcPort = binary.LittleEndian.Uint16(buf[off:])
pkg/cluster/sync_persistent_nat_lease_8121.go:206:	l.RemotePort = binary.LittleEndian.Uint16(buf[off:])
pkg/cluster/sync_persistent_nat_lease_8121.go:214:	l.TranslatedPort = binary.LittleEndian.Uint16(buf[off:])
pkg/cluster/sync_persistent_nat_lease_8121.go:224:	l.RemainingNs = binary.LittleEndian.Uint64(buf[off:])
pkg/cluster/sync_persistent_nat_lease_8121.go:225:	l.TimeoutNs = binary.LittleEndian.Uint64(buf[off+8:])
pkg/cluster/failover.go:562:	seen := make(map[int]struct{}, len(rgIDs))
pkg/cluster/failover.go:563:	ids := make([]int, 0, len(rgIDs))
pkg/cluster/failover.go:579:	parts := make([]string, 0, len(rgIDs))
pkg/cluster/failover.go:646:	batchGen := make(map[int]uint64, len(ids))
pkg/cluster/failover.go:730:	resolved := make([]*RedundancyGroupState, 0, len(ids))
pkg/cluster/failover.go:1100:	activeRGs := make([]int, 0, len(m.localTransferOutHoldUntil))
pkg/cluster/sync_conn_gen.go:162:		s.genSentV4 = make(map[dataplane.SessionKey]uint64)
pkg/cluster/sync_conn_gen.go:182:		s.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
pkg/cluster/sync_conn_gen.go:275:		s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
pkg/cluster/sync_conn_gen.go:289:		s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
pkg/cluster/sync_conn_gen.go:327:			s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
pkg/cluster/sync_conn_gen.go:347:			s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
pkg/cluster/sync_conn_gen.go:376:	s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
pkg/cluster/sync_conn_gen.go:377:	s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
pkg/cluster/status.go:32:	peerGroups := make(map[int]PeerGroupState, len(m.peerGroups))
pkg/cluster/status.go:1114:	allMonitors := make([]InterfaceMonitorInfo, 0, len(input.Monitors)+len(input.PeerMonitors))
pkg/cluster/sync.go:1346:	payload := make([]byte, 1+len(rgIDs)+8)
pkg/cluster/sync.go:1365:	rgIDs := make([]int, 0, count)
pkg/cluster/sync.go:1373:	return ids, binary.LittleEndian.Uint64(payload[1+count : 1+count+8]), nil
pkg/cluster/sync.go:1376:	payload := make([]byte, 1+len(rgIDs)+1+8+len(detail))
pkg/cluster/sync.go:1397:	rgIDs := make([]int, 0, count)
pkg/cluster/sync.go:1406:	reqID := binary.LittleEndian.Uint64(payload[1+count+1 : 1+count+1+8])
pkg/cluster/sync.go:1441:		sendCh:                     make(chan []byte, 4096),
pkg/cluster/sync.go:1443:		failoverWaiters:            make(map[int]failoverWaiter),
pkg/cluster/sync.go:1444:		failoverCommitWaiters:      make(map[int]failoverWaiter),
pkg/cluster/sync.go:1445:		failoverBatchWaiters:       make(map[string]failoverWaiter),
pkg/cluster/sync.go:1446:		failoverBatchCommitWaiters: make(map[string]failoverWaiter),
pkg/cluster/sync.go:1475:	s.genSentV4 = make(map[dataplane.SessionKey]uint64)

exec
/bin/bash -lc "nl -ba pkg/configstore/store_commit.go | sed -n '1,300p'; nl -ba pkg/config/bounded_read.go; rg -n 'func .*Load|ReadFile|MaxConfig|[Ll]imit|Format\\(|[Pp]ersist|[Ww]rite' pkg/configstore/store_persist.go pkg/configstore/store.go pkg/daemon/daemon.go cmd --glob '*.go' | head -160" in /var/tmp/RES8865
 succeeded in 0ms:
     1	package configstore
     2	
     3	import (
     4		"bytes"
     5		"errors"
     6		"fmt"
     7		"log/slog"
     8		"os"
     9		"path/filepath"
    10		"time"
    11	
    12		"github.com/psaab/xpf/pkg/config"
    13		"github.com/psaab/xpf/pkg/fsatomic"
    14	)
    15	
    16	// isPostRenameDurabilityFailure reports whether err is fsatomic's
    17	// post-rename directory-fsync failure (#5185). At that point the NEW
    18	// content is already VISIBLE on disk (a daemon restart would load it),
    19	// only its durability across power loss is unknown — categorically
    20	// different from a pre-rename failure, which leaves the OLD content intact.
    21	// The commit paths use it to converge to the new content on a post-rename
    22	// failure instead of reporting a clean rejection while the new content is
    23	// durable on disk (durable(C) != in-memory/applied(A)).
    24	func isPostRenameDurabilityFailure(err error) bool {
    25		var e *fsatomic.PostRenameSyncError
    26		return errors.As(err, &e)
    27	}
    28	
    29	// Rollback/archive persistence seams (#3441, following the #1916
    30	// pkg/api/tls_test.go pattern). Production code must never mutate these;
    31	// tests override them to record durability calls (so a test fails RED if a
    32	// WriteFileDurable is downgraded to atomic or a SyncDir is dropped) and to
    33	// inject write failures. nil-free: each aliases the real fsatomic writer.
    34	var (
    35		rbWriteFileDurable = fsatomic.WriteFileDurable
    36		rbWriteFileAtomic  = fsatomic.WriteFileAtomic
    37		rbSyncDir          = fsatomic.SyncDir
    38		rbRemove           = os.Remove
    39	)
    40	
    41	// archiveWriteBarrier is a test-only seam (#5869) invoked AFTER the archive
    42	// fence check and BEFORE the actual write by BOTH archive writers: the async
    43	// auto-archive goroutine and the synchronous Store.ArchiveConfig path (#6185).
    44	// Production is a no-op. A test overrides it to hold a writer MID-FLIGHT —
    45	// deliberately PAST the fence check, so the fence cannot mask it — to prove
    46	// QuiesceArchival JOINS an in-flight writer (not merely fences future ones)
    47	// before a factory reset erases the archive directory. Never mutated by
    48	// production code.
    49	var archiveWriteBarrier = func() {}
    50	
    51	// maxCommitDescriptionBytes bounds the operator-supplied commit description
    52	// (the `commit comment` text) that is recorded verbatim in the in-memory
    53	// history entry and the durable JSONL audit journal.
    54	//
    55	// #4891: an unbounded description marshals into a single oversized JSONL line.
    56	// The journal's bounded reverse-tail scanner (journal.maxTailLineBytes, 16 MiB)
    57	// treats any line past its cap as a poisoned newline-free fragment and discards
    58	// it — so an oversized-but-valid commit record would VANISH from bounded
    59	// history / `show system commit` views after allocating memory and disk
    60	// proportional to its size. 4 KiB is far above any human-authored commit
    61	// comment while keeping every journal line orders of magnitude below the
    62	// tail-scanner cap. Enforced strictly on the operator commit path (fail the
    63	// commit with a clear error before anything is persisted — the #1960 strict-at-
    64	// commit doctrine) and, as a structural belt at the journal boundary,
    65	// defensively truncated in journalLog so no Detail from any caller can poison
    66	// the tail scanner.
    67	const maxCommitDescriptionBytes = 4 << 10
    68	
    69	// CommitCheck validates the candidate configuration without applying it.
    70	func (s *Store) CommitCheck() (*config.Config, error) {
    71		s.mu.RLock()
    72		defer s.mu.RUnlock()
    73	
    74		if s.candidate == nil {
    75			return nil, fmt.Errorf("not in configuration mode")
    76		}
    77	
    78		compiled, err := s.compileTree(s.candidate)
    79		if err != nil {
    80			return nil, err
    81		}
    82	
    83		return compiled, nil
    84	}
    85	
    86	// Commit validates, compiles, and applies the candidate configuration.
    87	// Returns the compiled config for the caller to apply to the dataplane.
    88	// Identical to CommitWithDescription with an empty description (the two
    89	// were verbatim duplicates before #1799 unified them).
    90	func (s *Store) Commit() (*config.Config, error) {
    91		return s.CommitWithDescription("")
    92	}
    93	
    94	// CommitWithDescription validates, compiles, and applies the candidate configuration
    95	// with an optional comment/description attached to the history and journal entries.
    96	//
    97	// Persistence contract (#1799, Option A — persist-before-promote): the
    98	// candidate tree is written to the on-disk active config BEFORE any
    99	// in-memory promotion. WriteActive is temp-file + rename atomic
   100	// (db.go), so a persist failure leaves the previous active config
   101	// intact on disk; the commit then fails with the candidate left
   102	// intact and NOTHING mutated — no active/candidate/compiled/dirty
   103	// change, no history push, no journal entry, no rollback-file save.
   104	// A commit that reports success can therefore never silently revert
   105	// to the previous config on daemon restart.
   106	func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
   107		s.mu.Lock()
   108		defer s.mu.Unlock()
   109		return s.commitWithDescriptionLocked(description)
   110	}
   111	
   112	// CommitWithDescriptionGen is CommitWithDescription bound to an expected
   113	// candidate generation (#5848). It promotes the candidate ONLY if the current
   114	// candidate generation still equals expectedGen — the token the caller captured
   115	// (via CompileCandidateGen) before running its external device-map pre-flight.
   116	// A concurrent set/delete/load/rollback/enter-exit between snapshot and promote
   117	// bumps the generation, so this returns ErrCandidateGenerationConflict WITHOUT
   118	// mutating any store state, and the caller re-runs the whole
   119	// snapshot→pre-flight→commit against the new generation. This closes the
   120	// examined-generation-vs-promoted-generation race: the compiled config the
   121	// daemon pre-flighted against live hardware is exactly the one promoted, or the
   122	// commit conflicts — never a silent substitution.
   123	func (s *Store) CommitWithDescriptionGen(description string, expectedGen uint64) (*config.Config, error) {
   124		return s.CommitWithDescriptionGenAs(InternalCommitter(), description, expectedGen)
   125	}
   126	
   127	// CommitWithDescriptionGenAs is CommitWithDescriptionGen additionally bound to
   128	// the AUTHORITY the commit was granted under (#6808).
   129	//
   130	// It verifies BOTH tokens under one acquisition of s.mu, immediately before
   131	// promotion, because they answer different questions and neither implies the
   132	// other:
   133	//
   134	//   - expectedGen answers "is the candidate CONTENT the one that was examined?"
   135	//   - authority answers "is the SESSION that was authorized to commit still the
   136	//     one holding the lock?"
   137	//
   138	// A holder turnover that completes before the caller's snapshot produces a
   139	// perfectly consistent generation pair — describing the NEW holder's candidate.
   140	// Only the authority check rejects that.
   141	//
   142	// On turnover it returns ErrConfigHolderTurnover, NOT
   143	// ErrCandidateGenerationConflict, so it can never be swept into the caller's
   144	// generation-conflict retry: retrying would re-snapshot the new holder's
   145	// candidate and promote it under the old holder's authorization, which is
   146	// precisely the substitution being closed.
   147	func (s *Store) CommitWithDescriptionGenAs(
   148		authority CommitAuthority, description string, expectedGen uint64,
   149	) (*config.Config, error) {
   150		s.mu.Lock()
   151		defer s.mu.Unlock()
   152		if err := s.verifyCommitAuthorityLocked(authority); err != nil {
   153			return nil, err
   154		}
   155		if s.candidateGen != expectedGen {
   156			return nil, fmt.Errorf("%w (examined generation %d, current %d)",
   157				ErrCandidateGenerationConflict, expectedGen, s.candidateGen)
   158		}
   159		return s.commitWithDescriptionLocked(description)
   160	}
   161	
   162	// commitWithDescriptionLocked is the shared body of CommitWithDescription and
   163	// the generation-bound CommitWithDescriptionGen. Caller holds s.mu.Lock.
   164	func (s *Store) commitWithDescriptionLocked(description string) (*config.Config, error) {
   165		// #3893: reject a user-session commit on a read-only secondary. The
   166		// internal HA-sync ingress (SyncApply) and the commit-confirmed timeout
   167		// revert (PromoteRollback) promote the active config directly and never
   168		// reach here, so they are unaffected by this gate.
   169		if err := s.ensureWritableLocked(); err != nil {
   170			return nil, err
   171		}
   172		if s.candidate == nil {
   173			return nil, fmt.Errorf("not in configuration mode")
   174		}
   175	
   176		// #4891: reject an over-cap commit description BEFORE anything is
   177		// persisted or promoted. Fail-fast with a clear error (the #1960
   178		// strict-at-commit doctrine) so an oversized comment never bloats the
   179		// journal nor hides itself behind the tail scanner's corrupt-line defense.
   180		if len(description) > maxCommitDescriptionBytes {
   181			return nil, fmt.Errorf("commit description too long: %d bytes (max %d)",
   182				len(description), maxCommitDescriptionBytes)
   183		}
   184	
   185		compiled, err := s.compileTree(s.candidate)
   186		if err != nil {
   187			return nil, fmt.Errorf("commit check failed: %w", err)
   188		}
   189	
   190		// #1799 Option A: persist BEFORE promote. On a PRE-rename failure the
   191		// old active stays on disk and in memory; the operator sees the error
   192		// and the candidate is still there to retry.
   193		//
   194		// #5185: a POST-rename directory-fsync failure is categorically
   195		// different — the candidate (C) is already VISIBLE on disk (a restart
   196		// would load C), only its durability across power loss is unknown.
   197		// Returning a plain "commit failed" there would leave
   198		// durable(C) != in-memory/applied(A): the operator is told REJECTED
   199		// while a restart activates C — the reported-rejected-but-durable
   200		// divergence. So on a post-rename failure CONVERGE instead of rejecting:
   201		// promote C in memory and return the compiled config so the daemon
   202		// APPLIES it, restoring durable==memory==applied, and flag the
   203		// durability uncertainty through the Option-B degraded machinery
   204		// (health 503, gauge, journal ERROR, background re-fsync retry via
   205		// noteActivePersistFailureLocked). Converge-to-C is chosen over
   206		// durably-restoring-A because restoring A needs ANOTHER rename that can
   207		// itself fail post-rename — fsatomic cannot guarantee an atomic restore
   208		// — whereas C is already the durable content, so converging to it needs
   209		// no further write to hold the invariant.
   210		if err := s.writeActive(s.candidate); err != nil {
   211			if !isPostRenameDurabilityFailure(err) {
   212				return nil, fmt.Errorf("commit failed: persist active config: %w", err)
   213			}
   214			// Post-rename: converge memory+applied to C (fall through to the
   215			// promotion below), but keep the degraded signal. everCommitted /
   216			// persistMarkerCommitted are set BEFORE noteActivePersistFailureLocked
   217			// so the background retry re-writes committed=1 for C.
   218			s.everCommitted = true
   219			s.persistMarkerCommitted = true
   220			s.noteActivePersistFailureLocked("commit_postrename", err)
   221			// #5473: this commit's config C is VISIBLE on disk (post-rename: the
   222			// rename landed, only the dir-fsync is uncertain) and supersedes any
   223			// commit-confirmed window whose earlier resolution write failed. Finalize
   224			// the deferred (retained) confirm.json removal now — symmetric with the
   225			// success branch. Without this the stale flag persists into the degraded
   226			// retry, whose heal would then delete a LATER-armed window's fresh record
   227			// (or, for a plain commit, a stale PrevTree=A record lingers and a crash
   228			// reverts this just-committed C back to A). No-op unless a removal was
   229			// deferred.
   230			s.clearConfirmResolutionPendingLocked()
   231		} else {
   232			s.persistDegraded = false       // disk now holds the current config
   233			s.everCommitted = true          // #1922 step-0: a real commit has succeeded
   234			s.persistMarkerCommitted = true // #1922: degraded-retry writes committed=1
   235			// #5473: this commit's config is now durable and supersedes any
   236			// commit-confirmed window whose earlier resolution write failed. Drop
   237			// the deferred (retained) confirm.json so a reboot does not re-drive a
   238			// stale rollback that this commit has replaced. No-op unless a removal
   239			// was deferred.
   240			s.clearConfirmResolutionPendingLocked()
   241		}
   242	
   243		// Push current active to history with description
   244		s.history.Push(&HistoryEntry{
   245			Config:    s.active.Clone(),
   246			Timestamp: time.Now(),
   247			Comment:   description,
   248		})
   249	
   250		// Promote candidate to active
   251		s.active = s.candidate
   252		s.candidate = s.active.Clone()
   253		s.bumpCandidateGenLocked() // #5848: fresh candidate — advance the generation
   254		s.compiled = compiled
   255		s.dirty = false
   256		s.touchConfigLockLocked() // #4476: a commit is activity — refresh the lease
   257	
   258		// #3861: a PLAIN commit during a pending commit-confirmed window is
   259		// the confirmation (Junos semantics: any subsequent explicit commit
   260		// confirms a pending `commit confirmed`). The frontend `commit` path
   261		// intercepts a pending confirm and calls ConfirmCommit before it ever
   262		// reaches here, but NON-frontend callers (the eventengine remediation
   263		// commit, cli/gRPC/REST commit handlers) reach CommitWithDescription
   264		// directly. Without clearing the armed timer, its rollback target (the
   265		// pre-confirm T0 tree) stays live and reverts THIS just-promoted
   266		// config when it fires — silently discarding the background commit.
   267		// clearPendingConfirmLocked cancels the timer AND bumps confirmGen so a
   268		// callback that already fired and is blocked on s.mu no-ops instead of
   269		// reverting. Runs only AFTER the persist+promote succeeded, so a failed
   270		// commit leaves the pending confirm fully intact.
   271		// #5835: a plain commit is non-interactive here (the frontend confirm path
   272		// already returned an error to the operator when applicable); a durable
   273		// confirm.json-removal failure is retained as retry debt + degraded health
   274		// inside clearPendingConfirmLocked and converges autonomously.
   275		if cleared, _ := s.clearPendingConfirmLocked(); cleared {
   276			slog.Info("plain commit confirmed a pending commit-confirmed window")
   277		}
   278	
   279		// Log to journal with description
   280		s.journalLog(&JournalEntry{
   281			Action:     "commit",
   282			Detail:     description,
   283			ConfigHash: journalConfigHash(s.active),
   284		})
   285	
   286		s.saveRollbackFiles()
   287	
   288		// Auto-archive if configured (#3441 H4). Capture the JUST-COMMITTED
   289		// text, directory, max, and a nanosecond-resolution timestamp INSIDE
   290		// the commit critical section, then hand only those immutable values
   291		// to the async writer. The previous code passed nothing and let the
   292		// goroutine read s.active.Format() whenever it eventually ran: two
   293		// rapid commits raced so goroutine A could archive commit B's tree
   294		// (mislabeled archive), and the second-resolution filename meant two
   295		// same-second commits wrote the same path (later overwrote earlier).
   296		// The nanosecond timestamp makes the filename unique per commit (no
   297		// overwrite) and correctly labels the captured tree.
   298		//
   299		// #5869: skip launching a writer once the archive fence is set (a factory
   300		// reset is erasing the archive directory) and TRACK every writer we do
nl: pkg/config/bounded_read.go: No such file or directory
pkg/daemon/daemon.go:98:	// raced the bootstrap-exit `d.dp = nil` writer against the
pkg/daemon/daemon.go:259:	// (#5036): d.feeds.Apply (producer swap; persisted feeds carry their
pkg/daemon/daemon.go:383:	// write racing those reads is a data race on the pointer that gates the
pkg/daemon/daemon.go:463:	// snmpBootsPath overrides the SNMPv3 engineBoots persistence path passed
pkg/daemon/daemon.go:468:	// snmpEngineIDPath overrides the per-device EngineID component persistence
pkg/daemon/daemon.go:584:	// stays a flat Daemon field: it is the standby-side refresh rate limit read
pkg/daemon/daemon.go:641:	// #3932: the flow-traceoptions writer is published through an atomic
pkg/daemon/daemon.go:644:	// traceoptions SWAPS the underlying writer (closing the old one) instead
pkg/daemon/daemon.go:647:	// TraceWriter regardless of commit count. traceReconMu serializes the
pkg/daemon/daemon.go:649:	traceWriterPtr atomic.Pointer[logging.TraceWriter]
pkg/daemon/daemon.go:710:	// moments later). Once set, every config writer that acquires applySem
pkg/daemon/daemon.go:713:	// periodic DHCP-lease IPsec rebind) short-circuits, so nothing re-persists
pkg/daemon/daemon.go:938:	// concurrent map-pointer read/write (a real Go data race). The published
pkg/daemon/daemon.go:983:	fabricPopulated  bool   // true after first successful fab0 write
pkg/daemon/daemon.go:984:	fabric1Populated bool   // true after first successful fab1 write
pkg/daemon/daemon.go:998:	lastFabricProbe  time.Time     // rate-limit active fab0 neighbor probes
pkg/daemon/daemon.go:999:	lastFabricProbe1 time.Time     // rate-limit active fab1 neighbor probes
pkg/daemon/daemon.go:1000:	lastFabricLog0   time.Time     // rate-limit fab0 refresh failure logs
pkg/daemon/daemon.go:1001:	lastFabricLog1   time.Time     // rate-limit fab1 refresh failure logs
pkg/daemon/daemon.go:1013:	// and two reconcile writers are a fatal `concurrent map writes` throw.
pkg/daemon/daemon.go:1079:	// Guarded by clusterCommsMu since #6290; write only through
pkg/daemon/daemon.go:1082:	// directly — the boot writer holds neither applySem nor this mutex, so
pkg/daemon/daemon.go:1115:	// goroutine's write and its next read) or let a stale constructor overwrite
pkg/daemon/daemon.go:1116:	// a newer epoch's session/endpoints. The mutex makes every read/write of
pkg/daemon/daemon.go:1139:	// bind/write failure leaves it unset so the reconcile ticker retries.
pkg/daemon/daemon.go:1335:	// networkd takeover writes beyond the lifeline .network, dataplane arm,
pkg/daemon/daemon.go:1543:// .configdb): a daemon that cannot persist configuration must not
pkg/daemon/daemon.go:1569:	// write (#1917 increment B, plan §6.4 / D1). The envelope's magic header
pkg/daemon/daemon.go:1572:	store.SetConfigDBWriterVersion(opts.Version)
pkg/daemon/daemon.go:1577:	if data, err := os.ReadFile(nodeIDFile); err == nil {
pkg/configstore/store.go:8://   - store_persist.go — Load/Save, writeActive*, journal helpers, the
pkg/configstore/store.go:9://     #1799 degrade-and-retry persist machinery,
pkg/configstore/store.go:16://     file persistence
pkg/configstore/store.go:40:// MaxConfigSize bounds a single configuration payload accepted by any parse
pkg/configstore/store.go:48:// that reaches these methods without passing through the gRPC/REST limits
pkg/configstore/store.go:50:const MaxConfigSize = 16 << 20 // 16 MiB
pkg/configstore/store.go:54:	if len(content) > MaxConfigSize {
pkg/configstore/store.go:56:			len(content), MaxConfigSize)
pkg/configstore/store.go:90:	// Persistent storage
pkg/configstore/store.go:94:	// writeActiveFn is a test seam for active-config persistence
pkg/configstore/store.go:95:	// (#1799). nil (production) means s.db.WriteActive. Set via
pkg/configstore/store.go:96:	// SetWriteActiveForTesting; never assigned on production paths.
pkg/configstore/store.go:97:	writeActiveFn func(*config.ConfigTree) error
pkg/configstore/store.go:99:	// writeActiveMarkerFn is the marker-aware test seam for the #1922
pkg/configstore/store.go:101:	// db.WriteActiveMarker. Set via SetWriteActiveMarkerForTesting.
pkg/configstore/store.go:102:	writeActiveMarkerFn func(*config.ConfigTree, bool) error
pkg/configstore/store.go:107:	// on a fresh store and after the Item 1b first-commit rollback writes
pkg/configstore/store.go:114:	// #1799 Option B (degrade-not-fail) state for the persist paths
pkg/configstore/store.go:115:	// that must proceed in memory even when the disk write fails
pkg/configstore/store.go:117:	// persistDegraded is surfaced via ConfigPersistDegraded() to the
pkg/configstore/store.go:118:	// /health 503 check and the xpf_daemon_config_persist_degraded
pkg/configstore/store.go:119:	// gauge. persistRetryActive is the singleton guard for the
pkg/configstore/store.go:123:	persistDegraded            bool
pkg/configstore/store.go:124:	persistRetryActive         bool
pkg/configstore/store.go:125:	persistRetryInitialBackoff time.Duration
pkg/configstore/store.go:126:	persistRetryMaxBackoff     time.Duration
pkg/configstore/store.go:128:	// persistMarkerCommitted records the #1922 step-0 committed flag the
pkg/configstore/store.go:129:	// degraded-persist retry loop must re-write. Defaults true; set false
pkg/configstore/store.go:131:	// marker write that later heals via the retry loop persists committed=0
pkg/configstore/store.go:135:	// Every successful committed write resets it to true.
pkg/configstore/store.go:136:	persistMarkerCommitted bool
pkg/configstore/store.go:138:	// confirmResolvePendingPersist records that a commit-confirmed window was
pkg/configstore/store.go:140:	// config-sync that superseded it) but the resolving active-config write
pkg/configstore/store.go:147:	// removed) by the next durable active write — the persist-retry heal or any
pkg/configstore/store.go:150:	confirmResolvePendingPersist bool
pkg/configstore/store.go:155:	// removal is not yet durable on disk. UNLIKE confirmResolvePendingPersist
pkg/configstore/store.go:163:	// rather than reporting a false success. Surfaced via ConfigPersistDegraded()
pkg/configstore/store.go:164:	// (and ConfirmRemovalDegraded()) until the singleton persist-retry loop lands
pkg/configstore/store.go:176:	// and nothing else: `ConfigPersistDegraded()` was false, so /health returned
pkg/configstore/store.go:177:	// 200 and `xpf_daemon_config_persist_degraded` read 0. The box came up
pkg/configstore/store.go:197:	// (WriteConfirm is temp+fsync+rename+dir-fsync), so the older record is
pkg/configstore/store.go:227:	// destructive for the second: committed=0 persisted over a REAL config, so
pkg/configstore/store.go:287:	// rather than write a below-max seq rotation would prune. This marker is
pkg/configstore/store.go:293:	// not a failure — seq 0 is correct and the write path creates the dir.
pkg/configstore/store.go:319:	// write would overwrite the earlier archive. The seq always advances, so
pkg/configstore/store.go:329:	// archiveWG tracks the in-flight async auto-archive writer goroutines
pkg/configstore/store.go:331:	// fire-and-forget writer; QuiesceArchival Wait()s on it so a factory reset
pkg/configstore/store.go:332:	// can JOIN every writer that has already started before it erases the
pkg/configstore/store.go:333:	// archive directory. Without the join an untracked writer could resume
pkg/configstore/store.go:341:	// reset (#5869). Once set, no NEW archive writer is launched (the commit
pkg/configstore/store.go:343:	// and an already-launched writer that has not yet written no-ops instead of
pkg/configstore/store.go:350:	// rollbackPersistDegraded records that the most recent
pkg/configstore/store.go:351:	// saveRollbackFiles() failed to durably write a rollback slot or sync
pkg/configstore/store.go:353:	// canonical active config persisted via the #1799 persist-before-promote
pkg/configstore/store.go:358:	rollbackPersistDegraded bool
pkg/configstore/store.go:380:// backend — every persistence path (Load, writeActive, the #1799
pkg/configstore/store.go:381:// persist-retry goroutine) dereferences the DB, so constructing a Store
pkg/configstore/store.go:388:		return nil, fmt.Errorf("config db %s unusable: %w (no file-only fallback exists; refusing to run without config persistence)", dbDir, err)
pkg/configstore/store.go:400:		persistMarkerCommitted: true,
pkg/configstore/store.go:405:// loads from and persists to — the daemon's `-config` path (New's filePath).
pkg/configstore/store.go:420:// SetConfigDBWriterVersion sets the xpf build version stamped into the
pkg/configstore/store.go:421:// config-DB compatibility-envelope header on write (#1917 increment B).
pkg/configstore/store.go:424:func (s *Store) SetConfigDBWriterVersion(v string) {
pkg/configstore/store.go:425:	s.db.SetWriterVersion(v)
pkg/configstore/store.go:509:	// so a ${node} apply-group substitution / per-node rewrite that selects a
pkg/configstore/store.go:522:	// rewriteRetiredDataplaneType BEFORE compileTreeLenient, so a peer
pkg/configstore/store.go:532:	// The rewrite is applied to a CLONE. Mutating the candidate here would
pkg/configstore/store.go:538:	rewriteRetiredDataplaneType(peerTree, SyncCaller)
pkg/configstore/store.go:636:// did NOT just author — a persisted active config on local boot, or a
pkg/configstore/store.go:652:	// A persisted config written by an older binary (pre-gate, or before a
pkg/configstore/store.go:771:	// sync rejection would alarm-loop the cluster. Rewrite the
pkg/configstore/store.go:774:	rewriteRetiredDataplaneType(tree, SyncCaller)
pkg/configstore/store.go:819:	// promotion (Option B: the apply stands even if the disk write below
pkg/configstore/store.go:823:	// its removal AFTER the writeActive below so the crash-recovery record is
pkg/configstore/store.go:825:	// degrade-not-fail write fails and we had removed confirm.json up front, a
pkg/configstore/store.go:836:	// MUST stand even if the disk write fails — failing the
pkg/configstore/store.go:847:	// the markers BEFORE the persist so a failed-then-healed write (the
pkg/configstore/store.go:850:	s.persistMarkerCommitted = true
pkg/configstore/store.go:851:	if err := s.writeActive(s.active); err != nil {
pkg/configstore/store.go:852:		s.noteActivePersistFailureLocked("config_sync", err)
pkg/configstore/store.go:856:		// into a state where the persisted rollback still fires.
pkg/configstore/store.go:858:			s.confirmResolvePendingPersist = true
pkg/configstore/store.go:861:		s.persistDegraded = false
pkg/configstore/store.go:870:		// write (e.g. a prior rollback whose persist failed): the synced config
pkg/configstore/store.go:907:	s.appliedDigest = configTextDigest(s.active.Format())
pkg/configstore/store.go:922:	return s.appliedDigest == configTextDigest(s.active.Format())
pkg/configstore/store.go:927:// (configTextDigest(s.active.Format()), the ShowActive render). It lets a
pkg/configstore/store.go:941:	return configTextDigest(s.active.Format())
pkg/configstore/store_persist.go:23:func (s *Store) Load() error {
pkg/configstore/store_persist.go:52:	// persist failure triggers the #1799 retry loop BEFORE any commit/sync
pkg/configstore/store_persist.go:53:	// resets the marker, the retry must re-write committed=0 — not the
pkg/configstore/store_persist.go:56:	s.persistMarkerCommitted = committed
pkg/configstore/store_persist.go:59:	// with `system dataplane-type ebpf` or `... dpdk` persisted
pkg/configstore/store_persist.go:61:	// this rewrite, compileTree below returns
pkg/configstore/store_persist.go:66:	rewriteRetiredDataplaneType(tree, LoadCaller)
pkg/configstore/store_persist.go:68:	// #1798 migration: a persisted free-text value carrying control
pkg/configstore/store_persist.go:76:		slog.Warn("sanitized control characters in persisted config value",
pkg/configstore/store_persist.go:80:	// Tolerant compile: an already-persisted config must boot through
pkg/configstore/store_persist.go:126:// config can lock the operator out. Junos persists the pending confirm across
pkg/configstore/store_persist.go:132://   - deadline already passed during downtime -> roll back to the persisted
pkg/configstore/store_persist.go:143:// (rewriteRetiredDataplaneType, SanitizeTreeControlChars) but never the
pkg/configstore/store_persist.go:162:		// no timer, no debt, and `ConfigPersistDegraded()` false, so /health
pkg/configstore/store_persist.go:177:		slog.Error("failed to read persisted commit-confirmed state; the pending auto-rollback "+
pkg/configstore/store_persist.go:179:			"timer — configuration persistence is degraded until a commit or confirm clears it",
pkg/configstore/store_persist.go:243:		// with the same persistence semantics as PromoteRollback.
pkg/configstore/store_persist.go:247:		// this branch so the rollback's persistence/journal/record-removal all
pkg/configstore/store_persist.go:252:			// persist committed=0 and clear everCommitted so a later restart
pkg/configstore/store_persist.go:255:			s.persistMarkerCommitted = false
pkg/configstore/store_persist.go:257:			perr = s.writeActiveMarker(prevTree, false)
pkg/configstore/store_persist.go:279:			s.persistMarkerCommitted = true
pkg/configstore/store_persist.go:281:			perr = s.writeActive(prevTree)
pkg/configstore/store_persist.go:285:		// durable (writeActive above SUCCEEDED). On failure keep it — the
pkg/configstore/store_persist.go:289:		// failed write would boot the un-reverted config with no record.
pkg/configstore/store_persist.go:291:			s.noteActivePersistFailureLocked("confirm_recovery_rollback", perr)
pkg/configstore/store_persist.go:292:			s.confirmResolvePendingPersist = true
pkg/configstore/store_persist.go:294:			s.persistDegraded = false
pkg/configstore/store_persist.go:295:			s.confirmResolvePendingPersist = false
pkg/configstore/store_persist.go:340:			// rollback persists the target as COMMITTED (#6538) rather than
pkg/configstore/store_persist.go:359:// Save persists the active configuration to disk.
pkg/configstore/store_persist.go:364:	return s.writeActive(s.active)
pkg/configstore/store_persist.go:367:// writeActive persists tree as the on-disk active configuration.
pkg/configstore/store_persist.go:368:// Routes through the writeActiveFn test seam when set (#1799);
pkg/configstore/store_persist.go:370:// write (#1894). Caller must hold s.mu (read or write lock).
pkg/configstore/store_persist.go:371:func (s *Store) writeActive(tree *config.ConfigTree) error {
pkg/configstore/store_persist.go:372:	if s.writeActiveFn != nil {
pkg/configstore/store_persist.go:373:		return s.writeActiveFn(tree)
pkg/configstore/store_persist.go:375:	return s.db.WriteActive(tree)
pkg/configstore/store_persist.go:378:// writeActiveMarker persists tree as the on-disk active config with an
pkg/configstore/store_persist.go:379:// explicit #1922 step-0 committed marker. committed=false writes the
pkg/configstore/store_persist.go:381:// the writeActiveMarkerFn test seam when set; otherwise the production

exec
/bin/bash -lc "rg -n 'muse-spark|8830|8859|8791' . --glob '"'!go.sum'"' --glob '"'!Cargo.lock'"' --glob '"'!**/8865-muse-spark-008-009/*'"' --glob '"'!vendor/**'"' --glob '"'!node_modules/**'"' | head -150; git remote -v; git log --all --oneline --grep='8830\\|muse-spark-review-008\\|muse-spark-review-009\\|8859'" in /var/tmp/RES8865
 succeeded in 502ms:
codex
The proposed “same-shape” wire fix already has a contract problem: the fixed NAT decoder explicitly documents why DHCP preserves different behavior. I also found a wire-count allocation outside the claimed five-member enumeration. I’m checking those boundaries and the evidence behind the broader triage recommendation.

exec
/bin/bash -lc "nl -ba pkg/cluster/heartbeat.go | sed -n '310,432p'; nl -ba pkg/cluster/sync_truncated_fullset_7175_test.go | sed -n '1,250p'; nl -ba pkg/cluster/sync_conn_read.go | sed -n '425,485p'; nl -ba pkg/dhcpserver/lease_sync.go | sed -n '68,118p'" in /var/tmp/RES8865
 succeeded in 0ms:
   310			}
   311		}
   312	
   313		// Append monitor section, fitting as many monitors as possible.
   314		monCountOff := off // remember offset of NumMonitors byte
   315		buf[off] = 0       // NumMonitors — updated below
   316		off++
   317		numMon := 0
   318		for _, mon := range pkt.Monitors {
   319			nameBytes := []byte(mon.Interface)
   320			entrySize := 4 + len(nameBytes) // RGID + Flags + Weight + NameLen + name
   321			if off+entrySize > maxHeartbeatSize-versionReserve-tailReserve {
   322				break
   323			}
   324			buf[off] = mon.RGID
   325			flags := uint8(0)
   326			if mon.Up {
   327				flags |= 1
   328			}
   329			buf[off+1] = flags
   330			buf[off+2] = mon.Weight
   331			buf[off+3] = uint8(len(nameBytes))
   332			off += 4
   333			copy(buf[off:off+len(nameBytes)], nameBytes)
   334			off += len(nameBytes)
   335			numMon++
   336		}
   337		heartbeatMonitorTruncations.observe(len(pkt.Monitors), numMon)
   338		buf[monCountOff] = uint8(numMon)
   339		if off+versionReserve+tailReserve <= maxHeartbeatSize {
   340			buf[off] = uint8(len(version))
   341			off++
   342			if len(version) > 0 {
   343				copy(buf[off:off+len(version)], version)
   344				off += len(version)
   345			}
   346			binary.LittleEndian.PutUint16(buf[off:off+2], normalizeHAProtocolVersion(pkt.HAProtocolVersion))
   347			off += 2
   348		}
   349		return buf[:off]
   350	}
   351	
   352	// UnmarshalHeartbeat decodes a heartbeat packet from wire format.
   353	func UnmarshalHeartbeat(data []byte) (*HeartbeatPacket, error) {
   354		if len(data) < heartbeatHeaderSize {
   355			return nil, fmt.Errorf("heartbeat too short: %d bytes", len(data))
   356		}
   357		if string(data[0:4]) != heartbeatMagic {
   358			return nil, fmt.Errorf("invalid heartbeat magic: %q", string(data[0:4]))
   359		}
   360		if data[4] != heartbeatVersion {
   361			return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
   362		}
   363	
   364		pkt := &HeartbeatPacket{
   365			NodeID:            data[5],
   366			ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
   367			HAProtocolVersion: LegacyHAProtocolVersion,
   368		}
   369	
   370		numGroups := int(data[8])
   371		need := heartbeatHeaderSize + numGroups*heartbeatGroupSize
   372		if len(data) < need {
   373			return nil, fmt.Errorf("heartbeat truncated: have %d, need %d", len(data), need)
   374		}
   375	
   376		pkt.Groups = make([]HeartbeatGroup, numGroups)
   377		off := heartbeatHeaderSize
   378		for i := 0; i < numGroups; i++ {
   379			pkt.Groups[i] = HeartbeatGroup{
   380				GroupID:  data[off],
   381				Priority: binary.LittleEndian.Uint16(data[off+1 : off+3]),
   382				Weight:   data[off+3],
   383				State:    data[off+4],
   384			}
   385			off += heartbeatGroupSize
   386		}
   387	
   388		// Parse monitor section if present (backwards compatible — old packets
   389		// without monitors just have no remaining data). If the monitor section
   390		// is truncated (sender capped at maxHeartbeatSize), return whatever
   391		// monitors were successfully parsed rather than erroring — RG state
   392		// (already parsed above) is the critical data.
   393		monitorSectionComplete := true
   394		if off < len(data) {
   395			numMonitors := int(data[off])
   396			off++
   397			for i := 0; i < numMonitors; i++ {
   398				if off+4 > len(data) {
   399					monitorSectionComplete = false
   400					break // truncated — return what we have
   401				}
   402				rgID := data[off]
   403				up := data[off+1]&1 != 0
   404				weight := data[off+2]
   405				nameLen := int(data[off+3])
   406				off += 4
   407				if off+nameLen > len(data) {
   408					monitorSectionComplete = false
   409					break // truncated name — return what we have
   410				}
   411				name := string(data[off : off+nameLen])
   412				off += nameLen
   413				pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
   414					RGID:      rgID,
   415					Weight:    weight,
   416					Up:        up,
   417					Interface: name,
   418				})
   419			}
   420		}
   421		versionSectionComplete := false
   422		if monitorSectionComplete && off < len(data) {
   423			versionLen := int(data[off])
   424			off++
   425			if off+versionLen <= len(data) {
   426				pkt.SoftwareVersion = string(data[off : off+versionLen])
   427				off += versionLen
   428				versionSectionComplete = true
   429			} else {
   430				return pkt, nil
   431			}
   432		}
nl: pkg/cluster/sync_truncated_fullset_7175_test.go: No such file or directory
   425				// key. Drop it; the sender re-pushes on the next reconcile tick.
   426				//
   427				// NOT BOUND BY A TEST, and deliberately recorded as such: removing
   428				// this branch changes nothing observable, because
   429				// openConfigPayload fails closed on a nil key (aes.NewCipher(nil)
   430				// errors) and the decrypt-failure branch below drops the payload
   431				// anyway. It is kept for the DIAGNOSTIC — "we never negotiated"
   432				// and "it did not decrypt" send an operator to entirely different
   433				// places — and as defence in depth if openConfigPayload ever grows
   434				// a path that tolerates a short key. The safety property (an
   435				// unopenable payload never reaches the apply path) is bound by
   436				// TestConfigCryptoDropsUndecryptablePayload6629.
   437				s.stats.Errors.Add(1)
   438				slog.Error("cluster sync: encrypted config received but no key was negotiated on "+
   439					"this connection — dropping (#6629)", "remote", connRemoteAddrString(conn))
   440				return
   441			}
   442			plaintext, err := openConfigPayload(key, payload)
   443			if err != nil {
   444				s.stats.Errors.Add(1)
   445				slog.Error("cluster sync: could not decrypt config payload — dropping (#6629)",
   446					"err", err, "remote", connRemoteAddrString(conn))
   447				return
   448			}
   449			s.handleConfigPayload(conn, plaintext)
   450		case syncMsgConfigKeyExchange:
   451			s.handleConfigKeyExchange(conn, payload)
   452		case syncMsgAuthUpgradeRequest:
   453			// #6628: the responder-role peer committed a key and is asking THIS
   454			// node (the initiator by node id) to start the exchange.
   455			s.handleAuthUpgradeRequest(conn, payload)
   456		case syncMsgAuthUpgradeHello:
   457			// #6628: the peer committed a key and is offering to authenticate this
   458			// established connection in place. Never drops it.
   459			s.handleAuthUpgradeHello(conn, payload)
   460		case syncMsgAuthUpgradeProof:
   461			s.handleAuthUpgradeProof(conn, payload)
   462		case syncMsgAuthUpgradeConfirm:
   463			s.handleAuthUpgradeConfirm(conn, payload)
   464		case syncMsgIPsecSA:
   465			s.stats.IPsecSAReceived.Add(1)
   466			// #5706: split off the (incarnation, seq) ordering trailer and admit
   467			// only a strictly-newer full-set. A stale set reordered across the
   468			// redundant fabric streams is dropped so it cannot regress the held SA
   469			// set. A legacy peer sends no trailer -> (0,0) -> accept-always.
   470			base, incarnation, seq := stripFullSetSeq(payload)
   471			s.recvSeqMu.Lock()
   472			admit := s.ipsecRecvSeq.admit(incarnation, seq)
   473			s.recvSeqMu.Unlock()
   474			if !admit {
   475				s.stats.IPsecSAStaleIgnored.Add(1)
   476				slog.Warn("cluster sync: dropping out-of-order IPsec SA set (stale sequence) — standby retains newer set",
   477					"incarnation", incarnation, "seq", seq)
   478				return
   479			}
   480			// #5706 review fold: strip the '\n' delimiter a new sender inserts
   481			// between the SA name list and the trailer so a new->new roundtrip
   482			// leaves no trailing empty name. A legacy / pre-fold frame has no
   483			// delimiter, so this is a no-op for it.
   484			names := decodeIPsecSAPayload(stripIPsecFullSetDelim(base))
   485			s.peerIPsecSAsMu.Lock()
    68	// Remaining is the SECONDS of valid lifetime left at the moment the SENDER read
    69	// the lease (Expire - now_sender). The receiver re-anchors it to fresh absolute
    70	// time at seed (now_local + Remaining) — see the clock invariant above.
    71	type SyncLease struct {
    72		Family int // 4 or 6
    73	
    74		Address  string // v4 dotted / v6 colon address (or PD prefix base for IA_PD)
    75		SubnetID int    // Kea subnet-id the lease belongs to
    76	
    77		// v4 identity. At least one of HWAddress / ClientID is set.
    78		HWAddress string // "aa:bb:cc:dd:ee:ff"
    79		ClientID  string // RFC 2131 client identifier, Kea hex form ("01:..")
    80	
    81		// v6 identity (DUID/IAID) + lease kind. Type is "IA_NA", "IA_TA", or "IA_PD".
    82		DUID      string
    83		IAID      uint32
    84		LeaseType string // v6: "IA_NA"/"IA_TA" (address) or "IA_PD" (prefix delegation)
    85		PrefixLen int    // v6 IA_PD: delegated prefix length (0 for IA_NA / IA_TA)
    86	
    87		Hostname  string
    88		FQDNFwd   bool // client requested forward DNS update
    89		FQDNRev   bool // client requested reverse DNS update
    90		ValidLife int  // the lease's configured valid-lifetime (seconds)
    91		Remaining int  // seconds of lifetime left at read time (clock-skew-safe)
    92	
    93		// PreferredRemaining is the SECONDS of PREFERRED lifetime left at the moment
    94		// the SENDER read the lease. For DHCPv6 the preferred lifetime is a SEPARATE
    95		// deadline from the valid lifetime: a DEPRECATED binding has preferred=0 with
    96		// a still-positive valid lifetime (the client must stop using the address for
    97		// new connections but the lease is not yet expired). It is re-anchored to the
    98		// receiver's local clock at seed exactly like Remaining (the #2239 clock
    99		// invariant) and the invariant 0 <= PreferredRemaining <= Remaining always
   100		// holds (#5073). A value of 0 means DEPRECATED. For DHCPv4 (no preferred
   101		// concept) and for leases synced from an OLDER peer that predates this field,
   102		// PreferredRemaining defaults to Remaining (preferred==valid), preserving the
   103		// pre-#5073 behavior.
   104		PreferredRemaining int
   105	
   106		State int // Kea lease state (0=default/active)
   107	}
   108	
   109	// clampPreferredRemaining enforces the #5073 invariant 0 <= pref <= remaining.
   110	// The preferred lifetime can never outlive the valid lifetime (RFC 8415 §6.3),
   111	// and a negative computed remainder (a deprecated lease whose preferred deadline
   112	// has already passed) floors to 0 (deprecated), never revives.
   113	func clampPreferredRemaining(pref, remaining int) int {
   114		if pref < 0 {
   115			return 0
   116		}
   117		if pref > remaining {
   118			return remaining

exec
/bin/bash -lc "nl -ba pkg/configstore/store_commit.go | sed -n '162,275p'; nl -ba pkg/config/bounded_read.go; rg -n 'func .*Load|ReadConfig|ReadFile|configStore.Load|store.Load|s.Load' pkg/configstore/store_persist.go pkg/daemon/daemon.go pkg/configstore/store.go cmd --glob '*.go'" in /var/tmp/RES8865
 succeeded in 0ms:
   162	// commitWithDescriptionLocked is the shared body of CommitWithDescription and
   163	// the generation-bound CommitWithDescriptionGen. Caller holds s.mu.Lock.
   164	func (s *Store) commitWithDescriptionLocked(description string) (*config.Config, error) {
   165		// #3893: reject a user-session commit on a read-only secondary. The
   166		// internal HA-sync ingress (SyncApply) and the commit-confirmed timeout
   167		// revert (PromoteRollback) promote the active config directly and never
   168		// reach here, so they are unaffected by this gate.
   169		if err := s.ensureWritableLocked(); err != nil {
   170			return nil, err
   171		}
   172		if s.candidate == nil {
   173			return nil, fmt.Errorf("not in configuration mode")
   174		}
   175	
   176		// #4891: reject an over-cap commit description BEFORE anything is
   177		// persisted or promoted. Fail-fast with a clear error (the #1960
   178		// strict-at-commit doctrine) so an oversized comment never bloats the
   179		// journal nor hides itself behind the tail scanner's corrupt-line defense.
   180		if len(description) > maxCommitDescriptionBytes {
   181			return nil, fmt.Errorf("commit description too long: %d bytes (max %d)",
   182				len(description), maxCommitDescriptionBytes)
   183		}
   184	
   185		compiled, err := s.compileTree(s.candidate)
   186		if err != nil {
   187			return nil, fmt.Errorf("commit check failed: %w", err)
   188		}
   189	
   190		// #1799 Option A: persist BEFORE promote. On a PRE-rename failure the
   191		// old active stays on disk and in memory; the operator sees the error
   192		// and the candidate is still there to retry.
   193		//
   194		// #5185: a POST-rename directory-fsync failure is categorically
   195		// different — the candidate (C) is already VISIBLE on disk (a restart
   196		// would load C), only its durability across power loss is unknown.
   197		// Returning a plain "commit failed" there would leave
   198		// durable(C) != in-memory/applied(A): the operator is told REJECTED
   199		// while a restart activates C — the reported-rejected-but-durable
   200		// divergence. So on a post-rename failure CONVERGE instead of rejecting:
   201		// promote C in memory and return the compiled config so the daemon
   202		// APPLIES it, restoring durable==memory==applied, and flag the
   203		// durability uncertainty through the Option-B degraded machinery
   204		// (health 503, gauge, journal ERROR, background re-fsync retry via
   205		// noteActivePersistFailureLocked). Converge-to-C is chosen over
   206		// durably-restoring-A because restoring A needs ANOTHER rename that can
   207		// itself fail post-rename — fsatomic cannot guarantee an atomic restore
   208		// — whereas C is already the durable content, so converging to it needs
   209		// no further write to hold the invariant.
   210		if err := s.writeActive(s.candidate); err != nil {
   211			if !isPostRenameDurabilityFailure(err) {
   212				return nil, fmt.Errorf("commit failed: persist active config: %w", err)
   213			}
   214			// Post-rename: converge memory+applied to C (fall through to the
   215			// promotion below), but keep the degraded signal. everCommitted /
   216			// persistMarkerCommitted are set BEFORE noteActivePersistFailureLocked
   217			// so the background retry re-writes committed=1 for C.
   218			s.everCommitted = true
   219			s.persistMarkerCommitted = true
   220			s.noteActivePersistFailureLocked("commit_postrename", err)
   221			// #5473: this commit's config C is VISIBLE on disk (post-rename: the
   222			// rename landed, only the dir-fsync is uncertain) and supersedes any
   223			// commit-confirmed window whose earlier resolution write failed. Finalize
   224			// the deferred (retained) confirm.json removal now — symmetric with the
   225			// success branch. Without this the stale flag persists into the degraded
   226			// retry, whose heal would then delete a LATER-armed window's fresh record
   227			// (or, for a plain commit, a stale PrevTree=A record lingers and a crash
   228			// reverts this just-committed C back to A). No-op unless a removal was
   229			// deferred.
   230			s.clearConfirmResolutionPendingLocked()
   231		} else {
   232			s.persistDegraded = false       // disk now holds the current config
   233			s.everCommitted = true          // #1922 step-0: a real commit has succeeded
   234			s.persistMarkerCommitted = true // #1922: degraded-retry writes committed=1
   235			// #5473: this commit's config is now durable and supersedes any
   236			// commit-confirmed window whose earlier resolution write failed. Drop
   237			// the deferred (retained) confirm.json so a reboot does not re-drive a
   238			// stale rollback that this commit has replaced. No-op unless a removal
   239			// was deferred.
   240			s.clearConfirmResolutionPendingLocked()
   241		}
   242	
   243		// Push current active to history with description
   244		s.history.Push(&HistoryEntry{
   245			Config:    s.active.Clone(),
   246			Timestamp: time.Now(),
   247			Comment:   description,
   248		})
   249	
   250		// Promote candidate to active
   251		s.active = s.candidate
   252		s.candidate = s.active.Clone()
   253		s.bumpCandidateGenLocked() // #5848: fresh candidate — advance the generation
   254		s.compiled = compiled
   255		s.dirty = false
   256		s.touchConfigLockLocked() // #4476: a commit is activity — refresh the lease
   257	
   258		// #3861: a PLAIN commit during a pending commit-confirmed window is
   259		// the confirmation (Junos semantics: any subsequent explicit commit
   260		// confirms a pending `commit confirmed`). The frontend `commit` path
   261		// intercepts a pending confirm and calls ConfirmCommit before it ever
   262		// reaches here, but NON-frontend callers (the eventengine remediation
   263		// commit, cli/gRPC/REST commit handlers) reach CommitWithDescription
   264		// directly. Without clearing the armed timer, its rollback target (the
   265		// pre-confirm T0 tree) stays live and reverts THIS just-promoted
   266		// config when it fires — silently discarding the background commit.
   267		// clearPendingConfirmLocked cancels the timer AND bumps confirmGen so a
   268		// callback that already fired and is blocked on s.mu no-ops instead of
   269		// reverting. Runs only AFTER the persist+promote succeeded, so a failed
   270		// commit leaves the pending confirm fully intact.
   271		// #5835: a plain commit is non-interactive here (the frontend confirm path
   272		// already returned an error to the operator when applicable); a durable
   273		// confirm.json-removal failure is retained as retry debt + degraded health
   274		// inside clearPendingConfirmLocked and converges autonomously.
   275		if cleared, _ := s.clearPendingConfirmLocked(); cleared {
nl: pkg/config/bounded_read.go: No such file or directory
pkg/configstore/store.go:776:	// #1798 migration: same tolerance as Load — a peer-synced config
pkg/daemon/daemon.go:1577:	if data, err := os.ReadFile(nodeIDFile); err == nil {
pkg/configstore/store_persist.go:23:func (s *Store) Load() error {
pkg/configstore/store_persist.go:1321:func (s *Store) LoadRescueConfig() (string, error) {
pkg/configstore/store_persist.go:1325:	// finding, which listed two sites; a census of os.ReadFile in this package
pkg/configstore/store_persist.go:1357:func (s *Store) LoadRescueConfigRedacted() (string, error) {
pkg/configstore/store_persist.go:1358:	text, err := s.LoadRescueConfig()
cmd/xpfd/main.go:131:// The pre-#4909 check-config path did os.Stat (size gate) then os.ReadFile
cmd/xpfd/main.go:134:// unbounded body to ReadFile, ballooning memory before the post-read cap fires.
cmd/xpfd/main.go:146:// os.ReadFile materialized the WHOLE file before any cap, so a FUSE/racing file
cmd/xpfd/check_config_bounded_4909_test.go:26:// drain the whole source (the TOCTOU where os.ReadFile ballooned memory before
cmd/xpfd/check_config_bounded_4909_test.go:58:// decision AND the allocation. The pre-fix path did os.Stat then os.ReadFile
cmd/xpfd/check_config_bounded_4909_test.go:66:// os.Stat+os.ReadFile logic offered no reusable bounded reader); the contract
cmd/cli/main.go:550:	return cliterm.ReadConfig(readLine)
cmd/cli/main.go:553:func (c *ctl) handleLoad(args []string) error {
cmd/cli/load_bounded_read_7469_test.go:23:func TestCtlHandleLoadBoundsTheReadItself_7469(t *testing.T) {
cmd/cli/load_bounded_read_7469_test.go:49:func TestCtlHandleLoadDoesNotBlockOnAFIFO_7469(t *testing.T) {
cmd/cli/gofmt_clean_tree_test.go:57:			src, err := os.ReadFile(path)
cmd/cli/cos_apply_markers_6440_test.go:59:func (m *markerClient) Load(_ context.Context, _ *pb.LoadRequest, _ ...grpc.CallOption) (*pb.LoadResponse, error) {
cmd/cli/cos_apply_markers_6440_test.go:127:func TestLoadMergePrintsMarkerOnSuccess_6440(t *testing.T) {
cmd/cli/cos_apply_markers_6440_test.go:150:func TestLoadMergeWithholdsMarkerOnFailure_6440(t *testing.T) {
cmd/cli/cos_apply_markers_6440_test.go:234:	data, err := os.ReadFile("../../test/incus/cos-apply-lib.sh")
cmd/cli/cos_apply_markers_6440_test.go:309:		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))

exec
/bin/bash -lc "rg --files -g '"'!docs/pr/**'"' -g '"'!userspace-dp/target/**'"' -g '"'!cache/**'"' -g '"'!**/*.json*'"' | head -75; rg -l 'muse-spark-review-008|muse-spark-review-009|#8830' --glob '*.md' --glob '"'!**/8865-muse-spark-008-009/*'"' --glob '"'!_Log.md'"' .; git remote -v; git log --all --oneline --grep='8830\\|muse-spark-review-008\\|muse-spark-review-009\\|8859'" in /var/tmp/RES8865
 succeeded in 538ms:
exec
/bin/bash -lc "rg -n -m 12 --max-columns 450 'muse-spark-review-008|muse-spark-review-009|#8830|#8865' _Log.md; rg --hidden --files -g '"'!**/.git/**'"' -g '"'!**/cache/**'"' -g '"'!**/node_modules/**'"' -g '"'!**/target/**'"' /var/tmp /home/ps/.codex 2>/dev/null | rg 'muse|8830|8865|review-008|review-009' | head -75; rg --files pkg/configstore pkg/cluster | rg 'bounded|7175'" in /var/tmp/RES8865
 succeeded in 0ms:
/var/tmp/RES8865/AGENTS.md
/var/tmp/RES8865/Makefile
/var/tmp/RES8865/.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh
/var/tmp/RES8865/.codex/skills/iperf-grpc-tcpdump/SKILL.md
/var/tmp/RES8865/.codex/skills/userspace-ha-validation/SKILL.md
/var/tmp/RES8865/.codex/skills/userspace-native-gre-iperf/SKILL.md
/var/tmp/RES8865/userspace-xdp/.gitignore
/var/tmp/RES8865/userspace-xdp/src/wg_classify.rs
/var/tmp/RES8865/userspace-xdp/src/lib.rs
/var/tmp/RES8865/userspace-xdp/src/ipv6_ext_walk.rs
/var/tmp/RES8865/userspace-xdp/src/binding_index.rs
/var/tmp/RES8865/userspace-xdp/Cargo.toml
/var/tmp/RES8865/userspace-xdp/rust-toolchain.toml
/var/tmp/RES8865/userspace-xdp/Cargo.lock
/var/tmp/RES8865/userspace-xdp/.cargo/config.toml
/var/tmp/RES8865/pkg/authz/passwd.go
/var/tmp/RES8865/pkg/authz/peer.go
/var/tmp/RES8865/pkg/authz/peer_loopback_noenumerate_6974_test.go
/var/tmp/RES8865/pkg/authz/peer_5561_test.go
/var/tmp/RES8865/pkg/authz/authz_5561_test.go
/var/tmp/RES8865/pkg/authz/socketscan.go
/var/tmp/RES8865/pkg/authz/authz.go
/var/tmp/RES8865/pkg/ra/sender_marshal_rdnss_6695_test.go
/var/tmp/RES8865/pkg/ra/sender_marshal_4307_test.go
/var/tmp/RES8865/pkg/ra/sender_linklocal_test.go
/var/tmp/RES8865/pkg/ra/goodbye_retry_debt_6777_test.go
/var/tmp/RES8865/pkg/ra/withdraw_once_skip_epoch_8597_test.go
/var/tmp/RES8865/pkg/ra/README.md
/var/tmp/RES8865/pkg/ra/sender_delegated_prefixlen_6587_test.go
/var/tmp/RES8865/pkg/ra/sender_interval_4525_test.go
/var/tmp/RES8865/pkg/ra/timer_leak_4830_test.go
/var/tmp/RES8865/pkg/ra/sender_marshal_4119_test.go
/var/tmp/RES8865/pkg/ra/rs_receive_validation_5095_test.go
/var/tmp/RES8865/pkg/ra/filter.go
/var/tmp/RES8865/pkg/ra/reclaimer_sender_5094_test.go
/var/tmp/RES8865/pkg/ra/serialize_test.go
/var/tmp/RES8865/pkg/ra/dead_sender_probe_6793_test.go
/var/tmp/RES8865/pkg/ra/ra_test.go
/var/tmp/RES8865/pkg/ra/config_removal_goodbye_5092_test.go
/var/tmp/RES8865/pkg/ra/sender.go
/var/tmp/RES8865/pkg/ra/sender_prefixlen_6531_test.go
/var/tmp/RES8865/pkg/ra/ra.go
/var/tmp/RES8865/pkg/ra/goodbye_failure_5093_test.go
/var/tmp/RES8865/pkg/ra/ra_header_timer_bounds_8597_test.go
/var/tmp/RES8865/pkg/ra/ra_mac_refresh_5302_test.go
/var/tmp/RES8865/pkg/ra/sender_marshal_3895_test.go
/var/tmp/RES8865/pkg/ra/per_iface_epoch_4961_test.go
/var/tmp/RES8865/pkg/sysservices/listeners.go
/var/tmp/RES8865/pkg/sysservices/listeners_test.go
/var/tmp/RES8865/pkg/bootstrapshow/bootstrapshow.go
/var/tmp/RES8865/pkg/bootstrapshow/bootstrapshow_6496_test.go
/var/tmp/RES8865/pkg/webmgmt/ports.go
/var/tmp/RES8865/pkg/dataplane/compiler_screenids_solewriter_4960_test.go
/var/tmp/RES8865/pkg/dataplane/dataplane.go
/var/tmp/RES8865/pkg/dataplane/compiler_nat.go
/var/tmp/RES8865/pkg/dataplane/compiler_iface_st_prefix_6729_6730_test.go
/var/tmp/RES8865/pkg/dataplane/zone_counter_retention_6843_test.go
/var/tmp/RES8865/pkg/dataplane/userspace_xdp_facts.go
/var/tmp/RES8865/pkg/dataplane/screen_reason_counters_3343_test.go
/var/tmp/RES8865/pkg/dataplane/policy_display_4626_test.go
/var/tmp/RES8865/pkg/dataplane/optional_probe_unwraps_6743_test.go
/var/tmp/RES8865/pkg/dataplane/compiler_prepass_logging_4960_test.go
/var/tmp/RES8865/pkg/dataplane/session_value_offsets_6816_test.go
/var/tmp/RES8865/pkg/dataplane/loader_userspace_shim.go
/var/tmp/RES8865/pkg/dataplane/build-userspace-xdp.sh
/var/tmp/RES8865/pkg/dataplane/verify_userspace_shim_headroom_test.go
/var/tmp/RES8865/pkg/dataplane/nat_write_surface_retired_7268_test.go
/var/tmp/RES8865/pkg/dataplane/maps_mirror.go
/var/tmp/RES8865/pkg/dataplane/compiler_nat_dead_writes_6420_test.go
/var/tmp/RES8865/pkg/dataplane/compiler_iface_bare_st_address_6955_test.go
/var/tmp/RES8865/pkg/dataplane/legacy_bpf_manifest_canary_test.go
/var/tmp/RES8865/pkg/dataplane/maps_nat.go
/var/tmp/RES8865/pkg/dataplane/validation_pass_declaration_census_7754_test.go
/var/tmp/RES8865/pkg/dataplane/loader.go
/var/tmp/RES8865/pkg/dataplane/testdata/userspace_xdp_bpfel_1864_reject.o
pkg/configstore/bounded_read.go
pkg/cluster/sync_truncated_record_7175_test.go
pkg/configstore/bounded_authoritative_reads_8597_test.go
pkg/configstore/bounded_read_6753_test.go

exec
/bin/bash -lc "nl -ba pkg/configstore/bounded_read.go; nl -ba pkg/configstore/store_persist.go | sed -n '1,145p'; rg -n 'func .*writeActive|func .*compileTree|func .*persist|readBounded|readConfig|MaxConfig|[Cc]onfig[Ss]ize' pkg/configstore --glob '*.go' --glob '"'!**/*test.go'"'; rg -n '\\.store.Load\\(|\\.Load\\(\\).*err|load config' pkg/daemon/daemon*.go cmd/xpfd/main.go | head -65" in /var/tmp/RES8865
 succeeded in 0ms:
     1	package configstore
     2	
     3	import (
     4		"errors"
     5		"fmt"
     6		"io"
     7		"os"
     8		"syscall"
     9	)
    10	
    11	// ErrExceedsLimit is returned (wrapped) when a bounded read refuses a source
    12	// for being over its ceiling. It exists so callers can identify THIS refusal
    13	// structurally with errors.Is rather than by matching an error string.
    14	//
    15	// #7469: the #6753 tests originally distinguished the bounded read's refusal
    16	// from the store's post-materialisation "config too large" rejection by
    17	// checking for the substring "limit". Both messages are maintained
    18	// independently, so rewording either one silently changed the verdict — and
    19	// rewording the STORE's to contain "limit" would have made the test pass
    20	// against the very code #6753 fixed, with no change to any #6753 file.
    21	var ErrExceedsLimit = errors.New("exceeds size limit")
    22	
    23	// ReadBounded reads at most max+1 bytes from r and rejects a source that
    24	// exceeds max, allocating no more than max+1 bytes REGARDLESS of how much data
    25	// r would supply. This is the load-bearing half of the #4909 fix: a plain
    26	// io.ReadAll materializes the WHOLE source before any cap, so a FUSE/racing
    27	// file that under-reported its Stat size could still stream an unbounded body
    28	// and balloon memory. io.LimitReader(max+1) caps the read; reaching the
    29	// (max+1)-th byte proves the source is over-cap.
    30	func ReadBounded(r io.Reader, max int64) ([]byte, error) {
    31		data, err := io.ReadAll(io.LimitReader(r, max+1))
    32		if err != nil {
    33			return nil, err
    34		}
    35		if int64(len(data)) > max {
    36			return nil, fmt.Errorf("%w: %d byte ceiling", ErrExceedsLimit, max)
    37		}
    38		return data, nil
    39	}
    40	
    41	// ReadBoundedFile reads path, refusing anything larger than max bytes while
    42	// allocating at most max+1 bytes REGARDLESS of the file's reported size.
    43	//
    44	// The pre-#4909 pattern was os.Stat (size gate) then os.ReadFile (whole-file
    45	// alloc) then a post-read len(data) cap — a TOCTOU: an adversarial or
    46	// FUSE-backed file can under-report its size to Stat and then stream an
    47	// unbounded body to ReadFile, ballooning memory before the post-read cap
    48	// fires. Reading through an io.LimitReader(max+1) on a single opened
    49	// descriptor closes the window: the allocation is bounded by the limit, not by
    50	// what Stat claimed, and reaching the (max+1)-th byte proves the file is
    51	// over-cap. A non-regular file (dir/device/FIFO) is refused up front.
    52	//
    53	// The IsRegular check MUST precede the read, and the ordering is load-bearing
    54	// rather than stylistic (#7469). On a pipe, O_NONBLOCK silently turns a
    55	// would-be 24-byte read into a 0-byte read with err == nil — a truncation that
    56	// reports success. Refusing every non-regular path before any read is the only
    57	// thing that keeps this function from returning a silently short payload, and
    58	// it is exported, so a caller reordering these two steps would reintroduce
    59	// that. O_NONBLOCK being a no-op for regular files is the half that is NOT the
    60	// risk.
    61	//
    62	// #6753: the open uses O_NONBLOCK. Opening a FIFO for reading BLOCKS until a
    63	// writer appears, so a plain os.Open hangs before Stat can classify the path
    64	// and reject it — the "or blocks" half of the defect, which a size cap alone
    65	// does not address. O_NONBLOCK is a no-op for regular files, so the fast path
    66	// is unchanged; it only ensures a non-regular path can be reached, classified
    67	// and refused instead of hanging the process.
    68	func ReadBoundedFile(path string, max int64) ([]byte, error) {
    69		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
    70		if err != nil {
    71			return nil, err
    72		}
    73		defer f.Close()
    74		fi, err := f.Stat()
    75		if err != nil {
    76			return nil, err
    77		}
    78		if !fi.Mode().IsRegular() {
    79			return nil, fmt.Errorf("%s: not a regular file", path)
    80		}
    81		data, err := ReadBounded(f, max)
    82		if err != nil {
    83			return nil, fmt.Errorf("%s: %w", path, err)
    84		}
    85		return data, nil
    86	}
    87	
    88	// ReadBoundedConfigFile reads a configuration file under the same MaxConfigSize
    89	// ceiling the store enforces on any payload it accepts.
    90	//
    91	// It exists because that ceiling was previously enforced only AFTER the whole
    92	// file was resident: checkConfigSize takes an already-materialised string, so
    93	// it bounds what the store will ACCEPT, never what a caller will ALLOCATE. The
    94	// CLI load paths read with os.ReadFile and then handed the result over, so a
    95	// multi-gigabyte file was fully read and only then rejected (#6753).
    96	//
    97	// Both CLI surfaces call this rather than each bounding its own read: #4883-D
    98	// fixed a directly analogous divergence between the local and remote CLI by
    99	// moving the shared logic to one place, and the comment at that site records
   100	// that the divergence itself is what produced the bug.
   101	func ReadBoundedConfigFile(path string) ([]byte, error) {
   102		return ReadBoundedFile(path, MaxConfigSize)
   103	}
     1	package configstore
     2	
     3	import (
     4		"crypto/sha256"
     5		"encoding/hex"
     6		"encoding/json"
     7		"errors"
     8		"fmt"
     9		"log/slog"
    10		"os"
    11		"path/filepath"
    12		"sort"
    13		"strconv"
    14		"strings"
    15		"time"
    16		"unicode/utf8"
    17	
    18		"github.com/psaab/xpf/pkg/config"
    19		"github.com/psaab/xpf/pkg/fsatomic"
    20	)
    21	
    22	// Load builds the configuration from disk.
    23	func (s *Store) Load() error {
    24		s.mu.Lock()
    25		defer s.mu.Unlock()
    26	
    27		tree, committed, err := s.db.ReadActiveMeta()
    28		if err != nil {
    29			// A read/parse/decrypt/envelope failure on a PRESENT active.json is
    30			// the fail-closed case (#1917 increment B, D1): an unparseable or
    31			// too-new DB must NOT be silently overwritten by a blind bootstrap.
    32			// Tag it with ErrConfigDBUnreadable so the daemon can make it fatal
    33			// (daemon_run.go), distinct from a compile error (handled leniently
    34			// below) or an absent DB (handled above as start-fresh).
    35			return fmt.Errorf("read config: %w: %w", ErrConfigDBUnreadable, err)
    36		}
    37		if tree == nil {
    38			// Absent DB: start fresh. everCommitted stays false (a never-booted
    39			// store has never committed); the daemon's bootstrapFromFile may
    40			// import a preseeded xpf.conf, which resolves NOT-bootstrap on its
    41			// own (case 2). The #1922 step-0 marker only governs the DB-present
    42			// disambiguation.
    43			return nil
    44		}
    45		// #1922 step-0 marker: record whether the on-disk DB represents a
    46		// successfully-committed config. A legacy/older-build DB (no envelope
    47		// field) reads committed=true (migration rule C3), so an upgrade never
    48		// misclassifies an existing active config into bootstrap.
    49		s.everCommitted = committed
    50		// Seed the degraded-retry marker from the on-disk state too (Copilot
    51		// finding): if Load reads a never-committed DB (committed=0) and a later
    52		// persist failure triggers the #1799 retry loop BEFORE any commit/sync
    53		// resets the marker, the retry must re-write committed=0 — not the
    54		// New() default of true, which would silently heal the never-committed
    55		// marker into an operator-committed-empty DB and re-enable takeover.
    56		s.persistMarkerCommitted = committed
    57	
    58		// Rolling-upgrade tolerance (#1373 / #1525): a node may boot
    59		// with `system dataplane-type ebpf` or `... dpdk` persisted
    60		// from before the retirement-strict validator landed. Without
    61		// this rewrite, compileTree below returns
    62		// ErrEBPFDataplaneRetired / ErrDPDKDataplaneRetired, the daemon
    63		// gets nil active config, and bootstraps blind. Rewriting the
    64		// leaf to absent (defaults to userspace) lets the daemon come
    65		// up so the operator can fix the config from CLI.
    66		rewriteRetiredDataplaneType(tree, LoadCaller)
    67	
    68		// #1798 migration: a persisted free-text value carrying control
    69		// characters (e.g. a "lan\nDHCP=ipv4" description committed before
    70		// the strict commit-time gate landed) must neither fail boot now
    71		// nor make the operator's next unrelated commit fail mysteriously.
    72		// Scrub the tree in place with a warning — this tree becomes the
    73		// active config (and the candidate clones from it), so the next
    74		// strict commit sees only clean values.
    75		for _, p := range config.SanitizeTreeControlChars(tree) {
    76			slog.Warn("sanitized control characters in persisted config value",
    77				"path", p, "issue", "#1798")
    78		}
    79	
    80		// Tolerant compile: an already-persisted config must boot through
    81		// (see compileTreeLenient for the validator downgrades).
    82		compiled, err := s.compileTreeLenient(tree)
    83		if err != nil {
    84			// #1960 fail-closed: the bytes read+parsed fine (this is NOT
    85			// ErrConfigDBUnreadable) but a PRESENT, previously-committed config
    86			// no longer compiles. s.everCommitted was already set true above, so
    87			// the daemon could otherwise see ActiveConfig()==nil + everCommitted
    88			// and resolve to NORMAL boot — positional claim-all interface naming.
    89			// Tag the error with ErrConfigCompile so the daemon can detect this
    90			// edge with errors.Is and refuse takeover (enter the #1922
    91			// bootstrap/lifeline safe state) instead.
    92			//
    93			// s.compiled MUST stay nil — ActiveConfig() returns s.compiled, and
    94			// nil is precisely the signal that forces bootstrap (computeBootClass).
    95			// BUT retain the parsed-but-broken tree as s.active and load rollback
    96			// history, so the recovery the daemon advertises ("fix the config from
    97			// the CLI/gRPC and commit, or roll back") actually works (Codex #1991
    98			// r1): EnterConfigure clones s.active into the candidate, so `configure`
    99			// + `show | compare` surface the broken stanza for the operator to fix,
   100			// and Rollback(n) / `show | compare rollback n` reach the on-disk
   101			// history. Without this, s.active stayed the empty New() tree and the
   102			// history was never loaded — the operator saw an empty config and no
   103			// rollbacks, with no in-band way to recover. s.active is always non-nil
   104			// (New seeds an empty tree), so the (active non-nil, compiled nil) shape
   105			// here is the same one a fresh boot already has — no new invariant.
   106			s.active = tree
   107			s.loadRollbackHistory()
   108			return fmt.Errorf("compile config: %w: %w", ErrConfigCompile, err)
   109		}
   110	
   111		s.active = tree
   112		s.compiled = compiled
   113		s.loadRollbackHistory()
   114		// #6538: the recovery can leave the store with a nil compiled config (its
   115		// rollback target failed even the lenient compile). Load MUST NOT report
   116		// success in that state — see recoverPendingConfirmLocked.
   117		return s.recoverPendingConfirmLocked()
   118	}
   119	
   120	// recoverPendingConfirmLocked restores a commit-confirmed window that was
   121	// still pending when the daemon last stopped (#4577). The in-memory
   122	// time.AfterFunc rollback timer does not survive a process restart, so without
   123	// this an UNCONFIRMED config that the operator armed with `commit confirmed`
   124	// (relying on it to auto-revert) becomes PERMANENT after a crash/reboot inside
   125	// the window — the safety hatch is silently lost and a management-stranding
   126	// config can lock the operator out. Junos persists the pending confirm across
   127	// a reboot and rolls back if it is not confirmed; this gives xpf the same
   128	// property.
   129	//
   130	// Runs at the tail of a SUCCESSFUL Load (active.json read+compiled), under
   131	// s.mu. Two outcomes:
   132	//   - deadline already passed during downtime -> roll back to the persisted
   133	//     prev tree NOW (the operator never confirmed) exactly as the in-memory
   134	//     PromoteRollback would have, including the #1922 Item 1b first-commit
   135	//     never-committed marker, then clear the state.
   136	//   - deadline still in the future -> re-arm the timer for the REMAINING
   137	//     duration so the original auto-rollback still fires; a clean restart
   138	//     inside the window therefore also keeps the hatch.
   139	//
   140	// #6538: it returns an error so Load can FAIL CLOSED when the recovery leaves
   141	// no compiled config. The rollback target here is a previously-committed
   142	// config, and Load repairs the tree it reads from active.json
   143	// (rewriteRetiredDataplaneType, SanitizeTreeControlChars) but never the
   144	// PrevTree carried inside confirm.json — so a target committed on an older
   145	// build can fail even the LENIENT compile. Warning and continuing assigned the
pkg/configstore/store_commit.go:1437:		data, err := ReadBoundedFile(path, MaxConfigSize)
pkg/configstore/store_commit.go:1461:		// via checkConfigSize). loadRollbackHistory reads straight off disk
pkg/configstore/store_commit.go:1467:		if len(data) > MaxConfigSize {
pkg/configstore/store_commit.go:1469:				"path", path, "bytes", len(data), "max", MaxConfigSize)
pkg/configstore/bounded_read.go:88:// ReadBoundedConfigFile reads a configuration file under the same MaxConfigSize
pkg/configstore/bounded_read.go:92:// file was resident: checkConfigSize takes an already-materialised string, so
pkg/configstore/bounded_read.go:102:	return ReadBoundedFile(path, MaxConfigSize)
pkg/configstore/store.go:40:// MaxConfigSize bounds a single configuration payload accepted by any parse
pkg/configstore/store.go:50:const MaxConfigSize = 16 << 20 // 16 MiB
pkg/configstore/store.go:52:// checkConfigSize rejects an over-large payload before it reaches the parser.
pkg/configstore/store.go:53:func checkConfigSize(content string) error {
pkg/configstore/store.go:54:	if len(content) > MaxConfigSize {
pkg/configstore/store.go:56:			len(content), MaxConfigSize)
pkg/configstore/store.go:467:func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
pkg/configstore/store.go:477:func compileTreeStrict(tree *config.ConfigTree, nodeID int) (*config.Config, error) {
pkg/configstore/store.go:647:func (s *Store) compileTreeLenient(tree *config.ConfigTree) (*config.Config, error) {
pkg/configstore/store.go:752:	if err := checkConfigSize(content); err != nil {
pkg/configstore/check.go:32:	if err := checkConfigSize(content); err != nil {
pkg/configstore/db.go:269:	data, err := ReadBoundedFile(db.confirmPath(), MaxConfigSize)
pkg/configstore/db.go:354:	data, err := ReadBoundedFile(path, MaxConfigSize)
pkg/configstore/store_command.go:323:	if err := checkConfigSize(content); err != nil {
pkg/configstore/store_command.go:432:	if err := checkConfigSize(content); err != nil {
pkg/configstore/store_command.go:605:	if err := checkConfigSize(content); err != nil {
pkg/configstore/store_persist.go:371:func (s *Store) writeActive(tree *config.ConfigTree) error {
pkg/configstore/store_persist.go:386:func (s *Store) writeActiveMarker(tree *config.ConfigTree, committed bool) error {
pkg/configstore/store_persist.go:564:func (s *Store) persistRetryLoop(backoff, maxBackoff time.Duration) {
pkg/configstore/store_persist.go:1327:	data, err := ReadBoundedFile(path, MaxConfigSize)
pkg/daemon/daemon_run_bringup.go:299:	switch loadErr := d.store.Load(); classifyLoadError(loadErr) {
pkg/daemon/daemon_run_bringup.go:325:		slog.Warn("failed to load config from db", "err", loadErr)

exec
/bin/bash -lc "nl -ba pkg/config/schema.go | sed -n '40,108p'; nl -ba pkg/config/compact_normalize_8662.go | sed -n '1450,1590p'; nl -ba pkg/config/packed_optin_guard_8768_test.go | sed -n '1,48p;245,335p'; rg -n '8830|32|perfect-forward|prereq|advisory|unreachable|keys|defect' pkg/config/schema_spelling_gate_coverage_7484_test.go | head -80; git show --stat a7f84a209" in /var/tmp/RES8865
 succeeded in 0ms:
    40		// bracket-list value absorption (#3872 static `next-hop [ a b ]`). By
    41		// default the SetPath absorber only collapses a trailing value list onto a
    42		// multi leaf when children == nil (ast_edit.go); a multi leaf WITH children
    43		// (e.g. the CoS named containers) stays a container. valueList lets such a
    44		// node absorb trailing tokens that are neither a sibling NOR a known child
    45		// (the bracket list) while STILL descending into the container when the
    46		// next token names a known child (the `interface` modifier). Only next-hop
    47		// sets it; every other multi+children node is unchanged.
    48		valueList bool
    49	
    50		// packedTail opts a CONTAINER into having its packed tail VALIDATED
    51		// (#6821).
    52		//
    53		// The gate's default for a container is to IGNORE tokens packed past the
    54		// identity, and that default is not laziness — it is a compiler-faithful
    55		// contract (see the long note in schema_walk.go). The gate must not
    56		// validate what no compiler reads, or a stray token becomes a commit
    57		// error for a configuration that behaves identically with or without it.
    58		//
    59		// The contract is BIDIRECTIONAL, and that is the half #6821 turns on: the
    60		// moment a compiler DOES read a container's packed tail, ignoring it here
    61		// turns "not compiled" into "compiled, UNVALIDATED". Measured on
    62		// `security log stream <s> transport` before this flag existed:
    63		//
    64		//	transport { protocol tpc; }   gate REJECTS (enum)
    65		//	transport protocol tpc;       gate ACCEPTS  <- the hole
    66		//
    67		// So this flag is the explicit pairing. Setting it says "a compiler reads
    68		// this container's packed tail", and the walker then validates the same
    69		// expansion `packedBodyChildren` hands that compiler — one schema fact
    70		// instead of two files agreeing by comment.
    71		// TestPackedTailContainersValidateBothSpellings6821 holds the pairing.
    72		packedTail bool
    73	
    74		// packedStatements opts a CONTAINER into having its packed tail split into
    75		// one child per STATEMENT by the brace-elision fold (#8768), instead of the
    76		// whole run becoming a single child.
    77		//
    78		// It is OPT-IN and defaults off, for two measured reasons.
    79		//
    80		// Splitting changes what a packed run lowers to, and at least one container
    81		// has a gate that depends on the current lowering: the NAT `then` family
    82		// rejects a packed cross-mode contradiction with a check that exists
    83		// PRECISELY BECAUSE `pool <p> off` lowers to one action and cannot be
    84		// counted (#7033). Two earlier attempts to fix that class in the lowering
    85		// were reverted; splitting `source-nat` would be a third.
    86		//
    87		// And splitting is only possible where the schema models the tail. The fold
    88		// consumes each statement with consumeNodeKeys and stops the moment a token
    89		// leaves the modelled grammar, so a container whose leaves take values the
    90		// schema does not describe cannot be split even if it opts in — `ike policy
    91		// <p> pre-shared-key ascii-text <v> mode main` is one: `ascii-text` is not
    92		// modelled, so the tail is returned whole and `mode main` stays swallowed.
    93		//
    94		// So a container opts in after someone measures that its packed and braced
    95		// spellings compile identically once split, one container at a time. That
    96		// is the same discipline the #8690 scope list arrived at.
    97		packedStatements bool
    98	
    99		// blockValue opts a single-value typed leaf into the HIERARCHICAL BLOCK
   100		// spelling `keyword { value; }`, in addition to the ordinary
   101		// `keyword value` (#6774).
   102		//
   103		// This is an OPT-IN, not a general relaxation, because the two spellings
   104		// are not interchangeable in Junos. `default-policy` is a CHOICE
   105		// CONTAINER in the Junos schema — `permit-all` / `deny-all` /
   106		// `reject-all` are alternative sub-statements, which is why Junos itself
   107		// DISPLAYS it as `default-policy { deny-all; }` — while this schema
   108		// models it as a valued leaf so the flat-set spelling works. The compiler
  1450				if _, isBody := childSub.children[head]; isBody && inScope(ckw, head) {
  1451					tail := append([]string(nil), node.Keys[identity:]...)
  1452					body := node.Children
  1453					node.Keys = append([]string(nil), node.Keys[:identity]...)
  1454					node.Children = nil
  1455					node.IsLeaf = false
  1456					stmts := splitPackedStatements8768(tail, childSub)
  1457					for i, stmt := range stmts {
  1458						child := &Node{Keys: stmt, IsLeaf: true}
  1459						// The braced body belongs to the LAST packed statement --
  1460						// the deepest node the run names. Attaching it to the
  1461						// container, or to every statement, invents structure the
  1462						// operator did not write.
  1463						if i == len(stmts)-1 && len(body) > 0 {
  1464							child.Children = body
  1465							child.IsLeaf = false
  1466						}
  1467						node.Children = append(node.Children, child)
  1468					}
  1469					n++
  1470				}
  1471			}
  1472			n += normalizeCompactNodes(node.Children, childSub, inScope)
  1473		}
  1474		return n
  1475	}
  1476	
  1477	// splitPackedStatements8768 divides a packed tail into one node per STATEMENT,
  1478	// instead of moving the whole run into a single child.
  1479	//
  1480	// The fold emitted `tail` as one node, which is right only when the run holds
  1481	// one statement. A run may hold several, and then every statement after the
  1482	// first was swallowed into the first one's Keys and lost:
  1483	//
  1484	//	policy p1 pre-shared-key ascii-text SEKRIT mode main;
  1485	//	  before -> policy p1 { [pre-shared-key ascii-text SEKRIT mode main] }
  1486	//	  after  -> policy p1 { [pre-shared-key ascii-text SEKRIT] [mode main] }
  1487	//
  1488	// THE BOUNDARY IS ANSWERED BY consumeNodeKeys, NOT GUESSED. Asking "is this
  1489	// token a sibling keyword" is not sufficient and is actively wrong: a VALUE may
  1490	// coincide with a sibling keyword, and #4313 makes some tails open-world. The
  1491	// measured case is `then { source-nat pool P persistent-nat permit off; }`,
  1492	// where `off` is a source-nat child AND a value inside a sub-grammar the schema
  1493	// does not model. Splitting on the name invents a second translation action and
  1494	// rejects a config that commits today — there is a cell for it,
  1495	// TestOpenWorldTailContainingOffStillCommits_7033, and it is why the
  1496	// name-matching version of this function was abandoned.
  1497	//
  1498	// So this borrows packedBodyChildren's contract: consume each statement by the
  1499	// schema's own count, and THE MOMENT a token leaves the modelled grammar, stop
  1500	// and hand back the whole tail unsplit. Not guessing is the entire safety
  1501	// argument; a partial split is worse than none because it publishes a shape the
  1502	// operator did not write.
  1503	func splitPackedStatements8768(tail []string, container *schemaNode) [][]string {
  1504		if len(tail) == 0 || container == nil || !container.packedStatements {
  1505			return [][]string{tail}
  1506		}
  1507		var out [][]string
  1508		rest := tail
  1509		for len(rest) > 0 {
  1510			childSchema := resolveSchemaChild(container, rest[0])
  1511			if childSchema == nil {
  1512				// Outside the modelled grammar: do not guess where the next
  1513				// statement starts. Everything measured so far is discarded and the
  1514				// tail is returned whole, which is the pre-#8768 behaviour.
  1515				return [][]string{tail}
  1516			}
  1517			n, _ := consumeNodeKeys(rest, childSchema)
  1518			if n <= 0 || n > len(rest) {
  1519				return [][]string{tail}
  1520			}
  1521			out = append(out, append([]string(nil), rest[:n]...))
  1522			rest = rest[n:]
  1523		}
  1524		if len(out) <= 1 {
  1525			return [][]string{tail}
  1526		}
  1527		return out
  1528	}
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"sort"
     6		"strings"
     7		"testing"
     8	)
     9	
    10	// #8768: a container that opts into packedStatements must compile the PACKED
    11	// and BRACED spellings identically for EVERY ORDERED PAIR of its admitted
    12	// leaves — not for the one pair whoever opted it in happened to measure.
    13	//
    14	// THE JUSTIFICATION IS A PRIORI, NOT A COUNTER-EXAMPLE, and an earlier version
    15	// of this comment claimed otherwise. Opting a container in is a claim about
    16	// EVERY admitted leaf — that each survives the packed spelling — so every pair
    17	// has to be compared for the claim to be tested. That argument needs no
    18	// observed defect and does not weaken without one.
    19	//
    20	// THE MECHANISM THIS ORIGINALLY CITED WAS RETRACTED. It said `snmp community`
    21	// showed a leaf-level reader ignoring a correctly-split tail. It does not:
    22	// `snmp community` does not fold at all, because ("community","authorization")
    23	// is not in the scope list, so there is no split structure and no reader
    24	// ignoring one. Its lost `clients` is an ordinary drop at an unadmitted site
    25	// (#8778). NO per-leaf reader divergence has ever been demonstrated, and the
    26	// 18-of-18 EQUAL measured here is entirely consistent with none existing.
    27	//
    28	// The retraction is recorded rather than deleted because the cell's assertions
    29	// were never affected by it — only the story about why they matter. A guard
    30	// whose stated reason is a phantom still passes review, and the next person to
    31	// read it inherits the phantom.
    32	//
    33	// "Multi-ness is not the discriminator" is likewise NOT asserted here. It was
    34	// supported by `snmp community clients` diverging, and that divergence is not a
    35	// fold divergence, so the evidence is gone even though the claim may still be
    36	// true. `snmp trap-group targets` is multi and fine, which is one half and not
    37	// a discriminator.
    38	//
    39	// THE REGISTRY IS ASSERTED AGAINST THE SCHEMA IN BOTH DIRECTIONS. A container
    40	// that opts in without adding fixtures here reds, because otherwise this cell
    41	// would silently cover only the containers someone remembered — the same
    42	// accumulating-registry failure the #8690 buckets were built to avoid.
    43	type packedOptInCase8768 struct {
    44		prefix string            // text before the container statement
    45		open   string            // the container statement itself, e.g. `trap-group tg1`
    46		closer string            // text after
    47		stmts  map[string]string // admitted leaf -> a REAL statement for it
    48		read   func(*Config) string
   245		// KEYED BY SCHEMA PATH, not by container name. Names repeat: `proposal`
   246		// exists under both `ike` and `ipsec`, and `dead-peer-detection` under both
   247		// too. A name-keyed registry does not fail on that — it silently holds
   248		// whichever node the walk reached last and enumerates the WRONG container's
   249		// leaves while reading as coverage for the one someone opted in.
   250		//
   251		// The earlier version refused when two names collided, which was correct
   252		// and blocked three containers from opting in. A path is unique by
   253		// construction, so the refusal is replaced by an address that cannot be
   254		// ambiguous. Wildcard levels render as `*`, matching how the schema
   255		// addresses an instance rather than a keyword.
   256		optedIn := map[string]*schemaNode{}
   257		canonical := map[*schemaNode]string{}
   258		var walk func(n *schemaNode, path string, depth int)
   259		walk = func(n *schemaNode, path string, depth int) {
   260			if n == nil || depth > 12 {
   261				return
   262			}
   263			if n.packedStatements && path != "" {
   264				// THE SAME NODE IS REACHABLE BY TWO PATHS. Junos `groups` mirrors
   265				// the entire schema, so every container also has a
   266				// `groups/*/<path>` address pointing at the identical node. Keying
   267				// on the raw path would list each opted-in container twice and
   268				// demand two identical fixture sets.
   269				//
   270				// Dedupe by node IDENTITY and keep the shortest path as the
   271				// canonical address — which is the non-groups one, because the
   272				// mirror only ever adds a prefix.
   273				if prev, seen := canonical[n]; !seen || len(path) < len(prev) {
   274					canonical[n] = path
   275				}
   276			}
   277			for cn, ch := range n.children {
   278				next := cn
   279				if path != "" {
   280					next = path + "/" + cn
   281				}
   282				walk(ch, next, depth+1)
   283			}
   284			if n.wildcard != nil {
   285				walk(n.wildcard, path+"/*", depth+1)
   286			}
   287		}
   288		walk(setSchema, "", 0)
   289		for n, path := range canonical {
   290			optedIn[path] = n
   291		}
   292	
   293		if len(optedIn) == 0 {
   294			t.Fatal("no container declares packedStatements, so this cell asserts " +
   295				"nothing — either the flag was removed or the walk lost reach (#8768)")
   296		}
   297	
   298		cases := packedOptInCases8768()
   299	
   300		// BOTH DIRECTIONS. An opted-in container with no fixtures is unverified; a
   301		// fixture for a container that no longer opts in is stale.
   302		var unfixtured, stale []string
   303		for name := range optedIn {
   304			if _, ok := cases[name]; !ok {
   305				unfixtured = append(unfixtured, name)
   306			}
   307		}
   308		for name := range cases {
   309			if _, ok := optedIn[name]; !ok {
   310				stale = append(stale, name)
   311			}
   312		}
   313		sort.Strings(unfixtured)
   314		sort.Strings(stale)
   315		if len(unfixtured) > 0 {
   316			t.Errorf("%d container(s) declare packedStatements with NO fixtures here: %v.\n"+
   317				"Opting a container in is a claim that every admitted leaf survives the "+
   318				"packed spelling, and every one has to be COMPARED for that claim to "+
   319				"be tested. Add real statements for each admitted leaf (#8768).",
   320				len(unfixtured), unfixtured)
   321		}
   322		if len(stale) > 0 {
   323			t.Errorf("%d fixture set(s) name a container that no longer opts in: %v.\n"+
   324				"Remove them; a registry that only grows stops being a measurement.",
   325				len(stale), stale)
   326		}
   327	
   328		compile := func(txt string, read func(*Config) string) string {
   329			tr, perrs := NewParser(txt).Parse()
   330			if len(perrs) > 0 {
   331				return "<parse err>"
   332			}
   333			cfg, err := compileConfigWithOpts(tr, lenientCompileOpts())
   334			if err != nil || cfg == nil {
   335				return fmt.Sprintf("<err %v>", err)
30://	             two-value differential is meaningless for it. Not a defect,
32://	unreachable  the leaf changed nothing at all: the synthetic parent stanza
41:// so: of the 232 `args == 0` leaves, 15 are compared TODAY and are genuinely
54:// information, drop the verdict — do not claim a defect.
61:	gateBlindUnreachable gateBlindClass = "unreachable (leaf changed nothing)"
64:	// #8830: the leaf IS read and its value is DELIBERATELY ignored, with an
65:	// advisory saying so -- `system dataplane cores` compiles to "retired
69:	// `unreachable`, which asserts the leaf changed NOTHING.
70:	gateBlindAdvisory gateBlindClass = "advisory (read, value ignored, warning says so)"
112:// explanation that says it did not), then the flag/unreachable split.
114:	// #7492: apply the same parent prerequisite the differential uses, or the
116:	// a leaf the prerequisite rescued would still be reported as unreachable.
144:	// #8830: everything above compared through gateMarshal, which NULLS
146:	// advisory about a rejected value would make it look installed when
148:	// "did the leaf reach the compiler at all", and for THAT an advisory is
163:// advisory output. It is deliberately separate from gateMarshal rather than a
221:// #7132 raised it 689 -> 691. Modeling the `system ntp server` modifiers as
272:// 705 -> 706 for #8844. Declaring `keys` under `perfect-forward-secrecy`
274:// same move: it was a childless leaf and now has a child, so `unreachable`
281:	// #7492 moved leaves out of `unreachable` in two rounds. The parent
282:	// prerequisite moved 13 (10 compared, 3 revealed as flags); the typed
307:	// prerequisite (`host`) rescued all seven of that parent's leaves. See the
316:	//     NO prerequisite can ever rescue these; only implementing the feature
326:	//     prereq rows could ever recover, not a count of recoverable work. The
338:	// per-parent prerequisite synthesis — was tried and refuted by measurement:
379:	// stated — moved it out of the unreachable class. The ratchet is tightened
381:	// Both #8844 and #8830 moved this bucket, in DIFFERENT ways, and the value
385:	//   reclassification: `perfect-forward-secrecy` was a CHILDLESS leaf
387:	//   `keys` CHILD. Declaring that child moved the parent out of the leaf
388:	//   enumeration and put `keys` in as COMPARED. The tree got less blind.
390:	//   #8830 (this branch) moves SEVEN leaves to `advisory` -- they DO
396:	// confirmatory: `perfect-forward-secrecy` is NOT one of the seven, so
399:	// #8830: read, value deliberately ignored, advisory says so. Measured at
406:	// #7132 raised this 175 -> 176 for `system ntp server ... prefer`.
413:	// parent-stanza fix can rescue an `unreachable` leaf. It is in this class
416:	// It is not untested: both spellings of `prefer` are pinned by the #7132
440:	// "unreachable" and into this class. It is a value-less flag, so the
458:	// named by no advisory, so there was nothing to assert. Now
460:	// config AND produces its accepted-only advisory, and it is a member of the
479:	// completion still offers only <[Enter]>, so it does not fix the defect. The
641:// to collide, at which point the prerequisite would author the very value it
648:	// A leaf whose name collides with the prerequisite's first statement.
651:		t.Errorf("prerequisite was applied to the leaf it names: body=%q sets=%v.\n"+
660:		t.Errorf("a non-colliding leaf must still receive the prerequisite; got body=%q sets=%v", body, sets)
664:			t.Errorf("set-spelling prerequisite must be rooted at the PARENT path, got %q", cmd)
commit a7f84a20923a96b58ab66ec168e4609b7d94339a
Author: Paul Saab <paul.m.saab@gmail.com>
Date:   Sat Sep 5 02:39:45 2026 -0700

    security: declare `keys` under perfect-forward-secrecy (#8844)
    
    `security ipsec policy <p> perfect-forward-secrecy keys <group>;` -- the
    brace-elided spelling -- silently DISABLED PFS:
    
      braced   perfect-forward-secrecy { keys group14; }   PFSGroup=14
      packed   perfect-forward-secrecy keys group14;       PFSGroup=0
      absent   (no stanza)                                 PFSGroup=0
    
    The #8800 shape: `perfect-forward-secrecy` was declared `children: nil`
    while compileIPsec reads a `keys` CHILD of it, so the head was not a
    schema child, the brace-elision pass was never ASKED about the pair, and
    no scope entry could have named it. The schema's own desc -- "Perfect
    forward secrecy (keys group<N>)" -- documented the child it failed to
    declare.
    
    WHY THIS ONE IS DIFFERENT FROM THE REST OF ITS FAMILY. Every other
    member fails CLOSED or LOUD: #8800's zero-address NAT pool is rejected
    at strict commit, #8825's empty application-set is caught by the #3146
    gate. This one fails OPEN and is undetectable afterwards, because
    PFSGroup==0 is a legitimate value meaning "deliberately disabled" -- no
    downstream gate can distinguish "operator chose no PFS" from "operator
    configured PFS and we dropped it". The tunnel comes up, traffic flows,
    and a later compromise of long-term keys retroactively decrypts every
    session negotiated meanwhile. The operator meanwhile has positive
    evidence it worked: the stanza is in the file, the commit succeeded, and
    `show configuration` displays it.
    
    Two-part remedy, both required, as measured on #8800: declare `keys` so
    the pass ASKS, and admit ("perfect-forward-secrecy","keys") in
    compactNormalizeInScope so it says yes.
    
    NO VALIDATOR ON `keys`, deliberately. parseDHGroup accepts `group<N>` or
    a bare integer and leaves PFSGroup at 0 otherwise, so validating here
    would newly REJECT a value the tolerant Load path accepts today.
    The bad-value route to a silent disable is a SEPARATE question from the
    spelling route this fixes, and the guard pins it as known-and-unfixed so
    nobody reads this as closing the whole surface.
    
    The guard carries a baseline arm (the pair masked AND
    skipCompactNormalize, since the pass also runs inside
    compileConfigWithOpts and a pre-normalised tree is not a baseline on its
    own) and a degeneracy control: absent must still be 0, or a fix that
    hard-coded a non-zero default would satisfy every other assertion.
    
    Found by the #8830 behavioural predicate after correcting a defect in
    the probe itself -- it had compared only the FIRST value pair, so a leaf
    needing a type-specific value looked inert. #7484's wordInert already
    tried every pair with a comment saying why.
    
    Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01Nyps5vzpffdfem9WCUMZKC

 pkg/config/compact_normalize_8662.go    |   1 +
 pkg/config/pfs_packed_keys_8844_test.go | 125 ++++++++++++++++++++++++++++++++
 pkg/config/schema_security.go           |  25 ++++++-
 3 files changed, 150 insertions(+), 1 deletion(-)

exec
/bin/bash -lc "rg -n 'ReadActiveMeta|WriteActive|readEnvelope|ReadBoundedFile|MaxConfigSize|Marshal|writeActive|compileTree|s.store.Load|d.store.Load|ErrConfigDBUnreadable' pkg/configstore/disk*.go pkg/configstore/store_persist.go pkg/configstore/store.go pkg/daemon/daemon_run.go; nl -ba pkg/daemon/daemon_apply_interfaces.go | sed -n '175,285p'; rg -n 'reserved|\"mgmt\"|[Nn]ame.*collision|reservedNames' pkg/config --glob '*.go' --glob '"'!**/*test.go'"' | head -65" in /var/tmp/RES8865
 succeeded in 0ms:
rg: pkg/configstore/disk*.go: No such file or directory (os error 2)
pkg/configstore/store.go:8://   - store_persist.go — Load/Save, writeActive*, journal helpers, the
pkg/configstore/store.go:40:// MaxConfigSize bounds a single configuration payload accepted by any parse
pkg/configstore/store.go:50:const MaxConfigSize = 16 << 20 // 16 MiB
pkg/configstore/store.go:54:	if len(content) > MaxConfigSize {
pkg/configstore/store.go:56:			len(content), MaxConfigSize)
pkg/configstore/store.go:94:	// writeActiveFn is a test seam for active-config persistence
pkg/configstore/store.go:95:	// (#1799). nil (production) means s.db.WriteActive. Set via
pkg/configstore/store.go:96:	// SetWriteActiveForTesting; never assigned on production paths.
pkg/configstore/store.go:97:	writeActiveFn func(*config.ConfigTree) error
pkg/configstore/store.go:99:	// writeActiveMarkerFn is the marker-aware test seam for the #1922
pkg/configstore/store.go:101:	// db.WriteActiveMarker. Set via SetWriteActiveMarkerForTesting.
pkg/configstore/store.go:102:	writeActiveMarkerFn func(*config.ConfigTree, bool) error
pkg/configstore/store.go:380:// backend — every persistence path (Load, writeActive, the #1799
pkg/configstore/store.go:452:// compileTree compiles a config tree using the appropriate method based on
pkg/configstore/store.go:464:// compileTreeLenient below, which downgrades the same gate to a warning
pkg/configstore/store.go:467:func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
pkg/configstore/store.go:468:	return compileTreeStrict(tree, s.nodeID)
pkg/configstore/store.go:471:// compileTreeStrict is the package-level strict commit-check pipeline
pkg/configstore/store.go:473:// then strict compile). It backs both Store.compileTree (every
pkg/configstore/store.go:477:func compileTreeStrict(tree *config.ConfigTree, nodeID int) (*config.Config, error) {
pkg/configstore/store.go:522:	// rewriteRetiredDataplaneType BEFORE compileTreeLenient, so a peer
pkg/configstore/store.go:548:// (Store.compileTree passes s.nodeID) or the `-node-id` flag on
pkg/configstore/store.go:555:// This runs ONLY on the strict commit/commit-check path (compileTreeStrict).
pkg/configstore/store.go:556:// The tolerant Store.Load / Store.SyncApply ingress uses compileTreeLenient,
pkg/configstore/store.go:602:// Strict on the operator commit / commit-check path (compileTreeStrict);
pkg/configstore/store.go:604:// ingress (compileTreeLenient) so a legacy or peer-synced config cannot
pkg/configstore/store.go:628:// compileTreeLenient is compileTree with the tolerant-path validator
pkg/configstore/store.go:647:func (s *Store) compileTreeLenient(tree *config.ConfigTree) (*config.Config, error) {
pkg/configstore/store.go:649:	// operator-driven commit / commit-check path (compileTree). Here — the
pkg/configstore/store.go:787:	// primary must not alarm-loop HA sync (see compileTreeLenient for
pkg/configstore/store.go:789:	compiled, err := s.compileTreeLenient(tree)
pkg/configstore/store.go:823:	// its removal AFTER the writeActive below so the crash-recovery record is
pkg/configstore/store.go:851:	if err := s.writeActive(s.active); err != nil {
pkg/configstore/store_persist.go:27:	tree, committed, err := s.db.ReadActiveMeta()
pkg/configstore/store_persist.go:32:		// Tag it with ErrConfigDBUnreadable so the daemon can make it fatal
pkg/configstore/store_persist.go:35:		return fmt.Errorf("read config: %w: %w", ErrConfigDBUnreadable, err)
pkg/configstore/store_persist.go:61:	// this rewrite, compileTree below returns
pkg/configstore/store_persist.go:81:	// (see compileTreeLenient for the validator downgrades).
pkg/configstore/store_persist.go:82:	compiled, err := s.compileTreeLenient(tree)
pkg/configstore/store_persist.go:85:		// ErrConfigDBUnreadable) but a PRESENT, previously-committed config
pkg/configstore/store_persist.go:257:			perr = s.writeActiveMarker(prevTree, false)
pkg/configstore/store_persist.go:259:			compiled, cerr := s.compileTreeLenient(prevTree)
pkg/configstore/store_persist.go:281:			perr = s.writeActive(prevTree)
pkg/configstore/store_persist.go:285:		// durable (writeActive above SUCCEEDED). On failure keep it — the
pkg/configstore/store_persist.go:334:		compiled, cerr := s.compileTreeLenient(prevTree)
pkg/configstore/store_persist.go:364:	return s.writeActive(s.active)
pkg/configstore/store_persist.go:367:// writeActive persists tree as the on-disk active configuration.
pkg/configstore/store_persist.go:368:// Routes through the writeActiveFn test seam when set (#1799);
pkg/configstore/store_persist.go:371:func (s *Store) writeActive(tree *config.ConfigTree) error {
pkg/configstore/store_persist.go:372:	if s.writeActiveFn != nil {
pkg/configstore/store_persist.go:373:		return s.writeActiveFn(tree)
pkg/configstore/store_persist.go:375:	return s.db.WriteActive(tree)
pkg/configstore/store_persist.go:378:// writeActiveMarker persists tree as the on-disk active config with an
pkg/configstore/store_persist.go:381:// the writeActiveMarkerFn test seam when set; otherwise the production
pkg/configstore/store_persist.go:382:// DB.WriteActiveMarker. Caller must hold s.mu. When only the legacy
pkg/configstore/store_persist.go:383:// writeActiveFn seam is set (older tests), the marker degrades to that seam
pkg/configstore/store_persist.go:386:func (s *Store) writeActiveMarker(tree *config.ConfigTree, committed bool) error {
pkg/configstore/store_persist.go:387:	if s.writeActiveMarkerFn != nil {
pkg/configstore/store_persist.go:388:		return s.writeActiveMarkerFn(tree, committed)
pkg/configstore/store_persist.go:390:	if s.writeActiveFn != nil {
pkg/configstore/store_persist.go:391:		return s.writeActiveFn(tree)
pkg/configstore/store_persist.go:393:	return s.db.WriteActiveMarker(tree, committed)
pkg/configstore/store_persist.go:456:// and `json.MarshalIndent` (the DB persistence format) coerces it to U+FFFD.
pkg/configstore/store_persist.go:479:	data, err := json.Marshal(tree)
pkg/configstore/store_persist.go:529:// noteActivePersistFailureLocked records a WriteActive failure on an
pkg/configstore/store_persist.go:581:			if err := s.writeActiveMarker(s.active, s.persistMarkerCommitted); err == nil {
pkg/configstore/store_persist.go:1327:	data, err := ReadBoundedFile(path, MaxConfigSize)
   175			return err, nil
   176		}
   177	
   178		// 0. Reconcile VRF devices (routing-instance VRFs + management VRF).
   179		// ReconcileVRFs is idempotent: VRFs already present with the correct
   180		// table ID are preserved (ifindex unchanged). Removed-from-config
   181		// VRFs are deleted. #847: xpfd claims the entire `vrf-*` kernel
   182		// namespace — orphan vrf-* devices not in desired and not in
   183		// m.vrfs (e.g. left over from a routing-instance rename across
   184		// a daemon restart) are also reaped. Operators MUST NOT
   185		// pre-create vrf-<name> outside xpfd config.
   186		//
   187		// (The original docs/pr/844-vrf-idempotent/plan.md described an
   188		// earlier design where external VRFs were left alone; the
   189		// namespace-claim policy in this code supersedes that plan. See
   190		// the godoc on routing.ReconcileVRFs for the current contract.)
   191		const mgmtVRFName = "mgmt"
   192		const mgmtTableID = 999
   193		mgmtIfaces := managementVRFIfaceSet(cfg)
   194	
   195		if d.routing != nil {
   196			var desired []routing.VRFSpec
   197			for _, ri := range cfg.RoutingInstances {
   198				if ri.InstanceType == "forwarding" {
   199					slog.Info("forwarding instance, skipping VRF creation",
   200						"instance", ri.Name)
   201					continue
   202				}
   203				desired = append(desired, routing.VRFSpec{
   204					Name:    ri.Name,
   205					TableID: ri.TableID,
   206				})
   207			}
   208			if len(mgmtIfaces) > 0 {
   209				desired = append(desired, routing.VRFSpec{
   210					Name:    mgmtVRFName,
   211					TableID: mgmtTableID,
   212				})
   213			}
   214			if err := d.routing.ReconcileVRFs(desired); err != nil {
   215				// #5700: the VRF DEVICE setup failed (vrf-* could not be created/
   216				// reconciled). reconcileVRFs still records the VRF as managed on a
   217				// partial failure, so surface this into commit truth rather than
   218				// swallowing it at WARN — otherwise the commit reports the VRF
   219				// configured while it is not on the kernel (false convergence). This is
   220				// transient-free: VRF device creation depends on no other interface.
   221				slog.Warn("failed to reconcile VRFs", "err", err)
   222				vrfErr = errors.Join(vrfErr, fmt.Errorf("reconcile VRFs: %w", err))
   223			}
   224		}
   225	
   226		// 0a. Bind routing-instance interfaces to their VRFs.
   227		// Name normalization is shared with collectAppliedTunnels'
   228		// RIListMember scan via riMemberLinuxName (#1884) so the tunnel
   229		// manager's unbind veto can never diverge from what this loop
   230		// actually binds. Tunnel list members resolve through
   231		// cfg.TunnelNameMap() (#1904) so a unit>0 entry like gr-0/0/0.1
   232		// binds the real per-unit device (gr-0-0-0u1), not the literal
   233		// ".1" name.
   234		//
   235		// #5700: deliberately best-effort (WARN, not surfaced). This runs BEFORE
   236		// applyInterfaceReconcile creates tunnel/xfrmi devices, so a routing-instance
   237		// member that is a later-created tunnel is legitimately "not found" here — an
   238		// EXPECTED transient absence that must NOT be promoted into a permanent
   239		// commit failure.
   240		//
   241		// #6805: and because it is legitimately absent here, this pass alone left it
   242		// UNBOUND. The tunnel manager will not bind a list-only member either — its
   243		// case-2 arm only OBSERVES, because "0a owns list binds" — so on a FIRST
   244		// apply the tunnel came up outside its VRF, in the default table, and stayed
   245		// there until some later apply happened to run this loop while the device
   246		// existed. rebindRoutingInstanceMembers re-drives the SAME loop after the
   247		// devices exist; see its comment.
   248		d.bindRoutingInstanceMembers(cfg)
   249	
   250		// 0b. Bind management interfaces (fxp*/fab*/em*) to vrf-mgmt, but
   251		// only if ReconcileVRFs actually got vrf-mgmt into the managed set.
   252		// If reconcile errored out before vrf-mgmt could be created,
   253		// downstream code (applyMgmtVRFRoutes, HA sync) would otherwise
   254		// run against a non-existent VRF.
   255		// Compute the final management-VRF interface set, then publish it with a
   256		// single atomic Store (#5113) so a lock-free DHCP-callback reader never
   257		// observes the transient nil the old two-step (= nil then = mgmtIfaces)
   258		// published. mgmtSet stays nil (readers see the safe empty state) unless
   259		// reconcile actually got vrf-mgmt into the managed set.
   260		var mgmtSet map[string]bool
   261		if d.routing != nil && len(mgmtIfaces) > 0 && d.routing.IsManagedVRF(mgmtVRFName) {
   262			mgmtSet = mgmtIfaces
   263			for ifName := range mgmtIfaces {
   264				// #5700: this PRE-networkd bind is best-effort (WARN, not surfaced).
   265				// applyNetworkdConfig's `networkctl reconfigure` strips the VRF master
   266				// binding right after this phase, so the AUTHORITATIVE management-VRF
   267				// bind is the post-networkd rebindManagementVRFIfaces (whose failure IS
   268				// surfaced into commit truth). Surfacing this pre-strip bind would report
   269				// a failure for a binding networkd is about to remove and re-establish.
   270				if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
   271					slog.Warn("failed to bind interface to management VRF",
   272						"interface", ifName, "err", err)
   273				}
   274			}
   275		}
   276		d.publishMgmtVRFIfaces(mgmtSet)
   277	
   278		// #5867: the DHCP management-VRF route program+reconcile (formerly step 0.6
   279		// here) now runs in applyConfigLocked immediately after this reconcile
   280		// returns, so its RouteReplace / cleanup error is threaded into the tail
   281		// commit-error join (fail-closed but complete) instead of being swallowed at
   282		// this early phase. Moving it out of applyVRFReconcile also keeps a stale-
   283		// route-pin failure from aborting the whole apply early (it must NOT skip the
   284		// dataplane apply). Ordering is unchanged: it still runs after this reconcile
   285		// (which publishes the mgmt-interface set it reads) and before the interface/
pkg/config/compiler_security_addressbook.go:36:// #4340 prefix-in-name convention. Only the reserved "zone-local/" prefix is
pkg/config/appid_stable.go:12:// reserved "unknown" sentinel, so real applications take ids 1..65535 (#3438).
pkg/config/appid_stable.go:51:// operator-named zones can afford a hard hash-collision reject): the application
pkg/config/appid_stable.go:85:		return nil, fmt.Errorf("application catalog holds %d distinct applications, but the uint16 app_id space can assign at most %d distinct ids (0 is the reserved unknown sentinel); reduce the number of referenced applications", len(set), MaxCatalogAppID)
pkg/config/lifeline.go:42:// preserved). A standalone config (no chassis-cluster stanza) contributes no
pkg/config/ast_edit.go:38:// RenamePath's collision guard. The destination parent is resolved and the
pkg/config/ast_edit.go:95:// source parent) is performed IN PLACE so sibling order is preserved. A rename
pkg/config/compiler_uniformgates_ipsec_event.go:11:// order (invariant #7) are preserved. See runUniformGates.
pkg/config/compiler_validate_strict_zones.go:9:// reservedZoneNames is the set of tokens the dataplane / Junos grammar reserves
pkg/config/compiler_validate_strict_zones.go:33://     reserved policy-context token, never a named zone-id lookup, so a real
pkg/config/compiler_validate_strict_zones.go:39://   - "junos-host"  — Junos reserved self-traffic zone (host-inbound / host-
pkg/config/compiler_validate_strict_zones.go:41:var reservedZoneNames = map[string]struct{}{
pkg/config/compiler_validate_strict_zones.go:47:// policyZoneSpecialTokens is the set of reserved from-zone/to-zone tokens
pkg/config/compiler_validate_strict_zones.go:62://   - "junos-host"  — Junos reserved self-traffic zone (host-inbound / host-
pkg/config/compiler_validate_strict_zones.go:65:// This set is DELIBERATELY NOT derived from reservedZoneNames and DELIBERATELY
pkg/config/compiler_validate_strict_zones.go:67:// definition gate rejects a reserved NAME, while this reference gate must keep
pkg/config/compiler_validate_strict_zones.go:89:// <name>` DEFINITION whose name is a reserved sentinel token (#3055).
pkg/config/compiler_validate_strict_zones.go:97:// a silent security-boundary escape. "any" and "junos-host" are reserved policy
pkg/config/compiler_validate_strict_zones.go:119:		if _, reserved := reservedZoneNames[name]; reserved {
pkg/config/compiler_validate_strict_zones.go:121:				"security zone %q uses a reserved name: %q (along with \"any\" "+
pkg/config/compiler_validate_strict_zones.go:122:					"and \"junos-host\") is a reserved dataplane/Junos context "+
pkg/config/compiler_validate_strict_zones.go:140:// SUPERSEDED) but the reserved-sentinel range at the top of the u16 space:
pkg/config/compiler_validate_strict_zones.go:145:// no configured zone ever lands in the reserved range; the StableZoneID
pkg/config/compiler_validate_strict_zones.go:157:// fold itself guarantees no reserved-sentinel id is ever produced. (#2391 is
pkg/config/compiler_validate_strict_zones.go:172:			"configuration defines %d security zones, but the dataplane can address at most %d distinct zones (zone ids are a stable name-hash in a u16 space, top two ids reserved); reduce the zone count to %d or fewer",
pkg/config/compiler_validate_strict_zones.go:324://   - "lo0" — the loopback is a reserved, always-present interface in Junos
pkg/config/compiler_validate_strict_zones.go:340:	// lo0 is always materialized (loopback); reserved always-present in Junos.
pkg/config/ast_redact.go:60:// values are preserved, so the redacted render is byte-identical to the
pkg/config/compiler_class_of_service.go:561:	// why the different-names case is preserved.
pkg/config/compiler_class_of_service.go:625:	// why the different-names case is preserved.
pkg/config/compiler_routing.go:640:	// folds into a 900k-slot reserved band so a collision is astronomically
pkg/config/compiler_uniformgates_dhcp_app.go:11:// order (invariant #7) are preserved. See runUniformGates.
pkg/config/compiler_uniformgates_dhcp_app.go:13:	// #2243 DHCP-server static (fixed/reserved) host bindings. Strict on
pkg/config/compiler_uniformgates_dhcp_app.go:121:	// #5821 reserved application-name gate. The AppID display/filter surface
pkg/config/compiler_uniformgates_dhcp_app.go:133:	// config carrying the reserved name still BOOTS — #1960 no-brick), strict on
pkg/config/compiler_uniformgates_dhcp_app.go:138:				fmt.Sprintf("reserved application name (downgraded to warning on tolerant path): %v", err))
pkg/config/compiler_validate_strict_chassis.go:55:// reserved value; both are excluded. The schema `priority` leaf
pkg/config/compiler_validate_strict_chassis.go:294:					"RFC 5798 IP-owner reserved value; the priority feeds VRRP and "+
pkg/config/compiler_uniformgates_sampling_appset.go:11:// order (invariant #7) are preserved. See runUniformGates.
pkg/config/types_routing.go:403:	// preserved through to the wire. When DefaultLifetimeSet is false the
pkg/config/compiler_uniformgates_screen.go:11:// order (invariant #7) are preserved. See runUniformGates.
pkg/config/compiler_system.go:2523:	// ids is preserved so the compiled slice stays deterministic.
pkg/config/compiler_system.go:2585://     reserved immediately after it) starts a new entry.
pkg/config/compiler_system.go:3511:// An EMPTY value token is preserved as an entry: the pre-#6692 reader appended
pkg/config/compiler_validate_strict_routing.go:703:// `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and FRR/vtysh
pkg/config/compiler_validate_strict_routing.go:709:// The valid 4-byte AS space is 1..4294967295 (uint32 max); 0 is reserved
pkg/config/compiler_validate_strict_routing.go:710:// (RFC 7607) and 23456 (AS_TRANS) is reserved for 4-byte transition but is a
pkg/config/compiler_validate_strict_routing.go:749:					"reserved (RFC 7607) and FRR/vtysh rejects `remote-as 0`, "+
pkg/config/compiler_validate_strict_routing.go:986:// operator typed (route.NextTableRaw, preserved before the suffix strip, #5693)
pkg/config/compiler_validate_strict_routing.go:1321:// policy-statement whose name ends in the reserved ReservedRedistSuffix. That
pkg/config/compiler_validate_strict_routing.go:1329:// Strict on commit / commit-check (hard reject so the reserved name is
pkg/config/compiler_validate_strict_routing.go:1350:				"policy-statement %q ends in the reserved %q suffix; xpf owns "+
pkg/config/compiler_validate_strict_routing.go:1355:					"— rename the policy-statement off the reserved suffix",
pkg/config/compiler_validate_strict_routing.go:1376:// policy-statement whose name ends in the reserved ReservedChainSuffix. That
pkg/config/compiler_validate_strict_routing.go:1387:// Strict on commit / commit-check (hard reject so the reserved name is
pkg/config/compiler_validate_strict_routing.go:1408:				"policy-statement %q ends in the reserved %q suffix; xpf owns "+
pkg/config/compiler_validate_strict_routing.go:1414:					"policy-statement off the reserved suffix",
pkg/config/compiler_uniformgates_policy.go:11:// order (invariant #7) are preserved. See runUniformGates.
pkg/config/compiler_validate_warn.go:226:	// Validate policies. Exempt the reserved special-zone tokens (`any`,
pkg/config/compiler_validate_warn.go:1243:		// TransmitRateExact, so configured intent is preserved on the
pkg/config/compiler_validate_warn.go:1803:	// docs/nat-destination.md and the preserved plan
pkg/config/zoneid.go:11:// u16 zone space are reserved sentinels — JUNOS_GLOBAL_ZONE_ID (u16::MAX) and
pkg/config/zoneid.go:33:// 255-id wire field but the reserved-sentinel range, so the usable space is
pkg/config/zoneid.go:118:// config, so the union stays a pure function of config (HA symmetry preserved),
pkg/config/zoneid.go:123:// the fold guarantees no reserved-sentinel id and the dataplane independently

exec
/bin/bash -lc "rg --hidden --files -g '"'!**/.git/**'"' -g '"'!**/cache/**'"' -g '"'!**/node_modules/**'"' -g '"'!**/target/**'"' /var/tmp /home/ps/.codex 2>/dev/null | rg '/["'^/]*(muse|8830|review-008|review-009)[''^/]*$'"' | head -60; nl -ba pkg/cluster/sync_truncated_record_7175_test.go | sed -n '1,190p'; nl -ba pkg/cluster/sync_conn_read.go | sed -n '480,505p'" in /var/tmp/RES8865
 succeeded in 36ms:
/var/tmp/L8858/docs/reviews/archive/ps-review-008.md
/var/tmp/L8858/docs/reviews/archive/ps-review-009.md
/var/tmp/L8859/docs/reviews/archive/ps-review-008.md
/var/tmp/L8859/docs/reviews/archive/ps-review-009.md
/var/tmp/Lsweep/docs/reviews/archive/ps-review-008.md
/var/tmp/Lsweep/docs/reviews/archive/ps-review-009.md
/var/tmp/L8388-pos/docs/reviews/archive/ps-review-008.md
/var/tmp/L8388-pos/docs/reviews/archive/ps-review-009.md
/var/tmp/GE/docs/reviews/archive/ps-review-008.md
/var/tmp/GE/docs/reviews/archive/ps-review-009.md
/var/tmp/L8791/docs/reviews/archive/ps-review-008.md
/var/tmp/L8791/docs/reviews/archive/ps-review-009.md
/var/tmp/RES8865/docs/reviews/archive/ps-review-008.md
/var/tmp/RES8865/docs/reviews/archive/ps-review-009.md
/var/tmp/L8791base/docs/reviews/archive/ps-review-008.md
/var/tmp/L8791base/docs/reviews/archive/ps-review-009.md
/var/tmp/K8862b/docs/reviews/archive/ps-review-008.md
/var/tmp/K8862b/docs/reviews/archive/ps-review-009.md
/home/ps/.codex/sessions/2026/07/12/rollout-2026-07-12T02-50-48-019f55bc-8e9a-7900-87e0-3288302a2f9b.jsonl
/var/tmp/L8388-cmp/docs/reviews/archive/ps-review-008.md
/var/tmp/L8388-cmp/docs/reviews/archive/ps-review-009.md
     1	package cluster
     2	
     3	import (
     4		"encoding/binary"
     5		"testing"
     6	
     7		"github.com/psaab/xpf/pkg/dataplane"
     8		"github.com/psaab/xpf/pkg/dhcpserver"
     9	)
    10	
    11	// #7175: a truncated-but-framed session-sync record must not decode ok=true
    12	// with its policy/zone/NAT fields left at zero.
    13	//
    14	// WHY ZERO IS NOT "MISSING". A zeroed SessionID, PolicyID, zone pair and NAT
    15	// tuple are not absent values — they are VALUES the standby installs and
    16	// carries, and they become live forwarding state on the next failover.
    17	//
    18	// CORRECTION to the original #7175 rationale: this said zone id 0 against zone
    19	// id 0 is matched by a `from-zone any to-zone any permit` rule with no zone
    20	// guard, citing #6682. That was the PROBLEM STATEMENT of a CLOSED issue, not
    21	// current behaviour. Two mechanisms make it false: #3110 fenced every rule
    22	// tier against zone 0, so a wildcard never reaches a zero pair, and #6682 then
    23	// made an unzoned INGRESS an explicit deny. The corrected version was ALREADY
    24	// written in this repo — compiler_wireguard_plaintext_warn_5618_test.go says
    25	// the older claim "was wrong" — before I asserted the superseded one.
    26	//
    27	// The assertions below are unchanged and still correct, because they never
    28	// depended on that claim: they assert that no ACCEPTED prefix may carry zeroed
    29	// forwarding fields, which is a property of the decoder. A decoder must not
    30	// report success for input it did not decode. What is deliberately NOT asserted
    31	// here is any downstream consequence of an installed zero-zone session — that
    32	// would need measuring, and asserting it unmeasured is how the original error
    33	// got in.
    34	//
    35	// WHY A FULL PREFIX SWEEP RATHER THAN A FEW BOUNDARY CASES. The property is not
    36	// "these particular lengths are rejected", it is "no accepted length yields
    37	// zeroed forwarding fields". Sweeping every prefix and asserting the INVARIANT
    38	// at each one covers the interiors of blocks as well as their boundaries, and it
    39	// keeps holding if a future field moves a boundary — a boundary-listing test
    40	// would silently stop covering the interior it was written for.
    41	//
    42	// WHAT IS DELIBERATELY STILL TOLERATED. Everything from the counters block
    43	// onward stays length-gated, because those are genuine append-only wire
    44	// extensions that older peers legitimately omit (#2170 Generation, #3301
    45	// AppTimeout/PolicyCounterIdx, #5274 ConfigEpoch, #5212 RTFlowSessionID, #7095
    46	// IngressIfaceFold). TestCrossVersionShortPayloadDecode and the #7095 truncation
    47	// case pin that tolerance and must keep passing: the fix draws the line at
    48	// forwarding semantics, not at "any short read".
    49	
    50	func fullV4Record(t *testing.T) (dataplane.SessionKey, dataplane.SessionValue, []byte) {
    51		t.Helper()
    52		// Every field the assertion reads is NON-ZERO and distinct, so a decode that
    53		// silently substitutes a zero is caught. A fixture using the value the bug
    54		// falls back to would go green against the very defect it is written for.
    55		key := dataplane.SessionKey{
    56			SrcIP: [4]byte{10, 1, 2, 3}, DstIP: [4]byte{10, 4, 5, 6},
    57			SrcPort: 1111, DstPort: 2222, Protocol: 6,
    58		}
    59		val := dataplane.SessionValue{
    60			State: dataplane.SessStateEstablished,
    61			// The forwarding-semantic block that truncation used to zero.
    62			SessionID: 0x1122334455667788, PolicyID: 0xABCD,
    63			IngressZone: 0x0101, EgressZone: 0x0202,
    64			NATSrcIP: 0x0A0B0C0D, NATDstIP: 0x0E0F1011,
    65			NATSrcPort: 3333, NATDstPort: 4444,
    66		}
    67		return key, val, encodeSessionV4Payload(key, val)
    68	}
    69	
    70	func TestTruncatedV4RecordNeverDecodesWithZeroedForwardingFields7175(t *testing.T) {
    71		_, val, full := fullV4Record(t)
    72	
    73		accepted := 0
    74		for n := 0; n <= len(full); n++ {
    75			_, got, ok := decodeSessionV4Payload(full[:n])
    76			if !ok {
    77				continue
    78			}
    79			accepted++
    80			// The invariant: anything ACCEPTED must carry the real forwarding
    81			// fields, never the zero the truncation used to substitute.
    82			if got.PolicyID != val.PolicyID {
    83				t.Fatalf("prefix of %d bytes decoded ok=true with PolicyID=%d, want %d — a truncated "+
    84					"record must not be accepted with a zeroed policy id (#7175)", n, got.PolicyID, val.PolicyID)
    85			}
    86			if got.IngressZone != val.IngressZone || got.EgressZone != val.EgressZone {
    87				t.Fatalf("prefix of %d bytes decoded ok=true with zones (%d,%d), want (%d,%d) — a "+
    88					"decoder must not report success for a record whose zone identity it never read",
    89					n, got.IngressZone, got.EgressZone, val.IngressZone, val.EgressZone)
    90			}
    91			if got.NATSrcIP != val.NATSrcIP || got.NATDstIP != val.NATDstIP ||
    92				got.NATSrcPort != val.NATSrcPort || got.NATDstPort != val.NATDstPort {
    93				t.Fatalf("prefix of %d bytes decoded ok=true with NAT (%d,%d,%d,%d), want (%d,%d,%d,%d) — "+
    94					"a session installed with no translation misforwards (#7175)",
    95					n, got.NATSrcIP, got.NATDstIP, got.NATSrcPort, got.NATDstPort,
    96					val.NATSrcIP, val.NATDstIP, val.NATSrcPort, val.NATDstPort)
    97			}
    98		}
    99		// Negative control. Without it "no accepted prefix violated the invariant"
   100		// is also what a decoder that rejects EVERYTHING reports — including the
   101		// complete record, which would break session sync entirely while this test
   102		// stayed green.
   103		if accepted == 0 {
   104			t.Fatal("no prefix decoded at all, so the sweep above asserted nothing: a decoder that " +
   105				"rejects every input would pass it. The complete record must still decode")
   106		}
   107		t.Logf("%d of %d prefix lengths accepted, all carrying intact forwarding fields", accepted, len(full)+1)
   108	}
   109	
   110	// The complete record must round-trip unchanged — the other half of the control:
   111	// the fix must reject partial state without disturbing the valid path.
   112	func TestCompleteV4RecordStillRoundTrips7175(t *testing.T) {
   113		key, val, full := fullV4Record(t)
   114		gotKey, got, ok := decodeSessionV4Payload(full)
   115		if !ok {
   116			t.Fatal("the complete record must decode")
   117		}
   118		if gotKey != key {
   119			t.Errorf("key round-trip: got %+v want %+v", gotKey, key)
   120		}
   121		if got.PolicyID != val.PolicyID || got.IngressZone != val.IngressZone ||
   122			got.EgressZone != val.EgressZone || got.SessionID != val.SessionID {
   123			t.Errorf("forwarding fields round-trip: got policy=%d zones=(%d,%d) id=%d",
   124				got.PolicyID, got.IngressZone, got.EgressZone, got.SessionID)
   125		}
   126	}
   127	
   128	func TestTruncatedV6RecordNeverDecodesWithZeroedForwardingFields7175(t *testing.T) {
   129		key := dataplane.SessionKeyV6{SrcPort: 1111, DstPort: 2222, Protocol: 6}
   130		key.SrcIP[0], key.DstIP[0] = 0x20, 0x30
   131		val := dataplane.SessionValueV6{
   132			State: dataplane.SessStateEstablished,
   133			// v6 splits NAT into its own block; both blocks are asserted.
   134			SessionID: 0x99AABBCC, PolicyID: 0x4321,
   135			IngressZone: 0x0303, EgressZone: 0x0404,
   136			NATSrcPort: 5555, NATDstPort: 6666,
   137		}
   138		val.NATSrcIP[0], val.NATDstIP[0] = 0x40, 0x50
   139		full := encodeSessionV6Payload(key, val)
   140	
   141		accepted := 0
   142		for n := 0; n <= len(full); n++ {
   143			_, got, ok := decodeSessionV6Payload(full[:n])
   144			if !ok {
   145				continue
   146			}
   147			accepted++
   148			if got.PolicyID != val.PolicyID || got.IngressZone != val.IngressZone || got.EgressZone != val.EgressZone {
   149				t.Fatalf("v6 prefix of %d bytes decoded ok=true with policy=%d zones=(%d,%d) (#7175)",
   150					n, got.PolicyID, got.IngressZone, got.EgressZone)
   151			}
   152			if got.NATSrcIP != val.NATSrcIP || got.NATDstIP != val.NATDstIP ||
   153				got.NATSrcPort != val.NATSrcPort || got.NATDstPort != val.NATDstPort {
   154				t.Fatalf("v6 prefix of %d bytes decoded ok=true with zeroed/incorrect NAT — v6 carries NAT "+
   155					"in its own 36-byte block, which was separately fail-open (#7175)", n)
   156			}
   157		}
   158		if accepted == 0 {
   159			t.Fatal("no v6 prefix decoded at all — the sweep asserted nothing")
   160		}
   161	}
   162	
   163	// C179-075, the sibling on the DHCP full-set path. A full-set push REPLACES the
   164	// peer lease set, so accepting a prefix DELETES every lease past the cut on the
   165	// standby.
   166	func TestDHCPFullSetRejectsARecordCutMidStream7175(t *testing.T) {
   167		in := []dhcpserver.SyncLease{
   168			{Family: 4, Address: "10.0.0.1", SubnetID: 1, Remaining: 10, ValidLife: 10},
   169			{Family: 4, Address: "10.0.0.2", SubnetID: 1, Remaining: 20, ValidLife: 20},
   170		}
   171		full := encodeDHCPLeasePayload(in)
   172	
   173		// Positive control FIRST: without it, a decoder that rejects everything
   174		// passes the rejection cell below.
   175		if out, ok := decodeDHCPLeasePayload(full); !ok || len(out) != 2 {
   176			t.Fatalf("control: the complete lease set must decode (ok=%v, %d leases)", ok, len(out))
   177		}
   178	
   179		// Cut the LAST record in half. Its length prefix still claims the full
   180		// length, so the frame is framed-but-truncated — the exact shape that used
   181		// to return a silently shortened set.
   182		cut := full[:len(full)-6]
   183		out, ok := decodeDHCPLeasePayload(cut)
   184		if ok {
   185			t.Errorf("a lease record cut mid-stream decoded ok=true with %d of %d leases — a full-set "+
   186				"push replaces the set, so the standby would silently drop the rest (C179-075)", len(out), len(in))
   187		}
   188		if len(out) != 0 {
   189			t.Errorf("a rejected decode must yield no leases, got %d — the caller stores what it is "+
   190				"handed, so a non-empty prefix here still replaces the set", len(out))
   480			// #5706 review fold: strip the '\n' delimiter a new sender inserts
   481			// between the SA name list and the trailer so a new->new roundtrip
   482			// leaves no trailing empty name. A legacy / pre-fold frame has no
   483			// delimiter, so this is a no-op for it.
   484			names := decodeIPsecSAPayload(stripIPsecFullSetDelim(base))
   485			s.peerIPsecSAsMu.Lock()
   486			s.peerIPsecSAs = names
   487			s.peerIPsecSAsMu.Unlock()
   488			slog.Debug("cluster sync: received IPsec SA list", "count", len(names), "incarnation", incarnation, "seq", seq)
   489			if s.OnIPsecSAReceived != nil {
   490				s.OnIPsecSAReceived(names)
   491			}
   492		case syncMsgPersistentNatLease:
   493			// #8121: a full IDLE persistent-NAT lease set. Same two refusals the
   494			// DHCP full-set arms make, and for the same reason: a full set
   495			// REPLACES, so installing a stale or truncated one is worse than
   496			// installing nothing. The standby simply keeps rebuilding leases from
   497			// sessions (#7360) until a good set arrives.
   498			base, incarnation, seq := stripFullSetSeq(payload)
   499			s.recvSeqMu.Lock()
   500			admit := s.persistentNatLeaseRecvSeq.admit(incarnation, seq)
   501			s.recvSeqMu.Unlock()
   502			if !admit {
   503				slog.Warn("cluster sync: dropping out-of-order persistent-NAT lease set (stale sequence)",
   504					"incarnation", incarnation, "seq", seq)
   505				return

web search: 
web search: https://github.com/psaab/xpf/issues/8865
exec
/bin/bash -lc "rg -n 'func .*ReadActiveMeta|func .*WriteActive|ReadBoundedFile|MaxConfigSize|func .*writeTree|MarshalIndent|readEnvelope' pkg/configstore/db*.go; nl -ba pkg/configstore/store.go | sed -n '477,520p'; rg -n 'ErrConfigDBUnreadable|\\.Load\\(' pkg/daemon/daemon_run*.go; nl -ba pkg/cluster/sync_truncated_record_7175_test.go | sed -n '192,248p'; rg -n '32|predicate|PFS|seven|SEVEN|7|8817|8830' pkg/config/pfs_packed_keys_8844_test.go pkg/config/schema_spelling_gate_coverage_7484_test.go | head -60" in /var/tmp/RES8865
 succeeded in 21ms:
   192	}
   193	
   194	// The deliberately TOLERATED case, pinned so the rejection above cannot quietly
   195	// widen into it. An over-declared count whose records all arrived WHOLE loses no
   196	// data — only the sender's count was wrong — and this is the contract
   197	// TestDHCPLeasePayload_TruncatedStream already documents.
   198	func TestDHCPFullSetStillToleratesAnOverDeclaredCount7175(t *testing.T) {
   199		in := []dhcpserver.SyncLease{
   200			{Family: 4, Address: "10.0.0.1", SubnetID: 1, Remaining: 10, ValidLife: 10},
   201			{Family: 4, Address: "10.0.0.2", SubnetID: 1, Remaining: 20, ValidLife: 20},
   202		}
   203		payload := encodeDHCPLeasePayload(in)
   204		binary.LittleEndian.PutUint32(payload[:4], 5) // claim 5, ship 2 complete records
   205		out, ok := decodeDHCPLeasePayload(payload)
   206		if !ok || len(out) != 2 {
   207			t.Fatalf("an over-declared count with every record whole must still decode "+
   208				"(ok=%v, %d leases, want true/2). #7175 rejects data LOSS, not a wrong count", ok, len(out))
   209		}
   210	}
pkg/config/schema_spelling_gate_coverage_7484_test.go:11:// #7484 — COVERAGE OF THE SPELLING GATE IS ITSELF A GATED PROPERTY.
pkg/config/schema_spelling_gate_coverage_7484_test.go:41:// so: of the 232 `args == 0` leaves, 15 are compared TODAY and are genuinely
pkg/config/schema_spelling_gate_coverage_7484_test.go:47:// cells to make a number look better — the exact move #7484 says not to make.
pkg/config/schema_spelling_gate_coverage_7484_test.go:64:	// #8830: the leaf IS read and its value is DELIBERATELY ignored, with an
pkg/config/schema_spelling_gate_coverage_7484_test.go:67:	// That is the LOUD form of dropping a value and it is #8785's documented
pkg/config/schema_spelling_gate_coverage_7484_test.go:95:			// convention. TestGateSpellingSetsAreConsistent_7484 guards the
pkg/config/schema_spelling_gate_coverage_7484_test.go:114:	// #7492: apply the same parent prerequisite the differential uses, or the
pkg/config/schema_spelling_gate_coverage_7484_test.go:144:	// #8830: everything above compared through gateMarshal, which NULLS
pkg/config/schema_spelling_gate_coverage_7484_test.go:153:	// Re-scored with warnings included, 7 of the 141 leaves this branch used to
pkg/config/schema_spelling_gate_coverage_7484_test.go:212:// Measured at 6b47801de. Raising a ceiling is a real decision: it says a leaf
pkg/config/schema_spelling_gate_coverage_7484_test.go:215:// #7448 raised this 687 -> 689. Declaring `chassis cluster fabric1-interface`
pkg/config/schema_spelling_gate_coverage_7484_test.go:221:// #7132 raised it 689 -> 691. Modeling the `system ntp server` modifiers as
pkg/config/schema_spelling_gate_coverage_7484_test.go:227:// LOWERED 705 -> 701 for the #8781-follow-up IKE identity fix. The value was
pkg/config/schema_spelling_gate_coverage_7484_test.go:228:// RE-MEASURED after merging another lane's increase to 705, not arithmetically
pkg/config/schema_spelling_gate_coverage_7484_test.go:229:// adjusted from the pre-merge number — the two happen to agree here (705 minus
pkg/config/schema_spelling_gate_coverage_7484_test.go:259:// 702 -> 703 for the destination-pool half of #8800. Declaring `address`
pkg/config/schema_spelling_gate_coverage_7484_test.go:265:// 703 -> 705 for #8825: declaring `application` and `application-set` under
pkg/config/schema_spelling_gate_coverage_7484_test.go:268:// `flag` ceiling going 179 -> 209 for the #8807 `then` fix, not this one, and
pkg/config/schema_spelling_gate_coverage_7484_test.go:272:// 705 -> 706 for #8844. Declaring `keys` under `perfect-forward-secrecy`
pkg/config/schema_spelling_gate_coverage_7484_test.go:278:const gateCoverageFloor = 706
pkg/config/schema_spelling_gate_coverage_7484_test.go:281:	// #7492 moved leaves out of `unreachable` in two rounds. The parent
pkg/config/schema_spelling_gate_coverage_7484_test.go:283:	// path-identifier fallback then moved 72 more (58 compared, 14 revealed as
pkg/config/schema_spelling_gate_coverage_7484_test.go:288:	// #6875 raised this 143 -> 144, deliberately, for
pkg/config/schema_spelling_gate_coverage_7484_test.go:301:	// constructs the parent stanza — the #7492-style fix, which is a change to
pkg/config/schema_spelling_gate_coverage_7484_test.go:302:	// the gate and not to #6875. The leaf itself is covered behaviourally by
pkg/config/schema_spelling_gate_coverage_7484_test.go:303:	// TestStreamSourceInterfaceCompiles_6875, its validator by
pkg/config/schema_spelling_gate_coverage_7484_test.go:304:	// TestStreamSourceInterfaceIsValidated_6875, and both apply paths by the
pkg/config/schema_spelling_gate_coverage_7484_test.go:306:	// #7492 lowered this 144 -> 137: a `security log stream <*>` parent
pkg/config/schema_spelling_gate_coverage_7484_test.go:307:	// prerequisite (`host`) rescued all seven of that parent's leaves. See the
pkg/config/schema_spelling_gate_coverage_7484_test.go:310:	// WHAT THE REMAINING 137 ACTUALLY ARE, measured rather than assumed —
pkg/config/schema_spelling_gate_coverage_7484_test.go:312:	// never be paid. The 137 span 66 parents and are TWO populations, counted:
pkg/config/schema_spelling_gate_coverage_7484_test.go:330:	//     another 7 (security log stream). But absence of an inertness marker
pkg/config/schema_spelling_gate_coverage_7484_test.go:336:	// So do NOT read this ceiling as 137 missing tests. At least 33 are
pkg/config/schema_spelling_gate_coverage_7484_test.go:337:	// correctly reported and always will be. #7492's original plan — a GENERAL
pkg/config/schema_spelling_gate_coverage_7484_test.go:342:	// This constant is the tracker. #7492 was CLOSED rather than retitled
pkg/config/schema_spelling_gate_coverage_7484_test.go:346:	// -> 137); a number that lives beside the code it measures cannot.
pkg/config/schema_spelling_gate_coverage_7484_test.go:347:	// #8445 tightened this 137 -> 136. `firewall policer <*> then discard` was
pkg/config/schema_spelling_gate_coverage_7484_test.go:355:	// #7971 raised this 136 -> 140, deliberately, for the four
pkg/config/schema_spelling_gate_coverage_7484_test.go:358:	// (schema_login_regexps_7971.go), so both spellings of each produce the same
pkg/config/schema_spelling_gate_coverage_7484_test.go:367:	// and the routing-instances copy). Like the #7971 `-regexps` family above,
pkg/config/schema_spelling_gate_coverage_7484_test.go:377:	// 142 -> 141 (#8768): declaring `args: 2` on the IKE policy
pkg/config/schema_spelling_gate_coverage_7484_test.go:381:	// Both #8844 and #8830 moved this bucket, in DIFFERENT ways, and the value
pkg/config/schema_spelling_gate_coverage_7484_test.go:390:	//   #8830 (this branch) moves SEVEN leaves to `advisory` -- they DO
pkg/config/schema_spelling_gate_coverage_7484_test.go:396:	// confirmatory: `perfect-forward-secrecy` is NOT one of the seven, so
pkg/config/schema_spelling_gate_coverage_7484_test.go:397:	// the two changes are disjoint and 140 - 7 = 133 was expected.
pkg/config/schema_spelling_gate_coverage_7484_test.go:399:	// #8830: read, value deliberately ignored, advisory says so. Measured at
pkg/config/schema_spelling_gate_coverage_7484_test.go:405:	gateBlindAdvisory: 7,
pkg/config/schema_spelling_gate_coverage_7484_test.go:406:	// #7132 raised this 175 -> 176 for `system ntp server ... prefer`.
pkg/config/schema_spelling_gate_coverage_7484_test.go:412:	// any change to the gate or to the schema, the way a #7492-style
pkg/config/schema_spelling_gate_coverage_7484_test.go:416:	// It is not untested: both spellings of `prefer` are pinned by the #7132
pkg/config/schema_spelling_gate_coverage_7484_test.go:422:	// #7441 raised this 176 -> 177 for `chassis cluster strict-session-auth`,
pkg/config/schema_spelling_gate_coverage_7484_test.go:431:	// (TestStrictSessionAuthCompiles7441, which asserts presence AND absence),
pkg/config/schema_spelling_gate_coverage_7484_test.go:433:	// (TestClusterSplitterAndSchemaAgree_6672 / #6672 — that gate is what
pkg/config/schema_spelling_gate_coverage_7484_test.go:436:	// (TestStrictSessionAuthIsInTheSetSchema7441), and the strict/tolerant
pkg/config/schema_spelling_gate_coverage_7484_test.go:438:	// #8445 raised this 177 -> 178, and it is the SAME leaf as the -1 above,
pkg/config/schema_spelling_gate_coverage_7484_test.go:450:	// #8296 raises this 178 -> 179 for `security flow tcp-session
pkg/config/schema_spelling_gate_coverage_7484_test.go:463:	// RAISED 179 -> 209 for the #8807-followup completion fix, DELIBERATELY and
pkg/config/schema_spelling_gate_coverage_7484_test.go:475:	// 179, where "make them compare" is a real option.
pkg/config/schema_spelling_gate_coverage_7484_test.go:497:func TestSchemaSpellingGateCoverageIsGated_7484(t *testing.T) {
pkg/config/schema_spelling_gate_coverage_7484_test.go:517:	// which is strictly worse than sitting in the wrong bucket: seven leaves

exec
/bin/bash -lc "rg -n 'const .*([Nn]ame|[Pp]refix|[Ss]uffix)|Reserved.*(Prefix|Suffix)|vrf-.*name|func.*[Vv][Rr][Ff].*[Nn]ame|func.*[Nn]ame' pkg/routing/vrf*.go pkg/config/compiler_validate_strict_routing.go pkg/config/compiler_routing.go | head -65; nl -ba pkg/config/schema_spelling_gate_coverage_7484_test.go | sed -n '282,409p'; nl -ba pkg/config/pfs_packed_keys_8844_test.go | sed -n '1,51p'" in /var/tmp/RES8865
 succeeded in 7ms:
codex
The five-member completeness claim is false: `UnmarshalHeartbeat` has another allocation sized from a wire count, with a check before allocation. I also confirmed that #8830’s corrected probe found the PFS defect fixed by #8844. The “1 from 32” ratio alone does not justify discounting that method.

exec
/bin/bash -lc "nl -ba pkg/configstore/db.go | sed -n '84,135p;325,404p;467,523p'; nl -ba pkg/daemon/daemon_run_bringup.go | sed -n '290,329p'; rg -n 'func classifyLoadError|loadFatalDB|ErrConfigDBUnreadable|loadFatal' pkg/daemon --glob '*.go' --glob '"'!**/*test.go'"'; nl -ba pkg/configstore/store.go | sed -n '40,61p'; nl -ba pkg/config/schema.go | sed -n '74,98p'" in /var/tmp/RES8865
 succeeded in 0ms:
    84	func (db *DB) rollbackPath(n int) string {
    85		return filepath.Join(db.dir, fmt.Sprintf("rollback.%d.json", n))
    86	}
    87	
    88	// ReadActive loads the active configuration from disk.
    89	// Returns nil (no error) if the file doesn't exist.
    90	func (db *DB) ReadActive() (*config.ConfigTree, error) {
    91		tree, _, err := db.readTreeMeta(db.activePath())
    92		return tree, err
    93	}
    94	
    95	// ReadActiveMeta loads the active configuration AND the #1922 step-0
    96	// committed marker. committed is TRUE when the file is absent (no marker to
    97	// honor — Load treats absent as start-fresh anyway), TRUE for a legacy
    98	// (no-envelope) DB, and TRUE for any enveloped DB that omits or sets
    99	// committed=1; it is FALSE only for an enveloped DB this build wrote with
   100	// the explicit never-committed marker (committed=0).
   101	func (db *DB) ReadActiveMeta() (tree *config.ConfigTree, committed bool, err error) {
   102		return db.readTreeMeta(db.activePath())
   103	}
   104	
   105	// WriteActive persists the active configuration to disk atomically. The
   106	// on-disk envelope is stamped committed=1 (a real successful commit/sync).
   107	func (db *DB) WriteActive(tree *config.ConfigTree) error {
   108		return db.writeTreeMarked(db.activePath(), tree, true)
   109	}
   110	
   111	// WriteActiveMarker persists tree as the active config with an explicit
   112	// #1922 step-0 committed marker. committed=false writes the never-committed
   113	// marker used by the Item 1b first-commit rollback (enterBootstrapMode):
   114	// the empty tree on disk must NOT later classify as operator-committed-empty.
   115	func (db *DB) WriteActiveMarker(tree *config.ConfigTree, committed bool) error {
   116		return db.writeTreeMarked(db.activePath(), tree, committed)
   117	}
   118	
   119	// ReadCandidate loads the candidate configuration from disk.
   120	// Returns nil (no error) if the file doesn't exist.
   121	func (db *DB) ReadCandidate() (*config.ConfigTree, error) {
   122		tree, _, err := db.readTreeMeta(db.candidatePath())
   123		return tree, err
   124	}
   125	
   126	// WriteCandidate persists the candidate configuration to disk atomically.
   127	func (db *DB) WriteCandidate(tree *config.ConfigTree) error {
   128		return db.writeTreeMarked(db.candidatePath(), tree, true)
   129	}
   130	
   131	// DeleteCandidate removes the candidate file from disk.
   132	func (db *DB) DeleteCandidate() error {
   133		err := os.Remove(db.candidatePath())
   134		if err != nil && !os.IsNotExist(err) {
   135			return fmt.Errorf("delete candidate: %w", err)
   325			if !os.IsNotExist(err) {
   326				return fmt.Errorf("delete confirm state: %w", err)
   327			}
   328			// Already absent. This is EITHER "never existed" OR "a prior call
   329			// unlinked it but its dir fsync failed" — the removal is then not yet
   330			// durable and a crash could replay the stale dirent (#5835). The DB
   331			// layer cannot tell the two apart across calls, so it does NOT short-
   332			// circuit here: it falls through to the dir fsync below so an absent-
   333			// file RETRY still reaches the #4864 durability sync. The caller's
   334			// confirmRemoveDegraded flag carries the cross-call "sync owed" state;
   335			// this method keeps returning an error until a dir fsync succeeds, so a
   336			// post-unlink sync failure can never be laundered into a false success
   337			// by a subsequent absent-file retry.
   338		}
   339		if err := rbSyncDir(filepath.Dir(db.confirmPath())); err != nil {
   340			return fmt.Errorf("sync dir after delete confirm state: %w", err)
   341		}
   342		return nil
   343	}
   344	
   345	// readTreeMeta reads and parses a config tree from a JSON file, returning
   346	// the #1922 step-0 committed marker alongside it. Returns (nil, true, nil)
   347	// if the file doesn't exist (absent => start-fresh; committed is irrelevant
   348	// but defaults true so an absent-DB caller never sees a spurious
   349	// never-committed signal). A legacy (no-envelope) DB also reads committed.
   350	func (db *DB) readTreeMeta(path string) (*config.ConfigTree, bool, error) {
   351		// #8597 (muse-004 K70): BOUNDED — see ReadConfirm above. This is the SSOT
   352		// the daemon must load to take over, so it was the least bounded read of
   353		// the most important file.
   354		data, err := ReadBoundedFile(path, MaxConfigSize)
   355		if err != nil {
   356			if os.IsNotExist(err) {
   357				return nil, true, nil
   358			}
   359			return nil, true, fmt.Errorf("read %s: %w", path, err)
   360		}
   361		// Config compatibility envelope (#1917 increment B). The envelope is
   362		// the OUTERMOST framing — a magic header line prepended to the
   363		// (possibly-encrypted) body. Strip+validate it BEFORE decryption so a
   364		// too-new DB fails closed here, never silently empty-loads. A body
   365		// with no envelope is a pre-floor (legacy) DB and is read unchanged
   366		// (committed defaults true — migration rule C3).
   367		committed := true
   368		// #7176 (C179-053): the AAD for the body is the stored header line, but
   369		// ONLY for envelopes stamped at or above envelopeAADFormatVersion. Below
   370		// that the body was sealed with nil AAD and must be opened the same way.
   371		//
   372		// The gate reads the STORED v=, not this build's constant, and that is what
   373		// makes a forced downgrade fail closed: rewriting a v2 header to v=1 selects
   374		// the nil-AAD path against a ciphertext sealed with AAD, so the tag check
   375		// fails. Editing anything else in a v2 header — the committed= marker
   376		// included — changes the AAD and fails the same way.
   377		var aad []byte
   378		if hasEnvelope(data) {
   379			body, hdr, eerr := stripEnvelope(data)
   380			if eerr != nil {
   381				return nil, true, fmt.Errorf("read %s: %w", path, eerr)
   382			}
   383			if hdr.FormatVersion >= envelopeAADFormatVersion {
   384				aad = envelopeHeaderLineBytes(data)
   385			}
   386			data = body
   387			committed = hdr.Committed
   388		}
   389	
   390		data, decrypted, err := db.maybeDecryptTreeJSON(data, aad)
   391		if err != nil {
   392			return nil, true, fmt.Errorf("decrypt %s: %w", path, err)
   393		}
   394	
   395		// Reject a body whose top-level JSON is not an OBJECT (#5474 fail-open).
   396		// Go's json.Unmarshal([]byte("null"), &ConfigTree{}) returns NO error and
   397		// leaves the tree at its zero value — a semantically EMPTY config. A
   398		// legacy/plaintext (or enveloped-but-unencrypted) active body of literal
   399		// `null` would therefore decode to an empty tree and Store.Load would
   400		// compile+boot it normally, so the firewall comes up with policy ABSENT
   401		// (fail-open) instead of failing closed. Syntactically-invalid bodies and
   402		// top-level arrays/scalars already error against the struct target, but
   403		// `null` is syntactically valid and decodes to zero policy — this is the
   404		// specific gap. Authoritative persisted state must REJECT malformed/partial
   467				"a null/array/scalar body decodes to an EMPTY config and would boot with "+
   468				"policy absent (fail-open) — refusing", string(snippet))
   469		}
   470		return nil
   471	}
   472	
   473	// writeTree persists a config tree to a JSON file durably (#1894,
   474	// DurableState class): temp + fsync + rename + dir fsync, so a commit
   475	// that reported success cannot be silently lost to a power cut — the
   476	// guarantee the #1799 persist-before-promote contract is built on.
   477	func (db *DB) writeTreeMarked(path string, tree *config.ConfigTree, committed bool) error {
   478		data, err := json.MarshalIndent(tree, "", "  ")
   479		if err != nil {
   480			return fmt.Errorf("marshal config: %w", err)
   481		}
   482		// #7176 (C179-053): the header must exist BEFORE the seal, because it IS
   483		// the AAD. Encryption-ness is known here (the same predicate
   484		// maybeEncryptTreeJSON uses), which also lets min-reader be exact: only an
   485		// ENCRYPTED v2 envelope is unreadable by a pre-v2 build, so only that case
   486		// raises the floor. An unencrypted v2 envelope has no ciphertext to bind
   487		// and stays readable by an older reader — stamping min-reader=2 on it would
   488		// refuse a downgrade for no reason.
   489		//
   490		// The alternative — leaving min-reader at 1 always — is also fail-closed,
   491		// but an old build would report an opaque "decrypt config tree" failure
   492		// instead of the envelope layer's explicit "too new" message. A confusing
   493		// error during a rollback is the worst time for one.
   494		encrypted := masterPasswordPRF(tree) != ""
   495		minReader := EnvelopeMinReaderVersion
   496		if encrypted {
   497			minReader = envelopeAADFormatVersion
   498		}
   499		header := buildEnvelopeHeaderLine(db.writerVersion, committed, minReader)
   500	
   501		var aad []byte
   502		if encrypted {
   503			aad = header
   504		}
   505		data, err = db.maybeEncryptTreeJSON(data, tree, aad)
   506		if err != nil {
   507			return fmt.Errorf("encrypt config: %w", err)
   508		}
   509	
   510		// Wrap the (possibly-encrypted) body in the config compatibility
   511		// envelope (#1917 increment B). The magic header line makes a pre-floor
   512		// reader fail closed (its json.Unmarshal rejects a leading '#'), so a
   513		// future format bump can never silently empty-load on an old reader.
   514		// committed stamps the #1922 step-0 marker.
   515		out := make([]byte, 0, len(header)+len(data))
   516		out = append(out, header...)
   517		data = append(out, data...)
   518	
   519		// Owner-only 0600 (#4056): active.json / candidate.json /
   520		// rollback.N.json carry the full config, including secret leaves (IKE
   521		// PSK, WireGuard/auth keys, SNMP community). When master-password is
   522		// set the body is AES-GCM encrypted, but when it is not the secrets are
   523		// cleartext — either way the DB must not be world-readable. The daemon
   290		// the foreign/non-appliance host case (noted in the PR; not implemented
   291		// here).
   292		// configCompileFailed records the #1960 fail-closed case: a PRESENT,
   293		// previously-committed active.json read+parsed fine but no longer
   294		// compiles. It must NOT fall back to bootstrapFromFile() (which would
   295		// blind-import the text config file over a broken-but-present committed
   296		// DB — the same silently-wrong takeover this issue closes) and it forces
   297		// bootstrap mode below regardless of computeBootClass's other inputs.
   298		configCompileFailed := false
   299		switch loadErr := d.store.Load(); classifyLoadError(loadErr) {
   300		case loadFatalUnreadable:
   301			// Point recovery at the actual unreadable artifact — the config
   302			// DB under .configdb/, NOT the text config file (Copilot).
   303			dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
   304			return false, fmt.Errorf("config DB is present but unreadable; refusing to "+
   305				"start and overwrite it (fail closed). Inspect/repair %s (the on-disk "+
   306				"config DB, NOT the text config file) or roll the xpf binary forward "+
   307				"to a build that can read it: %w",
   308				dbPath, loadErr)
   309		case loadCompileFailed:
   310			// #1960 fail-closed: a previously-committed config no longer
   311			// compiles. Store.Load set everCommitted=true but left compiled
   312			// nil, so without this the boot predicate would resolve to NORMAL
   313			// (ActiveConfig()==nil + everCommitted) and run the positional
   314			// claim-all interface rename — exactly the safety hole this fixes.
   315			// Surface it LOUDLY (Error, not the ignored Warn) and route into
   316			// the #1922 bootstrap/lifeline safe state below.
   317			configCompileFailed = true
   318			dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
   319			slog.Error("active config DB is present but no longer compiles; refusing interface "+
   320				"takeover and entering BOOTSTRAP/lifeline safe state (management preserved, NO "+
   321				"positional claim-all). Fix the config from the CLI/gRPC and 'commit confirmed', "+
   322				"or repair/remove the on-disk config DB",
   323				"db_path", dbPath, "err", loadErr)
   324		case loadOtherError:
   325			slog.Warn("failed to load config from db", "err", loadErr)
   326		case loadOK:
   327			// nil error: absent DB (start-fresh) or a valid loaded config.
   328		}
   329	
pkg/daemon/bootstrap.go:37:	// loadFatalUnreadable — ErrConfigDBUnreadable (#1917 D1): present but
pkg/daemon/bootstrap.go:40:	loadFatalUnreadable
pkg/daemon/bootstrap.go:53:func classifyLoadError(err error) loadErrorClass {
pkg/daemon/bootstrap.go:57:	case errors.Is(err, configstore.ErrConfigDBUnreadable):
pkg/daemon/bootstrap.go:58:		return loadFatalUnreadable
pkg/daemon/bootstrap.go:242:	// reachable path (Load already returned ErrConfigDBUnreadable and Run
pkg/daemon/daemon_run_bringup.go:300:	case loadFatalUnreadable:
    40	// MaxConfigSize bounds a single configuration payload accepted by any parse
    41	// entry point: LoadOverride, LoadMerge, LoadSet, and the HA SyncApply ingress.
    42	// Real configurations are well under 1 MiB; this generous 16 MiB ceiling
    43	// rejects a hostile or corrupt payload with a clean error before the parser
    44	// runs, so a pathological input cannot exhaust memory or (together with the
    45	// pkg/config lexer/depth guards) the goroutine stack. It is the
    46	// transport-independent backstop for the grpc.MaxRecvMsgSize / http
    47	// .MaxBytesReader caps, covering any caller — a future one, or an HA peer —
    48	// that reaches these methods without passing through the gRPC/REST limits
    49	// (fable-review-164 H-2).
    50	const MaxConfigSize = 16 << 20 // 16 MiB
    51	
    52	// checkConfigSize rejects an over-large payload before it reaches the parser.
    53	func checkConfigSize(content string) error {
    54		if len(content) > MaxConfigSize {
    55			return fmt.Errorf("config too large: %d bytes exceeds maximum %d bytes",
    56				len(content), MaxConfigSize)
    57		}
    58		return nil
    59	}
    60	
    61	// Store manages the candidate and active configuration.
    74		// packedStatements opts a CONTAINER into having its packed tail split into
    75		// one child per STATEMENT by the brace-elision fold (#8768), instead of the
    76		// whole run becoming a single child.
    77		//
    78		// It is OPT-IN and defaults off, for two measured reasons.
    79		//
    80		// Splitting changes what a packed run lowers to, and at least one container
    81		// has a gate that depends on the current lowering: the NAT `then` family
    82		// rejects a packed cross-mode contradiction with a check that exists
    83		// PRECISELY BECAUSE `pool <p> off` lowers to one action and cannot be
    84		// counted (#7033). Two earlier attempts to fix that class in the lowering
    85		// were reverted; splitting `source-nat` would be a third.
    86		//
    87		// And splitting is only possible where the schema models the tail. The fold
    88		// consumes each statement with consumeNodeKeys and stops the moment a token
    89		// leaves the modelled grammar, so a container whose leaves take values the
    90		// schema does not describe cannot be split even if it opts in — `ike policy
    91		// <p> pre-shared-key ascii-text <v> mode main` is one: `ascii-text` is not
    92		// modelled, so the tail is returned whole and `mode main` stays swallowed.
    93		//
    94		// So a container opts in after someone measures that its packed and braced
    95		// spellings compile identically once split, one container at a time. That
    96		// is the same discipline the #8690 scope list arrived at.
    97		packedStatements bool
    98	

exec
/bin/bash -lc "rg -n 'func.*blind|8859|64|43|18|pair|resist|inert' pkg/config/*sweep*test.go pkg/config/*blind*test.go | head -95; nl -ba pkg/routing/vrf.go | sed -n '180,238p'; rg -n '\"routing-instances\"|routingInstanceSchema|routingInstancesSchema|\"instance-type\"' pkg/config/schema_routing.go | head -30; git diff b24e26d3b HEAD --stat; git show a7f84a209 -- pkg/config/schema_security.go pkg/config/compact_normalize_8662.go" in /var/tmp/RES8865
 succeeded in 0ms:
pkg/config/compact_scope_blind_pairs_8852_test.go:10:// #8852: a scope widening whose pair yields ZERO census sites is
pkg/config/compact_scope_blind_pairs_8852_test.go:20:// So admitting a pair whose HEAD is a plain container, a zero-arg leaf, or a
pkg/config/compact_scope_blind_pairs_8852_test.go:21:// multi-arg node produces no site at all — the pair is adjudicated by nothing,
pkg/config/compact_scope_blind_pairs_8852_test.go:26:// MEASURED. #8847 admitted three top-level pairs and arm 2 adjudicated NONE of
pkg/config/compact_scope_blind_pairs_8852_test.go:32:// when its actual pair is ("static","route"), because the arm derives
pkg/config/compact_scope_blind_pairs_8852_test.go:33:// `stanza := container[len-1]`. A site's path prefix is not its pair.
pkg/config/compact_scope_blind_pairs_8852_test.go:37:// NEW blind pair reds, and a pair that BECOMES adjudicated also reds, so the
pkg/config/compact_scope_blind_pairs_8852_test.go:40:// become a silent escape hatch — you cannot park a pair here with a reason that
pkg/config/compact_scope_blind_pairs_8852_test.go:41:// is not true of its node. And a pair blind for NO recognised structural reason
pkg/config/compact_scope_blind_pairs_8852_test.go:44:// Registering a pair here is NOT a statement that its folding is correct. It
pkg/config/compact_scope_blind_pairs_8852_test.go:51:// BLINDNESS IS DURABLE: a pair is here because arm 2's census emits no site for
pkg/config/compact_scope_blind_pairs_8852_test.go:78:// sound method. Fixed by 648ff4690 ("fold a packed tail even when the node has
pkg/config/compact_scope_blind_pairs_8852_test.go:93:// pairs arm 2 adjudicates nothing for. A pair leaves only when the census
pkg/config/compact_scope_blind_pairs_8852_test.go:119:func blindShape8852(n *schemaNode) string {
pkg/config/compact_scope_blind_pairs_8852_test.go:137:	// on container[len-1] verbatim makes almost every named-instance pair look
pkg/config/compact_scope_blind_pairs_8852_test.go:171:		t.Fatal("DEGENERACY: no admitted pair was reachable in the schema, so " +
pkg/config/compact_scope_blind_pairs_8852_test.go:192:	// A pair blind for no recognised structural reason is a census bug, not a
pkg/config/compact_scope_blind_pairs_8852_test.go:196:		t.Errorf("%d admitted pair(s) yield NO census site for a reason this "+
pkg/config/compact_scope_blind_pairs_8852_test.go:198:			"single-arg valued leaf or a named-instance container. A pair "+
pkg/config/compact_scope_blind_pairs_8852_test.go:210:		t.Errorf("the set of admitted pairs arm 2 adjudicates NOTHING for has "+
pkg/config/compact_scope_blind_pairs_8852_test.go:214:			"measure at all — it is green and silent about that pair, which is "+
pkg/config/compact_scope_blind_pairs_8852_test.go:216:			"means a pair became adjudicated and its registration must go, so "+
pkg/config/compact_scope_blind_pairs_8852_test.go:222:	// The registered reason is RE-DERIVED and compared, so a pair cannot be
pkg/config/compact_scope_blind_pairs_8852_test.go:230:			t.Errorf("blind pair %q is registered as %q but its schema node is "+
pkg/config/compact_scope_blind_pairs_8852_test.go:237:	t.Logf("#8852: %d admitted pairs, %d with >=1 adjudicated site, %d blind (all registered)",
pkg/config/nat_source_axis_sweep_6812_test.go:40:// today; repaired at the reflect.Map arm, where the reasoning is written down.
pkg/config/nat_source_axis_sweep_6812_test.go:400:func axisUintKey6812(u uint64) string { return fmt.Sprintf("%020d", u) }
pkg/config/nat_source_axis_sweep_6812_test.go:401:func axisIntKey6812(i int64) string   { return axisUintKey6812(uint64(i) + 1<<63) }
pkg/config/nat_source_axis_sweep_6812_test.go:430:	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
pkg/config/nat_source_axis_sweep_6812_test.go:432:	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
pkg/config/nat_source_axis_sweep_6812_test.go:442:			var nanos int64
pkg/config/nat_source_axis_sweep_6812_test.go:485:		add(path+".len", axisLeaf6812(present, axisUintKey6812(uint64(v.Len()))))
pkg/config/nat_source_axis_sweep_6812_test.go:496:		add(path+".len", axisLeaf6812(present, axisUintKey6812(uint64(v.Len()))))
pkg/config/nat_source_axis_sweep_6812_test.go:545:// that the repaired form separates it.
pkg/config/nat_source_axis_sweep_6812_test.go:576:// axisEncodeMap6812 renders a map as its SORTED (key, value) pairs.
pkg/config/nat_source_axis_sweep_6812_test.go:706:	//	POPULATION A, CELLS (sweep x column):  186 = 29 guarded + 139
pkg/config/nat_source_axis_sweep_6812_test.go:707:	//	                                       fixture-constant + 18 prod-constant
pkg/config/nat_source_axis_sweep_6812_test.go:718:	// universe that grew from 108 cells to 186. Nothing became blind. The
pkg/config/nat_source_axis_sweep_6812_test.go:784:	ChargeAddrs   uint64
pkg/config/nat_source_axis_sweep_6812_test.go:785:	ChargePortCap uint64
pkg/config/nat_source_axis_sweep_6812_test.go:900:			"(compiler_nat_pool_ref_5626_test.go:164), so `Pool` CAN be nil for a config "+
pkg/config/nat_source_axis_sweep_6812_test.go:981:		"#8430 compile-time diagnostic state: whether the rule AUTHORED a `match` "+
   180	// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
   181	// tracked set. Similarly, LinkDel failures retain ownership. This
   182	// ensures a future reconcile can retry.
   183	func reconcileVRFs(ops vrfOps, tracked []string, desired []VRFSpec) ([]string, error) {
   184		desiredByName := make(map[string]int, len(desired))
   185		for _, spec := range desired {
   186			desiredByName["vrf-"+spec.Name] = spec.TableID
   187		}
   188		managed := make(map[string]bool, len(tracked))
   189		for _, name := range tracked {
   190			managed[name] = true
   191		}
   192	
   193		var firstErr error
   194		recordErr := func(err error) {
   195			if err != nil && firstErr == nil {
   196				firstErr = err
   197			}
   198		}
   199		newTracked := make([]string, 0, len(desired))
   200	
   201		for _, spec := range desired {
   202			vrfName := "vrf-" + spec.Name
   203			link, kerErr := ops.LinkByName(vrfName)
   204	
   205			if kerErr != nil {
   206				if !isLinkNotFound(kerErr) {
   207					// Transient netlink error — don't assume the VRF is
   208					// absent and don't attempt to create it. Next
   209					// reconcile will retry. CRUCIALLY: if this name was
   210					// already in v.vrfs, retain ownership — otherwise a
   211					// transient blip would silently drop us from the
   212					// managed set and IsManaged would start lying.
   213					if managed[vrfName] {
   214						newTracked = append(newTracked, vrfName)
   215					}
   216					recordErr(fmt.Errorf("lookup VRF %s: %w", vrfName, kerErr))
   217					continue
   218				}
   219				// Genuinely not in kernel — create it.
   220				added, err := createLinkedVRF(ops, vrfName, spec.TableID)
   221				if added {
   222					newTracked = append(newTracked, vrfName)
   223				}
   224				recordErr(err)
   225				continue
   226			}
   227	
   228			// Present in kernel. Adopt it — the vrf-<desired-name>
   229			// namespace is ours, regardless of who created the device.
   230			currentTable := vrfTable(link)
   231			if currentTable == uint32(spec.TableID) {
   232				if err := ops.LinkSetUp(link); err != nil {
   233					slog.Debug("VRF set-up failed (non-fatal)", "name", vrfName, "err", err)
   234				}
   235				newTracked = append(newTracked, vrfName)
   236				continue
   237			}
   238	
827:	"instance-type": {desc: "Routing instance type", args: 1, placeholder: "<type>", children: nil},
 docs/research/8865-muse-spark-008-009/plan.md     | 153 ++++++++++++++++++++++
 pkg/config/compact_scope_blind_pairs_8852_test.go |  73 +++++++----
 2 files changed, 201 insertions(+), 25 deletions(-)
commit a7f84a20923a96b58ab66ec168e4609b7d94339a
Author: Paul Saab <paul.m.saab@gmail.com>
Date:   Sat Sep 5 02:39:45 2026 -0700

    security: declare `keys` under perfect-forward-secrecy (#8844)
    
    `security ipsec policy <p> perfect-forward-secrecy keys <group>;` -- the
    brace-elided spelling -- silently DISABLED PFS:
    
      braced   perfect-forward-secrecy { keys group14; }   PFSGroup=14
      packed   perfect-forward-secrecy keys group14;       PFSGroup=0
      absent   (no stanza)                                 PFSGroup=0
    
    The #8800 shape: `perfect-forward-secrecy` was declared `children: nil`
    while compileIPsec reads a `keys` CHILD of it, so the head was not a
    schema child, the brace-elision pass was never ASKED about the pair, and
    no scope entry could have named it. The schema's own desc -- "Perfect
    forward secrecy (keys group<N>)" -- documented the child it failed to
    declare.
    
    WHY THIS ONE IS DIFFERENT FROM THE REST OF ITS FAMILY. Every other
    member fails CLOSED or LOUD: #8800's zero-address NAT pool is rejected
    at strict commit, #8825's empty application-set is caught by the #3146
    gate. This one fails OPEN and is undetectable afterwards, because
    PFSGroup==0 is a legitimate value meaning "deliberately disabled" -- no
    downstream gate can distinguish "operator chose no PFS" from "operator
    configured PFS and we dropped it". The tunnel comes up, traffic flows,
    and a later compromise of long-term keys retroactively decrypts every
    session negotiated meanwhile. The operator meanwhile has positive
    evidence it worked: the stanza is in the file, the commit succeeded, and
    `show configuration` displays it.
    
    Two-part remedy, both required, as measured on #8800: declare `keys` so
    the pass ASKS, and admit ("perfect-forward-secrecy","keys") in
    compactNormalizeInScope so it says yes.
    
    NO VALIDATOR ON `keys`, deliberately. parseDHGroup accepts `group<N>` or
    a bare integer and leaves PFSGroup at 0 otherwise, so validating here
    would newly REJECT a value the tolerant Load path accepts today.
    The bad-value route to a silent disable is a SEPARATE question from the
    spelling route this fixes, and the guard pins it as known-and-unfixed so
    nobody reads this as closing the whole surface.
    
    The guard carries a baseline arm (the pair masked AND
    skipCompactNormalize, since the pass also runs inside
    compileConfigWithOpts and a pre-normalised tree is not a baseline on its
    own) and a degeneracy control: absent must still be 0, or a fix that
    hard-coded a non-zero default would satisfy every other assertion.
    
    Found by the #8830 behavioural predicate after correcting a defect in
    the probe itself -- it had compared only the FIRST value pair, so a leaf
    needing a type-specific value looked inert. #7484's wordInert already
    tried every pair with a comment saying why.
    
    Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01Nyps5vzpffdfem9WCUMZKC

diff --git a/pkg/config/compact_normalize_8662.go b/pkg/config/compact_normalize_8662.go
index 1443acb2d..19085df4f 100644
--- a/pkg/config/compact_normalize_8662.go
+++ b/pkg/config/compact_normalize_8662.go
@@ -1249,6 +1249,7 @@ func compactNormalizeInScope(containerKeyword, head string) bool {
 		"policy description",
 		"policy mode",
 		"policy proposals",
+		"perfect-forward-secrecy keys",
 		"policy-stats system-wide",
 		"pool address",
 		"pool port-overloading-factor",
diff --git a/pkg/config/schema_security.go b/pkg/config/schema_security.go
index 7ad9da2cf..1594e6c69 100644
--- a/pkg/config/schema_security.go
+++ b/pkg/config/schema_security.go
@@ -1194,7 +1194,30 @@ var schemaSecurity = &schemaNode{desc: "Security configuration", children: map[s
 			"description": {desc: "Proposal description", args: 1, scalar: true, placeholder: "<text>", children: nil},
 		}},
 		"policy": {desc: "IPsec policy name", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
-			"perfect-forward-secrecy": {desc: "Perfect forward secrecy (keys group<N>)", children: nil},
+			// #8844: `keys` was NOT declared while compileIPsec reads it as a child
+			// (compiler_ipsec.go, `case "perfect-forward-secrecy"` iterates
+			// p.Children for "keys"). The desc above already documented the child
+			// it failed to declare. Undeclared meant the head was not a schema
+			// child, the brace-elision pass was never ASKED about the
+			// ("perfect-forward-secrecy","keys") pair, and the packed spelling
+			// `perfect-forward-secrecy keys group14;` produced PFSGroup=0 --
+			// byte-identical to never configuring PFS at all.
+			//
+			// This is the #8800 shape failing in the INSECURE direction. The other
+			// members fail closed (a zero-address NAT pool is rejected at strict
+			// commit; an empty application-set is caught by #3146); this one
+			// commits clean with forward secrecy silently off, and no gate can
+			// detect it afterwards because 0 is a legitimate "disabled" value.
+			//
+			// No keyValidator/validator on `keys`: parseDHGroup accepts any
+			// `group<N>` or bare integer and leaves PFSGroup at 0 otherwise, and
+			// validating here would newly REJECT a value the tolerant Load path
+			// accepts today. The silent-disable-by-bad-value route is noted on
+			// #8844 as a separate question from the silent-disable-by-SPELLING
+			// route this fixes.
+			"perfect-forward-secrecy": {desc: "Perfect forward secrecy (keys group<N>)", children: map[string]*schemaNode{
+				"keys": {desc: "Diffie-Hellman group for phase-2 PFS (e.g. group14)", args: 1, placeholder: "<group>", children: nil},
+			}},
 			// multi (#3904): mirror of the IKE proposals leaf — offer every
 			// listed ESP proposal for phase-2 negotiation.
 			"proposals": {desc: "IPsec proposal reference(s)", args: 1, multi: true, placeholder: "<proposal-name>", children: nil},

exec
/bin/bash -lc "nl -ba pkg/config/compiler_validate_strict_routing.go | sed -n '1308,1336p;1362,1394p'; nl -ba pkg/config/compiler_uniformgates_dhcp_app.go | sed -n '120,139p'; rg -n 'func.*Set|func .*LoadMerge|checkConfigSize' pkg/configstore/store_edit.go pkg/configstore/store_commit.go pkg/configstore/store.go | head -45; rg -n 'packedStatements: true' pkg/config/schema*.go" in /var/tmp/RES8865
 succeeded in 0ms:
  1308	// ReservedRedistSuffix is the route-map name suffix xpf RESERVES for the
  1309	// per-use-site fail-closed redistribute aliases the FRR renderer derives
  1310	// (redistFailClosedRouteMap in pkg/frr/policy_render.go emits `name + suffix`).
  1311	// FRR keys route-maps by NAME in a single GLOBAL namespace, so an operator
  1312	// policy-statement whose name ends in this suffix would collide with a
  1313	// generated alias in that shared object and could silently undo the #4481
  1314	// fail-closed BGP/IGP separation — reintroducing route redistribution leakage
  1315	// under a config that otherwise passes validation (#5116). The alias derivation
  1316	// (pkg/frr) and the strict validator below MUST agree on this exact string;
  1317	// pkg/frr references this constant so the two never drift.
  1318	const ReservedRedistSuffix = "-xpf-redist"
  1319	
  1320	// validatePolicyReservedRedistNameStrict hard-rejects an operator
  1321	// policy-statement whose name ends in the reserved ReservedRedistSuffix. That
  1322	// suffix is owned by the FRR renderer's generated fail-closed redistribute
  1323	// aliases (#4481); an operator name in that namespace can collide with a
  1324	// generated alias in FRR's global name-keyed route-map object and silently
  1325	// reintroduce BGP/IGP redistribution leakage (#5116). Reserving the suffix at
  1326	// commit makes the generated-alias namespace injective BY CONSTRUCTION — no
  1327	// legal config can name a policy-statement into the generated slot.
  1328	//
  1329	// Strict on commit / commit-check (hard reject so the reserved name is
  1330	// operator-visible); lenient on load / peer-sync (warn so an already-persisted
  1331	// or peer-synced config an older binary accepted still boots — #1960
  1332	// fail-closed-on-load class). The render-side defense-in-depth (redistAliasCollision
  1333	// in pkg/frr) fails the whole managed-section apply CLOSED on the tolerant path,
  1334	// so a leniently-loaded collision cannot leak. Runs on the fully-compiled
  1335	// *Config so the policy-statement map is populated regardless of authoring
  1336	// order. Mirrors validateRoutingExportReferencesStrict.
  1362	// ReservedChainSuffix is the route-map name suffix xpf RESERVES for the composed
  1363	// BGP policy-chain route-maps the FRR renderer derives for an ordered
  1364	// import/export policy list of length >= 2 (composedChainName in pkg/frr joins
  1365	// the member policy names and appends this suffix). FRR keys route-maps by NAME
  1366	// in a single GLOBAL namespace, so an operator policy-statement whose name ends
  1367	// in this suffix would collide with a generated composed route-map in that
  1368	// shared object and FRR would MERGE the two same-named definitions, silently
  1369	// altering the operator's BGP filtering (#5277/#5442). The composed-name
  1370	// derivation (pkg/frr) and the strict validator below MUST agree on this exact
  1371	// string; pkg/frr re-exports this constant (frr.ReservedChainSuffix =
  1372	// config.ReservedChainSuffix) so the two never drift.
  1373	const ReservedChainSuffix = "-xpf-chain"
  1374	
  1375	// validatePolicyReservedChainNameStrict hard-rejects an operator
  1376	// policy-statement whose name ends in the reserved ReservedChainSuffix. That
  1377	// suffix is owned by the FRR renderer's generated composed BGP policy-chain
  1378	// route-maps (#5277): an ordered import/export chain of length >= 2 is joined
  1379	// and suffixed with ReservedChainSuffix (composedChainName in pkg/frr). An
  1380	// operator name in that suffix namespace can collide with a generated composed
  1381	// route-map in FRR's global name-keyed route-map object; FRR MERGES two
  1382	// same-named route-map definitions, silently altering the operator's BGP
  1383	// filtering (#5442). Reserving the suffix at commit makes the composed-name
  1384	// namespace injective against operator policy-statements BY CONSTRUCTION — no
  1385	// legal config can name a policy-statement into the generated slot.
  1386	//
  1387	// Strict on commit / commit-check (hard reject so the reserved name is
  1388	// operator-visible); lenient on load / peer-sync (warn so an already-persisted
  1389	// or peer-synced config an older binary accepted still boots — #1960
  1390	// fail-closed-on-load class). The render-side defense-in-depth
  1391	// (bgpComposedChainCollision in pkg/frr) fails the whole managed-section apply
  1392	// CLOSED on the tolerant path, so a leniently-loaded collision cannot leak. Runs
  1393	// on the fully-compiled *Config so the policy-statement map is populated
  1394	// regardless of authoring order. Mirrors validatePolicyReservedRedistNameStrict.
   120	
   121		// #5821 reserved application-name gate. The AppID display/filter surface
   122		// (ResolveSessionName / SessionMatches, pkg/appid/runtime.go) uses the
   123		// literal "UNKNOWN" as the "no known application" sentinel and carries a
   124		// user-defined application/application-set name verbatim into the SAME
   125		// flattened string, so a catalog application literally named UNKNOWN
   126		// (case-insensitively, since SessionMatches folds case) is indistinguishable
   127		// from the sentinel — `show ... application UNKNOWN` cannot tell unclassified
   128		// sessions from the configured app, and the destructive `clear ...
   129		// application UNKNOWN` selector could delete both. Reserve the sentinel out
   130		// of the user application/application-set namespace at commit. This is a NEW
   131		// fail-closed restriction that can reject a config an older binary accepted;
   132		// lenient on load / peer-sync (warn so an already-persisted or peer-synced
   133		// config carrying the reserved name still BOOTS — #1960 no-brick), strict on
   134		// commit so the operator's next edit fails loudly.
   135		if err := validateReservedApplicationNamesStrict(cfg); err != nil {
   136			if opts.lenientReservedApplicationNames {
   137				cfg.Warnings = append(cfg.Warnings,
   138					fmt.Sprintf("reserved application name (downgraded to warning on tolerant path): %v", err))
   139			} else {
rg: pkg/configstore/store_edit.go: No such file or directory (os error 2)
pkg/configstore/store.go:52:// checkConfigSize rejects an over-large payload before it reaches the parser.
pkg/configstore/store.go:53:func checkConfigSize(content string) error {
pkg/configstore/store.go:424:func (s *Store) SetConfigDBWriterVersion(v string) {
pkg/configstore/store.go:431:func (s *Store) SetClusterReadOnly(ro bool) {
pkg/configstore/store.go:446:func (s *Store) SetNodeID(id int) {
pkg/configstore/store.go:752:	if err := checkConfigSize(content); err != nil {
pkg/configstore/store_commit.go:365:func (s *Store) SetRollbackExecutor(fn func(gen uint64)) {
pkg/configstore/store_commit.go:1461:		// via checkConfigSize). loadRollbackHistory reads straight off disk
pkg/config/schema_security.go:1016:		"proposal": {desc: "IKE proposal name", args: 1, placeholder: "<proposal-name>", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
pkg/config/schema_security.go:1042:		"policy": {desc: "IKE policy name", args: 1, placeholder: "<policy-name>", packedStatements: true, children: map[string]*schemaNode{
pkg/config/schema_security.go:1079:		"gateway": {desc: "IKE gateway (VPN peer) name", args: 1, placeholder: "<gateway-name>", packedStatements: true, children: map[string]*schemaNode{
pkg/config/schema_security.go:1109:			"dead-peer-detection": {desc: "Dead peer detection", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
pkg/config/schema_security.go:1163:		"proposal": {desc: "IPsec (Phase 2) proposal name", args: 1, placeholder: "<proposal-name>", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
pkg/config/schema_security.go:1246:		"gateway": {desc: "IKE gateway (VPN peer) name", args: 1, packedStatements: true, placeholder: "<gateway-name>", children: map[string]*schemaNode{
pkg/config/schema_security.go:1354:			"vpn-monitor": {desc: "Tunnel liveness monitoring (accepted-but-not-enforced advisory)", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
pkg/config/schema_system.go:1243:	"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", packedStatements: true, children: map[string]*schemaNode{

exec
/bin/bash -lc "rg --files --hidden -g '"'!**/.git/**'"' -g '"'!**/node_modules/**'"' /tmp 2>/dev/null | rg '/["'^/]*(muse|spark|8830|8865|008|009)[''^/]*$'"' | head -70; nl -ba pkg/configstore/db.go | sed -n '477,534p'; nl -ba pkg/config/schema_security.go | sed -n '43,80p'; rg -n 'case \"security-zone\"|case \"screen\"|case \"description\"|case \"interfaces\"' pkg/config/compiler_security_zones.go | head -30; rg -n 'len\\(.*[Cc]ount|count :=|Count :=|num[A-Z].*:=|make\\(\\[\\].*,.*count|make\\(\\[\\].*,.*num' pkg/cluster --glob '*.go' --glob '"'!**/*test.go'"' | head -60" in /var/tmp/RES8865
 succeeded in 0ms:
/tmp/muse-spark-review-009.md
/tmp/muse-architect-design-check.out
/tmp/muse-mode-results.zy5ExM.tsv
/tmp/muse-mode-results.VzeoSF.tsv
/tmp/muse-mode-results.YJhjU8.tsv
/tmp/muse-support-results.tdVkEe.tsv
/tmp/review-work-codex-001/muse-delta-status.tsv
/tmp/review-work-codex-001/muse-current-source-delta.txt
/tmp/nat8800-review/cache/00/00887862974b5a7f22314b8cedea6267039f5206a452f0e01dc3891902621d28-a
/tmp/nat8800-review/cache/07/07ccff9148914710129700c4af0a5aac6b1141cdf8d00093fc312ccee47aa98c-a
/tmp/nat8800-review/cache/09/090cffb2691f19bfc41ade1a1d642b888305a26d882eb974c7608b61fe20a92e-a
/tmp/nat8800-review/cache/09/0989a200982d4bb7aa2220d9848c90e3c4ea7858e0f80081133e5b0f30c69140-a
/tmp/nat8800-review/cache/0b/0ba98d3ab578fbcbac5f0c2c87fe5d0270098e57c9b41a703ca1587c64405d4d-a
/tmp/nat8800-review/cache/0f/0fc1d5ebb9346847f42c10008038d67c0c7be8f05b0be436a9159837cae4d53a-a
/tmp/muse-spark-review-007.md
/tmp/nat8800-review/cache/18/18bfe4a155d7b0ba71161bb2bad77b99d174638bba59e65a2b0de366008679b2-a
/tmp/nat8800-review/cache/1f/1f550bf39c668c4f52d04e9b6ce09008515c0112011634d99ac794a9ed3e1a3f-a
/tmp/review-work.bwyxqLum9b/muse-spark-review-009.draft.md
/tmp/nat8800-review/cache/29/295d24c7c6c3e82ee9eb3dcf5008df244fc1f99ce881d5c6155ade26842b2e63-d
/tmp/nat8800-review/cache/31/31441ac2f9abee00284744ed58f795a2280b533c462badf09b008d8b06ad24f7-d
/tmp/nat8800-review/cache/fd/fdff8fa0c772b77cfe96c3d092efe3d1821a67421a9bde878e729ca008972d8a-a
/tmp/nat8800-review/cache/36/366752e20608703e1e096cdda3b402cd2ec5376c5fe2343ce096325b17009e06-a
/tmp/nat8800-review/cache/37/3710824a62687967a4ddba1730f6dff5af0a491245b8f0094aef45834a4110c8-a
/tmp/nat8800-review/cache/39/39d46a971910322e4d6f7b2b4009b26b9244a9611cbaa77623a5208051fd57fd-a
/tmp/nat8800-review/cache/49/492a20ad737cfadbc60e5d18b3344b4899a49a6c418300808a33b05fd31501eb-a
/tmp/nat8800-review/cache/4d/4d9f2f3c6b30854cf80ee00927c5d4a02c244693df25326bf53f760c0a5d0d4c-d
/tmp/nat8800-review/cache/4d/4dfef7d5d291c86ca6c480d27818bb9a65850b0a6c98131cf8a77900805e899f-d
/tmp/nat8800-review/cache/55/55a7d5c8aab0d33bd44648500350147a1413d5520087b8d2fc7c26be3029de07-a
/tmp/nat8800-review/cache/61/61ad084008197a4cedadc0b60f55a4f14b8abdba7e47289e63c6b4734ee2e640-a
/tmp/nat8800-review/cache/64/64ca7a9090b7d43a84678f5ed3284917fa50d28c53f963e5700829396f358468-d
/tmp/nat8800-review/cache/67/67951135147a2ca970e53fc9e25f95d10094a7e0a2e6042137cab0da188f4fd0-a
/tmp/nat8800-review/cache/69/6961c1b1aca355d6205c70c38defb1b99674b1aa26b1b588a45bc9f009d23178-d
/tmp/nat8800-review/cache/6d/6dbdab9bfbfa370fae41f06bf38da008e9682364f0f41b27f6ed11baa3d08422-d
/tmp/nat8800-review/cache/74/744b00d26675b207b93e46bc03aa65b8cd917f1c510eadc40886a2cb95009316-d
/tmp/nat8800-review/cache/7b/7bbe62005128bd009275705c8250a1dcee47889955695b6b975960ea63cb17dd-a
/tmp/nat8800-review/cache/7d/7d069fab62e140096512af56c47a7f64dac5c5da5d5af1b7225af92857a85ba2-a
/tmp/nat8800-review/cache/82/8281172e295373690885008226d1fc80e680aae0ab2223917808561d9cd43831-d
/tmp/nat8800-review/cache/86/86242909799ec6caad43d0b5c5b7ef49a6c0e30fdec8df90090c755f6e2a7d77-d
/tmp/nat8800-review/cache/92/92a9646dd010093fc109ccea78b83720c9556f1172b15c79cbe925f544cbdd89-a
/tmp/nat8800-review/cache/93/938ac5303d39af009ef710f52f0af4b00f9192b0b63e63454baa24db233ed087-a
/tmp/nat8800-review/cache/95/95200877904312d8654a744fd72112ce39f6eca2110e7a7b7811afc3ddece1ee-a
/tmp/nat8800-review/cache/d2/d25f54f1d57e3c36a591f0bc32ebc50099ae7ca8ea6a8060e1a08584b6071a66-a
/tmp/nat8800-review/cache/da/da2d812a215dcf9deb1e314771e7222666a0194d5d4b2fd4b8234d272009151c-a
/tmp/nat8800-review/cache/ab/abe9ef16916a579c923495de71e1aeaf1f398bed5c0a132e0bbcbb78720dd008-a
/tmp/nat8800-review/cache/ac/ac2809d5160e693f626b7996781eb337ae080efd594a372b20ea00984d228a1a-a
/tmp/nat8800-review/cache/e7/e7afcad9eeb050ca1057c18bcb46087c82008c6dfa9e9dde35d292fe80425d79-a
/tmp/nat8800-review/cache/e8/e81f1475ddced4d8c576963ed040b8ae995062009f96d1d333107154fca8e86f-a
/tmp/nat8800-review/cache/b2/b262cb22c4eff1d64c96ddf8719ca200867be13206eecc14a96f964ebbe32d6e-a
/tmp/muse-spark-review-008.md
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/anchors/A-C008-8425.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/anchors/A-C008-8622.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/anchors/A-C009-6457.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/anchors/A-C009-8576.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/anchors/A-C009-8586.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/anchors/A-C009-8610.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/query-results/C008.tsv
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/derived-G002/query-results/C009.tsv
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0008.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/hostile-R0008.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0009.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/hostile-R0009.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0080.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/hostile-R0080.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0081.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/hostile-R0081.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0082.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/hostile-R0082.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0083.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/hostile-R0083.txt
/tmp/review-cache-claude-opus-003/w0m-validation/dev-closure-1/sidecars/root-source-R0084.txt
   477	func (db *DB) writeTreeMarked(path string, tree *config.ConfigTree, committed bool) error {
   478		data, err := json.MarshalIndent(tree, "", "  ")
   479		if err != nil {
   480			return fmt.Errorf("marshal config: %w", err)
   481		}
   482		// #7176 (C179-053): the header must exist BEFORE the seal, because it IS
   483		// the AAD. Encryption-ness is known here (the same predicate
   484		// maybeEncryptTreeJSON uses), which also lets min-reader be exact: only an
   485		// ENCRYPTED v2 envelope is unreadable by a pre-v2 build, so only that case
   486		// raises the floor. An unencrypted v2 envelope has no ciphertext to bind
   487		// and stays readable by an older reader — stamping min-reader=2 on it would
   488		// refuse a downgrade for no reason.
   489		//
   490		// The alternative — leaving min-reader at 1 always — is also fail-closed,
   491		// but an old build would report an opaque "decrypt config tree" failure
   492		// instead of the envelope layer's explicit "too new" message. A confusing
   493		// error during a rollback is the worst time for one.
   494		encrypted := masterPasswordPRF(tree) != ""
   495		minReader := EnvelopeMinReaderVersion
   496		if encrypted {
   497			minReader = envelopeAADFormatVersion
   498		}
   499		header := buildEnvelopeHeaderLine(db.writerVersion, committed, minReader)
   500	
   501		var aad []byte
   502		if encrypted {
   503			aad = header
   504		}
   505		data, err = db.maybeEncryptTreeJSON(data, tree, aad)
   506		if err != nil {
   507			return fmt.Errorf("encrypt config: %w", err)
   508		}
   509	
   510		// Wrap the (possibly-encrypted) body in the config compatibility
   511		// envelope (#1917 increment B). The magic header line makes a pre-floor
   512		// reader fail closed (its json.Unmarshal rejects a leading '#'), so a
   513		// future format bump can never silently empty-load on an old reader.
   514		// committed stamps the #1922 step-0 marker.
   515		out := make([]byte, 0, len(header)+len(data))
   516		out = append(out, header...)
   517		data = append(out, data...)
   518	
   519		// Owner-only 0600 (#4056): active.json / candidate.json /
   520		// rollback.N.json carry the full config, including secret leaves (IKE
   521		// PSK, WireGuard/auth keys, SNMP community). When master-password is
   522		// set the body is AES-GCM encrypted, but when it is not the secrets are
   523		// cleartext — either way the DB must not be world-readable. The daemon
   524		// runs as the owner, so 0600 does not affect read-back.
   525		if err := fsatomic.WriteFileDurable(path, data, 0600); err != nil {
   526			return fmt.Errorf("persist %s: %w", path, err)
   527		}
   528		return nil
   529	}
    43		syslogFacilities = []string{
    44			"auth", "change-log", "daemon", "kern",
    45			"local0", "local1", "local2", "local3",
    46			"local4", "local5", "local6", "local7",
    47			"syslog", "user",
    48		}
    49		syslogCategories = []string{"all", "firewall", "policy", "screen", "session"}
    50	)
    51	
    52	// securitySessionLogModes is the fixed set of session-logging tokens accepted
    53	// by every session-log LIST surface (#3703): the per-policy `then log`, the
    54	// deny-collapsed `then deny log`, `default-policy-log`, and
    55	// `pre-id-default-policy then log`. It is the SSOT shared by the schema
    56	// (sessionLogModeLeaf below) and the compiler readers (session log values are
    57	// accumulated via firewallMatchValues and matched against these tokens).
    58	var securitySessionLogModes = []string{"session-init", "session-close"}
    59	
    60	// sessionLogModeLeaf builds the shared multi-value enum leaf for a session-log
    61	// list surface (#3703). Before this the four surfaces modeled `log` /
    62	// `default-policy-log` as CONTAINERS with session-init / session-close
    63	// children, so a bracket / single-line list (`then log [ session-init
    64	// session-close ]`) mis-nested the tail under the first token and the compiler
    65	// readers dropped everything after session-init (the #2419 collapse class,
    66	// unfixed on these leaves). Modeled here as a `multi && children == nil` typed
    67	// enum leaf so:
    68	//   - SetPath collapses ALL list values onto the one leaf's Keys (ast_edit.go
    69	//     absorbs trailing non-sibling tokens for a multi value-tail leaf), and
    70	//   - SchemaValidate (validateMultiValueLeaf) rejects an UNKNOWN token at
    71	//     commit-check — strict on the operator commit path, downgraded to a
    72	//     warning on the tolerant load / peer-sync path (#1960 no-brick) — instead
    73	//     of the token being silently swallowed.
    74	//
    75	// children MUST stay nil: both the SetPath collapse (ast_edit.go:260) and the
    76	// validateMultiValueLeaf dispatch (schema_walk.go:256) key on children == nil.
    77	// The value-slot `?` completion surfaces the two modes via valueExamples, so
    78	// dropping the container children does not lose completion coverage.
    79	func sessionLogModeLeaf(desc string) *schemaNode {
    80		return &schemaNode{
209:			case "interfaces":
382:			case "screen":
396:			case "description":
pkg/cluster/heartbeat.go:317:	numMon := 0
pkg/cluster/heartbeat.go:370:	numGroups := int(data[8])
pkg/cluster/heartbeat.go:376:	pkt.Groups = make([]HeartbeatGroup, numGroups)
pkg/cluster/heartbeat.go:395:		numMonitors := int(data[off])
pkg/cluster/sync_failover.go:13:	if len(rgIDs) > maxFailoverBatchRGCount {
pkg/cluster/sync_failover.go:14:		return fmt.Errorf("too many redundancy groups in failover batch: %d > %d", len(rgIDs), maxFailoverBatchRGCount)
pkg/cluster/status.go:412:		bulkCount := syncStats.BulkSyncs
pkg/cluster/sync_protocol.go:1213:	count := int(binary.LittleEndian.Uint32(payload[:4]))
pkg/cluster/sync_protocol.go:1222:	// count is always <= len(payload)/4). Clamping count also bounds the loop.
pkg/cluster/sync_protocol.go:1227:	if maxRecords := len(payload) / 4; count > maxRecords {
pkg/cluster/sync_protocol.go:1231:	out := make([]dhcpserver.SyncLease, 0, count)
pkg/cluster/sync_persistent_nat_lease_8121.go:116:	count := int(binary.LittleEndian.Uint32(buf))
pkg/cluster/sync_persistent_nat_lease_8121.go:127:	// after the count can hold at most (len(buf)-4)/4 of them. A count above
pkg/cluster/sync_persistent_nat_lease_8121.go:149:	if maxRecords := (len(buf) - 4) / 4; count < 0 || count > maxRecords {
pkg/cluster/sync_persistent_nat_lease_8121.go:152:	out := make([]userspace.IdleLeaseWire, 0, count)
pkg/cluster/sync.go:1358:	count := int(payload[0])
pkg/cluster/sync.go:1362:	if len(payload) < 1+count+8 {
pkg/cluster/sync.go:1365:	rgIDs := make([]int, 0, count)
pkg/cluster/sync.go:1390:	count := int(payload[0])
pkg/cluster/sync.go:1394:	if len(payload) < 1+count+1+8 {
pkg/cluster/sync.go:1397:	rgIDs := make([]int, 0, count)
pkg/cluster/heartbeat_auth_replay.go:57:	// stays at len(marks) and next cycles, so marks[:count] still spans every
pkg/cluster/sync_conn_read.go:101:			count := s.stats.BulkSyncSessions.Add(1)
pkg/cluster/sync_conn_read.go:136:			count := s.stats.BulkSyncSessions.Add(1)

exec
/bin/bash -lc "rg -n '"'^#{1,5} |[Bb]ase|[Cc]ommit|109|findings|reviewed|exclud|[a-f0-9]{9,40}'"' /tmp/muse-spark-review-008.md | head -160; nl -ba /tmp/muse-spark-review-009.md | sed -n '1,235p'" in /var/tmp/RES8865
 succeeded in 0ms:
1:# Deep review — kill campaign UPFNnV6ltt (final report)
3:- Run ID: `UPFNnV6ltt` | Base: `c16a9b12a` | Verify tip: `29d9cb196` (= origin/master at verify time; only a test-only commit sits above it now)
5:- Verdict: **109 findings, all OPEN and UNFIXED (review only; no source changed) — 11 High, 59 Medium, 39 Low.**
6:  (Rounds: R1 = 39 at verify-tip `29d9cb196`; R2 at tip `feaa31b2e`: +26; R3 at tip `5184c40fe`: +13;
7:  R4 at tip `72957962b`: +18; R5 at tip `0c57c0c87`: G1 = +1, G2 = +5, G3 = +3, orchestrator follow-ups = +3. All batches complete.)
12:## Method (why the count is 37 and not 100)
20:- Tip verification (this session, worktree `/tmp/review-work.UPFNnV6ltt/wt-verify` @ `29d9cb196`,
21:  left clean): base→tip diff is 15 files, all in `pkg/config` + docs. Every `pkg/config`-linked
24:  every other High/Medium cites files byte-identical between base and tip, confirmed by diff-scope
26:- Notable tip interaction: #8798 (`3fc95c0bd`, gateway packedStatements opt-in) fixed #8796 but does
29:## HIGH findings (5)
31:### H1 (A3b1-F1) — Multi-statement compact tail drops the zone screen profile; strict-clean fail-open
34:  `description` and never sees `screen`. Strict commits clean with `ScreenProfile=""`.
40:### H2 (A3b1-F2) — Same lossy fold drops the zone interface binding AND evades the strict undefined-interface rejection
42:- Mechanism: elided `security-zone z1 description hi interfaces ge-0-0-0;` (undefined) commits strict-clean
48:### H3 (C4-F1) — Multi-statement packed tail still drops at admitted non-opted-in sites; tolerant-path fail-open
58:### H4 (A4-F1) — Commit persists configs the boot loader refuses: accepted commit bricks the next boot
59:- Files: no size check in `commitWithDescriptionLocked` (`pkg/configstore/store_commit.go:164`),
60:  `commitConfirmedLocked` (:445), `writeTreeMarked` (`pkg/configstore/db.go:477`); fatal-on-unreadable
62:- Mechanism: incremental `Set`/`Annotate`/`Insert`/`Copy`/`LoadMerge` have no cumulative bound, and commit
64:  `Set(system description <16MiB+1KiB>)` → `Commit()` SUCCESS → new `Store.Load()` fails
65:  `exceeds size limit: 16777216 byte ceiling`. All cited files untouched base→tip: holds at tip.
67:  the probe config fails at commit, never at next boot.
69:### H5 (A7-F1) — Routing-instance named "mgmt" collides with the hardcoded management VRF
73:- Mechanism: `routing-instances { mgmt { … } }` is strict-commit-clean (no reserved-name check anywhere;
78:  acceptance: commit of RI `mgmt` is rejected strict, and a no-op commit performs zero VRF churn.
80:## MEDIUM findings — R1 batch (15; R2 Mediums accumulate as M16+ in the ROUND 2 section)
82:### M1 (A3b2-F1) — Zone-ID collision gate misses zones in a second `zones {}` block; collides strict-clean
89:### M2 (C2-F1) — Open-world `security ike policy` / `security ike gateway`: typo'd leaves silently dropped
99:### M3 (C4-F2) — Packed ipsec-policy multi-proposal mints phantom proposal ref `proposals`, commit-clean
104:- Fix: opt ipsec `policy` in per the b3581b021 standard + differential cell.
106:### M4 (C4-F3) — `vpn-monitor` packedStatements opt-in is unreachable; packed vpn-monitor silently dropped
115:### M5 (C4-F4) — `("community","clients")` admission breaks hierarchical clients-first packing (order-dependent)
122:- Fix: opt `community` in after per-leaf-reader audit, or exclude the pair with a stated order rationale.
124:### M6 (C4-F5) — `unit inner-vlan-id` elision inverts: braced REJECTED, elided commits clean (QinQ unenforced)
131:### M7 (A2-F1) — Intra-pool duplicate members mint one wire identity twice
135:  the same `(addr,port)` (probe-executed). Strict commit rejects duplicates → lenient/sync path only.
138:### M8 (A2-F2) — Interface-mode registry ↔ NAT64 prefix allocator: no mutual exclusion either direction
145:### M9 (A2-F3) — NAT64 synced reserve skips the peer-ownership refusal the mint and SNAT-synced paths enforce
152:### M10 (A5-F1) — VRRP Max-Adver-Int wire double-narrowing (unclamped runtime encoder + learned high side)
160:### M11 (A5-F2) — BulkAck with future epoch releases the manual-failover gate
164:  promoted session-less → post-takeover drop. The fence-ack waiter next door requires exact-seq — reviewed
169:### M12 (A8-F1) — HEAD method alias bypasses the #6660 REST read gate on every GET route
178:### M13 (A8-F2) — Present-but-nil slots panic REST `GET /api/v1/show-text` on eight topics (daemon crash, no recovery)
186:### M14 (A10b1-F1) — Three `show system` exec sinks stream attacker-controlled process text unsanitized
194:### M15 (C1-F3) — Lenient-retained `redundancy-group` ≥ 256 wraps to `rgID` 0/aliased in `SetZone`
203:## LOW findings — R1 batch (19; R2 Lows accumulate as L20+ in the ROUND 2 section)
207:| A1b1-F1 | Preflight cannot express the enforce L4 bound; post-commit safety rests on callee conventions | `userspace-dp/src/afxdp/frame/mod.rs:730-758` |
222:| C1-F1 | Lenient-retained GRE tunnel `key` wraps through `uint32(Atoi)` (two sites; tip-confirmed: `-1 → 4294967295`) | `pkg/routing/tunnel.go` cast sites |
229:## ROUND 2 — continued hunt at tip `feaa31b2e` (accumulating)
231:### R2-D1 — pkg/cluster HA sync fabric (+2 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround2/D1-sync.md`)
236:  offset and rebases every subsequently installed session's Created/LastSeen to 0 (stealthy,
238:  `offset=0`; `peerMono=0x7FFFFFFFFFFFFFFF` → `offset=-9223372036848963099`, stamps →0,
263:### R2-D2 — IPsec render chain (+1 High, +5 Medium; report: `/tmp/review-work.UPFNnV6lttround2/D2-ipsec.md`)
294:  path) at apply, after a success commit. Fix: consumable arity for `dynamic hostname` + scope admission.
304:### R2-D5 — control-plane input hardening (+3 Medium; report: `/tmp/review-work.UPFNnV6lttround2/D5-ctlinput.md`)
310:  calls no regex family). E2E probe: committed class `deny-configuration "system host-name"` —
314:- **M24 (D5-F2, Medium)** — Console `load` (and `commit`/`rollback`) bypass `deny-configuration`;
318:  scratch candidate, evaluate touched paths); state a posture for whole-candidate `commit`/`rollback`.
326:  parity, CommitCheck read-only, tcpdump smuggling (fixed #4524/#4540/#4883-A/#4005), flow-file handling
328:  caps (A10b1-F4 tradeoff stands), software/rescue operands, failover grammar (#5810), commit-desc bound +
331:### R2-D3 — routing compile+render (+2 High, +5 Medium; report: `/tmp/review-work.UPFNnV6lttround2/D3-routing.md`)
348:  vanishes from FRR while commit succeeds — sessions never establish. Same fold mechanism as H3, distinct
373:### R2-D6 — daemon apply beyond interfaces (+1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround2/D6-apply.md`)
380:  address-book entry with no cap, feeding a SYNCHRONOUS commit-path resolve (apply slot + 500 ms sleep,
384:  opposite bounding. Fix: share the cap (truncate/tier + Warn) or a commit-time bound on warmup inputs.
388:  commit though the kernel holds the desired state. Probe: fake ENOENT → siblings nil, PBR
397:### R2-D4 — tip fix-residual delta c16a9b12a..feaa31b2e (+2 High, +3 Medium; report: `/tmp/review-work.UPFNnV6lttround2/D4-fixresid2.md`)
439:### TIP UPDATE — M3 (C4-F2) behavior shift at `feaa31b2e`
442:proposal "proposals"`) where base `c16a9b12a` accepted commit-clean. **Lenient still mints the phantom**
444:tolerant-path (boot/HA-sync) phantom only — same standing as H3/C4-F1. The "commit-clean" wording in the
447:### R3-E5 — operational config lifecycle, at tip `5184c40fe` (+2 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround3/E5-opspaths.md`)
459:  (`store_commit.go:1044-1048`) AND peer sync (`store.go:804-808`) discard staged edits and report
461:  the wrong base and a later commit ACKs a config missing believed-included edits. Probes: confirm-window
465:  `load override` + commit installs (same unclassified-parse root as M35, other direction; doc comment
466:  "same strict parse LoadOverride uses" is false for flat input). Capped at Low: commit still validates
468:- **L23 (E5-F4, Low)** — gRPC/REST `commit confirmed` with `minutes<=0` silently arms a 10-minute window
469:  (store default `store_commit.go:460-462`); neither transport validates nor echoes the deadline, while the
472:- NEG ledger: load-verb annotation parity, H4/M24 exclusions, internal-committer design (#6808), non-holder
473:  Commit (shared-candidate + #3861), CommitCheck oracle weakness (fail-closed direction), rescue (no restore
477:### R3-E1/E2/E3/E4 — services, VRRP states, Rust sessions, telemetry (reports: `/tmp/review-work.UPFNnV6lttround3/E{1,2,3,4}-*.md`)
478:All worktrees @ tip `5184c40fe`, probes executed then deleted, suites green, trees clean. Key cites
480:`build_synced_session_key`; telemetry packages byte-identical since `c16a9b12a`).
482:- **M37 (E2-F1, Medium)** — DHCP-server pool `address-range`/`subnet`/`router` unvalidated at commit AND
493:  reads a held live master as stale. Probe: `advertMS=4000000000000` → horizon `-1794222h…`,
503:  cast (`backend_rfc2136.go:496,523` "small positive" comment): `4294967296` → wire 0 (cache-disable +
504:  query amplification), `5000000000` → `705032704`. Strict rejects (#6773 verified); tolerant-only, hence Low.
512:- **E4: honest zero.** Telemetry packages untouched in 37 commits; no new finding. K31 (nil-unit panic,
520:  DSCP shift masked, generation equality-based, update-reject matches comments, #5674 cap placement
524:### R3-E6 — new-tip fix-residual delta feaa31b2e..5184c40fe (+1 High, +1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround3/E6-newresid.md`)
534:  `packedStatements` (b3581b021 standard) or reject multi-statement tails at non-opted-in admitted pairs.
552:### R4-F3 — trust + lifecycle ops, at tip `72957962b` (+1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround4/F3-pki.md`)
570:  mixed-base gate), bad-image revert (test-pinned), foreign-restore (re-validated history, tombstones loud,
574:### R4-F2 — BPF/XDP program lifecycle, at tip `72957962b` (+1 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround4/F2-bpf.md`)
588:- **L28 (F2-F2, Low)** — Firewall filter map caps (64 configs / 512 rules) are warn-only commit-green;
593:  at commit or record in `UnappliedFilterBindings`.
606:### R4-F1 — FRR render + vtysh-output parsing, at tip `72957962b` (+7 Medium; report: `/tmp/review-work.UPFNnV6lttround4/F1-frrparse.md`)
636:  Fix: reject `protocols` under `forwarding` at strict commit, or render VRF-scoped.
640:  commit bricks all dynamic routing (FRR holds last-good). M37's twin shape, different sink. Fix: strict
644:  failing the whole managed-section reload from a commit-clean config. Needs no control character (passes
651:### R4-F4 — L2/multicast/legacy, at tip `72957962b` (+1 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround4/F4-l2.md`)
656:  commit: any non-EINTR `Recvfrom` error → `return` (no retry — the class LLDP's `rxLoop` fixed with
661:  addresses → pool return-traffic blackhole; one WARN at death, reconcile reports success, no later commit
670:- **L31 (F4-F3, Low)** — proxy-ARP commit-path cost unbounded in statement count (per-statement expansion
672:  socket storm under `applySem`. M31's weaker sibling (no goroutines/sleep), hence Low. Fix: commit-time
680:### R4-F5 — control binaries + local IPC, at tip `72957962b` (+2 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround4/F5-ctlbins.md`)
692:  runs once, `daemon_run.go:859`); a later demoting commit changes nothing on the open console — a live
706:### R5-G1 — web management surface, at tip `0c57c0c87` (+1 Medium; report: `/tmp/review-work.UPFNnV6lttround5/G1-webmgmt.md`)
726:### R5-G2 — render-back fidelity + #8812 group residuals, at tip `0c57c0c87` (+3 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround5/G2-renderfid.md`)
733:  availability consequence). `manage-down` arm commits: ge-0/0/2 unmapped → daemon brings it DOWN.
763:### R5-G3 — daemon entry + fabric client, at tip `0c57c0c87` (+3 Low; report: `/tmp/review-work.UPFNnV6lttround5/G3-xpfd.md`)
786:  (#5883 sound), mid-teardown commit (bounded 2 s graceful), watchVRRPEvents (channel-closed + teardown),
793:### Orchestrator follow-ups — G2's handed-off leads, probed at tip `0c57c0c87` (+3 Medium; log: `/tmp/review-work.UPFNnV6lttround5/evidence-verify/r5-followup.log`)
807:## Fresh-issue reconciliation (no DUPs)
818:  neither covers E5 findings → no DUPs.
819:- R4 updates (tip `72957962b`): #8797 FIXED by #8809 (inet6-mode shape fix) and #8800 FIXED by #8804
824:## Coverage and remaining validation
827:  A4/A7/A8 carry coverage tables of reviewed-but-clean files). Probe sources preserved at
829:- Not independently re-derived at tip: value-level consequences downstream of the Medium config findings
     1	# Deep review kill campaign — final report
     2	
     3	- Review contract: `xpf-review-v3`
     4	- Run ID: `review-work.bwyxqLum9b`
     5	- Repository identity: `git@github.com:psaab/xpf.git`
     6	- Control checkout: `/home/ps/git/codex-bpfrx`
     7	- Base SHA: `b0f3aba21aede755573fb61714d3bfad15b795ab`
     8	- Comparison repository/ref/SHA: `origin/master` at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`
     9	- Initial fetch time: `2026-09-05T05:31:59Z`; final fetch/pull verification: `2026-09-05T06:32:40Z`
    10	- Model identity/family: coordinator is Codex based on GPT-5 (runtime system identity); final bounded adversarial discovery used explicitly selected `gpt-daybreak-blue-latest`; compatibility family `muse-spark`
    11	- Mode: full-product deep-review kill, read-only production review with bounded local probes
    12	- Requested scope: find 25 **new** Major-or-higher defects, prioritizing high-impact and difficult state-machine/trust-boundary failures
    13	- Effective scope: all 8,125 tracked paths inventoried and assigned; behavioral inspection was risk-ranked across packet/dataplane, HA, config/compiler, persistence, APIs, host reconciliation, services, tooling, packaging, tests, and contract documentation
    14	- Focus: remote/control-plane resource amplification, HA convergence/ownership, strict-versus-tolerant config transitions, durable acknowledgement/recovery truth, policy enforcement, and recent-fix residuals
    15	- Exclusions: all findings in `/tmp/muse-spark-review-007.md` and `/tmp/muse-spark-review-008.md`; no production edits, issue filing, deployment, live cluster mutation, or destructive maximum-allocation probe
    16	- Validation limits: no live failover or packet injection; no intentional 672 MiB/1.3 GiB allocation; encrypted confirm-record expansion was traced, not executed; component tests and static production-chain evidence are labeled separately
    17	- Output path: `/tmp/muse-spark-review-009.md`
    18	- Retained evidence: `/tmp/review-work.bwyxqLum9b/evidence`
    19	
    20	## Outcome
    21	
    22	**Four new High findings survived the kill gate. No Critical finding survived.** The requested target of 25 Major findings was not reached. The target is not a severity or duplication rule: independently demonstrated siblings with one corrective owner were merged, prior-report and existing-owner findings were removed, and four material behaviors were downgraded to Medium. Reporting 25 would require recycling or splitting work that the review contract forbids.
    23	
    24	| Rank | Finding ID | Severity | Result |
    25	|---:|---|---|---|
    26	| 1 | `PHA-001` | High | One DHCP full-set frame expands into 672 MiB retained state per family |
    27	| 2 | `PHA-002` | High | Origin-only HA strict validation permits peer policy bypass, VRRP split-brain, and AF_XDP takeover blackhole |
    28	| 3 | `DBK-001` | High | Peer-reboot classifiers retire the corpse but fail to re-prime established sessions |
    29	| 4 | `CSA-R-CONFIGSTORE-002` | High | Commit-confirmed writes a same-build-unreadable recovery record and loses rollback on restart |
    30	
    31	## Finding 1
    32	
    33	Finding ID: `PHA-001`
    34	
    35	Title: DHCP lease full-set decoder amplifies one 16 MiB frame into 672 MiB of retained peer state
    36	
    37	Severity: **High**. A maximum legal outer frame produces a 42x decoded backing allocation and retains it; one v4 plus one v6 frame retains 1.3125 GiB before input buffers and normal daemon state. A supported 2 GiB appliance can OOM/GC-collapse and restart-loop. Normally keyed clusters require the authenticated peer/PSK holder; the explicitly supported unkeyed migration posture exposes the listener to any reachable control-segment host. This actor boundary and finite input cap prevent a Critical rating.
    38	
    39	Confidence: **High**. Exact capacity arithmetic, type size, decoder behavior, both retained family slots, lifecycle, authentication boundary, and restart policy were independently checked. A scaled production-decoder probe confirmed linear amplification without deliberately allocating the maximum.
    40	
    41	Verification: **EXECUTED + STATIC**. The real decoder round-tripped a valid lease and accepted a 4 KiB zero-record payload as 1,023 leases/capacity 1,024. `unsafe.Sizeof(SyncLease{})` was 168 bytes. Maximum resource and restart consequences are static by design.
    42	
    43	Gate verdict: **MATERIAL; independently ACCEPTED at High**.
    44	
    45	Contract: A wire-controlled count must be bounded by complete valid records and a documented decoded-resource budget before allocation. A malformed full-set must not replace or retain peer state. The 16 MiB outer ceiling must cap receive resources rather than amplify them.
    46	
    47	Adversarial analysis: The boundary is the HA session-sync TCP listener. With Noise/PSK configured, the actor is a compromised, faulty, or malicious authenticated peer; without a key during supported in-place migration, any host reaching the control segment can complete the pass-through handshake. No race or malformed crypto is required. The official current encoder cannot emit this shape, which narrows ordinary fault likelihood but is not a receiver trust boundary.
    48	
    49	Evidence: At `b0f3aba21`, `pkg/cluster/sync_protocol.go:1227-1232` reads:
    50	
    51	```go
    52	if maxRecords := len(payload) / 4; count > maxRecords {
    53	    count = maxRecords
    54	    malformed = true
    55	}
    56	out := make([]dhcpserver.SyncLease, 0, count)
    57	```
    58	
    59	The bound accounts only for four-byte record-length prefixes. Empty record bodies decode to zero-valued leases, and the final missing prefix breaks without marking malformed. `pkg/cluster/sync.go:1945-1960` retains the slice directly in the independent v4/v6 peer slots; `:1915-1935` can preallocate another full-length slice while aging.
    60	
    61	Probe: `go test -overlay=/tmp/review-work.bwyxqLum9b/evidence/host-services/cluster_dhcp_count_amplification_overlay.json ./pkg/cluster -run '^TestReviewDHCPLeaseCountCapacityAmplification$' -count=1 -v` passed. At the 16,777,216-byte ceiling, count `4,194,304` equals `len(payload)/4`, so the clamp does not fire; `4,194,304 * 168 = 704,643,072` bytes (672 MiB). The decoder returns 4,194,303 zero leases with capacity 4,194,304 because only the last prefix is absent. Evidence records: `packet-ha/material-candidates.md` and `host-services/cluster-dhcp-count-review.md`.
    62	
    63	Trace: reachable HA socket -> optional keyed handshake -> 16 MiB frame accepted -> type 25/26 -> legacy `(incarnation,seq)=(0,0)` admitted -> physical-count equality bypasses malformed arm -> backing slice allocated before body validation -> millions of zero records appended -> final absent prefix tolerated -> `ok=true` -> v4/v6 peer set retained -> aging/replacement adds peak allocation -> memory pressure/OOM -> systemd restarts xpfd and the input can recur.
    64	
    65	Refutation attempt: The outer frame, setup concurrency, correct encoder, optional Noise authentication, sequence guard, and later valid replacement were checked. The cap bounds input but still permits 672 MiB decoded state; setup concurrency does not bound an installed connection; authentication changes the actor, not the peer-supplied count; zero bodies are accepted for compatibility; and disconnect does not clear held DHCP sets. These guards narrow scope but do not refute material availability loss.
    66	
    67	HPC/invariant check: The cold decoder violates memory conservation and bounded work: O(input/4) iterations materialize O(input/4 * 168) pointer-bearing retained state. The fix belongs before allocation and adds no packet-hot work. A semantic lease-count/decoded-byte budget and checked record preflight are required; finite is not the same as operationally bounded.
    68	
    69	Why it matters: A single accepted frame can consume roughly one third of a 2 GiB VM per family; both families exceed 1.3 GiB before normal state and transient copies. The process owns HA, management, and control functions, so OOM severs failover readiness and may repeat after automatic restart.
    70	
    71	Fix direction: Preflight every record envelope using checked subtraction, reject zero/undersized bodies below the oldest supported layout, and enforce an explicit lease-count/decoded-byte budget before `make`. Acceptance must drive real v4/v6 receive arms and prove malformed/over-budget frames do not update timestamps, retained sets, callbacks, or allocation beyond the stated bound, while valid legacy/current layouts and full-set trailers round-trip.
    72	
    73	Labels: `packet-ha`, `cluster-sync`, `dhcp`, `resource-exhaustion`, `availability`, `CWE-770`
    74	
    75	Dedup note: Prior report 007 finding 3 and open #8792 own the distinct persistent-NAT type-38 four-byte/448 GiB decoder. `PHA-001` is the DHCP type-25/26 equality residual of commit `0a507c4e2`: that fix clamps `0xffffffff` against a tiny payload but treats `len(payload)/4` as safe. #7175 owns truncated full-set replacement, not the accepted zero-record resource multiplier. Reports 007/008 contain no DHCP residual owner.
    76	
    77	Verified against comparison revision: **Yes**, all named production paths are byte-identical at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`; the scaled decoder probe was rerun there and passed with the same 168-byte/672 MiB result. Final log: `evidence/final-verify/verification.log`.
    78	
    79	Remediation status: **confirmed, independently accepted, unfixed; recommended for filing**. No source or external issue was changed.
    80	
    81	## Finding 2
    82	
    83	Finding ID: `PHA-002`
    84	
    85	Title: A shared HA commit runs the full strict pipeline only for the origin, permitting a peer-only policy bypass, VRRP split-brain, or AF_XDP takeover blackhole
    86	
    87	Severity: **High**. Three independently executed witnesses cross the same admission defect: a peer-only mixed application loses its TCP/22 deny and defaults it to permit after failover; a peer-only 40960 ms RETH timer aliases to zero on the VRRP wire and creates recurring competing VIP ownership; and peer-only `ring-entries 16385` tears down the healthy AF_XDP helper and leaves crash takeover dropping transit. Configuration authority is required, consequences are scoped, and two branches need a role/timing transition, so Critical is not justified.
    88	
    89	Confidence: **High**. Origin/peer strict gates, raw config sync, tolerant peer promotion/reload, policy snapshot, VRRP collection/marshal/parse/timing, ring boundary, real Rust CLI, and controls were executed. Three independent reviewers accepted High but required one deduplicated root finding.
    90	
    91	Verification: **EXECUTED + STATIC**. Component tests executed exact ingress and artifact chains. Rust default evaluation, full live VRRP posture, failover election, and traffic consequences were statically traced; no live cluster or packets were used.
    92	
    93	Gate verdict: **MATERIAL; ACCEPT at High as one finding**. The policy, VRRP, and ring witnesses share one complete corrective owner and are not separate countable bugs.
    94	
    95	Contract: A strict authoritative commit of one clustered raw tree must run all applicable structural, schema, and compiled-config checks on both node-effective expansions before success. Recovery-only tolerant ingress must not be the first validation of a newly authored peer view. Dropped policy constraints must fail closed; protocol values must be representable; impossible process replacements must be rejected before destroying last-known-good forwarding.
    96	
    97	Adversarial analysis: An authenticated operator or node-specific template error supplies `groups node0/node1` plus `apply-groups "${node}"`. The three peer branches respectively require a mixed direct/term application with deny/default-permit, supported non-default RETH VRRP with 40960 ms, or userspace dataplane with ring 16385 and later primary loss. Config sync is keyed in the policy fixture. No hostile network peer, race, disk fault, or mixed version is needed.
    98	
    99	Evidence: `pkg/configstore/store.go:478-539` validates/strict-compiles only the submitting `nodeID`; `pkg/config/compiler_peer_effective.go:49-75,131-151` then runs only SNAT and IPIP subjects. Peer `Store.SyncApply` warns and continues (`store.go:660-668`). The policy loss is explicit at `pkg/config/compiler_applications.go:509-518`; VRRP narrows then masks at `pkg/vrrp/instance_send.go:62-70` and `packet.go:68-75`; ring compilation retains the warned value and `pkg/dataplane/userspace/process.go:95-115` stops the healthy helper before Rust rejects it at `userspace-dp/src/server/lifecycle.rs:526-535`.
   100	
   101	Probe: The mixed-application overlay passed: node0 strict accepted, node1 strict rejected, node1 `SyncApply` emitted only UDP/53 deny, `PolicyContentRejected=[]`, and default permit. The VRRP overlay passed with node0=30 ms, peer=40960 ms, pre-wire=4096 cs, wire=0, backup master-down=108.28125 ms, sender cadence=40.96 s; 40959 encoded 4095 in the control. The ring overlay passed with node0=1024, peer warning/persist/reload=16385, and 16384 clean. Four Rust ring tests passed; the built helper exited 1 on `--ring-entries 16385`. Full synthesis and hashes: `evidence/orchestrator/peer-effective-merged-finding.md`; independent records: `host-services/peer-policy-appdrop-review.md`, `config-storage-api/review-pha-002-peer-vrrp-timer.md`, and `packet-ha/peer-ring-independent-review.md`.
   102	
   103	Trace: raw grouped tree -> node0-only strict pipeline -> incomplete peer registry -> green commit -> raw config sync -> node1 warning-only compile/promotion/persistence. Policy: direct TCP/22 discarded -> only UDP/53 deny emitted -> TCP/22 misses -> default permit. VRRP: 40960 ms -> 4096 cs -> 12-bit mask zero -> backup retains 108 ms local timeout -> competing VIP/RG ownership recurs through posture/safety-timer cycles. Ring: 16385 changes process config -> healthy helper stopped -> new helper rejects before ready -> bad active state retries/persists -> planned transfer blocks, but crash takeover intentionally bypasses readiness -> helperless node claims RG and transit stays fail-closed.
   104	
   105	Refutation attempt: Every local guard works, which proves the defect is distributed admission rather than missing local validation. Policy poisoning does not cover application metadata; tolerant sync neither reconstructs dropped constraints nor preserves all last-good runtime; VRRP eventually reacts to usable adverts but zero/cadence and posture reopen ownership; Rust prevents OOM only after teardown; readiness blocks planned failover but intentionally not peer-loss takeover. Corrected consequence wording is competing VIP ownership from per-node MACs, not identical virtual MACs or 378 independent backup expiries.
   106	
   107	HPC/invariant check: The common fix is cold commit work: `strict-success(raw) => strict-valid(expand(raw,node0)) && strict-valid(expand(raw,node1))`. One additional linear strict validation per commit is appropriate. Defense-in-depth policy poison, numeric narrowing, and pre-teardown scalar checks are cold O(1)/config-linear work and must not enter packet loops.
   108	
   109	Why it matters: A green shared commit can quietly leave the standby weaker, split-brained, or unable to forward. The current primary masks the defect until traffic, posture, or failover activates it, precisely when operators depend on the peer.
   110	
   111	Fix direction: Run the complete strict validation pipeline on both node-effective trees at the origin with peer/object context. Retain tolerant recovery only with last-known-good/fail-closed belts: poison referencing policies on invalid application metadata, checked VRRP narrowing, and ring validation before teardown. Acceptance includes all three failing peer-only fixtures, reversed node roles, clean application controls, 40959/16384 boundaries, historical tolerated state, and explicit takeover policy under failed config apply.
   112	
   113	Labels: `packet-ha`, `config-validation`, `peer-effective`, `policy`, `vrrp`, `afxdp`, `fail-open`, `split-brain`, `failover-blackhole`, `CWE-1284`, `CWE-754`
   114	
   115	Dedup note: Reports 007/008 have no full peer-effective owner. #3366, #8483, and #2524 own the respective local guards; #1319 owns tolerant typed-leaf recovery; #5876/#4785 own the current two-subject peer registry. The three witnesses merge because one both-node strict pipeline fixes the shared root; their separate runtime belts remain acceptance criteria only.
   116	
   117	Verified against comparison revision: **Yes**, all decisive production paths are byte-identical at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`. Because the final pull changed adjacent normalizer/schema code, the policy and ring peer-effective probes plus local VRRP controls were rerun there and reproduced; VRRP runtime blobs were unchanged. Final log: `evidence/final-verify/verification.log`.
   118	
   119	Remediation status: **confirmed, independently accepted, unfixed; recommended for filing as one issue**. No production or external state changed.
   120	
   121	## Finding 3
   122	
   123	Finding ID: `DBK-001`
   124	
   125	Title: Peer-reboot classifiers retire the old incarnation without rearming cold-prime, so no authoritative replay reaches the replacement
   126	
   127	Severity: **High**. A recognized peer reboot can leave the replacement missing all pre-reboot established sessions and NAT associations; the next ownership transfer can reset or blackhole them. It needs one fabric already empty, a stale established socket on the other, the replacement entering the alternate slot, and a later failover, so Critical is not supportable.
   128	
   129	Confidence: **High**. Daybreak found the split conditional; both production signal orderings produced expected red tests, current positive guards passed, issue/fix history explicitly requires cold-prime, and two independent adversarial reviewers checked alternate recovery edges.
   130	
   131	Verification: **EXECUTED + STATIC**. The overlay executed both `installConn`'s heartbeat-epoch classifier and `handleMessage(BulkStart)`'s boot-ID classifier; downstream bulk retry, sticky ack, disconnect, sweep, and failover behavior were source-traced. No appliance reboot/failover was performed.
   132	
   133	Gate verdict: **MATERIAL; independently ACCEPTED at High**.
   134	
   135	Contract: A peer reboot positively classified by either raised heartbeat epoch or changed BulkStart boot ID must retire the old incarnation **and** create a durable outbound cold-prime obligation until the replacement acknowledges the survivor's authoritative session table. `pkg/cluster/README.md:3689-3739`, closed #6910/#7762, and fixing commit `af145890c` all name missing cold-prime as the unbounded failover-blackhole consequence.
   136	
   137	Adversarial analysis: No adversary is required. Starting from an already primed/acked HA pair: fabric 1 is empty, peer A hard-reboots while local `conn0` remains ESTABLISHED, and A' connects on fabric 1. Either the authenticated heartbeat epoch reaches the survivor before that connection, or A's changed boot ID arrives in the replacement's inbound BulkStart before the heartbeat. Both signals correctly distinguish reboot from normal second-fabric recovery. The defect is that incarnation retirement and outbound recovery debt are separate transitions.
   138	
   139	Evidence: At `pkg/cluster/sync_conn.go:761-815`:
   140	
   141	```go
   142	epochReboot := s.peerEpochRebootLocked()
   143	if supersededCurrent || epochReboot {
   144	    s.peerIncarnation++
   145	    s.peerHeartbeatAckEver.Store(false)
   146	    s.evictStaleIncarnationConnsLocked(fabricIdx)
   147	}
   148	...
   149	if d.wasDisconnected || supersededCurrent {
   150	    s.needColdPrime.Store(true)
   151	}
   152	```
   153	
   154	The second conditional omits `epochReboot`. In the opposite ordering, `applyPeerIncarnationSwitchLocked` at `sync_conn.go:262-289` retires/rebases/evicts on the changed BulkStart boot ID but also never arms `needColdPrime`; its caller at `sync_conn_read.go:223-283` only continues the inbound bulk. The current #7762 test checks only that the replacement becomes preferred, despite its own failure message naming cold-prime/session loss.
   155	
   156	Probe: `go test -overlay=.../daybreak_epoch_prime_overlay.json ./pkg/cluster -run '^TestDaybreak(Epoch|BootID)RebootRearmsColdPrime$' -count=1 -v` failed both cells after correct corpse eviction: heartbeat-first observed `needColdPrime=false shouldColdPrime=false`, and connection/BulkStart-first reported that boot-ID retirement did not arm survivor outbound cold-prime. The shipped #7762 replacement property, ordinary supersession cold-prime, and same-boot second-fabric controls passed. Probe SHA-256 `e1d647182bde24cb8b946868b4c9c61e633925c5e118d954ff4361928d5d8f5d`; overlay SHA-256 `bdbe3946e3299bd4b84155bacad926f901cfcde177213b1fdd5c95f928afc23e`; output `evidence/orchestrator/daybreak_epoch_prime_validation.log`; source record `evidence/packet-ha/daybreak-final-kill-review.md` (SHA-256 `c75b73a770dacf68ad1c16894038e596a1c98da07ccbc152078aaa905bf092fa`); independent record `evidence/config-storage-api/review-daybreak-epoch-prime.md` (SHA-256 `7f769a9163be91ea0c3305eb87cd45c03e1b08943be06f82383a937459030247`).
   157	
   158	Trace: peer reboot -> either heartbeat epoch classifies during install or changed boot ID classifies during inbound BulkStart -> incarnation advances and corpse is eagerly evicted -> replacement becomes active -> neither classifier creates outbound cold-prime debt -> `handleNewConnection` has already skipped or never sees its authoritative-bulk arm -> evicted corpse's receive loop reaches stale-disconnect no-op -> old incarnation's `outboundBulkAcked` remains sticky -> survivor/sweep retry paths see neither unacked nor owed bulk -> replacement's empty inbound bulk travels the wrong direction -> incremental sweep omits rows older than its watermark -> replacement stays empty -> later failover lacks established state.
   159	
   160	Refutation attempt: Full disconnect, occupied-slot supersession, both reboot-signal orders, peer empty outbound bulk, survivor redrive, forced resync, config reconcile, periodic sweep, and sticky ACK semantics were checked. Neither classifier arms outbound recovery after eager eviction; the boot-ID path is not a fallback because it repeats the omission. The routine second-fabric path must not prime, but either authenticated reboot signal already distinguishes this event, so no heuristic is required.
   161	
   162	HPC/invariant check: This is incarnation-scoped cold-path accounting: each recognized reboot must create exactly one owed O(session-count) bulk and discharge it only after success. Reusing the existing atomic latch/mutex adds no packet-hot work; one redundant idempotent bulk is the already accepted false-positive cost.
   163	
   164	Why it matters: The peer appears reconnected and the dead fabric is correctly removed, hiding that its pre-existing state was never restored. Failover then loses session and NAT continuity across affected RGs, with no time-based self-heal.
   165	
   166	Fix direction: Unify both “retire a proven peer incarnation” consumers with durable outbound-prime debt. Include `epochReboot` in `installConn`'s under-lock arm. When changed BulkStart boot ID wins after install, arm and immediately or boundedly drive the existing serialized success-only re-drive; merely setting debt after the install consumer passed is insufficient. Acceptance covers both signal orders, dual-signal one-reboot/no duplicate storm, corpse eviction, live replacement, actual survivor-to-replacement bulk, old-ACK/empty-inbound-prime non-suppression, success-only discharge, and same-boot second-fabric controls.
   167	
   168	Labels: `packet-ha`, `cluster-sync`, `peer-reboot`, `state-machine`, `cold-prime`, `session-loss`, `failover`, `false-closure-residual`
   169	
   170	Dedup note: Reports 007/008 contain no exact owner. Report 007 helper-restart finding concerns local helper generation while daemon TCP survives; the delayed-lower-bulk finding concerns ordering after two bulks exist. Here no survivor bulk is sent. This is one fresh incomplete-fix/false-closure residual of closed #6910/#7762: `af145890c` fixes connection preference/eviction but omits the explicitly required prime arm, and the boot-ID path has the same omission. The two signal orderings share one invariant and are not separate findings.
   171	
   172	Verified against comparison revision: **Yes**, classifier, wiring, bulk sender, disconnect, retry/sweep, sticky ACK, tests, README, issue bodies, and fix diff are unchanged at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`. Both expected-red cells and all shipped controls were rerun there with the same outcomes. Final log: `evidence/final-verify/verification.log`.
   173	
   174	Remediation status: **confirmed, independently accepted, unfixed; recommended for reopening #7762**. No source or issue was changed.
   175	
   176	## Finding 4
   177	
   178	Finding ID: `CSA-R-CONFIGSTORE-002`
   179	
   180	Title: Commit-confirmed can write a recovery record that same-build boot refuses, losing the rollback window
   181	
   182	Severity: **High**. A readable prior active DB expands beyond 16 MiB when nested in `confirm.json`; `CommitConfirmed` reports success, but restart keeps the unconfirmed active generation, refuses the recovery record, and never re-arms rollback. This can permanently strand the management path the feature is meant to protect. Configuration authority, a large prior tree, and restart during the window cap severity below Critical.
   183	
   184	Confidence: **High**. The real strict prior commit, real `CommitConfirmed`, raw sizes, fresh-store recovery state, degraded signal, timer absence, and under-limit positive control were executed.
   185	
   186	Verification: **EXECUTED + STATIC**. Plaintext record behavior was executed hermetically; management lockout and encrypted/base64 expansion were traced.
   187	
   188	Gate verdict: **MATERIAL; independently ACCEPTED at High**.
   189	
   190	Contract: Commit-confirmed must durably preserve the prior tree/deadline so restart within the window re-arms rollback. The same-build writer domain must be a subset of `ReadConfirm`'s domain. The source invariant at `pkg/configstore/store_commit.go:752-755` itself assumes `writeConfirmState` always writes a record `ReadConfirm` accepts.
   191	
   192	Adversarial analysis: An authenticated administrator has a large but valid active tree, applies a small potentially management-stranding change using commit-confirmed, and the daemon restarts before confirmation. No malicious actor, race, I/O error, disk corruption, or foreign version is required. #8566 exposes degraded health after boot, but the changed management path may already be unreachable.
   193	
   194	Evidence: `pkg/configstore/db.go:229-238` writes the fully nested record without a size check:
   195	
   196	```go
   197	data, err := json.MarshalIndent(rec, "", "  ")
   198	...
   199	data, err = db.maybeEncryptTreeJSON(data, rec.PrevTree, nil)
   200	...
   201	if err := fsatomic.WriteFileDurable(db.confirmPath(), data, 0600); err != nil {
   202	```
   203	
   204	`ReadConfirm` caps the complete file at `MaxConfigSize` before decrypt/decode (`db.go:264-271`). `recoverPendingConfirmLocked` handles refusal by keeping the unconfirmed active config, setting degraded health, and returning without a timer (`store_persist.go:154-187`).
   205	
   206	Probe: The independent configstore overlay passed. A prior strict commit produced a readable 16,441,659-byte active DB. A tiny next candidate plus `CommitConfirmed(10)` returned success, wrote a 562-byte active DB and 17,773,786-byte `confirm.json`; fresh `Load` kept the new active config, reported degraded recovery, and had no confirm timer. The identical state machine with a 4,791,786-byte confirm record re-armed normally. Artifacts/hashes and full record: `evidence/config-storage-api/review-configstore-size-symmetry.md`.
   207	
   208	Trace: large readable active tree -> small confirmed candidate -> active write/promote -> prior tree nested/pretty-printed in confirm record -> record crosses raw reader ceiling -> durable write succeeds -> operation reports armed -> restart loads small active -> `ReadConfirm` refuses -> #8566 degraded-but-boot path -> no rollback timer -> unconfirmed generation persists.
   209	
   210	Refutation attempt: #8566's fail-open boot posture truthfully logs/journals and avoids bricking the daemon; it is appropriate for corrupt/foreign records. It does not justify the same writer creating an unreadable record while reporting a crash-surviving window. Active DB size is not a bound on nested/indented/encrypted confirm bytes. The positive control proves recovery works when writer and reader domains agree.
   211	
   212	HPC/invariant check: `WriteConfirm` already materializes exact bytes, so checking `len(data)` is O(1) cold-path work. The invariant is artifact-specific closure; a preflight must occur before promotion if rollback durability is part of success. No additional tree walk or packet-hot work is needed.
   213	
   214	Why it matters: Commit-confirmed is specifically used for changes that may sever access. A restart can remove that safety hatch while leaving the dangerous change active, and the resulting health alarm may be unreachable over the broken path.
   215	
   216	Fix direction: Encode/preflight the exact confirm artifact before active promotion. If unreadable, reject with the candidate intact or transactionally restore the prior generation; post-promotion logging is insufficient. Acceptance covers all confirmed wrappers, nested re-arms, N/N+1 exact bytes, plaintext/encrypted records, restart before/after deadline, first-commit empty target, and an under-limit control.
   217	
   218	Labels: `area/configstore`, `commit-confirmed`, `persistence`, `writer-reader-asymmetry`, `lost-rollback-window`, `restart`, `configuration-authorized`, `false-closure-residual`
   219	
   220	Dedup note: Prior report 008 H4 owns active DB commit/read asymmetry, including the active write performed by `commitConfirmedLocked`, but it does not own `WriteConfirm`'s separate nested recovery artifact or crash-window acceptance. #4577 owns durable windows, #8566 truthful handling of externally unreadable records, and #8597 the newly bounded reader; none requires every fresh `WriteConfirm` output to pass `ReadConfirm`. Fixing active preflight alone does not bound the nested record, so this is distinct.
   221	
   222	Verified against comparison revision: **Yes**, wrappers, ordering, writer/reader, #8566 recovery state, docs, #8597 diff, and owner baselines are unchanged at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`. Both material and positive-control confirmed-commit probes were rerun there and passed. Final log: `evidence/final-verify/verification.log`.
   223	
   224	Remediation status: **confirmed, independently accepted, unfixed; recommended for filing**. No source or issue was changed.
   225	
   226	## Inspection, disposition, and count reconciliation
   227	
   228	Formal candidate ledger:
   229	
   230	| Disposition | Count | Stable IDs / reason |
   231	|---|---:|---|
   232	| Confirmed High | 4 | `PHA-001`, `PHA-002`, `DBK-001`, `CSA-R-CONFIGSTORE-002` |
   233	| Unresolved High-impact | 0 | No candidate remains awaiting evidence or adjudication |
   234	| Fixed in source | 0 | No new accepted finding was fixed during this read-only run |
   235	| Duplicate/prior owner | 4 | `DUP-01` active DB = report 008 H4; `DUP-02` `mgmt` VRF = report 008 H5; `DUP-03` proxy-ARP socket = report 007 F9; `DUP-04` late RI bind = existing #6805 acceptance scope |

exec
/bin/bash -lc "nl -ba /tmp/muse-spark-review-008.md | sed -n '1,240p'; rg --files --hidden -g '*.md' -g '*.txt' -g '*.json' -g '"'!**/cache/**'"' -g '"'!**/.git/**'"' /tmp 2>/dev/null | rg '/["'^/]*(8830|8865|8859|8791)[''^/]*$'"' | head -40" in /var/tmp/RES8865
 succeeded in 112ms:
/tmp/claude-1000/-home-ps-git-bpfrx/e6d144c5-87d8-40ab-b8fa-26172876c242/scratchpad/codex-prompt-8865.txt
/tmp/review-work-claude-opus-003/superseded/2e5c740d96c9da89aa7440a2736cdd6b1b424616/dedup-staging/G001/comment-bodies/issue-5486-comment-4988596849.txt
/tmp/review-work-claude-opus-003/dedup-staging/P1-remote/comment-bodies/issue-5486-comment-4988596849.txt
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md

exec
/bin/bash -lc "nl -ba /tmp/muse-spark-review-009.md | sed -n '43,74p;142,186p'; nl -ba /tmp/muse-spark-review-008.md | sed -n '1,28p;242,259p;395,438p;524,551p'; rg -n '32|predicate|defect|8844|PFS|correct' /tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md /tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md" in /var/tmp/RES8865
 succeeded in 0ms:
    43	Gate verdict: **MATERIAL; independently ACCEPTED at High**.
    44	
    45	Contract: A wire-controlled count must be bounded by complete valid records and a documented decoded-resource budget before allocation. A malformed full-set must not replace or retain peer state. The 16 MiB outer ceiling must cap receive resources rather than amplify them.
    46	
    47	Adversarial analysis: The boundary is the HA session-sync TCP listener. With Noise/PSK configured, the actor is a compromised, faulty, or malicious authenticated peer; without a key during supported in-place migration, any host reaching the control segment can complete the pass-through handshake. No race or malformed crypto is required. The official current encoder cannot emit this shape, which narrows ordinary fault likelihood but is not a receiver trust boundary.
    48	
    49	Evidence: At `b0f3aba21`, `pkg/cluster/sync_protocol.go:1227-1232` reads:
    50	
    51	```go
    52	if maxRecords := len(payload) / 4; count > maxRecords {
    53	    count = maxRecords
    54	    malformed = true
    55	}
    56	out := make([]dhcpserver.SyncLease, 0, count)
    57	```
    58	
    59	The bound accounts only for four-byte record-length prefixes. Empty record bodies decode to zero-valued leases, and the final missing prefix breaks without marking malformed. `pkg/cluster/sync.go:1945-1960` retains the slice directly in the independent v4/v6 peer slots; `:1915-1935` can preallocate another full-length slice while aging.
    60	
    61	Probe: `go test -overlay=/tmp/review-work.bwyxqLum9b/evidence/host-services/cluster_dhcp_count_amplification_overlay.json ./pkg/cluster -run '^TestReviewDHCPLeaseCountCapacityAmplification$' -count=1 -v` passed. At the 16,777,216-byte ceiling, count `4,194,304` equals `len(payload)/4`, so the clamp does not fire; `4,194,304 * 168 = 704,643,072` bytes (672 MiB). The decoder returns 4,194,303 zero leases with capacity 4,194,304 because only the last prefix is absent. Evidence records: `packet-ha/material-candidates.md` and `host-services/cluster-dhcp-count-review.md`.
    62	
    63	Trace: reachable HA socket -> optional keyed handshake -> 16 MiB frame accepted -> type 25/26 -> legacy `(incarnation,seq)=(0,0)` admitted -> physical-count equality bypasses malformed arm -> backing slice allocated before body validation -> millions of zero records appended -> final absent prefix tolerated -> `ok=true` -> v4/v6 peer set retained -> aging/replacement adds peak allocation -> memory pressure/OOM -> systemd restarts xpfd and the input can recur.
    64	
    65	Refutation attempt: The outer frame, setup concurrency, correct encoder, optional Noise authentication, sequence guard, and later valid replacement were checked. The cap bounds input but still permits 672 MiB decoded state; setup concurrency does not bound an installed connection; authentication changes the actor, not the peer-supplied count; zero bodies are accepted for compatibility; and disconnect does not clear held DHCP sets. These guards narrow scope but do not refute material availability loss.
    66	
    67	HPC/invariant check: The cold decoder violates memory conservation and bounded work: O(input/4) iterations materialize O(input/4 * 168) pointer-bearing retained state. The fix belongs before allocation and adds no packet-hot work. A semantic lease-count/decoded-byte budget and checked record preflight are required; finite is not the same as operationally bounded.
    68	
    69	Why it matters: A single accepted frame can consume roughly one third of a 2 GiB VM per family; both families exceed 1.3 GiB before normal state and transient copies. The process owns HA, management, and control functions, so OOM severs failover readiness and may repeat after automatic restart.
    70	
    71	Fix direction: Preflight every record envelope using checked subtraction, reject zero/undersized bodies below the oldest supported layout, and enforce an explicit lease-count/decoded-byte budget before `make`. Acceptance must drive real v4/v6 receive arms and prove malformed/over-budget frames do not update timestamps, retained sets, callbacks, or allocation beyond the stated bound, while valid legacy/current layouts and full-set trailers round-trip.
    72	
    73	Labels: `packet-ha`, `cluster-sync`, `dhcp`, `resource-exhaustion`, `availability`, `CWE-770`
    74	
   142	epochReboot := s.peerEpochRebootLocked()
   143	if supersededCurrent || epochReboot {
   144	    s.peerIncarnation++
   145	    s.peerHeartbeatAckEver.Store(false)
   146	    s.evictStaleIncarnationConnsLocked(fabricIdx)
   147	}
   148	...
   149	if d.wasDisconnected || supersededCurrent {
   150	    s.needColdPrime.Store(true)
   151	}
   152	```
   153	
   154	The second conditional omits `epochReboot`. In the opposite ordering, `applyPeerIncarnationSwitchLocked` at `sync_conn.go:262-289` retires/rebases/evicts on the changed BulkStart boot ID but also never arms `needColdPrime`; its caller at `sync_conn_read.go:223-283` only continues the inbound bulk. The current #7762 test checks only that the replacement becomes preferred, despite its own failure message naming cold-prime/session loss.
   155	
   156	Probe: `go test -overlay=.../daybreak_epoch_prime_overlay.json ./pkg/cluster -run '^TestDaybreak(Epoch|BootID)RebootRearmsColdPrime$' -count=1 -v` failed both cells after correct corpse eviction: heartbeat-first observed `needColdPrime=false shouldColdPrime=false`, and connection/BulkStart-first reported that boot-ID retirement did not arm survivor outbound cold-prime. The shipped #7762 replacement property, ordinary supersession cold-prime, and same-boot second-fabric controls passed. Probe SHA-256 `e1d647182bde24cb8b946868b4c9c61e633925c5e118d954ff4361928d5d8f5d`; overlay SHA-256 `bdbe3946e3299bd4b84155bacad926f901cfcde177213b1fdd5c95f928afc23e`; output `evidence/orchestrator/daybreak_epoch_prime_validation.log`; source record `evidence/packet-ha/daybreak-final-kill-review.md` (SHA-256 `c75b73a770dacf68ad1c16894038e596a1c98da07ccbc152078aaa905bf092fa`); independent record `evidence/config-storage-api/review-daybreak-epoch-prime.md` (SHA-256 `7f769a9163be91ea0c3305eb87cd45c03e1b08943be06f82383a937459030247`).
   157	
   158	Trace: peer reboot -> either heartbeat epoch classifies during install or changed boot ID classifies during inbound BulkStart -> incarnation advances and corpse is eagerly evicted -> replacement becomes active -> neither classifier creates outbound cold-prime debt -> `handleNewConnection` has already skipped or never sees its authoritative-bulk arm -> evicted corpse's receive loop reaches stale-disconnect no-op -> old incarnation's `outboundBulkAcked` remains sticky -> survivor/sweep retry paths see neither unacked nor owed bulk -> replacement's empty inbound bulk travels the wrong direction -> incremental sweep omits rows older than its watermark -> replacement stays empty -> later failover lacks established state.
   159	
   160	Refutation attempt: Full disconnect, occupied-slot supersession, both reboot-signal orders, peer empty outbound bulk, survivor redrive, forced resync, config reconcile, periodic sweep, and sticky ACK semantics were checked. Neither classifier arms outbound recovery after eager eviction; the boot-ID path is not a fallback because it repeats the omission. The routine second-fabric path must not prime, but either authenticated reboot signal already distinguishes this event, so no heuristic is required.
   161	
   162	HPC/invariant check: This is incarnation-scoped cold-path accounting: each recognized reboot must create exactly one owed O(session-count) bulk and discharge it only after success. Reusing the existing atomic latch/mutex adds no packet-hot work; one redundant idempotent bulk is the already accepted false-positive cost.
   163	
   164	Why it matters: The peer appears reconnected and the dead fabric is correctly removed, hiding that its pre-existing state was never restored. Failover then loses session and NAT continuity across affected RGs, with no time-based self-heal.
   165	
   166	Fix direction: Unify both “retire a proven peer incarnation” consumers with durable outbound-prime debt. Include `epochReboot` in `installConn`'s under-lock arm. When changed BulkStart boot ID wins after install, arm and immediately or boundedly drive the existing serialized success-only re-drive; merely setting debt after the install consumer passed is insufficient. Acceptance covers both signal orders, dual-signal one-reboot/no duplicate storm, corpse eviction, live replacement, actual survivor-to-replacement bulk, old-ACK/empty-inbound-prime non-suppression, success-only discharge, and same-boot second-fabric controls.
   167	
   168	Labels: `packet-ha`, `cluster-sync`, `peer-reboot`, `state-machine`, `cold-prime`, `session-loss`, `failover`, `false-closure-residual`
   169	
   170	Dedup note: Reports 007/008 contain no exact owner. Report 007 helper-restart finding concerns local helper generation while daemon TCP survives; the delayed-lower-bulk finding concerns ordering after two bulks exist. Here no survivor bulk is sent. This is one fresh incomplete-fix/false-closure residual of closed #6910/#7762: `af145890c` fixes connection preference/eviction but omits the explicitly required prime arm, and the boot-ID path has the same omission. The two signal orderings share one invariant and are not separate findings.
   171	
   172	Verified against comparison revision: **Yes**, classifier, wiring, bulk sender, disconnect, retry/sweep, sticky ACK, tests, README, issue bodies, and fix diff are unchanged at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`. Both expected-red cells and all shipped controls were rerun there with the same outcomes. Final log: `evidence/final-verify/verification.log`.
   173	
   174	Remediation status: **confirmed, independently accepted, unfixed; recommended for reopening #7762**. No source or issue was changed.
   175	
   176	## Finding 4
   177	
   178	Finding ID: `CSA-R-CONFIGSTORE-002`
   179	
   180	Title: Commit-confirmed can write a recovery record that same-build boot refuses, losing the rollback window
   181	
   182	Severity: **High**. A readable prior active DB expands beyond 16 MiB when nested in `confirm.json`; `CommitConfirmed` reports success, but restart keeps the unconfirmed active generation, refuses the recovery record, and never re-arms rollback. This can permanently strand the management path the feature is meant to protect. Configuration authority, a large prior tree, and restart during the window cap severity below Critical.
   183	
   184	Confidence: **High**. The real strict prior commit, real `CommitConfirmed`, raw sizes, fresh-store recovery state, degraded signal, timer absence, and under-limit positive control were executed.
   185	
   186	Verification: **EXECUTED + STATIC**. Plaintext record behavior was executed hermetically; management lockout and encrypted/base64 expansion were traced.
     1	# Deep review — kill campaign UPFNnV6ltt (final report)
     2	
     3	- Run ID: `UPFNnV6ltt` | Base: `c16a9b12a` | Verify tip: `29d9cb196` (= origin/master at verify time; only a test-only commit sits above it now)
     4	- Contract: `xpf-review-v3` kill campaign. Model: `muse-spark`.
     5	- Verdict: **109 findings, all OPEN and UNFIXED (review only; no source changed) — 11 High, 59 Medium, 39 Low.**
     6	  (Rounds: R1 = 39 at verify-tip `29d9cb196`; R2 at tip `feaa31b2e`: +26; R3 at tip `5184c40fe`: +13;
     7	  R4 at tip `72957962b`: +18; R5 at tip `0c57c0c87`: G1 = +1, G2 = +5, G3 = +3, orchestrator follow-ups = +3. All batches complete.)
     8	  The 100-major target was NOT reached: every assigned batch (A1–A10, C1–C4) ran to completion,
     9	  adversarial NEG sweeps killed the rest, and the remaining candidate pool is exhausted.
    10	  This report states that plainly rather than inflating severity.
    11	
    12	## Method (why the count is 37 and not 100)
    13	
    14	- 22 batch reports under `/tmp/review-work.UPFNnV6ltt/` (A1-b1…b4, A2-nat, A3-b1/b2, A4-store, A5-ha,
    15	  A6-b1/b2, A7-daemon, A8-api, A9-telemetry, A10-b1/b2, C1-casts, C2-defaults, C3-nilderef, C4-fixresid),
    16	  each with executed probes (temp tests, removed after runs; worktrees left clean) and a dedup pass
    17	  against 240 K/L rows plus fresh issues.
    18	- Whole-class NEG kills with evidence: A1-b2 (14 WG/dataplane candidates), C3 (19 nil-deref census
    19	  entries), A9 (verification-only, no new filing), plus per-batch NEG ledgers.
    20	- Tip verification (this session, worktree `/tmp/review-work.UPFNnV6ltt/wt-verify` @ `29d9cb196`,
    21	  left clean): base→tip diff is 15 files, all in `pkg/config` + docs. Every `pkg/config`-linked
    22	  High/Medium was **re-probed at tip** (logs: `evidence-verify/tip-c4c1.log`,
    23	  `evidence-verify/tip-a3c2.log`, `evidence-verify/tip-a3c2b.log`, `evidence-verify/tip-reprobe.log`);
    24	  every other High/Medium cites files byte-identical between base and tip, confirmed by diff-scope
    25	  inspection (A7-F1's two compiler cites re-checked: still no `mgmt` refusal at tip).
    26	- Notable tip interaction: #8798 (`3fc95c0bd`, gateway packedStatements opt-in) fixed #8796 but does
    27	  NOT fix C2-F1 (re-probed: typo leaves still silently dropped).
    28	
   242	  (same "honest peer never sends it" rationale), distinct sink/consequence — not a twin.
   243	- **M17 (D1-F2, Medium)** — `decodeIPsecSAPayload` splits a 16 MB frame into ~8 M entries (~1 GB transient,
   244	  persistently held), detonating as 8.4 M `swanctl --initiate` execs at failover. Probe: 16 MB `"\n"`-only
   245	  → 525 ms / 285 MB; 16 MB `"a\n"`×8 M → 8,388,608 names / 1.55 s / 978 MB. Sites:
   246	  `sync_protocol.go:801-814` (unbounded Split), `sync_conn_read.go:484-488` (retained),
   247	  `daemon_ha.go:2297-2311` × `ike.go:665-670` (exec per name). Keyed clusters sealed; default-open
   248	  clusters take it from any fabric-adjacent host. Fix: cap decoded names (≈4096, mirror the DHCP
   249	  decoder clamp) + bound retained bytes. Dedup: #8792 neighbor (same decoder class hunt), distinct
   250	  sink (delimiter-count split vs u32-count `make`) and second stage (exec storm) — not a twin.
   251	- **L20 (D1-F3, Low)** — Heartbeat monitor name length byte wraps for config names ≥256 (300→44);
   252	  peer misframes monitors and destroys version/HA-proto (`SoftwareVersion` garbage, `HAProtocolVersion`
   253	  0x6161 → Legacy fallback). Election-critical RG groups parse first, unaffected — capped at Low.
   254	  Site: `pkg/cluster/heartbeat.go:331` vs decoder `:405-412`; names deliberately unbounded
   255	  (`validate_interface_name.go:41`). Fix: truncate to 255 with Warn at marshal (mirror
   256	  `maxHeartbeatSoftwareVersionSize`). Dedup: K02 neighbor, distinct field/consequence.
   257	- NEG ledger (15 kills): legacy `(0,0)` set guard, DHCP family byte, failover-batch RG range, `numMon`
   258	  wrap (unreachable), NodeID/ClusterID casts (consistent-wrap), election arithmetic (clamped upstream),
   259	  replay-ring eviction (PSK-bound), BulkStart reset (legit-prime-indistinguishable), barrier-ack future
   395	  static/tunnel/XFRM fail-closed seams, prio-shift convergence, route-subscription overflow (below bar).
   396	
   397	### R2-D4 — tip fix-residual delta c16a9b12a..feaa31b2e (+2 High, +3 Medium; report: `/tmp/review-work.UPFNnV6lttround2/D4-fixresid2.md`)
   398	Worktree `wt-D4` @ tip; per-fix ledger over #8788/#8789/#8790/#8793/#8795/#8798/#8799 with three-way
   399	packed/braced/flat + pass-off probes, full `pkg/config` suite green, tree clean. Orchestrator re-probed
   400	D4-F1/F2 at tip (`evidence-verify/r2-verify.log`): CONFIRMED both.
   401	
   402	- **H9 (D4-F1, High)** — REGRESSION from #8793: modifier-first `then` multi-tail (`then count C1 discard;`)
   403	  folds to one child, `discard` buried, `Action=""` renders ACCEPT. Pass-off proves pre-fix the leaf path
   404	  read it correctly. Reverse order never folds (opposite outcome — order-dependent). The exact fail-open
   405	  the #2399 belt exists to prevent. Tip evidence: `F1 packed action=""` vs `F1 braced action="discard"`.
   406	  Fix: opt `then` into packedStatements (ordered pairs incl. modifier mixes) or scan one level for terminal
   407	  actions in the children path.
   408	- **H10 (D4-F2, High)** — Multi-statement `from` headed by declared-but-unadmitted `next-header` compiles to
   409	  EMPTY match, strict-clean: `packedBodyChildren` chains statements, and after `[next-header tcp]` the
   410	  cursor sits on a leaf schema so `source-address` resolves nil → whole body discarded → match-all term
   411	  with `accept`. Reversed order strict-REJECTS (same leaf, opposite verdicts by order). The precise leaf
   412	  #8788 just repaired still yields a no-warning match-everything term. Tip evidence: `F2 packed
   413	  match-proto=[] src=[] action="accept"` vs `F2 braced match-proto=[tcp] src=[2001:db8::/32]`. Fix: admit
   414	  (`from`,`next-header`) AND harden `packedBodyChildren` (reset per sibling statement instead of discarding
   415	  even the consumed head).
   416	- **M32 (D4-F3, Medium)** — Admitted-first multi-statement `from` tails now strict-REJECT legitimate configs
   417	  (first arm absorbs the sibling keyword as a value); lenient keeps verbatim garbage with a warning.
   418	  No fail-open post-fix, but strict availability break + tolerant garbage; the landing cell can't see it
   419	  (single-statement fixtures; `pOff==br` checked before `pOn==br`). Fix: same as H9, or an explicit
   420	  INTRODUCES-REJECTION entry per pair in the landing table.
   421	- **M33 (D4-F4, Medium)** — Multi-statement `flow-server`/`output` tails keep the first statement only:
   422	  `flow-server X port A source-address B;` drops source-address; reversed order drops the ENTIRE flow-server
   423	  stanza. Two of the 20 pairs #8799 leaves to "agreement + corpus" do NOT agree with braced, and flat was
   424	  never measured. Silent flow-export misconfiguration. Fix: extend absolute-outcome cells to the remaining
   425	  pairs, all 3 AST shapes.
   426	- **M34 (D4-F5, Medium)** — `security/ipsec` DPD twin folds but never splits (`threshold` buried):
   427	  path-keyed #8790 covers the ike-copy node but not the identical ipsec-copy node while keyword-shared
   428	  scope admits both. Probe: packed `int=10 thr=0` vs braced `int=10 thr=3`, warn=0. Same twin-container class
   429	  as H6 at the next level down; distinct from M20 (split-abort vs never-split). Fix: opt in the ipsec-copy
   430	  DPD node + guard asserting both copies split identically.
   431	- Dedup confirmations (no new IDs): packed RI containers → H7 (credited); elided-gateway no-fold instances
   432	  → M18's documented class; M3 still divergent (see TIP UPDATE below); DPD valueless-flag orders agree
   433	  (dual-path reader saves it); #8788 singles hold.
   434	- NEG ledger: inner-merged leaf-tails (pre-existing class outside the normalizer's contract — flagged to the
   435	  #8796/D2-F1 fixer, not filed), fixture-misread "ipsec drops external-interface" (killed by re-probe),
   436	  `vrf-target` stop-tokens (matches D3-N5), `then next` agreement, cross-family map complete, `then`
   437	  modifier singles (need ≥2 statements — H9).
   438	
   524	### R3-E6 — new-tip fix-residual delta feaa31b2e..5184c40fe (+1 High, +1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround3/E6-newresid.md`)
   525	Worktree `wt-E6` @ tip; per-fix ledger over #8801/#8802/#8803/#8805/#8806 with three-way probes,
   526	`pkg/config` + `pkg/cluster` suites green, tree clean. Discriminator + guard-cell cites re-verified at
   527	tip by the orchestrator; E6-F1 accepted on executed three-way evidence (mechanism consistent with the
   528	single-child fold at a #8803-touched but un-opted-in site).
   529	
   530	- **H11 (E6-F1, High)** — Multi-statement elided `family inet` tail keeps the first statement only:
   531	  `address X filter input f1;` → `fin4=""` (filter lost → forwards unfiltered, fail-open); reversed →
   532	  `addrs=[]` (availability). Braced and flat deliver both. The #8755 cell fixtures only single-statement
   533	  tails while admitted pairs route multi-tails into the single-child fold. Fix: opt `inet`/`inet6` into
   534	  `packedStatements` (b3581b021 standard) or reject multi-statement tails at non-opted-in admitted pairs.
   535	- **M40 (E6-F2, Medium)** — Childless zone-group spellings bypass the #8802 fan-out: `security-zone
   536	  [ zga zgb ];` → 1 zone; `… [ zga zgb ] screen edge;` → 1 zone with `ScreenProfile=""`. The
   537	  discriminator (`Keys ≥ 3 && Children > 0`, `compiler_security_zones.go:148-170`) cannot distinguish a
   538	  childless group from a packed tail. Fail-CLOSED per #8794's posture (policy naming the lost zone
   539	  strict-rejects) → Medium. Fix: resolve by schema membership or fan out childless multi-key zones.
   540	- **L26 (E6-F3, Low)** — #8806 agreement cell covers 1 of 6 routed sites against revert: reverting ONE
   541	  strict-validator site to `namedInstances` leaves the cell GREEN (proven by executed single-site revert
   542	  mutation; fixture group carries no interfaces so the validator path is never stressed). Test-strength
   543	  only, no product divergence today (C4-F7 precedent). Fix: per-site agreement subtests.
   544	- Confirmations (no new IDs): #8801 scope holds (absolute assertions genuine); #8805 bound sound+tight
   545	  (probed edges + same-file/area census); M17 Split still unbounded (already filed); M34 still divergent;
   546	  M1 group-in-second-block behaves exactly as filed; `inet mtu/sampling/dhcp/unnumbered-address` singles
   547	  stay inventory-tracked open work (not believed-fixed); #8800/#8797 untouched (out of scope).
   548	- NEG ledger: identity orders both copies, lease-bound edges, grouped interfaces fail closed through
   549	  routed validators, inet6-output 6th combo delivers, advisory coverage transitive, test-only census
   550	  remainder, stale-comment trivia.
   551	
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:1:**Status corrected: this is NOT blocked, and my earlier comment on it was wrong in three ways. The predicate is usable now, at 3 hits — and its realised precision on that run was 1 in 3, or 1 in 32 against what I first reported.**
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:5:I reported the SILENT bucket at **32** and attributed it to fixture inadequacy from type-invalid synthetic identity names. All three parts were wrong:
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:7:- **29 of the 32 were a defect in my probe**, not the fixtures. I compared only `gateValuePairs[0]`, so a leaf needing a type-specific value looked inert when it was merely mismatched. **#7484's `wordInert` already tries every pair, with a comment stating exactly that reason** — I reused that file's fixtures without reusing the discipline written in them. With every pair, SILENT is **3**.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:11:## What the corrected predicate actually found
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:13:**3 SILENT rows. One is a real defect, and it is a security one:**
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:15:- **#8844** — packed `perfect-forward-secrecy keys <group>` silently DISABLED PFS. Fixed and merged. Unlike the rest of this family it failed **open** and was undetectable afterwards, because `PFSGroup==0` is a legitimate "deliberately disabled" value.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:16:- `class-of-service schedulers equal-flow-enforcement` — **not a defect.** It is read (`sched.EqualFlowEnforcement = true`) and moves output in a realistic fixture. The gate's fixture lacks `transmit-rate ... exact`, which its own desc says it requires. With a parent prerequisite it reclassifies correctly to **`flag`**.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:17:- `class-of-service schedulers equal-flow-target-policy` — **not a defect**, and fixture-limited for a *different* reason: it is an enum, and the gate's value pool contains no valid member, so the value is refused and the leaf looks inert. A parent prerequisite does **not** rescue it; it needs a type-appropriate value.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:25:**1 defect from 3 hits on the corrected run; 1 from the 32 I originally reported.**
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:27:This is published in that form for the same reason the arity census's 12/0 was: **a hit list is only reusable if its ratio is known.** And the sharper lesson is that the noisy version concealed its own best finding — **#8844 was already inside the 32 I had described as "mostly artefacts"**, and shipping that list would have gotten a security defect skimmed past with the other 29.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:29:The honest recommendation for this instrument: **its value was one security defect, and finding it required correcting the instrument twice** — once for the value-pair defect, once for the fixture-adequacy control. Anyone reusing it should assume a third correction is outstanding.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:33:The false-negative shape is still real and is tracked in this issue's body: the predicate scores a head as READ if any `.Name()` clause names it, never checking the clause does anything with the value. The #8785 control proves **sensitivity, not soundness**, and its passing is partly luck about which form #8785 took.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:1:**Findings, and why this is BLOCKED rather than stalled — it should not be closed, and the next person should not rebuild the predicate.**
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:3:## The predicate works, and it is not new work
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:7:Restricted to heads that DO have a compiler clause at their container — the AST predicate's blind spot, which is what this issue is about:
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:12:SILENT (the #8830 class)                   32
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:19:A two-outcome predicate is not merely noisy here, it is **inverted** on a whole subset:
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:23:read, deliberately ignored, ADVISORY   NOT a defect
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:27:`system dataplane cores` compiles to *"retired DPDK-era knob (#1525), accepted for config compatibility but ignored"*. That is the **loud** form of dropping a value, and it is #8785's own documented remedy shape — *read it AND say it does nothing*. Reporting those as defects flags the correct handling as the bug.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:29:**The mechanism that hid this is worth more than the count.** #7484's `gateMarshal` nulls `cfg.Warnings`, and its rationale is written down and **correct for its question**: comparing two spellings, an advisory about a rejected value would make it look installed. For *this* question — "was the value read at all" — an advisory is **evidence of reading**. The same channel is signal for one question and noise for the other, and inheriting the helper inherits its question silently, with no diagnostic. That cost 7 false positives on exactly the subset where someone had already done the right thing. Corrected in #7484 in place: a new `advisory` blind class, `unreachable` 141 → 134, blind total unchanged at 393 — a reclassification, not a regression.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:33:**The SILENT bucket is dominated by fixture inadequacy, not defects.** `vrrp-group priority` sat in it and is plainly read:
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:43:Shipping 32 candidates that are mostly artefacts would be worse than shipping nothing: **a hit list with a bad ratio trains people to ignore the instrument.** The arity census was worth having at 12 hits / 0 defects precisely because its ratio was published; this one's would not survive that test.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:47:**Blocked on #8839** — `args: 1` identity slots with no `keyValidator`, censused at 40 typed / 121 untyped. That is what makes the fixtures viable, and it also moves leaves out of #7484's blind buckets and corrects part of #7492's 228.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:49:A partial fixture-adequacy control is already prototyped (a container is only measurable if some leaf there demonstrably moves output) and took SILENT from 52 to 32, but it is too weak on its own: it passed containers where a *sibling* moved the output while the leaf under test still needed something absent.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:53:- #7484's `advisory` blind class and the `unreachable` correction.
/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830.md:54:- The `gateParentPrereq` header's `vrrp-group` attribution, corrected in place.

exec
/bin/bash -lc "python3 - <<'PY'
from pathlib import Path
import re,subprocess
p=Path('/tmp/muse-spark-review-008.md')
s=p.read_text()
for k in 'HML':
    matches=list(re.finditer(r'"'^(?:### |'"\\- \\*\\*)('+k+r'\\d+)\\b(["'^'"\\n]*)',s,re.M))
    ids=[m.group(1) for m in matches]
    print(k, 'definitions',len(ids),'unique',len(set(ids)), 'ids',','.join(ids))
    if k=='H':
        for m in matches: print(s[:m.start()].count('\\n')+1,m.group(0))
low=s.split('## LOW findings')[1].split('## ROUND 2')[0]
rows=[l for l in low.splitlines() if re.match(r'"'^'"\\| [AC]\\w+-F\\d+ \\|',l)]
print('R1 low table entries:',len(rows))
for sha in ['29d9cb196','feaa31b2e','5184c40fe','72957962b','0c57c0c87','c1f4ddb2103de189e63f0d9d09c79d990d512a5b']:
    for tip in ['b24e26d3b','HEAD']:
        r=subprocess.run(['git','rev-list','--count',sha+'..'+tip],text=True,capture_output=True)
        print(sha,tip,r.stdout.strip() or r.stderr.strip())
PY" in /var/tmp/RES8865
 succeeded in 222ms:
H definitions 11 unique 11 ids H1,H2,H3,H4,H5,H6,H7,H8,H9,H10,H11
31 ### H1 (A3b1-F1) — Multi-statement compact tail drops the zone screen profile; strict-clean fail-open
40 ### H2 (A3b1-F2) — Same lossy fold drops the zone interface binding AND evades the strict undefined-interface rejection
48 ### H3 (C4-F1) — Multi-statement packed tail still drops at admitted non-opted-in sites; tolerant-path fail-open
58 ### H4 (A4-F1) — Commit persists configs the boot loader refuses: accepted commit bricks the next boot
69 ### H5 (A7-F1) — Routing-instance named "mgmt" collides with the hardcoded management VRF
271 - **H6 (D2-F2, High)** — Packed `security ipsec gateway` twin container never splits; `ike-policy` loss
337 - **H7 (D3-F1, High)** — Packed routing-instance tail carrying `routing-options`/`protocols` silently
345 - **H8 (D3-F2, High)** — Elided BGP group `peer-as`-first drops the ENTIRE neighbor set, strict-clean,
402 - **H9 (D4-F1, High)** — REGRESSION from #8793: modifier-first `then` multi-tail (`then count C1 discard;`)
408 - **H10 (D4-F2, High)** — Multi-statement `from` headed by declared-but-unadmitted `next-header` compiles to
530 - **H11 (E6-F1, High)** — Multi-statement elided `family inet` tail keeps the first statement only:
M definitions 59 unique 59 ids M1,M2,M3,M4,M5,M6,M7,M8,M9,M10,M11,M12,M13,M14,M15,M16,M17,M18,M19,M20,M21,M22,M23,M24,M25,M26,M27,M28,M29,M30,M31,M32,M33,M34,M35,M36,M37,M38,M39,M40,M41,M42,M43,M44,M45,M46,M47,M48,M49,M50,M51,M52,M53,M54,M55,M56,M57,M58,M59
L definitions 18 unique 18 ids L20,L21,L22,L23,L24,L25,L26,L27,L28,L29,L30,L31,L32,L33,L34,L35,L36,L37
R1 low table entries: 19
29d9cb196 b24e26d3b 128
29d9cb196 HEAD 131
feaa31b2e b24e26d3b 125
feaa31b2e HEAD 128
5184c40fe b24e26d3b 106
5184c40fe HEAD 109
72957962b b24e26d3b 100
72957962b HEAD 103
0c57c0c87 b24e26d3b 90
0c57c0c87 HEAD 93
c1f4ddb2103de189e63f0d9d09c79d990d512a5b b24e26d3b 109
c1f4ddb2103de189e63f0d9d09c79d990d512a5b HEAD 112

exec
/bin/bash -lc "rg -n '\\bLow\\b|\\bLOW\\b|\\bL3[89]\\b|\\+.*Low|"'^'"\\| [A-Z]' /tmp/muse-spark-review-008.md; nl -ba /tmp/muse-spark-review-009.md | sed -n '169,209p'; nl -ba /tmp/muse-spark-review-008.md | sed -n '395,435p;524,548p'" in /var/tmp/RES8865
 succeeded in 0ms:
5:- Verdict: **109 findings, all OPEN and UNFIXED (review only; no source changed) — 11 High, 59 Medium, 39 Low.**
203:## LOW findings — R1 batch (19; R2 Lows accumulate as L20+ in the ROUND 2 section)
205:| ID | Title | Key site |
207:| A1b1-F1 | Preflight cannot express the enforce L4 bound; post-commit safety rests on callee conventions | `userspace-dp/src/afxdp/frame/mod.rs:730-758` |
208:| A1b3-F1 | PPTP `remove()` unconditionally deletes allocator keys, clobbering a live call on 16-bit id reuse | PPTP allocator |
209:| A1b3-F2 | PPTP install-broadcast shortfall silently dropped (`drain_pptp_control_inbox` ignores partial count) | PPTP control inbox |
210:| A1b4-F1 | GRE-inner IPv4 classifier parses L4 ports out of non-first fragments | GRE classifier |
211:| A1b4-F2 | SlowPath startup handshake spuriously fails a live-but-degraded worker | SlowPath handshake |
212:| A1b4-F3 | Per-creation XSK diagnostic dumps raw ring/mmap pointers, validates nothing | XSK bring-up |
213:| A5-F3 | FenceAck `Status()` confirms on inconsistent counts (`RGsFenced > RGsTotal`) | cluster fence-ack |
214:| A6b1-F1 | Event-stream pause/resume is a dormant leg: write-only flag, zero production callers | `pkg/dataplane/userspace/eventstream.go:85,328-337` |
215:| A6b2-F1 | Zone quarantine scrubs policies/interfaces but leaves NAT snapshots referencing the zone | `zones_quarantine.go:57-126` |
216:| A7-F2 | HA shutdown clear shares one 2 s context across all RGs (first-RG starvation) | `pkg/daemon` shutdown path |
217:| A8-F3 | Long-lived read streams authorized once, never re-validated (revocation does not sever) | `pkg/api` streams |
218:| A10b1-F2 | Local-console ping/traceroute skip shared `diagcmd.CheckArgs` `MaxArgLen` | CLI diag surface |
219:| A10b1-F3 | `csvField` omits `\r` from quote-trigger set on Kea memfile path (client hostnames) | Kea writer |
220:| A10b1-F4 | In-process CLI full-table session walks bypass aggregate `SessionWalkLimiter` (documented tradeoff) | CLI session walk |
221:| A10b2-F1 | Protocol-omitted fragment query skips frag-deny override: false PERMIT (diagnostic-only; dataplane drops) | fragment query path |
222:| C1-F1 | Lenient-retained GRE tunnel `key` wraps through `uint32(Atoi)` (two sites; tip-confirmed: `-1 → 4294967295`) | `pkg/routing/tunnel.go` cast sites |
223:| C1-F2 | Lenient-retained tunnel `ttl` reaches `uint8(ttl)` unchecked (tip-confirmed: `-1 → 255`, `256 → 0`) | `pkg/routing/tunnel.go:736` |
224:| C4-F6 | #8752 fold resolves conflicting scalars first-wins; flat `set` last-wins (tip-confirmed: `desc="second"` vs `"third"`) | `dup_instance_merge_8752.go:100-108` |
225:| C4-F7 | Stale "NOT covered" comment for `from-zone policy` contradicts admitted scope (docs only) | scope comment |
231:### R2-D1 — pkg/cluster HA sync fabric (+2 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround2/D1-sync.md`)
251:- **L20 (D1-F3, Low)** — Heartbeat monitor name length byte wraps for config names ≥256 (300→44);
253:  0x6161 → Legacy fallback). Election-critical RG groups parse first, unaffected — capped at Low.
373:### R2-D6 — daemon apply beyond interfaces (+1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround2/D6-apply.md`)
385:- **L21 (D6-F2, Low)** — `pbrManager.clear()` aggregates ENOENT from an already-gone rule while both
389:  `err=delete stale PBR rule prio 31000`. Retry converges (noise, hence Low). Fix: call
447:### R3-E5 — operational config lifecycle, at tip `5184c40fe` (+2 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround3/E5-opspaths.md`)
464:- **L22 (E5-F2, Low)** — `CheckText` attests a flat file as valid while meaning a different tree than
466:  "same strict parse LoadOverride uses" is false for flat input). Capped at Low: commit still validates
468:- **L23 (E5-F4, Low)** — gRPC/REST `commit confirmed` with `minutes<=0` silently arms a 10-minute window
502:- **L24 (E2-F2, Low)** — DHCP DDNS `ttl` ≥ 2³² retained on the tolerant path, wraps at the RFC 2136 `uint32`
504:  query amplification), `5000000000` → `705032704`. Strict rejects (#6773 verified); tolerant-only, hence Low.
506:- **L25 (E1-F1, Low)** — `build_synced_session_key` (`session_sync.rs:165`) accepts `addr_family`/IP-version
524:### R3-E6 — new-tip fix-residual delta feaa31b2e..5184c40fe (+1 High, +1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround3/E6-newresid.md`)
540:- **L26 (E6-F3, Low)** — #8806 agreement cell covers 1 of 6 routed sites against revert: reverting ONE
552:### R4-F3 — trust + lifecycle ops, at tip `72957962b` (+1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround4/F3-pki.md`)
564:- **L27 (F3-F2, Low)** — World-readable management private key loads silently: write path disciplines
566:  with no warning. Root-only exploitation → defense-in-depth, hence Low. Fix: Warn on group/other-readable
574:### R4-F2 — BPF/XDP program lifecycle, at tip `72957962b` (+1 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround4/F2-bpf.md`)
588:- **L28 (F2-F2, Low)** — Firewall filter map caps (64 configs / 512 rules) are warn-only commit-green;
594:- **L29 (F2-F3, Low, static-evidence)** — Attach-side pin durability best-effort at both ends
598:  accepted as Low on code evidence + in-file asymmetry. Fix: return/record pin failures; mark unpinned
651:### R4-F4 — L2/multicast/legacy, at tip `72957962b` (+1 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround4/F4-l2.md`)
664:- **L30 (F4-F1, Low)** — BFD `minimum-interval`/`multiplier` unvalidated at all 7 schema sites
668:  failover. Filed as Low in the L075 numerics class (L075 doesn't enumerate BFD; sink is the bfdd global
670:- **L31 (F4-F3, Low)** — proxy-ARP commit-path cost unbounded in statement count (per-statement expansion
672:  socket storm under `applySem`. M31's weaker sibling (no goroutines/sleep), hence Low. Fix: commit-time
680:### R4-F5 — control binaries + local IPC, at tip `72957962b` (+2 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround4/F5-ctlbins.md`)
697:- **L32 (F5-F3, Low)** — `HOME` unset drops a CWD-relative history file: secrets land outside `$HOME`;
699:  follows planted symlinks as the operator. Chain needs unset-HOME + attacker CWD → Low. Fix: disable
726:### R5-G2 — render-back fidelity + #8812 group residuals, at tip `0c57c0c87` (+3 Medium, +2 Low; report: `/tmp/review-work.UPFNnV6lttround5/G2-renderfid.md`)
748:- **L33 (G2-F4, Low)** — `display json` drops legitimately-merged duplicate-container content: two same-name
753:- **L34 (G2-F5, Low)** — #8812's OSPF guard cell asserts counts with `{ metric 10; }`, a body the compiler
763:### R5-G3 — daemon entry + fabric client, at tip `0c57c0c87` (+3 Low; report: `/tmp/review-work.UPFNnV6lttround5/G3-xpfd.md`)
768:- **L35 (G3-F1, Low)** — `--grpc-addr=""` violates the `(empty = disabled)` contract (`daemon.go:54`):
774:- **L36 (G3-F2, Low)** — Read-only verbs swallow leftover operands: `version`, `protocol-versions`,
779:- **L37 (G3-F3, Low)** — `syncPeerAddr`/`syncPeerAddr1` data race: async constructor write
   169	
   170	Dedup note: Reports 007/008 contain no exact owner. Report 007 helper-restart finding concerns local helper generation while daemon TCP survives; the delayed-lower-bulk finding concerns ordering after two bulks exist. Here no survivor bulk is sent. This is one fresh incomplete-fix/false-closure residual of closed #6910/#7762: `af145890c` fixes connection preference/eviction but omits the explicitly required prime arm, and the boot-ID path has the same omission. The two signal orderings share one invariant and are not separate findings.
   171	
   172	Verified against comparison revision: **Yes**, classifier, wiring, bulk sender, disconnect, retry/sweep, sticky ACK, tests, README, issue bodies, and fix diff are unchanged at `c1f4ddb2103de189e63f0d9d09c79d990d512a5b`. Both expected-red cells and all shipped controls were rerun there with the same outcomes. Final log: `evidence/final-verify/verification.log`.
   173	
   174	Remediation status: **confirmed, independently accepted, unfixed; recommended for reopening #7762**. No source or issue was changed.
   175	
   176	## Finding 4
   177	
   178	Finding ID: `CSA-R-CONFIGSTORE-002`
   179	
   180	Title: Commit-confirmed can write a recovery record that same-build boot refuses, losing the rollback window
   181	
   182	Severity: **High**. A readable prior active DB expands beyond 16 MiB when nested in `confirm.json`; `CommitConfirmed` reports success, but restart keeps the unconfirmed active generation, refuses the recovery record, and never re-arms rollback. This can permanently strand the management path the feature is meant to protect. Configuration authority, a large prior tree, and restart during the window cap severity below Critical.
   183	
   184	Confidence: **High**. The real strict prior commit, real `CommitConfirmed`, raw sizes, fresh-store recovery state, degraded signal, timer absence, and under-limit positive control were executed.
   185	
   186	Verification: **EXECUTED + STATIC**. Plaintext record behavior was executed hermetically; management lockout and encrypted/base64 expansion were traced.
   187	
   188	Gate verdict: **MATERIAL; independently ACCEPTED at High**.
   189	
   190	Contract: Commit-confirmed must durably preserve the prior tree/deadline so restart within the window re-arms rollback. The same-build writer domain must be a subset of `ReadConfirm`'s domain. The source invariant at `pkg/configstore/store_commit.go:752-755` itself assumes `writeConfirmState` always writes a record `ReadConfirm` accepts.
   191	
   192	Adversarial analysis: An authenticated administrator has a large but valid active tree, applies a small potentially management-stranding change using commit-confirmed, and the daemon restarts before confirmation. No malicious actor, race, I/O error, disk corruption, or foreign version is required. #8566 exposes degraded health after boot, but the changed management path may already be unreachable.
   193	
   194	Evidence: `pkg/configstore/db.go:229-238` writes the fully nested record without a size check:
   195	
   196	```go
   197	data, err := json.MarshalIndent(rec, "", "  ")
   198	...
   199	data, err = db.maybeEncryptTreeJSON(data, rec.PrevTree, nil)
   200	...
   201	if err := fsatomic.WriteFileDurable(db.confirmPath(), data, 0600); err != nil {
   202	```
   203	
   204	`ReadConfirm` caps the complete file at `MaxConfigSize` before decrypt/decode (`db.go:264-271`). `recoverPendingConfirmLocked` handles refusal by keeping the unconfirmed active config, setting degraded health, and returning without a timer (`store_persist.go:154-187`).
   205	
   206	Probe: The independent configstore overlay passed. A prior strict commit produced a readable 16,441,659-byte active DB. A tiny next candidate plus `CommitConfirmed(10)` returned success, wrote a 562-byte active DB and 17,773,786-byte `confirm.json`; fresh `Load` kept the new active config, reported degraded recovery, and had no confirm timer. The identical state machine with a 4,791,786-byte confirm record re-armed normally. Artifacts/hashes and full record: `evidence/config-storage-api/review-configstore-size-symmetry.md`.
   207	
   208	Trace: large readable active tree -> small confirmed candidate -> active write/promote -> prior tree nested/pretty-printed in confirm record -> record crosses raw reader ceiling -> durable write succeeds -> operation reports armed -> restart loads small active -> `ReadConfirm` refuses -> #8566 degraded-but-boot path -> no rollback timer -> unconfirmed generation persists.
   209	
   395	  static/tunnel/XFRM fail-closed seams, prio-shift convergence, route-subscription overflow (below bar).
   396	
   397	### R2-D4 — tip fix-residual delta c16a9b12a..feaa31b2e (+2 High, +3 Medium; report: `/tmp/review-work.UPFNnV6lttround2/D4-fixresid2.md`)
   398	Worktree `wt-D4` @ tip; per-fix ledger over #8788/#8789/#8790/#8793/#8795/#8798/#8799 with three-way
   399	packed/braced/flat + pass-off probes, full `pkg/config` suite green, tree clean. Orchestrator re-probed
   400	D4-F1/F2 at tip (`evidence-verify/r2-verify.log`): CONFIRMED both.
   401	
   402	- **H9 (D4-F1, High)** — REGRESSION from #8793: modifier-first `then` multi-tail (`then count C1 discard;`)
   403	  folds to one child, `discard` buried, `Action=""` renders ACCEPT. Pass-off proves pre-fix the leaf path
   404	  read it correctly. Reverse order never folds (opposite outcome — order-dependent). The exact fail-open
   405	  the #2399 belt exists to prevent. Tip evidence: `F1 packed action=""` vs `F1 braced action="discard"`.
   406	  Fix: opt `then` into packedStatements (ordered pairs incl. modifier mixes) or scan one level for terminal
   407	  actions in the children path.
   408	- **H10 (D4-F2, High)** — Multi-statement `from` headed by declared-but-unadmitted `next-header` compiles to
   409	  EMPTY match, strict-clean: `packedBodyChildren` chains statements, and after `[next-header tcp]` the
   410	  cursor sits on a leaf schema so `source-address` resolves nil → whole body discarded → match-all term
   411	  with `accept`. Reversed order strict-REJECTS (same leaf, opposite verdicts by order). The precise leaf
   412	  #8788 just repaired still yields a no-warning match-everything term. Tip evidence: `F2 packed
   413	  match-proto=[] src=[] action="accept"` vs `F2 braced match-proto=[tcp] src=[2001:db8::/32]`. Fix: admit
   414	  (`from`,`next-header`) AND harden `packedBodyChildren` (reset per sibling statement instead of discarding
   415	  even the consumed head).
   416	- **M32 (D4-F3, Medium)** — Admitted-first multi-statement `from` tails now strict-REJECT legitimate configs
   417	  (first arm absorbs the sibling keyword as a value); lenient keeps verbatim garbage with a warning.
   418	  No fail-open post-fix, but strict availability break + tolerant garbage; the landing cell can't see it
   419	  (single-statement fixtures; `pOff==br` checked before `pOn==br`). Fix: same as H9, or an explicit
   420	  INTRODUCES-REJECTION entry per pair in the landing table.
   421	- **M33 (D4-F4, Medium)** — Multi-statement `flow-server`/`output` tails keep the first statement only:
   422	  `flow-server X port A source-address B;` drops source-address; reversed order drops the ENTIRE flow-server
   423	  stanza. Two of the 20 pairs #8799 leaves to "agreement + corpus" do NOT agree with braced, and flat was
   424	  never measured. Silent flow-export misconfiguration. Fix: extend absolute-outcome cells to the remaining
   425	  pairs, all 3 AST shapes.
   426	- **M34 (D4-F5, Medium)** — `security/ipsec` DPD twin folds but never splits (`threshold` buried):
   427	  path-keyed #8790 covers the ike-copy node but not the identical ipsec-copy node while keyword-shared
   428	  scope admits both. Probe: packed `int=10 thr=0` vs braced `int=10 thr=3`, warn=0. Same twin-container class
   429	  as H6 at the next level down; distinct from M20 (split-abort vs never-split). Fix: opt in the ipsec-copy
   430	  DPD node + guard asserting both copies split identically.
   431	- Dedup confirmations (no new IDs): packed RI containers → H7 (credited); elided-gateway no-fold instances
   432	  → M18's documented class; M3 still divergent (see TIP UPDATE below); DPD valueless-flag orders agree
   433	  (dual-path reader saves it); #8788 singles hold.
   434	- NEG ledger: inner-merged leaf-tails (pre-existing class outside the normalizer's contract — flagged to the
   435	  #8796/D2-F1 fixer, not filed), fixture-misread "ipsec drops external-interface" (killed by re-probe),
   524	### R3-E6 — new-tip fix-residual delta feaa31b2e..5184c40fe (+1 High, +1 Medium, +1 Low; report: `/tmp/review-work.UPFNnV6lttround3/E6-newresid.md`)
   525	Worktree `wt-E6` @ tip; per-fix ledger over #8801/#8802/#8803/#8805/#8806 with three-way probes,
   526	`pkg/config` + `pkg/cluster` suites green, tree clean. Discriminator + guard-cell cites re-verified at
   527	tip by the orchestrator; E6-F1 accepted on executed three-way evidence (mechanism consistent with the
   528	single-child fold at a #8803-touched but un-opted-in site).
   529	
   530	- **H11 (E6-F1, High)** — Multi-statement elided `family inet` tail keeps the first statement only:
   531	  `address X filter input f1;` → `fin4=""` (filter lost → forwards unfiltered, fail-open); reversed →
   532	  `addrs=[]` (availability). Braced and flat deliver both. The #8755 cell fixtures only single-statement
   533	  tails while admitted pairs route multi-tails into the single-child fold. Fix: opt `inet`/`inet6` into
   534	  `packedStatements` (b3581b021 standard) or reject multi-statement tails at non-opted-in admitted pairs.
   535	- **M40 (E6-F2, Medium)** — Childless zone-group spellings bypass the #8802 fan-out: `security-zone
   536	  [ zga zgb ];` → 1 zone; `… [ zga zgb ] screen edge;` → 1 zone with `ScreenProfile=""`. The
   537	  discriminator (`Keys ≥ 3 && Children > 0`, `compiler_security_zones.go:148-170`) cannot distinguish a
   538	  childless group from a packed tail. Fail-CLOSED per #8794's posture (policy naming the lost zone
   539	  strict-rejects) → Medium. Fix: resolve by schema membership or fan out childless multi-key zones.
   540	- **L26 (E6-F3, Low)** — #8806 agreement cell covers 1 of 6 routed sites against revert: reverting ONE
   541	  strict-validator site to `namedInstances` leaves the cell GREEN (proven by executed single-site revert
   542	  mutation; fixture group carries no interfaces so the validator path is never stressed). Test-strength
   543	  only, no product divergence today (C4-F7 precedent). Fix: per-site agreement subtests.
   544	- Confirmations (no new IDs): #8801 scope holds (absolute assertions genuine); #8805 bound sound+tight
   545	  (probed edges + same-file/area census); M17 Split still unbounded (already filed); M34 still divergent;
   546	  M1 group-in-second-block behaves exactly as filed; `inet mtu/sampling/dhcp/unnumbered-address` singles
   547	  stay inventory-tracked open work (not believed-fixed); #8800/#8797 untouched (out of scope).
   548	- NEG ledger: identity orders both copies, lease-bound edges, grouped interfaces fail closed through

exec
/bin/bash -lc "python3 - <<'PY'
import subprocess
files=['pkg/configstore/store_commit.go','pkg/configstore/db.go','pkg/configstore/store_persist.go','pkg/configstore/bounded_read.go','pkg/daemon/daemon_run_bringup.go']
for sha in ['29d9cb196','0c57c0c87','c1f4ddb2103de189e63f0d9d09c79d990d512a5b']:
    r=subprocess.run(['git','diff','--stat',sha,'HEAD','--',*files],text=True,capture_output=True)
    print(sha,r.stdout.strip() or '(all five paths unchanged)')
PY
nl -ba /tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md | sed -n '1,35p'" in /var/tmp/RES8865
 succeeded in 114ms:
29d9cb196 (all five paths unchanged)
0c57c0c87 (all five paths unchanged)
c1f4ddb2103de189e63f0d9d09c79d990d512a5b (all five paths unchanged)
     1	**Status corrected: this is NOT blocked, and my earlier comment on it was wrong in three ways. The predicate is usable now, at 3 hits — and its realised precision on that run was 1 in 3, or 1 in 32 against what I first reported.**
     2	
     3	## Retraction of my previous comment
     4	
     5	I reported the SILENT bucket at **32** and attributed it to fixture inadequacy from type-invalid synthetic identity names. All three parts were wrong:
     6	
     7	- **29 of the 32 were a defect in my probe**, not the fixtures. I compared only `gateValuePairs[0]`, so a leaf needing a type-specific value looked inert when it was merely mismatched. **#7484's `wordInert` already tries every pair, with a comment stating exactly that reason** — I reused that file's fixtures without reusing the discipline written in them. With every pair, SILENT is **3**.
     8	- **The gate does not synthesise type-invalid identities.** `gateEffectivePath` already falls back to numeric args — for vrrp it chooses `vrrp-group 7`, and `wordInert(numeric)` is false, meaning the leaf does move output. #7492's typed path-identifier fallback covers this. My three-row isolation was real; I generalised it to a population it does not describe.
     9	- **Not blocked on #8839.** That fix is a commit-time validator; nothing in SILENT was ever an identity-name problem, so it could not have moved the bucket — and measured, it moved it by exactly **0**. #8839's vrrp validator stands on its own as an operator-facing fix.
    10	
    11	## What the corrected predicate actually found
    12	
    13	**3 SILENT rows. One is a real defect, and it is a security one:**
    14	
    15	- **#8844** — packed `perfect-forward-secrecy keys <group>` silently DISABLED PFS. Fixed and merged. Unlike the rest of this family it failed **open** and was undetectable afterwards, because `PFSGroup==0` is a legitimate "deliberately disabled" value.
    16	- `class-of-service schedulers equal-flow-enforcement` — **not a defect.** It is read (`sched.EqualFlowEnforcement = true`) and moves output in a realistic fixture. The gate's fixture lacks `transmit-rate ... exact`, which its own desc says it requires. With a parent prerequisite it reclassifies correctly to **`flag`**.
    17	- `class-of-service schedulers equal-flow-target-policy` — **not a defect**, and fixture-limited for a *different* reason: it is an enum, and the gate's value pool contains no valid member, so the value is refused and the leaf looks inert. A parent prerequisite does **not** rescue it; it needs a type-appropriate value.
    18	
    19	**The two causes are distinct and recorded as such deliberately** — "fixture-limited" alone would invite someone to re-measure them as candidates.
    20	
    21	**A prerequisite for `class-of-service schedulers <*>` was tried and backed out**: it also moves `codel-target` from `unreachable` into `valueMoves`, whose ceiling is **0**, so it would red the ratchet to buy a reclassification not verified end to end. #7484's convention is that only end-to-end-verified rows belong in that map.
    22	
    23	## Realised precision, published
    24	
    25	**1 defect from 3 hits on the corrected run; 1 from the 32 I originally reported.**
    26	
    27	This is published in that form for the same reason the arity census's 12/0 was: **a hit list is only reusable if its ratio is known.** And the sharper lesson is that the noisy version concealed its own best finding — **#8844 was already inside the 32 I had described as "mostly artefacts"**, and shipping that list would have gotten a security defect skimmed past with the other 29.
    28	
    29	The honest recommendation for this instrument: **its value was one security defect, and finding it required correcting the instrument twice** — once for the value-pair defect, once for the fixture-adequacy control. Anyone reusing it should assume a third correction is outstanding.
    30	
    31	## Standing limitations (unchanged)
    32	
    33	The false-negative shape is still real and is tracked in this issue's body: the predicate scores a head as READ if any `.Name()` clause names it, never checking the clause does anything with the value. The #8785 control proves **sensitivity, not soundness**, and its passing is partly luck about which form #8785 took.

codex
I found local copies of both reports. Their contents contradict two planning premises: I count 111 finding entries across them, while 128 commits applies only to 008’s first-round verification tip. At the plan’s base, 008’s final round is 90 commits old and 009’s comparison tip is 109. The persistence paths cited for H4 are unchanged from those report revisions.

exec
/bin/bash -lc "python3 - <<'PY'
from pathlib import Path
import re
s=Path('/tmp/muse-spark-review-008.md').read_text()
entries=[]
for i,l in enumerate(s.splitlines(),1):
    if re.match(r'"'^(?:### |'"\\- \\*\\*)[HML]\\d+\\b',l): entries.append((i,l))
    elif re.match(r'"'^'"\\| [AC]\\w+-F\\d+ \\|',l): entries.append((i,l))
print('008 numbered definitions plus R1 Low table rows:',len(entries))
s9=Path('/tmp/muse-spark-review-009.md').read_text()
print('009 numbered findings:',len(re.findall(r'"'^## Finding '"\\d+"'$'"',s9,re.M)))
print('Total:',len(entries)+len(re.findall(r'"'^## Finding '"\\d+"'$'"',s9,re.M)))
print('008 final low definitions:')
for i,l in entries:
    if re.match(r'"'^- '"\\*\\*L3[4-9]\\b',l): print(i,l)
PY" in /var/tmp/RES8865
 succeeded in 0ms:
008 numbered definitions plus R1 Low table rows: 107
009 numbered findings: 4
Total: 111
008 final low definitions:
753 - **L34 (G2-F5, Low)** — #8812's OSPF guard cell asserts counts with `{ metric 10; }`, a body the compiler
768 - **L35 (G3-F1, Low)** — `--grpc-addr=""` violates the `(empty = disabled)` contract (`daemon.go:54`):
774 - **L36 (G3-F2, Low)** — Read-only verbs swallow leftover operands: `version`, `protocol-versions`,
779 - **L37 (G3-F3, Low)** — `syncPeerAddr`/`syncPeerAddr1` data race: async constructor write

exec
/bin/bash -lc "nl -ba pkg/configstore/db.go | sed -n '205,243p;260,277p'; nl -ba pkg/configstore/store_persist.go | sed -n '151,188p'; nl -ba /tmp/muse-spark-review-009.md | sed -n '174,190p'; nl -ba pkg/config/compiler_security_zones.go | sed -n '374,407p'; rg -n '\"security-zone\"' pkg/config/schema_security.go | head -8; git status --short" in /var/tmp/RES8865
 succeeded in 0ms:
   205		// Written durably BEFORE the delete it precedes, and only at the point the
   206		// removal is actually reached — which #5473 already defers until the
   207		// resolving write is durable — so a tombstone never marks a window whose
   208		// resolution did not take effect. A tombstone write that itself fails
   209		// degrades to exactly the pre-#8565 behaviour, never worse.
   210		//
   211		// Additive, per this file's own contract: an older reader ignores the
   212		// unknown field and behaves as it does today.
   213		Resolved bool `json:"resolved,omitempty"`
   214	}
   215	
   216	// confirmPath returns the path to the pending commit-confirmed state file.
   217	func (db *DB) confirmPath() string {
   218		return filepath.Join(db.dir, "confirm.json")
   219	}
   220	
   221	// WriteConfirm persists the pending commit-confirmed state durably (#4577):
   222	// temp + fsync + rename + dir fsync, so the deadline+rollback-target survive
   223	// power loss. The embedded PrevTree may carry secret leaves (IKE PSK, auth
   224	// keys), so it is encrypted with the same master-password machinery as
   225	// active.json (keyed off the prev tree's master-password leaf) and written
   226	// owner-only 0600. No #1917 compatibility envelope is used — the file is
   227	// transient recovery state, not a committed config, and confirmRecord evolves
   228	// via additive JSON fields.
   229	func (db *DB) WriteConfirm(rec *confirmRecord) error {
   230		data, err := json.MarshalIndent(rec, "", "  ")
   231		if err != nil {
   232			return fmt.Errorf("marshal confirm state: %w", err)
   233		}
   234		data, err = db.maybeEncryptTreeJSON(data, rec.PrevTree, nil)
   235		if err != nil {
   236			return fmt.Errorf("encrypt confirm state: %w", err)
   237		}
   238		if err := fsatomic.WriteFileDurable(db.confirmPath(), data, 0600); err != nil {
   239			return fmt.Errorf("persist confirm state: %w", err)
   240		}
   241		return nil
   242	}
   243	
   260	//
   261	// recoverPendingConfirmLocked already treats a read error as fail-closed (log
   262	// + skip restore, keep the loaded active config, never panic), so a degenerate
   263	// record can no longer drive a bogus empty rollback.
   264	func (db *DB) ReadConfirm() (*confirmRecord, error) {
   265		// #8597 (muse-004 K70): BOUNDED. This module's own answer to an unbounded
   266		// authoritative read is ReadBoundedFile (#6753/#4909) — which also refuses a
   267		// non-regular file — and the most privileged reads on the boot path were the
   268		// ones still using os.ReadFile.
   269		data, err := ReadBoundedFile(db.confirmPath(), MaxConfigSize)
   270		if err != nil {
   271			if os.IsNotExist(err) {
   272				return nil, nil
   273			}
   274			return nil, fmt.Errorf("read confirm state: %w", err)
   275		}
   276		data, _, err = db.maybeDecryptTreeJSON(data, nil)
   277		if err != nil {
   151	// rollback itself still runs to completion first — reverting the unconfirmed
   152	// config is the safety property, and the operator needs the reverted tree
   153	// reachable to fix it from the CLI.
   154	func (s *Store) recoverPendingConfirmLocked() error {
   155		if s.db == nil {
   156			return nil
   157		}
   158		rec, err := s.db.ReadConfirm()
   159		if err != nil {
   160			// #8566: this used to be a bare WARN + `return nil`, so `Load` reported
   161			// success and the box came up with the rollback window silently gone —
   162			// no timer, no debt, and `ConfigPersistDegraded()` false, so /health
   163			// returned 200. Every OTHER way the store ends a boot unsafe raises
   164			// degraded health; this one did not, so nothing alerted on it.
   165			//
   166			// `Load` still succeeds: refusing to boot on an unreadable TRANSIENT
   167			// recovery file would turn a corrupt 200-byte file into an outage,
   168			// which is the #1960 no-brick posture. The state is made VISIBLE
   169			// instead, and the record is left in place — a decrypt failure can be a
   170			// transient master-key problem and the window may be readable on a
   171			// later boot.
   172			//
   173			// Deliberately NOT added here: a bounded in-`Load` retry split by error
   174			// class. That is a startup-latency and taxonomy change with its own
   175			// design (the #7675 seed's TRANSIENT/PERMANENT split) and belongs in its
   176			// own review, not folded into making the state legible.
   177			slog.Error("failed to read persisted commit-confirmed state; the pending auto-rollback "+
   178				"window is LOST for this process and the unconfirmed config now stands with no "+
   179				"timer — configuration persistence is degraded until a commit or confirm clears it",
   180				"err", err, "issue", "#8566")
   181			s.confirmRecoveryReadFailed = true
   182			s.journalLog(&JournalEntry{
   183				Action: "confirm_recovery_read_error",
   184				Detail: fmt.Sprintf("pending commit-confirmed record unreadable on boot; auto-rollback window lost: %v", err),
   185			})
   186			return nil
   187		}
   188		if rec == nil {
   174	Remediation status: **confirmed, independently accepted, unfixed; recommended for reopening #7762**. No source or issue was changed.
   175	
   176	## Finding 4
   177	
   178	Finding ID: `CSA-R-CONFIGSTORE-002`
   179	
   180	Title: Commit-confirmed can write a recovery record that same-build boot refuses, losing the rollback window
   181	
   182	Severity: **High**. A readable prior active DB expands beyond 16 MiB when nested in `confirm.json`; `CommitConfirmed` reports success, but restart keeps the unconfirmed active generation, refuses the recovery record, and never re-arms rollback. This can permanently strand the management path the feature is meant to protect. Configuration authority, a large prior tree, and restart during the window cap severity below Critical.
   183	
   184	Confidence: **High**. The real strict prior commit, real `CommitConfirmed`, raw sizes, fresh-store recovery state, degraded signal, timer absence, and under-limit positive control were executed.
   185	
   186	Verification: **EXECUTED + STATIC**. Plaintext record behavior was executed hermetically; management lockout and encrypted/base64 expansion were traced.
   187	
   188	Gate verdict: **MATERIAL; independently ACCEPTED at High**.
   189	
   190	Contract: Commit-confirmed must durably preserve the prior tree/deadline so restart within the window re-arms rollback. The same-build writer domain must be a subset of `ReadConfirm`'s domain. The source invariant at `pkg/configstore/store_commit.go:752-755` itself assumes `writeConfirmState` always writes a record `ReadConfirm` accepts.
   374							// if #6735's gate is ever narrowed, this belt becomes
   375							// live again, and the next reader should know the
   376							// dependency runs in that direction.
   377							for _, name := range zoneInterfaceMemberKeys(iface) {
   378								zone.InterfaceHostInbound[name] = mergeHostInbound(zone.InterfaceHostInbound[name], cloneHostInbound(hib))
   379							}
   380						}
   381					}
   382				case "screen":
   383					zone.ScreenProfile = nodeVal(prop)
   384				case "host-inbound-traffic":
   385					// #4544: MERGE repeated zone-level host-inbound-traffic blocks
   386					// rather than overwrite (Junos merge semantics). This case
   387					// fires once per host-inbound-traffic child; `load override`
   388					// splices a raw hierarchical parse whose two literal blocks stay
   389					// as separate siblings, so a bare `=` assignment silently drops
   390					// every block but the last. Accumulate into the zone value.
   391					// #4818 extends this across duplicate top-level security-zone
   392					// instances too, since zone is now find-or-create.
   393					zone.HostInboundTraffic = mergeHostInbound(zone.HostInboundTraffic, parseHostInboundNode(prop))
   394				case "tcp-rst":
   395					zone.TCPRst = true
   396				case "description":
   397					zone.Description = nodeVal(prop)
   398				case "address-book":
   399					// #3061: zone-local address book. Same entry grammar as the
   400					// global book; resolved into the global book under
   401					// zone-qualified internal names later (resolveZoneLocalAddressBooks).
   402					// #4818: find-or-create rather than always allocating a fresh
   403					// AddressBook, so a second security-zone instance's
   404					// address-book block MERGES into the first's (by address/
   405					// address-set name, via parseAddressBookEntries's own
   406					// find-or-create — #4706) instead of replacing it outright.
   407					ab := zone.AddressBook
168:		"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
?? docs/research/8865-muse-spark-008-009/claude-smr-plan-r1.md
?? docs/research/8865-muse-spark-008-009/codex-plan-r1.md
?? docs/research/8865-muse-spark-008-009/codex-plan-r1b.md

codex
PLAN-REVISE

1. **The central five-member enumeration is demonstrably incomplete.** At `958de0c92`, [heartbeat.go:370](/var/tmp/RES8865/pkg/cluster/heartbeat.go:370) reads a wire group count, validates the required length, then allocates `[]HeartbeatGroup` at line 376. This is another safe member under the plan’s stated `pkg/cluster` boundary, directly comparable to its two failover examples. The plan’s “four commands” are not published, so their coverage cannot be audited. **Verified:** an omitted member, not an additional vulnerability. **Conclusion:** the example used to establish complete enumeration already disproves that claim.

2. **“Reject versus clamp” is not a sufficient repair invariant.** I verified the DHCP allocation at [sync_protocol.go:1231](/var/tmp/RES8865/pkg/cluster/sync_protocol.go:1231), the IPsec split at [line 806](/var/tmp/RES8865/pkg/cluster/sync_protocol.go:806), and the fixed NAT sibling at [sync_persistent_nat_lease_8121.go:149](/var/tmp/RES8865/pkg/cluster/sync_persistent_nat_lease_8121.go:149). Rejecting counts above a bound based on four-byte prefixes still permits amplified allocation for counts within that bound. PHA-001 explicitly identifies this and requires valid-record checks and a decoded-resource budget. [Report evidence](/tmp/muse-spark-review-009.md:59).

   IPsec also has no explicit wire count or rejection result: its caller unconditionally replaces the held set with the returned names. Returning `nil` as “rejection” would therefore clear state. [Caller](/var/tmp/RES8865/pkg/cluster/sync_conn_read.go:484). Meanwhile, the NAT sibling explicitly documents DHCP’s different compatibility contract, which an existing test preserves. [Contract test](/var/tmp/RES8865/pkg/cluster/sync_truncated_record_7175_test.go:194). **Conclusion:** “fix is one shape” conceals distinct allocation, compatibility, and state-update decisions. The proposed rejection assertion would not establish the required memory bound.

3. **The class-first recommendation extrapolates from its easiest example without establishing comparable enumeration for the other classes.** I checked all three:

   - **Packed folds:** searching `packedStatements: true` finds eight existing opt-ins; it cannot identify missing opt-ins. The implementation also depends on scope admission, schema completeness, statement boundaries, and compiler behavior. The schema documents incompatible lowering cases, while the guard requires fixtures for every ordered leaf pair. [Schema contract](/var/tmp/RES8865/pkg/config/schema.go:74), [guard](/var/tmp/RES8865/pkg/config/packed_optin_guard_8768_test.go:10).
   - **Reserved names:** collision analysis crosses user namespaces, generated names, activation conditions, and downstream reconciliation. I verified conditional insertion of `mgmt`, `vrf-` name construction, and separately reserved generated route-map suffixes. These are not equivalent to enumerating string constants. [Management insertion](/var/tmp/RES8865/pkg/daemon/daemon_apply_interfaces.go:191), [reconciliation](/var/tmp/RES8865/pkg/routing/vrf.go:183), [generated-name contracts](/var/tmp/RES8865/pkg/config/compiler_validate_strict_routing.go:1308).
   - **Commit/load asymmetry:** writers serialize, optionally encrypt, and frame data before readers apply their limits. Recovery artifacts have different failure dispositions. Establishing symmetry requires tracing those transformations and callers. [Writer](/var/tmp/RES8865/pkg/configstore/db.go:477), [recovery handling](/var/tmp/RES8865/pkg/configstore/store_persist.go:154).

   **Conclusion:** none has a published complete enumeration or measured comparable cost. The plan establishes neither that these classes enumerate cheaply nor that enumeration is complete enough to choose the overall triage method.

4. **The four-class map covers the sampled findings, not the reports.** The plan explicitly identifies only seven report IDs: H1–H5, M17, and PHA-001. “+ M-rows” supplies no auditable mapping. It leaves 008 H6–H11 and three of 009’s four Highs without an explicit disposition. [008 High definitions](/tmp/muse-spark-review-008.md:271), [009 inventory](/tmp/muse-spark-review-009.md:24).

   More damagingly, **009 CSA-R-CONFIGSTORE-002 is already a named commit/load sibling**, yet the class table calls H4 a “single instance.” I verified that `WriteConfirm` writes without a corresponding size gate, `ReadConfirm` applies the ceiling, and failed recovery leaves no rollback timer. [Write/read paths](/var/tmp/RES8865/pkg/configstore/db.go:229), [recovery consequence](/var/tmp/RES8865/pkg/configstore/store_persist.go:158). **Conclusion:** even the existing class map misses an explicitly reported High in its own class. Deferring everything else to “remaining ~104” does not establish coverage.

5. **Putting H4 verification second is unjustified by the supplied evidence.** I traced commit through persistence, bounded active-DB loading, and fatal startup handling. [Commit](/var/tmp/RES8865/pkg/configstore/store_commit.go:185), [bounded read](/var/tmp/RES8865/pkg/configstore/db.go:354), [startup refusal](/var/tmp/RES8865/pkg/daemon/daemon_run_bringup.go:299). The five relevant persistence/bring-up files are unchanged from 008’s verification revision. The report records an end-to-end accepted-commit/failed-reload result. [H4 evidence](/tmp/muse-spark-review-008.md:58).

   **Verified here:** the source chain and unchanged files; I did not independently reproduce the failure. **Conclusion:** the plan’s own “highest consequence” assessment has substantial supporting evidence. It provides no dependency, exposure comparison, or time-to-fix argument for completing the wire class before resolving H4’s status. The sequence is not defensible as written.

6. **“One change closes many findings” is stronger than the demonstrated benefit.** The wire class proposes two decoder repairs addressing exactly two report findings. The other three listed members are already safe or fixed; they are not new closures. [Proposed sequence](/var/tmp/RES8865/docs/research/8865-muse-spark-008-009/plan.md:114). Moreover, finding 2 above shows those repairs do not yet share a complete implementation contract. **Conclusion:** the evidence supports investigating siblings together. It does not demonstrate the broad closure multiplier used to recommend class-first across the corpus.

7. **The instrument comparison selectively uses the obsolete denominator and discounts the security outcome.** The retained #8830 correction states **one defect from three corrected hits**, versus one from the original 32; 29 original hits resulted from a probe defect. [Correction](/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:5). I corroborated the discovery through commit `a7f84a209` and the PFS regression guard: the corrected behavioral predicate found the silent loss of configured PFS that the schema-based enumeration could not represent. [Guard and mechanism](/var/tmp/RES8865/pkg/config/pfs_packed_keys_8844_test.go:5).

   **Conclusion:** two corrections are legitimate development cost. “1 from 32” is not evidence that the successful method was uneconomic, particularly without elapsed-cost, severity, missed-defect, or reuse comparisons. It cannot justify the categorical restriction against instruments for apparently enumerable classes.

8. **The corpus and staleness premises fail the plan’s own “derive counts” requirement.** Counting actual entries in the available reports gives **008: 11 High + 59 Medium + 37 Low = 107**, plus 009’s four findings: **111 listed entries**. The 008 header claims 109, but its Low entries comprise 19 initial table rows followed by L20–L37. Two claimed entries remain unreconciled. [Initial Low table](/tmp/muse-spark-review-008.md:203), [last Low entries](/tmp/muse-spark-review-008.md:763).

   `git rev-list --count <revision>..b24e26d3b` gives **128** for 008’s first-round verification tip, **90** for its final-round tip, and **109** for 009’s comparison tip—not “128+ since either report’s tip.” [008 revisions](/tmp/muse-spark-review-008.md:3), [009 revision](/tmp/muse-spark-review-009.md:7). These reports are stale, but their evidence spans different revisions. The workload and staleness argument uses unreconciled metadata. All verification above was document, source, and Git-history inspection; no runtime reproductions or tests were executed.
tokens used
137,105
PLAN-REVISE

1. **The central five-member enumeration is demonstrably incomplete.** At `958de0c92`, [heartbeat.go:370](/var/tmp/RES8865/pkg/cluster/heartbeat.go:370) reads a wire group count, validates the required length, then allocates `[]HeartbeatGroup` at line 376. This is another safe member under the plan’s stated `pkg/cluster` boundary, directly comparable to its two failover examples. The plan’s “four commands” are not published, so their coverage cannot be audited. **Verified:** an omitted member, not an additional vulnerability. **Conclusion:** the example used to establish complete enumeration already disproves that claim.

2. **“Reject versus clamp” is not a sufficient repair invariant.** I verified the DHCP allocation at [sync_protocol.go:1231](/var/tmp/RES8865/pkg/cluster/sync_protocol.go:1231), the IPsec split at [line 806](/var/tmp/RES8865/pkg/cluster/sync_protocol.go:806), and the fixed NAT sibling at [sync_persistent_nat_lease_8121.go:149](/var/tmp/RES8865/pkg/cluster/sync_persistent_nat_lease_8121.go:149). Rejecting counts above a bound based on four-byte prefixes still permits amplified allocation for counts within that bound. PHA-001 explicitly identifies this and requires valid-record checks and a decoded-resource budget. [Report evidence](/tmp/muse-spark-review-009.md:59).

   IPsec also has no explicit wire count or rejection result: its caller unconditionally replaces the held set with the returned names. Returning `nil` as “rejection” would therefore clear state. [Caller](/var/tmp/RES8865/pkg/cluster/sync_conn_read.go:484). Meanwhile, the NAT sibling explicitly documents DHCP’s different compatibility contract, which an existing test preserves. [Contract test](/var/tmp/RES8865/pkg/cluster/sync_truncated_record_7175_test.go:194). **Conclusion:** “fix is one shape” conceals distinct allocation, compatibility, and state-update decisions. The proposed rejection assertion would not establish the required memory bound.

3. **The class-first recommendation extrapolates from its easiest example without establishing comparable enumeration for the other classes.** I checked all three:

   - **Packed folds:** searching `packedStatements: true` finds eight existing opt-ins; it cannot identify missing opt-ins. The implementation also depends on scope admission, schema completeness, statement boundaries, and compiler behavior. The schema documents incompatible lowering cases, while the guard requires fixtures for every ordered leaf pair. [Schema contract](/var/tmp/RES8865/pkg/config/schema.go:74), [guard](/var/tmp/RES8865/pkg/config/packed_optin_guard_8768_test.go:10).
   - **Reserved names:** collision analysis crosses user namespaces, generated names, activation conditions, and downstream reconciliation. I verified conditional insertion of `mgmt`, `vrf-` name construction, and separately reserved generated route-map suffixes. These are not equivalent to enumerating string constants. [Management insertion](/var/tmp/RES8865/pkg/daemon/daemon_apply_interfaces.go:191), [reconciliation](/var/tmp/RES8865/pkg/routing/vrf.go:183), [generated-name contracts](/var/tmp/RES8865/pkg/config/compiler_validate_strict_routing.go:1308).
   - **Commit/load asymmetry:** writers serialize, optionally encrypt, and frame data before readers apply their limits. Recovery artifacts have different failure dispositions. Establishing symmetry requires tracing those transformations and callers. [Writer](/var/tmp/RES8865/pkg/configstore/db.go:477), [recovery handling](/var/tmp/RES8865/pkg/configstore/store_persist.go:154).

   **Conclusion:** none has a published complete enumeration or measured comparable cost. The plan establishes neither that these classes enumerate cheaply nor that enumeration is complete enough to choose the overall triage method.

4. **The four-class map covers the sampled findings, not the reports.** The plan explicitly identifies only seven report IDs: H1–H5, M17, and PHA-001. “+ M-rows” supplies no auditable mapping. It leaves 008 H6–H11 and three of 009’s four Highs without an explicit disposition. [008 High definitions](/tmp/muse-spark-review-008.md:271), [009 inventory](/tmp/muse-spark-review-009.md:24).

   More damagingly, **009 CSA-R-CONFIGSTORE-002 is already a named commit/load sibling**, yet the class table calls H4 a “single instance.” I verified that `WriteConfirm` writes without a corresponding size gate, `ReadConfirm` applies the ceiling, and failed recovery leaves no rollback timer. [Write/read paths](/var/tmp/RES8865/pkg/configstore/db.go:229), [recovery consequence](/var/tmp/RES8865/pkg/configstore/store_persist.go:158). **Conclusion:** even the existing class map misses an explicitly reported High in its own class. Deferring everything else to “remaining ~104” does not establish coverage.

5. **Putting H4 verification second is unjustified by the supplied evidence.** I traced commit through persistence, bounded active-DB loading, and fatal startup handling. [Commit](/var/tmp/RES8865/pkg/configstore/store_commit.go:185), [bounded read](/var/tmp/RES8865/pkg/configstore/db.go:354), [startup refusal](/var/tmp/RES8865/pkg/daemon/daemon_run_bringup.go:299). The five relevant persistence/bring-up files are unchanged from 008’s verification revision. The report records an end-to-end accepted-commit/failed-reload result. [H4 evidence](/tmp/muse-spark-review-008.md:58).

   **Verified here:** the source chain and unchanged files; I did not independently reproduce the failure. **Conclusion:** the plan’s own “highest consequence” assessment has substantial supporting evidence. It provides no dependency, exposure comparison, or time-to-fix argument for completing the wire class before resolving H4’s status. The sequence is not defensible as written.

6. **“One change closes many findings” is stronger than the demonstrated benefit.** The wire class proposes two decoder repairs addressing exactly two report findings. The other three listed members are already safe or fixed; they are not new closures. [Proposed sequence](/var/tmp/RES8865/docs/research/8865-muse-spark-008-009/plan.md:114). Moreover, finding 2 above shows those repairs do not yet share a complete implementation contract. **Conclusion:** the evidence supports investigating siblings together. It does not demonstrate the broad closure multiplier used to recommend class-first across the corpus.

7. **The instrument comparison selectively uses the obsolete denominator and discounts the security outcome.** The retained #8830 correction states **one defect from three corrected hits**, versus one from the original 32; 29 original hits resulted from a probe defect. [Correction](/tmp/claude-1000/-home-ps-git-bpfrx/3da4478d-01e7-4b1d-9dd0-6f56a1f49b5f/scratchpad/c8830b.md:5). I corroborated the discovery through commit `a7f84a209` and the PFS regression guard: the corrected behavioral predicate found the silent loss of configured PFS that the schema-based enumeration could not represent. [Guard and mechanism](/var/tmp/RES8865/pkg/config/pfs_packed_keys_8844_test.go:5).

   **Conclusion:** two corrections are legitimate development cost. “1 from 32” is not evidence that the successful method was uneconomic, particularly without elapsed-cost, severity, missed-defect, or reuse comparisons. It cannot justify the categorical restriction against instruments for apparently enumerable classes.

8. **The corpus and staleness premises fail the plan’s own “derive counts” requirement.** Counting actual entries in the available reports gives **008: 11 High + 59 Medium + 37 Low = 107**, plus 009’s four findings: **111 listed entries**. The 008 header claims 109, but its Low entries comprise 19 initial table rows followed by L20–L37. Two claimed entries remain unreconciled. [Initial Low table](/tmp/muse-spark-review-008.md:203), [last Low entries](/tmp/muse-spark-review-008.md:763).

   `git rev-list --count <revision>..b24e26d3b` gives **128** for 008’s first-round verification tip, **90** for its final-round tip, and **109** for 009’s comparison tip—not “128+ since either report’s tip.” [008 revisions](/tmp/muse-spark-review-008.md:3), [009 revision](/tmp/muse-spark-review-009.md:7). These reports are stale, but their evidence spans different revisions. The workload and staleness argument uses unreconciled metadata. All verification above was document, source, and Git-history inspection; no runtime reproductions or tests were executed.
