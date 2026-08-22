# Recovered: claude-opus-XC-show — show-surface review (source for cohort #6565)

**Recovered 2026-08-22 from a subagent transcript, not from the original file.**

The sub-report this cohort was built from (`claude-opus-XC-show.md`) is gone from
disk. Its body survived only inside
`~/.claude/projects/.../subagents/agent-arev-XC-show-bf87c83860afd790.jsonl`
(dated 2026-07-24), which is not version-controlled, not backed up, and ages out.
A lane verifying #6565 found that four named members were still live and that the
other nine were recoverable *only* from that file.

Committed verbatim below so the cohort's evidence outlives the transcript. Two
coordinates in #6565's issue body are known **stale-but-live** and are corrected
here rather than in the recovered text:

- `pkg/config/nat_source.go` **no longer exists**; the predicate moved to
  `pkg/config/compiler_validate_strict_nat.go` (~:3374). A reader who runs the
  issue's path will get `ls: No such file` and may read that as ALREADY FIXED.

Treat every file:line below as needing re-verification at HEAD before use — the
review is from 2026-07-24 and this campaign has repeatedly found cohort cites
rotted by unrelated refactors.

---

# claude-opus-001 — XC-show: cross-cutting sweep of operator-facing show/status/metric surfaces

- **Base SHA**: `8b74794264b88551b98cf5a390233e30ae1b328b` (== origin/master tip; "verified against origin/master" is satisfied by reading at this SHA).
- **Worktree**: `/tmp/review-wt-claude-opus-001-XC-show` (detached at base SHA). Every file below was read through that path.
- **Scope**: `pkg/cli/`, `pkg/grpcapi/`, `pkg/api/`, `pkg/natshow/`, `pkg/diagcmd/`, `pkg/monitoriface/`, plus the rendering helpers those surfaces delegate to (`pkg/dataplane/userspace/format/`), and the Prometheus collector (`pkg/api/metrics*`).
- **Pattern hunted**: *the show surface reports a value the dataplane does not actually enforce.*
- **The six seed instances are NOT re-reported.** They define the pattern.

---

## 0. Method, and what "closure" means here

I attacked the class from the **producer** end rather than the consumer end, because enumerating every printed field across ~65,000 LOC of surface is not closable in one pass, whereas enumerating everything the dataplane **refuses to enforce** is.

Three mechanical sweeps:

**Sweep A — the `security flow` config→wire→consumer chain (CLOSED).**
`config.FlowConfig` (`pkg/config/types_security.go:131-166`) has 21 fields. For each I grepped `FlowSnapshot` (`pkg/dataplane/userspace/protocol.go:168-205`) for a carrier and `userspace-dp/` for a live reader, then grepped all six scope packages for a print site. Result table in §3.

**Sweep B — fail-closed snapshot exclusions (CLOSED over `pkg/dataplane/userspace/`).**
The richest source of this defect turned out to be a structural one nobody has named: **the snapshot builders drop configured objects that cannot be safely lowered, and every operator-facing surface that renders those objects reads the config, not the snapshot.** I enumerated every such site with `grep -n "slog.Warn" pkg/dataplane/userspace/{nat_*,filters,cos,mirrors,flow,policies*,zones_snapshot,interfaces,fabric,neighbors,nat64}.go` and read each one. 20 sites drop or degrade a *config object*; 4 more (`maps_sync.go:1313,1323,1370,1380`, `eventstream.go:1091`) drop *runtime-internal* records with no config-object surface and are excluded. For each of the 20 I then asked: does a `show` surface render that object? Result table in §4.

**Sweep C — documented-inert config fields (CLOSED over `pkg/config/types_*.go`).**
`grep -rniE "(accepted.only|not enforced|no.op|inert|never read|not read by|deferred feature|not yet (read|enforced|implemented|wired))" pkg/config/types_*.go` yields the set of fields the codebase itself admits are not enforced. I grepped every one against the six scope packages. Result in §5 — this sweep produced almost entirely **negative** results, which is the valuable part: it bounds the class.

**Closure verdict: partial, and I will not overclaim.**
- Sweeps A, B and C are **closed** over their stated domains, and the closure arguments are stated as such below.
- I did **not** achieve closure over the full "every printed field on every surface" population. Routing (`cli_show_routing.go`, 11 config reads), system (`cli_show_system.go`, 10), and the cluster surfaces were **sampled**, not enumerated.

---

## 1. Summary

**13 new instances**, all in the *display/observability* materiality band. Per CONTRACT.md severity calibration ("Display/show-only, counter-only, or test-only defects are COHORT, not MATERIAL") every one carries `Gate verdict: COHORT`. I have kept that discipline rather than inflating, but I want to be explicit for the parent's ranking: **findings 1 and 2 are the two where an operator cannot detect that a security control is entirely absent**, and I would rank them above the six seed instances on operator impact. The contract's display-only rule is what caps them, not their consequence.

Ordered by my judgement of operator impact:

| # | Severity | Site | One line |
|---|----------|------|----------|
| 1 | Medium | `pkg/natshow/source.go:77-119` | SNAT rule the builder flagged `pool_unusable` renders as a fully-armed rule — ground truth is already on the wire and unread |
| 2 | Medium | `pkg/natshow/static.go:88-113`, `:41-86`; `pkg/api/show_text.go:329-351` | NPTv6 rule **dropped entirely** by #5818 renders as active on three surfaces |
| 3 | Medium | `pkg/cli/cli_show_flow.go:627` | Peer `Maximum-sessions: 10000000` — unfixed #5323 residual, 45 lines below the fix |
| 4 | Medium | `.../format/cos_show.go:285` | `Transmit rate: -` for an **enforced** `transmit-rate percent`; plus stale "ACCEPTED-BUT-INERT" doc |
| 5 | Low-Med | `pkg/natshow/{source,dest,static}.go` | The other four NAT fail-closed drops render as configured |
| 6 | Low-Med | `pkg/cli/show_services_mirror.go:10-38` | Port-mirroring show is 100% config; five drop conditions; negative rate renders as "all packets" |
| 7 | Low-Med | `.../format/cos_show.go:159-190, 268-292` | CoS classifier / scheduler-map entries with an undefined forwarding-class render as active |
| 8 | Low-Med | `pkg/cli/cli_show_security_filters.go:114,292`; `pkg/grpcapi/server_show_firewall.go:144,581` | `then dscp` renders for a rewrite the builder drops; rejected terms render as active |
| 9 | Low-Med | `pkg/cli/cli_show_flow.go:952-954` | `gre-performance-acceleration: enabled` unannotated — same function annotates a sibling |
| 10 | Low | `pkg/monitoriface/monitor.go:502-519, 603-611` | "Error statistics" has no liveness gate; sibling branch 15 lines below has one |
| 11 | Low | `pkg/cli/cli_show_flow.go:1186-1205` | Flow-export collector with port 0 / out-of-range renders as an active collector |
| 12 | Low | `pkg/api/metrics_descriptors_forwarding.go:11-16` | `xpf_pbr_rules_installed` is a config-derived *desired* set under an `_installed` name |
| 13 | Low | `pkg/api/security.go:382-384`; `pkg/grpcapi/server_show_zones.go:342-344` | Default-policy row renders `LogSessionInit/Close` active where they are inert (default-DENY) |

**Candidates disproved: 19** (§5, §6). Recorded so a future reviewer does not re-chase them.

**Remediation judgement: shared mechanism, and specifically not the annotation helper.** See §7.

---

## 2. Findings

### 1. Source-NAT rule flagged `pool_unusable` by the snapshot builder renders as a fully-armed rule

**Title**: `show security nat source rule [detail]` renders pool, port range and action for a rule the dataplane has marked unusable — the unusable state is computed in Go, carried on the wire, and enforced in Rust, but no surface reads it

**Severity**: Medium
**Confidence**: High
**Gate verdict**: COHORT (display-only per CONTRACT.md §severity-calibration; ranked first on operator impact)

**Evidence**

The builder computes and names the failure (`pkg/dataplane/userspace/nat_source.go:66-124`):

```go
			var poolUnusable bool
			var poolUnusableReason string
...
					slog.Warn("userspace snapshot: marking source NAT rule with missing pool unusable",
						"rule", rule.Name, "pool", rule.Then.PoolName)
					poolUnusable = true
					poolUnusableReason = "missing_pool"
```

Four causes, all in that block: `missing_pool` (:80-81), `empty_pool` (:90-91), `zone_scoped_pool_address` (:107-108), `invalid_port_range` (:123-124).

It is on the wire — `userspace-dp/src/protocol/nat.rs:104-107`:

```rust
    #[serde(rename = "pool_unusable", default)]
    pub pool_unusable: bool,
    #[serde(rename = "pool_unusable_reason", default)]
    pub pool_unusable_reason: String,
```

And it is enforced — `userspace-dp/src/nat/source.rs:685-698`, gating allocation at `:339` and `:714`:

```rust
        if snap.pool_unusable {
            rule.pool_failure = Some(source_nat_failure_reason_from_snapshot(
                &snap.pool_unusable_reason,
            ));
        } else if rule.pool_mode && invalid_pool_address {
```
```rust
        (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
```

The renderer reads none of it — `pkg/natshow/source.go:77-119`:

```go
			fmt.Fprintf(w, "source NAT rule: %s\n", rule.Name)
			fmt.Fprintf(w, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(w, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
...
			fmt.Fprintf(w, "    Action:                  %s\n", action)
...
					fmt.Fprintf(w, "    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
...
					fmt.Fprintf(w, "    Port range:              %d-%d\n", portLow, portHigh)
```

`natshow.Reader` (`pkg/natshow/natshow.go:60-67`) exposes `IsLoaded / IterateSessions / IterateSessionsV6 / ReadNATRuleCounter / GetPersistentNAT` — there is **no** accessor for the applied snapshot, so the renderer structurally cannot reach the flag. Both consumers (CLI `cli_show_nat.go`, gRPC `server_show_nat.go`) inherit this.

**Trace**

1. Operator (or an HA peer push, or a boot-time `Store.Load`) supplies `set security nat source rule-set rs1 rule r1 then source-nat pool p1` where `p1`'s `port-low`/`port-high` are inverted.
2. `CompileConfigLenient` is the compile path on boot and on `Store.SyncApply` (ORIENTATION.md §lenient-vs-strict) — the strict gate that would reject this runs only at `commit`, so the config lands.
3. `buildSourceNATSnapshots` hits `nat_source.go:120-124`, logs the warning, sets `poolUnusable=true, reason="invalid_port_range"`, and emits the rule with the flag set.
4. Rust `nat/source.rs:685` sets `rule.pool_failure`; `:339` and `:714` then exclude the rule from allocation. Traffic matching `r1` gets no translation.
5. Operator runs `show security nat source rule r1 detail`. Output shows `Action: p1`, `Pool addresses: 203.0.113.10`, `Port range: 60000-1024`. Nothing indicates the rule is inert.
6. The only signal is a `slog.Warn` in the journal at snapshot-build time — not on any `show` path.

**Refutation attempt**

I tried three ways to kill this.
(a) *Does the strict commit gate make it unreachable?* No — ORIENTATION.md §lenient-vs-strict and the `#1960` no-brick doctrine mean the lenient path warns rather than rejects, precisely so a persisted config cannot brick the box. Boot and HA peer-sync both take that path.
(b) *Is the flag really unread, or does some other surface show it?* `grep -rn "pool_unusable\|PoolUnusable" pkg/cli pkg/grpcapi pkg/api pkg/natshow` returns nothing outside the builder and the protocol struct.
(c) *Does a counter give the operator the signal instead?* There is a global `NAT allocation failures` counter (`cli_show_flow.go:1011`), but it is a single global scalar with no rule attribution, and it counts runtime allocation exhaustion — a rule excluded at snapshot-build time never reaches the allocator, so it does not even increment it.
It survives all three.

**HPC/invariant check**: Not a hot path. The fix is a snapshot read on a `show` path (1/operator-command), no packet-path cost. `natshow.Reader` would gain one accessor.

**Why it matters**: The operator's mental model is "the rule exists, so traffic is being translated." Four distinct misconfigurations produce a rule that silently does not translate, and the box has already computed and transmitted the exact reason. This is the pattern in its purest form: not "we never modelled it," but "we modelled it, wired it, enforced it, and then didn't show it."

**Fix direction**: Add an applied-snapshot accessor to `natshow.Reader` and render `Action: p1 (INACTIVE: invalid port range)` when `pool_unusable` is set. The reason string is already an enum-like token — map it to operator prose. Same treatment for the destination/static renderers (finding 5).

**Labels**: `observability`, `nat`, `show-surface`, `cohort`

**Dedup note**: Checked against DEDUP-INDEX §A — #6211 is synced source-NAT *rule-selection* divergence (different mechanism), #5837/#6051 are XDP DNAT/static-NAT ordering, #4960 is destructive netlink mutation during compile. §B/§C: spark003-17 is address-only SNAT *false exhaustion* at runtime; spark004-02 is a pool *leak* on `DeleteSynced`. Neither is a show-surface finding. Not one of the six seeds.

**Verified against origin/master**: `pkg/natshow/source.go:77-119`, `pkg/dataplane/userspace/nat_source.go:66-124`, `userspace-dp/src/nat/source.rs:685-698` — all still present at base SHA (== tip).

---

### 2. NPTv6 rule dropped entirely by the #5818 fail-closed gate renders as active on three surfaces

**Title**: A scoped NPTv6 rule is excluded from the snapshot (installs nothing) but `show security nat nptv6`, `show security nat static rule detail`, and REST `show/nat-nptv6` all render it from config

**Severity**: Medium
**Confidence**: High
**Gate verdict**: COHORT (display-only)

**Evidence**

`pkg/dataplane/userspace/nat_nptv6.go:18-43` — the exclusion is deliberate and total:

```go
			// #5818 fail-closed: the NPTv6 wire/dataplane carry only `from zone`
			// (Nptv6RuleSnapshot has no interface/routing-instance/source field). A
			// rule-set scoped `from interface` / `from routing-instance` cannot be
			// honored, so emitting the rule would install an over-broad zone/global
			// rewrite that translates traffic the operator scoped OUT
...
			scopeUnsupported := rs.FromInterface != "" || rs.FromRoutingInstance != ""
...
				if scopeUnsupported || len(rule.SourceAddresses) > 0 || rule.SourceAddress != "" || rule.MatchDestinationPort != 0 {
					slog.Warn("userspace snapshot: dropping NPTv6 rule carrying an unsupported match scope ...
					continue
				}
```

The comment at `:23-26` states the reachability explicitly: *"The strict commit gate (validateNPTv6ScopeStrict) rejects this; on the tolerant load / peer-sync path (where that gate only warns, #1960) exclude the rule here."*

`pkg/natshow/static.go:88-113` (`RenderNPTv6`) takes `cfg *config.Config` and nothing else — no dataplane parameter exists in the signature. It prints every NPTv6 rule unconditionally. `RenderStaticRule` (`static.go:41-86`) does the same and additionally prints the very scope that caused the drop:

```go
		if detail && rs.FromInterface != "" {
			fmt.Fprintf(w, "  From interface: %s\n", rs.FromInterface)
		}
		if detail && rs.FromRoutingInstance != "" {
			fmt.Fprintf(w, "  From routing-instance: %s\n", rs.FromRoutingInstance)
		}
```

REST is a third, independently-written copy — `pkg/api/show_text.go:329-351`, `case "nat-nptv6"`, same config-only source.

**Trace**

1. `set security nat static rule-set ns1 from interface ge-0/0/1` + an NPTv6 rule under it. Committed on node A (rejected by `validateNPTv6ScopeStrict`? — no: the operator authored it on a path that reached the lenient compile, e.g. it was already persisted, or it arrived via HA config-sync).
2. Node B's `Store.SyncApply` → `CompileConfigLenient` → config accepted with a warning.
3. `buildNptv6Snapshots` reaches `:36`, logs, `continue`. `out` never receives the rule. The wire carries zero NPTv6 rules.
4. Operator on node B runs `show security nat nptv6`. Output: a table row with rule-set, rule, external prefix, internal prefix. Identical to a healthy install.
5. IPv6 prefix translation is not happening. The operator has no surface that says so.

**Refutation attempt**

(a) *Is `RenderStaticRule`'s existing annotation enough?* No — `static.go:80-81` annotates only `Then routing-instance` (`"(accepted; cross-VRF post-translation routing not enforced)"`). `From interface` / `From routing-instance` at `:53-56`, which are the fields that trigger the drop, carry no annotation. That the file already annotates one field and not the other is what makes this an oversight rather than a design choice.
(b) *Does the strict gate make it unreachable?* The source comment itself says no, and names the two reaching paths.
(c) *Is this just #6043?* #6043 is "carry + evaluate interface/routing-instance/source-address scope" — the *enforcement* feature. Even when #6043 lands, `RenderNPTv6` still has no dataplane input and would still render a rule dropped for any future reason. The show-surface blindness is orthogonal and outlives the feature.
Survives.

**HPC/invariant check**: N/A — operator-command path.

**Why it matters**: NPTv6's job is to translate a prefix. A silently-uninstalled rule means the internal prefix egresses untranslated. Three independent surfaces all say the rule is live.

**Fix direction**: Give `RenderNPTv6` / `RenderStaticRule` / the REST topic the applied NPTv6 snapshot and mark rules absent from it. Cheapest correct version: recompute `scopeUnsupported` in the renderer from the same predicate and print `(NOT INSTALLED: unsupported match scope, #5818)` — but see §7 for why recomputation is the wrong long-term answer.

**Labels**: `observability`, `nat`, `nptv6`, `show-surface`, `cohort`

**Dedup note**: DEDUP-INDEX §A — #6043 (NPTv6 scope enforcement) is the enforcement half and is cited above; #5818 is the closed fail-closed change this rides on. spark003-09/-18 are NPTv6 *ifindex* and *zone-only scoping* enforcement findings, not show-surface. Not a seed.

**Verified against origin/master**: `pkg/dataplane/userspace/nat_nptv6.go:18-43`, `pkg/natshow/static.go:41-113`, `pkg/api/show_text.go:329-351` — present at base SHA (== tip).

---

### 3. Peer `Maximum-sessions: 10000000` — the #5323 fix landed on the local path and not the peer path in the same function

**Title**: `show security flow session summary` renders the retired hardcoded 10000000 for the peer node, 45 lines below the local path that #5323 fixed, while the correct value is on the wire and populated

**Severity**: Medium
**Confidence**: High
**Gate verdict**: COHORT (display-only)

**Evidence**

`pkg/cli/cli_show_flow.go:574-582` — the fix, with its rationale:

```go
		// #5323: render the dataplane's dynamic max (worker_count x per-worker
		// capacity) from the live helper status, not the old hardcoded
		// 10000000. If no userspace status is available (max 0), render
		// "unknown" instead of a fabricated authoritative bound.
		if st, err := c.userspaceDataplaneStatus(); err == nil && st.MaxSessions > 0 {
			fmt.Printf("Maximum-sessions: %d\n", st.MaxSessions)
		} else {
			fmt.Printf("Maximum-sessions: unknown\n")
		}
```

`pkg/cli/cli_show_flow.go:627` — the peer block in the same `if f.summary` branch:

```go
				fmt.Printf("  Sessions in other states: 0\n")
				fmt.Printf("Maximum-sessions: 10000000\n")
```

The value is available. `proto/xpf/v1/xpf.proto:448-452`:

```proto
  // max_sessions is the dataplane's dynamic session-table capacity: the live
  // AF_XDP helper publishes worker_count x per-worker capacity. 0 = unknown
  // (no userspace status attached), so a consumer must render "unknown" rather
  // than a fabricated authoritative bound (#5323, replaces the hardcoded
  // 10000000 the CLI used to print).
  uint64 max_sessions = 12;
```

and every server populates it — `pkg/grpcapi/server_sessions.go:856-859`:

```go
	if st, err := s.userspaceDataplaneStatus(); err == nil {
		resp.MaxSessions = st.MaxSessions
	}
```

`fetchPeerSessionSummary` returns the peer's own `GetSessionSummaryResponse`, so `peerResp.MaxSessions` is the peer's real capacity and is simply discarded.

**Trace**

1. Two-node cluster; node 1 has a different worker count from node 0 (asymmetric queue count, or a different `ProcessStatus` after a rolling deploy).
2. Operator runs `show security flow session summary` on node 0.
3. Node 0's block prints its real max (e.g. `786432`) via the #5323 path.
4. `c.cluster.PeerAlive()` is true, `fetchPeerSessionSummary()` returns node 1's response with `MaxSessions` correctly populated.
5. Line 627 ignores it and prints `10000000`.
6. Operator now sees two nodes with wildly different capacities in the same output and concludes the peer has ~13x the headroom. Capacity planning and failover-readiness judgement are both wrong.

**Refutation attempt**

(a) *Is the peer field actually populated, or is this a "no data available so we print a placeholder" case?* Populated — `server_sessions.go:856` runs unconditionally before the peer fan-out, on every node. The peer's response carries its own value.
(b) *Did #5323 deliberately scope itself to local?* The regression test `pkg/cli/cli_show_flow_summary_5323_test.go` asserts `Maximum-sessions: 786432` and, at line 69, `if strings.Contains(out, "10000000")` → fail. That guard passes today only because the test fixture is standalone (`c.cluster == nil`), so the peer block never executes. The test's own stated intent — "restoring `Maximum-sessions: 10000000` makes the 786432 assertion fail" (`:54`) — shows the author meant to eliminate the literal, not to preserve it on one branch.
(c) *Is it dead code?* No: it is inside `if c.cluster != nil && c.cluster.PeerAlive()`, the normal HA operating state.
Survives.

**HPC/invariant check**: N/A.

**Why it matters**: This is the clearest "unfinished fix" in the batch, and the cheapest to close. It is also evidence for §7: a per-site fix left a sibling site 45 lines away unfixed *in the same function*, and the regression test could not catch it.

**Fix direction**: `if peerResp.MaxSessions > 0 { printf("Maximum-sessions: %d\n", peerResp.MaxSessions) } else { printf("Maximum-sessions: unknown\n") }`. Extend the #5323 test with a cluster-mode fixture so the peer branch is exercised.

**Labels**: `observability`, `ha`, `show-surface`, `cohort`, `residual`

**Dedup note**: DEDUP-INDEX §A has no entry for this; #5323 is closed (the local half). Not a seed. §B/§C have no match.

**Verified against origin/master**: `pkg/cli/cli_show_flow.go:574-582` (fixed) and `:627` (unfixed) both present at base SHA (== tip); `proto/xpf/v1/xpf.proto:452`; `pkg/grpcapi/server_sessions.go:856`.

---

### 4. `show class-of-service scheduler-map` renders `Transmit rate: -` for an ENFORCED `transmit-rate percent`

**Title**: The scheduler-map renderer reads only the absolute `TransmitRateBytes`, so a scheduler configured with the Junos `transmit-rate percent` form displays as having no rate — while the Rust side resolves and shapes to it. The Go type comment also still calls the field ACCEPTED-BUT-INERT.

**Severity**: Medium
**Confidence**: High
**Gate verdict**: COHORT (display-only)

**Evidence**

Renderer — `pkg/dataplane/userspace/format/cos_show.go:281-291`:

```go
				if sched := cos.Schedulers[entry.Scheduler]; sched != nil {
					if sched.Priority != "" {
						priority = sched.Priority
					}
					rate = formatCoSRate(sched.TransmitRateBytes)
					buffer = formatSchedulerBuffer(sched)
					exact = yesNo(sched.TransmitRateExact)
				}
```

`formatCoSRate` — `pkg/dataplane/userspace/format/cos.go:166-171`:

```go
func formatCoSRate(bytesPerSecond uint64) string {
	if bytesPerSecond == 0 {
		return "-"
	}
	return formatBitsPerSecondFloat(float64(bytesPerSecond) * 8)
}
```

`TransmitRatePercent` and `TransmitRateBytes` are mutually exclusive (`types_cos.go:148-149`, enforced by `validateClassOfServiceStrict`), so the percent form always yields `TransmitRateBytes == 0` → `"-"`.

It **is** carried: `pkg/dataplane/userspace/protocol_cos.go:60` `TransmitRatePercent float64`; `pkg/dataplane/userspace/cos.go:169` populates it.

It **is** enforced — `userspace-dp/src/afxdp/forwarding_build/cos.rs:306-318`, called from the live snapshot build at `:564`:

```rust
fn cos_effective_transmit_rate_bytes(
    scheduler: Option<&CoSSchedulerSnapshot>,
    iface_shaping_rate_bytes: u64,
) -> Option<u64> {
    let sched = scheduler?;
    if sched.transmit_rate_bytes > 0 {
        return Some(sched.transmit_rate_bytes);
    }
    if sched.transmit_rate_percent > 0.0 {
        return cos_percent_rate_bytes(iface_shaping_rate_bytes, sched.transmit_rate_percent);
    }
    None
}
```

Secondary doc-drift — `pkg/config/types_cos.go:143-150` still says:

```go
	// TransmitRatePercent (#4228 Gap 2) carries the Junos `transmit-rate
	// percent <n>` form: a share (0,100] of the bound interface's rate. It is
	// accepted for vSRX-config import parity but ACCEPTED-BUT-INERT — the
	// userspace dataplane consumes an absolute byte/sec TransmitRateBytes, and
	// xpf does not yet resolve the percent against the interface's shaping-rate
	// (a commit advisory surfaces this).
```

That statement is false at base SHA — `forwarding_build/cos.rs:314-316` resolves it.

**Trace**

1. `set class-of-service schedulers sched-video transmit-rate percent 30`, bound via a scheduler-map to `forwarding-class video`.
2. Compile: `TransmitRatePercent = 30.0`, `TransmitRateBytes = 0`. Wire carries `transmit_rate_percent: 30.0`.
3. Rust `cos_effective_transmit_rate_bytes(sched, iface.cos_shaping_rate_bytes_per_sec)` → `Some(0.30 * iface_rate)`. The queue is shaped.
4. Operator runs `show class-of-service scheduler-map sm1`. The `Transmit rate` column reads `-`.
5. The operator concludes the rate did not take, and either re-authors it as an absolute (changing behavior) or files a false bug.

**Refutation attempt**

(a) *Is the percent path actually reached, or is `cos_effective_transmit_rate_bytes` dead?* `grep -rn "cos_effective_transmit_rate_bytes" userspace-dp/src/` → declaration at `:306` and one call at `forwarding_build/cos.rs:564`, inside the live forwarding-state build. Live.
(b) *Does the sibling surface compensate?* Partially, and this is why I scoped the finding to `scheduler-map` only: `show class-of-service interface` goes through `cos_sections.go`, which seeds from config (`:521,:525`) but then **overrides from the runtime queue** (`:550-558`), so it shows the resolved rate. Only the config-only `scheduler-map` view is wrong. I checked this specifically to avoid over-scoping.
(c) *Is `-` defensible as "no absolute rate"?* No — the column header is `Transmit rate`, not `Transmit rate (bytes)`, and `-` is the same glyph used for "scheduler not found" at `:276`.
Survives.

**HPC/invariant check**: N/A.

**Why it matters**: This is the class running in the opposite direction — the surface **under**-reports an enforced control. It is worth reporting under the same banner because the root cause is identical: the renderer reads one config field instead of the effective state, and there is no mechanism forcing it to consider the alternatives.

**Fix direction**: Render the effective rate: absolute when set, else `30% (of shaping-rate)` when percent is set, else `-`. And correct the `types_cos.go:143-150` comment — the "inert" claim is stale and will mislead the next reviewer into reporting a false positive.

**Labels**: `observability`, `cos`, `show-surface`, `doc-drift`, `cohort`

**Dedup note**: DEDUP-INDEX §A #4228 is the vSRX CoS parity umbrella (7 enumerated gaps) — Gap 2 is the *enforcement* of percent/remainder, which is partly done; this is the display half and the stale comment. #5193/#1359/#1365 are fairness/latency. spark004-22/-26/-27 are buffer/waterfill numerics. Not a seed.

**Verified against origin/master**: `format/cos_show.go:285`, `format/cos.go:166-171`, `protocol_cos.go:60`, `userspace-dp/src/afxdp/forwarding_build/cos.rs:306-318,564`, `pkg/config/types_cos.go:143-150` — all present at base SHA (== tip).

---

### 5. The remaining four NAT fail-closed drops render as configured rules

**Severity**: Low-Medium · **Confidence**: High · **Gate verdict**: COHORT

Same shape as findings 1 and 2, grouped because the mechanism and fix are identical.

| Drop site | Condition | Rendered by |
|---|---|---|
| `nat_static.go:66-69` | `then static-nat inet` (NAT64 via static) — dropped, "#5859 fail-closed" | `natshow/static.go:26-30` prints `Then static-nat prefix: inet` |
| `nat_static.go:82` | present-but-out-of-range destination/mapped port — dropped, "#5101 ... fail CLOSED" | `natshow/static.go:72-77` prints `Match destination-port` / `Then mapped-port` |
| `nat_destination.go:138-140` | non-host DNAT pool address — "skipping DNAT rule ... (fail-closed, #3450)" | `natshow/dest.go` pool/rule render |
| `nat_destination.go:143-145` | out-of-range DNAT pool port — same | `natshow/dest.go` pool/rule render |

`pkg/dataplane/userspace/nat_static.go:60-69`:

```go
			// peer-sync path it is a surfaced compile warning. Drop the rule
			// here too so the unparseable "inet" sentinel never reaches the
			// dataplane — fail CLOSED, symmetric with the #5101 out-of-range
			// port drop below.
			if rule.Then == "inet" {
				slog.Warn("userspace snapshot: dropping static NAT `then static-nat inet` (NAT64) rule; not representable in the static_nat table (use `security nat nat64`) (fail-closed, #5859)",
					"ruleset", rs.Name, "rule", rule.Name)
				continue
			}
```

**Why it matters**: `Then static-nat prefix: inet` is rendered verbatim — the operator sees the literal token they typed and no indication the rule installed nothing.

**Fix direction**: Covered by the finding-1 fix (applied-snapshot accessor on `natshow.Reader`), applied uniformly across the four renderers.

**Dedup note**: #5859, #5101, #3450 are the closed enforcement changes; none covers the display side. Not seeds.

**Verified against origin/master**: `nat_static.go:60-82`, `nat_destination.go:132-146`, `pkg/natshow/static.go`, `pkg/natshow/dest.go` at base SHA (== tip).

---

### 6. `show forwarding-options port-mirroring` is 100% config; a negative input rate renders as "all packets"

**Severity**: Low-Medium · **Confidence**: High · **Gate verdict**: COHORT

**Evidence** — the entire renderer, `pkg/cli/show_services_mirror.go:10-38`. It takes `c.store.ActiveConfig()` and touches no dataplane state:

```go
	for name, inst := range pm.Instances {
		fmt.Printf("Instance: %s\n", name)
		if inst.InputRate > 0 {
			fmt.Printf("  Input rate: 1/%d\n", inst.InputRate)
		} else {
			fmt.Printf("  Input rate: all packets\n")
		}
```

Five drop conditions in `pkg/dataplane/userspace/mirrors.go`:

| Line | Condition |
|---|---|
| `:52` | instance has no output interface → instance skipped |
| `:58-60` | negative input rate → instance skipped |
| `:67-68` | output interface not found in the ifindex map → instance skipped |
| `:78` | input interface not found → that input skipped |
| `:85` | duplicate ingress interface (one output per ingress) → skipped |

`mirrors.go:55-60`:

```go
		if inst.InputRate < 0 {
			// A negative rate would wrap in uint32(inst.InputRate) below. Drop
			// only this instance; the commit gate rejects it up front.
			slog.Warn("port-mirroring: skipping instance with negative input rate",
				"name", name, "rate", inst.InputRate)
			continue
		}
```

The negative-rate case is the sharpest: `InputRate = -1` fails `inst.InputRate > 0`, so the CLI prints **`Input rate: all packets`** — the most permissive possible reading — for an instance the dataplane discarded entirely.

`:67` (output interface not found) is the most *likely* in practice: it fires whenever the named output interface has no ifindex, e.g. it is admin-down or renamed. The show still prints `Output interface: <name>`.

**Why it matters**: Port mirroring is a forensic/compliance tool. "The SPAN is configured" and "the SPAN is capturing" being indistinguishable is the failure mode that matters for the one use case mirroring has.

**Fix direction**: Pass the applied mirror snapshot (or the resolved ifindex map) into the renderer and mark instances that did not install, with the reason.

**Dedup note**: No DEDUP-INDEX entry for port-mirroring display. Not a seed.

**Verified against origin/master**: `pkg/cli/show_services_mirror.go:10-38`, `pkg/dataplane/userspace/mirrors.go:52-86` at base SHA (== tip).

---

### 7. CoS classifier / scheduler-map entries with an undefined forwarding-class render as active

**Severity**: Low-Medium · **Confidence**: High · **Gate verdict**: COHORT

**Evidence** — `pkg/dataplane/userspace/format/cos_show.go:131-191` renders every entry of every classifier straight from `cfg.ClassOfService`:

```go
			c := cos.DSCPClassifiers[name]
			blk := classifierBlock{name: name, cpType: "dscp"}
			for _, e := range c.Entries {
				for _, dscp := range e.DSCPValues {
					blk.rows = append(blk.rows, cpRow{
						value: uint16(dscp),
						bits:  6,
						fc:    e.ForwardingClass,
						lp:    lossPriorityOrDefault(e.LossPriority),
					})
```

There is no membership check against `cos.ForwardingClasses`. The builder does exactly that check and drops — `pkg/dataplane/userspace/cos.go:63-71`:

```go
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					slog.Warn("cos dscp-classifier references undefined forwarding-class; skipping entry (classifier partially absent)",
						"classifier", classifier.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
```

Four sibling sites: `cos.go:99` (802.1p classifier), `:138` (DSCP rewrite-rule), `:228` (scheduler-map entry), `:248` (scheduler-map naming an undefined *scheduler* — degraded rather than dropped, "dataplane applies safe best-effort"). `FormatCoSSchedulerMaps` (`cos_show.go:268-292`) renders the `:228` and `:248` cases.

The renderer's own doc-comment at `cos_show.go:126-130` says it renders *"from the compiled classifiers"* — it does not; it renders from `cfg.ClassOfService`. That mismatch is itself worth fixing because it tells the next reader the surface is already snapshot-backed.

**Why it matters**: "classifier partially absent" is the operator-invisible state — the classifier exists, most entries work, one silently does not, and the show output is identical either way.

**Fix direction**: The cheap, correct, purely-local fix here is a membership check in the renderer against `cos.ForwardingClasses` — the same predicate the builder uses — rendering `<fc> (UNDEFINED — entry not installed)`. Unlike findings 1/2 this needs no new plumbing because the predicate is a pure function of the config the renderer already holds.

**Dedup note**: #2696/#2409/#2704 are the closed builder-side skip+warn changes; they explicitly made the *log* non-silent but did not touch the show surface. #4228 is the CoS parity umbrella. Not a seed.

**Verified against origin/master**: `format/cos_show.go:126-191, 268-292`, `pkg/dataplane/userspace/cos.go:63-71, 93-104, 132-143, 219-252` at base SHA (== tip).

---

### 8. `show firewall filter` renders `then dscp` for a rewrite the builder drops, and renders terms it rejects

**Severity**: Low-Medium · **Confidence**: Medium-High · **Gate verdict**: COHORT

**Evidence** — the builder drops the rewrite while *keeping the term active*, `pkg/dataplane/userspace/filters.go:243-247`:

```go
			} else {
				slog.Warn("dropping unresolvable filter term dscp/traffic-class rewrite "+
					"(CoS marking lost — the term still matches and acts)",
					"filter", filterName, "term", term.Name, "dscp_rewrite", term.DSCPRewrite)
			}
```

Four surfaces print it unconditionally: `pkg/cli/cli_show_security_filters.go:113-115` and `:291-293`, `pkg/grpcapi/server_show_firewall.go:143-145` and `:580-582`:

```go
				if term.DSCPRewrite != "" {
					fmt.Printf("    then dscp %s\n", term.DSCPRewrite)
				}
```

Two further `filters.go` sites reject more than the rewrite: `:266` (*"rejecting filter term with unparseable tcp-flags expression"* — whole term) and `:628` (*"firewall filter prefix-list reference unresolved"*).

**Confidence caveat, stated honestly**: I confirmed the drop sites and the print sites, and that no print site consults the applied filter snapshot. I did **not** trace the `:266` / `:628` rejections through to the exact rendered output for every filter view, so I rate the DSCP half High and the tcp-flags/prefix-list half Medium. A follow-up should close that.

**Why it matters**: `filters.go:244`'s own parenthetical — "the term still matches and acts" — describes a *partial* enforcement state, which is strictly harder for an operator to detect than a whole-rule drop: the traffic is filtered, so the term is visibly "working", but the CoS marking is silently absent and downstream queueing misbehaves.

**Fix direction**: Same shared mechanism as §7.

**Dedup note**: DEDUP-INDEX §A #4422 is the test-coverage/observability backlog including filter items; #4434/#6434 are filter-compiler refactors. spark004-11 is `TermMatchExtra::default()` losing flex/tcp-flags on a *cached* evaluation path — an enforcement bug, not display. Not a seed.

**Verified against origin/master**: `pkg/dataplane/userspace/filters.go:243-247, 266, 628`, `pkg/cli/cli_show_security_filters.go:113-115, 291-293`, `pkg/grpcapi/server_show_firewall.go:143-145, 580-582` at base SHA (== tip).

---

### 9. `gre-performance-acceleration: enabled` is unannotated, in a function that annotates its sibling

**Severity**: Low-Medium · **Confidence**: High · **Gate verdict**: COHORT

**Evidence** — `pkg/cli/cli_show_flow.go:942-957`:

```go
	if flow.AllowDNSReply || flow.AllowEmbeddedICMP || flow.GREPerformanceAcceleration || flow.PowerModeDisable {
		fmt.Println()
		fmt.Println("Flow options:")
...
		if flow.GREPerformanceAcceleration {
			fmt.Println("  gre-performance-acceleration:  enabled")
		}
```

The wire struct is explicit that nothing reads it — `pkg/dataplane/userspace/protocol.go:178-186`:

```go
	// GREAcceleration carries `security flow gre-performance-acceleration`
	// (#3360). On vSRX this extracts the GRE key/call-id into the session tuple
	// so multiple GRE tunnels between the same endpoints map to distinct
	// sessions. The userspace dataplane keys GRE flows on the 5-tuple only, so
	// this threads the operator's intent into the Rust ForwardingState
	// (mirroring the PowerModeDisable plumbing) for config truth/parity; the bit
	// is NOT yet read by any forwarding path. The consumer (GRE key/call-id
	// extraction) is a deferred feature.
```

Twenty lines above, the same function annotates a sibling — `cli_show_flow.go:931-933`:

```go
		if flow.TCPMSSIPsecVPN > 0 {
			fmt.Printf("  %-30s %d\n", "IPsec VPN MSS (not enforced):", flow.TCPMSSIPsecVPN)
		}
```

**Why it matters**: The operator enables it precisely to get per-tunnel session separation between the same endpoint pair. Sessions still collapse on the 5-tuple. The mitigation is that #5804 tracks the enforcement gap, so this is a labelling defect on a known-open feature — hence Low-Medium, not Medium.

**Fix direction**: `gre-performance-acceleration:  enabled (not enforced — #5804)`.

**Dedup note**: **#5804 is open** ("userspace-dp/GRE: implement key and call-ID session identity for gre-performance-acceleration") and covers the *enforcement* gap — I am reporting only the unannotated render, which #5804 does not mention. #3360 is the closed plumbing change. Not a seed.

**Verified against origin/master**: `pkg/cli/cli_show_flow.go:931-933, 952-954`, `pkg/dataplane/userspace/protocol.go:178-186` at base SHA (== tip).

---

### 10. `monitor interface` "Error statistics" has no liveness gate — the sibling branch has one

**Severity**: Low · **Confidence**: High · **Gate verdict**: COHORT

**Evidence** — `pkg/monitoriface/monitor.go:502-528`:

```go
	link, err := netlink.LinkByName(kernelName)
	if err == nil {
		if stats := link.Attrs().Statistics; stats != nil {
			snap.RxErrors = stats.RxErrors
			snap.TxErrors = stats.TxErrors
			snap.RxDrops = stats.RxDropped
...
	if statusReader != nil {
		status, err := statusReader()
		if err != nil {
			snap.Userspace = &UserspaceSnapshot{StatusNote: err.Error()}
```

The netlink error at `:502` is swallowed with no record; the userspace error at `:523` gets a `StatusNote`. The renderer prints all seven counters as authoritative — `monitor.go:603-611`:

```go
	fmt.Fprintf(w, "Error statistics:                                  Current delta\n")
	fmt.Fprintf(w, "  Input  errors:        %20d          [%d]\n", snap.RxErrors, rxErrDelta)
	fmt.Fprintf(w, "  Output errors:        %20d          [%d]\n", snap.TxErrors, txErrDelta)
	fmt.Fprintf(w, "  Input  drops:         %20d          [%d]\n", snap.RxDrops, rxDropDelta)
```

`Snapshot` has no field in which a netlink failure could be recorded, so this is structural, not an oversight at one call site.

Secondary, same function — `monitor.go:512-517`:

```go
			if snap.RxBytes == 0 && snap.TxBytes == 0 {
				snap.RxBytes = stats.RxBytes
				snap.TxBytes = stats.TxBytes
```

A genuinely idle interface (dataplane counters legitimately 0/0) silently takes the kernel-stats fallback. The two sources have different epochs — kernel counts since boot, the dataplane since helper load — and the header (`"Traffic statistics (interface counters + userspace XSK traffic)"`) does not say which one produced the number.

**Why it matters**: `monitor interface` is the tool an operator reaches for during a live incident to answer "are we dropping?". A fabricated `0` answers "no" when the truth is "unknown".

**Fix direction**: Add `StatsNote string` to `Snapshot`, set it on the `netlink.LinkByName` error, and render `Error statistics: (unavailable: <err>)` — exactly mirroring the `StatusNote` treatment already present 15 lines below.

**Dedup note**: DEDUP-INDEX §A #5250 is the metrics/leak/error-swallow hardening cohort — I checked its description and it names "error-swallow across observability, dataplane, daemon, api, config" generically; this specific site is not enumerated there, but a triager may reasonably fold it in. Flagging that explicitly. Not a seed.

**Verified against origin/master**: `pkg/monitoriface/monitor.go:486-530, 603-611` at base SHA (== tip).

---

### 11. Flow-export collector with port 0 or out-of-range renders as an active collector

**Severity**: Low · **Confidence**: High · **Gate verdict**: COHORT

**Evidence** — builder, `pkg/dataplane/userspace/flow.go:230-239`:

```go
				if server.Port == 0 {
					continue
				}
				if server.Port < 0 || server.Port > math.MaxUint16 {
					slog.Warn("userspace: skipping flow-server with out-of-range port (#1977)",
						"address", server.Address, "port", server.Port)
					continue
				}
```

Renderer, `pkg/cli/cli_show_flow.go:1187-1205`:

```go
				for _, fs := range fam.FlowServers {
					portStr := ""
					if fs.Port > 0 {
						portStr = fmt.Sprintf(":%d", fs.Port)
					}
...
					fmt.Printf("    Collector: %s%s%s%s\n", fs.Address, portStr, srcStr, tmplStr)
```

Port 0 renders as a bare `Collector: 10.0.0.1` — a plausible-looking line for a collector that receives nothing. Note the port-0 case at `flow.go:230` is a *silent* `continue` with no warning at all, so there is not even a journal record.

**Fix direction**: Render `Collector: 10.0.0.1 (NOT EXPORTING: no port)`. Add a warn at `flow.go:230` for parity with `:234`.

**Dedup note**: #1977 is the closed port-range change. #4422 covers flowexport test-coverage follow-ups. spark003-25 is a flowexport `uint16` wrap in the *datagram* path. Not a seed.

**Verified against origin/master**: `pkg/dataplane/userspace/flow.go:230-239`, `pkg/cli/cli_show_flow.go:1187-1205` at base SHA (== tip).

---

### 12. `xpf_pbr_rules_installed` publishes a config-derived *desired* set under an `_installed` name

**Severity**: Low · **Confidence**: High · **Gate verdict**: COHORT

**Evidence** — `pkg/api/metrics_descriptors_forwarding.go:6-16`:

```go
	// #4422: policy-based-routing (filter-based-forwarding) build health.
	// xpf_pbr_rules_installed is the number of kernel `ip rule` FBF entries
	// the active config's routing-instance filter terms yield (the
	// desired-install set). Config-derived (routing.PBRBuildStats, a pure
	// function of config), emitted BEFORE the dataplane gate.
	c.pbrRulesInstalled = prometheus.NewDesc(
		"xpf_pbr_rules_installed",
```

`pkg/routing/rules.go:906-920` confirms it is a pure config function — `installed = len(rules)` where `rules, err := BuildPBRRules(cfg)`. `pkg/api/metrics_counters.go:163-173` emits it with no dataplane or netlink read.

**Refutation attempt**: The internal comment is scrupulously honest ("the desired-install set", "emitted BEFORE the dataplane gate") and the exported HELP string says the terms *"yield"* rather than *"are installed"*. So this is not a case of the code lying to itself. The defect is narrower and real: the **metric name** is what lands in dashboards and alert expressions, and `_installed` reads as kernel state to every consumer. `xpf_pbr_rules_installed > 0` is true even if the daemon never successfully wrote an `ip rule`. There is no companion applied-count metric to compare against. That is why I rate it Low rather than dropping it.

**Fix direction**: Rename to `xpf_pbr_rules_desired` (or add `xpf_pbr_rules_applied` read back from netlink so the pair is comparable, which is the more useful outcome).

**Dedup note**: #4422 is the backlog that created this metric. Not a seed.

**Verified against origin/master**: `pkg/api/metrics_descriptors_forwarding.go:6-31`, `pkg/api/metrics_counters.go:163-173`, `pkg/routing/rules.go:906-920` at base SHA (== tip).

---

### 13. Default-policy row renders `LogSessionInit/Close` as active where they are inert

**Severity**: Low · **Confidence**: Medium-High · **Gate verdict**: COHORT

**Evidence** — `pkg/api/security.go:382-384` (and the byte-equivalent `pkg/grpcapi/server_show_zones.go:342-344`):

```go
			Log:             cfg.Security.DefaultPolicyLogSessionInit || cfg.Security.DefaultPolicyLogSessionClose,
			LogSessionInit:  cfg.Security.DefaultPolicyLogSessionInit,
			LogSessionClose: cfg.Security.DefaultPolicyLogSessionClose,
```

`pkg/config/types_security.go:108-112` states the inertness:

```go
	// records only fire for a default-PERMIT verdict (which installs a session);
	// a default-DENY/REJECT verdict installs no session and is already logged
	// unconditionally via the policy-deny RT_FLOW record, so the flags are inert
	// there (commit emits a WARNING — validateDefaultPolicyLogWarnings).
```

**Why it is only Low**: two real mitigations. Commit emits a warning (`validateDefaultPolicyLogWarnings`), and deny is logged unconditionally anyway — so an auditor asking "is the default-deny boundary logged?" gets the right *answer* even though the specific `session-init` record type it promises never appears. The over-promise is about record type, not about whether logging happens.

**Fix direction**: Gate the two fields on `cfg.Security.DefaultPolicy` being permit, or carry an `Inert bool` on the synthetic row.

**Dedup note**: #3670/#3534/#3363 are the closed changes that created this row. Not a seed.

**Verified against origin/master**: `pkg/api/security.go:362-387`, `pkg/grpcapi/server_show_zones.go:335-345`, `pkg/config/types_security.go:102-114` at base SHA (== tip).

---

## 3. Sweep A — `security flow` chain, CLOSED

`config.FlowConfig` has 21 fields (`pkg/config/types_security.go:131-166`). Carrier = a field in `FlowSnapshot` (`protocol.go:168-205`). Printed = any of the six scope packages.

| Config field | Wire carrier | Live Rust reader | Printed | Verdict |
|---|---|---|---|---|
| `TCPSession.EstablishedTimeout` | `TCPSessionTimeout` | yes | yes | NEG |
| `TCPSession.InitialTimeout` | **none** | — | yes | **seed instance 1 — not re-reported** |
| `TCPSession.ClosingTimeout` | **none** | — | yes | **seed instance 1** |
| `TCPSession.TimeWaitTimeout` | **none** | — | yes | **seed instance 1** |
| `UDPSessionTimeout` | `UDPSessionTimeout` | yes | yes | NEG |
| `ICMPSessionTimeout` | `ICMPSessionTimeout` | yes | yes | NEG |
| `TCPMSSAllTCP` | `TCPMSSAllTCP` | yes | yes | NEG |
| `TCPMSSIPsecVPN` | carried | rejected at commit (#2486) | yes, **annotated** `(not enforced)` | NEG — correct precedent |
| `TCPMSSGreIn` / `GreOut` | carried | yes | yes | NEG |
| `AllowDNSReply` | carried | yes | yes | NEG |
| `AllowEmbeddedICMP` | carried | yes | yes | NEG |
| `GREPerformanceAcceleration` | `GREAcceleration` | **no** (`protocol.go:184-185`) | yes, unannotated | **finding 9** |
| `PowerModeDisable` | carried | no behavioral effect | yes, unannotated | **NEG — see §5 disproofs** |
| `SynFloodProtectionMode` | via screen | yes | via `show security screen` | NEG |
| `Traceoptions` | n/a (host-side) | n/a | yes | NEG |
| `AgingEarlyAgeout` | **none** | — | **no** | NEG — closes the branch |
| `AgingHighWatermark` | **none** | — | **no** | NEG |
| `AgingLowWatermark` | **none** | — | **no** | NEG |
| `RouteChangeTimeout` | **none** (#4231) | — | **no** | NEG |
| `SyncICMPSession` | **none** (#4231) | — | **no** | NEG |
| `ForceIPReassembly` | **none** (#4231) | — | **no** | NEG |
| `MulticastSessionLifetime` | **none** (#4231) | — | **no** | NEG |
| `PreserveIncomingFragmentSize` | **none** (#4231) | — | **no** | NEG |

**Closure argument**: these are all 21 fields of `FlowConfig`; the carrier column is a complete grep of `FlowSnapshot`; the printed column is a complete grep of the six scope packages. Therefore the `security flow` instance set is exactly {the three seed timeouts, finding 9} — **N = 4, of which 1 is new**. The eight `**none**`-carrier fields that are *not printed* are the reason the class does not extend further here: someone deliberately kept them off the show surface.

## 4. Sweep B — fail-closed snapshot exclusions, CLOSED over `pkg/dataplane/userspace/`

20 sites drop or degrade a config object. Rendered = a `show` surface renders that object from config with no snapshot cross-check.

| Site | Object dropped | Rendered? | Finding |
|---|---|---|---|
| `nat_source.go:78,88,105,120` (4) | source-NAT rule marked unusable | yes | **1** |
| `nat_nptv6.go:37` | NPTv6 rule w/ unsupported scope | yes (×3 surfaces) | **2** |
| `nat_static.go:66` | `then static-nat inet` | yes | **5** |
| `nat_static.go:82` | out-of-range dest/mapped port | yes | **5** |
| `nat_destination.go:138` | non-host DNAT pool address | yes | **5** |
| `nat_destination.go:143` | out-of-range DNAT pool port | yes | **5** |
| `mirrors.go:52,58,67,78,85` (5) | mirror instance / input iface | yes | **6** |
| `cos.go:64,99,138,228,248` (5) | classifier / rewrite / sched-map entry | yes | **7** |
| `filters.go:244` | DSCP rewrite (term still acts) | yes | **8** |
| `filters.go:266` | whole term (bad tcp-flags) | yes | **8** |
| `filters.go:628` | unresolved prefix-list ref | yes | **8** |
| `filters.go:195,201,705` (3) | positive/except mixing | fail-closed narrowing, not a drop | NEG |
| `flow.go:230,234` (2) | flow-export collector | yes | **11** |
| `maps_sync.go:1313,1323,1370,1380` (4) | binding-array slot (watchdog) | no config object | NEG — excluded |
| `eventstream.go:1091` | unsupported callback frame | runtime-internal | NEG — excluded |

**Closure argument**: the enumeration is a complete `slog.Warn`/`slog.Error` sweep of every config→wire builder file in `pkg/dataplane/userspace/` (`nat_source, nat_destination, nat_static, nat_nptv6, nat64, policies, policies_lower, zones_snapshot, filters, cos, mirrors, flow, interfaces, fabric, neighbors`), cross-checked by counting `continue` occurrences per file to catch unlogged drops. Every site that drops a *config object* has a show surface that renders it, and **not one of them annotates the exclusion**. Therefore, within this sub-class, the instance set is exactly the 20 sites → findings 1, 2, 5, 6, 7, 8, 11.

This is the finding I would most want carried forward: **the fail-closed drop is a systematically invisible state.** Every one of these sites was added by a previous fix that correctly chose to fail closed rather than widen — and every one of them created a new instance of this class as a side effect, because failing closed and telling the operator are separate acts and only the first was done.

## 5. Sweep C — documented-inert config fields, CLOSED over `pkg/config/types_*.go`

Grepped every field the codebase itself documents as unenforced against all six scope packages.

**Not printed by any surface → class does not extend (12):**
`AgingEarlyAgeout`, `AgingHighWatermark`, `AgingLowWatermark`, the #4231 five (`RouteChangeTimeout`, `SyncICMPSession`, `ForceIPReassembly`, `MulticastSessionLifetime`, `PreserveIncomingFragmentSize`), CoS `TransmitRateRemainder` / `BufferSizeTemporalUS` / `GuaranteedRateBytes` / `DelayBufferRateBytes` / IEEE8021 rewrite rules, interface `NativeVlanID` / `GratuitousARPReply` / `NoGratuitousARPRequest` / `UnnumberedInet` / `TargetedBroadcast`, login-class `IdleTimeout` / `AllowCommands` / `DenyCommands` / `AllowConfiguration` / `DenyConfiguration` (the #5831 RBAC gap — **not** rendered anywhere, which is the right outcome), NAT pool `PortOverloadingFactor`, NAT pool `RoutingInstance`, `PersistGroupsInheritance`, `DNSProxyConfigured`.

**Printed WITH a correct annotation → NEG, and these are the model (4):**
- `pkg/cli/cli_show_flow.go:932` — `"IPsec VPN MSS (not enforced):"`
- `pkg/api/show_text.go:293` — `"TCP MSS (IPsec VPN):  %d (not enforced)"`
- `pkg/cli/show_services_dhcp.go:135,138` — `"forward-only (accepted-only)"`, `"relay-agent-option (accepted-only)"`
- `pkg/natshow/static.go:81` — `"Then routing-instance: %s (accepted; cross-VRF post-translation routing not enforced)"`

**Closure argument**: the grep pattern covers every phrasing the repo uses for inertness (`accepted-only`, `not enforced`, `no-op`, `inert`, `never read`, `not read by`, `deferred feature`, `not yet {read,enforced,implemented,wired}`), and each hit was individually checked against the six packages. The Sweep-C instance set is exactly {finding 9}.

## 6. Disproofs — recorded so a future reviewer does not re-chase (19)

1. **`power-mode-disable: yes`** (`cli_show_flow.go:955-957`). `protocol.go:187-194` says it "does not currently alter packet handling (there is no express/regular split to switch between)". Since xpf has only the regular path, "power mode is disabled" is *vacuously true*. Printing `yes` is accurate. NEG — this one looks like an instance and is not.
2. **Per-application `inactivity-timeout` / `ALG`** (`cli_show_security_dispatch.go:162-198`). Carried (#3227) at `protocol_policies.go:283` + `protocol_ha.go:95`, populated at `capabilities.go:342`, read on the Rust side. NEG.
3. **`show class-of-service interface` queue table** (`format/cos_sections.go:505-560`). Seeds from config then **overrides from the live runtime queue** at `:550-558`. Correct design — and the reason finding 4 is scoped to `scheduler-map` only. NEG.
4. **`show interfaces detail/extensive`** speed/duplex/MTU (`cli_show_interfaces_detail.go:91-104`) — live `netlink` attrs + `readLinkSpeed`/`readLinkDuplex` sysfs. NEG.
5. **`show security ipsec security-associations` / `statistics`** (`cli_show_security_ipsec.go:17, 128, 180`) — live `c.ipsec.GetSAStatus()`. NEG.
6. **`show security ipsec` (no args)** (`:77-119`) — renders configured VPNs (gateway, policy, bind-interface, traffic selectors). All are config facts rendered as config facts; no state word appears. Junos puts the live view under `security-associations`, which this surface routes to correctly. NEG.
7. **`show security screen` / `screen-ids-option`** (`cli_show_security_screen.go`) — all 16 checks are dataplane-enforced (CLAUDE.md); `alarm-threshold` is log-only in Junos too, so the unannotated render is parity-correct. NEG. (The dangling-profile-reference hazard is #5806, DUP.)
8. **`showScreen` drop counters** (`:83-101`) — reads live counters and surfaces `readErr` as an explicit warning. Correct. NEG.
9. **`monitoriface` traffic counters** — live `ReadInterfaceCounters`, and the userspace branch carries `StatusNote` on error (`monitor.go:521-527`). Correct — it is the *sibling* error branch that is missing one (finding 10). NEG for the traffic half.
10. **`pkg/diagcmd`** (all 273 LOC) — argv construction for ping/traceroute (`VRFDeviceName`, `MaxPingSize`, `PingOptions`). No rendering, no config-vs-runtime surface. NEG.
11. **`natshow.noteSessionScanError`** (`natshow.go:41-52`, #5557) — *"a zero that reads as 'no sessions' rather than 'could not read'"*. This is the fix for the exact hazard in seed instance 3, already applied to the session-scan half. NEG, and a model for §7.
12. **Local `Maximum-sessions`** (`cli_show_flow.go:574-582`, #5323) — correct; renders `unknown` rather than fabricating. NEG (the peer half is finding 3).
13. **`FormatInterfacesQueue` nil-vs-error** (`show_services_cos.go:78-88`, #5326) — *"a nil status must not conflate 'unreachable' with 'empty'"*. NEG, another model.
14. **`show security flow session summary` hardcoded zeros** (`cli_show_flow.go:565-573`, `:618-626`) — `Multicast-sessions`, `Services-offload-sessions`, `Failed-sessions`, `Sessions-in-drop-flow`, `Pending`, `Invalidated`, `Sessions in other states`. These are Junos schema fields for states xpf's session model does not have (there is no pending/invalidated state to count). A structural `0` for a state that cannot exist is not the same defect as a `0` for an unmeasured state. Borderline — I record it as NEG but flag that a triager could reasonably disagree on `Failed-sessions`.
15. **`Scope Policy: 0`** (`cli_show_security.go:259, 308`) — Junos cosmetic field, no xpf analogue. NEG.
16. **`printAppDetail` `appName == "any"`** (`cli_show_security_dispatch.go:163-168`) — the `0`s are Junos's literal representation of the `any` application. NEG.
17. **`maps_sync.go:1313,1323,1370,1380` + `eventstream.go:1091` drops** — binding-array watchdog slots and unsupported callback frames. Runtime-internal; no config object, no show surface renders them. NEG, and this is what bounds Sweep B.
18. **`filters.go:195, 201, 705`** — positive/except list mixing. These *narrow* the match fail-closed rather than dropping the term, and the narrowing is the documented intent. NEG.
19. **`cos.go:248`** (scheduler-map naming an undefined *scheduler*) — the comment says "dataplane applies safe best-effort", i.e. degraded rather than dropped. Folded into finding 7 rather than counted separately, since the show surface consequence is the same but the severity is lower.

---

## 7. Remediation: shared mechanism, and specifically **not** the annotation helper

The parent asked for a per-site-vs-shared judgement. **Shared** — but I want to argue against the obvious shared mechanism, because I think it is the wrong one.

**The obvious answer is an annotation helper** — a render function that requires an explicit "config-only / not enforced" flag. The repo has effectively already built this by hand four times (§5), and it works well: `(not enforced)`, `(accepted-only)`, `(accepted; cross-VRF post-translation routing not enforced)` are all clear and correct. Generalising it would close findings 9, 12 and 13.

**It would not close findings 1–8 or 11**, which are the majority and the more serious half. Those are not "we knew at authoring time that this field is inert." They are **"the dataplane decided at runtime that this specific object is not installed."** An annotation is a *static* fact about a field; the fail-closed drop is a *dynamic* fact about an instance. No amount of authoring discipline catches `pool_unusable` on rule `r1` but not rule `r2`.

So the mechanism I would build is **an applied-set readback**, and the annotation helper second:

1. **Give every operator-facing renderer the applied snapshot alongside the config, and make the config-only signature the exception that must be justified.** Concretely: `natshow.Reader` (`natshow.go:60-67`) gains an applied-snapshot accessor; `FormatCoSClassifiers` / `FormatCoSSchedulerMaps` / `showPortMirroring` / `RenderNPTv6` gain a snapshot parameter. The renderer then diffs: *configured but not in the applied set* → render with an explicit not-installed marker and the builder's own reason string. Findings 1, 2, 5, 6, 7, 8 and 11 all collapse into this one change, and — importantly — **future fail-closed drops are covered automatically**, which is the property that matters given Sweep B showed every past fail-closed fix silently minted a new instance of this class.

2. **Make the reason travel.** `pool_unusable_reason` already does exactly this (`protocol_nat.go`, `nat.rs:106-107`) and is the existing proof the approach works. The other drop sites currently put their reason only in a `slog.Warn` string. Promoting those to a structured reason on the (absent) snapshot entry is what makes the marker say *why*.

3. **Then** the annotation helper, for the genuinely static cases (§5's four correct precedents plus finding 9). Low cost, and it makes the convention discoverable instead of folkloric — right now whether a field gets `(not enforced)` depends on whether the author of that particular line happened to know.

4. **`pkg/policymatch` is the right model and I would say so explicitly in the fix PR.** A sibling agent's observation matches what I found independently: policymatch maintains `DisplayAction`, `RouteDropNote` and `FragmentDenyNote` as three separate SSOT advisory strings precisely so a verdict can never over-promise. That is the same insight as (2) — *the reason a thing is not what it appears must be a first-class value that travels with the thing*, not a log line and not a comment.

**Testing note.** Finding 3 is the argument for why per-site fixes fail here: #5323 fixed the local path, added a regression test that explicitly greps for the retired literal, and still left the identical literal 45 lines below in the same function — because the test fixture was standalone and never entered the peer branch. A per-site campaign against this class will reproduce that outcome. A shared readback makes the wrong thing hard to write in the first place.

---

## 8. Coverage log

Swept and covered, with the invariant checked:

- **`pkg/natshow/` (535 LOC, all 6 files)** — `natshow.go` (Reader surface, `noteSessionScanError`), `source.go`, `dest.go`, `static.go`, `persistent.go`. Invariant: does each renderer read runtime state for values it presents as runtime state? Findings 1, 2, 5; NEG on `noteSessionScanError`.
- **`pkg/diagcmd/` (273 LOC, all files)** — argv construction only, no rendering surface. NEG (disproof 10).
- **`pkg/monitoriface/` (957 LOC)** — `monitor.go`. Invariant: is every printed counter gated on a successful read? Finding 10; NEG on the traffic/userspace halves.
- **`pkg/cli/` show surfaces** — `cli_show_flow.go` (full read: sessions, summary, timeouts, statistics, traceoptions, flow-monitoring), `cli_show_security_screen.go`, `cli_show_security_ipsec.go`, `cli_show_security_dispatch.go`, `cli_show_security_filters.go`, `show_services_cos.go`, `show_services_dhcp.go`, `show_services_mirror.go`, `cli_show_interfaces_detail.go`, `cli_show_security.go`, `cli_show_security_zones.go`, `cli_show_interfaces.go`. Findings 3, 6, 8, 9, 11.
- **`pkg/api/`** — `show_text.go` (all topics), `security.go`, `metrics_counters.go`, `metrics_descriptors_forwarding.go`, `metrics.go` (descriptor registry). Findings 2, 12, 13.
- **`pkg/grpcapi/`** — `server_show_flow.go`, `server_sessions.go`, `server_show_zones.go`, `server_show_firewall.go`, `server_show.go`, `server_show_nat.go` (via natshow). Findings 8, 13.
- **`pkg/dataplane/userspace/format/`** — `cos.go`, `cos_show.go`, `cos_sections.go`. Findings 4, 7; NEG on the runtime-preferring interface queue table.
- **Producer side, read to establish ground truth** — `protocol.go`, `protocol_cos.go`, `protocol_nat.go`, `protocol_policies.go`, `protocol_ha.go`, `nat_source.go`, `nat_destination.go`, `nat_static.go`, `nat_nptv6.go`, `cos.go`, `filters.go`, `mirrors.go`, `flow.go`, `capabilities.go`, `maps_sync.go`, `eventstream.go`; `pkg/config/types_security.go`, `types_cos.go`, `types_system.go`, `types_interfaces.go`; `pkg/routing/rules.go`; `proto/xpf/v1/xpf.proto`.
- **Rust side, read to prove enforcement** — `userspace-dp/src/nat/source.rs`, `src/protocol/nat.rs`, `src/protocol/cos.rs`, `src/afxdp/forwarding_build/cos.rs`.

**Sampled, not enumerated** (stated so the coverage claim is honest): `pkg/cli/cli_show_routing.go` (11 config reads), `pkg/cli/cli_show_system.go` (10), `pkg/cli/cli_show_cluster.go` / `pkg/grpcapi/server_cluster.go` (9 combined), `pkg/cli/cli_show_security_objects.go`, `show_services_snmp.go`, `show_services_ddns.go`, `show_services_lldp.go`, and the ~30 `metrics_descriptors_*.go` files beyond the forwarding/policy ones. A follow-up pass applying Sweep B's method to the routing/system/cluster builders is the highest-value next step.
