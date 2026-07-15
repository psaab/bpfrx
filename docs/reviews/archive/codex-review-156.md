# Codex Review 156 - routing PBR/FBF kernel mirror audit

Date: 2026-07-01
Checkout: `/home/ps/git/codex-bpfrx`
HEAD: `5d77dbde724c` on `master`

## Pull / Sync

- Ran `git pull --rebase`; origin fetched and the checkout reported `Already up to date`.
- Worktree was restored clean after audit-only probes.

## Duplicate Suppression

Read/suppressed against prior review files and repo issue/pr docs:

- `/tmp/codex-review*.md`, `/tmp/agy-review*.md`
- `docs/issues/issue-history.md`, `docs/issues/pr-history.md`
- repo docs matching `PBR`, `FBF`, `next-table`, `rib-group`, and `RuleAdd`

Not re-filed here:

- #3430 closed: unattached filters, DSCP 0, PBR add-error aggregation, `any`/bare-host/prefix-list support, overflow surfacing.
- #3432 closed: output-attached `then routing-instance` rejected.
- #2273 closed: per-family `RuleList` clear errors surfaced.
- #1706 closed: next-table/rib-group priority-window overflow.
- Prior AppID/NAT/filter/host-inbound findings from reviews 153-155.

This report focuses on residual Linux `ip rule` mirror divergence for firewall-filter `then routing-instance` and adjacent route-leak apply semantics.

## Module Checklist

1. `pkg/routing/rules.go` PBR rule shape/build/apply: findings H01-H03, M01-M07, M10.
2. `pkg/dataplane/userspace/filters.go` userspace filter snapshot builder: inspected as contrast; no direct new bug here, but proves richer predicate surface.
3. `userspace-dp/src/filter/engine/eval.rs` PBR routing-instance evaluator: inspected as contrast; no direct new bug here.
4. `userspace-dp/src/filter/engine/matching.rs` per-packet matcher: inspected as contrast; no direct new bug here.
5. `userspace-dp/src/filter/compiler.rs` filter compiler: inspected as contrast; no direct new bug here.
6. `pkg/daemon/daemon_apply.go` routing apply caller: finding M08.
7. `pkg/routing/rules.go` next-table manager: finding H04.
8. `pkg/routing/rules.go` rib-group manager: finding H05.
9. `pkg/routing/rules_test.go` and `pkg/routing/routing_test.go`: findings L02-L05.
10. `pkg/routing/README.md`, `docs/multi-wan.md`, `docs/feature-gaps.md`: findings L01, L06-L09.

## Audit Probes Run

Temporary audit-only tests were created and removed before writing this report. They asserted current behavior, not desired behavior.

Command:

```bash
go test ./pkg/routing -run 'TestCodexAudit(PBR|NextTable|RibGroup)' -count=1
```

Result:

```text
ok  	github.com/psaab/xpf/pkg/routing	0.003s
```

The probes verified:

- destination-port-only PBR emits zero kernel rules and returns no build error.
- destination-port + destination-address PBR emits an address-only kernel rule.
- the same input filter attached to two interfaces dedupes to one global kernel rule.
- next-table `RuleAdd` failure returns nil from `Apply`.
- rib-group `RuleAdd` failure returns nil from `Apply`.

## High Confidence Findings

### H01 - Port-only FBF/PBR terms no-op on the kernel path with no returned degraded error

Evidence:

- `PBRRule` can carry only `TOS`, `Src`, `Dst`, table, and instance: `pkg/routing/rules.go:331-345`.
- Builder emits rules only when DSCP/source/destination is present; otherwise it logs and continues: `pkg/routing/rules.go:660-672`.
- Userspace snapshot does carry destination ports: `pkg/dataplane/userspace/filters.go:116-123`.

Snippet:

```go
type PBRRule struct {
    TOSSet bool
    Src string
    Dst string
    TableID int
}
...
if !hasDSCP && !srcConstrained && !dstConstrained {
    slog.Warn("PBR: filter term has routing-instance but no ip-rule-compatible criteria ...")
    continue
}
```

Runtime trace:

1. Operator configures `filter input steer term https from destination-port 443 then routing-instance blue`.
2. Userspace filter snapshot carries `DestPorts` and Rust can evaluate the routing-instance term.
3. `BuildPBRRules` sees no DSCP/source/destination criterion, logs only, and returns zero rules with nil error.
4. Any kernel/XDP_PASS path uses the default/main routing table instead of `blue`.

Fix direction: make L4-only FBF terms explicitly degraded in `BuildPBRRules` and surface through config/apply status, or add a kernel strategy that can represent L4 FBF (marking/classifier + `fwmark` rule).

### H02 - Port + address FBF widens to address-only on the kernel path

Evidence:

- Builder only resolves source/destination address and DSCP: `pkg/routing/rules.go:590-689`.
- It never reads `term.DestinationPorts`, `term.SourcePorts`, or their except variants.
- Audit probe confirmed `destination-port 443 + destination-address 203.0.113.10/32` emits one rule with `Dst=203.0.113.10/32` and no port selector.

Runtime trace:

1. Operator intends `to 203.0.113.10 tcp/443 -> blue`.
2. Kernel mirror installs `ip rule to 203.0.113.10/32 lookup blue`.
3. SSH, DNS, ICMP, and every other protocol to that host are steered to `blue` on kernel paths.

This is worse than H01 because it over-matches rather than under-steers.

Fix direction: treat any L4/per-packet constraint as unrepresentable unless the kernel mirror can enforce it exactly. Fail-safe should be "drop the kernel mirror rule and return degraded", not "emit a widened address-only rule."

### H03 - FBF rules are global, not ingress-interface scoped

Evidence:

- Current code documents the widening: `pkg/routing/rules.go:475-479`.
- Attachment collection stores only a set of filter names, not interface/unit/direction context: `pkg/routing/rules.go:533-559`.
- `PBRRule` has no incoming-interface/iif field: `pkg/routing/rules.go:331-345`.
- Audit probe with the same filter on two interfaces produced one global rule.

Snippet:

```go
// resulting ip rules carry no incoming-interface selector
...
if unit.FilterInputV4 != "" {
    inet[unit.FilterInputV4] = struct{}{}
}
```

Runtime trace:

1. Junos FBF is attached to a specific interface input filter.
2. xpf derives one global `ip rule` from the filter name.
3. Any packet matching DSCP/source/destination can hit the FBF rule even if it entered a different interface where the filter was not attached.

Fix direction: preserve attachment context through `BuildPBRRules` and emit `iif`-scoped rules where kernel support allows it. If ifname mapping is unavailable, surface "kernel mirror widened to global" as an explicit degraded capability.

### H04 - next-table `RuleAdd` failures are swallowed after clear-then-add

Evidence:

- `nextTableManager.Apply` clears first, then logs `RuleAdd` failure and `continue`s: `pkg/routing/rules.go:60-125`.
- It returns only `clearErr`: `pkg/routing/rules.go:123-125`.
- PBR has the safer pattern and aggregates add errors: `pkg/routing/rules.go:374-433`; tests pin this at `pkg/routing/rules_test.go:484-502`.

Snippet:

```go
if err := n.ops.RuleAdd(rule); err != nil {
    slog.Warn("failed to add next-table rule", ...)
    continue
}
...
return clearErr
```

Runtime trace:

1. Existing next-table leak rules are cleared.
2. A transient `RuleAdd` failure prevents the desired leak from being installed.
3. `Apply` returns nil when `clearErr` is nil.
4. Caller has no programmatic failure signal; only an ephemeral log records that inter-VRF forwarding is gone.

Fix direction: mirror PBR: collect per-route parse/add failures with `errors.Join` and return non-nil while still attempting all desired rules.

### H05 - rib-group IPv4/IPv6 `RuleAdd` failures are swallowed after clear-then-add

Evidence:

- `ribGroupManager.Apply` clears first: `pkg/routing/rules.go:178-186`.
- IPv4 add failure logs only: `pkg/routing/rules.go:272-279`.
- IPv6 add failure logs only: `pkg/routing/rules.go:282-295`.
- Return value is only `clearErr`: `pkg/routing/rules.go:298-299`.

Snippet:

```go
if err := rg.ops.RuleAdd(rule); err != nil {
    slog.Warn("failed to add rib-group IPv4 rule", ...)
}
...
return clearErr
```

Runtime trace:

1. Existing rib-group leak rules are cleared.
2. IPv4 add fails, IPv6 add succeeds, or both fail.
3. `Apply` returns nil when clear succeeded.
4. The route-leak state is partially installed, but daemon-level code cannot tell from the return value.

Fix direction: aggregate both family add failures and return a joined error. Do not mark a table as successfully leaked until both required family outcomes are represented explicitly.

## Medium Confidence Findings

### M01 - `from protocol` is ignored by the kernel FBF mirror

Evidence:

- Userspace snapshot carries protocols: `pkg/dataplane/userspace/filters.go:108-115`.
- Rust compiler lowers them into protocol bitmaps: `userspace-dp/src/filter/compiler.rs:530-638`.
- Rust matcher enforces the bitmap: `userspace-dp/src/filter/engine/matching.rs:188-190`.
- `PBRRule` has no protocol field and `buildPBRFromFilter` never reads `term.Protocols`.

Runtime trace: `from protocol tcp destination-address X then routing-instance blue` becomes kernel `to X lookup blue`, steering UDP/ICMP too.

Fix direction: mark protocol-constrained kernel PBR terms unrepresentable or implement mark-based classification.

### M02 - Source-port constraints are ignored by the kernel FBF mirror

Evidence:

- Userspace snapshot carries `SourcePorts`: `pkg/dataplane/userspace/filters.go:116-123`.
- Rust compiler builds source-port matchers: `userspace-dp/src/filter/compiler.rs:551-642`.
- `PBRRule` has no source-port field.

Runtime trace: `from source-port 12345 source-address 10.0.0.0/8 then routing-instance blue` widens to all source ports from `10.0.0.0/8` on kernel paths.

Fix direction: same capability degradation path as H02.

### M03 - Destination-port-except/source-port-except constraints are ignored by the kernel FBF mirror

Evidence:

- Userspace snapshot carries except-port vectors: `pkg/dataplane/userspace/filters.go:120-148`.
- Rust compiler carries inversion flags: `userspace-dp/src/filter/compiler.rs:551-645`.
- Kernel PBR builder has no port or inversion fields.

Runtime trace: `destination-port-except ssh` with an address emits an address-only kernel rule, routing the excluded SSH traffic too.

Fix direction: any positive/negative L4 port criterion must either be exactly represented or make the kernel mirror fail-safe degraded.

### M04 - TCP flags are ignored by the kernel FBF mirror

Evidence:

- Go snapshot carries TCP flags and forbidden masks: `pkg/dataplane/userspace/filters.go:192-221`.
- Rust matcher enforces `tcp_flags_mask` / `tcp_flags_forbidden`: `userspace-dp/src/filter/engine/matching.rs:33-55`.
- Kernel PBR has no TCP flag fields.

Runtime trace: SYN-only steering such as `from tcp-flags "syn & !ack"` becomes all-address/all-DSCP steering on kernel paths if paired with representable address/DSCP criteria.

Fix direction: treat per-packet TCP flag criteria as unrepresentable for Linux `ip rule`.

### M05 - ICMP type/code constraints are ignored by the kernel FBF mirror

Evidence:

- Go snapshot carries ICMP type/code lists: `pkg/dataplane/userspace/filters.go:223-251`.
- Rust matcher gates ICMP type/code on protocol and L4 presence: `userspace-dp/src/filter/engine/matching.rs:59-77`.
- Kernel PBR has no ICMP type/code fields.

Runtime trace: ping-only or traceroute-only FBF terms paired with an address become all-ICMP/all-protocol address routing on kernel paths.

Fix direction: degrade rather than widen.

### M06 - `from is-fragment` is ignored by the kernel FBF mirror

Evidence:

- Go snapshot carries `IsFragment`: `pkg/dataplane/userspace/filters.go:222`.
- Rust matcher enforces `term.is_fragment`: `userspace-dp/src/filter/engine/matching.rs:56-58`.
- Kernel PBR has no fragment field.

Runtime trace: a fragment-only steering term can either no-op (if no DSCP/address) or widen to non-fragments as well.

Fix direction: make fragment criteria an explicit kernel-PBR unsupported capability.

### M07 - Flexible-match-range FBF criteria are ignored by the kernel mirror

Evidence:

- Go snapshot carries `FlexMatch`: `pkg/dataplane/userspace/filters.go:253-300`.
- Rust matcher evaluates byte-window constraints fail-closed: `userspace-dp/src/filter/engine/matching.rs:79-149`.
- Kernel PBR has no flex-match representation.

Runtime trace: custom byte-offset FBF terms are exact in userspace but either absent or widened in the kernel mirror.

Fix direction: do not emit a Linux `ip rule` for a flex-constrained term unless there is a classifier/mark backend that enforces the same predicate.

### M08 - PBR degraded build state is log-only at the daemon boundary

Evidence:

- `daemon_apply.go` logs build degradation and continues: `pkg/daemon/daemon_apply.go:1098-1110`.
- No structured status/counter is updated there.

Snippet:

```go
pbrRules, buildErr := routing.BuildPBRRules(cfg)
if buildErr != nil {
    slog.Warn("PBR rule build degraded", "err", buildErr)
}
if err := d.routing.ApplyPBRRules(pbrRules); err != nil {
    slog.Warn("failed to apply PBR rules", "err", err)
}
```

Runtime trace:

1. A term is dropped or degraded during kernel PBR build.
2. Daemon emits a warning log.
3. Monitoring/API users do not get a stable "PBR degraded" state to alert on.

Fix direction: expose degraded kernel PBR terms in system status and metrics, naming filter/term/reason.

### M09 - FBF kernel mirror uses `ip rule` linear policy lookup for high fanout

Evidence:

- PBR expands DSCP x source x destination to individual rules: `pkg/routing/rules.go:675-689`.
- `maxPBRRules` is 1000: `pkg/routing/rules.go:347-352`.
- Linux fib rule lookup is ordered and priority-scanned.

Risk trace: large enterprise FBF policies with hundreds of source/destination scopes add per-packet rule-walk cost to every kernel-routed packet before main-table lookup.

Fix direction: if kernel mirror remains required, use nft/clsact/TC-BPF mark classification plus a small `fwmark` ip-rule set instead of exploding every predicate into `fib_rules`.

### M10 - PBR builder's "matching Junos FBF semantics" comment is no longer precise

Evidence:

- Comment claims `BuildPBRRules` matches Junos FBF semantics: `pkg/routing/rules.go:464-465`.
- Same comment later admits no incoming-interface selector: `pkg/routing/rules.go:475-479`.
- The builder also ignores L4/per-packet predicates described above.

Risk trace: future callers/tests may treat the kernel mirror as semantically complete because the top-level comment says so.

Fix direction: rename/comment this as a limited Linux kernel mirror: exact only for DSCP/source/destination, degraded/unsupported for L4, fragments, flex, and interface scoping.

## Low Confidence / Triage Findings

### L01 - Docs overstate PBR without documenting kernel-mirror limitations

Evidence:

- `docs/feature-gaps.md:371` lists PBR as present.
- `docs/multi-wan.md:331-333` says kernel steering emits rules matching DSCP/addresses, but does not call out that L4/interface-scoped FBF terms diverge from userspace.
- `pkg/routing/README.md:115-118` only documents the priority band.

Suggested issue: label as feature-parity/vSRX. Document the exact PBR matrix: userspace full filter evaluator vs Linux kernel mirror limited to DSCP/source/destination and no iif.

### L02 - No regression coverage for L4-constrained PBR widening

Evidence:

- `TestBuildPBRRules` covers DSCP/address/prefix-list/overflow but not protocol/ports/TCP flags/ICMP/fragment/flex: `pkg/routing/routing_test.go:723-1149`.

Suggested issue: add tests that prove every unrepresentable criterion returns degraded and emits no widened rule.

### L03 - No regression coverage for per-interface FBF scoping

Evidence:

- `pbrTestConfig` creates one attached input filter on one unit: `pkg/routing/routing_test.go:704-720`.
- No test attaches the same filter to multiple interfaces or asserts `iif`.

Suggested issue: add explicit tests for per-interface FBF intent. If current global behavior is accepted, assert and document the degradation.

### L04 - next-table lacks RuleAdd error aggregation tests

Evidence:

- `TestPBRApplyAggregatesAddErrors` exists for PBR: `pkg/routing/rules_test.go:484-502`.
- Next-table tests cover fake apply and priority cap, but not RuleAdd failure propagation: `pkg/routing/rules_test.go:250-344`.

Suggested issue: add `TestNextTableApplyAggregatesAddErrors` and make it fail on current code.

### L05 - rib-group lacks RuleAdd error aggregation tests

Evidence:

- Rib-group tests cover fake apply, unknown rib, defined rib, and priority cap: `pkg/routing/rules_test.go:108-247`, `pkg/routing/rules_test.go:345-431`.
- No add-error propagation test exists.

Suggested issue: add IPv4-only, IPv6-only, and both-family add-failure cases.

### L06 - `pkg/routing/rules.go` still mixes three distinct routing domains

Evidence:

- `rules.go` owns next-table, rib-group, and PBR in one file; routing README lists all three as one rule domain: `pkg/routing/routing.go:13-15`.

Suggested refactor: split into real domain packages/files such as `routing/rules/nexttable`, `routing/rules/ribgroup`, `routing/rules/pbr` or `routing/pbr/kernel`, not `rules_nexttable.go` file-motion. Each should have its own capability/error contract.

### L07 - PBR builder has no capability result type

Evidence:

- `BuildPBRRules` returns only `[]PBRRule, error`: `pkg/routing/rules.go:486-530`.

Risk: callers cannot distinguish "exact", "under-steered", "over-steer avoided", and "global iif widening accepted".

Suggested refactor: return a structured build report with per-filter/per-term `Supported`, `Dropped`, `Widened`, `Reason`, and `KernelRuleIDs`.

### L08 - No stable operator metric for kernel PBR skipped/widened/degraded terms

Evidence:

- Daemon path only logs warnings: `pkg/daemon/daemon_apply.go:1103-1110`.

Suggested issue: expose counters/gauges such as `xpf_kernel_pbr_degraded_terms{filter,term,reason}` and show them in CLI/API.

### L09 - Multi-WAN FBF recipe lacks a negative validation cell for kernel-path L4 predicates

Evidence:

- `docs/multi-wan.md:331-349` documents DSCP/address kernel steering and counters.
- No documented test matrix checks `destination-port`/`protocol` FBF on XDP_PASS/kernel path.

Suggested issue: extend smoke to prove DSCP/address exactness and L4 unsupported/degraded behavior.

### L10 - Route-leak managers should share a common clear/add transaction contract

Evidence:

- PBR aggregates clear/parse/add/overflow errors: `pkg/routing/rules.go:374-433`.
- next-table and rib-group return only clear errors: `pkg/routing/rules.go:123-125`, `pkg/routing/rules.go:298-299`.

Suggested refactor: one small `iprule/reconciler` helper with:

- clear window
- add all desired rules
- aggregate add/delete/list errors
- domain-specific rule rendering

This would reduce drift between PBR and the older route-leak managers.

### L11 - `pkg/routing/README.md` documents `RuleDel` best-effort but not per-rule `RuleAdd` contract

Evidence:

- README covers `RuleList` and `RuleDel` behavior: `pkg/routing/README.md:146-172`.
- It does not state whether `RuleAdd` failures are fatal/observable for each reconciler.

Suggested issue: update the contract after H04/H05 are fixed. The intended production bar should be consistent across next-table, rib-group, and PBR.

### L12 - vSRX parity should label FBF as split-brain until kernel mirror limitations are closed

Evidence:

- vSRX/Junos FBF is an interface input-filter semantic.
- xpf userspace evaluator has rich filter semantics, while Linux mirror is DSCP/source/destination and global-iif only.

Suggested issue label: `feature-parity/vsrx`, `routing`, `pbr`, `kernel-mirror`.

## Negative Results

- No new issue found in userspace filter snapshot carrying protocols/ports/tcp-flags/icmp/flex; those paths already look heavily defended and tested.
- No duplicate filed for #3430 DSCP/address/prefix-list fixes; those are visibly fixed and tested.
- No duplicate filed for #2273 RuleList clear errors; the prior PR intentionally left per-rule `RuleDel` best-effort, so this report focuses on per-rule `RuleAdd` asymmetry.
- No new issue filed for output-attached FBF; #3432 closed that direction gate.

## Recommended Issue Batch

1. **HIGH**: routing/PBR kernel mirror must not silently drop or widen L4/per-packet FBF terms.
2. **HIGH**: routing/PBR kernel mirror needs ingress-interface scoping or explicit degraded state.
3. **HIGH**: next-table `RuleAdd` failures must be aggregated and returned.
4. **HIGH**: rib-group `RuleAdd` failures must be aggregated and returned.
5. **MEDIUM**: expose structured kernel PBR degraded state in status/metrics.
6. **LOW**: split rule reconcilers into true domain modules and add a shared ip-rule transaction contract.
7. **LOW**: update docs/tests for the exact userspace-vs-kernel FBF support matrix.

