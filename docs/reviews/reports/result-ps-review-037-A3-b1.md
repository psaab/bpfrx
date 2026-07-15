# Triage result — ps-review-037-A3-b1

- **Subsystem**: Go config compiler, schema & CLI grammar (batch 1 of 3) — `pkg/config/*`, `pkg/cmdtree/*`, `pkg/appid/*`
- **Source**: Codex per-subsystem deep audit (ps-037 A-series)
- **Base reviewed**: `d4506d4450e2` == **current `origin/master`** (verified — `git rev-parse origin/master` = d4506d445...). Base is fresh, not stale.
- **Cohort**: ps-037 A-series (A1 mem-safety 0 residuals; A2 NAT 0; A6 1 LOW DoS #4572). This is A3 batch 1.
- **Outcome counts**: 2 findings triaged →
  - GENUINE-RESIDUAL (novel, untracked): **2** — A3-B1-001 (Low-Med), A3-B1-002 (Low)
  - NEGATIVE (whole §6 verified consistent): the rest of the review's ~40 explicit negatives
  - CONFABULATED / ALREADY-FIXED / DUP / NOT-MATERIAL / DELIBERATE-only: 0
- **Overall**: A careful, low-noise audit. Both findings are real, all cited symbols exist on master, and neither duplicates the #4517-#4572 merged backlog or the open-issue set (#4548/#4549 are the nearest VRRP neighbors and are distinct). The reviewer's negatives match the CLAUDE.md-documented state and the merged fixes.

---

## Per-finding disposition

### A3-B1-001 — VRRP GroupID (VRID) 1..255 not validated → int→uint8 truncation → VRID 0/collision — **GENUINE-RESIDUAL, severity Low-Med (reviewer said Med — defensible)**

**All cited symbols verified on origin/master:**
- `pkg/config/schema_interfaces.go` `vrrpGroupSchemaNode(v6)` — the instance-name slot is `&schemaNode{desc:"VRRP group", args:1, placeholder:"<group-id>"}` with **no `keyValidator`** and no typed value on the id token. Confirmed the `schemaNode` type *does* carry a `keyValidator` field (schema.go:167) and it IS used elsewhere (address CIDR slots use `keyValidator: ValidateIPv4CIDR`), so the omission on vrrp-group is real, not a missing-feature confabulation.
- `pkg/config/compiler_interfaces.go:694-698` `parseVRRPGroups` — `groupID, err := strconv.Atoi(vrrpInst.name); if err != nil { continue }`. Only **non-numeric** garbage is dropped; out-of-range **numeric** (0, 256, 257, -1, 65536) is stored verbatim into `VRRPGroup{ID: groupID}`.
- `pkg/vrrp/instance.go` — `uint8(vi.cfg.GroupID)` wire truncation confirmed at RX filters `:1148, :1249, :1364, :1425` (`payload[1] != uint8(vi.cfg.GroupID)`) and TX `:1834, :1849` (`VRID: uint8(vi.cfg.GroupID)`). No range guard on GroupID anywhere in `pkg/vrrp` (`grep GroupID < 1 / > 255` → nothing).

**Why GENUINE-RESIDUAL and not DELIBERATE-only** (the sharp point):
The schema comment (schema_interfaces.go:14-21) *does* explicitly defer typing `vrrp-group <id>`: "Deliberately NOT typed: `unit <n>` / `vrrp-group <id>` instance ids (same deferral class as the chassis PR-2 redundancy-group/node ids ... deserve one dedicated pass)". So the *general* deferral is documented. **But two things make the specific harm a real residual the deferral rationale does not cover:**

1. The deferral's stated safety justification is *"garbage ids make the compiler silently drop the instance"* — which is true only for **non-numeric** garbage (Atoi err → `continue`). Out-of-range **numeric** ids are NOT dropped; they are stored and produce a **live** VRRP instance whose wire VRID is silently truncated (256→0, 257→1). The author's "silently drop = fail-safe" reasoning does not hold for the numeric-out-of-range case, which is fail-*dangerous* (a running instance with a reserved/aliased VRID).

2. The chassis analog the comment cites as its model **was subsequently hardened and VRRP was not.** `pkg/config/compiler_validate_strict_chassis.go:72` (`if id < 0 || id > MaxHeartbeatRedundancyGroupID` = 255) hard-rejects out-of-range redundancy-group ids at commit precisely to prevent the identical `uint8` wrap/collision (test `compiler_validate_strict_chassis_4434_test.go`). VRRP has **no** analogous `validateVRRPGroupIDStrict`. So the identical risk class was deemed worth a strict gate for chassis RG ids but left unguarded for vrrp-group ids — that asymmetry is the novel, actionable gap.

**Dedup (hard):** Not in `/tmp/all_findings.txt` (only F-077 accept-data, F-263 IsActive — neither is VRID range). Not in any open issue: #4548 = *learned* MaxAdvertInt RX clamp (a different mechanism — peer-advert interval, not config id); #4549 = 4 LOW crypto/HA residuals (hop-limit, heartbeat IPv4-only, PSK zeroize, same-node-id election) — no group-id range. `gh issue list` grep for vrid/vrrp-group/range → nothing. Genuinely untracked.

**Severity reconciliation (why Low-Med, not High, not merely Low):**
- Not High: requires **operator misconfiguration** (typing `vrrp-group 256`/`0`) — no external/remote attack surface. Junos itself validates 1..255, so this is a parity/robustness gap, not an exploit primitive.
- Not merely Low: it is on the **HA cold-boot critical path** (project focus area). The single-group fat-finger `vrrp-group 0` or `256` → wire VRID 0 (RFC 5798 reserved) produces a group that a strict RFC peer (real Juniper) discards → the VIP never masters → cold-boot blackhole on that group. The contrived dual-master case (ids 1 and 257 on the same interface aliasing to VRID 1) is less realistic but real. The project's own chassis precedent hard-rejects this class. Reviewer's Med is defensible; I'd anchor Low-Med.

**Fix direction (reviewer's is correct):** add `validateVRRPGroupIDStrict` mirroring `validateChassisClusterStrict` — iterate compiled `VRRPGroups`, hard-reject `ID < 1 || ID > 255` on strict commit (warn on lenient for #1960 parity), plus a defensive `GroupID` range check at `pkg/vrrp` instance creation. Test 0/256/257/-1.

---

### A3-B1-002 — VRRP priority flat-set parse ignores Atoi error, lenient path keeps 0/300 → uint8 truncation — **GENUINE-RESIDUAL, severity Low (marginal; reviewer said Low — correct)**

**Cited symbols verified on origin/master:**
- `pkg/config/compiler_interfaces.go:732` (flat-set Keys arm) `vg.Priority, _ = strconv.Atoi(keys[i])` — error swallowed. Same pattern for `PreemptHoldTime` and `AdvertiseInterval` (`:743`, `:751`).
- `pkg/config/compiler_interfaces.go:817` (hierarchical arm) `vg.Priority, _ = strconv.Atoi(v)` — same swallow.
- `pkg/vrrp/instance.go:1835`/`1850` `Priority: uint8(priority)` — truncation on wire.

**Why GENUINE but marginal (severity Low is right, arguably borderline NOT-MATERIAL):**
Unlike group-id, the priority leaf **does** carry a schema validator — `schema_interfaces.go` priority node has `validator: ValidateInteger(1, 255)`. So **strict commit rejects** non-numeric / out-of-range priority. The residual is confined to the **lenient path** (`CompileConfigLenient` used by `Load`/HA-sync), which downgrades SchemaValidate errors to warnings while `parseVRRPGroups` still swallows the Atoi error and keeps the bad value (0 on non-numeric, or the raw int later `uint8`-truncated on wire).

Reachability is narrow: a `priority 300` or `priority high` only reaches the lenient path if the config already **bypassed strict commit** (hand-edited DB, forward-compat load, or a schema regression) — HA config-sync ships already-strict-validated config, so a peer can't normally inject it. And the failure mode is **fail-closed** (priority 0 = RFC resignation → backup takes over; a truncated-down priority loses election) rather than fail-open. So it is defensive hardening with a very narrow trigger — a real latent parser bug (`_ =` should be `if …, err == nil`), correctly self-rated Low, and best folded into the A3-B1-001 fix.

**Dedup:** Distinct from #4548 (learned interval) and #4549 (crypto/HA batch). Not in all_findings.txt. Novel.

---

## §6 Negatives — verified consistent (no re-report)

Spot-verified the load-bearing negative claims against origin/master; they hold and match the merged backlog:
- Chassis strict gate exists and covers RG-id wrap (`compiler_validate_strict_chassis.go:72`, `MaxHeartbeatRedundancyGroupID=255`) — this is exactly what makes A3-B1-001's *absence* for VRRP the residual.
- `schemaNode.keyValidator` feature exists and is used (address CIDR slots) — confirms the vrrp-group omission is a real gap, and confirms the reviewer understood the mechanism.
- Schema comment documents the deliberate deferral of `vrrp-group`/`unit` instance-id typing (schema_interfaces.go:14-26) — consistent with the reviewer's own refutation notes.
- WG port/keepalive range-checked before cast, screen `uint32` wrap guard, CoS code-point 0..63/0..7, flex-match byte-offset/bit-length, NAT pool 256-cap, deterministic-NAT advisory (#4559 open) — all match documented state; no new findings warranted.

No negative was found to be a hidden residual; the audit's NEGATIVE verdicts are sound.

---

## Bottom line
2 GENUINE-RESIDUAL, both novel and untracked, both VRRP config-validation robustness gaps on the HA path:
1. **A3-B1-001 (Low-Med)** — `vrrp-group <id>` has no range validator; out-of-range numeric id → live instance with `uint8`-truncated wire VRID (256→0 reserved, 257→1 collision). Novel because the chassis analog got a strict gate (`validateChassisClusterStrict`) and VRRP did not, and the deferral comment's "garbage silently drops" rationale doesn't cover numeric out-of-range. Operator-misconfig only → capped below High.
2. **A3-B1-002 (Low)** — priority/hold-time/advertise-interval flat-set arms swallow the Atoi error; only the lenient path is exposed (schema validator covers strict), fail-closed. Fold into the A3-B1-001 fix.

No confabulations, no already-fixed, no dups. Result file written to `/tmp/result-ps-review-037-A3-b1.md`.
