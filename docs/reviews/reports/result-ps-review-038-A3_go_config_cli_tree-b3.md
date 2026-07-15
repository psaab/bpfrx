# Triage Result: ps-review-038-A3_go_config_cli_tree-b3

- **Subsystem**: A3 batch 3/3 — Go config schema / validators / compilers / cmdtree completers
  (pkg/config/schema_*.go, compiler_*.go, cmdtree completers, appid matchers)
- **Base**: d4506d4450e23f9a3fc572206b3c82f6b6c99029 (review) vs current
  origin/master **cc451b6b58112328143c8afa654bdb8e48074a99** — triaged against
  current master.
- **Repo**: real bpfrx (symbols confirmed present/absent below).
- **Outcome counts**: 1 explicit finding + 4 embedded module notes.
  → 0 GENUINE-RESIDUAL, 1 NEGATIVE (the sole finding), 1 DELIBERATE
  (gratuitous-arp-count no-max), 3 CONFABULATED-filename module notes
  (2 of which are NEGATIVE-by-content).

## Nature of this batch

This is an explicit **coverage / negative** report. The single entry under
"Findings:" is:

> Title: "A3_b3 batch - no new high findings beyond dedup"
> Severity: Low, Confidence: Medium
> Fix direction: **No new fix needed.**

The reviewer states outright there is no new bug. The body is module-by-module
coverage notes plus an "integer truncation audit" whose conclusion is "No new
truncation bugs beyond already-filed issues."

## Per-item disposition

### Finding 1 — "A3_b3 batch - no new high findings beyond dedup" (Low / coverage)
**Disposition: NEGATIVE.** The reviewer explicitly asserts no bug and "No new
fix needed." Nothing to drive. Not a residual.

### Module note — schema_chassis.go: `gratuitous-arp-count` ValidateIntegerMin(1), no max → "GARP storm"
**Disposition: DELIBERATE (also reviewer-dedup'd F8-F11).**
- Symbol CONFIRMED present: `origin/master:pkg/config/schema_chassis.go:209`
  `"gratuitous-arp-count"` with `validator: ValidateIntegerMin(1)` and no max.
- Directly above it (schema_chassis.go:205-208) is the documented rationale:
  *"no-schema-only-caps doctrine (Codex, PR #1845) — Junos caps at 16, but
  enforcing that here would reject configs the runtime executes fine; a sanity
  cap belongs in the runtime first. Deployed: 8."* This is an intentional
  design posture, not an oversight.
- Blast radius: the value is an **operator-set local config knob** (failover
  GARP/NA burst count), not attacker-controllable. A large value costs a bigger
  local ARP burst on failover — no memory-safety/overflow issue, no remote
  reachability.
- The reviewer itself marks it Low and notes "dedup already has F8-F11."
  Not a novel reachable residual.

### Module note — schema_screen.go: "thresholds u32->u16 should be validated"
**Disposition: CONFABULATED filename + NEGATIVE by content.**
- `pkg/config/schema_screen.go` **does not exist** on origin/master. Screen/IDS
  schema lives in `pkg/config/schema_security.go`.
- In that file the screen protection leaves (`syn-flood` at
  schema_security.go:315, etc.) are **boolean-flag leaves with no typed value**
  — schema_security.go:330 documents "Boolean flag leaf, no value" (threshold-
  tuning posture). There is **no u32→u16 cast in the schema layer** to
  validate. The note is a coverage aspiration ("should be validated"), asserts
  no concrete bug, and points at a nonexistent file. Screen thresholds are
  operator config, not attacker input.

### Module note — schema_nat.go: "port 1..65535 correctly validated before uint16 cast"
**Disposition: CONFABULATED filename + NEGATIVE by content.**
- `pkg/config/schema_nat.go` does not exist; NAT schema lives in
  `schema_security.go`. The note is explicitly a **positive/clean** observation
  ("correctly validated"). No residual.

### Module note — schema_system.go: "MTU, etc. correctly bounded"
**Disposition: NEGATIVE.** `schema_system.go` confirmed present; the note is a
clean/positive observation. No residual.

### Module note — schema_snmp.go / schema_flow.go references
**Disposition: CONFABULATED filenames.** Neither `schema_snmp.go` nor
`schema_flow.go` exists on origin/master; SNMP/flow schema live elsewhere
(schema_security.go / schema_system.go). No concrete finding attached to these
— purely a mislabeled coverage list. Confirms this was a low-effort scan that
guessed at file organization.

## Dedup / cross-check
- gratuitous-arp-count: reviewer-dedup'd against F8-F11 (this batch's own chassis
  group) and is DELIBERATE per PR #1845; nothing to file.
- No overlap with the session backlog (#4517-#4604, open #2387/#4455/#4478/
  #4498/#4549/#4555/#4569/#4584/#4590) — none of those touch a schema integer-cap
  gap, and this batch surfaces no new concrete defect.
- The reviewer's own dedup note ("Atoi->uint32 ASN bug filed in A3_b2 review")
  points the one real integer bug to the sibling A3_b2 batch, not here.

## Conclusion
No novel, reachable, un-fixed defect. The sole finding is self-declared
coverage/no-fix; the one quasi-technical observation (gratuitous-arp-count
no-max) is a documented deliberate doctrine (PR #1845) on an operator-set knob,
already dedup'd. Three module notes reference confabulated filenames and assert
no bug. **0 genuine residuals.**
