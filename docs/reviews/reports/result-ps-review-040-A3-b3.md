# Triage Result: ps-review-040-A3-b3

- **Subsystem:** A3 — config parser/compiler, schema, CoS, HA/VRRP (129-file sweep)
- **Review base:** `0ebdb74b2e8bf04b40495f49b6a64f9146af09fc` (report header)
- **Triaged against:** current `origin/master` = `95b33d49634d56086269a62a92e213dae7926f88` (base != master; verified vs CURRENT master)
- **Repo cited by review:** `/home/ps/git/gemini-xpf/...` — this is the **gemini-xpf fork path**, not bpfrx. Symbols were re-verified in `/home/ps/git/bpfrx` on `origin/master`; all three cited symbols exist here, so this is a real path-name aliasing (gemini fork tracking bpfrx), not confabulation of the code.
- **Outcome counts:** 1 GENUINE-RESIDUAL (LOW-MED) / 2 NOT-MATERIAL / 0 ALREADY-FIXED / 0 CONFABULATED / 0 DUP

---

## Finding 1 — Nil deref in `ExpandApplicationSet()` / `memberIsNestedSet()` when `apps` is nil — **NOT-MATERIAL**

**Symbol check:** EXISTS. `pkg/config/predefined.go:228` `ExpandApplicationSet`, `:232` `expandAppSet` (derefs `apps.ApplicationSets` at line 237 via `lookupApplicationSet`), `:284` `memberIsNestedSet` (derefs `apps.ApplicationSets` at :285). The nil-deref *would* panic **if** any caller passed a nil pointer.

**Why NOT-MATERIAL — unreachable; the nil-passing caller is confabulated.**
Every real caller passes the **address of a struct field** (`&cfg.Applications`) or the address of a zero-value struct — both are never nil:
- 13 production callers all pass `&cfg.Applications`: `pkg/appid/runtime.go:67`, `compiler_validate_strict_application.go:82,578`, `compiler_validate_strict_nat.go:65`, `compiler_validate_strict_policy.go:194`, `pkg/dataplane/compiler.go:793,929`, `compiler_nat.go:761`, `userspace/capabilities.go:418`, `nat_destination.go:274`, `nat_source.go:411`, `policymatch.go:1473`.
- `memberIsNestedSet` is called from exactly one site (`predefined.go:250`, inside `expandAppSet`) — it is not an independent public nil-entry.
- Every test passes non-nil: `predefined_app_sets_4102_test.go:44` uses `empty := &ApplicationsConfig{}` (non-nil pointer to a zero struct); `app_set_failclosed_3727_test.go:50` passes `&config.ApplicationsConfig{...}`.

The review's trace step 1 ("an external telemetry handler or administrative CLI command attempts to query ... using `ExpandApplicationSet(setName, nil)`") names a caller that **does not exist** — the review admits in its own Refutation that "the compiler does so [passes non-nil]" and then rationalizes the finding purely on "the functions are exported ... accessible by tests/telemetry." No such nil-passing path is present on master. `&cfg.Applications` cannot be nil (address-of-field). This is a pure defensive-nil-guard suggestion with no reachable trigger. Not a genuine residual.

---

## Finding 2 — Unvalidated `then local-preference` / `metric` / `metric-type` in policy-statement actions → silent fail-open + potential FRR-reload break — **GENUINE-RESIDUAL (LOW-MED)**

**Symbol check:** EXISTS and confirmed on master.
- `pkg/config/schema_routing.go:202-204` — the three `then` leaves are declared with **no validator and no `valueType`**:
  ```
  "local-preference": {desc: "Local preference", args: 1, placeholder: "<value>", children: nil},
  "metric":           {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
  "metric-type":      {desc: "Metric type", args: 1, placeholder: "<type>", children: nil},
  ```
  (Contrast: nearly every *other* routing leaf on this file carries `validator: ValidateInteger(...)` — OSPF timers :271-274, BGP peer-as/local-as :318/:336/:371, static route metric :112/:128, RA lifetimes, etc. These three `then`-action leaves were missed.)
- `pkg/config/compiler_routing.go:870-885` (hierarchical AST) and `:1056-1080` (flat-set) both parse via `strconv.Atoi` under an `err == nil` gate **with no else branch**:
  ```
  case "local-preference":
      if v := nodeVal(ac); v != "" {
          if n, err := strconv.Atoi(v); err == nil { term.LocalPreference = n; term.HasLocalPreference = true }
      }
  ```
- Render sink: `pkg/frr/policy_render.go:1767-1775` emits `set local-preference %d` / `set metric %d` gated only on `HasLocalPreference` / `HasMetric`.

**Already-fixed check:** NO. `git log -S local-preference -- pkg/config/schema_routing.go` shows only `381b7c025` (#1891 mechanical schema extraction) — no validator was ever added to these leaves. The recent #4517-#4685 validator campaign (#4594-4596 CoS/LLDP, f285c0f5a OSPF/BGP hold-time, 78147f745 BGP peer-as wrap, d274a9de0 RA) explicitly covered *other* routing leaves and did not touch policy-statement `then` actions.

**Why GENUINE + reachable (two distinct failure modes):**
1. **Fail-open silent drop:** `set policy-options policy-statement P term T then local-preference abc` — schema has no `valueType`/validator, so `SchemaValidate` accepts free-form arg; the compiler's `strconv.Atoi("abc")` fails, the `err == nil` gate is skipped silently, `HasLocalPreference` stays false, and the FRR clause is never emitted. Commit **succeeds with no warning**; the intended routing attribute is silently unenforced. Junos rejects this at commit — parity/robustness gap.
2. **Overflow → FRR-reload break:** `then local-preference 42949672960` — `strconv.Atoi` returns a 64-bit `int` and **succeeds** (`n = 42949672960`), so `HasLocalPreference=true` and `policy_render.go` emits `set local-preference 42949672960`. BGP local-preference is a uint32 in FRR; the managed `frr-reload.py` run rejects the clause. This is the exact fable-167 R-1 class ("one out-of-range leaf aborts the whole FRR reload" → routing config-apply failure), which the project has repeatedly remediated by bounding leaves at the commit gate.

**Severity justification (LOW-MED, review said Medium):** Both triggers require **operator misconfiguration** (a typo or an out-of-range value), and only routing-policy attributes are affected — not a security boundary, no unauthenticated trigger. That caps it below a clean MEDIUM. But mode (2) can abort the whole managed FRR reload (blast radius = all routing config for that commit), and the class is one the project actively closes, which lifts it above a pure LOW. Net LOW-MED.

**Fix:** add `valueType: ValueInteger` + `validator: ValidateInteger(0, maxWireU32)` to `local-preference` and `metric` at `schema_routing.go:202-203`; for `metric-type`, bound to the Junos-legal set (OSPF external type `1`/`2`) — `ValidateInteger(1, 2)`. This rejects both non-numeric and overflow input at commit, matching the file's established pattern.

**Lane:** config (Go schema-validator addition in `pkg/config/schema_routing.go`).

---

## Finding 3 — `SNMPCommunity` lacks `String()` redaction risking cleartext community in logs — **NOT-MATERIAL**

**Symbol check:** EXISTS. `pkg/config/types_system.go:514` `type SNMPCommunity struct { Name string; ... }`. No `func (SNMPCommunity) String()`.

**Why NOT-MATERIAL — no reachable log sink; every actual surface already redacts; the plain-string design is deliberate and documented.**
- **Deliberate, documented design (types_system.go:503-513):** the doc comment states `Name` "IS the shared secret" AND "is also the key of the `SNMPConfig.Communities` map, so it stays a plain string" — redaction is intentionally applied on the marshal surface, not the field type.
- **Marshal surface already redacted (#2053):** `SNMPCommunity.MarshalJSON` (:538) and `MarshalYAML` (:549) exist and redact `Name`; the enclosing config `MarshalJSON/YAML` (:428-497) route through them. This is the real persistence/serialization leak vector, and it is closed.
- **Operator-display surfaces already redacted:** `pkg/cli/cli_show_system.go:296-302` masks the community with `config.SecretDataPlaceholder` for any non-super-user class (#4111); the `show configuration` render redacts via `showConfigRedacted` (#4099/#4106).
- **SNMP agent deliberately does not log the value:** `pkg/snmp/agent.go:576-595` comments explicitly say the community is "redacted everywhere else" and log only booleans/`src` (`slog.Debug("SNMP: invalid community", "src", srcIP, "known_community", false)`), never the secret string.
- **No `%v`/`%+v` struct-value log sink exists:** a grep for any `slog`/`Printf` printing an `SNMPCommunity` value or the community string turned up nothing. (`cli_show_routing.go:798` `from community %s` is a **BGP routing community** e.g. `65000:100`, a different type entirely — not the SNMP secret.)

The finding is a defense-in-depth suggestion (add a `fmt.Stringer` in case future code logs the struct raw). It has **no demonstrated reachable leak** on master and contradicts a deliberately documented design. Not material.

---

### Summary
The A3 config/schema/CoS/HA scope is well-hardened (consistent with ps-038's ~0-residual result and the #4517-#4685 validator campaign). Finding 1's nil-panic is unreachable (confabulated caller). Finding 3's leak is closed on every real surface (marshal + show-config + show-system + agent-log) by deliberate design. The one genuine residual is Finding 2: three policy-statement `then` routing-action leaves (`local-preference`/`metric`/`metric-type`) escaped the commit-gate validator campaign, leaving a fail-open silent drop on non-numeric input and an overflow-into-FRR-reload-break path — LOW-MED, config lane.
