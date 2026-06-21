# Claude SMR — hostile plan review r1 (#2129 + #2130)

Reviewer posture: HOSTILE. I re-verified every load-bearing claim against
`325d106838` source rather than trusting the plan prose.

## Claims I independently confirmed

1. **v9 export is live + Go-side.** `netflow.go:504` puts `Version: 9` on the
   wire; `NewExporter`→`dialCollectors` (netflow.go:434); driven by
   `flowExportCallback` (daemon_flowexport.go:271-289) on SESSION_CLOSE.
   Lifecycle: `reconcileFlowExporters` at boot (daemon_run.go:843,857) + every
   commit (daemon_apply.go:1209). CONFIRMED — the plan's central diagnosis is
   correct.

2. **Rust FlowExporter is dead.** `grep` confirms `flow_export_config` has one
   writer (forwarding_build/mod.rs:251), zero readers. `FlowExporter::new`
   appears only in `flowexport_tests.rs`. `main.rs:11` references `flowexport`
   ONLY as `mod flowexport;`; no worker/poll loop references it. CONFIRMED.

3. **The gating asymmetry is real.** `BuildIPFIXExportConfig` gates on
   `VersionIPFIX != nil` (manager.go:149-151); `BuildExportConfig` does NOT gate
   on `Version9` (manager.go:53-56 only checks sampling). CONFIRMED — the fix
   correctly mirrors the existing IPFIX guard.

## Hostile findings

### F1 (MAJOR → must address before READY): the double-export deferral is under-argued, and the gate fix INTERACTS with it.

The plan defers "double-export to one collector when both v9+ipfix configured"
to a follow-up (§8). But after the §5.1 gate fix, the double-export case is
*precisely the case that survives*: a config with BOTH `version9` AND
`version-ipfix` still passes the new `Version9 != nil` gate AND the existing
`VersionIPFIX != nil` gate, so both exporters start and both `dialCollectors`
the same flow-server (verified: both collector loops read the same
`fo.Sampling...FlowServers`, manager.go:101-122 and 184-205). The gate fix does
NOT touch this. The plan is HONEST that it defers it, but it must state more
sharply that **#2129 has two harms and this PR fixes only harm #1 (unrequested
v9 for IPFIX-only) and explicitly leaves harm #2 (double-export when both)
present**. As written, a reader could think #2129 is "fixed." Required: the
issue comment + plan §3/§9 must say "#2129 partially fixed; double-export
tracked as follow-up" and the follow-up MUST be filed as a concrete issue
number at /engineer time (not a vague "file a follow-up"). This is the
difference between a clean partial fix and a misleading "resolved."

Is the deferral itself defensible? YES — the double-export de-dup requires the
per-flow-server version-binding redesign (resolve collectors per server from its
version selector), which is genuinely a larger change touching collector
resolution in both builders. Splitting it is correct. But the framing must not
overstate completeness.

### F2 (MINOR): 5.2-keep leaves a *new* documented-dead wire field — but that is consistent with an EXISTING project convention, so it is defensible. Sharpen the rationale.

I checked: the same forwarding-state struct already carries `#[allow(dead_code)]
gre_acceleration` and `power_mode_disable` "held for config truth/parity"
(forwarding.rs:78-86). So "keep a parsed-but-unused config field" is an
established pattern here. HOWEVER those are inline scalars; `flow_export_config`
pulls in a whole 490-line executable module. The plan's 5.2-keep removes the
EXECUTABLE module but keeps the *wire field producer* (`buildFlowExportSnapshot`
+ `FlowExportSnapshot` Go/Rust). That is coherent: the audit's actual complaint
is "the dataplane has a flow exporter that emits nothing" — removing the
executable module (FlowExporter + flow_export_config consumer) kills that signal
even if the wire field stays. The #1977 decode-safety tests
(protocol/tests.rs:1708-1769) are preserved under 5.2-keep, which is a real
benefit (they guard the #1961-class decode-abort). VERDICT on the sub-decision:
5.2-keep is acceptable AND better-justified than the plan currently states; cite
the gre_acceleration/power_mode_disable precedent explicitly in the plan so a
reviewer doesn't re-litigate it. 5.2-remove is also acceptable but trades the
decode-safety tests + a (small) rolling-upgrade-skew for cleaner removal —
serde `default` + Go `omitempty` make the skew benign, so 5.2-remove is not
*wrong*, just a bigger diff. Either converges; recommend keeping 5.2-keep as
the default with the precedent cited.

### F3 (MINOR): removal completeness — verify the field initializer, not just the field decl.

The plan's §5.2 removal list is correct as far as it goes, but
`flow_export_config` is written at forwarding_build/mod.rs:251 AND declared at
forwarding.rs:86. I confirmed the struct is built field-by-field (no `..Default`
shorthand for that field that I found), so removing both the decl and the
mod.rs:251 writer block is sufficient. /engineer MUST `cargo build` + `grep -rn
'flow_export_config\|FlowExporter\|crate::flowexport'` → expect zero hits after
removal (the `mod flowexport;` in main.rs goes too). Add this exact grep gate to
§7.

### F4 (NIT): behavior-change release note is correctly flagged but underspecified.

§5.1 correctly calls out that "sampling + flow-server, no flow-monitoring
stanza" loses v9 export after the fix. Good. But also note: a config with
`flow-monitoring version9` present but EMPTY (no templates) — `BuildExportConfig`
after the gate still proceeds (the gate is `Version9 != nil`, and the timeout
loop tolerates zero templates, manager.go:64-83). That matches the intent (the
presence of the `version9` stanza signals intent to export). Confirm this is the
desired semantic in the plan (it is the right call — presence, not non-empty —
mirrors IPFIX which also only checks `!= nil`). One sentence in §5.1 would
remove ambiguity.

## Scope / verdict reasoning

- Diagnosis: correct and well-verified.
- #2129 fix: correct mechanism, but the plan must stop short of implying full
  resolution (F1).
- #2130 fix: correct (Path A / 5.2-keep), better-justified than written (F2).
- One PR for both is right (they are coupled via Version9Template; small diff).
- No PLAN-KILL grounds — both are real, the fixes are sound, scope is sane.

Required before PLAN-READY: fold F1 (sharpen partial-fix framing + commit to a
concrete follow-up), F3 (grep gate in §7). F2/F4 are improvements to fold.

VERDICT: PLAN-CHANGES-REQUIRED
