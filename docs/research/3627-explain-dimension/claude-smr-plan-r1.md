# Claude SMR — hostile plan review r1 (#3627 part-B)

Reviewer stance: hostile. First-pass "READY with nits" is a yellow flag; I am
looking for reasons the architecture and the verdict are WRONG.

## Claims I verified against origin/master 63d1052e2

- **Current matcher has no per-dimension data and no host-inbound token.**
  CONFIRMED. `Result` (policymatch.go 277-328) has no miss-reason and no
  host-inbound-service field. `ruleMatches` (624-642) computes the failing
  dimension internally and discards it (returns bool). `matchJunosHost`
  (497-532) returns `HostInboundUnmatched:true` with no token and never consults
  the ingress zone's `host-inbound-traffic` stanza — it only looks at
  `security policies … to-zone junos-host` rules. TRUE.
- **`policymatch` already imports `pkg/dataplane/userspace`.** CONFIRMED
  (import line 59: `dpuserspace "…/pkg/dataplane/userspace"`). So the proposed
  B1 classifier home does not add a new dependency edge. Good — the layering
  claim holds.
- **Host-inbound token knowledge exists only as nft strings + Rust, not a
  structured tuple table.** CONFIRMED. `pkg/daemon/daemon_nft.go`
  `hostInboundServiceMatches`/`hostInboundProtocolMatches` return `[]string`
  ("tcp dport 22", …). `pkg/config/host_inbound_tokens.go` has the token *sets* +
  *family* maps but no port/proto tuples. So B1 genuinely needs a THIRD
  representation unless B1a extracts a shared one. The plan states this. TRUE.
- **Not Junos parity.** CONFIRMED from domain knowledge: Junos
  `show security match-policies` returns the first matching policy or "No
  matching policy found"; `result-count` returns first-N *matching* policies. No
  per-dimension miss explanation exists in Junos. B2 is a value-add beyond vSRX.
  The plan does not oversell this as parity — correct.

## Where I attack the plan

### A1 — B2's coarse `application` dimension may DEFEAT the feature (KILL lever)
The single most common no-match cause in practice is **wrong destination port**
or **wrong protocol** against an application-constrained policy (e.g. query
tcp/8080 vs a policy admitting `junos-http` = tcp/80). B2 reports this as
`application` — which is exactly the dimension the operator already SUSPECTS and
the least informative answer. If B2 cannot say "destination-port" for the common
case, its marginal value over `show security policies` collapses. The OR-over-
apps ambiguity is real (I verified `matchApp` 891-920 ORs; `matchSingleApp`
922-1014 checks protocol→icmp→dst-port→src-port per app). The plan's "best-effort
non-authoritative hint" is a band-aid. **This is the strongest argument that B2
should be KILLed, not deferred.** The plan already surfaces it as Q4; I am
upgrading it: coarse-application is close to fatal for B2's stated purpose.

### A2 — the "accuracy fix" for B1 is overstated as a *bug*
The current message is `host-inbound (local delivery; not governed by
transit/global/default policy)`. That statement is *narrowly true*: it asserts
the host path is not governed by the transit/global/default TIERS, which is
correct (#3285). It does NOT claim host-inbound-traffic admits the packet — it
just doesn't MENTION it. So it is INCOMPLETE, not FALSE. The plan's §2/§5 lean
toward calling it an accuracy bug ("can over-state admission"). That is only true
for the no-admitting-token case, where "local delivery" does imply delivery. So
the honest framing is: **completeness gap for the admit case, mild inaccuracy
only for the drop case.** The plan should not use this to smuggle B1 toward
READY as if fixing a security bug. Downgrade the framing.

Corollary: there is a CHEAP middle path the plan buries in Q5 — a one-line
message-completeness edit ("…governed by host-inbound-traffic
system-services/protocols") that ships accuracy WITHOUT the full structured
classifier + parity-web work. If any part of B1 has near-term value, it is this
one-liner, not the token-naming machinery.

### A3 — B1a is scope-creep on a security-sensitive path; B1b is a drift trap
B1a refactors `pkg/daemon` nft string emission to render from a new structured
SSOT. That touches the host-inbound KERNEL enforcement path — golden/parity tests
guard it, but for a Low diagnostic item this is disproportionate risk (R5 in the
plan; agreed). B1b (self-contained classifier + domain-parity test) leaves
per-token PORT correctness unverified — the classifier could say `ssh` admits
tcp/22 while a future edit changes the nft to tcp/2222 and only nft/Rust get the
parity test. So B1 is a genuine fork with no cheap-and-safe option. That
*supports* DEFER over READY: neither B1 sub-option is a clean quick win.

### A4 — DEFER vs KILL: is DEFER a cop-out?
The hostile read: DEFER can be a way to avoid deciding. But here DEFER is
justified because (a) part-A already shipped the driveable half, so the issue is
not left in limbo; (b) B1 has real (if modest) value and a documented design, so
preserving it is cheap; (c) B2 is KILL-leaning but the user explicitly wants the
design captured. My converged position: **PLAN-DEFER for part-B as a feature**,
with the explicit sub-notes that (i) B2 is the weakest slice and KILL is
defensible for it in isolation, and (ii) the ONLY cheap near-term extract is the
A2 message-completeness one-liner. I would REJECT a bare "PLAN-READY, build it
all now" — the ROI does not clear the quad-review bar for a Low item.

### A5 — minor
- §5 B2 proto uses resp field 16 and req field 10 — verify no reserved gaps;
  plan says 15+/10+ free, consistent with the proto I read (resp uses 1-14, req
  uses 1-9). OK.
- The consistency invariant test (R2 mitigation) is the right guard; keep it
  mandatory, not optional.
- `ShowText test-policy:` + remote `cmd/cli` explain deferral is fine (opt-in
  everywhere), but the plan should not later be read as "all surfaces support
  explain" — it will not initially. Noted in §6; acceptable.

## Verdict

**PLAN-DEFER** (`plan-deferred-research`).

Rationale: part-B is a Low-severity, non-parity diagnostic nicety with concrete
operator workarounds (`show security policies` + `show security zones`). B2's
coarse-application granularity is near-fatal for its most common use case and is
KILL-defensible on its own; B1 has real but modest value and no cheap-and-safe
build option (B1a = scope creep on the nft enforcement path, B1b = a port-drift
trap). The design is sound and worth preserving for later pickup, but does not
clear the build+quad-review bar now. If the user wants ANY near-term motion, the
cheapest correct slice is the A2 host-inbound message-completeness one-liner —
NOT the token classifier and NOT B2. I reject PLAN-READY (ROI too low for a Low
item) and stop short of PLAN-KILL for the whole (B1 + the design are worth
keeping alive; only B2 in isolation is KILL-worthy).
