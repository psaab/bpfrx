# Triage result — ps-review-038 / A7_go_daemon_host — batch 2/2

## Header
- **Review**: paladin-038 / A7_go_daemon_host b2 (Codex audit, 138 files: frr/ipsec/routing/upgrade/networkd/lldp/fsatomic/devicemap/fwdstatus/wgkey…).
- **Review base**: `d4506d445` (Merge PR #4571, 2026-07-07 17:47). **STALE by 23 commits / ~1h45m** vs current master.
- **Triaged against**: `origin/master` = `30eb568ad` (Merge PR #4593 "#4588-vtysh-ip-guard", 2026-07-07 19:32) — fetched fresh.
- **Real bpfrx code?** YES. Every cited symbol exists in bpfrx (vtysh.go, lldp.go, networkd.go, tunnel.go, cluster_cli.go all present at cited lines). No avacado-fork confabulation.
- **Codex weighting**: file is well-scoped and accurate on *code location*; but of 5 findings, 4 have their headline scenario neutralized by an upstream guard the review either missed or acknowledged-and-pivoted-around. This is the A2 pattern (claimed severity refuted by an upstream gate) and the #4572 pattern (headline already neutralized) the prompt warned about.
- **Outcome counts**: GENUINE-RESIDUAL 1 (Low) · ALREADY-FIXED 1 · NOT-MATERIAL 3 (of which 1 also DELIBERATE-documented). No High/Critical. No CONFABULATED.

The local checkout has uncommitted edits to `pkg/lldp/lldp.go` + `socket_test.go` (git status) — IGNORED; all verification is `git show origin/master:<path>`.

---

## Per-finding dispositions

### FINDING-1 — vtysh injection via unsanitized BGP neighbor IP (Medium) → **ALREADY-FIXED (#4588 / PR #4593)** + DUP of prompt's `#4588 vtysh guard` dedup entry
**Why:** Master HEAD is literally PR #4593 "frr: validate BGP-neighbor SHOW IP before it reaches vtysh (#4588)" (commit `4d71c1050`). Current `origin/master:pkg/frr/vtysh.go` now guards all three helpers the finding names:
- `GetBGPNeighborReceivedRoutes` (l.202-204): `if net.ParseIP(ip) == nil { return "", fmt.Errorf("invalid neighbor IP %q", ip) }`
- `GetBGPNeighborAdvertisedRoutes` (l.214-216): same `net.ParseIP` reject.
- `GetBGPNeighborDetail` (l.227-231): `net.ParseIP` reject, empty-string allowed (unchanged "no neighbor filter" semantics).

`net.ParseIP` rejects any string containing `\n`, `\r`, `;`, or spaces, so no raw token reaches the `vtysh -c` command line — exactly the fix the finding prescribes. The in-code comments cite #4588 and the same rationale (unauthenticated local gRPC show path, no config-style sanitizer). The review's base `d4506d445` (#4571) predates this merge by ~1h45m — a classic stale-base already-fixed. **The finding is real and was correct; it is closed on current master.** No new issue.

### FINDING-2 — LLDP TTL `int→uint16` truncation (Low) → **GENUINE-RESIDUAL (novel, Low, lane: go)**
**Why genuine + reachable:** On current master the truncation is unguarded on BOTH ends:
- `pkg/lldp/lldp.go:398` — `ttl := int(interval.Seconds()) * holdMult` (unbounded int product).
- `pkg/lldp/lldp.go:725-728` — `encodeTTL(seconds int)` does `binary.BigEndian.PutUint16(val, uint16(seconds))` with **no clamp**.
- `pkg/config/schema_routing.go:585-586` — the `transmit-interval` and `hold-multiplier` schema leaves have **NO `validator:` and no `valueType`** (`{desc:…, args:1, placeholder:…, children:nil}`). `compiler_protocols.go:33-44` compiles them with a bare `strconv.Atoi` and stores the raw int. So an operator `set protocols lldp transmit-interval 16384` (with the default hold-multiplier 4) **commits cleanly** → `ttl = 16384*4 = 65536` → `uint16(65536) = 0` → LLDP TTL 0 on the wire → peers **immediately expire** the neighbor. A larger interval (e.g. 30000) wraps to 54464s instead of 120000s. This is a real unbounded-input truncation with no commit-time cap and no wire-encode clamp.
**Severity — Low (agree with review):**
- *Trigger*: requires a local operator to author an absurd `transmit-interval` (>16383s ≈ 4.5h, vs the 30s default) — a fat-finger misconfig, not a remote/on-path attack, and not attacker-reachable (config-mode only).
- *Blast radius*: management-plane observability only — LLDP neighbor discovery used by monitoring/automation degrades or drops. No effect on the forwarding path, security policy, or session state.
- *Bounding*: LLDP is advisory; a wrong/zero TTL causes premature neighbor aging, self-corrected on the next TX. No fail-open of traffic.
- *Why not higher*: nothing security- or dataplane-critical touches LLDP TTL. *Why not dismissed*: it is a silently-wrong on-wire value with zero validation, distinct from the two existing (CLOSED) LLDP issues (#4044 unbounded neighbor table; #2551 truncated-TLV parse) — neither covers TTL encode truncation.
**Fix (file:line):** clamp in `encodeTTL` (`if seconds < 0 || seconds > 0xffff { seconds = 0xffff }` before the cast) AND/OR add `validator: ValidateInteger(1, …)` to the `transmit-interval`/`hold-multiplier` leaves at `schema_routing.go:585-586` (Junos caps transmit-interval at 32768 / hold-multiplier 2..10; a bound of interval×mult ≤ 65535 is the belt). **Lane: go.** Novel — file as a new issue.

### FINDING-3 — networkd `junosSpeedToNetworkd` passes unknown speed verbatim (Low) → **NOT-MATERIAL**
**Disproving mechanism:** the injection vector (control char / newline in `Speed` reaching `BitsPerSecond=<payload>` in the `.link` file) is blocked before `ifc.Speed` is ever set. `pkg/config/compiler_prewalk.go:33-42` (`runPreWalkGates`) runs the #1798 free-text control-char gate over the **entire group-expanded AST, over every node Key, BEFORE section compilation**:
- Strict path (commit / commit-check): `validateNodesControlChars` (`freetext.go:163`) **hard-rejects** any value with a control char.
- Lenient path (load / peer-sync / peer-display): `sanitizeNodesControlChars` **scrubs** control chars in place, then compiles from the scrubbed tree.

So `ifc.Speed` is guaranteed control-char-free on both the commit and the load/peer-sync paths — the review's own trace concedes the normal whitespace-tokenized `set` path cannot carry a newline, and the "hierarchical parse / peer-sync / DB-write" residual it pivots to is precisely what the lenient scrub covers. The residual after that is only: an *unknown-but-clean* speed string (e.g. `foobar`) written verbatim as `BitsPerSecond=foobar`, which systemd-networkd simply ignores/rejects as an invalid value — a benign operator-error cosmetic, well below Low, with no injection and no DoS (bad `BitsPerSecond` does not break interface naming). Not a security or correctness residual. Confidence "Medium" in the review is itself a tell it is defense-in-depth-only.

### FINDING-4 — tunnel TTL `int→uint8` truncation in `applyKernelTunnelLocked` (Medium) → **NOT-MATERIAL / DELIBERATE-documented**
**Disproving mechanism:** the headline (`set interfaces gr-0/0/0 tunnel ttl 300`) is **rejected at commit** — the `ttl` leaf at `pkg/config/schema_interfaces.go:394-402` carries `validator: ValidateInteger(0, 255)` (valueDesc: "Tunnel TTL (0..255; 0 = use the default 64, one wire byte)"). `SchemaValidate` runs strict on commit/commit-check, so 300 never reaches the `uint8(ttl)` cast at `tunnel.go:767` on the normal path.
**Deliberate/documented:** the truncation is an explicitly-recorded known item — `schema_interfaces.go:351-356` documents "*ttl: stored verbatim by the compiler, then truncated to the netlink uint8 Ttl field (tunnel.go:218/:226/:235) — 256 would silently wrap to 0 … (AGY r1 Low on PR #1886)*". It was already reviewed (AGY, PR #1886), rated Low, and dispositioned with the range validator as the guard — not a cast clamp.
**Residual the review pivots to:** a *legacy* config persisted before the validator existed (or a hand-edited on-disk DB) loaded on a new daemon would warn-not-reject (#1960 no-brick) and carry ttl 300 to the cast → wraps to 44. This is extremely narrow (not remotely triggerable; requires a pre-#1886 persisted value or DB tampering) and the blast radius is a *wrong tunnel TTL* (transit hop-count / PMTUD semantics) — a correctness/observability effect, not a bypass or crash.
**Why downgraded from the review's Medium:** the review missed the commit-time `ValidateInteger(0, 255)` and the #1886 documentation; the only path it can point to is the guarded lenient/legacy one, whose impact is a cosmetic TTL value, not fail-open forwarding. This is the documented, already-dispositioned AGY-#1886 Low, guarded at commit — no new issue. (A defense-in-depth `min(ttl,255)` clamp at the cast is an optional sub-Low hardening the project already considered and declined in favor of the validator.)

### FINDING-5 — manual atoi overflow in `cluster_cli.go` (Low) → **NOT-MATERIAL**
**Disproving mechanism:** the three parsers (`trailingInt` l.278, `atoiSafe` l.456, `parseNodeToken` l.485) only ever see **locally-rendered FormatStatus text** whose numeric fields all originate from bounded ints. `HAProtocolCompatible` → `statusText()` → a *loopback* gRPC `ShowText(chassis-cluster-status)` (l.145-168) returning the local daemon's own `FormatStatus` render. The HA protocol version is a `uint16` (`pkg/cluster/heartbeat.go:29` `LegacyHAProtocolVersion uint16 = 1`) rendered with `%d` (max 5 digits); RG IDs (0-15), node IDs (0-1), and failover counts are likewise small ints. There is **no path that supplies a 20-digit string** to any of these loops — even a fully-compromised peer can only advertise a `uint16` on the wire, which the local daemon renders as ≤5 digits before re-parsing. `n = n*10 + digit` therefore never approaches `MaxInt`. The review itself concedes "practical exploitability is negligible … the overflow is theoretical." It is a legitimate code-smell (prefer `strconv.Atoi`) but an unreachable one — a robustness nit below Low, not a genuine residual. No new issue (tracked here as the disposition of record).

---

## Method note
- Base `d4506d445` is only ~1h45m / 23 commits stale, but that window contained PR #4593 — so FINDING-1 flips stale→already-fixed. This underscores the SKILL rule: verify vs CURRENT master (grep the fix symbol `net.ParseIP` in vtysh.go), never the review's "the finding survives".
- 4 of 5 findings are neutralized by an upstream guard the review missed or side-stepped: commit-time schema validators (`ValidateInteger(0,255)` tunnel ttl), the #1798 control-char prewalk (networkd speed), a merged PR (#4593 vtysh), and bounded-int provenance (`uint16` HA version). Only the LLDP TTL path has genuinely NO validator + NO clamp — the one novel residual.
- Codex accuracy: file locations and code quotes were all correct; the miss was severity/materiality reconciliation against upstream gates (over-scoped FINDING-4 Medium; the acknowledged-but-live-pivot on FINDING-3/5). No confabulation.

## Summary counts
- GENUINE-RESIDUAL (novel): **1** — FINDING-2 LLDP TTL uint16 truncation (Low, lane go).
- ALREADY-FIXED: **1** — FINDING-1 (#4588 / PR #4593).
- NOT-MATERIAL: **3** — FINDING-3 (networkd speed; #1798 belt), FINDING-4 (tunnel ttl; ValidateInteger(0,255) + DELIBERATE-documented AGY #1886), FINDING-5 (cluster_cli atoi; bounded-int provenance).
- CONFABULATED / DUP-only / DELIBERATE-standalone: 0 (FINDING-4 carries the DELIBERATE note within NOT-MATERIAL).
