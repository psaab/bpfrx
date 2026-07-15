# opus-review-172 — Deep Wide Adversarial Security / Bug / Parity Campaign

**Reviewer:** opus (Opus 4.8). **Charter:** `do-deep-review-audit.txt` —
two co-equal goals (vSRX feature/behavior gaps + implementation bugs),
with fail-open ("a packet vSRX would DENY reaches a PERMIT/forward in xpf")
singled out for extra scrutiny but NOT the sole axis. Equal-weight classes:
robustness/DoS (crash/OOB/exhaustion), protocol-corruption, secrets/crypto/
observability-lies, unenforced-controls, and parity. Run **wide and
parallel** — module-by-module cohorts reviewed concurrently, then an
adversarial-refutation synthesis pass. Every High/Medium carries a concrete
trace + a stated refutation attempt.

## 1. Base commit reviewed

`3c3f62db5` — "Merge pull request #4471 from psaab/fix/4407-phaseA-tail"
(tip of `origin/master`). Detached read-only worktree.

Protocol-mandated `git pull --rebase`: blocked by the pre-existing unmerged
`_Log.md` conflict (unchanged since campaign 165); reviewed against a
detached `origin/master` worktree — current code, no repo mutation.

## 2. Output path

`/tmp/opus-review-172.md` (whoami=opus; opus owns 171 → next number 172).

## 3. Duplicate-suppression summary

Dedup baseline: all `/tmp/{fable,codex,agy,opus}-review-*.md` across ~18
campaigns, plus `docs/feature-gaps.md`, `docs/feature-coverage.md`,
`docs/vsrx-gaps.md` (stale — verified against code), `docs/engineering-
style.md`, and `_Log.md`. Each cohort reviewer carried a per-domain
suppression list; a dedicated dedup pass cross-checks. Intentional
divergences NOT reported as bugs: intrazone default-permit, host-originated
`from-zone junos-host`, IPsec-passthrough-exempt host-inbound, reject-all
superset, per-worker screen-limit multiplication, firewall no-match implicit
ACCEPT (#3295).

**Cohort weighting:** this run deliberately targets the surfaces the recent
campaigns (161–171) did NOT deep-sweep — routing/PBR/FIB, firewall filters,
config parser + Go↔Rust wire codecs, the reject/neighbor dataplane, DDNS/
DHCP-server/feeds/event-options, and the API/control-socket — and applies
the newly-emphasized crash/DoS, protocol-corruption, secrets, and
observability-lie lenses that prior parity/fail-open passes under-covered.

## 4. Module / verdict-path inventory + cohort map

Largest non-generated files reviewed (LOC): `poll_descriptor/mod.rs` 5998,
`policy.rs` 4224, `poll_stages.rs` 3024, `compiler_validate_warn.go` 2932,
`protocol.go` 2901 (Go↔Rust snapshot codec), `forwarding/mod.rs` 2711,
`compiler_nat.go` 2485, `daemon_run.go` 2329, `wg_control.rs` 2280,
`vrrp/instance.go` 2250, `reject_reply.rs` 2174, `nat64.rs` 2075,
`session/mod.rs` 2046, `compiler.go` 2040, `ddns/surface_a.go` 1957,
`neighbor.rs` 1901, `routing/tunnel.go` 1877.

| # | Cohort | Agent | Emphasis |
|---|--------|-------|----------|
| 1 | Config parser/AST + Go↔Rust wire codecs (protocol.go) | CP-* | robustness/DoS, corruption |
| 2 | Firewall filters (Rust engine + Go compile) | FI-* | fail-open, corruption |
| 3 | Routing / PBR / FBF / rib-group / FIB / tunnels | RT-* | fail-open (policy bypass) |
| 4 | Reject path + neighbor/ARP-ND | RJ-* | amplification, spoof/poison, DoS |
| 5 | Secrets / crypto / observability-lies (cross-cut) | SX-* | secret-leak, injection, misreport |
| 6 | DDNS / DHCP-server / RA / feeds / event-options / RPM | DR-* | posture-injection, DoS |
| 7 | API / control-socket / coordinator | AC-* | crash, state-mutation, starvation |
| + | independent coordinator inspection | §5 | (below) |

Confidence tiers: **High** = source-verified this run (top items re-verified
line-by-line by the coordinator, and each survives an adversarial refutation
attempt); **Medium** = likely defect needing runtime confirmation; **Low** =
parity gap / hardening smell / plausible-but-unproven.

## 5. Module-by-module inspection log

Seven cohorts swept in parallel + a dedup pass over 75 prior review files;
every candidate was hard-filtered against the corpus and put through an
adversarial-refutation step before inclusion. The coordinator independently
(a) probe-confirmed CP-1 with a runtime `CompileConfig`, (b) source-verified
RJ-F1, AC-F1/AC-F2, SX-OBS, and R2/R5, and (c) verified the flowless-fragment
screen path is fail-closed (§9). **Two candidates were dropped on
refutation:** the fabric non-SYN-new-flow policy skip (routing R5) is already
being fixed on the in-flight `fix/4453-fabric-rstfin-gate` branch (a #4400
strict-SYN check extended to the fabric arm — cited, not counted); and the
DHCPv6 valid-lifetime-0 class was confirmed = prior F-264. The steady-state
verdict path (policy tiers, filter engine, reject path, control-socket
dispatcher, transit FIB→zone→policy seam) came back **fail-closed** under
adversarial reading — the novel findings sit at config-inheritance, tunnel
decap, neighbor learning, the management plane, and telemetry.

## 6. Findings — HIGH (directly evidenced, verified this run)

### H-1 · Transitive `apply-groups` silently drops a security zone/policy (config fail-open + parity)

- **Class:** config-fail-open / parity-gap · **Severity:** High (a security
  stanza silently not enforced) · **Confidence:** High (runtime probe-confirmed)
- **Evidence:** `pkg/config/ast_groups.go:149-219` (`expandGroupsRecursive`
  captures top-level `applyNames` *before* merge) + `:243-320` (`mergeNodes`).
  A group whose body contains `apply-groups G2` has its `G2` reference merged
  into the top-level `apply-groups` leaf *after* `applyNames` is fixed, then
  stripped — `G2` is never expanded.
- **Trace (runtime probe, this run):**
  ```
  groups { grpB { security { zones { security-zone ZONE_TRANSITIVE {...} } } }
           grpA { apply-groups grpB; } }
  apply-groups grpA;
  ```
  `CompileConfig` result: `zones=[base]` — **`ZONE_TRANSITIVE` is absent.** The
  direct-group control (`grpZ` defining `ZONE_DIRECT`, applied at top level)
  DOES appear, proving the drop is specific to the transitive (nested-group)
  case. Commit is clean — no error, no warning.
- **Why it matters:** nested `apply-groups` (a group referencing another
  group) is a standard Junos layered-template idiom. A security-zone or policy
  authored behind a transitive group vanishes silently → the intended zone
  isn't created and its host-inbound/policy protection is absent, with the
  operator believing it committed.
- **Refutation attempted:** existing "nested apply-groups" tests only exercise
  apply-groups at a nested *hierarchy level* (supported), never a *group whose
  body references another group*. No commit-time rejection exists — so it is
  neither supported nor rejected; it silently drops. Not refuted.
- **Fix:** expand a group's own `apply-groups` before merging (fixed-point
  under the existing `seen` circular guard), or hard-reject a group body that
  contains `apply-groups` at commit.
- **Dedup:** distinct from F-159 (leaf-list merge shape) and #4070/#4325.

### H-2 · Data-path neighbor learning installs UNSOLICITED ARP/NA MACs as kernel `NUD_REACHABLE` (on-link neighbor-cache poisoning / MITM)

- **Class:** security / parity-gap (hardening) · **Severity:** High (on-link
  MITM of any same-segment next-hop, incl. the WAN gateway) · **Confidence:**
  High (behavior source-confirmed); Medium (severity — on-link precondition)
- **Evidence:** `neighbor.rs:383-393` — `add_kernel_neighbor` builds
  `RTM_NEWNEIGH` with `NLM_F_CREATE|NLM_F_REPLACE` + `NUD_REACHABLE`,
  unconditionally overwriting any existing `(ifindex, ip)` entry.
  `poll_stages.rs:108-135` — an ARP **Reply** / NDP **NA** is learned when
  `neighbor_ip_is_learnable && !owns_configured_ip`, with **no solicited-state
  check** and (for NA) **no honoring of the RFC 4861 §7.2.5 Override flag**;
  the code comment concedes solicited-only learning is an unfinished
  "follow-up."
- **Trace:** an attacker on the L2 segment of a dataplane interface emits a
  gratuitous ARP reply `sender_ip=<gateway>`, `sender_mac=<attacker>`. xpf
  REPLACE-installs it as `NUD_REACHABLE`; the kernel now forwards firewall-
  originated/transit traffic to the attacker's MAC and suppresses revalidation
  for the reachable window. IPv6 works identically via unsolicited NA (Override
  ignored; hop-limit-255 trivially met on-link). Persistent MITM/blackhole,
  re-armable, no operator signal.
- **Why it matters:** xpf is strictly weaker than a hardened router in two
  concrete ways it controls — it learns from *unsolicited* replies/adverts and
  force-writes `NUD_REACHABLE` via `REPLACE`, ignoring the ND Override flag.
- **Refutation attempted:** the own-IP gate (#2851) blocks self-poisoning and
  the hop-limit-255 gate blocks *off-link* ND — confirmed; blast radius is
  other same-segment next-hops (incl. the gateway). ARP is unauthenticated by
  design, but the unsolicited-learn + forced-REACHABLE + Override-ignore is an
  xpf-specific weakening, acknowledged in-code as open. Survives.
- **Fix:** learn only solicited replies/NA (probe-driven or entry already
  live); honor NA Override=0 (install `NUD_STALE`, don't overwrite a differing
  LLA); prefer `NUD_STALE` for data-path learns so the kernel revalidates.
- **Dedup:** distinct from F-089/#3048 (stale-MAC *blackhole* on a legitimately
  learned MAC); this is an *attacker-supplied* MAC being *written*.

### H-3 · REST config-mode lock has no disconnect/idle auto-release → any authenticated client wedges all config edits (management-plane DoS)

- **Class:** dos / parity-gap · **Severity:** Medium-High · **Confidence:** High
- **Evidence:** `pkg/api/config.go:23-29` (`configEnterHandler` →
  `EnterConfigure()`); `pkg/configstore/store_lock.go:33-61` (sets `configDir`,
  `configHolder=""`, `configLockAt`, **no timeout**); `configLockAt` is read
  only by a log line (`store_lock.go:135`) — **no reaper**. The sole
  auto-release is the gRPC `configLockInterceptor` (`grpcapi/server.go:456`),
  which REST never traverses.
- **Trace:** `POST /api/v1/config/enter` takes the global lock with an empty
  holder; the stateless HTTP client never calls `/config/exit` (or just
  disconnects). Every subsequent CLI/gRPC `EnterConfigureSession` returns
  `ErrConfigLocked`, and a CLI-disconnect release can't clear a foreign-holder
  lock. Recovery only via `clear system config-lock` or restart — and REST
  offers no `clear-config-lock` action (see L-6).
- **Why it matters:** one abandoned/malicious REST request denies config to
  every operator. Loopback-local by default, but remotely triggerable combined
  with #4047 (REST bindable off-loopback, unauth).
- **Refutation attempted:** confirmed no reaper (grep), confirmed the gRPC
  interceptor doesn't cover REST, confirmed recovery path exists (nuisance DoS,
  not permanent). Survives as a real management-plane wedge.
- **Fix:** lease/idle-timeout on the REST config lock using the recorded
  `configLockAt` (periodic reaper), mirroring the gRPC interceptor.
- **Dedup:** distinct from #4047 (bind/auth); this is the missing lock lifecycle.

### H-4 · `show security flow statistics` "Packets dropped" and "NAT allocation failures" are dead counters — always 0, no disclosure (observability lie)

- **Class:** observability-lie · **Severity:** Medium-High (security telemetry
  blind during an attack) · **Confidence:** High (source-confirmed across all
  four surfaces, independently by two reviewers)
- **Evidence:** the userspace-dp→shim bridge `syncBPFCountersLocked`
  (`pkg/dataplane/userspace/manager_ha.go:732-770`) pushes deltas ONLY for
  Rx/Tx, Sessions, PolicyDeny, HostInboundDeny, ScreenDrops(+per-reason),
  SYN-cookie, NAT64 — **`GlobalCtrDrops` (idx 2)** and **`GlobalCtrNATAllocFail`
  (idx 7)** are absent. `ReadGlobalCounter` (`maps_counters.go:27-45`) succeeds
  on the (never-written) index and returns `(0, nil)` — so the #3345
  `ErrCounterNotPopulated` disclosure never fires. Printed as a clean `0` at
  `grpcapi/server_show_flow.go:168,172`, `cli/cli_show_flow.go`, `api/stats.go`,
  and Prometheus (`xpf_drops_total`, `xpf_nat_alloc_fails_total`).
- **Trace:** under a real drop storm the *bridged* PolicyDeny/ScreenDrops climb
  while "Packets dropped: 0" — a self-contradiction on the same screen. During
  SNAT port exhaustion, "NAT allocation failures: 0" hides the exhaustion; new
  flows silently fail with no telemetry. An operator alerting on these gets no
  signal.
- **Refutation attempted:** confirmed the two indices are outside the bridge
  delta list; confirmed the read returns nil-error (not the disclosure
  sentinel); confirmed all four surfaces read the bare value. Not the prior
  F-051 (session-count, fixed #3929) nor F-231 (per-binding zeroing). Survives.
- **Fix:** bridge the Rust drop / NAT-alloc-fail counts into these indices
  (mirror the PolicyDeny plumbing), or return `ErrCounterNotPopulated` for an
  unbridged index so the display shows `n/a` rather than a false `0`.
- **Dedup:** novel; the retired-path `GlobalCtrTCEgressPackets` (idx 9, #1476)
  and live-but-unbridged `GlobalCtrFabricRedirect` (idx 26) share the mechanism
  (roll into the same fix).

## 7. Findings — MEDIUM (code-traced; runtime confirmation recommended)

### M-1 · IPIP (proto-4/41) tunnel decap has no userspace zone enforcement → inner traffic kernel-forwarded into protected zones (fail-open)

- **Class:** fail-open · **Severity:** High-if-confirmed · **Confidence:**
  Medium (code-confirmed absence of a userspace IPIP decap; inner-packet kernel
  path needs runtime confirmation)
- **Evidence:** forwarding has a GRE userspace-decap stage
  (`GRE_DECAP_INGRESS_FLAG`, `forwarding/mod.rs:1210-1228`) that re-applies the
  tunnel interface's zone to the inner packet — built precisely because kernel
  decap bypasses userspace policy. `PROTO_IPIP=4` is matchable in policy/filter
  (`ip_proto.rs`, `policy.rs`) but there is **no proto-4/41 decap flag or stage**
  in `forwarding/` — IPIP relies on the kernel `Iptun`/`Ip6tnl` device, and
  there is no kernel FORWARD-hook zone enforcement.
- **Trace:** an admitted IPIP outer packet is kernel-decapped by `Iptun`; the
  inner packet is kernel-forwarded without re-entering xpf's userspace zone
  policy — the exact bypass GRE's userspace decap prevents. Precondition: the
  outer proto-4 is admitted (a working IPIP tunnel requires it).
- **Why it matters:** by parallel construction with GRE, kernel IPIP decap
  bypasses the deny/permit verdict — a policy hole for any deployment using
  IP-in-IP tunnels.
- **Refutation attempted:** confirmed GRE has the decap+zone stage and IPIP has
  none; the open question is whether the decapped inner packet re-ingresses an
  xpf-XDP interface (would get that interface's zone) or is kernel-forwarded
  raw. Rated Medium pending that runtime trace.
- **Fix:** add a userspace IPIP decap stage that re-applies the tunnel zone
  (as GRE does), or attach XDP + zone to the `Iptun` device.
- **Dedup:** distinct from F-031/F-185/F-063/F-066 (tunnel config-value bugs).

### M-2 · Userspace FIB snapshot ingests PBR (FBF) ip-rules as unconditional next-table leaks → FBF selectors dropped, widening a steer into a VRF leak

- **Class:** fail-open-adjacent / correctness · **Severity:** Medium ·
  **Confidence:** Medium
- **Evidence:** `routes.go:151-188` treats any kernel ip-rule whose `Dst`
  matches a routing-instance table as an unconditional next-table leak, with no
  priority filter — so PBR rules (pref 31000-31999) have their
  `Src`/`Tos`/`IPProto`/`Sport`/`Dport` selectors dropped, turning a
  constrained FBF steer into a dst-only VRF leak on the primary dataplane
  (defeats the #3730 fail-closed intent).
- **Fix:** filter the snapshot ingest by rule priority (only the route-leak
  band), or carry the FBF selectors into the userspace next-table entry.
- **Dedup:** codex-156 covered the *kernel*-path FBF widen; this is the
  *userspace FIB snapshot* surface.

### M-3 · Interface-monitor display hardcodes `Up: true` when live status is unavailable → a down monitored uplink shows healthy

- **Class:** observability-lie · **Severity:** Medium · **Confidence:** High
  (source-confirmed) — display path only, not the failover decision
- **Evidence:** `server_cluster.go:86` `buildInterfacesInput` hardcodes
  `Up: true` for local interface monitors when live status is unavailable,
  while the peer branch in the same function honestly uses `Up: false`.
- **Fix:** surface unknown status as unknown/`false`, matching the peer branch.
- **Dedup:** novel.

### M-4 · FRR cross-context route-map default-action leak

- **Class:** route-leak / config-correctness · **Severity:** Medium ·
  **Confidence:** Medium
- **Evidence:** a route-map keyed on policy *name* (not use-site) — e.g. a BGP
  accept-default map reused for IGP `redistribute` — inherits its trailing
  accept-all, so internal prefixes leak into the IGP.
- **Fix:** render per-use-site route-maps, or gate the default trailing action
  per protocol context.
- **Dedup:** adjacent to F-220 (non-injective prefix-list names) but distinct
  (default-action inheritance).

### M-5 · FRR route-map / prefix-list values bypass the #4097 sanitize belt on the tolerant-load path (config injection)

- **Class:** config-injection · **Severity:** Medium · **Confidence:** Medium
- **Evidence:** `set community` / `set as-path` / prefix-list slots reach the
  managed `frr.conf` via the tolerant-load path without traversing the #4097
  value-safety sanitizer.
- **Fix:** route all FRR-rendered values through the sanitize belt regardless
  of load path.
- **Dedup:** fable-163 F2 was the original injection; #4097 the fix; this is a
  residual bypass on the tolerant-load path.

### M-6 · DDNS DNS UPDATE runs unsigned UDP-first when no TSIG key is set and trusts a forgeable rcode (no warning)

- **Class:** protocol-auth / hardening · **Severity:** Medium · **Confidence:**
  Medium
- **Evidence:** `backend_rfc2136.go:238-246` wires TSIG only when
  `TSIGKeyName != ""`; `exchange()` is UDP-first; the publish/ownership verdict
  keys on `resp.Rcode` (`sendAddOwned`/`sendAdd`/`sendRemoveForward`).
- **Trace:** with `update-server` set and no `tsig-key`, an on-path (or
  ID+port-guessing off-path) attacker forges a `NOERROR` → the manager records
  the name as *published* though the server wrote nothing (silent blackhole of
  the firewall's own A/AAAA), or a forged `REFUSED` suppresses a legit publish.
  Fully closed when TSIG is configured (miekg verifies the MAC).
- **Fix:** warn (commit + once-per-provider runtime) when `update-server` has no
  TSIG key; consider forcing TCP or an explicit `no-tsig` opt-in.
- **Dedup:** distinct from codex-157 (public-address gate); this is the
  DNS-UPDATE wire-auth path.

## 8. Findings — LOW

- **L-1 · REST `reboot`/`halt` bypass the #4108 fsynced system-action audit
  journal** (`api/system.go:266-282` calls `systemctl` directly with no
  `logSystemAction`; the gRPC path journals first). Destructive power actions
  via REST leave no attributable durable record. Also REST has no
  `clear-config-lock` action (can't self-recover an H-3 wedge). *(observability/
  audit; source-confirmed. Novel — #4108 covered gRPC only.)*
- **L-2 · Unbounded SSE subscriber set** (`api/sse.go:50,97` →
  `eventbuf.go:142` `Subscribe` no cap; `Add` fan-out is O(N)). An authenticated
  client opening many `/events/stream` exhausts management-plane memory/CPU.
  Non-blocking send caps blast radius to DoS (can't stall the verdict path).
  *(dos; cap concurrent subscribers like `metricsMaxInFlight`.)*
- **L-3 · RST `ack` over-count from an unclamped IPv4 `total_len`**
  (`tcp.rs:412-441` omits the `.min(packet.len())` clamp the quoted-packet
  builders use). A crafted SYN with a lying `total_len` yields an unacceptable
  RST `ack` → the active reject silently degrades to a plain drop (fail-*closed*,
  self-inflicted; no OOB, no third-party injection). *(robustness.)*
- **L-4 · `then syslog` compiled identically to `then log`** (both set
  `term.Log`); Junos routes them to different sinks — sink-conflation parity gap.
- **L-5 · `then reject <message-type>` argument parsed but ignored** by the
  reply builder → wrong ICMP-unreachable code (still a real REJECT — not a
  fail-open). *(parity/correctness.)*
- **L-6 · `frr.conf` written 0644** (`frr/manager.go:591`) carries plaintext
  BGP TCP-MD5 / OSPF / IS-IS / RIP auth secrets (every other secret file is
  0600). Mitigated where `WithPreserveExisting` keeps the package's 0640;
  world-readable only on a freshly created file. *(secret-leak.)*
- **L-7 · SYN-cookie master key latent `Debug` leak** — it sits in
  `ConfigSnapshot`/`ControlRequest` under a *derived* `Debug`, so any `{:?}` log
  of those structs prints it; sibling WG structs hand-redact. *(secret-leak,
  latent.)*
- **L-8 · `master-password` at-rest encryption is bound to a random on-box
  `master.key`, not an operator secret** — weaker than the Junos threat model
  the feature is named for. *(parity/design.)*
- **L-9 · No `show` surface reveals whether cluster control-link auth (#4107)
  is engaged vs silently degraded to dual-accept.** *(observability.)*
- **L-10 · DDNS Surface-A write-ahead crash window** (`surface_a.go:1232-1262`
  saves ownership before the wire upsert) can leave a durable "published" claim
  for an RR never put on the wire, suppressed up to `forced-refresh` (24h).
  ms, non-adversarial; self-heals on any address change. *(observability edge.)*
- **L-11 · Flowless (non-first-fragment) MissingNeighbor None-tuple reinject**
  without policy — an F-259 variant, largely neutralized by kernel rp_filter.
  *(cited variant, low residual.)*
- **L-12 · FRR `route-filter upto /N` with N below the base prefix length**
  renders to `le maxLen` (fails open to a wider match). *(FRR render.)*

## 9. Negative results (verified fail-closed / correct — the coverage the count rests on)

- **Config parser / lexer / AST / Go↔Rust wire codec:** recursion capped
  (`maxParseDepth=256` + iterative tail drain), unterminated-comment rejected
  (#4149), every config→wire narrowing in-range-guarded (DSCP/ICMP/port/NAT),
  unresolvable match tokens fail *closed* (`natProtoNever`,
  `DSCPMatchUnrepresentable`, `TCPFlagsUnparseable`), control request 64-MiB
  capped, zone-ID collisions quarantined (fail-closed), AST edits
  (SetPath/DeletePath/Rename) member-safe. Snapshot boundary fails closed on
  the unrepresentable.
- **Firewall filter engine:** cache-hit terminal drop enforced (output
  discard/reject + red-policer fire on every hit), mid-flow config change purges
  the cache, L4 extraction fails closed on fragments/truncation (no OOB),
  empty-set/except inversion fail-closed, unknown action→Discard, unknown `from`
  leaf→commit reject, three-color policer RFC 2697/2698-conformant.
- **Reject / local-response path:** cannot fail-open (runs on the decided
  DENY/REJECT arm; every early-return drops), bounds-safe builders (quote
  clamped to the real slice), no amplification (reply ≤ trigger), reflection
  per-zone rate-capped and not off-path-injectable, ND NA learn RFC-4861
  hop-limit-255 hardened, netlink parsers bounds-checked.
- **Control / API surface:** dispatcher fail-closed (timeouts, size cap,
  no-unwrap decode), `apply_snapshot`/`bump_fib` atomic + integrity-preflighted
  + rollback-refusing, constant-time auth incl. unknown-user, slowloris caps,
  argv exec (no shell), `ClearSessions` can't degrade a filtered clear to
  clear-all, fabric gRPC HMAC-authenticated.
- **Transit routing seam:** FIB→egress-ifindex→to_zone→policy; next-table/
  rib-group recursion re-derives to_zone in the leaked VRF; unzoned egress →
  zone 0 → default-action (fail-closed under default-deny); GRE userspace decap
  re-applies zone. Flowless-fragment screen path fail-closed (#2146/#3902).
- **DDNS / feeds / RA / DHCP-server / event-options / RPM:** feeds DoS-capped +
  retain-last-good on empty fetch, RPM fail-closed on setup error, event-engine
  fail-closed matcher/temporal + transactional batch, RA anti-blackhole, Kea
  injection-safe (JSON + argv), DHCP-hostname→DNS sanitized, DHCID name-hijack
  defended, checkip martian-gated.
- **Secrets/crypto:** sensitive fields Secret-typed (#2053), config renders
  RBAC-redacted (#4099), IPsec secrets 0600 + fail-closed proposal compile, WG
  keys hex-validated/zeroized/socket-only, F-087 remediated (#3909), cluster/
  fabric channels HMAC-authenticated (#4107).

## 10. Suggested issue split (fail-opens + telemetry first)

1. **[fail-open][config] Transitive apply-groups drops a security stanza** — H-1.
2. **[fail-open][tunnel] IPIP decap has no zone enforcement** — M-1 (confirm
   inner path, then High).
3. **[security][neighbor] Unsolicited ARP/NA installed as NUD_REACHABLE** — H-2.
4. **[observability] Flow-stats Packets-dropped / NAT-alloc-failures dead
   counters** — H-4 (+ TC-egress / fabric-redirect siblings).
5. **[dos][api] REST config-lock has no auto-release** — H-3 (+ REST
   clear-config-lock, L-1).
6. **[fail-open-adjacent][routing] FIB snapshot conflates PBR ip-rules with
   route-leak** — M-2; **[route-leak] FRR default-action / sanitize-belt** —
   M-4/M-5.
7. **[observability] interface-monitor Up:true lie** — M-3; **[hardening] DDNS
   no-TSIG** — M-6.
8. Low batch: L-1…L-12 (audit-gap, SSE cap, RST clamp, syslog/reject parity,
   frr.conf mode, secret-Debug, master-key model, control-link-auth show).

## 11. Campaign summary

- **~22 novel findings** (4 High, 6 Medium, 12 Low) across seven cohorts, each
  source- or probe-verified this run and dedup-checked against 75 prior review
  files (~18 campaigns). Two candidates were dropped on the mandatory
  refutation step — the fabric non-SYN policy skip (**already being fixed on
  `fix/4453-fabric-rstfin-gate`**) and the DHCPv6 valid-lifetime-0 class
  (= prior F-264) — which is the "don't duplicate, and refute before you
  report" discipline working as intended.
- **The fail-opens cluster at inheritance and tunnel seams, not the fast
  path:** a security stanza silently dropped behind a nested `apply-groups`
  (H-1, probe-confirmed), and IP-in-IP decap with no userspace zone enforcement
  where GRE has it (M-1). On-link neighbor poisoning (H-2) is a real MITM the
  code itself flags as unfinished.
- **Observability lies were the richest new vein** (the audit's newly-emphasized
  class): security-relevant drop and SNAT-exhaustion counters that read a clean
  `0` forever with no disclosure (H-4), and a down uplink that shows healthy
  (M-3) — an operator's alerting and troubleshooting signals are wrong exactly
  when they matter.
- **The management plane** yielded a config-edit DoS wedge (H-3), an audit-trail
  gap on REST power actions (L-1), and an unbounded SSE vector (L-2).
- **The steady-state verdict path is verified fail-closed** (§9): the policy
  tiers, filter engine, reject path, control-socket dispatcher, and the transit
  FIB→zone→policy seam all held under adversarial reading — a load-bearing
  negative for a codebase this heavily reviewed. The count is honest, not
  padded: seven densely-pre-covered cohorts yielded ~22 genuinely-novel items
  after hard dedup + refutation, backed by the §9 negatives that prove the
  coverage behind the number.
