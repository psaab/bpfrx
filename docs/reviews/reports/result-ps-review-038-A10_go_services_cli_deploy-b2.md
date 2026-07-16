# Triage result — ps-review-038-A10_go_services_cli_deploy-b2

- **Subsystem**: A10_go_services_cli_deploy, batch 2/3 (150 files: pkg/ddns, pkg/dhcp,
  pkg/dhcprelay, pkg/dhcpserver, pkg/natshow, pkg/policymatch, pkg/cli tests,
  scripts/deploy, scripts/dist, scripts/image, test/incus harness).
- **Base == master?** Base `d4506d4450e23f9a3fc572206b3c82f6b6c99029` IS an ancestor of
  current `origin/master` `57d24d9aed4b64680831a1765a128921e79c00f7` (verified
  `git merge-base --is-ancestor`). Base <= master; findings triaged against master.
- **Real bpfrx or avacado?** Review cites `/home/ps/git/avacado-xpf/...` paths (reviewer
  working copy), but every cited symbol EXISTS verbatim in bpfrx on origin/master. Real code.
- **Master SHA**: 57d24d9aed4b64680831a1765a128921e79c00f7
- **Outcome counts**: 1 GENUINE-RESIDUAL (LOW), 1 REFUTED/NOT-MATERIAL (F-02),
  1 NOT-MATERIAL/DELIBERATE (F-03), remainder NEGATIVE (reviewer's own clean modules — not findings).

This is a low-yield batch: the reviewer surfaced only 3 Low findings out of 150 files and
marked everything else negative. Weight-verify confirms the batch is well-hardened; one
genuine (LOW) validation gap survives.

---

## F-01 — GENUINE-RESIDUAL (LOW, lane=go)

**Claim**: `validateGenericURLTemplate` (pkg/ddns/backend_generic.go:109) accepts
`http://:8080/update?...` because it only rejects `authority == ""`, but `:8080` is a
non-empty authority with an EMPTY host. Config commits clean; failure surfaces only at
first publish (perpetual transient DDNS failure with backoff), not at commit.

**Verification**:
- Symbol present on master. `backend_generic.go:134` is exactly
  `if authority == "" { return ... "has no host" }`. For `http://:8080/upd`, the loop sets
  `authEnd` at the first `/`, so `authority = ":8080"` (userinfo strip is a no-op, no `@`),
  and `":8080" != ""` → returns nil. Empty-host slips through. Confirmed.
- **Both** validation paths share the bug. There is a commit-time mirror
  `ddnsGenericURLTemplateValid` (pkg/config/compiler_validate_warn.go:2272) built by #2841 to
  fail typos closed at commit. Its body ends `return authority != ""` — byte-for-byte the same
  gap. So `http://:8080/...` passes the commit warning AND the runtime constructor. The #2841
  test (`compiler_p3_http_providers_test.go:363`) only pins the *empty-authority* case
  (`https:///upd`), not the `:port`-only case — so this is a residual gap in #2841's own fix,
  exactly as the reviewer's dedup note states.
- Contrast is real: `backend_dyndns2.go` rejects via `u.Hostname() == ""` (net/url parses
  `:8080` to Host `:8080`, Hostname `""`). The generic path is deliberately string-based (to
  tolerate `%h/%i/%u/%p` inadyn specifiers), so it can't reuse net/url — but it can still split
  the authority on the last `:` and require a non-empty host segment.

**Dedup**: Not in the #4517-#4581 merged range nor the open set (#2387/#4455/#4478/#4498/#4549/
#4555/#4559/#4565/#4566/#4569/#4573/#4576/#4577/#4578/#4579) — none touch ddns generic
url-template host validation. #2841 is the prior fix this is a residual of (merged). Novel.

**Severity reasoning — LOW (agree with reviewer)**:
- Exploitability: operator config typo only; no attacker input (url-template is operator-authored
  trusted config). Not a security bug.
- Blast radius: a single mis-configured DDNS provider that never publishes; the daemon retries
  with backoff forever. A minor secondary edge — Go's dialer treats an empty-host URL
  (`http://:8080`) as localhost, so a credential-bearing template could POST to `localhost:8080`
  — but on a firewall nothing listens there, so it's connection-refused, and this is still LOW.
- Bounds: fail-late instead of fail-fast; self-evident once the operator reads DDNS logs. No
  data-plane / forwarding / HA impact.
- Why-not-INFO: it defeats the STATED purpose of the #2841 commit-time validator (catch
  url-template typos AT COMMIT). A whole class of host typo (`:port`-only) evades the guard the
  fix was built to provide — a genuine functional gap, so LOW rather than pure cosmetic INFO.
- Why-not-higher: no security/data-integrity/availability blast radius beyond the one provider.

**Fix**: In BOTH `validateGenericURLTemplate` (backend_generic.go) and its lockstep mirror
`ddnsGenericURLTemplateValid` (compiler_validate_warn.go), after stripping userinfo, extract the
host segment from the authority (split off `:port` — handle bracketed IPv6 `[...]`) and require it
non-empty. Keep the two in lockstep (the #2841 fold invariant) and add a red-going test for
`http://:8080/upd` to `compiler_p3_http_providers_test.go`. Lane=go (non-cargo).

---

## F-02 — REFUTED / NOT-MATERIAL

**Claim (Low, confidence High)**: `buildL2Reply` (pkg/dhcprelay/l2send_linux.go:164) writes
`uint16(totalLen)`/`uint16(udpLen)`; on a DHCP reply payload up to 65535 (readBufSize), totalLen
= 65563 wraps to a bogus 16-bit IPv4 total-length; on jumbo/MTU-0 interfaces the MTU guard
doesn't fire, so the client silently gets a malformed frame counted as delivered.

**Refutation — the crafted input (65535-byte payload) is physically unreachable**:
- The reply payload originates from a UDP datagram: `serverConn` is
  `ListenPacket(ctx, "udp4", ...)` (relay.go:423) and the reply is read via
  `serverConn.ReadFrom(buf)` (relay.go:1265), then `replyData := pkt.ToBytes()` (relay.go:1336).
- A single IPv4/UDP datagram payload is capped at **65507 bytes** (65535 IPv4 total − 20 IPv4
  header − 8 UDP header). `conn.ReadFrom` returns at most one datagram, so `n <= 65507` — the
  65535-byte read the finding posits cannot happen (readBufSize 65535 is the buffer, not the
  achievable datagram payload; the code's own comment at relay.go:51 notes ReadFrom copies only
  the first len(buf) bytes of a datagram).
- Re-encapsulation worst case: `len(payload) <= 65507` → `udpLen = 8+65507 = 65515`,
  `totalLen = 20+65515 = 65535` → `uint16(65535) = 65535` **exactly the max, no wrap**. The
  finding's arithmetic (payload 65535 → totalLen 65563 → wrap to 28) is built on the impossible
  65535 payload.
- The only theoretical over-boundary path is `pkt.ToBytes()` appending a 1-byte End(0xff)
  option to a maximally-sized (~65507-byte) parsed reply, nudging totalLen to 65536. That
  requires: (a) a trusted, operator-configured DHCP server emitting a physically-maximal 65507-
  byte reply (real DHCP replies are hundreds of bytes, capped by the client's Max-Message-Size
  option 57); AND (b) an interface MTU >= 65535 or MTU==0 so the `l3Size > iface.MTU` guard
  (l2send_linux.go:138) doesn't fire first; AND (c) even then the effect is a dropped frame that
  ordinary DHCP retransmit recovers. Not a reachable exploit.

**Disposition**: NOT-MATERIAL. A defensive `if totalLen > 65535 { fall back to broadcast }` belt
is harmless and matches the finding's own fix direction, but there is no crafted input that
reaches truncation on this codebase — the UDP source bounds payload to 65507, putting worst-case
totalLen at the uint16 ceiling, not over it. Confidence "High" in the review is misplaced (the
trace overstates achievable payload). Not surfaced as a genuine residual.

---

## F-03 — NOT-MATERIAL / DELIBERATE

**Claim (Low, informational)**: `stableGroups` (pkg/dhcpserver/dhcpserver.go:728) assigns Kea
subnet_id by sorted group name, so renaming a group reorders IDs and remaps live memfile leases
to the wrong subnet.

**Verification / refutation**:
- Symbols present; behavior as described (subnet_id assigned in `stableGroups`×`stablePools`
  order at dhcpserver.go:786-801 / 909-920).
- The stability contract is **explicitly documented and scoped**: the code comment
  (dhcpserver.go:723-727) guarantees "the same subnet the same subnet_id across reloads of an
  **UNCHANGED** config" — a group rename IS a config change, outside the stated contract. This is
  DELIBERATE design, not an accidental gap. #2668 built determinism against Go map-iteration
  randomization, which it fully achieves.
- The proposed alternative (key subnet_id on subnet prefix globally) trades one edge for a worse
  one: an address/prefix change would then shift IDs, and address changes are more common than
  group renames — and a subnet whose prefix changed genuinely needs new leases anyway. The
  group-name key is a defensible SSOT.
- Impact is bounded and self-healing: after a rename, mis-bound leases churn out as clients
  renew/expire (Kea NAKs a lease whose address falls outside the reassigned subnet's pool). No
  security or forwarding impact; group rename with live leases is a rare operator action.

**Disposition**: NOT-MATERIAL / DELIBERATE. Documented-contract-honored + self-healing + rare +
alternative-has-its-own-tradeoff. The reviewer themselves marked it "informational." Not a
genuine residual. (If ever driven, it's a needs-research design decision, not a bug fix.)

---

## Negatives (reviewer's clean modules — spot-checked, concur)

The remaining ~147 files were marked negative by the reviewer with specific correctness
rationale per module (ddns never-delete-non-owned + per-family/per-RG gating + write-ahead
durability; dhcp RFC-correct renewal + #4526 divide-first renewalTimers; dhcprelay hop-limit-
before-increment + #4163 source-validation; dhcpserver generation-ordered supersession + lenient
parseLeaseCSV; policymatch 5-tier precedence + fail-closed omitted-selectors matching Rust
policy.rs; sign.py/publish.py TOCTOU-safe verify-and-read + fail-closed gates; bake.py validate-
before-sign #4017). These map to already-merged dedup issues and show no novel reachable bug.
Concur — negatives, not findings.
