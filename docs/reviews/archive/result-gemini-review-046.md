# Triage result — gemini-review-046

**Base reviewed:** 33ea184d3 (matches current origin/master — fetched, HEAD 33ea184d3ac86)
**Triage authority:** single (this run). No code mutated; no git state changed.
**Outcome:** 3 filed (#5231, #5232, #5233), 1 dup, 1 already-tracked-closed, 8 non-material/unverifiable.

Gates per finding: (1) SYMBOL-EXISTS on origin/master, (2) ALREADY-FIXED / DUP,
(3) REAL+MATERIAL. All ground truth via `git show origin/master:` (main checkout is
~3300 commits stale).

---

## HIGH 1 — master-password via groups/apply-groups → plaintext DB write
- **Symbol:** EXISTS. `masterPasswordPRF` at `pkg/configstore/crypto.go:56`; scans only
  `systemBlocksOf(tree)` (`dataplane_retire.go:140`, top-level `system` children only).
- **Already-fixed/dup:** NO. #4705 (CLOSED) fixed *split top-level system* stanzas via
  `systemBlocksOf`; it does NOT descend into `groups`. #4578 = PRF typo. Neither covers
  groups/apply-groups. `groupsBlocksOf` + `systemBlocksOfNode` helpers exist (used by the
  retirement walk) but `masterPasswordPRF` never calls them.
- **Material:** YES. Confirmed xpf expands apply-groups (`pkg/config/README.md`: "Clones the
  tree, expands apply-groups"); expansion is on a compile-time clone, so the persisted
  candidate is unexpanded → a groups-declared master-password is active at runtime but
  invisible to the encrypt gate → active.json (IKE PSKs, WG keys, SNMP communities) written
  plaintext despite encryption being configured.
- **VERDICT: FILED #5231** (bug, security).

## MED 1 — BPF NPTv6 0xFFFF fold, no skip guard (`bpf/headers/xpf_nat.h:540`)
- **Symbol:** EXISTS (`nptv6_translate`), but **dead code**: legacy eBPF dataplane retired
  (#1476), hard-rejected at runtime; only callers are the header itself, docs, and the parity
  test `pkg/dataplane/nptv6_test.go`. Runtime NPTv6 is `userspace-dp/src/nptv6.rs`.
- **Already-fixed/dup:** YES. **#3233 (CLOSED)** = "NPTv6: zero-adjustment rule still folds
  0xFFFF→0x0000, corrupting a valid host-ID word" — the exact defect, priority very-low.
  Also #4089 (CLOSED) verifies the same 0xFFFF handling. gemini's own dedup note cites #3233.
- **Material:** NO (retired-dataplane dead code) AND already tracked.
- **VERDICT: DUP-of-#3233 / non-material. Not filed.** (Distinct from open #5176, which is
  NPTv6 static-NAT from_zone scope — unrelated.)

## MED 2 — world-readable day-0 config-drive ISO (`scripts/image/make_config_drive.py`)
- **Symbol:** EXISTS. Confirmed: stage `xpf.conf` chmod 0o644 (line 72); output ISO `out`
  gets NO chmod (line 82). Genuine gap.
- **Already-fixed/dup:** **DUP of #4905 (OPEN), Section C** — verbatim: "Config-drive builder
  leaves secret-bearing ISOs world-readable — scripts/image/make_config_drive.py:68/77 ...
  chmod 0600 the ISO (match the deploy path)."
- **VERDICT: DUP-of-#4905. Not filed.**

## MED 3 — CGNAT deterministic port linear scan under global lock (`nat/allocator.rs:1345`)
- **Symbol:** EXISTS.
- **Material:** NO. Code comment documents the deliberate tradeoff: "The block is small
  (typically a few thousand ports) and this is the cold path (first packet of a flow), so a
  linear CAS probe is fine." Perf micro-opt, no measured impact, bounded by block size.
- **VERDICT: non-material (documented design tradeoff). Not filed.**

## MED 4 — bgpHandler no request-context cancel check (`pkg/api/routing.go:80`)
- **Symbol:** EXISTS. Loop at `:109`, flush at `:115`; verified NO `r.Context().Err()` check.
- **Already-fixed/dup:** NO (searched; #4708 was memory-streaming only; #5060 = grpcapi pipe
  leak, different bug).
- **Material:** YES. 900k-route table → CPU/GC waste per client disconnect; repeatable.
  Localhost-bound API bounds the surface but the waste is real on constrained firewalls.
- **VERDICT: FILED #5232** (bug).

## MED 5 — session handlers no request-context cancel check (`pkg/api/sessions.go:88/110`)
- **Symbol:** EXISTS. Callback returns `true` unconditionally; NO context check. Pattern
  recurs in `sessionSummaryHandler:457` and `sessionZonePairHandler:639`.
- **Already-fixed/dup:** NO (searched).
- **Material:** YES — full BPF conntrack-map traversal takes per-bucket locks that contend
  with the live dataplane session-sync; runs to completion after disconnect on million-entry
  tables. More material than MED4 (lock contention vs dataplane).
- **VERDICT: FILED #5233** (bug).

## LOW 1 — PrefixTrie pointer chasing (`userspace-dp/src/prefix_set.rs:260`)
- Perf micro-opt. Design already gates small sets to a cache-friendly linear vector
  (`PREFIX_SET_LINEAR_MAX = 16`). No measured impact. **VERDICT: non-material. Not filed.**

## LOW 2 — ParseVRRPPacket nil deref on malformed IPv6 (`pkg/vrrp/packet.go:130`)
- Symbol EXISTS (`srcIP == nil` guard, then `srcIP.To16()`). The finding's OWN refutation
  admits all production callers pass valid 4/16-byte IPs (`receiverIPv6`, `parseAfPacketIPv6
  → make(net.IP,16)`). Only reachable via a hypothetical malformed non-nil IP from tests/CLI.
  **VERDICT: non-material (no production trigger). Not filed.**

## LOW 3 — captureMlx5Coalesce nil-map (`pkg/daemon/host_tunables.go:643`)
- Symbol EXISTS. Production allocates only via `newPriorHostTunables()` (`:590`), which
  initializes `mlx5Adaptive`. Only a hypothetical struct-literal bypass panics. Defensive nit.
  **VERDICT: non-material. Not filed.**

## LOW 4 — systemd-networkd quoted `Name=` bypass in FindExternallyManaged
- File: `unknown`; "No direct evidence snippet provided." Unverifiable — cannot locate a
  symbol/line. **VERDICT: unverifiable, dropped.**

## LOW 5 — O(N) sysfs/netlink loop in interface show commands
- File: `unknown`; no evidence. Perf, unverifiable. **VERDICT: unverifiable/non-material,
  dropped.**

## LOW 6 — unlocked regexCache back-fill in attributesMatch (`pkg/eventengine/engine.go:1084`)
- Symbol EXISTS. Code comment (verified): "Production callers reach here under e.mu ... so the
  write is serialized." The finding (Confidence Medium) is an explicitly TEST-ONLY concurrency
  observation. Per triage rules, a test-only observation is non-material.
  **VERDICT: non-material (test-only). Not filed.**

## LOW 7 — sendTrap double-bracketing of IPv6 target (`pkg/snmp/traps.go:213`)
- Symbol EXISTS. Bug only manifests if a target is ALREADY bracketed (`[2001:db8::1]` w/o
  port). Targets come from `tg.Targets` (Junos-style SNMP trap-group config), which are bare
  IPs; a bare IPv6 → SplitHostPort err → JoinHostPort yields the CORRECT `[..]:162`.
  Confidence Low; requires non-standard operator input. **VERDICT: non-material. Not filed.**

---

## Summary
- **Filed (3):** #5231 (HIGH1, security), #5232 (MED4), #5233 (MED5).
- **Dup (2):** MED1 → #3233 (CLOSED, also dead eBPF code); MED2 → #4905 (OPEN, Section C).
- **Non-material / unverifiable (8):** MED3, LOW1, LOW2, LOW3, LOW4, LOW5, LOW6, LOW7.
- Signal rate: 3/13 genuine+material+novel — consistent with gemini's historical ~90% false/
  non-material rate on this project, with the recent-base structured section yielding a few
  real survivors (the master-password-in-groups leak is the strongest).
