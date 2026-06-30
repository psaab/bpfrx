# Codex hostile plan review r1 — #2354 QinQ transit

task-mr0z5z4h-xlhx7i (session 019f19c5-75f3-7a03-8f6b-133f1300b6e7). Plan v1 @ 903f2d2bb.

## Verdict: PLAN-DEFER

Per-check (Codex's own words, summarized):
1. GAP ACCURACY — CONFIRMED. parse_l2 lib.rs:1153 strips one tag (if 1161, read 1162, l3+= 1168, return 1171); double-tag → `_ => pass_non_ip_l2_direct()` lib.rs:407-410 → XDP_PASS lib.rs:1011-1015. Meta sizeof 96 lib.rs:153, meta_flags@39 / reserved@42 / reserved2@92. InnerVlanID set compiler_interfaces.go:299-303, zero prod reads. ethernet_l3 rejects QinQ ecn.rs:84-85. (Minor: path is frame/headers.rs not headers.rs.)
2. FORK (a) — PARTIALLY WRONG. Byte reuse fine; verifier story hand-wavy until cmd/shimverify runs. C-tag TCI = packet bytes 18-19, L3 starts at 22. Use CONSTANT packet offsets, not widened meta-derived offsets.
3. FORK (b) — PARTIALLY WRONG. Today's key is FastMap<(i32,u16),i32> types/forwarding.rs:102; builder forwarding_build/interfaces.rs:216-225; lookup forwarding/mod.rs:583-591. (ifindex,outer,inner) is a strict superset ONLY IF the lookup pins EXACT inner match wins BEFORE inner=0 wildcard, else a single-tag wildcard row shadows a QinQ exact row.
4. TPID PRESERVATION — CONFIRMED. TxVlanTag::from forces TPID_8021Q headers.rs:123-130; egress helpers use it 148-155/188-195; wire carries only TXVLANID protocol.go:2614/2687. PR-C emitting an S-tag via TxVlanTag::from would silently rewrite the service tag to 0x8100 — wrong.
5. PR-A DEAD CODE — PARTIALLY WRONG. Snapshot field inert until Rust consumes it, BUT networkd device creation before XSK support is WORSE than dead: double-tag XDP_PASS lib.rs:407-410 + kernel forwarding on daemon_run.go:1817-1820 = kernel slow-path bypass window.
6. COS/ECN FLIP — PARTIALLY WRONG. Callers maybe_mark_ecn_ce ecn.rs:179-189 + _prepared 216-235 use None=>false; tests pin rejection ecn_tests.rs:281-306 (warn L3 is really 22; guessing 18 stamps inner TCI). Safe only after ALL parsers + TX agree on two tags.
7. PHASING — PARTIALLY WRONG. META/XSK coupling in PR-B is RIGHT (version gate lib.rs:397, ver=4 lib.rs:14). Bad phasing is networkd-before-dataplane. Single-tag must keep writing reserved=0 (lib.rs:690-700).
8. DISPOSITION — issue is Low priority + "do NOT do speculatively" (issue-history.md:36567-36578); feature-gaps.md:681 Low/Partial. Not PLAN-KILL on hardware grounds (mlx5 native XDP, software byte-parse). Not PLAN-READY: no verified demand + unresolved phasing/TPID/verifier/classification-shadowing hazards.

OVERALL: PLAN-DEFER. Gap inventory solid; engineering should not start from v1. Tighten: PR-A device-before-XSK bypass, exact/wildcard classification precedence, S-tag TPID egress contract beyond TxVlanTag::from. Stay deferred until real demand + tightened plan.
