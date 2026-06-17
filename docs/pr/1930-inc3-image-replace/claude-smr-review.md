# #1930 INC-3 — Claude SMR adversarial review (PR #1942)

Reviewing `origin/master..HEAD` on `engineer/1930-inc3` (final increment;
PR body carries `Closes #1930`). Domain SMR (HA/session-sync), CPU
arch/design, and SW design-patterns lenses.

## Scope
LANE-2/3 image-replace + mixed-base HA compatibility gate + base-OS docs:
- `pkg/upgrade/imageversions.go` — `GateMixedBaseSwap`, `parseImageVersions`
- `pkg/upgrade/imageversions_test.go` — 6 gate/parse tests
- `cmd/xpfd/main.go` — `protocol-versions` subcommand
- `pkg/cluster/heartbeat.go` — `MinCompatHAProtocolVersion`
- `pkg/cluster/sync.go` — `SessionSyncWireVersion`
- `scripts/deploy/xpf-deploy.py` — `image-roll` driver + `_gate_mixed_base`
- `scripts/image/bake.py` — version manifest recording
- `pkg/upgrade/kernel_drain.go` + `cmd/xpfd/upgrade_kernel.go` — `--allow-mixed-ha`
- `docs/in-place-upgrade.md`, `docs/install-images.md`

## Findings

### Gate soundness — PASS
`GateMixedBaseSwap` returns `SessionsSurvive=true` only after passing, in
order: non-nil image; all `requiredKeys` present; `peerHAProtocol != 0`;
peer within `[MinCompat, HAProtocol]`; `peerSessionSync != 0`;
`peerSessionSync == SessionSyncProtocol`. Every other branch returns the
zero-value (`false`) verdict with a reason. The previously-flagged
`peerSessionSync == 0` permissive path (r1/r3 Codex) is fixed — it now
fails closed at imageversions.go:156-159. No input reaches `true` when a
required protocol is unknown or out of window.

### Go vs Python gate parity — PASS
`_gate_mixed_base` (xpf-deploy.py:945-971) mirrors the Go gate
branch-for-branch: same required keys, same `peer_ha == 0` fail-closed,
same window check, same `peer_sync == 0` fail-closed, same exact-match.
`_u16` rejects unparsable/out-of-range as `None` → fail closed. Identical
decisions for identical inputs.

### protocol-versions correctness — PASS
Emits `cluster.SessionSyncWireVersion` (cross-chassis sync schema), NOT
`userspace.ProtocolVersion` (local daemon↔helper socket). The exact
subtle bug to avoid; the code comment calls it out explicitly. Keys are
stable `key=value`; bake re-keys `-`→`_` and the Go parser accepts both
separators and both delimiters (`=`/`:`).

### never-both-down invariant — PASS
`cmd_image_roll` rolls one node at a time: drain→recreate→poll-back→
rejoin+confirm-sync, and only THEN `roll_one` on the second node. Boot
failure `die`s with the peer still primary. Cross-orchestrator lease is
acquired in sorted (canonical) order with release-what-we-got on partial
acquisition, preventing two operators draining in opposite order.

### --allow-mixed-ha scoping — PASS
`DrainAndConfirm(..., allowMixedHA)` relaxes ONLY the exact-equality
`HAProtocolCompatible` precheck, and only for the gate-validated second
drain (or operator-waived `--allow-session-drop`). The peer-alive and
peer-takeover-ready prechecks still run. LANE-1 kernel-roll keeps exact
equality (single-version cluster).

### base-OS / do-release-upgrade — PASS
`docs/in-place-upgrade.md` marks `do-release-upgrade` UNSUPPORTED with
the documented rationale (irreversible userspace move under kernel hold;
N+1-userspace-on-N-kernel brick; untestable). No fake live test — the
base-OS major path is correctly bench/manual + image-replace only.

## Verdict: MERGE-READY
Build clean (`go build ./...`), `go test ./...` clean, `py_compile`
clean, `xpfd protocol-versions` emits the expected stable output.
