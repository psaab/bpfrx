# #1914 tunnel-endpoint-id collision gate — reviewer ledger

PR: #1952  •  final rev: `e954ba4bd`  •  branch: `engineer/1914-collision-gate`

## Quad-review verdicts (final rev e954ba4bd)

| Reviewer | Task / ref | Verdict |
|----------|-----------|---------|
| Claude SMR | in-conversation (domain SMR: config-compiler + HA-symmetry + dataplane parity) | **MERGE-READY** |
| Codex | `task-mqi3lk7p-lq319j` (session 019ed5bc-e8b7-7ae1-9f62-c2c248980f81) | **MERGE-READY** (read-only-sandbox caveat: could not run Go build/test itself; run clean inline) |
| Antigravity | `adversarial-review-mqi3lwg2-r8wip9` | **MERGE-READY** (all 6 hostile checks confirmed) |
| Copilot | review @ e954ba4bd | infra error ("Copilot encountered an error and was unable to review"); re-requested; no findings — merged on 3-of-4 clean + Copilot-infra exception |

## Invariants verified (all three reviewers convergent)

- **A Recursion-free**: gate called only from compiler.go:115/176; emitNodeExpandedTunnelNames → compileInterfaces + EmitTunnelEndpointNames never reach the gate.
- **B HA cross-node symmetry (#1873)**: gate always computes View2(node0)+View3(node1) regardless of compiling node; pure fn of (tree, nodeID); no hostname/node-id/env read.
- **C Parity**: buildTunnelEndpointSnapshots drives off config.EmitTunnelEndpointNames; pinned by TestEmitTunnelEndpointNamesMatchesBuilder (differential).
- **D Monotonicity**: View 1 byte-identical to pre-#1914; Views 2/3 only add map keys → only add rejects. Pinned by TestTunnelEndpointIDView1PresenceUnionPreserved.
- **E node1-undefined-group expansion**: non-fatal empty-set, no panic, View 1 rejects preserved.
- **F StableTunnelEndpointID fold unchanged** (wire-adjacent, #1873). Pinned by TestStableTunnelEndpointIDHashFreeze.
- **G Defect B (documented accept)**: presence-only View 1 phantom non-WG ref ~1/65535 false reject; mutually exclusive with the Defect-A fix; safe failure mode (commit reject + rename remediation). Pinned by TestTunnelEndpointIDDefectBIncompleteGREStillRejects.

## Validation (run inline on e954ba4bd)

- `go build ./...` clean; `go vet ./pkg/config/... ./pkg/dataplane/userspace/...` clean.
- `go test ./...` full suite: pass (0 failures).
- `TestTunnelEndpointID*` 5×: 0 flakes. `TestEmitTunnelEndpointNamesMatchesBuilder` 5×: 0 flakes.
- Control-plane-only change (Go config compiler + Go snapshot builder; no Rust dataplane). No cluster smoke required; functional coverage is the new unit/differential/parity tests.
