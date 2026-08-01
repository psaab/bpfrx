# Claude SMR hostile plan-review — round 43 (plan v43 @ `586a0c6d9`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r42's SMR
raised the counter-balance pin at MINOR (Codex + AGY independently
rated the same defect MAJOR — the fold treated it as MAJOR); r43
re-verifies the v43 folds of Codex's 3M/2m and AGY's 1M against the
real code, then attacks the teardown-cap window, the EOF witness, and
the restart/reconnect edges. All line numbers re-verified against the
worktree.

## A. Fold verification (r42 findings → v43)

### 1. Codex M1 + AGY M1 + SMR m1 (total retirement) — FOLDED

Token-path enumeration, each verified in code: (i) successful enqueue
(`sync_conn_read.go:321-324`) → consumer dequeues → dequeue-scoped
`defer` retires after the apply returns — success, failure
(`sync_conn_config.go:345-360`), and panic unwind all fire the defer;
(ii) nil-channel guard (`sync_conn_read.go:318`) — no increment;
(iii) queue-full `default:` drop (`sync_conn_read.go:324-331`) — no
increment, so no leaked +1 hanging the drain; (iv) stale-generation
skip (`sync_conn_config.go:331-336`) and (v) nil-handler skip
(`sync_conn_config.go:337-341`) — both inside the consumer's per-item
scope, so the defer retires them; (vi) teardown with buffered items —
`SessionSync.Stop` cancels the consumer
(`sync_conn_config.go:325-330`, `sync_conn.go:349-385`) and the plan
pins drain-and-retire at Stop, so no token survives a provider
replacement. One increment, exactly one retirement, per token.
FOLDED.

### 2. Codex M2 (node-lifetime ownership + EOF witness) — FOLDED, with nit m1

The provider-replacement window is real (re-verified): apply step 20
restarts comms on a transport change (`daemon_apply_tail.go:238-255`),
`stopClusterComms` nils `d.sessionSync` and `ss.Stop()`s with a 5s cap
(`daemon_ha_sync.go:1405-1415`, `sync_conn.go:349-385`), and the
manager's provider re-points (`sync_state.go:47-63`,
`daemon_ha_sync.go:906-913`) — a provider-scoped counter would read
zero on the fresh provider while the old apply holds its token.
Node-lifetime ownership closes it by construction. The partial-frame
window closes via the EOF witness: the read loop dispatches only on a
COMPLETE frame (`io.ReadFull` of header and payload,
`sync_conn_read.go:28-69`), so bytes the peer sent before dying are
either fully dispatched (counted) or abandoned mid-frame at EOF
(never counted, never applied). FOLDED — but see m1: the witness's
observable surface is not named.

### 3. Codex M3 (admitted residual shape iii) — FOLDED

Bound walk, verified: the peer's promote-then-`writeActive`-failure
raises `ActivePersistDegraded` process-locally
(`store.go:687-717,738-746`); the stop abandons the retry
(`store_persist.go:397-401`); the peer's PERSISTED active config is
untouched (the failed write never landed), so its restart `Load`
classifies the prior records through the same machinery; the reconnect
re-drive re-pushes the current config (`daemon_ha_sync.go:926-956`)
and the peer re-converges; a PERMANENT persist failure surfaces as the
peer's `/health` 503 (the `config_persist_degraded` pattern,
`pkg/api/health.go:65-71`). Nothing is lost silently. The
deterministic alternative — a producer-pause knob — is new machinery
the narrow-scope idiom declines; the admit+bound pattern is this
runbook's established shape (r29/r37/r38). FOLDED.

### 4. Codex m1 (acceptance read surface) — FOLDED

The acceptance copy now reads the peer's mask + persist via `/health`
and the peer's counter via the peer's cluster-status RPC. Grep
verified: no surviving text attributes `ConfigSyncOutstanding` to
`/health`. FOLDED.

### 5. Codex m2 (JOIN-COHERENCE sub-legs) — FOLDED

Five named sub-legs cover every window named across M1/M2:
framed-blocking-apply (dequeue/applySem), legacy gen-0 payload,
concurrent `resetRecvGen`, provider-replacement (node-lifetime
survival), and retirement-totality (drop / stale-skip /
nil-handler-skip / teardown-with-buffered). FOLDED.

## B. Fresh attacks on the v43 delta

**Attack 1 (SUCCEEDED as nit m1) — the EOF witness's observable
surface is unnamed.** The plan requires observing "the LOCAL
EOF/disconnection of the stopped peer's session(s)" before trusting
the counter read, but never says WHERE the operator reads it. The
surface exists today — `Manager.IsSyncConnected()`
(`sync_state.go:66-74`) rendered as the sync "Status: Up/Down" line
(`status.go:263-267`) — so the pin is one clause: the witness is the
EXISTING sync-peer connection state on the cluster status surface,
observed Down (which requires BOTH redundant sessions EOF'd, since the
flag aggregates liveness) — and it belongs in the §5.1 `pkg/cluster`
entry next to the counter so the runbook's two observations (witness +
counter) live on the same surface. MINOR.

**Attack 2 (FAILED) — the 5s Stop cap vs an applySem-blocked apply.**
`Stop` proceeds past the cap with the consumer still inside
`OnConfigReceived` (`sync_conn.go:375-385`); when the apply eventually
returns, the dequeue-scoped `defer` still retires the token into the
NODE-LIFETIME counter — which survives the provider swap — so the
counter reads >0 until then and never false-idles. A late retirement
is a correct retirement here. FAILED.

**Attack 3 (FAILED) — heartbeat-timeout and bad-magic read-loop
exits.** The witness is the disconnection SURFACE, not the exit cause:
EOF, heartbeat-ack timeout (`sync_conn_read.go:33-46`), and bad magic
(:54-57) all terminate the loop and drop the connection state; any of
them satisfies "no more frames can be dispatched from this
connection". FAILED.

**Attack 4 (FAILED) — systemd re-driving the peer.** A clean
`systemctl stop` does not trigger `Restart=on-failure`; the runbook
stops the peer, it does not kill it. FAILED.

**Attack 5 (FAILED) — a stale peer process or third party reconnecting
mid-drain.** Frames on an authenticated connection are HMAC-verified
BEFORE dispatch (`sync_conn_read.go:73-89` — a bad trailer drops the
connection before `handleMessage`), and pre-auth connections sit in
the #5303 setup window, so no unauthenticated frame can be counted or
applied. A legitimately-reconnecting peer requires a RUNNING peer
xpfd, which (2b) excludes. FAILED.

## C. Findings

### MAJOR (0)

None. All r42 majors fold on independent verification; the join is now
a totally-retired, node-lifetime counter with a transport-level
ingress witness and an honestly-bounded residual set.

### MINOR (1)

**m1.** Name the EOF witness's observable surface: the existing
sync-peer connection state (`IsSyncConnected`,
`sync_state.go:66-74`, rendered at `status.go:263-267`), observed Down
— which aggregates both redundant sessions — with the pin added to the
§5.1 `pkg/cluster` entry so the witness and the counter live on the
same status surface.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the witness-surface
pin). A v44 containing only this pin is PLAN-READY by inspection from
me.
