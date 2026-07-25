# AGY hostile plan review — round 6 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only). Scope: plan v7 @ 238038949.
Run ledger: full-prompt runs out1/out2/out3/out4 all hit the 5m timeout (4 documented attempts, plan doc now ~1150 lines); completed as two single-question runs (out5 = Phase-2 pipeline, out6 = activation authority) per the r1 split pattern.

## Run 1 — Phase-2 AnchorUpdate pipeline (out5)

### Question (1): Volume model vs. shared control socket
**Verdict: UNSOUND**

**Analysis:**
Per-entry 1 Hz rate-limiting scales linearly with session count ($N$). If an attacker or traffic pattern maintains $10^5$ to $10^6$ active flows that each advance within slack once per second, the pipeline generates up to $N$ `AnchorUpdate` messages/sec. Because `AnchorUpdate` deltas share the single Rust$\rightarrow$Go event stream and control socket with `Open`/`Close` session installs, un-capped aggregate update volume can saturate the IPC ring (~4096 slots per worker) and HA control channel. This introduces Head-of-Line (HoL) blocking or starves critical session lifecycle deltas. An aggregate throughput ceiling or dedicated low-priority queue is required.

---

### Question (2): Exploiting quiet-flow emission filter via fast-moving anchors
**Verdict: SOUND**

**Analysis:**
Keeping an anchor moving faster than one slack per second suppresses `AnchorUpdate` emissions, leaving the standby node with either the initial `Open`-delta anchor or no update. Post-failover, a stale anchor window lags far behind the live flow sequence numbers. When an off-path attacker sends a blind RST/FIN target sequence near the live flow, it fails validation against the standby's stale anchor window. The standby enters the designed **refuse-biased** posture (soft-refusing un-anchored demotions until natural session churn). Suppressing updates strengthens refusal rather than enabling blind teardowns.

---

### Question (3): `anchor_seqno` serial-compare import vs. event-stream reordering
**Verdict: SOUND**

**Analysis:**
Using a 32-bit serial number comparison (RFC 1982 arithmetic, `(int32_t)(new_seq - stored_seq) > 0`) is robust against out-of-order event stream delivery. If update $k+1$ arrives ahead of update $k$, the entry updates its `anchor_seqno` to $k+1$. When delayed update $k$ subsequently arrives, $k - (k+1) < 0$, causing the late delta to be discarded without mutating the newer in-place anchor state. At 1 Hz max per entry, $2^{32}$ sequence wraparound is not an issue over any practical session lifetime.

## Run 2 — activation-time authority (out6)

### Design Review: Issue #6461 (Blind RST / Authority Transfer)

#### **Question (1): SOUND**
- **Analysis:** Blind close packets (RST/FIN) are completely inert when validation fails: they neither mark the session for accelerated teardown nor refresh its timeout. Furthermore, closing packets are explicitly prohibited from promoting session ownership (Section 5.2 Rule 5). Self-heal re-stamping occurs during RG activation timer sweeps, not on packet receipt. Consequently, packet spray or unauthenticated close attempts cannot accelerate an entry's reap beyond its natural timeout.

#### **Question (2): SOUND**
- **Analysis:** Ownership transition is strictly decoupled across HA state changes. When a Redundancy Group (RG) demotes, the node retags its active session entries as `SyncImport` (`install.rs:572`, `shared_ops.rs:179-206`), revoking Close authority so subsequent reaps are silent. When the target node activates, the activation self-heal (`expire.rs:213-237`) promotes imported entries to locally-authoritative (`SharedPromote`). Because demotion strips authority before/upon losing active status, dual authority never overlaps across flaps.

#### **Question (3): UNSOUND**
- **Analysis:** Between RG activation and an entry's first lazy timer-wheel evaluation, the entry's authority remains `SyncImport` (peer-synced / non-authoritative). If a close packet arrives during this window:
  1. Closing packets never promote ownership (`SyncImport` is not upgraded to `SharedPromote`).
  2. If the session reaps while still tagged as `SyncImport`, the HA replica invariant suppresses cluster-wide Close delta emission (`expire.rs:342-345`).
  3. Because Close delta emission is suppressed, shared-map NAT alias cleanup (`session_delta.rs:406-452`) is stranded until/unless an eager activation sweep guarantees authority promotion prior to packet handling or reap.
