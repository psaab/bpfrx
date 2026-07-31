# AGY hostile plan-review — round 116 (v10.32.0)

Reviewer: AGY (direct binary). Verdict: SOUND — state-keyed proof, two-direction binding, single carrier, ordering, and footprint all verified; no findings.

## Verbatim review

SOUND

### Executive Summary & Review Verdict

Document `docs/research/6461-blind-rst/plan.md` (v10.32.0) is **SOUND**. The round-116 folds resolve the remaining subtle edge cases around reverse-NAT synthesis, cache identity checks, and alias replacement races without introducing new state-machine contradictions or security regressions.

---

### Detailed Checklist Verification

#### (a) Verification of the State-Keyed Proof Against Pickup & Repair Paths
* **Mechanics (§5.6, Site 2b):** Reverse-NAT synthesis (`install_reverse_session_from_forward_match`) now evaluates the **FORWARD ENTRY'S STATE** rather than the packet's raw flags:
  1. **OPENING Forward Entry:** Any non-closing reverse segment arriving against an `OPENING` forward entry must pass the strong `OPENING` handshake proof against `[open_ack_lo, open_ack_hi]`. A valid `SYN-ACK` passing this proof synthesizes the reverse entry AND applies the forward companion's flag-only establishment update (`established = true`, keeping the absolute opening deadline intact). An unproven non-closing packet (such as a bare `ACK` or `PSH-ACK`) has no ISN proof to give and **skips the install entirely** (`created=false, install_failed=true`), leaving the forward entry in `OPENING` without creating a zombie reverse entry.
  2. **ESTABLISHED Forward Entry (including #3152 Pickup & Imports):** When the forward entry is already `ESTABLISHED`, the reverse synth proceeds verbatim per master without forcing an `OPENING` proof. This preserves asymmetric routing pickup and mid-stream repair flows, as pickup sessions do not record an immutable `OPENING` interval.
* **Soundness:** This eliminates the vulnerability where a spoofed `ACK` or `PSH-ACK` hitting a reverse NAT match could prematurely synthesize an `ESTABLISHED` reverse entry and pin an `OPENING` forward half through companion retention (`expire.rs:296-320`).

#### (b) Verification of Two-Direction Binding and Single Carrier
* **Two-Direction Identity Binding (§5.5, §5.8):** 
  - Each forward and reverse entry allocates its own `install_epoch` at install time.
  - The reverse entry records `fwd_companion_epoch: u64` from the forward entry's `install_epoch` at reverse installation (`entry.rs:208-213`).
  - During the `account_packet`-style reverse-to-forward hop (`session/mod.rs:1177-1205`), the hop re-verifies that the forward entry's current `(key, NAT, install_epoch)` matches `(key, NAT, fwd_companion_epoch)`.
  - In an ABA scenario where the forward entry was replaced by $K_2$ (same key/NAT, new epoch), $R_1$'s sample fails epoch validation against $K_2$ and is dropped, preventing anchor corruption.
* **Single Carrier Slot (§5.8):**
  - A single `matched_token` slot on the per-descriptor dispatch context carries the identity token `Option<(SessionKey, NatDecision, bool, u64)>` from the lookup result (hit/materialize) or the fresh forward install's `OUT` parameter into flow-cache entry construction.
  - A subsequent reverse-companion synthesis token is explicitly forbidden from overwriting `matched_token`, guaranteeing that the cache entry binds to the primary matched forward identity.

#### (c) Verification of Cache-Hit Ordering Against Decision Consumers
* **Ordering (§5.8, ~`flow_cache_hit.rs:133`):**
  - The identity token compare (`cached.token == dispatch.token`) is executed **immediately after** cache validity checking (`cached_flow_decision_valid` around line 133) and **BEFORE** any cached-decision consumer:
    - TTL / Hop-Limit handling (`:155-188`)
    - Filter counters (`:191-207`)
    - Policy hit counters (`:219-224`)
    - Three-color policers (`:225-229`)
    - Input/Output filter logging (`:230-237`, `:258-268`)
    - Filter reject reply synthesis (`:245-256`)
    - Terminal drop decisions (`:269-272`)
* **Soundness:** On a token mismatch, the cache hit immediately evicts the slot (`invalidate_slot`) and returns `FlowCacheOutcome::FallThrough` to trigger slow-path resolution. This guarantees no egress counters, policers, or side-effects are executed for a mismatched or stale cache entry.

#### (d) Surviving Surface & Residual Assessment
* **Demote Spray Difficulty:** Attacker must guess both sequence and ack positions within active windows ($\approx 1/2^{12}$ cap to $1/2^{14}$ floor per blind packet). At 1,000 pps, expected spray time to force a demote is ~6.5 s to 16 s of continuous traffic.
* **HA-Imported / Pre-Upgrade Absorbing State:** Imported entries carry no local trusted anchor. Blind closes soft-refuse, and the session idles out on its normal established timeout (or until master's flag-agnostic transient purge reaps it). Delivery is never blocked; connection teardown at endpoints remains unaffected.
* **Non-First Fragments:** Flowless (`frame/inspect.rs:1455`); cannot hit session state or drive demotion.

#### (e) Full-Document Consistency Sweep
* **Footprint & Sizing (§8):** Correctly accounts for $\approx 49\text{ B}$ slab growth per `SessionEntry` ($40\text{ B}$ `TcpSeqAnchor` + $1\text{ B}$ `probation` + $8\text{ B}$ `fwd_companion_epoch`). Cache token footprint is correctly scoped per-binding ($\approx 48\text{ B} \times 4096 \approx 192\text{ KiB}$ per binding).
* **Cross-Section References:** All file:line citations across `session/mod.rs`, `lookup.rs`, `install.rs`, `shared_ops.rs`, `entry.rs`, and `flow_cache_hit.rs` are consistent with origin base `023f17a606d8` and master drift deltas in §3.1.
