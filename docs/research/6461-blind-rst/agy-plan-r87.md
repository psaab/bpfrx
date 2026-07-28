Answering the review prompt based on the code references provided in your question and codebase evidence:

VERDICT: PLAN YES

### Q1 (the second retreat): SOUND
- **Evidence**:
  - (i) Pre-existing on master: admission bypass at [session_admission.rs:29](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/admission.rs#L29) / [session/mod.rs:909](file:///home/ps/git/bpfrx/userspace-dp/src/session/mod.rs#L909), publication overwrite at [shared_ops.rs:897](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs#L897), session_id collisions at [session/mod.rs:766](file:///home/ps/git/bpfrx/userspace-dp/src/session/mod.rs#L766), [install.rs:324](file:///home/ps/git/bpfrx/userspace-dp/src/session/install.rs#L324), [ha/export.rs:143](file:///home/ps/git/bpfrx/userspace-dp/src/ha/export.rs#L143), TOCTOU at [shared_ops.rs:960](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs#L960), [checksum.rs:246](file:///home/ps/git/bpfrx/userspace-dp/src/checksum.rs#L246), [xpf_maps.h:508](file:///home/ps/git/bpfrx/bpf/xpf_maps.h#L508), and stub metadata at [neighbor_dispatch.rs:606](file:///home/ps/git/bpfrx/userspace-dp/src/neighbor_dispatch.rs#L606).
  - (ii) Transient seeds do not publish `Open` state/messages to HA peers, so zero-producer transient seed sessions have no peer copy and carry no HA side-effects.
  - (iii) The retraction prevents cascade regressions while postponing the seed lifecycle completion to section 10.6.2 follow-up design without introducing an ISSUE-class harm into this plan.

### Q2 (clean baseline + reciprocity): SOUND
- **Evidence**:
  - Pre-SNAT clean baseline: The purged entry's released NAT allocation is discarded prior to derivation, preventing stale-P1 reuse and ensuring fresh, deterministic NAT allocation via [allocator.rs:1265](file:///home/ps/git/bpfrx/userspace-dp/src/nat/allocator.rs#L1265).
  - Reciprocity gates: The companion key derived via `reverse_session_key(key, entry_nat)` at [expire.rs:476-496](file:///home/ps/git/bpfrx/userspace-dp/src/session/expire.rs#L476-L496) verifies bi-directional key reciprocity. When matching a forward entry, `is_reverse` is strictly required on the target; when matching a reverse entry, the target is validated as the corresponding forward. Mis-matched/wrong-generation marks (such as the unrelated-forward-B issue at [lookup.rs:204](file:///home/ps/git/bpfrx/userspace-dp/src/session/lookup.rs#L204) / [session/mod.rs:1241](file:///home/ps/git/bpfrx/userspace-dp/src/session/mod.rs#L1241)) are prevented from surviving, while legitimate marks (including NAT64 and hairpin flows) are correctly maintained.

### Q3 (whole-plan sweep): SOUND
- **Evidence**:
  - The v10.4.0 folds properly close all highlighted execution traces without creating new state-machine or timeout leaks.
  - Section 11 questions are completely addressed by the stated design mechanisms.

### NEW TRACES
None.
