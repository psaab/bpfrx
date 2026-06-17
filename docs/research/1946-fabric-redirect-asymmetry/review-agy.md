# AGY adversarial plan review, #1946

- r1 job: `adversarial-review-mqi87f3t-vf66ct` — Verdict **PLAN-NEEDS-WORK**.

## r1 findings

1. **CRITICAL — wire specimen fixture omission breaks cargo tests.**
   Adding a field to `BindingStatus` (`protocol/binding.rs`) without
   regenerating the checked-in specimen makes
   `wire_invariant_default_specimens` (`protocol/tests.rs:1083`) fail.
   Fix: regenerate `userspace-dp/tests/fixtures/protocol_wire_v1.json`
   via `XPF_PROTOCOL_WIRE_REGEN=1 cargo test ... wire_invariant_default_specimens`
   in the same commit. **Accepted — added to plan §4.** (Confirmed: the
   fixture already carries `tunnel_encap_unresolved_drops`.)

2. **HIGH — FabricRedirect build-failure cascades to wrong-path
   reinject.** Binding present but frame build fails →
   `fallback_to_slow_path = true` → `handle_forward_build_failure` →
   unfiltered `maybe_reinject_slow_path_from_frame` → local kernel FIB.
   Same wrong-path / conntrack-poison hazard the fix targets.
   **Accepted — same as Codex r1 HIGH; gated in
   `handle_forward_build_failure` (plan §3/§4).**

3. Owned-vs-Live semantics + borrow-checker validation: AGY concurred
   the drop block has no borrow hazard and that the two frame kinds are
   representations of one canonical packet (Owned = GRE-decap copy), so
   representation must not change FabricRedirect disposition policy.

## r2

Re-review dispatched after plan update (expanded scope to the
build-failure gate, single `fabric_redirect_unsendable_drops` counter,
wire-fixture regen step, fail-closed framing). Verdict pending.
