# Claude SMR — #1961 wire-type plan review, round 1

**Posture:** hostile domain SMR (CPU/serialization/Go-Rust interop). Verdict
below is deliberately NOT a self-rubber-stamp of my own plan.

**Verdict: PLAN-NEEDS-MINOR** — the root cause is proven and the design is
sound, but three strengthening items should be folded before `/engineer`.

## What holds up under hostile inspection

- **Root cause rests on ground truth, not on the EOF-vs-timeout argument.** The
  34,895-byte `apply_snapshot` JSON, built from `test/incus/xpf-test.conf` via
  the *real* `buildSnapshot()` path, makes `serde_json::from_str::<ControlRequest>`
  fail at `dscp_values` (`invalid type: string "Lg==", expected a sequence`),
  and rewriting that field to a numeric array makes the full request decode.
  This is reproducible and independent of any reasoning about socket deadlines.
  The live xpf-fwd journal (`publish userspace snapshot: EOF` repeatedly, then
  `apply_snapshot generation=3` only after the DSCP filter was stripped)
  corroborates it. Confidence in the cause: very high.
- **Audit is complete for the `[]uint8` class.** Exactly three `[]uint8` json
  wire fields in `pkg/dataplane/userspace` (protocol.go:194/205/417), each with
  a matching Rust `Vec<u8>` (cos.rs:47/64, security.rs:105). No `deny_unknown_fields`
  anywhere in `protocol/`, so the failure is a *type* rejection, not a missing
  field — consistent with the observed error.
- **Wire-compat reasoning is sound.** Every combination that changes goes
  broken→working: old-Go-base64 always failed for a populated field; new-Go
  numeric works against both old and new Rust (Rust always wanted a sequence).
  No persisted base64 blob exists for Go to read back (configstore stores Junos
  text; `ProcessStatus` carries none of these fields). No regression path.

## Required minor strengthening (fold into v2)

1. **Add a class-level regression guard, not just a value test.** A round-trip
   test on the three known fields prevents *this* regression, but a fourth
   `[]uint8` json wire field added later reintroduces the exact bug silently.
   Add a Go test (reflection over the snapshot wire structs) that fails if any
   exported field is `[]uint8`/`[]byte` with a `json:` tag — the project's
   "compile-time invariant" idiom. Cheap, and it closes the whole class.
2. **Actually perform the Q5 type-parity audit during `/engineer`, don't just
   list it.** `[]uint8` is one mismatch family; there may be a *second* latent
   wire-type mismatch (enum variant, int-vs-string, option handling) that only
   surfaces on a config no current smoke exercises. A bounded Go-struct↔Rust-
   struct field-by-field parity pass is in-scope, because shipping the DSCP fix
   and then hitting a different decode-EOF on the next config would be a poor
   outcome.
3. **Keep the superseded XSK-delivery plan referenced (not deleted) until
   §8.3 passes.** Q1 (does virtio forward once the snapshot publishes?) is
   genuinely open until the live transit test on a config with zones+policies.
   The plan says this; make it a hard gate — if §8.3 still shows 0 sessions
   after a clean publish, the XSK-delivery investigation reopens rather than the
   issue being declared fixed.

## Notes (non-blocking)

- Q8 (is a `/research` round warranted?) — honestly borderline for the code
  change alone; justified by the verification + guard + audit design. The user
  has already elected to re-plan, so this is moot, but I won't pretend the code
  diff is large.
- The pure-read `status` instrumentation (§3) is genuinely useful and should be
  folded into the fix PR, with the childless-leaf dispatch quirk fixed and
  `socket_queue_id` added to `FormatBindings` — but it is not on the critical
  path and must not gate the fix.
- §8.3 live verification must run on **Ubuntu 26.04** (production parity), not
  the ad-hoc 25.10 `xpf-fwd` VM — recreate it per `feedback_ubuntu_vms_always_2604`.
