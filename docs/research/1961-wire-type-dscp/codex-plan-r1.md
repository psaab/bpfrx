# Codex adversarial plan review — #1961 wire-type, round 1

**Task:** task-mqjjyebz-g13x12 (3m6s). **Verdict: PLAN-KILL** — "Not because
the premise is wrong. The premise is correct. Kill the research loop and send
this straight to /engineer."

## Findings
- **Process:** more /research adds little; the remaining decisive question is
  live behavior after the wire fix, which needs implementation. Keep the PR
  scoped to wire fix + focused regression tests + helper decode-error logging +
  live virtio validation. Do not drag the status instrumentation in unless
  strictly needed for validation.
- **Overclaim:** title/early framing says XSK delivery is "refuted" / virtio
  "unblocked" before the post-fix transit test exists; later text correctly
  treats it as unproven. Reword early language to "proven current blocker", not
  "the only root cause".
- **Compat wording bug:** "Old Go -> any Rust already always failed" is too
  broad — it failed only when one of these []uint8 fields was populated;
  empty/omitted configs worked. Engineering conclusion (new Go numeric works
  with existing Rust Vec<u8>) still holds.

## Verification (root cause confirmed)
- Go encoding/json special-cases []uint8 -> base64 (encode.go); byte == uint8;
  base64("." ) == "Lg==" == DSCP EF 46.
- Rust expects plain Vec<u8> (cos.rs:46,63; security.rs:104) — no
  deserialize_with, no base64 adapter.
- Whole request dies before any response (from_str at handlers/mod.rs:66);
  accept loops discard the Err (lifecycle.rs:220,239); Go wraps as
  "publish userspace snapshot: EOF" (process.go:208, manager.go:678).
- Field audit complete: only []uint8 json wire fields are protocol.go:194,205,
  417. InjectPacketRequest is scalar metadata on both sides.

## Fix direction
- Option A, but name it generically (carries 802.1p code points too) — e.g.
  wireUint8List, not dscpByteList.
- MarshalJSON must NOT convert to []uint8 + json.Marshal (recreates the bug);
  convert to []uint16/[]int or write the array directly. Keep UnmarshalJSON;
  accepting legacy base64 on unmarshal is harmless.

## Test requirements
- Rust test must deserialize a full ControlRequest (not leaf structs).
- Go test must assert JSON token type is array (not substring contains).
- Inline JSON fine; separate Go-emits-arrays + Rust-decodes-full-request tests
  are enough.

## Q3/Q4
In scope as small hardening: log handle_stream decode errors in Rust in the
same PR; improve bare EOF if cheap, without expanding the fix.

**Final instruction:** implement now, then run the live virtio transit test. If
transit still fails after a successful apply_snapshot, resurrect the
XSK-delivery plan.
