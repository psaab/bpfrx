# #1961 — virtio "no transit" is a Go↔Rust snapshot wire-type bug (not XSK delivery)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Base:** origin/master (`fc4ba8eb7`)
**Issue:** #1961 (plain-virtio AF_XDP firewall does not forward transit). This
plan **supersedes** the prior converged plan
`docs/research/1961-virtio-xsk-delivery/plan.md` (PLAN-READY v1.3), whose
XSK-delivery / queue-bound / NAPI hypothesis is **refuted** by the diagnosis
below. `/research` only — no production code in this branch.

## 1. Issue framing

On a plain virtio incus VM the firewall does not forward transit. The prior
research localized this to "the redirect→XSK delivery layer" and proposed
diagnosing *which shim gate* drops the frame. That framing was **wrong**.

This session reproduced the failure end-to-end and found the real cause is
**upstream of the dataplane entirely**: the Go control plane's `apply_snapshot`
control-socket request **fails to deserialize on the Rust helper**, so the
helper never leaves bootstrap (`enabled:false`) and **no packet path is ever
armed**. The "virtio delivers 0 packets to the XSK" observation is an artifact
of measuring a dataplane that was never enabled.

### Proven root cause: `[]uint8` ⇒ base64 string vs Rust `Vec<u8>` ⇒ sequence

- Go's snapshot structs carry DSCP/code-point lists as `[]uint8`. Go's
  `encoding/json` **special-cases `[]uint8`/`[]byte` and emits a base64
  string**, e.g. `"dscp_values":"Lg=="` (`Lg==` = base64 of byte `46` = DSCP
  EF).
- The Rust `ConfigSnapshot` expects these as `Vec<u8>` — a **numeric JSON
  array** (a serde *sequence*).
- serde therefore rejects the value:
  `invalid type: string "Lg==", expected a sequence`. The failure aborts the
  **entire** `apply_snapshot` decode (not just the one field).
- `userspace-dp/src/server/handlers/mod.rs:66` returns `Err` from
  `handle_stream` *before writing any response*; the accept loop discards it
  (`let _ = handle_stream(...)`, `server/lifecycle.rs:221,239`) and the socket
  closes. The Go side (`pkg/dataplane/userspace/process.go:208`,
  `json.Decoder.Decode`) reads a clean FIN with no bytes → **`EOF`**, surfaced
  as `WARN "failed to compile dataplane" err="publish userspace snapshot: EOF"`.
- The `,omitempty` json tag is why this is config-dependent: an empty list is
  omitted from the wire, so a **stripped/minimal config publishes fine**, while
  any config that populates one of these fields fails **silently and totally**.

### The three affected wire fields (complete audit)

| Go struct (`pkg/dataplane/userspace/protocol.go`) | Field | Rust (`Vec<u8>`) |
|---|---|---|
| `CoSDSCPClassifierEntrySnapshot` (:194) | `DSCPValues []uint8` `json:"dscp_values"` | `protocol/cos.rs:47` |
| `CoSIEEE8021ClassifierEntrySnapshot` (:205) | `CodePoints []uint8` `json:"code_points"` | `protocol/cos.rs:64` |
| `FirewallTermSnapshot` (:417) | `DSCPValues []uint8` `json:"dscp_values"` | `protocol/security.rs:105` |

These are the **only** `[]uint8`/`[]byte` json wire fields in
`pkg/dataplane/userspace`. (`inject_packet` does not use a `[]byte` json field —
to be re-confirmed at implementation, see Q6.)

### Evidence (all reproduced VM-free + corroborated live)

1. Dumped the exact 34,895-byte `apply_snapshot` ControlRequest JSON the daemon
   builds from `test/incus/xpf-test.conf` (the config xpf-fwd ran) via the real
   `buildSnapshot()` path.
2. `serde_json::from_str::<ControlRequest>` panics at the `dscp_values` field
   (column 10081): `invalid type: string "Lg==", expected a sequence`.
3. Rewriting that one field to a numeric array → the **full request decodes
   OK** → `dscp_values` is the sole blocker for this config.
4. Live journal on xpf-fwd: repeated `publish userspace snapshot: EOF`; the
   first `CTRL_REQ: apply_snapshot generation=3` succeeded only **after** the
   config was stripped of the DSCP filter.
5. `xpf-test.conf:397` `filter dscp-filter { term mark-ef { ... dscp ef } }`
   populates `FirewallTermSnapshot.DSCPValues=[46]`. `cos-iperf-config.set`
   (loss cluster) defines **no** classifier/dscp/code-points → none of the 3
   fields populated → the loss cluster always published & forwarded fine. This
   is why the bug was invisible on the only smoke environment.

## 2. Honest scope / value framing

The win is large and was badly mislabeled:
- It unblocks **plain-virtio as a forwarding venue** (every default
  incus/qemu/cloud VM), which is high value for image validation and
  bare-metal-ish testing.
- It fixes a **general latent bug**: any production config with a DSCP firewall
  filter, a DSCP classifier, or an 802.1p classifier silently fails to forward
  **anything**, with only a misleading `EOF` in the log. This is not
  virtio-specific.
- It retires a multi-session false trail (#1928 "rx=0 invariant across
  kernels/bind-modes"; the helper was never enabled).

*If reviewers conclude the code fix is mechanical enough that a research round
adds no value, that is a fair verdict — but the value here is the **regression
test + verification design + error-visibility hardening**, not the one-line
type change. PLAN-KILL is acceptable if reviewers think even those are
unjustified; the diagnosis stands regardless.*

## 3. What is already done / carried forward

- **Diagnosis** (this session): root cause proven; the prior XSK-delivery plan
  is superseded by this doc.
- **Pure-read `status` instrumentation** (uncommitted on
  `engineer/1961-virtio-xsk-delivery`): a `request chassis cluster data-plane
  userspace status` subcommand (`pkg/cli/cli_request.go`) + cmdtree leaf
  (`pkg/cmdtree/tree.go`) that surface the binding/XSK inventory + degraded-path
  counters without mutating dataplane state. Useful observability — proposed to
  carry into the fix PR (with the childless-leaf dispatch quirk fixed and
  `socket_queue_id` added to `FormatBindings`). Reviewers: in or out of scope?

## 4. Concrete design (fix shape deferred to quad-review)

Rust stays `Vec<u8>` (already correct — it always wanted a numeric array). The
fix is on the **Go** side so it stops emitting base64 for these 3 fields.

- **Option A — named type + custom (Un)MarshalJSON.** Define one Go type over
  `[]uint8` (e.g. `type dscpByteList []uint8`) with `MarshalJSON` that emits a
  numeric array `[46]` and `UnmarshalJSON` that parses one (and, defensively,
  still accepts a base64 string so Go's own round-trip / any persisted blob is
  tolerant). Change the 3 fields to that type. Assignment sites
  (`filters.go:89,91`, `cos.go:58`) keep assigning `[]uint8{…}` (assignable to a
  named type with that underlying type → no caller churn). Self-documenting,
  type-safe, uniform.
- **Option B — `[]uint16`.** Change the 3 fields to `[]uint16`; Go marshals
  **and** unmarshals these as numeric arrays natively (no custom marshaler).
  Rust `Vec<u8>` decodes `[46]` cleanly (values ≤ 63). Mechanical churn at
  assignment sites (`[]uint8{val}` → `[]uint16{uint16(val)}`) and any readers.

Both keep the Rust side untouched. **The quad-review picks** (Q2).

Separately, two hardening items the bug exposed:
- The helper **silently discards** `handle_stream` errors (`let _ =` at
  `lifecycle.rs:221,239`). Logging that `Err` (decode/read failure) would have
  collapsed this multi-session chase to one line. Proposed: log it (Q3).
- The Go side surfaces a bare `EOF`. Proposed: when the control socket closes
  with no response, emit a more actionable hint (Q4).

## 5. Public API / wire-compat preservation

The wire encoding of these 3 fields changes from base64-string to
numeric-array. Compatibility analysis (reviewers verify, Q7):
- **Old Go (base64) → any Rust**: already always failed (the bug). No working
  combination is regressed.
- **New Go (numeric) → old Rust**: old Rust already expects a sequence →
  **works** (this is in fact the first time it works).
- **Rust → Go direction**: these fields are Go→Rust only (CoS/firewall
  snapshots). `ProcessStatus` (Rust→Go) does not carry them. No reverse path.
- **Mixed-version HA rolling upgrade (#1917)**: must confirm a node pinned to an
  old helper binary isn't newly broken. Argued safe (old helper wanted a
  sequence anyway), but this is an explicit review item.

## 6. Hidden invariants the change must preserve

- DSCP (6-bit, 0–63) and 802.1p code-points fit in `u8`/`u16` — no truncation.
- List **ordering** must be preserved (classifier/rewrite semantics depend on
  entry order, though the per-entry list is a set of code-points).
- Go round-trip: if Option A adds `MarshalJSON`, it MUST add a matching
  `UnmarshalJSON` or Go-side round-trip tests / state reload break.
- No hot-path impact: these are compiled once per config commit, never
  per-packet.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Mechanical wire-encoding fix; Rust unchanged; covered by a round-trip test. |
| Lifetime / borrow-checker | N/A | No Rust change. |
| Performance regression | LOW | Config-commit-time only, not per-packet. |
| Architectural mismatch (#961/#946-P2 dead-end) | LOW | Not a refactor; a correctness fix to a proven bug. |
| Wire/mixed-version | MED | Encoding change — §5/Q7 must be verified, not assumed. |

## 8. Test plan

1. **Self-contained Go↔Rust round-trip regression** (the headline gap — the
   prior bug shipped because no test exercised a populated `dscp_values` over
   the wire):
   - Go: build a `ConfigSnapshot` with a firewall term + a DSCP classifier + an
     802.1p classifier all populated; `json.Marshal`; assert each field is a
     numeric array (not a base64 string).
   - Rust: deserialize the **same bytes** into `ControlRequest`; assert the
     three fields equal the expected `Vec<u8>`. Embed the JSON inline (no
     `/tmp` dependency).
2. `cargo test --release` full suite + 5× flake on the new test; `go test ./...`.
3. **Live virtio verification on xpf-fwd** (standalone, plain virtio):
   - Restore the full `xpf-test.conf`; confirm `apply_snapshot` now publishes
     (`enabled:true`, generation increments, no `EOF` in the journal).
   - **Run a real transit-forwarding test** through a zone pair with a permit
     policy and confirm sessions are created + bytes forwarded. This is the
     decisive answer to the residual question (Q1): does virtio actually forward
     once the snapshot publishes, or is there *also* an XSK-delivery issue
     underneath?
4. **Loss-cluster smoke (no regression)**: standard Pass A (CoS off) + Pass B
   (CoS on), v4+v6, push+reverse. Additionally exercise fields 194/205 by
   adding a DSCP/802.1p classifier to a smoke config and confirming it publishes
   and forwards.

## 9. Out of scope (explicitly)

- The XSK-delivery / queue-bound-stranding / NAPI investigation from the prior
  plan. Only reopen if §8.3's transit test **still** fails after the snapshot
  publishes (Q1). Captured as a fallback, not the primary work.
- The `status` instrumentation polish (childless-leaf dispatch, `socket_queue_id`)
  unless reviewers fold it in (§3).
- A broad serde/JSON fuzz of the whole wire surface (Q5 is a targeted audit, not
  a fuzz campaign).

## 10. Open questions for adversarial review (invite PLAN-KILL on any)

- **Q1 (decisive):** Once `apply_snapshot` publishes on virtio, does the
  dataplane actually forward transit, or is there a *second*, independent
  XSK-delivery bug? The plan assumes the wire fix is sufficient but mandates a
  live transit test to prove it. If reviewers believe a residual XSK bug is
  likely, the plan should keep the old diagnosis plan armed.
- **Q2:** Fix shape — Option A (named type + Marshal/Unmarshal) vs Option B
  (`[]uint16`)? Round-trip and mixed-version implications.
- **Q3:** Should the helper stop silently discarding `handle_stream` `Err`
  (`lifecycle.rs let _ =`)? In scope for this PR or a separate hardening issue?
- **Q4:** Should Go translate a "socket closed with no response" into a more
  actionable error than bare `EOF`?
- **Q5:** Beyond `[]uint8`, are there other Go↔Rust **type-parity** mismatches
  on the snapshot wire (enum variants, int-vs-string, optional handling) that
  could fail the same way on some unexercised config? Worth a bounded parity
  audit?
- **Q6:** Confirm `inject_packet` (and any other control verb) has no
  base64-by-design `[]byte` field that the fix would wrongly "correct," and no
  symmetric field that *should* stay base64.
- **Q7:** Mixed-version HA rolling upgrade (#1917): is a node pinned to an old
  helper binary regressed by the encoding change? (Argued no in §5.)
- **Q8:** Is a full `/research` round even warranted for a mechanical wire fix,
  or should this collapse straight to `/engineer`? (Honest self-check per §2.)
