PLAN NO

1. **BLOCKER — Mixed-version repair has no coherent completion rule.** For negotiated `repair-vN`, v9.9.43 correctly assigns applied `JOURNAL_END` to receiver readiness and matching `JOURNAL_ACK` to sender outbound/cold-prime discharge (`plan.md@7e7c90ced:1486-1508,2003-2017,3961-3987`). But new→legacy synchronization must be INSTALL-only, without `BulkEnd`, to avoid unsafe legacy reconciliation (`plan.md:3392-3411`). The legacy receiver therefore cannot return either `BulkAck` or `JOURNAL_ACK`, while the unqualified discharge rules require `JOURNAL_ACK`. A literal implementation leaves the new sender’s cold-prime/repair obligation armed indefinitely. Conversely, legacy→new requires the current `BulkEnd` readiness path at `pkg/cluster/sync_conn_read.go:241-247` → `pkg/daemon/daemon_ha_sync.go:90-100`, despite `plan.md:1729-1734` saying `BulkEnd` never discharges anything. Current state shows the consequence: unacknowledged outbound work blocks transfer readiness at `pkg/cluster/sync_bulk.go:218-242` and is repeatedly redriven at `pkg/cluster/sync_conn.go:572-618`.

   Required change: define a capability matrix:

   - `repair-vN`: applied `JOURNAL_END` clears receiver inbound/readiness; exact `JOURNAL_ACK` clears sender outbound/cold-prime.
   - Legacy→new full bulk: retain legacy `BulkEnd`/`BulkAck` completion.
   - New→legacy INSTALL-only prime: arm no negotiated repair obligation and clear cold-prime after successful lossless emission.

   Generic stragglers also remain at `plan.md:1447-1459,1756-1759,1928-1930,4279,4612-4617`.

2. **HIGH — The v1/v2 authentication transcript remains non-implementable as written.** Section 5.8 defines only v1-v1 and v2-v2 behavior (`plan.md:3917-3932`), not mixed v2↔v1 negotiation. Today v1 ignores the version field, reads its challenge from fixed bytes `payload[2:34]`, and always uses the nonce-only proof (`pkg/cluster/sync_auth.go:345-376,387-404`). The new declared field order places node/capability fields before nonces (`plan.md:3937-3942`); implemented literally, an old peer authenticates different bytes and proof verification fails at `sync_auth.go:401-404`, after which `sync_conn.go:106-110,435-477` closes and repeatedly reconnects.

   The v2 bytes are also ambiguous: no literal domain tag, record-order rule, length width/endianness, or proof-direction rule is specified. Additionally, `plan.md:3929-3932` correctly places proof before wrapper installation, but `:3933-3936` immediately says authentication occurs inside that wrapper; current code installs it only afterward at `sync_conn.go:100-118`. Specify byte-exact vectors, preserve the legacy HELLO prefix, make either-v1 select the v1 proof, and conservatively mask—or post-authenticate—all capability fields on a v1-proof connection.

3. **LOW — The new protocol boundaries lack explicit tests.** Section 9’s latest boundary inventory (`plan.md:4529-4562`) has no v2↔v1 interoperability, canonical transcript-vector, capability-masking, mixed-version discharge-matrix, pre-HELLO incarnation, or stale transition-CAS tests. These should accompany the contracts above.

Disposition r48-1: **partially resolved** — negotiated discharge direction is coherent; mixed-version completion is not.

Disposition r48-2: **partially resolved** — versioning and transcript concepts landed, but mixed-version selection and byte-exact authentication remain incomplete and contradictory.

Disposition r48-3: **resolved** — the metadata-only `s.mu` transition, post-unlock cleanup, transition-epoch CAS, live-lane cancellation, and per-identity reset high-water close the prior drain deadlock (`plan.md:1403-1435`; `pkg/cluster/sync_conn_read.go:14-17`; `pkg/cluster/sync_conn.go:480-494`).

Bottom line: Part A remains converged, and this round found no new blind-demotion or translated-tuple lifetime trace. Part B is not yet signable because its mixed-version repair path can leave readiness or cold-prime permanently armed, while its v2 authentication contract can prevent v1/v2 peers from connecting. The incarnation-transition fold itself is accepted.
