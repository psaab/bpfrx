# Triage Result: ps-review-040-A7-b1

- **Subsystem**: A7 batch 1 — daemon control-plane / HA session-sync (`pkg/daemon`, `pkg/cluster`)
- **Base == current master?**: Yes. Triaged against `origin/master` @ `95b33d49634d56086269a62a92e213dae7926f88` (fetched at triage time).
- **Repo**: real bpfrx (not the avacado-xpf fork). All cited symbols resolve on bpfrx master.
- **Findings in file**: 1 substantive (Finding 1, High) + 110 "negative result" entries (documentation of files swept with no finding — nothing to triage).
- **Outcome counts**: GENUINE-RESIDUAL 0 | NOT-MATERIAL 1 | ALREADY-FIXED 0 | DELIBERATE (overlap) 0 | CONFABULATED 0 | DUP 0.

---

## Finding 1 — "Concurrency race in handleEventStreamDelta vs fallback/reconciliation loop" (High) → NOT-MATERIAL

### Symbol existence / location
- Cited at `pkg/daemon/daemon_ha_userspace.go:579-581` and `:605-634`. Those line refs are **STALE**: on current master `daemon_ha_userspace.go` is only 74 lines (holds `buildZoneRGMap`/`rgHasRETH` only). The cited code was **split into `pkg/daemon/daemon_ha_userspace_stream.go`** (one of this session's cold-path Go refactor splits). The symbols themselves are REAL and present:
  - `wireUserspaceEventStreamCallbacks` sets `es.SetOnEvent(... d.handleEventStreamDelta ...)` at `daemon_ha_userspace_stream.go:153-154`.
  - `handleEventStreamDelta` body at `daemon_ha_userspace_stream.go:179-207` — and it is TRUE that it does **not** acquire `d.userspaceDeltaSyncMu` before calling `queueUserspaceSessionDeltas` (line 206). The drain paths DO hold it (lines 103-105, 305-307, 328-330).
- So the raw code fact ("handleEventStreamDelta bypasses the lock the drain loops hold") is accurate. Not confabulated. But the *consequence* claimed is not material. Four independent reasons:

### Reason 1 — It is NOT a data race (the "concurrency race" framing is wrong)
The finding labels this a concurrency race implying memory unsafety, but every piece of shared mutable state touched off `handleEventStreamDelta` is independently synchronized:
- `d.cluster`, `d.sessionSync` — set once at startup, read-only thereafter.
- `d.store.ActiveConfig()` — store has its own internal locking; returns an immutable snapshot.
- `buildZoneIDs(cfg)` / `userspaceSessionFromDeltaV4/6` — operate on the local `cfg` snapshot + local `delta`.
- `shouldSyncUserspaceDelta` (`daemon_ha_userspace_stream.go:23`) — reads only startup-immutable fields (`sessionSync.IsPrimaryForRGFn`, `ShouldSyncZone`) + local delta. No mutable shared state.
- `sessionSync.QueueSessionV4/QueueDeleteV4` → `stampInstallGenV4`/`takeDeleteGenV4` mutate `genSentV4/V6` **under `s.genSentMu`** (`sync_conn.go:79-86`, `:126-134`); the send is via `queueMessage` onto a channel; journal is under `deleteJournalMu`.

`d.userspaceDeltaSyncMu` is a **higher-level** lock whose documented purpose (`daemon.go:510-512`) is "serializes helper delta draining between the event-stream fallback loop and the background polling loop" — i.e. it stops two concurrent `DrainSessionDeltas` **control-socket** calls / double-draining the same helper buffer. `handleEventStreamDelta` performs **no drain** (it has its single pushed event in hand), so the reason the mutex exists does not apply to it. `go test -race` would not flag this path.

### Reason 2 — The logical reorder is the already-analyzed #2170 / #2221 design space
The finding's mechanism (steps 5-8: Close draws delete-gen 100, a stale Open then draws install-gen 101, standby applies 101 > 100 and resurrects the session) is the SAME reorder hazard that #2170 and #2221 were built to handle. The `takeDeleteGenV4` doc comment (`sync_conn.go:107-124`) explicitly names it:

> "the stamp and the sendCh enqueue are not atomic and **two producer goroutines** (the sweep stamping a live re-send, the delta-drain taking the close) mutate the same key, so a delete can be enqueued onto sendCh BEFORE the install it cancels."

The gen scheme was deliberately designed to be **reorder-safe without serializing the producers**: a delete draws a fresh generation strictly greater than every *prior* install of the key, so it out-ranks the install it cancels; a genuinely newer incarnation carries an even higher gen and still applies. The event-stream callback is simply a **third producer** feeding the identical `genSentMu`-protected machinery — it is inside the envelope #2221 already reasoned about, not outside it.

### Reason 3 — The proposed fix does NOT prevent the described failure (decisive tell of a misdiagnosis)
The fix direction is "acquire `d.userspaceDeltaSyncMu` in handleEventStreamDelta." Even fully serialized, the finding's own scenario still fires: if a stale Open for key K sits in the drain buffer and the Close for K arrives via the stream, then whichever path wins the lock first still produces `Delete(gen=100)` from the Close followed by `Install(gen=101)` from the drained stale Open → same resurrection. The mutex serializes the two goroutines; it does **not** discard a stale drained Open, nor force `install-gen < delete-gen` for the same incarnation. A fix that does not prevent the stated failure is strong evidence the mechanism is misattributed to the missing lock rather than to the (documented, accepted) gen-scheme residual.

### Reason 4 — Severity is overstated
The finding claims "unauthorized traffic … violating default-deny." The actual residual (#2170's own words) is **"stale-RETAIN rather than stale-delete"** — the intentionally-chosen fail-safe, because a wrongful *delete* kills LIVE traffic (worse). A leaked entry here is an *established* session for a 5-tuple that was legitimately open moments earlier — not admission of a new unauthorized flow. It lives only on the **standby** (which does not forward), and the standby's own session GC ages it out. It is not a default-deny bypass.

### Disposition
NOT-MATERIAL. Real code fact, but: (a) no data race — `genSentMu`/channel/store-snapshot cover all shared state; (b) the reorder is the #2170/#2221-analyzed multi-producer case whose residual is documented and accepted (retain-not-delete fail-safe); (c) the proposed mutex fix would not prevent the described resurrection; (d) severity overstated (standby-only, established-flow, GC-aged, not a default-deny bypass). Not a genuine, novel, reachable residual.

---

## Negative Results (items 1-110)
These are the reviewer's per-file "no finding" notes, not findings. No triage action; not counted.

## Genuine residuals
None. (Expected — A7/daemon HA-sync is among the most heavily hardened areas this session: #2170, #2198, #2221 gen-guard suite plus the cold-path split that relocated this exact code.)
