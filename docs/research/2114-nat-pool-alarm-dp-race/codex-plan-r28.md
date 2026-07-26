# Codex hostile plan-review — round 28 (plan v28 @ 7d772594f)

Task: task-ms1oasn4-40irsg (session 019f9e08-ae31-7190-b601-562535fbb2bd).
Verdict: NEEDS-REVISION (3 MAJOR, 3 MINOR; fold verification 2 FOLDED / 3 PARTIAL). Split ruling: (B) SPLIT — H+H2 follow-up must land BEFORE the A-G core merge unless G moves with it. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The three states and boot/runtime placements are explicit at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2227-2259`, matching absence at `pkg/configstore/db.go:319-330`. However, the R-kind match/mismatch actions at `plan.md:1823-1835` are omitted from the guard and x23 matrix (`plan.md:2955-2962`). The g-absent branch itself only fsyncs an already-absent slot, so it cannot delete a present live record; nevertheless, ENOENT proves no operator provenance (`db.go:302-330`), making “both-files operator intent” an unstated operational assumption.

2. PARTIAL — The no-create, same-key-byte design correctly closes `readOrCreateMasterKey` for the named W restores and D tombstones (`plan.md:2260-2283`; `db.go:207-217`; `crypto.go:262-270,443-479`). But “ALL” omits W’s `(w-a)` durable rewrite and R-kind tombstone/mismatch rewrite (`plan.md:1823-1835,1900-1919`), leaving those `WriteConfirm` producers on the original auto-create/check-write race.

3. FOLDED — The complete precondition appears at `plan.md:1966-1988,2405-2412`, with `(d-ii)/(d-iii)` gated at `plan.md:2441-2451` and both x22 legs at `plan.md:2943-2955`. SyncApply holds `s.mu` across cancellation and failure recording (`store.go:642-643,687-746`), so no intra-call actionable gap exists. Other `persistDegraded` setters can conservatively over-suppress D, but all represent uncertain active durability and self-heal loudly through `store_persist.go:367-386,419-428`.

4. FOLDED — Typed `ErrMasterKeyAuth` and `ErrMasterKeyLength` sources, both `errors.As` relationships, `%w` propagation, classification tests, and the `crypto.go` inventory are specified at `plan.md:2192-2214,2962-2971,3159-3171`, closing the current generic errors at `crypto.go:354-356,451-453,460-462` and `db.go:250-253`.

5. PARTIAL — The bool, x22, successful-restore wording, and superseded annotations exist, but stale contradictions remain: old three-field health copies at `plan.md:2617-2623,2861-2871,3915-3926,3987-4001`; old runtime key-class terminalization at `plan.md:2751-2756,3826-3830`; `crash-before-next-W` at `plan.md:703-704`; and an unconditional successful-arm D clear at `plan.md:2453-2457` despite the gated/inert rule at `plan.md:2405-2412`. Formal §9 also ends at x21 before item 3 (`plan.md:3987-4002`), omitting x22-x24.

New findings:

MAJOR 1 — The gate/no-create inventory still excludes retry-side `WriteConfirm` producers. W `(w-a)` rewrites the live record durably (`plan.md:1900-1919`), while R match/mismatch tombstones or rewrites the current record (`plan.md:1823-1835`); neither is included in the no-create list or x23/x24 (`plan.md:2265-2283,2955-2971`). Today every such call reaches the auto-create path (`db.go:207-217`; `crypto.go:262-270,457-479`). A key disappearance after validation can therefore create K′ and rewrite confirm.json while active.json remains K-encrypted. Enumerate every non-arm `WriteConfirm` producer and require the same active-gate/key-snapshot primitive.

MAJOR 2 — One byte snapshot does not prove that the installed key path remained unchanged. The plan claims a K→K′ race is impossible because validation and encryption consume the same bytes (`plan.md:2269-2274`), but `master.key` is an ordinary filesystem path with no lock (`crypto.go:443-479`), and the plan explicitly permits live operator restoration while admitting no flock (`plan.md:2575-2593`). Sequence: snapshot K, validate active under K, operator replaces the path with K′, write confirm under snapshot K, clear debt. Both files remain K-encrypted while the installed key is K′; health can turn green and the next Load fails. Key remediation must be explicitly offline/serialized, or path-generation stability must remain part of the retained health state.

MAJOR 3 — `ConfirmDebtKeyClass` cannot reliably carry the promised remediation. Multiple R debts plus W can coexist (`plan.md:1882-1887`), yet the singular bool is merely “populated at debt raise/retain” with no per-debt OR or clear rule (`plan.md:2651-2654`). Worse, boot authentication/length failure creates a terminal latch with no debt (`plan.md:2324-2325,2552-2555`); terminal precedence renders the generic corrupt-record message before the later debt-only key variant (`plan.md:2631-2660`). Carry key class per debt and on the boot latch, OR live causes in the snapshot, and clear each cause with its owning state.

MINOR 1 — The requested plaintext-active/encrypted-confirm K→K′ case is normatively retained with no write (`plan.md:2153-2159,2420-2431`), so the no-create primitive does not weaken the read-side rule. But the rationale incorrectly says the primitive blocks the operation: a plaintext tombstone intentionally performs no key access (`plan.md:2274-2283`; `crypto.go:262-265`). x24 tests classification and plaintext writing separately, allowing a bad branch ordering to pass both. Add the combined scenario and assert zero write/delete.

MINOR 2 — “bad nonce → non-key-class” is overbroad at `plan.md:2207-2212,2962-2967`. Bad encoding or nonce length fails before AEAD (`crypto.go:328-353`), but a valid-length tampered nonce reaches `gcm.Open` (`crypto.go:354-356`) and is indistinguishable from wrong-key authentication, hence key-class. Qualify the regression.

MINOR 3 — The successful-arm D rule remains ambiguous. The table says every D clear is inert while `armedArmID != ""` or another conjunct fails (`plan.md:2405-2412`), and x22 requires a durable arm whose blocked clear leaves D inert (`plan.md:2943-2949`), yet `plan.md:2453-2457` says any successful arm clears D unconditionally. State explicitly that arm-time clearing remains subject to the active gate; otherwise D stays inert until fresh reclassification.

Split ruling:

(B) SPLIT — Move H+H2 together into a named follow-up, “commit-confirmed recovery integrity and FirstCommit+cluster Load recovery,” seeded from v28. It must land BEFORE the A-G core merge unless G moves with it. G releases recovery only after phase 5 and manager construction (`plan.md:1343-1353`), while H says FirstCommit+cluster rollback is safe only at Load before `d.cluster` exists (`plan.md:1423-1433`). Landing G first can convert a short pre-manager timer into the known post-manager bootstrap-with-live-cluster hybrid. H cannot land alone because its correctness depends on H2 (`plan.md:1577-1603`).

NEEDS-REVISION

Codex session ID: 019f9e08-ae31-7190-b601-562535fbb2bd
Resume in Codex: codex resume 019f9e08-ae31-7190-b601-562535fbb2bd
