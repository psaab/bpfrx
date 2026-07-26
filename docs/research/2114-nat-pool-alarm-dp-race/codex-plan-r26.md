# Codex hostile plan-review — round 26 (plan v26 @ 1fda3b3c2)

Task: task-mrzn2yl4-p29s8i (session 019f96b4-30f2-7ad1-af45-907c26112bf3).
Verdict: NEEDS-REVISION (3 MAJOR, 1 MINOR; fold verification 2 FOLDED / 5 PARTIAL). Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The encrypted-confirm K→K′ authentication case is blocked at plan.md:1948-1969 and crypto.go:316-356. However, absent/malformed confirm slots bypass authentication entirely (db.go:242-264; crypto.go:366-394), leaving laundering paths open. Plaintext active validation itself does not over-block (crypto.go:307-314; db.go:348-400).

2. FOLDED — Every failed confirmed arm creates/re-keys W, D is suppressed while W pends, and confirmed-arm failure routes only to W at plan.md:1705-1715,1778-1810,2135-2146. This matches store_commit.go:503-553; plain commit and SyncApply arm no window (store_commit.go:228-247; store.go:697-760).

3. PARTIAL — The occupant-uncertainty rationale is correct at plan.md:1929-1938, but plan.md:1946-1947 immediately resurrects “the corrupt record’s owner is known.”

4. PARTIAL — Original-key restoration and the live-window deletion warning appear at plan.md:2235-2244, but the cause-blind health schema/messages at plan.md:2275-2302 cannot provide the promised key-specific guidance. The quoted key path is also wrong.

5. PARTIAL — The transient-seconds/deterministic-unbounded/no-post-crash-heal wording is correct at plan.md:3204-3215,3934-3938, but plan.md:1844-1851 still promises a seconds-wide, next-pass-restored window. Retries have no success guarantee and die at process exit (store_commit.go:611-628; store_persist.go:397-401).

6. FOLDED — plan.md:2245-2250,3965-3967 explicitly make ownership an operational one-xpfd assumption with no flock and a follow-up. The normal daemon constructs one Store, while Store/DB constructors enforce no process lock (daemon.go:1042-1053; store.go:296-319; db.go:37-70).

7. PARTIAL — Both x15 legs, both FirstCommit rationales, the principal generic message, and §5.1 seeding shorthand are repaired at plan.md:2044-2063,2296-2302,2333-2345,2511-2520,2771-2774,3506-3514. But plan.md:2848-2851,3024-3028 still omit slot-delete, and the W/D/x12 tables still authorize every permanent failure to write.

New findings:

MAJOR 1 — Observed-error-class validation still permits key laundering. A pre-rename arm failure creates W with an absent slot (plan.md:1705-1709,1725-1728). After K is replaced by valid K′, ReadConfirm returns absence without touching the key (db.go:242-253), then W restores using K′ through WriteConfirm/readOrCreateMasterKey (db.go:207-217; crypto.go:262-270,457-481). Because plan.md:1961-1969 requires active validation only after an observed key-class failure, W can clear while active.json remains K-encrypted; the next Load fails at store_persist.go:26-35. A malformed/too-new slot masks the wrong key similarly. Active validation must precede every W/D repair action and clear.

MAJOR 2 — The new validation rule creates an actionable D beside a live, durable window. A durable arm creates no W (plan.md:1705-1709) and normally clears D as moot (plan.md:2115-2117), but plan.md:1961-1966 forbids that clear if active validation fails. D suppression checks only for W (plan.md:1791-1803); no separate inert-D/key-health state exists. A later non-key permanent error therefore reaches d-i and overwrites/deletes the live record (plan.md:2097-2101). D must become independently moot, or remain suppressed whenever a live armedArmID exists.

MAJOR 3 — The executable taxonomy is contradictory. W and D repair every “PERMANENT-class” failure at plan.md:1772-1777,2097-2101,2479-2485,3477-3484, contradicting the key-class prohibition at plan.md:1948-1969. Master-key I/O is transient at plan.md:1916-1920,2101-2103,2513-2520,3506-3514 but permanent key-class at plan.md:1955-1959,3944-3949; crypto.go:443-465 confirms I/O and invalid length are distinct. The sole broad sentinel specified at plan.md:1983-1990 supplies no mechanical key/non-key discriminator.

MINOR 1 — Key remediation is both unrepresentable and misdirected. The exact three-field health state at plan.md:2275-2289 carries no crypto cause, and its prescribed messages at plan.md:2290-2302 never mention restoring the original key. Moreover, plan.md:2237-2240 names `/etc/xpf/master.key`; the default is `/etc/xpf/.configdb/master.key` (crypto.go:34-35; store.go:302-305; daemon.go:1047-1052).

NEEDS-REVISION

Codex session ID: 019f96b4-30f2-7ad1-af45-907c26112bf3
Resume in Codex: codex resume 019f96b4-30f2-7ad1-af45-907c26112bf3
