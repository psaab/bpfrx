# Reviewer task ledger - #6744

Base SHA: `ad959117748181dabe46b8ddc2827de670380cea`

## Source verification agents

- Group A: `019fc740-3164-7cf0-b320-9b234e0ba3c2` (completed)
- Group B: `019fc740-8b43-7e30-b8aa-34871c57e4f6` (completed)
- Group C: `019fc740-e66e-76e3-ab23-526b78363483` (completed)

## Hostile plan reviews

### Round 1 - plan commit `78891c3242a80b719bebdddc702087c07543e05b`

- Codex companion: `task-msd4pdsh-0u4bb0`; session
  `019fc752-45cb-7ce2-9e8e-95097ebc3624`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `86541`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY wrapper attempt `adversarial-review-msd4pdvi-cfuplm`: infrastructure
  invalid, command permission was auto-denied before review; not counted.
- AGY wrapper attempt `adversarial-review-msd4snv6-vn9m10`: infrastructure
  invalid, wrapper passed `--print-timeout` as the prompt; not counted.
- Claude Code CLI: attempted in detached worktree
  `/home/ps/git/xpf-worktrees/6744-plan-r1-claude`; failed before analysis with
  monthly-spend-limit error; no Anthropic verdict exists.
- SMR-method fallback agent: `019fc753-87a8-76d1-9a65-34c47efa84a3`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

A round is converged only when its valid reviewers agree on `PLAN-READY` or
`PLAN-KILL`. Infrastructure failures and malformed wrapper outputs never count
as reviewer verdicts.

### Round 2 - plan commit `01b67530e53016cf127d43c4a28c0582513718f8`

- Codex companion: `task-msd5ubyi-atsc3e`; session
  `019fc76f-546c-7400-a6a6-9f9d590a67a7`; verdict `PLAN-READY`.
- Codex companion attempt `task-msd5pnia-m84wjl`: infrastructure invalid;
  result was unavailable and no verdict is counted.
- AGY direct plan review: process session `7421`; verdict `PLAN-READY`.
- AGY sandbox attempt: process session `27597`; command permission was denied
  before analysis and no verdict is counted.
- Claude Code CLI: process session `64041`; failed before analysis with the
  monthly-spend-limit error; no Anthropic verdict exists.
- Independent SMR-method fallback agent:
  `019fc76c-3cfa-7393-88b1-2970cd07f410`; verdict `PLAN-NEEDS-MAJOR`. This is
  explicitly not represented as an Anthropic model review.

Round 2 did not converge: two reviewers returned `PLAN-READY`, while the
independent SMR-method review found material design gaps and returned
`PLAN-NEEDS-MAJOR`.

### Round 3 - plan commit `d746944992d3d91763e79498ba5bf5b139eff943`

- Codex direct hostile review: process session `1361`; reviewer session
  `019fc783-c0c7-7e13-b9e9-9e6e9c336aeb`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `16352`; verdict `PLAN-READY`.
- AGY attempts `79323`, `58624`, and `14333` were malformed, permission-denied,
  or help-only invocations and are not counted.
- Claude Code CLI: failed before analysis with the monthly-spend-limit error;
  no Anthropic verdict exists.
- Independent SMR-method fallback agent:
  `019fc784-3d6b-7aa3-b49a-ce3979b219b3`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 3 did not converge: AGY returned `PLAN-READY`; Codex and the independent
SMR-method review returned `PLAN-NEEDS-MAJOR` with convergent RG, peer-effective,
SNMP, DDNS, and confirm-recovery findings.

### Round 4 - plan commit `26843cb0f4870b89c4849bcb1f24ff7dc0ec658d`

- Codex direct hostile review: process session `69133`; reviewer session
  `019fc7a6-106a-7210-8797-a6e63e869f18`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `84223`; verdict `PLAN-READY`.
- Claude Code CLI: process session `45341`; failed before analysis with the
  monthly-spend-limit error; no Anthropic verdict exists.
- Independent SMR-method fallback agent:
  `019fc7a6-0d99-7d23-964f-90014234a599`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 4 did not converge: AGY returned `PLAN-READY`; Codex and the independent
SMR-method review returned `PLAN-NEEDS-MAJOR`. Their source-grounded blockers
cover DDNS fixed-mode and multi-cycle anchor authority, invalid persisted DDNS
families, compiler-equivalent RG normalization and pre-effect validation,
`FirstCommit` consistency plus confirm remediation, and the actual flat
`system snmp` shape and rejection/runtime lifecycle.

### Round 5 - plan commit `fdd7bbf06157ef18b295026d4b245c08c23e1090`

- Codex direct hostile review: process session `22870`; reviewer session
  `019fc7c7-881c-7181-a0e0-88b35f1d1b6b`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: valid output `/tmp/6744-agy-r5b.out`; verdict
  `PLAN-READY`. The earlier invalid invocation is not counted.
- Claude Code CLI: process session `44564`; failed before analysis with the
  monthly-spend-limit error; no Anthropic verdict exists.
- Independent SMR-method fallback: process session `2007`; reviewer session
  `019fc7c8-7fb4-7fa0-828e-a0e65451c2de`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 5 did not converge: AGY returned `PLAN-READY`; Codex and the independent
SMR-method review returned `PLAN-NEEDS-MAJOR`. The blocking roots are confirm
recovery classification/order, DDNS endpoint/provenance completeness, existing
SNMP compatibility and rejected-only diagnostics, the RG product domain and
mixed-version contract, and public `LoadOverride` behavior.

### Round 6 - plan commit `cab8851171889b6e97d518d6fe9540341fc942f7`

- Codex direct hostile review: process session `57655`; reviewer session
  `019fc7f3-5ec3-7363-a309-c78d0d6b6e3b`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: valid output `/tmp/6744-agy-r6d.out`; verdict
  `PLAN-NEEDS-MAJOR`. Three earlier invocations produced option-help or
  permission-denied output and are not counted.
- Claude Code CLI: process session `31570`; failed before analysis with the
  monthly-spend-limit error; no Anthropic verdict exists.
- Independent SMR-method fallback: process session `97542`; reviewer session
  `019fc7f3-a8e6-7991-b571-a6278971328a`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 6 converged only on rejection, not on a terminal `PLAN-KILL`: all valid
reviewers returned `PLAN-NEEDS-MAJOR`. The generalized DDNS teardown protocol,
commit-confirm transaction, SNMP normalization transport, and RG control versus
dataplane inventory require another design round. The narrow source-report
fixes remain viable.

### Round 7 - plan commit `c952d74ef6ea8bea994b44f1697b412353577d6d`

- Codex direct hostile review: valid output `/tmp/6744-codex-r7.out`; the
  direct process did not expose a durable reviewer-session identifier; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `46718`; valid output
  `/tmp/6744-agy-r7.out`; verdict `PLAN-READY`.
- Claude Code CLI: process session `84187`; failed before analysis with the
  monthly-spend-limit error; no Anthropic verdict exists.
- Independent SMR-method fallback agent:
  `019fc81e-a775-7061-b83a-214a6169c308`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 7 did not converge: AGY returned `PLAN-READY`; Codex and the independent
SMR-method review returned `PLAN-NEEDS-MAJOR`. The blocking roots are SNMP
normalization and structured client semantics, surface-aware DDNS state and
claim-release ordering, authoritative RG preflight and slot reuse, linearized
config/session application plus bulk recovery, persisted confirm-tree shape,
and the exact #6548 boundary.

### Round 8 - plan commit `bebffd32c7a0c2956a7eabbf584a92c6604ec5b2`

- Codex direct hostile review: process session `19554`; valid output
  `/tmp/6744-codex-r8.out`; verdict `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `73721`; valid output
  `/tmp/6744-agy-r8b.out`; verdict `PLAN-READY`. Earlier session `26940` was
  permission-denied and is not counted.
- Claude Code CLI: process session `4248`; failed before analysis with the
  monthly-spend-limit error; no Anthropic verdict exists.
- Independent SMR-method fallback agent:
  `019fc83c-f89b-7493-b8bc-c47473cf6dd8`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 8 did not converge. Codex, the independent SMR-method reviewer, and the
orchestrator's adversarial source trace found material config-incarnation,
legacy-zero, RG transition/full-replacement, authoritative-bulk,
repair-correlation, reconcile-error, SNMP-secret, DDNS durability, and
pre-#2903 compatibility gaps. AGY's `PLAN-READY` missed those traces. Revision
9 incorporates all valid findings before another immutable review round.

### Round 9 - plan commit `ff17e6351f0e0da4fc2ac0b45d0ecdd4c4b99be5`

- Codex direct hostile review: the first process session `97129` was stopped
  after it failed to produce a durable result; reviewer session
  `019fc86b-609d-74c1-9729-c00e73f13042` was resumed in process session
  `19413`. Valid output is `/tmp/6744-codex-r9-retry.out`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `5046`; valid output
  `/tmp/6744-agy-r9.out`; verdict `PLAN-READY`.
- Claude Code CLI: process session `55161`; failed before analysis with the
  monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent SMR-method fallback agent:
  `019fc86b-95fb-7a83-94db-6df880ed0beb`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic model
  review.

Round 9 did not converge. Codex and the independent SMR-method reviewer found
material one-fabric config-completion, readiness-timeout, old-receiver ACK,
RG0 safety-net, startup-authority, clustered helper-debt, capability setup,
repair-connection, and reconciliation-lifetime gaps. The orchestrator's
source trace additionally found used-but-disconnected send ordering, receive
lock ambiguity, cold-connect baseline ordering, config-sync protection,
capability/authentication staging, nontransactional partial-install wording,
all-capable-bulk authorization, and implementation-stack activation gaps.
AGY's `PLAN-READY` missed these executable traces. Revision 10 incorporates
all valid findings before another immutable review round.

### Round 10 - plan commit `103acbfd28115993f8f6393ed6b55d632bcfb4ee`

- Codex direct hostile review: process session `67056`; reviewer session
  `019fc888-0e86-7740-bcc4-c039440a6af2`; valid output
  `/tmp/6744-codex-r10.out`; verdict `PLAN-NEEDS-MAJOR`. The first direct
  attempt used a malformed quoted reasoning-effort value and produced no
  verdict; reviewer session `019fc885-9d97-7903-b4f4-e47f72598733` is not
  counted.
- AGY direct plan review: process session `6437`; valid output
  `/tmp/6744-agy-r10.out`; verdict `PLAN-READY`.
- Claude Code CLI: process session `98685`; failed before analysis with the
  monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent SMR-method fallback agent:
  `019fc885-9a87-7402-8b13-8a3535ec2cae`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic-model
  review.

Round 10 did not converge. Codex and the independent SMR-method fallback
converged on config-callback self-join, reentrant config-authority mutation,
and RG0 publication-before-authority blockers. Codex additionally found direct
HA actuator writers that bypass clustered helper debt. The fallback additionally
found uncancellable post-promotion config mutation and receive-worker
self-join. The orchestrator's hostile composition pass also found stale ACK
write ordering, missing pending peer-request ownership, one-way post-config
repair, authority-generation races, setup-auth ambiguity, readiness callback
ABA, request record-before-send, and unbounded request pressure. AGY's
`PLAN-READY` missed these executable traces. Revision 11 incorporates every
valid finding before another immutable review round.

### Round 11 - plan commit `e316e5b0c193f844289a6a6aeb505929108a550a`

- Codex direct hostile review: process session `65605`; reviewer session
  `019fc8a5-a289-7480-88b9-e470983d8faf`; valid output
  `/tmp/6744-codex-r11.out`; verdict `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `48585`; valid output
  `/tmp/6744-agy-r11b.out`; verdict `PLAN-READY`. Earlier session `29720` was
  permission-denied before analysis and is not counted.
- Claude Code CLI: process session `6546`; failed before analysis with the
  monthly-spend-limit error; no Anthropic-model verdict exists. An earlier
  malformed invocation produced no review and is not counted.
- Independent SMR-method fallback agent:
  `019fc8a6-0743-7dd3-8f23-d26873d7c21b`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic-model
  review.

Round 11 did not converge. Codex and the independent SMR-method fallback found
material config-replay ownership, all-RG authority, helper-status debt,
setup/protocol-worker lifetime, cluster-comms restart, notifier ordering,
exact bulk-token, callback self-transition, and raw-actuator gaps. AGY's
`PLAN-READY` missed those source-backed executable traces. Revision 12 closes
the complete union before another immutable review round.

### Round 12 - plan commit `1f1325f3348c5904e451e1e3b4dcd8cc8ec71bc6`

- Codex direct hostile review: process session `81167`; reviewer session
  `019fc8db-e071-79a1-9d83-ff8b412c2840`; valid output
  `/tmp/6744-codex-r12.out`; verdict `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: process session `54130`; valid output
  `/tmp/6744-agy-r12.out`; verdict `PLAN-READY`.
- Claude Code CLI: process session `18402`; failed before analysis with the
  monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent SMR-method fallback: process session `19503`; reviewer session
  `019fc8dc-53d4-7fc0-9aba-51b25ac6b933`; valid output
  `/tmp/6744-smr-fallback-r12.out`; verdict `PLAN-NEEDS-MAJOR`. This is
  explicitly not represented as an Anthropic-model review.

Round 12 did not converge. Codex and the independent fallback found material
heartbeat-snapshot, config/process namespace, peer-config preparation,
helper-request lifetime, final-fabric/setup, canonical-digest, counter
exhaustion, replay-ledger, and deadline gaps. The orchestrator's independent
composition pass additionally found lifecycle-coordinator self-membership,
missing local commit/rollback transaction APIs, ambiguous synchronous bulk
membership, helper-wrapper reentrancy, and underspecified prepare-activation
wire behavior. AGY's `PLAN-READY` missed these executable traces. Revision 13
incorporates the complete valid union before another immutable review round.

### Round 13 - plan commit `34619216673f66b1180274b50877f40628556999`

- Immutable checkout:
  `/home/ps/git/xpf-worktrees/6744-plan-r13-review`; detached, locked, and clean.
- Round-start issue comment:
  <https://github.com/psaab/xpf/issues/6744#issuecomment-5170899473>.
- Codex direct hostile review: process session `81696`; reviewer session
  `019fc922-7ab9-7541-a5f2-9dfe49e18b03`; valid output
  `/tmp/6744-codex-r13.out`; verdict `PLAN-NEEDS-MAJOR`.
- AGY direct plan review: valid output `/tmp/6744-agy-r13.out`; verdict
  `PLAN-READY`.
- Claude Code CLI: valid infrastructure attempt recorded in
  `/tmp/6744-claude-r13.out`; failed before analysis with the
  monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent SMR-method fallback agent:
  `019fc922-c521-77f3-a1d6-a4a78b20f01e`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic-model
  review.

Round 13 did not converge. Codex found urgent authority-mutator preemption,
receipt-waiter self-join, authoritative userspace bulk-source, and sparse replay
eviction blockers. The independent fallback converged on the bulk-source gap
and additionally found that helper result/event lifetime ended before final
generation-safe enqueue. The orchestrator's source audit also found that every
Rust-helper process replacement empties session state without invalidating
same-daemon continuity. AGY returned `PLAN-READY` with two valid nits for
test-duration injection and warning deduplication. Revision 14 incorporates the
complete valid union before another immutable review round.

### Round 14 - plan commit `df53c23111385e84178d4025788468e82b58d31a`

- Immutable checkout:
  `/home/ps/git/xpf-worktrees/6744-plan-r14-review`; detached, locked, and clean.
- Round-start issue comment:
  <https://github.com/psaab/xpf/issues/6744#issuecomment-5172060141>.
- Codex direct hostile review: process session `16721`; reviewer session
  `019fc994-5708-7cf2-b941-3a4bac5a70cf`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct hostile review: valid output `/tmp/6744-agy-r14.out`; verdict
  `PLAN-READY`. Earlier malformed and permission-denied invocations produced no
  review and are not counted.
- Claude Code CLI: valid infrastructure attempt recorded in
  `/tmp/6744-claude-r14.out`; failed before analysis with the account
  monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent non-Anthropic SMR-method fallback agent:
  `019fc995-e384-7373-a1fc-ee8cf891e0bd`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic-model
  review.
- Round synthesis:
  <https://github.com/psaab/xpf/issues/6744#issuecomment-5172300761>.

Round 14 did not converge. Codex found nonterminating legacy dual-publication,
unsafe NAT-reservation rollback, unproved worker-local delta loss, and omitted
static-DNAT/kernel-session capacity. The independent fallback found erased tail
tuple dependencies, local-tunnel/peer-authority provenance confusion, and
contradictory migration scope. AGY supplied valid migration-metric and SNMP
warning-key nits. The orchestrator additionally found the already-partial
legacy-map domain, cross-retry ambiguity-descriptor loss, and the causal early
maintenance-start/TailAck race. Revision 15 incorporates the complete valid
union before another immutable review round.

### Revision 15 pre-commit hostile design passes

- Design reviewer agent `019fc9b0-48a6-7ac1-a98b-666db50676aa` returned
  `PLAN-NEEDS-MAJOR`. It found that restart recovery trusted stale pinned cache
  rows, the rollback program identity was not crash-durable, replacement NAT
  needed separate incumbent/attempted reservation tokens, one global ambiguity
  journal could not represent concurrent admitted batches, and static-DNAT
  transition errors were not transactional.
- Protocol reviewer agent `019fc9af-ea73-7370-ad82-f954d9c94c24` returned
  `PLAN-NEEDS-MAJOR`. It found that the terminal sequence did not atomically
  partition the Go capture bank, private mutation events lacked pre-mutation
  authority, receive-tail work lacked independent frame/byte bounds, the
  proposed early-maintenance receive state was unreachable under the mandatory
  barrier, and provenance did not define legacy identity or safe demotion.
- The orchestrator incorporated the valid union before creating the immutable
  round-15 commit. It also corrected the capacity negotiation so a survivor can
  re-export both nodes' promoted authority to a restarted peer; local creation,
  receiver baseline, and transient tail capacity are now distinct fields.

These are pre-commit design reviews, not formal round-15 verdicts.

### Round 15 - plan commit `47b32a033e756316e5c24ba1e74442e58047968a`

- Immutable checkout:
  `/home/ps/git/xpf-worktrees/6744-plan-r15-review`; detached, locked, and clean.
- Round-start issue comment:
  <https://github.com/psaab/xpf/issues/6744#issuecomment-5172548142>.
- Codex direct hostile review: process session `37657`; reviewer session
  `019fc9d0-1acc-7f83-92ac-89ef061a8272`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct hostile review: process session `83588`; verdict `PLAN-READY`.
- Claude Code CLI: process session `38071`; failed before analysis with the
  account monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent non-Anthropic SMR-method fallback agent:
  `019fc9d1-0baf-74a2-bc0d-f6e0a82d9ff7`; verdict
  `PLAN-NEEDS-MAJOR`. This is explicitly not represented as an Anthropic-model
  review.
- Round synthesis:
  <https://github.com/psaab/xpf/issues/6744#issuecomment-5172635027>.

Round 15 did not converge. Codex found that sender-only release/acquire ordering
was erased by the receiver's mixed 256-operation batch, demotion hid rows before
the only valid handoff stream could export them, and static-DNAT transition was
named but operationally unbounded. The independent fallback found that static
DNAT was not atomic with config promotion, promoted replicas lacked one
canonical export owner, and same-key ordinary mutations could overlap across
the two fabrics. AGY returned `PLAN-READY`. Revision 16 incorporates the valid
union before another immutable review round.

### Revision 16 pre-commit hostile design passes

- Protocol/capacity reviewer agent `019fc9e6-8dd1-73f3-a5c4-5319f5d151f5`
  performed repeated hostile passes. Its initial pass found same-key releases
  missing from replacement escrow, contradictory `N+R`/tombstone accounting,
  persistent groups that could overflow the 384-operation request, and missing
  cross-fabric tuple-predecessor ordering. After those revisions it returned
  `PLAN-NEEDS-MAJOR` on five further traces: barrier-before-local-ACK stranded a
  predecessor; terminal repair could never satisfy local replay; an invariant
  incorrectly treated descriptor emission as remote proof; a full replacement
  was impossible at `R=1` because decoded rows charged the ledger too early; and
  one serial large-group plan deadlocked a two-group swap.
- Static/dataplane reviewer agent `019fc9e6-8e48-77c2-89d8-db817dd18dcf`
  performed repeated hostile passes. Its initial pass found mixed-generation
  XDP/TC readers, an unverifiable predecessor-root fallback, and non-atomic
  pin/manifest/control publication. After those revisions it returned
  `PLAN-NEEDS-MAJOR` because historical pinned readers made legacy DNAT deletion
  non-neutral, a prior-process orphan helper could race lookup/delete, and the
  promised persisted BPF hash cursor had no crash-safe protocol.
- The orchestrator independently corrected the capable barrier/ACK layout to
  the repository's little-endian codec, removed reliance on a nonexistent BPF
  compare-and-delete primitive, narrowed writes to a typed dynamic-only DNAT
  API, changed cross-key dependency entries from owners to non-owning waiters,
  required receiver-side aggregation of every frozen fabric marker before any
  ACK, and source-verified that the active userspace compiler already discards
  static-map writes while the separate historical static-NAT maps were never
  pinned.
- A later protocol pass found that generation barriers waited only on current
  mutation owners, so a non-owning descriptor waiter could be omitted and then
  mutate after ACK. The resulting draft allocates one generation-qualified
  `receiveBarrierAdmissionToken` in the read loop for every peer-wire lane and
  preserves it through waiter/dependency/owner transitions until final commit;
  barrier ACK scans all such tokens through G.
- A later static/dataplane pass closed the helper-retirement and cursor findings
  but found the deeper execution-quiescence flaw: replacing an XDP/TC link does
  not prove an old invocation has exited its RCU read-side critical section, so
  any in-place legacy DNAT deletion remains unsafe. The draft now performs one
  side-by-side forward-only migration of the v2 program, session map, and both
  discriminator-free dynamic-DNAT maps. It populates all v2 maps only from a
  stable coordinator serial, never reads or mutates old maps as authority,
  resumes only forward after the durable `forwardOnly` phase, and unpins old
  objects without lookup/update/delete. Historical invocations retain their
  kernel references and unchanged bytes until return.
- The orchestrator then source-verified that the retained userspace dataplane
  attaches no TC program. The final hook contract now selects the v2 program
  only for native/generic XDP and detaches every exactly owned legacy TC/TCX
  reader. A generated complete map-reference manifest, explicit held-FD
  `MapReplacements`, and full kernel program identities close implicit
  `PinByName`, pathname-reopen, short-tag, program-ID-reuse, and unclassified-map
  substitution paths.
- The integrated migration no longer treats a persisted digest or BPF hash-map
  iteration order as content proof. A fixed-credit walk requires every actual
  key/value to match coordinator-derived authority and requires exact
  cardinality; the stable-slot SHA-256 is diagnostic only.
- New-process recovery now quarantines every exactly owned prior XDP/TC/TCX
  hook with map-free typed drop programs before constructing a fresh XDP-only
  successor from restarted coordinator state. The journal records kernel boot
  identity and non-renewable `CLOCK_BOOTTIME` deadlines; expiry permits only
  bounded quarantine until an exact root-only forward-resume command renews the
  deadline. Old and superseded pins are unlinked only through a held root
  directory FD after comparing the full journaled object identity.
- The final protocol pre-commit pass returned `PLAN-NEEDS-MAJOR` because bounded
  lane storage alone did not supply bounded execution: synchronous receive-loop
  waiters could occupy both fabrics and prevent the predecessor Deletes that
  would wake them. The integrated draft now gives each capable transport one
  startup-owned 64-worker scheduler, an intrusive fixed ready FIFO, a fixed
  deadline/barrier coordinator, and read loops that only admit and enqueue.
  Dependency and same-key waiters consume no executor. Stop, replacement, and
  migration close admission and join the complete scheduler generation;
  migration additionally requires an empty arena/FIFO and zero ambiguity before
  map freeze. Its focused re-review of that integrated contract returned
  `PLAN-READY`.
- The final static/dataplane pre-commit pass returned `PLAN-NEEDS-MAJOR` on four
  historical-execution traces. Old XDP/TC programs can mutate session/DNAT maps
  after hook replacement; the kernel clears PROG_ARRAY targets when the last
  userspace reference disappears; the current in-place `bpf_link` update loses
  durable attachment ownership if its fixed alias and final FD close; and the
  draft had not defined a kernel-authoritative hook inventory. The integrated
  draft now treats old maps as isolated rather than immutable, pins one complete
  boot-scoped legacy root/map/PROG_ARRAY/tail-target capsule, gives every active
  BPF link a proved generation-owned pin before removing a legacy alias, and
  freezes a two-snapshot union of the root pin tree, BPF link IDs, RTM_GETLINK,
  RTM_GETTFILTER, Manager handles, and compiled expected hooks. Tests pause real
  tail-call fixtures before the call, close all ordinary references, permit a
  late old-only packet mutation, and prove both the historical target and v2
  isolation across every pin/link/journal crash boundary.
- Its focused re-review found two remaining kernel-model errors. The historical
  closure stopped at PROG_ARRAY and missed root -> CPUMAP/DEVMAP program edges
  plus the CPUMAP program's private tail-call array. It also assigned namespace
  identity from global `bpf_link_info`, which exposes ifindex but no netns. The
  intermediate draft walked a generated fixed point over PROG_ARRAY, CPUMAP, DEVMAP,
  DEVMAP_HASH, ARRAY_OF_MAPS, and HASH_OF_MAPS edges, rejecting unknown
  program/map-bearing types. Hook discovery performs TCX `BPF_PROG_QUERY` and
  RTM dumps inside the held namespace, correlates only the returned TCX link IDs
  to global info, and initially required root-pin/current-Manager proof for an XDP BPF link;
  same-ifindex cross-netns ambiguity fails closed.
- The next focused pass correctly rejected that last XDP exception: RTM exposes
  the program ID and global XDP link info exposes ifindex, but neither binds the
  link ID to a netns, so even a root pin can name the other namespace's same-
  ifindex/same-program link. The plan now requires a same-boot durable
  `{linkID,netns identity,hook,program,pin}` provenance record created before a
  new attachment becomes ready. A prior-process XDP BPF link without that record
  cannot be adopted or quarantined online and requires a proved clean reboot.
  The same pass also found and removed one stale `immutable-old-object` canary;
  the replacement permits capsule-local packet mutation while rejecting any
  userspace old-map access or v2/recovery effect. Its final focused re-review of
  the fixed-point closure, durable XDP namespace provenance/clean-reboot rule,
  cross-netns substitution test, and isolated-old-object contract returned
  `PLAN-READY`.
- The integrated draft also records remote barrier coverage independently of
  local ACK order; adds a generation-qualified terminal local-replay receipt;
  makes descriptors explicitly non-proofs; stages 128 incoming rows in the
  fixed journal and overlays exact old-to-new slot transitions; parks completed
  large groups before recycling the serial plan; and retires prior helper/socket
  owners under one inherited lifecycle lease.

These are pre-commit design reviews, not formal round-16 verdicts. The same two
agents were re-dispatched against the integrated draft before the immutable
round-16 commit.
