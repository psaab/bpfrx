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

### Round 16 - plan commit `0533766f6dda9f71268314e67dc83d5ff4d6bfbb`

- Immutable checkout:
  `/home/ps/git/xpf-worktrees/6744-plan-r16-review`; detached, locked, and clean.
- Round-start issue comment:
  <https://github.com/psaab/xpf/issues/6744#issuecomment-5174100507>.
- Codex direct hostile review: process session `40295`; verdict
  `PLAN-NEEDS-MAJOR`.
- AGY direct hostile review: valid retry process session `69232`; verdict
  `PLAN-READY`. The first invocation supplied flags in the wrong argument order
  and returned a generic CLI-mode explanation; it is invalid and not counted.
- Claude Code CLI: process session `11709`; failed before analysis with the
  account monthly-spend-limit error; no Anthropic-model verdict exists.
- Independent non-Anthropic SMR-method fallback agent:
  `019fcab9-43f6-75c1-9e68-76c3dad9e54d`; verdict `PLAN-NEEDS-MAJOR`.
  This is explicitly not represented as an Anthropic-model review.

Round 16 did not converge. Codex found a mutable post-receipt historical object
graph, missing last-owner semantics for shared BPF projections, contradictory
baseline/tail execution ownership and heartbeat starvation, an unobservable
`expectedAttachType` identity field, incomplete off-config hook discovery, no
terminal dependency-waiter timeout transition, a nine-worker capacity overflow,
and no implementable same-connection paired config/request write. The
independent fallback additionally found destructive startup cleanup before
inventory/capsule capture and the native mlx5 fresh-attach contradiction; its
off-config hook finding converged with Codex. AGY returned `PLAN-READY`.
Revision 17 incorporates the complete valid union before another immutable
review round.

### Revision 17 pre-commit architecture passes

- Kernel/AF_XDP migration architect agent:
  `019fcad0-089e-7293-b13b-fa79a511c037`; read-only against immutable round 16;
  conditional `PLAN-READY` after requiring complete old/new map-ID disjointness,
  non-destructive pre-`Manager.Load` recovery, finite runtime-semantic
  historical manifests, full namespace hook inventory, the durable forward-only
  journal state machine, and guard-plus-interface-down fresh XDP attachment with no retained-
  link retarget operation.
- HA/session protocol architect agent:
  `019fcad0-090e-7b51-8316-ec61e1f209e1`; read-only against immutable round 16;
  conditional `PLAN-READY` after requiring compatible shared-key owner counts,
  admission-only receive loops with explicit chunk credit/control priority,
  atomic not-started waiter transfer, fixed capacity behavior, and one bounded
  same-connection config/request writer.
- The orchestrator selected checked runtime map sizing with actual map-create
  preflight rather than the second architect's proposed hard eight-worker HA
  product limit. Revision 17 explicitly tests the nine-worker 10,485,764-row
  boundary, rejects `MaxUint32`/memory/resource overflow before publication, and
  leaves final acceptance of that tradeoff to the formal hostile reviewers.
- Both architect agents were closed after their findings were incorporated; no
  production file, issue, PR, or implementation was created.

#### Revision 17 pre-commit hostile design review 1

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit.md`; SHA-256
  `e687a32dfe27b57438fc9766d89c5a4f1b3fa1c99dc37c4e8ec0feaf127f3687`.
- Kernel/dataplane design reviewer: `019fcae9-10c4-7500-8034-6268dee5716c`;
  verdict `PLAN-NEEDS-MAJOR`. It required an exhaustive packet-authority map
  classification, generation-disjoint map publication, independent physical-
  interface and binding-readiness edges, explicit `PASS_TO_KERNEL` removal,
  and raw classic-TC ingress/egress shared-block discovery.
- HA/session design reviewer: `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`;
  verdict `PLAN-NEEDS-MAJOR`. It required a Manager-created registry that owns
  and joins the complete daemon runner epoch, feature-subepoch receipts for
  day-2 changes, and one atomic peer-config transaction whose ACK follows both
  packet-runtime and Manager publication.
- Whole-plan/API design reviewer: `019fcae9-d9d7-74b2-8a9d-a78022f076e3`;
  verdict `PLAN-NEEDS-MAJOR`. It required mutation-free Prepare separated from
  a typed Begin outcome that always preserves post-negative recovery state,
  and a Manager-owned terminal shutdown union that cannot reconstruct old
  opaque receipts or make callers guess the live state class.
- Follow-up design passes from the same three reviewers refined the required
  API shapes. The orchestrator integrated their valid union, rejected an
  alternate classifier-map sketch that used unsafe `BPF_F_NO_PREALLOC` and
  published authority after control, then performed an independent consistency
  audit. That audit also split physical-interface activation from per-binding
  XSK readiness, chained runtime selection/publication receipts to the complete
  map-set identity, and replaced the optional shutdown epoch-stop argument with
  a Manager-minted terminal epoch-union receipt.

#### Revision 17 pre-commit hostile design review 2

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-2.md`; SHA-256
  `9f6bae7d67dce667c079cfc5ca1cdf1aa7c9154f4039b3f4eb21b73b671c6013`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It found volatile qdisc statistics in the ownership digest, an unspecified
  mlx5 challenge-map/matcher contract plus contradictory timeout policy,
  assertion-only AF_XDP owner absence, an impossible private Go receipt
  constructor across `pkg/dataplane` and `pkg/dataplane/userspace`, two tests
  that contradicted Linux map-in-map synchronization/quiescence, and a 48-byte
  verification bound for the 56-byte v2 control row.
- HA/session design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict
  `PLAN-NEEDS-MAJOR`. It found normal replacement joining the daemon epoch
  before Manager's shared negative activation edge, runner wake before the
  activation release-store, peer callback lifetime ending before final
  publication/ACK authority, no transport-independent post-commit recovery
  owner, and feature rollback receipts that could not represent a fresh
  predecessor branch.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict
  `PLAN-NEEDS-MAJOR`. It independently found daemon producer closure before the
  first Manager negative config edge, the same unrepresentable feature rollback,
  and a config-authority Prepare API that required a SessionSync transport even
  in unavailable, boot-empty, and standalone state classes.

The integrated draft makes Manager retirement-begin the first replacement
negative edge, preloads activation before waking runners, gives peer apply one
Manager-created publisher and a daemon-lifetime recovery transfer, and prepares
fresh target/rollback feature children before stopping the predecessor. Config
authority is now transport-independent with exhaustive state-class behavior.
Kernel migration now hashes canonical structural qdisc attributes while
excluding named volatile statistics, defines exact expected/counter challenge
map ABIs and one `deferredChallengeUnavailable` policy, proves AF_XDP ownership
through stable `AF_XDP` socket-diag plus `/proc` correlation, and mints runtime
receipts through a base-package issuer. The next hostile pass corrected the
intermediate draft's kernel model; the final contract is recorded below.

#### Revision 17 pre-commit hostile design review 3

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-3.md`; SHA-256
  `1892644ae9468a5c640365132f359bdf0da9a974f1fb91680f322e8f6c9958e8`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It corrected the prior ledger's map-in-map claim: the outer pointer update
  returns while a paused BPF reader retains the displaced inner, so syscall
  completion is not a quiescence receipt. It also found that AF_XDP diag omits
  `XSK_UNBOUND`, the bootstrap challenge referred to a runtime generation that
  does not yet exist, queue-qualified challenge generation could miss RSS queue
  swaps, classic-TC identity omitted protocol, and the challenge counter ABI and
  lifecycle were incomplete.
- HA/session design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict `PLAN-NEEDS-MAJOR`.
  It found that feature target selection could destroy rollback before the
  irreversible authority decision, the daemon and Manager publication domains
  had no single observable positive edge, recovery transfer could remove a
  callback from transport join before its stack returned, daemon shutdown did
  not join recovery workers, applied-without-ACK lacked a typed replay-only
  transition, prepared/unarmed config handling was contradictory, and
  no-feature-delta commits used the broad authority generation.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict `PLAN-NEEDS-MAJOR`.
  It independently found destructive feature rollback ordering, fallible abort
  work after positive gates opened, arbitrary callback-based positive
  publication, unconstructible cross-package runtime-view types, unenforceable
  exported value invariants, and the incorrect PR-count claim.

The orchestrator self-corrected every valid finding before snapshot 4. The plan
now uses a journaled nonzero bootstrap generation independent of later runtime
authority; all-process AF_XDP FD plus conservative AF_UNIX rights-queue census;
queue-independent RSS tuple/nonce cloning with Toeplitz targeting; complete
classic-TC filter identity; preseeded checked per-CPU counters; and immediate
map-in-map update completion followed by explicit production quiescence. It
uses private-field configstore/cluster values, concrete Manager-owned transport
and config publication cells with daemon preload before one positive CAS,
durable ACK-outbox phases, split mutation/execution callback ownership, a
daemon-lifetime recovery registry, typed applied-without-ACK replay, an
irreversible target-decision receipt before branch retirement, fully fallible
rollback before the previous cell reopens, and mandatory prepared/unarmed
normalization before config Prepare. The child/PR topology is 13 child issues
and 16 implementation PRs.

#### Revision 17 pre-commit hostile design review 4

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-4.md`; SHA-256
  `ce6fcd27b9ce7f699626eac42caa8270880ec123aae7e9897b8efcf960c3794a`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It live-grounded a zero-payload `SCM_RIGHTS` escape from the AF_UNIX queue
  census, fixed and in-flight io_uring file-reference escapes, mutable nested
  TC-action data in the proposed structural digest, and incomplete RSS/hash-
  field plus pre-up corpus construction.
- HA/session design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict `PLAN-NEEDS-MAJOR`.
  It found a shutdown/adopted-callback deadlock, a recovery record unable to
  carry its required opaque state, dynamic recovery workers incompatible with
  the sealed lifetime registry, and recovered publication that could lose its
  ACK obligation.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict `PLAN-NEEDS-MAJOR`.
  It found self-attested publication preload, publicly mutable RG snapshots,
  incomplete runtime-authority predecessor issuance, no bilateral-baseline
  receipt issuer, a circular daemon-lifetime runner contract, stale test APIs,
  and the decisive scope defect: K003-10 had absorbed a new HA protocol, session
  store, map migration, helper lifecycle, capacity model, and binary floor that
  do not share the reported invalid-binding root cause or rollback boundary.

The orchestrator self-corrected the architecture rather than continuing to add
proof types to an unjustified design. The expanded SessionSync, stateful-map,
AF_XDP/hook, helper-lifecycle, ACK-outbox, migration-journal, and binary-floor
work was removed in full. K003-10 is now one bounded child/PR: reject explicit
dataplane owner bindings outside 1..15 before mutation, preserve legal unbound
control definitions through 255, feed fixed-slot writers from one validated
inventory, document the limit, and run RG15 plus rejection smoke. Snapshot-4
findings against the removed architecture are therefore **moot, not fixed**;
they remain research leads only if an independently evidenced future issue
proposes those mechanisms. The plan topology is corrected to 13 child issues
and 13 PRs.

#### Revision 17 pre-commit hostile design review 5

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-5.md`; SHA-256
  `43d836ec54a27178dab3c724d200545438a374aaf3668896115ddf7abb4b5fc5`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It found that legal control-only RGs still entered every daemon actuator loop,
  creating permanent apply debt and watchdog log storms, and that the proposed
  owner inventory had no generation-transactional publication or safe removal
  protocol. It required separate candidate/applied inventories, previous+target
  transition authority, clear-before-forget, post-ACK publication, and explicit
  unbound-to-bound replay.
- HA/compiler design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict `PLAN-NEEDS-MAJOR`.
  It found that typed zero cannot distinguish explicit RG0 from omission, a
  target-only inventory cannot clear an old owner slot, both-node proof was not
  wired through every compiler/store path, raw gates ignored repeated-section
  reduction semantics, and stale peer configuration made any new takeover
  unsafe. It also required smoke coverage for those exact transitions.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict `PLAN-NEEDS-MAJOR`.
  It found a cyclic B/C compiler API and false independent-PR/revert claim,
  unspecified SNMP evaluation constructor/update plumbing and copy ownership, a
  public `RejectedV3Users` schema change that contradicted the preservation
  contract, and independently confirmed the control-only RG actuator conflict.

The live revision candidate now treats typed zero only as omission while the raw
gate rejects explicit zero; reduces each raw section with its exact dispatcher
semantics; routes every public compile/store path through one both-node prepared
pipeline; and blocks all new takeover while peer-generation debt exists. RG
actuation uses generation-stamped staged/applied inventories, a previous+target
transition set, negative clear/readback before target publication, post-ACK
commit, cleanup debt, and explicit unbound-to-bound replay across every daemon
event/reconcile/watchdog/fence/shutdown loop. Compiler workstream B now owns a
neutral prerequisite pipeline that does not name C/I/M types, incorporates the
existing peer-effective SNAT proof without recursive compilation, and declares
dependent merge/revert ordering. SNMP evaluation now has exact immutable,
deep-copy constructor/update APIs and compatibility wrappers; production boot
and day-2 callers consume one precomputed evaluation. Rejection metadata remains
an internal Config sidecar plus existing warnings/logs, with no JSON/YAML/REST/
gRPC/CLI schema change. These are candidate corrections pending snapshot-6
hostile validation, not accepted closures.

#### Revision 17 pre-commit hostile design review 6

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-6.md`; SHA-256
  `2d2ab7f33e4ce9e49b2d94af834ffbe3c4943610f6f119aa741e608530f75ed2`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It found that a lost apply response can leave Rust on the target while Go
  claims previous-good, that the proposed pre-ACK row clear had no executable
  restore edge, that post-ACK errors discarded the target actuator inventory,
  that slot 0 conflated BPF cleanup, Rust's internal epoch, and a helper row,
  and that cold start trusted stale active pinned rows retained in the target.
- HA/compiler design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict `PLAN-NEEDS-MAJOR`.
  It found that the compiler rewrite omitted the existing ordered raw
  pre-expansion validators, contradicted strict duplicate-interface rejection,
  could broaden the peer-SNAT compatibility wrapper through unrelated peer
  strictness, had no executable pre/post-ACK result contract, and left config
  rejection debt owned by replaceable SessionSync state.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict `PLAN-NEEDS-MAJOR`.
  It independently found the omitted raw compiler phase and peer-SNAT contract,
  identified undefined/uncopyable SNMP runtime types and private cache aliasing,
  required a fingerprint over the evaluator-owned snapshot, and confirmed that
  post-ACK errors could commit Rust while daemon authority remained previous.

The live candidate now preserves a once-per-input raw compiler phase and exact
generic result/fallback semantics, prepares validation-only node views without
making unrelated peer checks strict, and keeps #5180 strict duplicate rejection
ahead of tolerant final-occurrence reduction. SNMP defines every carrier,
clones the private compiled client cache through `pkg/config`, and owns its
credential-aware fingerprint. RG replacement changes no HA row before the
snapshot decision, resolves lost ACKs through exact generation-bearing status,
quarantines unresolved outcomes, commits target inventory before fallible
follow-up, and returns a non-nil result with typed committed debt. Slot 0 is
cleanup-only, cold start clears all physical rows before authoritative replay,
and a daemon-owned durable nonsecret latch gates every new takeover after a
peer config rejection. These corrections require another immutable hostile
pass.

#### Revision 17 pre-commit hostile design review 7

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-7.md`; SHA-256
  `1c954ccf290d7dc6d056e8703b23912c233ec3e9d1faa90aa0158d3cd8e33ef9`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It found that pre-ACK classifier/hook mutation made previous-good restoration
  incomplete, disarmed helper apply could ACK an unbuildable target, generation
  equality did not prove workers live, helper commit was being confused with
  full daemon convergence, and the proposed persisted takeover marker had
  write-failure and downgrade holes.
- HA/compiler design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict
  `PLAN-NEEDS-MAJOR`. It found exported compile/load paths that mutate pins or
  choose programs before the new validator, the same helper/full-convergence
  conflation, a promotion race while peer validation was in progress, and a
  crash window before the old rejection-only marker write.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict
  `PLAN-NEEDS-MAJOR`. It additionally found that unconditional peer-SNAT
  proof broadened tolerant-load behavior, apply outcome/error carriers were
  undefined, actuator retry debt was unversioned and vulnerable to RG remove/
  re-add ABA, and the persisted marker contradicted the claimed revert and
  public-surface bounds.

The live candidate removes the speculative generic apply-transaction redesign
instead of adding more recovery states to K003-10. Every exported compiler,
loader, and Manager entry must prove the prepared views before any pin, map,
generation, program-selection, or hook side effect. Peer-SNAT remains limited
to its existing strict/wrapper callers. RG owner replacement now composes with
the existing fail-closed snapshot path: newly reachable rows are pre-cleared,
the acknowledged inventory changes only on ACK, exact helper replacement and
removed-row cleanup use generation-owned debt, and old debt cannot clear a
re-added owner. Ordinary errors keep `ActiveApplied` and SessionSync high-water
at the prior fully converged generation. The persisted marker and its rollback
contract are deleted; a clustered process starts with an in-memory takeover veto
closed, closes it before every peer apply, and opens only the exact fully
converged attempt. Crash therefore restarts closed without new durable state.
These are candidate corrections pending a fresh immutable pass.

#### Revision 17 pre-commit hostile design review 8

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-8.md`; SHA-256
  `e7949c9b6ddb7d5cef7a6eb5cb42d6a607f028b9992f6872627cb50e30517b2f`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It found that pending-XSK startup still returned success before snapshot ACK,
  asynchronous actuator-debt convergence had no mandatory daemon replay
  handoff, the sender did not actually resend a failed config on a stable
  connection, and a readiness recheck did not serialize config invalidation
  against ownership mutation.
- HA/compiler design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict
  `PLAN-NEEDS-MAJOR`. Its proof-carrier finding was already closed in the live
  candidate by pure typed downstream belts. It additionally found an RG0
  bootstrap cycle, no replay/rollback owner for a suppressed queued promotion,
  and an inaccurate assumption that every currently admitted config-sync
  transport is PSK-authenticated.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict
  `PLAN-NEEDS-MAJOR`. It independently confirmed the proof-boundary and RG0
  authority-cycle defects and required an exact receipt to cross the
  asynchronous election-to-daemon-actuation boundary.

The live candidate removes successful deferred publication: same-plan startup
updates publish synchronously and changed binding/RG plans restart then publish.
Post-ACK debt cannot arm until a daemon replay receipt read-backs the exact
generation. SessionSync owns a bounded local pending-delivery retry state so a
stable connection does not depend on a nonexistent resend/NACK. Configuration
authority is represented by an explicit process-lifetime receipt: fully
converged local config bootstraps RG0, sync-disabled mode is explicit, and a
fully converged received config records its actual PSK or intentionally
keyless/legacy trust mode. Secondary-to-primary state is pending until the
daemon claims an epoch-bound activation lease; config invalidation waits for
claimed leases, and stale events roll back/re-elect. These are candidate
corrections pending another immutable pass.

#### Revision 17 pre-commit hostile design review 9

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-9.md`; SHA-256
  `ccb94a5fb645a1865b896a39e99236899b17e32692bdad9223bd52c28305428d`.
- Kernel/dataplane design reviewer:
  `019fcae9-10c4-7500-8034-6268dee5716c`; verdict `PLAN-NEEDS-MAJOR`.
  It proved a stale config replay could overwrite a concurrent demotion,
  rollback could invalidate replay before proving the timer still owned a
  target, helper status did not fence asynchronous worker HA commands across
  remove/re-add, and queued VRRP/reconcile promotion lacked an authority epoch.
- HA/compiler design reviewer:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; verdict
  `PLAN-NEEDS-MAJOR`. It independently found that the compiler result types
  could not preserve per-view outcomes, peer rejection/readiness and newer
  delivery admission were contradictory, config replay raced demotion, RG0
  config authority was not serialized, bootstrap could leave the standby
  store writable, stale negative work lacked incarnation, and ordinary full
  apply failures had no recovery owner.
- Whole-plan/API design reviewer:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; verdict
  `PLAN-NEEDS-MAJOR`. It independently confirmed the compiler-outcome,
  rollback-order, connection-cancellation, stale replay, and workstream-scope
  defects, and additionally found caller-forgeable readiness tokens and no
  representable replay phase.

The orchestrator accepted the shared scope finding rather than adding another
generation/receipt layer. The applied-owner inventory, snapshot-ACK recovery,
SessionSync callback/retry change, hard-readiness transaction, election intent,
positive-actuation worker, and rollback supersession API were removed in full.
K003-10 now makes configured RG0..15 the one honest appliance domain, rejects
RG16+ definitions and bindings before mutation, and adds only first-operation
typed validators plus fixed-slot runtime range belts. This matches the source
report's bounded fix and turns every HA race above into a valid reason the
deleted architecture must not ship, not a hidden follow-up inside K003-10.

The compiler finding remained applicable outside that deletion. The live
candidate now runs B/C/I/M on prepared effective roots before lowering, lowers
only the requested view for ordinary compilation, and gives the existing
SNAT-only compatibility wrapper a separate `peerSourceNATOutcome` containing
both `Config` and `LoweringErr`. Error precedence and suppression policy are
explicit, so no prose-only per-view result is claimed.

#### Revision 17 pre-commit hostile design review 10

- Immutable plan snapshot: `/tmp/6744-plan-r17-precommit-10.md`; SHA-256
  `14b1dd652dc0a2ee2aa80b8c533901132e51e3e8bc1682ef124a23fe8d1d3460`.
- Kernel/dataplane design reviewer agent:
  `019fcae9-10c4-7500-8034-6268dee5716c`; submission:
  `019fcc73-770f-7223-bb26-e805af395341`; verdict `PLAN-NEEDS-MAJOR`.
  It found that an absent optional node1 group would become a new hard failure,
  configless `Load` cannot satisfy the claimed typed-config dominator, rolling
  upgrade had no staged config compatibility command before demotion, and the
  frozen snapshot still contradicted current warning order. The live draft had
  independently corrected warning order before results returned.
- HA/compiler design reviewer agent:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; submission:
  `019fcc73-7711-7e91-b6fe-3845decd694e`; verdict `PLAN-NEEDS-MAJOR`.
  It found the inactive-RG rejection contradicted pruning semantics, daemon
  config apply mutated multiple subsystems before the proposed runtime gate,
  `cluster.Manager.UpdateConfig` remained an unguarded publication path, the
  test matrix demanded errors for valid RG0/RG15 operations, and persisted
  confirm recovery promoted invalid targets before checking them.
- Whole-plan/API design reviewer agent:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; submission:
  `019fcc73-7715-7fa3-9ca8-b89fbd6cf6ff`; verdict `PLAN-NEEDS-MAJOR`.
  It found that `NodeID int` aliased unspecified generic evaluation with node
  0, independently confirmed inactive/rollback/upgrade gaps, and identified
  source-breaking removal/renaming of exported route-map and heartbeat APIs.

Revision 18 accepts the shared scope verdict. K003-10 remains confirmed but is
now a dedicated follow-on `/research` child with no production PR authorized by
this plan; its required comparison explicitly owns compiler, config-bearing
startup, cluster publication, pending-confirm recovery, staged-binary upgrade,
mixed-version, API, and smoke contracts. The remaining compiler pipeline now
preserves an explicit `{ID,Set}` evaluation context, treats only the exact
absent optional `${node}` validation view as unavailable, preserves current
warning order, and removes I from B's implementation dependency. Workstream H
retains deprecated exported compatibility wrappers while barring them from
safety decisions. Snapshot-10 RG implementation findings are therefore
**research requirements, not claimed code fixes**.

#### Revision 18 pre-commit hostile design review 11

- Immutable plan snapshot: `/tmp/6744-plan-r18-precommit-11.md`; SHA-256
  `fa8cb8afb846ec89e64fd84d1c0825f0b1e98a1269e27e85a04a9c41669270ba`.
- Kernel/dataplane design reviewer agent:
  `019fcae9-10c4-7500-8034-6268dee5716c`; submission:
  `019fcc85-f61b-7161-a541-6f47ce935f28`; verdict `PLAN-NEEDS-MAJOR`.
  It found that I-owned interface/chassis reductions still leaked into B, the
  current configstore sequence had no executable prepare-once strict compiler
  transaction, and the blanket no-double-expansion claim contradicted existing
  bounded raw gates that independently expand node views.
- HA/compiler design reviewer agent:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; submission:
  `019fcc86-0d2d-7ae1-8930-8f0bebec0aaf`; verdict `PLAN-NEEDS-MAJOR`.
  It independently confirmed the I-owned compiler leakage, proved that the
  optional-peer exception was not distinguishable after variable substitution,
  and required an exact compatibility rule for direct node IDs outside 0/1.
- Whole-plan/API design reviewer agent:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; submission:
  `019fcc86-22a2-7793-9ed6-fd1894777340`; verdict `PLAN-NEEDS-MAJOR`.
  It independently confirmed the I-owned compiler leakage and proved that
  expired and unexpired commit-confirm recovery can publish or arm an invalid
  B/M rollback target after compilation fails.

Revision 19 removes I's last production scaffolding, defines one strict
`CompileConfigForCommit` transaction with preserved error precedence, narrows
the expansion invariant to prepared views within that transaction, adds typed
undefined-group provenance and non-0/1 compatibility behavior, and makes
commit-confirm recovery fallible with explicit pending and first-commit state.

#### Revision 19 pre-commit hostile design review 12

- Immutable plan snapshot: `/tmp/6744-plan-r19-precommit-12.md`; SHA-256
  `c16dd42bf96031de3c8a0f753f0e0e1e7c545ab605febce198e3cd3c87bb6470`.
- Kernel/dataplane design reviewer agent:
  `019fcae9-10c4-7500-8034-6268dee5716c`; submission:
  `019fcc93-d2e2-71d0-9754-860c45d48502`; verdict `PLAN-NEEDS-MAJOR`.
  It proved blocked recovery still exposed a compiled active config to cluster
  election and other startup managers, demotion could clear the blocked record,
  and neither advertised recovery action completed a runtime transaction.
- HA/compiler design reviewer agent:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; submission:
  `019fcc93-d2e0-7000-b00c-edae24796884`; verdict `PLAN-NEEDS-MAJOR`.
  It proved validation-only B/C/M errors could precede an existing requested
  lowering error and required an explicit pending-state enum and complete
  transition table rather than timer-plus-Boolean ownership.
- Whole-plan/API design reviewer agent:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; submission:
  `019fcc93-d2e4-7512-b627-9ffc5e0d13f8`; verdict `PLAN-NEEDS-MAJOR`.
  It found indistinguishable prepared/alias/unavailable view states, the
  invalid-active/valid-target upgrade ordering hole, nil-based first-commit
  result callers and inconsistent persisted markers, the bootstrap recovery
  dead end, and stale scope exclusions.

Revision 20 defers every new hard-gate error behind existing requested and
cross-check slots, adds node-indexed resolution states, prepares active and
confirm artifacts before publication, restores valid rollback targets even
when the unconfirmed active tree is newly invalid, publishes nil compiled state
when blocked, migrates internal rollback callers to an explicit first-commit
result, validates the persisted marker, and defines the complete
none/armed/blocked transition matrix and bootstrap-only strict plain-commit
recovery path.

#### Revision 20 pre-commit hostile design review 13 - infrastructure blocked

- Immutable plan snapshot: `/tmp/6744-plan-r20-precommit-13.md`; SHA-256
  `825edf8ed010a506381938c734cffa7d4f4653f5d4998f1fb6882f8fa5a55c84`.
- Kernel/dataplane design reviewer agent:
  `019fcae9-10c4-7500-8034-6268dee5716c`; retry submission:
  `019fcca1-8cb9-74b1-82c8-7a30d6ef67b7`.
- HA/compiler design reviewer agent:
  `019fcae9-70f6-7f20-88ff-1fe8cbb92da0`; retry submission:
  `019fcca1-8cbc-7400-b9e2-71b04d29fd5b`.
- Whole-plan/API design reviewer agent:
  `019fcae9-d9d7-74b2-8a9d-a78022f076e3`; retry submission:
  `019fcca1-8cbe-74d2-ab36-38fa2d551c6b`.

All three submissions failed before analysis at the shared Codex usage limit.
They produced no verdict and are not counted toward convergence. The live draft
then received two orchestrator-only clarifications: successful typed rollback
results must satisfy the first-commit/config XOR invariant, and blocked recovery
must retain rollback history plus the parsed active tree for `EnterConfigure`.
The next formal round therefore reviews a new immutable commit rather than
claiming equivalence with this pre-commit snapshot.
