# #8943 batch 3 — the `syslog` destinations

- **Timestamp**: 2026-09-05
- **Action**: admit the three `system syslog` destinations; extend the #8852
  shape model with the case they exposed
- **File(s)**: `pkg/config/compact_normalize_8662.go`,
  `pkg/config/elision_admissions_8879_test.go`,
  `pkg/config/compact_scope_blind_pairs_8852_test.go`

## Verdict table (gate column FIRST)

| pair | gate | warns b/e | strict b/e | braced | elided | LIVE |
|---|---|---|---|---|---|---|
| `syslog host` | SILENT | 0/0 | ok/ok | `hosts=1` | `hosts=0` | yes |
| `syslog file` | SILENT | 0/0 | ok/ok | `files=1` | `files=0` | yes |
| `syslog user` | SILENT | 0/0 | ok/ok | `users=1` | `users=0` | yes |

**3 admitted, 0 declined.** #8921 collision check: one schema site each. Elided
arms parse-checked before their divergence was believed.

## Severity axis — does the lost field reach the dataplane, or stop at the compiler?

**It reaches the runtime.** `applySyslogConfig` (`pkg/daemon/daemon_system.go`)
constructs the syslog clients and local writers from these fields, so an elided
destination means the operator has configured a log target and has none — logs
are silently not delivered anywhere.

That axis is the one a fingerprint diff cannot see, and it is what separates
these from the `flow aging` row in batch 2, where the value was inert either way
and the loss was the advisory.

## No fail-open control here, and why that is stated rather than omitted

The #8928 three-row control applies where the elided container carries a
**cross-reference** that strict commit validates. No cross-reference validator
names `syslog`, so the class does not apply and there is nothing to control.
Recorded explicitly: the absence of a control is otherwise indistinguishable
from having forgotten one.

## The admission exposed a hole in the #8852 shape model

Registering the three blind pairs derived shape `""` — which
`blindShape8852` documents as *"the census DOES emit sites for this shape"*,
while the census emits none. The cell refuses to let that be registered, and it
is right to: *"a pair blind for no recognised structural reason is a census bug,
not a registrable exception."*

It was not a bug. These nodes are `args=1` **with a wildcard**, and every
existing branch requires `wildcard == nil`:

    host   args=1 children=11 wildcard=true -> ""
    file   args=1 children=6  wildcard=true -> ""
    user   args=1 children=5  wildcard=true -> ""

The blindness reason is real and structural — a NAMED container's synthesised
site carries the instance name in the container element (`host xpfarg`, not
`host`), so a pair-keyed census cannot match it against the bare `(syslog,
host)` the predicate is keyed on. Same permanent bound as `interfaces <name>`.

Added as `named-container`. It cannot reclassify any existing registration: it
requires `wildcard != nil`, which every other branch excludes, and `multi-arg`
still takes precedence. The cell re-derives every registration and passed.

## Mutations

| mutant | result |
|---|---|
| drop `syslog host` / `file` / `user` | KILLED — property `:599` **and** population `:1350`, 54 subtests executing |
| remove the `named-container` shape case | KILLED — fires the unexplained-shape arm **and** the registration-drift arm |

## The modularity floor

This batch pushed `compact_normalize_8662.go` from 1986 to exactly **2000 LOC**,
crossing the `[REFACTOR]` floor. Eleven of my fourteen added lines were
explanatory prose; moving it here brought the file to 1992.

That is the right fix on the merits rather than a way around the gate — the
adjudication detail belongs in a log entry, and the scope table needs a pointer,
not an essay. But the file is now **8 lines from the floor** and the next
admission crosses it, so the structural problem is filed as #8954: the admission
LIST and the fold MECHANICS have different growth rates and should not share a
file.

## The #8880 ratchet grew, and the residual is not its mechanism

463 → 466, one per admission. Measured for a config carrying two syslog hosts:

    braced                            before 2   after 2
    elided, two separate statements   before 0   after 1   <- improved, TRUNCATES
    elided, both in ONE packed run    before 0   after 0   <- unchanged

The pair joins the population because it is now reachable at all, and the loss
it leaves is smaller than the one it replaced — so the growth is deliberate,
attributed, and a strict improvement.

**But the residual is not the mechanism that population names.**
`packedStatements` on `syslog` does NOT fix it (still 1 and 0) and #8768 objects
to the opt-in besides. The two-separate-statements case loses its second host to
a **folded-sibling merge** — two `syslog host X { … }` statements each fold to a
`syslog` node and the merge keeps one — not to a packed run failing to split.

So a pair can sit in that population for a reason the population does not model,
and the opt-in is not a candidate remedy for it. Same shape as the `as-path`
correction recorded in that cell earlier: **the ratchet's remedy advice is
narrower than its membership.**

## Corpus

9 pass / 5 fail — unchanged.
