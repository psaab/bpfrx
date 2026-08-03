# Codex hostile plan review - round 7

Target commit: `c952d74ef6ea8bea994b44f1697b412353577d6d`

Valid output: `/tmp/6744-codex-r7.out`

The direct process did not expose a durable reviewer-session identifier. The
review ran against the clean, locked, detached worktree
`/home/ps/git/xpf-worktrees/6744-plan-r7-review` with write scope `NONE`.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. The SNMP compatibility contract is impossible on the current AST: genuine
   hierarchical `system { snmp { ... } }` input and flat
   `set system snmp ...` input become the same provenance-free tree. The plan
   must accept both normalized forms or add provenance before requiring one to
   reload and the other to reject.
2. SNMP `clients <prefix> [restrict]` is structured syntax. Treating it as a
   generic leaf-list can erase `restrict` and turn deny into allow. The fold
   needs explicit `(prefix, restrict)` semantics with equal-prefix deny wins.
3. The shared DDNS state loader has no persisted surface tag, and the proposed
   Surface-B validator does not define the complete legacy Surface-A matrix.
   Valid Surface-A rows use `Address=""` plus `AddrText`; hostname canonical
   form is also underspecified.
4. DDNS no-authority retention conflicts with the existing #6015 co-owner
   release. The exact order must be validation, claim-only release while a
   co-owner exists, then authority selection only for last-claimant wire I/O.
5. The RG upgrade preflight cannot prove that an arbitrary config file is the
   active authoritative artifact. The plan must add a real binding/export
   mechanism or remove its stale-artifact-rejection claim.
6. Reusing a bound RG slot can replay stale pinned `rg_active` and
   `ha_watchdog` state before reconciliation. The plan needs authoritative
   unbind/rebind clear-and-fence ordering and executable restart tests.
7. `BulkStart` currently clears config-generation authority as well as per-key
   session generations. That erases the proposed rejected-epoch fence and can
   admit sessions under the previous-good config.
8. A repair bulk is not an authoritative transaction because ordinary session
   incrementals can interleave between BulkStart and BulkEnd and enter the
   receiver's authoritative set.
9. Type-29 recovery debt has no atomic consume/rearm, partial-write, reconnect,
   concurrent-refusal, or completion semantics.
10. `LoadOverride` tests require terminal Ctrl-C behavior while the plan says
    #6548 remains out of scope. The plan must either own that narrow fix or stop
    claiming its acceptance test.

## Accepted portions

No separate material blocker was found in A, B, D, G, H, J, K, L, or M. The
bounded persisted-AST work, DDNS same-family `fpb1` authority, RG
definition-versus-bound-owner split, manual-versus-crash failover policy, and
SNMP credential matrix were otherwise accepted.
