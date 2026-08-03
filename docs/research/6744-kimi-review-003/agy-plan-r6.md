# AGY hostile plan review - round 6

Target commit: `cab8851171889b6e97d518d6fe9540341fc942f7`

Valid output: `/tmp/6744-agy-r6d.out`

Invalid attempts `/tmp/6744-agy-r6.out`, `r6b`, and `r6c` were malformed or
permission-blocked invocations and are not counted.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. The DDNS claimant election can choose a final deleter that lacks delete
   authority after an authorized nonleader has already erased its row. That
   strands the wire record with no actionable owner.
2. Nonleaders release before the leader completes DNS I/O. A leader crash or
   provider error after that release destroys the fallback cleanup path. A
   leader must prove/reserve authority and complete a durable handoff before
   peers can forget ownership.
3. The SNMP matrix needs an explicit no-downgrade rule: any partial privacy
   declaration, including privacy protocol without password, rejects the user
   entirely rather than falling back to `authNoPriv`.

## Accepted workstreams

AGY accepted A, B, D, F, G, H, I, J, K, L, and M as written. It accepted the
general SNMP direction subject to the explicit partial-privacy rule, and blocked
the DDNS teardown protocol.
