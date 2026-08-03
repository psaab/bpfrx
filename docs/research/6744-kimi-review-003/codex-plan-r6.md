# Codex hostile plan review - round 6

Target commit: `cab8851171889b6e97d518d6fe9540341fc942f7`

Process session: `57655`

Reviewer session: `019fc7f3-5ec3-7363-a309-c78d0d6b6e3b`

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

### DDNS

1. The proposed lock-free teardown election is not linearizable. Stale atomic
   snapshots permit each surface to release to the other, leaving no durable
   claim and issuing no wire delete.
2. Different configured DNS server strings do not prove independent wire
   namespaces. Aliases, replicas, and anycast can mutate one logical view, so
   unequal targets must remain ambiguous unless a logical namespace identity
   is proved.
3. A successful Surface-A reassert cannot safely migrate a legacy `fp1` row.
   The old fingerprint omitted TSIG and bind identity; reasserting through a
   changed view can publish a second copy and overwrite the only evidence of
   the old copy.
4. Delete authority omits the original conflict policy even though
   `skip-existing` and `replace-owned` use different DHCID delete protocols.
5. Election is over one forward tuple, but Surface B owns a compound
   forward/PTR/DHCID operation while Surface A owns only the forward record.
   Electing or delegating to A can strand B-only components.
6. `dhcidSharedWithOther` remains namespace-blind, so records on different
   family endpoints can suppress the last DHCID cleanup.

### Confirm recovery and override

7. `active.json` and `confirm.json` still have no crash-safe transaction.
   Either write order loses a nested confirmed generation without a transition
   record that describes both possible active generations.
8. Canonical-JSON hashing is not byte-compatible with the current
   `tree.Format()` hash. Guard encodings are also unversioned and malformed
   nonempty values are destructively classified as stale.
9. The envelope validation order contradicts stale-first target handling, and
   the claimed old-reader compatibility cannot represent a
   committed-but-uncompiled rollback target through the retained nil-config
   API.
10. Enabling empty override before fixing local terminal error handling turns
    Ctrl-C into a successful destructive empty override. Workstream F must
    depend on open issue #6548 or include that owner explicitly.

### SNMP

11. Concatenating synthetic roots does not implement keyed trap-group merge;
    the current compiler validates each occurrence and then overwrites prior
    state.
12. The plan has no carrier that transports the authoritative normalized SNMP
    node from preprocessing through intent validation and section compilation.

### RG/HA

13. Legal unbound RG definitions still reach fixed 16-slot actuator paths.
    Control inventory and dataplane-bound inventory must be distinct at every
    watchdog, reconcile, fence, shutdown, map, and helper call site.
14. The mixed-version contract refers to a config-sync acknowledgment that
    does not exist and contradicts the deliberate stale-config crash-takeover
    doctrine. The plan must choose and document the availability/security
    policy and give the upgrade preflight an exact command contract.
15. A rejected config generation does not fence later session installs stamped
    with that generation. The receiver can mutate helper/BPF state under the
    previous-good config after apply failure; an unapplied-epoch gate and
    recovery resweep are required.

## Accepted workstreams

No separate material blocker was found in A, B, D, H, J, K, L, or M. The
SNMP credential matrix and rejection dominance, confirm quarantine/removal
durability, and RG malformed-identity/pre-effect gates were otherwise accepted.
