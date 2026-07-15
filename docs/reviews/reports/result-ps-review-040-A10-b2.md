# Triage Result — ps-review-040-A10-b2

- **Subsystem / scope**: A10 Batch 2 defensive audit — core firewall (zone/global
  policies, host-inbound, app matching, default deny/permit), VRRP/HA failover &
  cold-boot, dataplane integer-truncation on config casts, DDNS/observability
  resource safety. 133 files across `pkg/cli`, `pkg/ddns`, `pkg/devicemap`,
  `pkg/dhcp`, `pkg/dhcprelay`, `pkg/dhcpserver`, `pkg/diagcmd`, `pkg/fairness`,
  `pkg/fsatomic`, `pkg/fwdstatus`, `pkg/ipmon`, `pkg/linuxsock`, `pkg/lldp`,
  `pkg/monitoriface`, `pkg/natpoolalarm`, `pkg/natshow`, `pkg/nftables`,
  `pkg/policymatch`.
- **Base == current master?**: N/A — the report cites no diff base. Triaged
  against current `origin/master`.
- **Master SHA**: `95b33d49634d56086269a62a92e213dae7926f88` (freshly fetched)
- **Real bpfrx or avacado fork?**: Real bpfrx. All spot-checked cited paths
  exist on `origin/master`; no `/home/ps/git/avacado-xpf` references, no
  confabulated filenames.
- **Outcome counts**: 0 findings in the report → 0 GENUINE-RESIDUAL, 0
  ALREADY-FIXED, 0 NOT-MATERIAL, 0 DELIBERATE, 0 CONFABULATED, 0 DUP.

## Disposition

This is a **pure negative-result audit**. The report explicitly states (line 5):
"No new security vulnerabilities or bugs were found during this round of audit."
Every one of the 18 module sections is a "**Negative Result**" that merely
records an invariant the reviewer confirmed to hold. There are **no findings** —
nothing is asserted as a defect, so there is nothing to classify as
GENUINE / FIXED / NOT-MATERIAL / etc.

### Grounding checks (to confirm this is a real audit of real code, not a
fabricated/avacado report)

Cited paths — all EXIST on origin/master:
`pkg/cli/session_filter.go`, `pkg/ddns/surface_a.go`,
`pkg/devicemap/devicemap.go`, `pkg/dhcprelay/relay.go`,
`pkg/natpoolalarm/natpoolalarm.go`, `pkg/natshow/natshow.go`,
`pkg/nftables/rst_suppress.go`,
`pkg/policymatch/app_junos_ping_3348_test.go`,
`pkg/monitoriface/monitor.go`, `pkg/fwdstatus/procreader.go`.

Concrete invariant claims spot-checked — all ACCURATE on origin/master:
- LLDP per-interface 64-neighbor cap → `pkg/lldp/lldp.go:536`
  `const maxNeighborsPerInterface = 64`.
- natpoolalarm `PortHigh < PortLow` underflow guard → referenced/tested in
  `pkg/natpoolalarm/natpoolalarm_test.go:300` ("uncomputable sample ...
  PortHigh<PortLow ... HOLDS").
- linuxsock forces `SOCK_CLOEXEC` atomically → `pkg/linuxsock/linuxsock.go`
  (helper ORs `unix.SOCK_CLOEXEC` into the type arg).
- monitoriface underflow-safe `deltaU64` delta helper → used at
  `pkg/monitoriface/monitor.go:158-160`.

The report accurately describes the current hardened state of these modules.
This is consistent with the campaign context: A10 Batch 2 covers cold-path Go
observability/config modules that were heavily hardened this session
(#4517-#4685) and in the ps-038 pass, so a clean negative sweep is the expected
outcome. No weakened-but-claimed-safe path was found: the invariants the report
asserts as present are genuinely present in the source.

## Conclusion

No findings to drive. Zero genuine residuals. The report is a truthful negative
result grounded in the real bpfrx tree.
