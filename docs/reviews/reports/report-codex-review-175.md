# Final report — codex-review-175 (Paladin Full-Tree Defensive Review — Codex)

**Triaged:** 2026-07-09
**Base:** `385f940b7` (base-lag — behind current master) vs current `origin/master`
(fragments verified across `29a046ec5`..`90af98b9d` as master advanced).
**Review:** Codex, high-signal defensive full-tree pass (~90%). **Confabulated: 0.**

## Headline

146 non-duplicate findings → **69 new issues**. High genuine yield; triaged in
3 parallel area slices (A1-A5 = 18 issues, A6-A9 = 27 issues, A10 = 24 issues).

## Consolidated buckets

| Bucket | Findings | Issues |
|---|---|---|
| GENUINE | 129 | 69 (near-identical items grouped into cohorts) |
| ALREADY-FIXED | 7 | — |
| DELIBERATE | 4 | — |
| NOT-MATERIAL | 7 | — |
| CONFABULATED | 0 | — |

## Issue index by category

### Security (~12 — real security-boundary / fail-open / crypto-at-rest impact)

- **#4862** — parser never asserts EOF; a stray unmatched `}` silently drops all trailing config (policies, default-policy) with zero ParseError (fail-open config acceptance)
- **#4895** — `reconcileSudoers` formats an unvalidated super-user username into a NOPASSWD sudoers grant → sudoers directive injection, fail-open to root (CWE-74)
- **#4897** — SNMPv3 enforces no per-user minimum security level → an authPriv-configured user queried at noAuthNoPriv is served plaintext (auth bypass)
- **#4903** — `hostIsLoopback("")` true → `xpfd --api-addr :8080` skips the loopback clamp and binds the unauthenticated REST API on all interfaces
- **#4857** — DHCP `ClearDUID` joins a raw, unvalidated interface name → path traversal / arbitrary root file unlink
- **#4858** — `request system zeroize` leaves `.configdb` + master.key behind (removes only `.conf`/`rollback*`) → config/secret data remanence
- **#4859** — operator RBAC gap: forwarding/queue/binding teardown + ISSU disarm reachable under PermControl (operator has it)
- **#4860** — view-only `show log <name>` tails any child of /var/log with no allowlist under PermView (arbitrary log read)
- **#4861** — DDNS backends accept plaintext `http://` and follow redirect downgrade → credentialed update creds exposed
- **#4904** — supply-chain signing/publication cohort: bake `--skip-validate` still signs; `publish.py` mutable-dist TOCTOU; unsigned/unpinned base image + checksums then XPF-signed
- **#4863** — NAT64/CGNAT `deterministic_indices_v6` omits the source-prefix check → an out-of-prefix IPv6 source sharing the subscriber word is placed in another tenant's block + lying reverse map
- **#4882** — `core::ptr::read` (align 2) from an align-1 `Vec` in the metrics map decoder → genuine unaligned-read UB (debug-log-gated → Low)

### Correctness / fail-open (52 — A1-A9 remainder + A10 substantive remainder)

**A1-A5 slice**
- **#4864** — `DeleteConfirm` is a non-dir-synced `os.Remove`; after a crash a stale `confirm.json` replays and reverts an already-confirmed config (HA re-divergence)
- **#4865** — appid catalog/runtime deref a nil `*Application` from a tolerated nil map value → control-plane panic
- **#4866** — cmdtree derefs nil `RoutingInstances`/`RedundancyGroups` entries (tolerated shape) → completion/help panic (SSOT)
- **#4867** — cluster `DualActiveWin` reaffirm dropped on a full eventCh and skips `onEventDrop` → post-split-brain GARP/NA lost, no reconcile → blackhole
- **#4877** — `ValidatePercent` lets `NaN` bypass min/max and the compiler clamp → CoS apply-time JSON marshal failure
- **#4878** — IPsec DPD interval/threshold untyped + `Atoi` errors ignored + `delay*threshold` overflow drops dpd_timeout (silent default)
- **#4879** — dynamic-address update/hold-interval untyped, `Atoi` errors ignored → runtime defaults (3600s / retain-forever); stale allowlist feeds
- **#4880** — packed one-liner `node 0 priority 999` bypasses the [1,254] range gate → election(999) vs wire(231) split
- **#4881** — NAT mixed-scope (`from zone`+`from interface`) OR-expands into separate rule-sets, contradicting the "AND-ed fail-closed" comment (scope widening)
- **#4887** — `catalogProtocolNumber` drops its `ok` → emits a Protocol:0/HOPOPT row for an unrepresentable protocol (false AppID label)
- **#4888** — `unmarshalEnvelope` returns `(false,nil)` for an unknown `format` → body decoded as an empty ConfigTree with no error (inner-envelope fail-closed gap)
- **#4889** — `learn_dynamic_neighbor` omits the learnable-class check → loopback/multicast/broadcast sources pollute the dynamic-neighbor cache
- **#4890** — screen `evict_stalest_in_zone` samples a fixed global prefix → a fresh scanner in a saturated zone is skipped, evading scan detection
- **#4891** — commit `description` stored uncapped → an oversized comment allocates then vanishes from the 16-MiB-bounded audit tail
- **#4892** — `putLeaseString` writes a `uint16` length but appends the full string → a >64 KiB field silently misframes a lease record on the peer

**A6-A9 slice**
- **#4894** — binding-array index has no `QueueID < 16` bound → on a >16-RX-queue NIC queue 16 aliases the next interface's slot (cross-interface XSK misdelivery)
- **#4896** — NetFlow records packed at a padded stride while the template advertises the unpadded width → every record after the first misdecodes on a multi-record close burst
- **#4898** — IPsec manager swallows the reload error on last-VPN-delete and terminates removed SAs even after a failed reload (reload-error/ordering)
- **#4899** — DHCP-lease-change IPsec reapply only warns on error → strongSwan left on stale local_addrs with no operator signal (bypasses fail-closed)
- **#4900** — networkd stale-file `os.Remove` failure is warn-only and not added to writeErrs → a stale `.network` resurrects removed addrs/VRF/bond/rename
- **#4901** — xfrm/bond/tunnel teardown drops the object from tracking after a failed `LinkDel` and reports success → orphaned link + lost ownership
- **#4902** — unvalidated system strings (chrony/sshd Kex+Ciphers+MACs/syslog/DNS) rendered verbatim into root-owned host config → directive injection (CWE-74)
- **#4910** — gRPC `GracefulStop` with no timeout/`Stop` fallback + `MonitorInterface` streams forever → a held stream blocks daemon shutdown/failover
- **#4911** — filtered `ClearSessions` snapshots every matching key before delete on a 10M-sized map → control-daemon OOM
- **#4912** — RPM `probeHTTP` builds a fresh `http.Transport` per probe (no keepalive close) → fd/goroutine leak per attempt
- **#4913** — feeds iterate a nondeterministic map and overwrite same-named workers → orphaned cancel + goroutine leak until shutdown
- **#4914** — event close encodes the zeroed `evt` → binary + slog SESSION_CLOSE emit policy 0 and action deny (residual of #4796)
- **#4915** — event `SessionID` is a per-event sequence → create/close get different IDs and cannot be correlated
- **#4916** — SNMP agent `Stop` leaks the ctx watcher, trap queue, and trap worker goroutines per enable/disable
- **#4917** — SNMP EngineID appends the OS hostname uncapped → a hostname >26 bytes yields an invalid EngineID and breaks all SNMPv3
- **#4918** — SNMP GET/GETNEXT skip `trimToFit` → oversized responses; `trimToFit` is O(n^2) and GETBULK still over-materializes (residual of #2612)
- **#4919** — FRR `bgp cluster-id` has no validator/sanitize and `set origin` isn't enum-validated → reload poison + newline injection
- **#4920** — REST peer-sessions forwards `limit` but not cursor `page_size` → peer request defaults to 100 → peer undercount
- **#4921** — `showTestRouting` has no `seen` map → a repeated `dest=`/`instance=` silently last-wins (answers a different query than typed)
- **#4922** — feeds `maxInvalidSample` bounds count not bytes → up to ~5 MiB verbatim retained/logged per degraded feed
- **#4923** — flowexport fallback `Time.Add(-duration)` overflows signed Duration above ~92.2B pkts → StartTime after EndTime
- **#4924** — SNMP `berEncodeTimeTicks` omits the high-bit leading-zero prepend → sysUpTime/traps encode negative at 248.55 days
- **#4925** — userspace NAT nested-set resolution uses the feed-unaware resolver → a feed-backed address-set member yields no prefixes (vSRX parity gap)
- **#4926** — REST `security` `limit` uses lenient `queryInt` (fail-open to default 50) while `zone` fails closed with 400 (scoping inconsistency)

**A10 slice**
- **#4868** — CLI commit/rollback grammar: unknown modifier falls to permanent Commit + `int32` narrowing (`4294967297`→1, rollback `4294967296`→0=reset) fail-open (HC-024/115/067)
- **#4869** — `xpfd upgrade` has no `NArg` check → `upgrade rolling` positional leaves `rolling=false` → uncoordinated standalone cut on a clustered node (HC-015)
- **#4870** — dhcpserver discards `cmd.Output` error → a failed query skips the restart while the generation advances and commit returns nil; async apply drops transient failures (HC-016/071)
- **#4871** — HA DHCP lease Remaining computed once with no sample epoch; peer lease copies carry no receipt time → stale-partition takeover revives leases (dup allocation) (HC-021)
- **#4872** — pkg/upgrade kernel-roll/self-recover fail-open cohort: prune-before-RunningKernel-check destroys the running candidate; JSON `{}`→NodeID 0 ResetFailover; swallowed watchdog arm/disarm; observation errors don't reset drainedSince (HC-018/100/068/131)
- **#4873** — DDNS durability/ownership cohort: quarantine is in-memory only with no restart rescan; non-fsync'd parent MkdirAll; single IPv4-first updater sends AAAA delete to the v4 provider (HC-019/076/027)
- **#4874** — DHCP client keeps an expired v4 addr/PD past T2 before reacquire, and stores a zero-lifetime IA_PD that RA re-advertises as a reclaimed prefix (HC-078/079)
- **#4875** — fwdstatus `allHeartbeatsFresh` treats an empty slice and future timestamps as fresh → default false-Online (HC-098)
- **#4876** — publish-generation GC runs with an empty protected set when the journal read fails → a crashed-cut source can be GC'd unrecoverably (HC-062)
- **#4883** — CLI command fail-open/footgun cohort: empty/unknown monitor filter → unfiltered tcpdump; writeLine-error path leaves monitor permanently Active; missing failover node → untargeted ManualFailover; interrupted `load terminal` partially applied; malformed interface DUID clear → ClearAllDUIDs (HC-061/064/065/075/089)
- **#4884** — interface/device-map identity cohort: one-interface-per-zone map targets the wrong interface; authored/logical/kernel name mixing hides devices + fabricates VLAN addrs; non-PCI MAC-only NIC skipped before netlink read → stranded interface (HC-086/087/088)
- **#4885** — policy simulator zone-detail omits the wildcard zone-pair/any→any and mis-orders sub-tiers vs runtime (HC-102)
- **#4886** — control-plane unbounded-memory cohort: filtered clear snapshots all keys; `show` re-buffers full output + nests an invisible pager; Kea DDNS reconcile ReadAll's the entire lease history (HC-053/093/094)

### Tooling (#4905–#4909 — build/deploy/test/perf/display cohorts)

- **#4905** — deploy/image filesystem-safety cohort: empty running-kernel readback sets rebooted=True + strands the node; `..` name/image escapes managed dirs into sudo write/delete sinks; world-readable secret config-drive ISO; validate.py deletes fixed Incus aliases/instances with no lock (HC-017/097/096/085)
- **#4906** — test/xsk-repro cohort: unchecked `fork()`→`kill(-1,SIGKILL)`; fixed `/tmp` .o symlink clobber; UMEM addr mishandling; uninitialized rx→PASS; rebind on failed link cycle; munmap UMEM while owners alive; secondary socket never polled; zero-flag attach replaces a live XDP program (HC-001/025/069/081/090/091/095/101)
- **#4907** — perf-analysis cohort: off-CPU interval closed on wrong event; empty-perf→definitive verdict exit 0; FAIL returns green; tuple-space collisions; `|| true` swallows failed RG polls; rc=1+PASS accepted; duty-cycle math errors; unbounded trial retention; skipped cells exit 0 (HC-026/029/070/072/083/084/092/128/130/132)
- **#4908** — CLI display cohort: cumulative screen drops labeled active; peer summary unfiltered / `Total sessions: -1`; DNAT joins by translated IP; DUID header over HWAddress; all sessions labeled RG0; cluster status drops logical-zone VRRP rows; lease-read failure → clean empty table; relayed counted on all-send-fail; TTL=0 LLDP learned; loose inventory parser drops malformed selectors; next-table static route counted but no row (HC-063/073/077/080/082/116/121/122/125/126/129)
- **#4909** — low control-plane correctness cohort: ClearAllDUIDs ignores delete errors; unpaginated Cloudflare lookup; IPv6 peer endpoint missing brackets; natpoolalarm double-close panic; ownership dropped without wire delete; DUID-LLT continues after persist failure; fwdstatus tick*1e9 overflow; persistent-NAT `All` returns mutable pointers (data race); GetStatus-before-dispatch blocks offline WG keygen; check-config Stat/ReadFile TOCTOU (HC-114/117/118/119/120/123/124/127/133/MC-013)

## ALREADY-FIXED (base-lag — closed by master ahead of the base)

- **#4791** — HC-002 address-set bracket-list members after the first dropped (compiler_security_addressbook.go now reads `Keys[1:]` + children)
- **#4706** — HC-041 repeated hierarchical `address-set` blocks replaced instead of merged (`parseAddressBookEntries` now merges by name)
- **`8febce63b`** — HC-037 inverted NAT dest-port range degraded silently (now rejects reversed destination-port ranges)
- **#4793** — HC-043 malformed AES-GCM nonce length panicked (crypto.go now guards `len(nonce) != gcm.NonceSize()`)
- **#4794** — HC-052 chunked DHCP identifier clear wiped all DUIDs (now gates on `ContentLength != 0` + decodes chunked bodies)
- **#4806** — HC-054 syslog client `Close` non-terminal / post-close reconnect (added a mu-guarded `closed` flag)
- **#4822** — HC-109 RPM probe-pin band `clear` dropped errors + always returned nil (now aggregates via `errors.Join`)

## DELIBERATE (documented tradeoff — not filed)

- **HC-005** — `CommitConfirmed` returns success when `WriteConfirm` fails (#1799 degrade-not-fail doctrine; in-memory timer covers the no-crash case). Its distinct durable-delete sibling IS filed as #4864.
- **HC-042** — master-password doesn't encrypt rollback/rescue/archive (#4056 owner-only 0600; those slots must stay restorable → perms, not encryption)
- **HC-105** — WG data/cookie parsers accept non-canonical reserved bytes (documented interop leniency; reserved bytes are outside the AEAD AAD, no forgery)
- **HC-066** — dhcpserver Kea `ddns_leases` treats a MISSING memfile as trusted-empty (ENOENT=empty, intentional per #1387; headerless/mangled cases already fail-safe)

## Verdict

A high-value pass. Codex ran the full tree defensively and surfaced ~12 real
security-boundary items — sudoers/DNS/FRR directive injection, an SNMPv3 auth-level
bypass, a REST loopback-clamp bypass, a DHCP path-traversal unlink, a NAT64
wrong-tenant placement, a `zeroize` data-remanence gap, and an operator RBAC
disarm — alongside a broad correctness/fail-open backlog. Severities are honestly
down-rated where the trigger is a malformed-config fail-stop (parser EOF, CoS NaN,
DPD/dynamic-address defaults) or a narrow defensive window (unaligned-read UB behind
a debug-log gate, wire codecs bounded by local-sourced field sizes). 0 findings were
confabulated; every cited symbol was verified live on current master, so base-lag
only produced the 7 ALREADY-FIXED items (already reconciled above). Full per-finding
reasoning, including the NOT-MATERIAL and DELIBERATE dispositions, is in
`/tmp/result-codex-review-175.md`.
