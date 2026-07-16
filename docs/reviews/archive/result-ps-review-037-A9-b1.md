# Triage Result — ps-review-037-A9-b1

- **Subsystem:** A9 — Observability & Telemetry (SNMP, NetFlow/IPFIX, Logging, RPM, Feeds, Event Engine)
- **Review paths:** pkg/flowexport, pkg/snmp, pkg/logging, pkg/rpm, pkg/feeds, pkg/eventengine
- **Base in header:** d4506d4450e2 | **Triaged against origin/master:** `57d24d9aed4b64680831a1765a128921e79c00f7`
- **Base == master:** effectively yes (header base is an ancestor; the one cited symbol is byte-identical on current master)
- **Real bpfrx or avacado:** REAL bpfrx (all cited file:line resolve on origin/master; module `github.com/psaab/xpf`, `go 1.24.9`)
- **Outcome counts (10 findings):** GENUINE-RESIDUAL 0 · NOT-MATERIAL 1 (A9-01) · DUP/known 1 (A9-07) · NEGATIVE 8 (A9-02/03/04/05/06/08/09/10; A9-03/08 also DELIBERATE, A9-09 also cross-refs #3934) · CONFABULATED 0

This review is self-described as "no new High/Confident issues"; its one actionable
item (A9-01, MEDIUM) is refuted below by the pinned toolchain's runtime semantics.

---

## A9-01 — SNMPv3 privParams RNG error unchecked — **NOT-MATERIAL (refuted)**

**Reviewer claim:** MEDIUM/High. `encryptDES` (`pkg/snmp/v3.go:778`) and `encryptAES128`
(`pkg/snmp/v3.go:802`) call `rand.Read(privParams)` and discard the `(n, err)` return.
On RNG failure `privParams` stays zero-filled → deterministic AES-128-CFB IV
(`boots||time||0000...`) / DES-CBC IV = `preIV` → keystream / equality leak.

**Symbol check — EXISTS, cited accurately.**
```
pkg/snmp/v3.go:771  func encryptDES(privKey, data []byte) ([]byte, []byte) {
pkg/snmp/v3.go:777      privParams := make([]byte, 8)
pkg/snmp/v3.go:778      rand.Read(privParams)              // return discarded — confirmed
pkg/snmp/v3.go:797  func encryptAES128(privKey, data []byte, boots, time int) ([]byte, []byte) {
pkg/snmp/v3.go:801      privParams := make([]byte, 8)
pkg/snmp/v3.go:802      rand.Read(privParams)              // return discarded — confirmed
```
Import is `crypto/rand` (v3.go:9), not `math/rand`. The observation (return discarded,
inconsistent with wgkey/configstore/api sites that check) is factually correct.

**Why NOT-MATERIAL — the exploit scenario is unreachable on the pinned toolchain.**
The described failure mode requires `crypto/rand.Read` to *return* with `err != nil`
leaving `privParams` zero/partial. On Go 1.24+ that cannot happen. `go.mod` pins
`go 1.24.9`. Go 1.24 changed `crypto/rand.Read` so it never returns a usable error —
it fills the buffer entirely or crashes the program irrecoverably before returning.
Verified directly in the toolchain source (`$GOROOT/src/crypto/rand/rand.go`, Go 1.24
semantics identical in the 1.26 tree present on this box):

```go
// Read fills b with cryptographically secure random bytes. It never returns an
// error, and always fills b entirely.
//
// Read calls io.ReadFull on Reader and crashes the program irrecoverably if
// an error is returned. ...
func Read(b []byte) (n int, err error) {
    ...
    fatal("crypto/rand: failed to read random data (see https://go.dev/issue/66821): " + err.Error())
    panic("unreachable") // To be sure.
}
```

Trace: at `v3.go:778`/`:802`, when `rand.Read` **returns**, `err` is provably `nil`
and `privParams` is fully populated with 8 random bytes; the only alternative is a
`fatal()` crash of xpfd inside `rand.Read` (SNMP goroutine → whole process). There is
no code path where `encryptDES`/`encryptAES128` proceed with a zero/partial salt.
The zero-salt deterministic-IV window the finding relies on does not exist.

Consequence for the proposed fix: adding `if _, err := rand.Read(privParams); err != nil { return nil, nil }`
would be **dead code** on go 1.24.9 (the `!= nil` branch is unreachable when `Read`
returns). The other sites the finding cites as the "correct pattern" (wgkey.go:101,
configstore/crypto.go:95) are equally dead error-checks post-1.24 — harmless belt, but
their presence is a style choice, not a security requirement the SNMP sites violate.

**Residual character:** purely cosmetic consistency nit (three-line style parity), no
reachable correctness or confidentiality defect. The finding's own Refutation section
already self-rates practical risk "very low" and notes `/dev/urandom` never fails on a
healthy host; it simply missed the decisive fact that the pinned toolchain converts
that rare failure into a crash, not a silent zero-salt. This is the A2/#4572 pattern:
headline (deterministic IV) neutralized by an upstream guard (the Go runtime).

**Dedup:** no existing issue tracks SNMP privParams RNG; not in the #4517–#4581 range
(that range covers EH/screens/session-cache/nat64-HA/VRRP/WG/IPsec/PBR/CGNAT/RA/CLI/
zeroize #4576/commit-confirmed #4577 — none SNMP-crypto). Not a DUP; disposition is
driven by unreachability, not prior coverage.

**Not filed as a residual.** If the maintainer wants byte-level style parity, a
follow-up "add dead err-check to snmp encrypt* for grep-consistency" is optional and
LOW/INFO — but it fixes no reachable defect.

---

## A9-02 — IPFIX ODID collision — **NEGATIVE (reviewer self-refuted, correct)**

Reviewer rates INFO/Low and concludes not exploitable. `stableExporterID` keys on
(protocol, instance, template); `Sampling.Instances` is a flat map keyed by name, so
two configs with the same InstanceName ARE the same instance (same collectors/rate).
Reasoning is sound; no collision path. Cited symbols (netflow.go NewExporter,
ipfix.go NewIPFIXExporter, exporterid.go, manager.go Resolve*TemplateGroups) are real.
No residual.

## A9-03 — RPM ICMP echoID predictable — **NEGATIVE / DELIBERATE**

`pkg/rpm/icmp.go:193` `id := int(uint16(os.Getpid()) ^ uint16(echoIDCounter.Add(1)))`.
ID/seq matching on a raw ICMP socket is the standard ping(8) mechanism; an on-path
attacker who can inject ICMP replies can already inject arbitrary packets, and a forged
PASS only delays failover by one probe interval before the next real probe fails.
By-design, matches every ping implementation. No residual.

## A9-04 — Event engine within Seconds==0 fail-closed — **NEGATIVE**

`pkg/eventengine/engine.go:1163-1165` `if wc.Seconds <= 0 || (wc.TriggerOn <= 0 && wc.TriggerUntil <= 0) { return false }`
is fail-closed; commit-time validator `validateEventOptionsWithinAST` rejects zero;
regression tests engine_4423_test.go / engine_within_failclosed_3751_test.go pin it.
Correct defense-in-depth. No residual.

## A9-05 — RPM buffered-event replay race — **NEGATIVE**

`pkg/rpm/rpm.go:226-239` `SetEventCallback` snapshots+nils `bufferedEvents` under `m.mu`,
then replays `fn(ev)` outside the lock. Concurrent `fireEvent` and replay both funnel to
`eventengine.Engine.HandleEvent`, which serializes on `e.mu`; `enqueue` is a channel send.
Each event delivered exactly once (buffered XOR direct); window math is wall-clock, not
sequence-ordered. Logically-interleaved but data-race-free. Reviewer's analysis correct.
No residual.

## A9-06 — flowBatch.maxDepth load-then-store — **NEGATIVE**

`pkg/flowexport/transport.go:403-422`: writers serialized by `b.mu`, readers use atomic
`Load()`. Worst case HWM under-reports by one concurrent-add for one cycle and
self-corrects; HWM is a monotonic diagnostic, not flow-control. Safe. No residual.

## A9-07 — Syslog TLS nil *tls.Config uses system roots — **DUP / KNOWN (#3350 / A8-N-11)**

`pkg/daemon/daemon_system.go:116-124` comment + `pkg/config/compiler_security_log.go:196`
show a named `transport tls-profile` is **rejected at commit** by
`validateSecurityLogStreamTLSProfileAST`, so the silent-system-root downgrade cannot be
configured. Reviewer explicitly cross-refs #3350 / A8-N-11 and does not re-report.
Terminal (already tracked). No new residual.

## A9-08 — RPM http-get default TLS verify (no pinning) — **NEGATIVE / DELIBERATE**

`pkg/rpm/rpm.go:741-771` uses default `http.Transport` (system CA roots, no
`InsecureSkipVerify`, no pinning). http-get is a liveness probe; system-root verification
is the standard Go posture and prevents random-endpoint spoofing while allowing PKI-backed
internal targets. MITM only shifts failover timing by a probe interval. By-design.
No residual.

## A9-09 — Feeds 30s total timeout / single GET per tick — **NEGATIVE (cross-refs #3934)**

`pkg/feeds/feeds.go` caps: 30s client timeout (slow-loris), 1 MiB/line, 32 MiB body via
`countingReader`+`io.LimitReader(...+1)`, 1 MiB prefix count, `retainForever` stale
default. Single GET, retry-on-next-tick avoids N× amplification of a down feed server.
Correct; #3934 hardening verified. No residual.

## A9-10 — Logging ringbuf 144→152 additive wire growth — **NEGATIVE**

`pkg/logging/ringbuf.go:77-104` compile-time size asserts (`rawEventWireSize=144`,
`rawEventExtSize=152`), additive min-frame acceptance stays 144 (rolling-upgrade safe both
directions), extended-field reads gated on `len(data) >= rawEventWireSize`. All offsets are
compile-time constants; no integer truncation. Correct. No residual.

---

## Bottom line

Zero genuine residuals. The single actionable finding (A9-01) is refuted by the pinned
`go 1.24.9` `crypto/rand.Read` crash-on-failure semantics — its zero-salt deterministic-IV
scenario is unreachable and the proposed err-check would be dead code. The remaining nine
findings are the reviewer's own negatives (8) plus one already-tracked TLS item (#3350).
No new issue warranted.
