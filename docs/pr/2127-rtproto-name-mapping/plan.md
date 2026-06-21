# #2127 — rtProtoName mislabels FRR route protocols

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`rtProtoName()` in `pkg/routing/routes.go` (lines 204-233) converts the
kernel rtnetlink route-protocol byte (`netlink.RouteProtocol`, i.e. the
`rtm_protocol` field on a route) into the xpf protocol name that drives
`show route`. That name is consumed downstream by `protoTag()` (single-
letter Junos marker, `pkg/routing/routeformat.go:11`) and
`junosProtoName()` (long Junos name, `routeformat.go:259`).

The numeric switch arms are wrong against the real kernel constants:

- There is **no `case 187`**, so IS-IS routes (zebra tags them
  `RTPROT_ISIS = 187`) fall through to `default: strconv.Itoa(pi)` and
  display as the literal string `"187"`. `protoTag("187")` returns `"?"`
  in `show route terse`; `junosProtoName("187")` returns `"187"` in the
  detail/summary views — instead of `I` / `IS-IS`. This is a real
  regression for any deployment using IS-IS (`set protocols isis`,
  rendered as `router isis xpf` in `policy_render.go`; IS-IS is listed as
  supported in CLAUDE.md).
- `case 11` (`RTPROT_ZEBRA = 11`) is mislabeled `"ospf"`.
- `case 12` (`RTPROT_BIRD = 12`) is mislabeled `"isis"`.
- `case 196` is labeled `// RTPROT_ZEBRA — FRR staticd-installed routes`,
  but `196` is **not** a kernel rtproto constant and ZEBRA is actually
  `11`. The comment is wrong and the arm is effectively dead.

Display-only; no forwarding impact. Severity LOW.

## Ground-truth verification (done before drafting)

Confirmed the constant values two ways:

1. `go run` against `golang.org/x/sys/unix` inside this module:
   `RTPROT_REDIRECT=1 KERNEL=2 BOOT=3 STATIC=4 RA=9 ZEBRA=11 BIRD=12
   DHCP=16 BABEL=42 BGP=186 ISIS=187 OSPF=188 RIP=189`.
2. `/usr/include/linux/rtnetlink.h`: `RTPROT_ZEBRA 11 /* Zebra */`,
   `RTPROT_BIRD 12 /* BIRD */`, `RTPROT_DHCP 16`, `RTPROT_BABEL 42`,
   `RTPROT_BGP 186`, `RTPROT_ISIS 187`, `RTPROT_OSPF 188`,
   `RTPROT_RIP 189`.

So the current code's `186->bgp`, `188->ospf`, `189->rip` are CORRECT;
`11->ospf`, `12->isis`, missing-187, and `196->static` are the bugs.

### What FRR's daemons actually install

FRR's zebra programs the kernel FIB and stamps each route's
`rtm_protocol` with the originating client protocol's value, using the
upstream-assigned `RTPROT_*` numbers above:

- bgpd → `RTPROT_BGP` (186)
- ospfd/ospf6d → `RTPROT_OSPF` (188)
- isisd → `RTPROT_ISIS` (187)
- ripd/ripngd → `RTPROT_RIP` (189)
- staticd → routes carry the route's own configured protocol; FRR's
  default for zebra/staticd-originated entries that have no dedicated
  rtproto is `RTPROT_ZEBRA` (11) unless `zebra` is built to use a
  distinct value. In practice xpf installs static routes through FRR's
  managed config; those that zebra stamps as ZEBRA appear as 11.
- connected/kernel → the kernel itself uses `RTPROT_KERNEL` (2) for
  link routes and `RTPROT_BOOT`/`RTPROT_STATIC` for boot/manual; these
  are already handled correctly by the existing arms.

Conclusion: 11 (`RTPROT_ZEBRA`) should map to a sensible xpf name. The
issue accepts `11 -> "static"` "to match FRR staticd" provided the
comment is corrected (196 is not ZEBRA). We adopt `11 -> "static"` with
a correct comment. We DROP the `12` (BIRD — not used by FRR/xpf) and
`196` (bogus) arms so they fall through to `default` (numeric string),
which is the honest behavior for a protocol byte xpf does not recognize.

## Concrete design

Rewrite `rtProtoName` to use the named `unix.RTPROT_*` constants
throughout (no magic numbers), add the IS-IS arm, fix ZEBRA, drop BIRD
and the bogus 196:

```go
// rtProtoName maps a netlink route protocol to its xpf protocol name.
//
// The protocol byte is the kernel rtnetlink rtm_protocol value. FRR's
// zebra stamps FIB routes with the originating daemon's RTPROT_*
// value (bgpd->BGP, ospfd->OSPF, isisd->ISIS, ripd->RIP); zebra/staticd
// routes appear as RTPROT_ZEBRA. Values xpf does not recognize fall
// through to their numeric string.
func rtProtoName(p netlink.RouteProtocol) string {
	switch int(p) {
	case unix.RTPROT_REDIRECT:
		return "redirect"
	case unix.RTPROT_KERNEL:
		return "connected"
	case unix.RTPROT_BOOT:
		return "dhcp"
	case unix.RTPROT_STATIC:
		return "static"
	case unix.RTPROT_DHCP: // 16
		return "dhcp"
	case unix.RTPROT_ZEBRA: // 11 — FRR zebra/staticd-installed routes
		return "static"
	case unix.RTPROT_BGP: // 186
		return "bgp"
	case unix.RTPROT_ISIS: // 187
		return "isis"
	case unix.RTPROT_OSPF: // 188
		return "ospf"
	case unix.RTPROT_RIP: // 189
		return "rip"
	default:
		return strconv.Itoa(int(p))
	}
}
```

Notes:
- All arms keyed on named constants; comments give the numeric value for
  the reader.
- `RTPROT_ZEBRA` (11) -> "static" replaces the wrong `11 -> "ospf"`.
- IS-IS (187) added.
- BIRD (12) and the bogus 196 arms removed -> they now hit `default`.
- `unix.RTPROT_STATIC` (4) and `unix.RTPROT_ZEBRA` (11) both return
  "static" — intentional: both are operator/FRR-originated static-style
  routes and Junos shows them as `S`/`Static`.

## Public API preservation

`rtProtoName` is an unexported helper. Its only caller is
`routes.go:171` (`Protocol: rtProtoName(r.Protocol)`). Signature
unchanged: `func rtProtoName(p netlink.RouteProtocol) string`. No
exported API touched. `protoTag` / `junosProtoName` unchanged — the
existing names ("isis", "static", etc.) already map correctly there
(`protoTag("isis")="I"`, `junosProtoName("isis")="IS-IS"`), so fixing
the producer is sufficient.

## Out of scope (explicitly)

- `pkg/frr/status_parse.go` `Protocol` field — that comes from FRR's
  vtysh JSON `protocol` string (already a name like "isis"), a separate
  path from the netlink rtproto byte. Not touched.
- Any change to `protoTag`/`junosProtoName` (they already handle the
  five corrected names).
- Adding RA (9) / Babel (42) arms — xpf does not surface those today;
  leaving them to `default` is acceptable and keeps the change minimal.

## Hidden invariants the change must preserve

- The five correct arms (REDIRECT, KERNEL->connected, BOOT->dhcp,
  STATIC->static, BGP/OSPF/RIP) keep their current outputs.
- `default` still returns the numeric string for unknown protos (so the
  output is never empty / never panics).
- DHCP (16) still -> "dhcp" (now via `unix.RTPROT_DHCP`).

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Only changes outputs for 11/12/187/196 inputs; 11 and 187 were already wrong/unmapped, 12/196 are not produced by FRR. Correct arms untouched. |
| Lifetime / borrow | N/A | Go, no borrow checker; pure value switch. |
| Performance | NONE | Same O(1) switch; display-only path. |
| Architectural mismatch | NONE | Direct correction of a lookup table; no new abstraction. |

## Test plan

New table-driven unit test in a new file
`pkg/routing/rtproto_test.go` (package `routing`, so it can call the
unexported `rtProtoName`). Assert, using the `unix.RTPROT_*` constants
as inputs (not magic numbers), that each maps to the expected name:

- `unix.RTPROT_ISIS` (187) -> "isis"  ← the regression the issue is about
- `unix.RTPROT_BGP` (186) -> "bgp"
- `unix.RTPROT_OSPF` (188) -> "ospf"
- `unix.RTPROT_RIP` (189) -> "rip"
- `unix.RTPROT_ZEBRA` (11) -> "static" (was "ospf" — fails pre-fix)
- `unix.RTPROT_KERNEL` (2) -> "connected"
- `unix.RTPROT_STATIC` (4) -> "static"
- `unix.RTPROT_BOOT` (3) -> "dhcp"
- `unix.RTPROT_DHCP` (16) -> "dhcp"
- `unix.RTPROT_REDIRECT` (1) -> "redirect"
- `unix.RTPROT_BIRD` (12) -> "12" (now falls through — was wrongly "isis")
- 196 -> "196" (now falls through — was wrongly "static")
- an arbitrary unknown (e.g. 250) -> "250"

Non-tautological: the test fails against pre-fix master for
`RTPROT_ISIS` (would be "187"), `RTPROT_ZEBRA` (would be "ospf"),
`RTPROT_BIRD` (would be "isis"), and 196 (would be "static").

Additionally a thin assertion that the produced name feeds the
formatters correctly: `protoTag(rtProtoName(unix.RTPROT_ISIS)) == "I"`
and `junosProtoName(rtProtoName(unix.RTPROT_ISIS)) == "IS-IS"` — proving
the end-to-end `show route` fix, not just the producer.

Gates:
- `go build ./...`
- `go test ./pkg/routing/...` (and full `go test ./...`)
- `go vet ./pkg/routing/...`

This is a CONTROL-PLANE (route-display) change with NO dataplane /
forwarding impact, so per the task's standing constraints there is NO
cluster smoke (no iperf3, no CoS matrix). The unit test is the
validation.

## Docs

No operator-facing doc claims the wrong mapping; `show route` output is
behavior, not documented as a table. The code comment is corrected
in-place. No separate doc update needed (stated here per the
documentation-contract rule).

## Open questions for adversarial review

1. Is `RTPROT_ZEBRA` (11) -> "static" the right name, or should it be a
   distinct "zebra"/"frr" name? (Junos has no "zebra" protocol; `S`/
   Static is the closest faithful mapping. PLAN-KILL the 11 arm if you
   think dropping it to `default` ("11") is more honest.)
2. Should BIRD (12) and 196 be DROPPED (fall through to numeric) as
   planned, or remapped? Is there any xpf/FRR path that installs 12 or
   196 today? (I found none.)
3. Should RA (9) and Babel (42) be added now, or is leaving them to
   `default` acceptable for this focused fix?
4. `unix.RTPROT_STATIC` (4) and `unix.RTPROT_ZEBRA` (11) both -> "static".
   Any reason these must be distinguished in `show route`?
5. Is a new file `rtproto_test.go` the right home, or should the test go
   into an existing `routing_test.go`? (New file keeps the focused fix
   self-contained.)
6. Any concern that switching from magic numbers to `unix.RTPROT_*`
   constants could change behavior on a non-Linux build? (pkg/routing is
   Linux-only; netlink is Linux-only — no cross-platform risk.)
