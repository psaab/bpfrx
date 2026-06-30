// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// nftApplyPayload runs `nft -f -` with the supplied ruleset payload on stdin.
// It is a package var so the host-inbound apply path's failure semantics are
// unit-testable without invoking nft (#3333). The 5s context + WaitDelay mirror
// the established inline apply sites (#1794): an `-f -` payload loads atomically,
// so on failure the kernel retains the PREVIOUS table untouched rather than a
// half-applied ruleset.
var nftApplyPayload = func(payload string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(payload)
	return cmd.CombinedOutput()
}

// nftDeleteTable idempotently removes an nft table using only the universally
// available `add` / `delete` verbs (NOT `nft destroy`). `destroy` is a recent
// nftables verb and the project does not pin a minimum nftables version
// (debian/control depends on UNVERSIONED `nftables`, with no preflight), so a
// `destroy` dependency would raise "unknown command" on any non-floor base —
// and, now that teardown failures propagate (#3333), that would fail EVERY
// commit. Instead emit a two-line `nft -f -` payload: `add table` makes the
// table exist (a no-op when it already does), so the following `delete table`
// always has a target whether or not the table pre-existed — idempotent without
// `destroy`. A genuine failure (permissions / kernel) still surfaces on either
// line. This mirrors the established in-tree `delete table` idiom (applyLo0Filter
// below, scripts/migrate-bpfrx-to-xpf.sh) and reuses the atomic nftApplyPayload
// runner. Package var for test failure injection.
var nftDeleteTable = func(family, name string) ([]byte, error) {
	payload := "add table " + family + " " + name + "\n" +
		"delete table " + family + " " + name + "\n"
	return nftApplyPayload(payload)
}

// Base-chain hook-input priorities for the two daemon-generated local-delivery
// nftables tables (#3364). Both register `type filter hook input`, but at
// DISTINCT priorities so their inter-chain evaluation order is a deterministic
// product invariant rather than implementation-defined. With two base chains at
// an IDENTICAL hook/priority, netfilter's order between them is unspecified, so
// which chain's reject/log/counter fires for a packet both would act on could
// vary silently across nft/kernel versions (a `drop` stays terminal regardless,
// so this was never a permit bypass — only an observability/determinism gap).
//
// Ordering: xpf_lo0 evaluates BEFORE xpf_hostinbound (lo0 has the strictly lower
// priority number). The lo0.0 input filter is the operator's explicit, named,
// RE-wide control-plane firewall — the authoritative statement of what is
// permitted to the box, written with explicit accept/reject/discard verdicts.
// The zone host-inbound-traffic admission is the coarser Junos default-deny
// backstop. Running the explicit lo0 filter first lets its operator-authored
// verdicts (and their reject messages / per-term effects) take observable
// precedence, with host-inbound governing whatever lo0 did not already
// terminate — the Junos lo0-filter-then-zone ordering. nftApplyPriorityInvariant
// (nft_chain_priority_test.go) pins nftLo0FilterPriority < nftHostInboundPriority
// so the spread cannot silently regress back to a shared priority.
const (
	// nftLo0FilterPriority is the `hook input` priority of the xpf_lo0 loopback
	// input-filter base chain. 0 is the conventional `filter` priority (the lo0
	// chain IS the operator's firewall filter); it is STRICTLY LESS THAN
	// nftHostInboundPriority so lo0 evaluates first.
	nftLo0FilterPriority = 0
	// nftHostInboundPriority is the `hook input` priority of the xpf_hostinbound
	// base chain. It is STRICTLY GREATER THAN nftLo0FilterPriority so the zone
	// host-inbound default-deny backstop runs AFTER the lo0 input filter, and is
	// kept well below the conventional `security` (50) / `srcnat` (100)
	// priorities so it stays within the input-filter band.
	nftHostInboundPriority = 10
)

// applyLo0Filter applies loopback filter rules for host-bound traffic.
// Implements "interfaces lo0 unit 0 family inet filter input <name>" by
// generating nftables rules from the named firewall filter.
//
// Fail-closed (#3392, mirroring the host-inbound #3333 fix): both the apply and
// the teardown surface their failure as a returned error instead of a swallowed
// WARN. applyConfigLocked joins this into the commit result, so a committed lo0
// input filter that did not reach the kernel reports commit FAILURE rather than
// silent success (the lo0 filter is host-protection control-plane enforcement,
// the same class of fail-open #3333 closed for host-inbound). The retained
// kernel state is always the more- or equally-restrictive prior state: an `-f -`
// apply loads atomically (the previous table is kept untouched on failure), and
// a failed teardown leaves the existing filter in place — neither relaxes
// enforcement silently. Boot / DHCP re-applies go through applyConfig(), which
// only logs the error, so a transient nft failure cannot brick startup; the next
// clean commit re-renders.
func (d *Daemon) applyLo0Filter(cfg *config.Config) error {
	filterV4 := cfg.System.Lo0FilterInputV4
	filterV6 := cfg.System.Lo0FilterInputV6
	if filterV4 == "" && filterV6 == "" {
		// No lo0 filter configured — remove any stale table. nftDeleteTable is
		// idempotent (an add-then-delete payload, so no error when the table is
		// absent — the common no-lo0-filter case), so a non-nil error here is a
		// REAL teardown failure that left a stale lo0 input filter in the kernel:
		// surface it so the commit fails closed rather than reporting that the lo0
		// filter was removed when it was not.
		if out, err := nftDeleteTable("inet", "xpf_lo0"); err != nil {
			slog.Warn("failed to delete stale lo0 filter table", "err", err, "output", string(out))
			return fmt.Errorf("delete stale lo0 nftables table: %w", err)
		}
		return nil
	}

	nftConf := buildLo0FilterPayload(cfg, filterV4, filterV6)
	if out, err := nftApplyPayload(nftConf); err != nil {
		slog.Warn("failed to apply lo0 filter", "err", err, "output", string(out))
		return fmt.Errorf("apply lo0 nftables filter: %w", err)
	}
	slog.Info("lo0 filter applied", "v4", filterV4, "v6", filterV6)
	return nil
}

// buildLo0FilterPayload assembles the exact nft ruleset payload that
// applyLo0Filter feeds to `nft -f -`. It is split out as a pure function so
// tests can capture and parse-check the full payload (#2069) without invoking
// nft or the daemon apply path. Callers pass the already-resolved v4/v6 filter
// names so the payload reflects exactly what applyLo0Filter would send.
//
// The leading three lines are the atomic flush idiom: create the table if it
// does not yet exist (`table inet xpf_lo0` with no body — idempotent), flush
// its contents, then redefine it. nft parses an `-f -` payload atomically, so
// a syntax error on any line rejects the ENTIRE payload. The pre-#2069
// `flush ruleset inet xpf_lo0` was NOT valid nft — `flush ruleset` takes at
// most an OPTIONAL family (`flush ruleset [<family>]`), never a table name, so
// the trailing table token was a parse error that rejected the whole ruleset
// (incl. the real filter rules) and made the lo0 filter fail OPEN.
func buildLo0FilterPayload(cfg *config.Config, filterV4, filterV6 string) string {
	var rules []string
	rules = append(rules, "table inet xpf_lo0")
	rules = append(rules, "flush table inet xpf_lo0")
	rules = append(rules, "table inet xpf_lo0 {")
	rules = append(rules, "  chain input {")
	// #3364: explicit distinct priority so lo0 evaluates BEFORE xpf_hostinbound.
	rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", nftLo0FilterPriority))

	prefixLists := cfg.PolicyOptions.PrefixLists
	if filterV4 != "" {
		if f, ok := cfg.Firewall.FiltersInet[filterV4]; ok {
			for _, term := range f.Terms {
				r := nftRuleFromTerm(term, "ip", prefixLists)
				if r != "" {
					rules = append(rules, "    "+r)
				}
			}
		}
	}
	if filterV6 != "" {
		if f, ok := cfg.Firewall.FiltersInet6[filterV6]; ok {
			for _, term := range f.Terms {
				r := nftRuleFromTerm(term, "ip6", prefixLists)
				if r != "" {
					rules = append(rules, "    "+r)
				}
			}
		}
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")

	return strings.Join(rules, "\n") + "\n"
}

// applyHostInboundFilter is the KERNEL-nftables PRIMARY enforcement of
// `security zones <z> host-inbound-traffic` (#3070). Ordinary host-bound
// traffic to a firewall interface IP / VRRP VIP (SSH, ping, OSPF/BGP to the
// box — exactly what host-inbound-traffic governs) is shunted to the Linux
// kernel by the XDP shim before it reaches userspace-dp, so the userspace
// LocalDelivery check (forwarding/host_inbound.rs) only catches the narrow
// subset that actually reaches the XSK. This kernel chain enforces the
// host-inbound set for the rest, mirroring the lo0-filter precedent.
//
// Safety: #3405 — EVERY configured security zone gets a rule (Junos default-deny
// parity). A zone with no `host-inbound-traffic` stanza is treated as an empty
// stanza: its firewall-local addresses get a catch-all DROP, denying every
// host-bound service/protocol not explicitly permitted. Management /
// cluster-control lifeline interfaces (fxp0 / em0 / fab*) are excluded from the
// address sets by BuildZoneHostInboundViews, so a host-inbound deny can never
// strand management or break HA. Established sessions and IPv6 ND / PMTUD
// control messages are accepted before any deny.
//
// Fail-closed (#3333): both the apply and the teardown surface their failure as
// a returned error instead of a swallowed WARN. applyConfigLocked joins this
// into the commit result, so a committed host-inbound deny that did not reach
// the kernel reports commit FAILURE rather than silent success. The retained
// kernel state is always the more- or equally-restrictive prior state: an `-f -`
// apply loads atomically (the previous table is kept on failure), and a failed
// teardown leaves the existing deny in place — neither can strand management,
// since lifeline interfaces are excluded from the address sets. Boot / DHCP
// re-applies go through applyConfig(), which only logs the error, so a transient
// nft failure cannot brick startup; the next clean commit re-renders.
func (d *Daemon) applyHostInboundFilter(cfg *config.Config) error {
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !hostInboundHasEnforceableView(views) {
		// No host-inbound-configured zone with a resolvable address — nothing to
		// enforce. Remove any stale table. nftDeleteTable is idempotent (an
		// add-then-delete payload, so no error when the table is absent — the
		// common case), so a non-nil error here is a REAL teardown failure that
		// left a stale deny in the kernel: surface it so the commit fails closed
		// rather than reporting that host-inbound was relaxed when it was not.
		if out, err := nftDeleteTable("inet", "xpf_hostinbound"); err != nil {
			slog.Warn("failed to delete stale host-inbound filter table", "err", err, "output", string(out))
			return fmt.Errorf("delete stale host-inbound nftables table: %w", err)
		}
		return nil
	}
	nftConf := buildHostInboundFilterPayload(views)
	if out, err := nftApplyPayload(nftConf); err != nil {
		slog.Warn("failed to apply host-inbound filter", "err", err, "output", string(out))
		return fmt.Errorf("apply host-inbound nftables filter: %w", err)
	}
	slog.Info("host-inbound filter applied", "zones", len(views))
	return nil
}

// hostInboundHasEnforceableView reports whether at least one view carries a
// resolvable address. Static, VRRP-VIP and DHCP/DHCPv6-learned addresses all
// count: the live interface snapshot enumerates every kernel address via
// AddrList(FAMILY_ALL), so a DHCP-only interface with a live lease IS scoped
// (#3224 — see BuildZoneHostInboundViews). The only no-address case left is a
// configured zone whose interfaces have no static address AND no live address
// yet (e.g. a DHCP WAN before its first lease). That zone produces nothing; if
// NO zone is enforceable the whole table is removed (it self-heals once an
// address appears, because the lease-change / commit paths re-render).
func hostInboundHasEnforceableView(views []dpuserspace.ZoneHostInboundView) bool {
	for _, v := range views {
		if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
			return true
		}
	}
	return false
}

// buildHostInboundFilterPayload assembles the exact `nft -f -` payload for the
// host-inbound kernel chain. Split out as a pure function so tests can
// parse-check the full payload without invoking nft. A syntax error on any line
// rejects the WHOLE payload (atomic load), so the chain fails closed-as-absent
// rather than half-applied.
//
// Atomic replace idiom: `add table` (create if absent), `delete table` (now
// always has a target -> removes the old chain AND its stateful objects), then a
// fresh `table { ... }` body. This replaces the plain create/flush/redefine used
// by lo0: `flush table` empties rules but does NOT delete named counter objects,
// so redeclaring the per-zone DROP counters (below) on the next commit would
// collide ("File exists"). delete+recreate guarantees the named counters are
// declared exactly once and never leaves a stale counter for a removed zone.
// (A consequence: the host-inbound deny counters reset to zero on every
// rebuild — every commit and every DHCP/DHCPv6 address change that re-renders
// the table. Prometheus rate() handles the reset; documented on the metric.)
//
// Layout of `chain input` (type filter hook input priority 10; policy accept —
// distinct from the xpf_lo0 chain's priority 0 so this host-inbound backstop
// evaluates AFTER the lo0 input filter, #3364):
//  1. ct state established,related accept   — return/ongoing host traffic.
//  2. meta l4proto { 50, 51 } accept — raw ESP/AH exemption for host-terminated
//     IPsec (mirrors the userspace stage_ipsec_passthrough_check); the kernel
//     XFRM stack decrypts before any host-inbound deny can apply.
//  3. icmpv6 ND + error/PMTUD accept, icmp error/PMTUD accept — IPv6 Neighbor
//     Discovery and v4/v6 PMTUD/error control messages (dest-unreachable,
//     packet-too-big, time-exceeded, parameter-problem) are mandatory link
//     operation, never a "service" exposure; accepted globally so a host-inbound
//     set omitting `ping` does not black-hole PMTUD/ND/error delivery. This set
//     is mirrored by the userspace host-inbound exemption (#3171) so kernel and
//     XSK LocalDelivery agree. Echo-request stays gated on the `ping` service.
//  4. Per host-inbound-configured zone, per family with addresses:
//     - if `system-services all` / `any-service`: <fam> daddr <addrs> accept
//     (and no deny — the operator opened the zone to all services).
//     - else: one accept per listed service/protocol scoped to the zone addrs
//     (`protocols all` expands to the routing-protocol set — #3199, NOT a
//     blanket accept), then a catch-all
//     `<fam> daddr <addrs> counter name "<n>" drop` (Junos default-deny to the
//     host is a silent drop). The named counter `<n>` is declared at the top of
//     the table body and scraped per zone/family into the
//     xpf_host_inbound_kernel_denies_total metric (#3361) — distinct from the
//     userspace-dp xpf_host_inbound_denies_total path (#3326).
func buildHostInboundFilterPayload(views []dpuserspace.ZoneHostInboundView) string {
	// Pre-pass: collect the named DROP counters the chain will reference, so they
	// can be declared at the top of the table body BEFORE the chain. A counter is
	// emitted exactly when emitHostInboundZone emits a catch-all drop
	// (hostInboundEmitsDrop) — the two MUST agree on that condition or nft rejects
	// the load (reference to an undeclared counter / declared-but-unused is fine,
	// but an undeclared reference is a hard error).
	//
	// The counter name is keyed only on (zone, family) — and so is the DROP rule
	// that references it (emitHostInboundZone). With per-interface host-inbound
	// overrides (#3362) a single zone can yield MULTIPLE views sharing the same
	// v.Zone (an override view plus the zone-default view), each emitting its own
	// catch-all DROP that references the same "<zone>_<fam>" counter. That is the
	// intended aggregation (one per-zone/family kernel-deny counter the #3361
	// scraper reads back via ParseHostInboundDenyCounterName), but the declaration
	// must be emitted EXACTLY ONCE: nft rejects `counter <name> {}` declared
	// twice in the same table body ("File exists"). Dedup the declarations on the
	// counter NAME so each is declared once no matter how many views share a zone;
	// the per-view DROP rules below still all reference it.
	var counters []string
	seenCounter := map[string]bool{}
	addCounter := func(name string) {
		if seenCounter[name] {
			return
		}
		seenCounter[name] = true
		counters = append(counters, name)
	}
	for _, v := range views {
		if hostInboundEmitsDrop(v, v.V4Addrs) {
			addCounter(xnft.HostInboundDenyCounterName(v.Zone, "ip"))
		}
		if hostInboundEmitsDrop(v, v.V6Addrs) {
			addCounter(xnft.HostInboundDenyCounterName(v.Zone, "ip6"))
		}
	}

	var rules []string
	rules = append(rules, "add table inet xpf_hostinbound")
	rules = append(rules, "delete table inet xpf_hostinbound")
	rules = append(rules, "table inet xpf_hostinbound {")
	for _, cn := range counters {
		// The DECLARATION must be UNQUOTED (#3578): nft v1.1.6 rejects a quoted
		// name in a counter declaration (`counter "<n>" {}` -> "syntax error,
		// unexpected quoted string"), even though it accepts a quoted name in the
		// REFERENCE below. cn is sanitized to a bare-safe nft identifier by
		// HostInboundDenyCounterName, so the unquoted declaration always parses and
		// matches the (quoted) reference object name byte-for-byte.
		rules = append(rules, "  counter "+cn+" {")
		rules = append(rules, "  }")
	}
	rules = append(rules, "  chain input {")
	// #3364: explicit distinct priority so host-inbound evaluates AFTER xpf_lo0.
	rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", nftHostInboundPriority))
	rules = append(rules, "    ct state established,related accept")
	// Raw ESP (50) / AH (51) are exempt from host-inbound enforcement so the
	// kernel XFRM stack can decrypt host-terminated IPsec — mirroring the
	// userspace stage_ipsec_passthrough_check, which runs BEFORE
	// host_inbound_admits (poll_descriptor mod.rs). Standard vSRX configures the
	// IPsec external zone with host-inbound `system-services { ike; }` (IKE
	// alone; ESP implicitly permitted): the `ike` token already accepts udp
	// 500/4500 (so IKE and NAT-T survive), and this exempts the raw ESP/AH data
	// plane (typical site-to-site). Without it a scoped `daddr <wan-ip> drop`
	// would black-hole the tunnel AFTER IKE succeeds — a silent upgrade
	// regression once #3070 turns a previously-no-op `ike` stanza into real
	// enforcement.
	rules = append(rules, "    meta l4proto { 50, 51 } accept")
	// IPv6 ND + v4/v6 PMTUD/error control messages — accepted regardless of the
	// host-inbound set so enforcement never breaks core L3 operation. The ICMP
	// error subtypes accepted here MUST stay in lock-step with the userspace
	// host-inbound exemption (`is_icmp_host_inbound_error` in
	// userspace-dp/.../forwarding/host_inbound.rs, #3171) so the kernel chain and
	// the XSK LocalDelivery classifier agree on a configured ping-less zone.
	// icmpv6 type 1 (destination-unreachable), 2 (packet-too-big, PMTUD), 3
	// (time-exceeded), 4 (parameter-problem) carry v6 error/PMTUD/traceroute
	// signalling; 133-137 are Neighbor Discovery. ICMPv4 destination-unreachable
	// (3, also PMTUD frag-needed code 4), time-exceeded (11, traceroute) and
	// parameter-problem (12) are the v4 error set. Echo-request is NOT here — it
	// stays gated on the per-zone `ping` system-service.
	rules = append(rules, "    icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } accept")
	rules = append(rules, "    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept")

	for _, v := range views {
		emitHostInboundZone(&rules, v, "ip", v.V4Addrs)
		emitHostInboundZone(&rules, v, "ip6", v.V6Addrs)
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")
	return strings.Join(rules, "\n") + "\n"
}

// hostInboundEmitsDrop reports whether emitHostInboundZone will emit a catch-all
// DROP (and therefore a named DROP counter) for this zone/family. A drop is
// emitted whenever the family has at least one address AND the zone is not opened
// to all services (`system-services all`/`any-service`). buildHostInboundFilterPayload
// uses this to pre-declare the matching counter objects, so the two sites cannot
// diverge on which (zone, family) pairs get a counter.
func hostInboundEmitsDrop(v dpuserspace.ZoneHostInboundView, addrs []string) bool {
	return len(addrs) > 0 && !hostInboundAllowsAll(v)
}

// emitHostInboundZone appends the accept(+drop) rules for one zone/family to
// rules. No-op when the zone has no address in this family.
func emitHostInboundZone(rules *[]string, v dpuserspace.ZoneHostInboundView, family string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	daddr := family + " daddr " + nftAddrSet(addrs)
	// Only `system-services all` / `any-service` fully opens the zone: accept
	// everything to its addresses, emit no deny. `protocols all` is scoped to
	// the routing-protocol set (#3199) and flows through the per-match path
	// below, so it still gets a catch-all drop for non-routing traffic.
	if hostInboundAllowsAll(v) {
		*rules = append(*rules, "    "+daddr+" accept")
		return
	}
	rulesSet := hostInboundMatchSet(v, family)
	// Zero recognized service/protocol matches for this configured zone — a zone
	// with NO `host-inbound-traffic` stanza (#3405 default-deny parity), an empty
	// `host-inbound-traffic { }` stanza (#3200), or (on the tolerant load path) a
	// zone whose every token was an unrecognized typo that commit-time validation
	// downgraded to a warning rather than rejected. Fall through to emit ONLY the
	// catch-all drop below: the operator opened nothing, so Junos denies all
	// host-bound traffic to the zone, and the Rust AF_XDP classifier already fails
	// CLOSED for the same case (host_inbound_admits returns deny when the zone is
	// configured but matches nothing). Emitting nothing here would fail OPEN and leave the
	// kernel and Rust paths in disagreement — the #3200 split-brain. Management
	// / cluster-control lifeline interfaces are excluded from v.V4Addrs /
	// v.V6Addrs by BuildZoneHostInboundViews, and the established / ESP-AH / ND
	// / PMTUD accepts precede this drop, so a zero-match zone cannot strand
	// management or break HA. The strict commit path rejects unknown tokens
	// outright (validateHostInboundTokensStrict), so this zero-match branch is
	// normally reachable only for a genuinely empty stanza.
	// Each recognized service/protocol match is emitted with its per-token
	// nft verdict. Almost every host-inbound token is a plain `accept`;
	// `system-services ident-reset` is the lone exception (#3310): Junos
	// ident-reset actively RESETS inbound ident (auth/TCP-113) probes rather
	// than admitting them, so its rule carries `reject with tcp reset`. The
	// reject rule is emitted here, BEFORE the catch-all drop below, so a fresh
	// ident SYN (no `established` state) hits it; the leading
	// `ct state established,related accept` and the global ND/ESP/ICMP accepts
	// still precede it (a fresh probe is a SYN, so this is fine).
	for _, m := range rulesSet {
		*rules = append(*rules, "    "+daddr+" "+m.match+" "+m.action)
	}
	// Catch-all deny for anything else destined to this zone's addresses
	// (Junos default-deny to the host is a silent drop). Attach a named counter
	// (declared at the top of the table body by buildHostInboundFilterPayload) so
	// the kernel host-inbound drops are scrapeable per zone/family (#3361) — the
	// drop was previously uncounted and invisible to operators.
	cn := xnft.HostInboundDenyCounterName(v.Zone, family)
	*rules = append(*rules, "    "+daddr+" counter name \""+cn+"\" drop")
}

// hostInboundAllowsAll reports whether the zone's system-services contains
// `all` / `any-service` (full admit). `protocols all` is deliberately NOT a
// full admit (#3199): in Junos it means all ROUTING protocols, not all
// system-services and not a blanket accept. `protocols all` is expanded to the
// concrete routing-protocol match set by hostInboundProtocolMatches instead, so
// it never opens SSH/HTTPS/SNMP/NETCONF on the box.
func hostInboundAllowsAll(v dpuserspace.ZoneHostInboundView) bool {
	for _, s := range v.SystemServices {
		if s == "all" || s == "any-service" {
			return true
		}
	}
	return false
}

// hostInboundReject is the nft verdict for `system-services ident-reset`: a
// TCP reset (RST) for inbound ident (auth/TCP-113) probes, not an admit (#3310).
// nftables synthesizes an RFC-correct RST (RST|ACK with seq/ack reflecting the
// inbound SYN) for the matched TCP packet, exactly Junos ident-reset semantics.
// This is the only host-inbound token that emits a `reject` rather than
// `accept`. Validated to parse on the appliance nft (v1.1.x) in an `inet`
// filter input chain by TestHostInboundFilterIdentResetPayloadParses.
const hostInboundReject = "reject with tcp reset"

// hostInboundAccept is the default host-inbound verdict (admit the service to
// the host stack). Every recognized system-service / protocol uses it except
// ident-reset (see hostInboundServiceAction).
const hostInboundAccept = "accept"

// hostInboundRule pairs an nft match fragment (WITHOUT the leading daddr) with
// the nft verdict to apply to it. Almost every host-inbound token is an
// `accept`; ident-reset resets TCP/113 (#3310), so the verdict must travel with
// the match rather than being a uniform trailing `accept`.
type hostInboundRule struct {
	match  string // nft match fragment, e.g. "tcp dport 22"
	action string // nft verdict, e.g. "accept" or "reject with tcp reset"
}

// hostInboundServiceAction returns the nft verdict for a `system-services`
// token. Junos `ident-reset` actively RESETS inbound ident (TCP/113) probes
// rather than permitting the service (#3310), so it maps to
// `reject with tcp reset`; every other recognized service is a plain admit.
// Protocols (routing) are always admits, so they do not consult this.
func hostInboundServiceAction(token string) string {
	if token == "ident-reset" {
		return hostInboundReject
	}
	return hostInboundAccept
}

// hostInboundMatchSet returns the de-duplicated nft match fragments — each
// paired with its nft verdict (hostInboundRule) — admitted (or, for
// ident-reset, reset) by the zone's system-services + protocols for the given
// family ("ip" / "ip6"). The match clause carries NO leading daddr or trailing
// verdict; emitHostInboundZone prepends the daddr and appends rule.action.
//
// This is the Go/nftables MIRROR of the Rust classifier in
// userspace-dp/src/afxdp/forwarding/host_inbound.rs — keep the two token sets
// in sync (the recognized-token SSOT is config.KnownHostInboundSystemServices /
// config.KnownHostInboundProtocols; TestHostInboundNftMatchesKnownTokens
// asserts this matcher's domain equals that SSOT). An unrecognised token
// contributes nothing here; if it leaves the zone with zero recognized matches,
// emitHostInboundZone emits a catch-all drop (fail CLOSED, matching the Rust
// classifier). Strict commit-time rejection of unknown tokens lands in
// validateHostInboundTokensStrict (#3200), so a zero-match zone normally only
// arises from a genuinely empty `host-inbound-traffic { }` stanza.
//
// #3310 note: ident-reset carries the `reject with tcp reset` verdict on the
// kernel (primary) path. The Rust AF_XDP secondary path does NOT admit TCP/113
// (host_inbound.rs ident-reset arm is a no-op for the admit set), so the rare
// AF_XDP-reached ident packet is dropped there rather than reset — a documented
// divergence (the AF_XDP path is reached only by DNAT/static-NAT-to-113, an
// edge of an edge; the kernel chain carries ~100% of real ident probes). Both
// layers stop the prior plain-admit of 113.
func hostInboundMatchSet(v dpuserspace.ZoneHostInboundView, family string) []hostInboundRule {
	var out []hostInboundRule
	seen := map[string]bool{}
	add := func(m, action string) {
		if m == "" {
			return
		}
		// Dedup on the match fragment: no two host-inbound tokens map to the
		// same match with different verdicts (ident-reset's `tcp dport 113` is
		// unique — pgm's proto-113 is `meta l4proto 113`, a different match), so
		// match-keyed dedup cannot drop or shadow a reject rule.
		if seen[m] {
			return
		}
		seen[m] = true
		out = append(out, hostInboundRule{match: m, action: action})
	}
	for _, s := range v.SystemServices {
		action := hostInboundServiceAction(s)
		for _, m := range hostInboundServiceMatches(s, family) {
			add(m, action)
		}
	}
	for _, p := range v.Protocols {
		for _, m := range hostInboundProtocolMatches(p, family) {
			add(m, hostInboundAccept)
		}
	}
	return out
}

// hostInboundServiceMatches maps a Junos `system-services` token to nft match
// fragments for the given family. Returns nil for `all` / `any-service`
// (handled by hostInboundAllowsAll) and for unrecognised tokens (fail-closed).
func hostInboundServiceMatches(token, family string) []string {
	// #3225: family-specific services (dhcp=v4, dhcpv6=v6) emit ONLY on their
	// own family. emitHostInboundZone calls this once per family with the same
	// token set, so a family-mismatched token must contribute no match (it would
	// otherwise be emitted under the wrong `ip`/`ip6 daddr`). The family map is
	// the SSOT shared with the Rust classifier (config.HostInboundServiceFamily).
	if fam, ok := config.HostInboundServiceFamily[token]; ok && fam != family {
		return nil
	}
	icmp := "icmp"
	if family == "ip6" {
		icmp = "icmpv6"
	}
	switch token {
	case "ssh":
		return []string{"tcp dport 22"}
	case "telnet":
		return []string{"tcp dport 23"}
	case "ftp":
		return []string{"tcp dport 21"}
	case "http", "webapi-clear-text":
		return []string{"tcp dport 80"}
	case "https", "webapi-ssl":
		return []string{"tcp dport 443"}
	case "ping":
		return []string{icmp + " type echo-request"}
	case "dns":
		return []string{"udp dport 53", "tcp dport 53"}
	case "dhcp", "bootp":
		return []string{"udp dport { 67, 68 }"}
	case "dhcpv6":
		return []string{"udp dport { 546, 547 }"}
	case "ntp":
		return []string{"udp dport 123"}
	case "snmp":
		return []string{"udp dport 161"}
	case "snmp-trap":
		return []string{"udp dport 162"}
	case "ike", "ipsec":
		// `ipsec` is the Junos system-service that permits host-terminated
		// IPsec: IKE negotiation (udp 500 / NAT-T 4500) plus the ESP/AH data
		// plane. The raw ESP (50) / AH (51) data plane is already accepted
		// globally in buildHostInboundFilterPayload (so the kernel XFRM stack
		// can decrypt), so the per-zone match only needs to open IKE — making
		// `ipsec` a superset of `ike`. Treating them as one case keeps the nft
		// mirror in parity with the Rust classifier.
		return []string{"udp dport { 500, 4500 }"}
	case "tftp":
		return []string{"udp dport 69"}
	case "netconf":
		return []string{"tcp dport 830"}
	case "ssh-netconf", "netconf-ssh":
		return []string{"tcp dport { 22, 830 }"}
	case "finger":
		return []string{"tcp dport 79"}
	case "ident-reset":
		return []string{"tcp dport 113"}
	case "lsping":
		return []string{"udp dport 3503"}
	case "sip":
		return []string{"udp dport 5060", "tcp dport 5060"}
	case "r-login", "rlogin":
		return []string{"tcp dport 513"}
	case "r-sh", "rsh":
		return []string{"tcp dport 514"}
	case "r-exec", "rexec":
		return []string{"tcp dport 512"}
	case "xnm-clear-text":
		return []string{"tcp dport 3221"}
	case "xnm-ssl":
		return []string{"tcp dport 3220"}
	case "traceroute":
		return []string{"udp dport 33434-33523"}
	case "gre":
		return []string{"meta l4proto 47"}
	default:
		return nil
	}
}

// hostInboundProtocolMatches maps a Junos `protocols` (routing-protocol) token
// to nft match fragments. `all` expands to the full routing-protocol set
// (#3199) — NOT a blanket accept (that would open every system-service). Returns
// nil for unrecognised tokens (fail-closed).
func hostInboundProtocolMatches(token, family string) []string {
	// #3225: family-specific routing protocols (ospf=v4 / ospf3=v6, rip=v4 /
	// ripng=v6, igmp=v4) emit ONLY on their own family — the SSOT is
	// config.HostInboundProtocolFamily, shared with the Rust classifier. `all`
	// is dual-family (absent from the map) and recurses into the per-token set,
	// each of which family-gates itself here.
	if fam, ok := config.HostInboundProtocolFamily[token]; ok && fam != family {
		return nil
	}
	switch token {
	case "all":
		// `protocols all` = every recognized routing protocol, scoped to
		// protocol traffic (#3199) — NOT a blanket accept. The expansion set is
		// the SSOT-derived config.HostInboundAllExpansionProtocols()
		// (KnownHostInboundProtocols minus `all` minus the L2/non-IP set
		// config.HostInboundL2Protocols), so an L2 protocol like IS-IS is
		// AUTOMATICALLY excluded from the IP expansion — adding one to the SSOT
		// requires no edit here (#3311). ospf+ospf3 both appear (#3225): both
		// ride IP protocol 89 but on different families; hostInboundProtocolMatches
		// family-gates each, so proto 89 emits once per family. The Rust `all`
		// arm mirrors this exclusion via routing_protocol_all_expansion().
		var out []string
		for _, p := range config.HostInboundAllExpansionProtocols() {
			out = append(out, hostInboundProtocolMatches(p, family)...)
		}
		return out
	case "ospf", "ospf3":
		// OSPFv2 (ospf, IPv4) and OSPFv3 (ospf3, IPv6) both ride IP protocol 89;
		// the family gate above scopes each to its own family.
		return []string{"meta l4proto 89"}
	case "bgp":
		return []string{"tcp dport 179"}
	case "rip":
		return []string{"udp dport 520"}
	case "ripng":
		return []string{"udp dport 521"}
	case "igmp":
		// v6 multicast group membership is MLD (icmpv6), reached via the ND
		// accept; the family gate restricts igmp to IPv4.
		return []string{"meta l4proto 2"}
	case "pim":
		return []string{"meta l4proto 103"}
	case "vrrp":
		return []string{"meta l4proto 112"}
	case "bfd":
		// #3299: single-hop control (3784) + echo (3785) AND multi-hop
		// control (4784, RFC 5883). Keep this set in lockstep with the
		// AF_XDP host_inbound classifier (host_inbound.rs "bfd" arm).
		return []string{"udp dport { 3784, 3785, 4784 }"}
	case "ldp":
		return []string{"tcp dport 646", "udp dport 646"}
	case "msdp":
		return []string{"tcp dport 639"}
	case "nhrp":
		return []string{"meta l4proto 54"}
	case "rsvp":
		// #3341: RSVP rides directly over IP, protocol 46 (dual-family).
		return []string{"meta l4proto 46"}
	case "pgm":
		// #3341: PGM (Pragmatic General Multicast) rides over IP, protocol 113
		// (dual-family).
		return []string{"meta l4proto 113"}
	case "sap":
		// #3341: SAP (Session Announcement Protocol) is UDP/9875 (dual-family).
		return []string{"udp dport 9875"}
	case "dvmrp":
		// #3341: DVMRP is carried inside IGMP (IP protocol 2) and is IPv4-only;
		// the family gate above (config.HostInboundProtocolFamily["dvmrp"]="ip")
		// restricts it to IPv4, matching igmp.
		return []string{"meta l4proto 2"}
	case "isis":
		// #3311: IS-IS rides OSI/CLNP directly over L2 (LLC-encapsulated, NOT
		// IP), so it cannot be expressed as an ip/ip6 host-inbound match. It is
		// a recognized-but-no-op token (config.HostInboundL2Protocols): the
		// kernel delivers IS-IS PDUs to FRR's isisd via an LLC packet socket,
		// outside this IP host-inbound filter. Returning nil keeps this surface
		// consistent with the Rust classifier's isis no-op arm. The nft parity
		// test skips L2 protocols and asserts they produce no IP match.
		return nil
	case "router-discovery":
		if family == "ip6" {
			// v6 RS/RA are part of the always-accepted ND set above.
			return nil
		}
		return []string{"icmp type { 9, 10 }"}
	default:
		return nil
	}
}

// nftAddrSet renders a single address as a bare token or multiple as an nft
// anonymous set.
func nftAddrSet(addrs []string) string {
	if len(addrs) == 1 {
		return addrs[0]
	}
	return "{ " + strings.Join(addrs, ", ") + " }"
}

// nftFamilyAddrs keeps only the addresses belonging to the chain's family
// ("ip" -> IPv4, "ip6" -> IPv6), dropping the empty / "any" placeholders, the
// malformed tokens, and the wrong-family literals. This mirrors the userspace
// matcher's per-family vectors (parse_address classifies each entry into
// source_v4 / source_v6, drops "any"/empty/malformed, and the inet / inet6 chain
// only ever consults the matching family): a v4 CIDR carried in an inet6 filter
// (#3433 H02) and an all-malformed list (#3433 H09) both leave THIS family's
// vector empty, which the matcher treats as the empty positive/except set. Each
// kept entry is re-rendered in its canonical form so a bare host IP and a CIDR
// are both valid nft right-hand sides.
func nftFamilyAddrs(family string, addrs []string) []string {
	wantV6 := family == "ip6"
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == "" || a == "any" {
			continue
		}
		if pfx, err := netip.ParsePrefix(a); err == nil {
			if pfx.Addr().Is6() == wantV6 {
				out = append(out, pfx.String())
			}
			continue
		}
		if ip, err := netip.ParseAddr(a); err == nil {
			if ip.Is6() == wantV6 {
				out = append(out, ip.String())
			}
			continue
		}
		// Malformed token: contributes nothing (mirrors parse_address's silent
		// drop). It still made the direction `constrained` upstream, so an
		// all-malformed positive set fails closed below (match NOTHING).
	}
	return out
}

// nftAddrPredicate lowers one direction (saddr / daddr) of a firewall-filter
// term's address scope into an nft predicate, mirroring nets_match_v4/v6 in
// userspace-dp filter/engine/matching.rs so the kernel lo0 chain enforces the
// SAME verdict as the userspace matcher (#3433). It returns the predicate string
// (empty == no constraint, i.e. match ALL for this direction) and
// matchesNothing == true when the direction is constrained but resolves to no
// prefix of this family with a POSITIVE (non-except) scope — the Junos
// empty-positive-set semantic (match NOTHING). The caller skips the whole rule in
// that case (a term that matches nothing contributes no enforcement). Semantics,
// per family F:
//   - !constrained                         -> "" (no scope -> match ALL)
//   - constrained, no F-prefix, except     -> "" (match every addr NOT in {} = ALL)
//   - constrained, no F-prefix, positive   -> matchesNothing (match addr in {} = none)
//   - constrained, F-prefixes,  positive   -> "<fam> <field> { prefixes }"
//   - constrained, F-prefixes,  except     -> "<fam> <field> != { prefixes }"
func nftAddrPredicate(field, family string, addrs []string, except, constrained bool) (pred string, matchesNothing bool) {
	if !constrained {
		return "", false
	}
	famAddrs := nftFamilyAddrs(family, addrs)
	if len(famAddrs) == 0 {
		if except {
			// Empty except set -> "match every address NOT in {}" = match ALL ->
			// no predicate. Mirrors nets_match returning `except` for an empty set.
			return "", false
		}
		// Empty positive set -> "match addresses in {}" = match NOTHING. Fail
		// closed: the term matches no packet (the caller skips the rule).
		return "", true
	}
	op := family + " " + field + " "
	if except {
		op = family + " " + field + " != "
	}
	return op + nftAddrSet(famAddrs), false
}

// nftRuleFromTerm converts a firewall filter term to an nftables rule string.
// prefixLists is used to expand source-prefix-list and destination-prefix-list references.
func nftRuleFromTerm(term *config.FirewallFilterTerm, family string, prefixLists map[string]*config.PrefixList) string {
	var parts []string

	// Source / destination address + prefix-list lowering (#3433). Route both
	// directions through the SHARED userspace resolver
	// (dpuserspace.ResolveFilterPrefixListAddrs) so the kernel lo0 mirror uses the
	// SAME empty-set / except / positive-wins / `any`-no-constraint semantics as
	// the userspace matcher (pkg/dataplane/userspace/filters.go +
	// userspace-dp/src/filter/engine/matching.rs nets_match_v4/v6) — the raw
	// string concatenation this replaced diverged on every one of those shapes
	// (over-matched in the kernel mirror, or emitted invalid nft that failed the
	// atomic load). nftAddrPredicate then family-filters the resolved set for THIS
	// chain's family and renders the matching nft predicate. When a direction is
	// constrained but resolves to no prefix of this family with a positive scope,
	// the term matches NOTHING (Junos empty-positive set) — skip the whole rule so
	// the kernel mirror neither over-matches (fail-open) nor emits unloadable nft.
	srcAddrs, srcExcept, srcConstrained := dpuserspace.ResolveFilterPrefixListAddrs(
		term.SourceAddresses, term.SourcePrefixLists, prefixLists, "", term.Name, "source")
	srcPred, srcMatchesNothing := nftAddrPredicate("saddr", family, srcAddrs, srcExcept, srcConstrained)
	if srcMatchesNothing {
		return ""
	}
	if srcPred != "" {
		parts = append(parts, srcPred)
	}

	dstAddrs, dstExcept, dstConstrained := dpuserspace.ResolveFilterPrefixListAddrs(
		term.DestAddresses, term.DestPrefixLists, prefixLists, "", term.Name, "destination")
	dstPred, dstMatchesNothing := nftAddrPredicate("daddr", family, dstAddrs, dstExcept, dstConstrained)
	if dstMatchesNothing {
		return ""
	}
	if dstPred != "" {
		parts = append(parts, dstPred)
	}

	// Protocol matching (#2545: multi-value — emit an nft set on >1).
	//
	// #3436: resolve every `from protocol` token through the shared
	// appid.ProtocolNumber SSOT and emit NUMERIC protocol numbers. The commit
	// gate (filterProtocolResolvable) and the userspace matcher (ip_proto.rs)
	// accept Junos predefined-protocol aliases — junos-gre, junos-tcp-any,
	// junos-icmp-all, ipip/junos-ip-in-ip, ... — that nft does NOT understand.
	// Emitting them raw (`meta l4proto junos-gre`) is an nft parse error that
	// rejects the WHOLE atomic lo0 table (legitimate commit broken) or, on the
	// lenient/peer-sync path, mirrors a DIFFERENT protocol than userspace. The
	// numeric form is unconditionally nft-safe and resolves to the SAME protocol
	// number the Rust matcher uses. A token outside the SSOT cannot reach a
	// committed config (the gate rejects it); a leniently-loaded one is dropped
	// with a warning rather than emitted as unloadable nft (mirroring the
	// tcp-flags lowering below).
	if len(term.Protocols) > 0 {
		protos := make([]string, 0, len(term.Protocols))
		for _, p := range term.Protocols {
			if n, ok := appid.ProtocolNumber(p); ok {
				protos = append(protos, strconv.Itoa(int(n)))
			} else {
				slog.Warn("dropping unresolvable protocol from lo0 filter term",
					"term", term.Name, "protocol", p)
			}
		}
		if len(protos) == 1 {
			parts = append(parts, "meta l4proto "+protos[0])
		} else if len(protos) > 1 {
			parts = append(parts, "meta l4proto { "+strings.Join(protos, ", ")+" }")
		}
	}

	// Source port matching
	if len(term.SourcePorts) == 1 {
		parts = append(parts, "th sport "+term.SourcePorts[0])
	} else if len(term.SourcePorts) > 1 {
		parts = append(parts, "th sport { "+strings.Join(term.SourcePorts, ", ")+" }")
	}

	// Destination port matching
	if len(term.DestinationPorts) == 1 {
		parts = append(parts, "th dport "+term.DestinationPorts[0])
	} else if len(term.DestinationPorts) > 1 {
		parts = append(parts, "th dport { "+strings.Join(term.DestinationPorts, ", ")+" }")
	}

	// Negated (except) port matching (#3231). `source-port-except` /
	// `destination-port-except` (parsed since #2622/#3205) were dropped here,
	// so a `discard` term blocked the ports it should have exempted and an
	// accept-all-except-SSH term silently permitted SSH — a control-plane
	// bypass on the lo0 input filter. Emit the nft negated form mirroring the
	// positive port emission above (`th sport != ...` / `th dport != ...`).
	if len(term.SourcePortsExcept) == 1 {
		parts = append(parts, "th sport != "+term.SourcePortsExcept[0])
	} else if len(term.SourcePortsExcept) > 1 {
		parts = append(parts, "th sport != { "+strings.Join(term.SourcePortsExcept, ", ")+" }")
	}
	if len(term.DestPortsExcept) == 1 {
		parts = append(parts, "th dport != "+term.DestPortsExcept[0])
	} else if len(term.DestPortsExcept) > 1 {
		parts = append(parts, "th dport != { "+strings.Join(term.DestPortsExcept, ", ")+" }")
	}

	// DSCP / traffic-class matching (#2545: multi-value).
	if len(term.DSCPs) > 0 {
		dscpKey := "ip dscp "
		if family == "ip6" {
			dscpKey = "ip6 dscp "
		}
		dscps := make([]string, 0, len(term.DSCPs))
		for _, d := range term.DSCPs {
			dscps = append(dscps, nftDSCPValue(d))
		}
		if len(dscps) == 1 {
			parts = append(parts, dscpKey+dscps[0])
		} else {
			parts = append(parts, dscpKey+"{ "+strings.Join(dscps, ", ")+" }")
		}
	}

	// ICMP type/code matching (#2545: multi-value).
	//
	// #3483: emit the `icmp code` predicate WHENEVER a code is configured,
	// independent of whether a type is also set. The userspace projections
	// enforce the code criterion on its own — pkg/dataplane/userspace/filters.go
	// emits ICMPCodes gated only on len(term.ICMPCodes) > 0, and the Rust matcher
	// (userspace-dp/src/filter/engine/matching.rs) tests icmp_code_match_enabled
	// in a block separate from icmp_type_match_enabled. The pre-fix nft mirror
	// nested the code predicate under `if len(term.ICMPTypes) > 0`, so a
	// code-only term (`from protocol icmp icmp-code 4 then discard`, no
	// icmp-type) dropped the code match entirely on the kernel lo0 path. That
	// made the kernel mirror match BROADER than userspace: a `discard` term
	// dropped ALL ICMP (fail-closed over-broad), an `accept` term admitted ALL
	// ICMP (fail-open). Render type and code as independent predicates so a
	// code-only term matches the same packets in nft as in userspace.
	if len(term.ICMPTypes) > 0 || len(term.ICMPCodes) > 0 {
		icmpFamily := "icmp"
		if family == "ip6" {
			icmpFamily = "icmpv6"
		}
		if len(term.ICMPTypes) > 0 {
			parts = append(parts, icmpFamily+" type "+nftIntSet(term.ICMPTypes))
		}
		if len(term.ICMPCodes) > 0 {
			parts = append(parts, icmpFamily+" code "+nftIntSet(term.ICMPCodes))
		}
	}

	// TCP flags matching (#3231). The Junos `tcp-flags` value is an
	// AND-conjunction with optional negation (`syn & !ack` = SYN required,
	// ACK forbidden). The pre-fix code joined the RAW tokens with commas
	// (`tcp flags syn,&,!ack`), which is invalid nft — and because nft loads
	// the lo0 ruleset atomically, that single syntax error rejected the WHOLE
	// ruleset and left the host control-plane filter fail-OPEN. Even a plain
	// list (`tcp flags syn,ack`) is wrong: nft reads a comma list as a
	// disjunctive set, not the Junos conjunction, and forbidden flags are not
	// representable that way at all. Reuse the commit-validated parser to get
	// the required/forbidden masks and emit the canonical
	// `tcp flags & (mentioned-mask) == required` form. A parse error is
	// unreachable for a committed config (compileFirewall rejects
	// unrepresentable expressions), but if one slips through we drop the
	// constraint with a warning rather than emit garbage that fails the whole
	// ruleset open — mirroring the userspace lowering in
	// pkg/dataplane/userspace/filters.go.
	if len(term.TCPFlags) > 0 {
		if required, forbidden, ok, err := config.ParseTCPFlagsExpression(term.TCPFlags); err != nil {
			slog.Warn("dropping unrepresentable tcp-flags expression from lo0 filter term",
				"term", term.Name, "tcp_flags", term.TCPFlags, "error", err)
		} else if ok {
			parts = append(parts, nftTCPFlagsMatch(required, forbidden))
		}
	}

	// IP fragment matching (#3231). `ip frag-off` is an IPv4-only header field;
	// emitting it in the inet6 chain is an nft syntax error that (atomic load)
	// rejected the whole ruleset and failed the lo0 filter open. Family-condition
	// the match: the IPv4 fragment-offset test for ip, and the IPv6 fragment
	// extension-header existence test for ip6.
	if term.IsFragment {
		if family == "ip6" {
			parts = append(parts, "exthdr frag exists")
		} else {
			parts = append(parts, "ip frag-off & 0x1fff != 0")
		}
	}

	// Disposition. Mirror the userspace lo0 evaluator
	// (pkg/dataplane/userspace/filters.go:89) so the kernel lo0 chain enforces the
	// SAME term semantics. The XDP shim shunts ordinary host-bound traffic to the
	// Linux kernel before it reaches userspace-dp, so this chain is the PRIMARY
	// enforcement for host traffic — a wrong terminating verdict here is a real
	// control-plane mis-enforcement, not a cosmetic shadow.
	//
	// #3427: a term with NO terminating action is a FALL-THROUGH in Junos — apply
	// the term's modifiers and continue to the NEXT term. This covers both the
	// explicit `then next term` (term.NextTerm) and a modifier-only term
	// (Action=="" carrying only count/log/forwarding-class/policer/dscp). The
	// pre-fix code mapped Action=="" to a terminating nft `accept`, which SHADOWED
	// every later discard/reject term in the kernel mirror — a fail-OPEN that
	// diverged from userspace (e.g. `from protocol tcp then next term` followed by
	// `from destination-port 22 then discard` accepted SSH at term 1, leaving the
	// drop unreachable). Emit NOTHING for a fall-through term: the kernel chain
	// does not mirror counters/log, so the term contributes no enforcement and the
	// subsequent terms must run. Returning "" makes buildLo0FilterPayload skip the
	// rule.
	//
	// A routing-instance (PBR) term is explicitly NOT a fall-through: userspace
	// sets continue_term=false when routing_instance is non-empty
	// (pkg/dataplane/userspace compiler.rs) and the evaluator TERMINATES the
	// matched term, returning its action — the empty-action placeholder Accept
	// (compiler.rs) — so the packet is ACCEPTED. The kernel lo0 input chain
	// cannot perform route-selection, but the filter VERDICT is accept, so it
	// must emit a TERMINATING accept (not skip): skipping would let a later
	// deny term match and OVER-DROP legitimate host traffic on the
	// kernel-primary lo0 chain. Userspace remains authoritative for the actual
	// route-selection. Falls through to the action switch below (empty action ->
	// default accept).
	if (term.NextTerm || term.Action == "") && term.RoutingInstance == "" {
		return ""
	}

	// Action: discard → drop (silent), reject → reject (ICMP unreachable),
	// accept → accept. An empty action with a routing-instance set reaches here
	// and takes the default accept (terminate-as-accept, mirroring userspace).
	// Any other explicit action is unexpected for a committed config; keep the
	// historical accept default rather than emit garbage.
	action := "accept"
	switch term.Action {
	case "discard":
		action = "drop"
	case "reject":
		action = "reject"
	case "accept":
		action = "accept"
	}

	if len(parts) == 0 {
		return action
	}
	return strings.Join(parts, " ") + " " + action
}

// nftTCPFlagOrder lists the TCP flag bits in canonical low-to-high bit order
// with their nftables symbolic names. The bit values match config.tcpFlagBits
// (the SSOT consumed by ParseTCPFlagsExpression) and userspace-dp/src/tcp_flags.rs.
var nftTCPFlagOrder = []struct {
	bit  uint8
	name string
}{
	{0x01, "fin"},
	{0x02, "syn"},
	{0x04, "rst"},
	{0x08, "psh"},
	{0x10, "ack"},
	{0x20, "urg"},
}

// nftTCPFlagNames renders a TCP-flags bit mask as the nftables symbolic flag
// list joined with " | " (e.g. 0x12 -> "syn | ack"). An empty mask renders as
// the numeric "0x0" so it is a valid right-hand side for the `== 0` (all-clear)
// case.
func nftTCPFlagNames(mask uint8) string {
	var names []string
	for _, f := range nftTCPFlagOrder {
		if mask&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		return "0x0"
	}
	return strings.Join(names, " | ")
}

// nftTCPFlagsMatch renders the canonical nftables masked-equality TCP-flags
// match for a required/forbidden mask pair, the form that expresses the Junos
// AND-conjunction semantics (a segment matches when (flags & required) ==
// required && (flags & forbidden) == 0):
//
//	tcp flags & (<required|forbidden flag names>) == <required flag names>
//
// Both sides are parenthesized when they name more than one flag so nft's `|`
// precedence cannot reassociate the right-hand side across the `==`. A single
// flag, or the all-clear "0x0" right-hand side, needs no parentheses.
func nftTCPFlagsMatch(required, forbidden uint8) string {
	mask := required | forbidden
	maskExpr := nftTCPFlagNames(mask)
	if mask&(mask-1) != 0 { // more than one bit set
		maskExpr = "(" + maskExpr + ")"
	}
	reqExpr := nftTCPFlagNames(required)
	if required&(required-1) != 0 { // more than one bit set
		reqExpr = "(" + reqExpr + ")"
	}
	return "tcp flags & " + maskExpr + " == " + reqExpr
}

// nftDSCPValue converts a Junos DSCP name to the nftables symbolic name.
// nftables accepts: cs0-cs7, af11-af43, ef, or numeric values.
// nftIntSet renders an int slice as a single nft scalar (e.g. "8") or an nft
// anonymous set (e.g. "{ 8, 13 }") for multi-value match criteria (#2545).
func nftIntSet(vals []int) string {
	if len(vals) == 1 {
		return strconv.Itoa(vals[0])
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(v)
	}
	return "{ " + strings.Join(strs, ", ") + " }"
}

// nftDSCPValue converts a firewall-filter DSCP / traffic-class match token to a
// numeric nft dscp token, resolving code-point NAMES through the
// dataplane.DSCPValues SSOT (#3436). The pre-fix pass-through was wrong on two
// counts that nft rejects atomically (failing the whole lo0 load) or that
// silently stop the kernel mirror matching:
//
//   - Case: the commit gate (filterDSCPResolvable) and the userspace matcher
//     (pkg/dataplane/userspace/filters.go, via strings.ToLower) accept names
//     case-insensitively, so `from dscp EF` reaches here as "EF" — but nft's
//     DSCP names are lowercase only, so `ip dscp EF` is a parse error.
//   - Name coverage: xpf accepts `be` (best-effort) as a code point, but nft
//     has NO `be` DSCP name at all — `ip dscp be` is unloadable.
//
// Resolving to the numeric value yields an unconditionally nft-safe token that
// matches the SAME code point as userspace (which resolves the identical table).
// A numeric 0..63 token passes through as-is. An unresolvable token is
// unreachable for a committed config (filterDSCPResolvable gates it); it is
// lower-cased as a best-effort fallback rather than emitted with stray case.
func nftDSCPValue(name string) string {
	if val, ok := dataplane.DSCPValues[strings.ToLower(strings.TrimSpace(name))]; ok {
		return strconv.Itoa(int(val))
	}
	if v, err := strconv.Atoi(strings.TrimSpace(name)); err == nil && v >= 0 && v <= 63 {
		return strconv.Itoa(v)
	}
	return strings.ToLower(strings.TrimSpace(name))
}
