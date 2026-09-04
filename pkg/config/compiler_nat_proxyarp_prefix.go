package config

import (
	"fmt"
	"net/netip"
)

// compiler_nat_proxyarp_prefix.go carries the #6559 host expansion for
// `security nat proxy-arp ... address <prefix>`.
//
// THE DEFECT. `ProxyARPEntry.Addresses` is documented as "/32 CIDRs (expanded
// from ranges)", and the installer reads it that way: pkg/dataplane/proxyarp.go
// parses each entry with netip.ParsePrefix and keys the desired set on
// `prefix.Addr()` alone — one kernel NTF_PROXY neighbour per configured STRING.
// The prefix length is referenced nowhere. So `address 10.0.1.0/24` installed
// exactly one entry.
//
// It is worse than "the base address only", because ParsePrefix does NOT mask:
// Addr() returns the address exactly as authored. For a CANONICAL prefix that
// is the NETWORK address, which no host ever ARPs for — the block gets ZERO
// useful proxy entries while the per-interface proxy_arp/proxy_ndp sysctl is
// still switched on, so the operator sees "proxy-arp configured" with nothing
// behind it. And it committed clean: validateProxyARPAddressesStrict checks
// parseability, and `netip.ParsePrefix("10.0.1.0/24")` parses fine.
//
// WHY THE COMPILER AND NOT THE INSTALLER. `Addresses` is the compiled contract
// the commit gate reads and the type comment describes. Expanding at the
// installer instead would leave both of those lying, and would put the bound
// on the far side of the gate that has to reject an over-bound block.
//
// THE BOUND IS 256, MATCHING THE RANGE SIBLING. `address <low> to <high>` — the
// other spelling of "a block of proxy-ARP addresses", under the SAME stanza —
// already expands with a hard cap of 256 (expandAddressRange,
// compiler_nat_helpers.go). Two spellings of one intent must not carry
// different caps, so the prefix branch takes the range branch's number rather
// than destination.rs's MAX_LOCAL_PREFIX_HOSTS (4096), which governs a
// different surface (the userspace local-address set, not kernel neighbour
// entries + a GARP each). A /24 is 254 usable hosts and fits; anything larger
// is rejected at commit rather than silently truncated.
//
// OVER-BOUND BLOCKS ARE LEFT AUTHORED, ON PURPOSE. When the host count exceeds
// the cap this function returns the value UNCHANGED. That keeps the offending
// prefix visible to validateProxyARPAddressesStrict, which rejects it on the
// strict path and warns on the tolerant one (#1960 no-brick: an appliance whose
// active config already carries an oversized block must still boot, and on that
// path the installed set is byte-identical to today's — one useless entry —
// so a leniently-loaded config is no worse than before this change).

// proxyARPMaxExpandedHosts is the per-statement host cap, deliberately equal to
// expandAddressRange's range cap (see the file comment).
const proxyARPMaxExpandedHosts = 256

// proxyARPHostSuffix returns the single-host prefix suffix for a bare address.
//
// Before #6559 the compiler appended "/32" unconditionally, so a bare IPv6
// address compiled to e.g. "2001:db8::1/32". That parsed, and Addr() recovered
// the full address, so the INSTALL was correct by accident — but the compiled
// form was a 32-bit prefix on a 128-bit address, indistinguishable from an
// authored /32 v6 block. That ambiguity has to go before a prefix length can
// mean anything here, because the expansion below keys on exactly that
// distinction.
func proxyARPHostSuffix(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is6() && !a.Is4In6() {
		return "/128"
	}
	return "/32"
}

// expandProxyARPPrefix expands one compiled proxy-ARP address value into the
// single-host prefixes the installer must program.
//
// A value that is already a single host, that does not parse, or whose host
// count exceeds proxyARPMaxExpandedHosts is returned unchanged as a one-element
// slice — the first two so this function never changes what an existing valid
// or already-diagnosed config installs, the third so the commit gate can see
// and reject the oversized block.
//
// v4 excludes the network and broadcast addresses, which are not ARP targets. A
// /31 is the RFC 3021 point-to-point exception: both addresses are usable, so
// neither is excluded. v6 has no broadcast address and no reserved host id in
// the general case, so every address in the block is expanded.
// proxyARPUnmap4In6 converts a v4-mapped prefix (`::ffff:a.b.c.d/N`) to its v4
// equivalent, converting the MASK as well as the address. Every other prefix is
// returned unchanged, so this is a no-op for genuine v6 and for plain v4.
//
// #8631: two layers classified the identical literal differently. The installer
// (`pkg/dataplane/proxyarp.go`) asks `addr.Is6() && !addr.Is4In6()`, so a
// `::ffff:` block is v4 and installs as AF_INET. The expansion here asked
// `addr.Is4()`, which is FALSE for a 4-in-6 address, so the same literal
// expanded under v6 rules — no network-address skip, and a `/128` suffix. A
// v4-mapped block therefore expanded into host entries the installer then
// treated as v4, including the network address no host ARPs for.
//
// THE MASK IS THE TRAP, and it is why this is not `Unmap()` and done. A
// prefix length on a 4-in-6 address is in v6 bit-space: `::ffff:10.0.0.0/126`
// describes four addresses, and the v4-equivalent mask is `126 - 96 = 30`.
// Unmapping the address while keeping `Bits()` at 126 constructs a v4 address
// with a /126 mask — not a narrower answer, an INVALID one, and everything
// downstream is then wrong in a new way.
//
// `Bits() < 96` is left ALONE rather than converted. Such a prefix does not
// denote a v4 block at all (`/64` would convert to a nonsensical `-32`), and it
// already fails closed: it is over the expansion cap, so it survives to
// `proxyARPNonHostPrefixError` and is rejected at commit. Converting it would
// replace a clear refusal with a malformed prefix.
//
// That floor and the `IsValid` check below are REDUNDANT with each other, and
// deliberately so — deleting the floor leaves every #8631 cell green, which was
// measured rather than assumed. `netip.PrefixFrom` returns an invalid prefix
// for a negative length, so the backstop catches the same inputs. The floor is
// kept because it states the INTENT ("below /96 is not a v4 block") where
// `IsValid` only states the mechanism, and a reader deleting either one should
// know the other still holds rather than discovering it from a green suite.
func proxyARPUnmap4In6(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() || p.Bits() < 96 {
		return p
	}
	q := netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
	if !q.IsValid() {
		return p
	}
	return q
}

func expandProxyARPPrefix(value string) []string {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return []string{value}
	}
	// #8631: decide v4-ness ONCE, here, on the same rule the installer uses.
	// `value` is re-derived so every return below — including the single-host
	// early return — emits the normalized literal rather than a v4 address
	// still wearing a v6 mask.
	if q := proxyARPUnmap4In6(p); q != p {
		p = q
		value = q.String()
	}
	addr := p.Addr()
	if p.Bits() == addr.BitLen() {
		// Already a single host.
		return []string{value}
	}
	n, ok := proxyARPPrefixHostCount(p)
	if !ok || n == 0 || n > proxyARPMaxExpandedHosts {
		return []string{value}
	}

	// Masked() is what makes this deterministic: an operator may author
	// `10.0.1.5/24`, which describes the same BLOCK as `10.0.1.0/24`. Both must
	// expand to the same host set, or the installed entries would depend on
	// which address inside the block happened to be typed.
	cur := p.Masked().Addr()
	if addr.Is4() && p.Bits() < 31 {
		cur = cur.Next() // skip the network address
	}
	out := make([]string, 0, n)
	suffix := "/32"
	if !addr.Is4() {
		suffix = "/128"
	}
	for i := 0; i < n; i++ {
		if !cur.IsValid() {
			break
		}
		out = append(out, cur.String()+suffix)
		cur = cur.Next()
	}
	if len(out) == 0 {
		return []string{value}
	}
	return out
}

// proxyARPPrefixHostCount returns the number of ARP/ND-addressable hosts in a
// multi-host prefix, and false when that count cannot be represented (a v6
// block wider than the cap can be, by many orders of magnitude).
//
// It is computed in a width that cannot wrap: the widest block this can be
// asked about is bounded below by the caller's cap check, and a v6 prefix
// shorter than /120 is reported as over-cap without ever forming the count.
func proxyARPPrefixHostCount(p netip.Prefix) (int, bool) {
	// #8631: normalize here too, so the count and the expansion cannot
	// disagree about what a `::ffff:` block is. Both callers reach this.
	p = proxyARPUnmap4In6(p)
	bits := p.Addr().BitLen() - p.Bits()
	if bits < 0 {
		return 0, false
	}
	// Anything with more than 16 host bits is over any plausible cap and would
	// overflow the shift on a 32-bit int; report it as un-representable rather
	// than forming a wrapped count (the #5194 A3-b2-F9 lesson from
	// expandAddressRange, where a uint32 +1 wrapped to 0 and let an oversized
	// range through as an EMPTY pool).
	if bits > 16 {
		return 0, false
	}
	total := 1 << uint(bits)
	if p.Addr().Is4() && p.Bits() < 31 {
		total -= 2 // network + broadcast
	}
	if total < 0 {
		return 0, false
	}
	return total, true
}

// proxyARPNonHostPrefixError reports a compiled proxy-ARP address that is still
// a multi-host prefix after expansion — i.e. one whose host count exceeded
// proxyARPMaxExpandedHosts. Returns nil for every single-host value.
func proxyARPNonHostPrefixError(iface, addr string) error {
	p, err := netip.ParsePrefix(addr)
	if err != nil {
		return nil // the parse arm of the gate owns this one
	}
	// #8631: a mapped single host (`::ffff:10.0.0.1/128`) is a v4 /32, so
	// normalize before the single-host test or it is misread as multi-host.
	// The error text below still quotes the address AS AUTHORED.
	p = proxyARPUnmap4In6(p)
	if p.Bits() == p.Addr().BitLen() {
		return nil
	}
	n, ok := proxyARPPrefixHostCount(p)
	size := "more than 65536"
	if ok {
		size = fmt.Sprintf("%d", n)
	}
	return fmt.Errorf(
		"security nat proxy-arp interface %q address %q covers %s hosts, more than "+
			"the %d this statement can install. The dataplane programs ONE kernel "+
			"proxy-neighbour entry per compiled address and sends a gratuitous "+
			"ARP for each, so an unbounded block cannot be expanded; before #6559 "+
			"it was not expanded at all and the whole block installed a single "+
			"entry for the address as authored — for a canonical prefix that is "+
			"the NETWORK address, which no host ARPs for, so the block answered "+
			"nothing while the proxy_arp sysctl still read as enabled. Split it "+
			"into blocks of at most %d hosts (the same cap `address <low> to "+
			"<high>` already carries)",
		iface, addr, size, proxyARPMaxExpandedHosts, proxyARPMaxExpandedHosts)
}
