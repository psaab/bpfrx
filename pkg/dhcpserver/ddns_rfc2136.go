package dhcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// ddns_rfc2136.go: the LIVE RFC 2136 DNS-update backend (#1387 increment 2,
// docs/research/1387-inc2-ddns-backend/plan.md §4.1). It implements the
// Inc-1 DNSUpdater interface (ddns_dns.go) so it slots in behind the same
// two-method contract the reconciler already drives — the diff/transition
// algorithm, the ownership state store, and deleteOwnedLocked-as-sole-
// delete-authority are unchanged; this backend only puts the exact wire
// adds/deletes the reconciler asks for onto the network.
//
// Exact-RR discipline (plan §4.1 / risk R1, the cardinal sin): the backend
// NEVER issues a delete-RRset or delete-name. Every wire op targets ONE
// exact RR (name + type + rdata). UpsertLease is an idempotent exact ADD;
// DeleteLease is an exact RFC 2136 §2.5.4 RR delete (TTL=0 / CLASS=NONE).
// A manually-added co-resident record on the same name is therefore never
// collateral. Re-adding an identical RR is a harmless idempotent no-op at
// the server, and Inc-1's recordsEqual short-circuit means a stable lease
// is not even re-upserted.
//
// Zone surface (plan §11 Q1): Inc-2 ships a Domain-derived forward zone +
// the canonical reverse zone (in-addr.arpa / ip6.arpa) derived from the
// PTR name. Explicit forward-zone/reverse-zone config leaves are the
// additive follow-up; resolveForwardZone/resolveReverseZone take an
// OPTIONAL explicit zone list so that follow-up wires straight into an
// existing parameter with no rewrite (today the lists are always empty).
//
// PTR NOTAUTH (plan §11 Q6): a NOTAUTH/REFUSED on the reverse-zone UPDATE
// is a COUNTED SKIP (skippedPTRNotAuth), NOT a blocking error — the forward
// A/AAAA add still succeeds and the lease's reconcile is not marked failed,
// so a reverse zone we do not own (delegated to an ISP) cannot drive a
// retry storm or fail the whole lease.

// defaultDDNSTimeout bounds one DNS UPDATE exchange (dial + write + read).
// The reconcile loop runs on a slow cadence and is a guarded phase, so a
// stuck server only delays DNS, never DHCP (plan risk R4).
const defaultDDNSTimeout = 5 * time.Second

// errDDNSConflictRefused is the sentinel an add returns when it REFUSES to
// claim a name owned by someone else. Two policies raise it:
//
//   - replace-owned (#2648): the name exists and its DHCID is not ours, or
//     there is no DHCID and the name pre-exists.
//   - skip-existing (#2660): the RRsetNotUsed prerequisite failed (the name
//     already exists), so a third party owns it.
//
// It is neither a success nor a hard transport error — it means "another party
// owns this name". The manager (upsertLocked) classifies it like the nop-skip
// so it records NO ownership: recording phantom ownership for a name xpf does
// not own on the wire would let a LATER release delete a third party's record
// (#2648/#2659/#2660 MAJOR) — directly for a no-identity lease (whose delete
// has no DHCID-match guard) and for EVERY skip-existing record (which never
// writes a DHCID, so its delete always takes the plain exact-RR branch), and
// as broad phantom-state pollution for every refused identity-bearing
// replace-owned add. Returning a DISTINCT error keeps the reverse PTR add from
// running on a refused forward and signals the manager not to put().
var errDDNSConflictRefused = errors.New("ddns: replace-owned add refused (name owned by another party)")

// errDDNSPTRPending is the sentinel UpsertLease returns when the forward
// A/AAAA add SUCCEEDED but the reverse PTR add failed with a NON-skippable
// error (timeout, SERVFAIL, etc.). The forward RR is already LIVE in DNS, so
// the manager (upsertLocked) MUST record ownership of it — otherwise the
// forward is orphaned: live in the authoritative zone but absent from the
// ownership store, so no later release can withdraw it (#2661, the exact
// stale-record class #1387 set out to prevent). It is a PARTIAL success:
// ownership IS recorded (the forward is tracked + cleanable) but with the
// PTRPending flag set so the NEXT reconcile re-attempts the PTR (the forward
// re-add is an idempotent no-op; only the still-missing PTR is published).
// The wrapped cause carries the underlying PTR error so the manager can log
// and count it. Distinct from errDDNSConflictRefused (which records NO
// ownership) and from a NOTAUTH/REFUSED skip (which records ownership with no
// pending retry, because that reverse zone is permanently not ours).
var errDDNSPTRPending = errors.New("ddns: forward published but reverse PTR add failed (pending retry)")

// dnsExchanger is the seam the backend uses to talk to the authoritative
// server. *dns.Client satisfies it; tests inject a recorder so the wire
// adds/deletes can be asserted without a real socket (though the test
// suite drives a real in-process miekg/dns server on 127.0.0.1:0, so the
// production *dns.Client path is itself exercised).
type dnsExchanger interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error)
}

// rfc2136Updater is the live DNSUpdater backend. It is STATELESS beyond
// its resolved config — all ownership/state lives in the DDNSManager store
// (unchanged from Inc-1). A new one is built per reconcile from the current
// policy (plan §6 fork 1: resolve-per-Reconcile), so a backend-config
// change at commit takes effect on the next cycle with no swap race.
type rfc2136Updater struct {
	server         string // host:port of the authoritative DNS
	defaultDomain  string // policy.Domain — forward-zone fallback
	conflictPolicy string // replace-owned | skip-existing | strict-fail

	tsigKeyName string // canonical (lowercase, trailing-dot) key name; "" = no TSIG
	tsigAlgo    string // canonical miekg algorithm name (hmac-sha256. etc)
	tsigSecret  string // revealed base64 secret

	// optional explicit zone lists (plan §11 Q1 follow-up). Always empty in
	// Inc-2; carried so the additive follow-up wires new leaves in here.
	forwardZones []string
	reverseZones []string

	timeout time.Duration

	// dhcidClientID is the client identity (from the LeaseDNSRecord) for the
	// record currently being upserted/deleted. It seeds the RFC 4701 DHCID
	// ownership marker under replace-owned. It is set at the top of each
	// UpsertLease / DeleteLease call (the manager serializes all reconcile
	// work under its mutex, so per-call mutation of this stateless-config
	// backend is safe). Empty ⇒ no DHCID (name-not-in-use guard only).
	dhcidClientID string

	client dnsExchanger // *dns.Client in production; recorder in tests

	// counters surfaced to the manager via the reason-tagged skip path.
	onPTRNotAuth func()
	onConflict   func()
}

// supportedTSIGAlgorithms maps an operator-facing algorithm name (with or
// without the trailing dot, case-insensitive) to the canonical miekg/dns
// constant. hmac-md5 is deliberately ABSENT — it is deprecated/insecure and
// miekg/dns no longer signs with it (plan §11 Q5); an md5 key is rejected.
var supportedTSIGAlgorithms = map[string]string{
	"hmac-sha1":   dns.HmacSHA1,
	"hmac-sha224": dns.HmacSHA224,
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// canonicalTSIGAlgorithm normalizes an operator algorithm string to the
// canonical miekg name, defaulting to hmac-sha256 when unset. Returns an
// error for an unsupported/insecure algorithm (hmac-md5).
func canonicalTSIGAlgorithm(algo string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(algo))
	a = strings.TrimSuffix(a, ".")
	if a == "" {
		return dns.HmacSHA256, nil
	}
	if canon, ok := supportedTSIGAlgorithms[a]; ok {
		return canon, nil
	}
	return "", fmt.Errorf("ddns: unsupported TSIG algorithm %q (supported: "+
		"hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512)", algo)
}

// normalizeUpdateServer turns a host or host:port into a host:port. A bare
// host gets the default DNS port 53.
func normalizeUpdateServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("ddns: update-server is empty")
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, nil
	}
	// No port. A bracketed IPv6 literal without a port ("[2001:db8::1]")
	// would be double-bracketed by JoinHostPort ("[[2001:db8::1]]:53"), so
	// strip an existing surrounding bracket pair first and let JoinHostPort
	// re-bracket the bare host exactly once. A bare IPv6 literal without
	// brackets ("2001:db8::1") and an IPv4/hostname both pass through to
	// JoinHostPort unchanged.
	host := s
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, "53"), nil
}

// newRFC2136Updater builds the live backend from a resolved policy plus the
// raw config (for the TSIG/server fields the policy struct does not carry).
// onPTRNotAuth/onConflict are the manager's skip counters. A nil client
// seam means a real *dns.Client is used. Returns an error when the policy
// is structurally unusable (no update-server / bad TSIG) so the caller can
// fall back to a no-op and count it rather than emit broken UPDATEs.
func newRFC2136Updater(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig, client dnsExchanger, onPTRNotAuth, onConflict func()) (*rfc2136Updater, error) {
	if c == nil {
		return nil, errors.New("ddns: nil config for rfc2136 backend")
	}
	server, err := normalizeUpdateServer(c.UpdateServer)
	if err != nil {
		return nil, err
	}
	u := &rfc2136Updater{
		server:         server,
		defaultDomain:  pol.domain,
		conflictPolicy: pol.conflictPolicy,
		timeout:        defaultDDNSTimeout,
		client:         client,
		onPTRNotAuth:   onPTRNotAuth,
		onConflict:     onConflict,
	}
	if c.TSIGKeyName != "" {
		algo, err := canonicalTSIGAlgorithm(c.TSIGAlgorithm)
		if err != nil {
			return nil, err
		}
		u.tsigKeyName = dns.CanonicalName(c.TSIGKeyName)
		u.tsigAlgo = algo
		u.tsigSecret = c.TSIGSecret.Reveal()
	}
	if u.client == nil {
		u.client = &dns.Client{
			Timeout:    u.timeout,
			TsigSecret: u.tsigSecretMap(),
		}
	}
	return u, nil
}

// tsigSecretMap returns the miekg TsigSecret map (key name → base64 secret)
// when TSIG is configured, else nil. The secret is read via Reveal() only
// here at construction; it never appears in an error message (plan risk R6).
func (u *rfc2136Updater) tsigSecretMap() map[string]string {
	if u.tsigKeyName == "" {
		return nil
	}
	return map[string]string{u.tsigKeyName: u.tsigSecret}
}

// resolveForwardZone returns the zone the forward UPDATE targets. With no
// explicit list (Inc-2), the zone is the configured Domain (the operator's
// authoritative zone) — failing that, the parent of the FQDN. The optional
// explicit list is the additive follow-up's input; longest matching suffix
// wins so a delegated cut is honored when configured.
func (u *rfc2136Updater) resolveForwardZone(fqdn string) string {
	if z := longestZoneSuffix(fqdn, u.forwardZones); z != "" {
		return z
	}
	// Use the configured Domain only when the name is actually UNDER it. A
	// name outside the domain (an explicit ClientFQDN in a different zone)
	// must not be sent to the domain's zone — the server would answer NOTAUTH
	// (or, worse, accept it into the wrong zone). Derive that name's own
	// parent zone instead.
	if u.defaultDomain != "" {
		if z := longestZoneSuffix(fqdn, []string{u.defaultDomain}); z != "" {
			return z
		}
	}
	// No (matching) domain configured: fall back to the parent label of the
	// name.
	return parentZone(dns.Fqdn(fqdn))
}

// resolveReverseZone returns the zone the PTR UPDATE targets. With no
// explicit list (Inc-2), the canonical in-addr.arpa/ip6.arpa parent of the
// PTR name is used.
func (u *rfc2136Updater) resolveReverseZone(ptrName string) string {
	if z := longestZoneSuffix(ptrName, u.reverseZones); z != "" {
		return z
	}
	return canonicalReverseZone(ptrName)
}

// longestZoneSuffix returns the longest configured zone that is a suffix of
// name (both compared canonically), or "" if none match. This is the seam
// the additive forward-zone/reverse-zone follow-up uses.
func longestZoneSuffix(name string, zones []string) string {
	cn := dns.CanonicalName(dns.Fqdn(name))
	best := ""
	for _, z := range zones {
		cz := dns.CanonicalName(dns.Fqdn(z))
		if cn == cz || strings.HasSuffix(cn, "."+cz) {
			if len(cz) > len(best) {
				best = dns.Fqdn(z)
			}
		}
	}
	return best
}

// parentZone returns the parent zone of a name (everything after the first
// label). A name with a single label returns the root ".".
func parentZone(fqdn string) string {
	fqdn = dns.Fqdn(fqdn)
	if i := strings.IndexByte(fqdn, '.'); i >= 0 && i+1 < len(fqdn) {
		return fqdn[i+1:]
	}
	return "."
}

// canonicalReverseZone derives the canonical reverse zone for a PTR name:
// the /24 in-addr.arpa for IPv4 (drop the host octet) or the parent
// ip6.arpa for IPv6 (drop the leading nibble). The PTR names are produced
// by Inc-1's reversePTRName, so this is the inverse of that construction.
func canonicalReverseZone(ptrName string) string {
	p := dns.Fqdn(ptrName)
	lower := strings.ToLower(p)
	switch {
	case strings.HasSuffix(lower, ".in-addr.arpa."):
		// "<d>.<c>.<b>.<a>.in-addr.arpa." -> "<c>.<b>.<a>.in-addr.arpa."
		// (drop the host octet to name the /24 the server is authoritative
		// for; if the server delegates a different boundary it answers
		// NOTAUTH, which the PTR path degrades to a counted skip).
		return parentZone(p)
	case strings.HasSuffix(lower, ".ip6.arpa."):
		// Drop the leading nibble to name the immediate parent.
		return parentZone(p)
	default:
		// Not a recognized reverse name: name its parent (best effort).
		return parentZone(p)
	}
}

// UpsertLease publishes the forward A/AAAA and reverse PTR for a lease
// (plan §4.1). The forward add is the operation whose success governs the
// lease's reconcile result; a PTR NOTAUTH/REFUSED is a counted skip.
func (u *rfc2136Updater) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	u.dhcidClientID = rec.ClientID
	forwardRR, err := u.forwardRR(rec)
	if err != nil {
		return err
	}
	// Forward zone add.
	zone := u.resolveForwardZone(rec.FQDN)
	if err := u.sendAdd(ctx, zone, forwardRR); err != nil {
		// A conflict refusal (the name is owned by another party) — from
		// replace-owned (#2648) OR skip-existing (#2660) — is propagated
		// UNWRAPPED so the manager's errors.Is check sees the sentinel and
		// records no ownership. Do NOT add the reverse PTR for a forward we did
		// not publish.
		if errors.Is(err, errDDNSConflictRefused) {
			return errDDNSConflictRefused
		}
		return fmt.Errorf("ddns: forward upsert %s %s: %w", rec.ForwardType, rec.FQDN, err)
	}
	// Reverse zone PTR add — NOTAUTH/REFUSED is a counted skip, not fatal.
	if rec.PTRName != "" {
		ptrRR := u.ptrRR(rec)
		rzone := u.resolveReverseZone(rec.PTRName)
		if err := u.sendAdd(ctx, rzone, ptrRR); err != nil {
			if isPTRSkippable(err) {
				if u.onPTRNotAuth != nil {
					u.onPTRNotAuth()
				}
				return nil
			}
			// The forward A/AAAA is already LIVE in DNS but the reverse PTR add
			// failed with a non-skippable (transient) error. Returning a plain
			// error here would make the manager record NO ownership, ORPHANING
			// the live forward (#2661). Instead, return the errDDNSPTRPending
			// sentinel wrapping the cause: the manager records ownership of the
			// forward (so it is tracked + cleanable) with PTRPending set, and the
			// next reconcile re-runs UpsertLease — the forward re-add is an
			// idempotent no-op and only the still-missing PTR is published.
			return fmt.Errorf("ddns: reverse upsert PTR %s: %w: %w", rec.PTRName, err, errDDNSPTRPending)
		}
	}
	return nil
}

// DeleteLease removes the exact forward and reverse RRs the firewall
// published (plan §4.1). Both are exact RFC 2136 §2.5.4 deletes (the
// miekg Remove path forces TTL=0 / CLASS=NONE), so a co-resident record on
// the same name is never collateral. A PTR NOTAUTH/REFUSED on delete is the
// same counted skip as on add.
func (u *rfc2136Updater) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	u.dhcidClientID = rec.ClientID
	forwardRR, err := u.forwardRR(rec)
	if err != nil {
		return err
	}
	zone := u.resolveForwardZone(rec.FQDN)
	if err := u.sendRemoveForward(ctx, zone, forwardRR); err != nil {
		return fmt.Errorf("ddns: forward delete %s %s: %w", rec.ForwardType, rec.FQDN, err)
	}
	if rec.PTRName != "" {
		ptrRR := u.ptrRR(rec)
		rzone := u.resolveReverseZone(rec.PTRName)
		if err := u.sendRemove(ctx, rzone, ptrRR); err != nil {
			if isPTRSkippable(err) {
				if u.onPTRNotAuth != nil {
					u.onPTRNotAuth()
				}
				return nil
			}
			return fmt.Errorf("ddns: reverse delete PTR %s: %w", rec.PTRName, err)
		}
	}
	return nil
}

// forwardRR builds the A or AAAA RR for a record.
func (u *rfc2136Updater) forwardRR(rec LeaseDNSRecord) (dns.RR, error) {
	name := dns.Fqdn(rec.FQDN)
	ttl := uint32(rec.TTL) //nolint:gosec // TTL is a small positive config value
	if rec.Addr.Is4() {
		a4 := rec.Addr.As4()
		ip := net.IP(a4[:])
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip,
		}, nil
	}
	if rec.Addr.Is6() {
		a16 := rec.Addr.As16()
		ip := net.IP(a16[:])
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ip,
		}, nil
	}
	return nil, fmt.Errorf("ddns: record %q has an unspecified address", rec.FQDN)
}

// ptrRR builds the PTR RR for a record's reverse name.
func (u *rfc2136Updater) ptrRR(rec LeaseDNSRecord) dns.RR {
	return &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(rec.PTRName),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    uint32(rec.TTL), //nolint:gosec // TTL is a small positive config value
		},
		Ptr: dns.Fqdn(rec.FQDN),
	}
}

// RFC 4701 §3.3 "identifier type codes" carried in the first 2 octets of the
// DHCID RDATA. They tell a reader WHICH client-identity form the digest was
// computed over, so a shared zone with another DHCID writer (ISC Kea, Windows
// DHCP) can interoperate. xpf maps them from the lease-parser identity prefix:
//
//   - 0x0000 — the 1-octet htype followed by the hardware address (the
//     DHCPv4 "htype+chaddr" form). xpf uses this for the hwaddr fallback
//     (identity4's "mac:" prefix, used only when no client-id option exists).
//   - 0x0001 — the data octets of the DHCPv4 Client Identifier option (RFC
//     2132 option 61). xpf uses this for identity4's "cid:" prefix.
//   - 0x0002 — the DHCPv6 DUID. xpf uses this for identity6's "duid:" prefix.
//
// RESIDUAL (documented): the DIGEST input below is xpf's canonical identity
// STRING (the prefixed, colon-hex form the Kea memfile parser produces), not
// the raw option byte stream RFC 4701 §3.5 specifies. So the identifier-TYPE
// is now RFC-correct, but the DIGEST is not guaranteed byte-identical to what
// ISC Kea / Windows would compute for the same client — cross-vendor DHCID
// MATCH on a shared name is therefore best-effort, not guaranteed. xpf is
// internally consistent (the same lease always yields the same DHCID across an
// add/delete pair, which is what the ownership boundary requires), and a
// non-matching foreign DHCID is treated as "owned by another party" and left
// untouched — the SAFE direction. Computing the digest over the raw option
// bytes would require threading the un-mangled DHCP option through the lease
// parser, deferred as an interop enhancement.
const (
	dhcidIDTypeHTypeChaddr = 0x0000 // "mac:" — htype+chaddr
	dhcidIDTypeClientID    = 0x0001 // "cid:" — DHCPv4 client-identifier option
	dhcidIDTypeDUID        = 0x0002 // "duid:" — DHCPv6 DUID
)

// dhcidIdentifierType returns the RFC 4701 §3.3 identifier-type code for an
// xpf lease identity, keyed on the prefix the lease parser (identity4 /
// identity6) attached. An unrecognized form falls back to htype+chaddr
// (0x0000) — it only affects the marker's self-description; xpf compares its
// own DHCID against itself, so the fallback is harmless.
func dhcidIdentifierType(clientID string) int {
	switch {
	case strings.HasPrefix(clientID, "duid:"):
		return dhcidIDTypeDUID
	case strings.HasPrefix(clientID, "cid:"):
		return dhcidIDTypeClientID
	case strings.HasPrefix(clientID, "mac:"):
		return dhcidIDTypeHTypeChaddr
	default:
		return dhcidIDTypeHTypeChaddr
	}
}

// dhcidDigestTypeSHA256 is the RFC 4701 §3.4 digest type code for SHA-256.
const dhcidDigestTypeSHA256 = 0x01

// dhcidRR builds the RFC 4701 DHCID resource record that proves xpf owns a
// forward name. The RDATA is: 2-byte identifier-type || 1-byte digest-type
// || SHA-256(client-identity || canonical-FQDN-in-wire-form) (RFC 4701
// §3.5). miekg's DHCID.Digest is the base64 of that whole RDATA blob.
//
// The FQDN is folded into the digest in DNS wire form (canonical, lowercased)
// so the marker is bound to BOTH the client identity and the exact name —
// the same (identity, name) pair always produces the same DHCID, and a
// different name or client cannot collide onto it. Returns ok=false when the
// lease has no stable client identity (the caller then omits the DHCID and
// uses the name-not-in-use prerequisite instead).
func dhcidRR(clientID, fqdn string, ttl uint32) (*dns.DHCID, bool) {
	if clientID == "" {
		return nil, false
	}
	name := dns.CanonicalName(dns.Fqdn(fqdn))
	wire := make([]byte, len(name)+1)
	off, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		// A name that cannot be packed (should not happen for a validated
		// FQDN) means we cannot bind the digest to it: omit the DHCID and let
		// the caller fall back to the name-not-in-use prerequisite.
		return nil, false
	}
	h := sha256.New()
	h.Write([]byte(clientID))
	h.Write(wire[:off])
	digest := h.Sum(nil)

	idType := dhcidIdentifierType(clientID)
	rdata := make([]byte, 0, 3+len(digest))
	rdata = append(rdata, byte(idType>>8), byte(idType&0xff))
	rdata = append(rdata, byte(dhcidDigestTypeSHA256))
	rdata = append(rdata, digest...)

	return &dns.DHCID{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeDHCID,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Digest: base64.StdEncoding.EncodeToString(rdata),
	}, true
}

// sendAdd issues an exact-RR ADD honoring the conflict policy.
//
//   - replace-owned (the SAFE default, #2648): xpf claims a name only when it
//     can PROVE ownership. It computes the RFC 4701 DHCID for (client-id,
//     name) and runs RFC 4703 §5.3 DHCID conflict resolution: first try to
//     add the A/AAAA + DHCID with a "name not in use" prerequisite (a fresh
//     name we are free to claim); if that collides (YXDOMAIN), retry with a
//     "DHCID matches OURS" prerequisite so we only adopt/update a name WE
//     already own. If neither holds — a third party owns the name (a
//     different or absent DHCID) — the add is REFUSED and counted, so xpf
//     never records ownership of, and therefore never later deletes, a
//     record it did not create. When the lease has no stable client identity
//     the DHCID is omitted and the name-not-in-use prerequisite alone guards
//     the claim (still never adopting a pre-existing third-party RR).
//   - skip-existing: precede the Insert with a "name not in use" prerequisite
//     and REFUSE on a YX collision (the name already exists = a third party
//     owns it) by returning errDDNSConflictRefused so the manager records NO
//     ownership. skip-existing never writes a DHCID, so phantom ownership here
//     would let a later release take the plain exact-RR delete and remove the
//     third party's RR (#2660).
//   - strict-fail: same prerequisite, surface the collision as an error.
func (u *rfc2136Updater) sendAdd(ctx context.Context, zone string, rr dns.RR) error {
	if u.conflictPolicy == "replace-owned" {
		return u.sendAddOwned(ctx, zone, rr)
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	switch u.conflictPolicy {
	case "skip-existing", "strict-fail":
		// Prerequisite: the exact RRset must NOT already exist (RFC 2136
		// §2.4.3). A collision returns YXRRSET/YXDOMAIN.
		m.RRsetNotUsed([]dns.RR{rr})
	}
	m.Insert([]dns.RR{rr})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain:
		// Prerequisite failed: a record already exists — a third party owns
		// this name. Refuse to claim it (count the conflict) and signal the
		// refusal with errDDNSConflictRefused, NOT nil. A nil return is a
		// SUCCESS to upsertLocked, which would then record phantom ownership
		// for a name xpf did not create; skip-existing never writes a DHCID, so
		// a later release would take sendRemoveForward's plain exact-RR delete
		// branch and DELETE the third party's RR (#2660, the skip-existing
		// sibling of the #2648/#2659 boundary breach). The sentinel tells the
		// manager to record NO ownership — exactly the replace-owned mechanism
		// (#2648), extended to skip-existing.
		if u.conflictPolicy == "skip-existing" {
			if u.onConflict != nil {
				u.onConflict()
			}
			return errDDNSConflictRefused
		}
		return fmt.Errorf("ddns: conflict on %s (rcode %s)", rr.Header().Name, dns.RcodeToString[resp.Rcode])
	default:
		return rcodeError(resp.Rcode)
	}
}

// dhcidForRR returns the DHCID RR that should accompany an A/AAAA add under
// replace-owned, derived from the client identity carried alongside the
// record. Reverse PTR adds get no DHCID (RFC 4701 binds the marker to the
// forward owner name only). ok=false means no DHCID applies (a reverse name,
// or a forward name with no stable client identity).
func (u *rfc2136Updater) dhcidForRR(rr dns.RR) (*dns.DHCID, bool) {
	if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
		return nil, false
	}
	return dhcidRR(u.dhcidClientID, rr.Header().Name, rr.Header().Ttl)
}

// sendAddOwned implements the replace-owned ownership-proving add via RFC 4703
// DHCID conflict resolution. The two-condition "DHCID matches OR name unused"
// guard cannot be a single RFC 2136 prerequisite (prerequisites are AND-ed),
// so it is two sequential attempts (RFC 4703 §5.3.2):
//
//  1. Attempt A — add A/AAAA (+ DHCID, when there is a client identity) with a
//     NAME-NOT-IN-USE prerequisite. Success ⇒ a fresh name we now own.
//  2. On YXDOMAIN/YXRRSET (the name already exists) — Attempt B — add the same
//     records with a DHCID-MATCHES-OURS prerequisite (a value-dependent RRset-
//     exists prereq, RFC 2136 §2.4.2). Success ⇒ a name WE already own,
//     refreshed. Another YX ⇒ a third party owns the name: REFUSE by returning
//     the errDDNSConflictRefused sentinel (and counting the conflict). The
//     manager classifies that sentinel as a skip — NOT a hard failure and NOT
//     a success — so upsertLocked records NO ownership for the refused name.
//     Recording phantom ownership would let a later release delete a record
//     xpf did not create (#2648 MAJOR-1).
//
// When the lease has no client identity there is no DHCID to match, so the
// name-not-in-use prerequisite alone gates the claim: a pre-existing name (by
// anyone) is refused (same sentinel) and never adopted.
func (u *rfc2136Updater) sendAddOwned(ctx context.Context, zone string, rr dns.RR) error {
	dhcid, hasDHCID := u.dhcidForRR(rr)

	// Attempt A: fresh-name claim (name not in use).
	mA := new(dns.Msg)
	mA.SetUpdate(dns.Fqdn(zone))
	mA.NameNotUsed([]dns.RR{rr})
	if hasDHCID {
		mA.Insert([]dns.RR{rr, dhcid})
	} else {
		mA.Insert([]dns.RR{rr})
	}
	resp, err := u.exchange(ctx, mA)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain:
		// Name already exists — fall through to the ownership-proving retry.
	default:
		return rcodeError(resp.Rcode)
	}

	if !hasDHCID {
		// No ownership proof available and the name already exists: this is a
		// pre-existing record we cannot claim as ours. Refuse (count + skip)
		// rather than adopt it — adopting would let a later release delete a
		// record xpf did not create (#2648). Signal the refusal with the
		// sentinel so the manager records NO ownership (a no-identity lease's
		// delete has no DHCID guard, so phantom ownership here would delete the
		// third party's record on release).
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	}

	// Attempt B: adopt/refresh a name whose existing DHCID matches OURS.
	// Use a SEPARATE copy of the DHCID for the prerequisite vs the update
	// section: miekg's Used()/Insert() mutate the RR header class in place, so
	// sharing one pointer would let Insert (CLASS=INET) clobber the
	// prerequisite's value-dependent class and corrupt the ownership check.
	mB := new(dns.Msg)
	mB.SetUpdate(dns.Fqdn(zone))
	mB.Used([]dns.RR{dns.Copy(dhcid)}) // value-dependent: our exact DHCID must exist
	mB.Insert([]dns.RR{rr, dhcid})
	resp, err = u.exchange(ctx, mB)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNXRrset, dns.RcodeNameError:
		// The existing DHCID is NOT ours (or absent): a third party owns this
		// name. Refuse to claim it — record NO ownership (the sentinel tells
		// the manager not to put()), so a later release cannot delete it
		// (#2648).
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	default:
		return rcodeError(resp.Rcode)
	}
}

// sendRemove issues an exact-RR delete (RFC 2136 §2.5.4 via miekg Remove,
// which forces TTL=0 / CLASS=NONE). An NXRRSET/NXDOMAIN-style "nothing to
// delete" is benign and treated as success (idempotent delete).
func (u *rfc2136Updater) sendRemove(ctx context.Context, zone string, rr dns.RR) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.Remove([]dns.RR{rr})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNXRrset, dns.RcodeNameError:
		return nil
	default:
		return rcodeError(resp.Rcode)
	}
}

// sendRemoveForward deletes the forward A/AAAA record. Under replace-owned
// (#2648) it is OWNERSHIP-GUARDED: when the record carries a client identity,
// it prepends a "DHCID matches OURS" prerequisite (RFC 2136 §2.4.2 value-
// dependent RRset-exists) and deletes the A/AAAA AND the DHCID together, so
// xpf removes a name ONLY when the on-wire DHCID proves xpf created it. If the
// DHCID does not match (a third party re-published the name, or there is no
// DHCID at all = a manual record), the prerequisite fails and the delete is
// SKIPPED + counted — xpf never deletes a record it does not own.
//
// The state store already prevents constructing a delete for a tuple xpf
// never recorded; this adds a SECOND, on-wire guard against the narrow race
// where a third party adopted the exact name+address between xpf's add and
// release. Without a client identity (no DHCID was ever written) the delete is
// the plain exact-RR delete — still only the firewall's own (name,type,rdata)
// tuple, never a delete-RRset.
func (u *rfc2136Updater) sendRemoveForward(ctx context.Context, zone string, rr dns.RR) error {
	if u.conflictPolicy != "replace-owned" {
		return u.sendRemove(ctx, zone, rr)
	}
	dhcid, hasDHCID := u.dhcidForRR(rr)
	if !hasDHCID {
		// No DHCID was ever published for this record (no client identity):
		// fall back to the plain exact-RR delete of the firewall's own tuple.
		return u.sendRemove(ctx, zone, rr)
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	// Separate DHCID copies for the prerequisite vs the delete: Remove() sets
	// CLASS=NONE in place, which would otherwise corrupt the value-dependent
	// Used() prerequisite that proves we own the record.
	m.Used([]dns.RR{dns.Copy(dhcid)}) // prerequisite: our exact DHCID must exist
	m.Remove([]dns.RR{rr, dhcid})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// Prerequisite held (our DHCID is present): the delete applied.
		return nil
	case dns.RcodeNXRrset, dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNameError:
		// The DHCID prerequisite failed: the name's DHCID is not ours (NXRRSET
		// = our value-dependent DHCID RRset is absent; NXDOMAIN = the name is
		// gone). Either way xpf does NOT own this record on the wire — skip the
		// delete and count it. The reconciler still clears the ownership entry
		// so xpf stops managing a name it no longer owns. (A name that simply
		// vanished is also a benign "nothing to delete".)
		if u.onConflict != nil {
			u.onConflict()
		}
		return nil
	default:
		return rcodeError(resp.Rcode)
	}
}

// exchange signs (when TSIG configured) and sends a message UDP-first,
// retrying over TCP on a truncated response. The per-call context bounds
// the network I/O.
func (u *rfc2136Updater) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if u.tsigKeyName != "" {
		m.SetTsig(u.tsigKeyName, u.tsigAlgo, 300, time.Now().Unix())
	}
	if u.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, u.timeout)
		defer cancel()
	}
	resp, _, err := u.client.ExchangeContext(ctx, m, u.server)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("ddns: nil response from update server")
	}
	if resp.Truncated {
		// Retry over TCP. A dns.Client honors Net="tcp"; the test recorder
		// never truncates, so this path is production-only.
		if tc, ok := u.client.(*dns.Client); ok {
			tcpClient := *tc
			tcpClient.Net = "tcp"
			// Derive the TCP retry context from the CALLER's ctx (not
			// context.Background()) so a canceled/deadline'd reconcile pass
			// actually cancels the retry. The per-exchange timeout is still
			// applied on top, so the retry is bounded even when the caller has
			// no deadline of its own.
			if u.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, u.timeout)
				defer cancel()
			}
			resp, _, err = tcpClient.ExchangeContext(ctx, m, u.server)
			if err != nil {
				return nil, err
			}
			if resp == nil {
				return nil, errors.New("ddns: nil response from update server (tcp)")
			}
		}
	}
	return resp, nil
}

// rcodeErr is the typed non-NOERROR update-rcode error. It carries the
// numeric rcode so isPTRSkippable can match NOTAUTH/REFUSED exactly via
// errors.As (no string sniffing), and it NEVER includes the TSIG secret
// (plan risk R6) — only the rcode string.
type rcodeErr struct{ rcode int }

func (e *rcodeErr) Error() string {
	name, ok := dns.RcodeToString[e.rcode]
	if !ok {
		name = fmt.Sprintf("rcode%d", e.rcode)
	}
	return fmt.Sprintf("ddns: update rejected (%s)", name)
}

// rcodeError turns a non-NOERROR update rcode into a typed error.
func rcodeError(rcode int) error { return &rcodeErr{rcode: rcode} }

// isPTRSkippable reports whether a reverse-zone error is a NOTAUTH/REFUSED
// that the PTR path degrades to a counted skip (plan §11 Q6) rather than a
// blocking failure. The forward/reverse senders wrap rcodeErr with
// fmt.Errorf, so errors.As unwraps to the typed cause.
func isPTRSkippable(err error) bool {
	if err == nil {
		return false
	}
	var re *rcodeErr
	if errors.As(err, &re) {
		return re.rcode == dns.RcodeNotAuth || re.rcode == dns.RcodeRefused
	}
	return false
}
