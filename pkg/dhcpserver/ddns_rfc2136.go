package dhcpserver

import (
	"context"
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
	forwardRR, err := u.forwardRR(rec)
	if err != nil {
		return err
	}
	// Forward zone add.
	zone := u.resolveForwardZone(rec.FQDN)
	if err := u.sendAdd(ctx, zone, forwardRR); err != nil {
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
			return fmt.Errorf("ddns: reverse upsert PTR %s: %w", rec.PTRName, err)
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
	forwardRR, err := u.forwardRR(rec)
	if err != nil {
		return err
	}
	zone := u.resolveForwardZone(rec.FQDN)
	if err := u.sendRemove(ctx, zone, forwardRR); err != nil {
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

// sendAdd issues an exact-RR ADD honoring the conflict policy. replace-owned
// sends a bare Insert (the never-delete-non-owned boundary lives in the
// reconciler, not on the wire); skip-existing precedes the Insert with a
// "name not in use" prerequisite and skips on a YX collision; strict-fail
// surfaces the collision as an error.
func (u *rfc2136Updater) sendAdd(ctx context.Context, zone string, rr dns.RR) error {
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
		// Prerequisite failed: a record already exists.
		if u.conflictPolicy == "skip-existing" {
			if u.onConflict != nil {
				u.onConflict()
			}
			return nil
		}
		return fmt.Errorf("ddns: conflict on %s (rcode %s)", rr.Header().Name, dns.RcodeToString[resp.Rcode])
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
