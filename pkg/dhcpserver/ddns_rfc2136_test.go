package dhcpserver

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #1387 inc-2 live RFC 2136 backend tests. The key to keeping the LIVE
// backend lab-free is an in-process miekg/dns server bound on 127.0.0.1:0
// (UDP+TCP) with a real TSIG secret map: it parses real DNS UPDATE
// messages, verifies real TSIG, and records every received UPDATE so the
// test asserts the EXACT wire adds/deletes. The production *dns.Client path
// is exercised — not stubbed — so this proves the wire format end to end.

// recordedUpdate is one UPDATE the fake server received, decomposed into the
// adds (Insert) and exact-RR deletes (CLASS=NONE) the backend sent.
type recordedUpdate struct {
	zone    string
	adds    []dns.RR
	deletes []dns.RR // CLASS=NONE exact-RR deletes
	prereqs []dns.RR // Answer-section prerequisites
}

// fakeDNSServer is an in-process authoritative responder for UPDATEs.
type fakeDNSServer struct {
	t   *testing.T
	udp *dns.Server
	tcp *dns.Server

	mu      sync.Mutex
	updates []recordedUpdate

	// rcodeForZone overrides the response rcode for an UPDATE whose zone
	// (Question[0].Name, canonical) matches — used to simulate NOTAUTH on a
	// reverse zone, or a conflict (YXRRSET) on a prerequisite.
	rcodeForZone map[string]int
	// conflictPrereq, when true, answers a prerequisite-bearing UPDATE for a
	// zone in conflictZones with YXRRSET (collision). Empty conflictZones
	// means "all zones" when conflictPrereq is set.
	conflictPrereq bool
	conflictZones  map[string]bool

	// truncateUDP, when set, marks every UDP reply Truncated so the client
	// retries over TCP (used to exercise the TCP-retry path).
	truncateUDP bool
	// tcpReplyDelay stalls the TCP reply so the client's read deadline (derived
	// from the caller ctx, post-fix) bounds the retry before the reply lands.
	tcpReplyDelay time.Duration

	addrUDP string
	addrTCP string
	tsig    map[string]string
}

func newFakeDNSServer(t *testing.T, tsig map[string]string) *fakeDNSServer {
	t.Helper()
	s := &fakeDNSServer{t: t, rcodeForZone: map[string]int{}, tsig: tsig}

	// Handle every message directly (no ServeMux name routing — an UPDATE's
	// "question" is the zone, and the default mux answers NOTIMP for the
	// UPDATE opcode unless a handler is registered for the exact zone name).
	handler := dns.HandlerFunc(s.handle)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	// Bind TCP on the SAME host:port the UDP socket got (UDP and TCP are
	// independent port namespaces), so a client that retries-over-TCP against
	// the single configured server address reaches this server's TCP listener
	// too — mirroring a real DNS server (UDP+TCP on :53). This makes the
	// truncation→TCP-retry path testable end to end.
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	s.addrUDP = pc.LocalAddr().String()
	s.addrTCP = l.Addr().String()

	// DefaultMsgAcceptFunc rejects the UPDATE opcode with NOTIMP; accept all
	// opcodes so the handler sees the UPDATE.
	acceptAll := func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }
	s.udp = &dns.Server{PacketConn: pc, Handler: handler, TsigSecret: tsig, MsgAcceptFunc: acceptAll}
	s.tcp = &dns.Server{Listener: l, Handler: handler, TsigSecret: tsig, MsgAcceptFunc: acceptAll}

	started := make(chan struct{}, 2)
	s.udp.NotifyStartedFunc = func() { started <- struct{}{} }
	s.tcp.NotifyStartedFunc = func() { started <- struct{}{} }
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	<-started
	<-started
	t.Cleanup(func() {
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
	})
	return s
}

func (s *fakeDNSServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	zone := ""
	if len(r.Question) > 0 {
		zone = dns.CanonicalName(r.Question[0].Name)
	}

	rec := recordedUpdate{zone: zone}
	for _, rr := range r.Ns {
		switch rr.Header().Class {
		case dns.ClassNONE:
			rec.deletes = append(rec.deletes, rr)
		case dns.ClassANY:
			// delete-RRset / delete-name (the backend must NEVER send these).
			rec.deletes = append(rec.deletes, rr)
		default:
			rec.adds = append(rec.adds, rr)
		}
	}
	rec.prereqs = append(rec.prereqs, r.Answer...)

	overTCP := w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp")

	s.mu.Lock()
	s.updates = append(s.updates, rec)
	override, hasOverride := s.rcodeForZone[zone]
	conflict := s.conflictPrereq && (len(s.conflictZones) == 0 || s.conflictZones[zone])
	truncate := s.truncateUDP && !overTCP
	tcpDelay := s.tcpReplyDelay
	s.mu.Unlock()
	// Mark a UDP reply Truncated to drive the client into the TCP-retry path.
	if truncate {
		m.Truncated = true
	}
	// Stall the TCP reply so the client's (caller-derived) read deadline can
	// bound the retry before the reply lands.
	if overTCP && tcpDelay > 0 {
		time.Sleep(tcpDelay)
	}

	// TSIG: when the request is signed and verification FAILED, reject with
	// NOTAUTH and an unsigned reply so the client surfaces an error (a wrong
	// shared secret must not silently succeed).
	signed := r.IsTsig() != nil
	tsigBad := signed && w.TsigStatus() != nil
	switch {
	case tsigBad:
		m.Rcode = dns.RcodeNotAuth
	case hasOverride:
		m.Rcode = override
	case conflict && len(r.Answer) > 0:
		// A prerequisite present + conflict flag → simulate a collision.
		m.Rcode = dns.RcodeYXRrset
	default:
		m.Rcode = dns.RcodeSuccess
	}

	// Sign the reply only when the request TSIG verified, so the client's
	// reply-verification succeeds on the happy path.
	if signed && !tsigBad && len(s.tsig) > 0 {
		t := r.IsTsig()
		m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	}
	_ = w.WriteMsg(m)
}

func (s *fakeDNSServer) recorded() []recordedUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedUpdate, len(s.updates))
	copy(out, s.updates)
	return out
}

// The setters below mutate handler-read fields under s.mu so tests configuring
// the server cannot race a lingering in-flight handler goroutine (the handler
// reads every such field under s.mu). All test configuration of the server
// MUST go through these rather than touching the fields directly.

func (s *fakeDNSServer) setRcode(zone string, rcode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rcodeForZone[dns.CanonicalName(zone)] = rcode
}

func (s *fakeDNSServer) clearRcode(zone string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rcodeForZone, dns.CanonicalName(zone))
}

func (s *fakeDNSServer) setConflict(prereq bool, zones map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conflictPrereq = prereq
	s.conflictZones = zones
}

func (s *fakeDNSServer) setTruncate(truncate bool, tcpDelay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncateUDP = truncate
	s.tcpReplyDelay = tcpDelay
}

// testUpdater builds an rfc2136Updater pointed at the fake server, using a
// real *dns.Client (UDP). Counters are captured into the returned closures.
func testUpdater(t *testing.T, srv *fakeDNSServer, c *config.DHCPDynamicDNSConfig, ptrNotAuth, conflict *int) *rfc2136Updater {
	t.Helper()
	c.UpdateServer = srv.addrUDP
	pol := policyFromConfig(c)
	u, err := newRFC2136Updater(pol, c, nil,
		func() { *ptrNotAuth++ },
		func() { *conflict++ })
	if err != nil {
		t.Fatalf("newRFC2136Updater: %v", err)
	}
	// Point the real client at our server; UDP only (the fake never
	// truncates). Keep TSIG from the constructor.
	if cl, ok := u.client.(*dns.Client); ok {
		cl.Timeout = 3 * time.Second
	}
	return u
}

func recV4(fqdn, addr string, ttl int) LeaseDNSRecord {
	a := netip.MustParseAddr(addr)
	return LeaseDNSRecord{FQDN: fqdn, Addr: a, TTL: ttl, ForwardType: "A", PTRName: reversePTRName(a)}
}

func recV6(fqdn, addr string, ttl int) LeaseDNSRecord {
	a := netip.MustParseAddr(addr)
	return LeaseDNSRecord{FQDN: fqdn, Addr: a, TTL: ttl, ForwardType: "AAAA", PTRName: reversePTRName(a)}
}

func TestRFC2136UpsertV4AddsForwardAndReverse(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	ups := srv.recorded()
	if len(ups) != 2 {
		t.Fatalf("want 2 UPDATEs (forward + reverse), got %d", len(ups))
	}
	// Forward: an A add in zone example.com., NO delete.
	fwd := ups[0]
	if fwd.zone != "example.com." {
		t.Errorf("forward zone = %q, want example.com.", fwd.zone)
	}
	if len(fwd.deletes) != 0 {
		t.Errorf("forward upsert must NOT delete-RRset; got %d deletes (R1 cardinal sin)", len(fwd.deletes))
	}
	if len(fwd.adds) != 1 {
		t.Fatalf("want 1 forward add, got %d", len(fwd.adds))
	}
	a, ok := fwd.adds[0].(*dns.A)
	if !ok || a.A.String() != "10.0.1.5" || a.Hdr.Name != "laptop.example.com." {
		t.Errorf("forward add wrong: %+v", fwd.adds[0])
	}
	if a.Hdr.Ttl != 300 {
		t.Errorf("forward TTL = %d, want 300", a.Hdr.Ttl)
	}
	// Reverse: a PTR add in 1.0.10.in-addr.arpa.
	rev := ups[1]
	if rev.zone != "1.0.10.in-addr.arpa." {
		t.Errorf("reverse zone = %q, want 1.0.10.in-addr.arpa.", rev.zone)
	}
	if len(rev.adds) != 1 {
		t.Fatalf("want 1 reverse add, got %d", len(rev.adds))
	}
	ptrRR, ok := rev.adds[0].(*dns.PTR)
	if !ok || ptrRR.Ptr != "laptop.example.com." {
		t.Errorf("reverse PTR wrong: %+v", rev.adds[0])
	}
}

func TestRFC2136UpsertV6AddsAAAAAndIP6Arpa(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV6("server6.example.com", "2001:db8::5", 600)); err != nil {
		t.Fatalf("UpsertLease v6: %v", err)
	}
	ups := srv.recorded()
	if len(ups) != 2 {
		t.Fatalf("want 2 UPDATEs, got %d", len(ups))
	}
	if _, ok := ups[0].adds[0].(*dns.AAAA); !ok {
		t.Errorf("forward add is not AAAA: %+v", ups[0].adds[0])
	}
	if !strings.HasSuffix(ups[1].zone, ".ip6.arpa.") {
		t.Errorf("reverse zone %q is not ip6.arpa", ups[1].zone)
	}
}

func TestRFC2136DeleteIsExactRRNotRRset(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	if err := u.DeleteLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	ups := srv.recorded()
	if len(ups) != 2 {
		t.Fatalf("want 2 UPDATEs (forward + reverse delete), got %d", len(ups))
	}
	fwd := ups[0]
	if len(fwd.adds) != 0 {
		t.Errorf("delete must not add; got %d adds", len(fwd.adds))
	}
	if len(fwd.deletes) != 1 {
		t.Fatalf("want 1 forward delete, got %d", len(fwd.deletes))
	}
	d := fwd.deletes[0]
	// EXACT-RR delete: CLASS=NONE, TTL=0, carries the exact rdata (an A, not
	// an ANY/delete-RRset). This is the R1 cardinal-sin guard.
	if d.Header().Class != dns.ClassNONE {
		t.Errorf("delete class = %d, want NONE (exact-RR delete, not delete-RRset)", d.Header().Class)
	}
	if d.Header().Ttl != 0 {
		t.Errorf("delete TTL = %d, want 0 (RFC 2136 §2.5.4)", d.Header().Ttl)
	}
	a, ok := d.(*dns.A)
	if !ok {
		t.Fatalf("delete RR is not an exact A (got %T) — a co-resident record on the same name would be collateral", d)
	}
	if a.A.String() != "10.0.1.5" {
		t.Errorf("delete rdata = %s, want 10.0.1.5", a.A.String())
	}
}

func TestRFC2136UpsertNeverSendsDeleteRRset(t *testing.T) {
	// The other half of R1: an UPSERT must be an exact ADD only — a
	// manually-added co-resident A on the same name survives.
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)
	if err := u.UpsertLease(context.Background(), recV4("shared.example.com", "10.0.1.9", 300)); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	for _, up := range srv.recorded() {
		for _, d := range up.deletes {
			t.Errorf("upsert sent a delete (%v) — would clobber co-resident records", d)
		}
		// A delete-RRset/delete-name would be a ClassANY ANY RR.
		for _, rr := range up.adds {
			if rr.Header().Class == dns.ClassANY {
				t.Errorf("upsert sent a ClassANY (delete-RRset/name) RR: %v", rr)
			}
		}
	}
}

func TestRFC2136TSIGSignedAndVerified(t *testing.T) {
	const keyName = "xpf-ddns."
	const secret = "c2VjcmV0LWtleS1iYXNlNjQtZW5jb2RlZA==" // arbitrary valid base64
	srv := newFakeDNSServer(t, map[string]string{keyName: secret})
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled:       true,
		Domain:        "example.com",
		TSIGKeyName:   keyName,
		TSIGAlgorithm: "hmac-sha256",
		TSIGSecret:    config.Secret(secret),
	}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV4("tsig.example.com", "10.0.1.7", 300)); err != nil {
		t.Fatalf("signed UpsertLease should succeed: %v", err)
	}
}

func TestRFC2136TSIGWrongSecretRejectedNoLeak(t *testing.T) {
	const keyName = "xpf-ddns."
	const serverSecret = "c2VydmVyLXNlY3JldC1iYXNlNjQ="
	const clientSecret = "Y2xpZW50LXdyb25nLXNlY3JldA==" // different → verify fails
	srv := newFakeDNSServer(t, map[string]string{keyName: serverSecret})
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled:       true,
		Domain:        "example.com",
		TSIGKeyName:   keyName,
		TSIGAlgorithm: "hmac-sha256",
		TSIGSecret:    config.Secret(clientSecret),
	}, &ptr, &conf)

	err := u.UpsertLease(context.Background(), recV4("bad.example.com", "10.0.1.8", 300))
	if err == nil {
		t.Fatal("wrong TSIG secret must produce an error")
	}
	if strings.Contains(err.Error(), clientSecret) || strings.Contains(err.Error(), serverSecret) {
		t.Errorf("error message leaks a TSIG secret: %q (R6)", err.Error())
	}
}

func TestRFC2136PTRNotAuthIsCountedSkipNotFatal(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeNotAuth)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	// Forward succeeds, reverse NOTAUTH → the whole upsert still succeeds.
	if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("PTR NOTAUTH must not fail the lease (plan §11 Q6): %v", err)
	}
	if ptr != 1 {
		t.Errorf("ptr-notauth skip counter = %d, want 1", ptr)
	}
}

func TestRFC2136SkipExistingConflictSkips(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	// Scope the collision to the forward zone so the skip count is
	// deterministic (the reverse zone add succeeds).
	srv.setConflict(true, map[string]bool{"example.com.": true})
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "skip-existing",
	}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV4("exists.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("skip-existing on a collision must NOT error: %v", err)
	}
	if conf != 1 {
		t.Errorf("conflict skip counter = %d, want 1", conf)
	}
	// The add carried a prerequisite (RRsetNotUsed → an Answer RR).
	ups := srv.recorded()
	if len(ups) == 0 || len(ups[0].prereqs) == 0 {
		t.Errorf("skip-existing must send a no-RRset prerequisite")
	}
}

func TestRFC2136StrictFailConflictErrors(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setConflict(true, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "strict-fail",
	}, &ptr, &conf)

	err := u.UpsertLease(context.Background(), recV4("exists.example.com", "10.0.1.5", 300))
	if err == nil {
		t.Fatal("strict-fail on a collision must error")
	}
}

func TestRFC2136ReplaceOwnedNoPrereq(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)
	if err := u.UpsertLease(context.Background(), recV4("r.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	for _, up := range srv.recorded() {
		if len(up.prereqs) != 0 {
			t.Errorf("replace-owned must send NO prerequisite; got %d", len(up.prereqs))
		}
	}
}

func TestRFC2136Timeout(t *testing.T) {
	// Point at an unroutable discard address so the exchange times out.
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.1:53"})
	u, err := newRFC2136Updater(pol, &config.DHCPDynamicDNSConfig{UpdateServer: "192.0.2.1:53"}, nil, func() {}, func() {})
	if err != nil {
		t.Fatalf("newRFC2136Updater: %v", err)
	}
	u.timeout = 200 * time.Millisecond
	if cl, ok := u.client.(*dns.Client); ok {
		cl.Timeout = 200 * time.Millisecond
	}
	start := time.Now()
	err = u.UpsertLease(context.Background(), recV4("t.example.com", "10.0.1.5", 300))
	if err == nil {
		t.Fatal("a non-responding server must error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("timeout not bounded: took %v", elapsed)
	}
}

func TestCanonicalTSIGAlgorithm(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", dns.HmacSHA256, false},
		{"hmac-sha256", dns.HmacSHA256, false},
		{"HMAC-SHA256", dns.HmacSHA256, false},
		{"hmac-sha256.", dns.HmacSHA256, false},
		{"hmac-sha1", dns.HmacSHA1, false},
		{"hmac-sha512", dns.HmacSHA512, false},
		{"hmac-md5", "", true}, // deprecated/insecure → rejected (plan §11 Q5)
		{"bogus-alg", "", true},
	}
	for _, c := range cases {
		got, err := canonicalTSIGAlgorithm(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("canonicalTSIGAlgorithm(%q) want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("canonicalTSIGAlgorithm(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("canonicalTSIGAlgorithm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeUpdateServer(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"192.0.2.53", "192.0.2.53:53", false},
		{"192.0.2.53:5353", "192.0.2.53:5353", false},
		{"dns.example.com", "dns.example.com:53", false},
		{"dns.example.com:53", "dns.example.com:53", false},
		// IPv6: bare literal gets bracketed exactly once; a bracketed literal
		// with no port must NOT be double-wrapped ("[[...]]:53"); host:port
		// forms pass through unchanged.
		{"2001:db8::1", "[2001:db8::1]:53", false},
		{"[2001:db8::1]", "[2001:db8::1]:53", false},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353", false},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := normalizeUpdateServer(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeUpdateServer(%q) want error", c.in)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("normalizeUpdateServer(%q) = %q,%v want %q", c.in, got, err, c.want)
		}
	}
}

func TestCanonicalReverseZone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"5.1.0.10.in-addr.arpa", "1.0.10.in-addr.arpa."},
		{reversePTRName(netip.MustParseAddr("10.0.1.5")), "1.0.10.in-addr.arpa."},
	}
	for _, c := range cases {
		if got := canonicalReverseZone(c.in); got != c.want {
			t.Errorf("canonicalReverseZone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// ip6.arpa: the parent (drop one nibble).
	v6ptr := reversePTRName(netip.MustParseAddr("2001:db8::5"))
	gotV6 := canonicalReverseZone(v6ptr)
	if !strings.HasSuffix(gotV6, ".ip6.arpa.") {
		t.Errorf("canonicalReverseZone(v6) = %q, want a *.ip6.arpa. zone", gotV6)
	}
	if gotV6 == dns.Fqdn(v6ptr) {
		t.Errorf("canonicalReverseZone(v6) must drop a nibble, got the full name %q", gotV6)
	}
}

func TestLongestZoneSuffix(t *testing.T) {
	zones := []string{"example.com", "dept.example.com"}
	if got := longestZoneSuffix("host.dept.example.com", zones); got != "dept.example.com." {
		t.Errorf("longestZoneSuffix = %q, want dept.example.com.", got)
	}
	if got := longestZoneSuffix("host.other.com", zones); got != "" {
		t.Errorf("longestZoneSuffix non-match = %q, want empty", got)
	}
}

func TestResolveForwardZone(t *testing.T) {
	// defaultDomain is the configured Domain; the forward zone may only be the
	// domain when the FQDN is actually UNDER it. An out-of-domain FQDN must
	// derive its OWN parent zone, not be misrouted into the domain.
	u := &rfc2136Updater{defaultDomain: "example.com"}
	cases := []struct {
		fqdn string
		want string
	}{
		// Under the domain → the domain zone.
		{"laptop.example.com", "example.com."},
		{"laptop.example.com.", "example.com."},
		// The domain name itself → the domain zone.
		{"example.com", "example.com."},
		// OUTSIDE the domain → the FQDN's own parent (NOT example.com.).
		{"host.other.org", "other.org."},
		{"a.b.other.org", "b.other.org."},
	}
	for _, c := range cases {
		if got := u.resolveForwardZone(c.fqdn); got != c.want {
			t.Errorf("resolveForwardZone(%q) = %q, want %q", c.fqdn, got, c.want)
		}
	}

	// No domain configured at all → always the FQDN's parent.
	un := &rfc2136Updater{}
	if got := un.resolveForwardZone("host.example.com"); got != "example.com." {
		t.Errorf("resolveForwardZone (no domain) = %q, want example.com.", got)
	}
}

func TestExchangeTCPRetryHonorsCallerCancellation(t *testing.T) {
	// The truncation→TCP retry must derive its context from the CALLER's ctx,
	// so a deadline'd reconcile pass actually bounds the in-flight retry rather
	// than running it on a fresh context.Background() that ignores the caller's
	// deadline.
	//
	// The fake server truncates the first (UDP) reply to drive the client into
	// the *dns.Client TCP-retry branch, then STALLS the TCP reply for 2s. The
	// caller passes a SHORT-deadline ctx (300ms). Post-fix the TCP retry's
	// read deadline derives from the caller (miekg clamps the read deadline to
	// ctx.Deadline()), so the retry aborts at ~300ms with an i/o timeout. Pre-
	// fix the TCP ctx is context.Background()+u.timeout (10s), which ignores
	// the caller deadline, so the retry waits out the 2s stall and SUCCEEDS
	// (nil error) — the test fails pre-fix.
	srv := newFakeDNSServer(t, nil)
	srv.setTruncate(true, 2*time.Second)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)
	// Per-exchange budget large enough that, pre-fix, the stalled TCP reply
	// lands within u.timeout (so pre-fix returns success, not a timeout — the
	// caller-deadline difference is the only thing the assertion observes).
	u.timeout = 10 * time.Second
	if cl, ok := u.client.(*dns.Client); ok {
		cl.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := u.UpsertLease(ctx, recV4("laptop.example.com", "10.0.1.5", 300))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("TCP retry ignored the caller deadline: returned success after the 2s stall " +
			"(pre-fix it runs on context.Background()+u.timeout)")
	}
	// The caller's 300ms deadline must bound the retry well before the 2s stall.
	if elapsed > time.Second {
		t.Errorf("caller deadline was not honored: took %v (stall is 2s) — err=%v", elapsed, err)
	}
}
