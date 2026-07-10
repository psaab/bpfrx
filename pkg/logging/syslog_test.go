package logging

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseSeverity(t *testing.T) {
	// #5314: ParseSeverity must map ALL ten Junos severities the config schema
	// accepts (junosSyslogSeverities), not just error/warning/info. Before the
	// fix, emergency/alert/critical/notice/debug/none all fell through to 0
	// (send-all), so a `host H <facility> critical` collapsed to no-filter and
	// over-forwarded. This table is the fail-on-revert guard for that mapping:
	// reverting to the 3-severity switch makes critical/emergency/etc. return 0
	// and fails the assertions below.
	tests := []struct {
		name string
		want int
	}{
		// Sentinels / extremes.
		{"any", 0},
		{"none", SeverityNone},
		{"emergency", SeverityEmergency},
		// Raw RFC levels.
		{"alert", SyslogAlert},
		{"critical", SyslogCritical},
		{"error", SyslogError},
		{"warning", SyslogWarning},
		{"notice", SyslogNotice},
		{"info", SyslogInfo},
		{"debug", SyslogDebug},
		// Case-insensitive.
		{"Critical", SyslogCritical},
		{"EMERGENCY", SeverityEmergency},
		{"None", SeverityNone},
		// Tolerant contract preserved: unknown / empty => 0 (no filter).
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.name); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// TestParseSeverityCoversSchema pins ParseSeverity to the exact severity
// vocabulary the config schema accepts, so a schema addition without a runtime
// mapping (the #5314 class of bug: schema accepts, runtime silently
// no-filters) fails here. "any" and unknown legitimately map to 0 (send-all);
// every OTHER schema token must map to a non-zero threshold.
func TestParseSeverityCoversSchema(t *testing.T) {
	// Mirror of config.junosSyslogSeverities (kept local to avoid an import
	// cycle; the schema comment cross-references this test).
	schemaSeverities := []string{
		"any", "none", "emergency", "alert", "critical",
		"error", "warning", "notice", "info", "debug",
	}
	for _, name := range schemaSeverities {
		got := ParseSeverity(name)
		if name == "any" {
			if got != 0 {
				t.Errorf("ParseSeverity(%q) = %d, want 0 (send-all)", name, got)
			}
			continue
		}
		if got == 0 {
			t.Errorf("ParseSeverity(%q) = 0 (send-all) — schema severity has no "+
				"runtime threshold, would over-forward (#5314)", name)
		}
	}
}

// TestShouldSend_AnyCritical is the core #5314 regression: `host H any critical`
// (facility=any, severity=critical) must forward critical AND more-severe
// records, and must NOT forward the less-severe error/warning/info records. On
// revert (ParseSeverity("critical") -> 0), MinSeverity becomes the send-all
// sentinel and every one of the "must NOT send" assertions goes RED.
func TestShouldSend_AnyCritical(t *testing.T) {
	c := &SyslogClient{MinSeverity: ParseSeverity("critical")}

	// critical and MORE severe -> sent.
	for _, sev := range []int{SyslogEmergency, SyslogAlert, SyslogCritical} {
		if !c.ShouldSend(sev) {
			t.Errorf("critical filter should forward severity %d (critical or more severe)", sev)
		}
	}
	// LESS severe than critical -> NOT sent (the leak the bug caused).
	for _, sev := range []int{SyslogError, SyslogWarning, SyslogNotice, SyslogInfo, SyslogDebug} {
		if c.ShouldSend(sev) {
			t.Errorf("critical filter MUST NOT forward severity %d (less severe than critical) — #5314 over-forward", sev)
		}
	}
}

// TestShouldSend_Emergency proves emergency is a real, most-restrictive
// threshold and NOT the send-all sentinel: only emergency records pass, and
// even alert/critical (the next-most-severe levels) are suppressed.
func TestShouldSend_Emergency(t *testing.T) {
	c := &SyslogClient{MinSeverity: ParseSeverity("emergency")}
	if !c.ShouldSend(SyslogEmergency) {
		t.Error("emergency filter should forward emergency")
	}
	for _, sev := range []int{SyslogAlert, SyslogCritical, SyslogError, SyslogWarning, SyslogInfo} {
		if c.ShouldSend(sev) {
			t.Errorf("emergency filter MUST NOT forward severity %d (emergency != send-all)", sev)
		}
	}
}

// TestShouldSend_AnyAndNone covers the two Junos extremes: `any` forwards
// everything, `none` forwards nothing.
func TestShouldSend_AnyAndNone(t *testing.T) {
	all := []int{SyslogEmergency, SyslogAlert, SyslogCritical, SyslogError,
		SyslogWarning, SyslogNotice, SyslogInfo, SyslogDebug}

	any := &SyslogClient{MinSeverity: ParseSeverity("any")}
	for _, sev := range all {
		if !any.ShouldSend(sev) {
			t.Errorf("any filter should forward severity %d", sev)
		}
	}

	none := &SyslogClient{MinSeverity: ParseSeverity("none")}
	for _, sev := range all {
		if none.ShouldSend(sev) {
			t.Errorf("none filter MUST NOT forward severity %d", sev)
		}
	}
}

// TestMoreRestrictiveMinSeverity checks the fold used to collapse a host's
// several `<facility> <severity>` pairs into one client filter. Ordering,
// most→least restrictive: none, emergency, alert..debug, any.
func TestMoreRestrictiveMinSeverity(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{ParseSeverity("critical"), ParseSeverity("info"), ParseSeverity("critical")}, // critical more restrictive than info
		{ParseSeverity("info"), ParseSeverity("critical"), ParseSeverity("critical")}, // order-independent
		{ParseSeverity("any"), ParseSeverity("info"), ParseSeverity("info")},          // any (send-all) least restrictive
		{ParseSeverity("emergency"), ParseSeverity("critical"), ParseSeverity("emergency")},
		{ParseSeverity("none"), ParseSeverity("emergency"), ParseSeverity("none")}, // none most restrictive
		{ParseSeverity("any"), ParseSeverity("none"), ParseSeverity("none")},
		{ParseSeverity("debug"), ParseSeverity("any"), ParseSeverity("debug")}, // debug edges out any
	}
	for _, tt := range tests {
		if got := MoreRestrictiveMinSeverity(tt.a, tt.b); got != tt.want {
			t.Errorf("MoreRestrictiveMinSeverity(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestParseFacility(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"kern", FacilityKern},
		{"user", FacilityUser},
		{"daemon", FacilityDaemon},
		{"auth", FacilityAuth},
		{"syslog", FacilitySyslog},
		{"local0", FacilityLocal0},
		{"local1", FacilityLocal1},
		{"local2", FacilityLocal2},
		{"local3", FacilityLocal3},
		{"local4", FacilityLocal4},
		{"local5", FacilityLocal5},
		{"local6", FacilityLocal6},
		{"local7", FacilityLocal7},
		{"unknown", FacilityLocal0},
		{"", FacilityLocal0},
	}
	for _, tt := range tests {
		if got := ParseFacility(tt.name); got != tt.want {
			t.Errorf("ParseFacility(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestShouldSend_NoFilter(t *testing.T) {
	c := &SyslogClient{MinSeverity: 0}
	if !c.ShouldSend(SyslogError) {
		t.Error("no filter should pass error")
	}
	if !c.ShouldSend(SyslogWarning) {
		t.Error("no filter should pass warning")
	}
	if !c.ShouldSend(SyslogInfo) {
		t.Error("no filter should pass info")
	}
}

func TestShouldSend_ErrorOnly(t *testing.T) {
	c := &SyslogClient{MinSeverity: SyslogError}
	if !c.ShouldSend(SyslogError) {
		t.Error("error filter should pass error")
	}
	if c.ShouldSend(SyslogWarning) {
		t.Error("error filter should block warning")
	}
	if c.ShouldSend(SyslogInfo) {
		t.Error("error filter should block info")
	}
}

func TestShouldSend_WarningAndAbove(t *testing.T) {
	c := &SyslogClient{MinSeverity: SyslogWarning}
	if !c.ShouldSend(SyslogError) {
		t.Error("warning filter should pass error (higher severity)")
	}
	if !c.ShouldSend(SyslogWarning) {
		t.Error("warning filter should pass warning")
	}
	if c.ShouldSend(SyslogInfo) {
		t.Error("warning filter should block info")
	}
}

func TestShouldSend_InfoAll(t *testing.T) {
	c := &SyslogClient{MinSeverity: SyslogInfo}
	if !c.ShouldSend(SyslogError) {
		t.Error("info filter should pass error")
	}
	if !c.ShouldSend(SyslogWarning) {
		t.Error("info filter should pass warning")
	}
	if !c.ShouldSend(SyslogInfo) {
		t.Error("info filter should pass info")
	}
}

func TestSyslogSendReceive(t *testing.T) {
	// Start a UDP listener
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)

	client, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.Send(SyslogWarning, "test message"); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	got := string(buf[:n])
	// Priority = facility*8 + severity = 16*8 + 4 = 132
	if got[:5] != "<132>" {
		t.Errorf("unexpected priority prefix: %q", got[:10])
	}
	if !strings.Contains(got, "xpf: test message") {
		t.Errorf("message not found in %q", got)
	}
}

func TestSyslogFacilityInPriority(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)

	client, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.Facility = FacilityDaemon // 3

	if err := client.Send(SyslogError, "error msg"); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	got := string(buf[:n])
	// Priority = 3*8 + 3 = 27
	if got[:4] != "<27>" {
		t.Errorf("unexpected priority for daemon+error: %q", got[:10])
	}
}

func TestSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	// Accept one connection in background
	msgCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		// Read octet-counted frame: "<length> <message>"
		line, err := reader.ReadString(' ')
		if err != nil {
			msgCh <- fmt.Sprintf("ERROR reading length: %v", err)
			return
		}
		length, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			msgCh <- fmt.Sprintf("ERROR parsing length %q: %v", line, err)
			return
		}
		buf := make([]byte, length)
		n := 0
		for n < length {
			nn, err := reader.Read(buf[n:])
			if err != nil {
				msgCh <- fmt.Sprintf("ERROR reading body: %v", err)
				return
			}
			n += nn
		}
		msgCh <- string(buf[:n])
	}()

	client, err := NewSyslogClientTransport("127.0.0.1", addr.Port, "", "tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.Send(SyslogWarning, "tcp test"); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-msgCh:
		if strings.HasPrefix(msg, "ERROR") {
			t.Fatal(msg)
		}
		if !strings.Contains(msg, "xpf: tcp test") {
			t.Errorf("expected message to contain 'xpf: tcp test', got %q", msg)
		}
		// Check priority: 16*8 + 4 = 132
		if !strings.HasPrefix(msg, "<132>") {
			t.Errorf("unexpected priority prefix in %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCP syslog message")
	}
}

func TestSyslogTCPReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)

	// Accept first connection and close it to simulate server restart
	connCh := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		connCh <- conn
	}()

	client, err := NewSyslogClientTransport("127.0.0.1", addr.Port, "", "tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Wait for first connection to be accepted then close it
	select {
	case conn := <-connCh:
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for initial connection")
	}

	// Wait for the RST to propagate
	time.Sleep(50 * time.Millisecond)

	// Force the client to detect the closed connection by writing twice.
	// First write may succeed (kernel buffer), second will see RST.
	_ = client.Send(SyslogInfo, "probe")
	time.Sleep(20 * time.Millisecond)

	// Accept reconnection
	msgCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString(' ')
		length, _ := strconv.Atoi(strings.TrimSpace(line))
		buf := make([]byte, length)
		n := 0
		for n < length {
			nn, _ := reader.Read(buf[n:])
			n += nn
		}
		msgCh <- string(buf[:n])
	}()

	// Send should trigger reconnect after write fails on dead connection
	if err := client.Send(SyslogInfo, "after reconnect"); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-msgCh:
		if !strings.Contains(msg, "after reconnect") {
			t.Errorf("expected 'after reconnect' in message, got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for reconnected message")
	}

	ln.Close()
}

func TestSyslogTLS(t *testing.T) {
	// Generate self-signed cert for test
	cert, pool := generateTestCert(t)

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsLn.Close()

	addr := tlsLn.Addr().(*net.TCPAddr)

	msgCh := make(chan string, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString(' ')
		length, _ := strconv.Atoi(strings.TrimSpace(line))
		buf := make([]byte, length)
		n := 0
		for n < length {
			nn, _ := reader.Read(buf[n:])
			n += nn
		}
		msgCh <- string(buf[:n])
	}()

	clientTLSCfg := &tls.Config{
		RootCAs: pool,
	}
	client, err := NewSyslogClientTransport("127.0.0.1", addr.Port, "", "tls", clientTLSCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.Send(SyslogError, "tls test"); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-msgCh:
		if !strings.Contains(msg, "xpf: tls test") {
			t.Errorf("expected 'xpf: tls test' in message, got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TLS syslog message")
	}
}

func TestSyslogDefaultProtocol(t *testing.T) {
	// Empty protocol should default to UDP
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)
	client, err := NewSyslogClientTransport("127.0.0.1", addr.Port, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if client.protocol != "udp" {
		t.Errorf("expected protocol 'udp', got %q", client.protocol)
	}
}

func TestSyslogCategoryFilter(t *testing.T) {
	c := &SyslogClient{Categories: CategorySession | CategoryPolicy}
	if !c.ShouldSendEvent(SyslogInfo, CategorySession) {
		t.Error("should pass session")
	}
	if !c.ShouldSendEvent(SyslogInfo, CategoryPolicy) {
		t.Error("should pass policy")
	}
	if c.ShouldSendEvent(SyslogInfo, CategoryScreen) {
		t.Error("should block screen")
	}
	// Zero categories = no filter
	c2 := &SyslogClient{Categories: 0}
	if !c2.ShouldSendEvent(SyslogInfo, CategoryScreen) {
		t.Error("no filter should pass all")
	}
}

func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, pool
}
