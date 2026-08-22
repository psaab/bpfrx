// #6585: the remote-syslog handler reconstructed log attributes with a raw
// slog.Value.String() and inserted the result unchanged into the RFC 3164 /
// RFC 5424 wire message, so attacker-controlled text reaching ANY log attribute
// reached remote syslog with its control bytes intact.
//
// WHY THE LOCAL COPY WAS SAFE AND THIS ONE WAS NOT. Go's standard slog text
// handler quotes non-printing attribute values, so the stderr/journald copy is
// protected. SyslogSlogHandler deliberately bypasses that path to build the
// syslog framing itself, and reintroduced the raw value.
//
// PROVEN LIVE PRODUCER. DDNS provider error text is passed to slog.Warn in
// pkg/ddns, and that text embeds the PROVIDER's HTTP response body via %s for
// both Cloudflare and Route 53. So a hostile or compromised DDNS endpoint gets
// its bytes onto the operator's remote syslog. This is the same string PR #6579
// sanitizes for the terminal; the syslog sink was out of that PR's scope.
//
// TWO CONSEQUENCES, both worse than the terminal case because syslog is
// aggregated and long-retained:
//
//  1. LOG INJECTION — a bare LF is a record delimiter in RFC 3164, so the
//     payload forges a frame boundary and synthesizes an entire additional
//     syslog line with arbitrary facility/severity/timestamp/host as far as
//     the collector is concerned.
//  2. DEFERRED TERMINAL INJECTION — ESC/CSI stored verbatim fires whenever an
//     operator later cats or tails the archive.
//
// The guard is at Send, the LAST boundary before the wire, because the
// producers are open-ended (any slog attribute anywhere in the daemon) and a
// per-producer fix rots on the next one.
//
// FAIL-ON-REVERT: drop the termsafe.SanitizeForDisplay call from
// SyslogClient.Send and every wire assertion below reds.
package logging

import (
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// recvOneFrame returns the bytes of exactly one UDP datagram, which for RFC
// 3164 is exactly one syslog record. Asserting on the WIRE BYTES is the point:
// a test on the slog.Record, or on formatRecord's string, cannot see whether a
// control byte survived into the frame.
func recvOneFrame(t *testing.T, pc net.PacketConn) string {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read syslog frame: %v", err)
	}
	return string(buf[:n])
}

func newLoopbackSyslogClient(t *testing.T) (*SyslogClient, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	c, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, pc
}

// rawControlBytes reports the control bytes that survived into a frame. The
// trailing LF some senders append is not counted — the injection concern is a
// delimiter INSIDE the message, which is why the payload's own LF must not
// reach the wire.
func rawControlBytes(frame string) []byte {
	var got []byte
	for i := 0; i < len(frame); i++ {
		b := frame[i]
		if b == '\n' && i == len(frame)-1 {
			continue
		}
		if b < 0x20 || b == 0x7f {
			got = append(got, b)
		}
	}
	return got
}

// TestSyslogFrameCarriesNoControlBytes6585 drives the real handler end to end:
// slog record -> SyslogSlogHandler -> SyslogClient.Send -> UDP wire.
func TestSyslogFrameCarriesNoControlBytes6585(t *testing.T) {
	c, pc := newLoopbackSyslogClient(t)

	base := slog.NewTextHandler(discardWriter{}, nil)
	h := NewSyslogSlogHandler(base)
	h.SetClients([]*SyslogClient{c})
	// SetClients closes the OLD set, not the new one; the client's own
	// t.Cleanup still owns closing this one.
	log := slog.New(h)

	// The shape a DDNS provider response body can carry: a bare LF that forges
	// an RFC 3164 record boundary, plus ESC/CSI for the deferred-terminal half,
	// plus CR and a DEL.
	payload := "boom\nJan  1 00:00:00 evil-host xpf: FORGED RECORD\x1b[2Jcls\rback\x7f"
	log.Warn("ddns update failed", "err", payload)

	frame := recvOneFrame(t, pc)

	if got := rawControlBytes(frame); len(got) != 0 {
		t.Fatalf("raw control bytes %q survived into the syslog frame:\n%q\n"+
			"An LF here forges an RFC 3164 record boundary (log injection); an ESC "+
			"fires whenever an operator later cats the collector's archive "+
			"(deferred terminal injection) (#6585)", got, frame)
	}
	// The escaped forms must be present — i.e. the bytes were neutralized, not
	// dropped. Dropping would lose evidence and would also pass the check above.
	for _, want := range []string{`\x0a`, `\x1b`, `\x0d`, `\x7f`} {
		if !strings.Contains(frame, want) {
			t.Errorf("frame does not contain the escaped form %s — the control byte was "+
				"DROPPED rather than escaped, which loses forensic content:\n%q", want, frame)
		}
	}
	// The surrounding text must survive so the record is still useful.
	if !strings.Contains(frame, "ddns update failed") || !strings.Contains(frame, "boom") {
		t.Errorf("sanitizing destroyed the legitimate message content:\n%q", frame)
	}
}

// TestSyslogFrameIsExactlyOneLine6585 is the log-injection assertion, stated
// as the property that is actually OBSERVABLE at this socket.
//
// A first draft of this test counted DATAGRAMS and asserted that one Send
// produced one frame. That is vacuous over UDP — one Send is one datagram no
// matter what the payload contains — and the mutation matrix proved it: the
// cell that swaps in the LF-PRESERVING block sanitizer left it green.
//
// The forgery is collector-side, not socket-side: RFC 3164 has no length
// prefix, so a collector writing records to a file, or a relay forwarding over
// TCP with non-transparent framing (RFC 6587 s3.4.2), treats an embedded LF as
// a record boundary. Our own TCP path uses octet-counting, so we cannot observe
// the split locally at all. What we CAN assert — and what fully determines the
// collector's behaviour — is that no LF ever leaves this process inside a
// message body.
func TestSyslogFrameIsExactlyOneLine6585(t *testing.T) {
	c, pc := newLoopbackSyslogClient(t)

	if err := c.Send(SyslogWarning, "first\n<0>Jan  1 00:00:00 h xpf: SECOND"); err != nil {
		t.Fatal(err)
	}
	frame := recvOneFrame(t, pc)

	body := strings.TrimRight(frame, "\n")
	if strings.Contains(body, "\n") {
		t.Fatalf("the emitted syslog frame contains an embedded LF, so a collector "+
			"(or a relay using RFC 6587 non-transparent framing) reads it as TWO "+
			"records — the payload forged a boundary and synthesized a record with "+
			"an arbitrary priority, timestamp and host:\n%q", frame)
	}
	if !strings.Contains(frame, "SECOND") {
		t.Fatalf("the forged text must still RIDE INSIDE the single frame, escaped, "+
			"rather than being dropped: %q", frame)
	}
}

// TestSyslogSanitizeDoesNotAlterOrdinaryMessages6585 is the over-reach guard.
// A sanitizer that mangles ordinary text is its own defect: operators read
// these records, and UTF-8 hostnames/identifiers are legitimate.
func TestSyslogSanitizeDoesNotAlterOrdinaryMessages6585(t *testing.T) {
	c, pc := newLoopbackSyslogClient(t)

	for _, msg := range []string{
		"interface ge-0/0/1 changed state to up",
		`policy "allow web" matched src=10.0.1.5 dst=10.0.2.7 app=junos-http`,
		"zone=trust user=café host=münchen.example.com emoji=🚀",
		"path=/var/log/messages pct=99.9% ratio=1/2 quoted=\"x\" tab_free=yes",
	} {
		if err := c.Send(SyslogInfo, msg); err != nil {
			t.Fatal(err)
		}
		frame := recvOneFrame(t, pc)
		if !strings.HasSuffix(strings.TrimRight(frame, "\n"), msg) {
			t.Errorf("ordinary message was altered on the wire.\n sent: %q\nframe: %q\n"+
				"Multi-word text and multibyte UTF-8 must pass through unchanged (#6585)", msg, frame)
		}
	}
}

// TestSyslogSanitizeAppliesToRFC5424Too6585 pins the guard's placement. It sits
// in Send, BEFORE the format branch, so both wire formats are covered. Putting
// it in either branch's formatter would leave the other raw — and sd-syslog is
// selected by config, so which format is live is an operator choice rather than
// a property of the code.
func TestSyslogSanitizeAppliesToRFC5424Too6585(t *testing.T) {
	c, pc := newLoopbackSyslogClient(t)
	c.Format = "sd-syslog"

	if err := c.Send(SyslogWarning, "x\x1b[31mred\ny"); err != nil {
		t.Fatal(err)
	}
	frame := recvOneFrame(t, pc)
	if got := rawControlBytes(frame); len(got) != 0 {
		t.Fatalf("raw control bytes %q survived into an RFC 5424 frame: %q", got, frame)
	}
	if !strings.HasPrefix(frame, "<") || !strings.Contains(frame, ">1 ") {
		t.Fatalf("expected an RFC 5424 frame, got %q", frame)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
