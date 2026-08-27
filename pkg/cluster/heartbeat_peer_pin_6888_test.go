package cluster

import (
	"net"
	"path/filepath"
	"testing"
)

// heartbeat_peer_pin_6888_test.go — #6888.
//
// The heartbeat read loop discarded the UDP source address, so nothing compared
// it to the configured control-link peer. This is NOT an authentication
// boundary and these cells must not be read as proving one: frames are
// HMAC-verified in admitFrame, and an attacker without the control-link PSK
// could never get one admitted whatever source it carried. What the pin adds is
// cheapest-point filtering, visibility of a misconfiguration that was
// previously silent, and a constraint on origin if the PSK ever leaks.
//
// The three rows that matter are peer-admitted, foreign-rejected-AND-COUNTED,
// and unset-fails-open. The third is the one a happy-path fixture omits, and it
// is the one whose absence takes a cluster down.

func udp6888(t *testing.T, host string, port int) *net.UDPAddr {
	t.Helper()
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("bad fixture address %q", host)
	}
	return &net.UDPAddr{IP: ip, Port: port}
}

// receiverPinnedTo6888 builds a receiver with a configured peer and no socket —
// srcIsConfiguredPeer is a pure predicate over the address, so no I/O is needed
// to drive it.
func receiverPinnedTo6888(peer *net.UDPAddr) *heartbeatReceiver {
	return &heartbeatReceiver{peerAddr: peer}
}

func TestPeerPinAdmitsTheConfiguredPeer6888(t *testing.T) {
	r := receiverPinnedTo6888(udp6888(t, "10.99.12.2", 4784))

	// The peer sends from an EPHEMERAL port, not the port it listens on — the
	// sender socket is bound with port 0. Measured on the live loss cluster:
	// fw1 listens on 10.99.12.2:4784 and sources from :50923. So the admitted
	// fixture deliberately uses a DIFFERENT port from the configured one; a
	// fixture reusing 4784 would pass under an address+port pin too and would
	// therefore prove nothing about which comparison shipped.
	if !r.srcIsConfiguredPeer(udp6888(t, "10.99.12.2", 50923)) {
		t.Fatal("the configured peer was rejected because its SOURCE port differs from " +
			"its listening port — that is how every real heartbeat arrives, so this " +
			"pin would take down every cluster (#6888)")
	}
}

func TestPeerPinRejectsAndCountsAForeignSource6888(t *testing.T) {
	r := receiverPinnedTo6888(udp6888(t, "10.99.12.2", 4784))

	if r.srcIsConfiguredPeer(udp6888(t, "10.99.12.3", 4784)) {
		t.Fatal("a datagram from a third node was accepted by the peer pin (#6888)")
	}

	// Rejection must be COUNTED. The issue's strongest argument is that a
	// misconfigured third node is currently invisible; a rejection that is not
	// counted reproduces exactly that, one layer down.
	if got := r.foreignSrc.Load(); got != 0 {
		t.Fatalf("precondition: counter should start at 0, got %d", got)
	}
	r.noteForeignSource(udp6888(t, "10.99.12.3", 4784))
	if got := r.foreignSrc.Load(); got != 1 {
		t.Fatalf("foreignSrc = %d after one rejection, want 1 — a silent drop is the "+
			"invisibility this issue exists to fix", got)
	}
}

// TestPeerPinUnsetFailsOpen6888 is the row that takes a cluster down if missing.
//
// A receiver with no configured peer must accept every source, exactly as
// before #6888. A pin that rejects when it does not know what to accept is
// strictly worse than no pin: it converts a defence-in-depth gap into a comms
// outage.
func TestPeerPinUnsetFailsOpen6888(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *heartbeatReceiver
	}{
		{"nil peerAddr", receiverPinnedTo6888(nil)},
		{"peerAddr with nil IP", receiverPinnedTo6888(&net.UDPAddr{Port: 4784})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.r.srcIsConfiguredPeer(udp6888(t, "203.0.113.9", 1234)) {
				t.Fatal("an unset peer pin REJECTED a datagram — with no configured peer " +
					"there is nothing to pin against, and rejecting takes the cluster " +
					"down (#6888)")
			}
		})
	}
}

// TestPeerPinNilSourceFailsOpen6888 covers the other fail-open input: a read
// that produced no source address. Refusing there would turn an
// unexpected-but-harmless read into a comms outage.
func TestPeerPinNilSourceFailsOpen6888(t *testing.T) {
	r := receiverPinnedTo6888(udp6888(t, "10.99.12.2", 4784))
	if !r.srcIsConfiguredPeer(nil) {
		t.Fatal("a nil source address was rejected; the pin has no input to judge and " +
			"must fail open (#6888)")
	}
	if !r.srcIsConfiguredPeer(&net.UDPAddr{Port: 4784}) {
		t.Fatal("a source with no IP was rejected; same reasoning (#6888)")
	}
}

// TestPeerPinIgnoresPortEntirely6888 is the cell that pins the MEASURED design
// decision rather than the implementation.
//
// The peer's sender socket binds port 0, so its source port is ephemeral and
// changes on every daemon restart (observed: fw0 :40745, fw1 :50923, both
// listening on :4784). If someone later "tightens" this to compare the full
// UDPAddr, every legitimate heartbeat is rejected and both nodes declare the
// peer lost. This cell is what says so at review time instead of at failover
// time.
func TestPeerPinIgnoresPortEntirely6888(t *testing.T) {
	r := receiverPinnedTo6888(udp6888(t, "10.99.12.2", 4784))
	for _, port := range []int{1, 4784, 40745, 50923, 65535} {
		if !r.srcIsConfiguredPeer(udp6888(t, "10.99.12.2", port)) {
			t.Fatalf("the pin rejected the configured peer sourcing from port %d — it "+
				"must compare the ADDRESS only; the peer's sender socket is bound "+
				"with port 0 and its source port is ephemeral (#6888)", port)
		}
	}
}

// TestPeerPinMatchesV4MappedForm6888 guards the representation trap. A
// configured peer parsed to a 16-byte v4-in-v6 form and a source in 4-byte form
// are the SAME address, and a bytes.Equal-style comparison would reject the
// peer. net.IP.Equal handles it; this cell is what keeps that from being
// "simplified" to a byte compare.
func TestPeerPinMatchesV4MappedForm6888(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("10.99.12.2"), Port: 4784} // 16-byte form
	r := receiverPinnedTo6888(peer)
	four := net.IPv4(10, 99, 12, 2).To4()
	if len(four) != 4 {
		t.Fatal("precondition: fixture must be the 4-byte form")
	}
	if !r.srcIsConfiguredPeer(&net.UDPAddr{IP: four, Port: 50923}) {
		t.Fatal("the pin rejected the configured peer because the two IPs use different " +
			"internal representations (16-byte v4-mapped vs 4-byte) — use net.IP.Equal " +
			"(#6888)")
	}
}

// TestStartHeartbeatWiresThePeerIntoTheReceiver6888 binds the WIRING, and it is
// the cell without which everything above is inert.
//
// srcIsConfiguredPeer is a pure predicate; it decides nothing until
// startHeartbeatLocked hands the receiver the configured peer. The constructor
// takes the address as a required parameter, so DELETING the argument is a
// build break — but passing `nil` instead of `peer` compiles fine, leaves every
// cell above green, and silently restores the pre-#6888 behaviour, because
// unset fails open by design. That is precisely the mutation this cell exists
// to catch.
//
// It drives the real StartHeartbeat rather than reading the source, so a future
// refactor that moves the plumbing elsewhere still passes as long as the
// receiver ends up pinned.
func TestStartHeartbeatWiresThePeerIntoTheReceiver6888(t *testing.T) {
	m := keyedEpochManager(t, filepath.Join(t.TempDir(), "ha-peer-pin"))

	const peer = "127.0.0.2"
	if err := m.StartHeartbeat("127.0.0.1", peer, ""); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)

	m.mu.RLock()
	r := m.hbReceiver
	m.mu.RUnlock()
	if r == nil {
		t.Fatal("no receiver published after StartHeartbeat")
	}

	if r.peerAddr == nil {
		t.Fatal("the receiver was constructed with NO peer address, so the #6888 pin " +
			"fails open on every datagram and the feature is inert — every other " +
			"cell in this file still passes in that state")
	}
	if got := r.peerAddr.IP.String(); got != peer {
		t.Fatalf("receiver pinned to %q, want the configured peer %q", got, peer)
	}

	// And the pin must actually discriminate once wired — otherwise "peerAddr
	// is non-nil" could be satisfied by an address nothing is compared against.
	if !r.srcIsConfiguredPeer(&net.UDPAddr{IP: net.ParseIP(peer), Port: 33333}) {
		t.Fatal("the wired receiver rejects its own configured peer")
	}
	if r.srcIsConfiguredPeer(&net.UDPAddr{IP: net.ParseIP("127.0.0.9"), Port: 33333}) {
		t.Fatal("the wired receiver accepts a foreign source — it holds an address but " +
			"is not pinning on it")
	}
}
