package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/psaab/xpf/pkg/config"
)

// relayConfigWithRate builds a single-interface relay config whose group sets
// the #5670 per-interface ingress rate limit (packets/second).
func relayConfigWithRate(rate int) *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {
				Name:              "g",
				Interfaces:        []string{"ge-0-0-0"},
				ActiveServerGroup: "sg",
				MaximumPacketRate: rate,
			},
		},
	}
}

// TestTokenBucket_BurstThenRefill is the deterministic unit proof of the #5670
// token-bucket semantics with an injected (frozen/advanceable) clock — no
// sleeping. It pins three properties: (1) a frozen clock admits exactly the
// burst capacity then denies; (2) advancing the clock one second refills
// exactly `rate` tokens; (3) a long idle refill is CAPPED at the burst
// capacity, not rate×elapsed (so an idle relay cannot bank unbounded credit and
// defeat the limiter on the next flood).
func TestTokenBucket_BurstThenRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	b := newTokenBucket(10, 20, clock) // rate 10/s, burst 20

	// (1) Full bucket, frozen clock: exactly `burst` (20) admitted, rest denied.
	allowed := 0
	for i := 0; i < 50; i++ {
		if b.allow() {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("initial burst: allowed %d, want 20 (burst capacity)", allowed)
	}
	if b.allow() {
		t.Fatal("empty bucket must deny with no time advance")
	}

	// (2) Advance 1s → +10 tokens (== rate), so 10 more admitted.
	now = now.Add(time.Second)
	allowed = 0
	for i := 0; i < 50; i++ {
		if b.allow() {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("after 1s refill: allowed %d, want 10 (sustained rate)", allowed)
	}

	// (3) Advance far → refill capped at burst (20), NOT rate×100.
	now = now.Add(100 * time.Second)
	allowed = 0
	for i := 0; i < 200; i++ {
		if b.allow() {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("long-idle refill: allowed %d, want 20 (capped at burst, not rate×elapsed)", allowed)
	}
}

// TestRunRelay_RateLimit_5670 is the end-to-end fail-on-revert proof for the
// #5670 per-interface DHCP relay ingress rate limit. A burst of N valid
// BOOTREQUEST/DISCOVER datagrams is pushed through the live runRelay loop with
// the clock FROZEN, so the whole burst arrives "instantly": the token bucket
// refills nothing, admits exactly its burst capacity, and drops the excess
// BEFORE the DHCP parse + Option-82 fan-out.
//
// GREEN (rate limiter present): exactly `burst` datagrams reach the server and
// the excess (N-burst) is counted in RequestsDroppedRateLimit.
//
// RED-on-revert: neutralize the limiter (delete the `if !rateBucket.allow()`
// drop, or wire an effectively-infinite rate) and ALL N datagrams are relayed
// with RequestsDroppedRateLimit == 0 — both assertions below fail. Verified RED
// during development by removing the drop block.
func TestRunRelay_RateLimit_5670(t *testing.T) {
	const rate = 5
	burst := relayBurstFor(rate) // 10
	const n = 25

	// One valid client DISCOVER, replayed N times to model a flood from a single
	// untrusted client-facing segment.
	discover, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	discover.OpCode = dhcpv4.OpcodeBootRequest
	discover.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x05}
	discover.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	wire := discover.ToBytes()

	pending := make([][]byte, n)
	for i := range pending {
		pending[i] = append([]byte(nil), wire...)
	}

	client := newFakeConn()
	client.pending = pending
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	// Freeze the clock: the whole burst is admitted/denied at one instant, so the
	// bucket refills nothing mid-burst and the outcome is deterministic.
	frozen := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return frozen }

	m.Apply(context.Background(), relayConfigWithRate(rate))
	defer m.Stop()

	// Wait until the loop has read all N datagrams and blocked on the (N+1)th
	// read — at that point every pending packet has been fully processed (the
	// loop reads, acts, then loops back to ReadFrom).
	deadline := time.Now().Add(2 * time.Second)
	for client.readCalls.Load() < int64(n+1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := client.readCalls.Load(); got < int64(n+1) {
		t.Fatalf("relay did not consume all %d datagrams (readCalls=%d)", n, got)
	}

	// Exactly `burst` relayed to the one configured server.
	if got := server.writeCount(); got != burst {
		t.Errorf("relayed %d datagrams, want %d (token-bucket burst) — "+
			"rate limiter not bounding the flood", got, burst)
	}

	var relayed, dropped uint64
	for _, s := range m.Stats() {
		relayed += s.RequestsRelayed
		dropped += s.RequestsDroppedRateLimit
	}
	if relayed != uint64(burst) {
		t.Errorf("RequestsRelayed = %d, want %d (burst admitted)", relayed, burst)
	}
	if dropped != uint64(n-burst) {
		t.Errorf("RequestsDroppedRateLimit = %d, want %d (excess dropped) — "+
			"the flood was not throttled", dropped, n-burst)
	}
}

// TestRunRelay_RateLimit_DefaultBound proves an UNCONFIGURED relay still gets a
// bound (the security-hardening default): with no `overrides
// maximum-packet-rate`, the resolver applies defaultMaxPacketRate (100 pps) so
// its burst is relayBurstFor(100)=200 — a frozen-clock flood of 250 admits
// exactly 200 and drops 50. RED-on-revert: if the default is not applied
// (bucket rate 0 / limiter opt-in only), an unconfigured relay would relay all
// 250 with zero drops.
func TestRunRelay_RateLimit_DefaultBound(t *testing.T) {
	burst := relayBurstFor(defaultMaxPacketRate) // 200
	const n = 250

	discover, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	discover.OpCode = dhcpv4.OpcodeBootRequest
	discover.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x06}
	discover.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	wire := discover.ToBytes()

	pending := make([][]byte, n)
	for i := range pending {
		pending[i] = append([]byte(nil), wire...)
	}

	client := newFakeConn()
	client.pending = pending
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	frozen := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return frozen }

	// singleInterfaceConfig sets NO maximum-packet-rate → resolver default.
	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for client.readCalls.Load() < int64(n+1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := client.readCalls.Load(); got < int64(n+1) {
		t.Fatalf("relay did not consume all %d datagrams (readCalls=%d)", n, got)
	}

	if got := server.writeCount(); got != burst {
		t.Errorf("relayed %d datagrams, want %d (default %d pps → burst %d) — "+
			"unconfigured relay is unbounded", got, burst, defaultMaxPacketRate, burst)
	}
	var dropped uint64
	for _, s := range m.Stats() {
		dropped += s.RequestsDroppedRateLimit
	}
	if dropped != uint64(n-burst) {
		t.Errorf("RequestsDroppedRateLimit = %d, want %d (default bound not applied?)",
			dropped, n-burst)
	}
}
