package flowexport

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCollectorAddress_IPv6IsBracketed proves the collector destination
// address built by the shared collector resolver (collectVersionCollectors,
// reached via BuildExportConfig for v9 and BuildIPFIXExportConfig for IPFIX)
// is parseable by net.ResolveUDPAddr for BOTH IPv4 and IPv6 flow servers.
//
// Regression for #2183: the pre-fix code built the address with
// fmt.Sprintf("%s:%d", ...), which leaves an IPv6 literal unbracketed
// (2001:db8::9:4739). net.ResolveUDPAddr / net.Dial cannot parse that, so
// IPv6 NetFlow/IPFIX collectors silently never dialed. net.JoinHostPort
// brackets the IPv6 host ([2001:db8::9]:4739) so resolution succeeds. The
// IPv6 sub-case of this test FAILS against the pre-fix %s:%d (the address
// is unparseable); the IPv4 sub-case is unchanged either way.
func TestCollectorAddress_IPv6IsBracketed(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		port     int
		wantAddr string
	}{
		{name: "ipv4", addr: "1.2.3.4", port: 4739, wantAddr: "1.2.3.4:4739"},
		{name: "ipv6", addr: "2001:db8::9", port: 4739, wantAddr: "[2001:db8::9]:4739"},
	}

	// buildersUnderTest drives the real address-build path through both
	// exporter config resolvers; both funnel into collectVersionCollectors,
	// so a single address-format fix must satisfy both.
	buildersUnderTest := []struct {
		name  string
		svc   func() *config.ServicesConfig
		build func(*config.ServicesConfig, *config.ForwardingOptionsConfig) *ExportConfig
	}{
		{
			name:  "v9",
			svc:   v9Svc,
			build: BuildExportConfig,
		},
		{
			name: "ipfix",
			svc: func() *config.ServicesConfig {
				return &config.ServicesConfig{
					FlowMonitoring: &config.FlowMonitoringConfig{
						VersionIPFIX: &config.NetFlowIPFIXConfig{
							Templates: map[string]*config.NetFlowIPFIXTemplate{
								"t": {TemplateRefreshRate: 90},
							},
						},
					},
				}
			},
			build: BuildIPFIXExportConfig,
		},
	}

	for _, b := range buildersUnderTest {
		for _, tc := range cases {
			t.Run(b.name+"/"+tc.name, func(t *testing.T) {
				fo := &config.ForwardingOptionsConfig{
					Sampling: &config.SamplingConfig{
						Instances: map[string]*config.SamplingInstance{
							"test": {
								Name: "test",
								FamilyInet: &config.SamplingFamily{
									FlowServers: []*config.FlowServer{
										{Address: tc.addr, Port: tc.port},
									},
								},
							},
						},
					},
				}

				ec := b.build(b.svc(), fo)
				if ec == nil {
					t.Fatal("expected non-nil ExportConfig")
				}
				if len(ec.Collectors) != 1 {
					t.Fatalf("collectors = %d, want 1", len(ec.Collectors))
				}
				got := ec.Collectors[0].Address
				if got != tc.wantAddr {
					t.Errorf("collector address = %q, want %q", got, tc.wantAddr)
				}
				// The acceptance criterion: the built address must be
				// parseable by the consumer in transport.go.
				if _, err := net.ResolveUDPAddr("udp", got); err != nil {
					t.Errorf("net.ResolveUDPAddr(%q) failed: %v", got, err)
				}
			})
		}
	}
}

// TestCollectorAddress_NoPortIsExcludedEntirely is the #8163 successor to
// TestCollectorAddress_NoPortLeavesBareAddress.
//
// That test documented, correctly for its time, that a flow-server with no
// explicit port was carried through as a BARE address with no ":0" appended.
// #8163 changed the contract rather than the formatting: such a collector can
// never receive a record (net.Dial rejects the bare host with "missing port in
// address"), and carrying it to dialCollectors made that failure fatal for the
// whole group — and, through reconcileFlowExporter's build loop, for every
// other group too. config.FlowServerExcludedReason now drops it where the
// collector list is built.
//
// The test MOVES with the code instead of being deleted or loosened: its
// subject is still "what does a portless flow-server produce", and the answer
// is now "nothing at all". Deleting it would have quietly retired the only
// cell watching this input shape.
//
// The `if fs.Port > 0` guard in collectInstanceVersionCollectors is kept
// deliberately even though the exclusion above makes Port >= 1 on every path
// that reaches it. It is the FAIL-LOUD leg: if the exclusion is ever moved or
// bypassed, a bare address dies at dial with a named error, whereas an
// unconditional JoinHostPort would emit "host:0", which dials successfully and
// discards every record silently. Defence-in-depth, in the direction that
// stays diagnosable.
func TestCollectorAddress_NoPortIsExcludedEntirely(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "2001:db8::9"}, // Port left 0
						},
					},
				},
			},
		},
	}

	ec := BuildExportConfig(v9Svc(), fo)
	if ec != nil && len(ec.Collectors) != 0 {
		t.Fatalf("a flow-server with no `port` produced collectors %v; it can "+
			"never receive a record, and carrying it here makes the dial "+
			"failure fatal for every other collector in the group (#8163)",
			ec.Collectors)
	}
}

// TestDialCollectors_IPv6SourceAddressResolves proves the local bind
// address built from an IPv6 SourceAddress in dialCollectors is parseable.
//
// Sibling regression for #2183: the pre-fix code built the local bind
// string with c.SourceAddress+":0", which leaves an IPv6 source literal
// unbracketed (2001:db8::1:0) and fails net.ResolveUDPAddr. With the fix
// (net.JoinHostPort(c.SourceAddress, "0")) it resolves and the dial is
// reached. The resolve seam delegates to the real net.ResolveUDPAddr so
// it rejects the pre-fix unbracketed string, while the dial seam returns
// a fakeConn to avoid an actual kernel bind to a non-local IPv6 address.
func TestDialCollectors_IPv6SourceAddressResolves(t *testing.T) {
	var resolvedLocal string
	dialReached := false

	withSeams(t,
		func(network, address string) (*net.UDPAddr, error) {
			ua, err := net.ResolveUDPAddr(network, address)
			if err != nil {
				return nil, err
			}
			// First call is the local SourceAddress bind ("...:0"); the
			// second is the destination collector address.
			if resolvedLocal == "" {
				resolvedLocal = address
			}
			return ua, nil
		},
		func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
			dialReached = true
			return &fakeConn{}, nil
		},
		func() {
			cc, err := dialCollectors([]CollectorConfig{
				{Address: "[2001:db8::9]:4739", SourceAddress: "2001:db8::1"},
			})
			if err != nil {
				t.Fatalf("dialCollectors with IPv6 source-address failed: %v", err)
			}
			cc.close()
		})

	if want := "[2001:db8::1]:0"; resolvedLocal != want {
		t.Errorf("local bind resolved = %q, want bracketed %q", resolvedLocal, want)
	}
	if !dialReached {
		t.Error("dial was not reached for IPv6 source-address collector")
	}
}
