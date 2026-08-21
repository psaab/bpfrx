package ra

// Regression test for #6695: the compiler read
// `protocols router-advertisement interface <if> dns-server-address` with a
// single-value accessor, so a bracketed two-address RDNSS list compiled its
// first address and the hierarchical block spelling compiled none at all.
//
// The pkg/config half of that fix asserts the compiled slice. THIS test closes
// the loop the issue asks for — that the RA actually put on the wire carries
// both servers — by driving the real Junos text through CompileConfig into the
// sender's own buildRA and re-parsing the marshalled option. The sender emits
// ONE RFC 8106 RecursiveDNSServer option holding every address, so a dropped
// address is invisible in the option COUNT and only shows in its Servers list.
//
// RED-on-revert (restore the nodeVal read in compiler_protocols.go): the
// bracket case reads back one server and the block case emits no RDNSS option
// at all.

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func compileRAIface6695(t *testing.T, hier string, setCmds ...string) *config.RAInterfaceConfig {
	t.Helper()
	var tree *config.ConfigTree
	if hier != "" {
		p := config.NewParser(hier)
		parsed, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", hier, errs)
		}
		tree = parsed
	} else {
		tree = &config.ConfigTree{}
		for _, c := range setCmds {
			path, err := config.ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Protocols.RouterAdvertisement) != 1 {
		t.Fatalf("compiled %d RA interfaces, want 1", len(cfg.Protocols.RouterAdvertisement))
	}
	return cfg.Protocols.RouterAdvertisement[0]
}

func TestBuildRA_6695_EveryRDNSSServerOnWire(t *testing.T) {
	cases := []struct {
		name string
		hier string
		set  []string
	}{
		{
			name: "hier-bracket",
			hier: `protocols { router-advertisement { interface ge-0-0-0 {` +
				` dns-server-address [ 2001:db8::53 2001:db8::54 ]; } } }`,
		},
		{
			name: "hier-block",
			hier: `protocols { router-advertisement { interface ge-0-0-0 {` +
				` dns-server-address { 2001:db8::53; 2001:db8::54; } } } }`,
		},
		{
			name: "flat-set-bracket",
			set: []string{"set protocols router-advertisement interface ge-0-0-0 " +
				"dns-server-address [ 2001:db8::53 2001:db8::54 ]"},
		},
		{
			name: "flat-set-repeated",
			set: []string{
				"set protocols router-advertisement interface ge-0-0-0 dns-server-address 2001:db8::53",
				"set protocols router-advertisement interface ge-0-0-0 dns-server-address 2001:db8::54",
			},
		},
	}
	want := []netip.Addr{
		netip.MustParseAddr("2001:db8::53"),
		netip.MustParseAddr("2001:db8::54"),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &sender{
				cfg: compileRAIface6695(t, tc.hier, tc.set...),
				iface: &net.Interface{
					Name:         "ge-0-0-0",
					HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				},
			}
			raw, err := ndp.MarshalMessage(s.buildRA())
			if err != nil {
				t.Fatalf("MarshalMessage: %v", err)
			}
			msg, err := ndp.ParseMessage(raw)
			if err != nil {
				t.Fatalf("ParseMessage: %v", err)
			}
			got, ok := msg.(*ndp.RouterAdvertisement)
			if !ok {
				t.Fatalf("parsed message is %T, want *ndp.RouterAdvertisement", msg)
			}
			var servers []netip.Addr
			for _, opt := range got.Options {
				if rdnss, isRDNSS := opt.(*ndp.RecursiveDNSServer); isRDNSS {
					servers = append(servers, rdnss.Servers...)
				}
			}
			if len(servers) != len(want) {
				t.Fatalf("RA carries %d RDNSS servers (%v), want %d (%v) — a dropped "+
					"address is invisible in the option COUNT, only in its Servers list",
					len(servers), servers, len(want), want)
			}
			for i := range want {
				if servers[i] != want[i] {
					t.Errorf("RDNSS server %d = %v, want %v", i, servers[i], want[i])
				}
			}
		})
	}
}
