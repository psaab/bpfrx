package daemon

import (
	"net"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/webmgmt"
)

// webmgmt_port_contract_5715_test.go is the #5715 cross-package contract: the
// web-management LISTENER bind ports (derived by resolveAPIBinds from a
// web-management config) must EQUAL the host-inbound service-catalog admit ports
// for the `http` / `https` tokens (config.HostInboundServiceMatch, the Go SSOT
// the nft kernel mirror renders and the Rust classifier parity-tracks).
//
// Before #5715 the listener bound 8080/8443 while the catalog admitted 80/443,
// so a zoned interface configured with least-privilege `system-services https`
// admitted an unused TCP/443 socket and DROPPED the real TCP/8443 listener. Both
// sides now derive from the pkg/webmgmt SSOT (HTTPPort=80 / HTTPSPort=443).

// hostInboundTCPPort returns the single TCP admit port the host-inbound catalog
// grants for token in family, failing if the token does not map to exactly one
// single-port TCP match (the http/https contract shape).
func hostInboundTCPPort(t *testing.T, token, family string) uint16 {
	t.Helper()
	ms := config.HostInboundServiceMatch(token, family)
	if len(ms) != 1 {
		t.Fatalf("HostInboundServiceMatch(%q,%q) returned %d matches, want exactly 1", token, family, len(ms))
	}
	m := ms[0]
	if m.Proto != config.HostInboundProtoTCP {
		t.Fatalf("HostInboundServiceMatch(%q,%q) proto = %d, want TCP", token, family, m.Proto)
	}
	if len(m.Ports) != 1 || m.Ports[0].Lo != m.Ports[0].Hi {
		t.Fatalf("HostInboundServiceMatch(%q,%q) ports = %+v, want one single port", token, family, m.Ports)
	}
	return m.Ports[0].Lo
}

// listenerPort extracts the numeric port from a "host:port" listen address.
func listenerPort(t *testing.T, addr string) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return uint16(p)
}

// webmgmtCfg builds a web-management config binding HTTP and/or HTTPS to a Junos
// interface, WITH api-auth so an off-loopback resolved bind survives the
// #4047/#5127 loopback fail-safe clamp (otherwise the assertion would see the
// clamped loopback, not the resolved bind — but the PORT is preserved either
// way, which is what this contract checks).
func webmgmtCfg(http, https bool, iface string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	wm := &config.WebManagementConfig{
		APIAuth: &config.APIAuthConfig{
			Users: []*config.APIAuthUser{{Username: "admin", Password: config.Secret("secret")}},
		},
	}
	if http {
		wm.HTTP = true
		wm.HTTPInterface = iface
	}
	if https {
		wm.HTTPS = true
		wm.HTTPSInterface = iface
	}
	cfg.System.Services = &config.SystemServicesConfig{WebManagement: wm}
	return cfg
}

// TestWebMgmtListenerMatchesHostInboundAdmit_5715 is the load-bearing #5715
// contract test.
//
// FAIL-ON-REVERT: restore the old listener port (bind 8080/8443 instead of the
// webmgmt SSOT 80/443) and the derived listener port no longer equals the
// host-inbound admit port — every assertion below goes RED. Likewise, changing
// only the catalog (config.HostInboundServiceMatch) breaks the equality.
func TestWebMgmtListenerMatchesHostInboundAdmit_5715(t *testing.T) {
	// The interface seam resolves ge-0-0-0 to a routable v4 address so the bind
	// is off-loopback (mgmt-relevant); api-auth keeps it off-loopback past the
	// clamp.
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		if kernelName == "ge-0-0-0" {
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)}}, nil
		}
		return nil, nil
	}

	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, webmgmtCfg(true, true, "ge-0/0/0.0"))

	httpBind := listenerPort(t, apiCfg.Addr)
	httpsBind := listenerPort(t, apiCfg.HTTPSAddr)

	// (1) listener == catalog admit, per family, for http and https.
	for _, fam := range []string{"ip", "ip6"} {
		if admit := hostInboundTCPPort(t, "http", fam); httpBind != admit {
			t.Errorf("[%s] HTTP listener binds :%d but host-inbound admits :%d — contract broken", fam, httpBind, admit)
		}
		if admit := hostInboundTCPPort(t, "https", fam); httpsBind != admit {
			t.Errorf("[%s] HTTPS listener binds :%d but host-inbound admits :%d — contract broken", fam, httpsBind, admit)
		}
	}
	// (2) both sides equal the webmgmt SSOT constants.
	if httpBind != webmgmt.HTTPPort {
		t.Errorf("HTTP listener :%d != webmgmt.HTTPPort %d", httpBind, webmgmt.HTTPPort)
	}
	if httpsBind != webmgmt.HTTPSPort {
		t.Errorf("HTTPS listener :%d != webmgmt.HTTPSPort %d", httpsBind, webmgmt.HTTPSPort)
	}
	// (3) the webapi-* aliases share the same admit ports (they are web-mgmt).
	if p := hostInboundTCPPort(t, "webapi-clear-text", "ip"); p != webmgmt.HTTPPort {
		t.Errorf("webapi-clear-text admits :%d, want %d", p, webmgmt.HTTPPort)
	}
	if p := hostInboundTCPPort(t, "webapi-ssl", "ip"); p != webmgmt.HTTPSPort {
		t.Errorf("webapi-ssl admits :%d, want %d", p, webmgmt.HTTPSPort)
	}
	// (4) negative control: the OLD listener ports are NOT what the catalog
	// admits (a lifeline guard — 8080/8443 must not be silently admitted).
	if webmgmt.HTTPPort == 8080 || webmgmt.HTTPSPort == 8443 {
		t.Fatalf("canonical ports regressed to the pre-#5715 8080/8443")
	}
}

// TestWebMgmtBindPortSelection_5715 pins the resolveAPIBinds port-selection
// cases the #5715 research spec enumerates: HTTP-only, HTTPS-only, both (v4/v6),
// no-stanza (diagnostic default retained), and api-auth-only (not moved to 80).
func TestWebMgmtBindPortSelection_5715(t *testing.T) {
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		switch kernelName {
		case "ge-0-0-0":
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)}}, nil
		case "ge-0-0-1":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)}}, nil
		}
		return nil, nil
	}

	t.Run("http-only binds 80", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, webmgmtCfg(true, false, "ge-0/0/0.0"))
		if apiCfg.Addr != "10.0.0.5:80" {
			t.Errorf("http-only Addr = %q, want 10.0.0.5:80", apiCfg.Addr)
		}
		if apiCfg.TLS {
			t.Errorf("http-only must not enable TLS")
		}
	})

	t.Run("https-only binds 443, http keeps loopback default", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, webmgmtCfg(false, true, "ge-0/0/0.0"))
		if apiCfg.HTTPSAddr != "10.0.0.5:443" {
			t.Errorf("https-only HTTPSAddr = %q, want 10.0.0.5:443", apiCfg.HTTPSAddr)
		}
		// HTTP was NOT configured → apiCfg.Addr stays the diagnostic default
		// (loopback 8080), never exposed off-loopback implicitly.
		if apiCfg.Addr != "127.0.0.1:8080" {
			t.Errorf("https-only HTTP Addr = %q, want the retained loopback default 127.0.0.1:8080", apiCfg.Addr)
		}
	})

	t.Run("ipv6 interface binds bracketed 80/443", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, webmgmtCfg(true, true, "ge-0/0/1.0"))
		if apiCfg.Addr != "[2001:db8::5]:80" {
			t.Errorf("v6 HTTP Addr = %q, want [2001:db8::5]:80", apiCfg.Addr)
		}
		if apiCfg.HTTPSAddr != "[2001:db8::5]:443" {
			t.Errorf("v6 HTTPS Addr = %q, want [2001:db8::5]:443", apiCfg.HTTPSAddr)
		}
	})

	t.Run("no web-management stanza keeps -api-addr default", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, &config.Config{})
		if apiCfg.Addr != "127.0.0.1:8080" {
			t.Errorf("no-stanza Addr = %q, want the untouched diagnostic default 127.0.0.1:8080", apiCfg.Addr)
		}
		if apiCfg.TLS {
			t.Errorf("no-stanza must not enable HTTPS")
		}
	})

	t.Run("api-auth-only block does not move loopback listener to 80", func(t *testing.T) {
		cfg := &config.Config{System: config.SystemConfig{Services: &config.SystemServicesConfig{
			WebManagement: &config.WebManagementConfig{
				APIAuth: &config.APIAuthConfig{
					Users: []*config.APIAuthUser{{Username: "admin", Password: config.Secret("secret")}},
				},
			},
		}}}
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, cfg)
		if apiCfg.Addr != "127.0.0.1:8080" {
			t.Errorf("api-auth-only Addr = %q, want the retained diagnostic default 127.0.0.1:8080 "+
				"(an api-auth-only block must NOT silently move the loopback listener to port 80)", apiCfg.Addr)
		}
	})
}
