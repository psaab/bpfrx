package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
)

// webmgmtIfnameCfg builds a config whose web-management HTTP listener binds to
// the authored Junos interface httpIface, WITH api-auth so an off-loopback
// resolved bind survives the #4047/#5127 loopback fail-safe clamp (an
// unauthenticated off-loopback bind is otherwise pulled back to loopback,
// masking the resolution result). The dataplane interface ge-0/0/0 is modeled
// so config.ResolveKernelIfName maps the Junos ref to its Linux ifname.
func webmgmtIfnameCfg(httpIface string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			HTTP:          true,
			HTTPInterface: httpIface,
			APIAuth: &config.APIAuthConfig{
				Users: []*config.APIAuthUser{{Username: "admin", Password: config.Secret("secret")}},
			},
		},
	}
	return cfg
}

// TestWebMgmtBindResolvesJunosIfnameToLinux_5714 is the #5714 fail-on-revert
// guard: a web-management bind to an AUTHORED Junos interface name (ge-0/0/0.0)
// must resolve to the mapped LINUX kernel ifname (ge-0-0-0) and listen on THAT
// interface's address — not fall back to loopback because the Junos name was
// handed verbatim to net.InterfaceByName (which only knows kernel names).
//
// FAIL-ON-REVERT: dropping the config.ResolveKernelIfName mapping in
// resolveInterfaceAddr passes "ge-0/0/0.0" straight to the kernel lookup, which
// (via the mocked seam, and in reality) does not match "ge-0-0-0", so the bind
// silently falls back to 127.0.0.1 and the address assertion below fires RED.
func TestWebMgmtBindResolvesJunosIfnameToLinux_5714(t *testing.T) {
	// Kernel-address seam: ONLY the resolved Linux name "ge-0-0-0" has an
	// address; the authored Junos name (or any other) errors — exactly the
	// asymmetry net.InterfaceByName exhibits on a renamed interface.
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		if kernelName == "ge-0-0-0" {
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)}}, nil
		}
		return nil, fmt.Errorf("no such kernel interface: %s", kernelName)
	}

	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, webmgmtIfnameCfg("ge-0/0/0.0"))

	if apiCfg.Addr != "10.0.0.5:80" {
		t.Fatalf("web-mgmt bind Addr = %q, want 10.0.0.5:80 (Junos ge-0/0/0.0 -> Linux ge-0-0-0, canonical web-mgmt port #5715). "+
			"127.0.0.1 means the authored Junos name reached the kernel lookup verbatim (the #5714 bug)", apiCfg.Addr)
	}
}

// TestWebMgmtBindUnresolvableLogsLoudError_5714 pins the "fail loudly" half of
// #5714: when the configured web-management interface cannot be resolved to a
// usable address, the bind must emit a LOUD ERROR naming the interface (so the
// operator learns web-management is NOT reachable where configured) rather than
// silently falling back to loopback. The loopback fallback itself is retained so
// the mgmt API is not stranded (a mgmt interface merely not up yet at daemon
// start must not abort the daemon).
//
// FAIL-ON-REVERT: the pre-#5714 code logged this at slog.Warn (silent-ish); the
// ERROR-level assertion below fires RED if the level is reverted to Warn.
func TestWebMgmtBindUnresolvableLogsLoudError_5714(t *testing.T) {
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		return nil, fmt.Errorf("no such kernel interface: %s", kernelName)
	}

	sink := newCaptureSink()
	prevLog := slog.Default()
	slog.SetDefault(slog.New(capturingHandler{sink: sink}))
	defer slog.SetDefault(prevLog)

	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, webmgmtIfnameCfg("ge-0/0/9.0"))

	var loud bool
	for _, r := range sink.records() {
		if r.level == slog.LevelError && r.attrs["interface"] == "ge-0/0/9.0" {
			loud = true
			break
		}
	}
	if !loud {
		t.Fatalf("unresolvable web-mgmt interface must log a LOUD ERROR naming the interface, "+
			"not a silent fallback; got records: %+v", sink.records())
	}
	// Fallback is retained (loopback), so the mgmt API still serves locally —
	// on the canonical web-mgmt port (#5715), since `web-management http` is
	// explicitly configured.
	if apiCfg.Addr != "127.0.0.1:80" {
		t.Fatalf("unresolvable interface bind Addr = %q, want loopback fallback 127.0.0.1:80", apiCfg.Addr)
	}
}
