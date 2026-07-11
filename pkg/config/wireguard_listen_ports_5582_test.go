package config

import (
	"testing"
)

// TestWireGuardListenPorts_5582 proves the compile-time SSOT the host-inbound
// kernel filter consumes to admit the WireGuard listen port(s). The XDP shim
// steers local-destination UDP on the configured WG listen port to the kernel;
// the daemon host-inbound builder must know those ports to admit them (else a
// fresh passive handshake to a restricted zoned address is dropped, #5582).
//
// It compiles two WG tunnels on distinct listen ports plus a GRE tunnel, and
// asserts WireGuardListenPorts() returns exactly the two WG ports, sorted and
// de-duplicated, ignoring the non-WireGuard tunnel.
//
// Fail-on-revert: drop the WgListenPort collection (or return nil) and this goes
// RED, mirroring the loss of the host-inbound WG admission.
func TestWireGuardListenPorts_5582(t *testing.T) {
	lines := []string{
		// wg1 on the HIGHER port, declared FIRST — proves sort, not authoring order.
		"set interfaces wg1 tunnel mode wireguard",
		"set interfaces wg1 tunnel wireguard listen-port 51900",
		"set interfaces wg1 tunnel wireguard private-key " + wgKeyA,
		"set interfaces wg1 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.2.0.0/24",
		// wg0 on the LOWER port.
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wgKeyB,
		"set interfaces wg0 tunnel wireguard peer " + wgKeyA + " allowed-ips 10.1.0.0/24",
		// A GRE tunnel — NOT WireGuard, must not contribute a port.
		"set interfaces gr-0/0/0 unit 0 tunnel source 172.16.50.8",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 172.16.60.9",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	got := cfg.WireGuardListenPorts()
	want := []uint16{51820, 51900}
	if len(got) != len(want) {
		t.Fatalf("WireGuardListenPorts() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("WireGuardListenPorts() = %v, want %v (sorted, deduped)", got, want)
		}
	}
}

// TestWireGuardListenPorts_5582_None proves the no-WireGuard case returns nil
// (a cheap len()==0 test at the call site), so a config with no WG tunnel emits
// no host-inbound WG accept and the restricted-default posture is unchanged.
func TestWireGuardListenPorts_5582_None(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if ports := cfg.WireGuardListenPorts(); len(ports) != 0 {
		t.Fatalf("WireGuardListenPorts() with no WG tunnel = %v, want empty", ports)
	}
}
