package config

import (
	"strings"
	"testing"
)

func wgMultiportTree9016(t *testing.T, ports ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const peer = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	for i, p := range ports {
		name := "wg" + string(rune('0'+i))
		for _, c := range []string{
			"set interfaces " + name + " tunnel mode wireguard",
			"set interfaces " + name + " tunnel wireguard listen-port " + p,
			"set interfaces " + name + " tunnel wireguard private-key " + key,
			"set interfaces " + name + " tunnel wireguard peer " + peer + " allowed-ips 10.99.0.0/24",
		} {
			cmd, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("parse %q: %v", c, err)
			}
			if err := tree.SetPath(cmd); err != nil {
				t.Fatalf("setpath %q: %v", c, err)
			}
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

// #9016: the advisory told the operator the unsteered tunnel was "dead while
// appearing configured" and that "no handshake ever completes". Both are false.
// The host-inbound filter admits EVERY configured listen-port (see
// TestHostInboundAdmitsEveryWireGuardPort9016 in pkg/daemon) and the helper
// binds a socket per wireguard endpoint, so the unsteered port is served by the
// KERNEL path — not by nothing. An operator told a live tunnel is dead leaves
// it in place.
//
// Nothing bound this text before, which is how a false security-relevant claim
// survived in a warning that reads as authoritative.
func TestMultiportAdvisoryDoesNotClaimTheTunnelIsDead9016(t *testing.T) {
	cfg := wgMultiportTree9016(t, "51820", "51821")
	adv := validateWireguardSingleSteeredPort(cfg)
	if len(adv) != 1 {
		t.Fatalf("two distinct listen-ports must produce exactly one advisory, got %d: %v",
			len(adv), adv)
	}
	text := adv[0]

	// The retracted claims. Each asserted a fact about the wire that is not true.
	for _, forbidden := range []string{
		"dead while appearing configured",
		"no handshake ever",
		"no inbound WireGuard transport reaches",
		"silently down",
		"and works",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("advisory still claims %q; the unsteered tunnel receives inbound "+
				"transport and its socket decapsulates it — telling the operator it is "+
				"dead points them away from the real posture.\n\n%s", forbidden, text)
		}
	}

	// What it must say instead: the port is unsteered, NOT inert.
	for _, required := range []string{"51821", "KERNEL path", "steered"} {
		if !strings.Contains(text, required) {
			t.Fatalf("advisory omits %q:\n\n%s", required, text)
		}
	}

	// It must NOT imply the steered tunnel is adjudicated. No WireGuard
	// tunnel's plaintext is, steered or not; claiming otherwise here is the
	// same false reassurance in the other direction.
	if !strings.Contains(text, "zone-adjudicated") {
		t.Fatalf("advisory must state that steering is not adjudication, or a reader "+
			"infers the steered tunnel is policed:\n\n%s", text)
	}

	// CONTROL: one tunnel, no advisory. A check that fired always would satisfy
	// every assertion above.
	if adv := validateWireguardSingleSteeredPort(wgMultiportTree9016(t, "51820")); len(adv) != 0 {
		t.Fatalf("a single listen-port must produce NO multi-port advisory, got: %v", adv)
	}

	// CONTROL: two tunnels sharing ONE port are not a multi-port config either.
	if adv := validateWireguardSingleSteeredPort(wgMultiportTree9016(t, "51820", "51820")); len(adv) != 0 {
		t.Fatalf("two tunnels on the SAME port are all steered; no advisory is due, got: %v", adv)
	}
}
