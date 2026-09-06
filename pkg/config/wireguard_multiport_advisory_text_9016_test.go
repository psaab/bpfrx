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

	// THE ASYMMETRY. This assertion is INVERTED from what it originally
	// required, and the inversion is the point of the change that brought it.
	//
	// It used to demand that the advisory deny any difference — "no WireGuard
	// tunnel's plaintext is zone-adjudicated, steered or not". That was written
	// from the #5618 advisory, which describes the PRE-#8274 world. Three
	// independent statements in this tree say it is false at HEAD:
	//
	//  1. userspace-xdp/src/lib.rs, the #8274 step 3 arm: "a WireGuard
	//     TRANSPORT-DATA record for a configured local listener is NOT local
	//     delivery any more — the worker decaps it and adjudicates the inner
	//     packet under the tunnel's logical ingress zone."
	//  2. userspace-dp poll_descriptor/mod.rs at the stage_wg_decap call:
	//     "Everything downstream then sees the INNER packet — flow parse,
	//     screen, session, policy, NAT, forward build ... instead of being
	//     written to the wgN TUN for the kernel to forward with no zone policy
	//     at all."
	//  3. maps_sync.go: userspaceCtrlFlagWgRx is set iff at least one WireGuard
	//     tunnel is configured, so the gate those two describe is armed exactly
	//     when this advisory can fire.
	//
	// The steered port IS adjudicated and an unsteered port is NOT. Requiring
	// the advisory to deny that erased the only difference an operator needs to
	// see, in the one message that reads as authoritative on the subject — and
	// a cell demanding the denial is what would have kept it there.
	for _, required := range []string{
		"NOT THE SAME",
		"adjudicated under the tunnel's ingress zone",
		"forwarded by the KERNEL with no zone policy",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("advisory must state the steered/unsteered SECURITY asymmetry "+
				"(missing %q). Denying it tells an operator the bypass is not a "+
				"bypass:\n\n%s", required, text)
		}
	}
	if strings.Contains(text, "steered or not") {
		t.Fatalf("advisory still denies the asymmetry:\n\n%s", text)
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
