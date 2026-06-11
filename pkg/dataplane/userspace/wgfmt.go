package userspace

import (
	"fmt"
	"strings"
	"time"
)

// FormatWireguardStatus renders the #1865 per-WG-tunnel telemetry rows
// for `show security wireguard [detail]`. Shared by the local CLI
// (pkg/cli) and the gRPC text server (pkg/grpcapi) so both surfaces
// render identically — the FormatSystemBuffers pattern.
//
// `now` is passed explicitly (rather than read inside) so the
// handshake-age rendering is testable; callers pass time.Now().
//
// The summary view is the wg-show-shaped operator glance: identity,
// session state, latest handshake, transfer, and a drop TOTAL. The
// detail view adds the full per-reason drop tables — the one-glance
// diagnosis for the #1736 class of failures (silent sends, MTU
// blackholes, wrong-key peers).
func FormatWireguardStatus(status ProcessStatus, detail bool, now time.Time) string {
	if len(status.WgTunnels) == 0 {
		return "No WireGuard tunnels configured\n"
	}
	var b strings.Builder
	for i, t := range status.WgTunnels {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Tunnel: %s (endpoint id %d)\n", t.Tunnel, t.TunnelEndpointID)
		fmt.Fprintf(&b, "  Listen port:        %d\n", t.ListenPort)
		fmt.Fprintf(&b, "  Peer public key:    %s\n", t.PeerPubkeyHex)
		endpoint := t.PeerEndpoint
		if endpoint == "" {
			endpoint = "(responder-only; learned at runtime)"
		}
		fmt.Fprintf(&b, "  Peer endpoint:      %s\n", endpoint)
		state := "no session"
		if t.SessionConfirmed {
			state = "session confirmed"
		} else if t.LastHandshakeUnixSecs > 0 {
			state = "handshake completed, unconfirmed"
		}
		fmt.Fprintf(&b, "  Session:            %s\n", state)
		fmt.Fprintf(&b, "  Latest handshake:   %s\n",
			formatHandshakeAge(t.LastHandshakeUnixSecs, now))
		fmt.Fprintf(&b, "  Handshakes:         %d initiator, %d responder (initiations sent %d, send errors %d)\n",
			t.HsCompletionsInitiator, t.HsResponsesCreated,
			t.HsInitiationsCreated, t.HsSendErrors)
		fmt.Fprintf(&b, "  Transfer:           %d pkts / %d bytes received, %d pkts / %d bytes sent (inner IP)\n",
			t.DecapPackets, t.DecapBytes, t.EncapPackets, t.EncapBytes)
		if t.DecapKeepalives > 0 {
			fmt.Fprintf(&b, "  Keepalives:         %d received\n", t.DecapKeepalives)
		}
		decapDrops := t.DecapDropsMalformedHeader + t.DecapDropsUnknownSession +
			t.DecapDropsCounterCeiling + t.DecapDropsCrypto + t.DecapDropsReplay +
			t.DecapDropsAllowedIPs + t.DecapDropsMalformedInner + t.DecapDropsBuffer
		encapDrops := t.EncapDropsNoSession + t.EncapDropsUnconfirmed +
			t.EncapDropsRekeyRequired + t.EncapDropsOther + t.EncapMtuDrops
		hsDrops := t.HsRxDropsMac1Mismatch + t.HsRxDropsMalformed + t.HsRxDropsCrypto +
			t.HsRxDropsUnknownPeer + t.HsRxDropsStaleResponse + t.HsRxDropsIndexExhausted +
			t.HsRxCookieUnsupported + t.RxUnknownType
		ioErrors := t.HsSendErrors + t.TransportSendErrors + t.TunWriteErrors +
			t.TunRxDropsNoEndpoint
		fmt.Fprintf(&b, "  Drops:              %d receive, %d transmit, %d handshake, %d I/O errors\n",
			decapDrops, encapDrops, hsDrops, ioErrors)
		if !detail {
			continue
		}
		b.WriteString("  Receive drops by reason:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"malformed-header", t.DecapDropsMalformedHeader},
			{"unknown-session", t.DecapDropsUnknownSession},
			{"counter-ceiling", t.DecapDropsCounterCeiling},
			{"decrypt-failed", t.DecapDropsCrypto},
			{"replay", t.DecapDropsReplay},
			{"allowed-ips-violation", t.DecapDropsAllowedIPs},
			{"malformed-inner", t.DecapDropsMalformedInner},
			{"buffer", t.DecapDropsBuffer},
		})
		b.WriteString("  Transmit drops by reason:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"no-session", t.EncapDropsNoSession},
			{"unconfirmed-session", t.EncapDropsUnconfirmed},
			{"rekey-required", t.EncapDropsRekeyRequired},
			{"mtu-exceeded", t.EncapMtuDrops},
			{"other", t.EncapDropsOther},
		})
		b.WriteString("  Handshake drops by reason:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"mac1-mismatch", t.HsRxDropsMac1Mismatch},
			{"malformed", t.HsRxDropsMalformed},
			{"crypto", t.HsRxDropsCrypto},
			{"unknown-peer", t.HsRxDropsUnknownPeer},
			{"stale-response", t.HsRxDropsStaleResponse},
			{"index-exhausted", t.HsRxDropsIndexExhausted},
			{"cookie-unsupported", t.HsRxCookieUnsupported},
			{"unknown-type", t.RxUnknownType},
		})
		b.WriteString("  I/O errors:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"handshake-send", t.HsSendErrors},
			{"transport-send", t.TransportSendErrors},
			{"tun-write", t.TunWriteErrors},
			{"tun-read-no-endpoint", t.TunRxDropsNoEndpoint},
		})
		fmt.Fprintf(&b, "  Handshake activity: %d initiations created, %d build failures, %d requests armed\n",
			t.HsInitiationsCreated, t.HsInitiationBuildFailures, t.HsRequestsArmed)
		fmt.Fprintf(&b, "  Keepalives:         %d received\n", t.DecapKeepalives)
	}
	return b.String()
}

type wgReasonRow struct {
	reason string
	count  uint64
}

func writeWgReasonRows(b *strings.Builder, rows []wgReasonRow) {
	for _, r := range rows {
		fmt.Fprintf(b, "    %-24s %d\n", r.reason, r.count)
	}
}

// formatHandshakeAge renders the last-handshake timestamp like wg
// show's "latest handshake" line. 0 means never (the in-band wire
// sentinel). A timestamp in the future (clock step between helper
// conversion and this render) clamps to "0 seconds ago" rather than
// going negative.
func formatHandshakeAge(unixSecs uint64, now time.Time) string {
	if unixSecs == 0 {
		return "never"
	}
	age := now.Unix() - int64(unixSecs)
	if age < 0 {
		age = 0
	}
	d := time.Duration(age) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds ago", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
}
