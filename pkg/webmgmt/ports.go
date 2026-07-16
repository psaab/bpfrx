// Package webmgmt holds the single source of truth for the web-management
// service contract shared across the control plane and the host-inbound
// admission surfaces. It is a LEAF package (imports only the standard library)
// so both pkg/config (the host-inbound service catalog) and pkg/daemon (the
// listener bind) can depend on it without an api<->config import cycle and
// without making pkg/daemon constants authoritative to pkg/config.
package webmgmt

import "strconv"

// Canonical external TCP ports for an explicitly configured `system services
// web-management http|https` service (#5715). Junos J-Web binds http=80 /
// https=443 by default and xpfd already requires privileged networking (no
// systemd User= directive), so binding these privileged ports adds no new
// requirement. These are THE contract: the host-inbound service catalog
// (config.HostInboundServiceMatch for the http / https / webapi-clear-text /
// webapi-ssl tokens, mirrored by the Rust classify_system_service admit set)
// admits EXACTLY these ports, so the listener bind and the host-inbound admit
// are ONE cross-package contract. Before #5715 the listener bound 8080/8443
// while the catalog admitted 80/443, so host-inbound admitted an unused socket
// and dropped the real listener on a zoned interface.
//
// NOT the loopback diagnostic default: with NO `system services web-management`
// stanza the daemon keeps the `-api-addr` flag default (127.0.0.1:8080), a
// loopback-only REST/diagnostic path that is never subject to host-inbound
// admission (loopback traffic does not traverse the zone host-inbound gate).
const (
	HTTPPort  uint16 = 80
	HTTPSPort uint16 = 443
)

// HTTPPortString and HTTPSPortString are the net.JoinHostPort spellings of the
// canonical ports (net.JoinHostPort takes a string port).
func HTTPPortString() string  { return strconv.Itoa(int(HTTPPort)) }
func HTTPSPortString() string { return strconv.Itoa(int(HTTPSPort)) }
