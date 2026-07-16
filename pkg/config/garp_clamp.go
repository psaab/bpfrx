package config

// GratuitousARPBurstClamp is the runtime resource-safety maximum for the
// per-VIP gratuitous ARP (IPv4) / unsolicited NA (IPv6) burst emitted on a
// VRRP or chassis-cluster failover. Any configured gratuitous-arp-count is
// clamped to this value before it drives raw-socket sends.
//
// Rationale for the value (#5695, codex-182 M16 — VRRP/GARP unbounded burst).
// The burst helper (pkg/cluster/garp.go) sends one synchronous frame plus
// (count-1) follow-ups at 50ms intervals, PER VIP, on every failover. A
// neighbor cache is refreshed by the first valid frame; a burst beyond ~16
// frames only adds redundancy for a lossy segment and yields no further cache
// benefit. Junos itself caps gratuitous-arp-count at 16 (schema_chassis.go
// valueDesc; the deployed value here is 8). 32 is 2x that documented Junos
// maximum, so every legitimate configuration (1..16, plus generous
// over-provisioning up to 32) passes through UNCHANGED — the clamp never
// alters a count an operator could plausibly intend — while the per-VIP budget
// is hard-bounded to 32 raw-socket sends and a ~(32-1)*50ms ≈ 1.55s burst
// tail. Without the clamp a pathological count (e.g. 100000) fans
// (100000-1)*50ms ≈ 83 minutes of raw-socket sends per VIP across EVERY VIP —
// a self-inflicted CPU/socket-exhaustion vector on failover.
//
// The clamp lives in the RUNTIME (this constant is consumed by pkg/vrrp
// sendGARP and pkg/daemon directSendGARPs) per the no-schema-only-caps doctrine
// (schema_chassis.go, PR #1845): a sanity cap belongs in the runtime first, not
// as a schema hard-reject of counts the runtime executes fine. The commit path
// only WARNS (validateGratuitousARPCountAST) when a configured count exceeds
// this bound, so a runtime-valid config is never rejected.
const GratuitousARPBurstClamp = 32

// ClampGratuitousARPCount bounds a configured gratuitous ARP / unsolicited NA
// burst count to GratuitousARPBurstClamp. It returns the effective count and
// whether clamping occurred. A count <= 0 is returned unchanged — only the
// upper safety bound is enforced here; callers apply their own >0 default
// (3) for the unset case.
func ClampGratuitousARPCount(count int) (int, bool) {
	if count > GratuitousARPBurstClamp {
		return GratuitousARPBurstClamp, true
	}
	return count, false
}
