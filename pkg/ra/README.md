# pkg/ra

Embedded IPv6 Router Advertisement sender. Replaces external `radvd`
with per-interface goroutines built on `mdlayher/ndp`. Handles startup
burst, goodbye RAs, and re-burst recovery after RETH MAC link-cycle.

## Entry points

- `Manager` — `ra.go`.
- `New()` — `ra.go`.
- `Apply(configs []*config.RAInterfaceConfig) error` — `ra.go`.
  Starts/stops per-interface senders.
- `Withdraw() error` — `ra.go`. Stops every sender.
- `ResendBurst()` — `ra.go`. Re-sends the startup burst (used after a
  link cycle) on every active sender.
- `WithdrawInterfaces(names []string)` — `ra.go`. Stops senders by
  interface name.
- `WithdrawOnce(configs []*config.RAInterfaceConfig)` — `ra.go`.
  Sends a single goodbye RA (lifetime=0) on each listed interface.
- `Status()` — `ra.go`. Per-interface SenderInfo.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Link DOWN→UP during a RETH MAC cycle kills the AF_PACKET socket.
  `ResendBurst()` is what closes that gap — without it, hosts see an RA
  outage from the moment of the link cycle until the next periodic RA.
- The goodbye RA carries router lifetime 0, telling hosts to drop this
  router as default gateway. Send one when explicitly withdrawing a zone
  or shutting down.
- IPv6 NODAD is set on the per-instance NDP socket so it doesn't fight
  the kernel's own duplicate-address detection on the link-local
  address.
- `ensureLinkLocal` (`sender.go`) guarantees a link-local exists for the
  NDP socket. RETH members run with `addr_gen_mode=1` (set by the daemon's
  `setRethIPv6Knobs`) to suppress kernel EUI-64 auto-generation and its
  MLDv2 noise, so a member may have no link-local when the sender starts.
  When one is missing the sender adds the EUI-64 `fe80::/64` directly via
  `netlink.AddrAdd` with `IFA_F_NODAD` — the same primitive the daemon uses
  in `ensureRethLinkLocal` / `addStableLLToInterface`. It does **not** mutate
  `addr_gen_mode` and does **not** cycle the link (#2034): `addr_gen_mode=1`
  is a contract the apply path sets deliberately, and an out-of-band link
  DOWN/UP from inside the RA manager would un-reconcile VIPs / stable LLAs
  and race the AF_XDP dataplane rebind. An interface with no usable 6-byte
  MAC degrades to a soft-logged warning (the caller only `slog.Warn`s the
  error); the explicit `source-link-local` config and the `start()` retry
  loop are the recovery path.
- Per RFC 5798, `AdvertiseInterval` is stored in milliseconds but goes
  on the wire in centiseconds. Don't double-convert.
