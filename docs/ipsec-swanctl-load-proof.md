# Proving the generated strongSwan config actually LOADS

This is the procedure #7165 item 2 asked for, plus the two dead ends that look
like it works and do not.

## Why a text assertion is not a proof

Every renderer test in `pkg/ipsec` asserts on the emitted **text**. A text
assertion cannot know which keys strongSwan accepts — it will happily confirm
that a line strongSwan *rejects* was emitted exactly as intended.

That gap was not hypothetical. The first run of this procedure found that
`start_action` was emitted at **connection** level as well as child level, and
strongSwan answers:

```
loading connection 'vpn-a' failed: unknown option: start_action, config discarded
loaded 0 of 1 connections, 1 failed to load, 0 unloaded
```

`config discarded` is the **whole connection**. Every VPN with
`establish-tunnels immediately` generated a config strongSwan refused in its
entirety — IPsec did not come up at all — and the full Go suite was green
throughout. Fixed in #7165; pinned structurally by
`start_action_placement_7165_test.go`.

## Two instruments that DO NOT work

Both return the same answer for a valid and a malformed config, so both
"confirm" whatever you expected.

**1. `swanctl --load-conns --file <path> --uri <bogus>`.** swanctl fails on the
vici connection *before* parsing, so a good config and a deliberately truncated
one produce byte-identical output. Verified with a control; without one this
reads as a clean parse.

**2. Any path under `/tmp`.** The strongSwan unit runs with `PrivateTmp`, so
swanctl cannot see the host's `/tmp` and reports `failed to open config file`
for a file that demonstrably exists — again identically for good and bad input.

## The procedure that works

Requires a node with strongSwan installed and `charon` running. The loss
userspace cluster nodes qualify (`/usr/sbin/swanctl`, strongSwan 6.0.5);
a developer workstation generally does not, which is what made this look
environmentally blocked. Take the #1875 cluster lock first — this loads
into the live daemon.

```bash
N=loss:xpf-userspace-fw0
D=/etc/swanctl/conf.d

# 0. Record the starting state. conf.d is normally EMPTY on a cluster node.
incus exec $N -- bash -c "ls $D; swanctl --list-conns"

# 1. NEGATIVE CONTROL FIRST. A malformed config must be REJECTED, or the
#    positive result below means nothing.
incus exec $N -- bash -c "printf 'connections {\n  broken {\n' > $D/zz-proof.conf && swanctl --load-conns"
#    Expect: syntax error, unexpected end of file

# 2. The generated config.
incus file push ./rendered.conf ${N}${D}/zz-proof.conf
incus exec $N -- swanctl --load-conns
#    Expect: loaded connection '<name>' / successfully loaded N connections

# 3. Verify it is really there, not merely accepted.
incus exec $N -- swanctl --list-conns

# 4. RESTORE. Always — the cluster is shared.
incus exec $N -- bash -c "rm -f $D/zz-proof.conf && swanctl --load-conns"
incus exec $N -- bash -c "swanctl --list-conns; ls $D"
```

Generate `rendered.conf` by calling `Manager.renderConfig` from a throwaway test
with a representative `config.IPsecConfig`.

## Reading the result

- `loaded 0 of 1 connections, 1 failed to load` — a **failure**, even though the
  command exits 0. Read the line, not the exit code.
- A config that renders to `connections {\n}` is **empty** and proves nothing.
  Check the byte count and that a connection name appears before trusting a
  pass; a skipped VPN (unresolved IKE chain, unrenderable gateway) produces
  exactly that and loads cleanly.
- Step 1 failing to be rejected means the instrument is broken, not that the
  config is good.

## Restore, always

The cluster is shared and `conf.d` is normally empty. Leaving a proof config
behind changes what the next holder of the lock is testing — the same class of
contamination as leaving a CoS fixture applied.
