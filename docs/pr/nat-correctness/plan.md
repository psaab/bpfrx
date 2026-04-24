# PR E: NAT correctness (#858 #859 #861 #862)

Four NAT bugs from mythos.md security audit.

## #858 — NAT CPU stride + NAT64 return-ignored
Allocators mask CPU to 4 bits (`& 0xF`) → cores 0 and 16 collide on
>16-core hosts. NAT64 additionally ignores `bpf_map_update_elem`
return on `nat64_state` insert → cross-tenant v6 delivery on collision.

**Fix**: widen mask to `& 0x7F` (128 CPU stride). Check return of
`nat64_state` insert in `nat64_xlate_6to4`; drop + counter bump on
conflict. With 128-core stride collisions are rare enough that
drops are acceptable without a reservation retry loop (filed
separately as a future polish if needed).

## #859 — IPv6 syncookie validated_client_key truncated
`struct validated_client_key` used `__be32 src_ip` so v6 addresses
were truncated to the first 4 bytes (global routing prefix). One
handshake whitelisted a /32.

**Fix**: widen `src_ip`/`dst_ip` to `__u8[16]`. v4 zero-extends
into the low 4 bytes; v6 stores full 16-byte address. Update all
3 call sites in `xdp_screen.c`.

## #861 — IPv6 SESSION_OPEN logs post-NAT addrs as "original"
`xdp_policy.c:1545` stashed pre-NAT src/dst into
`session_v6_scratch[1]`. `create_session_v6` uses same slot as
`rev_val` and overwrites. `emit_event_nat6_orig` read back
post-NAT addresses.

**Fix**: bump `session_v6_scratch` max_entries from 2 to 3. Move
orig stash to slot 2 (dedicated). `create_session_v6` still uses
slot 1 for rev_val.

## #862 — NAT64 ICMP csum loop limited to 128 bytes
3 sites used `#pragma unroll for (i<64)` = 64 × 2 = 128 bytes max.
Larger ICMP payloads got bad L4 checksum.

**Fix**: replace with `#pragma unroll 1 for (i<750)` mirroring
`finalize_csum_partial` pattern. Applied to `nat64_xlate_6to4`,
`nat64_xlate_4to6`, `nat64_icmp_error_4to6`.
