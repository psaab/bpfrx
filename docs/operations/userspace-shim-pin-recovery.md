# Userspace Shim Pin Recovery

Use this runbook only when `xpfd` refuses to start the userspace shim with an
error like:

```text
refusing to reset incompatible userspace shim map <name> at <pin path>: ...
```

That error is intentionally fail-closed. The daemon found a pinned compatibility
map whose ABI no longer matches the retained userspace XDP shim. Normal startup
will not delete the pin because doing so can drop active state such as sessions
or DNAT reverse mappings.

## Recovery

1. Confirm the node is drained or the cluster peer owns traffic for the affected
   redundancy groups. Removing a stateful pin loses the state in that map.

2. Stop the local daemon so no new FDs are opened against the incompatible pin:

   ```sh
   sudo systemctl stop xpfd
   ```

3. Inspect the pin named in the error:

   ```sh
   sudo bpftool map show pinned /sys/fs/bpf/xpf/<map-name>
   ```

4. Remove only the incompatible pin path from the error. Do not remove
   `/sys/fs/bpf/xpf` as a whole.

   ```sh
   sudo rm -- /sys/fs/bpf/xpf/<map-name>
   ```

5. Start the daemon and verify it recreated the map:

   ```sh
   sudo systemctl start xpfd
   sudo journalctl -u xpfd -b --no-pager | tail -200
   sudo bpftool map show pinned /sys/fs/bpf/xpf/<map-name>
   ```

6. Repeat on the peer only after traffic ownership is safe for that peer.

## Notes

- `sessions`, `sessions_v6`, `dnat_table`, and `dnat_table_v6` are stateful
  compatibility pins. Removing one resets the corresponding dataplane state.
- The loader removes only legacy-only pins automatically:
  `xdp_progs`, `tc_progs`, and `policer_states`.
- A targeted migration tool does not exist yet. Until one exists, manual pin
  removal is an explicit state-reset operation.
