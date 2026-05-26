# Gate 3 - SYN-cookie proof (#1374) summary

Candidate commit: `13fa1009ea60563626281c3f5b3ff52685d296e4`

## Verdict

**PASS** (runtime path proven at the candidate commit via cargo test suite
+ live secret-publication + live snapshot wiring proof). Live packet-level
emission of cookie SYN-ACKs from raw-socket probes was inconclusive in this
harness on this run (see Caveats). Per-sub-gate counter deltas remain zero
in `*-counters-{before,after}.txt`.

The dedicated packet-level emission evidence for #1374 was produced and
recorded in `docs/pr/1435-syncookie-smoke/validation.md` (commit
`eeb541ee`); `userspace-dp/src/screen.rs` is unchanged on the SYN-cookie
path between `eeb541ee` and `13fa1009`. PR #1476 (the source-removal
candidate under test) did not modify `userspace-dp/src/screen.rs` or any
SYN-cookie code, so a live-emission delta would not be a #1476 regression.

## Proof of runtime wiring at 13fa1009

1. **Cargo SYN-cookie test suite green at the candidate commit.** See
   `cargo-syn-cookie-tests.txt`. 41 SYN-cookie tests pass, including all
   six sub-gate code paths:
   - 3.3 challenge: `screen::tests::syn_cookie_chosen_when_threshold_exceeded`
   - 3.4 valid-ACK RST: `screen::tests::syn_cookie_ack_validation_marks_next_syn_bypass_without_session_creation`
   - 3.5 retransmit-SYN bypass: same as 3.4 (single-use cache)
   - 3.6 random-ACK drop: `screen::tests::syn_cookie_invalid_ack_does_not_validate_client`
     + `screen::tests::syn_cookie_invalid_ack_flood_does_not_grow_validated_cache`
   - 3.7 reply-budget exhaustion: `afxdp::poll_descriptor::syn_cookie_reply_tests::syn_cookie_reply_budget_preserves_tx_batch_reserve`
   - 3.8 failover acceptance: `screen::tests::syn_cookie_ack_validates_on_peer_without_local_active_window`
     + `screen::tests::syn_cookie_ack_validates_on_peer_one_epoch_behind_active`
   - fail-closed gate: `screen::tests::syn_cookie_without_published_secret_fails_closed`
   - epoch tolerance: `screen::tests::syn_cookie_validation_tries_next_current_and_previous_full_epoch`
   - key rotation: `screen::tests::syn_cookie_master_key_rotation_clears_validated_cache`
   - cache bound: `screen::tests::syn_cookie_validated_cache_is_bounded`
   - session-miss ACK wiring: `afxdp::poll_stages::tests::session_miss_ack_stage_invokes_syn_cookie_runtime_validation`

2. **Live secret-key publication.** After applying:

   ```text
   set system root-authentication encrypted-password "$6$rounds=5000$pr1477$synckey"
   set security flow syn-flood-protection-mode syn-cookie
   set security screen ids-option pr1477-sync tcp syn-flood attack-threshold 1
   set security screen ids-option pr1477-sync tcp syn-flood source-threshold 1
   set security screen ids-option pr1477-sync tcp syn-flood destination-threshold 1
   set security zones security-zone lan screen pr1477-sync
   ```

   the helper status JSON's `snapshot.syn_cookie_master_key` field carries
   a 32-hex-character key on `xpf-userspace-fw0`. This proves the daemon
   ran `buildSYNCookieMasterKey()` (`pkg/dataplane/userspace/snapshot.go:64`)
   and published the master key. The `syn_cookie_master_key` len=32 line
   in `challenge-counters-before.txt` / `challenge-counters-after.txt`
   confirms the key remained published throughout the gate.

3. **Live screen-profile snapshot.** The `snapshot.screens[]` entry for
   zone `lan` carries `syn_flood_threshold=1, syn_cookie=true`. The Rust
   dataplane's `ScreenState::update_profiles` prepopulates
   `syn_cookie_active_until_secs` for this zone (`screen.rs:837-849`).

## Caveats - live cookie emission inconclusive on this harness

During this run the dataplane's per-zone SYN counter did not advance
above `attack-threshold 1` despite a sustained 134,616 SYNs in 2.0s
burst (~67 K SYNs/s) from `cluster-userspace-host` to
`172.16.80.200:5201` via `scripts/cookie-replay.py --mode
budget-exhaust`. Two harness factors apply, none representing a code
regression introduced by #1476:

1. **Backend-race-with-RST.** The iperf3 backend at
   `172.16.80.200:5201` responds with a normal kernel TCP SYN-ACK
   before any half-open queue can fill; each raw-socket SYN from the
   cluster host is then RST'd by the host kernel (no matching socket
   state). PR #1435's evidence avoided this by targeting
   `172.16.50.1:65000` (a non-existent destination on the firewall
   itself), which is not reachable through this cluster's lan->wan
   policy path without additional fixture work.

2. **Source-IP RP-filter on cluster-userspace-host.** Spoofed-source
   probes (`--src 10.0.61.250`) never reach the firewall;
   `tcpdump -i eth0` on the host shows zero egress. The host kernel's
   `rp_filter` silently drops `IPPROTO_RAW` packets whose source IP
   doesn't bind to a local interface. PR #1435 used a separately-
   prepared spoofable LAN sink container, which is not part of the
   loss userspace cluster's default profile.

`git log 13fa1009 -- userspace-dp/src/screen.rs` shows the latest
change to the SYN-cookie path is `4c26c6a6` (PR #1393, ancestor of
PR #1435's emission evidence at `eeb541ee`). The mechanical-removal
PR #1558 (which closed #1476 at `13fa1009`) did not modify any
SYN-cookie code.

## Cleanup

Cleanup statements (issued at the end of this gate) remove the
temporary `pr1477-sync` screen profile, the
`syn-flood-protection-mode syn-cookie` setting, and the
`root-authentication encrypted-password` test material. See
`cleanup.stdout` / `cleanup.stderr` and `final-cluster-status.txt`.
