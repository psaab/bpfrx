# #2153 DHCP relay must relay DHCPINFORM — reviewer record

PR: #2164
Branch: `refactor/2153-dhcp-relay-inform`
Base: `origin/master`

## Fix summary

The relay client→server forwarding gate (`runRelay`,
`pkg/dhcprelay/relay.go`) relayed only DISCOVER/REQUEST and `continue`d
on everything else, silently dropping DHCPINFORM (RFC 2131 §3.4). The
gate was extracted into a pure `clientRequestRelayable` predicate and
`MessageTypeInform` added to the relayable set.

The server→client reply path needed no change: an INFORM is answered with
an ACK (already permitted by `handleServerResponses`), and the #2076
reply matrix already routes an ACK with `yiaddr==0` + real `ciaddr` via
the `ciaddrReal` UDP-unicast case (`deliverReply`). Existing coverage:
`TestDeliverReply_Matrix/flag0_no_yiaddr_ciaddr_unicast`.

## Reviewer verdicts

| Reviewer | Round | Verdict | Notes |
|----------|-------|---------|-------|
| Copilot | 1 | inline comment | README NAK row inaccurate — fixed `da4788ec7` + replied |
| Codex (codex-rescue) | 1 | MERGE-NEEDS-MAJOR | hop-count wrap BUG, README NAK lie, DECLINE comment wrong; 3 pre-existing concerns |
| Codex (codex-rescue) | 2 | MERGE-NEEDS-MINOR | all round-1 BUGs resolved; concerns confirmed pre-existing; 1 minor: DECLINE README row |
| Claude SMR | 1 | MERGE-READY | gate == old expr + INFORM; reply path already covers INFORM-ACK; tests non-tautological |
| AGY | — | not dispatched | flagged for parent (the agy adversarial-review tool diffs the active workspace and must not touch the live main checkout per repo-hygiene rules) |

## Review-driven changes

- `da4788ec7` — README reply-type row: state `handleServerResponses`
  forwards OFFER/ACK only (Copilot).
- `a4add25ac` — hop-count: enforce RFC 1542 §4.1.1 limit BEFORE the
  `uint8` increment (drop on `HopCount >= 16`); an incoming 255 wrapped
  to 0 past the old post-increment `> 16` test. New non-tautological
  `TestRunRelay_HopCountLimit`. DECLINE comment corrected (DECLINE is
  broadcast per RFC 2131 §4.4). (Codex round 1)
- `0d9727283` — README DECLINE table row corrected to match the comment
  (Codex round 2).

## Out of scope (noted follow-ups, NOT fixed here — both pre-date #2153)

- NAK is silently dropped by `handleServerResponses` (separate from the
  INFORM client→server gate; an INFORM is normally answered with ACK).
- giaddr is overwritten even when already nonzero (second-hop relay,
  RFC 1542/3046) — affects DISCOVER/REQUEST identically.

## Validation

- `go test -race ./pkg/dhcprelay/` — green
- All 3 new tests (`TestClientRequestRelayable`, `TestRunRelay_RelaysInform`,
  `TestRunRelay_HopCountLimit`) proven to FAIL against the pre-fix forms
  (non-tautological).
- 5/5 flake check on the runRelay tests (`-race`).
- `go vet ./pkg/dhcprelay/` clean.
- Control-plane relay change; no loss-cluster smoke required (live flag0
  capture lab-gated per #2115).
