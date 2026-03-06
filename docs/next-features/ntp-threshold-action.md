# Next Feature: `system ntp threshold <seconds> action <accept|reject>`

Date: 2026-03-06
Status: Implemented

## Config Evidence
- Present in `/home/ps/git/bpfrx/vsrx.conf:109` as `threshold 400 action accept;`

## Implemented Behavior
1. `system ntp threshold <seconds> action accept` writes chrony `logchange <seconds>` so large offsets are logged while remaining acceptable.
2. `system ntp threshold <seconds> action reject` writes `logchange <seconds>` and `maxchange <seconds> 1 -1` so large post-startup corrections are rejected.
3. `show ntp` and system summary output display the configured threshold mode.
4. Threshold config is reconciled through a managed chrony drop-in file alongside the existing managed source list.

## Notes
- This maps the Junos operator intent onto chrony primitives rather than re-implementing NTP discipline in bpfrxd.
- The value is treated as seconds, matching Junos documentation and chrony directive units.

## Validation
- Unit tests cover chrony source rendering, threshold rendering for `accept` and `reject`, and managed file reconciliation.
