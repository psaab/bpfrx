# Next Feature: `monitor` Operational Commands

Date: 2026-03-01  
Status: Implemented (`docs/phases.md` Sprint: Monitor Commands, PR #67)

## Why this doc exists
This document captures Junos monitor behavior observed on `claude@172.16.100.1` (JUNOS 24.4R1-S2.9) and serves as the behavior reference for bpfrx monitor command parity.

## Command discovery (live)
Top-level `monitor` subtree:

```text
monitor ?
  interface
  label-switched-path
  list
  security
  start
  static-lsp
  stop
```

Security subtree:

```text
monitor security ?
  flow
  packet-drop
```

## `monitor security flow`
`monitor security flow` is stateful and uses a 3-step workflow:

1. Configure trace file
2. Configure one or more filters
3. Start monitoring

### Syntax discovered
```text
monitor security flow ?
  file
  filter
  start
  stop
```

#### File configuration
```text
monitor security flow file ?
  <filename>
  files                (2..1000)
  match                (regex)
  no-world-readable
  size                 (10240..1073741824)
  world-readable
```

Observed behavior:
- `monitor security flow start` fails if file is not configured:
  - `error: Please specify the monitor flow trace file.`
- The configured file resolves to `/var/log/<filename>` in status output.

#### Filter configuration
```text
monitor security flow filter ?
  <filter-name>
  conn-tag
  destination-port
  destination-prefix
  destination-service
  geneve-vni
  interface
  logical-system
  protocol
  root-logical-system
  source-port
  source-prefix
  source-tenant
  tenant
  tunnel-inspection-type
  vxlan-vni
```

Observed behavior:
- `monitor security flow start` fails if no filter exists:
  - `error: Please specify monitor security flow filter.`
- Filter with no criteria is accepted (`monitor security flow filter <name>`).
- Protocol accepts numeric `0..255` and named values (`tcp`, `udp`, `icmp`, `icmp6`, `esp`, etc.).

#### Start / Stop
```text
monitor security flow start
monitor security flow stop
```

Observed behavior:
- `start` is silent on success.
- `stop` is silent on success.
- Filter objects persist across stop/start.

### Status view (for validation)
Although implementation target is `monitor ...`, Junos status is reported by:

```text
show monitor security flow
```

Observed output fields:
- `Monitor security flow session status: Active|Inactive`
- `Monitor security flow trace file: /var/log/<name>`
- `Monitor security flow filters: <N>`
- Per-filter block:
  - `Name`
  - `Status: Active|Inactive`
  - `Source` (prefix + port range)
  - `Destination` (prefix + port range)
  - `Logical system`
  - `Interface`

## `monitor security packet-drop`
This command is immediate/streaming (not a separate start/stop state machine).

### Syntax discovered
```text
monitor security packet-drop ?
  all-logical-systems-tenants
  count                (default 50) (1..8192)
  destination-port
  destination-prefix
  explicit-proxy-profile
  from-zone
  interface
  logical-system
  node                 (0..1 | all | local | primary)
  protocol
  root-logical-system
  source-port
  source-prefix
  tenant
```

### Runtime behavior observed
- Without `count`, command streams packet-drop records and can page output.
- With `count N`, command prints exactly `N` matching entries and returns to prompt.
- Output starts with:
  - `Starting packet drop:`
- Sample line format:

```text
07:43:11.684547:LSYS-ID-00 172.16.103.254/5353-->224.0.0.251/5353;udp,ipid-11343,reth1.100,Dropped by FLOW:First path Self but not interested
```

Fields present in each line:
- timestamp
- logical-system identifier
- source ip/port
- destination ip/port
- protocol
- packet metadata (for example `ipid-*`, ingress interface)
- drop reason text

## Other `monitor` commands to support later
- `monitor start <filename>` / `monitor stop [filename]`
- `monitor list`
- `monitor interface ...`
- `monitor label-switched-path ...`
- `monitor static-lsp ...`

For now, security monitor commands are highest value for firewall operations.

## Implementation summary in bpfrx

### CLI grammar (operational mode)
Implement these first:

1. `monitor security flow file ...`
2. `monitor security flow filter ...`
3. `monitor security flow start`
4. `monitor security flow stop`
5. `monitor security packet-drop [filters] [count N] [node ...]`

### Data model
Add daemon-side monitor state:
- flow trace config (`filename`, `size`, `files`, `match`, visibility flags)
- flow filters map by name
- flow active bool
- packet-drop monitor request model (inline command execution, no persistent active state required)

### Output compatibility targets
Match Junos user-facing behavior:
- explicit precondition errors for missing flow file/filter on `start`
- silent success for `start`/`stop`
- packet-drop line format close to Junos ordering
- count-limited packet-drop runs that terminate cleanly

### Datapath/event source mapping in bpfrx
- `monitor security packet-drop` should consume policy/screen/drop events from the existing event pipeline and format them as packet-drop records.
- `monitor security flow` should stream flow/session events into configured trace output with filter evaluation before write.

## Open follow-up questions
1. Should bpfrx write `flow` trace data to filesystem like Junos (`/var/log/<file>`) or keep initial implementation in-memory/CLI only?
2. Do we need multi-node output prefixes (`node0/node1`) in standalone mode, or only when cluster mode is enabled?
3. How strict should compatibility be for named port aliases in CLI parsing (`domain`, `https`, etc.) in the first iteration?
