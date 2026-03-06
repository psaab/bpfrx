# vSRX Monitor Commands — Research Notes

Source: SSH to vsrx-bert (172.16.100.1), 2026-03-02

## Top-Level Monitor Commands
```
monitor interface            Show interface traffic
monitor label-switched-path  Show label-switched-path traffic (MPLS, skip)
monitor list                 Show status of monitored files
monitor security             Monitor security information
monitor start                Start showing log file in real time
monitor stop                 Stop showing log file in real time
monitor static-lsp           Show static label-switched-path traffic (MPLS, skip)
monitor traffic              Packet capture (disabled on vSRX)
```

## 1. `monitor interface <name>` — Single Interface

### Header Format
```
<hostname>                         Seconds: N          Time: HH:MM:SS
                                                       Delay: cur/avg/max
```

### RETH / Loopback Interface
```
Interface: reth0, Enabled, Link is Up
Encapsulation: Ethernet, Speed: 1000mbps
Traffic statistics:                                          Current delta
  Input bytes:                 831899245355 (17295576 bps)   [4338479]
  Output bytes:               1471787490490 (107670272 bps)  [21150007]
  Input packets:                  682417205 (3054 pps)       [6708]
  Output packets:                1070845052 (9690 pps)       [16021]
Error statistics:
  Input errors:                           0                  [0]
  Input drops:                            0                  [0]
  Input framing errors:                   0                  [0]
  Carrier transitions:                    1                  [0]
  Output errors:                          0                  [0]
  Output drops:                           0                  [0]
```

Error fields (RETH/lo): Input errors, Input drops, Input framing errors,
Carrier transitions, Output errors, Output drops (6 fields)

### Physical Interface (ge-/xe-/et-)
Same Traffic statistics, but MORE Error fields:
- Input errors, Input drops, Input framing errors
- Policed discards, L3 incompletes, L2 channel errors, L2 mismatch timeouts
- Carrier transitions
- Output errors, Output drops, Aged packets

Also adds:
- Active alarms / Active defects
- Input MAC/Filter statistics (Unicast/Broadcast/Multicast/Oversized/Reject/DA/SA)
- Output MAC/Filter Statistics (Unicast/Broadcast/Multicast/Pad/Error)

### Sub-Interface (reth1.100, ge-0/0/0.0)
Completely different layout:
```
Interface: reth1.100, Enabled, Link is Up
Flags: SNMP-Traps 0x4000
Encapsulation: ENET2
VLAN-Tag [ 0x8100.100 ]
Local statistics:                                            Current delta
  Input bytes:                    38813899                   [0]
  Output bytes:                   41545287                   [0]
  Input packets:                    269971                   [0]
  Output packets:                   211247                   [0]
Remote statistics:
  Input bytes:              55703618516 (607552 bps)         [550629]
  Output bytes:            447625036615 (4660016 bps)        [228324]
  Input packets:               85126002 (533 pps)           [1205]
  Output packets:             311017098 (558 pps)            [544]
IPv6 statistics:
  Input bytes:                          0                    [0]
  Output bytes:                         0                    [0]
  Input packets:                        0                    [0]
  Output packets:                       0                    [0]
```

No Error statistics section for sub-interfaces.

### Keyboard Controls (single interface)
```
Next='n'       Switch to next interface
Quit='q'/ESC   Exit monitor
Freeze='f'     Freeze display (pause refresh)
Thaw='t'       Resume after freeze
Clear='c'      Clear/reset counters
Interface='i'  Switch to specific interface (prompts)
```

### Refresh Behavior
- Full-screen alternate buffer (\e[?1049h)
- ~1 second refresh interval
- "Current delta" = change since last refresh
- Delay: cur/avg/max processing delay

## 2. `monitor interface traffic` — All-Interfaces Summary

```
<hostname>                         Seconds: N          Time: HH:MM:SS
Interface    Link  Input packets        (pps)     Output packets        (pps)
 ge-0/0/0      Up              1          (0)                  0          (0)
 ge-7/0/0      Up      682559938       (4524)       1071237914      (12823)
```

- Shows PHYSICAL interfaces only (no reth, no sub-ifaces, no lo0)
- Default: packet counts + pps
- Toggleable: bytes, packets, delta, rate

### Keyboard Controls (traffic summary)
```
Bytes='b'      Switch to bytes
Clear='c'      Clear counters
Delta='d'      Show delta
Packets='p'    Switch to packets (default)
Quit='q'/ESC   Exit
Rate='r'       Show rate (pps/bps)
Up=^U          Scroll up
Down=^D        Scroll down
```

## 3. `monitor security packet-drop`

Streaming (not full-screen). Shows dropped packets with reason:
```
19:49:40.509943:LSYS-ID-00 172.16.15.245/5353-->224.0.0.251/5353;udp,ipid-61567,reth1.1,Dropped by FLOW:First path Self but not interested
```

Format: `TIMESTAMP:LSYS SRC/PORT-->DST/PORT;PROTO,ipid-N,IFACE,Dropped by REASON:DETAIL`

Filter options: destination-port, destination-prefix, from-zone, interface,
protocol, source-port, source-prefix, count (default 50)

## 4. `monitor security flow`

Flow debug tracing with filters:
- file (filename, files count, match regex, size)
- filter (conn-tag, destination-port/prefix, interface, protocol, source-port/prefix)
- start / stop

## 5. `monitor start/stop/list` — Log File Tailing

- `monitor start <filename>` — tail -f a log file
- `monitor stop <filename>` — stop
- `monitor list` — show monitored files

## Implementation Priority

### P1: Most Useful
1. `monitor interface <name>` — full-screen single interface
2. `monitor interface traffic` — all-interfaces summary table

### P2: Useful
3. `monitor security packet-drop` — streaming drop log with filters

### P3: Nice to Have
4. `monitor security flow` — flow debug tracing
5. `monitor start/stop/list` — log tailing
