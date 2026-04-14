# Standalone VM Tests

## Overview

Standalone VM tests validate basic forwarding, NAT, policy, screens, and routing on a single firewall instance (no HA clustering).

## Setup

```bash
make test-vm           # Create VM (one-time)
make test-deploy       # Build + push + restart
make test-ssh          # Shell into VM
make test-status       # Check status
make test-logs         # View recent logs
```

## Test 1: Basic Forwarding

**What it tests**: IPv4 and IPv6 transit between zones.

```bash
# trust → untrust
incus exec trust-host -- ping -c 3 10.0.2.102    # untrust-host
incus exec trust-host -- ping6 -c 3 2001:559:8585:bf02::102

# trust → dmz
incus exec trust-host -- ping -c 3 10.0.30.101   # dmz-host

# untrust → trust (should be denied by default policy)
incus exec untrust-host -- ping -c 1 -W 1 10.0.1.102  # expect: 100% loss
```

## Test 2: SNAT (Interface Mode)

**What it tests**: Source NAT rewrites outbound source IP to the egress interface address.

```bash
# From trust-host, access untrust via SNAT
incus exec trust-host -- curl -s --max-time 5 http://10.0.2.102:80

# Verify SNAT'd source on the firewall:
echo "show security flow session" | cli
# Should show: In: 10.0.1.102 -> 10.0.2.102 / Out: with SNAT'd source
```

## Test 3: DNAT

**What it tests**: Destination NAT rewrites inbound destination to internal server.

```bash
# Verify DNAT rules in config
echo "show security nat destination" | cli
```

## Test 4: Security Policies

**What it tests**: Zone-based policy permit/deny decisions.

```bash
# Verify policy configuration
echo "show security policies" | cli

# Test deny (untrust → trust should be blocked by default-deny)
incus exec untrust-host -- ping -c 1 -W 1 10.0.1.102  # expect: timeout

# Test permit (trust → untrust should be allowed)
incus exec trust-host -- ping -c 1 -W 1 10.0.2.102    # expect: success
```

## Test 5: Host-Inbound Traffic

**What it tests**: Traffic to the firewall's own addresses is filtered by host-inbound-traffic rules.

```bash
# SSH should work on mgmt zone
incus exec trust-host -- ssh -o ConnectTimeout=2 root@10.0.1.10 exit 2>/dev/null
# Ping should work on trust zone (host-inbound-traffic system-services ping)
incus exec trust-host -- ping -c 1 -W 1 10.0.1.10

# SSH should fail on untrust zone (not in host-inbound-traffic)
incus exec untrust-host -- ssh -o ConnectTimeout=1 root@10.0.2.10 exit 2>/dev/null
# expect: timeout
```

## Test 6: Screen/IDS

**What it tests**: Stateless packet screening (land attack, SYN flood, etc.).

```bash
# Verify screens configured
echo "show security screen" | cli

# Test land attack (src=dst) — should be dropped
# (requires crafted packet tools like hping3/scapy)
```

## Test 7: Routing (FRR)

**What it tests**: Static routes, default route, VRF, route redistribution.

```bash
# Verify routes in kernel
incus exec xpf-fw -- ip route show
incus exec xpf-fw -- ip -6 route show

# Verify FRR status
incus exec xpf-fw -- vtysh -c "show ip route"
incus exec xpf-fw -- vtysh -c "show bgp summary"
```

## Test 8: VLAN Tagging

**What it tests**: 802.1Q VLAN trunk handling in BPF.

```bash
# If WAN interface has VLAN subs (ge-0-0-3.50)
# Verify traffic flows through VLAN-tagged path
incus exec trust-host -- ping -c 1 -W 1 <wan-target>
```

## Test 9: CLI

**What it tests**: Junos-style CLI commands, tab completion, pipe filters.

```bash
echo "show interfaces terse" | cli
echo "show security flow session" | cli
echo "show system uptime" | cli
echo "show route" | cli
echo "show security policies | match trust" | cli
```

## Test 10: Config Management

**What it tests**: Commit, rollback, compare.

```bash
# Modify config
echo -e "edit security zones\nset security-zone test\ncommit" | cli
# Rollback
echo "rollback 1" | cli
echo "commit" | cli
```

## Connectivity Test Script

```bash
./test/incus/test-connectivity.sh
```

Runs automated connectivity checks across all zones.
