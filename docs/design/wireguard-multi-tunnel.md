# Design Doc: Multi-Tunnel WireGuard Support in Userspace Dataplane

## Overview
This document outlines the design and implementation for supporting multiple WireGuard tunnels in the `userspace-dp` (Rust) and `xpf` control plane (Go). This is a critical requirement for multi-site VPN and service provider edge

## Configuration Model

We support a simplified **Global Identity** model where a single private key and listening port can be shared across multiple interfaces.

### Global Identity
```bash
set security wireguard private-key <key>
set security wireguard listen-port 51820
```

### Interface Configuration
Interfaces inherit the global identity but define their own peers.
```bash
set interfaces wg0 wireguard peer <pubkey> allowed-ips 3fff:1::/48
```

Per-interface overrides are still supported if a different identity is required for specific tunnels.
tance. This prevented the configuration of multiple WireGuard interfaces (e.g., `wg0`, `wg1`) each having its own:
- Private/Public key pair
- UDP listening port
- Set of peers and allowed IPs

## Architecture

### Control Plane (Go)
The control plane now treats WireGuard as a first-class interface property. 
- `InterfaceSnapshot` includes an optional `WireGuard` pointer containing the interface's specific private key and listening port.
- `TunnelEndpointSnapshot` (used for encapsulation) now includes a `WgListenPort` field to identify which local WireGuard engine should perform the encapsulation for a specific peer.
- The `show security wireguard public-key` command derives the public key from the configured private key on a per-interface basis.

### Data Plane (Rust)
The `BindingWorker` (representing a per-interface worker thread) has been refactored to support multiple `WireGuardEngine` instances.
- Engines are stored in a `FxHashMap<u16, WireGuardEngine>` indexed by the UDP listening port.
- The `WorkerCommand::UpdateWireGuard` now carries a map of updates (`FxHashMap<String, WireGuardInterfaceSnapshot>`) to synchronize multiple interfaces across all workers.

#### RX Path (Decapsulation)
Incoming UDP packets are parsed to extract the destination port. The worker uses this port to look up the corresponding `WireGuardEngine` in its map. If a match is found, the packet is passed to that engine for decapsulation.

#### TX Path (Encapsulation)
When a packet is routed to a WireGuard tunnel endpoint, the `tx::dispatch` logic looks up the `TunnelEndpointSnapshot`. It uses the `wg_listen_port` from the snapshot to find the correct `WireGuardEngine` and performs encapsulation using that engine's local identity and the peer's public key.

## Key Management
Users can generate keys using the operational command:
`request security wireguard generate-private-key`

This command generates a new X25519 key pair and displays both the private and public keys. The private key can then be configured on an interface:
```
set interfaces wg0 wireguard private-key <key>
set interfaces wg0 wireguard listen-port 51820
```

## Security Considerations
- **Isolation**: Each engine maintains its own session keys and replay protections.
- **Port Sharding**: Multiple tunnels can share the same interface if they use different listening ports, although typically each `wgN` interface maps to one port.
- **Performance**: Sharding engines across workers maintains the lock-free nature of the dataplane fast path.

## Verification
- `show security wireguard public-key [interface]` verifies that the control plane correctly derives keys from the configuration.
- Functional tests verify that packets arriving on different ports are correctly handled by the independent engines.
