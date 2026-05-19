# Design Doc: High-Performance WireGuard Support in xpf

## Overview
This document outlines the design for integrating WireGuard support into the `xpf` userspace dataplane (`userspace-dp`). The goal is to provide high-performance, low-latency encryption and decapsulation within the XDP-based userspace pipeline.

## Architectural Goals
1.  **High Throughput**: Achieve multi-gigabit performance by leveraging modern CPU features (SIMD via `boringtun`) and minimizing lock contention.
2.  **Low Latency**: Integrate directly into the `poll_descriptor` RX loop to avoid context switches or cross-thread synchronization for the data path.
3.  **Scalability**: Bind `WireGuardEngine` instances to individual `BindingWorker` threads to ensure linear scaling with the number of RX queues.
4.  **Roaming Support**: Automatically update peer endpoints based on incoming traffic to support mobile/roaming peers.

## Data Path Integration

### RX Path (Decapsulation)
The decapsulation stage is placed early in the pipeline, immediately after initial frame parsing but before session lookup.
1.  **Identification**: Incoming UDP packets on the WireGuard port are passed to the `WireGuardEngine`.
2.  **Decryption**: If the packet is a valid data packet, it is decrypted in-place (or into a scratch buffer) and the inner IP frame is extracted.
3.  **Handshake Handling**: Handshake and control packets are processed by the engine. If a response is generated, it is immediately enqueued for transmission back to the sender.
4.  **Inner Pipeline**: Decrypted frames are reinjected into the pipeline as if they arrived on a logical tunnel interface.

### TX Path (Encapsulation)
Encapsulation occurs in the TX dispatch stage.
1.  **Session Lookup**: The standard session lookup determines that a packet should be routed via a WireGuard tunnel.
2.  **Encap**: The `WireGuardEngine` encrypts the packet and wraps it in a new UDP/IP/Ethernet header.
3.  **Transmission**: The encrypted frame is transmitted via the physical binding.

## Control Plane Integration
The Go control plane (`xpfd`) is responsible for:
1.  **Key Management**: Generating and storing local private keys and peer public keys.
2.  **State Propagation**: Sending `WireGuardInterfaceSnapshot` updates to the Rust workers via the existing protocol.
3.  **Peer Discovery**: Managing static and dynamic peer endpoints.

## Implementation Details
- **Library**: `boringtun` 0.6 (Rust implementation by Cloudflare).
- **Threading**: Shared-nothing architecture. Each worker has its own engine state. Peer roaming updates are localized to the worker thread that received the traffic (consistent with RSS).
- **Metadata**: `UserspaceDpMeta` is updated to carry `wg_public_key` to identify the tunnel context across stages.

## Performance Considerations
- **SIMD**: `boringtun` uses SIMD instructions for ChaCha20-Poly1305.
- **Allocation**: Decapsulation uses pre-allocated scratch buffers per worker to avoid runtime allocations.
- **RSS Consistency**: By ensuring the same 5-tuple flows to the same worker, we maintain WireGuard session consistency without global locks.
