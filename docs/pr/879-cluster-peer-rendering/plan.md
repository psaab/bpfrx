# PR: #879 show chassis forwarding — per-node (node0:/node1:) cluster rendering

## Goal

Eliminate the `Note: peer-node rendering deferred to #879` placeholder
in `show chassis forwarding` cluster-mode output. Render full
forwarding-status blocks for both nodes with `node0:` / `node1:`
headers, matching the existing `show chassis cluster` shape.

## Context

This PR removes the limitation that turned the #883 investigation into
a 30-minute detour: with cluster-wide rendering, the operator would
have immediately seen `node0: workers 5%` and `node1: workers 96%`
instead of querying each node separately and discovering the active
forwarder by accident.

## Approach

Reuse the existing peer-RPC infrastructure — `s.dialPeer()` in
`pkg/grpcapi/server_diag.go:462` already opens a gRPC connection to
the cluster peer over the fabric link (handles dual-fabric, VRF
binding). Call `ShowText` with topic `chassis-forwarding` on the peer
client, get back its formatted output, and stitch the two blocks
together.

### gRPC handler change

In `pkg/grpcapi/server_show.go`, the `chassis-forwarding` case
currently does:

```go
case "chassis-forwarding":
    var snap fwdstatus.SamplerSnapshot
    if s.fwdSampler != nil { snap = s.fwdSampler.Snapshot() }
    fs, err := fwdstatus.Build(s.dp, fwdstatus.OSProcReader{}, s.startTime,
        s.cluster != nil, snap)
    if err != nil { return nil, status.Errorf(...) }
    buf.WriteString(fwdstatus.Format(fs))
```

Replace the `s.cluster != nil` clusterMode boolean (which currently
just triggers the deferred-peer note) with actual peer rendering:

```go
case "chassis-forwarding":
    localBuf, err := s.buildLocalForwarding()  // existing logic
    if err != nil { return ... }
    if s.cluster == nil {
        buf.WriteString(localBuf)
        break
    }
    // Cluster mode — render BOTH node blocks.
    localNodeID := s.cluster.NodeID()
    peerNodeID := s.peerNodeIDForRender()  // detects from existing peer state, not blindly `1 - local`
    fmt.Fprintf(&buf, "node%d:\n%s\n%s",
        localNodeID, separator(), localBuf)
    peerBuf, peerErr := s.dialAndShowForwarding(ctx)
    fmt.Fprintf(&buf, "\nnode%d:\n%s\n", peerNodeID, separator())
    if peerErr != nil {
        fmt.Fprintf(&buf, "FWDD status:\n  (peer unreachable: %s)\n", peerErr)
    } else {
        buf.WriteString(peerBuf)
    }
```

Where `separator()` returns the `--------` line matching `show chassis
cluster`. `dialAndShowForwarding` is a new helper:

```go
func (s *Server) dialAndShowForwarding(ctx context.Context) (string, error) {
    conn, err := s.dialPeer()  // already does a 2s GetStatus probe per fabric (server_diag.go:487-499)
    if err != nil { return "", err }
    defer conn.Close()
    client := pb.NewBpfrxServiceClient(conn)
    // Total peer-render budget: dialPeer probe (≤4s for fab0+fab1) + this 5s ShowText
    // gives ~9s worst case. show chassis cluster's user perception is similar; matches
    // the operator timeout tolerance from `show chassis cluster`.
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
    resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
    if err != nil { return "", err }
    return resp.Output, nil
}
```

**Timeout budget rationale (Codex round-1 fix):** dialPeer's existing
internal probe is 2s × up-to-2-fabrics = up to 4s before our outer
ShowText even starts. Adding 5s for the actual ShowText gives a
worst-case 9s wait under failover stress (peer mid-RG-transition
holding `userspace.Manager.mu`). Setting our outer to 3s would race
with dialPeer itself. 5s outer + 4s inherited dial = comfortable
margin; spurious "(peer unreachable)" rendering avoided on
healthy-but-loaded peers.

### Recursion prevention: in-band metadata, not a new topic

(Codex round-1 noted that adding a new topic exposes it to raw gRPC
clients; cmdtree gates the user-facing CLI but not direct gRPC.) The
cleanest fix is to keep ONE topic `chassis-forwarding` and use a
gRPC metadata key `xpf-no-peer: 1` to signal "this is a peer call,
do not dial peer back". `pkg/grpcapi/server_sessions.go:621-639`
already uses metadata for similar guard purposes.

```go
case "chassis-forwarding":
    md, _ := metadata.FromIncomingContext(ctx)
    isPeerCall := len(md.Get("xpf-no-peer")) > 0
    localBuf, err := s.buildLocalForwarding()
    if err != nil { return nil, err }
    if s.cluster == nil || isPeerCall {
        buf.WriteString(localBuf)
        break
    }
    // Cluster mode, original call — render BOTH node blocks.
    ...
    peerBuf, peerErr := s.dialAndShowForwarding(ctx)  // injects xpf-no-peer:1
    ...
```

`dialAndShowForwarding` adds the metadata before the call:

```go
ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
```

This keeps the topic surface clean; the in-band signal can't be
inadvertently triggered by an operator typing `show chassis
forwarding`.

### fwdstatus changes

`fwdstatus.ForwardingStatus.ClusterMode` semantic shifts from "render
deferred-peer note" to "this is the local block of a multi-node
render" — but actually we no longer need that field at all, because
the gRPC handler now controls the framing (node headers + separators)
externally. `Format` reverts to a simple single-block formatter; the
gRPC handler concatenates two blocks with the `node%d:` headers.

Drop `ClusterMode` and `ClusterFollowupRef` from `ForwardingStatus`.
Drop `fwdstatus.ClusterPeerFollowup()` constant. Update the formatter
to no longer emit the deferred-peer note.

### Files touched

| File | Change |
|---|---|
| `pkg/grpcapi/server_show.go` | `chassis-forwarding` case rewritten: check `xpf-no-peer` metadata; if absent and cluster mode, compose local + peer with `nodeN:` headers. New `dialAndShowForwarding` helper that injects `xpf-no-peer:1`. |
| `pkg/cluster/cluster.go` | NO change — `Manager.NodeID()` accessor already exists at line 322 (Codex round-1 fix). Use as-is. |
| `pkg/fwdstatus/fwdstatus.go` | Drop `ClusterMode`, `ClusterFollowupRef` fields. Drop the cluster-note rendering branch. |
| `pkg/fwdstatus/builder.go` | Drop `clusterMode` parameter from `Build()`. Drop `ClusterPeerFollowup()` constant. |
| `pkg/fwdstatus/fwdstatus_test.go` | Drop the `TestFormat_ClusterModeNote` test. Adjust `TestBuild_ClusterMode` to verify peer is queried (or drop — the cluster framing is now in grpcapi, not fwdstatus). |
| `pkg/cli/cli_show_chassis.go` | Local-TTY handler uses `c.dialPeer()` (existing on `*cli.CLI` at `pkg/cli/cli.go:173-181, 206-230`), NOT `*grpcapi.Server.dialPeer()` (Codex round-1 fix). Same compose pattern: build local block, dial peer via the existing CLI fabric path, inject the no-peer metadata, render two blocks. |

### Test strategy

1. **fwdstatus unit tests**: simplified — `Format` produces single-block
   output without cluster note. Existing format/short-uptime/state
   tests adapt.
2. **gRPC handler test**: spin up a fake peer that handles
   `chassis-forwarding` and inspects incoming metadata; verify it
   only renders local-block when `xpf-no-peer: 1` is present and
   would otherwise dial back. The test then drives the local
   handler and checks the combined `node0:` + `node1:` output.
   This validates the recursion guard end-to-end.
3. **Recursion-guard direct test**: call the local handler twice —
   once without `xpf-no-peer` (cluster mode → dials peer fake),
   once WITH `xpf-no-peer` set on the incoming context (peer
   simulation → renders local only, never dials back). Asserts the
   metadata gate is the sole recursion barrier.
3. **Peer-unreachable test**: dial fails → output contains
   `(peer unreachable: ...)` for the peer block; local block still
   renders normally.
4. **Deploy + validation**: on `loss:xpf-userspace-fw0` with cluster
   active and iperf3 load on fw1, run `cli -c "show chassis
   forwarding"`. Output should contain BOTH `node0:` and `node1:`
   blocks; `node1:` shows non-zero worker CPU; `node0:` shows ~idle.

### Peer node ID detection

(Codex round-1 fix.) Although the cluster is documented as 2-node,
the code paths accept arbitrary node IDs (config compiler / daemon).
`pkg/grpcapi/server_show.go:797-817` already has peer-ID detection
logic from the cluster manager's peer state. Reuse that — do NOT
hardcode `1 - localNodeID`.

`s.peerNodeIDForRender()` returns the peer's node ID from the
cluster manager's `peerNodeID` field if known, falling back to
`localNodeID == 0 ? 1 : 0` only as a degenerate default when the
peer has never been seen.

### Recursion / timeout safety

- Recursion blocked by `xpf-no-peer:1` outbound metadata that the
  peer sees as `incoming context` and short-circuits to local-only
  render.
- Total peer-render budget: dialPeer's 2s × 2 fabrics (≤4s) +
  ShowText timeout 5s = up to 9s worst case. Budget rationale
  documented inline.
- Peer-unreachable case prints `(peer unreachable: ...)` for the
  peer block; never blocks the local render.

## Alternatives rejected

1. **New gRPC method `GetForwardingStatus`** — rejected in original
   #877 plan and still rejected. The `ShowText` topic surface is the
   designated extension point.
2. **Render peer block in `fwdstatus.Format`** — would require
   passing peer query callbacks through fwdstatus, polluting a
   pure-formatter package. Better to keep cluster framing in grpcapi.
3. **Sync fwdstatus over HA channel** — invasive, adds new sync
   message type. The on-demand peer-RPC path used by `show chassis
   cluster` is established.

## Refs

Closes #879. Builds on #877 (chassis forwarding) + #882 (CPU windows).
