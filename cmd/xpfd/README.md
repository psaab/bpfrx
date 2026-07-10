# cmd/xpfd

The xpfd daemon — the firewall control plane. Starts the configured
dataplane, applies compiled config to every subsystem, handles signals,
and exposes gRPC + HTTP REST + an interactive CLI.

## Entry

`main.go` parses flags and constructs `pkg/daemon.Daemon` via
`daemon.New(opts)`. The daemon instance assembles every subsystem
manager from `pkg/*` and runs them under an errgroup.

`main()` first routes on `classifyCommand(os.Args)` — the pure,
side-effect-free SSOT for the top-level subcommand decision (which
subcommand runs for a given argv; `cmdDaemon` is the fall-through that
parses the daemon flags). `xpfd upgrade` then routes on
`upgradeArgsSelectKernel` (binary cut-over vs `upgrade kernel`). Both
routing decisions and every subcommand arg parser
(`parseUpgradeArgs`, `parseSeedRuntimeArgs`,
`parsePublishGenerationArgs`, `parseCleanupArgs`,
`validateKernelVerbArgs`) are unit-testable without `os.Exit` or the
real upgrade/cleanup side effects (`dispatch_test.go`,
`upgrade_args_4869_test.go`, `leftover_args_5322_test.go`).

## Flags

- `-config` — config file path. Default `/etc/xpf/xpf.conf`.
- `-no-dataplane` — config-only mode (parse + validate without starting
  the dataplane). Useful for offline checks.
- `-api-addr` — HTTP REST listener. Default `127.0.0.1:8080`.
- `-grpc-addr` — gRPC listener. Default `127.0.0.1:50051`.
- `-debug` — verbose logging.

## Subcommands

- `xpfd version` — prints version and commit.
- `xpfd cleanup` — removes pinned BPF state and FRR-managed routes.
  Runs on uninstall.

## TTY detection

`unix.IoctlGetTermios(fd, TCGETS)` — when stdin is a real TTY, the
daemon spawns the local CLI (`pkg/cli`) on the same terminal. Service
units run without a TTY and skip that path.

## Cluster mode

`/etc/xpf/node-id` selects node (`0` or `1`); absence is standalone.
Cluster nodes pick up the bondless-RETH naming convention
(`fxp0`, `em0`, `ge-{0,7}-0-X`) and run the chassis-cluster state
machine.

## Read order

Start at `pkg/daemon/daemon.go` (`New`) for the assembly. From
there, every imported `pkg/*` has its own README.
