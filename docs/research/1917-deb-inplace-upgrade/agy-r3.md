I will locate and view the plan document specified by the user.
I will list the permissions to see the workspace paths or allowed paths.
I will list the contents of the `/home/ps/.gemini/antigravity-cli/scratch` directory.
I will list the contents of the `/home/ps/.gemini/antigravity-cli/worktrees` directory.
I will search for the plan.md file inside the scratch directory.
I will run printenv to see what environment variables are present and understand the environment.
I will list the files in `/home/ps/git/bpfrx` to check if that is where the target repository is located.
I will check if I can view the plan file directly.
I will run a find command to locate any file containing "plan.md" or "1917" under `/home/ps/git/bpfrx`.
I will look specifically for files in the repository that contain `1917` in their path.
I will run git branch to see the available branches in this repository.
I will run git status to check the current branch.
I will retrieve the contents of the plan file from the `origin/research/1917-deb-inplace-upgrade` branch using git show.
I will write the complete contents of `docs/research/1917-deb-inplace-upgrade/plan.md` from the remote branch into a file in the scratch directory so that I can read it without truncation.
I will view the complete plan file from the scratch directory.
I will run `dh_installsystemd --help` to check the supported flags and their exact behavior.
I will search the web for the `dh_installsystemd` manpage and options.
I will search the web for details on how to completely prevent systemd services from being restarted during package upgrades with `dh_installsystemd`.
I will search the web for the official Debian manpage text of `dh_installsystemd` to verify exactly what `--no-stop-on-upgrade` and `--no-restart-after-upgrade` do.
I will search for the specific option list of `dh_installsystemd` to clarify the behavior of `--no-stop-on-upgrade` versus `--no-restart-after-upgrade`.
I will search for the exact debhelper man page text for the `--no-stop-on-upgrade` option.
I will search the repository to see how `active.json` is read and handled on startup or during a rollback.
I will run a grep command to find where "active.json" is referenced in the codebase.
I will print the contents of `pkg/configstore/db.go` to see how it reads the config.
I will list the files in `pkg/configstore` using a command.
I will print `pkg/configstore/crypto.go` to see the encryption/decryption logic.
I will search the repository to see how `ReadActive` is called and how errors are handled.
I will print lines 70 to 110 of `pkg/configstore/store.go` to see the logic that reads the active config.
I will search for references to the `.Load(` method in the codebase to see how config loading errors affect daemon startup.
I will check where the configstore is loaded during the startup of the `xpfd` daemon.
I will list the files in the `cmd` directory to locate the main entry point of the daemon.
I will grep for `Load` inside `cmd/xpfd/main.go` to see how it loads configuration on startup.
I will print the contents of `cmd/xpfd/main.go` to understand how the daemon initializes itself and gets its configuration.
I will list the files in `pkg/daemon` to find the main runner logic.
I will search for the word `Load` in `pkg/daemon/daemon_run.go` to see how configstore loading errors are handled.
I will print the config loading section in `daemon_run.go`.
I will grep for `ActiveConfig` in `pkg/configstore/store.go` to see what it returns.
I will print the `ActiveConfig` function in `store.go`.
I will find the definition of `bootstrapFromFile` in `pkg/daemon` to see what it does.
I will print the `bootstrapFromFile` function in `daemon_apply.go`.
I will search for the definition of `verify-dataplane` or `Verify` in the codebase to understand what dependencies it has.
I will search for `verify-dataplane` or `verify` in the repository files using grep.
I will search the entire codebase for `verify-dataplane`.
I will check the status of the background task.
I will terminate the grep task and run a more specific grep to find where `verify-dataplane` argument is handled.
I will search for occurrences of `verify-dataplane` in the remote branch using `git grep`.
I will display the `cmd/xpfd/main.go` from the research branch to see the `verify-dataplane` implementation.
PLAN-NEEDS-REVISION

### 1. Blocker Status & v4 Revisions Verification

*   **Blocker 1 (dh_installsystemd auto-restart):** Resolved, but with a new gap. Mandating `--no-stop-on-upgrade` (and pinning `debhelper-compat`) successfully stops `debhelper` from generating restarts. However, it exposes the system to `needrestart` (see New Issues).
*   **Blocker 2 (Kernel verify boot/watchdog):** Partially resolved. Replacing "verify unbooted" with a one-shot `grub-reboot` is correct, but the watchdog fallback design has a fatal software watchdog gap (see New Issues).
*   **Blocker 3 (Non-atomic manifest / Old-Reader-Rejecting Envelope):** Partially resolved. The envelope concept (using an array or magic prefix) correctly triggers a JSON unmarshal error in binary N. However, the daemon startup behavior does not actually "fail closed" on a database parse error (see New Issues).
*   **Blocker 4 (Run staged orchestrator):** Resolved. Running the staged `/usr/local/lib/xpf/<N+1>/xpf-upgrade` by absolute versioned path prevents path and version dependency resolution errors.

---

### 2. New Issues & Blockers (v4 Gaps)

#### [BLOCKER 1] Daemon Startup Does Not Fail Closed on Config Load Errors
In [daemon_run.go:L122-132](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go#L122-L132), if [Load](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L80) returns an error (which it will when binary N encounters the N+1 format), the daemon logs a warning and proceeds:
```go
if err := d.store.Load(); err != nil {
    slog.Warn("failed to load config from db", "err", err)
}
if d.store.ActiveConfig() == nil {
    if err := d.bootstrapFromFile(); err != nil {
        slog.Warn("failed to bootstrap config from file", "err", err)
    }
}
```
Because the active config failed to parse, `ActiveConfig()` returns `nil`. The daemon will attempt [bootstrapFromFile](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L32). If `/etc/xpf/xpf.conf` exists, the daemon will load it and **overwrite** the `active.json` file with the bootstrap config (erasing the active database). If the file does not exist, it starts degraded with an empty configuration.
*   **Mitigation:** The daemon must treat startup database parse errors (excluding `os.IsNotExist`) as fatal and exit immediately rather than bootstrapping or running unconfigured.

#### [BLOCKER 2] dpkg Deletes Old Versioned Directories, Breaking Rollback and Running State
Because binaries are installed directly by the package to `/usr/local/lib/xpf/<version>/`, `dpkg` will automatically delete the old `/usr/local/lib/xpf/<N>/` directory during the upgrade to version N+1.
*   **The Gaps:** 
    1. If verification fails in `postinst`, local rollback is impossible because the version N binaries have been deleted from disk.
    2. If the running daemon needs to restart its helper during the upgrade transaction but before the cut-over, it will fail because `/usr/local/lib/xpf/<N>/xpf-userspace-dp` is gone.
*   **Mitigation:** Separate staging from runtime execution. dpkg should install to a static path (e.g., `/usr/local/share/xpf/staged`), and `xpf-upgrade` should copy the staged files to versioned runtime paths (`/var/lib/xpf/versions/<version>`) which are not managed or deleted by dpkg.

#### [BLOCKER 3] Software Watchdog (`softdog`) Cannot Recover from Early Boot Hangs
The plan proposes using a `softdog` module armed before reboot. However, `softdog` is a kernel-space software watchdog. If the candidate kernel hangs or panics during decompression or early initialization (before `softdog` or systemd is loaded and armed), the software timer is gone, resulting in a permanent node brick.
*   **Mitigation:** The plan must explicitly state that a hardware or hypervisor-level watchdog (`/dev/watchdog`) is required for the "never-brick" guarantee, and that `softdog` is insufficient for early-boot protection.

#### [BLOCKER 4] `needrestart` Will Force a Service Restart on Upgrade
Modern Ubuntu/Debian server environments install `needrestart` by default. At the end of any `apt` transaction, `needrestart` scans for processes running deleted binaries. Because dpkg deletes `/usr/local/lib/xpf/<N>/xpfd`, `needrestart` will detect `xpfd` as running a deleted binary and automatically restart the service, cutting the dataplane during the apt transaction regardless of the `dh_installsystemd` configuration.
*   **Mitigation:** Package a `needrestart` override configuration file (e.g. under `/etc/needrestart/conf.d/xpf.conf`) to blacklist `xpfd.service` or `/usr/local/lib/xpf/` paths from auto-restart.

#### [BLOCKER 5] GRUB Configuration Dependency
`grub-reboot` requires `GRUB_DEFAULT=saved` inside `/etc/default/grub` to function. If the base appliance image configures a hardcoded entry (e.g., `GRUB_DEFAULT=0`), `grub-reboot` will be ignored or the system will boot-loop.
*   **Mitigation:** Mandate verifying/updating the GRUB configuration to `GRUB_DEFAULT=saved` as part of the package post-install or appliance build.
