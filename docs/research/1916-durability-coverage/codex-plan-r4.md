PLAN-READY

Scope: r4 review only of the r3 blocking item, the Step 2b timezone control-flow regression.

The blocker is resolved. In §5 Step 2b, the revised plan explicitly prevents the bad path: "do NOT re-run the symlink mutation when localtime is already correct" and then requires "always write `/etc/timezone` via `fsatomic.WriteFileAtomic` when its content differs" including "the branch where localtime was already correct". That directly handles the stale-`/etc/timezone` case without re-removing a correct `/etc/localtime`.

This is implementable against `pkg/daemon/daemon_system.go`: the current function returns at `if current == target { return }` before writing `/etc/timezone`, and only later performs `os.Remove("/etc/localtime")` plus `os.Symlink`. The r4 case split can preserve the existing symlink mutation only for the localtime-mismatch branch while adding an atomic `/etc/timezone` write for the localtime-already-correct branch.

The risk table also captures the fix: §7 says "re-run symlink path ONLY when localtime mismatches; write /etc/timezone atomically whenever its content differs, including the localtime-already-correct branch." The changelog matches the design: §14 says "(1) both match -> return; (2) localtime mismatch -> run existing remove+symlink; (3) always write `/etc/timezone` atomically when its content differs".

No new problem introduced in the reviewed r4 delta.
