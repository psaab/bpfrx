# #1755 codegen + validation evidence

## Codegen proof (release build, `objdump -d -C`)

Before (from research plan §2.1 / §2.2a, build-id f8949d18):
- `cos_queue_push_back`: `sub $0x56000,%r11` (352 KB frame) + `__rust_probestack`
  page-touch loop = ~61% of the fn's self-time on every push.
- `ensure_cos_interface_runtime`: `sub $0x9000,%r11` (36 KB frame) + probe loop
  on every ingress packet (~25% of fn self-time).

After (this PR, `/dev/shm/cargo/release/xpf-userspace-dp`):

| symbol | frame | probe loop? |
|---|---|---|
| `cos_queue_push_back` | `sub $0x18,%rsp` (24 B) | **gone** |
| `promote_to_flow_fair` (cold) | `sub $0xb8,%rsp` (184 B) | none (new_boxed → heap) |
| `cos_queue_push_front` (control) | `sub $0x58,%rsp` (88 B) | none |
| `FlowFairState::new_boxed` | tiny, builds into heap | none |
| `ensure_cos_interface_runtime` (outer, `#[inline]`) | inlined; no giant frame at the per-packet call site | none |
| `ensure_cos_interface_runtime_cold` | `sub $0x9000,%r11` (36 KB) | present, but fires ≤ once per (binding, ifindex), NOT per packet |

`grep -c __rust_probestack` over the whole binary = **0** call sites; the 36 KB
inline probe loop now exists only inside the cold callee.

## Tests
- `cargo test --release` (userspace-dp): 1787 passed, 0 failed.
- miri (`MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test
  flow_fair_state_tests`): 2 passed, 0 failed — no UB in the unsafe
  `new_boxed` constructor (uninit reads / borrow stacks clean).
- 5× flake on `afxdp::cos::queue_ops`: 60 passed / 0 failed each run.
- Go suite (`go test ./...`, short TMPDIR): 0 failures. The one failure under a
  `/dev/shm` TMPDIR (`TestWireUserspaceEventStream…FullResync`) is the documented
  unix-socket sun_path >108-char env artifact — passes on master and here with a
  short `/tmp` TMPDIR.
