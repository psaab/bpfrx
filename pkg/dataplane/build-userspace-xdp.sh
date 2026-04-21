#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CRATE_DIR="${REPO_ROOT}/userspace-xdp"
OUT_FILE="${SCRIPT_DIR}/userspace_xdp_bpfel.o"
CARGO_BIN="${CARGO:-${HOME}/.cargo/bin/cargo}"
RUSTUP_BIN="${RUSTUP:-${HOME}/.cargo/bin/rustup}"
TOOLCHAIN="${RUST_BPF_TOOLCHAIN:-nightly}"

if [[ ! -x "${CARGO_BIN}" ]]; then
	echo "cargo not found at ${CARGO_BIN}" >&2
	exit 1
fi
if [[ ! -x "${HOME}/.cargo/bin/bpf-linker" ]]; then
	echo "bpf-linker not found at ${HOME}/.cargo/bin/bpf-linker" >&2
	exit 1
fi
if [[ -x "${RUSTUP_BIN}" ]]; then
	"${RUSTUP_BIN}" component add rust-src --toolchain "${TOOLCHAIN}-x86_64-unknown-linux-gnu" >/dev/null 2>&1 || \
	"${RUSTUP_BIN}" component add rust-src --toolchain "${TOOLCHAIN}" >/dev/null 2>&1 || true
fi
# Thread MAX_INTERFACES from the C header into the Rust build so
# BINDING_ARRAY_MAX_ENTRIES (and userspace_ingress_ifaces max_entries)
# stay locked to the same value as tx_ports' MAX_INTERFACES. Drift
# between these constants is the exact failure mode #814 is fixing.
MAX_INTERFACES="$(awk '/^#define MAX_INTERFACES /{print $3; exit}' "${REPO_ROOT}/bpf/headers/xpf_common.h")"
if [[ -z "${MAX_INTERFACES}" ]]; then
	echo "build-userspace-xdp.sh: failed to parse MAX_INTERFACES from ${REPO_ROOT}/bpf/headers/xpf_common.h" >&2
	exit 1
fi
export MAX_INTERFACES
(
	cd "${CRATE_DIR}"
	"${CARGO_BIN}" +"${TOOLCHAIN}" build --release
)
install -m 0644 "${CRATE_DIR}/target/bpfel-unknown-none/release/libxpf_userspace_xdp.so" "${OUT_FILE}"
