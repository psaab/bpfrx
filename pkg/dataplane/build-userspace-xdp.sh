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
(
	cd "${CRATE_DIR}"
	"${CARGO_BIN}" +"${TOOLCHAIN}" build --release
)
install -m 0644 "${CRATE_DIR}/target/bpfel-unknown-none/release/libbpfrx_userspace_xdp.so" "${OUT_FILE}"
