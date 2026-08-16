#!/usr/bin/env bash
# setup_ebpf.sh — install toolchain pieces needed to build ahr-ebpf (Linux)
set -euo pipefail

echo "AHR eBPF toolchain setup"
echo "========================"

if ! command -v rustup >/dev/null; then
  echo "rustup not found. Install from https://rustup.rs"
  exit 1
fi

echo "[1/3] Nightly + rust-src"
rustup toolchain install nightly --component rust-src

echo "[2/3] bpf-linker"
cargo install bpf-linker || cargo +nightly install bpf-linker

echo "[3/3] Notes"
echo "  - Run the userspace agent anytime: cargo build --release && ./target/release/ahr-endpoint"
echo "  - Full eBPF object build needs Linux + BTF-capable kernel"
echo "  - See ebpf/README.md and docs/eBPF_Enforcement.md"
echo "Done."
