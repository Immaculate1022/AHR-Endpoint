#!/usr/bin/env bash
# build_ebpf.sh — best-effort compile of ahr-ebpf (Linux + nightly + bpf-linker)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "AHR eBPF build"
echo "=============="

if ! command -v rustc >/dev/null; then
  echo "rustc not found"; exit 1
fi

if ! rustup toolchain list | grep -q nightly; then
  echo "Install nightly: rustup toolchain install nightly --component rust-src"
  exit 1
fi

if ! command -v bpf-linker >/dev/null; then
  echo "Install bpf-linker: cargo install bpf-linker"
  exit 1
fi

ARCH="${ARCH:-bpfel-unknown-none}"
echo "Target: $ARCH"
echo "Note: full Aya workspace (xtask) is the reliable long-term path."
echo "This script documents the intended compile; success depends on local toolchain."

# Placeholder compile attempt — ebpf/ is a standalone crate sketch
cd ebpf
if cargo +nightly build -Z build-std=core --target "$ARCH" --release 2>/tmp/ahr-ebpf-build.log; then
  echo "Build reported success. Copy object if produced:"
  find ../target -name '*ahr-ebpf*' -o -name '*.o' 2>/dev/null | head -20 || true
  echo "Then: export AHR_EBPF_OBJECT=/path/to/object"
else
  echo "Build failed (expected until full Aya workspace is in place)."
  echo "Log: /tmp/ahr-ebpf-build.log"
  tail -30 /tmp/ahr-ebpf-build.log || true
  echo ""
  echo "Recommended next step:"
  echo "  cargo generate --git https://github.com/aya-rs/aya-template --name ahr-ebpf-ws"
  echo "  then merge ACTION_MAP + signal logic from ebpf/src/main.rs"
  exit 1
fi
