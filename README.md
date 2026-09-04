# PegaConstellation > IOF > AHR-Endpoint

**Adaptive Hollow Reflector (AHR)** is a Linux endpoint-security prototype for detecting ransomware-like behavior and routing signals through graduated response controls. It is part of the [PegaConstellation](https://github.com/Immaculate1022/pegaconstellation-hub) ecosystem.

> **Status:** research prototype, version 0.2.1. The repository contains a userspace Rust agent, an optional Aya/eBPF loader path, and experimental enforcement code. The README describes intended behavior and build paths; it does not claim measured sub-second containment, production readiness, or universal ransomware detection.

## What is here

| Area | Current repository surface |
|---|---|
| Behavioral detection | Userspace heuristics in `src/detection.rs`, currently based on process names and resource pressure. |
| Graduated enforcement | Risk-to-action logic and process-tree controls in `src/enforcement.rs` and `src/action.rs`. |
| Cross-host signaling | NATS dependency and propagation scaffolding; deployment and latency claims still require measurement. |
| Kernel path | Optional Aya loader plus an eBPF program under `ebpf/`; Linux toolchain and permissions are required. |
| Research candidates | Versioned AHR scoring modules are preserved under [`docs/archive/`](docs/archive/), separate from the active engine. |

## Quick start: userspace build

The smallest path is a normal Rust build on a supported platform with a stable toolchain:

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint
cargo build --release
RUST_LOG=info ./target/release/ahr-endpoint
```

Run the test suite before making changes:

```bash
cargo test
```

The agent is a prototype and should be exercised in an isolated test environment. Do not point it at production endpoints until its detection thresholds, response policy, audit trail, and rollback behavior have been reviewed.

## Optional NATS path

The project includes NATS-related scaffolding for cross-host signaling. A local NATS container can be started for development:

```bash
docker run --rm --name ahr-nats -p 4222:4222 nats:latest
```

Treat this as a development dependency. The repository does not currently provide a complete production topology, authentication policy, or measured propagation benchmark.

## Optional eBPF path

The kernel path is Linux-only and requires a compatible kernel, Rust nightly components, `rust-src`, `bpf-linker`, and suitable privileges. Start with the setup helper:

```bash
cargo build --release --features ebpf
bash scripts/setup_ebpf.sh
sudo RUST_LOG=info ./target/release/ahr-endpoint
```

Read [`docs/eBPF_Enforcement.md`](docs/eBPF_Enforcement.md) and [`ebpf/README.md`](ebpf/README.md) before attempting a kernel build. The userspace fallback should remain available while the eBPF object and loader are being tested.

## Detection and response model

The active detector is intentionally modest: it combines suspicious process-name indicators with CPU and memory pressure, then returns a `FileHollow` record. This is a starting point, not a complete behavioral ransomware detector.

Response actions are consequential. Any extension that can stop processes, kill a process tree, isolate a host, revoke a session, quarantine a file, or capture memory should be treated as a recommendation until policy gates, dry-run mode, audit logging, human review, and false-positive tests exist.

| Stage | Intended meaning |
|---|---|
| Observe | Record a signal and retain context. |
| Suspend | Apply a reversible process-level intervention in a controlled test. |
| Isolate | Remove a host from relevant network paths only under explicit policy. |
| Terminate | Kill a process tree only after a high-confidence, reviewed decision. |

## Repository layout

```text
src/
  main.rs           Agent loop and runtime wiring
  detection.rs      Current userspace behavioral heuristics
  enforcement.rs    Graduated response and process controls
  action.rs         Action definitions
  ebpf_loader.rs    Optional Aya loader path
ebpf/
  src/main.rs       Kernel-side prototype
  README.md         eBPF build notes
docs/
  eBPF_Enforcement.md
  archive/          Unmerged research candidates and review notes
scripts/
  setup_ebpf.sh     Linux/nightly/bpf-linker setup helper
```

## Research archive

The [version 05 candidate](docs/archive/Pasted_content_05_hollow.rs) introduced expanded telemetry fields and risk scoring. The [version 06 candidate](docs/archive/Pasted_content_06_hollow.rs) adds score explanations, decoy suppression, injection-API signals, privilege-aware recommendations, companion actions, and unit tests. Neither candidate is merged into the active engine.

## Attribution and license

This repository is distributed under the [IOF Attribution License v1.0](LICENSE). Attribution is required for public distribution or derivatives. The license does not turn prototype behavior or performance statements into validated results.

**AHR-Endpoint · Gregory Scott Davis**  
*Part of the Infinite Optical Fabric / PegaConstellation research constellation.*

## Related project links

- [PegaConstellation Hub](https://github.com/Immaculate1022/pegaconstellation-hub)
- [IOF Resonance Core](https://github.com/Immaculate1022/IOF-Resonance-Core)
- [Sovereign Reality Engine](https://github.com/Immaculate1022/sovereign-reality-engine)
- [PegaConstellation Documentation](https://github.com/Immaculate1022/docs)
