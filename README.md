# AHR-Endpoint

**Adaptive Hollow Reflector (AHR)** is an experimental Rust endpoint-security agent for exploring ransomware-like process detection and graduated response controls on Linux. It is intended for security researchers and engineers using an isolated test environment. A safe first look is a single, non-enforcing dry run:

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint
RUST_LOG=info cargo run --release -- --dry-run --once
```

> **Status — research prototype (v0.2.1):** AHR has a userspace agent, an optional Aya/eBPF loader path, and experimental process-control code. It does **not** establish production readiness, universal ransomware detection, false-positive rates, or measured containment timing.

## What is here

| Area | Current repository surface |
|---|---|
| Behavioral detection | Userspace heuristics in `src/detection.rs`, based on selected process-name indicators and CPU or memory pressure. |
| Graduated enforcement | Risk-to-action logic and process-tree controls in `src/enforcement.rs` and `src/action.rs`. |
| Cross-host signaling | NATS dependency and development scaffolding; deployment and latency claims require measurement. |
| Kernel path | Optional Aya loader plus an eBPF prototype under `ebpf/`; a separately built object, Linux toolchain, and permissions are required. |
| Research candidates | Versioned AHR scoring modules are preserved under [`docs/archive/`](docs/archive/), separate from the active engine. |

## Quick start

Install a current stable Rust toolchain, then use the dry-run command above. `--dry-run` evaluates the active detector and reports intended actions without loading eBPF, sending process signals, or publishing NATS invariants. `--once` completes one scan cycle and exits.

The dry-run path is a source-level safety check, not an enforcement validation or a detection benchmark. To verify that the guards are present without compiling or launching the agent, run:

```bash
python3 scripts/dry_run_audit.py
```

To build the userspace binary without running it:

```bash
cargo build --release
```

Without `--dry-run`, a matching signal can lead to `SIGSTOP` or `SIGKILL` actions. Exercise only in an isolated environment after reviewing detection thresholds, response policy, audit logging, and rollback behavior.

## Optional paths

### NATS development scaffolding

The project includes NATS-related scaffolding for cross-host signaling. A local NATS container can be started for development:

```bash
docker run --rm --name ahr-nats -p 4222:4222 nats:latest
```

Treat this as a development dependency. The repository does not provide a complete production topology, authentication policy, or measured propagation benchmark.

### Experimental eBPF path

The kernel path is Linux-only and requires a compatible kernel, Rust nightly components, `rust-src`, `bpf-linker`, suitable privileges, and an eBPF object. This repository does not provide a reproducible in-repo BPF object or CI artifact. Start by reading the build notes and, if appropriate for a disposable lab host, installing the helper prerequisites:

```bash
bash scripts/setup_ebpf.sh
cargo build --release --features ebpf
```

Read [`docs/eBPF_Enforcement.md`](docs/eBPF_Enforcement.md), [`ebpf/README.md`](ebpf/README.md), and [`scripts/build_ebpf.sh`](scripts/build_ebpf.sh) before attempting a kernel build. Set `AHR_EBPF_OBJECT` to a compatible object before trying the loader. The userspace fallback remains available if the loader cannot attach.

## Detection and response model

The active detector is intentionally modest: it combines selected suspicious process-name indicators with CPU or memory pressure, then returns a `FileHollow` record. This is a starting point, not a complete behavioral ransomware detector.

Current userspace responses can stop a process or stop/kill a process tree. Host isolation, session revocation, file quarantine, and memory capture are not active-engine responses. All consequential use needs policy gates, dry-run review, audit logging, human review, and false-positive testing.

| Stage | Intended meaning |
|---|---|
| Observe | Record a signal and retain context. |
| Suspend | Apply a reversible process-level intervention in a controlled test. |
| Isolate | A planned policy concept; active host-isolation behavior is not implemented. |
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

## License and attribution

This repository is distributed under the [IOF Attribution License v1.0](LICENSE). It permits use, copying, modification, publication, distribution, sublicensing, and deployment; any public use, derivative work, or implementation must clearly attribute **“AHR-Endpoint / Adaptive Hollow Reflector by Gregory Scott Davis, Princeton, NC.”** See [`LICENSE`](LICENSE) for the complete terms and warranty disclaimer.

**AHR-Endpoint · Gregory Scott Davis**  
*Part of the Infinite Optical Fabric / PegaConstellation research constellation.*

## Related project links

- [PegaConstellation Hub](https://github.com/Immaculate1022/pegaconstellation-hub) — the ecosystem hub referenced above
- [IOF Resonance Core](https://github.com/Immaculate1022/IOF-Resonance-Core)
- [Sovereign Reality Engine](https://github.com/Immaculate1022/sovereign-reality-engine)
- [PegaConstellation Documentation](https://github.com/Immaculate1022/docs)

## Dry-run audit path

The source-level audit checks the presence of the dry-run and single-cycle guards:

```bash
python3 scripts/dry_run_audit.py
```

The audit never imports or launches the agent. It verifies that `--dry-run` disables eBPF loading, NATS connection, process mutation, and invariant publication, and that `--once` is available for a bounded single-cycle run. A runtime dry run still requires an isolated environment and must not be confused with an enforcement validation.

The archived scoring candidates are indexed in [`docs/archive/README.md`](docs/archive/README.md) and are intentionally outside the active Cargo source path. The candidate modules must not be merged into enforcement until they have compatibility tests, structured audit logging, false-positive review, explicit dry-run behavior, and human authorization for consequential actions.
