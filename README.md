# AHR-Endpoint

**Adaptive Hollow Reflector (AHR)** is an experimental Rust endpoint-security agent for exploring ransomware-like process detection and graduated response controls on Linux. It is intended for security researchers and engineers using an isolated test environment. A safe first look is a single, non-enforcing dry run:

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint
RUST_LOG=info cargo run --release -- --dry-run --once
```

> **Status — research prototype (v0.3.0):** AHR has a userspace agent, an optional Aya/eBPF loader path, and experimental process-control code. It does **not** establish production readiness, universal ransomware detection, false-positive rates, or measured containment timing.

## What is here

| Area | Current repository surface |
|---|---|
| Behavioral detection | Userspace heuristics in `src/detection.rs`, based on selected process-name indicators and CPU or memory pressure. |
| Telemetry scoring | The merged version 06 scoring model in `src/hollow.rs`: weighted signal scoring with human-readable reasons, decoy suppression, and privilege-aware recommendations. |
| Decision policy | `src/policy.rs` combines the detector ladder and the telemetry score; privilege-escalated recommendations are held for human authorization. |
| Audit + control plane | Structured JSON audit records (`src/audit.rs`, `AHR_AUDIT_LOG`) and Sentinel X evidence events (`src/sentinel.rs`, `sentinelx.evidence` NATS subject / `AHR_SENTINELX_SINK`). |
| Graduated enforcement | Risk-to-action logic and process-tree controls in `src/enforcement.rs` and `src/action.rs`. |
| Cross-host signaling | NATS dependency and development scaffolding; deployment and latency claims require measurement. |
| Kernel path | Optional Aya loader plus an eBPF prototype under `ebpf/`; a separately built object, Linux toolchain, and permissions are required. |
| Research candidates | Versioned AHR scoring modules are preserved under [`docs/archive/`](docs/archive/) for provenance; version 06 was merged into the active engine on 2026-10-04. |

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

The active detector is intentionally modest: it combines selected suspicious process-name indicators with CPU or memory pressure, then returns a `FileHollow` snapshot. This is a starting point, not a complete behavioral ransomware detector.

Each snapshot is bridged into the merged telemetry scoring model (`src/hollow.rs`, the version 06 candidate), which scores every observed signal and records human-readable reasons for the score. The policy layer (`src/policy.rs`) takes the more severe of the detector ladder and the telemetry score as the effective risk, so every decision can be traced to the scorer that drove it. The detector only carries signals it actually observed — process-tree depth and the privilege the process runs with — so today the telemetry score mostly reflects those; richer file telemetry (entropy, write velocity, rename bursts) will populate the rest as the eBPF path matures.

Current userspace responses can stop a process or stop/kill a process tree. Host isolation, session revocation, file quarantine, and memory capture are not active-engine responses: when the scoring model recommends them, the recommendation is recorded in the audit trail and emitted as a Sentinel X evidence event, and — where it would otherwise mean killing a privileged process tree — the executable action is held at suspend until a human authorizes the escalation. Every decision, dry-run or live, produces a structured JSON audit record (`src/audit.rs`).

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
  detection.rs      Current userspace behavioral heuristics + scoring bridge
  hollow.rs         Merged v06 telemetry scoring model (reasons, decoy guard)
  policy.rs         Decision policy + human-authorization caps
  audit.rs          Structured JSON audit records (AHR_AUDIT_LOG)
  sentinel.rs       Sentinel X evidence events (NATS / AHR_SENTINELX_SINK)
  enforcement.rs    Graduated response and process controls
  action.rs         Action definitions
  ebpf_loader.rs    Optional Aya loader path
ebpf/
  src/main.rs       Kernel-side prototype
  README.md         eBPF build notes
docs/
  eBPF_Enforcement.md
  archive/          Research candidates and review notes (provenance)
scripts/
  setup_ebpf.sh     Linux/nightly/bpf-linker setup helper
```

## Research archive

The [version 05 candidate](docs/archive/Pasted_content_05_hollow.rs) introduced expanded telemetry fields and risk scoring. The [version 06 candidate](docs/archive/Pasted_content_06_hollow.rs) adds score explanations, decoy suppression, injection-API signals, privilege-aware recommendations, companion actions, and unit tests. Version 06 was merged into the active engine as `src/hollow.rs` on 2026-10-04, behind the policy layer's human-authorization gates; the archived files remain unchanged for provenance.

## License and attribution

This repository is distributed under the [IOF Attribution License v1.0](LICENSE). It permits use, copying, modification, publication, distribution, sublicensing, and deployment; any public use, derivative work, or implementation must clearly attribute **“AHR-Endpoint / Adaptive Hollow Reflector by Gregory Scott Davis, Princeton, NC.”** See [`LICENSE`](LICENSE) for the complete terms and warranty disclaimer.

**AHR-Endpoint · Gregory Scott Davis**  
*Part of the Infinite Optical Fabric / PegaConstellation research constellation.*

## Related project links

- [PegaConstellation Hub](https://github.com/Immaculate1022/pegaconstellation-hub) — the ecosystem hub referenced above
- [Sentinel X](https://github.com/Immaculate1022/SentinelX) — forensic telemetry control plane; AHR decisions stream to it as evidence events
- [IOF Resonance Core](https://github.com/Immaculate1022/IOF-Resonance-Core)
- [Sovereign Reality Engine](https://github.com/Immaculate1022/sovereign-reality-engine)
- [PegaConstellation Documentation](https://github.com/Immaculate1022/docs)

## Dry-run audit path

The source-level audit checks the presence of the dry-run and single-cycle guards:

```bash
python3 scripts/dry_run_audit.py
```

The audit never imports or launches the agent. It verifies that `--dry-run` disables eBPF loading, NATS connection, process mutation, and invariant publication, and that `--once` is available for a bounded single-cycle run. A runtime dry run still requires an isolated environment and must not be confused with an enforcement validation.

The archived scoring candidates are indexed in [`docs/archive/README.md`](docs/archive/README.md) and retained for provenance. Their merge into the active engine (2026-10-04) followed the gates named here: compatibility tests in the real crate, structured audit logging, explicit dry-run behavior, and human authorization for consequential actions; false-positive benchmarking remains open work.
