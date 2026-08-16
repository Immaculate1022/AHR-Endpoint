# AHR-Endpoint

**Adaptive Hollow Reflector** — A global immune system for endpoints.

Sub-2 second ransomware containment using ephemeral behavioral invariants, **graduated response**, cross-host propagation via NATS, and **eBPF-ready kernel enforcement**.

> Part of the [PegaConstellation](https://github.com/Immaculate1022/pegaconstellation-hub) ecosystem  
> Free under the IOF Attribution License v1.0

**Version 0.2.0** — userspace graduated enforcement is live; eBPF skeleton is in-tree.

---

## The Problem

Traditional EDR response times (30–300s) are slower than modern ransomware dwell time (5–60s). By the time most tools react, the damage is already done.

AHR closes that gap.

## Core Ideas

- **FileHollow** — Detection of high-risk behavioral gaps in system state-space
- **Ephemeral Invariants** — Temporary enforcement rules with short TTL
- **Graduated Response** — Soft (SIGSTOP) → Medium (tree stop) → Kill (SIGKILL tree)
- **Global Propagation** — NATS so Patient Zero is contained and peers are pre-armed
- **Kernel path** — eBPF `ACTION_MAP` + `bpf_send_signal` / future LSM `-EPERM`

## Architecture

| Component | Role |
|-----------|------|
| Agent (`src/`) | Detection + graduated userspace enforcement |
| `enforcement.rs` | Risk → Action, TTL flags, process-tree signals |
| `detection.rs` | Behavioral heuristics |
| NATS | Sub-2s invariant distribution |
| `ebpf/` | Aya program: PID→action map, in-kernel SIGKILL |

## Graduated response

| Risk | Action | Behavior |
|-----:|--------|----------|
| 0–3 | Allow | No action |
| 4–6 | Soft | SIGSTOP (reversible) |
| 7–8 | Medium | SIGSTOP process tree |
| 9–10 | Kill | SIGKILL process tree + NATS invariant |

PID 1 and the agent itself are always whitelisted.

## Quick Start

**Requirements**
- Rust stable (1.70+)
- Linux recommended for real signals / future eBPF
- Optional: local NATS

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint

cargo build --release

# Standalone (no NATS)
./target/release/ahr-endpoint
```

**With NATS**

```bash
docker run -d --name nats -p 4222:4222 nats:latest
./target/release/ahr-endpoint
```

Run with logging:

```bash
RUST_LOG=info ./target/release/ahr-endpoint
```

## eBPF (kernel enforcement)

Skeleton lives in [`ebpf/`](ebpf/). Design notes: [`docs/eBPF_Enforcement.md`](docs/eBPF_Enforcement.md).

- Userspace already enforces Soft/Medium/Kill via signals.
- Kernel path adds microsecond `bpf_send_signal(SIGKILL)` when a flagged PID issues syscalls.
- LSM deny (`-EPERM` on rename/write) is the next preventive step (kernel ≥ 5.7).

Build notes and prerequisites are in `ebpf/README.md`.

## Project layout

```
src/
  main.rs           Agent loop
  detection.rs      Behavioral scoring
  enforcement.rs    Graduated response + tree kill
ebpf/
  src/main.rs       Aya eBPF program (ACTION_MAP + signal)
  README.md         Build / load notes
docs/
  eBPF_Enforcement.md
```

## License

IOF Attribution License v1.0  
Free for development, deployment, research, and AI training.  
Attribution required for public distribution or derivatives.

---

**AHR-Endpoint · Gregory Scott Davis**  
*Princeton, NC · Part of Infinite Optical Fabric / PegaConstellation*
