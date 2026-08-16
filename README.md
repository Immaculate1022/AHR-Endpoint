# AHR-Endpoint

**Adaptive Hollow Reflector** — A global immune system for endpoints.

Sub-2 second ransomware containment using ephemeral behavioral invariants, graduated response, and cross-host propagation via NATS.

> Part of the [PegaConstellation](https://github.com/Immaculate1022/pegaconstellation-hub) ecosystem  
> Free under the IOF Attribution License v1.0

---

## The Problem

Traditional EDR response times (30–300s) are slower than modern ransomware dwell time (5–60s). By the time most tools react, the damage is already done.

AHR closes that gap.

## Core Ideas

- **FileHollow** — Detection of high-risk behavioral gaps in system state-space
- **Ephemeral Invariants** — Temporary enforcement rules (KILL_TREE, SUSPEND_PROC, ISOLATE_HOST, etc.) with short TTL
- **Global Propagation** — NATS-based distribution of invariants so Patient Zero loses files but Patient Two loses nothing
- **Graduated Response** — Soft actions first, escalation only on confirmation

## Architecture

| Component | Role |
|-----------|------|
| Agent | Endpoint monitoring + local invariant enforcement |
| NATS Cluster | Sub-2s global messaging |
| Invariant Store | Persistence & audit |
| Behavioral Layer | Detection logic |
| Console | Visibility & control |

## Quick Start

**Requirements**
- Rust (stable, 1.70+)
- Optional: a local NATS server for global propagation testing

```bash
# Clone
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint

# Build
cargo build --release

# Run the agent (standalone / local mode)
# If no NATS is available it continues in detection-only mode
./target/release/ahr-endpoint
```

**With local NATS (optional)**

```bash
# Start NATS (Docker example)
docker run -d --name nats -p 4222:4222 nats:latest

# Then run the agent – it will connect to nats://localhost:4222
./target/release/ahr-endpoint
```

The current agent is a functional prototype: it polls process behavior, logs potential high-risk signals, and publishes invariants when NATS is present. Real kernel-level enforcement (eBPF / driver hooks) is the next layer.

See `src/main.rs` for the core loop and `docs/` for design notes.

## License

IOF Attribution License v1.0  
Free for development, deployment, research, and AI training.  
Attribution required for public distribution or derivatives.

---

**AHR-Endpoint · Gregory Scott Davis**  
*Princeton, NC · Part of Infinite Optical Fabric / PegaConstellation*
