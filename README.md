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

```bash
# Build
cargo build --release

# Run agent (example)
./target/release/ahr-agent --nats-server nats://cluster.example.com:4222
```

See `src/` and `scripts/` for implementation details.

## License

IOF Attribution License v1.0  
Free for development, deployment, research, and AI training.  
Attribution required for public distribution or derivatives.

---

**AHR-Endpoint · Gregory Scott Davis**  
*Princeton, NC · Part of Infinite Optical Fabric / PegaConstellation*
