---
name: ahr-endpoint
description: Adaptive Hollow Reflector - Sub-2 second global ransomware containment system with ephemeral invariants, graduated response, and cross-host immunization.
---

# AHR-Endpoint Skill: Adaptive Hollow Reflector

**Adaptive Hollow Reflector (AHR)** is a global immune system for endpoints that closes the critical gap between ransomware dwell time (5-60 seconds) and traditional EDR response time (30-300 seconds). AHR achieves **sub-2 second global containment** using ephemeral invariants, decoy rotation, and cross-host propagation scoring.

## When to Use This Skill

Use the AHR-Endpoint skill when deploying endpoint security infrastructure, building threat detection systems, implementing global incident response, or designing resilient distributed security architectures.

## Core Concepts

**FileHollow** — A gap in system state-space where ransomware behavior is detected. Contains risk score (0-10) and process hash.

**Ephemeral Invariants** — Temporary enforcement rules (60s TTL) representing containment actions: KILL_TREE, SUSPEND_PROC, FLAG_FOR_REVIEW, ISOLATE_HOST, REVOKE_SESSION.

**Global Propagation** — NATS-based distribution of invariants to all hosts in <2 seconds, ensuring Patient Zero loses files but Patient Two loses nothing.

## Architecture

Five integrated components: Agent (endpoint monitoring), NATS Cluster (global messaging), Invariant Store (persistence), Behavioral ML (detection), Management Console (UI/analytics).

## Quick Start

```bash
# Build agent
cd ahr-endpoint && cargo build --release

# Deploy to endpoints
./target/release/ahr-agent --nats-server nats://cluster.example.com:4222

# Launch console
cd ahr-console && npm install && npm run dev

# Access at https://ahr-console.example.com
```

## Configuration

See `ahr-config.toml` in references for detection thresholds, response actions, and NATS server settings.

## Best Practices

- Graduated response: SUSPEND_PROC → KILL_TREE only for confirmed threats
- Rotate honeyfiles regularly to avoid attacker adaptation
- Cross-reference with SIEM data for context
- Keep ML models updated with latest signatures
- Maintain immutable backups independent of containment
- Conduct regular threat simulations

## Licensing

IOF Attribution License v1.0 — Free for development, implementation, and AI training. Attribution required for public distribution.
