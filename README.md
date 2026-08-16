# AHR-Endpoint

**Adaptive Hollow Reflector** — A global immune system for endpoints.

Sub-2 second ransomware containment using ephemeral behavioral invariants, **graduated response**, cross-host propagation via NATS, and **Aya eBPF kernel enforcement**.

> Part of the [PegaConstellation](https://github.com/Immaculate1022/pegaconstellation-hub) ecosystem  
> Free under the IOF Attribution License v1.0

**Version 0.2.1** — userspace graduated enforcement + Aya loader wired.

---

## The Problem

Traditional EDR response times (30–300s) are slower than modern ransomware dwell time (5–60s). By the time most tools react, the damage is already done.

AHR closes that gap.

## Core Ideas

- **FileHollow** — Detection of high-risk behavioral gaps in system state-space
- **Ephemeral Invariants** — Temporary enforcement rules with short TTL
- **Graduated Response** — Soft (SIGSTOP) → Medium (tree stop) → Kill (SIGKILL tree)
- **Global Propagation** — NATS so Patient Zero is contained and peers are pre-armed
- **Kernel path** — Aya loader → `ACTION_MAP` + `bpf_send_signal` on flagged syscalls

## Architecture

| Component | Role |
|-----------|------|
| Agent (`src/`) | Detection + graduated userspace enforcement |
| `ebpf_loader.rs` | Aya load / attach / map write (`--features ebpf`) |
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
| 9–10 | Kill | SIGKILL process tree + eBPF map + NATS |

PID 1 and the agent itself are always whitelisted.

## Quick Start (userspace)

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint
cargo build --release
RUST_LOG=info ./target/release/ahr-endpoint
```

Optional NATS:

```bash
docker run -d --name nats -p 4222:4222 nats:latest
```

## eBPF kernel path (Aya loader)

### 1. Build the agent with the loader

```bash
cargo build --release --features ebpf
```

### 2. Build the eBPF object (Linux + nightly + bpf-linker)

```bash
bash scripts/setup_ebpf.sh
# then compile the program in ebpf/ (see ebpf/README.md)
# place the object where the loader can find it:
#   ./ahr-ebpf.o
#   or export AHR_EBPF_OBJECT=/path/to/object
```

### 3. Run as root (CAP_BPF)

```bash
sudo RUST_LOG=info ./target/release/ahr-endpoint
```

On start you should see either:

- `Kernel eBPF enforcement: ACTIVE` — map writes + in-kernel SIGKILL armed  
- `Kernel eBPF enforcement: inactive (...)` — userspace-only fallback (still safe)

Object search order: `$AHR_EBPF_OBJECT` → `./ahr-ebpf.o` → `./target/bpfel-unknown-none/release/ahr-ebpf` → `/usr/lib/ahr-endpoint/ahr-ebpf.o`

Design notes: [`docs/eBPF_Enforcement.md`](docs/eBPF_Enforcement.md)

## Project layout

```
src/
  main.rs           Agent loop + dual-path enforcement
  detection.rs      Behavioral scoring
  enforcement.rs    Graduated response + tree kill
  ebpf_loader.rs    Aya load / attach / ACTION_MAP writes
ebpf/
  src/main.rs       Kernel program (tracepoint + signal)
  README.md         BPF build notes
docs/
  eBPF_Enforcement.md
scripts/
  setup_ebpf.sh
```

## License

IOF Attribution License v1.0  
Free for development, deployment, research, and AI training.  
Attribution required for public distribution or derivatives.

---

**AHR-Endpoint · Gregory Scott Davis**  
*Princeton, NC · Part of Infinite Optical Fabric / PegaConstellation*
