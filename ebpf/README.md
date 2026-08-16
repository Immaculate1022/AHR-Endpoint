# ahr-ebpf

Kernel enforcement for AHR-Endpoint using [Aya](https://aya-rs.dev/).

## Action map

| Value | Meaning |
|------:|---------|
| 0 | Allow |
| 1 | Soft (userspace SIGSTOP) |
| 2 | Medium (tree SIGSTOP) |
| 3 | Kill (`bpf_send_signal(SIGKILL)`) |

Userspace agent writes `(tgid, action)` after behavioral scoring. This program enforces Kill in-kernel on subsequent syscalls.

## Prerequisites (Linux)

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
# Kernel: CONFIG_BPF, CONFIG_BPF_SYSCALL, BTF preferred; LSM BPF needs 5.7+
```

## Build

```bash
# From repo root (adjust target as needed)
cargo +nightly build -Z build-std=core,alloc \
  --target bpfel-unknown-none \
  -p ahr-ebpf \
  --release
```

Full Aya workspace layout (common + xtask) can be generated with:

```bash
cargo generate --git https://github.com/aya-rs/aya-template --name ahr-ebpf-ws
```

Then merge the ACTION_MAP + signal logic from `src/main.rs` here.

## Load

Requires CAP_BPF / root. The userspace agent will gain an optional `--features ebpf` loader that:

1. Loads the `.o` via Aya
2. Attaches the tracepoint (or LSM hook)
3. Exposes the HashMap for PID flagging

Until the loader is wired, run the userspace agent alone — it already performs graduated SIGSTOP/SIGKILL in process space.

## Next upgrades

1. LSM `path_rename` + write hooks → return `-EPERM` for Medium/Kill (preventive)
2. Ring buffer events back to userspace for audit
3. Short TTL eviction inside eBPF or via userspace sweep
4. cgroup scoping so only monitored workloads are covered
