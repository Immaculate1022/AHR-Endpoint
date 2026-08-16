# AHR-Endpoint — status

**Version:** 0.2.1  
**Updated:** 2026-08-15

## Working today

- Userspace agent: detection → graduated Soft/Medium/Kill
- Process-tree SIGSTOP / SIGKILL with PID 1 + self whitelist
- Optional NATS invariant publish
- Aya **loader** (`--features ebpf`): load object, attach tracepoint, write `ACTION_MAP`
- Graceful fallback if object missing or not root

## Not working yet (honest)

- No reproducible BPF **object** in-repo (needs full Aya workspace / xtask on Linux)
- LSM `-EPERM` path not implemented (signal-only kernel sketch)
- No CI artifact for `ahr-ebpf.o`

## Suggested next engineering steps

1. Generate Aya template workspace; merge `ebpf/src/main.rs` logic  
2. Wire `clear_action` on TTL sweep  
3. Add LSM `path_rename` deny for Medium/Kill  
4. Minimal QEMU/test harness with a toy high-entropy writer  

## Run

```bash
cargo build --release
RUST_LOG=info ./target/release/ahr-endpoint

# kernel path (Linux)
cargo build --release --features ebpf
sudo AHR_EBPF_OBJECT=./ahr-ebpf.o RUST_LOG=info ./target/release/ahr-endpoint
```
