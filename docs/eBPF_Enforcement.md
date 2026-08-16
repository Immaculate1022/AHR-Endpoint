# AHR eBPF Kernel Enforcement

**Status:** v0.2.1 — userspace graduated response + Aya loader wired  
**Owner:** Gregory Scott Davis / PegaConstellation  
**License:** IOF Attribution License v1.0

---

## Goal

Move containment from a ~3 s userspace poll loop to microsecond-scale kernel enforcement so ransomware cannot complete bulk encryption after Patient Zero is scored.

## Architecture

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│  Userspace agent        │         │  eBPF (Aya)                  │
│  detection.rs           │  flag   │  ACTION_MAP: tgid → u8       │
│  enforcement.rs         │ ──────► │  0 Allow / 1 Soft / 2 Med /  │
│  ebpf_loader.rs         │ insert  │  3 Kill                      │
│  risk → Action          │         │  bpf_send_signal(SIGKILL)    │
│  SIGSTOP / SIGKILL tree │         │  attach: sys_enter_openat    │
│  NATS invariant publish │         │  (future: LSM -EPERM)        │
└─────────────────────────┘         └──────────────────────────────┘
```

## Graduated response

| Risk | Action | Userspace | Kernel |
|-----:|--------|-----------|--------|
| 0–3 | Allow | — | — |
| 4–6 | Soft | SIGSTOP | map write (no kill) |
| 7–8 | Medium | SIGSTOP tree | map write |
| 9–10 | Kill | SIGKILL tree | map write + `bpf_send_signal(9)` |

Whitelist always includes PID 1 and the agent itself.

## Loader (`src/ebpf_loader.rs`)

```bash
cargo build --release --features ebpf
sudo RUST_LOG=info ./target/release/ahr-endpoint
```

1. Raises `RLIMIT_MEMLOCK` (older kernels)
2. Resolves object path (`AHR_EBPF_OBJECT` or defaults)
3. `Ebpf::load_file`
4. Attaches `TracePoint` program `sys_enter_openat` on `syscalls/sys_enter_openat`
5. Exposes `set_action(tgid, action)` → `ACTION_MAP.insert`

If load fails, the agent logs and continues in userspace-only mode.

## Implementation checklist

### Done (v0.2.1)

- [x] `enforcement::Action` + risk mapping
- [x] Userspace SIGSTOP / process-tree SIGKILL
- [x] TTL-flagged PID set + sweep
- [x] NATS invariant includes action code
- [x] `ebpf/` Aya skeleton with ACTION_MAP + signal path
- [x] **Aya userspace loader** (`--features ebpf`)
- [x] Dual-path: map write then userspace signals

### Next

- [ ] Produce a reproducible BPF object via xtask / CI artifact
- [ ] LSM hooks: `path_rename`, write-related → `-EPERM` for Medium/Kill
- [ ] Ringbuf audit events back to userspace
- [ ] Map TTL eviction from userspace sweep (`clear_action`)
- [ ] Integration tests under QEMU with sample encryptor

## Safety

- Never flag PID 1 or self
- Prefer Soft/Medium before Kill
- Short TTLs (default 60 s)
- All enforcements logged; NATS carries the same decision for peer hosts
- Loader failure is non-fatal

## References

- Aya book: https://aya-rs.dev/book/
- `bpf_send_signal` — kernel ≥ 5.3
- LSM BPF — kernel ≥ 5.7
