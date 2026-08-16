# AHR eBPF Kernel Enforcement

**Status:** v0.2 — userspace graduated response live; eBPF program skeleton ready  
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
│  risk → Action          │         │  3 Kill                      │
│  SIGSTOP / SIGKILL tree │         │  bpf_send_signal(SIGKILL)    │
│  NATS invariant publish │         │  (future: LSM -EPERM)        │
└─────────────────────────┘         └──────────────────────────────┘
```

## Graduated response

| Risk | Action | Userspace | Kernel (target) |
|-----:|--------|-----------|-----------------|
| 0–3 | Allow | — | — |
| 4–6 | Soft | SIGSTOP | log / rate-limit |
| 7–8 | Medium | SIGSTOP tree | LSM deny rename/write |
| 9–10 | Kill | SIGKILL tree | `bpf_send_signal(9)` |

Whitelist always includes PID 1 and the agent itself.

## Implementation phases

### Done (v0.2)

- [x] `enforcement::Action` + risk mapping
- [x] Userspace SIGSTOP / process-tree SIGKILL
- [x] TTL-flagged PID set + sweep
- [x] NATS invariant includes action code
- [x] `ebpf/` Aya skeleton with ACTION_MAP + signal path
- [x] Design doc (this file)

### Next

- [ ] Full Aya workspace (common types shared with userspace)
- [ ] Userspace loader (`--features ebpf`) that pins maps and attaches programs
- [ ] LSM hooks: `path_rename`, write-related file hooks → `-EPERM`
- [ ] Ringbuf audit events
- [ ] Integration tests under QEMU / nested VM with sample encryptor

## Safety

- Never flag PID 1 or self
- Prefer Soft/Medium before Kill
- Short TTLs (default 60 s) match ephemeral invariants
- All enforcements logged; NATS carries the same decision for peer hosts

## References

- Aya book: https://aya-rs.dev/book/
- `bpf_send_signal` — kernel ≥ 5.3
- LSM BPF — kernel ≥ 5.7
- Prior art: LARM, ROFBS, Tetragon-style runtime enforcement
