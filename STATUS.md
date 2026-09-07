# AHR-Endpoint — status

**Version:** 0.2.1  
**Updated:** 2026-09-07

## Public boundary

Research prototype. Userspace Rust agent with optional Aya/eBPF loader path and experimental enforcement scaffolding. Does **not** claim measured sub-second containment, production readiness, or universal ransomware detection.

## Working today

- Userspace agent loop with process-name + resource-pressure heuristics (`src/detection.rs`)
- Graduated response scaffolding (observe / suspend / isolate / terminate concepts)
- Process-tree controls with basic whitelist considerations
- Optional NATS dependency for cross-host signaling (development scaffolding only)
- Optional Aya loader path under `--features ebpf` with graceful fallback
- Source-level dry-run audit script: `python3 scripts/dry_run_audit.py`
- Archived research scoring candidates under `docs/archive/` (not in the active engine)

## Not established yet

- Validated behavioral-detection benchmarks or false-positive rates
- Safe default dry-run mode as the primary runtime posture for all consequential actions
- Production host isolation, session revocation, or network quarantine behavior
- Reproducible in-repo BPF object / CI artifact for the kernel path
- LSM deny path and measured end-to-end containment timing
- Merge of archived scoring modules (versions 05/06) into the active engine

## Suggested next engineering steps

1. Keep dry-run / log-only as the default posture for any demo path
2. Add structured audit logging around detection → action decisions
3. Write at least one integration test that exercises detection without mutating processes
4. Merge or drop archived scoring candidates only after compatibility tests and explicit authorization gates
5. Treat kernel/eBPF work as optional and secondary until userspace safety rails are solid

## Run (prototype)

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint
cargo build --release
RUST_LOG=info ./target/release/ahr-endpoint

# safety audit (does not launch the agent)
python3 scripts/dry_run_audit.py

# optional kernel path (Linux only; requires privileges and toolchain)
cargo build --release --features ebpf
bash scripts/setup_ebpf.sh
sudo RUST_LOG=info ./target/release/ahr-endpoint
```

Exercise only in an isolated test environment. Do not point this agent at production endpoints until detection thresholds, response policy, audit trail, and rollback behavior have been reviewed.

## Related

- [README](README.md) — primary public description and prototype boundary
- [PegaConstellation Hub STATUS](https://github.com/Immaculate1022/pegaconstellation-hub/blob/main/STATUS.md)
- [docs/archive/](docs/archive/) — unmerged research candidates

---

*Part of the Infinite Optical Fabric / PegaConstellation research constellation.*
