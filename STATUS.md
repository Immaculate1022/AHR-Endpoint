# AHR-Endpoint — status

**Version:** 0.3.0  
**Updated:** 2026-10-04

## Public boundary

Research prototype. Userspace Rust agent with optional Aya/eBPF loader path and experimental enforcement scaffolding. Does **not** claim measured sub-second containment, production readiness, or universal ransomware detection.

## Working today

- Userspace agent loop with process-name + resource-pressure heuristics (`src/detection.rs`)
- Merged version 06 telemetry scoring model in the active engine (`src/hollow.rs`): weighted signal scoring with human-readable `score_reasons`, decoy suppression, injection-API weighting, privilege-aware recommendations, and companion actions — unit-tested in the crate
- Decision policy layer (`src/policy.rs`): effective risk is the more severe of the detector ladder and the telemetry score, both kept in the audit record; privilege-escalated recommendations (session revocation, host isolation, MFA reprompt) are held at suspend pending human authorization, never auto-executed
- Structured audit logging (`src/audit.rs`): one JSON record per decision, optionally appended as JSONL via `AHR_AUDIT_LOG`
- Sentinel X evidence stream (`src/sentinel.rs`): decisions emitted as evidence events on the `sentinelx.evidence` NATS subject and/or a local JSONL sink (`AHR_SENTINELX_SINK`)
- Graduated response scaffolding (observe / suspend / isolate / terminate concepts)
- Process-tree controls with basic whitelist considerations
- Optional NATS dependency for cross-host signaling (development scaffolding only)
- Optional Aya loader path under `--features ebpf` with graceful fallback
- Source-level dry-run audit script: `python3 scripts/dry_run_audit.py`
- Archived research scoring candidates under `docs/archive/` (versions 05/06; version 06 merged into the active engine 2026-10-04, archive retained for provenance)

## Not established yet

- Validated behavioral-detection benchmarks or false-positive rates
- Safe default dry-run mode as the primary runtime posture for all consequential actions
- Production host isolation, session revocation, or network quarantine behavior (the scoring model recommends them; the engine records the recommendation and holds for human authorization — it does not perform them)
- Reproducible in-repo BPF object / CI artifact for the kernel path
- LSM deny path and measured end-to-end containment timing
- Rich file-telemetry population of the scoring model (entropy, write velocity, rename bursts); today the bridge carries only signals the userspace detector observes

## Suggested next engineering steps

1. Keep dry-run / log-only as the default posture for any demo path
2. Populate the merged scoring model from real file telemetry (eBPF path) instead of name/pressure bridges
3. Write at least one integration test that exercises detection without mutating processes
4. False-positive review of the merged scorer against benign process corpora
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
