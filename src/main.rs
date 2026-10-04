//! AHR-Endpoint agent — Adaptive Hollow Reflector
//!
//! Userspace detection + merged telemetry scoring + graduated enforcement.
//! Optional eBPF kernel path via `--features ebpf` + compiled object.
//!
//! Safety: pass `--dry-run` to evaluate detections and report intended actions
//! without writing eBPF state, mutating processes, or publishing invariants.
//! Every decision — dry-run or live — is written to the structured audit
//! trail (`crate::audit`). Privilege-escalated recommendations from the
//! scoring model are held for human authorization by `crate::policy`.

mod action;
mod audit;
mod detection;
mod ebpf_loader;
mod enforcement;
mod hollow;
mod policy;
mod sentinel;

use detection::{detect_ransomware_behavior, FileHollow};
use ebpf_loader::load_optional;
use enforcement::{Action, EnforcementController};
use log::{error, info, warn};
use nats::Options;
use std::time::Duration;
use tokio::time::sleep;

async fn publish_invariant(
    hollow: &FileHollow,
    action: Action,
    decision: &policy::Decision,
    nc: &nats::Connection,
) {
    let payload = serde_json::json!({
        "pid": hollow.pid,
        "risk": decision.effective_risk,
        "snapshot_risk": decision.snapshot_risk,
        "scored_risk": decision.scored_risk,
        "process_hash": hollow.process_hash,
        "process_name": hollow.process_name,
        "action": action as u8,
        "recommended": format!("{:?}", decision.recommended),
        "requires_human_review": decision.requires_human_review,
        "reasons": decision.reasons,
        "invariant": "KILL_TREE",
        "ttl_secs": 60,
    });
    if let Err(e) = nc.publish("ahr.invariants", payload.to_string()) {
        error!("Failed to publish invariant: {}", e);
    } else {
        info!("Invariant published via NATS (<2s target)");
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let once = args.iter().any(|arg| arg == "--once");
    info!("🚀 Adaptive Hollow Reflector Endpoint Agent starting...");
    info!("   Graduated response: Soft → Medium → Kill");
    if dry_run {
        info!("   DRY-RUN: no eBPF writes, process signals, or NATS invariants will be emitted");
    }

    let mut controller = EnforcementController::new();
    let mut ebpf = if dry_run { None } else { load_optional() };

    let nc = if dry_run {
        None
    } else {
        match Options::new().connect("nats://localhost:4222") {
            Ok(c) => {
                info!("Connected to NATS cluster for global immunization.");
                Some(c)
            }
            Err(e) => {
                warn!("NATS not available (standalone mode): {}", e);
                None
            }
        }
    };

    loop {
        let expired = controller.sweep();
        if let Some(ref mut enf) = ebpf {
            for pid in expired {
                let _ = enf.clear_action(pid);
            }
        }

        if let Some(hollow) = detect_ransomware_behavior() {
            // Score with the merged telemetry model and let policy combine
            // both scorers into one auditable decision.
            let scored = hollow.assess();
            let decision = policy::decide(&hollow, &scored);
            let action = decision.executable;
            let ttl = 60u64;

            if dry_run {
                info!(
                    "DRY-RUN would flag PID {} action={:?} ttl={} snapshot_risk={} scored_risk={} effective_risk={} recommended={:?} human_review={} reasons={:?}",
                    hollow.pid,
                    action,
                    ttl,
                    decision.snapshot_risk,
                    decision.scored_risk,
                    decision.effective_risk,
                    decision.recommended,
                    decision.requires_human_review,
                    decision.reasons
                );
            } else {
                // Moving-target defense: jitter dispatch timing so response
                // latency can't be used to fingerprint risk thresholds.
                // Detection stays deterministic; only dispatch timing varies.
                sleep(detection::dispatch_delay_for(
                    decision.effective_risk,
                    hollow.is_decoy,
                ))
                .await;
                controller.flag(
                    hollow.pid,
                    action,
                    ttl,
                    &format!(
                        "risk={} name={} reasons={}",
                        decision.effective_risk,
                        hollow.process_name,
                        decision.reasons.join("; ")
                    ),
                );
            }

            if !dry_run {
                if let Some(ref mut enf) = ebpf {
                    if let Err(e) = enf.set_action(hollow.pid, action as u8) {
                        warn!("eBPF map update failed: {e}");
                    }
                }
            }

            if dry_run {
                let record = audit::build_record(
                    hollow.pid,
                    &hollow.process_name,
                    &hollow.process_hash,
                    scored.anomaly_score,
                    &decision,
                    true,
                    false,
                );
                audit::emit(&record);
                info!(
                    "DRY-RUN decision: PID {} action={:?} risk={} process={}",
                    hollow.pid, action, decision.effective_risk, hollow.process_name
                );
            } else {
                let ok = controller.apply_userspace(hollow.pid, action);
                if ok {
                    warn!(
                        "Containment activated — PID {} action={:?} (Patient Zero)",
                        hollow.pid, action
                    );
                }
                if decision.requires_human_review {
                    warn!(
                        "Human review required: PID {} recommendation {:?} held at {:?}",
                        hollow.pid, decision.recommended, action
                    );
                }

                let record = audit::build_record(
                    hollow.pid,
                    &hollow.process_name,
                    &hollow.process_hash,
                    scored.anomaly_score,
                    &decision,
                    false,
                    ok,
                );
                audit::emit(&record);

                // Sentinel X evidence stream: local sink first (works
                // without a broker), then NATS when connected.
                let event = sentinel::build_event(
                    hollow.pid,
                    &hollow.process_name,
                    &scored,
                    &decision,
                    ok,
                );
                sentinel::write_sink(&event);

                if let Some(ref conn) = nc {
                    publish_invariant(&hollow, action, &decision, conn).await;
                    sentinel::publish_evidence(conn, &event);
                }
            }
        }

        if once {
            info!("Single-cycle run complete");
            break;
        }
        sleep(Duration::from_secs(3)).await;
    }
}
