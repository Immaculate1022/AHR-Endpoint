//! AHR-Endpoint agent — Adaptive Hollow Reflector
//!
//! Userspace detection + graduated enforcement.
//! Optional eBPF kernel path via `--features ebpf` + compiled object.

mod action;
mod detection;
mod ebpf_loader;
mod enforcement;

use detection::{detect_ransomware_behavior, FileHollow};
use ebpf_loader::load_optional;
use enforcement::{Action, EnforcementController};
use log::{error, info, warn};
use nats::Options;
use std::time::Duration;
use tokio::time::sleep;

async fn publish_invariant(hollow: &FileHollow, action: Action, nc: &nats::Connection) {
    let payload = serde_json::json!({
        "pid": hollow.pid,
        "risk": hollow.risk,
        "process_hash": hollow.process_hash,
        "process_name": hollow.process_name,
        "action": action as u8,
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
    info!("🚀 Adaptive Hollow Reflector Endpoint Agent starting...");
    info!("   Graduated response: Soft → Medium → Kill");

    let mut controller = EnforcementController::new();
    let mut ebpf = load_optional();

    let nc = match Options::new().connect("nats://localhost:4222") {
        Ok(c) => {
            info!("Connected to NATS cluster for global immunization.");
            Some(c)
        }
        Err(e) => {
            warn!("NATS not available (standalone mode): {}", e);
            None
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
            let action = EnforcementController::action_for_risk(hollow.risk);
            let ttl = 60u64;

            controller.flag(
                hollow.pid,
                action,
                ttl,
                &format!("risk={} name={}", hollow.risk, hollow.process_name),
            );

            if let Some(ref mut enf) = ebpf {
                if let Err(e) = enf.set_action(hollow.pid, action as u8) {
                    warn!("eBPF map update failed: {e}");
                }
            }

            let ok = controller.apply_userspace(hollow.pid, action);
            if ok {
                warn!(
                    "Containment activated — PID {} action={:?} (Patient Zero)",
                    hollow.pid, action
                );
            }

            if let Some(ref conn) = nc {
                publish_invariant(&hollow, action, conn).await;
            }
        }

        sleep(Duration::from_secs(3)).await;
    }
}
