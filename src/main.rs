//! AHR-Endpoint agent — Adaptive Hollow Reflector
//!
//! Userspace detection + graduated enforcement (SIGSTOP / process-tree SIGKILL).
//! eBPF kernel enforcement lives in `ebpf/` and is loaded when available.

mod detection;
mod enforcement;

use detection::{detect_ransomware_behavior, FileHollow};
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
    info!("   Graduated response: Soft → Medium → Kill (userspace + eBPF-ready)");

    let mut controller = EnforcementController::new();

    // Optional NATS for global propagation
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

    // Main detection + enforcement loop
    loop {
        controller.sweep();

        if let Some(hollow) = detect_ransomware_behavior() {
            let action = EnforcementController::action_for_risk(hollow.risk);
            let ttl = 60u64;

            controller.flag(
                hollow.pid,
                action,
                ttl,
                &format!("risk={} name={}", hollow.risk, hollow.process_name),
            );

            // Userspace enforcement (always available)
            let ok = controller.apply_userspace(hollow.pid, action);
            if ok {
                warn!(
                    "Containment activated — PID {} action={:?} (Patient Zero)",
                    hollow.pid, action
                );
            }

            // Global propagation
            if let Some(ref conn) = nc {
                publish_invariant(&hollow, action, conn).await;
            }

            // NOTE: When eBPF is loaded, also write (pid, action) into the
            // kernel HashMap so LSM / bpf_send_signal enforce in-kernel.
            // See docs/eBPF_Enforcement.md and ebpf/
        }

        sleep(Duration::from_secs(3)).await;
    }
}
