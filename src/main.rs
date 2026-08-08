use std::process;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, System};
use sha2::{Sha256, Digest};
use rand::Rng;
use tokio::time::sleep;
use nats::Options;
use log::{info, warn, error};

#[derive(Debug)]
struct FileHollow {
    risk: u8,
    process_hash: String,
}

async fn detect_ransomware_behavior() -> Option<FileHollow> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    for (pid, process) in sys.processes() {
        // Simulate high-entropy writes + suspicious behavior
        if process.cpu_usage() > 50.0 || process.memory() > 1_000_000_000 {
            let name = process.name().to_string_lossy();
            if name.contains("cmd") || name.contains("powershell") || name.contains("ransom") {
                let mut hasher = Sha256::new();
                hasher.update(name.as_bytes());
                let hash = format!("{:x}", hasher.finalize());

                info!("Potential ransomware detected in {} (PID: {})", name, pid);
                return Some(FileHollow {
                    risk: 9,
                    process_hash: hash,
                });
            }
        }
    }
    None
}

async fn drop_invariant(hollow: &FileHollow) {
    info!("Dropping 60s KILL_TREE invariant for hash: {}", hollow.process_hash);
    // In real impl: enforce via kernel hooks / eBPF / driver
    sleep(Duration::from_secs(60)).await; // Simulate TTL
}

async fn publish_invariant(hollow: &FileHollow, nc: &nats::Connection) {
    let payload = serde_json::to_string(hollow).unwrap();
    if let Err(e) = nc.publish("ahr.invariants", payload) {
        error!("Failed to publish invariant: {}", e);
    } else {
        info!("Invariant published globally via NATS (<2s target)");
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("🚀 Adaptive Hollow Reflector Endpoint Agent starting...");

    // Connect to NATS for global propagation (configure your server)
    let nc = match Options::new().connect("nats://localhost:4222") {
        Ok(c) => c,
        Err(e) => {
            warn!("NATS not available (dev mode): {}", e);
            // Continue in standalone mode
            loop {
                if let Some(hollow) = detect_ransomware_behavior().await {
                    drop_invariant(&hollow).await;
                }
                sleep(Duration::from_secs(5)).await;
            }
        }
    };

    info!("Connected to NATS cluster for global immunization.");

    // Main detection loop
    loop {
        if let Some(hollow) = detect_ransomware_behavior().await {
            drop_invariant(&hollow).await;
            publish_invariant(&hollow, &nc).await;

            // Graduated response simulation
            warn!("Containment activated - Patient Zero contained.");
        }

        sleep(Duration::from_secs(3)).await; // Fast polling
    }
}