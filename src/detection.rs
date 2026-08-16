//! Behavioral detection for ransomware-like activity.
//!
//! Prototype heuristics: high CPU/memory + suspicious process names.
//! Production path will combine eBPF file-op telemetry (rename/write/unlink
//! rates, entropy signals) with this userspace scorer.

use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::{ProcessesToUpdate, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHollow {
    pub pid: u32,
    pub risk: u8,
    pub process_hash: String,
    pub process_name: String,
}

/// Scan running processes for high-risk behavioral signals.
pub fn detect_ransomware_behavior() -> Option<FileHollow> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_string();
        let name_l = name.to_lowercase();

        // Suspicious name indicators (prototype)
        let name_hit = name_l.contains("ransom")
            || name_l.contains("encrypt")
            || name_l.contains("locker")
            || name_l.contains("cryptor")
            || name_l.contains("cmd")
            || name_l.contains("powershell")
            || name_l.contains("pwsh");

        // Resource pressure indicators
        let cpu_hot = process.cpu_usage() > 40.0;
        let mem_hot = process.memory() > 500_000_000; // ~500 MB

        if name_hit && (cpu_hot || mem_hot) {
            let mut hasher = Sha256::new();
            hasher.update(name.as_bytes());
            hasher.update(pid.as_u32().to_le_bytes());
            let hash = format!("{:x}", hasher.finalize());

            let mut risk: u8 = 5;
            if name_l.contains("ransom") || name_l.contains("encrypt") {
                risk = 9;
            } else if cpu_hot && mem_hot {
                risk = 8;
            } else if name_hit {
                risk = 7;
            }

            info!(
                "Potential ransomware signal: {} (PID {}) risk={}",
                name,
                pid,
                risk
            );

            return Some(FileHollow {
                pid: pid.as_u32(),
                risk,
                process_hash: hash,
                process_name: name,
            });
        }
    }
    None
}
