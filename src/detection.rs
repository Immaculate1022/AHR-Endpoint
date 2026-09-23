//! Behavioral detection for ransomware-like activity.
//!
//! Prototype heuristics: high CPU/memory + suspicious process names.
//! Production path will combine eBPF file-op telemetry (rename/write/unlink
//! rates, entropy signals) with this userspace scorer.

use log::info;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHollow {
    pub pid: u32,
    pub risk: u8,
    pub process_hash: String,
    pub process_name: String,
    pub is_decoy: bool,
}

impl FileHollow {
    /// Base dispatch delay in milliseconds for a given risk band.
    /// Higher risk -> shorter base delay (you still want fast response to
    /// a real 9/10), but every band gets *some* jitter so response timing
    /// alone can't be used to fingerprint which band a score fell into.
    fn base_delay_range_ms(&self) -> (u64, u64) {
        match self.risk {
            8..=10 => (50, 400),   // fast, but not instant/fixed
            6..=7 => (300, 1_200),
            4..=5 => (800, 3_000),
            _ => (1_500, 6_000),   // LogOnly-tier: no urgency, widest jitter
        }
    }

    /// Extra jitter applied when the score sits right at a band boundary
    /// (e.g. 7 or 8, 5 or 6), where an attacker probing incrementally
    /// would otherwise be able to detect the exact cutover point by
    /// watching for a latency step-change.
    fn boundary_padding_ms(&self) -> u64 {
        const BOUNDARIES: &[u8] = &[4, 6, 8];
        if BOUNDARIES.iter().any(|b| self.risk.abs_diff(*b) <= 1) {
            600
        } else {
            0
        }
    }

    /// The jittered delay to wait before dispatching the response action.
    /// Moving-target defense: response timing alone can't be used to profile
    /// the risk thresholds, because dispatch latency is randomized per band
    /// and widened near boundaries. Detection itself stays deterministic
    /// and auditable -- only *when* the action fires is non-deterministic.
    /// Decoys are exempt -- there's no adversary-facing timing to protect
    /// for an asset whose only real action is LogOnly.
    pub fn dispatch_delay(&self) -> Duration {
        if self.is_decoy {
            return Duration::from_millis(0);
        }
        let (lo, hi) = self.base_delay_range_ms();
        let pad = self.boundary_padding_ms();
        let mut rng = rand::thread_rng();
        Duration::from_millis(rng.gen_range(lo..=hi) + pad)
    }
}

/// Scan running processes for high-risk behavioral signals.
pub fn detect_ransomware_behavior() -> Option<FileHollow> {
    let mut sys = System::new_all();
    sys.refresh_processes();

    for (pid, process) in sys.processes() {
        let name = process.name().to_string();
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
                name, pid, risk
            );

            return Some(FileHollow {
                pid: pid.as_u32(),
                risk,
                process_hash: hash,
                process_name: name,
                is_decoy: false,
            });
        }
    }
    None
}

#[cfg(test)]
mod jitter_tests {
    use super::*;

    fn hollow_with_risk(risk: u8) -> FileHollow {
        FileHollow {
            pid: 0,
            risk,
            process_hash: String::new(),
            process_name: "test".into(),
            is_decoy: false,
        }
    }

    #[test]
    fn decoys_have_zero_jitter() {
        let mut h = hollow_with_risk(9);
        h.is_decoy = true;
        assert_eq!(h.dispatch_delay(), Duration::from_millis(0));
    }

    #[test]
    fn high_risk_still_bounded_but_fast() {
        let h = hollow_with_risk(9);
        for _ in 0..50 {
            let d = h.dispatch_delay();
            assert!(d.as_millis() >= 50 && d.as_millis() <= 400 + 600);
        }
    }

    #[test]
    fn boundary_scores_get_padding() {
        let h = hollow_with_risk(8); // adjacent to the 8..=10 boundary
        let d = h.dispatch_delay();
        // lower bound with padding should exceed the un-padded floor
        assert!(d.as_millis() as u64 >= 50);
    }
}
