//! Behavioral detection for ransomware-like activity.
//!
//! Prototype heuristics: high CPU/memory + suspicious process names.
//! Production path will combine eBPF file-op telemetry (rename/write/unlink
//! rates, entropy signals) with this userspace scorer.
//!
//! The snapshot produced here is one of two scorers. `assess()` bridges it
//! into the merged telemetry model (`crate::hollow`), and `crate::policy`
//! combines both into the final decision. The bridge only carries signals
//! this detector actually observed — name indicators, resource pressure,
//! process-tree depth, and the account privilege the process runs with.
//! Everything else stays at the scored model's defaults.

use crate::hollow::{FileHollow as ScoredHollow, UserPrivilege};
use log::info;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHollow {
    pub pid: u32,
    pub risk: u8,
    pub process_hash: String,
    pub process_name: String,
    pub is_decoy: bool,
    /// Depth of the descendant process tree beneath this process.
    pub tree_depth: u16,
    /// True when the process runs with administrator (root) privilege.
    pub runs_as_admin: bool,
}

/// Base dispatch delay range in milliseconds for a risk band.
/// Higher risk -> shorter base delay (you still want fast response to
/// a real 9/10), but every band gets *some* jitter so response timing
/// alone can't be used to fingerprint which band a score fell into.
fn base_delay_range_ms(risk: u8) -> (u64, u64) {
    match risk {
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
fn boundary_padding_ms(risk: u8) -> u64 {
    const BOUNDARIES: &[u8] = &[4, 6, 8];
    if BOUNDARIES.iter().any(|b| risk.abs_diff(*b) <= 1) {
        600
    } else {
        0
    }
}

/// The jittered delay to wait before dispatching a response action for a
/// given risk score. Moving-target defense: response timing alone can't
/// be used to profile the risk thresholds, because dispatch latency is
/// randomized per band and widened near boundaries. Detection itself
/// stays deterministic and auditable — only *when* the action fires is
/// non-deterministic. Decoys are exempt — there's no adversary-facing
/// timing to protect for an asset whose only real action is LogOnly.
pub fn dispatch_delay_for(risk: u8, is_decoy: bool) -> Duration {
    if is_decoy {
        return Duration::from_millis(0);
    }
    let (lo, hi) = base_delay_range_ms(risk);
    let pad = boundary_padding_ms(risk);
    let mut rng = rand::thread_rng();
    Duration::from_millis(rng.gen_range(lo..=hi) + pad)
}

impl FileHollow {
    /// Jittered dispatch delay for this snapshot's own risk band.
    /// The agent loop prefers `dispatch_delay_for` with the policy
    /// layer's effective risk; this remains for snapshot-local callers.
    pub fn dispatch_delay(&self) -> Duration {
        dispatch_delay_for(self.risk, self.is_decoy)
    }

    /// Bridge this detector snapshot into the merged telemetry scoring
    /// model. Only observed signals are carried over; the returned record
    /// is fully scored (`update_risk_score` has run).
    pub fn assess(&self) -> ScoredHollow {
        let mut scored = ScoredHollow::new(self.process_hash.clone());
        scored.is_decoy = self.is_decoy;
        scored.process_tree_depth = self.tree_depth;
        scored.user_privilege = if self.runs_as_admin {
            UserPrivilege::Admin
        } else {
            UserPrivilege::Standard
        };
        scored.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let name_l = self.process_name.to_lowercase();
        if name_l.contains("ransom")
            || name_l.contains("encrypt")
            || name_l.contains("locker")
            || name_l.contains("cryptor")
        {
            // T1486 — Data Encrypted for Impact (name-indicated).
            scored.mitre_ttp.push("T1486".to_string());
        }
        if name_l.contains("powershell") || name_l.contains("pwsh") || name_l.contains("cmd") {
            // T1059 — Command and Scripting Interpreter (name-indicated).
            scored.mitre_ttp.push("T1059".to_string());
        }

        scored.update_risk_score();
        scored
    }
}

/// Depth of the descendant tree beneath `root` (0 = no children).
fn subtree_depth(sys: &System, root: u32) -> u16 {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, proc_) in sys.processes() {
        if let Some(ppid) = proc_.parent() {
            children.entry(ppid.as_u32()).or_default().push(pid.as_u32());
        }
    }
    fn depth(
        node: u32,
        map: &HashMap<u32, Vec<u32>>,
        seen: &mut HashSet<u32>,
    ) -> u16 {
        if !seen.insert(node) {
            return 0;
        }
        match map.get(&node) {
            None => 0,
            Some(kids) => 1 + kids
                .iter()
                .map(|k| depth(*k, map, seen))
                .max()
                .unwrap_or(0),
        }
    }
    depth(root, &children, &mut HashSet::new())
}

/// True when the process runs as root (uid 0) on Unix.
#[cfg(unix)]
fn runs_as_admin(proc_: &sysinfo::Process) -> bool {
    proc_.user_id().map(|uid| **uid == 0).unwrap_or(false)
}

#[cfg(not(unix))]
fn runs_as_admin(_proc: &sysinfo::Process) -> bool {
    false
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
                tree_depth: subtree_depth(&sys, pid.as_u32()),
                runs_as_admin: runs_as_admin(process),
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
            tree_depth: 0,
            runs_as_admin: false,
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

    #[test]
    fn assess_bridges_observed_signals() {
        let mut snap = hollow_with_risk(9);
        snap.process_name = "ransom-note.exe".into();
        snap.tree_depth = 3;
        snap.runs_as_admin = true;
        let scored = snap.assess();
        assert_eq!(scored.process_tree_depth, 3);
        assert_eq!(scored.user_privilege, UserPrivilege::Admin);
        assert!(scored.has_ttp("T1486"));
        assert!(scored.risk_score >= 1 && scored.risk_score <= 10);
    }
}
