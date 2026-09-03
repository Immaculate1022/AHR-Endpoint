// ARCHIVAL CANDIDATE — NOT MERGED OR VALIDATED
// Source: Pasted_content_05.txt supplied by the project author on 2026-09-03.
// This module is preserved for review. It requires integration with the repository’s actual detection and action contracts before use.
// engine/src/hollow.rs
/*
 * Adaptive Hollow Reflector - Endpoint Edition
 * Copyright 2026 Gregory Scott Davis
 * Licensed under the Apache License, Version 2.0
 */

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserPrivilege {
    Standard,
    Admin,
    DomainAdmin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EndpointAction {
    LogOnly,
    SuspendProc,
    KillTree,
    IsolateHost,
    SnapshotLock,
    Sinkhole,
    RevokeSession,
    TriggerMfaReprompt,
    SendSocWebhook,
    FlagForHumanReview,
    // New: More aggressive options
    QuarantineFile,
    MemoryDump,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHollow {
    // Core AHR fields
    pub proc_hash: String,           // sha256(exe_path + cmdline + parent)
    pub entropy_delta: f32,          // avg entropy of last 50 writes
    pub write_velocity: u32,         // files/sec
    pub rename_burst: bool,          // mass .docx -> .lockbit
    pub backup_tamper: bool,         // vssadmin, wmic shadowcopy delete
    pub c2_contact: bool,            // outbound to .onion, mega.nz
    pub decoy_touched: bool,         // hit honeypot dir
    pub risk_score: u8,              // 1-10
    pub last_seen: u64,              // unix timestamp
    pub is_decoy: bool,

    // META ADDITIONS by Gregory Scott Davis
    pub peer_risk: f32,              // Jaccard similarity to LockBit, BlackCat, REvil
    pub propagation_score: u32,      // # adjacent endpoints with same proc_hash in 60s
    pub mitre_ttp: Vec<String>,      // T1486 (Encrypt), T1490 (VSS), T1048 (Exfil)
    pub threat_intel_match: bool,    // VirusTotal/Meta internal hash DB hit
    pub user_privilege: UserPrivilege,
    pub geo_fencing_risk: bool,      // Login from anomalous ASN during business hours
    pub clipboard_monitor: bool,     // Detected crypto wallet address replacement

    // New fields I added
    pub process_tree_depth: u16,
    pub suspicious_imports: HashSet<String>, // e.g., "VirtualAllocEx", "WriteProcessMemory"
    pub signed_status: bool,
    pub injected_dll_count: u8,
    pub anomaly_score: f32,          // 0.0 - 1.0 normalized composite score
}

impl FileHollow {
    pub fn new(proc_hash: String) -> Self {
        Self {
            proc_hash,
            entropy_delta: 0.0,
            write_velocity: 0,
            rename_burst: false,
            backup_tamper: false,
            c2_contact: false,
            decoy_touched: false,
            risk_score: 1,
            last_seen: 0,
            is_decoy: false,
            peer_risk: 0.0,
            propagation_score: 0,
            mitre_ttp: Vec::new(),
            threat_intel_match: false,
            user_privilege: UserPrivilege::Standard,
            geo_fencing_risk: false,
            clipboard_monitor: false,
            process_tree_depth: 0,
            suspicious_imports: HashSet::new(),
            signed_status: false,
            injected_dll_count: 0,
            anomaly_score: 0.0,
        }
    }

    /// Recalculate overall risk score based on all signals
    pub fn update_risk_score(&mut self) {
        let mut score = 1u8;

        if self.entropy_delta > 0.7 { score += 3; }
        if self.write_velocity > 50 { score += 2; }
        if self.rename_burst { score += 2; }
        if self.backup_tamper { score += 3; }
        if self.c2_contact { score += 3; }
        if self.decoy_touched { score += 2; }
        if self.peer_risk > 0.6 { score += 2; }
        if self.propagation_score > 3 { score += 2; }
        if self.threat_intel_match { score += 3; }
        if self.geo_fencing_risk { score += 1; }
        if self.clipboard_monitor { score += 1; }
        if self.injected_dll_count > 2 { score += 2; }

        self.risk_score = score.clamp(1, 10);
        self.anomaly_score = self.risk_score as f32 / 10.0;
    }

    /// Decide recommended action based on risk
    pub fn recommended_action(&self) -> EndpointAction {
        match self.risk_score {
            8..=10 => EndpointAction::KillTree,
            6..=7 => EndpointAction::IsolateHost,
            4..=5 => EndpointAction::SuspendProc,
            _ => EndpointAction::LogOnly,
        }
    }

    /// Check if this matches a specific MITRE TTP
    pub fn has_ttp(&self, ttp: &str) -> bool {
        self.mitre_ttp.iter().any(|t| t == ttp)
    }

    /// Quick threat summary for logging/UI
    pub fn summary(&self) -> String {
        format!(
            "FileHollow[{}] Risk:{} Anomaly:{:.2} TTPs:{}",
            self.proc_hash.chars().take(8).collect::<String>(),
            self.risk_score,
            self.anomaly_score,
            self.mitre_ttp.len()
        )
    }
}
