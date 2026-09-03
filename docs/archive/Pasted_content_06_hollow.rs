// ARCHIVAL CANDIDATE — UPDATED, NOT MERGED OR VALIDATED
// Source: Pasted_content_06.txt supplied by the project author on 2026-09-03.
// This version supersedes Pasted_content_05_hollow.rs for review purposes. It requires integration with the repository’s actual detection and action contracts before use.
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
    QuarantineFile,
    MemoryDump,
}

/// Known-suspicious Windows API imports commonly seen in process
/// injection / credential theft chains. Not exhaustive — tune per telemetry.
const INJECTION_APIS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetThreadContext",
    "QueueUserAPC",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHollow {
    pub proc_hash: String,
    pub entropy_delta: f32,
    pub write_velocity: u32,
    pub rename_burst: bool,
    pub backup_tamper: bool,
    pub c2_contact: bool,
    pub decoy_touched: bool,
    pub risk_score: u8,
    pub last_seen: u64,
    pub is_decoy: bool,

    pub peer_risk: f32,
    pub propagation_score: u32,
    pub mitre_ttp: Vec<String>,
    pub threat_intel_match: bool,
    pub user_privilege: UserPrivilege,
    pub geo_fencing_risk: bool,
    pub clipboard_monitor: bool,

    pub process_tree_depth: u16,
    pub suspicious_imports: HashSet<String>,
    pub signed_status: bool,
    pub injected_dll_count: u8,
    pub anomaly_score: f32,

    /// Human-readable reasons behind the last risk_score computation.
    /// Populated by update_risk_score(); useful for SOC-facing logs/UI
    /// so an analyst isn't left guessing why a score fired.
    #[serde(default)]
    pub score_reasons: Vec<String>,
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
            score_reasons: Vec::new(),
        }
    }

    /// Recalculate overall risk score based on all signals.
    ///
    /// Two changes from the original:
    /// 1. Decoy processes never escalate — a honeypot doing exactly what
    ///    it was built to do (getting touched) shouldn't self-trigger a
    ///    KillTree/IsolateHost response. We still record the touch signal
    ///    for correlation, but the score is capped low.
    /// 2. `signed_status` and `suspicious_imports` now actually feed the
    ///    score — previously captured but unused.
    pub fn update_risk_score(&mut self) {
        self.score_reasons.clear();

        if self.is_decoy {
            // A decoy's own hollow being scored high has no operational
            // meaning — it's not something you isolate a host over.
            self.risk_score = 1;
            self.anomaly_score = 0.1;
            self.score_reasons
                .push("is_decoy: score suppressed (honeypot asset)".into());
            return;
        }

        let mut score: i16 = 1;
        let mut add = |points: i16, reason: &str, reasons: &mut Vec<String>| {
            score += points;
            reasons.push(format!("{reason} (+{points})"));
        };

        if self.entropy_delta > 0.7 {
            add(3, "high write entropy (mass encryption pattern)", &mut self.score_reasons);
        }
        if self.write_velocity > 50 {
            add(2, "abnormal write velocity", &mut self.score_reasons);
        }
        if self.rename_burst {
            add(2, "mass rename burst", &mut self.score_reasons);
        }
        if self.backup_tamper {
            add(3, "shadow copy / backup tampering", &mut self.score_reasons);
        }
        if self.c2_contact {
            add(3, "outbound C2 contact", &mut self.score_reasons);
        }
        if self.decoy_touched {
            add(2, "honeypot directory touched", &mut self.score_reasons);
        }
        if self.peer_risk > 0.6 {
            add(2, "high similarity to known ransomware families", &mut self.score_reasons);
        }
        if self.propagation_score > 3 {
            add(2, "propagating to adjacent endpoints", &mut self.score_reasons);
        }
        if self.threat_intel_match {
            add(3, "threat intel hash match", &mut self.score_reasons);
        }
        if self.geo_fencing_risk {
            add(1, "anomalous login geo/ASN", &mut self.score_reasons);
        }
        if self.clipboard_monitor {
            add(1, "clipboard wallet-swap behavior", &mut self.score_reasons);
        }
        if self.injected_dll_count > 2 {
            add(2, "multiple injected DLLs", &mut self.score_reasons);
        }

        // New: unsigned binary is a mild signal on its own, but unsigned
        // + injection-capable imports together is a much stronger tell
        // than either alone, so it's weighted as a combined case.
        let has_injection_api = self
            .suspicious_imports
            .iter()
            .any(|i| INJECTION_APIS.contains(&i.as_str()));

        match (self.signed_status, has_injection_api) {
            (false, true) => add(
                3,
                "unsigned binary using process-injection APIs",
                &mut self.score_reasons,
            ),
            (false, false) => add(1, "unsigned binary", &mut self.score_reasons),
            (true, true) => add(
                1,
                "signed binary using process-injection APIs (still notable)",
                &mut self.score_reasons,
            ),
            (true, false) => {}
        }

        // Deep process trees (living-off-the-land chains) get a small bump.
        if self.process_tree_depth > 6 {
            add(1, "unusually deep process tree", &mut self.score_reasons);
        }

        self.risk_score = score.clamp(1, 10) as u8;
        self.anomaly_score = self.risk_score as f32 / 10.0;
    }

    /// Decide recommended action based on risk *and* the privilege context
    /// of the account the process is running as. A domain admin session
    /// hijack is a case where killing the process tree may be less useful
    /// than immediately revoking the session and forcing re-auth — you
    /// want the attacker locked out, not just the process reaped while
    /// the token is still live elsewhere.
    pub fn recommended_action(&self) -> EndpointAction {
        if self.is_decoy {
            return EndpointAction::LogOnly;
        }

        match (self.risk_score, &self.user_privilege) {
            (8..=10, UserPrivilege::DomainAdmin) => EndpointAction::RevokeSession,
            (8..=10, UserPrivilege::Admin) => EndpointAction::IsolateHost,
            (8..=10, UserPrivilege::Standard) => EndpointAction::KillTree,

            (6..=7, UserPrivilege::DomainAdmin) => EndpointAction::TriggerMfaReprompt,
            (6..=7, _) => EndpointAction::IsolateHost,

            (4..=5, _) => EndpointAction::SuspendProc,

            _ => EndpointAction::LogOnly,
        }
    }

    /// Secondary actions worth firing alongside the primary recommendation
    /// — e.g. a KillTree should usually also ship a SOC webhook and queue
    /// the binary for review, but the original API only ever returned one
    /// action, forcing callers to hand-roll this logic themselves.
    pub fn companion_actions(&self) -> Vec<EndpointAction> {
        let mut actions = Vec::new();
        if self.is_decoy {
            return actions;
        }
        if self.risk_score >= 6 {
            actions.push(EndpointAction::SendSocWebhook);
        }
        if self.risk_score >= 7 && !self.signed_status {
            actions.push(EndpointAction::QuarantineFile);
        }
        if self.risk_score >= 8 {
            actions.push(EndpointAction::MemoryDump);
        }
        if self.risk_score >= 4 && self.risk_score < 8 {
            actions.push(EndpointAction::FlagForHumanReview);
        }
        actions
    }

    /// Check if this matches a specific MITRE TTP
    pub fn has_ttp(&self, ttp: &str) -> bool {
        self.mitre_ttp.iter().any(|t| t == ttp)
    }

    /// Quick threat summary for logging/UI
    pub fn summary(&self) -> String {
        format!(
            "FileHollow[{}] Risk:{} Anomaly:{:.2} TTPs:{} Action:{:?}",
            self.proc_hash.chars().take(8).collect::<String>(),
            self.risk_score,
            self.anomaly_score,
            self.mitre_ttp.len(),
            self.recommended_action(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_never_escalates() {
        let mut h = FileHollow::new("abc".into());
        h.is_decoy = true;
        h.entropy_delta = 0.9;
        h.backup_tamper = true;
        h.c2_contact = true;
        h.update_risk_score();
        assert_eq!(h.risk_score, 1);
        assert_eq!(h.recommended_action(), EndpointAction::LogOnly);
    }

    #[test]
    fn domain_admin_high_risk_revokes_session_not_kill() {
        let mut h = FileHollow::new("abc".into());
        h.user_privilege = UserPrivilege::DomainAdmin;
        h.entropy_delta = 0.9;
        h.backup_tamper = true;
        h.c2_contact = true;
        h.threat_intel_match = true;
        h.update_risk_score();
        assert!(h.risk_score >= 8);
        assert_eq!(h.recommended_action(), EndpointAction::RevokeSession);
    }

    #[test]
    fn unsigned_plus_injection_apis_outweighs_unsigned_alone() {
        let mut plain_unsigned = FileHollow::new("a".into());
        plain_unsigned.signed_status = false;
        plain_unsigned.update_risk_score();

        let mut injecting_unsigned = FileHollow::new("b".into());
        injecting_unsigned.signed_status = false;
        injecting_unsigned
            .suspicious_imports
            .insert("WriteProcessMemory".into());
        injecting_unsigned.update_risk_score();

        assert!(injecting_unsigned.risk_score > plain_unsigned.risk_score);
    }
}
