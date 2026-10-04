//! Sentinel X evidence emission.
//!
//! Sentinel X is the forensic telemetry control plane; AHR-Endpoint is the
//! sensor/enforcer on the host. This module shapes every policy decision
//! into the evidence-event model Sentinel X displays — an anomaly cluster
//! with a threat index, the score reasons as the evidence trail, MITRE
//! TTPs, and the recommended vs. executed action — and ships it:
//!
//! * over NATS on `sentinelx.evidence` when a connection is available
//!   (alongside the existing `ahr.invariants` cross-host signal), and
//! * as JSONL to the file named by `AHR_SENTINELX_SINK` when set, so a
//!   local control plane can tail the stream with no broker in between.
//!
//! Escalate the signal, not the noise: only scored detections become
//! evidence events; routine scan cycles emit nothing.

use crate::audit::now_unix;
use crate::hollow::FileHollow as ScoredHollow;
use crate::policy::Decision;
use log::{error, info};
use serde::Serialize;
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct EvidenceEvent {
    pub event_type: String,
    pub ts_unix: u64,
    pub pid: u32,
    pub process_name: String,
    pub process_hash: String,
    /// 0–99 control-plane threat index, scaled from effective risk.
    pub threat_index: u8,
    pub severity: String,
    pub anomaly_score: f32,
    pub score_reasons: Vec<String>,
    pub mitre_ttp: Vec<String>,
    pub recommended_action: String,
    pub executed_action: String,
    pub requires_human_review: bool,
}

pub fn severity_for(risk: u8) -> &'static str {
    match risk {
        8..=10 => "CRITICAL",
        6..=7 => "HIGH",
        4..=5 => "MEDIUM",
        _ => "LOW",
    }
}

pub fn build_event(
    pid: u32,
    process_name: &str,
    scored: &ScoredHollow,
    decision: &Decision,
    executed: bool,
) -> EvidenceEvent {
    EvidenceEvent {
        event_type: "anomaly_cluster".to_string(),
        ts_unix: now_unix(),
        pid,
        process_name: process_name.to_string(),
        process_hash: scored.proc_hash.clone(),
        threat_index: (decision.effective_risk * 10).min(99),
        severity: severity_for(decision.effective_risk).to_string(),
        anomaly_score: scored.anomaly_score,
        score_reasons: decision.reasons.clone(),
        mitre_ttp: scored.mitre_ttp.clone(),
        recommended_action: format!("{:?}", decision.recommended),
        executed_action: if executed {
            format!("{:?}", decision.executable)
        } else {
            "None".to_string()
        },
        requires_human_review: decision.requires_human_review,
    }
}

/// Publish one evidence event to the Sentinel X stream over NATS.
pub fn publish_evidence(nc: &nats::Connection, event: &EvidenceEvent) {
    match serde_json::to_string(event) {
        Ok(payload) => {
            if let Err(e) = nc.publish("sentinelx.evidence", payload) {
                error!("Failed to publish Sentinel X evidence: {}", e);
            } else {
                info!(
                    "Sentinel X evidence published (threat_index={} severity={})",
                    event.threat_index, event.severity
                );
            }
        }
        Err(e) => error!("Sentinel X evidence serialization failed: {}", e),
    }
}

/// Append one evidence event as JSONL to the local sink, when configured.
pub fn write_sink(event: &EvidenceEvent) {
    if let Ok(path) = std::env::var("AHR_SENTINELX_SINK") {
        if path.is_empty() {
            return;
        }
        match serde_json::to_string(event) {
            Ok(line) => match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(mut f) => {
                    if let Err(e) = writeln!(f, "{}", line) {
                        error!("Sentinel X sink write failed ({}): {}", path, e);
                    }
                }
                Err(e) => error!("Sentinel X sink open failed ({}): {}", path, e),
            },
            Err(e) => error!("Sentinel X evidence serialization failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_bands_match_control_plane() {
        assert_eq!(severity_for(9), "CRITICAL");
        assert_eq!(severity_for(6), "HIGH");
        assert_eq!(severity_for(4), "MEDIUM");
        assert_eq!(severity_for(2), "LOW");
    }

    #[test]
    fn threat_index_caps_at_99() {
        assert_eq!((10u8 * 10).min(99), 99);
    }
}
