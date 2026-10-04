//! Structured audit logging for detection → decision → action.
//!
//! Every detection produces one JSON audit record: both risk scores, the
//! effective risk, the score reasons, the recommendation, the executable
//! action, whether a human must review the escalation, and whether the
//! record comes from a dry run. Records go to the log, and are appended as
//! JSONL to the file named by `AHR_AUDIT_LOG` when that variable is set —
//! an append-only trail a SOC (or Sentinel X) can tail in real time.

use crate::hollow::EndpointAction;
use crate::policy::Decision;
use log::info;
use serde::Serialize;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub ts_unix: u64,
    pub pid: u32,
    pub process_name: String,
    pub process_hash: String,
    pub snapshot_risk: u8,
    pub scored_risk: u8,
    pub effective_risk: u8,
    pub anomaly_score: f32,
    pub reasons: Vec<String>,
    pub recommended: String,
    pub companions: Vec<String>,
    pub executable_action: String,
    pub requires_human_review: bool,
    pub dry_run: bool,
    pub applied: bool,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn build_record(
    pid: u32,
    process_name: &str,
    process_hash: &str,
    anomaly_score: f32,
    decision: &Decision,
    dry_run: bool,
    applied: bool,
) -> AuditRecord {
    AuditRecord {
        ts_unix: now_unix(),
        pid,
        process_name: process_name.to_string(),
        process_hash: process_hash.to_string(),
        snapshot_risk: decision.snapshot_risk,
        scored_risk: decision.scored_risk,
        effective_risk: decision.effective_risk,
        anomaly_score,
        reasons: decision.reasons.clone(),
        recommended: format!("{:?}", decision.recommended),
        companions: decision
            .companions
            .iter()
            .map(|c: &EndpointAction| format!("{:?}", c))
            .collect(),
        executable_action: format!("{:?}", decision.executable),
        requires_human_review: decision.requires_human_review,
        dry_run,
        applied,
    }
}

/// Emit one audit record to the log and, when `AHR_AUDIT_LOG` is set, to
/// the append-only JSONL trail. File failures are logged, never fatal —
/// the audit trail must not take the agent down with it.
pub fn emit(record: &AuditRecord) {
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            log::error!("audit serialization failed: {}", e);
            return;
        }
    };
    info!("AUDIT {}", line);
    if let Ok(path) = std::env::var("AHR_AUDIT_LOG") {
        if !path.is_empty() {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(mut f) => {
                    if let Err(e) = writeln!(f, "{}", line) {
                        log::error!("audit trail write failed ({}): {}", path, e);
                    }
                }
                Err(e) => log::error!("audit trail open failed ({}): {}", path, e),
            }
        }
    }
}
