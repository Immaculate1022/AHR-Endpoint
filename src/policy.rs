//! Decision policy: turns a detector snapshot plus a scored telemetry
//! record (`crate::hollow`) into one auditable decision.
//!
//! Two scorers look at every detection — the userspace heuristic ladder in
//! `crate::detection` and the telemetry scorer in `crate::hollow`. The
//! effective risk is the more severe of the two, and the audit record keeps
//! both numbers, so a decision can always be traced to the scorer that
//! drove it.
//!
//! Hardening rules:
//! * Decoys never escalate (the telemetry scorer already caps them; the
//!   policy layer enforces it independently).
//! * The telemetry model may *recommend* privilege-escalated responses
//!   (RevokeSession, IsolateHost, TriggerMfaReprompt). Those are account-
//!   and host-level actions this engine does not perform autonomously:
//!   when one is recommended at a severity that would otherwise execute a
//!   process-tree kill, the executable action is held at Medium (suspend
//!   tree — reversible) and the decision is marked
//!   `requires_human_review` until a human authorizes the escalation.
//! * Companion actions (quarantine, memory capture, SOC webhook, human
//!   review) are emitted as audit/telemetry records. They are not executed
//!   by this engine.

use crate::action::Action;
use crate::detection::FileHollow as Snapshot;
use crate::enforcement::EnforcementController;
use crate::hollow::{EndpointAction, FileHollow as ScoredHollow};

#[derive(Debug, Clone)]
pub struct Decision {
    /// More severe of the detector ladder and the telemetry score (1..=10).
    pub effective_risk: u8,
    /// The detector's heuristic risk, kept for audit.
    pub snapshot_risk: u8,
    /// The telemetry scorer's risk, kept for audit.
    pub scored_risk: u8,
    /// What the scored model recommends (may exceed what we may execute).
    pub recommended: EndpointAction,
    /// What the engine is permitted to execute on its own.
    pub executable: Action,
    /// Companion recommendations, emitted as records — not executed.
    pub companions: Vec<EndpointAction>,
    /// True when a human must authorize the recommended escalation.
    pub requires_human_review: bool,
    /// Combined human-readable reasons from both scorers and this policy.
    pub reasons: Vec<String>,
}

pub fn decide(snapshot: &Snapshot, scored: &ScoredHollow) -> Decision {
    let mut reasons: Vec<String> = scored.score_reasons.clone();
    reasons.push(format!(
        "userspace heuristic ladder: risk {} (name/resource indicators)",
        snapshot.risk
    ));

    // Decoy suppression, enforced at the policy layer as well as in the
    // scorer: a honeypot asset is observed, never acted on.
    if snapshot.is_decoy || scored.is_decoy {
        reasons.push("policy: decoy asset — observation only".into());
        return Decision {
            effective_risk: 1,
            snapshot_risk: snapshot.risk,
            scored_risk: scored.risk_score,
            recommended: EndpointAction::LogOnly,
            executable: Action::Allow,
            companions: Vec::new(),
            requires_human_review: false,
            reasons,
        };
    }

    let effective_risk = snapshot.risk.max(scored.risk_score);
    let recommended = scored.recommended_action();
    let companions = scored.companion_actions();

    let mut executable = EnforcementController::action_for_risk(effective_risk);
    let mut requires_human_review =
        companions.contains(&EndpointAction::FlagForHumanReview);

    // Privilege-aware authorization cap: session revocation, host
    // isolation, and MFA reprompts are recommended, never auto-executed.
    // If the ladder would kill the tree behind one of those
    // recommendations, hold at suspend (reversible) for a human decision.
    let privilege_escalated = matches!(
        recommended,
        EndpointAction::RevokeSession
            | EndpointAction::IsolateHost
            | EndpointAction::TriggerMfaReprompt
    );
    if privilege_escalated && executable == Action::Kill {
        executable = Action::Medium;
        requires_human_review = true;
        reasons.push(format!(
            "policy: {:?} is a privilege-escalated recommendation — executable action held at suspend pending human authorization",
            recommended
        ));
    }

    Decision {
        effective_risk,
        snapshot_risk: snapshot.risk,
        scored_risk: scored.risk_score,
        recommended,
        executable,
        companions,
        requires_human_review,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hollow::UserPrivilege;

    fn snapshot(risk: u8) -> Snapshot {
        Snapshot {
            pid: 4242,
            risk,
            process_hash: "deadbeef".into(),
            process_name: "ransom-note.exe".into(),
            is_decoy: false,
            tree_depth: 2,
            runs_as_admin: false,
        }
    }

    fn scored_high(privilege: UserPrivilege) -> ScoredHollow {
        let mut h = ScoredHollow::new("deadbeef".into());
        h.user_privilege = privilege;
        h.entropy_delta = 0.9;
        h.backup_tamper = true;
        h.c2_contact = true;
        h.threat_intel_match = true;
        h.update_risk_score();
        h
    }

    #[test]
    fn standard_user_high_risk_executes_kill() {
        let d = decide(&snapshot(9), &scored_high(UserPrivilege::Standard));
        // Scored model saturates at 10 (four +3 signals and unsigned, clamped).
        assert_eq!(d.effective_risk, 10);
        assert_eq!(d.recommended, EndpointAction::KillTree);
        assert_eq!(d.executable, Action::Kill);
    }

    #[test]
    fn domain_admin_recommendation_is_capped_for_human() {
        let d = decide(&snapshot(9), &scored_high(UserPrivilege::DomainAdmin));
        assert_eq!(d.recommended, EndpointAction::RevokeSession);
        assert_eq!(d.executable, Action::Medium);
        assert!(d.requires_human_review);
    }

    #[test]
    fn decoy_never_executes() {
        let mut snap = snapshot(9);
        snap.is_decoy = true;
        let d = decide(&snap, &scored_high(UserPrivilege::Standard));
        assert_eq!(d.executable, Action::Allow);
        assert_eq!(d.effective_risk, 1);
    }

    #[test]
    fn mid_band_suspends_without_human_review() {
        let mut h = ScoredHollow::new("x".into());
        h.signed_status = true;
        h.update_risk_score();
        let d = decide(&snapshot(5), &h);
        assert_eq!(d.effective_risk, 5);
        assert_eq!(d.executable, Action::Soft);
    }
}
