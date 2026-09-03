# Pasted Content 06 — Updated Adaptive Hollow Reflector Candidate

This version supersedes the earlier [`Pasted_content_05_hollow.rs`](Pasted_content_05_hollow.rs) archive. The update adds explicit injection-API matching, reason strings for risk-score decisions, decoy suppression, privilege-aware primary actions, companion actions, and unit tests.

The candidate is **not merged into the active AHR-Endpoint engine**. The current engine still uses the smaller `FileHollow` shape in [`src/detection.rs`](../../src/detection.rs). The updated module has a different data model and would require an integration design, serialization compatibility review, test coverage in the real crate, and policy review before it can replace or augment the active scorer.

The action policy is consequential: high-risk domain-admin activity maps to `RevokeSession`, high-risk admin activity maps to `IsolateHost`, and high-risk standard activity maps to `KillTree`. Companion actions may request quarantine, memory capture, SOC notification, or human review. These should remain recommendations until explicit authorization, dry-run behavior, audit logging, and false-positive tests are in place.

The attached candidate includes useful improvements over version 05, especially the decoy guard and `score_reasons` audit trail. It has not been compiled or tested in this environment because the Rust toolchain is unavailable, so the repository should not claim that these tests pass here.

For the exact updated source, see [`Pasted_content_06_hollow.rs`](Pasted_content_06_hollow.rs).
