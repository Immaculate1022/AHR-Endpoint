# Archived AHR scoring candidates

This directory contains supplied scoring and response candidates retained for provenance and review. Files here are **not compiled into the active AHR-Endpoint crate**, are not loaded by the eBPF path, and must not be treated as production enforcement code.

The active engine currently uses the smaller `FileHollow` model in [`src/detection.rs`](../../src/detection.rs), maps risk through [`src/enforcement.rs`](../../src/enforcement.rs), and exposes the non-enforcing `--dry-run --once` audit controls in [`src/main.rs`](../../src/main.rs).

Before any archived candidate is merged, it needs a compatibility design, unit and integration tests in the real Cargo crate, explicit dry-run behavior, structured audit logging, false-positive review, and human authorization for consequential actions such as process termination, host isolation, session revocation, or memory capture.

The current archive includes the versioned `Pasted_content_05_hollow.rs` and `Pasted_content_06_hollow.rs` candidates. Version 06 adds scoring reasons, decoy suppression, injection-API signals, privilege-aware actions, companion actions, and unit tests, but it remains an unmerged research candidate.
