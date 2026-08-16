//! Graduated response enforcement for AHR-Endpoint.
//!
//! Soft  → log + optional SIGSTOP
//! Medium → deny-style containment (userspace kill of children + SIGSTOP parent)
//! Hard  → SIGKILL process tree + publish invariant
//!
//! When eBPF is loaded (see `ebpf/`), the same action codes are written into
//! the kernel map so LSM / bpf_send_signal can act in microseconds.

use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};

/// Action level stored in eBPF map (u8) and used by userspace fallback.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow = 0,
    Soft = 1,   // log / rate-limit / SIGSTOP
    Medium = 2, // contain without full kill
    Kill = 3,   // SIGKILL + tree
}

impl From<u8> for Action {
    fn from(v: u8) -> Self {
        match v {
            1 => Action::Soft,
            2 => Action::Medium,
            3 => Action::Kill,
            _ => Action::Allow,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementRecord {
    pub pid: u32,
    pub action: Action,
    pub reason: String,
    pub process_hash: String,
    pub applied_at: u64, // unix secs
    pub ttl_secs: u64,
}

/// In-memory flagged set (mirrors what will live in the eBPF HashMap).
pub struct EnforcementController {
    flagged: HashMap<u32, (Action, Instant, u64)>, // pid → (action, applied, ttl_secs)
    whitelist: Vec<u32>,
}

impl EnforcementController {
    pub fn new() -> Self {
        let mut whitelist = Vec::new();
        // Never touch PID 1 or our own process
        whitelist.push(1);
        whitelist.push(std::process::id());
        Self {
            flagged: HashMap::new(),
            whitelist,
        }
    }

    pub fn is_whitelisted(&self, pid: u32) -> bool {
        self.whitelist.contains(&pid)
    }

    /// Flag a PID with an action and TTL (seconds).
    pub fn flag(&mut self, pid: u32, action: Action, ttl_secs: u64, reason: &str) {
        if self.is_whitelisted(pid) {
            warn!("Refusing to flag whitelisted PID {}", pid);
            return;
        }
        info!(
            "Flagging PID {} → {:?} (ttl={}s) reason={}",
            pid, action, ttl_secs, reason
        );
        self.flagged
            .insert(pid, (action, Instant::now(), ttl_secs));
    }

    /// Expire old entries.
    pub fn sweep(&mut self) {
        self.flagged.retain(|pid, (_, at, ttl)| {
            let keep = at.elapsed() < Duration::from_secs(*ttl);
            if !keep {
                info!("TTL expired for PID {}", pid);
            }
            keep
        });
    }

    /// Apply userspace enforcement for a flagged PID (fallback when eBPF not loaded).
    pub fn apply_userspace(&self, pid: u32, action: Action) -> bool {
        if self.is_whitelisted(pid) {
            return false;
        }
        match action {
            Action::Allow => true,
            Action::Soft => {
                // SIGSTOP — reversible
                send_signal(pid, 19); // SIGSTOP
                info!("Soft containment: SIGSTOP sent to PID {}", pid);
                true
            }
            Action::Medium => {
                // Stop parent + children, do not SIGKILL yet
                let children = collect_descendants(pid);
                for c in &children {
                    send_signal(*c, 19);
                }
                send_signal(pid, 19);
                info!(
                    "Medium containment: SIGSTOP on PID {} and {} children",
                    pid,
                    children.len()
                );
                true
            }
            Action::Kill => {
                let children = collect_descendants(pid);
                // Kill children first, then parent (KILL_TREE)
                for c in children.iter().rev() {
                    send_signal(*c, 9); // SIGKILL
                }
                send_signal(pid, 9);
                warn!(
                    "Hard containment: SIGKILL tree for PID {} ({} descendants)",
                    pid,
                    children.len()
                );
                true
            }
        }
    }

    /// Map risk score (0–10) to graduated action.
    pub fn action_for_risk(risk: u8) -> Action {
        match risk {
            0..=3 => Action::Allow,
            4..=6 => Action::Soft,
            7..=8 => Action::Medium,
            _ => Action::Kill,
        }
    }
}

fn send_signal(pid: u32, sig: i32) {
    // Prefer libc kill; fall back to kill(1) for portability in prototype
    #[cfg(unix)]
    {
        unsafe {
            let _ = libc::kill(pid as i32, sig);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = Command::new("kill")
            .arg(format!("-{}", sig))
            .arg(pid.to_string())
            .status();
    }
}

fn collect_descendants(root: u32) -> Vec<u32> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        for (pid, proc) in sys.processes() {
            if let Some(ppid) = proc.parent() {
                if ppid.as_u32() == p {
                    let child = pid.as_u32();
                    if !out.contains(&child) {
                        out.push(child);
                        stack.push(child);
                    }
                }
            }
        }
    }
    out
}

// Minimal libc binding for kill on Unix
#[cfg(unix)]
mod libc {
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
    }
}
