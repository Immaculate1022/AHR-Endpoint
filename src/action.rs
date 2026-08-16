//! Shared action codes for userspace and eBPF.
//!
//! Keep these numeric values identical to `ebpf/src/main.rs`.
//! When the Aya workspace gains a real `ahr-common` crate, move this there.

use serde::{Deserialize, Serialize};

/// Action level stored in eBPF `ACTION_MAP` (u8).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow = 0,
    Soft = 1,
    Medium = 2,
    Kill = 3,
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

impl Action {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
