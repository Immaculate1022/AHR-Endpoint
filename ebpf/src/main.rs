//! AHR eBPF enforcement program (Aya).
//!
//! Action codes (must match userspace `enforcement::Action`):
//!   0 = Allow, 1 = Soft, 2 = Medium, 3 = Kill
//!
//! Build (Linux, with bpf-linker + nightly):
//!   cargo +nightly build -Z build-std=core --target bpfel-unknown-none -p ahr-ebpf
//!
//! The userspace agent writes flagged PIDs into ACTION_MAP.
//! This program kills (SIGKILL) when action == 3 on a monitored path.
//!
//! LSM deny path (path_rename / file write) can be added once BTF + LSM
//! BPF is confirmed on the target kernel (5.7+).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_send_signal},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

/// PID (tgid) → action level
#[map]
static ACTION_MAP: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

const ACTION_KILL: u8 = 3;
const SIGKILL: u32 = 9;

/// Example attachment: sys_enter_openat — any open by a flagged process.
/// Replace / extend with LSM hooks (path_rename, file_permission) for
/// preventive -EPERM when kernel supports BPF_PROG_TYPE_LSM.
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if let Some(action) = ACTION_MAP.get(&tgid) {
        if *action >= ACTION_KILL {
            // Hard kill from kernel — process is stopped mid-syscall path
            let _ = bpf_send_signal(SIGKILL);
            info!(&ctx, "AHR eBPF: SIGKILL tgid={}", tgid);
        }
        // Soft/Medium: userspace already handled SIGSTOP; kernel path can
        // later return -EPERM via LSM for rename/write.
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
