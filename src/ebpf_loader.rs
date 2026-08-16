//! Aya-based eBPF loader for AHR-Endpoint.
//!
//! Build with: `cargo build --release --features ebpf`
//! Requires a compiled eBPF object (see `ebpf/README.md`).
//!
//! Object search order:
//!   1. `$AHR_EBPF_OBJECT`
//!   2. `./ahr-ebpf.o`
//!   3. `./target/bpfel-unknown-none/release/ahr-ebpf`
//!   4. `/usr/lib/ahr-endpoint/ahr-ebpf.o`

use log::{info, warn};

#[cfg(feature = "ebpf")]
mod imp {
    use super::*;
    use aya::{
        maps::HashMap as EbpfHashMap,
        programs::TracePoint,
        Ebpf,
    };
    use std::path::{Path, PathBuf};

    pub struct EbpfEnforcer {
        ebpf: Ebpf,
    }

    impl EbpfEnforcer {
        /// Try to load and attach the AHR eBPF program.
        pub fn try_load() -> Result<Self, String> {
            bump_memlock_rlimit();

            let path = resolve_object_path().ok_or_else(|| {
                "no eBPF object found (set AHR_EBPF_OBJECT or place ahr-ebpf.o in CWD)".to_string()
            })?;

            info!("Loading eBPF object from {}", path.display());

            let mut ebpf = Ebpf::load_file(&path).map_err(|e| format!("Ebpf::load_file: {e}"))?;

            if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
                warn!("eBPF logger init skipped: {e}");
            }

            let program: &mut TracePoint = ebpf
                .program_mut("sys_enter_openat")
                .ok_or_else(|| "program sys_enter_openat not found in object".to_string())?
                .try_into()
                .map_err(|e| format!("program type: {e}"))?;

            program
                .load()
                .map_err(|e| format!("program.load: {e}"))?;
            program
                .attach("syscalls", "sys_enter_openat")
                .map_err(|e| format!("program.attach: {e}"))?;

            info!("eBPF attached: syscalls/sys_enter_openat → ACTION_MAP enforcement live");

            Ok(Self { ebpf })
        }

        /// Write (tgid, action) into the kernel HashMap.
        pub fn set_action(&mut self, tgid: u32, action: u8) -> Result<(), String> {
            let map = self
                .ebpf
                .map_mut("ACTION_MAP")
                .ok_or_else(|| "ACTION_MAP not found".to_string())?;

            let mut map: EbpfHashMap<_, u32, u8> =
                EbpfHashMap::try_from(map).map_err(|e| format!("map type: {e}"))?;

            map.insert(tgid, action, 0)
                .map_err(|e| format!("map.insert({tgid}): {e}"))?;

            info!("eBPF ACTION_MAP: tgid={tgid} action={action}");
            Ok(())
        }

        /// Remove a PID from the map (TTL expiry / allow).
        pub fn clear_action(&mut self, tgid: u32) -> Result<(), String> {
            let map = self
                .ebpf
                .map_mut("ACTION_MAP")
                .ok_or_else(|| "ACTION_MAP not found".to_string())?;

            let mut map: EbpfHashMap<_, u32, u8> =
                EbpfHashMap::try_from(map).map_err(|e| format!("map type: {e}"))?;

            // insert Allow(0) as soft clear if remove unsupported on older maps
            let _ = map.insert(tgid, 0u8, 0);
            Ok(())
        }
    }

    fn resolve_object_path() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("AHR_EBPF_OBJECT") {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        const CANDIDATES: &[&str] = &[
            "./ahr-ebpf.o",
            "./target/bpfel-unknown-none/release/ahr-ebpf",
            "./target/bpfel-unknown-none/debug/ahr-ebpf",
            "/usr/lib/ahr-endpoint/ahr-ebpf.o",
        ];
        for c in CANDIDATES {
            let p = Path::new(c);
            if p.is_file() {
                return Some(p.to_path_buf());
            }
        }
        None
    }

    fn bump_memlock_rlimit() {
        // Needed on kernels that still enforce RLIMIT_MEMLOCK for BPF maps
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            warn!("setrlimit(RLIMIT_MEMLOCK) failed — BPF load may fail on older kernels");
        }
    }
}

#[cfg(feature = "ebpf")]
pub use imp::EbpfEnforcer;

/// No-op stand-in when built without `--features ebpf`.
#[cfg(not(feature = "ebpf"))]
pub struct EbpfEnforcer;

#[cfg(not(feature = "ebpf"))]
impl EbpfEnforcer {
    pub fn try_load() -> Result<Self, String> {
        Err("built without `ebpf` feature — cargo build --features ebpf".into())
    }

    pub fn set_action(&mut self, _tgid: u32, _action: u8) -> Result<(), String> {
        Err("ebpf feature disabled".into())
    }

    pub fn clear_action(&mut self, _tgid: u32) -> Result<(), String> {
        Ok(())
    }
}

/// Attempt load; log and return None on failure so agent always starts.
pub fn load_optional() -> Option<EbpfEnforcer> {
    match EbpfEnforcer::try_load() {
        Ok(e) => {
            info!("Kernel eBPF enforcement: ACTIVE");
            Some(e)
        }
        Err(e) => {
            warn!("Kernel eBPF enforcement: inactive ({e})");
            warn!("  Continuing with userspace graduated response only.");
            None
        }
    }
}
