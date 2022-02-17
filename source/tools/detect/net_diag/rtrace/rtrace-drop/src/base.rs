use anyhow::Result;
use cached::proc_macro::cached;
use dyn_clone::{clone_trait_object, DynClone};
use rtrace_parser::func::Func;
use std::boxed::Box;
use uname::uname;

/// 
pub enum RtraceDropAction {
    Continue,
    Consume(String),
}

/// This trait can be used to define a packet drop point.
/// For example, TcpConnRequest implements RtraceDrop with
/// the packet drop point in tcp_conn_request. It is also
/// possible to define a module, such as the tcp module contains
/// four RtraceDrop instances.
pub trait RtraceDrop: DynClone {
    /// do some initialization.
    fn init(&mut self) -> Result<()> {
        Ok(())
    }
    /// Data analysis to determine whether the packet drop condition
    /// is established.
    fn check_func(&mut self, _: &Func, _: &Vec<u64>) -> RtraceDropAction {
        RtraceDropAction::Continue
    }
    /// Returns the tracing toml configuration string.
    fn get_probe_string(&self) -> &str {
        ""
    }
    /// Returns the name of the packet drop point.
    fn get_name(&self) -> &str;
    /// Returns "Support" or "Not Support".
    fn get_status(&self) -> &str {
        "[Not Support]"
    }
    /// Get the child RtraceDrop instance contained in the module.
    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        None
    }

    fn is_periodic(&self) -> bool {
        false
    }

    fn run_periodically(&mut self) -> RtraceDropAction {
        RtraceDropAction::Continue
    }

}

clone_trait_object!(RtraceDrop);

#[cached(size = 1)]
pub fn get_current_kernel_version() -> u64 {
    let info = uname().expect("uname failed").release;
    let tmps: Vec<&str> = info.split(".").collect();
    if tmps.len() < 3 {
        panic!("failed to parser kenel release version");
    }
    let major: u64 = tmps[0]
        .parse()
        .expect("failed to parser kenel release version");
    let minor: u64 = tmps[1]
        .parse()
        .expect("failed to parser kenel release version");
    let patch: u64 = tmps[2]
        .parse()
        .expect("failed to parser kenel release version");
    ((major) << 16) + ((minor) << 8) + (patch)
}

// 0 is equal, <0 is less than current, >0 is larger than.
pub fn kernel_version_compare(major: u64, minor: u64, patch: u64) -> i32 {
    let current_version = get_current_kernel_version();
    let target_version = ((major) << 16) + ((minor) << 8) + (patch);
    if target_version > current_version {
        1
    } else if target_version < current_version {
        -1
    } else {
        0
    }
}
