use crate::bindings::*;
use crate::rtrace::Filterx;
use anyhow::anyhow;
use anyhow::Result;
use libbpf_sys::*;
use log::*;
use std::os::raw::{c_int, c_void};

/// filter module
///
/// Used to process filter maps in eBPF programs.
pub struct Filter {
    fd: i32,
    key: i32,
}

impl Filter {
    pub fn new(fd: i32) -> Filter {
        // value of default key of Filter is 0
        Filter { fd, key: 0 }
    }

    fn raw_update(&self, key: *const c_void, value: *const c_void) -> Result<()> {
        let ret = unsafe { bpf_map_update_elem(self.fd, key, value, BPF_ANY as u64) };
        if ret < 0 {
            return Err(anyhow!("update err, errno: {}", ret));
        }
        Ok(())
    }

    pub fn update(&self, filters: &Vec<Filterx>, protocol: Protocol) -> Result<()> {
        let zero_fm = filter_meta {
            pid: 0,
            ap: addr_pair {
                saddr: 0,
                daddr: 0,
                sport: 0,
                dport: 0,
            },
        };
        let mut tmp_filter_metas = [zero_fm; 10usize];
        debug!("protocol: {:?}", protocol);
        for (idx, filter) in filters.iter().enumerate() {
            tmp_filter_metas[idx] = filter_meta {
                pid: filter.pid as i32,
                ap: addr_pair::from_string(&filter.src, &filter.dst)?,
            };
            debug!(
                "pid: {}, ap: {}",
                tmp_filter_metas[idx].pid,
                tmp_filter_metas[idx].ap.into_string()
            );
        }

        let fp = filter_params {
            protocol: protocol as u32,
            cnt: filters.len() as i32,
            fm: tmp_filter_metas,
        };

        self.raw_update(
            &self.key as *const c_int as *const c_void,
            &fp as *const filter_params as *const c_void,
        )
    }
}
