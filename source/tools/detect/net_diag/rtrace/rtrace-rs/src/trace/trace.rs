use crate::bindings::*;
use crate::rtrace::Function;
use crate::trace::prog::Prog;
use anyhow::anyhow;
use anyhow::Result;
use libbpf_sys::{bpf_kprobe_opts, size_t};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use log::*;

/// dynamic trace module
///
///
pub struct Trace {
    r: *mut rtrace,

    func: CString,
    sk: c_int,
    skb: c_int,
}

impl Trace {
    pub fn new(r: *mut rtrace, function: &Function) -> Result<Trace> {
        let func = CString::new(function.name.clone())?;
        let mut sk = 0;
        let mut skb = 0;
        if let Some(x) = function.sk {
            sk = x;
        }
        if let Some(x) = function.skb {
            skb = x;
        }
        Ok(Trace {
            r,
            func,
            sk,
            skb,
        })
    }

    /// load and attach kprobe type eBPF program for this func.
    pub fn attach_kprobe(&self, prog: &Prog) -> Result<()> {
        let err = unsafe {
            rtrace_trace_load_prog(self.r, prog.raw_ptr(), prog.insns(), prog.insns_cnt() as size_t)
        };

        if err < 0 {
            return Err(anyhow!("unable to load kprobe -> {:?}, err: {}", self.func, err));
        }

        let bl = unsafe {
            libbpf_sys::bpf_program__attach_kprobe(
                prog.raw_ptr(),
                false,
                self.func.as_ptr() as *const c_char,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(bl as *const c_void) };
        if err < 0 {
            return Err(anyhow!("failed to attach kprobe -> {:?}", self.func));
        }

        debug!("attach kprobe ({:?}) successfully.", self.func);
        Ok(())
    }

    pub fn attach_kretprobe(&self, prog: &Prog) -> Result<()> {
        let bl = unsafe {
            libbpf_sys::bpf_program__attach_kprobe(
                prog.raw_ptr(),
                true,
                self.func.as_ptr() as *const c_char,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(bl as *const c_void) };
        if err < 0 {
            return Err(anyhow!("failed to attach kretprobe -> {:?}", self.func,));
        }
        debug!("attach kretprobe ({:?}) successfully.", self.func);
        Ok(())
    }

    fn attach_line(&self, prog: &Prog, offset: u64) -> Result<()> {
        let mut opts = bpf_kprobe_opts::default();
        opts.sz = std::mem::size_of::<bpf_kprobe_opts>() as u64;
        opts.bpf_cookie = 0;
        opts.offset = offset;
        opts.retprobe = false;

        unsafe {
            let bl = libbpf_sys::bpf_program__attach_kprobe_opts(
                prog.raw_ptr(),
                self.func.as_ptr() as *mut c_char,
                &opts as *const libbpf_sys::bpf_kprobe_opts,
            );

            let err = libbpf_sys::libbpf_get_error(bl as *const c_void);
            if err < 0 {
                return Err(anyhow!(
                    "failed to attach kprobe+{} -> {:?} ",
                    opts.offset,
                    self.func
                ));
            }
        }
        debug!("attach kprobe ({:?}+{}) successfully.", self.func, offset);
        Ok(())
    }

    pub fn attach_lines(&self, prog: &Prog, offsets: &Vec<u64>) -> Result<()> {
        for offset in offsets {
            self.attach_line(prog, *offset)?;
        }
        Ok(())
    }
}


