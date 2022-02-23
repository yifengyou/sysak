use crate::bindings::*;
use crate::builtin::builtin::Builtin;
use crate::dynamic::dynamic::Dynamic;
use crate::filter::filter::Filter;
use crate::trace::prog::Prog;
use crate::trace::trace::Trace;
use crate::utils::gdb::Gdb;
use anyhow::anyhow;
use anyhow::Result;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use toml;

#[derive(Debug, Deserialize, Serialize)]
pub struct Basic {
    pub debug: bool,
    pub btf_path: Option<String>,
    pub pin_path: Option<String>,
    pub vmlinux: Option<String>,
    pub ksyms: Option<String>,
    pub duration: usize,
    pub protocol: String,
    pub recv: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Filterx {
    pub pid: usize,
    pub dst: String,
    pub src: String,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Function {
    pub name: String,
    pub enable: Option<bool>,
    pub sk: Option<c_int>,
    pub skb: Option<c_int>,
    pub params: Vec<String>,
    pub exprs: Option<Vec<String>>,
    pub lines: Option<Vec<String>>,

    offsets: Option<Vec<u64>>,
}
// see: https://github.com/alexcrichton/toml-rs/issues/395
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct FunctionContainer {
    pub function: Vec<Function>,
}

impl FunctionContainer {
    pub fn from_str(s: &str) -> Result<FunctionContainer> {
        match toml::from_str(s) {
            Ok(x) => Ok(x),
            Err(y) => Err(anyhow!("str to FunctionContainer failed: {}", y)),
        }
    }
}

impl Function {
    pub fn from_str(s: &str) -> Result<Function> {
        match toml::from_str(s) {
            Ok(x) => Ok(x),
            Err(y) => Err(anyhow!("str to Function failed: {}", y)),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub basic: Basic,
    pub filter: Option<Vec<Filterx>>,
    pub function: Option<Vec<Function>>,
}

impl Config {
    pub fn from_str(s: &str) -> Result<Config> {
        match toml::from_str(s) {
            Ok(x) => Ok(x),
            Err(_) => Err(anyhow!("str to Config failed")),
        }
    }

    pub fn to_string(&self) -> Result<String> {
        match toml::to_string(self) {
            Ok(x) => Ok(x),
            Err(_) => Err(anyhow!("config to string failed")),
        }
    }
}

pub struct Probe {
    builtin: Builtin,
    trace: Trace,
    dynamic: Dynamic,
}

impl Probe {
    pub fn get_exprs(&self) -> &Vec<String> {
        self.dynamic.get_exprs()
    }

    pub fn get_expr_sz(&self) -> &Vec<u8> {
        self.dynamic.get_sz()
    }
}

pub struct Rtrace {
    ptr: *mut rtrace,
    filter: Filter,
    probes: HashMap<String, Probe>,
    progs: HashMap<String, Prog>,
    config: Option<Config>,
}

impl Rtrace {
    pub fn new(btf_path: Option<String>, pin_path: Option<String>) -> Result<Rtrace> {
        let ptr = Rtrace::init(btf_path, pin_path)?;
        let filter_map_fd = unsafe { rtrace_filter_map_fd(ptr) };
        let mut r = Rtrace {
            ptr,
            filter: Filter::new(filter_map_fd),
            probes: HashMap::new(),
            progs: HashMap::new(),
            config: None,
        };
        Ok(r)
    }

    fn init(btf_path: Option<String>, pin_path: Option<String>) -> Result<*mut rtrace> {
        let mut tmp_btf = CString::default();
        let mut tmp_pin = CString::default();
        let mut tmp_btf_ptr = std::ptr::null_mut();
        let mut tmp_pin_ptr = std::ptr::null_mut();
        if let Some(x) = btf_path {
            tmp_btf = CString::new(x.clone())?;
            tmp_btf_ptr = tmp_btf.as_ptr() as *mut c_char;
        }

        if let Some(x) = pin_path {
            tmp_pin = CString::new(x.clone())?;
            tmp_pin_ptr = tmp_pin.as_ptr() as *mut c_char;
        }

        let ptr = unsafe { rtrace_alloc_and_init(tmp_btf_ptr, tmp_pin_ptr) };
        if ptr == std::ptr::null_mut() {
            return Err(anyhow!("unable to open rtrace object"));
        }
        Ok(ptr)
    }

    pub fn insert_prog(&mut self, name: &String, prog: Prog) {
        self.progs.insert(name.clone(), prog);
    }

    pub fn get_prog(&mut self, name: &String, sk: Option<i32>, skb: Option<i32>) -> Result<Prog> {
        let mut skv = 0;
        let mut skbv = 0;
        if let Some(x) = sk {
            skv = x;
        }
        if let Some(x) = skb {
            skbv = x;
        }

        if let Some(x) = self.progs.remove(name) {
            return Ok(x);
        }
        
        let cname = CString::new(name.clone())?;
        let prog = unsafe {
            rtrace_trace_program(self.ptr, cname.as_ptr(), skv, skbv)
        };

        if prog == std::ptr::null_mut() {
            return Err(anyhow!(
                "failed to find bpf program for function: {}, sk-{}, skb-{}",
                name,
                skv,
                skbv
            ));
        }
        Ok(Prog::new(prog))
    }

    pub fn from_file(path: &PathBuf) -> Result<Rtrace> {
        let contents =
            std::fs::read_to_string(path).expect("Something went wrong reading config file");
        Rtrace::from_str(&contents[..])
    }

    pub fn from_str(s: &str) -> Result<Rtrace> {
        let config: Config = toml::from_str(s).expect("Config file parsed failed");
        unsafe {
            rtrace_set_debug(config.basic.debug);
        }
        let ptr = Rtrace::init(config.basic.btf_path.clone(), config.basic.pin_path.clone())?;
        let filter_map_fd = unsafe { rtrace_filter_map_fd(ptr) };
        let r = Rtrace {
            ptr,
            filter: Filter::new(filter_map_fd),
            probes: HashMap::new(),
            progs: HashMap::new(),
            config: Some(config),
        };
        Ok(r)
    }

    fn probe_function(&mut self, function: &Function, offsets: Option<Vec<u64>>) -> Result<Probe> {
        let builtin = Builtin::new(function)?;
        let trace = Trace::new(self.ptr, function)?;
        let mut dynamic = Dynamic::new(function)?;

        let mut prog = self.get_prog(&function.name, function.sk, function.skb)?;
        let kretprog = self.get_prog(&"kretprobe_common".to_owned(), None, None)?;
        let lineprog = self.get_prog(&"kprobe_lines".to_owned(), None, None)?;
        prog.patch_builtin_insn(builtin.get_mask())?;
        if let Some(_) = function.exprs {
            prog.patch_dynamic_insn(&dynamic.codegen(self.ptr, prog.cd_off())?)?;
        }
        trace.attach_kprobe(&prog)?;
        if builtin.has_kretprobe() {
            trace.attach_kretprobe(&kretprog)?;
        }

        if let Some(offs) = &offsets {
            trace.attach_lines(&lineprog, offs)?;
            if !builtin.has_kretprobe() {
                trace.attach_kretprobe(&kretprog)?; // to clear tid_map
            }
        }

        self.insert_prog(&function.name, prog);
        self.insert_prog(&"kretprobe_common".to_owned(), kretprog);
        self.insert_prog(&"kprobe_lines".to_owned(), lineprog);

        let p = Probe {
            builtin: builtin,
            trace: trace,
            dynamic: dynamic,
        };

        Ok(p)
    }

    fn __probe_functions(&mut self, functions: &Vec<Function>) -> Result<()> {
        let mut gdb = None;
        let mut vmlinux = None;
        if let Some(config) = &self.config {
            vmlinux = config.basic.vmlinux.clone();
        }
        for function in functions {
            if let Some(enable) = function.enable {
                if enable == false {
                    continue;
                }
            }
            let mut offsets = None;
            if let Some(lines) = &function.lines {
                let mut offs = Vec::new();
                for line in lines {
                    let off = line.parse::<u64>();
                    match off {
                        Ok(x) => {
                            offs.push(x);
                            continue;
                        }
                        _ => {}
                    }

                    match gdb {
                        None => {
                            if let Some(x) = &vmlinux {
                                gdb = Some(Gdb::new(x)?);
                            }
                        }
                        _ => {}
                    }
                    if let Some(g) = &mut gdb {
                        offs.push(g.infoline(line)?);
                    }
                }
                offsets = Some(offs);
            }
            let p = self.probe_function(function, offsets)?;
            self.probes.entry(function.name.clone()).or_insert(p);
        }
        Ok(())
    }

    pub fn probe_functions(&mut self) -> Result<()> {
        let mut funtions = None;
        if let Some(config) = &self.config {
            if let Some(funcs) = &config.function {
                funtions = Some(funcs.clone());
            }
        }

        if let Some(x) = &funtions {
            self.__probe_functions(x)?;
        }
        Ok(())
    }

    pub fn probe_functions_from_str(&mut self, s: &str) -> Result<()> {
        let functions: FunctionContainer = toml::from_str(s).expect("functions str parsed failed");
        self.__probe_functions(&functions.function)?;
        Ok(())
    }

    pub fn probe_functions_from_functions(&mut self, functions: &Vec<Function>) -> Result<()> {
        self.__probe_functions(functions)?;
        Ok(())
    }

    pub fn get_probe(&self, func: &String) -> Option<&Probe> {
        if self.probes.contains_key(func) {
            return Some(&self.probes[func]);
        }
        None
    }

    pub fn probe_filter(&mut self) -> Result<()> {
        if let Some(config) = &self.config {
            if let Some(filter) = &config.filter {
                self.filter
                    .update(&filter, Protocol::from_string(&config.basic.protocol)?)?;
            }
        }
        Ok(())
    }

    pub fn probe_filter_from_str(&mut self, protocol: Protocol, s: &str) -> Result<()> {
        let filters: Vec<Filterx> = toml::from_str(s).expect("filter str parsed failed");
        self.filter.update(&filters, protocol)
    }

    pub fn perf_fd(&self) -> i32 {
        unsafe { rtrace_perf_map_fd(self.ptr) as i32 }
    }

    pub fn protocol(&self) -> Result<Protocol> {
        if let Some(config) = &self.config {
            return Protocol::from_string(&config.basic.protocol);
        }
        Err(anyhow!("Please specified config info"))
    }

    pub fn is_recv(&self) -> bool {
        if let Some(config) = &self.config {
            return config.basic.recv;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rtrace_from_str() {
        let text = r#"
                [basic]
                debug = false
                btf_path = "/boot/vmlinux-4.19.91-007.ali4000.alios7.x86_64"
                duration = 0
                protocol = "tcp"
                "#;
        let r = Rtrace::from_str(text).unwrap();
    }

    #[test]
    fn test_rtrace_probe_functions() {
        let text = r#"
        [basic]
        debug = false
        btf_path = "/boot/vmlinux-4.19.91-007.ali4000.alios7.x86_64"
        duration = 0
        protocol = "tcp"

        [[filter]]
        pid = 0
        dst = "0.0.0.0:0"
        src = "0.0.0.0:0"

        [[function]]
        name = "__ip_queue_xmit"
        enable = true
        params = ["basic", "stack", "kretprobe"]

        [[function]]
        name = "dev_hard_start_xmit"
        enable = true
        params = ["basic"]

        [[function]]
        name = "__netif_receive_skb_core"
        enable = true
        params = ["basic"]

        [[function]]
        name = "tcp_rcv_state_process"
        enable = true
        params = ["basic"]
        "#;
        let mut r = Rtrace::from_str(text).unwrap();
        r.probe_functions().unwrap();
    }

    #[test]
    fn test_probe_functions_from_str_basic1() {
        let text = r#"
        [[function]]
        name = "tcp_rcv_state_process"
        enable = true
        params = ["basic"]
        "#;
        let mut r = Rtrace::new(None, None).unwrap();
        r.probe_functions_from_str(text).unwrap();
    }

    #[test]
    fn test_probe_functions_from_str_basic2() {
        let text = r#"
        [[function]]
        name = "tcp_rcv_state_process"
        enable = true
        params = ["basic"]
        expr = ["skb.data"]
        "#;
        let mut r = Rtrace::new(None, None).unwrap();
        r.probe_functions_from_str(text).unwrap();
    }
}
