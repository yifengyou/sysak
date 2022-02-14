use crate::bindings::*;
use crate::dynamic::offset::Offset;
use crate::dynamic::parser::Parser;
use crate::rtrace::Function;
use anyhow::anyhow;
use anyhow::Result;
use libbpf_sys::{bpf_insn, btf, btf_type};
use std::ffi::CString;
use log::*;

pub struct Dynamic {
    func: CString,
    exprs: Vec<String>,

    sz: Vec<u8>,
}

impl Dynamic {
    pub fn new(function: &Function) -> Result<Dynamic> {
        let mut exprs = Vec::new();
        if let Some(xs) = &function.exprs {
            exprs = xs.clone();
        }
        
        Ok(Dynamic {
            func: CString::new(function.name.clone())?,
            exprs,
            sz: Vec::new(),
        })
    }

    pub fn codegen(&mut self, r: *mut rtrace, cd_off: i32) -> Result<Vec<bpf_insn>> {
        let mut insns = vec![bpf_insn::default(); 4096usize];
        let btf = unsafe { rtrace_dynamic_btf(r) };
        let func_id = unsafe {
            libbpf_sys::btf__find_by_name_kind(btf, self.func.as_ptr(), libbpf_sys::BTF_KIND_FUNC)
        };
        if func_id <= 0 {
            return Err(anyhow!("unable to find function: {:?} in btf", self.func));
        }
        let bt = unsafe { libbpf_sys::btf__type_by_id(btf, func_id as u32) };
        let func_proto_id = unsafe { (*bt).__bindgen_anon_1.type_ };
        let mut p = Parser::new();
        let mut o = Offset::new(r);
        let mut insns_cnt = 0;

        for expr in &self.exprs {
            debug!("expr: {}", expr);
            let fields = p.parse(expr)?;
            debug!("fields: {:?}", fields);
            let mut offsets = o.parse(func_proto_id, &fields)?;
            self.sz.push(offsets.size as u8);
            debug!("expr size: {}", offsets.size);
            let ret =
                unsafe { rtrace_dynamic_gen_insns(r, &mut offsets, &mut insns[insns_cnt], cd_off) };
            if ret <= 0 {
                return Err(anyhow!("failed to generate insns"));
            }

            insns_cnt += ret as usize;
        }
        insns.resize(insns_cnt, bpf_insn::default());
        Ok(insns)
    }

    pub fn get_sz(&self) -> &Vec<u8>{
        &self.sz
    }

    pub fn get_exprs(&self) -> &Vec<String>{
        &self.exprs
    }
}
