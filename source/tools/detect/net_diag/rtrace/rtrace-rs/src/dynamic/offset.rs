use crate::bindings::*;
use crate::dynamic::parser::{CastType, Field, Parser};
use anyhow::anyhow;
use anyhow::Result;
use std::ffi::CString;
use std::os::raw::c_char;

pub struct OffsetInfo {
    offs: Vec<i32>,
    arg: i32, //position
    size: i32,
}

pub struct Offset {
    r: *mut rtrace,
}

impl Offset {
    pub fn new(r: *mut rtrace) -> Offset {
        Offset { r }
    }

    pub fn parse(&mut self, func_proto_id: u32, fields: &Vec<Field>) -> Result<dynamic_offsets> {
        let mut dos = dynamic_offsets::default();
        let mut dfs = Vec::new();
        for field in fields {
            let mut cast_name_ptr = std::ptr::null_mut();
            let mut pointer = 0;
            let mut index = -1;
            let mut cast_type = 0;
            if let Some(cast) = &field.cast {
                match &cast.ct {
                    CastType::Struct(name) => {
                        cast_name_ptr = name.as_ptr() as *mut c_char;
                        cast_type = libbpf_sys::BTF_KIND_STRUCT;
                    }
                    _ => return Err(anyhow!("CastType: {:?} not support", cast)),
                }
                pointer = cast.pointer;
            }
            if let Some(x) = field.index {
                index = x;
            }
            dfs.push(dynamic_fields {
                ident: field.ident.as_ptr() as *mut c_char,
                cast_name: cast_name_ptr,
                cast_type: cast_type as i32,
                index: index,
                pointer: pointer,
            });
        }
        let ret = unsafe {
            rtrace_dynamic_gen_offset(
                self.r,
                dfs.as_ptr() as *mut dynamic_fields,
                dfs.len() as i32,
                func_proto_id as i32,
                &mut dos,
            )
        };

        if ret != 0 {
            return Err(anyhow!("rtrace dynamic gen offsets failed: err {}", ret));
        }
        Ok(dos)
    }
}
