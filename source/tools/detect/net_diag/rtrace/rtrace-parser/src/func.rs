use crate::ksyms::ksyms_addr_to_name;
use anyhow::anyhow;
use anyhow::Result;
use rtrace_rs::bindings::*;
use std::fmt;
use std::os::raw::{c_char, c_int};

#[derive(Clone, Debug, Default)]
pub struct Func {
    // Structure data contained in a single trace function.
    // Such as basic information, context or tcp window.
    name: String,
    kretname: String,
    data: Vec<u8>,
    mask: u64,
    types: Vec<*const u8>,
    extra: usize,
}

impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ty = INFO_TYPE::BASIC_INFO;
        match self.get_struct(ty) {
            Ok(x) => {
                let bi = x as *const BASIC_INFO_struct;
                unsafe {
                    writeln!(f, "{:?}", *bi);
                }
            }
            _ => {}
        }
        write!(f, "a")
    }
}

impl Func {
    pub fn new(data: Vec<u8>) -> Func {
        let mut f = Func {
            data: Vec::new(),
            name: String::new(),
            kretname: String::new(),
            mask: 0,
            types: Vec::with_capacity(64),
            extra: 0,
        };
        let mut off = 0;
        f.data = data;
        f.types.resize(64, std::ptr::null());
        f.mask = f.get_u64_by_off(0);

        for i in 0..64 {
            if ((1 << i) & f.mask) != 0 {
                let ty = INFO_TYPE::from_u32(i);
                match ty {
                    INFO_TYPE::BASIC_INFO => {
                        f.types[i as usize] = &f.data[off] as *const u8;
                        off += ty.get_size();
                    }
                    INFO_TYPE::CGROUP => {
                        f.types[i as usize] = &f.data[off] as *const u8;
                        off += ty.get_size();
                    }
                    INFO_TYPE::STACK => {
                        f.types[i as usize] = &f.data[off] as *const u8;
                        off += ty.get_size();
                    }
                    INFO_TYPE::KRETPROBE | INFO_TYPE::LINEPROBE => {
                        assert_eq!(f.types[INFO_TYPE::BASIC_INFO as usize], std::ptr::null());
                        f.types[INFO_TYPE::BASIC_INFO as usize] = &f.data[off] as *const u8;
                        off += ty.get_size();
                    }
                    _ => panic!("not support type"),
                }
            }
        }

        f.extra = off;
        if f.types[INFO_TYPE::BASIC_INFO as usize] != std::ptr::null() {
            let bi = f.types[INFO_TYPE::BASIC_INFO as usize] as *const BASIC_INFO_struct;
            unsafe { f.name = ksyms_addr_to_name((*bi).ip) };
            f.kretname = f.name.clone();
            if f.is_kretprobe() {
                unsafe { f.kretname.push_str(&format!("({})", (*bi).ret)[..]) };
            }
        }

        f
    }
    fn get_u32_by_off(&self, off: usize) -> u32 {
        let ptr = &self.data[off] as *const u8 as *const u32;
        unsafe { *ptr }
    }

    fn get_u64_by_off(&self, off: usize) -> u64 {
        let ptr = &self.data[off] as *const u8 as *const u64;
        unsafe { *ptr }
    }

    pub fn get_struct(&self, ty: INFO_TYPE) -> Result<*const u8> {
        let ptr = self.types[ty as usize];
        if ptr == std::ptr::null() {
            return Err(anyhow!("{:?} not exist", ty));
        }
        Ok(ptr)
    }

    pub fn get_name_no_offset(&self) -> String {
        let mut name = self.name.clone();
        if let Some(x) = name.find('+') {
            name.truncate(x);
        }
        name
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_kretname(&self) -> &String {
        &self.kretname
    }

    pub fn get_ts(&self) -> u64 {
        let bi = self.get_struct(INFO_TYPE::BASIC_INFO).unwrap() as *const BASIC_INFO_struct;
        unsafe { (*bi).ts }
    }

    pub fn is_send(&self) -> bool {
        (self.get_ts() & 0x1) == 1
    }

    pub fn is_kretprobe(&self) -> bool {
        (self.mask & (1 << INFO_TYPE::KRETPROBE as u64)) != 0
    }

    pub fn get_seq(&self) -> (usize, usize) {
        let bi = self.get_struct(INFO_TYPE::BASIC_INFO).unwrap() as *const BASIC_INFO_struct;
        unsafe {
            let seq = (*bi).seq as usize;
            let end_seq = (*bi).end_seq as usize;
            (seq, end_seq)
        }
    }

    pub fn get_rseq(&self) -> (usize, usize) {
        let bi = self.get_struct(INFO_TYPE::BASIC_INFO).unwrap() as *const BASIC_INFO_struct;
        unsafe {
            let rseq = (*bi).rseq as usize;
            let rend_seq = (*bi).rend_seq as usize;
            (rseq, rend_seq)
        }
    }

    pub fn get_ap(&self) -> addr_pair {
        let bi = self.get_struct(INFO_TYPE::BASIC_INFO).unwrap() as *const BASIC_INFO_struct;
        unsafe { (*bi).ap }
    }

    /// extra mean data of expression statement.
    pub fn get_extra(&self, off: usize) -> *const u8 {
        &self.data[off + self.extra] as *const u8
    }

    pub fn show_brief(&self) {
        // println!(
        //     "func: {}, seq: {:?}, rseq: {:?}, ts: {}",
        //     self.get_func_name_with_kret(),
        //     self.get_seq(),
        //     self.get_rseq(),
        //     self.get_ts()
        // );
    }

    pub fn get_stack_string(&self) -> Result<String> {
        let st = self.get_struct(INFO_TYPE::STACK)? as *const STACK_struct;
        let mut vec_str = Vec::new();
        for i in 0..5 {
            let mut tmp = unsafe {ksyms_addr_to_name((*st).kern_stack[i])};
            tmp.insert(0, '\t');
            vec_str.push(tmp);
        }
        Ok(format!("{}", vec_str.join("\n")))
    }

    pub fn show_stack(&self) {
        unsafe { println!("{}\n", self.get_stack_string().unwrap()) };
    }

    pub fn show(&self) {
        // for (i, item) in self.data.iter().enumerate() {
        //     let typ = get_type_from_ptr(*item);
        //     println!("{}: {:?}", i, typ);
        //     match get_type_from_ptr(*item) {
        //         INFO_TYPE::BASIC_INFO => {
        //             let bi = *item as *const BASIC_INFO_struct;
        //             unsafe {
        //                 println!("{:#?}", *bi);
        //             }
        //         }
        //         INFO_TYPE::CONTEXT => {
        //             let ct = *item as *const CONTEXT_struct;
        //             unsafe {
        //                 println!("{:#?}", *ct);
        //             }
        //         }
        //         INFO_TYPE::MEMORY => {
        //             let mm = *item as *const MEMORY_struct;
        //             unsafe {
        //                 println!("{:#?}", *mm);
        //             }
        //         }
        //         INFO_TYPE::TCP_WINDOW => {
        //             let tw = *item as *const TCP_WINDOW_struct;
        //             unsafe {
        //                 println!("{:#?}", *tw);
        //             }
        //         }
        //         _ => {
        //             panic!("Unknown format\n");
        //         }
        //     }
        // }
    }
}
