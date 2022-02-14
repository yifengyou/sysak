use anyhow::anyhow;
use anyhow::Result;
use libbpf_sys::{bpf_insn, bpf_program, btf, size_t};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::raw::{c_char, c_int};

#[derive(PartialEq, Debug, Copy, Clone)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum Protocol {
    IPPROTO_ICMP = 1,
    IPPROTO_TCP = 6,
    IPPROTO_UDP = 17,

    IPPROTO_TCP_SYN = (1 << 8) + 6,
}

impl Protocol {
    pub fn from_string(protocol: &String) -> Result<Protocol> {
        match &protocol[..] {
            "icmp" => Ok(Protocol::IPPROTO_ICMP),
            "tcp" => Ok(Protocol::IPPROTO_TCP),
            "udp" => Ok(Protocol::IPPROTO_UDP),
            "tcp-syn" => Ok(Protocol::IPPROTO_TCP_SYN),
            _ => Err(anyhow!("could not parse protocol type")),
        }
    }

    pub fn into_str(ty: &Protocol) -> &str {
        match ty {
            Protocol::IPPROTO_ICMP => "icmp",
            Protocol::IPPROTO_TCP => "tcp",
            Protocol::IPPROTO_UDP => "udp",
            Protocol::IPPROTO_TCP_SYN => "tcp-syn",
            _ => "unknown",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Hash, Copy, Clone, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct addr_pair {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

impl addr_pair {
    pub fn from_string(src: &String, dst: &String) -> Result<addr_pair> {
        let s: SocketAddrV4 = src.parse()?;
        let d: SocketAddrV4 = dst.parse()?;
        Ok(addr_pair {
            saddr: u32::from_le_bytes(s.ip().octets()),
            daddr: u32::from_le_bytes(d.ip().octets()),
            sport: s.port(),
            dport: d.port(),
        })
    }

    pub fn into_string(&self) -> String {
        format!(
            "{} - {}",
            SocketAddrV4::new(Ipv4Addr::from(u32::from_be(self.saddr)), self.sport),
            SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(self.daddr)),
                self.dport
            )
        )
    }
}

#[allow(non_camel_case_types)]
#[derive(Default, Copy, Clone, Debug)]
#[repr(C)]
pub struct pid_info {
    pub pid: u32,
    pub comm: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug)]
pub struct BASIC_INFO_struct {
    pub mask: u64,
    pub ip: u64,
    pub ts: u64,
    pub seq: u32,
    pub end_seq: u32,
    pub rseq: u32,
    pub rend_seq: u32,
    pub ap: addr_pair,
    pub pi: pid_info,
    pub ret: u64,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct CGROUP_struct {
    pub inum: u32,
    __pad_4: [u8; 4],
    pub cgroupid: u64,
}

#[allow(non_camel_case_types)]
#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct STACK_struct {
    pub kern_stack: [u64; 5],
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Copy, Clone)]
#[repr(u32)]
pub enum INFO_TYPE {
    BASIC_INFO = 0,
    CGROUP,
    STACK,
    KRETPROBE, // Get the return parameter of the function
    LINEPROBE,
    ENUM_END,
}

impl INFO_TYPE {
    pub fn from_string(string: &String) -> Result<INFO_TYPE> {
        match string.as_str() {
            "basic" => Ok(INFO_TYPE::BASIC_INFO),
            "cgroup" => Ok(INFO_TYPE::CGROUP),
            "stack" => Ok(INFO_TYPE::STACK),
            "kretprobe" => Ok(INFO_TYPE::KRETPROBE),
            "lineprobe" => Ok(INFO_TYPE::LINEPROBE),
            _ => Err(anyhow!("{} -> INFO_TYPE not support", string)),
        }
    }

    pub fn from_u32(value: u32) -> INFO_TYPE {
        match value {
            0 => INFO_TYPE::BASIC_INFO,
            1 => INFO_TYPE::CGROUP,
            2 => INFO_TYPE::STACK,
            3 => INFO_TYPE::KRETPROBE,
            4 => INFO_TYPE::LINEPROBE,
            5 => INFO_TYPE::ENUM_END,
            _ => panic!("Unknown value: {}", value),
        }
    }

    pub fn get_size(&self) -> usize {
        let sz;
        match self {
            INFO_TYPE::BASIC_INFO => sz = std::mem::size_of::<BASIC_INFO_struct>(),
            INFO_TYPE::CGROUP => sz = std::mem::size_of::<CGROUP_struct>(),
            INFO_TYPE::STACK => sz = std::mem::size_of::<STACK_struct>(),
            INFO_TYPE::KRETPROBE => sz = std::mem::size_of::<BASIC_INFO_struct>(),
            INFO_TYPE::LINEPROBE => sz = std::mem::size_of::<BASIC_INFO_struct>(),
            _ => sz = 0,
        }
        sz
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct filter_meta {
    pub pid: c_int,
    pub ap: addr_pair,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct filter_params {
    pub fm: [filter_meta; 10usize],
    pub protocol: u32,
    pub cnt: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct dynamic_offsets {
    pub offs: [c_int; 10usize],
    pub cnt: c_int,
    pub arg: c_int,
    pub size: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dynamic_fields {
    pub ident: *mut c_char,
    pub cast_name: *mut c_char,
    pub cast_type: c_int,
    pub index: c_int,
    pub pointer: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtrace {
    _unused: [u8; 0],
}

extern "C" {
    pub fn rtrace_dynamic_gen_offset(
        r: *mut rtrace,
        df: *mut dynamic_fields,
        df_cnt: c_int,
        func_proto_id: c_int,
        dos: *mut dynamic_offsets,
    ) -> c_int;
}

extern "C" {
    pub fn rtrace_dynamic_gen_insns(
        r: *mut rtrace,
        dos: *mut dynamic_offsets,
        insns: *mut bpf_insn,
        cd_off: c_int,
    ) -> c_int;
}

extern "C" {
    pub fn rtrace_dynamic_btf(r: *mut rtrace) -> *mut btf;
}

extern "C" {
    pub fn rtrace_alloc_and_init(
        pin_path: *mut ::std::os::raw::c_char,
        btf_custom_path: *mut ::std::os::raw::c_char,
    ) -> *mut rtrace;
}

extern "C" {
    pub fn rtrace_perf_map_fd(r: *mut rtrace) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn rtrace_filter_map_fd(r: *mut rtrace) -> ::std::os::raw::c_int;
}

extern "C" {
    pub fn rtrace_trace_load_prog(
        r: *mut rtrace,
        prog: *const bpf_program,
        insns: *const bpf_insn,
        insns_cnt: size_t,
    ) -> c_int;
}

extern "C" {
    pub fn rtrace_trace_program(
        r: *mut rtrace,
        func: *const c_char,
        sk: c_int,
        skb: c_int,
    ) -> *mut bpf_program;
}

extern "C" {
    pub fn rtrace_set_debug(debug: bool);
}
