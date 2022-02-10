use crate::bindings::*;
use anyhow::anyhow;
use anyhow::Result;
use libbpf_sys::{
    bpf_insn, bpf_link, bpf_program, BPF_ALU64, BPF_CALL, BPF_DW, BPF_EXIT, BPF_IMM, BPF_JMP,
    BPF_LD, BPF_MOV, BPF_REG_1, BPF_REG_10, BPF_X,
};

pub const INSNS_SPLIT_POS: usize = 18;

#[derive(Clone, Debug)]
pub struct Prog {
    ptr: *const bpf_program,

    builtin_insn_pos: i32,
    cd_off: i32,
    origin_insns: Vec<bpf_insn>,

    insns: Vec<bpf_insn>,
    bl: *mut bpf_link,
}

impl Prog {
    pub fn new(ptr: *const bpf_program) -> Prog {
        let mut p = Prog {
            ptr,
            builtin_insn_pos: -1,
            cd_off: i32::MAX,
            origin_insns: Vec::new(),
            insns: Vec::with_capacity(4096),
            bl: std::ptr::null_mut(),
        };
        p.clone_insns();
        p.builtin_insn_pos = p.find_builtin_insn_pos();
        p.cd_off = p.find_cd_off();
        p
    }

    /// delete patched instructions, and reset original status.
    pub fn reset(&mut self) {
        self.insns.clear();
    }

    fn sys_prog_insns(&self) -> *const bpf_insn {
        unsafe { libbpf_sys::bpf_program__insns(self.ptr) }
    }

    fn sys_prog_insns_cnt(&self) -> usize {
        unsafe { libbpf_sys::bpf_program__insn_cnt(self.ptr) as usize }
    }

    pub fn is_double_insn(&self, insn: bpf_insn) -> bool {
        insn.code as u32 == (BPF_LD | BPF_IMM | BPF_DW)
    }

    fn clone_insns(&mut self) {
        let cnt = self.sys_prog_insns_cnt();
        let insns = self.sys_prog_insns();

        for i in 0..cnt {
            unsafe { self.origin_insns.push(*insns.offset(i as isize)) };
        }
    }

    fn find_cd_off(&mut self) -> i32 {
        // * 1139: (bf) r1 = r10
        // * 1140: (07) r1 += -280
        // * 1141: (bf) r1 = r1
        // * 1142: (b7) r0 = 0
        // * 1143: (95) exit
        let tmp_insn = self.origin_insns[self.origin_insns.len() - INSNS_SPLIT_POS];
        if tmp_insn.code == (BPF_ALU64 | BPF_MOV | BPF_X) as u8
            && tmp_insn.dst_reg() == BPF_REG_1 as u8
            && tmp_insn.src_reg() == BPF_REG_10 as u8
        {
            return self.origin_insns[self.origin_insns.len() - INSNS_SPLIT_POS + 1].imm;
        }
        i32::MAX
    }

    fn find_builtin_insn_pos(&mut self) -> i32 {
        let mut double_insn = false;
        for i in 0..self.origin_insns.len() {
            if double_insn {
                double_insn = false;
                continue;
            }
            // 0: (79) r9 = *(u64 *)(r1 +104)
            // 1: (7b) *(u64 *)(r10 -296) = r1
            // 2: (79) r8 = *(u64 *)(r1 +112)
            // 3: (7b) *(u64 *)(r10 -32) = r8
            // 4: (b7) r7 = 2184
            // 5: (b7) r6 = 0
            double_insn = self.is_double_insn(self.origin_insns[i]);
            // notice: not double insns.
            if !double_insn {
                let imm = self.origin_insns[i].imm as u64;
                if imm == 0x888 {
                    return i as i32;
                }
            }
        }
        -1
    }

    pub fn patch_builtin_insn(&mut self, mask: u64) -> Result<()> {
        if self.builtin_insn_pos < 0 {
            return Err(anyhow!("unable to find target builtin insn"));
        }
        self.origin_insns[self.builtin_insn_pos as usize].imm = mask as i32;
        Ok(())
    }

    /// Merge the instructions of the ebpf program with the newly
    /// generated instructions.
    ///  
    ///  1. copy insns.
    ///  1. Calculate the instruction split point based on the previous buried
    ///  point position.
    ///  1. fixup jmp.
    ///  1. Merge instructions.
    pub fn patch_dynamic_insn(&mut self, insns: &Vec<bpf_insn>) -> Result<()> {
        let mark_off = self.origin_insns.len() - INSNS_SPLIT_POS;
        // copy insns
        for i in 0..mark_off {
            self.insns.push(self.origin_insns[i]);
        }
        // fixup jmp
        for i in 0..self.insns.len() {
            let class = self.insns[i].code & 0x07;
            let opcode;

            if class != BPF_JMP as u8 {
                continue;
            }

            opcode = self.insns[i].code & 0xf0;
            if opcode == BPF_CALL as u8 || opcode == BPF_EXIT as u8 {
                continue;
            }

            if self.insns[i].off as usize + i + 1 >= mark_off + 3 {
                self.insns[i].off += insns.len() as i16;
            }
        }
        // merge insns
        for i in 0..insns.len() {
            self.insns.push(insns[i]);
        }
        // copy left insns
        for i in mark_off..self.origin_insns.len() {
            self.insns.push(self.origin_insns[i]);
        }
        // fix err code
        for i in 0..self.insns.len() {
            let class = self.insns[i].code & 0x07;
            let opcode;

            if class != BPF_JMP as u8 {
                continue;
            }

            opcode = self.insns[i].code & 0xf0;
            if opcode == BPF_CALL as u8 || opcode == BPF_EXIT as u8 {
                continue;
            }

            if self.insns[i].off == 4096 {
                self.insns[i].off = (self.insns.len() - 5 - i - 1) as i16;
            }
        }
        Ok(())
    }

    pub fn insns(&self) -> *const bpf_insn {
        if self.insns.len() == 0 {
            return self.origin_insns.as_ptr() as *const bpf_insn;
        }
        self.insns.as_ptr() as *const bpf_insn
    }

    pub fn insns_cnt(&self) -> usize {
        if self.insns.len() == 0 {
            return self.origin_insns.len();
        }
        self.insns.len()
    }

    /// return struct cache_data offset in eBPF program stack
    pub fn cd_off(&self) -> i32 {
        self.cd_off
    }

    /// return builtin mask instruction position
    pub fn builtin_insn_pos(&self) -> i32 {
        self.builtin_insn_pos
    }

    /// c raw pointer
    pub fn raw_ptr(&self) -> *const bpf_program {
        self.ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    #[test]
    fn test_prog_find_builtin_insn_pos() {
        let ptr = unsafe { rtrace_alloc_and_init(std::ptr::null_mut(), std::ptr::null_mut()) };
        let name = CString::new("ip_queue_xmit").unwrap();
        let prog_ptr = unsafe { rtrace_trace_program(ptr, name.as_ptr(), 0, 0) };
        let prog = Prog::new(prog_ptr);
        assert_eq!(prog.builtin_insn_pos() > 0, true);

        let name = CString::new("kretprobe_common").unwrap();
        let prog_ptr = unsafe { rtrace_trace_program(ptr, name.as_ptr(), 0, 0) };
        let prog = Prog::new(prog_ptr);
        assert_eq!(prog.builtin_insn_pos() > 0, false);
    }

    #[test]
    fn test_prog_find_cd_off() {
        let ptr = unsafe { rtrace_alloc_and_init(std::ptr::null_mut(), std::ptr::null_mut()) };
        let name = CString::new("ip_queue_xmit").unwrap();
        let prog_ptr = unsafe { rtrace_trace_program(ptr, name.as_ptr(), 0, 0) };
        let prog = Prog::new(prog_ptr);
        assert_ne!(prog.cd_off(), i32::MAX);

        let name = CString::new("kretprobe_common").unwrap();
        let prog_ptr = unsafe { rtrace_trace_program(ptr, name.as_ptr(), 0, 0) };
        let prog = Prog::new(prog_ptr);
        assert_eq!(prog.cd_off(), i32::MAX);
    }
}
