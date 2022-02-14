#ifndef __RTRACE_UTILS_INSN_H
#define __RTRACE_UTILS_INSN_H

extern uint64_t insn_get_imm(struct bpf_insn *insn);
void insn_set_imm(struct bpf_insn *insn, uint64_t imm);
void insns_dump(struct bpf_insn *insns, int cnt);
#endif
