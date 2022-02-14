
#include <uapi/linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "utils/insn.h"
#include "utils/disasm.h"

#define SYM_MAX_NAME 256
struct dump_data
{
	char scratch_buff[SYM_MAX_NAME + 8];
};

uint64_t insn_get_imm(struct bpf_insn *insn)
{
	uint64_t imm = 0;
	imm = insn[0].imm + ((uint64_t)insn[1].imm << 32);
	return imm;
}

void insn_set_imm(struct bpf_insn *insn, uint64_t imm)
{
	insn[0].imm = (int)((imm << 32) >> 32);
	insn[1].imm = (int)(imm >> 32);
}

static const char *print_call(void *private_data,
							  const struct bpf_insn *insn)
{
	struct dump_data *dd = private_data;
	snprintf(dd->scratch_buff, sizeof(dd->scratch_buff), "funccall");
	return dd->scratch_buff;
}

static void print_insn(void *private_data, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static const char *print_imm(void *private_data,
							 const struct bpf_insn *insn,
							 __u64 full_imm)
{
	struct dump_data *dd = private_data;

	if (insn->src_reg == BPF_PSEUDO_MAP_FD)
		snprintf(dd->scratch_buff, sizeof(dd->scratch_buff),
				 "map[id:%u]", insn->imm);
	else if (insn->src_reg == BPF_PSEUDO_MAP_VALUE)
		snprintf(dd->scratch_buff, sizeof(dd->scratch_buff),
				 "map[id:%u][0]+%u", insn->imm, (insn + 1)->imm);
	// else if (insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE)
	// 	snprintf(dd->scratch_buff, sizeof(dd->scratch_buff),
	// 			 "map[idx:%u]+%u", insn->imm, (insn + 1)->imm);
	// else if (insn->src_reg == BPF_PSEUDO_FUNC)
	// 	snprintf(dd->scratch_buff, sizeof(dd->scratch_buff),
	// 			 "subprog[%+d]", insn->imm);
	else
		snprintf(dd->scratch_buff, sizeof(dd->scratch_buff),
				 "0x%llx", (unsigned long long)full_imm);
	return dd->scratch_buff;
}

void insns_dump(struct bpf_insn *insns, int cnt)
{
	struct dump_data dd = {0};
	const struct bpf_insn_cbs cbs = {
		.cb_print = print_insn,
		.cb_call = print_call,
		.cb_imm = print_imm,
		.private_data = &dd,
	};
	int i;
	bool double_insn = false;

	for (i = 0; i < cnt; i++)
	{
		if (double_insn)
		{
			double_insn = false;
			continue;
		}

		double_insn = insns[i].code == (BPF_LD | BPF_IMM | BPF_DW);
		printf("% 4d: ", i);
		print_bpf_insn(&cbs, insns + i, true);
	}
}