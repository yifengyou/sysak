#include <assert.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/ptrace.h>
#include <sys/resource.h>

#include "common.usr.h"
#include "utils/btf.h"
#include <linux/filter.h>

#include "rtrace.h"
#include "rtrace.skel.h"

#define RTRACE_DYNAMIC_CTX_REG BPF_REG_6
#define JMP_ERR_CODE 4096

#define BPF_ALU64_REG(OP, DST, SRC)             \
    ((struct bpf_insn){                         \
        .code = BPF_ALU64 | BPF_OP(OP) | BPF_X, \
        .dst_reg = DST,                         \
        .src_reg = SRC,                         \
        .off = 0,                               \
        .imm = 0})

struct rtrace
{
    struct rtrace_bpf *obj;
    char *pin_path;
    char *btf_custom_path;
    struct btf *btf;
};

bool gdebug = false;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (gdebug)
        return vfprintf(stderr, format, args);
    return 0;
}

int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

/**
 * @brief enable debug or not
 *
 * @param debug debug output or not
 */
void rtrace_set_debug(bool debug)
{
    gdebug = debug;
}

/**
 * @brief Get the fd of the perf map
 *
 * @param r rtrace context
 * @return int map fd of type BPF_MAP_TYPE_PERF_EVENT_ARRAY
 */
int rtrace_perf_map_fd(struct rtrace *r)
{
    return bpf_map__fd(r->obj->maps.perf);
}
/**
 * @brief Get the fd of the filter map
 *
 * @param r rtrace context
 * @return int fd of filter map
 */
int rtrace_filter_map_fd(struct rtrace *r)
{
    return bpf_map__fd(r->obj->maps.filter_map);
}

static void rtrace_free(struct rtrace *r) 
{
    rtrace_bpf__destroy(r->obj);

    free(r->btf);
    r->btf = NULL;

    free(r->btf_custom_path);
    r->btf_custom_path = NULL;
    
    free(r->pin_path);
    r->pin_path = NULL;

    free(r);
}

static int rtrace_init(struct rtrace *r, char *btf_custom_path, char *pin_path)
{
    int err;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    r->btf_custom_path = btf_custom_path;
    r->pin_path = pin_path;
    open_opts.btf_custom_path = btf_custom_path;
    r->obj = rtrace_bpf__open_opts(&open_opts);
    if (!r->obj)
    {
        pr_err("failed to open BPF object\n");
        err = -EINVAL;
        goto err_out;
    }

    err = rtrace_bpf__load(r->obj);
    if (err)
    {
        pr_err("failed to load bpf, err: %s\n", strerror(-err));
        goto err_out;
    }

    if (pin_path)
    {
        err = bpf_object__pin_maps(r->obj->obj, pin_path);
        if (err)
        {
            pr_err("failed to pin maps\n");
            goto err_out;
        }
    }

    r->btf = btf_load(btf_custom_path);
    if (!r->btf)
    {
        pr_err("Failed to load vmlinux BTF: %d, err msg: %s\n", -errno, strerror(errno));
        err = -errno;
        goto err_out;
    }

    return 0;

err_out:

    return err;
}

/**
 * @brief
 *
 * @param btf_custom_path
 * @param pin_path
 * @return struct rtrace*
 */
struct rtrace *rtrace_alloc_and_init(char *btf_custom_path, char *pin_path)
{
    struct rtrace *r;
    int err;

    r = malloc(sizeof(struct rtrace));
    if (!r)
    {
        errno = ENOMEM;
        return NULL;
    }

    err = rtrace_init(r, btf_custom_path, pin_path);
    if (err)
    {
        errno = -err;
        goto err_out;
    }
    return r;

err_out:
    rtrace_free(r);
    return NULL;
}

/**
 * @brief Find the corresponding ebpf program according to the function name and the sk,
 * skb parameter positions
 *
 * @param r rtrace context
 * @param func function name, eg. __ip_queue_xmit
 * @param sk optional, the parameter position of the sk parameter in the function prototype
 * @param skb optional, the parameter position of the skb parameter in the function prototype
 * @return struct bpf_program* ebpf program
 */
struct bpf_program *rtrace_trace_program(struct rtrace *r, char *func, int sk, int skb)
{
    struct bpf_program *prog;
    int err, func_proto_id;

    err = 0;
    if (is_special_func(func))
    {
        prog = bpf_object__find_program_by_name(r->obj->obj, func);
        goto find_prog;
    }

    // When skb is 0, it means that the skb parameter position
    // needs to be automatically located.
    if (skb == 0)
    {
        func_proto_id = btf_find_func_proto_id(r->btf, func);
        sk = btf_func_proto_find_param_pos(r->btf, func_proto_id, "sock", NULL);
        sk = sk < 0 ? 0 : sk;
        skb = btf_func_proto_find_param_pos(r->btf, func_proto_id, "sk_buff", NULL);
        if (skb <= 0)
        {
            err = skb;
            goto err_out;
        }
    }
    prog = object_find_program(r->obj->obj, sk, skb);

find_prog:
    if (!prog)
    {
        err = -ENOENT;
        goto err_out;
    }

    pr_dbg("find prog: %s for func: %s, sk = %d, skb = %d\n", bpf_program__name(prog), func, sk, skb);
    return prog;

err_out:
    pr_err("failed to find prog for func: %s, sk = %d, skb = %d, err = %d.\n", func, sk, skb, err);
    errno = -err;
    return NULL;
}

/**
 * @brief Load the incoming ebpf instruction, after verification by the kernel,
 * return the corresponding file descriptor
 *
 * @param r rtrace context
 * @param prog bpf program to laod
 * @param insns the ebpf instruction that really needs to be loaded
 * @param insns_cnt instruction count
 * @return int fd
 */
int rtrace_trace_load_prog(struct rtrace *r, struct bpf_program *prog,
                           struct bpf_insn *insns, size_t insns_cnt)
{
    struct bpf_load_program_attr attr;
    static const int log_buf_size = 1024 * 1024;
    char log_buf[log_buf_size];
    int fd;

    // if (gdebug)
    //     insns_dump(insns, insns_cnt);

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = bpf_program__get_type(prog);
    attr.expected_attach_type = bpf_program__get_expected_attach_type(prog);
    attr.name = bpf_program__name((const struct bpf_program *)prog);
    attr.insns = insns;
    attr.insns_cnt = insns_cnt;
    attr.license = "Dual BSD/GPL";
    attr.kern_version = bpf_object__kversion(r->obj->obj);
    attr.prog_ifindex = 0;

    // fd = bpf_load_program_xattr(&attr, log_buf, log_buf_size);
    fd = bpf_load_program_xattr(&attr, NULL, 0);
    if (fd < 0)
    {
        printf("%s\n", log_buf);
        return fd;
    }
    bpf_program__nth_fd(prog, fd);
    return fd;
}

struct dynamic_parse
{
    struct
    {
        int offset; // in bits
        int size;
        int elem_size;
        bool is_ptr;
    } attr[10];
    int cnt;

    int offsets[10];
    int offset_cnt;
    int size;
    int arg_pos;
};

#define OFFSET_REGS_PARM1 offsetof(struct pt_regs, rdi)
#define OFFSET_REGS_PARM2 offsetof(struct pt_regs, rsi)
#define OFFSET_REGS_PARM3 offsetof(struct pt_regs, rdx)
#define OFFSET_REGS_PARM4 offsetof(struct pt_regs, rcx)
#define OFFSET_REGS_PARM5 offsetof(struct pt_regs, r8)

static int dynamic_ptregs_param_offset(int param_pos)
{
    if (param_pos >= 5 || param_pos <= 0)
        return -EINVAL;

    switch (param_pos)
    {
    case 1:
        return OFFSET_REGS_PARM1;
    case 2:
        return OFFSET_REGS_PARM2;
    case 3:
        return OFFSET_REGS_PARM3;
    case 4:
        return OFFSET_REGS_PARM4;
    case 5:
        return OFFSET_REGS_PARM5;
    default:
        return -EINVAL;
    }
    return -EINVAL;
}

/**
 * @brief Calculate the corresponding offset according to the accessed structure member
 *
 * @param r rtrace context
 * @param df array of members accessed by the structure
 * @param df_cnt array length
 * @param func_proto_id btf id
 * @param dos offsets for struct members
 * @return int 0 is ok
 */
int rtrace_dynamic_gen_offset(struct rtrace *r, struct dynamic_fields *df,
                              int df_cnt, int func_proto_id, struct dynamic_offsets *dos)
{
    struct dynamic_parse dp = {0};
    const struct btf_member *mem;
    int i, err, offset, pre_typeid, root_typeid, cnt, off_sum;

    if (!r || !r->btf || df_cnt <= 0)
        return -EINVAL;

    root_typeid = btf_func_proto_find_param(r->btf, func_proto_id, NULL, df[0].ident);
    if (root_typeid <= 0)
    {
        pr_err("failed to find param: %s in function", df[0].ident);
        err = root_typeid;
        goto err_out;
    }

    err = btf_func_proto_find_param_pos(r->btf, func_proto_id, NULL, df[0].ident);
    if (err <= 0)
    {
        pr_err("failed to find param pos: %s in function", df[0].ident);
        goto err_out;
    }

    cnt = 0;
    dp.attr[cnt].offset = err;
    if (df[0].cast_type > 0)
    {
        root_typeid = btf__find_by_name_kind(r->btf, df[0].cast_name, df[0].cast_type);
        if (root_typeid < 0)
        {
            pr_err("failed to do casting\n");
            err = root_typeid;
            goto err_out;
        }
        if (df[0].pointer == 1)
            dp.attr[cnt].is_ptr = true;
        else
            dp.attr[cnt].is_ptr = false;
    }
    else
        dp.attr[cnt].is_ptr = btf_typeid_has_ptr(r->btf, root_typeid);

    cnt++;
    pre_typeid = root_typeid;
    for (i = 1; i < df_cnt; i++)
    {
        offset = 0;
        mem = btf_find_member(r->btf, pre_typeid, df[i].ident, &offset);
        if (mem == NULL)
        {
            err = -errno;
            pr_err("failed to find member: %s in struct: %s, err = %d\n", df[i].ident, btf__name_by_offset(r->btf, btf__type_by_id(r->btf, pre_typeid)->name_off), err);
            goto err_out;
        }
        dp.attr[cnt].offset = offset;
        if (df[i].cast_type > 0)
        {
            pre_typeid = btf__find_by_name_kind(r->btf, df[i].cast_name, df[i].cast_type);
            if (pre_typeid < 0)
            {
                pr_err("failed to do casting\n");
                err = pre_typeid;
                goto err_out;
            }
            if (df[i].pointer == 1)
                dp.attr[cnt].is_ptr = true;
            else
                dp.attr[cnt].is_ptr = false;
        }
        else
        {
            dp.attr[cnt].is_ptr = btf_typeid_has_ptr(r->btf, mem->type);
            pre_typeid = mem->type;
        }

        cnt++;
    }

    dp.cnt = cnt;

    off_sum = 0;
    cnt = 0;
    for (i = 1; i < dp.cnt - 1; i++)
    {
        off_sum += dp.attr[i].offset;
        if (dp.attr[i].is_ptr)
        {
            dp.offsets[cnt++] = off_sum / 8;
            off_sum = 0;
        }
    }
    dos->offs[cnt++] = (dp.attr[dp.cnt - 1].offset + off_sum) / 8;
    dos->cnt = cnt;
    dos->size = btf__resolve_size(r->btf, pre_typeid);
    dos->arg = dp.attr[0].offset;

    pr_dbg("offset array:\n");
    for (i = 0; i < dos->cnt; i++)
        pr_dbg("%d %s", dos->offs[i], i == dos->cnt - 1 ? "\n" : "");

    return 0;

err_out:
    return err;
}

/**
 * @brief
 *
 * @param r rtrace context
 * @param dos offsets for struct members
 * @param insns pointer to save instructions
 * @param cd_off struct cache_data offset in stack
 * @return int instruction count
 */
int rtrace_dynamic_gen_insns(struct rtrace *r, struct dynamic_offsets *dos, struct bpf_insn *insns, int cd_off)
{
    int i, insns_cnt, ctx_off, regs_off, buff_off;

    insns_cnt = 0;
    ctx_off = cd_off + offsetof(struct cache_data, ctx);
    buff_off = cd_off + offsetof(struct cache_data, buffer);
    insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, RTRACE_DYNAMIC_CTX_REG, BPF_REG_10, ctx_off);

    regs_off = dynamic_ptregs_param_offset(dos->arg);
    insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_3, RTRACE_DYNAMIC_CTX_REG, regs_off);
    for (i = 0; i < dos->cnt - 1; i++)
    {
        insns[insns_cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, dos->offs[i]);
        insns[insns_cnt++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        insns[insns_cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8);
        insns[insns_cnt++] = BPF_MOV64_IMM(BPF_REG_2, 8);
        insns[insns_cnt++] = BPF_EMIT_CALL(BPF_FUNC_probe_read);
        insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_10, -8);
    }
    insns[insns_cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, dos->offs[i]);
    insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, buff_off);
    insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0);
    insns[insns_cnt++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_2, MAX_BUFFER_SIZE - dos->size, JMP_ERR_CODE);
    insns[insns_cnt++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2);
    insns[insns_cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 8);
    insns[insns_cnt++] = BPF_MOV64_IMM(BPF_REG_2, dos->size);
    insns[insns_cnt++] = BPF_EMIT_CALL(BPF_FUNC_probe_read);
    insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, buff_off);
    insns[insns_cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0);
    insns[insns_cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, dos->size);
    insns[insns_cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, 0);

    pr_dbg("generate new insns, insns cnt: %d\n", insns_cnt);
    // if (gdebug)
    //     insns_dump(insns, insns_cnt);
    return insns_cnt;
}

struct btf *rtrace_dynamic_btf(struct rtrace *r)
{
    return r->btf;
}