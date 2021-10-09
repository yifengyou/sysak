#include "lbc.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

#define TASK_COMM_LEN 16
#define CON_NAME_LEN 72
#define TASK_RUNNING 0
#define TASK_BLOCK_MAX 100000

LBC_HASH(start, u32, u64, 16384);
struct data_rq_t {
    u32 pid;
    u64 delta_us;
    char task[TASK_COMM_LEN];
    char con[CON_NAME_LEN];
};
LBC_PERF_OUTPUT(delay_out, struct data_rq_t, 128);

static int trace_enqueue(u32 tgid, u32 pid)
{
    if (pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

static void store_con(char* con, struct task_struct *p)
{
    struct cgroup_name *cname;
    cname = BPF_CORE_READ(p, cgroups, subsys[0], cgroup, name);
    if (cname != NULL) {
        char *name;

        bpf_core_read(&name, sizeof(void *), &cname->name);
        bpf_core_read(con, CON_NAME_LEN, name);
    } else {
        con[0] = '\0';
    }
}

SEC("kprobe/wake_up_new_task")
int trace_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct *p = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 tgid = BPF_CORE_READ(p, tgid);
    u32 pid = BPF_CORE_READ(p, pid);
    return trace_enqueue(tgid, pid);
}

SEC("kprobe/ttwu_do_wakeup")
int trace_ttwu_do_wakeup(struct pt_regs *ctx)
{
    struct task_struct *p = (struct task_struct *)PT_REGS_PARM2(ctx);
    u32 tgid =BPF_CORE_READ(p, tgid);
    u32 pid = BPF_CORE_READ(p, pid);
    return trace_enqueue(tgid, pid);
}
// calculate latency
SEC("kprobe/finish_task_switch")
int trace_finish_task_switch(struct pt_regs *ctx)
{
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 pid, tgid;
    u64 *tsp, delta_us;

    // ivcsw: treat like an enqueue event and store timestamp
    if (BPF_CORE_READ(prev, state) == TASK_RUNNING) {
        tgid = BPF_CORE_READ(prev, tgid);
        pid = BPF_CORE_READ(prev, pid);
        u64 ts = bpf_ktime_get_ns();
        if (pid != 0) {
            bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
        }
    }
    pid = bpf_get_current_pid_tgid();
    // fetch timestamp and calculate delta
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    if (delta_us <= TASK_BLOCK_MAX)
        return 0;
    struct task_struct *curr_task;
    struct data_rq_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;

    bpf_get_current_comm(&data.task, sizeof(data.task));
    curr_task = (struct task_struct *) bpf_get_current_task();
    store_con(&data.con[0], curr_task);
    // output
    bpf_perf_event_output(ctx, &delay_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    bpf_map_delete_elem(&start, &pid);
    return 0;
}

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
    char con[CON_NAME_LEN];
};

LBC_PERF_OUTPUT(oom_out, struct data_t, 128);

SEC("kprobe/oom_kill_process")
int oom_kill_process(struct pt_regs *ctx)
{
    struct data_t data = {};
    int ret;
    struct task_struct *p = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.fpid = pid;
    data.tpid = BPF_CORE_READ(p, pid);
    data.pages = BPF_CORE_READ(p, mm, total_vm);
    bpf_get_current_comm(&data.fcomm, TASK_COMM_LEN);
    bpf_probe_read(&data.tcomm[0], TASK_COMM_LEN, &p->comm[0]);

    store_con(&data.con[0], p);
    bpf_perf_event_output(ctx, &oom_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
