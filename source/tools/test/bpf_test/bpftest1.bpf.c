#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpftest.h"



SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect,struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    u64 tgid = bpf_get_current_pid_tgid();
    return 0;
}


char LICENSE[] SEC("license") = "GPL";