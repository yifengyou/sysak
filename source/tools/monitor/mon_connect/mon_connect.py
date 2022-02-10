# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     mon_connect
   Description :
   Author :       liaozhaoyan
   date:          2021/4/1
-------------------------------------------------
   Change Activity:
                   2021/4/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from bcc import BPF
from subprocess import PIPE, Popen
from socket import inet_ntop, AF_INET
from struct import pack
import shlex
import datetime
import time
import re

cmd = "netstat -antu"

class CconnAna():
    def __init__(self):
        self.__initTrace()

    def exec_cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        return p.stdout.read().strip()

    def proc(self, lines):
        dIps = {}
        for line in lines:
            line = re.sub(" +", " ", line).strip()
            ls = line.split(' ')
            if ls[-1] != 'LISTEN' and (ls[0] == 'udp' or ls[0] == 'tcp'):
                ip = ls[3].split(':')[0]
                if dIps.has_key(ip):
                    dIps[ip] += 1
                else:
                    dIps[ip] = 1
        return sorted(dIps.items(), key=lambda x: x[1], reverse=True)

    def __initTrace(self):
        self.__b = BPF(text=self._getProgFreeEnter())
        # self.__b.attach_kprobe(event="tcp_v4_conn_request", fn_name="j_tcp_v4_conn_request")
        self.__b.attach_kprobe(event="tcp_connect", fn_name="j_tcp_connect")
        self.__b.attach_kprobe(event="udp_sendmsg", fn_name="j_udp_sendmsg")

    def _report(self):
        ihs = self.__b['in_port_var']
        cUdp = cIn = cOut = 0
        c = 5
        for k, v in sorted(ihs.items(), key=lambda ihs: ihs[1].value, reverse=True):
            cIn += v.value
            if c:
                print k.port, inet_ntop(AF_INET, pack("I", k.ip)).encode(), v.value
            c -= 1
        self.__b['in_port_var'].clear()
        ohs = self.__b['out_port_var'].items()
        self.__b['out_port_var'].clear()
        uhs = self.__b['udp_port_var'].items()
        self.__b['udp_port_var'].clear()
        chs = self.__b['close_var'].items()
        self.__b['close_var'].clear()
        for h in ohs:
            # print("port: count: ", h)
            cOut += h[1].value
        for h in uhs:
            # print("port: count: ", h)
            cUdp += h[1].value
        print("%s: sync %d in, %d out, %d udp, %d close" % (datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S"), cIn, cOut, cUdp, chs[0][1].value))


    def mainLoop(self):
        while 1:
            time.sleep(10)
            self._report()
            # lines = self.exec_cmd(cmd).split('\n')
            # print datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S"), self.proc(lines[2:])


    def _getProgFreeEnter(self):
        return """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <bcc/proto.h>

    struct cell{
        u32 ip;
        u16 port;
    };

    BPF_HASH(close_var, u16, u64, 4);
    BPF_HASH(in_port_var, struct cell, u64, 65536);
    BPF_HASH(out_port_var, u16, u64, 65536);
    BPF_HASH(udp_port_var, u16, u64, 65536);

    static void increase_in_port_val(struct cell k){
        u64 v = 0;
        u64 *r;

        r = in_port_var.lookup_or_try_init(&k, &v);
        if (!r)
            return;
        v = *r;
        v ++;
        in_port_var.update(&k, &v);
    }

    static void increase_out_port_val(u16 k){
        u64 v = 0;
        u64 *r;

        r = out_port_var.lookup_or_try_init(&k, &v);
        if (!r)
            return;
        v = *r;
        v ++;
        out_port_var.update(&k, &v);
    }

    static void increase_udp_port_val(u16 k){
        u64 v = 0;
        u64 *r;

        r = udp_port_var.lookup_or_try_init(&k, &v);
        if (!r)
            return;
        v = *r;
        v ++;
        udp_port_var.update(&k, &v);
    }

    int kretprobe__inet_csk_accept(struct pt_regs *ctx)
    {
        struct cell k;
        struct sock *sk = (struct sock *)PT_REGS_RC(ctx);

        if (sk == NULL) {
            return 0;
        }
        k.port = sk->__sk_common.skc_num;
        k.ip = sk->__sk_common.skc_rcv_saddr;
        increase_in_port_val(k);
        return 0;
    }

    int kretprobe__tcp_close(struct pt_regs *ctx)
    {
        close_var.increment(0);
        return 0;
    }

    int j_tcp_v4_conn_request(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
        struct cell k;
        k.port = sk->__sk_common.skc_num;
        k.ip = sk->__sk_common.skc_daddr;
        increase_in_port_val(k);
        return 0;
    }

    int j_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
        u16 dport;
        dport = sk->__sk_common.skc_dport;
        increase_out_port_val(dport);
        return 0;
    }

    int j_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
        u16 dport;
        if (sk->__sk_common.skc_dport == 0)
        {
            dport = sk->__sk_common.skc_dport;
            increase_udp_port_val(dport);
        }
        return 0;
    }
    """


if __name__ == "__main__":
    conn = CconnAna()
    conn.mainLoop()
