# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     retransMon
   Description :
   Author :       liaozhaoyan
   date:          2021/7/14
-------------------------------------------------
   Change Activity:
                   2021/7/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
from influxSend import CslsSend
from subprocess import PIPE, Popen
import shlex
import time
import re

socketStatCmd = "ss -tnpi"

class CretransMon(object):
    def __init__(self, host="127.0.0.1", port=8086, db='longcheer', user="admin", pswd='alios123'):
        self.__cmds = shlex.split(socketStatCmd)
        self.__send = CslsSend()
        self.__reComm = re.compile("\"(.+)\"")
        self.__rePid = re.compile("pid=[0-9]+")
        self.__reRetrans = re.compile("retrans:\\d+/\\d+")
        self.__lastDict = self.__getDict()

    def _exec(self):
        p = Popen(self.__cmds, stdout=PIPE)
        return p.stdout.readlines()

    """
    ['State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              \n', 'ESTAB      0      0      172.24.183.145:22                 42.120.75.145:35828               users:(("sshd",pid=680615,fd=3))\n', '\t cubic wscale:6,7 rto:247 rtt:46.089/0.209 ato:40 mss:1448 rcvmss:1392 advmss:1448 cwnd:8 ssthresh:7 bytes_acked:26373 bytes_received:19193 segs_out:548 segs_in:831 send 2.0Mbps lastsnd:23134 lastrcv:23093 lastack:23088 pacing_rate 4.0Mbps retrans:0/1 rcv_rtt:50 rcv_space:28960\n', 'ESTAB      0      0      172.24.183.145:22                 42.120.75.145:23932               users:(("sshd",pid=611623,fd=3))\n', '\t cubic wscale:6,7 rto:253 rtt:52.271/24.335 ato:40 mss:1448 rcvmss:1392 advmss:1448 cwnd:7 ssthresh:4 bytes_acked:7736697 bytes_received:55437 segs_out:9248 segs_in:7753 send 1.6Mbps lastsnd:1008 lastrcv:7154 lastack:905 pacing_rate 3.1Mbps retrans:0/743 reordering:4 rcv_rtt:41 rcv_space:28960\n']
    """

    def __transDict(self, lines):
        l = len(lines) / 2
        d = {}
        for i in range(l):
            l1 = lines[2 * i].strip()
            l2 = lines[2 * i + 1]
            l1 = re.sub(" +", " ", l1)
            src, dst, comm = l1.split(" ")[-3:]
            try:
                name = self.__reComm.findall(comm)[0]
            except IndexError:
                continue
            pid = self.__rePid.findall(comm)[0].split('=')[1]
            ss = self.__reRetrans.findall(l2)
            if len(ss):
                retrans = ss[0].split('/')[1]
            else:
                continue
            k = "%s %s %s %s" % (name, pid, src, dst)
            d[k] = int(retrans)
        return d

    def __getDict(self):
        lines = self._exec()
        return self.__transDict(lines[1:])

    def proc(self):
        dNow = self.__getDict()
        total = 0
        log = ""
        for k, v in dNow.items():
            if k in self.__lastDict.keys():
                delta = dNow[k] - self.__lastDict[k]
                if delta > 0:
                    total += delta
                    log += "%s retrans %d; " % (k, delta)
        if len(log):
            self.__send.put('net_retrans_log', ' log="%s"' % log[:-2])
        self.__send.put('net_retrans', ' total=%di' %total)
        self.__send.push()
        self.__lastDict = dNow

if __name__ == "__main__":
    if len(sys.argv) == 6:
        s = CretransMon(host=sys.argv[1], port=int(sys.argv[2]), db=sys.argv[3], user=sys.argv[4], pswd=sys.argv[5])
    else:
        s = CretransMon(host=sys.argv[1])
    while True:
        time.sleep(60)
        s.proc()
    pass
