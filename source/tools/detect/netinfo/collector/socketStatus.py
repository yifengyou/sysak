# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     socketStatus
   Description :
   Author :       liaozhaoyan
   date：          2021/10/23
-------------------------------------------------
   Change Activity:
                   2021/10/23:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import sys
from .baseCollector import CbaseCollector
import re
sys.path.append("..")
from common.cmds import execCmd

class CsocketStatus(CbaseCollector):
    def __init__(self, sender):
        super(CsocketStatus, self).__init__(sender)

    def putDict(self, tbl, d):
        s = " "
        for k, v in d.items():
            s += "%s=%d," %(k, v)
        self._sender.put(tbl, s[:-1])
    """
    Total: 77 (kernel 350)
    TCP:   11 (estab 3, closed 3, orphaned 0, synrecv 0, timewait 3/0), ports 0

    Transport Total     IP        IPv6
    *	  350       -         -
    RAW	  0         0         0
    UDP	  9         5         4
    TCP	  8         6         2
    INET	  17        11        6
    FRAG	  0         0         0
    """

    def proc(self):
        cmd = "/usr/sbin/ss -s"
        lines = execCmd(cmd).split('\n')
        if len(lines) < 10:
            return
        d = {}

        line = lines[0]
        v = line.split(":")[1].strip()
        total, title, kernel = v.split(" ")
        d['total'] = int(total)
        d['kernel'] = int(kernel[:-1])

        line = lines[1]
        v = line.split(":")[1].strip()
        tcp, vv = v.split("(")
        d['tcp'] = int(tcp.strip())
        stats, port = vv.split(")")
        for stat in stats.split(","):
            h, v = stat.strip().split(' ')
            if '/' in v:
                v = v.split("/")[0]
            d['tcp_' + h] = int(v)

        for line in lines[5:]:
            line = re.sub(" +", " ", line)
            ts = line.split(" ")
            if len(ts) < 2 or ts[0][:-1] == "TCP":
                continue
            d[ts[0][:-1]] = int(ts[1])
        self.putDict('socket', d)

if __name__ == "__main__":
    pass
