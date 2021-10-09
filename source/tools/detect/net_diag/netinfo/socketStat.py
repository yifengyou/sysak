# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     socketStat
   Description :
   Author :       liaozhaoyan
   date：          2021/7/1
-------------------------------------------------
   Change Activity:
                   2021/7/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
from influxSend import CslsSend
from subprocess import PIPE, Popen
import shlex
import time
import re

socketStatCmd = "ss -s"

class CsocketStat(object):
    def __init__(self, host="127.0.0.1", port=8086, db='longcheer', user="admin", pswd='alios123'):
        self.__cmds = shlex.split(socketStatCmd)
        self.__send = CslsSend()

    def _exec(self):
        p = Popen(self.__cmds, stdout=PIPE)
        return p.stdout.readlines()

    def putDict(self, tbl, d):
        s = " "
        for k, v in d.items():
            s += "%s=%d," %(k, v)
        self.__send.put(tbl, s[:-1])

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
        lines = self._exec()
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
            d['tcp_' +h] = int(v)

        for line in lines[5:]:
            line = re.sub(" +", " ", line)
            ts = line.split(" ")
            if len(ts) < 2 or ts[0][:-1] == "TCP":
                continue
            d[ts[0][:-1]] = int(ts[1])
        self.putDict('socket', d)
        self.__send.push()

if __name__ == "__main__":
    if len(sys.argv) == 6:
        s = CsocketStat(host=sys.argv[1], port=int(sys.argv[2]), db=sys.argv[3], user=sys.argv[4], pswd=sys.argv[5])
    else:
        s = CsocketStat(host=sys.argv[1])
    while True:
        time.sleep(60)
        s.proc()
    pass
