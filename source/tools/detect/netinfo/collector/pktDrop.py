# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     pktdrop
   Description :
   Author :       liaozhaoyan
   date：          2021/6/22
-------------------------------------------------
   Change Activity:
                   2021/6/22:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from subprocess import PIPE, Popen
import shlex
import time

catCmds = ["cat /proc/net/snmp", "cat /proc/net/netstat"]
cells = ['Abort', 'PAWS', 'Err', 'Fail', 'Drop']

class CprocCat(object):
    def __init__(self, cmds, cell):
        self.__cmds = shlex.split(cmds)
        self.cells = cell
        self._d = self.proc()

    def merge_dict(self, ds):
        r = {}
        for d in ds:
            for k, v in d.items():
                for cell in self.cells:
                    if cell in k:
                        r[k] = v
                        continue
        return r

    def parse_vars(self, h, v):
        ss = h.split(" ")
        t = ss[0]
        ts = ss[1:]
        ss = v.split(" ")
        vs = ss[1:]
        ret = {}
        for i, s in enumerate(ts):
            ret[t + s] = int(vs[i])
        return ret

    def _exec(self):
        p = Popen(self.__cmds, stdout=PIPE)
        return p.stdout.read().decode('utf-8')

    def proc(self):
        hs = self._exec().split('\n')
        size = (len(hs) - 1) >> 1
        ds = []
        for i in range(size):
            ds.append(self.parse_vars(hs[2 * i].strip(), hs[2 * i + 1].strip()))
        return self.merge_dict(ds)

    def check(self):
        d = self.proc()
        for k in d.keys():
            if d[k] > self._d[k]:
                print(k, d[k] - self._d[k])
                self._d[k] = d[k]

if __name__ == "__main__":
    ps = []
    for c in catCmds:
        ps.append(CprocCat(c, cells))
    while True:
        time.sleep(60)
        for p in ps:
            p.check()
    pass
