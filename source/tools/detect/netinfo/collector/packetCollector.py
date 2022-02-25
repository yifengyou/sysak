# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     pktMon
   Description :
   Author :       liaozhaoyan
   date：          2021/6/27
-------------------------------------------------
   Change Activity:
                   2021/6/27:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from .pktDrop import CprocCat
from .baseCollector import CbaseCollector
cellsMon = ['Abort', 'PAWS', 'Err', 'Fail', 'Drop', 'Overflow']


class ClocalDrop(CprocCat):
    def __init__(self, cmds, cell):
        super(ClocalDrop, self).__init__(cmds, cell)

    def checkAdditon(self, dSum):
        d = self.proc()
        log = ""
        for k in d.keys():
            if d[k] > self._d[k]:
                delta = d[k] - self._d[k]
                log += "%s: %d, " %(k, delta)
                for cell in self.cells:
                    if cell in k:
                        dSum[cell] += delta
                self._d[k] = d[k]
        return log

class CpacketCollector(CbaseCollector):
    def __init__(self, sender, cells=cellsMon):
        super(CpacketCollector, self).__init__(sender)
        catCmds = ["cat /proc/net/snmp", "cat /proc/net/netstat"]
        self.__ps = []
        self.__cell = cells
        for c in catCmds:
            self.__ps.append(ClocalDrop(c, cells))

    def __createCellDict(self):
        vList = [0] * len(self.__cell)
        return dict(zip(self.__cell, vList))

    def proc(self):
        dSum = self.__createCellDict()
        logs = ""
        for p in self.__ps:
            logs += p.checkAdditon(dSum)
        if len(logs):
            self._sender.put("pkt_log", ' logs="%s"' % logs[:-2])
        for k in dSum.keys():
            self._sender.put("pkt_staus", ",status=%s count=%d" % (k, dSum[k]))

if __name__ == "__main__":
    pass
