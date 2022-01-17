# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     pktMon
   Description :
   Author :       liaozhaoyan
   date:          2021/6/27
-------------------------------------------------
   Change Activity:
                   2021/6/27:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys

from pktdrop import CprocCat
from influxSend import CslsSend
import time
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

class CpktMon(object):
    def __init__(self, cells=cellsMon, host="127.0.0.1", port=8086, db='longcheer', user="admin", pswd='alios123'):
        catCmds = ["cat /proc/net/snmp", "cat /proc/net/netstat"]
        self.__ps = []
        self.__cell = cells
        for c in catCmds:
            self.__ps.append(ClocalDrop(c, cells))
        self.__send = CslsSend()

    def __createCellDict(self):
        vList = [0] * len(self.__cell)
        return dict(zip(self.__cell, vList))

    def proc(self):
        dSum = self.__createCellDict()
        logs = ""
        for p in self.__ps:
            logs += p.checkAdditon(dSum)
        if len(logs):
            self.__send.put("pkt_log", ' logs="%s"' % logs[:-2])
        for k in dSum.keys():
            self.__send.put("pkt_staus", ",status=%s count=%d" % (k, dSum[k]))
        self.__send.push()

if __name__ == "__main__":
    if len(sys.argv) == 6:
        mon = CpktMon(cells=cellsMon, host=sys.argv[1], port=int(sys.argv[2]), db=sys.argv[3], user=sys.argv[4], pswd=sys.argv[5])
    else:
        mon = CpktMon(cells=cellsMon, host=sys.argv[1])
    while True:
        time.sleep(10)
        mon.proc()
    pass
