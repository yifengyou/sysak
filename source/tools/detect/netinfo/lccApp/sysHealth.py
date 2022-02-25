# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     sysHealth
   Description :
   Author :       liaozhaoyan
   date：          2022/2/17
-------------------------------------------------
   Change Activity:
                   2022/2/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
from pylcc import ClbcBase
from surftrace import CexecCmd

sys.path.append("../")
from collector.baseCollector import CbaseCollector

class CsysHealth(ClbcBase):
    def __init__(self, sender):
        self._echo = False
        self._sender = sender
        super(CsysHealth, self).__init__("sysHealth")
        self._c = CexecCmd()
        self.setupSchedstats()

    def __del__(self):
        if self._echo:
            self._c.system("echo 0 > /proc/sys/kernel/sched_schedstats")

    def setupSchedstats(self):
        res = self._c.cmd("cat /proc/sys/kernel/sched_schedstats")
        if res == "0":
            self._c.system("echo 1 > /proc/sys/kernel/sched_schedstats")
            self._echo = True

    def _proc(self):
        dMap = self.maps['outCnt']
        return dMap.get()

    def proc(self):
        return self._proc()


class ChealthCollector(CbaseCollector):
    def __init__(self, sender):
        super(ChealthCollector, self).__init__(sender)
        self._bpf = CsysHealth(sender)
        self._hIndex = ("wait_ts", "waits",
                        "io_ts", "ios",
                        "hung_ts", "hungs",
                        "net_ts", "nets",
                        "mem_ts", "mems"
                        )
        self._vd = dict(zip(self._hIndex, [0] * len(self._hIndex)))
        self._dLast = {}

    def proc(self):
        d = self._bpf.proc()
        dNow = {}
        for k, v in d.items():
            dNow[self._hIndex[k]] = v
        dDelta = self._vd.copy()
        for k in dDelta.keys():
            if k in dNow:
                if k in self._dLast:
                    dDelta[k] = dNow[k] - self._dLast[k]
                else:
                    dDelta[k] = dNow[k]
        self._dLast = dNow.copy()

        s = " "
        for k, v in dDelta.items():
            s += "%s=%s," % (k, v)
        self._sender.put("health", s[:-1])

if __name__ == "__main__":
    pass
