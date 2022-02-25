# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     pingSls.py
   Description :
   Author :       liaozhaoyan
   date：          2021/8/3
-------------------------------------------------
   Change Activity:
                   2021/8/3:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
import time
import json
from threading import Lock
from collections import deque
from .baseCollector import CbaseCollector
sys.path.append("../")
from common.cmds import CasyncCmdQue, execCmd

getIndex = ["l_tx_kern", "l_tx_qdisc", "l_rx_kern", "l_rx_task_waking", "l_rx_task_queue", "l_tx_merged_kern", "l_rx_merged_kern", "total"]


class CpingTrace(CbaseCollector):
    def __init__(self, sender):
        super(CpingTrace, self).__init__(sender)
        self._gw = self._getGW()
        self._lock = Lock()
        self.t = CasyncCmdQue("%s/pingtrace -c %s" %(os.getcwd(), self._gw), self._cb)
        self.q = deque(maxlen=60)
        self._dRec = None

    def parse(self, line):
        d = json.loads(line)
        delays = d['delays']
        dRet = {}
        dRet['seq'] = d['meta']['seq']
        for ddelay in delays:
            if ddelay['delay'] in getIndex:
                dRet[ddelay['delay']] = ddelay['ts']
        return dRet

    def _cb(self, line):
        r = self.parse(line)
        with self._lock:
            if self._dRec is None:
                self._dRec = r
            elif r['total'] > self._dRec['total']:
                self._dRec = r

    def _getGW(self):
        lines = execCmd('ip route').split('\n')
        for line in lines:
            if line.startswith("default via"):
                ls = line.split(' ')
                return ls[2]
        raise Exception("no default gw.")

    def popEle(self):
        with self._lock:
            if self._dRec is None:
                return
            for k, v in self._dRec.items():
                self._sender.put('pingtrace', " %s=%d" % (k, v))
            self._dRec = None

    def proc(self):
        self.popEle()

    def loop(self):
        while True:
            time.sleep(60)
            self.popEle()


if __name__ == "__main__":
    p = CpingTrace()
    p.loop()
    pass
