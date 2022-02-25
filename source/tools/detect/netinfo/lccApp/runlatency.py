# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     runlantency
   Description :
   Author :       liaozhaoyan
   date：          2021/7/28
-------------------------------------------------
   Change Activity:
                   2021/7/28:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
sys.path.append("../")

import time
import json
import ctypes as ct
from threading import Thread
from queue import Queue

from pylcc.lbcBase import ClbcBase

class CoomThread(Thread):
    def __init__(self, e, q):
        super(CoomThread, self).__init__()
        self._q = q
        self.setDaemon(True)
        self._e = e

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        n = self._e.event(stream)
        with open('/proc/loadavg') as stats:
            avgline = stats.read().rstrip()
        # con = self._cp.getDockerName(n.con)
        con = n.con
        log = "OOM kill task, con: %s, pid: %d, comm: %s, pages:%d, loadavg: %s" % (con, n.tpid, n.tcomm, n.pages, avgline)
        try:
            self._q.put(log, block=False)
        except:
            pass

    def run(self):
        self._e.open_perf_buffer(self._callback)
        try:
            self._e.perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()

class CrunLantency(ClbcBase):
    def __init__(self, soPath, sender):
        super(CrunLantency, self).__init__(soPath, workPath=os.path.split(os.path.realpath(__file__))[0])
        self.__q = Queue()
        self.__q.maxsize = 60
        self._send = sender
        oom = CoomThread(self.maps['oom_out'], self.__q)
        oom.start()

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['oom_out'].event(stream)
        print(e.tcomm, e.fcomm)

    def loop(self):
        count = 0; i = 0
        while True:
            logs = ""
            while not self.__q.empty():
                log = self.__q.get()
                logs += log + "; "
                count += 1
            if len(logs):
                self._send.put("net_log", ',level=warn,src=run log="%s"' % (logs[:-2]))
            i += 1
            if i >= 60:
                self._send.put("net_log_c", ' count=%d' % (count))
                i = 0; count = 0
            time.sleep(1)

def runqLoop(sender, version):
    if "3.10" in version:
        r = CrunLantency('runq.3.10', sender)
    else:
        r = CrunLantency('runq.4.plus', sender)
    r.loop()

if __name__ == "__main__":
    pass
