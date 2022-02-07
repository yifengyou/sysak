# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     runlantency
   Description :
   Author :       liaozhaoyan
   date:          2021/7/28
-------------------------------------------------
   Change Activity:
                   2021/7/28:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import time
from pylcc.lbcBase import ClbcBase
import ctypes as ct
from threading import Thread
from Queue  import Queue
from influxSend import CslsSend

class CoomThread(Thread):
    def __init__(self, e, q):
        super(CoomThread, self).__init__()
        self._q = q
        self.setDaemon(True)
        self._e = e
        self.start()

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        n = self._e.event(stream)
        with open('/proc/loadavg') as stats:
            avgline = stats.read().rstrip()
        log = ("Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
               ", %d pages, loadavg: %s") % (n.fpid, n.fcomm, n.tpid,
                                             n.tcomm, n.pages, avgline)
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

class CrunqThread(Thread):
    def __init__(self, e, q):
        super(CrunqThread, self).__init__()
        self._q = q
        self.setDaemon(True)
        self._e = e
        self.start()

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        n = self._e.event(stream)
        log = "task:%s pid: %d, delayed for %d us" % (n.task, n.pid, n.delta_us)
        try:
            self._q.put(log, block=False)
        except:
            pass

    def run(self):
        print "run runq thread."
        self._e.open_perf_buffer(self._callback)
        try:
            self._e.perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()

class CrunLantency(ClbcBase):
    def __init__(self, soPath):
        super(CrunLantency, self).__init__(soPath)
        self.__q = Queue()
        self.__q.maxsize = 60
        oom = CoomThread(self.maps['oom_out'], self.__q)
        delay = CrunqThread(self.maps['delay_out'], self.__q)
        self._send = CslsSend()

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['oom_out'].event(stream)
        print e.tcomm, e.fcomm

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
                self._send.push()
            i += 1
            if i >= 60:
                self._send.put("net_log_c", ' count=%d' % (count))
                self._send.push()
                i = 0; count = 0
            time.sleep(1)

def runqLoop(ip, version):
    if "3.10" in version:
        r = CrunLantency('./runq.3.10.so')
    else:
        r = CrunLantency('./runq.4.9plus.so')
    r.loop()

if __name__ == "__main__":
    r = CrunLantency('./runq.4.9plus.so')
    r.loop()
    pass
