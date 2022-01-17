# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     pingSls.py
   Description :
   Author :       liaozhaoyan
   date:          2021/8/3
-------------------------------------------------
   Change Activity:
                   2021/8/3:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import collections
import re
import signal
import sys
import os
import shlex
import time
import atexit
import json
from subprocess import PIPE, Popen
from threading import Thread, Lock
from influxSend import CslsSend
from collections import deque
ON_POSIX = 'posix' in sys.builtin_module_names

class CasyncCmdQue(Thread):
    def __init__(self, cmd, callBack):
        super(CasyncCmdQue, self).__init__()
        self.daemon = True  # thread dies with the program

        self.__p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, close_fds=ON_POSIX)
        self._callBack = callBack
        self._stop = False
        self.start()
        atexit.register(self.hook)

    def hook(self):
        print "stop."
        self._stop = True
        self.__p.kill()

    def setCallBack(self, callBack):
        self._callBack = callBack

    def run(self):
        out = self.__p.stdout
        for line in iter(out.readline, b''):
            self._callBack(line)
            if self._stop:
                break
        out.close()

getIndex = ["l_tx_kern", "l_tx_qdisc", "l_rx_kern", "l_rx_task_waking", "l_rx_task_queue", "l_tx_merged_kern", "l_rx_merged_kern", "total"]

class CpingSls():
    def __init__(self, host="127.0.0.1", port=8086, db='longcheer', user="admin", pswd='alios123'):
        self._gw = self._getGW()
        self.t = CasyncCmdQue("./pingtrace -c %s" % self._gw, self._cb)
        self.q = deque(maxlen=60)
        self.__send = CslsSend()
        self._dRec = None
        self._lock = Lock()

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

    def _exec(self, cmd):
        p = Popen(shlex.split(cmd), stdout=PIPE)
        return p.stdout.read()

    def _getGW(self):
        lines = self._exec('ip route').split('\n')
        for line  in lines:
            if line.startswith("default via"):
                ls = line.split(' ')
                return ls[2]
        raise Exception("no default gw.")

    def popEle(self):
        with self._lock:
            if self._dRec is None:
                return
            for k, v in self._dRec.items():
                self.__send.put('pingtrace', " %s=%d" % (k, v))
            self._dRec = None
        self.__send.push()

    def proc(self):
        self.popEle()

    def loop(self):
        while True:
            time.sleep(60)
            self.popEle()


if __name__ == "__main__":
    p = CpingSls()
    p.loop()
    pass
