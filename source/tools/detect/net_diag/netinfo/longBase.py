# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     longBase
   Description :
   Author :       liaozhaoyan
   date：          2021/8/14
-------------------------------------------------
   Change Activity:
                   2021/8/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys

from pingSls import CasyncCmdQue
from influxSend import ChostId, CslsSend
import time
from collections import deque

class ClongBase():
    def __init__(self):
        h = ChostId()
        host = h.getHost()
        cmd = "./longcheer -d -X %s" % (host)
        self.__toKill = 0
        self._t = CasyncCmdQue(cmd, self._proc)
        self._q = deque()
        self.__send = CslsSend()

    def __getKilling(self, lines):
        if (lines.startswith("pid:")):
            _, pid = lines.split(":", 1)
            self.__toKill = int(pid.strip())
        else:
            print("longtrace start: %s, not pid: xxxx" % lines)
            sys.exit(1)

    def _proc(self, lines):
        self._q.append(lines)

    def loop(self):
        while True:
            time.sleep(1)

    def proc(self):
        lines = ""
        while True:
            try:
                lines += self._q.pop()
            except IndexError:
                break
        if len(lines) > 0:
            self.__send.setStr(lines)
            self.__send.push()


if __name__ == "__main__":
    l = ClongBase()
    l.loop()
