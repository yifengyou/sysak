# -*- coding: utf-8 -*-
# cython:language_level=3
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

import sys
from .baseCollector import CbaseCollector
import time
import os
from collections import deque
sys.path.append("../")
from common.cmds import CasyncCmdQue


class ClongBase(CbaseCollector):
    def __init__(self, sender):
        super(ClongBase, self).__init__(sender)
        cmd = "%s/longcheer -d -C -X %s" % (os.getcwd(), sender.host)
        self.__toKill = 0
        self._t = CasyncCmdQue(cmd, self._proc)
        self._q = deque()

    def __getKilling(self, lines):
        if lines.startswith("pid:"):
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
            self._sender.puts(lines[:-1])


if __name__ == "__main__":
    l = ClongBase()
    l.loop()
