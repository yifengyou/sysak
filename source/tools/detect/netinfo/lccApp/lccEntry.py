# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     lccEntry
   Description :
   Author :       liaozhaoyan
   date：          2022/2/18
-------------------------------------------------
   Change Activity:
                   2022/2/18:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import sys
import threading
from .netCollect import netCLoop
from .runlatency import runqLoop
sys.path.append("../")
from common.cmds import execCmd
from collector.baseCollector import CbaseCollector


class ClccEntry(CbaseCollector):
    def __init__(self, sender):
        super(ClccEntry, self).__init__(sender)
        self._entry(sender)

    def _entry(self, send):
        version = execCmd('uname -r')
        ts = [threading.Thread(target=runqLoop, args=(send, version)),
              threading.Thread(target=netCLoop, args=(send, version))]
        for t in ts:
            t.start()

if __name__ == "__main__":
    pass
