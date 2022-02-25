# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     netSender
   Description :
   Author :       liaozhaoyan
   date：          2022/2/17
-------------------------------------------------
   Change Activity:
                   2022/2/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
from threading import Thread
from queue import Queue, Empty

class CnetSender(Thread):
    def __init__(self, confd):
        super(CnetSender, self).__init__()
        self.host = confd["hostId"]
        self._confd = confd
        self._pStr = ""
        self._q = Queue()
        self.start()

    def run(self):
        while True:
            count = 0
            try:
                send = self._q.get(timeout=30) + "\n"
            except Empty:
                continue

            while count < 20:
                try:
                    send += self._q.get(timeout=0.1) + "\n"
                    count += 1
                except Empty:
                    break
            if len(send) > 0:
                self.push(send[:-1])

    def puts(self, s):
        self._q.put(s)

    def put(self, table, s):
        self._q.put(s)

    def push(self, s):
        print(s)
        pass


if __name__ == "__main__":
    pass
