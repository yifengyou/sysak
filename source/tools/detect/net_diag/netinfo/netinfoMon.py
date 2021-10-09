# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     netinfoMon
   Description :
   Author :       liaozhaoyan
   date：          2021/7/14
-------------------------------------------------
   Change Activity:
                   2021/7/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import time
import sched
from subprocess import PIPE, Popen
import shlex
from pktMon import CpktMon
from socketStat import CsocketStat
from retransMon import CretransMon
from pingSls import CpingSls
from runlatency import runqLoop
from netCollect import netCLoop
from longBase import ClongBase
import thread

logSched = sched.scheduler(time.time, time.sleep)

def _exec(cmd):
    p = Popen(shlex.split(cmd), stdout=PIPE)
    return p.stdout.read()

def loop(ms, t):
    logSched.enter(t, 0, loop, (ms,t))
    for m in ms:
        m.proc()

def mainLoop(ip):
    version = _exec('uname -r')
    thread.start_new_thread(runqLoop, (ip, version))
    thread.start_new_thread(netCLoop, (ip, version))
    ms = [CsocketStat(), CpktMon(), CretransMon(), CpingSls(), ClongBase()]
    logSched.enter(0, 0, loop, (ms, 60))
    logSched.run()

if __name__ == "__main__":
    print sys.argv[1]
    mainLoop(sys.argv[1])
    pass
