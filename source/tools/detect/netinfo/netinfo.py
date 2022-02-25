# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     entry
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
import time
from common.argParser import installConfig
from common.hostId import ChostId
from sender.influxSender import CinfluxSender

from collector.retransCollector import CretransCollector
from collector.packetCollector import CpacketCollector
from collector.longBase import ClongBase
from collector.diskFree import CdiskFree
from collector.pingTrace import CpingTrace
from collector.socketStatus import CsocketStatus
from lccApp.sysHealth import ChealthCollector
from lccApp.lccEntry import ClccEntry

tUrl = "http://pylcc.openanolis.cn:8086/?db=sysom&user=Y%3D4WatRW&pass=bpxWY%3DMjMxM3&baseMon=off&hMode=local"
baseConf = ["host", "db", "user", "pass"]
opdConf = {"baseMon": "on",
           "pingtrace": "on",
           "netMon": "on",
           "lcc": "on",
           "pusher": "influx"}
sendD = {"influx": CinfluxSender}
monD = {
    "baseMon": [ClongBase, CdiskFree],
    "pingtrace": [CpingTrace],
    "netMon": [CpacketCollector, CsocketStatus, CretransCollector],
    "lcc": [ChealthCollector, ClccEntry],
}

def _setupCollector(send, op):
    global monD
    gms = []
    for k in monD:
        if op[k] == "on":
            for c in monD[k]:
                gms.append(c(send))
    while True:
        for m in gms:
            m.proc()
        print("loop.")
        time.sleep(60)

def checkConf(base, op, url):
    op.update(installConfig(url, base))
    ChostId(op)
    send = sendD[op["pusher"]](op)  # setup pusher
    _setupCollector(send, op)

if __name__ == "__main__":
    checkConf(baseConf, opdConf, sys.argv[1])
    # checkConf(baseConf, opdConf, tUrl)
    pass
