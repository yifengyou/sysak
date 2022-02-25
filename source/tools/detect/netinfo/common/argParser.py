# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     argParser
   Description :
   Author :       liaozhaoyan
   date：          2022/2/16
-------------------------------------------------
   Change Activity:
                   2022/2/16:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from .codec import decodeArgs
from urllib import parse
tUrl = "http://pylcc.openanolis.cn:8086/?db=sysom&user=Y%3D4WatRW&pass=bpxWY%3DMjMxM3"


def installConfig(url, qList):
    res = parse.urlparse(url)
    qs = parse.parse_qs(res.query)
    qDict = {}
    if "host" in qList:
        qDict["host"] = res.netloc
    for q in qs:
        if q not in qDict:
            decodeArgs(qDict, q, qs[q][0])
    for k in qList:
        if k not in qDict:
            raise ValueError("%s is a variable that must be set" % k)
    return qDict


if __name__ == "__main__":
    wants = ["host", "db", "user", "pass"]
    print(installConfig(tUrl, wants))
    pass
