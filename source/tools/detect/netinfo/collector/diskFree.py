# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     conHost
   Description :
   Author :       liaozhaoyan
   date：          2021/9/17
-------------------------------------------------
   Change Activity:
                   2021/9/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
from .baseCollector import CbaseCollector
import time
sys.path.append("../")
from common.cmds import execCmd

LONG_COUNT = 600


class CdiskFree(CbaseCollector):
    def __init__(self, sender):
        super(CdiskFree, self).__init__(sender)
        self.__count = 0

    def _transSize(self, s):
        unitD = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024, "T": 1024 * 1024 * 1024 * 1024, "P": 1024 * 1024 * 1024 * 1024 * 1024, "E": 1024 * 1024 * 1024 * 1024 * 1024 * 1024, "Z": 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024}
        if str.isdigit(s):
            return float(s)
        else:
            f = float(s[:-1])
            unit = s[-1]
            return f * unitD[unit] / (unitD['G'])

    def proc(self):
        #   get file system
        dfs = execCmd('df -h')
        for l in dfs.split('\n'):
            if l.startswith("/dev/"):
                # Filesystem      Size  Used Avail Use% Mounted on
                hard, total, use, free, percent, mount = l.split()
                mount = '/' + mount[9:]
                self._sender.put("fsinfo", ',disk=%s total=%f,use=%f,free=%f,percent=%f,mount="%s"' % (hard, self._transSize(total), self._transSize(use), self._transSize(free), float(percent[:-1]), mount))

        if self.__count % LONG_COUNT:
            self.__count += 1
            return
        self.__count += 1

        # os-release
        dRelease = {}
        heads = ["NAME", "VERSION", "PRETTY_NAME", "VERSION_ID"]
        lines = execCmd('cat /etc/os-release').split('\n')
        for line in lines:
            try:
                head, content = line.split('=', 1)
            except ValueError:
                break
            if head in heads:
                dRelease[str.lower(head)] = content.strip('"')
        dRelease['os_kernel'] = execCmd('uname -r')
        s = ""
        for k, v in dRelease.items():
            s += '%s="%s",' % (k, v)
        self._sender.put('os_host_release', " %s" % s[:-1])

if __name__ == "__main__":
    h = CdiskFree()
    while True:
        h.proc()
        time.sleep(60)
    pass
