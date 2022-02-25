# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     hostId
   Description :
   Author :       liaozhaoyan
   date：          2022/2/17
-------------------------------------------------
   Change Activity:
                   2022/2/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import socket
from subprocess import PIPE, Popen
import shlex
from threading import Timer

class ChostId(object):
    def __init__(self, confd):
        """
        setup confd
        :param confd: configure dict for common use
        """
        super(ChostId, self).__init__()
        self._disDict = {"local": self._formNetloc,
                         "instance": self._instance,
                         }
        self._dispatchMode(confd)

    def _exec(self, cmd):
        kill = lambda process: process.kill()
        p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
        mtimer = Timer(5, kill, [p])
        r = ""
        try:
            mtimer.start()
            r = p.stdout.read().decode('')
        finally:
            mtimer.cancel()
            return r

    def _instance(self, dummy):
        l = self._exec("curl 100.100.100.200/latest/meta-data/instance-id").strip()
        if l in ["", b'']:
            return self._exec('hostname').strip()
        return l

    def _formNetloc(self, confd):
        loc = confd['host']
        dst, port = loc.split(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, int(port)))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def _dispatchMode(self, confd):
        """

        :param confd: configure dict for common use
        """
        if "hostId" not in confd:
            mode = confd['hMode']
            if mode not in self._disDict:
                raise ValueError("unknown hMode: %s" % mode)
            confd["hostId"] = self._disDict[mode](confd)


if __name__ == "__main__":
    pass
