# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     cmds
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
import json
from threading import Thread
import atexit
from subprocess import PIPE, Popen
import shlex
ON_POSIX = 'posix' in sys.builtin_module_names

def execCmd(cmd):
    p = Popen(shlex.split(cmd), stdout=PIPE)
    return p.stdout.read().decode('utf-8')

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
        print("stop.")
        self._stop = True
        self.__p.kill()

    def setCallBack(self, callBack):
        self._callBack = callBack

    def run(self):
        out = self.__p.stdout
        for line in iter(out.readline, b''):
            self._callBack(line.decode())
            if self._stop:
                break
        out.close()

class CconProc(object):
    def __init__(self):
        super(CconProc, self).__init__()

    def getDockerName(self, serial):
        if serial == '' or serial == '/':
            return "host"
        try:
            con = serial.split("-", 1)[1].split(".", 1)[0]  # docker-xxxxx.scope
        except IndexError:
            print(serial, type(serial))
            con = serial.split("-", 1)[1]
        dDocker = json.loads(execCmd('docker inspect %s' % con))
        if dDocker is not None:
            return dDocker[0]['Name']
        else:
            return None

if __name__ == "__main__":
    pass
