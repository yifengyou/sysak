# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     influxSend
   Description :
   Author :       liaozhaoyan
   date:          2021/6/26
-------------------------------------------------
   Change Activity:
                   2021/6/26:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import requests
from subprocess import PIPE, Popen
from aliyun.log import LogClient, PutLogsRequest, LogItem, GetLogsRequest
import shlex
import time
import base64
from threading import Timer

class CinfluxSend():
    def __init__(self, host="127.0.0.1", port=8086, db='longcheer', user="admin", pswd='alios123'):
        self.__url = 'http://%s:%d/write?db=%s&u=%s&p=%s' %(host, port, db, user, pswd)
        self.getHead()
        self.__pStr = ""

    def _exec(self, cmd):
        p = Popen(shlex.split(cmd), stdout=PIPE)
        return p.stdout.read()

    def getHead(self):
        self.__host = self._exec('hostname').split(".")[0].strip()
        self.__arch = self.__mtm = "Unknown"
        lscpu = self._exec('lscpu')
        for line in lscpu.split("\n"):
            if line.startswith("Architecture"):
                self.__arch = line.split(":", 1)[1].strip()
            elif line.startswith("Hypervisor vendor"):
                self.__mtm = line.split(":", 1)[1].strip()
            elif line.startswith("超管理器厂商"):
                self.__mtm = line.split(" ", 1)[1].strip()
        self.__os = 'Unknown'
        os = self._exec('cat /etc/os-release')
        for line in os.split("\n"):
            if line.startswith("ID="):
                self.__os = line.split("=")[1].strip()[1:-1]
        self.__head = "host=%s,os=%s,architecture=%s,mtm=%s" % ( \
                    self.__host, self.__os, self.__arch, self.__mtm )

    #interrupts_c,host=localhost,os=Alibaba,architecture=x86-64,serial_no=unknown,mtm=KVM,interrupts_c_name=cpu0 count=467.991
    def put(self, table, data):
        s = "%s,%s%s\n" %(table, self.__head, data)
        self.__pStr += s

    def push(self):
        if (len(self.__pStr)):
            response = requests.post(self.__url, data=self.__pStr)
            if response.status_code != 204:
                print("sever return %d: %s" % ( response.status_code, response.headers))
            self.__pStr = ""

hostId = ""
class ChostId():
    def __init__(self):
        pass

    def _exec(self, cmd):
        kill = lambda process: process.kill()
        p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
        mtimer = Timer(1, kill, [p])
        r = ""
        try:
            mtimer.start()
            r = p.stdout.read()
        finally:
            mtimer.cancel()
            return r

    def getHost(self):
        global hostId
        if hostId != "":
            return hostId
        l = self._exec("curl 100.100.100.200/latest/meta-data/instance-id").strip()
        if l == "":
            return self._exec('hostname').strip()
        hostId = l
        return hostId

class CslsSend():
    def __init__(self, project="influxdb", logstore="bixin"):
        k = "TFRBSTV0OHJWS1U1SllNSm9wQlh4Z1pt"
        v = "SDFyMHVkb25vaTVxREsxSnlrbXBpYTZWSW9Ddklj"
        self._client = LogClient("cn-hangzhou.log.aliyuncs.com", base64.b64decode(k), base64.b64decode(v))
        self.__project = project
        self.__logstore = logstore
        self.getHead()
        self.__pStr = ""

    def _exec(self, cmd):
        p = Popen(shlex.split(cmd), stdout=PIPE)
        return p.stdout.read()

    def getHead(self):
        host = ChostId()
        self.__host = host.getHost()
        self.__os = 'Unknown'
        os = self._exec('cat /etc/os-release')
        for line in os.split("\n"):
            if line.startswith("ID="):
                self.__os = line.split("=")[1].strip()[1:-1]
        self.__head = "host=%s,os=%s" % ( \
                    self.__host, self.__os )

    def put(self, table, data):
        s = "%s,%s%s\n" %(table, self.__head, data)
        self.__pStr += s

    def setStr(self, lines):
        self.__pStr = lines

    def push(self):
        if (len(self.__pStr)):
            contents = [
                ('vm', self.__host),
                ('log', self.__pStr)
            ]
            log_item = LogItem()
            log_item.set_contents(contents)
            request = PutLogsRequest(self.__project, self.__logstore, "", "", [log_item], compress=True)
            self._client.put_logs(request)
            self.__pStr = ""


if __name__ == "__main__":
    send = CslsSend()
    for i in range(10):
        send.put('test', ' count=%d' % i)
    send.push()
    pass

