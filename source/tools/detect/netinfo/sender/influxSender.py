# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     influxSender
   Description :
   Author :       liaozhaoyan
   date：          2022/2/17
-------------------------------------------------
   Change Activity:
                   2022/2/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import requests
from .netSender import CnetSender

class CinfluxSender(CnetSender):
    def __init__(self, confd):
        super(CinfluxSender, self).__init__(confd)
        self._head = self._setupHead()
        self._url = self._setupUrl()

    def _setupHead(self):
        return "host=%s" % (self._confd['hostId'])

    def _setupUrl(self):
        return "http://%s/write?db=%s&u=%s&p=%s" % (
            self._confd['host'],
            self._confd['db'],
            self._confd['user'],
            self._confd['pass']
        )

    def push(self, s):
        if s:
            response = requests.post(self._url, data=s)
            if response.status_code != 204:
                print("sever return %d: %s" % (response.status_code, response.headers))

    def put(self, table, s):
        w = "%s,%s%s" % (table, self._head, s)
        super(CinfluxSender, self).puts(w)

if __name__ == "__main__":
    pass
