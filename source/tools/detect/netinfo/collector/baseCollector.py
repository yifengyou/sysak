# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     baseCollector
   Description :
   Author :       liaozhaoyan
   date：          2021/10/23
-------------------------------------------------
   Change Activity:
                   2021/10/23:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

class CbaseCollector(object):
    def __init__(self, sender):
        super(CbaseCollector, self).__init__()
        self._sender = sender

    def proc(self):
        pass

if __name__ == "__main__":
    pass
