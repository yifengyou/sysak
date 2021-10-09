# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     compile
   Description :
   Author :       liaozhaoyan
   date：          2021/9/8
-------------------------------------------------
   Change Activity:
                   2021/9/8:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from pylcc.lbcBase import ClbcBase
import sys

class compile(ClbcBase):
    def __init__(self, bpf, ver):
        super(compile, self).__init__(bpf, ver=ver)

if __name__ == "__main__":
    c = compile(sys.argv[1], sys.argv[2])
    pass
